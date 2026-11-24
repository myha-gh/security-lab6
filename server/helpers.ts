import type { Context } from 'hono';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import { HTTPException } from 'hono/http-exception';
import { and, eq, gt, sql } from 'drizzle-orm';
import { z } from 'zod';
import { Resend } from 'resend';
import { readConfig } from './config';
import { connectDatabase, type Database } from './db';
import { users, tokens, sessions, loginLogs, rateLimits, type User } from './db/schema';
import { digest, randomToken, generateOtp, otpDigest } from './security';

type Env = { Variables: { user: User; sessionHash: string; ip: string } };
type Transaction = Parameters<Parameters<Database['transaction']>[0]>[0];
type LoginResult = { twoFactor: boolean; token: string };
const minute = 60_000;
const expiresIn = (ms: number) => new Date(Date.now() + ms);
const emailSchema = z.string().trim().toLowerCase().email().max(254);
const credentials = z.object({
  email: emailSchema,
  password: z.string().min(1).max(128),
});
const codeSchema = z.string().regex(/^\d{6}$/);
const tokenSchema = z.string().min(32).max(100);
const emailMessage = {
  message: 'Якщо адреса зареєстрована, ми надіслали лист. Перевірте пошту.',
};

function fail(message: string, status: 400 | 401 | 403 | 404 | 429 = 400): never {
  throw new HTTPException(status, { message });
}

function publicUser(user: User) {
  return {
    id: user.id,
    email: user.email,
    role: user.role,
    activatedAt: user.activatedAt,
    twoFactor: user.twoFactor,
    hasPassword: !!user.passwordHash,
    googleLinked: !!user.googleSub,
    createdAt: user.createdAt,
  };
}

const config = readConfig();
const { db, pool } = connectDatabase(config.DATABASE_URL);
const resend = new Resend(config.RESEND_API_KEY);
async function sendMail(to: string, subject: string, text: string) {
  const { error } = await resend.emails.send({
    from: config.MAIL_FROM,
    to,
    subject,
    text,
  });
  if (error) throw new Error('MAIL_DELIVERY_FAILED');
}

const cookieOptions = {
  httpOnly: true,
  secure: config.NODE_ENV === 'production',
  sameSite: 'Lax' as const,
  path: '/',
};
const set = (c: Context, name: string, value: string, maxAge: number) =>
  setCookie(c, name, value, { ...cookieOptions, maxAge });

async function read<T extends z.ZodType>(c: Context, schema: T): Promise<z.infer<T>> {
  const result = schema.safeParse(await c.req.json().catch(() => null));
  if (!result.success) fail('Перевірте введені дані.');
  return result.data;
}

async function lockUser(tx: Transaction, id: string) {
  const [user] = await tx.select().from(users).where(eq(users.id, id)).for('update');
  if (!user) fail('Користувача не знайдено.', 404);
  return user;
}

function requireActive(user: User) {
  if (user.blocked) fail('Обліковий запис заблокований.', 403);
  if (!user.activatedAt) fail('Спочатку підтвердьте електронну пошту.', 403);
  if (user.lockedUntil && user.lockedUntil > new Date()) fail('Спробуйте через 15 хвилин.', 429);
}

async function log(
  tx: Database | Transaction,
  c: Context<Env>,
  user: User | string,
  event: string,
  success: boolean,
) {
  await tx.insert(loginLogs).values({
    email: typeof user === 'string' ? user : user.email,
    userId: typeof user === 'string' ? undefined : user.id,
    ip: c.get('ip'),
    event,
    success,
  });
}

async function createSession(tx: Transaction, user: User) {
  const token = randomToken();
  await tx.insert(sessions).values({
    hash: digest(token),
    userId: user.id,
    expiresAt: expiresIn(24 * 60 * minute),
  });
  return token;
}

async function revokeAccess(tx: Transaction, userId: string) {
  await tx.delete(sessions).where(eq(sessions.userId, userId));
  await tx.delete(tokens).where(eq(tokens.userId, userId));
}

async function throttle(key: string, limit: number, duration: number, executor: Database | Transaction = db) {
  const now = new Date();
  const [rate] = await executor
    .insert(rateLimits)
    .values({ key, resetsAt: expiresIn(duration) })
    .onConflictDoUpdate({
      target: rateLimits.key,
      set: {
        count: sql`case when ${rateLimits.resetsAt} <= ${now} then 1 else ${rateLimits.count} + 1 end`,
        resetsAt: sql`case when ${rateLimits.resetsAt} <= ${now} then ${expiresIn(duration)} else ${rateLimits.resetsAt} end`,
      },
    })
    .returning();
  if (rate.count > limit) fail('Забагато запитів. Спробуйте пізніше.', 429);
}

async function sendLink(tx: Transaction, user: User, purpose: 'activate' | 'reset') {
  const token = randomToken();
  const lifetime = purpose === 'activate' ? 24 * 60 * minute : 30 * minute;
  await tx.delete(tokens).where(and(eq(tokens.userId, user.id), eq(tokens.purpose, purpose)));
  await tx.insert(tokens).values({
    userId: user.id,
    purpose,
    hash: digest(token),
    expiresAt: expiresIn(lifetime),
  });
  const title = purpose === 'activate' ? 'Підтвердження електронної пошти' : 'Відновлення пароля';
  await sendMail(
    user.email,
    `lab6 — ${title}`,
    `${title}\n\n${config.APP_ORIGIN}/${purpose}#token=${token}\n\nПосилання одноразове. Термін дії: ${purpose === 'activate' ? '24 години' : '30 хвилин'}.`,
  );
}

async function requestLink(email: string, purpose: 'activate' | 'reset') {
  await throttle(`${purpose}:${digest(email)}`, 3, 60 * minute);
  await db.transaction(async (tx) => {
    const [user] = await tx.select().from(users).where(eq(users.email, email)).for('update');
    if (!user || user.blocked) return;
    const eligible = purpose === 'activate' ? !user.activatedAt : !!user.activatedAt;
    if (eligible) await sendLink(tx, user, purpose);
  });
}

async function sendCode(tx: Transaction, user: User, purpose: string) {
  await throttle(`otp:${user.id}:${purpose}`, 3, 15 * minute, tx);
  await tx.delete(tokens).where(and(eq(tokens.userId, user.id), eq(tokens.purpose, purpose)));
  const id = crypto.randomUUID();
  const code = generateOtp();
  await tx.insert(tokens).values({
    id,
    userId: user.id,
    purpose,
    hash: otpDigest(id, code, config.TOKEN_PEPPER),
    expiresAt: expiresIn(5 * minute),
  });
  const action = purpose === 'login' ? 'вхід' : purpose === 'enable2fa' ? 'увімкнення 2FA' : 'вимкнення 2FA';
  await sendMail(
    user.email,
    'lab6 — код підтвердження',
    `Ваш код: ${code}\n\nПризначення: ${action}. Код діє 5 хвилин.`,
  );
  return id;
}

async function verifyCode(tx: Transaction, userId: string, id: string, code: string, purpose: string) {
  const [token] = await tx
    .select()
    .from(tokens)
    .where(and(eq(tokens.id, id), eq(tokens.userId, userId), eq(tokens.purpose, purpose)))
    .for('update');
  if (!token || token.expiresAt <= new Date() || token.attempts >= 5) return false;
  if (token.hash !== otpDigest(id, code, config.TOKEN_PEPPER)) {
    await tx
      .update(tokens)
      .set({ attempts: token.attempts + 1 })
      .where(eq(tokens.id, id));
    return false;
  }
  await tx.delete(tokens).where(eq(tokens.id, id));
  return true;
}

async function beginLogin(
  tx: Transaction,
  c: Context<Env>,
  user: User,
  method: 'password' | 'google',
): Promise<LoginResult> {
  const event = user.twoFactor ? `${method}_two_factor_required` : `${method}_login`;
  const token = user.twoFactor ? await sendCode(tx, user, 'login') : await createSession(tx, user);
  await log(tx, c, user, event, !user.twoFactor);
  return { twoFactor: user.twoFactor, token };
}

// Cookies are set only after the database transaction commits.
function loginCookies(c: Context, result: LoginResult) {
  if (result.twoFactor) set(c, 'challenge', result.token, 300);
  else {
    set(c, 'session', result.token, 24 * 60 * 60);
    deleteCookie(c, 'challenge', cookieOptions);
  }
}

const authenticated = async (c: Context<Env>, next: () => Promise<void>) => {
  const token = getCookie(c, 'session');
  if (!token) fail('Увійдіть у систему.', 401);
  const hash = digest(token);
  const [row] = await db
    .select({ user: users })
    .from(sessions)
    .innerJoin(users, eq(sessions.userId, users.id))
    .where(and(eq(sessions.hash, hash), gt(sessions.expiresAt, new Date())));
  if (!row || row.user.blocked || !row.user.activatedAt) {
    deleteCookie(c, 'session', cookieOptions);
    fail('Сесія завершена. Увійдіть повторно.', 401);
  }
  c.set('user', row.user);
  c.set('sessionHash', hash);
  await next();
};

export type { Env };
export {
  config,
  db,
  pool,
  minute,
  expiresIn,
  emailSchema,
  credentials,
  codeSchema,
  tokenSchema,
  emailMessage,
  fail,
  publicUser,
  cookieOptions,
  set,
  read,
  lockUser,
  requireActive,
  log,
  createSession,
  revokeAccess,
  throttle,
  sendLink,
  requestLink,
  sendCode,
  verifyCode,
  beginLogin,
  loginCookies,
  authenticated,
};
