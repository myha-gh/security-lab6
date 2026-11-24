import { Hono } from 'hono';
import { deleteCookie } from 'hono/cookie';
import { and, eq, gt } from 'drizzle-orm';
import { z } from 'zod';
import { users, tokens } from '../db/schema';
import { digest, hashPassword, verifyPassword, passwordError } from '../security';
import {
  db,
  type Env,
  minute,
  expiresIn,
  credentials,
  emailSchema,
  tokenSchema,
  emailMessage,
  fail,
  read,
  throttle,
  sendLink,
  requestLink,
  lockUser,
  log,
  beginLogin,
  loginCookies,
  revokeAccess,
  cookieOptions,
} from '../helpers';

const router = new Hono<Env>();

// Registration and email activation.
router.post('/register', async (c) => {
  const { email, password } = await read(c, credentials);
  const error = passwordError(password);
  if (error) fail(error);
  await throttle(`register:${digest(email)}`, 3, 60 * minute);
  const passwordHash = await hashPassword(password);
  const [user] = await db.insert(users).values({ email, passwordHash }).onConflictDoNothing().returning();
  if (user) await db.transaction((tx) => sendLink(tx, user, 'activate'));
  return c.json(emailMessage, 201);
});
router.post('/resend-activation', async (c) => {
  const { email } = await read(c, z.object({ email: emailSchema }));
  await requestLink(email, 'activate');
  return c.json(emailMessage);
});
router.post('/activate', async (c) => {
  const { token } = await read(c, z.object({ token: tokenSchema }));
  const activated = await db.transaction(async (tx) => {
    const [saved] = await tx
      .delete(tokens)
      .where(
        and(eq(tokens.hash, digest(token)), eq(tokens.purpose, 'activate'), gt(tokens.expiresAt, new Date())),
      )
      .returning();
    if (!saved) return false;
    await tx.update(users).set({ activatedAt: new Date() }).where(eq(users.id, saved.userId));
    return true;
  });
  if (!activated) fail('Посилання недійсне або термін дії минув.');
  return c.json({ message: 'Пошту підтверджено. Тепер можна увійти.' });
});

// Password login and the second step of login.
router.post('/login', async (c) => {
  const { email, password } = await read(c, credentials);
  const [found] = await db.select().from(users).where(eq(users.email, email));
  const valid = await verifyPassword(password, found?.passwordHash ?? null);
  const result = await db.transaction(async (tx) => {
    if (!found) {
      await log(tx, c, email, 'password_failed', false);
      return { error: 'Невірна пошта або пароль.', status: 401 as const };
    }
    const user = await lockUser(tx, found.id);
    if (user.blocked || (user.lockedUntil && user.lockedUntil > new Date())) {
      await log(tx, c, user, 'login_blocked', false);
      return {
        error: 'Вхід тимчасово або адміністративно заблоковано.',
        status: 403 as const,
      };
    }
    if (!valid || user.passwordHash !== found.passwordHash) {
      const attempts = (user.lockedUntil ? 0 : user.failedAttempts) + 1;
      await tx
        .update(users)
        .set({
          failedAttempts: attempts,
          lockedUntil: attempts >= 5 ? expiresIn(15 * minute) : null,
        })
        .where(eq(users.id, user.id));
      await log(tx, c, user, attempts >= 5 ? 'password_lockout' : 'password_failed', false);
      return { error: 'Невірна пошта або пароль.', status: 401 as const };
    }
    if (!user.activatedAt) {
      await log(tx, c, user, 'unverified_login', false);
      return { error: 'Спочатку підтвердьте пошту.', status: 403 as const };
    }
    await tx.update(users).set({ failedAttempts: 0, lockedUntil: null }).where(eq(users.id, user.id));
    return beginLogin(tx, c, user, 'password');
  });
  // Failed attempts must commit before returning an error.
  if ('error' in result) fail(result.error, result.status);
  loginCookies(c, result);
  return c.json(result.twoFactor ? { twoFactorRequired: true } : { ok: true });
});
// Password recovery.
router.post('/forgot-password', async (c) => {
  const { email } = await read(c, z.object({ email: emailSchema }));
  await requestLink(email, 'reset');
  return c.json(emailMessage);
});
router.post('/reset-password', async (c) => {
  const { token, password } = await read(c, z.object({ token: tokenSchema, password: z.string().max(128) }));
  const error = passwordError(password);
  if (error) fail(error);
  const passwordHash = await hashPassword(password);
  const [pending] = await db
    .select()
    .from(tokens)
    .where(and(eq(tokens.hash, digest(token)), eq(tokens.purpose, 'reset')));
  if (!pending) fail('Посилання недійсне або термін дії минув.');
  const changed = await db.transaction(async (tx) => {
    const user = await lockUser(tx, pending.userId);
    if (user.blocked) return false;
    const [saved] = await tx
      .delete(tokens)
      .where(and(eq(tokens.id, pending.id), gt(tokens.expiresAt, new Date())))
      .returning();
    if (!saved) return false;
    await tx
      .update(users)
      .set({ passwordHash, failedAttempts: 0, lockedUntil: null })
      .where(eq(users.id, user.id));
    await revokeAccess(tx, user.id);
    await log(tx, c, user, 'password_reset', true);
    return true;
  });
  if (!changed) fail('Посилання недійсне або термін дії минув.');
  deleteCookie(c, 'session', cookieOptions);
  return c.json({ message: 'Пароль змінено. Увійдіть з новим паролем.' });
});

export default router;
