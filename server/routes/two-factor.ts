import { Hono } from 'hono';
import { getCookie } from 'hono/cookie';
import { and, eq } from 'drizzle-orm';
import { z } from 'zod';
import { users, tokens } from '../db/schema';
import {
  db,
  type Env,
  minute,
  codeSchema,
  fail,
  read,
  lockUser,
  requireActive,
  verifyCode,
  log,
  createSession,
  loginCookies,
  throttle,
  sendCode,
  revokeAccess,
  authenticated,
} from '../helpers';

const router = new Hono<Env>();
router.use('/account/2fa/*', authenticated);

router.post('/auth/2fa/verify', async (c) => {
  const { code } = await read(c, z.object({ code: codeSchema }));
  const id = getCookie(c, 'challenge');
  if (!id || !z.string().uuid().safeParse(id).success) fail('Увійдіть повторно.', 401);
  const [pending] = await db
    .select()
    .from(tokens)
    .where(and(eq(tokens.id, id), eq(tokens.purpose, 'login')));
  if (!pending) fail('Увійдіть повторно.', 401);
  const token = await db.transaction(async (tx) => {
    const user = await lockUser(tx, pending.userId);
    requireActive(user);
    const valid = await verifyCode(tx, user.id, id, code, 'login');
    await log(tx, c, user, valid ? 'two_factor_login' : 'two_factor_failed', valid);
    return valid ? createSession(tx, user) : null;
  });
  if (!token) fail('Код невірний, використаний або прострочений.', 401);
  loginCookies(c, { token, twoFactor: false });
  return c.json({ ok: true });
});

router.post('/account/2fa/request', async (c) => {
  const { enable } = await read(c, z.object({ enable: z.boolean() }));
  await throttle(`2fa-settings:${c.get('user').id}`, 3, 15 * minute);
  const id = await db.transaction(async (tx) => {
    const user = await lockUser(tx, c.get('user').id);
    requireActive(user);
    if (user.twoFactor === enable) fail('Цей стан 2FA вже встановлений.');
    return sendCode(tx, user, enable ? 'enable2fa' : 'disable2fa');
  });
  return c.json({
    challengeId: id,
    message: 'Код підтвердження надіслано на пошту.',
  });
});
router.post('/account/2fa/confirm', async (c) => {
  const { enable, challengeId, code } = await read(
    c,
    z.object({
      enable: z.boolean(),
      challengeId: z.string().uuid(),
      code: codeSchema,
    }),
  );
  const token = await db.transaction(async (tx) => {
    const user = await lockUser(tx, c.get('user').id);
    requireActive(user);
    if (!(await verifyCode(tx, user.id, challengeId, code, enable ? 'enable2fa' : 'disable2fa'))) return null;
    await tx.update(users).set({ twoFactor: enable }).where(eq(users.id, user.id));
    await revokeAccess(tx, user.id);
    await log(tx, c, user, enable ? 'two_factor_enabled' : 'two_factor_disabled', true);
    return createSession(tx, user);
  });
  if (!token) fail('Код невірний, використаний або прострочений.');
  loginCookies(c, { token, twoFactor: false });
  return c.json({
    message: enable ? 'Двофакторний захист увімкнено.' : 'Двофакторний захист вимкнено.',
  });
});

export default router;
