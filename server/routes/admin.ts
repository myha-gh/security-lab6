import { Hono } from 'hono';
import { eq, desc } from 'drizzle-orm';
import { z } from 'zod';
import { users, loginLogs } from '../db/schema';
import { db, type Env, publicUser, fail, read, lockUser, revokeAccess, log, authenticated } from '../helpers';

const router = new Hono<Env>();
router.use('*', authenticated);
router.use('*', async (c, next) => {
  if (c.get('user').role !== 'admin') fail('Недостатньо прав.', 403);
  await next();
});

// Admin users and login history.
router.get('/users', async (c) => {
  const rows = await db.select().from(users).orderBy(desc(users.createdAt));
  return c.json({
    users: rows.map((user) => ({
      ...publicUser(user),
      blocked: user.blocked,
      failedAttempts: user.failedAttempts,
      lockedUntil: user.lockedUntil,
    })),
  });
});
router.get('/logs', async (c) => {
  const logs = await db.select().from(loginLogs).orderBy(desc(loginLogs.createdAt));
  return c.json({ logs });
});
router.post('/users/:id/status', async (c) => {
  const id = c.req.param('id');
  if (!z.string().uuid().safeParse(id).success) fail('Невірний ідентифікатор.');
  const { blocked } = await read(c, z.object({ blocked: z.boolean() }));
  if (id === c.get('user').id) fail('Не можна заблокувати власний акаунт.');
  await db.transaction(async (tx) => {
    const user = await lockUser(tx, id);
    await tx.update(users).set({ blocked, failedAttempts: 0, lockedUntil: null }).where(eq(users.id, id));
    await revokeAccess(tx, id);
    await log(tx, c, user, `${blocked ? 'admin_block' : 'admin_unblock'}:${c.get('user').id}`, true);
  });
  return c.json({ ok: true });
});

export default router;
