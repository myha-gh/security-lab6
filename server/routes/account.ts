import { Hono } from 'hono';
import { deleteCookie } from 'hono/cookie';
import { eq } from 'drizzle-orm';
import { sessions } from '../db/schema';
import { db, type Env, publicUser, cookieOptions, authenticated } from '../helpers';

const router = new Hono<Env>();
router.use('*', authenticated);

router.get('/me', (c) => c.json({ user: publicUser(c.get('user')) }));
router.post('/logout', async (c) => {
  await db.delete(sessions).where(eq(sessions.hash, c.get('sessionHash')));
  deleteCookie(c, 'session', cookieOptions);
  deleteCookie(c, 'challenge', cookieOptions);
  return c.json({ ok: true });
});

export default router;
