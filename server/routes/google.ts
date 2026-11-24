import { Hono } from 'hono';
import { getCookie, deleteCookie } from 'hono/cookie';
import { eq } from 'drizzle-orm';
import { OAuth2Client, CodeChallengeMethod } from 'google-auth-library';
import { users } from '../db/schema';
import { randomToken } from '../security';
import {
  config,
  db,
  type Env,
  set,
  cookieOptions,
  emailSchema,
  log,
  requireActive,
  beginLogin,
  loginCookies,
} from '../helpers';

const router = new Hono<Env>();
const google = new OAuth2Client(
  config.GOOGLE_CLIENT_ID,
  config.GOOGLE_CLIENT_SECRET,
  config.GOOGLE_REDIRECT_URI,
);

// Google OpenID Connect.
router.get('/', async (c) => {
  const state = randomToken();
  const nonce = randomToken();
  const { codeVerifier, codeChallenge } = await google.generateCodeVerifierAsync();
  set(c, 'oauth', Buffer.from(JSON.stringify({ state, nonce, codeVerifier })).toString('base64url'), 600);
  return c.redirect(
    google.generateAuthUrl({
      scope: ['openid', 'email'],
      state,
      nonce,
      code_challenge: codeChallenge,
      code_challenge_method: CodeChallengeMethod.S256,
      prompt: 'select_account',
    }),
  );
});
router.get('/callback', async (c) => {
  const raw = getCookie(c, 'oauth');
  deleteCookie(c, 'oauth', cookieOptions);
  try {
    if (!raw) throw new Error('Missing state');
    const flow = JSON.parse(Buffer.from(raw, 'base64url').toString());
    const code = c.req.query('code');
    const state = c.req.query('state');
    if (!code || !state || state !== flow.state || c.req.query('error')) throw new Error('Invalid state');
    const { tokens: googleTokens } = await google.getToken({
      code,
      codeVerifier: flow.codeVerifier,
      redirect_uri: config.GOOGLE_REDIRECT_URI,
    });
    if (!googleTokens.id_token) throw new Error('Missing ID token');
    const ticket = await google.verifyIdToken({
      idToken: googleTokens.id_token,
      audience: config.GOOGLE_CLIENT_ID,
    });
    const identity = ticket.getPayload();
    if (!identity?.sub || !identity.email || !identity.email_verified || identity.nonce !== flow.nonce)
      throw new Error('Invalid identity');
    const email = emailSchema.parse(identity.email);
    const result = await db.transaction(async (tx) => {
      let [user] = await tx.select().from(users).where(eq(users.googleSub, identity.sub)).for('update');
      if (!user) {
        const [existing] = await tx.select().from(users).where(eq(users.email, email));
        if (existing) {
          await log(tx, c, existing, 'google_email_conflict', false);
          return { error: 'google_conflict' };
        }
        [user] = await tx
          .insert(users)
          .values({ email, googleSub: identity.sub, activatedAt: new Date() })
          .returning();
      }
      if (user.blocked || (user.lockedUntil && user.lockedUntil > new Date())) {
        await log(tx, c, user, 'google_blocked', false);
        return { error: 'blocked' };
      }
      requireActive(user);
      return beginLogin(tx, c, user, 'google');
    });
    if ('error' in result) return c.redirect(`${config.APP_ORIGIN}/?error=${result.error}`);
    loginCookies(c, result);
    return c.redirect(config.APP_ORIGIN + (result.twoFactor ? '/?step=2fa' : '/'));
  } catch {
    await log(db, c, '(google)', 'google_failed', false);
    return c.redirect(`${config.APP_ORIGIN}/?error=google_failed`);
  }
});

export default router;
