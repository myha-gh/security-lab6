import { randomBytes, randomInt, createHash, createHmac, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
const scrypt = (password: string, salt: string) =>
  new Promise<Buffer>((resolve, reject) => {
    scryptCallback(password, salt, 64, { N: 32768, r: 8, p: 3, maxmem: 64 * 1024 * 1024 }, (err, key) =>
      err ? reject(err) : resolve(key),
    );
  });
export const randomToken = () => randomBytes(32).toString('base64url');
export const digest = (value: string) => createHash('sha256').update(value).digest('hex');
export const otpDigest = (id: string, code: string, pepper: string) =>
  createHmac('sha256', pepper).update(`${id}:${code}`).digest('hex');
export const generateOtp = () => randomInt(0, 1_000_000).toString().padStart(6, '0');
export const passwordError = (p: string) =>
  p.length < 8 ||
  p.length > 128 ||
  !/\p{Lu}/u.test(p) ||
  !/\p{Ll}/u.test(p) ||
  !/\d/.test(p) ||
  !/[^\p{L}\p{N}\s]/u.test(p)
    ? 'Пароль: 8–128 символів, великі й малі літери, цифра та спеціальний символ.'
    : null;
export async function hashPassword(password: string) {
  const salt = randomBytes(16).toString('hex');
  const key = await scrypt(password, salt);
  return `scrypt$${salt}$${key.toString('hex')}`;
}
export async function verifyPassword(password: string, stored: string | null) {
  const [algorithm, salt, hex] = (stored ?? '').split('$');
  // Equal-cost work for unknown accounts and Google-only accounts.
  const key = await scrypt(password, salt || '00000000000000000000000000000000');
  const expected = Buffer.from(hex || '00'.repeat(64), 'hex');
  return algorithm === 'scrypt' && key.length === expected.length && timingSafeEqual(key, expected);
}
