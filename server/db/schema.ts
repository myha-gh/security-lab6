import { sql } from 'drizzle-orm';
import { pgTable, uuid, text, timestamp, boolean, integer, index, check } from 'drizzle-orm/pg-core';
const time = (name: string) => timestamp(name, { withTimezone: true, mode: 'date' });
export const users = pgTable(
  'users',
  {
    id: uuid('id').defaultRandom().primaryKey(),
    email: text('email').notNull().unique(),
    passwordHash: text('password_hash'),
    googleSub: text('google_sub').unique(),
    role: text('role', { enum: ['user', 'admin'] })
      .notNull()
      .default('user'),
    activatedAt: time('activated_at'),
    blocked: boolean('blocked').notNull().default(false),
    twoFactor: boolean('two_factor').notNull().default(false),
    failedAttempts: integer('failed_attempts').notNull().default(0),
    lockedUntil: time('locked_until'),
    createdAt: time('created_at').notNull().defaultNow(),
  },
  (t) => [check('users_role_check', sql`${t.role} in ('user', 'admin')`)],
).enableRLS();
export const tokens = pgTable(
  'tokens',
  {
    id: uuid('id').defaultRandom().primaryKey(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    hash: text('hash').notNull().unique(),
    purpose: text('purpose').notNull(),
    attempts: integer('attempts').notNull().default(0),
    expiresAt: time('expires_at').notNull(),
    createdAt: time('created_at').notNull().defaultNow(),
  },
  (t) => [index('tokens_user_purpose').on(t.userId, t.purpose)],
).enableRLS();
export const sessions = pgTable(
  'sessions',
  {
    hash: text('hash').primaryKey(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    expiresAt: time('expires_at').notNull(),
    createdAt: time('created_at').notNull().defaultNow(),
  },
  (t) => [index('sessions_user').on(t.userId)],
).enableRLS();
export const loginLogs = pgTable(
  'login_logs',
  {
    id: uuid('id').defaultRandom().primaryKey(),
    userId: uuid('user_id').references(() => users.id, { onDelete: 'set null' }),
    email: text('email').notNull(),
    ip: text('ip').notNull(),
    event: text('event').notNull(),
    success: boolean('success').notNull(),
    createdAt: time('created_at').notNull().defaultNow(),
  },
  (t) => [index('logs_time').on(t.createdAt)],
).enableRLS();
export const rateLimits = pgTable('rate_limits', {
  key: text('key').primaryKey(),
  count: integer('count').notNull().default(1),
  resetsAt: time('resets_at').notNull(),
}).enableRLS();
export type User = typeof users.$inferSelect;
