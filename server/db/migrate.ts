import 'dotenv/config';
import { migrate } from 'drizzle-orm/node-postgres/migrator';
import { connectDatabase } from './index';
if (!process.env.DATABASE_URL) throw new Error('Set DATABASE_URL in .env');
const { db, pool } = connectDatabase(process.env.DATABASE_URL);
try {
  await migrate(db, { migrationsFolder: './drizzle' });
  console.log('Міграції застосовано.');
} finally {
  await pool.end();
}
