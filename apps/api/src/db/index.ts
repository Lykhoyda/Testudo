import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import * as schema from './schema.js';

const databaseUrl = process.env.DATABASE_URL;

if (!databaseUrl) {
	throw new Error('DATABASE_URL environment variable is required');
}

const client = postgres(databaseUrl);
export const db = drizzle(client, { schema });

export async function checkConnection(): Promise<boolean> {
	try {
		await client`SELECT 1`;
		return true;
	} catch (error) {
		console.error('[Testudo API] Database connection check failed:', error);
		return false;
	}
}
