import { desc, eq, sql } from 'drizzle-orm';
import { Hono } from 'hono';
import { db } from '../db/index.js';
import { domains, syncLogs, threats } from '../db/schema.js';

export const syncRoutes = new Hono();

syncRoutes.get('/summary', async (c) => {
	const logs = await db
		.select()
		.from(syncLogs)
		.where(eq(syncLogs.status, 'SUCCESS'))
		.orderBy(desc(syncLogs.syncedAt));

	const sourcesObj: Record<string, { lastSync: string; status: string; recordsAdded: number }> = {};

	for (const log of logs) {
		if (!sourcesObj[log.source]) {
			sourcesObj[log.source] = {
				lastSync: log.syncedAt.toISOString(),
				status: log.status,
				recordsAdded: log.recordsAdded,
			};
		}
	}

	const [threatResult] = await db.select({ count: sql<number>`count(*)` }).from(threats);
	const [domainResult] = await db.select({ count: sql<number>`count(*)` }).from(domains);

	const lastSyncLog = logs[0] ?? null;

	return c.json({
		lastSync: lastSyncLog?.syncedAt.toISOString() ?? null,
		threatCount: Number(threatResult?.count ?? 0),
		domainCount: Number(domainResult?.count ?? 0),
		sources: sourcesObj,
	});
});
