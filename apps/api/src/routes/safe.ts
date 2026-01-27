import { timingSafeEqual } from 'node:crypto';
import { eq } from 'drizzle-orm';
import { Hono } from 'hono';
import { db } from '../db/index.js';
import { revocations, safeAddresses } from '../db/schema.js';
import { buildFilter, buildRevocations, getManifest } from '../modules/safe/filter-service.js';
import { runSafeSync } from '../modules/safe/orchestrator.js';
import { isValidAddress, normalizeAddress } from '../utils/validation.js';

export const safeRoutes = new Hono();

function requireAdmin(secret: string | undefined): boolean {
	const expected = process.env.ADMIN_API_SECRET;
	if (!expected || !secret || secret.length !== expected.length) return false;
	return timingSafeEqual(Buffer.from(secret), Buffer.from(expected));
}

safeRoutes.get('/address/:address', async (c) => {
	const raw = c.req.param('address');

	if (!isValidAddress(raw)) {
		return c.json({ error: 'Invalid address format', code: 'INVALID_ADDRESS' }, 400);
	}

	const address = normalizeAddress(raw);

	const results = await db
		.select({
			address: safeAddresses.address,
			chainId: safeAddresses.chainId,
			name: safeAddresses.name,
			category: safeAddresses.category,
			isDelegationSafe: safeAddresses.isDelegationSafe,
			confidence: safeAddresses.confidence,
			sources: safeAddresses.sources,
			firstSeen: safeAddresses.firstSeen,
		})
		.from(safeAddresses)
		.where(eq(safeAddresses.address, address))
		.limit(1);

	if (results.length === 0) {
		return c.json({ isSafe: false, address });
	}

	const entry = results[0];
	return c.json({
		isSafe: true,
		address: entry.address,
		chainId: entry.chainId,
		name: entry.name,
		category: entry.category,
		isDelegationSafe: entry.isDelegationSafe,
		confidence: Number(entry.confidence),
		sources: entry.sources,
		firstSeen: entry.firstSeen.toISOString(),
	});
});

safeRoutes.post('/revocations', async (c) => {
	const secret = c.req.header('x-admin-secret');
	if (!requireAdmin(secret)) {
		return c.json({ error: 'Unauthorized', code: 'UNAUTHORIZED' }, 401);
	}

	const body = await c.req.json<{ address: string; chainId?: number; reason: string }>();

	if (!body.address || !isValidAddress(body.address) || !body.reason) {
		return c.json({ error: 'Invalid request body', code: 'INVALID_BODY' }, 400);
	}

	const [result] = await db
		.insert(revocations)
		.values({
			address: normalizeAddress(body.address),
			chainId: body.chainId ?? 1,
			reason: body.reason,
			revokedBy: 'admin',
		})
		.returning({ id: revocations.id });

	return c.json({ success: true, id: result.id });
});

safeRoutes.post('/build', async (c) => {
	const secret = c.req.header('x-admin-secret');
	if (!requireAdmin(secret)) {
		return c.json({ error: 'Unauthorized', code: 'UNAUTHORIZED' }, 401);
	}

	await runSafeSync();
	const filterResult = await buildFilter();
	const revocationResult = await buildRevocations();

	return c.json({
		filter: filterResult,
		revocations: revocationResult,
	});
});

safeRoutes.get('/manifest', async (c) => {
	const manifest = await getManifest();

	if (!manifest) {
		return c.json({ error: 'No builds found', code: 'NO_BUILDS' }, 404);
	}

	return c.json(manifest);
});
