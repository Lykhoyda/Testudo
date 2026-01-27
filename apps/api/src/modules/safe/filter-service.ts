import { createHash } from 'node:crypto';
import { promisify } from 'node:util';
import { gzip } from 'node:zlib';

const gzipAsync = promisify(gzip);

import { eq, gt, sql } from 'drizzle-orm';
import { db } from '../../db/index.js';
import { revocations, safeAddresses, safeFilterBuilds } from '../../db/schema.js';
import { uploadToR2 } from '../../shared/r2-service.js';

interface SafeFilterEntry {
	c: number;
	a: string;
	n: string | null;
	t: string;
	d: boolean;
}

interface SafeFilterPayload {
	version: string;
	format: string;
	count: number;
	generatedAt: string;
	entries: SafeFilterEntry[];
}

export async function buildFilter(): Promise<{ version: string; url: string; count: number }> {
	const startTime = Date.now();

	const revokedAddrs = await db
		.select({ address: revocations.address, chainId: revocations.chainId })
		.from(revocations)
		.where(eq(revocations.isActive, true));

	const revokedSet = new Set(revokedAddrs.map((r) => `${r.chainId}:${r.address}`));

	const PAGE_SIZE = 10_000;
	const filtered: {
		address: string;
		chainId: number;
		name: string | null;
		category: string;
		isDelegationSafe: boolean;
	}[] = [];
	let lastSeenId = 0;

	while (true) {
		const page = await db
			.select({
				id: safeAddresses.id,
				address: safeAddresses.address,
				chainId: safeAddresses.chainId,
				name: safeAddresses.name,
				category: safeAddresses.category,
				isDelegationSafe: safeAddresses.isDelegationSafe,
			})
			.from(safeAddresses)
			.where(gt(safeAddresses.id, lastSeenId))
			.orderBy(safeAddresses.id)
			.limit(PAGE_SIZE);

		if (page.length === 0) break;

		lastSeenId = page[page.length - 1].id;

		for (const s of page) {
			if (!revokedSet.has(`${s.chainId}:${s.address}`)) {
				filtered.push(s);
			}
		}

		if (page.length < PAGE_SIZE) break;
	}

	const version = new Date().toISOString().replace(/[:.]/g, '-');

	const payload: SafeFilterPayload = {
		version,
		format: 'json-gzip',
		count: filtered.length,
		generatedAt: new Date().toISOString(),
		entries: filtered.map((s) => ({
			c: s.chainId,
			a: s.address,
			n: s.name,
			t: s.category,
			d: s.isDelegationSafe,
		})),
	};

	const jsonStr = JSON.stringify(payload);
	const gzipped = await gzipAsync(Buffer.from(jsonStr));
	const sha256 = createHash('sha256').update(gzipped).digest('hex');
	const r2Key = `safe-filter/${version}.json.gz`;

	const r2Url = await uploadToR2(r2Key, gzipped, 'application/gzip');

	const durationMs = Date.now() - startTime;

	await db.insert(safeFilterBuilds).values({
		version,
		format: 'json-gzip',
		entryCount: filtered.length,
		fileSizeBytes: gzipped.length,
		sha256,
		r2Key,
		r2Url,
		revocationCount: revokedAddrs.length,
		buildDurationMs: durationMs,
	});

	console.log(
		`[SafeFilter] Built filter v${version}: ${filtered.length} entries, ${gzipped.length} bytes (${durationMs}ms)`,
	);

	return { version, url: r2Url, count: filtered.length };
}

export async function buildRevocations(): Promise<{ version: string; url: string; count: number }> {
	const active = await db
		.select({
			address: revocations.address,
			chainId: revocations.chainId,
			reason: revocations.reason,
			createdAt: revocations.createdAt,
		})
		.from(revocations)
		.where(eq(revocations.isActive, true));

	const version = new Date().toISOString().replace(/[:.]/g, '-');
	const payload = {
		version,
		count: active.length,
		generatedAt: new Date().toISOString(),
		entries: active,
	};
	const jsonStr = JSON.stringify(payload);
	const r2Key = `revocations/${version}.json`;

	const r2Url = await uploadToR2(r2Key, jsonStr, 'application/json');

	console.log(`[SafeFilter] Built revocations v${version}: ${active.length} entries`);

	return { version, url: r2Url, count: active.length };
}

export async function getManifest(): Promise<{
	version: string;
	format: string;
	entryCount: number;
	fileSizeBytes: number;
	sha256: string;
	url: string;
	revocationCount: number;
	createdAt: string;
} | null> {
	const [latest] = await db
		.select()
		.from(safeFilterBuilds)
		.orderBy(sql`${safeFilterBuilds.createdAt} DESC`)
		.limit(1);

	if (!latest) return null;

	return {
		version: latest.version,
		format: latest.format,
		entryCount: latest.entryCount,
		fileSizeBytes: latest.fileSizeBytes,
		sha256: latest.sha256,
		url: latest.r2Url,
		revocationCount: latest.revocationCount,
		createdAt: latest.createdAt.toISOString(),
	};
}
