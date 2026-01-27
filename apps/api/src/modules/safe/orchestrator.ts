import { sql } from 'drizzle-orm';
import { db } from '../../db/index.js';
import { safeAddresses, syncLogs } from '../../db/schema.js';
import * as defillama from './adapters/defillama.js';
import * as eip7702Delegates from './adapters/eip7702-delegates.js';
import * as l2Bridges from './adapters/l2-bridges.js';
import * as manualCuration from './adapters/manual-curation.js';
import * as safeContracts from './adapters/safe-contracts.js';
import * as stablecoins from './adapters/stablecoins.js';
import * as tokenLists from './adapters/token-lists.js';
import { removeStaleEntries, upsertSafeAddresses } from './aggregator.js';

const DROP_THRESHOLD = 0.1;

export async function runSafeSync(): Promise<void> {
	console.log('[SafeSync] Starting safe address sync...');

	const [countResult] = await db
		.select({ count: sql<number>`count(*)` })
		.from(safeAddresses);
	const previousCount = Number(countResult?.count ?? 0);

	await syncSafeSource('safe-stablecoins', () => stablecoins.fetchSafeAddresses());
	await syncSafeSource('safe-contracts', () => safeContracts.fetchSafeAddresses());
	await syncSafeSource('safe-l2-bridges', () => l2Bridges.fetchSafeAddresses());
	await syncSafeSource('safe-eip7702-delegates', () => eip7702Delegates.fetchSafeAddresses());
	await syncSafeSource('safe-manual-curation', () => manualCuration.fetchSafeAddresses());
	await syncSafeSource('safe-token-lists', () => tokenLists.fetchSafeAddresses());
	await syncSafeSource('safe-defillama', () => defillama.fetchSafeAddresses());

	if (previousCount > 0) {
		const [newCountResult] = await db
			.select({ count: sql<number>`count(*)` })
			.from(safeAddresses);
		const newCount = Number(newCountResult?.count ?? 0);
		const dropRatio = (previousCount - newCount) / previousCount;

		if (dropRatio > DROP_THRESHOLD) {
			throw new Error(
				`[SafeSync] Sanity check failed: count dropped from ${previousCount} to ${newCount} (${(dropRatio * 100).toFixed(1)}%). Aborting.`,
			);
		}
	}

	console.log('[SafeSync] Safe address sync complete');
}

async function syncSafeSource(
	sourceName: string,
	fetchFn: () => Promise<{ source: string; entries: { address: string; category: string; chainId?: number }[] }>,
): Promise<void> {
	const startTime = Date.now();

	try {
		const result = await fetchFn();
		const { added, updated } = await upsertSafeAddresses(result.entries, result.source);
		const { removed, orphaned } = await removeStaleEntries(
			result.entries.map((e) => ({ address: e.address, chainId: e.chainId ?? 1 })),
			result.source,
		);
		const durationMs = Date.now() - startTime;

		await db.insert(syncLogs).values({
			source: sourceName,
			status: 'SUCCESS',
			recordsAdded: added,
			recordsUpdated: updated,
			durationMs,
		});

		console.log(`[SafeSync] ${sourceName}: +${added} added, ~${updated} updated, -${removed} stale, -${orphaned} orphaned (${durationMs}ms)`);
	} catch (error) {
		const durationMs = Date.now() - startTime;
		const errorMessage = error instanceof Error ? error.message : String(error);

		await db.insert(syncLogs).values({
			source: sourceName,
			status: 'FAILED',
			recordsAdded: 0,
			recordsUpdated: 0,
			errorMessage,
			durationMs,
		});

		console.error(`[SafeSync] ${sourceName} failed (${durationMs}ms):`, errorMessage);
	}
}

export async function runSafeSyncSafe(): Promise<void> {
	try {
		await runSafeSync();
	} catch (error) {
		console.error('[SafeSync] Unhandled error:', error);
	}
}
