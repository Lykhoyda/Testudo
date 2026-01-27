import { db } from '../../db/index.js';
import { syncLogs } from '../../db/schema.js';
import * as ethPhishingDetect from './adapters/eth-phishing-detect.js';
import * as scamSniffer from './adapters/scam-sniffer.js';
import { upsertAddresses, upsertDomains } from './aggregator.js';

export async function runSync(): Promise<void> {
	console.log('[Sync] Starting batch sync...');

	// ScamSniffer addresses
	await syncSource('scam-sniffer-addresses', async () => {
		const result = await scamSniffer.fetchAddresses();
		return upsertAddresses(result.entries, result.source);
	});

	// ScamSniffer domains
	await syncSource('scam-sniffer-domains', async () => {
		const result = await scamSniffer.fetchDomains();
		return upsertDomains(result.entries, result.source);
	});

	// eth-phishing-detect domains
	await syncSource('eth-phishing-detect', async () => {
		const result = await ethPhishingDetect.fetchDomains();
		return upsertDomains(result.entries, result.source);
	});

	console.log('[Sync] Batch sync complete');
}

async function syncSource(
	sourceName: string,
	operation: () => Promise<{ added: number; updated: number }>,
): Promise<void> {
	const startTime = Date.now();

	try {
		const { added, updated } = await operation();
		const durationMs = Date.now() - startTime;

		await db.insert(syncLogs).values({
			source: sourceName,
			status: 'SUCCESS',
			recordsAdded: added,
			recordsUpdated: updated,
			durationMs,
		});

		console.log(`[Sync] ${sourceName}: +${added} added, ~${updated} updated (${durationMs}ms)`);
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

		console.error(`[Sync] ${sourceName} failed (${durationMs}ms):`, errorMessage);
	}
}

export async function runSyncSafe(): Promise<void> {
	try {
		await runSync();
	} catch (error) {
		console.error('[Sync] Unhandled error in sync:', error);
	}
}

// Allow manual trigger: tsx src/modules/threats/orchestrator.ts
if (process.argv[1]?.endsWith('orchestrator.ts') || process.argv[1]?.endsWith('orchestrator.js')) {
	runSync()
		.then(() => process.exit(0))
		.catch((err) => {
			console.error(err);
			process.exit(1);
		});
}
