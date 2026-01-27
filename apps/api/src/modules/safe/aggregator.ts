import { inArray, sql } from 'drizzle-orm';
import { db } from '../../db/index.js';
import { safeAddresses } from '../../db/schema.js';
import type { RawSafeAddressEntry } from './adapters/types.js';

const BATCH_SIZE = 500;

export async function removeStaleEntries(
	currentEntries: { address: string; chainId: number }[],
	source: string,
): Promise<{ removed: number; orphaned: number }> {
	const currentSet = new Set(currentEntries.map((e) => `${e.chainId}:${e.address.toLowerCase()}`));

	const dbEntries = await db
		.select({
			id: safeAddresses.id,
			address: safeAddresses.address,
			chainId: safeAddresses.chainId,
			sources: safeAddresses.sources,
		})
		.from(safeAddresses)
		.where(sql`${source} = ANY(${safeAddresses.sources})`);

	const staleIds: number[] = [];
	for (const entry of dbEntries) {
		if (!currentSet.has(`${entry.chainId}:${entry.address}`)) {
			staleIds.push(entry.id);
		}
	}

	if (staleIds.length === 0) {
		return { removed: 0, orphaned: 0 };
	}

	for (let i = 0; i < staleIds.length; i += BATCH_SIZE) {
		const batch = staleIds.slice(i, i + BATCH_SIZE);
		await db
			.update(safeAddresses)
			.set({
				sources: sql`array_remove(${safeAddresses.sources}, ${source})`,
				confidence: sql`GREATEST(0.50, LEAST(1.00, 0.50 + COALESCE(array_length(array_remove(${safeAddresses.sources}, ${source}), 1), 0) * 0.15))::numeric(3,2)`,
				lastUpdated: new Date(),
			})
			.where(inArray(safeAddresses.id, batch));
	}

	const deleteResult = await db
		.delete(safeAddresses)
		.where(
			sql`array_length(${safeAddresses.sources}, 1) IS NULL OR array_length(${safeAddresses.sources}, 1) = 0`,
		)
		.returning({ id: safeAddresses.id });

	return { removed: staleIds.length, orphaned: deleteResult.length };
}

export async function upsertSafeAddresses(
	entries: RawSafeAddressEntry[],
	source: string,
): Promise<{ added: number; updated: number }> {
	let added = 0;
	let updated = 0;

	for (let i = 0; i < entries.length; i += BATCH_SIZE) {
		const batch = entries.slice(i, i + BATCH_SIZE);
		const addresses = batch.map((e) => e.address.toLowerCase());

		const existing = await db
			.select({ address: safeAddresses.address })
			.from(safeAddresses)
			.where(inArray(safeAddresses.address, addresses));

		const existingSet = new Set(existing.map((r) => r.address));

		const values = batch.map((entry) => ({
			address: entry.address.toLowerCase(),
			chainId: entry.chainId ?? 1,
			name: entry.name ?? null,
			category: entry.category,
			isDelegationSafe: entry.isDelegationSafe ?? false,
			confidence: '0.65',
			sources: [source],
			firstSeen: new Date(),
			lastUpdated: new Date(),
		}));

		await db
			.insert(safeAddresses)
			.values(values)
			.onConflictDoUpdate({
				target: [safeAddresses.address, safeAddresses.chainId],
				set: {
					sources: sql`ARRAY(SELECT DISTINCT unnest(array_cat(${safeAddresses.sources}, ARRAY[${source}]::text[])))`,
					confidence: sql`LEAST(1.00, 0.50 + COALESCE(array_length(ARRAY(SELECT DISTINCT unnest(array_cat(${safeAddresses.sources}, ARRAY[${source}]::text[]))), 1), 0) * 0.15)::numeric(3,2)`,
					isDelegationSafe: sql`${safeAddresses.isDelegationSafe} OR EXCLUDED.is_delegation_safe`,
					lastUpdated: new Date(),
				},
			});

		added += addresses.filter((a) => !existingSet.has(a)).length;
		updated += addresses.filter((a) => existingSet.has(a)).length;
	}

	return { added, updated };
}
