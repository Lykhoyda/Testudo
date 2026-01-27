import { inArray, sql } from 'drizzle-orm';
import { db } from '../../db/index.js';
import { domains, threats } from '../../db/schema.js';
import type { RawAddressEntry, RawDomainEntry } from './adapters/types.js';

const BATCH_SIZE = 500;

export function calculateConfidence(sourceCount: number): string {
	const value = Math.min(1.0, 0.5 + sourceCount * 0.15);
	return value.toFixed(2);
}

export async function upsertAddresses(
	entries: RawAddressEntry[],
	source: string,
): Promise<{ added: number; updated: number }> {
	let added = 0;
	let updated = 0;

	for (let i = 0; i < entries.length; i += BATCH_SIZE) {
		const batch = entries.slice(i, i + BATCH_SIZE);
		const addresses = batch.map((e) => e.address.toLowerCase());

		const existing = await db
			.select({ address: threats.address })
			.from(threats)
			.where(inArray(threats.address, addresses));

		const existingSet = new Set(existing.map((r) => r.address));

		const values = batch.map((entry) => ({
			address: entry.address.toLowerCase(),
			chainId: entry.chainId ?? 1,
			threatType: entry.threatType ?? 'UNKNOWN',
			threatLevel: entry.threatLevel ?? 'HIGH',
			confidence: calculateConfidence(1),
			sources: [source],
			firstSeen: new Date(),
			lastUpdated: new Date(),
		}));

		await db
			.insert(threats)
			.values(values)
			.onConflictDoUpdate({
				target: threats.address,
				set: {
					sources: sql`ARRAY(SELECT DISTINCT unnest(array_cat(${threats.sources}, ARRAY[${source}]::text[])))`,
					confidence: sql`LEAST(1.00, 0.50 + array_length(ARRAY(SELECT DISTINCT unnest(array_cat(${threats.sources}, ARRAY[${source}]::text[]))), 1) * 0.15)::numeric(3,2)`,
					lastUpdated: new Date(),
				},
			});

		added += addresses.length - existingSet.size;
		updated += existingSet.size;
	}

	return { added, updated };
}

export async function upsertDomains(
	entries: RawDomainEntry[],
	source: string,
): Promise<{ added: number; updated: number }> {
	let added = 0;
	let updated = 0;

	for (let i = 0; i < entries.length; i += BATCH_SIZE) {
		const batch = entries.slice(i, i + BATCH_SIZE);
		const domainNames = batch.map((e) => e.domain.toLowerCase().trim());

		const existing = await db
			.select({ domain: domains.domain })
			.from(domains)
			.where(inArray(domains.domain, domainNames));

		const existingSet = new Set(existing.map((r) => r.domain));

		const values = batch.map((entry) => ({
			domain: entry.domain.toLowerCase().trim(),
			threatType: entry.threatType ?? 'PHISHING',
			confidence: calculateConfidence(1),
			sources: [source],
			isFuzzyMatch: entry.isFuzzyMatch ?? false,
			matchedLegitimate: entry.matchedLegitimate ?? null,
			firstSeen: new Date(),
			lastUpdated: new Date(),
		}));

		await db
			.insert(domains)
			.values(values)
			.onConflictDoUpdate({
				target: domains.domain,
				set: {
					sources: sql`ARRAY(SELECT DISTINCT unnest(array_cat(${domains.sources}, ARRAY[${source}]::text[])))`,
					confidence: sql`LEAST(1.00, 0.50 + array_length(ARRAY(SELECT DISTINCT unnest(array_cat(${domains.sources}, ARRAY[${source}]::text[]))), 1) * 0.15)::numeric(3,2)`,
					lastUpdated: new Date(),
				},
			});

		added += domainNames.length - existingSet.size;
		updated += existingSet.size;
	}

	return { added, updated };
}
