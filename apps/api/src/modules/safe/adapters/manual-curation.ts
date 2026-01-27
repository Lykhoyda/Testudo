import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AdapterResult, RawSafeAddressEntry } from './types.js';

const SOURCE_NAME = 'manual-curation';

interface SafeAddressJson {
	address: string;
	chainId?: number;
	name?: string;
	category: string;
	isDelegationSafe?: boolean;
}

export async function fetchSafeAddresses(): Promise<AdapterResult<RawSafeAddressEntry>> {
	const dir = dirname(fileURLToPath(import.meta.url));
	const filePath = join(dir, '../../../data/safe-addresses.json');

	const content = await readFile(filePath, 'utf-8');
	const raw = JSON.parse(content) as SafeAddressJson[];

	const entries: RawSafeAddressEntry[] = raw.map((e) => ({
		address: e.address.toLowerCase(),
		chainId: e.chainId ?? 1,
		name: e.name,
		category: e.category,
		isDelegationSafe: e.isDelegationSafe ?? false,
	}));

	return { source: SOURCE_NAME, entries, fetchedAt: new Date() };
}
