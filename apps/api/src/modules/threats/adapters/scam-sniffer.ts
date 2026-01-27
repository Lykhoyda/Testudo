import type { AdapterResult, RawAddressEntry, RawDomainEntry } from './types.js';

const ADDRESS_URL =
	'https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json';
const DOMAINS_URL =
	'https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json';

const ADDRESS_REGEX = /^0x[a-fA-F0-9]{40}$/;
const SOURCE_NAME = 'scam-sniffer';

export async function fetchAddresses(): Promise<AdapterResult<RawAddressEntry>> {
	const response = await fetch(ADDRESS_URL);

	if (!response.ok) {
		throw new Error(
			`ScamSniffer addresses fetch failed: ${response.status} ${response.statusText}`,
		);
	}

	const raw: unknown = await response.json();

	if (!Array.isArray(raw)) {
		throw new Error('ScamSniffer addresses response is not an array');
	}

	const entries: RawAddressEntry[] = raw
		.filter((entry): entry is string => typeof entry === 'string' && ADDRESS_REGEX.test(entry))
		.map((address) => ({
			address: address.toLowerCase(),
			chainId: 1,
			threatType: 'SCAM',
			threatLevel: 'HIGH',
		}));

	return {
		source: SOURCE_NAME,
		entries,
		fetchedAt: new Date(),
	};
}

export async function fetchDomains(): Promise<AdapterResult<RawDomainEntry>> {
	const response = await fetch(DOMAINS_URL);

	if (!response.ok) {
		throw new Error(`ScamSniffer domains fetch failed: ${response.status} ${response.statusText}`);
	}

	const raw: unknown = await response.json();

	if (!Array.isArray(raw)) {
		throw new Error('ScamSniffer domains response is not an array');
	}

	const entries: RawDomainEntry[] = raw
		.filter((entry): entry is string => typeof entry === 'string' && entry.length > 0)
		.map((domain) => ({
			domain: domain.toLowerCase().trim(),
			threatType: 'PHISHING',
		}));

	return {
		source: SOURCE_NAME,
		entries,
		fetchedAt: new Date(),
	};
}
