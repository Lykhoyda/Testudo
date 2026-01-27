import type { AdapterResult, RawSafeAddressEntry } from './types.js';

const PROTOCOLS_URL = 'https://api.llama.fi/protocols';
const SOURCE_NAME = 'defillama';
const MIN_TVL = 1_000_000;
const ADDRESS_REGEX = /^0x[a-fA-F0-9]{40}$/;

const CHAIN_ID_MAP: Record<string, number> = {
	Ethereum: 1,
	Arbitrum: 42161,
	Optimism: 10,
	Base: 8453,
	Polygon: 137,
	Avalanche: 43114,
	BSC: 56,
	Gnosis: 100,
	Fantom: 250,
	zkSync: 324,
	Linea: 59144,
	Scroll: 534352,
};

interface DefiLlamaProtocol {
	name: string;
	address: string | null;
	chain: string;
	tvl: number;
}

export async function fetchSafeAddresses(): Promise<AdapterResult<RawSafeAddressEntry>> {
	const response = await fetch(PROTOCOLS_URL);

	if (!response.ok) {
		throw new Error(`DefiLlama fetch failed: ${response.status} ${response.statusText}`);
	}

	const raw: unknown = await response.json();

	if (!Array.isArray(raw)) {
		throw new Error('DefiLlama response is not an array');
	}

	const entries: RawSafeAddressEntry[] = (raw as DefiLlamaProtocol[])
		.filter((p) => {
			if (!p.address || typeof p.address !== 'string' || !ADDRESS_REGEX.test(p.address)) return false;
			if (typeof p.tvl !== 'number' || p.tvl < MIN_TVL) return false;
			if (!CHAIN_ID_MAP[p.chain]) {
				console.warn(`[DefiLlama] Unknown chain: ${p.chain} (protocol: ${p.name}). Skipping.`);
				return false;
			}
			return true;
		})
		.map((p) => ({
			address: p.address!.toLowerCase(),
			chainId: CHAIN_ID_MAP[p.chain],
			category: 'DEFI_PROTOCOL',
			name: p.name,
		}));

	return { source: SOURCE_NAME, entries, fetchedAt: new Date() };
}
