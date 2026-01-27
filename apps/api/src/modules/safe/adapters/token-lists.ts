import type { AdapterResult, RawSafeAddressEntry } from './types.js';

const UNISWAP_TOKEN_LIST_URL = 'https://tokens.uniswap.org';
const SOURCE_NAME = 'uniswap-token-list';
const ADDRESS_REGEX = /^0x[a-fA-F0-9]{40}$/;

interface TokenListToken {
	chainId: number;
	address: string;
	name: string;
	symbol: string;
}

interface TokenListResponse {
	tokens: TokenListToken[];
}

export async function fetchSafeAddresses(): Promise<AdapterResult<RawSafeAddressEntry>> {
	const response = await fetch(UNISWAP_TOKEN_LIST_URL);

	if (!response.ok) {
		throw new Error(`Uniswap token list fetch failed: ${response.status} ${response.statusText}`);
	}

	const data = (await response.json()) as TokenListResponse;

	if (!Array.isArray(data.tokens)) {
		throw new Error('Token list response missing tokens array');
	}

	const entries: RawSafeAddressEntry[] = data.tokens
		.filter((t) => ADDRESS_REGEX.test(t.address) && t.chainId === 1)
		.map((t) => ({
			address: t.address.toLowerCase(),
			chainId: t.chainId,
			name: `${t.name} (${t.symbol})`,
			category: 'TOKEN',
		}));

	return { source: SOURCE_NAME, entries, fetchedAt: new Date() };
}
