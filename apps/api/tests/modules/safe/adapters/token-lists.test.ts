import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fetchSafeAddresses } from '../../../../src/modules/safe/adapters/token-lists.js';

const originalFetch = globalThis.fetch;

beforeEach(() => {
	vi.stubGlobal('fetch', vi.fn());
});

afterEach(() => {
	globalThis.fetch = originalFetch;
});

describe('Token Lists adapter', () => {
	it('parses Uniswap token list for mainnet tokens', async () => {
		const mockResponse = {
			tokens: [
				{ chainId: 1, address: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48', name: 'USD Coin', symbol: 'USDC' },
				{ chainId: 137, address: '0x2791bca1f2de4661ed88a30c99a7a9449aa84174', name: 'USD Coin (PoS)', symbol: 'USDC' },
				{ chainId: 1, address: '0xdac17f958d2ee523a2206206994597c13d831ec7', name: 'Tether USD', symbol: 'USDT' },
			],
		};

		vi.mocked(fetch).mockResolvedValue(
			new Response(JSON.stringify(mockResponse), { status: 200 }),
		);

		const result = await fetchSafeAddresses();

		expect(result.source).toBe('uniswap-token-list');
		expect(result.entries).toHaveLength(2);
		expect(result.entries[0].category).toBe('TOKEN');
		expect(result.entries[0].name).toBe('USD Coin (USDC)');
	});

	it('throws on non-200 response', async () => {
		vi.mocked(fetch).mockResolvedValue(new Response('Error', { status: 404 }));
		await expect(fetchSafeAddresses()).rejects.toThrow('Uniswap token list fetch failed');
	});
});
