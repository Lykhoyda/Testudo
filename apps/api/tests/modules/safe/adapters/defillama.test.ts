import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fetchSafeAddresses } from '../../../../src/modules/safe/adapters/defillama.js';

const originalFetch = globalThis.fetch;

beforeEach(() => {
	vi.stubGlobal('fetch', vi.fn());
});

afterEach(() => {
	globalThis.fetch = originalFetch;
});

describe('DefiLlama adapter', () => {
	it('filters protocols with TVL >= $1M and valid addresses', async () => {
		const mockProtocols = [
			{ name: 'Aave', address: '0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9', chain: 'Ethereum', tvl: 10_000_000 },
			{ name: 'SmallProtocol', address: '0x1234567890abcdef1234567890abcdef12345678', chain: 'Ethereum', tvl: 500 },
			{ name: 'NoAddress', address: null, chain: 'Ethereum', tvl: 5_000_000 },
			{ name: 'InvalidAddr', address: 'not-an-address', chain: 'Ethereum', tvl: 2_000_000 },
		];

		vi.mocked(fetch).mockResolvedValue(
			new Response(JSON.stringify(mockProtocols), { status: 200 }),
		);

		const result = await fetchSafeAddresses();

		expect(result.source).toBe('defillama');
		expect(result.entries).toHaveLength(1);
		expect(result.entries[0].address).toBe('0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9');
		expect(result.entries[0].category).toBe('DEFI_PROTOCOL');
		expect(result.entries[0].name).toBe('Aave');
	});

	it('maps chain names to chain IDs', async () => {
		const mockProtocols = [
			{ name: 'Aave', address: '0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9', chain: 'Ethereum', tvl: 10_000_000 },
			{ name: 'ArbProtocol', address: '0x1234567890abcdef1234567890abcdef12345678', chain: 'Arbitrum', tvl: 5_000_000 },
			{ name: 'UnknownChain', address: '0xabcdef1234567890abcdef1234567890abcdef12', chain: 'SomeNewChain', tvl: 2_000_000 },
		];

		vi.mocked(fetch).mockResolvedValue(
			new Response(JSON.stringify(mockProtocols), { status: 200 }),
		);

		const result = await fetchSafeAddresses();

		expect(result.entries).toHaveLength(2);
		expect(result.entries[0].chainId).toBe(1);
		expect(result.entries[1].chainId).toBe(42161);
	});

	it('throws on non-200 response', async () => {
		vi.mocked(fetch).mockResolvedValue(new Response('Error', { status: 500 }));
		await expect(fetchSafeAddresses()).rejects.toThrow('DefiLlama fetch failed');
	});

	it('throws if response is not an array', async () => {
		vi.mocked(fetch).mockResolvedValue(
			new Response(JSON.stringify({ data: [] }), { status: 200 }),
		);
		await expect(fetchSafeAddresses()).rejects.toThrow('not an array');
	});
});
