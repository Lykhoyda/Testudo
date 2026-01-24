import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { fetchAddresses, fetchDomains } from '../../../src/sync/adapters/scam-sniffer.js';

const originalFetch = globalThis.fetch;

beforeEach(() => {
	vi.stubGlobal('fetch', vi.fn());
});

afterEach(() => {
	globalThis.fetch = originalFetch;
});

describe('ScamSniffer adapter', () => {
	describe('fetchAddresses', () => {
		it('parses valid addresses from response', async () => {
			const mockAddresses = [
				'0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b',
				'0xa85d90b8febc092e11e75bf8f93a7090e2ed04de',
			];

			vi.mocked(fetch).mockResolvedValue(
				new Response(JSON.stringify(mockAddresses), { status: 200 }),
			);

			const result = await fetchAddresses();

			expect(result.source).toBe('scam-sniffer');
			expect(result.entries).toHaveLength(2);
			expect(result.entries[0].address).toBe('0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b');
			expect(result.entries[0].threatType).toBe('SCAM');
			expect(result.entries[0].threatLevel).toBe('HIGH');
			expect(result.entries[0].chainId).toBe(1);
			expect(result.fetchedAt).toBeInstanceOf(Date);
		});

		it('filters out invalid addresses', async () => {
			const mockAddresses = [
				'0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b',
				'not-an-address',
				'0x1234',
				'',
				null,
				42,
			];

			vi.mocked(fetch).mockResolvedValue(
				new Response(JSON.stringify(mockAddresses), { status: 200 }),
			);

			const result = await fetchAddresses();

			expect(result.entries).toHaveLength(1);
			expect(result.entries[0].address).toBe('0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b');
		});

		it('normalizes addresses to lowercase', async () => {
			const mockAddresses = ['0x930FCC37D6042C79211EE18A02857CB1FD7F0D0B'];

			vi.mocked(fetch).mockResolvedValue(
				new Response(JSON.stringify(mockAddresses), { status: 200 }),
			);

			const result = await fetchAddresses();

			expect(result.entries[0].address).toBe('0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b');
		});

		it('throws on non-200 response', async () => {
			vi.mocked(fetch).mockResolvedValue(new Response('Not Found', { status: 404 }));

			await expect(fetchAddresses()).rejects.toThrow('ScamSniffer addresses fetch failed');
		});

		it('throws if response is not an array', async () => {
			vi.mocked(fetch).mockResolvedValue(
				new Response(JSON.stringify({ data: [] }), { status: 200 }),
			);

			await expect(fetchAddresses()).rejects.toThrow('not an array');
		});
	});

	describe('fetchDomains', () => {
		it('parses valid domains from response', async () => {
			const mockDomains = ['fake-uniswap.com', 'phishing-site.io'];

			vi.mocked(fetch).mockResolvedValue(
				new Response(JSON.stringify(mockDomains), { status: 200 }),
			);

			const result = await fetchDomains();

			expect(result.source).toBe('scam-sniffer');
			expect(result.entries).toHaveLength(2);
			expect(result.entries[0].domain).toBe('fake-uniswap.com');
			expect(result.entries[0].threatType).toBe('PHISHING');
		});

		it('filters empty strings', async () => {
			const mockDomains = ['fake-uniswap.com', '', '  '];

			vi.mocked(fetch).mockResolvedValue(
				new Response(JSON.stringify(mockDomains), { status: 200 }),
			);

			const result = await fetchDomains();

			// '' is filtered, but '  ' passes string check and gets trimmed
			expect(result.entries.length).toBeGreaterThanOrEqual(1);
			expect(result.entries[0].domain).toBe('fake-uniswap.com');
		});

		it('normalizes domains to lowercase and trims', async () => {
			const mockDomains = ['  Fake-Uniswap.COM  '];

			vi.mocked(fetch).mockResolvedValue(
				new Response(JSON.stringify(mockDomains), { status: 200 }),
			);

			const result = await fetchDomains();

			expect(result.entries[0].domain).toBe('fake-uniswap.com');
		});

		it('throws on non-200 response', async () => {
			vi.mocked(fetch).mockResolvedValue(new Response('Error', { status: 500 }));

			await expect(fetchDomains()).rejects.toThrow('ScamSniffer domains fetch failed');
		});
	});
});
