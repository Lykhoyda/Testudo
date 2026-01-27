import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { fetchDomains } from '../../../../src/modules/threats/adapters/eth-phishing-detect.js';

const originalFetch = globalThis.fetch;

beforeEach(() => {
	vi.stubGlobal('fetch', vi.fn());
});

afterEach(() => {
	globalThis.fetch = originalFetch;
});

describe('eth-phishing-detect adapter', () => {
	describe('fetchDomains', () => {
		it('parses blacklist domains', async () => {
			const config = {
				blacklist: ['fake-uniswap.com', 'phishing-aave.io'],
				fuzzylist: ['uniswap.org', 'aave.com'],
				whitelist: [],
			};

			vi.mocked(fetch).mockResolvedValue(
				new Response(JSON.stringify(config), { status: 200 }),
			);

			const result = await fetchDomains();

			expect(result.source).toBe('eth-phishing-detect');
			expect(result.entries).toHaveLength(2);
			expect(result.entries[0].domain).toBe('fake-uniswap.com');
			expect(result.entries[0].threatType).toBe('PHISHING');
		});

		it('sets isFuzzyMatch when Levenshtein distance is within tolerance', async () => {
			const config = {
				blacklist: ['uniswap.com'],
				fuzzylist: ['uniswap.org'],
				whitelist: [],
			};

			vi.mocked(fetch).mockResolvedValue(
				new Response(JSON.stringify(config), { status: 200 }),
			);

			const result = await fetchDomains();

			expect(result.entries[0].isFuzzyMatch).toBe(true);
			expect(result.entries[0].matchedLegitimate).toBe('uniswap.org');
		});

		it('does not set fuzzy match when distance exceeds tolerance', async () => {
			const config = {
				blacklist: ['completely-different-site.com'],
				fuzzylist: ['uniswap.org'],
				whitelist: [],
			};

			vi.mocked(fetch).mockResolvedValue(
				new Response(JSON.stringify(config), { status: 200 }),
			);

			const result = await fetchDomains();

			expect(result.entries[0].isFuzzyMatch).toBe(false);
			expect(result.entries[0].matchedLegitimate).toBeNull();
		});

		it('excludes whitelisted domains from results', async () => {
			const config = {
				blacklist: ['uniswap.org', 'evil-site.com'],
				fuzzylist: [],
				whitelist: ['uniswap.org'],
			};

			vi.mocked(fetch).mockResolvedValue(
				new Response(JSON.stringify(config), { status: 200 }),
			);

			const result = await fetchDomains();

			expect(result.entries).toHaveLength(1);
			expect(result.entries[0].domain).toBe('evil-site.com');
		});

		it('normalizes domains to lowercase', async () => {
			const config = {
				blacklist: ['EVIL-SITE.COM'],
				fuzzylist: [],
				whitelist: [],
			};

			vi.mocked(fetch).mockResolvedValue(
				new Response(JSON.stringify(config), { status: 200 }),
			);

			const result = await fetchDomains();

			expect(result.entries[0].domain).toBe('evil-site.com');
		});

		it('filters empty strings from blacklist', async () => {
			const config = {
				blacklist: ['evil.com', '', '  '],
				fuzzylist: [],
				whitelist: [],
			};

			vi.mocked(fetch).mockResolvedValue(
				new Response(JSON.stringify(config), { status: 200 }),
			);

			const result = await fetchDomains();

			expect(result.entries).toHaveLength(1);
			expect(result.entries[0].domain).toBe('evil.com');
		});

		it('throws on non-200 response', async () => {
			vi.mocked(fetch).mockResolvedValue(new Response('Error', { status: 403 }));

			await expect(fetchDomains()).rejects.toThrow('eth-phishing-detect fetch failed');
		});

		it('throws if blacklist is not an array', async () => {
			const config = { blacklist: 'not-array', fuzzylist: [], whitelist: [] };

			vi.mocked(fetch).mockResolvedValue(
				new Response(JSON.stringify(config), { status: 200 }),
			);

			await expect(fetchDomains()).rejects.toThrow('not an array');
		});

		it('handles missing fuzzylist and whitelist gracefully', async () => {
			const config = {
				blacklist: ['evil.com'],
			};

			vi.mocked(fetch).mockResolvedValue(
				new Response(JSON.stringify(config), { status: 200 }),
			);

			const result = await fetchDomains();

			expect(result.entries).toHaveLength(1);
			expect(result.entries[0].isFuzzyMatch).toBe(false);
		});
	});
});
