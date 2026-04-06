import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { checkAddressThreat, checkDomainThreat } from '../src/api-client';

const BASE_URL = 'https://api.testudo.test';
const ADDRESS = '0xAbCdEf1234567890AbCdEf1234567890AbCdEf12';
const ADDRESS_LOWER = ADDRESS.toLowerCase();

function mockResponse(body: unknown, init?: ResponseInit): Response {
	return {
		ok: init?.status ? init.status >= 200 && init.status < 300 : true,
		status: init?.status ?? 200,
		json: () => Promise.resolve(body),
	} as Response;
}

const cleanThreat = {
	isMalicious: false,
	address: ADDRESS_LOWER,
};

const maliciousThreat = {
	isMalicious: true,
	address: ADDRESS_LOWER,
	threatType: 'ETH_DRAINER',
	threatLevel: 'CRITICAL',
	confidence: 0.95,
	sources: ['scam-sniffer', 'testudo'],
	firstSeen: '2026-01-15T00:00:00Z',
};

let originalOnLine: boolean;

describe('checkAddressThreat', () => {
	beforeEach(() => {
		originalOnLine = navigator.onLine;
		Object.defineProperty(navigator, 'onLine', { value: true, writable: true, configurable: true });
		vi.stubGlobal('fetch', vi.fn());
		vi.spyOn(console, 'log').mockImplementation(() => {});
		vi.spyOn(console, 'warn').mockImplementation(() => {});
	});

	afterEach(() => {
		Object.defineProperty(navigator, 'onLine', {
			value: originalOnLine,
			writable: true,
			configurable: true,
		});
		vi.restoreAllMocks();
	});

	it('returns offline when navigator.onLine is false', async () => {
		Object.defineProperty(navigator, 'onLine', { value: false, configurable: true });

		const result = await checkAddressThreat(ADDRESS, { baseUrl: BASE_URL });

		expect(result).toEqual({
			success: false,
			offline: true,
			error: 'Offline',
			errorCategory: 'offline',
		});
		expect(fetch).not.toHaveBeenCalled();
	});

	it('returns success with data for a clean address', async () => {
		vi.mocked(fetch).mockResolvedValue(mockResponse(cleanThreat));

		const result = await checkAddressThreat(ADDRESS, { baseUrl: BASE_URL });

		expect(result).toEqual({ success: true, data: cleanThreat });
	});

	it('returns success with full threat data for a malicious address', async () => {
		vi.mocked(fetch).mockResolvedValue(mockResponse(maliciousThreat));

		const result = await checkAddressThreat(ADDRESS, { baseUrl: BASE_URL });

		expect(result.success).toBe(true);
		expect(result.data).toEqual(maliciousThreat);
		expect(result.data?.isMalicious).toBe(true);
		expect(result.data?.threatType).toBe('ETH_DRAINER');
	});

	it('returns rateLimited on 429 without retrying', async () => {
		vi.mocked(fetch).mockResolvedValue(mockResponse(null, { status: 429 }));

		const result = await checkAddressThreat(ADDRESS, { baseUrl: BASE_URL });

		expect(result).toEqual({
			success: false,
			rateLimited: true,
			error: 'Rate limited',
			errorCategory: 'rate_limited',
		});
		expect(fetch).toHaveBeenCalledTimes(1);
	});

	it('retries on HTTP 500 and succeeds on second attempt', async () => {
		vi.mocked(fetch)
			.mockResolvedValueOnce(mockResponse(null, { status: 500 }))
			.mockResolvedValueOnce(mockResponse(cleanThreat));

		const result = await checkAddressThreat(ADDRESS, { baseUrl: BASE_URL });

		expect(result).toEqual({ success: true, data: cleanThreat });
		expect(fetch).toHaveBeenCalledTimes(2);
	});

	it('fails after exhausting retries on HTTP 500', async () => {
		vi.mocked(fetch).mockResolvedValue(mockResponse(null, { status: 500 }));

		const result = await checkAddressThreat(ADDRESS, { baseUrl: BASE_URL });

		expect(result).toEqual({ success: false, error: 'HTTP 500', errorCategory: 'http_error' });
		expect(fetch).toHaveBeenCalledTimes(2);
	});

	it('retries and fails on invalid response structure', async () => {
		vi.mocked(fetch).mockResolvedValue(mockResponse({ foo: 'bar' }));

		const result = await checkAddressThreat(ADDRESS, { baseUrl: BASE_URL });

		expect(result).toEqual({
			success: false,
			error: 'Invalid API response',
			errorCategory: 'invalid_response',
		});
		expect(fetch).toHaveBeenCalledTimes(2);
	});

	it('retries on AbortError (timeout) and reports Timeout', async () => {
		const abortError = new DOMException('The operation was aborted', 'AbortError');
		vi.mocked(fetch).mockRejectedValue(abortError);

		const result = await checkAddressThreat(ADDRESS, { baseUrl: BASE_URL });

		expect(result).toEqual({ success: false, error: 'Timeout', errorCategory: 'timeout' });
		expect(fetch).toHaveBeenCalledTimes(2);
	});

	it('retries on network error and reports error message', async () => {
		const networkError = new TypeError('Failed to fetch');
		vi.mocked(fetch).mockRejectedValue(networkError);

		const result = await checkAddressThreat(ADDRESS, { baseUrl: BASE_URL });

		expect(result).toEqual({
			success: false,
			error: 'Failed to fetch',
			errorCategory: 'network_error',
		});
		expect(fetch).toHaveBeenCalledTimes(2);
	});

	it('lowercases the address in the request URL', async () => {
		vi.mocked(fetch).mockResolvedValue(mockResponse(cleanThreat));

		await checkAddressThreat(ADDRESS, { baseUrl: BASE_URL });

		expect(fetch).toHaveBeenCalledWith(
			`${BASE_URL}/api/v1/threats/address/${ADDRESS_LOWER}`,
			expect.objectContaining({ headers: { 'Content-Type': 'application/json' } }),
		);
	});

	it('uses custom baseUrl and timeout from options', async () => {
		const customUrl = 'https://custom.api.test';
		vi.mocked(fetch).mockResolvedValue(mockResponse(cleanThreat));

		await checkAddressThreat(ADDRESS, { baseUrl: customUrl, timeout: 2000 });

		expect(fetch).toHaveBeenCalledWith(
			`${customUrl}/api/v1/threats/address/${ADDRESS_LOWER}`,
			expect.any(Object),
		);
	});

	it('handles non-Error thrown objects with Unknown error', async () => {
		vi.mocked(fetch).mockRejectedValue('string error');

		const result = await checkAddressThreat(ADDRESS, { baseUrl: BASE_URL });

		expect(result).toEqual({ success: false, error: 'Unknown error', errorCategory: 'unknown' });
		expect(fetch).toHaveBeenCalledTimes(2);
	});
});

const DOMAIN = 'evil-phishing-site.xyz';

const maliciousDomainThreat = {
	isMalicious: true,
	domain: DOMAIN,
	threatType: 'PHISHING',
	sources: ['scam-sniffer', 'eth-phishing-detect'],
	matchedLegitimate: 'uniswap.org',
	firstSeen: '2026-03-01T00:00:00Z',
};

const cleanDomainThreat = {
	isMalicious: false,
	domain: DOMAIN,
};

describe('checkDomainThreat', () => {
	beforeEach(() => {
		originalOnLine = navigator.onLine;
		Object.defineProperty(navigator, 'onLine', { value: true, writable: true, configurable: true });
		vi.stubGlobal('fetch', vi.fn());
		vi.spyOn(console, 'log').mockImplementation(() => {});
		vi.spyOn(console, 'warn').mockImplementation(() => {});
	});

	afterEach(() => {
		Object.defineProperty(navigator, 'onLine', {
			value: originalOnLine,
			writable: true,
			configurable: true,
		});
		vi.restoreAllMocks();
	});

	it('returns threat data for malicious domain', async () => {
		vi.mocked(fetch).mockResolvedValue(mockResponse(maliciousDomainThreat));

		const result = await checkDomainThreat(DOMAIN, { baseUrl: BASE_URL });

		expect(result.success).toBe(true);
		expect(result.data).toEqual(maliciousDomainThreat);
		expect(result.data?.isMalicious).toBe(true);
		expect(result.data?.threatType).toBe('PHISHING');
	});

	it('returns clean result for safe domain', async () => {
		vi.mocked(fetch).mockResolvedValue(mockResponse(cleanDomainThreat));

		const result = await checkDomainThreat(DOMAIN, { baseUrl: BASE_URL });

		expect(result).toEqual({ success: true, data: cleanDomainThreat });
	});

	it('returns offline when navigator.onLine is false', async () => {
		Object.defineProperty(navigator, 'onLine', { value: false, configurable: true });

		const result = await checkDomainThreat(DOMAIN, { baseUrl: BASE_URL });

		expect(result).toEqual({
			success: false,
			offline: true,
			error: 'Offline',
			errorCategory: 'offline',
		});
		expect(fetch).not.toHaveBeenCalled();
	});

	it('calls correct API endpoint for domain lookup', async () => {
		vi.mocked(fetch).mockResolvedValue(mockResponse(cleanDomainThreat));

		await checkDomainThreat(DOMAIN, { baseUrl: BASE_URL });

		expect(fetch).toHaveBeenCalledWith(
			`${BASE_URL}/api/v1/threats/domain/${encodeURIComponent(DOMAIN)}`,
			expect.objectContaining({ headers: { 'Content-Type': 'application/json' } }),
		);
	});
});
