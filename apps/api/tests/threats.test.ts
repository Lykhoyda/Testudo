import { describe, expect, it, vi, beforeEach } from 'vitest';
import { Hono } from 'hono';
import type { ThreatResult, DomainResult } from '../src/services/threat-service.js';

vi.mock('../src/services/threat-service.js', () => ({
	lookupAddress: vi.fn(),
	lookupDomain: vi.fn(),
}));

import { lookupAddress, lookupDomain } from '../src/services/threat-service.js';
import { threatRoutes } from '../src/routes/threats.js';

const app = new Hono();
app.route('/api/v1/threats', threatRoutes);

const mockedLookupAddress = vi.mocked(lookupAddress);
const mockedLookupDomain = vi.mocked(lookupDomain);

beforeEach(() => {
	vi.clearAllMocks();
});

describe('GET /api/v1/threats/address/:address', () => {
	const maliciousAddress = '0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b';

	it('returns isMalicious: true for known malicious address', async () => {
		const mockThreat: ThreatResult = {
			address: maliciousAddress,
			chainId: 1,
			threatType: 'ETH_DRAINER',
			threatLevel: 'CRITICAL',
			confidence: '0.95',
			sources: ['scamsniffer', 'testudo'],
			firstSeen: new Date('2025-01-15T10:30:00Z'),
		};
		mockedLookupAddress.mockResolvedValue(mockThreat);

		const res = await app.request(`/api/v1/threats/address/${maliciousAddress}`);
		const body = await res.json();

		expect(res.status).toBe(200);
		expect(body.isMalicious).toBe(true);
		expect(body.address).toBe(maliciousAddress);
		expect(body.threatType).toBe('ETH_DRAINER');
		expect(body.threatLevel).toBe('CRITICAL');
		expect(body.confidence).toBe(0.95);
		expect(body.sources).toEqual(['scamsniffer', 'testudo']);
		expect(body.firstSeen).toBe('2025-01-15T10:30:00.000Z');
	});

	it('returns isMalicious: false for clean address', async () => {
		const cleanAddress = '0x0000000000000000000000000000000000000001';
		mockedLookupAddress.mockResolvedValue(null);

		const res = await app.request(`/api/v1/threats/address/${cleanAddress}`);
		const body = await res.json();

		expect(res.status).toBe(200);
		expect(body.isMalicious).toBe(false);
		expect(body.address).toBe(cleanAddress);
	});

	it('normalizes address to lowercase before lookup', async () => {
		const upperAddr = '0x930FCC37D6042C79211EE18A02857CB1FD7F0D0B';
		mockedLookupAddress.mockResolvedValue(null);

		await app.request(`/api/v1/threats/address/${upperAddr}`);

		expect(mockedLookupAddress).toHaveBeenCalledWith(upperAddr.toLowerCase());
	});

	it('returns 400 for invalid address format', async () => {
		const res = await app.request('/api/v1/threats/address/not-an-address');
		const body = await res.json();

		expect(res.status).toBe(400);
		expect(body.error).toBe('Invalid address format');
		expect(body.code).toBe('INVALID_ADDRESS');
		expect(mockedLookupAddress).not.toHaveBeenCalled();
	});

	it('returns 400 for address without 0x prefix', async () => {
		const res = await app.request(
			'/api/v1/threats/address/930fcc37d6042c79211ee18a02857cb1fd7f0d0b',
		);

		expect(res.status).toBe(400);
	});

	it('returns 400 for too-short address', async () => {
		const res = await app.request('/api/v1/threats/address/0x1234');

		expect(res.status).toBe(400);
	});

	it('converts confidence string to number in response', async () => {
		mockedLookupAddress.mockResolvedValue({
			address: maliciousAddress,
			chainId: 1,
			threatType: 'PHISHING',
			threatLevel: 'HIGH',
			confidence: '0.80',
			sources: ['goplus'],
			firstSeen: new Date('2025-06-01T00:00:00Z'),
		});

		const res = await app.request(`/api/v1/threats/address/${maliciousAddress}`);
		const body = await res.json();

		expect(typeof body.confidence).toBe('number');
		expect(body.confidence).toBe(0.8);
	});

	it('serializes firstSeen as ISO string', async () => {
		const date = new Date('2025-03-20T14:00:00Z');
		mockedLookupAddress.mockResolvedValue({
			address: maliciousAddress,
			chainId: 1,
			threatType: 'ETH_DRAINER',
			threatLevel: 'CRITICAL',
			confidence: '0.99',
			sources: ['testudo'],
			firstSeen: date,
		});

		const res = await app.request(`/api/v1/threats/address/${maliciousAddress}`);
		const body = await res.json();

		expect(body.firstSeen).toBe('2025-03-20T14:00:00.000Z');
	});
});

describe('GET /api/v1/threats/domain/:domain', () => {
	it('returns isMalicious: true for known malicious domain', async () => {
		const mockDomain: DomainResult = {
			domain: 'fake-uniswap.com',
			threatType: 'PHISHING',
			confidence: '0.90',
			sources: ['eth-phishing-detect'],
			isFuzzyMatch: true,
			matchedLegitimate: 'uniswap.org',
			firstSeen: new Date('2025-01-10T08:00:00Z'),
		};
		mockedLookupDomain.mockResolvedValue(mockDomain);

		const res = await app.request('/api/v1/threats/domain/fake-uniswap.com');
		const body = await res.json();

		expect(res.status).toBe(200);
		expect(body.isMalicious).toBe(true);
		expect(body.domain).toBe('fake-uniswap.com');
		expect(body.threatType).toBe('PHISHING');
		expect(body.confidence).toBe(0.9);
		expect(body.sources).toEqual(['eth-phishing-detect']);
		expect(body.isFuzzyMatch).toBe(true);
		expect(body.matchedLegitimate).toBe('uniswap.org');
		expect(body.firstSeen).toBe('2025-01-10T08:00:00.000Z');
	});

	it('returns isMalicious: false for clean domain', async () => {
		mockedLookupDomain.mockResolvedValue(null);

		const res = await app.request('/api/v1/threats/domain/uniswap.org');
		const body = await res.json();

		expect(res.status).toBe(200);
		expect(body.isMalicious).toBe(false);
		expect(body.domain).toBe('uniswap.org');
	});

	it('normalizes domain before lookup', async () => {
		mockedLookupDomain.mockResolvedValue(null);

		await app.request('/api/v1/threats/domain/www.Example.COM');

		expect(mockedLookupDomain).toHaveBeenCalledWith('example.com');
	});

	it('returns 400 for invalid domain (no TLD)', async () => {
		const res = await app.request('/api/v1/threats/domain/localhost');
		const body = await res.json();

		expect(res.status).toBe(400);
		expect(body.error).toBe('Invalid domain');
		expect(body.code).toBe('INVALID_DOMAIN');
		expect(mockedLookupDomain).not.toHaveBeenCalled();
	});

	it('returns null matchedLegitimate when not a fuzzy match', async () => {
		mockedLookupDomain.mockResolvedValue({
			domain: 'evil-site.com',
			threatType: 'PHISHING',
			confidence: '0.85',
			sources: ['testudo'],
			isFuzzyMatch: false,
			matchedLegitimate: null,
			firstSeen: new Date('2025-02-01T00:00:00Z'),
		});

		const res = await app.request('/api/v1/threats/domain/evil-site.com');
		const body = await res.json();

		expect(body.isFuzzyMatch).toBe(false);
		expect(body.matchedLegitimate).toBeNull();
	});

	it('converts confidence string to number in response', async () => {
		mockedLookupDomain.mockResolvedValue({
			domain: 'phish.io',
			threatType: 'PHISHING',
			confidence: '0.75',
			sources: ['goplus'],
			isFuzzyMatch: false,
			matchedLegitimate: null,
			firstSeen: new Date('2025-04-01T00:00:00Z'),
		});

		const res = await app.request('/api/v1/threats/domain/phish.io');
		const body = await res.json();

		expect(typeof body.confidence).toBe('number');
		expect(body.confidence).toBe(0.75);
	});
});
