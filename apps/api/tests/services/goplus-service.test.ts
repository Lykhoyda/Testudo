import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';

vi.mock('../../src/db/index.js', () => ({
	db: {
		insert: vi.fn().mockReturnValue({
			values: vi.fn().mockReturnValue({
				onConflictDoUpdate: vi.fn().mockResolvedValue(undefined),
			}),
		}),
	},
}));

import { checkAddress } from '../../src/services/goplus-service.js';
import { db } from '../../src/db/index.js';

beforeEach(() => {
	vi.clearAllMocks();
});

afterEach(() => {
	vi.restoreAllMocks();
});

function mockGoPlusResponse(address: string, flags: Record<string, string>) {
	return {
		code: 1,
		result: { [address.toLowerCase()]: flags },
	};
}

describe('goplus-service', () => {
	describe('checkAddress', () => {
		const testAddress = '0x1234567890abcdef1234567890abcdef12345678';

		it('maps stealing_attack to CRITICAL/ETH_DRAINER', async () => {
			vi.spyOn(globalThis, 'fetch').mockResolvedValue(
				new Response(
					JSON.stringify(mockGoPlusResponse(testAddress, { stealing_attack: '1' })),
					{ status: 200 },
				),
			);

			const result = await checkAddress(testAddress);

			expect(result).not.toBeNull();
			expect(result!.threatLevel).toBe('CRITICAL');
			expect(result!.threatType).toBe('ETH_DRAINER');
			expect(result!.confidence).toBe('0.65');
			expect(result!.sources).toEqual(['goplus']);
		});

		it('maps phishing_activities to HIGH/PHISHING', async () => {
			vi.spyOn(globalThis, 'fetch').mockResolvedValue(
				new Response(
					JSON.stringify(mockGoPlusResponse(testAddress, { phishing_activities: '1' })),
					{ status: 200 },
				),
			);

			const result = await checkAddress(testAddress);

			expect(result).not.toBeNull();
			expect(result!.threatLevel).toBe('HIGH');
			expect(result!.threatType).toBe('PHISHING');
		});

		it('maps blacklist_doubt to HIGH/SCAM', async () => {
			vi.spyOn(globalThis, 'fetch').mockResolvedValue(
				new Response(
					JSON.stringify(mockGoPlusResponse(testAddress, { blacklist_doubt: '1' })),
					{ status: 200 },
				),
			);

			const result = await checkAddress(testAddress);

			expect(result).not.toBeNull();
			expect(result!.threatLevel).toBe('HIGH');
			expect(result!.threatType).toBe('SCAM');
		});

		it('maps honeypot_related_address to MEDIUM/HONEYPOT', async () => {
			vi.spyOn(globalThis, 'fetch').mockResolvedValue(
				new Response(
					JSON.stringify(
						mockGoPlusResponse(testAddress, { honeypot_related_address: '1' }),
					),
					{ status: 200 },
				),
			);

			const result = await checkAddress(testAddress);

			expect(result).not.toBeNull();
			expect(result!.threatLevel).toBe('MEDIUM');
			expect(result!.threatType).toBe('HONEYPOT');
		});

		it('returns null for clean address (all flags "0")', async () => {
			vi.spyOn(globalThis, 'fetch').mockResolvedValue(
				new Response(
					JSON.stringify(
						mockGoPlusResponse(testAddress, {
							stealing_attack: '0',
							phishing_activities: '0',
							blacklist_doubt: '0',
							honeypot_related_address: '0',
						}),
					),
					{ status: 200 },
				),
			);

			const result = await checkAddress(testAddress);

			expect(result).toBeNull();
		});

		it('returns null on network timeout', async () => {
			vi.spyOn(globalThis, 'fetch').mockRejectedValue(new DOMException('Aborted', 'AbortError'));

			const result = await checkAddress(testAddress);

			expect(result).toBeNull();
		});

		it('returns null on API error (non-200)', async () => {
			vi.spyOn(globalThis, 'fetch').mockResolvedValue(
				new Response('Server Error', { status: 500 }),
			);

			const result = await checkAddress(testAddress);

			expect(result).toBeNull();
		});

		it('caches malicious result to DB via insert', async () => {
			vi.spyOn(globalThis, 'fetch').mockResolvedValue(
				new Response(
					JSON.stringify(mockGoPlusResponse(testAddress, { stealing_attack: '1' })),
					{ status: 200 },
				),
			);

			await checkAddress(testAddress);

			expect(db.insert).toHaveBeenCalled();
		});

		it('uses priority order - stealing_attack wins over phishing_activities', async () => {
			vi.spyOn(globalThis, 'fetch').mockResolvedValue(
				new Response(
					JSON.stringify(
						mockGoPlusResponse(testAddress, {
							stealing_attack: '1',
							phishing_activities: '1',
						}),
					),
					{ status: 200 },
				),
			);

			const result = await checkAddress(testAddress);

			expect(result!.threatType).toBe('ETH_DRAINER');
			expect(result!.threatLevel).toBe('CRITICAL');
		});

		it('normalizes address to lowercase in result', async () => {
			const upperAddress = '0x1234567890ABCDEF1234567890ABCDEF12345678';
			vi.spyOn(globalThis, 'fetch').mockResolvedValue(
				new Response(
					JSON.stringify(mockGoPlusResponse(upperAddress, { blacklist_doubt: '1' })),
					{ status: 200 },
				),
			);

			const result = await checkAddress(upperAddress);

			expect(result!.address).toBe(upperAddress.toLowerCase());
		});
	});
});
