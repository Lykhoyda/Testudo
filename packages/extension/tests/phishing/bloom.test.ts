import { describe, expect, it } from 'vitest';
import { PhishingBloomFilter } from '../../src/phishing/bloom';

const SAMPLE_DOMAINS = [
	'metamask-secure.io',
	'uniswap-airdrop.com',
	'wallet-connect-claim.xyz',
	'ethereum-bonus.net',
	'aave-protocol-claim.com',
];

describe('PhishingBloomFilter', () => {
	it('detects inserted domains', () => {
		const filter = PhishingBloomFilter.fromDomains(SAMPLE_DOMAINS, SAMPLE_DOMAINS.length);

		for (const domain of SAMPLE_DOMAINS) {
			expect(filter.has(domain)).toBe(true);
		}
	});

	it('rejects domains not inserted', () => {
		const filter = PhishingBloomFilter.fromDomains(SAMPLE_DOMAINS, SAMPLE_DOMAINS.length);

		const absent = ['google.com', 'uniswap.org', 'metamask.io', 'ethereum.org', 'aave.com'];

		for (const domain of absent) {
			expect(filter.has(domain)).toBe(false);
		}
	});

	it('handles empty filter', () => {
		const filter = PhishingBloomFilter.fromDomains([], 1);

		expect(filter.has('anything.com')).toBe(false);
		expect(filter.byteLength).toBeGreaterThan(0);
	});

	it('round-trips through binary serialization', () => {
		const filter = PhishingBloomFilter.fromDomains(SAMPLE_DOMAINS, SAMPLE_DOMAINS.length);
		const binary = filter.toBinary();
		const restored = PhishingBloomFilter.fromBinary(binary, filter.numHashes);

		for (const domain of SAMPLE_DOMAINS) {
			expect(restored.has(domain)).toBe(true);
		}
	});

	it('round-trips through base64 serialization', () => {
		const filter = PhishingBloomFilter.fromDomains(SAMPLE_DOMAINS, SAMPLE_DOMAINS.length);
		const b64 = filter.toBase64();
		const restored = PhishingBloomFilter.fromBase64(b64, filter.numHashes);

		for (const domain of SAMPLE_DOMAINS) {
			expect(restored.has(domain)).toBe(true);
		}
	});

	it('reports correct byteLength', () => {
		const filter = PhishingBloomFilter.fromDomains(SAMPLE_DOMAINS, 250_000);

		// For 250K items at 0.1% FPR: ~3.6M bits = ~450KB
		// bits is a Uint8Array, so bits.byteLength === bits.length (bytes, not bits)
		// byteLength getter must equal the underlying Uint8Array's byte length
		expect(filter.byteLength).toBe(filter.bits.byteLength);
		// Sanity check: 250K items at 0.1% FPR ≈ 449,300 bytes
		expect(filter.byteLength).toBeGreaterThan(400_000);
		expect(filter.byteLength).toBeLessThan(500_000);
	});

	it('round-trips at production (non-byte-aligned) size with no false negatives (AUDIT-6 guard)', () => {
		// optimalBitCount(250_000, 0.001) is NOT a multiple of 8. The audit alleged
		// that insert used that raw value while query used bits.length*8 after
		// deserialization, dropping ~99.97% of lookups. In reality the constructor
		// derives bitCount = bits.length*8 for BOTH insert and query, so the moduli
		// always match. This guards that invariant across the serialize boundary.
		const rawOptimalBits = Math.ceil((-250_000 * Math.log(0.001)) / (Math.LN2 * Math.LN2));
		const inserted: string[] = [];
		for (let i = 0; i < 2000; i++) {
			inserted.push(`phishing-${i}-${((i * 2654435761) >>> 0).toString(36)}.example`);
		}

		const filter = PhishingBloomFilter.fromDomains(inserted, 250_000);
		// Confirm we are genuinely in the non-byte-aligned regime the audit worried about.
		expect(rawOptimalBits % 8).not.toBe(0);
		expect(filter.byteLength * 8).not.toBe(rawOptimalBits);

		const restored = PhishingBloomFilter.fromBase64(filter.toBase64(), filter.numHashes);
		for (const domain of inserted) {
			expect(restored.has(domain)).toBe(true); // no false negatives after round-trip
		}
	});

	it('uses Uint8Array internally (no Node.js Buffer)', () => {
		const filter = PhishingBloomFilter.fromDomains(SAMPLE_DOMAINS, SAMPLE_DOMAINS.length);
		const binary = filter.toBinary();

		// toBinary returns ArrayBuffer — view it as Uint8Array, not Buffer
		const view = new Uint8Array(binary);
		expect(view).toBeInstanceOf(Uint8Array);

		// Critically: the internal bit array must NOT be a Buffer instance
		// (Buffer is a Node.js-only type that crashes Chrome service workers)
		const internalBits = filter.bits;
		expect(internalBits).toBeInstanceOf(Uint8Array);
		// Buffer extends Uint8Array, so check it's NOT a Buffer
		expect(internalBits.constructor.name).toBe('Uint8Array');
	});

	it('false positive rate is within bounds for large dataset', () => {
		// Insert 1000 known phishing domains
		const inserted: string[] = [];
		for (let i = 0; i < 1000; i++) {
			inserted.push(`phishing-domain-${i}.xyz`);
		}

		const filter = PhishingBloomFilter.fromDomains(inserted, inserted.length);

		// All inserted domains must be found (no false negatives)
		for (const domain of inserted) {
			expect(filter.has(domain)).toBe(true);
		}

		// Test 10000 random domains — expect < 50 false positives (< 0.5% FPR)
		let falsePositives = 0;
		for (let i = 0; i < 10000; i++) {
			const randomDomain = `legitimate-site-${i}-${Math.random().toString(36).slice(2)}.com`;
			if (filter.has(randomDomain)) {
				falsePositives++;
			}
		}

		expect(falsePositives).toBeLessThan(50);
	});
});
