import { describe, expect, it } from 'vitest';
import { parseChainId } from '../../src/utils/chain-id';

describe('parseChainId', () => {
	it('returns positive integer numbers unchanged', () => {
		expect(parseChainId(1)).toBe(1);
		expect(parseChainId(10)).toBe(10);
		expect(parseChainId(8453)).toBe(8453);
	});

	it('parses 0x-prefixed hex strings as base 16 (eth_chainId shape)', () => {
		expect(parseChainId('0x1')).toBe(1);
		expect(parseChainId('0xa')).toBe(10);
		expect(parseChainId('0x89')).toBe(137);
		expect(parseChainId('0X2105')).toBe(8453); // case-insensitive prefix
	});

	// AUDIT-4: EIP-712 / EIP-7702 typed data frequently serializes chainId as a
	// plain decimal string. The old parseChainIdHex always used base 16, routing
	// threat lookups to the wrong chain (false negatives).
	it('parses plain decimal strings as base 10 (typed-data shape)', () => {
		expect(parseChainId('1')).toBe(1);
		expect(parseChainId('10')).toBe(10); // was 16 under base-16
		expect(parseChainId('137')).toBe(137); // was 311
		expect(parseChainId('8453')).toBe(8453); // was 33875
	});

	it('parses bigint chain ids', () => {
		expect(parseChainId(10n)).toBe(10);
		expect(parseChainId(8453n)).toBe(8453);
	});

	it('trims surrounding whitespace', () => {
		expect(parseChainId(' 137 ')).toBe(137);
		expect(parseChainId('  0xa')).toBe(10);
	});

	it('returns undefined for zero / replay-risk values', () => {
		expect(parseChainId(0)).toBeUndefined();
		expect(parseChainId('0')).toBeUndefined();
		expect(parseChainId('0x0')).toBeUndefined();
		expect(parseChainId(0n)).toBeUndefined();
	});

	it('returns undefined for missing / malformed / invalid input', () => {
		expect(parseChainId(undefined)).toBeUndefined();
		expect(parseChainId(null)).toBeUndefined();
		expect(parseChainId('')).toBeUndefined();
		expect(parseChainId('   ')).toBeUndefined();
		expect(parseChainId('not-a-chain')).toBeUndefined();
		expect(parseChainId('0xZZ')).toBeUndefined();
	});

	it('returns undefined for negative or non-integer numbers (AUDIT-29 hygiene)', () => {
		expect(parseChainId(-1)).toBeUndefined();
		expect(parseChainId(1.5)).toBeUndefined();
		expect(parseChainId(Number.NaN)).toBeUndefined();
		expect(parseChainId(Number.POSITIVE_INFINITY)).toBeUndefined();
	});
});
