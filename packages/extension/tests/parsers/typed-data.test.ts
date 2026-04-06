import { describe, expect, it } from 'vitest';
import {
	extractPermitInfo,
	extractTypedDataAddresses,
	isEIP7702Authorization,
	isPermitSignature,
	validateAddress,
} from '../../src/parsers/typed-data';
import type { TypedDataMessage } from '../../src/utils/types';

const ADDR_A = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const ADDR_B = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const ADDR_C = '0xcccccccccccccccccccccccccccccccccccccccc';

function makeTypedData(overrides: Partial<TypedDataMessage> = {}): TypedDataMessage {
	return {
		types: { EIP712Domain: [] },
		primaryType: 'SomeType',
		domain: {},
		message: {},
		...overrides,
	};
}

describe('isEIP7702Authorization', () => {
	it('returns true when all conditions met', () => {
		const td = makeTypedData({
			types: { EIP712Domain: [], Authorization: [{ name: 'address', type: 'address' }] },
			primaryType: 'Authorization',
			message: { address: ADDR_A },
		});
		expect(isEIP7702Authorization(td)).toBe(true);
	});

	it('returns false when types.Authorization is missing', () => {
		const td = makeTypedData({
			primaryType: 'Authorization',
			message: { address: ADDR_A },
		});
		expect(isEIP7702Authorization(td)).toBe(false);
	});

	it('returns false when primaryType is not Authorization', () => {
		const td = makeTypedData({
			types: { EIP712Domain: [], Authorization: [{ name: 'address', type: 'address' }] },
			primaryType: 'Permit',
			message: { address: ADDR_A },
		});
		expect(isEIP7702Authorization(td)).toBe(false);
	});

	it('returns false when message.address is missing', () => {
		const td = makeTypedData({
			types: { EIP712Domain: [], Authorization: [{ name: 'address', type: 'address' }] },
			primaryType: 'Authorization',
			message: {},
		});
		expect(isEIP7702Authorization(td)).toBe(false);
	});
});

describe('isPermitSignature', () => {
	const permitTypes = [
		'Permit',
		'PermitSingle',
		'PermitBatch',
		'PermitTransferFrom',
		'PermitWitnessTransferFrom',
	] as const;

	for (const pt of permitTypes) {
		it(`returns true for primaryType "${pt}"`, () => {
			expect(isPermitSignature(makeTypedData({ primaryType: pt }))).toBe(true);
		});
	}

	it('returns false for non-permit primaryType', () => {
		expect(isPermitSignature(makeTypedData({ primaryType: 'Authorization' }))).toBe(false);
	});

	it('returns false for empty primaryType', () => {
		expect(isPermitSignature(makeTypedData({ primaryType: '' }))).toBe(false);
	});
});

describe('validateAddress', () => {
	it('returns lowercase for valid checksummed address', () => {
		expect(validateAddress('0xABCDEF1234567890abcdef1234567890ABCDEF12')).toBe(
			'0xabcdef1234567890abcdef1234567890abcdef12',
		);
	});

	it('returns lowercase for already-lowercase address', () => {
		expect(validateAddress(ADDR_A)).toBe(ADDR_A);
	});

	it('returns null for too-short hex', () => {
		expect(validateAddress('0xabc')).toBeNull();
	});

	it('returns null for too-long hex', () => {
		expect(validateAddress('0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')).toBeNull();
	});

	it('returns null for missing 0x prefix', () => {
		expect(validateAddress('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')).toBeNull();
	});

	it('returns null for non-hex characters', () => {
		expect(validateAddress('0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG')).toBeNull();
	});

	it('returns null for non-string input', () => {
		expect(validateAddress(42)).toBeNull();
		expect(validateAddress(null)).toBeNull();
		expect(validateAddress(undefined)).toBeNull();
	});
});

describe('extractTypedDataAddresses', () => {
	it('extracts domain.verifyingContract', () => {
		const td = makeTypedData({
			types: { EIP712Domain: [], Foo: [{ name: 'x', type: 'uint256' }] },
			primaryType: 'Foo',
			domain: { verifyingContract: ADDR_A },
			message: { x: 1 },
		});
		const result = extractTypedDataAddresses(td);
		expect(result).toEqual([{ address: ADDR_A, fieldPath: 'domain.verifyingContract' }]);
	});

	it('extracts address fields from message', () => {
		const td = makeTypedData({
			types: {
				EIP712Domain: [],
				Order: [
					{ name: 'maker', type: 'address' },
					{ name: 'taker', type: 'address' },
					{ name: 'amount', type: 'uint256' },
				],
			},
			primaryType: 'Order',
			domain: {},
			message: { maker: ADDR_A, taker: ADDR_B, amount: '1000' },
		});
		const result = extractTypedDataAddresses(td);
		expect(result).toHaveLength(2);
		expect(result[0]).toEqual({ address: ADDR_A, fieldPath: 'message.maker' });
		expect(result[1]).toEqual({ address: ADDR_B, fieldPath: 'message.taker' });
	});

	it('handles address[] arrays', () => {
		const td = makeTypedData({
			types: {
				EIP712Domain: [],
				Multi: [{ name: 'recipients', type: 'address[]' }],
			},
			primaryType: 'Multi',
			message: { recipients: [ADDR_A, ADDR_B, ADDR_C] },
		});
		const result = extractTypedDataAddresses(td);
		expect(result).toHaveLength(3);
		expect(result[0].fieldPath).toBe('message.recipients[0]');
		expect(result[1].fieldPath).toBe('message.recipients[1]');
		expect(result[2].fieldPath).toBe('message.recipients[2]');
	});

	it('handles nested struct types', () => {
		const td = makeTypedData({
			types: {
				EIP712Domain: [],
				Root: [{ name: 'inner', type: 'Inner' }],
				Inner: [{ name: 'target', type: 'address' }],
			},
			primaryType: 'Root',
			message: { inner: { target: ADDR_A } },
		});
		const result = extractTypedDataAddresses(td);
		expect(result).toEqual([{ address: ADDR_A, fieldPath: 'message.inner.target' }]);
	});

	it('handles struct[] arrays', () => {
		const td = makeTypedData({
			types: {
				EIP712Domain: [],
				Root: [{ name: 'items', type: 'Item[]' }],
				Item: [{ name: 'to', type: 'address' }],
			},
			primaryType: 'Root',
			message: {
				items: [{ to: ADDR_A }, { to: ADDR_B }],
			},
		});
		const result = extractTypedDataAddresses(td);
		expect(result).toHaveLength(2);
		expect(result[0]).toEqual({ address: ADDR_A, fieldPath: 'message.items[0].to' });
		expect(result[1]).toEqual({ address: ADDR_B, fieldPath: 'message.items[1].to' });
	});

	it('deduplicates addresses', () => {
		const td = makeTypedData({
			types: {
				EIP712Domain: [],
				Dup: [
					{ name: 'a', type: 'address' },
					{ name: 'b', type: 'address' },
				],
			},
			primaryType: 'Dup',
			message: { a: ADDR_A, b: ADDR_A },
		});
		const result = extractTypedDataAddresses(td);
		expect(result).toHaveLength(1);
	});

	it('deduplicates domain.verifyingContract against message addresses', () => {
		const td = makeTypedData({
			types: {
				EIP712Domain: [],
				Foo: [{ name: 'target', type: 'address' }],
			},
			primaryType: 'Foo',
			domain: { verifyingContract: ADDR_A },
			message: { target: ADDR_A },
		});
		const result = extractTypedDataAddresses(td);
		expect(result).toHaveLength(1);
		expect(result[0].fieldPath).toBe('domain.verifyingContract');
	});

	it('skips EIP712Domain type in walk', () => {
		const td = makeTypedData({
			types: {
				EIP712Domain: [{ name: 'verifyingContract', type: 'address' }],
				Root: [{ name: 'domain', type: 'EIP712Domain' }],
			},
			primaryType: 'Root',
			message: { domain: { verifyingContract: ADDR_A } },
		});
		const result = extractTypedDataAddresses(td);
		expect(result).toHaveLength(0);
	});

	it('respects MAX_ADDRESSES limit of 100', () => {
		const addresses = Array.from(
			{ length: 120 },
			(_, i) => `0x${i.toString(16).padStart(40, '0')}`,
		);
		const td = makeTypedData({
			types: {
				EIP712Domain: [],
				Huge: [{ name: 'addrs', type: 'address[]' }],
			},
			primaryType: 'Huge',
			message: { addrs: addresses },
		});
		const result = extractTypedDataAddresses(td);
		expect(result).toHaveLength(100);
	});
});

describe('extractPermitInfo', () => {
	describe('standard Permit (ERC-2612)', () => {
		it('extracts spender, value, deadline, token, tokenName', () => {
			const td = makeTypedData({
				types: {
					EIP712Domain: [],
					Permit: [
						{ name: 'owner', type: 'address' },
						{ name: 'spender', type: 'address' },
						{ name: 'value', type: 'uint256' },
						{ name: 'nonce', type: 'uint256' },
						{ name: 'deadline', type: 'uint256' },
					],
				},
				primaryType: 'Permit',
				domain: { name: 'USDC', verifyingContract: ADDR_A },
				message: { spender: ADDR_B, value: '1000000', deadline: '1700000000' },
			});
			const result = extractPermitInfo(td);
			expect(result).toEqual({
				type: 'permit',
				spender: ADDR_B,
				value: '1000000',
				deadline: '1700000000',
				token: ADDR_A,
				tokenName: 'USDC',
			});
		});

		it('uses expiry when deadline is absent', () => {
			const td = makeTypedData({
				types: {
					EIP712Domain: [],
					Permit: [
						{ name: 'spender', type: 'address' },
						{ name: 'value', type: 'uint256' },
						{ name: 'expiry', type: 'uint256' },
					],
				},
				primaryType: 'Permit',
				domain: {},
				message: { spender: ADDR_A, value: '500', expiry: '9999999' },
			});
			const result = extractPermitInfo(td);
			expect(result?.deadline).toBe('9999999');
		});

		it('returns null for invalid spender', () => {
			const td = makeTypedData({
				types: { EIP712Domain: [], Permit: [{ name: 'spender', type: 'address' }] },
				primaryType: 'Permit',
				message: { spender: 'not-an-address' },
			});
			expect(extractPermitInfo(td)).toBeNull();
		});
	});

	describe('DAI Permit', () => {
		it('detects dai-permit type with holder+allowed fields', () => {
			const td = makeTypedData({
				types: {
					EIP712Domain: [],
					Permit: [
						{ name: 'holder', type: 'address' },
						{ name: 'spender', type: 'address' },
						{ name: 'allowed', type: 'bool' },
						{ name: 'nonce', type: 'uint256' },
						{ name: 'expiry', type: 'uint256' },
					],
				},
				primaryType: 'Permit',
				domain: { name: 'Dai' },
				message: { holder: ADDR_A, spender: ADDR_B, allowed: true, expiry: '999' },
			});
			const result = extractPermitInfo(td);
			expect(result?.type).toBe('dai-permit');
			expect(result?.value).toBe('unlimited');
		});

		it('returns value "0" when allowed is false', () => {
			const td = makeTypedData({
				types: {
					EIP712Domain: [],
					Permit: [
						{ name: 'holder', type: 'address' },
						{ name: 'spender', type: 'address' },
						{ name: 'allowed', type: 'bool' },
					],
				},
				primaryType: 'Permit',
				domain: {},
				message: { spender: ADDR_A, allowed: false },
			});
			const result = extractPermitInfo(td);
			expect(result?.type).toBe('dai-permit');
			expect(result?.value).toBe('0');
		});
	});

	describe('PermitSingle', () => {
		it('extracts details.amount, details.token, sigDeadline', () => {
			const td = makeTypedData({
				types: { EIP712Domain: [], PermitSingle: [] },
				primaryType: 'PermitSingle',
				domain: {},
				message: {
					spender: ADDR_A,
					details: { amount: '5000', token: ADDR_B },
					sigDeadline: '1800000000',
				},
			});
			const result = extractPermitInfo(td);
			expect(result).toEqual({
				type: 'permit2-single',
				spender: ADDR_A,
				value: '5000',
				deadline: '1800000000',
				token: ADDR_B,
			});
		});

		it('handles missing details', () => {
			const td = makeTypedData({
				types: { EIP712Domain: [], PermitSingle: [] },
				primaryType: 'PermitSingle',
				domain: {},
				message: { spender: ADDR_A },
			});
			const result = extractPermitInfo(td);
			expect(result?.type).toBe('permit2-single');
			expect(result?.value).toBeUndefined();
			expect(result?.token).toBeUndefined();
		});
	});

	describe('PermitBatch', () => {
		it('extracts batch info with unlimited detection', () => {
			const td = makeTypedData({
				types: { EIP712Domain: [], PermitBatch: [] },
				primaryType: 'PermitBatch',
				domain: {},
				message: {
					spender: ADDR_A,
					details: [
						{ amount: '100', token: ADDR_B },
						{
							amount: '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
							token: ADDR_C,
						},
					],
					sigDeadline: '1800000000',
				},
			});
			const result = extractPermitInfo(td);
			expect(result?.type).toBe('permit2-batch');
			expect(result?.value).toBe('unlimited');
			expect(result?.token).toBe(ADDR_B);
			expect(result?.deadline).toBe('1800000000');
		});

		it('returns "batch" value when no unlimited amounts', () => {
			const td = makeTypedData({
				types: { EIP712Domain: [], PermitBatch: [] },
				primaryType: 'PermitBatch',
				domain: {},
				message: {
					spender: ADDR_A,
					details: [
						{ amount: '100', token: ADDR_B },
						{ amount: '200', token: ADDR_C },
					],
				},
			});
			const result = extractPermitInfo(td);
			expect(result?.value).toBe('batch');
		});

		it('returns null for empty details array', () => {
			const td = makeTypedData({
				types: { EIP712Domain: [], PermitBatch: [] },
				primaryType: 'PermitBatch',
				domain: {},
				message: { spender: ADDR_A, details: [] },
			});
			expect(extractPermitInfo(td)).toBeNull();
		});

		it('returns null for missing details', () => {
			const td = makeTypedData({
				types: { EIP712Domain: [], PermitBatch: [] },
				primaryType: 'PermitBatch',
				domain: {},
				message: { spender: ADDR_A },
			});
			expect(extractPermitInfo(td)).toBeNull();
		});
	});

	describe('PermitTransferFrom', () => {
		it('extracts permitted.amount and permitted.token', () => {
			const td = makeTypedData({
				types: { EIP712Domain: [], PermitTransferFrom: [] },
				primaryType: 'PermitTransferFrom',
				domain: {},
				message: {
					spender: ADDR_A,
					permitted: { amount: '7777', token: ADDR_B },
					deadline: '1900000000',
				},
			});
			const result = extractPermitInfo(td);
			expect(result).toEqual({
				type: 'permit2-transfer',
				spender: ADDR_A,
				value: '7777',
				deadline: '1900000000',
				token: ADDR_B,
			});
		});

		it('handles missing permitted', () => {
			const td = makeTypedData({
				types: { EIP712Domain: [], PermitTransferFrom: [] },
				primaryType: 'PermitTransferFrom',
				domain: {},
				message: { spender: ADDR_A },
			});
			const result = extractPermitInfo(td);
			expect(result?.value).toBeUndefined();
			expect(result?.token).toBeUndefined();
		});
	});

	describe('PermitWitnessTransferFrom', () => {
		it('returns permit2-witness-transfer type', () => {
			const td = makeTypedData({
				types: { EIP712Domain: [], PermitWitnessTransferFrom: [] },
				primaryType: 'PermitWitnessTransferFrom',
				domain: {},
				message: {
					spender: ADDR_A,
					permitted: { amount: '999', token: ADDR_B },
					deadline: '2000000000',
				},
			});
			const result = extractPermitInfo(td);
			expect(result?.type).toBe('permit2-witness-transfer');
			expect(result?.value).toBe('999');
			expect(result?.token).toBe(ADDR_B);
		});
	});

	it('returns null for invalid spender across all permit types', () => {
		for (const pt of [
			'Permit',
			'PermitSingle',
			'PermitBatch',
			'PermitTransferFrom',
			'PermitWitnessTransferFrom',
		]) {
			const td = makeTypedData({
				types: { EIP712Domain: [], [pt]: [] },
				primaryType: pt,
				domain: {},
				message: { spender: 'bad' },
			});
			expect(extractPermitInfo(td)).toBeNull();
		}
	});

	it('returns null for unknown primaryType', () => {
		const td = makeTypedData({
			types: { EIP712Domain: [], Unknown: [] },
			primaryType: 'Unknown',
			domain: {},
			message: { spender: ADDR_A },
		});
		expect(extractPermitInfo(td)).toBeNull();
	});

	it('handles missing optional fields gracefully', () => {
		const td = makeTypedData({
			types: {
				EIP712Domain: [],
				Permit: [
					{ name: 'spender', type: 'address' },
					{ name: 'value', type: 'uint256' },
				],
			},
			primaryType: 'Permit',
			domain: {},
			message: { spender: ADDR_A },
		});
		const result = extractPermitInfo(td);
		expect(result?.type).toBe('permit');
		expect(result?.value).toBe('');
		expect(result?.deadline).toBeUndefined();
		expect(result?.token).toBeUndefined();
		expect(result?.tokenName).toBeUndefined();
	});
});
