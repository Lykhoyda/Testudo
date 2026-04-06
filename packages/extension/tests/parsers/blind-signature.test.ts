import { describe, expect, it } from 'vitest';
import { isBlindSignature, parseBlindSignature } from '../../src/parsers/blind-signature';

describe('isBlindSignature', () => {
	it('returns true for personal_sign', () => {
		expect(isBlindSignature('personal_sign')).toBe(true);
	});

	it('returns false for eth_sign', () => {
		expect(isBlindSignature('eth_sign')).toBe(false);
	});

	it('returns false for eth_signTypedData_v4', () => {
		expect(isBlindSignature('eth_signTypedData_v4')).toBe(false);
	});

	it('returns false for empty string', () => {
		expect(isBlindSignature('')).toBe(false);
	});
});

describe('parseBlindSignature', () => {
	const validSigner = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';

	it('returns null for non-array params', () => {
		expect(parseBlindSignature('personal_sign', 'not-an-array' as unknown as unknown[])).toBeNull();
	});

	it('returns null for params with fewer than 2 elements', () => {
		expect(parseBlindSignature('personal_sign', ['only-one'])).toBeNull();
		expect(parseBlindSignature('personal_sign', [])).toBeNull();
	});

	it('returns null for invalid signer address — wrong length', () => {
		expect(parseBlindSignature('personal_sign', ['hello', '0xTOOSHORT'])).toBeNull();
	});

	it('returns null for invalid signer address — missing 0x prefix', () => {
		expect(
			parseBlindSignature('personal_sign', ['hello', 'd8dA6BF26964aF9D7eEd9e03E53415D37aA96045']),
		).toBeNull();
	});

	it('personal_sign: first param is message, second is signer', () => {
		const result = parseBlindSignature('personal_sign', ['hello world', validSigner]);
		expect(result).not.toBeNull();
		expect(result?.message).toBe('hello world');
		expect(result?.signer).toBe(validSigner.toLowerCase());
		expect(result?.type).toBe('personal_sign');
	});

	it('eth_sign: first param is signer, second is message', () => {
		const result = parseBlindSignature('eth_sign', [validSigner, '0xdeadbeef']);
		expect(result).not.toBeNull();
		expect(result?.message).toBe('0xdeadbeef');
		expect(result?.signer).toBe(validSigner.toLowerCase());
		expect(result?.type).toBe('eth_sign');
	});

	it('decodes hex message to ASCII when all printable', () => {
		const hex = `0x${Buffer.from('Hello World').toString('hex')}`;
		const result = parseBlindSignature('personal_sign', [hex, validSigner]);
		expect(result).not.toBeNull();
		expect(result?.decodedMessage).toBe('Hello World');
		expect(result?.isHex).toBe(true);
	});

	it('keeps original hex when decoded bytes contain non-printable characters', () => {
		const hex = '0x00010203';
		const result = parseBlindSignature('personal_sign', [hex, validSigner]);
		expect(result).not.toBeNull();
		expect(result?.decodedMessage).toBe(hex);
		expect(result?.isHex).toBe(true);
	});

	it('truncates message preview at 100 chars', () => {
		const longMessage = 'A'.repeat(200);
		const result = parseBlindSignature('personal_sign', [longMessage, validSigner]);
		expect(result).not.toBeNull();
		expect(result?.messagePreview.length).toBe(100);
		expect(result?.messagePreview).toBe(`${'A'.repeat(97)}...`);
	});

	it('does not truncate short messages', () => {
		const result = parseBlindSignature('personal_sign', ['short msg', validSigner]);
		expect(result).not.toBeNull();
		expect(result?.messagePreview).toBe('short msg');
	});

	it('lowercases the signer address', () => {
		const mixedCase = '0xAbCdEf0123456789AbCdEf0123456789AbCdEf01';
		const result = parseBlindSignature('personal_sign', ['msg', mixedCase]);
		expect(result).not.toBeNull();
		expect(result?.signer).toBe(mixedCase.toLowerCase());
	});

	it('sets isHex true for hex messages', () => {
		const result = parseBlindSignature('personal_sign', ['0xabcdef', validSigner]);
		expect(result).not.toBeNull();
		expect(result?.isHex).toBe(true);
	});

	it('sets isHex false for non-hex messages', () => {
		const result = parseBlindSignature('personal_sign', ['plain text', validSigner]);
		expect(result).not.toBeNull();
		expect(result?.isHex).toBe(false);
	});

	it('preserves plain text message as-is', () => {
		const result = parseBlindSignature('personal_sign', ['Sign this message', validSigner]);
		expect(result).not.toBeNull();
		expect(result?.message).toBe('Sign this message');
		expect(result?.decodedMessage).toBe('Sign this message');
	});
});
