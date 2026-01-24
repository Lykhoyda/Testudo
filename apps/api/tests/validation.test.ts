import { describe, expect, it } from 'vitest';
import {
	isValidAddress,
	isValidDomain,
	normalizeAddress,
	normalizeDomain,
} from '../src/utils/validation.js';

describe('isValidAddress', () => {
	it('accepts valid checksummed address', () => {
		expect(isValidAddress('0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b')).toBe(true);
	});

	it('accepts valid uppercase address', () => {
		expect(isValidAddress('0x930FCC37D6042C79211EE18A02857CB1FD7F0D0B')).toBe(true);
	});

	it('accepts valid mixed-case address', () => {
		expect(isValidAddress('0xAbCdEf0123456789AbCdEf0123456789AbCdEf01')).toBe(true);
	});

	it('rejects address without 0x prefix', () => {
		expect(isValidAddress('930fcc37d6042c79211ee18a02857cb1fd7f0d0b')).toBe(false);
	});

	it('rejects address too short', () => {
		expect(isValidAddress('0x930fcc37d6042c79211ee18a02857cb1fd7f0d')).toBe(false);
	});

	it('rejects address too long', () => {
		expect(isValidAddress('0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b00')).toBe(false);
	});

	it('rejects address with invalid characters', () => {
		expect(isValidAddress('0xGGGfcc37d6042c79211ee18a02857cb1fd7f0d0b')).toBe(false);
	});

	it('rejects empty string', () => {
		expect(isValidAddress('')).toBe(false);
	});

	it('rejects random string', () => {
		expect(isValidAddress('not-an-address')).toBe(false);
	});
});

describe('normalizeAddress', () => {
	it('lowercases address', () => {
		expect(normalizeAddress('0xAbCdEf0123456789AbCdEf0123456789AbCdEf01')).toBe(
			'0xabcdef0123456789abcdef0123456789abcdef01',
		);
	});

	it('keeps already-lowercase address unchanged', () => {
		const addr = '0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b';
		expect(normalizeAddress(addr)).toBe(addr);
	});
});

describe('normalizeDomain', () => {
	it('lowercases domain', () => {
		expect(normalizeDomain('Example.COM')).toBe('example.com');
	});

	it('strips www prefix', () => {
		expect(normalizeDomain('www.example.com')).toBe('example.com');
	});

	it('strips protocol and path from full URL', () => {
		expect(normalizeDomain('https://www.example.com/path/page')).toBe('example.com');
	});

	it('strips http protocol', () => {
		expect(normalizeDomain('http://malicious.site')).toBe('malicious.site');
	});

	it('handles domain with trailing slash', () => {
		expect(normalizeDomain('example.com/')).toBe('example.com');
	});

	it('handles domain with port in URL', () => {
		expect(normalizeDomain('https://example.com:8080/path')).toBe('example.com');
	});

	it('handles bare domain', () => {
		expect(normalizeDomain('uniswap.org')).toBe('uniswap.org');
	});

	it('handles subdomain', () => {
		expect(normalizeDomain('app.uniswap.org')).toBe('app.uniswap.org');
	});
});

describe('isValidDomain', () => {
	it('accepts valid domain', () => {
		expect(isValidDomain('example.com')).toBe(true);
	});

	it('accepts domain with subdomain', () => {
		expect(isValidDomain('app.example.com')).toBe(true);
	});

	it('accepts domain with www prefix (stripped during normalization)', () => {
		expect(isValidDomain('www.example.com')).toBe(true);
	});

	it('accepts full URL (normalized to domain)', () => {
		expect(isValidDomain('https://example.com/path')).toBe(true);
	});

	it('rejects domain without TLD', () => {
		expect(isValidDomain('localhost')).toBe(false);
	});

	it('rejects domain starting with dot', () => {
		expect(isValidDomain('.com')).toBe(false);
	});

	it('rejects very short input', () => {
		expect(isValidDomain('a')).toBe(false);
	});

	it('rejects empty string', () => {
		expect(isValidDomain('')).toBe(false);
	});
});
