import { describe, expect, it } from 'vitest';
import { normalizeDomain } from '../../src/phishing/normalize';

describe('normalizeDomain', () => {
	it('extracts hostname and registrable domain', () => {
		const result = normalizeDomain('https://evil.com/steal?token=abc');
		expect(result).toEqual({
			hostname: 'evil.com',
			registrable: 'evil.com',
			isIP: false,
		});
	});

	it('strips www prefix', () => {
		const result = normalizeDomain('https://www.uniswap.org/swap');
		expect(result).toEqual({
			hostname: 'uniswap.org',
			registrable: 'uniswap.org',
			isIP: false,
		});
	});

	it('lowercases hostname', () => {
		const result = normalizeDomain('https://EVIL.COM/phish');
		expect(result).toEqual({
			hostname: 'evil.com',
			registrable: 'evil.com',
			isIP: false,
		});
	});

	it('strips trailing dot', () => {
		const result = normalizeDomain('https://evil.com./path');
		expect(result).toEqual({
			hostname: 'evil.com',
			registrable: 'evil.com',
			isIP: false,
		});
	});

	it('handles Punycode/IDN automatically', () => {
		// ünïcödé.com in Punycode is xn--ncd3b4bzc.com (browser URL API converts it)
		const result = normalizeDomain('https://xn--ncd3b4bzc.com/');
		expect(result).not.toBeNull();
		expect(result?.isIP).toBe(false);
		expect(result?.hostname).toBe('xn--ncd3b4bzc.com');
	});

	it('handles co.uk eTLD correctly', () => {
		const result = normalizeDomain('https://subdomain.evil.co.uk/drain');
		expect(result).toEqual({
			hostname: 'subdomain.evil.co.uk',
			registrable: 'evil.co.uk',
			isIP: false,
		});
	});

	it('handles github.io private domain correctly', () => {
		const result = normalizeDomain('https://attacker.github.io/fake-uniswap');
		expect(result).toEqual({
			hostname: 'attacker.github.io',
			registrable: 'attacker.github.io',
			isIP: false,
		});
	});

	it('flags IP literals', () => {
		const result = normalizeDomain('http://192.168.1.1/drain');
		expect(result).toEqual({
			hostname: '192.168.1.1',
			registrable: '192.168.1.1',
			isIP: true,
		});
	});

	it('flags IPv6 literals', () => {
		const result = normalizeDomain('http://[::1]/drain');
		expect(result).toEqual({
			hostname: '[::1]',
			registrable: '[::1]',
			isIP: true,
		});
	});

	it('returns null for data: scheme', () => {
		expect(normalizeDomain('data:text/html,<h1>phish</h1>')).toBeNull();
	});

	it('returns null for blob: scheme', () => {
		expect(
			normalizeDomain('blob:https://evil.com/550e8400-e29b-41d4-a716-446655440000'),
		).toBeNull();
	});

	it('returns null for javascript: scheme', () => {
		expect(normalizeDomain('javascript:alert(1)')).toBeNull();
	});

	it('returns null for invalid URL', () => {
		expect(normalizeDomain('not a url at all')).toBeNull();
	});

	it('handles chrome-extension: scheme (returns null)', () => {
		expect(normalizeDomain('chrome-extension://abcdefghijklmnop/popup.html')).toBeNull();
	});

	it('handles port numbers (ignores them)', () => {
		const result = normalizeDomain('https://evil.com:8443/drain');
		expect(result).toEqual({
			hostname: 'evil.com',
			registrable: 'evil.com',
			isIP: false,
		});
	});

	it('handles subdomain chains', () => {
		const result = normalizeDomain('https://a.b.c.evil.com/phish');
		expect(result).toEqual({
			hostname: 'a.b.c.evil.com',
			registrable: 'evil.com',
			isIP: false,
		});
	});
});
