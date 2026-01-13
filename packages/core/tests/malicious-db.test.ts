import { describe, expect, it } from 'vitest';
import { checkKnownMalicious } from '../src/malicious-db';

describe('checkKnownMalicious', () => {
	describe('should detect known malicious contracts', () => {
		it('detects ETH_AUTO_FORWARDER contract', () => {
			const result = checkKnownMalicious('0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b');

			expect(result).not.toBeNull();
			expect(result?.type).toBe('ETH_AUTO_FORWARDER');
			expect(result?.source).toBe('SunSec Report May 2025');
			expect(result?.stolen).toBe('$2.3M+');
		});

		it('detects INFERNO_DRAINER contract', () => {
			const result = checkKnownMalicious('0xa85d90b8febc092e11e75bf8f93a7090e2ed04de');

			expect(result).not.toBeNull();
			expect(result?.type).toBe('INFERNO_DRAINER');
		});

		it('handles uppercase addresses', () => {
			const result = checkKnownMalicious('0x930FCC37D6042C79211EE18A02857CB1FD7F0D0B');

			expect(result).not.toBeNull();
			expect(result?.type).toBe('ETH_AUTO_FORWARDER');
		});

		it('handles mixed case addresses', () => {
			const result = checkKnownMalicious('0x930Fcc37d6042c79211Ee18a02857cb1fd7f0d0B');

			expect(result).not.toBeNull();
		});
	});

	describe('should return null for unknown contracts', () => {
		it('returns null for MetaMask legitimate delegator', () => {
			const result = checkKnownMalicious('0x63c0c19a282a1b52b07dd5a65b58948a07dae32b');

			expect(result).toBeNull();
		});

		it('returns null for random address', () => {
			const result = checkKnownMalicious('0x0000000000000000000000000000000000000001');

			expect(result).toBeNull();
		});

		it('returns null for zero address', () => {
			const result = checkKnownMalicious('0x0000000000000000000000000000000000000000');

			expect(result).toBeNull();
		});
	});

	describe('edge cases', () => {
		it('handles address without 0x prefix gracefully', () => {
			const result = checkKnownMalicious('930fcc37d6042c79211ee18a02857cb1fd7f0d0b');
			expect(result).toBeNull();
		});
	});
});
