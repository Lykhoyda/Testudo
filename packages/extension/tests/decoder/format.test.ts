import { describe, expect, it } from 'vitest';
import { formatDeadline, formatTokenAmount, getChainName, isNeverExpiry } from '../../src/decoder/format';
import { MAX_UINT160, MAX_UINT256 } from '../../src/utils/constants';

describe('formatTokenAmount', () => {
	it('formats whole number with decimals and symbol', () => {
		const result = formatTokenAmount('1000000', 6, 'USDC');
		expect(result).toBe('1 USDC');
	});

	it('formats fractional amount', () => {
		const result = formatTokenAmount('1500000', 6, 'USDC');
		expect(result).toBe('1.5 USDC');
	});

	it('formats large amounts with locale separators', () => {
		const result = formatTokenAmount('1000000000000', 6, 'USDC');
		expect(result).toBe('1,000,000 USDC');
	});

	it('returns Unlimited for MAX_UINT256', () => {
		expect(formatTokenAmount(MAX_UINT256, 18, 'DAI')).toBe('Unlimited DAI');
	});

	it('returns Unlimited for MAX_UINT160', () => {
		expect(formatTokenAmount(MAX_UINT160, 18, 'USDC')).toBe('Unlimited USDC');
	});

	it('returns Unlimited without symbol for max values', () => {
		expect(formatTokenAmount(MAX_UINT256, 18, null)).toBe('Unlimited');
	});

	it('formats without decimals', () => {
		const result = formatTokenAmount('42', null, 'TOKEN');
		expect(result).toBe('42 TOKEN');
	});

	it('formats without symbol', () => {
		const result = formatTokenAmount('1000000', 6, null);
		expect(result).toBe('1');
	});

	it('returns raw value on parse error', () => {
		expect(formatTokenAmount('not-a-number', 6, 'USDC')).toBe('? USDC');
	});

	it('handles zero', () => {
		expect(formatTokenAmount('0', 18, 'ETH')).toBe('0 ETH');
	});

	it('handles 18-decimal token amounts', () => {
		const oneEth = '1000000000000000000';
		expect(formatTokenAmount(oneEth, 18, 'ETH')).toBe('1 ETH');
	});

	it('truncates long fractional parts to 6 digits', () => {
		const result = formatTokenAmount('1000000000000001', 18, 'ETH');
		expect(result).toMatch(/^0\.\d{1,6} ETH$/);
	});

	it('handles very large unlimited-like values', () => {
		const huge = '0x' + 'ff'.repeat(32);
		expect(formatTokenAmount(huge, 18, 'DAI')).toBe('Unlimited DAI');
	});
});

describe('isNeverExpiry', () => {
	it('returns true for MAX_UINT256', () => {
		expect(isNeverExpiry(MAX_UINT256)).toBe(true);
	});

	it('returns true for MAX_UINT160', () => {
		expect(isNeverExpiry(MAX_UINT160)).toBe(true);
	});

	it('returns false for normal timestamp', () => {
		expect(isNeverExpiry('1700000000')).toBe(false);
	});

	it('returns false for invalid string', () => {
		expect(isNeverExpiry('not-a-number')).toBe(false);
	});

	it('returns true for decimal MAX_UINT256', () => {
		const decimalMax = BigInt(MAX_UINT256).toString();
		expect(isNeverExpiry(decimalMax)).toBe(true);
	});
});

describe('formatDeadline', () => {
	it('returns Never for MAX_UINT256', () => {
		expect(formatDeadline(MAX_UINT256)).toBe('Never');
	});

	it('returns Never for MAX_UINT160', () => {
		expect(formatDeadline(MAX_UINT160)).toBe('Never');
	});

	it('formats a future date', () => {
		const futureTs = Math.floor(Date.now() / 1000) + 3600;
		const result = formatDeadline(String(futureTs));
		expect(result).toContain('in');
	});

	it('marks expired dates', () => {
		const pastTs = Math.floor(Date.now() / 1000) - 86400;
		const result = formatDeadline(String(pastTs));
		expect(result).toContain('expired');
	});

	it('returns raw value for invalid input', () => {
		expect(formatDeadline('garbage')).toBe('garbage');
	});

	it('returns raw for zero', () => {
		expect(formatDeadline('0')).toBe('0');
	});
});

describe('getChainName', () => {
	it('returns Ethereum for chainId 1', () => {
		expect(getChainName(1)).toBe('Ethereum');
	});

	it('returns Base for chainId 8453', () => {
		expect(getChainName(8453)).toBe('Base');
	});

	it('returns Arbitrum One for chainId 42161', () => {
		expect(getChainName(42161)).toBe('Arbitrum One');
	});

	it('returns Polygon for chainId 137', () => {
		expect(getChainName(137)).toBe('Polygon');
	});

	it('returns Optimism for chainId 10', () => {
		expect(getChainName(10)).toBe('Optimism');
	});

	it('returns undefined for unknown chainId', () => {
		expect(getChainName(99999)).toBeUndefined();
	});

	it('returns undefined for undefined input', () => {
		expect(getChainName(undefined)).toBeUndefined();
	});

	it('handles string chainId', () => {
		expect(getChainName('1')).toBe('Ethereum');
	});

	it('returns Sepolia for chainId 11155111', () => {
		expect(getChainName(11155111)).toBe('Sepolia');
	});
});
