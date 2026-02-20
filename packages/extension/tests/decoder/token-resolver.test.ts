import { afterEach, describe, expect, it, vi } from 'vitest';
import { clearTokenCache, getInstantToken, resolveToken } from '../../src/decoder/token-resolver';

vi.mock('../../src/services/messaging', () => ({
	requestTokenResolve: vi.fn(),
}));

import { requestTokenResolve } from '../../src/services/messaging';

const mockRequestTokenResolve = vi.mocked(requestTokenResolve);

afterEach(() => {
	clearTokenCache();
	vi.clearAllMocks();
});

describe('getInstantToken', () => {
	it('returns null for unknown address', () => {
		expect(getInstantToken('0x0000000000000000000000000000000000000001')).toBeNull();
	});

	it('returns well-known token without prior cache population', () => {
		const info = getInstantToken('0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48');
		expect(info).not.toBeNull();
		expect(info?.symbol).toBe('USDC');
		expect(info?.decimals).toBe(6);
		expect(info?.name).toBe('USD Coin');
		expect(info?.isVerified).toBe(true);
	});

	it('normalizes addresses to lowercase', () => {
		const info = getInstantToken('0xA0B86991C6218B36C1D19D4A2E9EB0CE3606EB48');
		expect(info).not.toBeNull();
		expect(info?.symbol).toBe('USDC');
	});

	it('populates cache on well-known hit', () => {
		getInstantToken('0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48');
		const cached = getInstantToken('0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48');
		expect(cached).not.toBeNull();
		expect(cached?.symbol).toBe('USDC');
	});

	it('returns cached token from previous resolveToken call', async () => {
		mockRequestTokenResolve.mockResolvedValue({
			name: 'Test Token',
			symbol: 'TEST',
			decimals: 18,
		});

		await resolveToken('0x0000000000000000000000000000000000000099');
		const instant = getInstantToken('0x0000000000000000000000000000000000000099');
		expect(instant).not.toBeNull();
		expect(instant?.symbol).toBe('TEST');
		expect(instant?.isVerified).toBe(false);
	});
});

describe('resolveToken — well-known tokens', () => {
	it('resolves USDC with isVerified', async () => {
		const info = await resolveToken('0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48');
		expect(info.symbol).toBe('USDC');
		expect(info.decimals).toBe(6);
		expect(info.name).toBe('USD Coin');
		expect(info.isVerified).toBe(true);
	});

	it('resolves WETH', async () => {
		const info = await resolveToken('0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2');
		expect(info.symbol).toBe('WETH');
		expect(info.decimals).toBe(18);
	});

	it('resolves DAI', async () => {
		const info = await resolveToken('0x6B175474E89094C44Da98b954EedeAC495271d0F');
		expect(info.symbol).toBe('DAI');
		expect(info.decimals).toBe(18);
	});

	it('resolves USDT', async () => {
		const info = await resolveToken('0xdAC17F958D2ee523a2206206994597C13D831ec7');
		expect(info.symbol).toBe('USDT');
		expect(info.decimals).toBe(6);
	});

	it('resolves WBTC', async () => {
		const info = await resolveToken('0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599');
		expect(info.symbol).toBe('WBTC');
		expect(info.decimals).toBe(8);
	});

	it('normalizes addresses to lowercase', async () => {
		const info = await resolveToken('0xA0B86991C6218B36C1D19D4A2E9EB0CE3606EB48');
		expect(info.symbol).toBe('USDC');
	});

	it('does not call messaging bridge for well-known tokens', async () => {
		await resolveToken('0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48');
		expect(mockRequestTokenResolve).not.toHaveBeenCalled();
	});
});

describe('resolveToken — messaging bridge fallback', () => {
	it('returns unverified result with null fields when bridge returns no data', async () => {
		mockRequestTokenResolve.mockResolvedValue({ name: null, symbol: null, decimals: null });

		const info = await resolveToken('0x0000000000000000000000000000000000000001');
		expect(info.symbol).toBeNull();
		expect(info.decimals).toBeNull();
		expect(info.name).toBeNull();
		expect(info.address).toBe('0x0000000000000000000000000000000000000001');
		expect(info.isVerified).toBe(false);
	});

	it('caches result to avoid repeated bridge calls', async () => {
		mockRequestTokenResolve.mockResolvedValue({ name: null, symbol: null, decimals: null });

		await resolveToken('0x0000000000000000000000000000000000000002');
		await resolveToken('0x0000000000000000000000000000000000000002');
		expect(mockRequestTokenResolve).toHaveBeenCalledTimes(1);
	});

	it('resolves token metadata via bridge', async () => {
		mockRequestTokenResolve.mockResolvedValue({
			name: 'Test Token',
			symbol: 'TEST',
			decimals: 18,
		});

		const info = await resolveToken('0x0000000000000000000000000000000000000004');
		expect(info.name).toBe('Test Token');
		expect(info.symbol).toBe('TEST');
		expect(info.decimals).toBe(18);
		expect(info.isVerified).toBe(false);
		expect(mockRequestTokenResolve).toHaveBeenCalledWith(
			'0x0000000000000000000000000000000000000004',
		);
	});

	it('handles null fields from bridge gracefully', async () => {
		mockRequestTokenResolve.mockResolvedValue({
			name: null,
			symbol: null,
			decimals: null,
		});

		const info = await resolveToken('0x0000000000000000000000000000000000000005');
		expect(info.name).toBeNull();
		expect(info.symbol).toBeNull();
		expect(info.decimals).toBeNull();
		expect(info.isVerified).toBe(false);
	});
});
