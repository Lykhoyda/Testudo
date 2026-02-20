import { requestTokenResolve } from '../services/messaging';
import type { TokenInfo } from '../utils/types';

const MAX_CACHE_SIZE = 500;

const WELL_KNOWN_TOKENS: Record<string, Omit<TokenInfo, 'address'>> = {
	'0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48': {
		symbol: 'USDC',
		decimals: 6,
		name: 'USD Coin',
		isVerified: true,
	},
	'0xdac17f958d2ee523a2206206994597c13d831ec7': {
		symbol: 'USDT',
		decimals: 6,
		name: 'Tether USD',
		isVerified: true,
	},
	'0x6b175474e89094c44da98b954eedeac495271d0f': {
		symbol: 'DAI',
		decimals: 18,
		name: 'Dai Stablecoin',
		isVerified: true,
	},
	'0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2': {
		symbol: 'WETH',
		decimals: 18,
		name: 'Wrapped Ether',
		isVerified: true,
	},
	'0x2260fac5e5542a773aa44fbcfedf7c193bc2c599': {
		symbol: 'WBTC',
		decimals: 8,
		name: 'Wrapped BTC',
		isVerified: true,
	},
	'0x514910771af9ca656af840dff83e8264ecf986ca': {
		symbol: 'LINK',
		decimals: 18,
		name: 'ChainLink Token',
		isVerified: true,
	},
	'0x1f9840a85d5af5bf1d1762f925bdaddc4201f984': {
		symbol: 'UNI',
		decimals: 18,
		name: 'Uniswap',
		isVerified: true,
	},
	'0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9': {
		symbol: 'AAVE',
		decimals: 18,
		name: 'Aave Token',
		isVerified: true,
	},
	'0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2': {
		symbol: 'MKR',
		decimals: 18,
		name: 'Maker',
		isVerified: true,
	},
	'0xae7ab96520de3a18e5e111b5eaab095312d7fe84': {
		symbol: 'stETH',
		decimals: 18,
		name: 'Liquid staked Ether 2.0',
		isVerified: true,
	},
	'0xbe9895146f7af43049ca1c1ae358b0541ea49704': {
		symbol: 'cbETH',
		decimals: 18,
		name: 'Coinbase Wrapped Staked ETH',
		isVerified: true,
	},
	'0x853d955acef822db058eb8505911ed77f175b99e': {
		symbol: 'FRAX',
		decimals: 18,
		name: 'Frax',
		isVerified: true,
	},
	'0x4fabb145d64652a948d72533023f6e7a623c7c53': {
		symbol: 'BUSD',
		decimals: 18,
		name: 'Binance USD',
		isVerified: true,
	},
	'0x95ad61b0a150d79219dcf64e1e6cc01f0b64c4ce': {
		symbol: 'SHIB',
		decimals: 18,
		name: 'SHIBA INU',
		isVerified: true,
	},
};

const cache = new Map<string, TokenInfo>();

export function getInstantToken(address: string): TokenInfo | null {
	const normalized = address.toLowerCase();
	const cached = cache.get(normalized);
	if (cached) return cached;
	const wellKnown = WELL_KNOWN_TOKENS[normalized];
	if (wellKnown) {
		const info: TokenInfo = { address: normalized, ...wellKnown };
		cache.set(normalized, info);
		return info;
	}
	return null;
}

export async function resolveToken(address: string): Promise<TokenInfo> {
	const instant = getInstantToken(address);
	if (instant) return instant;

	const normalized = address.toLowerCase();
	const result = await requestTokenResolve(normalized);
	const info: TokenInfo = {
		address: normalized,
		name: result.name,
		symbol: result.symbol,
		decimals: result.decimals,
		isVerified: false,
	};

	cacheSet(normalized, info);
	return info;
}

function cacheSet(key: string, value: TokenInfo): void {
	if (cache.size >= MAX_CACHE_SIZE) cache.clear();
	cache.set(key, value);
}

export function clearTokenCache(): void {
	cache.clear();
}
