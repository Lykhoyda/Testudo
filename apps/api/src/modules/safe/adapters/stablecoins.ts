import type { AdapterResult, RawSafeAddressEntry } from './types.js';

const SOURCE_NAME = 'stablecoins';

const STABLECOINS: RawSafeAddressEntry[] = [
	{ address: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48', name: 'USDC', category: 'STABLECOIN' },
	{ address: '0xdac17f958d2ee523a2206206994597c13d831ec7', name: 'USDT', category: 'STABLECOIN' },
	{ address: '0x6b175474e89094c44da98b954eedeac495271d0f', name: 'DAI', category: 'STABLECOIN' },
	{ address: '0x4fabb145d64652a948d72533023f6e7a623c7c53', name: 'BUSD', category: 'STABLECOIN' },
	{ address: '0x853d955acef822db058eb8505911ed77f175b99e', name: 'FRAX', category: 'STABLECOIN' },
	{ address: '0x8e870d67f660d95d5be530380d0ec0bd388289e1', name: 'USDP', category: 'STABLECOIN' },
	{ address: '0x0000000000085d4780b73119b644ae5ecd22b376', name: 'TUSD', category: 'STABLECOIN' },
	{ address: '0x5f98805a4e8be255a32880fdec7f6728c6568ba0', name: 'LUSD', category: 'STABLECOIN' },
];

export async function fetchSafeAddresses(): Promise<AdapterResult<RawSafeAddressEntry>> {
	return { source: SOURCE_NAME, entries: STABLECOINS, fetchedAt: new Date() };
}
