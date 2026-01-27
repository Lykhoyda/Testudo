import type { AdapterResult, RawSafeAddressEntry } from './types.js';

const SOURCE_NAME = 'l2-bridges';

const CANONICAL_BRIDGES: RawSafeAddressEntry[] = [
	{
		address: '0x99c9fc46f92e8a1c0dec1b1747d010903e884be1',
		name: 'Optimism L1 Bridge',
		category: 'BRIDGE',
	},
	{
		address: '0x3154cf16ccdb4c6d922629664174b904d80f2c35',
		name: 'Base L1 Bridge',
		category: 'BRIDGE',
	},
	{
		address: '0xabea9132b05a70803a4e85094fd0e1800777fbef',
		name: 'zkSync Era Diamond Proxy',
		category: 'BRIDGE',
	},
	{
		address: '0x8315177ab297ba92a06054ce80a67ed4dbd7ed3a',
		name: 'Arbitrum Delayed Inbox',
		category: 'BRIDGE',
	},
	{
		address: '0xa3a7b6f88361f48403514059f1f16c8e78d60eec',
		name: 'Arbitrum One Bridge',
		category: 'BRIDGE',
	},
	{
		address: '0x2a3dd3eb832af982ec71669e178424b10dca2ede',
		name: 'Polygon zkEVM Bridge',
		category: 'BRIDGE',
	},
	{
		address: '0x32400084c286cf3e17e7b677ea9583e60a000324',
		name: 'zkSync Era Mailbox',
		category: 'BRIDGE',
	},
	{
		address: '0x49048044d57e1c92a77f79988d21fa8faf74e97e',
		name: 'Base Portal',
		category: 'BRIDGE',
	},
];

export async function fetchSafeAddresses(): Promise<AdapterResult<RawSafeAddressEntry>> {
	return { source: SOURCE_NAME, entries: CANONICAL_BRIDGES, fetchedAt: new Date() };
}
