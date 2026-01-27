import type { AdapterResult, RawSafeAddressEntry } from './types.js';

const SOURCE_NAME = 'eip7702-delegates';

const KNOWN_DELEGATES: RawSafeAddressEntry[] = [
	{
		address: '0x63c0c19a282a1b52b07dd5a65b58948a07dae32b',
		name: 'MetaMask Delegator',
		category: 'EIP7702_DELEGATE',
		isDelegationSafe: true,
	},
];

export async function fetchSafeAddresses(): Promise<AdapterResult<RawSafeAddressEntry>> {
	return { source: SOURCE_NAME, entries: KNOWN_DELEGATES, fetchedAt: new Date() };
}
