import type { AdapterResult, RawSafeAddressEntry } from './types.js';

const SOURCE_NAME = 'safe-contracts';

const SAFE_SINGLETONS: RawSafeAddressEntry[] = [
	{ address: '0xd9db270c1b5e3bd161e8c8503c55ceabee709552', name: 'Safe v1.3.0 Singleton', category: 'SAFE_WALLET', isDelegationSafe: true },
	{ address: '0x41675c099f32341bf84bfc5382af534df5c7461a', name: 'Safe v1.4.1 Singleton', category: 'SAFE_WALLET', isDelegationSafe: true },
	{ address: '0x29fcb43b46531bca003ddc8a9f1ef3735a360269', name: 'Safe v1.4.1 Singleton (L2)', category: 'SAFE_WALLET', isDelegationSafe: true },
	{ address: '0xa6b71e26c5e0845f74c812102ca7114b6a896ab2', name: 'Safe Proxy Factory v1.3.0', category: 'SAFE_WALLET', isDelegationSafe: true },
	{ address: '0x4e1dcf7ad4e460cfd30791ccc4f9c8a4f820ec67', name: 'Safe Proxy Factory v1.4.1', category: 'SAFE_WALLET', isDelegationSafe: true },
	{ address: '0xf48f2b2d2a534e402487b3ee7c18c33aec0fe5e4', name: 'Safe Compatibility Fallback Handler', category: 'SAFE_WALLET', isDelegationSafe: true },
];

export async function fetchSafeAddresses(): Promise<AdapterResult<RawSafeAddressEntry>> {
	return { source: SOURCE_NAME, entries: SAFE_SINGLETONS, fetchedAt: new Date() };
}
