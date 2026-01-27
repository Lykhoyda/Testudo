import { describe, expect, it } from 'vitest';
import { fetchSafeAddresses as fetchStablecoins } from '../../../../src/modules/safe/adapters/stablecoins.js';
import { fetchSafeAddresses as fetchSafeContracts } from '../../../../src/modules/safe/adapters/safe-contracts.js';
import { fetchSafeAddresses as fetchL2Bridges } from '../../../../src/modules/safe/adapters/l2-bridges.js';
import { fetchSafeAddresses as fetchEip7702 } from '../../../../src/modules/safe/adapters/eip7702-delegates.js';

describe('Static safe adapters', () => {
	it('stablecoins returns hardcoded entries', async () => {
		const result = await fetchStablecoins();
		expect(result.source).toBe('stablecoins');
		expect(result.entries.length).toBeGreaterThanOrEqual(5);
		expect(result.entries[0].category).toBe('STABLECOIN');
		expect(result.entries[0].address).toMatch(/^0x[a-f0-9]{40}$/);
	});

	it('safe-contracts returns singletons with isDelegationSafe', async () => {
		const result = await fetchSafeContracts();
		expect(result.source).toBe('safe-contracts');
		expect(result.entries.length).toBeGreaterThanOrEqual(3);
		expect(result.entries.every((e) => e.isDelegationSafe === true)).toBe(true);
		expect(result.entries[0].category).toBe('SAFE_WALLET');
	});

	it('l2-bridges returns canonical bridges', async () => {
		const result = await fetchL2Bridges();
		expect(result.source).toBe('l2-bridges');
		expect(result.entries.length).toBeGreaterThanOrEqual(5);
		expect(result.entries[0].category).toBe('BRIDGE');
	});

	it('eip7702-delegates returns MetaMask delegator', async () => {
		const result = await fetchEip7702();
		expect(result.source).toBe('eip7702-delegates');
		expect(result.entries.length).toBeGreaterThanOrEqual(1);
		expect(result.entries[0].address).toBe('0x63c0c19a282a1b52b07dd5a65b58948a07dae32b');
		expect(result.entries[0].isDelegationSafe).toBe(true);
	});
});
