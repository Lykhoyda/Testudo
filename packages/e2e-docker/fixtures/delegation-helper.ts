import type { Page } from '@playwright/test';
import { expect } from '@playwright/test';

/**
 * Test contracts deployed to Anvil via `anvil_setCode`.
 *
 * Real mainnet bytecodes:
 *   - crime-enjoyer: 0x930fcc37... — real ETH auto-forwarder ($2.3M+ stolen, SunSec May 2025)
 *   - inferno-drainer: 0x00008c22... — real Inferno Drainer ($12M campaign, SlowMist May 2025)
 *
 * Synthetic bytecodes (impossible to source from mainnet):
 *   - metamorphic: CREATE2+SELFDESTRUCT contracts self-destruct by definition — bytecode gone from chain
 *   - safe-wallet: real smart wallets (Gnosis Safe, MetaMask delegator) trigger HIGH/CRITICAL from
 *     bytecode analysis due to DELEGATECALL+token patterns. A truly benign contract is needed to
 *     test the fail-open path for LOW-risk delegations.
 */
export const TEST_CONTRACTS = {
	'crime-enjoyer': '0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b',
	'inferno-drainer': '0x00008c22f9f6f3101533f520e229bbb54be90000',
	metamorphic: '0xCCCC000000000000000000000000000000000004',
	'safe-wallet': '0xCCCC000000000000000000000000000000000005',
} as const;

export type ContractKey = keyof typeof TEST_CONTRACTS;

export async function waitForTestudo(page: Page): Promise<void> {
	await page.waitForFunction(
		() =>
			(window as unknown as { __TESTUDO_LOADED__: boolean }).__TESTUDO_LOADED__ === true,
		null,
		{ timeout: 15_000 },
	);
}

export async function triggerDelegation(page: Page, contractKey: ContractKey): Promise<void> {
	const address = TEST_CONTRACTS[contractKey];

	await page.evaluate((addr) => {
		const typedData = {
			types: {
				EIP712Domain: [
					{ name: 'name', type: 'string' },
					{ name: 'version', type: 'string' },
					{ name: 'chainId', type: 'uint256' },
				],
				Authorization: [
					{ name: 'chainId', type: 'uint256' },
					{ name: 'address', type: 'address' },
					{ name: 'nonce', type: 'uint256' },
				],
			},
			primaryType: 'Authorization',
			domain: { name: 'EIP-7702 Authorization', version: '1', chainId: 1 },
			message: { chainId: '1', address: addr, nonce: '0' },
		};

		const ethereum = (window as unknown as { ethereum: { request: (a: unknown) => Promise<string> } }).ethereum;
		const statusEl = document.getElementById('status');

		ethereum.request({
			method: 'eth_signTypedData_v4',
			params: ['0x0000000000000000000000000000000000000001', JSON.stringify(typedData)],
		}).then((r) => {
			if (statusEl) statusEl.textContent = 'Signed: ' + r;
		}).catch((e: Error) => {
			if (statusEl) statusEl.textContent = 'Result: ' + (e.message || e);
		});
	}, address);
}

export async function blockDelegation(page: Page, contractKey: ContractKey): Promise<void> {
	await triggerDelegation(page, contractKey);

	const modal = page.locator('#testudo-warning-overlay');
	await expect(modal).toBeVisible({ timeout: 30_000 });
	await expect(page.locator('#testudo-cancel')).toBeVisible({ timeout: 30_000 });
	await page.click('#testudo-cancel');

	await expect(modal).not.toBeVisible({ timeout: 10_000 });
	await expect(page.locator('#status')).toContainText('Delegation blocked', {
		timeout: 10_000,
	});
}
