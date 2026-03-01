import {
	ANVIL_ACCOUNT_0,
	getEthBalance,
	getTokenAllowance,
	getTokenBalance,
} from '../fixtures/anvil-rpc';
import { blockDelegation, waitForTestudo } from '../fixtures/delegation-helper';
import { expect, test } from '../fixtures/synpress';

const MOCK_TOKEN = '0xCCCC000000000000000000000000000000000006';
const SPENDER = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';

test.describe('Fund Safety After Blocking', () => {
	test('ETH balance is preserved after blocking malicious delegation', async ({
		page,
		// biome-ignore lint/correctness/noUnusedFunctionParameters: triggers fixture setup
		testudoExtensionId,
	}) => {
		await page.goto('/');
		await waitForTestudo(page);

		const balanceBefore = await getEthBalance(ANVIL_ACCOUNT_0);
		expect(balanceBefore).toBeGreaterThan(0n);

		await blockDelegation(page, 'inferno-drainer');

		const balanceAfter = await getEthBalance(ANVIL_ACCOUNT_0);
		expect(balanceAfter).toBe(balanceBefore);
	});

	test('ERC-20 token balance is preserved after blocking malicious delegation', async ({
		page,
		// biome-ignore lint/correctness/noUnusedFunctionParameters: triggers fixture setup
		testudoExtensionId,
	}) => {
		await page.goto('/');
		await waitForTestudo(page);

		const balanceBefore = await getTokenBalance(MOCK_TOKEN, ANVIL_ACCOUNT_0);
		expect(balanceBefore).toBeGreaterThan(0n);

		await blockDelegation(page, 'inferno-drainer');

		const balanceAfter = await getTokenBalance(MOCK_TOKEN, ANVIL_ACCOUNT_0);
		expect(balanceAfter).toBe(balanceBefore);
	});

	test('no token approvals are granted after blocking malicious delegation', async ({
		page,
		// biome-ignore lint/correctness/noUnusedFunctionParameters: triggers fixture setup
		testudoExtensionId,
	}) => {
		await page.goto('/');
		await waitForTestudo(page);

		const allowanceBefore = await getTokenAllowance(MOCK_TOKEN, ANVIL_ACCOUNT_0, SPENDER);
		expect(allowanceBefore).toBe(0n);

		await blockDelegation(page, 'inferno-drainer');

		const allowanceAfter = await getTokenAllowance(MOCK_TOKEN, ANVIL_ACCOUNT_0, SPENDER);
		expect(allowanceAfter).toBe(0n);
	});

	test('all assets remain protected after multiple blocked delegations', async ({
		page,
		// biome-ignore lint/correctness/noUnusedFunctionParameters: triggers fixture setup
		testudoExtensionId,
	}) => {
		await page.goto('/');
		await waitForTestudo(page);

		const ethBefore = await getEthBalance(ANVIL_ACCOUNT_0);
		const tokenBefore = await getTokenBalance(MOCK_TOKEN, ANVIL_ACCOUNT_0);

		await blockDelegation(page, 'inferno-drainer');

		// Fresh navigation for clean state before second delegation
		await page.goto('/');
		await waitForTestudo(page);

		await blockDelegation(page, 'crime-enjoyer');

		const ethAfter = await getEthBalance(ANVIL_ACCOUNT_0);
		const tokenAfter = await getTokenBalance(MOCK_TOKEN, ANVIL_ACCOUNT_0);
		const allowanceAfter = await getTokenAllowance(MOCK_TOKEN, ANVIL_ACCOUNT_0, SPENDER);

		expect(ethAfter).toBe(ethBefore);
		expect(tokenAfter).toBe(tokenBefore);
		expect(allowanceAfter).toBe(0n);
	});
});
