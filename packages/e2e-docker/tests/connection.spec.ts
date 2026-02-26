import { expect, test } from '../fixtures/synpress';

test.describe('MetaMask + Testudo Connection', () => {
	test('Testudo extension loads alongside MetaMask', async ({ page, testudoExtensionId }) => {
		await page.goto('/');

		await page.waitForFunction(
			() => (window as unknown as { __TESTUDO_LOADED__: boolean }).__TESTUDO_LOADED__ === true,
			null,
			{ timeout: 15_000 },
		);

		expect(testudoExtensionId).toBeTruthy();
	});

	// biome-ignore lint/correctness/noUnusedFunctionParameters: testudoExtensionId triggers fixture setup (configures storage + verifies SW readiness)
	test('Testudo and MetaMask provider coexist on page', async ({ page, testudoExtensionId }) => {
		await page.goto('/');

		await expect(page.locator('#testudo-status')).toHaveText('YES', {
			timeout: 15_000,
		});

		await expect(page.locator('#provider-status')).toContainText('detected', {
			timeout: 15_000,
		});
	});

	test('MetaMask provider responds to RPC calls through Testudo wrapper', async ({
		page,
		// biome-ignore lint/correctness/noUnusedFunctionParameters: triggers fixture setup (configures storage + verifies SW readiness)
		testudoExtensionId,
	}) => {
		await page.goto('/');

		await page.waitForFunction(
			() => !!(window as unknown as { ethereum: { isMetaMask: boolean } }).ethereum?.isMetaMask,
			null,
			{ timeout: 20_000 },
		);

		const chainId = await page.evaluate(() =>
			(
				window as unknown as {
					ethereum: { request: (a: unknown) => Promise<string> };
				}
			).ethereum.request({ method: 'eth_chainId' }),
		);
		expect(chainId).toBeTruthy();

		const accounts = await page.evaluate(() =>
			(
				window as unknown as {
					ethereum: { request: (a: unknown) => Promise<string[]> };
				}
			).ethereum.request({ method: 'eth_accounts' }),
		);
		expect(Array.isArray(accounts)).toBe(true);
	});
});
