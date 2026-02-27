import { triggerDelegation, waitForTestudo } from '../fixtures/delegation-helper';
import { expect, test } from '../fixtures/synpress';

test.describe('Safe Wallet Delegation', () => {
	test('safe wallet delegation does not trigger blocking warning', async ({
		page,
		// biome-ignore lint/correctness/noUnusedFunctionParameters: triggers fixture setup
		testudoExtensionId,
	}) => {
		await page.goto('/');
		await waitForTestudo(page);

		await triggerDelegation(page, 'safe-wallet');

		// Wait for the delegation request to complete (status element updates when Promise resolves/rejects).
		// For LOW risk, injected.tsx calls dismissLoading() — request passes through to MetaMask,
		// which rejects (dummy from address) and updates #status with the error.
		await expect(page.locator('#status')).not.toHaveText('', { timeout: 30_000 });

		// The blocking warning modal's cancel button should NOT be visible
		await expect(page.locator('#testudo-cancel')).not.toBeVisible({ timeout: 3_000 });

		// Testudo should not have blocked this delegation
		const statusText = await page.locator('#status').textContent();
		expect(statusText).not.toContain('Delegation blocked');
	});
});
