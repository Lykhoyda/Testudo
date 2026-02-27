import type { ContractKey } from '../fixtures/delegation-helper';
import { triggerDelegation, waitForTestudo } from '../fixtures/delegation-helper';
import { expect, test } from '../fixtures/synpress';

interface AttackPattern {
	key: ContractKey;
	name: string;
	expectedThreat: string;
	expectedRiskLevel: string;
}

/**
 * Real mainnet malicious contracts + synthetic patterns.
 *
 * CrimeEnjoyer: Real bytecode only triggers MEDIUM (CHAINID_READ) from bytecode analysis.
 *   In production, the API layer flags it as CRITICAL (known malicious address).
 *   Without API (test env), fail-safe kicks in: API timeout + local suspicious → BLOCK.
 *
 * Inferno Drainer: Real bytecode triggers CRITICAL from bytecode analysis alone
 *   (DELEGATECALL + TOKEN_WITH_AUTH + GAS_MANIPULATION).
 *
 * Metamorphic: Synthetic — real metamorphic contracts self-destruct by definition,
 *   so their bytecode can't be fetched from mainnet.
 */
const MALICIOUS_PATTERNS: AttackPattern[] = [
	{
		key: 'crime-enjoyer',
		name: 'CrimeEnjoyer (real mainnet — 0x930fcc37)',
		expectedThreat: 'Reads network ID',
		expectedRiskLevel: 'CRITICAL',
	},
	{
		key: 'inferno-drainer',
		name: 'Inferno Drainer (real mainnet — 0x00008c22)',
		expectedThreat: 'Uses DELEGATECALL',
		expectedRiskLevel: 'CRITICAL',
	},
	{
		key: 'metamorphic',
		name: 'Metamorphic (synthetic — self-destructing pattern)',
		expectedThreat: 'Metamorphic contract',
		expectedRiskLevel: 'CRITICAL',
	},
];

for (const pattern of MALICIOUS_PATTERNS) {
	test.describe(`${pattern.name}`, () => {
		test(`detects malicious pattern and shows blocking warning`, async ({
			page,
			// biome-ignore lint/correctness/noUnusedFunctionParameters: triggers fixture setup
			testudoExtensionId,
		}) => {
			await page.goto('/');
			await waitForTestudo(page);

			await triggerDelegation(page, pattern.key);

			const modal = page.locator('#testudo-warning-overlay');
			await expect(modal).toBeVisible({ timeout: 30_000 });

			await expect(modal.locator('.testudo-threat-item').first()).toBeVisible({
				timeout: 30_000,
			});

			// Verify risk level badge (e.g. "CRITICAL: Fund Drain Detected")
			const alertTitle = modal.locator('.testudo-alert-title');
			await expect(alertTitle).toContainText(pattern.expectedRiskLevel, { timeout: 5_000 });

			// Verify specific threat type in threat list
			const threatName = modal.locator('.testudo-threat-name').first();
			await expect(threatName).toContainText(pattern.expectedThreat, { timeout: 5_000 });
		});

		test(`user can cancel delegation`, async ({
			page,
			// biome-ignore lint/correctness/noUnusedFunctionParameters: triggers fixture setup
			testudoExtensionId,
		}) => {
			await page.goto('/');
			await waitForTestudo(page);

			await triggerDelegation(page, pattern.key);

			const modal = page.locator('#testudo-warning-overlay');
			await expect(modal).toBeVisible({ timeout: 30_000 });

			await expect(page.locator('#testudo-cancel')).toBeVisible({ timeout: 30_000 });
			await page.click('#testudo-cancel');

			await expect(modal).not.toBeVisible({ timeout: 10_000 });
			await expect(page.locator('#status')).toContainText('Delegation blocked', {
				timeout: 10_000,
			});
		});
	});
}

test.describe('Proceed Flow', () => {
	test('user can proceed through warning for Inferno Drainer delegation', async ({
		page,
		// biome-ignore lint/correctness/noUnusedFunctionParameters: triggers fixture setup
		testudoExtensionId,
	}) => {
		await page.goto('/');
		await waitForTestudo(page);

		await triggerDelegation(page, 'inferno-drainer');

		const modal = page.locator('#testudo-warning-overlay');
		await expect(modal).toBeVisible({ timeout: 30_000 });

		await expect(page.locator('#testudo-proceed')).toBeVisible({ timeout: 30_000 });
		await page.click('#testudo-proceed');

		await expect(modal).not.toBeVisible({ timeout: 10_000 });

		// Wait for status to update (MetaMask rejects due to dummy from address)
		await expect(page.locator('#status')).not.toHaveText('', { timeout: 30_000 });

		// After proceeding, status should NOT contain "Delegation blocked"
		const statusText = await page.locator('#status').textContent();
		expect(statusText).not.toContain('Delegation blocked');
	});

	test('user can proceed through warning for CrimeEnjoyer delegation', async ({
		page,
		// biome-ignore lint/correctness/noUnusedFunctionParameters: triggers fixture setup
		testudoExtensionId,
	}) => {
		await page.goto('/');
		await waitForTestudo(page);

		await triggerDelegation(page, 'crime-enjoyer');

		const modal = page.locator('#testudo-warning-overlay');
		await expect(modal).toBeVisible({ timeout: 30_000 });

		await expect(page.locator('#testudo-proceed')).toBeVisible({ timeout: 30_000 });
		await page.click('#testudo-proceed');

		await expect(modal).not.toBeVisible({ timeout: 10_000 });

		await expect(page.locator('#status')).not.toHaveText('', { timeout: 30_000 });

		const statusText = await page.locator('#status').textContent();
		expect(statusText).not.toContain('Delegation blocked');
	});
});
