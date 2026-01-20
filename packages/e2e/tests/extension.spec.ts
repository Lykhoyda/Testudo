import path from 'node:path';
import { expect, test } from '../fixtures/extension';

const MOCK_DAPP_PATH = `file://${path.join(__dirname, '../mock-dapp/index.html')}`;

test.describe('Extension Loading', () => {
	test('service worker activates successfully', async ({ context, extensionId }) => {
		expect(extensionId).toBeTruthy();
		expect(extensionId).toMatch(/^[a-z]{32}$/);

		const serviceWorkers = context.serviceWorkers();
		expect(serviceWorkers.length).toBeGreaterThan(0);
	});

	test('popup page is accessible', async ({ context, extensionId }) => {
		const popupPage = await context.newPage();
		await popupPage.goto(`chrome-extension://${extensionId}/popup.html`);

		await expect(popupPage.locator('body')).toBeVisible();
		await popupPage.close();
	});
});

test.describe('EIP-7702 Delegation Detection', () => {
	test('warning modal appears for malicious delegation', async ({ context }) => {
		const page = await context.newPage();
		await page.goto(MOCK_DAPP_PATH);

		await expect(page.locator('#provider-status')).toContainText('Ready');

		await page.click('#sign-malicious');

		const modal = page.locator('#testudo-warning-overlay');
		await expect(modal).toBeVisible({ timeout: 10000 });

		await expect(modal.locator('.testudo-title')).toContainText('Dangerous Contract Detected');

		const threatsList = modal.locator('.testudo-threat');
		await expect(threatsList.first()).toBeVisible();

		await page.close();
	});

	test('user can cancel malicious delegation', async ({ context }) => {
		const page = await context.newPage();
		await page.goto(MOCK_DAPP_PATH);

		await page.click('#sign-malicious');

		const modal = page.locator('#testudo-warning-overlay');
		await expect(modal).toBeVisible({ timeout: 10000 });

		await page.click('#testudo-cancel');

		await expect(modal).not.toBeVisible();

		await expect(page.locator('#result')).toContainText('Blocked');

		await page.close();
	});

	test('user can proceed despite warning', async ({ context }) => {
		const page = await context.newPage();
		await page.goto(MOCK_DAPP_PATH);

		await page.click('#sign-malicious');

		const modal = page.locator('#testudo-warning-overlay');
		await expect(modal).toBeVisible({ timeout: 10000 });

		await page.click('#testudo-proceed');

		await expect(modal).not.toBeVisible();

		await expect(page.locator('#result')).toContainText('Signature received');

		await page.close();
	});

	test('safe delegation proceeds without warning', async ({ context }) => {
		const page = await context.newPage();
		await page.goto(MOCK_DAPP_PATH);

		await expect(page.locator('#provider-status')).toContainText('Ready');

		await page.click('#sign-safe');

		const modal = page.locator('#testudo-warning-overlay');
		await expect(modal).not.toBeVisible({ timeout: 3000 });

		await expect(page.locator('#result')).toContainText('Signature received');

		await page.close();
	});
});

test.describe('Whitelist from Modal', () => {
	test('user can trust and whitelist address from warning', async ({ context }) => {
		const page = await context.newPage();
		await page.goto(MOCK_DAPP_PATH);

		await page.click('#sign-malicious');

		const modal = page.locator('#testudo-warning-overlay');
		await expect(modal).toBeVisible({ timeout: 10000 });

		await page.click('#testudo-trust');

		await expect(modal).not.toBeVisible({ timeout: 5000 });

		await expect(page.locator('#result')).toContainText('Signature received');

		await page.close();
	});
});
