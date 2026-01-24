import { expect, test } from '../fixtures/extension';

// Mock dApp URL served by Vite preview server (configured in playwright.config.ts)
const MOCK_DAPP_URL = 'http://localhost:4173';

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
	test('warning modal appears for malicious delegation', async ({ context, extensionId }) => {
		// First verify the background script is responding by checking via popup
		const verifyPage = await context.newPage();
		await verifyPage.goto(`chrome-extension://${extensionId}/popup.html`);

		// Try to get stats from background - this will confirm it's running
		const bgResponding = await verifyPage.evaluate(() => {
			return new Promise((resolve) => {
				const timeout = setTimeout(() => resolve({ error: 'timeout' }), 3000);
				chrome.runtime.sendMessage({ type: 'GET_STATS' }, (response) => {
					clearTimeout(timeout);
					resolve(response || { error: 'no response' });
				});
			});
		});
		console.log('[Test] Background script response:', JSON.stringify(bgResponding));
		await verifyPage.close();

		const page = await context.newPage();

		// Capture console logs for debugging
		const consoleLogs: string[] = [];
		page.on('console', (msg) => {
			consoleLogs.push(`[${msg.type()}] ${msg.text()}`);
		});

		await page.goto(MOCK_DAPP_URL);

		await expect(page.locator('#provider-status')).toContainText('Ready');

		await page.click('#sign-malicious');

		// Wait and print console logs for debugging
		await page.waitForTimeout(5000);
		console.log('[Test] Console logs from page:');
		consoleLogs.forEach((log) => console.log('  ', log));

		const modal = page.locator('#testudo-warning-overlay');
		await expect(modal).toBeVisible({ timeout: 10000 });

		await expect(modal.locator('.testudo-title')).toContainText('Dangerous Contract Detected');

		const threatsList = modal.locator('.testudo-threat-item');
		await expect(threatsList.first()).toBeVisible();

		await page.close();
	});

	test('user can cancel malicious delegation', async ({ context }) => {
		const page = await context.newPage();
		await page.goto(MOCK_DAPP_URL);

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
		await page.goto(MOCK_DAPP_URL);

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
		await page.goto(MOCK_DAPP_URL);

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
		await page.goto(MOCK_DAPP_URL);

		await page.click('#sign-malicious');

		const modal = page.locator('#testudo-warning-overlay');
		await expect(modal).toBeVisible({ timeout: 10000 });

		await page.click('#testudo-trust');

		await expect(modal).not.toBeVisible({ timeout: 5000 });

		await expect(page.locator('#result')).toContainText('Signature received');

		await page.close();
	});
});

test.describe('Settings Page', () => {
	test('options page loads correctly', async ({ context, extensionId }) => {
		const page = await context.newPage();
		await page.goto(`chrome-extension://${extensionId}/options.html`);

		await expect(page.locator('h1')).toContainText('Testudo Settings');
		await expect(page.locator('.tab.active')).toContainText('General');

		await page.close();
	});

	test('tab navigation works', async ({ context, extensionId }) => {
		const page = await context.newPage();
		await page.goto(`chrome-extension://${extensionId}/options.html`);

		// Click Whitelist tab
		await page.click('[data-tab="whitelist"]');
		await expect(page.locator('[data-tab="whitelist"]')).toHaveClass(/active/);
		await expect(page.locator('#tab-whitelist')).toBeVisible();

		// Click History tab
		await page.click('[data-tab="history"]');
		await expect(page.locator('[data-tab="history"]')).toHaveClass(/active/);
		await expect(page.locator('#tab-history')).toBeVisible();

		// Click Advanced tab
		await page.click('[data-tab="advanced"]');
		await expect(page.locator('[data-tab="advanced"]')).toHaveClass(/active/);
		await expect(page.locator('#tab-advanced')).toBeVisible();

		// Click back to General
		await page.click('[data-tab="general"]');
		await expect(page.locator('[data-tab="general"]')).toHaveClass(/active/);
		await expect(page.locator('#tab-general')).toBeVisible();

		await page.close();
	});

	test('protection level can be changed', async ({ context, extensionId }) => {
		const page = await context.newPage();
		await page.goto(`chrome-extension://${extensionId}/options.html`);

		const select = page.locator('#protection-level');
		await expect(select).toBeVisible();

		// Change to strict
		await select.selectOption('strict');
		await expect(select).toHaveValue('strict');

		// Change to permissive
		await select.selectOption('permissive');
		await expect(select).toHaveValue('permissive');

		await page.close();
	});

	test('whitelist address can be added', async ({ context, extensionId }) => {
		const page = await context.newPage();
		await page.goto(`chrome-extension://${extensionId}/options.html`);

		// Navigate to Whitelist tab
		await page.click('[data-tab="whitelist"]');

		// Add a test address
		const testAddress = '0x1234567890123456789012345678901234567890';
		await page.fill('#whitelist-address', testAddress);
		await page.fill('#whitelist-label', 'Test Address');
		await page.click('#btn-add-whitelist');

		// Verify address appears in the list (truncated format: 0x12345678...34567890)
		await expect(page.locator('.whitelist-address')).toContainText('0x12345678...34567890');

		await page.close();
	});

	test('custom RPC can be saved', async ({ context, extensionId }) => {
		const page = await context.newPage();
		await page.goto(`chrome-extension://${extensionId}/options.html`);

		// Navigate to Advanced tab
		await page.click('[data-tab="advanced"]');

		// Enter RPC URL
		const rpcUrl = 'https://eth.llamarpc.com';
		await page.fill('#custom-rpc', rpcUrl);
		await page.click('#btn-save-rpc');

		// Check for success toast
		await expect(page.locator('.toast.show')).toBeVisible({ timeout: 3000 });

		await page.close();
	});
});
