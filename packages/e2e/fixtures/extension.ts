import path from 'node:path';
import { type BrowserContext, type Page, chromium, test as base } from '@playwright/test';

const EXTENSION_PATH = path.join(__dirname, '../../extension/dist');

export const test = base.extend<{
	context: BrowserContext;
	extensionId: string;
}>({
	context: async ({}, use) => {
		const context = await chromium.launchPersistentContext('', {
			headless: false,
			args: [
				`--disable-extensions-except=${EXTENSION_PATH}`,
				`--load-extension=${EXTENSION_PATH}`,
				'--no-first-run',
				'--disable-default-apps',
			],
		});

		// Wait for service worker to be ready
		let serviceWorker = context.serviceWorkers()[0];
		if (!serviceWorker) {
			serviceWorker = await context.waitForEvent('serviceworker');
		}

		// Get extension ID from service worker URL
		const extensionId = serviceWorker.url().split('/')[2];

		// Open extension popup page to set storage (popup has chrome.storage access)
		const setupPage = await context.newPage();
		await setupPage.goto(`chrome-extension://${extensionId}/popup.html`);

		// Set the API URL in storage using the popup page context
		await setupPage.evaluate(() => {
			return new Promise<void>((resolve) => {
				chrome.storage.local.set(
					{
						settings: {
							protectionLevel: 'standard',
							customRpcUrl: null,
							apiUrl: 'http://localhost:3001',
							showMediumRiskToast: true,
							autoRecordScans: true,
						},
					},
					() => {
						console.log('[E2E Setup] Storage set with local API URL');
						resolve();
					},
				);
			});
		});

		// Verify the setting was saved
		const settings = await setupPage.evaluate(() => {
			return new Promise((resolve) => {
				chrome.storage.local.get('settings', (result) => {
					resolve(result.settings);
				});
			});
		});
		console.log('[E2E Setup] Verified settings:', settings);

		// Wait for the service worker to be ready by polling for a response
		let bgReady = false;
		for (let i = 0; i < 10; i++) {
			const response = await setupPage.evaluate(() => {
				return new Promise((resolve) => {
					const timeout = setTimeout(() => resolve(null), 1000);
					chrome.runtime.sendMessage({ type: 'GET_STATS' }, (result) => {
						clearTimeout(timeout);
						resolve(result);
					});
				});
			});

			if (response) {
				console.log('[E2E Setup] Service worker is ready');
				bgReady = true;
				break;
			}
			console.log(`[E2E Setup] Waiting for service worker... (attempt ${i + 1})`);
			await new Promise((resolve) => setTimeout(resolve, 500));
		}

		if (!bgReady) {
			console.error('[E2E Setup] WARNING: Service worker may not be ready!');
		}

		await setupPage.close();

		await use(context);
		await context.close();
	},

	extensionId: async ({ context }, use) => {
		let [serviceWorker] = context.serviceWorkers();
		if (!serviceWorker) {
			serviceWorker = await context.waitForEvent('serviceworker');
		}
		const extensionId = serviceWorker.url().split('/')[2];
		await use(extensionId);
	},
});

export const expect = test.expect;
