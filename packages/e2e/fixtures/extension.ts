import path from 'node:path';
import { type BrowserContext, chromium, test as base } from '@playwright/test';

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
