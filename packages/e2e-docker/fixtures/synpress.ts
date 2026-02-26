import { cpSync, existsSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { BrowserContext, Page } from '@playwright/test';
import { chromium, test as base } from '@playwright/test';
import { MetaMask, unlockForFixture } from '@synthetixio/synpress/playwright';
import basicSetup, { WALLET_PASSWORD } from '../wallet-setup/basic.setup';

const TESTUDO_PATH = path.resolve(process.cwd(), '../extension/dist');
const CACHE_DIR = path.resolve(process.cwd(), '.cache-synpress');

if (!existsSync(TESTUDO_PATH)) {
	throw new Error(
		`Testudo extension dist not found at ${TESTUDO_PATH}. Run "yarn workspace @testudo/extension run build" first.`,
	);
}

function findMetaMaskPath(): string {
	if (!existsSync(CACHE_DIR)) {
		throw new Error(
			`Synpress cache directory not found at ${CACHE_DIR}. Run "yarn cache:synpress" first.`,
		);
	}
	const entries = readdirSync(CACHE_DIR);
	const mmDir = entries.find((e) => e.startsWith('metamask-chrome-'));
	if (!mmDir) {
		throw new Error(
			'MetaMask extension not found in .cache-synpress/. Run "yarn cache:synpress" first.',
		);
	}
	return path.join(CACHE_DIR, mmDir);
}

export const test = base.extend<{
	context: BrowserContext;
	metamaskPage: Page;
	metamask: MetaMask;
	testudoExtensionId: string;
}>({
	// biome-ignore lint/correctness/noEmptyPattern: Playwright fixture override requires empty destructuring
	context: async ({}, use) => {
		const cacheDir = path.join(CACHE_DIR, basicSetup.hash);
		if (!existsSync(cacheDir)) {
			throw new Error(
				`Synpress cache not found at ${cacheDir}. Run "yarn cache:synpress" first.`,
			);
		}

		const tempDir = mkdtempSync(path.join(tmpdir(), 'synpress-testudo-'));
		cpSync(cacheDir, tempDir, { recursive: true });

		const metamaskPath = findMetaMaskPath();

		const context = await chromium.launchPersistentContext(tempDir, {
			headless: false,
			args: [
				`--disable-extensions-except=${metamaskPath},${TESTUDO_PATH}`,
				`--load-extension=${metamaskPath},${TESTUDO_PATH}`,
				'--no-first-run',
				'--disable-default-apps',
			],
		});

		try {
			await use(context);
		} finally {
			await context.close();
			rmSync(tempDir, { recursive: true, force: true });
		}
	},

	metamaskPage: async ({ context }, use) => {
		let mmPage = context.pages().find((p) => p.url().includes('home.html'));
		if (!mmPage) {
			mmPage = await context.waitForEvent('page', {
				predicate: (p) => p.url().includes('home.html'),
				timeout: 30_000,
			});
		}

		await unlockForFixture(mmPage, WALLET_PASSWORD);
		await use(mmPage);
	},

	metamask: async ({ context, metamaskPage }, use) => {
		const extensionId = metamaskPage.url().split('/')[2];
		const mm = new MetaMask(context, metamaskPage, WALLET_PASSWORD, extensionId);
		await use(mm);
	},

	testudoExtensionId: async ({ context, metamaskPage }, use) => {
		const mmExtId = metamaskPage.url().split('/')[2];

		let testudoSW = context
			.serviceWorkers()
			.find(
				(sw) =>
					sw.url().includes('chrome-extension://') && !sw.url().includes(mmExtId),
			);

		if (!testudoSW) {
			testudoSW = await context.waitForEvent('serviceworker', {
				predicate: (sw) => !sw.url().includes(mmExtId),
				timeout: 15_000,
			});
		}

		const extensionId = testudoSW.url().split('/')[2];

		const setupPage = await context.newPage();
		await setupPage.goto(`chrome-extension://${extensionId}/popup.html`);

		await setupPage.evaluate(() => {
			return new Promise<void>((resolve) => {
				chrome.storage.local.set(
					{
						settings: {
							apiUrl: 'http://localhost:3001',
							showMediumRiskToast: true,
							autoRecordScans: true,
						},
					},
					() => resolve(),
				);
			});
		});

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
				bgReady = true;
				break;
			}
			await new Promise((resolve) => setTimeout(resolve, 500));
		}

		if (!bgReady) {
			console.warn('[Synpress Fixture] Testudo service worker may not be ready');
		}

		await setupPage.close();
		await use(extensionId);
	},
});

export const expect = test.expect;
