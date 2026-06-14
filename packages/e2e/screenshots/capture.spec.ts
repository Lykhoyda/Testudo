// Chrome Web Store screenshot generator for the Testudo extension.
//
// Loads the built extension from packages/extension/dist, drives the mock-dapp,
// and captures (at 1280x800, opaque PNG — CWS spec):
//   - the injected warning modal (open shadow DOM)
//   - the popup
//   - the options page (general / whitelist / history tabs)
//   - the phishing blocked page
//
// Run via the sibling config (starts the mock-dapp dev server for you):
//   yarn workspace @testudo/extension build      # dist must be fresh
//   yarn workspace @testudo/e2e screenshots
// CI / headless box (MV3 needs a display):
//   xvfb-run --auto-servernum yarn workspace @testudo/e2e screenshots
//
// Output: packages/extension/store-assets/screenshots/*.png (a scratch subfolder,
// gitignored, so the curated store-assets/*.png and the release zip are untouched).

import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { type BrowserContext, type Page, chromium, expect, test as base } from '@playwright/test';

// Playwright transpiles specs to CJS, so __dirname is available (matches fixtures/extension.ts).
const EXTENSION_PATH = path.join(__dirname, '../../extension/dist');
const OUT_DIR = path.join(__dirname, '../../extension/store-assets/screenshots');
const MOCK_DAPP_URL = 'http://localhost:4173';
const VIEWPORT = { width: 1280, height: 800 } as const;
// Masking is opt-in: great for pixel-stable regression diffs, but it magenta-boxes
// the address/network fields, which looks broken in a marketing screenshot. The
// demo addresses are public/truncated, so default to clean (unmasked) shots.
const MASK = process.env.SCREENSHOT_MASK === '1';

mkdirSync(OUT_DIR, { recursive: true });

// --- Fixture: fork of packages/e2e/fixtures/extension.ts -----------------------
// Identical MV3 launch + service-worker-ID logic, plus a fixed viewport/scale and
// scrollbar/dpr args for pixel-stable, CWS-correct captures.
const test = base.extend<{ context: BrowserContext; extensionId: string }>({
	context: async ({}, use) => {
		const context = await chromium.launchPersistentContext('', {
			headless: false, // MV3 extensions cannot load in old headless; wrap CI in xvfb-run
			viewport: VIEWPORT,
			deviceScaleFactor: 1,
			args: [
				`--disable-extensions-except=${EXTENSION_PATH}`,
				`--load-extension=${EXTENSION_PATH}`,
				'--no-first-run',
				'--disable-default-apps',
				'--force-device-scale-factor=1',
				'--hide-scrollbars',
			],
		});

		// The service worker URL is the only source of the (non-deterministic) ext ID.
		let serviceWorker = context.serviceWorkers()[0];
		if (!serviceWorker) serviceWorker = await context.waitForEvent('serviceworker');
		const extensionId = serviceWorker.url().split('/')[2];

		// Seed settings + some stats/scans so popup/options show populated state.
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
						// Best-effort seed; harmless if the popup VM reads different keys.
						stats: { scanned: 1284, blocked: 37 },
						scans: [
							{
								type: 'delegation',
								risk: 'CRITICAL',
								address: '0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b',
								timestamp: 1_717_000_000_000,
							},
							{
								type: 'approval',
								risk: 'HIGH',
								address: '0x63c0c19a282a1b52b07dd5a65b58948a07dae32b',
								timestamp: 1_716_900_000_000,
							},
						],
					},
					() => resolve(),
				);
			});
		});

		// Same exponential-backoff wait as the e2e fixture so the SW-backed UI is ready.
		for (let i = 0; i < 8; i++) {
			const ok = await setupPage.evaluate(() => {
				return new Promise((resolve) => {
					const t = setTimeout(() => resolve(null), 2000);
					chrome.runtime.sendMessage({ type: 'GET_STATS' }, (r) => {
						clearTimeout(t);
						resolve(r);
					});
				});
			});
			if (ok !== null && ok !== undefined) break;
			await new Promise((r) => setTimeout(r, Math.min(500 * 2 ** i, 4000)));
		}
		await setupPage.close();

		await use(context);
		await context.close();
	},

	extensionId: async ({ context }, use) => {
		let [serviceWorker] = context.serviceWorkers();
		if (!serviceWorker) serviceWorker = await context.waitForEvent('serviceworker');
		await use(serviceWorker.url().split('/')[2]);
	},
});

// --- Helpers -------------------------------------------------------------------
async function prep(page: Page): Promise<void> {
	// Guarantee exact CWS dimensions (context viewport is not always inherited).
	await page.setViewportSize(VIEWPORT);
	await page.evaluate(() => document.fonts.ready);
}

// Optional mask (off by default) — only applied when SCREENSHOT_MASK=1.
function maskFor(page: Page, selector: string): { mask?: ReturnType<Page['locator']>[] } {
	return MASK ? { mask: [page.locator(selector)] } : {};
}

const STORE_SHOT = {
	type: 'png' as const,
	animations: 'disabled' as const,
	clip: { x: 0, y: 0, width: VIEWPORT.width, height: VIEWPORT.height },
	// omitBackground intentionally false — CWS rejects transparency.
};

// --- 1. Warning modal (injected, open shadow DOM) ------------------------------
test('1 - warning modal (malicious EIP-7702 delegation)', async ({ context }) => {
	const page = await context.newPage();
	await page.goto(MOCK_DAPP_URL);
	await prep(page);

	await expect(page.locator('#provider-status')).toContainText('Ready');
	await page.click('#sign-malicious'); // richest threat list

	const overlay = page.locator('#testudo-warning-overlay'); // pierces open shadow root
	await expect(overlay).toBeVisible({ timeout: 20_000 });
	// Wait for the full modal (NOT the optimistic loading skeleton).
	await expect(overlay.locator('.testudo-threat-item').first()).toBeVisible({ timeout: 20_000 });
	await expect(overlay.locator('.testudo-title')).toContainText('Wallet Delegation Request');
	await page.evaluate(() => document.fonts.ready);

	// Store asset: full 1280x800 dimmed-overlay shot, address masked for stable diffs.
	await page.screenshot({
		path: path.join(OUT_DIR, '1-warning-modal.png'),
		...STORE_SHOT,
		...maskFor(page, '.testudo-address-text'),
	});

	// Docs asset: just the modal card.
	await overlay.locator('.testudo-modal').first().screenshot({
		path: path.join(OUT_DIR, 'docs-modal-card.png'),
		type: 'png',
		animations: 'disabled',
	});

	await page.close();
});

// --- 2. Popup -----------------------------------------------------------------
test('2 - popup (protected)', async ({ context, extensionId }) => {
	const page = await context.newPage();
	await page.goto(`chrome-extension://${extensionId}/popup.html`);
	await prep(page);
	await expect(page.locator('body')).toBeVisible();
	await page.screenshot({
		path: path.join(OUT_DIR, '2-popup-protected.png'),
		...STORE_SHOT,
		...maskFor(page, '.testudo-address-text, time, [data-timestamp]'),
	});
	await page.close();
});

// --- 3-5. Options tabs --------------------------------------------------------
const OPTION_TABS: Array<{ tab: string; out: string }> = [
	{ tab: 'general', out: '3-options-general.png' },
	{ tab: 'whitelist', out: '4-options-whitelist.png' },
	{ tab: 'history', out: '5-options-history.png' },
];

for (const { tab, out } of OPTION_TABS) {
	test(`options - ${tab}`, async ({ context, extensionId }) => {
		const page = await context.newPage();
		await page.goto(`chrome-extension://${extensionId}/options.html`);
		await prep(page);
		await page.click(`[data-tab="${tab}"]`); // selector from TabNav.tsx
		await expect(page.locator(`[data-tab="${tab}"].active`)).toBeVisible();
		await page.evaluate(() => document.fonts.ready);
		await page.screenshot({
			path: path.join(OUT_DIR, out),
			...STORE_SHOT,
			...maskFor(page, '.testudo-address-text, time, [data-timestamp]'),
		});
		await page.close();
	});
}

// --- 6. Blocked page (phishing interstitial) ----------------------------------
// blockedVM.ts reads ?domain=&url=&action= from the URL.
test('blocked page (phishing hard-block)', async ({ context, extensionId }) => {
	const page = await context.newPage();
	const params = new URLSearchParams({
		domain: 'uniswaq-airdrop.com',
		url: 'https://uniswaq-airdrop.com/claim',
		action: 'hard-block',
	});
	await page.goto(`chrome-extension://${extensionId}/blocked.html?${params.toString()}`);
	await prep(page);
	// Wait for the resolved interstitial, not the "Analyzing…" loading frame:
	// blockedVM sets screenState to the action param even when the API is offline.
	await expect(page.getByText('THREAT INTERCEPTED')).toBeVisible({ timeout: 15_000 });
	await page.evaluate(() => document.fonts.ready);
	await page.screenshot({
		path: path.join(OUT_DIR, 'blocked-phishing.png'),
		...STORE_SHOT,
	});
	await page.close();
});
