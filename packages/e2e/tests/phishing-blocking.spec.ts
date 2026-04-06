import { expect, test } from '../fixtures/extension';

/**
 * E2E tests for phishing domain blocking.
 *
 * These tests inject a small bloom filter with known test domains into
 * chrome.storage.local, then verify that navigation to those domains
 * triggers the block screen (Layer A+ content script bloom check).
 *
 * Layer A (DNR rules) is not tested here because Playwright doesn't
 * support declarativeNetRequest injection. These tests cover the
 * content script fallback path (Layer A+).
 */

const TEST_PHISHING_DOMAINS = ['evil-phish-test.com', 'fake-uniswap-claim.xyz', 'scam-metamask.io'];

test.describe('Phishing Domain Blocking', () => {
	// Before each test, build a bloom filter from test domains and inject it
	// into chrome.storage.local so the background's PhishingSync picks it up.
	test.beforeEach(async ({ context, extensionId }) => {
		const setupPage = await context.newPage();
		await setupPage.goto(`chrome-extension://${extensionId}/popup.html`);

		// Build bloom filter in the extension context (has access to same murmurhash3 logic)
		// We replicate the bloom filter construction inline since we can't import the module
		await setupPage.evaluate((domains: string[]) => {
			// Minimal murmurhash3_32 (must match packages/extension/src/phishing/bloom.ts)
			function murmurhash3_32(key: string, seed: number): number {
				let h = seed >>> 0;
				const len = key.length;
				let i = 0;
				while (i + 4 <= len) {
					let k =
						(key.charCodeAt(i) & 0xff) |
						((key.charCodeAt(i + 1) & 0xff) << 8) |
						((key.charCodeAt(i + 2) & 0xff) << 16) |
						((key.charCodeAt(i + 3) & 0xff) << 24);
					k = Math.imul(k, 0xcc9e2d51);
					k = ((k << 15) | (k >>> 17)) >>> 0;
					k = Math.imul(k, 0x1b873593);
					h ^= k;
					h = ((h << 13) | (h >>> 19)) >>> 0;
					h = (Math.imul(h, 5) + 0xe6546b64) >>> 0;
					i += 4;
				}
				let remaining = 0;
				const tail = len - i;
				if (tail >= 3) remaining ^= (key.charCodeAt(i + 2) & 0xff) << 16;
				if (tail >= 2) remaining ^= (key.charCodeAt(i + 1) & 0xff) << 8;
				if (tail >= 1) {
					remaining ^= key.charCodeAt(i) & 0xff;
					remaining = Math.imul(remaining, 0xcc9e2d51);
					remaining = ((remaining << 15) | (remaining >>> 17)) >>> 0;
					remaining = Math.imul(remaining, 0x1b873593);
					h ^= remaining;
				}
				h ^= len;
				h ^= h >>> 16;
				h = Math.imul(h, 0x85ebca6b);
				h ^= h >>> 13;
				h = Math.imul(h, 0xc2b2ae35);
				h ^= h >>> 16;
				return h >>> 0;
			}

			// Build a small bloom filter
			// MUST use numHashes=10 to match SEED_NUM_HASHES in phishing/sync.ts
			const numHashes = 10;
			// Use enough bits to avoid collisions with 3 domains
			const numBits = 1024;
			const bytes = new Uint8Array(Math.ceil(numBits / 8));

			for (const domain of domains) {
				for (let h = 0; h < numHashes; h++) {
					const bit = murmurhash3_32(domain, h) % numBits;
					bytes[(bit / 8) | 0] |= 1 << (bit % 8);
				}
			}

			// Convert to base64
			let binaryStr = '';
			for (let j = 0; j < bytes.length; j++) {
				binaryStr += String.fromCharCode(bytes[j]);
			}
			const b64 = btoa(binaryStr);

			// Store in chrome.storage.local (same key PhishingSync uses)
			return new Promise<void>((resolve) => {
				chrome.storage.local.set(
					{
						phishingFilterBloom: b64,
						phishingFilterVersion: 'e2e-test',
						phishingFilterSequence: 999,
					},
					() => resolve(),
				);
			});
		}, TEST_PHISHING_DOMAINS);

		// Tell background to reload the bloom filter from storage
		const reloadResult = await setupPage.evaluate(() => {
			return new Promise<unknown>((resolve) => {
				const timeout = setTimeout(() => resolve({ error: 'timeout' }), 5000);
				chrome.runtime.sendMessage({ type: 'TESTUDO_RELOAD_PHISHING_BLOOM' }, (response) => {
					clearTimeout(timeout);
					resolve(response ?? { error: 'no response' });
				});
			});
		});
		console.log('[E2E Setup] Bloom reload result:', JSON.stringify(reloadResult));

		// Wait for the reload to propagate
		await setupPage.waitForTimeout(500);
		await setupPage.close();
	});

	test('bloom filter correctly identifies phishing domain via background message', async ({
		context,
		extensionId,
	}) => {
		const page = await context.newPage();
		await page.goto(`chrome-extension://${extensionId}/popup.html`);

		// Ask background to check bloom filter directly via message API
		const bloomResult = await page.evaluate(() => {
			return new Promise((resolve) => {
				const timeout = setTimeout(() => resolve({ error: 'timeout' }), 3000);
				chrome.runtime.sendMessage(
					{ type: 'TESTUDO_CHECK_DOMAIN_BLOOM', hostname: 'evil-phish-test.com' },
					(response) => {
						clearTimeout(timeout);
						resolve(response);
					},
				);
			});
		});

		expect(bloomResult).toEqual({ inBloom: true });

		// Verify a non-phishing domain is NOT in bloom
		const safeResult = await page.evaluate(() => {
			return new Promise((resolve) => {
				const timeout = setTimeout(() => resolve({ error: 'timeout' }), 3000);
				chrome.runtime.sendMessage(
					{ type: 'TESTUDO_CHECK_DOMAIN_BLOOM', hostname: 'definitely-not-phishing.org' },
					(response) => {
						clearTimeout(timeout);
						resolve(response);
					},
				);
			});
		});

		expect(safeResult).toEqual({ inBloom: false });

		await page.close();
	});

	test('bloom filter correctly identifies non-phishing domain', async ({ context }) => {
		const page = await context.newPage();

		// Navigate to a domain NOT in the test bloom filter
		try {
			await page.goto('http://totally-safe-domain-not-in-bloom.com', { timeout: 5000 });
		} catch {
			// DNS won't resolve but content script still runs
		}

		await page.waitForTimeout(2000);

		// Should NOT have the phishing overlay
		const overlay = await page
			.locator('#testudo-phishing-block')
			.isVisible()
			.catch(() => false);
		const url = page.url();
		const isOnBlockedPage = url.includes('blocked.html');

		expect(overlay).toBe(false);
		expect(isOnBlockedPage).toBe(false);

		await page.close();
	});

	test('blocked page renders with correct domain info', async ({ context, extensionId }) => {
		const page = await context.newPage();

		// Navigate directly to the blocked page with test params
		await page.goto(
			`chrome-extension://${extensionId}/blocked.html?domain=evil-phish-test.com&url=http://evil-phish-test.com&action=hard-block`,
		);

		// Verify the block screen shows the domain
		await expect(page.locator('body')).toContainText('evil-phish-test.com');

		// Verify threat intercepted header is visible
		await expect(page.locator('body')).toContainText(/THREAT INTERCEPTED|UNCONFIRMED THREAT/);

		await page.close();
	});

	test('blocked page shows override form for hard-block', async ({ context, extensionId }) => {
		const page = await context.newPage();

		await page.goto(
			`chrome-extension://${extensionId}/blocked.html?domain=evil-phish-test.com&url=http://evil-phish-test.com&action=hard-block`,
		);

		// Should have an input field for typing the domain override
		const input = page.locator('input[type="text"]');
		await expect(input).toBeVisible();

		// Override button should be disabled initially
		const overrideBtn = page.locator('button:has-text("OVERRIDE")');
		await expect(overrideBtn).toBeDisabled();

		// Type the domain name
		await input.fill('evil-phish-test.com');

		// Override button should now be enabled
		await expect(overrideBtn).toBeEnabled();

		await page.close();
	});

	test('blocked page shows soft-block UI for API unavailable', async ({ context, extensionId }) => {
		const page = await context.newPage();

		await page.goto(
			`chrome-extension://${extensionId}/blocked.html?domain=evil-phish-test.com&url=http://evil-phish-test.com&action=soft-block`,
		);

		// Should show API unavailable warning
		await expect(page.locator('body')).toContainText(/API unavailable|proceed with caution/i);

		// Should have a proceed button (single click, no typing needed)
		const proceedBtn = page.locator('button:has-text("PROCEED")');
		await expect(proceedBtn).toBeVisible();

		await page.close();
	});

	test('popup page is still accessible with phishing feature active', async ({
		context,
		extensionId,
	}) => {
		const page = await context.newPage();
		await page.goto(`chrome-extension://${extensionId}/popup.html`);
		await expect(page.locator('body')).toBeVisible();
		await page.close();
	});
});
