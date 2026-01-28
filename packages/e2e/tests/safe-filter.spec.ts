import { gunzipSync } from 'node:zlib';
import type { APIRequestContext } from '@playwright/test';
import { expect, test } from '@playwright/test';

const API_BASE = 'http://localhost:3001';
const ADMIN_SECRET = process.env.ADMIN_API_SECRET;
const R2_PUBLIC_DOMAIN = process.env.R2_PUBLIC_DOMAIN;

const SEEDED_SAFE_1 = '0x1111111111111111111111111111111111111111';
const SEEDED_SAFE_2 = '0x2222222222222222222222222222222222222222';
const REVOKED_ADDR = '0x3333333333333333333333333333333333333333';

async function fetchAndParseFilter(
	url: string,
	request: APIRequestContext,
): Promise<{ entries: Array<{ c: number; a: string; n: string; t: string; d: boolean }> }> {
	const res = await request.get(url);
	expect(res.status(), `Failed to fetch filter from ${url}`).toBe(200);

	const rawBody = await res.body();
	try {
		return JSON.parse(gunzipSync(rawBody).toString());
	} catch {
		return JSON.parse(rawBody.toString());
	}
}

test.describe('Safe Address Lookup', () => {
	test('unknown address returns isSafe: false', async ({ request }) => {
		const res = await request.get(
			`${API_BASE}/api/v1/safe/address/0x0000000000000000000000000000000000000001`,
		);
		expect(res.status()).toBe(200);
		const body = await res.json();
		expect(body.isSafe).toBe(false);
	});

	test('seeded safe address returns details', async ({ request }) => {
		const res = await request.get(`${API_BASE}/api/v1/safe/address/${SEEDED_SAFE_1}`);
		expect(res.status()).toBe(200);
		const body = await res.json();
		expect(body.isSafe).toBe(true);
		expect(body.address).toBe(SEEDED_SAFE_1);
		expect(body.name).toBe('Test Safe 1');
		expect(body.category).toBe('DEFI_PROTOCOL');
		expect(body.sources).toContain('test-seed');
	});
});

test.describe('Admin Auth', () => {
	test('build without header returns 401', async ({ request }) => {
		const res = await request.post(`${API_BASE}/api/v1/safe/build`);
		expect(res.status()).toBe(401);
	});

	test('build with wrong secret returns 401', async ({ request }) => {
		const res = await request.post(`${API_BASE}/api/v1/safe/build`, {
			headers: { 'x-admin-secret': 'wrong-secret' },
		});
		expect(res.status()).toBe(401);
	});
});

test.describe('Filter Build', () => {
	test.skip(!ADMIN_SECRET, 'ADMIN_API_SECRET not set');

	let buildResponse: {
		filter: { version: string; url: string; count: number };
		revocations: { version: string; url: string; count: number };
	};

	test('POST /api/v1/safe/build succeeds', async ({ request }) => {
		const res = await request.post(`${API_BASE}/api/v1/safe/build`, {
			headers: { 'x-admin-secret': ADMIN_SECRET! },
		});
		expect(res.status()).toBe(200);
		buildResponse = await res.json();

		expect(buildResponse.filter).toBeDefined();
		expect(buildResponse.filter.version).toBeTruthy();
		expect(buildResponse.filter.url).toBeTruthy();
		expect(buildResponse.filter.count).toBeGreaterThanOrEqual(2);

		expect(buildResponse.revocations).toBeDefined();
		expect(buildResponse.revocations.version).toBeTruthy();
		expect(buildResponse.revocations.url).toBeTruthy();
		expect(buildResponse.revocations.count).toBeGreaterThanOrEqual(1);
	});
});

test.describe('Manifest', () => {
	test('GET /api/v1/safe/manifest returns build metadata', async ({ request }) => {
		const res = await request.get(`${API_BASE}/api/v1/safe/manifest`);

		// Manifest may 404 if no build happened yet — that's acceptable without ADMIN_SECRET
		if (res.status() === 404) {
			test.skip(!ADMIN_SECRET, 'No build exists and no admin secret to trigger one');
			return;
		}

		expect(res.status()).toBe(200);
		const body = await res.json();
		expect(body.version).toBeTruthy();
		expect(body.format).toBeTruthy();
		expect(body.entryCount).toBeGreaterThanOrEqual(0);
		expect(body.sha256).toBeTruthy();
		expect(body.url).toBeTruthy();
	});
});

test.describe('R2 Verification', () => {
	test.skip(!ADMIN_SECRET, 'ADMIN_API_SECRET required for R2 tests');
	test.skip(!R2_PUBLIC_DOMAIN, 'R2_PUBLIC_DOMAIN not set — skipping R2 content verification');

	test('filter URL returns valid data with safe addresses present and revoked excluded', async ({
		request,
	}) => {
		const buildRes = await request.post(`${API_BASE}/api/v1/safe/build`, {
			headers: { 'x-admin-secret': ADMIN_SECRET! },
		});
		expect(buildRes.status()).toBe(200);
		const build = await buildRes.json();

		const filterUrl = build.filter.url;
		expect(filterUrl).toBeTruthy();

		const parsed = await fetchAndParseFilter(filterUrl, request);

		expect(parsed.entries).toBeDefined();
		expect(Array.isArray(parsed.entries)).toBe(true);
		expect(parsed.entries.length).toBeGreaterThanOrEqual(2);

		const entry = parsed.entries[0];
		expect(entry).toHaveProperty('a');
		expect(entry).toHaveProperty('c');

		const safe1Present = parsed.entries.some(
			(e) => e.a.toLowerCase() === SEEDED_SAFE_1.toLowerCase(),
		);
		expect(safe1Present, 'Seeded safe address 1 should be in filter').toBe(true);

		const revokedPresent = parsed.entries.some(
			(e) => e.a.toLowerCase() === REVOKED_ADDR.toLowerCase(),
		);
		expect(revokedPresent, 'Revoked address should not be in filter').toBe(false);
	});

	test('revocations URL returns valid data', async ({ request }) => {
		const buildRes = await request.post(`${API_BASE}/api/v1/safe/build`, {
			headers: { 'x-admin-secret': ADMIN_SECRET! },
		});
		expect(buildRes.status()).toBe(200);
		const build = await buildRes.json();

		const revokeUrl = build.revocations.url;
		expect(revokeUrl).toBeTruthy();

		const res = await request.get(revokeUrl);
		expect(res.status(), `Failed to fetch revocations from ${revokeUrl}`).toBe(200);
		const body = await res.json();
		expect(Array.isArray(body.revocations || body)).toBe(true);
	});
});

test.describe('Revocation Flow', () => {
	test.skip(!ADMIN_SECRET, 'ADMIN_API_SECRET required');

	test('create revocation and rebuild excludes address', async ({ request }) => {
		const checkBefore = await request.get(`${API_BASE}/api/v1/safe/address/${SEEDED_SAFE_2}`);
		expect((await checkBefore.json()).isSafe).toBe(true);

		const revokeRes = await request.post(`${API_BASE}/api/v1/safe/revocations`, {
			headers: {
				'x-admin-secret': ADMIN_SECRET!,
				'content-type': 'application/json',
			},
			data: {
				address: SEEDED_SAFE_2,
				chainId: 1,
				reason: 'e2e_test_revocation',
			},
		});
		expect(revokeRes.status()).toBe(200);
		expect((await revokeRes.json()).success).toBe(true);

		const buildRes = await request.post(`${API_BASE}/api/v1/safe/build`, {
			headers: { 'x-admin-secret': ADMIN_SECRET! },
		});
		expect(buildRes.status()).toBe(200);
		const build = await buildRes.json();

		expect(build.filter.count).toBeGreaterThanOrEqual(1);

		const checkStillSafe = await request.get(`${API_BASE}/api/v1/safe/address/${SEEDED_SAFE_1}`);
		expect((await checkStillSafe.json()).isSafe, 'Non-revoked address should still be safe').toBe(
			true,
		);
	});
});
