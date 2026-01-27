import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Hono } from 'hono';

vi.mock('../../src/db/index.js', () => ({
	db: {
		select: vi.fn().mockReturnValue({
			from: vi.fn().mockReturnValue({
				where: vi.fn().mockReturnValue({
					limit: vi.fn().mockResolvedValue([]),
				}),
			}),
		}),
		insert: vi.fn().mockReturnValue({
			values: vi.fn().mockReturnValue({
				returning: vi.fn().mockResolvedValue([{ id: 1 }]),
			}),
		}),
	},
}));

vi.mock('../../src/modules/safe/filter-service.js', () => ({
	buildFilter: vi.fn().mockResolvedValue({ version: 'v1', url: 'https://cdn.test/v1.json.gz', count: 10 }),
	buildRevocations: vi.fn().mockResolvedValue({ version: 'v1', url: 'https://cdn.test/rev.json', count: 0 }),
	getManifest: vi.fn().mockResolvedValue(null),
}));

vi.mock('../../src/modules/safe/orchestrator.js', () => ({
	runSafeSync: vi.fn().mockResolvedValue(undefined),
}));

import { safeRoutes } from '../../src/routes/safe.js';
import { getManifest } from '../../src/modules/safe/filter-service.js';

const app = new Hono();
app.route('/api/v1/safe', safeRoutes);

beforeEach(() => {
	vi.clearAllMocks();
	vi.stubEnv('ADMIN_API_SECRET', 'test-secret');
});

describe('Safe routes', () => {
	describe('GET /api/v1/safe/address/:address', () => {
		it('returns isSafe: false for unknown address', async () => {
			const res = await app.request('/api/v1/safe/address/0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b');
			const body = await res.json();

			expect(res.status).toBe(200);
			expect(body.isSafe).toBe(false);
		});

		it('returns 400 for invalid address', async () => {
			const res = await app.request('/api/v1/safe/address/invalid');
			expect(res.status).toBe(400);
		});
	});

	describe('POST /api/v1/safe/revocations', () => {
		it('returns 401 without admin secret', async () => {
			const res = await app.request('/api/v1/safe/revocations', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ address: '0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b', reason: 'Compromised' }),
			});
			expect(res.status).toBe(401);
		});

		it('creates revocation with valid admin secret', async () => {
			const res = await app.request('/api/v1/safe/revocations', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'x-admin-secret': 'test-secret',
				},
				body: JSON.stringify({ address: '0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b', reason: 'Compromised' }),
			});
			const body = await res.json();

			expect(res.status).toBe(200);
			expect(body.success).toBe(true);
			expect(body.id).toBe(1);
		});
	});

	describe('POST /api/v1/safe/build', () => {
		it('returns 401 without admin secret', async () => {
			const res = await app.request('/api/v1/safe/build', { method: 'POST' });
			expect(res.status).toBe(401);
		});
	});

	describe('GET /api/v1/safe/manifest', () => {
		it('returns 404 when no builds exist', async () => {
			const res = await app.request('/api/v1/safe/manifest');
			expect(res.status).toBe(404);
		});

		it('returns manifest when builds exist', async () => {
			vi.mocked(getManifest).mockResolvedValueOnce({
				version: 'v1',
				format: 'json-gzip',
				entryCount: 100,
				fileSizeBytes: 5000,
				sha256: 'abc123',
				url: 'https://cdn.test/v1.json.gz',
				revocationCount: 2,
				createdAt: '2026-01-27T00:00:00.000Z',
			});

			const res = await app.request('/api/v1/safe/manifest');
			const body = await res.json();

			expect(res.status).toBe(200);
			expect(body.version).toBe('v1');
			expect(body.entryCount).toBe(100);
		});
	});
});
