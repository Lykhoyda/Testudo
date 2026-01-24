import { describe, expect, it, vi, beforeEach } from 'vitest';
import { Hono } from 'hono';

vi.mock('../../src/db/index.js', () => ({
	db: {
		select: vi.fn(),
	},
}));

import { db } from '../../src/db/index.js';
import { syncRoutes } from '../../src/routes/sync.js';

const app = new Hono();
app.route('/api/v1/sync', syncRoutes);

beforeEach(() => {
	vi.clearAllMocks();
});

describe('GET /api/v1/sync/summary', () => {
	it('returns sync metadata with sources as object', async () => {
		const mockSyncLogs = [
			{
				source: 'scam-sniffer-addresses',
				status: 'SUCCESS',
				recordsAdded: 150,
				recordsUpdated: 10,
				syncedAt: new Date('2026-01-24T10:00:00Z'),
			},
			{
				source: 'eth-phishing-detect',
				status: 'SUCCESS',
				recordsAdded: 50120,
				recordsUpdated: 200,
				syncedAt: new Date('2026-01-24T09:30:00Z'),
			},
		];

		const mockFrom = vi.fn();
		const mockWhere = vi.fn();
		const mockOrderBy = vi.fn().mockResolvedValue(mockSyncLogs);

		mockWhere.mockReturnValue({ orderBy: mockOrderBy });
		mockFrom.mockReturnValue({ where: mockWhere });

		const selectFn = vi.mocked(db.select) as unknown as ReturnType<typeof vi.fn>;
		selectFn
			.mockReturnValueOnce({ from: mockFrom })
			.mockReturnValueOnce({
				from: vi.fn().mockResolvedValue([{ count: 5234 }]),
			})
			.mockReturnValueOnce({
				from: vi.fn().mockResolvedValue([{ count: 51000 }]),
			});

		const res = await app.request('/api/v1/sync/summary');
		const body = await res.json();

		expect(res.status).toBe(200);
		expect(body.lastSync).toBe('2026-01-24T10:00:00.000Z');
		expect(body.sources['scam-sniffer-addresses'].status).toBe('SUCCESS');
		expect(body.sources['scam-sniffer-addresses'].recordsAdded).toBe(150);
		expect(body.sources['eth-phishing-detect'].status).toBe('SUCCESS');
		expect(body.threatCount).toBe(5234);
		expect(body.domainCount).toBe(51000);
	});

	it('returns null lastSync when no sync has occurred', async () => {
		const mockFrom = vi.fn();
		const mockWhere = vi.fn();
		const mockOrderBy = vi.fn().mockResolvedValue([]);

		mockWhere.mockReturnValue({ orderBy: mockOrderBy });
		mockFrom.mockReturnValue({ where: mockWhere });

		const selectFn = vi.mocked(db.select) as unknown as ReturnType<typeof vi.fn>;
		selectFn
			.mockReturnValueOnce({ from: mockFrom })
			.mockReturnValueOnce({
				from: vi.fn().mockResolvedValue([{ count: 0 }]),
			})
			.mockReturnValueOnce({
				from: vi.fn().mockResolvedValue([{ count: 0 }]),
			});

		const res = await app.request('/api/v1/sync/summary');
		const body = await res.json();

		expect(res.status).toBe(200);
		expect(body.lastSync).toBeNull();
		expect(body.sources).toEqual({});
		expect(body.threatCount).toBe(0);
		expect(body.domainCount).toBe(0);
	});
});
