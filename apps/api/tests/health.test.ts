import { describe, expect, it, vi, beforeEach } from 'vitest';
import { Hono } from 'hono';

vi.mock('../src/db/index.js', () => ({
	checkConnection: vi.fn(),
	db: {},
}));

import { checkConnection } from '../src/db/index.js';
import { healthRoutes } from '../src/routes/health.js';

const app = new Hono();
app.route('/health', healthRoutes);

const mockedCheckConnection = vi.mocked(checkConnection);

beforeEach(() => {
	vi.clearAllMocks();
});

describe('GET /health', () => {
	it('returns 200 with status ok when database is connected', async () => {
		mockedCheckConnection.mockResolvedValue(true);

		const res = await app.request('/health');
		const body = await res.json();

		expect(res.status).toBe(200);
		expect(body.status).toBe('ok');
		expect(body.database).toBe('connected');
		expect(body.timestamp).toBeDefined();
	});

	it('returns 503 with status degraded when database is disconnected', async () => {
		mockedCheckConnection.mockResolvedValue(false);

		const res = await app.request('/health');
		const body = await res.json();

		expect(res.status).toBe(503);
		expect(body.status).toBe('degraded');
		expect(body.database).toBe('disconnected');
	});

	it('includes ISO timestamp in response', async () => {
		mockedCheckConnection.mockResolvedValue(true);

		const res = await app.request('/health');
		const body = await res.json();

		const parsed = new Date(body.timestamp);
		expect(parsed.toISOString()).toBe(body.timestamp);
	});
});
