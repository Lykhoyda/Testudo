import { Hono } from 'hono';
import { checkConnection } from '../db/index.js';

export const healthRoutes = new Hono();

healthRoutes.get('/', async (c) => {
	const dbConnected = await checkConnection();

	const status = dbConnected ? 'ok' : 'degraded';
	const statusCode = dbConnected ? 200 : 503;

	return c.json(
		{
			status,
			database: dbConnected ? 'connected' : 'disconnected',
			timestamp: new Date().toISOString(),
		},
		statusCode,
	);
});
