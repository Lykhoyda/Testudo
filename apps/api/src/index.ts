import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { secureHeaders } from 'hono/secure-headers';
import { healthRoutes } from './routes/health.js';
import { syncRoutes } from './routes/sync.js';
import { threatRoutes } from './routes/threats.js';
import { startScheduler, stopScheduler } from './sync/scheduler.js';

const app = new Hono();

app.use('*', logger());
app.use('*', secureHeaders());
app.use('*', cors());

app.get('/', (c) =>
	c.json({
		name: '@testudo/api',
		version: '0.1.0',
		description: 'Testudo Threat Intelligence API',
	}),
);

app.route('/health', healthRoutes);
app.route('/api/v1/threats', threatRoutes);
app.route('/api/v1/sync', syncRoutes);

app.onError((err, c) => {
	console.error('[Testudo API] Unhandled error:', err);
	return c.json({ error: 'Internal server error', code: 'INTERNAL_ERROR' }, 500);
});

const port = Number(process.env.PORT) || 3001;

console.log(`Testudo API starting on port ${port}`);

const server = serve({ fetch: app.fetch, port });

startScheduler();

const shutdown = () => {
	console.log('Shutting down gracefully...');
	stopScheduler();
	server.close();
	process.exit(0);
};

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
