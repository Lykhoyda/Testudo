import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { logger } from 'hono/logger';
import { healthRoutes } from './routes/health.js';

const app = new Hono();

app.use('*', logger());

app.get('/', (c) =>
	c.json({
		name: '@testudo/api',
		version: '0.1.0',
		description: 'Testudo Threat Intelligence API',
	}),
);

app.route('/health', healthRoutes);

const port = Number(process.env.PORT) || 3001;

console.log(`Testudo API starting on port ${port}`);

const server = serve({ fetch: app.fetch, port });

const shutdown = () => {
	console.log('Shutting down gracefully...');
	server.close();
	process.exit(0);
};

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
