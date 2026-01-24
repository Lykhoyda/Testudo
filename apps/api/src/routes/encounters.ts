import { Hono } from 'hono';
import { db } from '../db/index.js';
import { encounters } from '../db/schema.js';
import {
	isValidAddress,
	isValidDomain,
	normalizeAddress,
	normalizeDomain,
} from '../utils/validation.js';

const VALID_ACTIONS = ['blocked', 'proceeded', 'dismissed'] as const;

export const encounterRoutes = new Hono();

encounterRoutes.post('/', async (c) => {
	const body = await c.req.json().catch(() => null);
	if (!body) {
		return c.json({ error: 'Invalid JSON body', code: 'INVALID_BODY' }, 400);
	}

	const { address, domain, chainId, action, extensionVersion } = body;

	if (!address && !domain) {
		return c.json(
			{ error: 'At least one of address or domain is required', code: 'MISSING_IDENTIFIER' },
			400,
		);
	}

	if (address && !isValidAddress(address)) {
		return c.json({ error: 'Invalid address format', code: 'INVALID_ADDRESS' }, 400);
	}

	if (domain && !isValidDomain(domain)) {
		return c.json({ error: 'Invalid domain format', code: 'INVALID_DOMAIN' }, 400);
	}

	if (!VALID_ACTIONS.includes(action)) {
		return c.json(
			{
				error: `Invalid action. Must be one of: ${VALID_ACTIONS.join(', ')}`,
				code: 'INVALID_ACTION',
			},
			400,
		);
	}

	if (!extensionVersion || typeof extensionVersion !== 'string' || extensionVersion.trim() === '') {
		return c.json({ error: 'extensionVersion is required', code: 'MISSING_VERSION' }, 400);
	}

	const result = await db
		.insert(encounters)
		.values({
			address: address ? normalizeAddress(address) : null,
			domain: domain ? normalizeDomain(domain) : null,
			chainId: chainId ?? 1,
			action,
			extensionVersion: extensionVersion.trim(),
		})
		.returning({ id: encounters.id });

	return c.json({ success: true, id: result[0].id }, 201);
});
