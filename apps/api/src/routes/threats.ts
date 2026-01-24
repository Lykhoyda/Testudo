import { Hono } from 'hono';
import { lookupAddress, lookupDomain } from '../services/threat-service.js';
import {
	isValidAddress,
	isValidDomain,
	normalizeAddress,
	normalizeDomain,
} from '../utils/validation.js';

export const threatRoutes = new Hono();

threatRoutes.get('/address/:address', async (c) => {
	const raw = c.req.param('address');

	if (!isValidAddress(raw)) {
		return c.json({ error: 'Invalid address format', code: 'INVALID_ADDRESS' }, 400);
	}

	const address = normalizeAddress(raw);
	const threat = await lookupAddress(address);

	if (threat) {
		return c.json({
			isMalicious: true,
			address: threat.address,
			chainId: threat.chainId,
			threatType: threat.threatType,
			threatLevel: threat.threatLevel,
			confidence: Number(threat.confidence),
			sources: threat.sources,
			firstSeen: threat.firstSeen.toISOString(),
		});
	}

	return c.json({ isMalicious: false, address });
});

threatRoutes.get('/domain/:domain', async (c) => {
	const raw = c.req.param('domain');
	const domain = normalizeDomain(raw);

	if (!isValidDomain(raw)) {
		return c.json({ error: 'Invalid domain', code: 'INVALID_DOMAIN' }, 400);
	}

	const threat = await lookupDomain(domain);

	if (threat) {
		return c.json({
			isMalicious: true,
			domain: threat.domain,
			threatType: threat.threatType,
			confidence: Number(threat.confidence),
			sources: threat.sources,
			isFuzzyMatch: threat.isFuzzyMatch,
			matchedLegitimate: threat.matchedLegitimate,
			firstSeen: threat.firstSeen.toISOString(),
		});
	}

	return c.json({ isMalicious: false, domain });
});
