import { eq } from 'drizzle-orm';
import { db } from '../../db/index.js';
import { domains, threats } from '../../db/schema.js';
import { checkAddress as checkGoPlus } from './goplus-service.js';

export interface ThreatResult {
	address: string;
	chainId: number;
	threatType: string;
	threatLevel: string;
	confidence: string;
	sources: string[];
	firstSeen: Date;
}

export interface DomainResult {
	domain: string;
	threatType: string;
	confidence: string;
	sources: string[];
	isFuzzyMatch: boolean;
	matchedLegitimate: string | null;
	firstSeen: Date;
}

export async function lookupAddress(address: string): Promise<ThreatResult | null> {
	const result = await db
		.select({
			address: threats.address,
			chainId: threats.chainId,
			threatType: threats.threatType,
			threatLevel: threats.threatLevel,
			confidence: threats.confidence,
			sources: threats.sources,
			firstSeen: threats.firstSeen,
		})
		.from(threats)
		.where(eq(threats.address, address))
		.limit(1);

	if (result.length === 0) {
		const goplusResult = await checkGoPlus(address);
		return goplusResult;
	}
	return result[0] as ThreatResult;
}

export async function lookupDomain(domain: string): Promise<DomainResult | null> {
	const result = await db
		.select({
			domain: domains.domain,
			threatType: domains.threatType,
			confidence: domains.confidence,
			sources: domains.sources,
			isFuzzyMatch: domains.isFuzzyMatch,
			matchedLegitimate: domains.matchedLegitimate,
			firstSeen: domains.firstSeen,
		})
		.from(domains)
		.where(eq(domains.domain, domain))
		.limit(1);

	if (result.length === 0) return null;
	return result[0] as DomainResult;
}
