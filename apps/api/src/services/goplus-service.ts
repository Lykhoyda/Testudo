import { db } from '../db/index.js';
import { threats } from '../db/schema.js';
import type { ThreatResult } from './threat-service.js';

interface GoPlusAddressResponse {
	code: number;
	result: Record<
		string,
		{
			stealing_attack?: string;
			phishing_activities?: string;
			blacklist_doubt?: string;
			honeypot_related_address?: string;
		}
	>;
}

interface GoPlusThreatMapping {
	threatLevel: string;
	threatType: string;
}

const GOPLUS_TIMEOUT_MS = 5_000;

const THREAT_PRIORITY: { field: string; mapping: GoPlusThreatMapping }[] = [
	{ field: 'stealing_attack', mapping: { threatLevel: 'CRITICAL', threatType: 'ETH_DRAINER' } },
	{ field: 'phishing_activities', mapping: { threatLevel: 'HIGH', threatType: 'PHISHING' } },
	{ field: 'blacklist_doubt', mapping: { threatLevel: 'HIGH', threatType: 'SCAM' } },
	{
		field: 'honeypot_related_address',
		mapping: { threatLevel: 'MEDIUM', threatType: 'HONEYPOT' },
	},
];

export async function checkAddress(
	address: string,
	chainId: number = 1,
): Promise<ThreatResult | null> {
	try {
		const controller = new AbortController();
		const timeout = setTimeout(() => controller.abort(), GOPLUS_TIMEOUT_MS);

		const response = await fetch(
			`https://api.gopluslabs.io/api/v1/address_security/${address}?chain_id=${chainId}`,
			{ signal: controller.signal },
		);
		clearTimeout(timeout);

		if (!response.ok) return null;

		const data = (await response.json()) as GoPlusAddressResponse;
		if (data.code !== 1) return null;

		const result = data.result[address.toLowerCase()];
		if (!result) return null;

		for (const { field, mapping } of THREAT_PRIORITY) {
			if (result[field as keyof typeof result] === '1') {
				const now = new Date();
				const threatResult: ThreatResult = {
					address: address.toLowerCase(),
					chainId,
					threatType: mapping.threatType,
					threatLevel: mapping.threatLevel,
					confidence: '0.65',
					sources: ['goplus'],
					firstSeen: now,
				};

				await db
					.insert(threats)
					.values({
						address: address.toLowerCase(),
						chainId,
						threatType: mapping.threatType,
						threatLevel: mapping.threatLevel,
						confidence: '0.65',
						sources: ['goplus'],
						firstSeen: now,
						lastUpdated: now,
					})
					.onConflictDoUpdate({
						target: threats.address,
						set: {
							threatType: mapping.threatType,
							threatLevel: mapping.threatLevel,
							lastUpdated: now,
						},
					});

				return threatResult;
			}
		}

		return null;
	} catch (error) {
		console.error('[GoPlus] Lookup failed:', {
			address,
			chainId,
			error: error instanceof Error ? error.message : String(error),
		});
		return null;
	}
}
