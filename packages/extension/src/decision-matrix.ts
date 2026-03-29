import type { AnalysisResult } from '@testudo/core';
import type { ApiClientResult } from './api-client';

export interface ExtendedAnalysisResult extends AnalysisResult {
	whitelisted?: boolean;
	cached?: boolean;
	source?:
		| 'api'
		| 'api+local'
		| 'local'
		| 'fallback'
		| 'whitelist'
		| 'safe-filter'
		| 'local-malicious-db';
	apiUnavailable?: boolean;
}

export function applyDecisionMatrix(
	api: ApiClientResult,
	local: AnalysisResult,
	address: string,
): ExtendedAnalysisResult {
	const baseResult = {
		address: address as `0x${string}`,
		warnings: local.warnings,
		deployerRisk: local.deployerRisk,
	};

	// API returned malicious → BLOCK (highest priority)
	if (api.success && api.data?.isMalicious === true) {
		const apiThreat = api.data.threatType || 'KNOWN_MALICIOUS';
		const mergedThreats = [...new Set([apiThreat, ...(local.threats || [])])];
		console.log('[Testudo] API flagged as malicious:', address);
		return {
			...baseResult,
			risk: 'CRITICAL',
			threats: mergedThreats,
			blocked: true,
			source: 'api',
		};
	}

	// API available and clean (must have valid data with explicit false)
	if (api.success && api.data != null && api.data.isMalicious === false) {
		// API Clean + Local Clean → ALLOW
		if (local.risk === 'LOW') {
			console.log('[Testudo] Both API and local clean:', address);
			return {
				...baseResult,
				risk: 'LOW',
				threats: [],
				blocked: false,
				source: 'api+local',
			};
		}

		// API Clean + Local UNKNOWN → preserve UNKNOWN (analysis incomplete)
		// UNKNOWN means bytecode fetch failed or analysis errored — not "safe"
		if (local.risk === 'UNKNOWN') {
			console.log('[Testudo] API clean but local analysis incomplete:', address);
			return {
				...baseResult,
				risk: 'UNKNOWN',
				threats: local.threats,
				blocked: false,
				source: 'api+local',
			};
		}

		// API Clean + Local CRITICAL/HIGH → BLOCK (local override, ADR-013)
		// Local bytecode evidence is deterministic and catches zero-day threats
		// that the API hasn't indexed yet. CRITICAL/HIGH findings (auto-forwarder,
		// metamorphic, token drain) are high-confidence — they override API clean.
		if (local.risk === 'CRITICAL' || local.risk === 'HIGH') {
			console.log('[Testudo] API clean but local override (zero-day):', address);
			return {
				...baseResult,
				risk: local.risk,
				threats: local.threats,
				blocked: true,
				source: 'local',
			};
		}

		// API Clean + Local MEDIUM → WARN (local caught new pattern, don't block)
		console.log('[Testudo] API clean but local suspicious:', address);
		return {
			...baseResult,
			risk: local.risk,
			threats: local.threats,
			blocked: false,
			source: 'local',
		};
	}

	// API unavailable (timeout, offline, error, or success without valid data)
	if (local.risk === 'LOW') {
		console.log('[Testudo] API unavailable, local clean:', address);
		return {
			...baseResult,
			risk: 'LOW',
			threats: [],
			blocked: false,
			source: 'local',
			apiUnavailable: true,
		};
	}

	if (local.risk === 'UNKNOWN') {
		console.log('[Testudo] API unavailable, local unknown:', address);
		return {
			...baseResult,
			risk: 'UNKNOWN',
			threats: local.threats,
			blocked: false,
			source: 'local',
			apiUnavailable: true,
		};
	}

	// API Unavailable + Local Suspicious (MEDIUM/HIGH/CRITICAL) → BLOCK (fail-safe)
	console.log('[Testudo] API unavailable, local suspicious:', address);
	return {
		...baseResult,
		risk: local.risk,
		threats: local.threats,
		blocked: true,
		source: 'local',
		apiUnavailable: true,
	};
}
