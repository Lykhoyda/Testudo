import type { AnalysisResult, DeployerRiskAssessment, Warning } from '@testudo/core';
import { describe, expect, it } from 'vitest';
import type { ApiClientResult } from '../src/api-client';
import { applyDecisionMatrix } from '../src/decision-matrix';

const ADDRESS = '0xabcdef1234567890abcdef1234567890abcdef12';

function makeApiResult(overrides: Partial<ApiClientResult> = {}): ApiClientResult {
	return {
		success: true,
		data: { isMalicious: false, address: ADDRESS },
		...overrides,
	};
}

function makeLocalResult(overrides: Partial<AnalysisResult> = {}): AnalysisResult {
	return {
		address: ADDRESS as `0x${string}`,
		risk: 'LOW',
		threats: [],
		blocked: false,
		...overrides,
	};
}

function makeWarning(
	severity: Warning['severity'],
	type: Warning['type'] = 'AUTO_FORWARDER',
): Warning {
	return { type, severity, title: 'Test', description: 'Test warning' };
}

const mockDeployerRisk: DeployerRiskAssessment = {
	risk: 'HIGH',
	contractAge: 3600,
	deployerNonce: 2,
	reasons: ['Low nonce deployer'],
};

describe('applyDecisionMatrix', () => {
	// ====================================================================
	// Branch A: API malicious → always BLOCK
	// ====================================================================
	describe('API malicious (Branch A)', () => {
		it('blocks when API flags as malicious regardless of local result', () => {
			const api = makeApiResult({
				data: { isMalicious: true, address: ADDRESS, threatType: 'ETH_DRAINER' },
			});
			const local = makeLocalResult({ risk: 'LOW' });

			const result = applyDecisionMatrix(api, local, ADDRESS);

			expect(result.risk).toBe('CRITICAL');
			expect(result.blocked).toBe(true);
			expect(result.threats).toContain('ETH_DRAINER');
			expect(result.source).toBe('api');
		});

		it('uses KNOWN_MALICIOUS as default threat type when API omits threatType', () => {
			const api = makeApiResult({
				data: { isMalicious: true, address: ADDRESS },
			});

			const result = applyDecisionMatrix(api, makeLocalResult(), ADDRESS);

			expect(result.threats).toContain('KNOWN_MALICIOUS');
		});

		it('merges API and local threats when both present', () => {
			const api = makeApiResult({
				data: { isMalicious: true, address: ADDRESS, threatType: 'PHISHING' },
			});
			const local = makeLocalResult({
				risk: 'CRITICAL',
				threats: ['auto_forwarder', 'metamorphic'],
				warnings: [makeWarning('CRITICAL'), makeWarning('CRITICAL', 'METAMORPHIC')],
			});

			const result = applyDecisionMatrix(api, local, ADDRESS);

			expect(result.threats).toContain('PHISHING');
			expect(result.threats).toContain('auto_forwarder');
			expect(result.threats).toContain('metamorphic');
			expect(result.threats).toHaveLength(3);
		});

		it('deduplicates threats when API and local report same type', () => {
			const api = makeApiResult({
				data: { isMalicious: true, address: ADDRESS, threatType: 'auto_forwarder' },
			});
			const local = makeLocalResult({
				risk: 'CRITICAL',
				threats: ['auto_forwarder'],
			});

			const result = applyDecisionMatrix(api, local, ADDRESS);

			expect(result.threats).toEqual(['auto_forwarder']);
		});

		it('blocks even when local analysis found CRITICAL', () => {
			const api = makeApiResult({
				data: { isMalicious: true, address: ADDRESS, threatType: 'PHISHING' },
			});
			const local = makeLocalResult({
				risk: 'CRITICAL',
				threats: ['auto_forwarder'],
				warnings: [makeWarning('CRITICAL')],
			});

			const result = applyDecisionMatrix(api, local, ADDRESS);

			expect(result.risk).toBe('CRITICAL');
			expect(result.blocked).toBe(true);
			expect(result.source).toBe('api');
		});
	});

	// ====================================================================
	// Branch B1: API clean + Local clean → ALLOW
	// ====================================================================
	describe('API clean + Local clean (Branch B1)', () => {
		it('allows when both API and local say clean (LOW)', () => {
			const api = makeApiResult();
			const local = makeLocalResult({ risk: 'LOW' });

			const result = applyDecisionMatrix(api, local, ADDRESS);

			expect(result.risk).toBe('LOW');
			expect(result.blocked).toBe(false);
			expect(result.threats).toEqual([]);
			expect(result.source).toBe('api+local');
		});

		it('preserves UNKNOWN when API clean but local analysis incomplete', () => {
			const api = makeApiResult();
			const local = makeLocalResult({ risk: 'UNKNOWN', threats: ['Analysis failed'] });

			const result = applyDecisionMatrix(api, local, ADDRESS);

			expect(result.risk).toBe('UNKNOWN');
			expect(result.blocked).toBe(false);
			expect(result.threats).toEqual(['Analysis failed']);
			expect(result.source).toBe('api+local');
		});
	});

	// ====================================================================
	// Branch B2: API clean + Local suspicious → LOCAL OVERRIDE (ADR-013)
	// ====================================================================
	describe('API clean + Local CRITICAL/HIGH → BLOCK (Branch B2, ADR-013)', () => {
		it('blocks when API clean but local found CRITICAL (zero-day override)', () => {
			const warnings = [makeWarning('CRITICAL', 'AUTO_FORWARDER')];
			const api = makeApiResult();
			const local = makeLocalResult({
				risk: 'CRITICAL',
				threats: ['auto_forwarder'],
				blocked: true,
				warnings,
			});

			const result = applyDecisionMatrix(api, local, ADDRESS);

			expect(result.risk).toBe('CRITICAL');
			expect(result.blocked).toBe(true);
			expect(result.threats).toEqual(['auto_forwarder']);
			expect(result.source).toBe('local');
		});

		it('blocks when API clean but local found HIGH', () => {
			const warnings = [makeWarning('HIGH', 'SELF_DESTRUCT')];
			const api = makeApiResult();
			const local = makeLocalResult({
				risk: 'HIGH',
				threats: ['self_destruct'],
				blocked: true,
				warnings,
			});

			const result = applyDecisionMatrix(api, local, ADDRESS);

			expect(result.risk).toBe('HIGH');
			expect(result.blocked).toBe(true);
			expect(result.threats).toEqual(['self_destruct']);
			expect(result.source).toBe('local');
		});

		it('blocks CRITICAL even with multiple threats', () => {
			const warnings = [
				makeWarning('CRITICAL', 'METAMORPHIC'),
				makeWarning('HIGH', 'SELF_DESTRUCT'),
				makeWarning('MEDIUM', 'CREATE2'),
			];
			const api = makeApiResult();
			const local = makeLocalResult({
				risk: 'CRITICAL',
				threats: ['metamorphic', 'self_destruct', 'create2'],
				blocked: true,
				warnings,
			});

			const result = applyDecisionMatrix(api, local, ADDRESS);

			expect(result.risk).toBe('CRITICAL');
			expect(result.blocked).toBe(true);
			expect(result.threats).toHaveLength(3);
		});
	});

	describe('API clean + Local MEDIUM → WARN (Branch B2c)', () => {
		it('warns but does not block when API clean and local found MEDIUM', () => {
			const warnings = [makeWarning('MEDIUM', 'CREATE2')];
			const api = makeApiResult();
			const local = makeLocalResult({
				risk: 'MEDIUM',
				threats: ['create2'],
				blocked: false,
				warnings,
			});

			const result = applyDecisionMatrix(api, local, ADDRESS);

			expect(result.risk).toBe('MEDIUM');
			expect(result.blocked).toBe(false);
			expect(result.threats).toEqual(['create2']);
			expect(result.source).toBe('local');
		});
	});

	// ====================================================================
	// Branch C: API unavailable
	// ====================================================================
	describe('API unavailable (Branch C)', () => {
		const unavailableApi = makeApiResult({
			success: false,
			data: undefined,
			error: 'timeout',
		});

		it('allows when API unavailable and local clean (C1)', () => {
			const local = makeLocalResult({ risk: 'LOW' });

			const result = applyDecisionMatrix(unavailableApi, local, ADDRESS);

			expect(result.risk).toBe('LOW');
			expect(result.blocked).toBe(false);
			expect(result.source).toBe('local');
			expect(result.apiUnavailable).toBe(true);
		});

		it('returns UNKNOWN when API unavailable and local UNKNOWN (C2)', () => {
			const local = makeLocalResult({
				risk: 'UNKNOWN',
				threats: ['Local analysis failed'],
			});

			const result = applyDecisionMatrix(unavailableApi, local, ADDRESS);

			expect(result.risk).toBe('UNKNOWN');
			expect(result.blocked).toBe(false);
			expect(result.source).toBe('local');
			expect(result.apiUnavailable).toBe(true);
		});

		it('blocks when API unavailable and local found CRITICAL (C3)', () => {
			const local = makeLocalResult({
				risk: 'CRITICAL',
				threats: ['auto_forwarder'],
				blocked: true,
			});

			const result = applyDecisionMatrix(unavailableApi, local, ADDRESS);

			expect(result.risk).toBe('CRITICAL');
			expect(result.blocked).toBe(true);
			expect(result.source).toBe('local');
			expect(result.apiUnavailable).toBe(true);
		});

		it('blocks when API unavailable and local found HIGH (C3)', () => {
			const local = makeLocalResult({
				risk: 'HIGH',
				threats: ['delegate_call'],
				blocked: true,
			});

			const result = applyDecisionMatrix(unavailableApi, local, ADDRESS);

			expect(result.risk).toBe('HIGH');
			expect(result.blocked).toBe(true);
			expect(result.apiUnavailable).toBe(true);
		});

		it('blocks when API unavailable and local found MEDIUM (C3)', () => {
			const local = makeLocalResult({
				risk: 'MEDIUM',
				threats: ['create2'],
				blocked: false,
			});

			const result = applyDecisionMatrix(unavailableApi, local, ADDRESS);

			expect(result.risk).toBe('MEDIUM');
			expect(result.blocked).toBe(true);
			expect(result.apiUnavailable).toBe(true);
		});
	});

	// ====================================================================
	// Base result passthrough
	// ====================================================================
	describe('base result passthrough', () => {
		it('preserves warnings through API malicious branch', () => {
			const warnings = [makeWarning('HIGH', 'DELEGATE_CALL')];
			const api = makeApiResult({
				data: { isMalicious: true, address: ADDRESS, threatType: 'ETH_DRAINER' },
			});
			const local = makeLocalResult({ warnings });

			const result = applyDecisionMatrix(api, local, ADDRESS);

			expect(result.warnings).toEqual(warnings);
		});

		it('preserves deployerRisk through all branches', () => {
			const api = makeApiResult();
			const local = makeLocalResult({ deployerRisk: mockDeployerRisk });

			const result = applyDecisionMatrix(api, local, ADDRESS);

			expect(result.deployerRisk).toEqual(mockDeployerRisk);
		});

		it('preserves warnings through API clean + local CRITICAL branch', () => {
			const warnings = [makeWarning('CRITICAL', 'AUTO_FORWARDER')];
			const api = makeApiResult();
			const local = makeLocalResult({
				risk: 'CRITICAL',
				threats: ['auto_forwarder'],
				warnings,
			});

			const result = applyDecisionMatrix(api, local, ADDRESS);

			expect(result.warnings).toEqual(warnings);
			expect(result.deployerRisk).toBeUndefined();
		});

		it('preserves deployerRisk through API unavailable branch', () => {
			const api = makeApiResult({ success: false, data: undefined, error: 'offline' });
			const local = makeLocalResult({
				risk: 'HIGH',
				threats: ['delegate_call'],
				deployerRisk: mockDeployerRisk,
			});

			const result = applyDecisionMatrix(api, local, ADDRESS);

			expect(result.deployerRisk).toEqual(mockDeployerRisk);
		});
	});

	// ====================================================================
	// Edge cases
	// ====================================================================
	describe('edge cases', () => {
		it('normalizes address in output', () => {
			const api = makeApiResult();
			const local = makeLocalResult();

			const result = applyDecisionMatrix(api, local, ADDRESS);

			expect(result.address).toBe(ADDRESS);
		});

		it('handles API offline flag', () => {
			const api = makeApiResult({
				success: false,
				data: undefined,
				offline: true,
			});
			const local = makeLocalResult({ risk: 'LOW' });

			const result = applyDecisionMatrix(api, local, ADDRESS);

			expect(result.apiUnavailable).toBe(true);
			expect(result.blocked).toBe(false);
		});

		it('handles API rate limited', () => {
			const api = makeApiResult({
				success: false,
				data: undefined,
				rateLimited: true,
			});
			const local = makeLocalResult({
				risk: 'CRITICAL',
				threats: ['auto_forwarder'],
			});

			const result = applyDecisionMatrix(api, local, ADDRESS);

			expect(result.blocked).toBe(true);
			expect(result.apiUnavailable).toBe(true);
		});

		it('treats success:true with missing data as API unavailable', () => {
			const api: ApiClientResult = { success: true };
			const local = makeLocalResult({ risk: 'CRITICAL', threats: ['auto_forwarder'] });

			const result = applyDecisionMatrix(api, local, ADDRESS);

			expect(result.blocked).toBe(true);
			expect(result.apiUnavailable).toBe(true);
			expect(result.source).toBe('local');
		});

		it('does not treat success:true with missing data as clean', () => {
			const api: ApiClientResult = { success: true };
			const local = makeLocalResult({ risk: 'LOW' });

			const result = applyDecisionMatrix(api, local, ADDRESS);

			expect(result.apiUnavailable).toBe(true);
			expect(result.source).not.toBe('api+local');
		});
	});
});
