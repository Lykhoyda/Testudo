import { describe, expect, it } from 'vitest';
import { assessDeployerRisk, generateDeployerWarnings } from '../src/deployer-risk';
import type { DeployerInfo, DeployerRiskAssessment } from '../src/types';

const NOW = 1_700_000_000;

function makeInfo(overrides: Partial<DeployerInfo> = {}): DeployerInfo {
	return {
		deployerAddress: '0x1234567890abcdef1234567890abcdef12345678',
		deployerNonce: 100,
		contractCreationTimestamp: NOW - 7 * 86_400,
		currentTimestamp: NOW,
		...overrides,
	};
}

describe('assessDeployerRisk', () => {
	describe('CRITICAL: low nonce + fresh contract', () => {
		it('nonce=0, contract age 1 hour', () => {
			const result = assessDeployerRisk(
				makeInfo({ deployerNonce: 0, contractCreationTimestamp: NOW - 3600 }),
			);
			expect(result.risk).toBe('CRITICAL');
			expect(result.reasons).toHaveLength(1);
			expect(result.reasons[0]).toContain('0 transactions');
			expect(result.reasons[0]).toContain('less than 24h');
		});

		it('nonce=2, contract age 30 minutes', () => {
			const result = assessDeployerRisk(
				makeInfo({ deployerNonce: 2, contractCreationTimestamp: NOW - 1800 }),
			);
			expect(result.risk).toBe('CRITICAL');
		});

		it('nonce=4, contract age 23 hours', () => {
			const result = assessDeployerRisk(
				makeInfo({ deployerNonce: 4, contractCreationTimestamp: NOW - 23 * 3600 }),
			);
			expect(result.risk).toBe('CRITICAL');
		});
	});

	describe('HIGH: low nonce + older contract', () => {
		it('nonce=1, contract age 48 hours', () => {
			const result = assessDeployerRisk(
				makeInfo({ deployerNonce: 1, contractCreationTimestamp: NOW - 48 * 3600 }),
			);
			expect(result.risk).toBe('HIGH');
			expect(result.reasons[0]).toContain('1 transactions');
		});

		it('nonce=3, contract age 7 days', () => {
			const result = assessDeployerRisk(
				makeInfo({ deployerNonce: 3, contractCreationTimestamp: NOW - 7 * 86_400 }),
			);
			expect(result.risk).toBe('HIGH');
		});

		it('nonce=4, contract age 30 days', () => {
			const result = assessDeployerRisk(
				makeInfo({ deployerNonce: 4, contractCreationTimestamp: NOW - 30 * 86_400 }),
			);
			expect(result.risk).toBe('HIGH');
		});
	});

	describe('MEDIUM: moderate nonce + fresh contract', () => {
		it('nonce=5, contract age 6 hours', () => {
			const result = assessDeployerRisk(
				makeInfo({ deployerNonce: 5, contractCreationTimestamp: NOW - 6 * 3600 }),
			);
			expect(result.risk).toBe('MEDIUM');
			expect(result.reasons[0]).toContain('less than 24h');
			expect(result.reasons[0]).toContain('5 transactions');
		});

		it('nonce=25, contract age 12 hours', () => {
			const result = assessDeployerRisk(
				makeInfo({ deployerNonce: 25, contractCreationTimestamp: NOW - 12 * 3600 }),
			);
			expect(result.risk).toBe('MEDIUM');
		});

		it('nonce=49, contract age 1 hour', () => {
			const result = assessDeployerRisk(
				makeInfo({ deployerNonce: 49, contractCreationTimestamp: NOW - 3600 }),
			);
			expect(result.risk).toBe('MEDIUM');
		});
	});

	describe('LOW: established deployer', () => {
		it('nonce=50, any age', () => {
			const result = assessDeployerRisk(
				makeInfo({ deployerNonce: 50, contractCreationTimestamp: NOW - 3600 }),
			);
			expect(result.risk).toBe('LOW');
			expect(result.reasons).toHaveLength(0);
		});

		it('nonce=1500, old contract', () => {
			const result = assessDeployerRisk(
				makeInfo({ deployerNonce: 1500, contractCreationTimestamp: NOW - 365 * 86_400 }),
			);
			expect(result.risk).toBe('LOW');
		});

		it('nonce=5, old contract (>= 24h)', () => {
			const result = assessDeployerRisk(
				makeInfo({ deployerNonce: 5, contractCreationTimestamp: NOW - 25 * 3600 }),
			);
			expect(result.risk).toBe('LOW');
		});
	});

	describe('boundary conditions', () => {
		it('nonce=5 is boundary between suspicious and moderate', () => {
			const fresh = makeInfo({ deployerNonce: 5, contractCreationTimestamp: NOW - 3600 });
			expect(assessDeployerRisk(fresh).risk).toBe('MEDIUM');

			const old = makeInfo({ deployerNonce: 5, contractCreationTimestamp: NOW - 25 * 3600 });
			expect(assessDeployerRisk(old).risk).toBe('LOW');

			const belowFresh = makeInfo({ deployerNonce: 4, contractCreationTimestamp: NOW - 3600 });
			expect(assessDeployerRisk(belowFresh).risk).toBe('CRITICAL');
		});

		it('nonce=50 is boundary between moderate and established', () => {
			const fresh = makeInfo({ deployerNonce: 50, contractCreationTimestamp: NOW - 3600 });
			expect(assessDeployerRisk(fresh).risk).toBe('LOW');

			const belowFresh = makeInfo({ deployerNonce: 49, contractCreationTimestamp: NOW - 3600 });
			expect(assessDeployerRisk(belowFresh).risk).toBe('MEDIUM');
		});

		it('contract age exactly 24h is not < 24h', () => {
			const result = assessDeployerRisk(
				makeInfo({ deployerNonce: 2, contractCreationTimestamp: NOW - 86_400 }),
			);
			expect(result.risk).toBe('HIGH');
		});

		it('negative timestamp difference clamps to zero', () => {
			const result = assessDeployerRisk(
				makeInfo({ deployerNonce: 2, contractCreationTimestamp: NOW + 3600 }),
			);
			expect(result.contractAge).toBe(0);
			expect(result.risk).toBe('CRITICAL');
		});
	});

	it('returns correct contractAge and deployerNonce', () => {
		const result = assessDeployerRisk(
			makeInfo({ deployerNonce: 42, contractCreationTimestamp: NOW - 7200 }),
		);
		expect(result.contractAge).toBe(7200);
		expect(result.deployerNonce).toBe(42);
	});
});

describe('generateDeployerWarnings', () => {
	it('returns empty array for LOW risk', () => {
		const assessment: DeployerRiskAssessment = {
			risk: 'LOW',
			contractAge: 86_400 * 30,
			deployerNonce: 500,
			reasons: [],
		};
		expect(generateDeployerWarnings(assessment)).toEqual([]);
	});

	it('generates DEPLOYER_FRESH warning for CRITICAL risk', () => {
		const assessment: DeployerRiskAssessment = {
			risk: 'CRITICAL',
			contractAge: 3600,
			deployerNonce: 2,
			reasons: ['test'],
		};
		const warnings = generateDeployerWarnings(assessment);
		expect(warnings).toHaveLength(1);
		expect(warnings[0].type).toBe('DEPLOYER_FRESH');
		expect(warnings[0].severity).toBe('CRITICAL');
		expect(warnings[0].title).toBe('Freshly Deployed by New Account');
		expect(warnings[0].description).toContain('2 transactions');
		expect(warnings[0].technical).toContain('nonce: 2');
		expect(warnings[0].technical).toContain('1h');
	});

	it('generates DEPLOYER_LOW_NONCE warning for HIGH risk', () => {
		const assessment: DeployerRiskAssessment = {
			risk: 'HIGH',
			contractAge: 86_400 * 3,
			deployerNonce: 3,
			reasons: ['test'],
		};
		const warnings = generateDeployerWarnings(assessment);
		expect(warnings).toHaveLength(1);
		expect(warnings[0].type).toBe('DEPLOYER_LOW_NONCE');
		expect(warnings[0].severity).toBe('HIGH');
		expect(warnings[0].description).toContain('3');
	});

	it('generates DEPLOYER_NEW_CONTRACT warning for MEDIUM risk', () => {
		const assessment: DeployerRiskAssessment = {
			risk: 'MEDIUM',
			contractAge: 3600 * 6,
			deployerNonce: 25,
			reasons: ['test'],
		};
		const warnings = generateDeployerWarnings(assessment);
		expect(warnings).toHaveLength(1);
		expect(warnings[0].type).toBe('DEPLOYER_NEW_CONTRACT');
		expect(warnings[0].severity).toBe('MEDIUM');
		expect(warnings[0].technical).toContain('6h');
	});

	it('formats age correctly in technical field', () => {
		const minutesAssessment: DeployerRiskAssessment = {
			risk: 'CRITICAL',
			contractAge: 1800,
			deployerNonce: 1,
			reasons: ['test'],
		};
		expect(generateDeployerWarnings(minutesAssessment)[0].technical).toContain('30m');

		const hoursAssessment: DeployerRiskAssessment = {
			risk: 'CRITICAL',
			contractAge: 7200,
			deployerNonce: 1,
			reasons: ['test'],
		};
		expect(generateDeployerWarnings(hoursAssessment)[0].technical).toContain('2h');

		const daysAssessment: DeployerRiskAssessment = {
			risk: 'HIGH',
			contractAge: 86_400 * 3,
			deployerNonce: 1,
			reasons: ['test'],
		};
		expect(generateDeployerWarnings(daysAssessment)[0].technical).not.toContain('d');
	});
});
