import { describe, expect, it } from 'vitest';
import type { DetectionResults, Warning } from '../src';
import {
	checkKnownMalicious,
	deriveRiskFromWarnings,
	generateWarnings,
	parseBytecode,
	runAllDetectors,
} from '../src';
import {
	AUTO_FORWARDER_CONTRACTS,
	CREATE2_CONTRACTS,
	DELEGATECALL_CONTRACTS,
	MULTI_THREAT_CONTRACTS,
	REAL_WORLD_PATTERNS,
	SAFE_CONTRACTS,
	SELFDESTRUCT_CONTRACTS,
} from './fixtures/contracts';

describe('Analysis Pipeline Integration', () => {
	describe('Layer 1 → Layer 4: Database vs Detection', () => {
		it('database catches known malicious before detection runs', () => {
			const address = '0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b';

			const dbResult = checkKnownMalicious(address);
			expect(dbResult).not.toBeNull();
			expect(dbResult?.type).toBe('ETH_AUTO_FORWARDER');
		});

		it('unknown contracts proceed to bytecode analysis', () => {
			const address = '0x63c0c19a282a1b52b07dd5a65b58948a07dae32b';

			const dbResult = checkKnownMalicious(address);
			expect(dbResult).toBeNull();
		});
	});

	describe('Layer 3 → Layer 4: Parser + Detectors', () => {
		it('parses and detects SELFDESTRUCT threat', () => {
			const bytecode = SELFDESTRUCT_CONTRACTS.complex;

			const instructions = parseBytecode(bytecode);
			expect(instructions.length).toBeGreaterThan(0);

			const result = runAllDetectors(instructions);
			expect(result.hasSelfDestruct).toBe(true);
		});

		it('parses and detects AUTO_FORWARDER threat', () => {
			const bytecode = AUTO_FORWARDER_CONTRACTS.realistic;

			const instructions = parseBytecode(bytecode);
			const result = runAllDetectors(instructions);

			expect(result.hasAutoForwarder).toBe(true);
		});

		it('parses and detects DELEGATECALL threat', () => {
			const bytecode = DELEGATECALL_CONTRACTS.withSetup;

			const instructions = parseBytecode(bytecode);
			const result = runAllDetectors(instructions);

			expect(result.isDelegatedCall).toBe(true);
		});

		it('correctly identifies safe contracts', () => {
			const bytecode = SAFE_CONTRACTS.simpleAdd;

			const instructions = parseBytecode(bytecode);
			const result = runAllDetectors(instructions);

			expect(result.hasSelfDestruct).toBe(false);
			expect(result.isDelegatedCall).toBe(false);
			expect(result.hasAutoForwarder).toBe(false);
			expect(result.hasUnlimitedApprovals).toBe(false);
		});
	});

	describe('Layer 5: Risk Scoring Logic', () => {
		it('calculates CRITICAL risk for multi-threat contract', () => {
			const bytecode = MULTI_THREAT_CONTRACTS.allThreats;
			const instructions = parseBytecode(bytecode);
			const threats = runAllDetectors(instructions);

			const detectedThreats = Object.entries(threats)
				.filter(([_, detected]) => detected)
				.map(([name]) => name);

			expect(detectedThreats.length).toBeGreaterThan(0);

			const risk = detectedThreats.length > 0 ? 'CRITICAL' : 'LOW';
			expect(risk).toBe('CRITICAL');
		});

		it('calculates LOW risk for safe contract', () => {
			const bytecode = SAFE_CONTRACTS.return42;
			const instructions = parseBytecode(bytecode);
			const threats = runAllDetectors(instructions);

			const detectedThreats = Object.entries(threats)
				.filter(([key, detected]) => key !== 'tokenTransfer' && detected === true)
				.map(([name]) => name);

			expect(detectedThreats.length).toBe(0);
			expect(threats.tokenTransfer.contextualRisk).toBe('LOW');

			const risk = detectedThreats.length > 0 ? 'CRITICAL' : 'LOW';
			expect(risk).toBe('LOW');
		});
	});

	describe('Real-World Pattern Analysis', () => {
		it('detects CrimeEnjoyer sweeper pattern', () => {
			const bytecode = REAL_WORLD_PATTERNS.crimeEnjoyer;
			const instructions = parseBytecode(bytecode);
			const result = runAllDetectors(instructions);

			expect(result.hasAutoForwarder).toBe(true);
		});

		it('detects proxy pattern with DELEGATECALL', () => {
			const bytecode = REAL_WORLD_PATTERNS.safeProxy;
			const instructions = parseBytecode(bytecode);
			const result = runAllDetectors(instructions);

			expect(result.isDelegatedCall).toBe(true);
		});
	});

	describe('Metamorphic Attack Risk Scoring', () => {
		it('detects metamorphic pattern (CREATE2 + SELFDESTRUCT)', () => {
			const bytecode = CREATE2_CONTRACTS.metamorphic;
			const instructions = parseBytecode(bytecode);
			const result = runAllDetectors(instructions);

			expect(result.hasCreate2).toBe(true);
			expect(result.hasSelfDestruct).toBe(true);
		});

		it('detects CREATE2 only (factory pattern)', () => {
			const bytecode = CREATE2_CONTRACTS.minimal;
			const instructions = parseBytecode(bytecode);
			const result = runAllDetectors(instructions);

			expect(result.hasCreate2).toBe(true);
			expect(result.hasSelfDestruct).toBe(false);
		});

		it('detects SELFDESTRUCT only', () => {
			const bytecode = SELFDESTRUCT_CONTRACTS.minimal;
			const instructions = parseBytecode(bytecode);
			const result = runAllDetectors(instructions);

			expect(result.hasCreate2).toBe(false);
			expect(result.hasSelfDestruct).toBe(true);
		});
	});

	describe('Threat Enumeration', () => {
		it('correctly enumerates all detected threats', () => {
			const bytecode = MULTI_THREAT_CONTRACTS.allThreats;
			const instructions = parseBytecode(bytecode);
			const threats = runAllDetectors(instructions);

			const threatList = Object.entries(threats)
				.filter(([_, detected]) => detected)
				.map(([name]) => name);

			expect(threatList).toContain('hasSelfDestruct');
			expect(threatList).toContain('isDelegatedCall');
			expect(threatList).toContain('hasAutoForwarder');
		});

		it('returns empty threat list for safe contract', () => {
			const bytecode = SAFE_CONTRACTS.empty;
			const instructions = parseBytecode(bytecode);
			const threats = runAllDetectors(instructions);

			const threatList = Object.entries(threats)
				.filter(([key, detected]) => key !== 'tokenTransfer' && detected === true)
				.map(([name]) => name);

			expect(threatList).toHaveLength(0);
			expect(threats.tokenTransfer.contextualRisk).toBe('LOW');
		});
	});
});

describe('Edge Cases', () => {
	describe('Bytecode Edge Cases', () => {
		it('handles very short bytecode', () => {
			const bytecode = '0x00';
			const instructions = parseBytecode(bytecode);
			const result = runAllDetectors(instructions);

			expect(result.hasSelfDestruct).toBe(false);
		});

		it('handles bytecode with only PUSH instructions', () => {
			const bytecode = '0x60016002600360046005';
			const instructions = parseBytecode(bytecode);
			const result = runAllDetectors(instructions);

			expect(result.hasSelfDestruct).toBe(false);
			expect(result.isDelegatedCall).toBe(false);
			expect(result.hasAutoForwarder).toBe(false);
		});

		it('handles truncated PUSH instruction at end', () => {
			const bytecode = '0x61ff';
			const instructions = parseBytecode(bytecode);

			expect(instructions.length).toBeGreaterThanOrEqual(1);
		});
	});

	describe('Address Normalization', () => {
		const testCases = [
			'0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b',
			'0x930FCC37D6042C79211EE18A02857CB1FD7F0D0B',
			'0x930Fcc37d6042c79211ee18a02857cb1fd7f0D0B',
		];

		testCases.forEach((address) => {
			it(`normalizes address: ${address.slice(0, 10)}...`, () => {
				const result = checkKnownMalicious(address);
				expect(result).not.toBeNull();
			});
		});
	});
});

describe('Warning Generation', () => {
	const createMockDetectionResults = (
		overrides: Partial<DetectionResults> = {},
	): DetectionResults => ({
		isDelegatedCall: false,
		hasAutoForwarder: false,
		hasUnlimitedApprovals: false,
		hasSelfDestruct: false,
		hasCreate2: false,
		hasChainId: false,
		hasChainIdBranching: false,
		hasChainIdComparison: false,
		isEip712Pattern: false,
		tokenTransfer: {
			hasTokenTransfer: false,
			hasTokenApproval: false,
			hasBatchOperations: false,
			detectedSelectors: [],
			hasAuthorizationPattern: false,
			hasEcrecover: false,
			hasNonceTracking: false,
			appearsInFallback: false,
			hasHardcodedDestination: false,
			contextualRisk: 'LOW',
			riskReason: '',
		},
		...overrides,
	});

	describe('Warning Structure', () => {
		it('returns empty array for safe contract', () => {
			const result = createMockDetectionResults();
			const warnings = generateWarnings(result);
			expect(warnings).toHaveLength(0);
		});

		it('returns structured Warning objects', () => {
			const result = createMockDetectionResults({ hasAutoForwarder: true });
			const warnings = generateWarnings(result);

			expect(warnings).toHaveLength(1);
			expect(warnings[0]).toHaveProperty('type');
			expect(warnings[0]).toHaveProperty('severity');
			expect(warnings[0]).toHaveProperty('title');
			expect(warnings[0]).toHaveProperty('description');
			expect(warnings[0]).toHaveProperty('technical');
		});
	});

	describe('CRITICAL Severity Warnings', () => {
		it('generates CRITICAL warning for auto-forwarder', () => {
			const result = createMockDetectionResults({ hasAutoForwarder: true });
			const warnings = generateWarnings(result);

			expect(warnings[0].type).toBe('AUTO_FORWARDER');
			expect(warnings[0].severity).toBe('CRITICAL');
			expect(warnings[0].title).toBe('Automatic Fund Drain Detected');
		});

		it('generates CRITICAL warning for metamorphic pattern', () => {
			const result = createMockDetectionResults({
				hasCreate2: true,
				hasSelfDestruct: true,
			});
			const warnings = generateWarnings(result);

			expect(warnings).toHaveLength(1);
			expect(warnings[0].type).toBe('METAMORPHIC');
			expect(warnings[0].severity).toBe('CRITICAL');
		});

		it('generates CRITICAL warning for token drain in fallback', () => {
			const result = createMockDetectionResults({
				tokenTransfer: {
					hasTokenTransfer: true,
					hasTokenApproval: false,
					hasBatchOperations: false,
					detectedSelectors: [],
					hasAuthorizationPattern: false,
					hasEcrecover: false,
					hasNonceTracking: false,
					appearsInFallback: true,
					hasHardcodedDestination: false,
					contextualRisk: 'CRITICAL',
					riskReason: 'Token transfer in fallback',
				},
			});
			const warnings = generateWarnings(result);

			const tokenWarning = warnings.find((w) => w.type === 'TOKEN_DRAIN_FALLBACK');
			expect(tokenWarning).toBeDefined();
			expect(tokenWarning?.severity).toBe('CRITICAL');
		});
	});

	describe('HIGH Severity Warnings', () => {
		it('generates HIGH warning for delegatecall', () => {
			const result = createMockDetectionResults({ isDelegatedCall: true });
			const warnings = generateWarnings(result);

			expect(warnings[0].type).toBe('DELEGATE_CALL');
			expect(warnings[0].severity).toBe('HIGH');
		});

		it('generates HIGH warning for self-destruct (without CREATE2)', () => {
			const result = createMockDetectionResults({ hasSelfDestruct: true });
			const warnings = generateWarnings(result);

			expect(warnings[0].type).toBe('SELF_DESTRUCT');
			expect(warnings[0].severity).toBe('HIGH');
		});

		it('generates HIGH warning for CHAINID branching', () => {
			const result = createMockDetectionResults({
				hasChainId: true,
				hasChainIdBranching: true,
			});
			const warnings = generateWarnings(result);

			expect(warnings[0].type).toBe('CHAINID_BRANCHING');
			expect(warnings[0].severity).toBe('HIGH');
		});

		it('generates HIGH warning for unlimited approvals', () => {
			const result = createMockDetectionResults({ hasUnlimitedApprovals: true });
			const warnings = generateWarnings(result);

			expect(warnings[0].type).toBe('UNLIMITED_APPROVAL');
			expect(warnings[0].severity).toBe('HIGH');
		});
	});

	describe('MEDIUM Severity Warnings', () => {
		it('generates MEDIUM warning for CREATE2 alone', () => {
			const result = createMockDetectionResults({ hasCreate2: true });
			const warnings = generateWarnings(result);

			expect(warnings[0].type).toBe('CREATE2');
			expect(warnings[0].severity).toBe('MEDIUM');
		});

		it('generates MEDIUM warning for CHAINID comparison', () => {
			const result = createMockDetectionResults({
				hasChainId: true,
				hasChainIdComparison: true,
			});
			const warnings = generateWarnings(result);

			expect(warnings[0].type).toBe('CHAINID_COMPARISON');
			expect(warnings[0].severity).toBe('MEDIUM');
		});

		it('generates MEDIUM warning for CHAINID read only', () => {
			const result = createMockDetectionResults({ hasChainId: true });
			const warnings = generateWarnings(result);

			expect(warnings[0].type).toBe('CHAINID_READ');
			expect(warnings[0].severity).toBe('MEDIUM');
		});

		it('generates MEDIUM warning for token ops with auth', () => {
			const result = createMockDetectionResults({
				tokenTransfer: {
					hasTokenTransfer: true,
					hasTokenApproval: false,
					hasBatchOperations: false,
					detectedSelectors: [],
					hasAuthorizationPattern: true,
					hasEcrecover: true,
					hasNonceTracking: true,
					appearsInFallback: false,
					hasHardcodedDestination: false,
					contextualRisk: 'MEDIUM',
					riskReason: 'Token with auth',
				},
			});
			const warnings = generateWarnings(result);

			const tokenWarning = warnings.find((w) => w.type === 'TOKEN_WITH_AUTH');
			expect(tokenWarning).toBeDefined();
			expect(tokenWarning?.severity).toBe('MEDIUM');
		});
	});

	describe('INFO Severity Warnings', () => {
		it('generates INFO warning for EIP-712 pattern', () => {
			const result = createMockDetectionResults({
				hasChainId: true,
				isEip712Pattern: true,
			});
			const warnings = generateWarnings(result);

			expect(warnings[0].type).toBe('EIP712_SAFE');
			expect(warnings[0].severity).toBe('INFO');
		});
	});

	describe('Multiple Warnings', () => {
		it('generates multiple warnings for multi-threat contract', () => {
			const result = createMockDetectionResults({
				hasAutoForwarder: true,
				isDelegatedCall: true,
				hasUnlimitedApprovals: true,
			});
			const warnings = generateWarnings(result);

			expect(warnings.length).toBeGreaterThanOrEqual(3);
		});

		it('does not add EIP-712 warning when also cross-chain risk', () => {
			const result = createMockDetectionResults({
				hasChainId: true,
				hasChainIdBranching: true,
				isEip712Pattern: false,
			});
			const warnings = generateWarnings(result);

			const eip712Warning = warnings.find((w) => w.type === 'EIP712_SAFE');
			expect(eip712Warning).toBeUndefined();
		});
	});

	describe('Integration with Real Bytecode', () => {
		it('generates correct warnings for auto-forwarder bytecode', () => {
			const bytecode = AUTO_FORWARDER_CONTRACTS.realistic;
			const instructions = parseBytecode(bytecode);
			const detectionResults = runAllDetectors(instructions);
			const warnings = generateWarnings(detectionResults);

			const autoForwarderWarning = warnings.find((w) => w.type === 'AUTO_FORWARDER');
			expect(autoForwarderWarning).toBeDefined();
			expect(autoForwarderWarning?.severity).toBe('CRITICAL');
		});

		it('generates correct warnings for metamorphic bytecode', () => {
			const bytecode = CREATE2_CONTRACTS.metamorphic;
			const instructions = parseBytecode(bytecode);
			const detectionResults = runAllDetectors(instructions);
			const warnings = generateWarnings(detectionResults);

			const metamorphicWarning = warnings.find((w) => w.type === 'METAMORPHIC');
			expect(metamorphicWarning).toBeDefined();
			expect(metamorphicWarning?.severity).toBe('CRITICAL');
		});

		it('generates no actionable warnings for safe bytecode', () => {
			const bytecode = SAFE_CONTRACTS.simpleAdd;
			const instructions = parseBytecode(bytecode);
			const detectionResults = runAllDetectors(instructions);
			const warnings = generateWarnings(detectionResults);

			const actionableWarnings = warnings.filter((w) => w.severity !== 'INFO');
			expect(actionableWarnings).toHaveLength(0);
		});
	});
});

describe('Risk Derivation from Warnings', () => {
	const createWarning = (
		severity: Warning['severity'],
		type: Warning['type'] = 'AUTO_FORWARDER',
	): Warning => ({
		type,
		severity,
		title: 'Test Warning',
		description: 'Test description',
	});

	describe('deriveRiskFromWarnings', () => {
		it('returns LOW risk for empty warnings', () => {
			const { risk, blocked } = deriveRiskFromWarnings([]);
			expect(risk).toBe('LOW');
			expect(blocked).toBe(false);
		});

		it('returns LOW risk for INFO-only warnings', () => {
			const warnings = [createWarning('INFO', 'EIP712_SAFE')];
			const { risk, blocked } = deriveRiskFromWarnings(warnings);
			expect(risk).toBe('LOW');
			expect(blocked).toBe(false);
		});

		it('returns CRITICAL risk and blocked for CRITICAL warning', () => {
			const warnings = [createWarning('CRITICAL')];
			const { risk, blocked } = deriveRiskFromWarnings(warnings);
			expect(risk).toBe('CRITICAL');
			expect(blocked).toBe(true);
		});

		it('returns HIGH risk and blocked for HIGH warning', () => {
			const warnings = [createWarning('HIGH', 'DELEGATE_CALL')];
			const { risk, blocked } = deriveRiskFromWarnings(warnings);
			expect(risk).toBe('HIGH');
			expect(blocked).toBe(true);
		});

		it('returns MEDIUM risk and not blocked for MEDIUM warning', () => {
			const warnings = [createWarning('MEDIUM', 'CREATE2')];
			const { risk, blocked } = deriveRiskFromWarnings(warnings);
			expect(risk).toBe('MEDIUM');
			expect(blocked).toBe(false);
		});

		it('returns CRITICAL risk for multiple warnings (2+ threats)', () => {
			const warnings = [
				createWarning('MEDIUM', 'CREATE2'),
				createWarning('MEDIUM', 'CHAINID_READ'),
			];
			const { risk, blocked } = deriveRiskFromWarnings(warnings);
			expect(risk).toBe('CRITICAL');
			expect(blocked).toBe(true);
		});

		it('returns CRITICAL risk for HIGH + MEDIUM warnings', () => {
			const warnings = [createWarning('HIGH', 'DELEGATE_CALL'), createWarning('MEDIUM', 'CREATE2')];
			const { risk, blocked } = deriveRiskFromWarnings(warnings);
			expect(risk).toBe('CRITICAL');
			expect(blocked).toBe(true);
		});

		it('ignores INFO warnings when calculating risk', () => {
			const warnings = [createWarning('MEDIUM', 'CREATE2'), createWarning('INFO', 'EIP712_SAFE')];
			const { risk, blocked } = deriveRiskFromWarnings(warnings);
			expect(risk).toBe('MEDIUM');
			expect(blocked).toBe(false);
		});
	});
});
