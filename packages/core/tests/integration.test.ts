import { describe, expect, it } from 'vitest';
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
	DRAINER_PATTERNS,
	MINIMAL_PROXY_CONTRACTS,
	MULTI_THREAT_CONTRACTS,
	PERMIT2_CONTRACTS,
	REAL_WORLD_PATTERNS,
	SAFE_CONTRACTS,
	SELFDESTRUCT_CONTRACTS,
} from './fixtures/contracts';
import { createMockDetectionResults, createMockWarning } from './helpers/mock-detection';

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

		it('generates CRITICAL warning for Permit2 without auth (was silently dropped)', () => {
			const result = createMockDetectionResults({
				tokenTransfer: {
					hasTokenTransfer: false,
					hasTokenApproval: false,
					hasBatchOperations: false,
					detectedSelectors: [
						{
							selector: '30f28b7a',
							name: 'permitTransferFrom',
							standard: 'Permit2',
							type: 'permit',
						},
					],
					hasAuthorizationPattern: false,
					hasEcrecover: false,
					hasNonceTracking: false,
					appearsInFallback: false,
					hasHardcodedDestination: false,
					contextualRisk: 'CRITICAL',
					riskReason: 'Permit2 gasless transfer without access control',
				},
			});
			const warnings = generateWarnings(result);

			const permit2Warning = warnings.find((w) => w.type === 'TOKEN_PERMIT2_NO_AUTH');
			expect(permit2Warning).toBeDefined();
			expect(permit2Warning?.severity).toBe('CRITICAL');
			expect(permit2Warning?.title).toContain('Gasless');
		});

		it('generates CRITICAL warning for Permit2 batch without auth', () => {
			const result = createMockDetectionResults({
				tokenTransfer: {
					hasTokenTransfer: false,
					hasTokenApproval: false,
					hasBatchOperations: false,
					detectedSelectors: [
						{
							selector: 'edd9444b',
							name: 'permitTransferFromBatch',
							standard: 'Permit2',
							type: 'permit',
						},
					],
					hasAuthorizationPattern: false,
					hasEcrecover: false,
					hasNonceTracking: false,
					appearsInFallback: false,
					hasHardcodedDestination: false,
					contextualRisk: 'CRITICAL',
					riskReason: 'Permit2 gasless transfer without access control',
				},
			});
			const warnings = generateWarnings(result);

			const permit2Warning = warnings.find((w) => w.type === 'TOKEN_PERMIT2_NO_AUTH');
			expect(permit2Warning).toBeDefined();
			expect(permit2Warning?.severity).toBe('CRITICAL');
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

		it('generates MEDIUM warning for unlimited approvals (standard DeFi pattern)', () => {
			const result = createMockDetectionResults({ hasUnlimitedApprovals: true });
			const warnings = generateWarnings(result);

			expect(warnings[0].type).toBe('UNLIMITED_APPROVAL');
			expect(warnings[0].severity).toBe('MEDIUM');
		});
	});

	describe('CALLCODE Warnings', () => {
		it('generates HIGH warning for CALLCODE without proxy', () => {
			const result = createMockDetectionResults({ hasCallcode: true });
			const warnings = generateWarnings(result);

			const callcodeWarning = warnings.find((w) => w.type === 'CALLCODE');
			expect(callcodeWarning).toBeDefined();
			expect(callcodeWarning?.severity).toBe('HIGH');
			expect(callcodeWarning?.title).toContain('Legacy');
		});

		it('generates MEDIUM warning for CALLCODE with proxy pattern', () => {
			const result = createMockDetectionResults({
				hasCallcode: true,
				proxy: {
					isProxy: true,
					hasImplementationSlot: true,
					hasAdminSlot: false,
					hasBeaconSlot: false,
				},
			});
			const warnings = generateWarnings(result);

			const callcodeWarning = warnings.find((w) => w.type === 'CALLCODE');
			expect(callcodeWarning).toBeDefined();
			expect(callcodeWarning?.severity).toBe('MEDIUM');
		});

		it('CALLCODE + DELEGATECALL generates both warnings', () => {
			const result = createMockDetectionResults({
				hasCallcode: true,
				isDelegatedCall: true,
			});
			const warnings = generateWarnings(result);

			const callcodeWarning = warnings.find((w) => w.type === 'CALLCODE');
			const delegateWarning = warnings.find((w) => w.type === 'DELEGATE_CALL');
			expect(callcodeWarning).toBeDefined();
			expect(delegateWarning).toBeDefined();
		});

		it('generates HIGH warning for reentrancy risk', () => {
			const result = createMockDetectionResults({ hasReentrancyRisk: true });
			const warnings = generateWarnings(result);

			const reWarning = warnings.find((w) => w.type === 'REENTRANCY_RISK');
			expect(reWarning).toBeDefined();
			expect(reWarning?.severity).toBe('HIGH');
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

		it('generates MEDIUM warning for gas manipulation', () => {
			const result = createMockDetectionResults({ hasGasManipulation: true });
			const warnings = generateWarnings(result);

			const gasWarning = warnings.find((w) => w.type === 'GAS_MANIPULATION');
			expect(gasWarning).toBeDefined();
			expect(gasWarning?.severity).toBe('MEDIUM');
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

		it('generates INFO warning for EXTCODEHASH', () => {
			const result = createMockDetectionResults({ hasExtcodehash: true });
			const warnings = generateWarnings(result);

			const hashWarning = warnings.find((w) => w.type === 'EXTCODEHASH_CHECK');
			expect(hashWarning).toBeDefined();
			expect(hashWarning?.severity).toBe('INFO');
		});
	});

	describe('Proxy Pattern Warnings', () => {
		it('generates MEDIUM warning for proxy contract', () => {
			const result = createMockDetectionResults({
				proxy: {
					isProxy: true,
					hasImplementationSlot: true,
					hasAdminSlot: false,
					hasBeaconSlot: false,
				},
			});
			const warnings = generateWarnings(result);

			const proxyWarning = warnings.find((w) => w.type === 'PROXY_PATTERN');
			expect(proxyWarning).toBeDefined();
			expect(proxyWarning?.severity).toBe('MEDIUM');
		});

		it('does not generate proxy warning for non-proxy', () => {
			const result = createMockDetectionResults();
			const warnings = generateWarnings(result);

			const proxyWarning = warnings.find((w) => w.type === 'PROXY_PATTERN');
			expect(proxyWarning).toBeUndefined();
		});
	});

	describe('tx.origin Warnings', () => {
		it('generates HIGH warning for tx.origin phishing', () => {
			const result = createMockDetectionResults({ hasTxOrigin: true });
			const warnings = generateWarnings(result);

			const txOriginWarning = warnings.find((w) => w.type === 'TX_ORIGIN_PHISHING');
			expect(txOriginWarning).toBeDefined();
			expect(txOriginWarning?.severity).toBe('HIGH');
		});
	});

	describe('Timestamp Dependence Warnings', () => {
		it('generates MEDIUM warning for timestamp dependence', () => {
			const result = createMockDetectionResults({ hasTimestampDependence: true });
			const warnings = generateWarnings(result);

			const tsWarning = warnings.find((w) => w.type === 'TIMESTAMP_DEPENDENCE');
			expect(tsWarning).toBeDefined();
			expect(tsWarning?.severity).toBe('MEDIUM');
		});
	});

	describe('EIP-7702 Delegation Warnings', () => {
		it('generates INFO warning for delegation pointer', () => {
			const result = createMockDetectionResults({ isEip7702Delegation: true });
			const warnings = generateWarnings(result);

			const delegationWarning = warnings.find((w) => w.type === 'EIP7702_DELEGATION');
			expect(delegationWarning).toBeDefined();
			expect(delegationWarning?.severity).toBe('INFO');
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
	describe('deriveRiskFromWarnings', () => {
		it('returns LOW risk for empty warnings', () => {
			const { risk, blocked } = deriveRiskFromWarnings([]);
			expect(risk).toBe('LOW');
			expect(blocked).toBe(false);
		});

		it('returns LOW risk for INFO-only warnings', () => {
			const warnings = [createMockWarning('INFO', 'EIP712_SAFE')];
			const { risk, blocked } = deriveRiskFromWarnings(warnings);
			expect(risk).toBe('LOW');
			expect(blocked).toBe(false);
		});

		it('returns CRITICAL risk and blocked for CRITICAL warning', () => {
			const warnings = [createMockWarning('CRITICAL')];
			const { risk, blocked } = deriveRiskFromWarnings(warnings);
			expect(risk).toBe('CRITICAL');
			expect(blocked).toBe(true);
		});

		it('returns HIGH risk and blocked for HIGH warning', () => {
			const warnings = [createMockWarning('HIGH', 'DELEGATE_CALL')];
			const { risk, blocked } = deriveRiskFromWarnings(warnings);
			expect(risk).toBe('HIGH');
			expect(blocked).toBe(true);
		});

		it('returns MEDIUM risk and not blocked for MEDIUM warning', () => {
			const warnings = [createMockWarning('MEDIUM', 'CREATE2')];
			const { risk, blocked } = deriveRiskFromWarnings(warnings);
			expect(risk).toBe('MEDIUM');
			expect(blocked).toBe(false);
		});

		it('returns HIGH risk for multiple MEDIUM warnings (avoids smart wallet false positives)', () => {
			// 2+ MEDIUM warnings = HIGH (not CRITICAL) to avoid blocking legitimate smart wallets
			// e.g., Gnosis Safe with TOKEN_WITH_AUTH + CHAINID_COMPARISON
			const warnings = [
				createMockWarning('MEDIUM', 'CREATE2'),
				createMockWarning('MEDIUM', 'CHAINID_READ'),
			];
			const { risk, blocked } = deriveRiskFromWarnings(warnings);
			expect(risk).toBe('HIGH');
			expect(blocked).toBe(true);
		});

		it('returns CRITICAL risk for HIGH + MEDIUM warnings', () => {
			const warnings = [
				createMockWarning('HIGH', 'DELEGATE_CALL'),
				createMockWarning('MEDIUM', 'CREATE2'),
			];
			const { risk, blocked } = deriveRiskFromWarnings(warnings);
			expect(risk).toBe('CRITICAL');
			expect(blocked).toBe(true);
		});

		it('ignores INFO warnings when calculating risk', () => {
			const warnings = [
				createMockWarning('MEDIUM', 'CREATE2'),
				createMockWarning('INFO', 'EIP712_SAFE'),
			];
			const { risk, blocked } = deriveRiskFromWarnings(warnings);
			expect(risk).toBe('MEDIUM');
			expect(blocked).toBe(false);
		});
	});
});

describe('Multicall Warnings', () => {
	it('generates MEDIUM warning for multicall capability', () => {
		const result = createMockDetectionResults({ hasMulticall: true });
		const warnings = generateWarnings(result);
		const mcWarning = warnings.find((w) => w.type === 'MULTICALL_CAPABILITY');
		expect(mcWarning).toBeDefined();
		expect(mcWarning?.severity).toBe('MEDIUM');
	});

	it('generates INFO warning for EXTCODESIZE guard', () => {
		const result = createMockDetectionResults({ hasExtcodesizeGuard: true });
		const warnings = generateWarnings(result);
		const ecWarning = warnings.find((w) => w.type === 'EXTCODESIZE_GUARD');
		expect(ecWarning).toBeDefined();
		expect(ecWarning?.severity).toBe('INFO');
	});

	it('generates INFO warning for ERC-4337 pattern', () => {
		const result = createMockDetectionResults({ hasErc4337Pattern: true });
		const warnings = generateWarnings(result);
		const aaWarning = warnings.find((w) => w.type === 'ERC4337_PATTERN');
		expect(aaWarning).toBeDefined();
		expect(aaWarning?.severity).toBe('INFO');
	});

	it('generates MEDIUM warning for coinbase dependence', () => {
		const result = createMockDetectionResults({ hasCoinbaseDependence: true });
		const warnings = generateWarnings(result);
		const cbWarning = warnings.find((w) => w.type === 'COINBASE_DEPENDENCE');
		expect(cbWarning).toBeDefined();
		expect(cbWarning?.severity).toBe('MEDIUM');
	});

	it('generates INFO warning for EIP-1167 minimal proxy', () => {
		const result = createMockDetectionResults({ hasMinimalProxy: true });
		const warnings = generateWarnings(result);
		const mpWarning = warnings.find((w) => w.type === 'MINIMAL_PROXY');
		expect(mpWarning).toBeDefined();
		expect(mpWarning?.severity).toBe('INFO');
	});

	it('generates MEDIUM warning for Diamond proxy', () => {
		const result = createMockDetectionResults({ hasDiamondProxy: true });
		const warnings = generateWarnings(result);
		const dpWarning = warnings.find((w) => w.type === 'DIAMOND_PROXY');
		expect(dpWarning).toBeDefined();
		expect(dpWarning?.severity).toBe('MEDIUM');
	});

	it('generates INFO warning for EXTCODECOPY alone', () => {
		const result = createMockDetectionResults({ hasExtcodecopy: true });
		const warnings = generateWarnings(result);
		const ecWarning = warnings.find((w) => w.type === 'EXTCODECOPY_USAGE');
		expect(ecWarning).toBeDefined();
		expect(ecWarning?.severity).toBe('INFO');
	});

	it('generates MEDIUM warning for EXTCODECOPY + CREATE2 (code injection)', () => {
		const result = createMockDetectionResults({
			hasExtcodecopy: true,
			hasCreate2: true,
		});
		const warnings = generateWarnings(result);
		const ecWarning = warnings.find((w) => w.type === 'EXTCODECOPY_USAGE');
		expect(ecWarning).toBeDefined();
		expect(ecWarning?.severity).toBe('MEDIUM');
		expect(ecWarning?.title).toContain('External Code Deployment');
	});

	it('generates HIGH warning for BALANCE drain pattern', () => {
		const result = createMockDetectionResults({ hasBalanceDrain: true });
		const warnings = generateWarnings(result);
		const bdWarning = warnings.find((w) => w.type === 'BALANCE_DRAIN');
		expect(bdWarning).toBeDefined();
		expect(bdWarning?.severity).toBe('HIGH');
	});

	it('EXTCODECOPY + CREATE2 + SELFDESTRUCT: metamorphic takes precedence', () => {
		const result = createMockDetectionResults({
			hasExtcodecopy: true,
			hasCreate2: true,
			hasSelfDestruct: true,
		});
		const warnings = generateWarnings(result);
		const metamorphicWarning = warnings.find((w) => w.type === 'METAMORPHIC');
		expect(metamorphicWarning).toBeDefined();
		const ecWarning = warnings.find((w) => w.type === 'EXTCODECOPY_USAGE');
		expect(ecWarning).toBeDefined();
		expect(ecWarning?.severity).toBe('INFO');
	});
});

describe('Threat Combination Risk Scoring', () => {
	describe('metamorphic suppression', () => {
		it('metamorphic suppresses individual CREATE2 + SELFDESTRUCT warnings', () => {
			const result = createMockDetectionResults({ hasCreate2: true, hasSelfDestruct: true });
			const warnings = generateWarnings(result);

			expect(warnings).toHaveLength(1);
			expect(warnings[0].type).toBe('METAMORPHIC');
			const create2 = warnings.find((w) => w.type === 'CREATE2');
			const selfDestruct = warnings.find((w) => w.type === 'SELF_DESTRUCT');
			expect(create2).toBeUndefined();
			expect(selfDestruct).toBeUndefined();
		});
	});

	describe('realistic multi-threat combinations', () => {
		// AUDIT-10: a normal upgradeable proxy (proxy-mitigated DELEGATECALL + PROXY_PATTERN,
		// both benign MEDIUM capabilities) must NOT auto-block.
		it('proxy + delegatecall (benign capabilities) → MEDIUM, not blocked (AUDIT-10)', () => {
			const result = createMockDetectionResults({
				isDelegatedCall: true,
				proxy: {
					isProxy: true,
					hasImplementationSlot: true,
					hasAdminSlot: false,
					hasBeaconSlot: false,
				},
			});
			const warnings = generateWarnings(result);
			const { risk, blocked } = deriveRiskFromWarnings(warnings);

			const delegateWarning = warnings.find((w) => w.type === 'DELEGATE_CALL');
			expect(delegateWarning?.severity).toBe('MEDIUM');
			expect(risk).toBe('MEDIUM');
			expect(blocked).toBe(false);
		});

		it('diamond proxy + multicall (benign capabilities) → MEDIUM, not blocked (AUDIT-10)', () => {
			const result = createMockDetectionResults({ hasDiamondProxy: true, hasMulticall: true });
			const warnings = generateWarnings(result);
			const { risk, blocked } = deriveRiskFromWarnings(warnings);

			expect(risk).toBe('MEDIUM');
			expect(blocked).toBe(false);
		});

		it('timestamp + coinbase → HIGH (2x MEDIUM)', () => {
			const result = createMockDetectionResults({
				hasTimestampDependence: true,
				hasCoinbaseDependence: true,
			});
			const warnings = generateWarnings(result);
			const { risk, blocked } = deriveRiskFromWarnings(warnings);

			expect(risk).toBe('HIGH');
			expect(blocked).toBe(true);
		});

		it('auto-forwarder + unlimited approval → CRITICAL', () => {
			const result = createMockDetectionResults({
				hasAutoForwarder: true,
				hasUnlimitedApprovals: true,
			});
			const warnings = generateWarnings(result);
			const { risk, blocked } = deriveRiskFromWarnings(warnings);

			expect(risk).toBe('CRITICAL');
			expect(blocked).toBe(true);
		});

		it('tx.origin + chainid branching → CRITICAL (2x HIGH)', () => {
			const result = createMockDetectionResults({
				hasTxOrigin: true,
				hasChainId: true,
				hasChainIdBranching: true,
				hasChainIdComparison: true,
			});
			const warnings = generateWarnings(result);
			const { risk, blocked } = deriveRiskFromWarnings(warnings);

			expect(risk).toBe('CRITICAL');
			expect(blocked).toBe(true);
		});

		it('ERC-4337 + DELEGATECALL: mitigation reduces to MEDIUM', () => {
			const result = createMockDetectionResults({
				isDelegatedCall: true,
				hasErc4337Pattern: true,
			});
			const warnings = generateWarnings(result);
			const { risk, blocked } = deriveRiskFromWarnings(warnings);

			const delegateWarning = warnings.find((w) => w.type === 'DELEGATE_CALL');
			expect(delegateWarning?.severity).toBe('MEDIUM');
			expect(delegateWarning?.title).toContain('Proxy');
			const aaWarning = warnings.find((w) => w.type === 'ERC4337_PATTERN');
			expect(aaWarning?.severity).toBe('INFO');
			expect(risk).toBe('MEDIUM');
			expect(blocked).toBe(false);
		});

		it('Diamond proxy + DELEGATECALL: both benign MEDIUM → not blocked (AUDIT-10)', () => {
			const result = createMockDetectionResults({
				isDelegatedCall: true,
				hasDiamondProxy: true,
			});
			const warnings = generateWarnings(result);
			const { risk, blocked } = deriveRiskFromWarnings(warnings);

			const delegateWarning = warnings.find((w) => w.type === 'DELEGATE_CALL');
			expect(delegateWarning?.severity).toBe('MEDIUM');
			const diamondWarning = warnings.find((w) => w.type === 'DIAMOND_PROXY');
			expect(diamondWarning?.severity).toBe('MEDIUM');
			expect(risk).toBe('MEDIUM');
			expect(blocked).toBe(false);
		});

		it('CALLCODE + proxy: mitigation reduces CALLCODE to MEDIUM', () => {
			const result = createMockDetectionResults({
				hasCallcode: true,
				proxy: {
					isProxy: true,
					hasImplementationSlot: true,
					hasAdminSlot: false,
					hasBeaconSlot: false,
				},
			});
			const warnings = generateWarnings(result);

			const callcodeWarning = warnings.find((w) => w.type === 'CALLCODE');
			expect(callcodeWarning?.severity).toBe('MEDIUM');
		});

		it('BALANCE drain + auto-forwarder → CRITICAL (drains both ETH balance check and auto-forward)', () => {
			const result = createMockDetectionResults({
				hasBalanceDrain: true,
				hasAutoForwarder: true,
			});
			const warnings = generateWarnings(result);
			const { risk, blocked } = deriveRiskFromWarnings(warnings);

			expect(risk).toBe('CRITICAL');
			expect(blocked).toBe(true);
		});

		it('EXTCODECOPY + CREATE2 + DELEGATECALL → CRITICAL (code injection + arbitrary exec)', () => {
			const result = createMockDetectionResults({
				hasExtcodecopy: true,
				hasCreate2: true,
				isDelegatedCall: true,
			});
			const warnings = generateWarnings(result);
			const { risk, blocked } = deriveRiskFromWarnings(warnings);

			expect(risk).toBe('CRITICAL');
			expect(blocked).toBe(true);
		});

		it('Permit2 CRITICAL + BALANCE drain HIGH → CRITICAL', () => {
			const result = createMockDetectionResults({
				hasBalanceDrain: true,
				tokenTransfer: {
					hasTokenTransfer: false,
					hasTokenApproval: false,
					hasBatchOperations: false,
					detectedSelectors: [
						{
							selector: '30f28b7a',
							name: 'permitTransferFrom',
							standard: 'Permit2',
							type: 'permit',
						},
					],
					hasAuthorizationPattern: false,
					hasEcrecover: false,
					hasNonceTracking: false,
					appearsInFallback: false,
					hasHardcodedDestination: false,
					contextualRisk: 'CRITICAL',
					riskReason: 'Permit2 gasless transfer without access control',
				},
			});
			const warnings = generateWarnings(result);
			const { risk, blocked } = deriveRiskFromWarnings(warnings);

			expect(risk).toBe('CRITICAL');
			expect(blocked).toBe(true);
			expect(warnings.find((w) => w.type === 'TOKEN_PERMIT2_NO_AUTH')).toBeDefined();
			expect(warnings.find((w) => w.type === 'BALANCE_DRAIN')).toBeDefined();
		});

		it('DELEGATECALL without any proxy → stays HIGH', () => {
			const result = createMockDetectionResults({
				isDelegatedCall: true,
			});
			const warnings = generateWarnings(result);
			const { risk, blocked } = deriveRiskFromWarnings(warnings);

			const delegateWarning = warnings.find((w) => w.type === 'DELEGATE_CALL');
			expect(delegateWarning?.severity).toBe('HIGH');
			expect(risk).toBe('HIGH');
			expect(blocked).toBe(true);
		});

		it('ERC-4337 + extcodesize (INFO only) → LOW', () => {
			const result = createMockDetectionResults({
				hasErc4337Pattern: true,
				hasExtcodesizeGuard: true,
			});
			const warnings = generateWarnings(result);
			const { risk, blocked } = deriveRiskFromWarnings(warnings);

			expect(warnings.length).toBe(2);
			expect(risk).toBe('LOW');
			expect(blocked).toBe(false);
		});

		it('minimal proxy + EIP-7702 delegation (INFO only) → LOW', () => {
			const result = createMockDetectionResults({
				hasMinimalProxy: true,
				isEip7702Delegation: true,
			});
			const warnings = generateWarnings(result);
			const { risk, blocked } = deriveRiskFromWarnings(warnings);

			expect(warnings.length).toBe(2);
			expect(risk).toBe('LOW');
			expect(blocked).toBe(false);
		});
	});

	describe('risk derivation edge cases', () => {
		it('3+ MEDIUM warnings still → HIGH (not CRITICAL)', () => {
			const warnings = [
				createMockWarning('MEDIUM', 'CREATE2'),
				createMockWarning('MEDIUM', 'CHAINID_READ'),
				createMockWarning('MEDIUM', 'TIMESTAMP_DEPENDENCE'),
			];
			const { risk, blocked } = deriveRiskFromWarnings(warnings);
			expect(risk).toBe('HIGH');
			expect(blocked).toBe(true);
		});

		it('multiple CRITICAL warnings still → CRITICAL', () => {
			const warnings = [
				createMockWarning('CRITICAL', 'AUTO_FORWARDER'),
				createMockWarning('CRITICAL', 'METAMORPHIC'),
			];
			const { risk, blocked } = deriveRiskFromWarnings(warnings);
			expect(risk).toBe('CRITICAL');
			expect(blocked).toBe(true);
		});

		it('single MEDIUM + multiple INFO → MEDIUM (not blocked)', () => {
			const warnings = [
				createMockWarning('MEDIUM', 'CREATE2'),
				createMockWarning('INFO', 'EIP712_SAFE'),
				createMockWarning('INFO', 'ERC4337_PATTERN'),
				createMockWarning('INFO', 'EXTCODESIZE_GUARD'),
			];
			const { risk, blocked } = deriveRiskFromWarnings(warnings);
			expect(risk).toBe('MEDIUM');
			expect(blocked).toBe(false);
		});

		it('HIGH + CRITICAL → CRITICAL', () => {
			const warnings = [
				createMockWarning('HIGH', 'DELEGATE_CALL'),
				createMockWarning('CRITICAL', 'AUTO_FORWARDER'),
			];
			const { risk, blocked } = deriveRiskFromWarnings(warnings);
			expect(risk).toBe('CRITICAL');
			expect(blocked).toBe(true);
		});
	});

	describe('deployer warning interactions', () => {
		it('DEPLOYER_FRESH (CRITICAL) alone → CRITICAL blocked', () => {
			const warnings = [createMockWarning('CRITICAL', 'DEPLOYER_FRESH')];
			const { risk, blocked } = deriveRiskFromWarnings(warnings);
			expect(risk).toBe('CRITICAL');
			expect(blocked).toBe(true);
		});

		it('DEPLOYER_LOW_NONCE (HIGH) + DELEGATECALL (HIGH) → CRITICAL', () => {
			const warnings = [
				createMockWarning('HIGH', 'DEPLOYER_LOW_NONCE'),
				createMockWarning('HIGH', 'DELEGATE_CALL'),
			];
			const { risk, blocked } = deriveRiskFromWarnings(warnings);
			expect(risk).toBe('CRITICAL');
			expect(blocked).toBe(true);
		});

		it('DEPLOYER_NEW_CONTRACT (MEDIUM) + safe bytecode → MEDIUM (not blocked)', () => {
			const warnings = [createMockWarning('MEDIUM', 'DEPLOYER_NEW_CONTRACT')];
			const { risk, blocked } = deriveRiskFromWarnings(warnings);
			expect(risk).toBe('MEDIUM');
			expect(blocked).toBe(false);
		});

		it('DEPLOYER_NEW_CONTRACT (MEDIUM) + CREATE2 (MEDIUM) → HIGH', () => {
			const warnings = [
				createMockWarning('MEDIUM', 'DEPLOYER_NEW_CONTRACT'),
				createMockWarning('MEDIUM', 'CREATE2'),
			];
			const { risk, blocked } = deriveRiskFromWarnings(warnings);
			expect(risk).toBe('HIGH');
			expect(blocked).toBe(true);
		});
	});

	describe('token transfer + bytecode warning interactions', () => {
		// AUDIT-10: a genuine HIGH threat still blocks, but a benign MEDIUM capability
		// (proxy) no longer escalates it to CRITICAL.
		it('TOKEN_NO_AUTH (HIGH) + PROXY_PATTERN (benign MEDIUM) → HIGH, blocked', () => {
			const warnings = [
				createMockWarning('HIGH', 'TOKEN_NO_AUTH'),
				createMockWarning('MEDIUM', 'PROXY_PATTERN'),
			];
			const { risk, blocked } = deriveRiskFromWarnings(warnings);
			expect(risk).toBe('HIGH');
			expect(blocked).toBe(true);
		});

		it('TOKEN_WITH_AUTH (MEDIUM) + CHAINID_COMPARISON (MEDIUM) → HIGH', () => {
			const warnings = [
				createMockWarning('MEDIUM', 'TOKEN_WITH_AUTH'),
				createMockWarning('MEDIUM', 'CHAINID_COMPARISON'),
			];
			const { risk, blocked } = deriveRiskFromWarnings(warnings);
			expect(risk).toBe('HIGH');
			expect(blocked).toBe(true);
		});

		it('TOKEN_REPLAY_RISK (HIGH) alone → HIGH (not CRITICAL)', () => {
			const warnings = [createMockWarning('HIGH', 'TOKEN_REPLAY_RISK')];
			const { risk, blocked } = deriveRiskFromWarnings(warnings);
			expect(risk).toBe('HIGH');
			expect(blocked).toBe(true);
		});

		it('TOKEN_DRAIN_FALLBACK (CRITICAL) + any → CRITICAL', () => {
			const warnings = [
				createMockWarning('CRITICAL', 'TOKEN_DRAIN_FALLBACK'),
				createMockWarning('MEDIUM', 'TIMESTAMP_DEPENDENCE'),
			];
			const { risk, blocked } = deriveRiskFromWarnings(warnings);
			expect(risk).toBe('CRITICAL');
			expect(blocked).toBe(true);
		});
	});

	describe('full generateWarnings → deriveRisk pipeline edge cases', () => {
		it('EIP-712 pattern produces only INFO → LOW risk', () => {
			const result = createMockDetectionResults({
				hasChainId: true,
				isEip712Pattern: true,
			});
			const warnings = generateWarnings(result);
			const { risk, blocked } = deriveRiskFromWarnings(warnings);

			expect(warnings).toHaveLength(1);
			expect(warnings[0].severity).toBe('INFO');
			expect(risk).toBe('LOW');
			expect(blocked).toBe(false);
		});

		it('proxy + diamond + multicall = 3x benign MEDIUM → MEDIUM, not blocked (AUDIT-10)', () => {
			const result = createMockDetectionResults({
				proxy: {
					isProxy: true,
					hasImplementationSlot: true,
					hasAdminSlot: false,
					hasBeaconSlot: false,
				},
				hasDiamondProxy: true,
				hasMulticall: true,
			});
			const warnings = generateWarnings(result);
			const { risk, blocked } = deriveRiskFromWarnings(warnings);

			const mediumWarnings = warnings.filter((w) => w.severity === 'MEDIUM');
			expect(mediumWarnings.length).toBeGreaterThanOrEqual(3);
			expect(risk).toBe('MEDIUM');
			expect(blocked).toBe(false);
		});

		it('all INFO warnings = LOW even with many detections', () => {
			const result = createMockDetectionResults({
				hasErc4337Pattern: true,
				hasExtcodesizeGuard: true,
				hasMinimalProxy: true,
				isEip7702Delegation: true,
				hasChainId: true,
				isEip712Pattern: true,
			});
			const warnings = generateWarnings(result);
			const { risk, blocked } = deriveRiskFromWarnings(warnings);

			expect(warnings.length).toBeGreaterThanOrEqual(4);
			expect(warnings.every((w) => w.severity === 'INFO')).toBe(true);
			expect(risk).toBe('LOW');
			expect(blocked).toBe(false);
		});

		it('delegatecall + selfdestruct + create2 = CRITICAL (metamorphic + DELEGATECALL)', () => {
			const result = createMockDetectionResults({
				isDelegatedCall: true,
				hasSelfDestruct: true,
				hasCreate2: true,
			});
			const warnings = generateWarnings(result);
			const { risk, blocked } = deriveRiskFromWarnings(warnings);

			const metamorphicWarning = warnings.find((w) => w.type === 'METAMORPHIC');
			const delegateWarning = warnings.find((w) => w.type === 'DELEGATE_CALL');
			expect(metamorphicWarning).toBeDefined();
			expect(delegateWarning).toBeDefined();
			expect(risk).toBe('CRITICAL');
			expect(blocked).toBe(true);
		});
	});
});

describe('Drainer Pattern End-to-End Pipeline', () => {
	it('Inferno-style drainer: setApprovalForAll + hardcoded address → CRITICAL', () => {
		const instructions = parseBytecode(DRAINER_PATTERNS.infernoStyle);
		const detectionResults = runAllDetectors(instructions);
		const warnings = generateWarnings(detectionResults);
		const { risk, blocked } = deriveRiskFromWarnings(warnings);

		expect(risk).toBe('CRITICAL');
		expect(blocked).toBe(true);
	});

	it('CrimeEnjoyer with token: fallback drain → CRITICAL', () => {
		const instructions = parseBytecode(DRAINER_PATTERNS.crimeEnjoyerWithToken);
		const detectionResults = runAllDetectors(instructions);
		const warnings = generateWarnings(detectionResults);
		const { risk, blocked } = deriveRiskFromWarnings(warnings);

		expect(risk).toBe('CRITICAL');
		expect(blocked).toBe(true);
		const drainWarning = warnings.find((w) => w.type === 'TOKEN_DRAIN_FALLBACK');
		expect(drainWarning).toBeDefined();
	});

	it('Safe wallet pattern: authorized tokens → MEDIUM (not blocked)', () => {
		const instructions = parseBytecode(DRAINER_PATTERNS.safeWalletPattern);
		const detectionResults = runAllDetectors(instructions);
		const warnings = generateWarnings(detectionResults);
		const { risk, blocked } = deriveRiskFromWarnings(warnings);

		expect(risk).toBe('MEDIUM');
		expect(blocked).toBe(false);
	});

	it('Legitimate with auth: authorized tokens → MEDIUM (not blocked)', () => {
		const instructions = parseBytecode(DRAINER_PATTERNS.legitimateWithAuth);
		const detectionResults = runAllDetectors(instructions);
		const warnings = generateWarnings(detectionResults);
		const { risk, blocked } = deriveRiskFromWarnings(warnings);

		expect(risk).toBe('MEDIUM');
		expect(blocked).toBe(false);
	});

	it('Permit2 drainer: permitTransferFrom without auth → CRITICAL', () => {
		const instructions = parseBytecode(PERMIT2_CONTRACTS.permit2NoAuth);
		const detectionResults = runAllDetectors(instructions);
		const warnings = generateWarnings(detectionResults);
		const { risk, blocked } = deriveRiskFromWarnings(warnings);

		expect(risk).toBe('CRITICAL');
		expect(blocked).toBe(true);
		const permit2Warning = warnings.find((w) => w.type === 'TOKEN_PERMIT2_NO_AUTH');
		expect(permit2Warning).toBeDefined();
	});

	it('Permit2 with auth: authorized Permit2 → MEDIUM (not blocked)', () => {
		const instructions = parseBytecode(PERMIT2_CONTRACTS.permit2WithAuth);
		const detectionResults = runAllDetectors(instructions);
		const warnings = generateWarnings(detectionResults);
		const { risk, blocked } = deriveRiskFromWarnings(warnings);

		expect(risk).toBe('MEDIUM');
		expect(blocked).toBe(false);
	});

	it('BALANCE drain pattern: checks balance then calls → HIGH blocked', () => {
		const instructions = parseBytecode('0x3114f1');
		const detectionResults = runAllDetectors(instructions);
		const warnings = generateWarnings(detectionResults);
		const { risk, blocked } = deriveRiskFromWarnings(warnings);

		expect(risk).toBe('HIGH');
		expect(blocked).toBe(true);
		const bdWarning = warnings.find((w) => w.type === 'BALANCE_DRAIN');
		expect(bdWarning).toBeDefined();
	});

	it('EIP-1167 minimal proxy: DELEGATECALL mitigated to MEDIUM (not blocked)', () => {
		const bytecode = MINIMAL_PROXY_CONTRACTS.canonical;
		const instructions = parseBytecode(bytecode);
		const detectionResults = runAllDetectors(instructions, bytecode);
		const warnings = generateWarnings(detectionResults);
		const { risk, blocked } = deriveRiskFromWarnings(warnings);

		expect(detectionResults.hasMinimalProxy).toBe(true);
		expect(detectionResults.isDelegatedCall).toBe(true);
		const delegateWarning = warnings.find((w) => w.type === 'DELEGATE_CALL');
		expect(delegateWarning?.severity).toBe('MEDIUM');
		expect(risk).toBe('MEDIUM');
		expect(blocked).toBe(false);
		const mpWarning = warnings.find((w) => w.type === 'MINIMAL_PROXY');
		expect(mpWarning).toBeDefined();
	});

	it('Reentrancy: CALL then SSTORE → HIGH blocked', () => {
		const instructions = parseBytecode('0xf160015500');
		const detectionResults = runAllDetectors(instructions);
		const warnings = generateWarnings(detectionResults);
		const { risk, blocked } = deriveRiskFromWarnings(warnings);

		expect(detectionResults.hasReentrancyRisk).toBe(true);
		expect(risk).toBe('HIGH');
		expect(blocked).toBe(true);
		const reWarning = warnings.find((w) => w.type === 'REENTRANCY_RISK');
		expect(reWarning).toBeDefined();
		expect(reWarning?.severity).toBe('HIGH');
	});

	it('Reentrancy + DELEGATECALL: multiple HIGH → CRITICAL blocked', () => {
		// DELEGATECALL + SSTORE (reentrancy via delegatecall)
		const instructions = parseBytecode('0xf460015500');
		const detectionResults = runAllDetectors(instructions);
		const warnings = generateWarnings(detectionResults);
		const { risk, blocked } = deriveRiskFromWarnings(warnings);

		expect(detectionResults.hasReentrancyRisk).toBe(true);
		expect(detectionResults.isDelegatedCall).toBe(true);
		expect(risk).toBe('CRITICAL');
		expect(blocked).toBe(true);
	});

	it('Gas manipulation: GAS + comparison + branch → MEDIUM not blocked', () => {
		const instructions = parseBytecode('0x5a60011460105700');
		const detectionResults = runAllDetectors(instructions);
		const warnings = generateWarnings(detectionResults);
		const { risk, blocked } = deriveRiskFromWarnings(warnings);

		expect(detectionResults.hasGasManipulation).toBe(true);
		const gasWarning = warnings.find((w) => w.type === 'GAS_MANIPULATION');
		expect(gasWarning).toBeDefined();
		expect(gasWarning?.severity).toBe('MEDIUM');
		expect(risk).toBe('MEDIUM');
		expect(blocked).toBe(false);
	});

	it('EXTCODEHASH: code hash check → INFO not blocked', () => {
		const instructions = parseBytecode('0x3f');
		const detectionResults = runAllDetectors(instructions);
		const warnings = generateWarnings(detectionResults);
		const { risk, blocked } = deriveRiskFromWarnings(warnings);

		expect(detectionResults.hasExtcodehash).toBe(true);
		const hashWarning = warnings.find((w) => w.type === 'EXTCODEHASH_CHECK');
		expect(hashWarning).toBeDefined();
		expect(hashWarning?.severity).toBe('INFO');
		expect(risk).toBe('LOW');
		expect(blocked).toBe(false);
	});

	it('Reentrancy + gas manipulation: HIGH + MEDIUM → CRITICAL blocked', () => {
		// CALL + PUSH1 + SSTORE + GAS + comparison + JUMPI
		const instructions = parseBytecode('0xf1600155005a60011460105700');
		const detectionResults = runAllDetectors(instructions);
		const warnings = generateWarnings(detectionResults);
		const { risk, blocked } = deriveRiskFromWarnings(warnings);

		expect(detectionResults.hasReentrancyRisk).toBe(true);
		expect(detectionResults.hasGasManipulation).toBe(true);
		expect(risk).toBe('CRITICAL');
		expect(blocked).toBe(true);
	});
});
