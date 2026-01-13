import { describe, expect, it } from 'vitest';
import { runAllDetectors } from '../src/detectors';
import { checkKnownMalicious } from '../src/malicious-db';
import { parseBytecode } from '../src/parser';
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
