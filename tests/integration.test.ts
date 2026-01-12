import {describe, expect, it} from 'vitest';
import {parseBytecode} from '../src/parser';
import {runAllDetectors} from '../src/detectors';
import {checkKnownMalicious} from '../src/utils/malicious-db';
import {
    AUTO_FORWARDER_CONTRACTS,
    DELEGATECALL_CONTRACTS,
    MULTI_THREAT_CONTRACTS,
    REAL_WORLD_PATTERNS,
    SAFE_CONTRACTS,
    SELFDESTRUCT_CONTRACTS,
} from './fixtures/contracts';

/**
 * Integration tests for the full analysis pipeline.
 *
 * These tests verify that all layers work together correctly:
 * 1. Database lookup (Layer 1)
 * 2. Bytecode parsing (Layer 3)
 * 3. Pattern detection (Layer 4)
 * 4. Risk scoring (Layer 5)
 */

describe('Analysis Pipeline Integration', () => {
    describe('Layer 1 → Layer 4: Database vs Detection', () => {
        it('database catches known malicious before detection runs', () => {
            const address = '0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b';

            // Layer 1: Database check
            const dbResult = checkKnownMalicious(address);
            expect(dbResult).not.toBeNull();
            expect(dbResult?.type).toBe('ETH_AUTO_FORWARDER');

            // In real flow, we'd return early here without running detectors
        });

        it('unknown contracts proceed to bytecode analysis', () => {
            const address = '0x63c0c19a282a1b52b07dd5a65b58948a07dae32b';

            // Layer 1: Database check (miss)
            const dbResult = checkKnownMalicious(address);
            expect(dbResult).toBeNull();

            // Would proceed to Layer 2 (fetch) → Layer 3 (parse) → Layer 4 (detect)
        });
    });

    describe('Layer 3 → Layer 4: Parser + Detectors', () => {
        it('parses and detects SELFDESTRUCT threat', () => {
            const bytecode = SELFDESTRUCT_CONTRACTS.complex;

            // Layer 3: Parse
            const instructions = parseBytecode(bytecode);
            expect(instructions.length).toBeGreaterThan(0);

            // Layer 4: Detect
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
        /**
         * Risk calculation:
         * - Any threat detected → CRITICAL
         * - No threats → LOW
         */

        it('calculates CRITICAL risk for multi-threat contract', () => {
            const bytecode = MULTI_THREAT_CONTRACTS.allThreats;
            const instructions = parseBytecode(bytecode);
            const threats = runAllDetectors(instructions);

            // Count detected threats
            const detectedThreats = Object.entries(threats)
                .filter(([_, detected]) => detected)
                .map(([name]) => name);

            expect(detectedThreats.length).toBeGreaterThan(0);

            // Risk calculation
            const risk = detectedThreats.length > 0 ? 'CRITICAL' : 'LOW';
            expect(risk).toBe('CRITICAL');
        });

        it('calculates LOW risk for safe contract', () => {
            const bytecode = SAFE_CONTRACTS.return42;
            const instructions = parseBytecode(bytecode);
            const threats = runAllDetectors(instructions);

            const detectedThreats = Object.entries(threats)
                .filter(([_, detected]) => detected)
                .map(([name]) => name);

            expect(detectedThreats.length).toBe(0);

            const risk = detectedThreats.length > 0 ? 'CRITICAL' : 'LOW';
            expect(risk).toBe('LOW');
        });
    });

    describe('Real-World Pattern Analysis', () => {
        it('detects CrimeEnjoyer sweeper pattern', () => {
            const bytecode = REAL_WORLD_PATTERNS.crimeEnjoyer;
            const instructions = parseBytecode(bytecode);
            const result = runAllDetectors(instructions);

            // CrimeEnjoyer uses SELFBALANCE + CALL pattern
            expect(result.hasAutoForwarder).toBe(true);
        });

        it('detects proxy pattern with DELEGATECALL', () => {
            const bytecode = REAL_WORLD_PATTERNS.safeProxy;
            const instructions = parseBytecode(bytecode);
            const result = runAllDetectors(instructions);

            // Proxy contracts use DELEGATECALL
            expect(result.isDelegatedCall).toBe(true);
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
                .filter(([_, detected]) => detected)
                .map(([name]) => name);

            expect(threatList).toHaveLength(0);
        });
    });
});

describe('Edge Cases', () => {
    describe('Bytecode Edge Cases', () => {
        it('handles very short bytecode', () => {
            const bytecode = '0x00'; // Just STOP
            const instructions = parseBytecode(bytecode);
            const result = runAllDetectors(instructions);

            expect(result.hasSelfDestruct).toBe(false);
        });

        it('handles bytecode with only PUSH instructions', () => {
            const bytecode = '0x60016002600360046005';
            const instructions = parseBytecode(bytecode);
            const result = runAllDetectors(instructions);

            // Should not detect any threats
            expect(result.hasSelfDestruct).toBe(false);
            expect(result.isDelegatedCall).toBe(false);
            expect(result.hasAutoForwarder).toBe(false);
        });

        it('handles truncated PUSH instruction at end', () => {
            // PUSH2 expects 2 bytes but only 1 provided
            const bytecode = '0x61ff';
            const instructions = parseBytecode(bytecode);

            // Parser should handle gracefully
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
