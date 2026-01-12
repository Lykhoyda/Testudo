import { describe, it, expect } from 'vitest';
import { parseBytecode } from '../src/parser';
import {
    detectAutoForwarder,
    detectDelegateCall,
    detectSelfDestruct,
    detectUnlimitedApproval,
    runAllDetectors,
} from '../src/detectors';

import {
    SELFDESTRUCT_CONTRACTS,
    FALSE_POSITIVE_CONTRACTS,
    DELEGATECALL_CONTRACTS,
    AUTO_FORWARDER_CONTRACTS,
    UNLIMITED_APPROVAL_CONTRACTS,
    SAFE_CONTRACTS,
    MULTI_THREAT_CONTRACTS,
} from './fixtures/contracts';

// ============================================
// SELFDESTRUCT DETECTOR
// ============================================

describe('detectSelfDestruct', () => {
    describe('should detect SELFDESTRUCT opcode', () => {
        it('detects minimal SELFDESTRUCT', () => {
            const instructions = parseBytecode(SELFDESTRUCT_CONTRACTS.minimal);
            expect(detectSelfDestruct(instructions)).toBe(true);
        });

        it('detects SELFDESTRUCT with PUSH setup', () => {
            const instructions = parseBytecode(SELFDESTRUCT_CONTRACTS.withPush);
            expect(detectSelfDestruct(instructions)).toBe(true);
        });

        it('detects SELFDESTRUCT(msg.sender) pattern', () => {
            const instructions = parseBytecode(SELFDESTRUCT_CONTRACTS.toMsgSender);
            expect(detectSelfDestruct(instructions)).toBe(true);
        });

        it('detects SELFDESTRUCT in complex bytecode', () => {
            const instructions = parseBytecode(SELFDESTRUCT_CONTRACTS.complex);
            expect(detectSelfDestruct(instructions)).toBe(true);
        });
    });

    describe('should NOT false positive on 0xFF as data', () => {
        it('ignores 0xFF inside PUSH1 data', () => {
            const instructions = parseBytecode(FALSE_POSITIVE_CONTRACTS.ffAsPush1Data);
            expect(detectSelfDestruct(instructions)).toBe(false);
        });

        it('ignores 0xFF inside PUSH2 data', () => {
            const instructions = parseBytecode(FALSE_POSITIVE_CONTRACTS.ffAsPush2Data);
            expect(detectSelfDestruct(instructions)).toBe(false);
        });

        it('ignores max uint256 (32 bytes of 0xFF)', () => {
            const instructions = parseBytecode(FALSE_POSITIVE_CONTRACTS.maxUint256);
            expect(detectSelfDestruct(instructions)).toBe(false);
        });

        it('ignores multiple PUSH with 0xFF data', () => {
            const instructions = parseBytecode(FALSE_POSITIVE_CONTRACTS.multiplePushFF);
            expect(detectSelfDestruct(instructions)).toBe(false);
        });
    });
});

// ============================================
// DELEGATECALL DETECTOR
// ============================================

describe('detectDelegateCall', () => {
    describe('should detect DELEGATECALL opcode', () => {
        it('detects minimal DELEGATECALL', () => {
            const instructions = parseBytecode(DELEGATECALL_CONTRACTS.minimal);
            expect(detectDelegateCall(instructions)).toBe(true);
        });

        it('detects DELEGATECALL with setup', () => {
            const instructions = parseBytecode(DELEGATECALL_CONTRACTS.withSetup);
            expect(detectDelegateCall(instructions)).toBe(true);
        });
    });

    describe('should NOT false positive', () => {
        it('ignores 0xF4 inside PUSH data', () => {
            const instructions = parseBytecode(DELEGATECALL_CONTRACTS.f4AsPushData);
            expect(detectDelegateCall(instructions)).toBe(false);
        });

        it('returns false for safe contract', () => {
            const instructions = parseBytecode(SAFE_CONTRACTS.simpleAdd);
            expect(detectDelegateCall(instructions)).toBe(false);
        });
    });
});

// ============================================
// AUTO FORWARDER DETECTOR
// ============================================

describe('detectAutoForwarder', () => {
    describe('should detect SELFBALANCE + CALL pattern', () => {
        it('detects minimal pattern', () => {
            const instructions = parseBytecode(AUTO_FORWARDER_CONTRACTS.minimal);
            expect(detectAutoForwarder(instructions)).toBe(true);
        });

        it('detects realistic sweeper pattern', () => {
            const instructions = parseBytecode(AUTO_FORWARDER_CONTRACTS.realistic);
            expect(detectAutoForwarder(instructions)).toBe(true);
        });

        it('detects pattern even when spaced apart', () => {
            const instructions = parseBytecode(AUTO_FORWARDER_CONTRACTS.spaced);
            expect(detectAutoForwarder(instructions)).toBe(true);
        });
    });

    describe('should require BOTH opcodes', () => {
        it('rejects SELFBALANCE only', () => {
            const instructions = parseBytecode(AUTO_FORWARDER_CONTRACTS.selfBalanceOnly);
            expect(detectAutoForwarder(instructions)).toBe(false);
        });

        it('rejects CALL only', () => {
            const instructions = parseBytecode(AUTO_FORWARDER_CONTRACTS.callOnly);
            expect(detectAutoForwarder(instructions)).toBe(false);
        });
    });
});

// ============================================
// UNLIMITED APPROVAL DETECTOR
// ============================================

describe('detectUnlimitedApproval', () => {
    describe('should detect PUSH32 with all 0xFF', () => {
        it('detects max uint256', () => {
            const instructions = parseBytecode(UNLIMITED_APPROVAL_CONTRACTS.maxUint256);
            expect(detectUnlimitedApproval(instructions)).toBe(true);
        });
    });

    describe('should NOT detect partial patterns', () => {
        it('rejects partial 0xFF bytes', () => {
            const instructions = parseBytecode(UNLIMITED_APPROVAL_CONTRACTS.partialFF);
            expect(detectUnlimitedApproval(instructions)).toBe(false);
        });

        it('rejects all zeros', () => {
            const instructions = parseBytecode(UNLIMITED_APPROVAL_CONTRACTS.allZeros);
            expect(detectUnlimitedApproval(instructions)).toBe(false);
        });

        it('rejects almost-max (one byte different)', () => {
            const instructions = parseBytecode(UNLIMITED_APPROVAL_CONTRACTS.almostMax);
            expect(detectUnlimitedApproval(instructions)).toBe(false);
        });
    });
});

// ============================================
// COMBINED DETECTORS
// ============================================

describe('runAllDetectors', () => {
    describe('multi-threat contracts', () => {
        it('detects all threats in combined contract', () => {
            const instructions = parseBytecode(MULTI_THREAT_CONTRACTS.allThreats);
            const result = runAllDetectors(instructions);

            expect(result.hasSelfDestruct).toBe(true);
            expect(result.isDelegatedCall).toBe(true);
            expect(result.hasAutoForwarder).toBe(true);
        });

        it('detects delegatecall + selfdestruct combo', () => {
            const instructions = parseBytecode(MULTI_THREAT_CONTRACTS.delegateAndDestruct);
            const result = runAllDetectors(instructions);

            expect(result.hasSelfDestruct).toBe(true);
            expect(result.isDelegatedCall).toBe(true);
            expect(result.hasAutoForwarder).toBe(false);
        });

        it('detects sweeper + unlimited approval combo', () => {
            const instructions = parseBytecode(MULTI_THREAT_CONTRACTS.sweeperWithApproval);
            const result = runAllDetectors(instructions);

            expect(result.hasAutoForwarder).toBe(true);
            expect(result.hasUnlimitedApprovals).toBe(true);
        });
    });

    describe('safe contracts', () => {
        it('returns all false for simple add', () => {
            const instructions = parseBytecode(SAFE_CONTRACTS.simpleAdd);
            const result = runAllDetectors(instructions);

            expect(result.hasSelfDestruct).toBe(false);
            expect(result.isDelegatedCall).toBe(false);
            expect(result.hasAutoForwarder).toBe(false);
            expect(result.hasUnlimitedApprovals).toBe(false);
        });

        it('handles empty bytecode', () => {
            const instructions = parseBytecode(SAFE_CONTRACTS.empty);
            const result = runAllDetectors(instructions);

            expect(result.hasSelfDestruct).toBe(false);
            expect(result.isDelegatedCall).toBe(false);
            expect(result.hasAutoForwarder).toBe(false);
            expect(result.hasUnlimitedApprovals).toBe(false);
        });

        it('handles just STOP', () => {
            const instructions = parseBytecode(SAFE_CONTRACTS.justStop);
            const result = runAllDetectors(instructions);

            expect(result.hasSelfDestruct).toBe(false);
            expect(result.isDelegatedCall).toBe(false);
        });
    });
});

// ============================================
// PARSER EDGE CASES
// ============================================

describe('parseBytecode', () => {
    it('correctly separates PUSH data from opcodes', () => {
        // 60 FF 00 = PUSH1 0xFF, STOP
        const instructions = parseBytecode('0x60ff00');

        expect(instructions).toHaveLength(2);
        expect(instructions[0].opcode).toBe('PUSH1');
        expect(instructions[0].data?.[0]).toBe(0xff);
        expect(instructions[1].opcode).toBe('00'); // STOP
    });

    it('handles PUSH32 correctly', () => {
        const bytecode = '0x7f' + 'ab'.repeat(32);
        const instructions = parseBytecode(bytecode);

        expect(instructions).toHaveLength(1);
        expect(instructions[0].opcode).toBe('PUSH32');
        expect(instructions[0].data).toHaveLength(32);
    });

    it('handles bytecode without 0x prefix', () => {
        const instructions = parseBytecode('ff');
        expect(instructions).toHaveLength(1);
        expect(instructions[0].opcode).toBe('SELFDESTRUCT');
    });

    it('tracks correct byte indices', () => {
        // 60 01 60 02 = PUSH1 0x01, PUSH1 0x02
        const instructions = parseBytecode('0x60016002');

        expect(instructions[0].byteIndex).toBe(0);
        expect(instructions[1].byteIndex).toBe(2); // After PUSH1 + 1 byte data
    });
});
