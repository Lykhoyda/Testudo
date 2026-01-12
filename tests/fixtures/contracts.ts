/**
 * Test Contract Bytecodes
 *
 * Synthetic bytecode examples for testing detectors.
 * Each contract demonstrates specific opcode patterns.
 *
 * OPCODE REFERENCE:
 * ─────────────────
 * 0x00 = STOP
 * 0x47 = SELFBALANCE
 * 0x60 = PUSH1 (1 byte data follows)
 * 0x7F = PUSH32 (32 bytes data follows)
 * 0xF1 = CALL
 * 0xF4 = DELEGATECALL
 * 0xF5 = CREATE2
 * 0xFF = SELFDESTRUCT
 */

// ============================================
// SELFDESTRUCT CONTRACTS
// ============================================

export const SELFDESTRUCT_CONTRACTS = {
    /**
     * Minimal: just SELFDESTRUCT
     * Bytecode: FF
     * Parsed: [SELFDESTRUCT]
     */
    minimal: '0xff',

    /**
     * With address setup: PUSH1 0x00, SELFDESTRUCT
     * Bytecode: 60 00 FF
     * Parsed: [PUSH1 0x00] [SELFDESTRUCT]
     *
     * Real usage: selfdestruct(address(0))
     */
    withPush: '0x6000ff',

    /**
     * Realistic: CALLER, SELFDESTRUCT
     * Bytecode: 33 FF
     * Parsed: [CALLER] [SELFDESTRUCT]
     *
     * Real usage: selfdestruct(msg.sender)
     */
    toMsgSender: '0x33ff',

    /**
     * Complex: Multiple ops then SELFDESTRUCT
     * Bytecode: 60 01 60 02 01 33 FF
     * Parsed: [PUSH1 0x01] [PUSH1 0x02] [ADD] [CALLER] [SELFDESTRUCT]
     */
    complex: '0x600160020133ff',
};

// ============================================
// FALSE POSITIVE CONTRACTS (contain 0xFF but NOT as opcode)
// ============================================

export const FALSE_POSITIVE_CONTRACTS = {
    /**
     * 0xFF as PUSH1 data (NOT selfdestruct!)
     * Bytecode: 60 FF 00
     * Parsed: [PUSH1 0xFF] [STOP]
     *
     * The 0xFF is consumed as data by PUSH1
     */
    ffAsPush1Data: '0x60ff00',

    /**
     * 0xFF inside PUSH2 data
     * Bytecode: 61 FF FF 00
     * Parsed: [PUSH2 0xFFFF] [STOP]
     */
    ffAsPush2Data: '0x61ffff00',

    /**
     * Max uint256 (all 0xFF in PUSH32)
     * Bytecode: 7F + 32 bytes of FF + 00
     * Parsed: [PUSH32 0xFFFF...FF] [STOP]
     *
     * Common in approve(spender, type(uint256).max)
     */
    maxUint256: '0x7f' + 'ff'.repeat(32) + '00',

    /**
     * Multiple PUSH with FF data
     * Bytecode: 60 FF 60 FF 01 00
     * Parsed: [PUSH1 0xFF] [PUSH1 0xFF] [ADD] [STOP]
     *
     * Calculates 255 + 255 = 510
     */
    multiplePushFF: '0x60ff60ff0100',
};

// ============================================
// DELEGATECALL CONTRACTS
// ============================================

export const DELEGATECALL_CONTRACTS = {
    /**
     * Minimal: just DELEGATECALL
     * Bytecode: F4
     * Parsed: [DELEGATECALL]
     */
    minimal: '0xf4',

    /**
     * With setup (typical proxy pattern)
     * Bytecode: 60 00 ... F4
     */
    withSetup: '0x6000600060006000945af4',

    /**
     * 0xF4 as PUSH data (NOT delegatecall!)
     * Bytecode: 60 F4 00
     * Parsed: [PUSH1 0xF4] [STOP]
     */
    f4AsPushData: '0x60f400',
};

// ============================================
// AUTO FORWARDER CONTRACTS (SELFBALANCE + CALL)
// ============================================

export const AUTO_FORWARDER_CONTRACTS = {
    /**
     * Minimal: SELFBALANCE then CALL
     * Bytecode: 47 F1
     * Parsed: [SELFBALANCE] [CALL]
     *
     * Gets contract balance, then calls (sends ETH)
     */
    minimal: '0x47f1',

    /**
     * Realistic sweeper pattern
     * Bytecode: 47 60 00 80 80 80 61 de ad 5a F1
     * SELFBALANCE, PUSH1 0x00, DUP1, DUP1, DUP1, PUSH2 0xdead, GAS, CALL
     */
    realistic: '0x47600080808061dead5af1',

    /**
     * Only SELFBALANCE (missing CALL)
     * Bytecode: 47 00
     * Parsed: [SELFBALANCE] [STOP]
     *
     * Should NOT trigger - needs both
     */
    selfBalanceOnly: '0x4700',

    /**
     * Only CALL (missing SELFBALANCE)
     * Bytecode: F1 00
     * Parsed: [CALL] [STOP]
     *
     * Should NOT trigger - needs both
     */
    callOnly: '0xf100',

    /**
     * SELFBALANCE and CALL far apart
     * Still should trigger - order doesn't matter
     */
    spaced: '0x4760016002600301f1',
};

// ============================================
// UNLIMITED APPROVAL CONTRACTS
// ============================================

export const UNLIMITED_APPROVAL_CONTRACTS = {
    /**
     * PUSH32 with all 0xFF (type(uint256).max)
     * Bytecode: 7F + 32×FF
     *
     * Used in: approve(spender, type(uint256).max)
     */
    maxUint256: '0x7f' + 'ff'.repeat(32),

    /**
     * Partial FF - should NOT trigger
     * Bytecode: 7F + 16×00 + 16×FF
     */
    partialFF: '0x7f' + '00'.repeat(16) + 'ff'.repeat(16),

    /**
     * All zeros - should NOT trigger
     * Bytecode: 7F + 32×00
     */
    allZeros: '0x7f' + '00'.repeat(32),

    /**
     * Single FF byte different - should NOT trigger
     * Bytecode: 7F + FE + 31×FF
     */
    almostMax: '0x7ffe' + 'ff'.repeat(31),
};

// ============================================
// CREATE2 CONTRACTS
// ============================================

export const CREATE2_CONTRACTS = {
    /**
     * Minimal: just CREATE2
     * Bytecode: F5
     * Parsed: [CREATE2]
     */
    minimal: '0xf5',

    /**
     * 0xF5 as PUSH data (NOT create2!)
     * Bytecode: 60 F5 00
     * Parsed: [PUSH1 0xF5] [STOP]
     */
    f5AsPushData: '0x60f500',
};

// ============================================
// SAFE CONTRACTS (no threats)
// ============================================

export const SAFE_CONTRACTS = {
    /**
     * Simple storage: PUSH, PUSH, ADD, STOP
     * Bytecode: 60 01 60 02 01 00
     * Parsed: [PUSH1 0x01] [PUSH1 0x02] [ADD] [STOP]
     */
    simpleAdd: '0x6001600201',

    /**
     * Return value
     * Bytecode: 60 2A 60 00 52 60 20 60 00 F3
     * Returns 42
     */
    return42: '0x602a60005260206000f3',

    /**
     * Empty contract
     */
    empty: '0x',

    /**
     * Just STOP
     * Bytecode: 00
     */
    justStop: '0x00',
};

// ============================================
// MULTI-THREAT CONTRACTS
// ============================================

export const MULTI_THREAT_CONTRACTS = {
    /**
     * All threats combined
     * Bytecode: 47 F4 F1 FF
     * Parsed: [SELFBALANCE] [DELEGATECALL] [CALL] [SELFDESTRUCT]
     *
     * Triggers: autoForwarder, delegatecall, selfDestruct
     */
    allThreats: '0x47f4f1ff',

    /**
     * Delegatecall + SelfDestruct (proxy that can die)
     * Bytecode: F4 FF
     */
    delegateAndDestruct: '0xf4ff',

    /**
     * Sweeper + Unlimited approval
     * Bytecode: 47 7F + 32×FF + F1
     */
    sweeperWithApproval: '0x477f' + 'ff'.repeat(32) + 'f1',
};

// ============================================
// REAL-WORLD APPROXIMATIONS
// ============================================

export const REAL_WORLD_PATTERNS = {
    /**
     * CrimeEnjoyer-style sweeper (simplified)
     * Pattern: receive ETH → forward to attacker
     *
     * This is a simplified version of the 0x930fcc37 pattern
     */
    crimeEnjoyer: '0x47600080808061dead5af1',

    /**
     * Proxy pattern (safe, common)
     * DELEGATECALL to implementation
     */
    safeProxy: '0x363d3d373d3d3d363d73bebebebebebebebebebebebebebebebebebebebe5af43d82803e903d91602b57fd5bf3',
};
