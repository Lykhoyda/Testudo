/**
 * Test Contract Bytecodes
 *
 * Synthetic bytecode examples for testing detectors.
 * Each contract demonstrates specific opcode patterns.
 *
 * OPCODE REFERENCE:
 * 0x00 = STOP
 * 0x47 = SELFBALANCE
 * 0x60 = PUSH1 (1 byte data follows)
 * 0x7F = PUSH32 (32 bytes data follows)
 * 0xF1 = CALL
 * 0xF4 = DELEGATECALL
 * 0xF5 = CREATE2
 * 0xFF = SELFDESTRUCT
 */

export const SELFDESTRUCT_CONTRACTS = {
	minimal: '0xff',
	withPush: '0x6000ff',
	toMsgSender: '0x33ff',
	complex: '0x600160020133ff',
};

export const FALSE_POSITIVE_CONTRACTS = {
	ffAsPush1Data: '0x60ff00',
	ffAsPush2Data: '0x61ffff00',
	maxUint256: `0x7f${'ff'.repeat(32)}00`,
	multiplePushFF: '0x60ff60ff0100',
};

export const DELEGATECALL_CONTRACTS = {
	minimal: '0xf4',
	withSetup: '0x6000600060006000945af4',
	f4AsPushData: '0x60f400',
};

export const AUTO_FORWARDER_CONTRACTS = {
	minimal: '0x47f1',
	realistic: '0x47600080808061dead5af1',
	selfBalanceOnly: '0x4700',
	callOnly: '0xf100',
	spaced: '0x4760016002600301f1',
};

export const UNLIMITED_APPROVAL_CONTRACTS = {
	maxUint256: `0x7f${'ff'.repeat(32)}`,
	partialFF: `0x7f${'00'.repeat(16)}${'ff'.repeat(16)}`,
	allZeros: `0x7f${'00'.repeat(32)}`,
	almostMax: `0x7ffe${'ff'.repeat(31)}`,
};

export const CREATE2_CONTRACTS = {
	minimal: '0xf5',
	f5AsPushData: '0x60f500',
};

export const SAFE_CONTRACTS = {
	simpleAdd: '0x6001600201',
	return42: '0x602a60005260206000f3',
	empty: '0x',
	justStop: '0x00',
};

export const MULTI_THREAT_CONTRACTS = {
	allThreats: '0x47f4f1ff',
	delegateAndDestruct: '0xf4ff',
	sweeperWithApproval: `0x477f${'ff'.repeat(32)}f1`,
};

export const REAL_WORLD_PATTERNS = {
	crimeEnjoyer: '0x47600080808061dead5af1',
	safeProxy:
		'0x363d3d373d3d3d363d73bebebebebebebebebebebebebebebebebebebebe5af43d82803e903d91602b57fd5bf3',
};
