/**
 * Test Contract Bytecodes
 *
 * Synthetic bytecode examples for testing detectors.
 * Each contract demonstrates specific opcode patterns.
 *
 * OPCODE REFERENCE:
 * 0x00 = STOP
 * 0x10 = LT
 * 0x11 = GT
 * 0x12 = SLT
 * 0x13 = SGT
 * 0x14 = EQ
 * 0x20 = KECCAK256
 * 0x46 = CHAINID
 * 0x47 = SELFBALANCE
 * 0x52 = MSTORE
 * 0x57 = JUMPI
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
	withSetup: '0x6000600060006000f5',
	inComplexCode: '0x600160020133f500',
	f5AsPushData: '0x60f500',
	f5AsPush2Data: '0x61f5f500',
	metamorphic: '0xf5ff',
	metamorphicReverse: '0xfff5',
	metamorphicWithCode: '0x6000f5336080ff',
};

export const CHAINID_CONTRACTS = {
	minimal: '0x46',
	withBranching: '0x46600114601057',
	branchingSpaced: '0x4660016002600314601057',
	x46AsPushData: '0x610046',
	x46AsPush1Data: '0x604600',
	noBranching: '0x4660015500',
	withComparison: '0x46600114',
	withComparisonLT: '0x46600110',
	withComparisonGT: '0x46600111',
	withComparisonSLT: '0x46600112',
	withComparisonSGT: '0x46600113',
	withBranchingAndComparison: '0x4660011460105700',
	eip712Pattern: '0x466001600220',
	eip712PatternDirect: '0x4620',
	eip712Complex: '0x466000526020600020',
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

/**
 * Token Transfer Test Contracts
 *
 * SELECTOR REFERENCE:
 * 0xa9059cbb = transfer(address,uint256) [ERC20]
 * 0x23b872dd = transferFrom(address,address,uint256) [ERC20]
 * 0x095ea7b3 = approve(address,uint256) [ERC20]
 * 0x39509351 = increaseAllowance(address,uint256) [ERC20]
 * 0x42842e0e = safeTransferFrom(address,address,uint256) [ERC721]
 * 0xb88d4fde = safeTransferFrom(address,address,uint256,bytes) [ERC721]
 * 0xa22cb465 = setApprovalForAll(address,bool) [ERC721]
 * 0xf242432a = safeTransferFrom(...) [ERC1155]
 * 0x2eb2c2d6 = safeBatchTransferFrom(...) [ERC1155]
 *
 * OPCODE REFERENCE:
 * 0x33 = CALLER (msg.sender)
 * 0x36 = CALLDATASIZE
 * 0x54 = SLOAD
 * 0x55 = SSTORE
 * 0x63 = PUSH4
 * 0x73 = PUSH20
 * 0xFA = STATICCALL
 */

export const TOKEN_TRANSFER_CONTRACTS = {
	erc20Transfer: '0x63a9059cbb',
	erc20TransferFrom: '0x6323b872dd',
	erc20Approve: '0x63095ea7b3',
	erc20IncreaseAllowance: '0x6339509351',
	erc721SafeTransfer: '0x6342842e0e',
	erc721SafeTransferWithData: '0x63b88d4fde',
	erc721SetApprovalForAll: '0x63a22cb465',
	erc1155SafeTransfer: '0x63f242432a',
	erc1155BatchTransfer: '0x632eb2c2d6',
	multipleSelectors: '0x63a9059cbb6323b872dd63095ea7b3',
	selectorInPush32NotDetected: `0x7fa9059cbb${'00'.repeat(28)}`,
	noTokenSelectors: '0x6001600201',
};

export const AUTHORIZATION_CONTRACTS = {
	withEcrecover: '0x6001fa',
	withEcrecoverPush20: `0x73${'00'.repeat(19)}01fa`,
	withMsgSenderCheck: '0x3360001014',
	withNonceTracking: '0x60005460016001015500',
	withFullAuth: '0x6001fa3360001014600054600100015500',
	noAuth: '0x63a9059cbb',
	ecrecoverWithoutNonce: '0x63a9059cbb6001fa',
	msgSenderWithoutEcrecover: '0x63a9059cbb3360001014',
};

export const FALLBACK_CONTRACTS = {
	callInFallback: '0x36600052f1',
	callWithDispatcher: '0x3663a9059cbb1460105760006000f1',
	noCalldatasize: '0x60006000f1',
	dispatcherBeforeCall: '0x3663a9059cbb1463095ea7b31460205760006000f1',
};

export const HARDCODED_DESTINATION_CONTRACTS = {
	hardcodedAddress: '0x73deadbeefdeadbeefdeadbeefdeadbeefdeadbeeff1',
	callerDestination: `0x73${'00'.repeat(19)}00f1`,
	precompileDestination: `0x73${'00'.repeat(19)}01f1`,
	noHardcodedAddr: '0x60006000f1',
};

export const DRAINER_PATTERNS = {
	infernoStyle: '0x63a22cb46573deadbeefdeadbeefdeadbeefdeadbeefdeadbeeef1',
	crimeEnjoyerWithToken: '0x3663a9059cbb60006000f1',
	safeWalletPattern: '0x63a9059cbb6001fa600054600100015500',
	legitimateWithAuth: '0x63a9059cbb3360001014600054600100015500',
};
