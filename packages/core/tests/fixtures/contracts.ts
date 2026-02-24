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
	// SELFBALANCE followed by 16+ instructions before CALL (beyond LOOK_AHEAD.address=15)
	beyondProximity: `0x47${'6001'.repeat(16)}f1`,
	// CALL appears BEFORE SELFBALANCE (wrong order)
	reversedOrder: '0xf14700',
	// SELFBALANCE at very end, no CALL after
	selfBalanceAtEnd: '0x600160024700',
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
	erc20Permit: '0x63d505accf',
	erc721SafeTransfer: '0x6342842e0e',
	erc721SafeTransferWithData: '0x63b88d4fde',
	erc721SetApprovalForAll: '0x63a22cb465',
	erc1155SafeTransfer: '0x63f242432a',
	erc1155BatchTransfer: '0x632eb2c2d6',
	permit2TransferFrom: '0x6330f28b7a',
	permit2TransferFromBatch: '0x63edd9444b',
	multipleSelectors: '0x63a9059cbb6323b872dd63095ea7b3',
	selectorInPush32NotDetected: `0x7fa9059cbb${'00'.repeat(28)}`,
	noTokenSelectors: '0x6001600201',
};

export const AUTHORIZATION_CONTRACTS = {
	withEcrecover: '0x6001fa',
	withEcrecoverPush20: `0x73${'00'.repeat(19)}01fa`,
	withEcrecoverCall: '0x6001f1',
	withEcrecoverCallPush20: `0x73${'00'.repeat(19)}01f1`,
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

export const PROXY_CONTRACTS = {
	eip1967Implementation: `0x7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc54f4`,
	eip1967Admin: `0x7fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d610354`,
	eip1967Beacon: `0x7fa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d5054`,
	eip1967Full: `0x7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc547fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d610354f4`,
	notProxy: '0x6001600201',
};

export const TX_ORIGIN_CONTRACTS = {
	originEq: '0x3214',
	originCallerEq: '0x323314',
	originOnly: '0x3200',
	originFarFromEq: '0x3260016002600360041400',
	originInPushData: '0x603200',
};

export const EIP7702_CONTRACTS = {
	validDelegation: `0xef0100${'ab'.repeat(20)}`,
	wrongPrefix: `0xef0200${'ab'.repeat(20)}`,
	tooShort: '0xef0100ab',
	tooLong: `0xef0100${'ab'.repeat(21)}`,
	normalBytecode: '0x6001600201',
};

export const TIMESTAMP_CONTRACTS = {
	withComparisonAndBranch: '0x4260011460105700',
	withGtAndBranch: '0x426001116010570054',
	timestampOnly: '0x4200',
	timestampNoComparison: '0x42600157',
	inPushData: '0x604200',
};

export const NONCE_TRACKING_CONTRACTS = {
	incrementPattern: '0x60005460010155',
	subtractPattern: '0x60005460010355',
	sloadWithoutArithmetic: '0x60005460015500',
	sstoreWithoutSload: '0x60016001015500',
};

export const DECREASE_ALLOWANCE_CONTRACTS = {
	decreaseAllowance: '0x63a457c2d7',
};

export const MULTICALL_CONTRACTS = {
	multicall: '0x63ac9650d8',
	aggregate: '0x63252dba42',
	tryAggregate: '0x63bce38bd7',
	aggregate3: '0x6382ad56cb',
	noMulticall: '0x6001600201',
	selectorInPush32: `0x7fac9650d8${'00'.repeat(28)}`,
};

export const EXTCODESIZE_CONTRACTS = {
	withIszero: '0x3b15',
	withEq: '0x3b14',
	withGt: '0x3b11',
	alone: '0x3b00',
	inPushData: '0x603b00',
};

export const ERC4337_CONTRACTS = {
	handleOpsSelector: '0x631fad948c',
	handleAggregatedOpsSelector: '0x634b1d7cf5',
	validateUserOpSelector: '0x633a871cdd',
	entryPointV06: `0x735ff137d4b0fdcd49dca30c7cf57e578a026d2789f4`,
	entryPointV07: `0x730000000071727de22e5e9d8baf0edac6f37da032f4`,
	notErc4337: '0x6001600201',
	selectorInPush32: `0x7f1fad948c${'00'.repeat(28)}`,
};

export const COINBASE_CONTRACTS = {
	withComparisonAndBranch: '0x4160011460105700',
	withGtAndBranch: '0x416001116010570054',
	coinbaseOnly: '0x4100',
	coinbaseNoComparison: '0x41600157',
	inPushData: '0x604100',
};

export const MINIMAL_PROXY_CONTRACTS = {
	canonical:
		'0x363d3d373d3d3d363d73bebebebebebebebebebebebebebebebebebebebe5af43d82803e903d91602b57fd5bf3',
	uniswapImpl:
		'0x363d3d373d3d3d363d731f98431c8ad98523631ae4a59f267346ea31f9845af43d82803e903d91602b57fd5bf3',
	wrongPrefix:
		'0x373d3d373d3d3d363d73bebebebebebebebebebebebebebebebebebebebe5af43d82803e903d91602b57fd5bf3',
	wrongSuffix:
		'0x363d3d373d3d3d363d73bebebebebebebebebebebebebebebebebebebebe5af43d82803e903d91602b57fd5bf4',
	tooShort: '0x363d3d373d3d3d363d73bebe5af43d82803e903d91602b57fd5bf3',
	tooLong:
		'0x363d3d373d3d3d363d73bebebebebebebebebebebebebebebebebebebeee5af43d82803e903d91602b57fd5bf300',
	normalBytecode: '0x6001600201',
};

export const DIAMOND_PROXY_CONTRACTS = {
	diamondCutSelector: '0x631f931c1c',
	facetsSelector: '0x637a0ed627',
	facetAddressSelector: '0x63cdffacc6',
	facetFunctionSelectorsSelector: '0x63adfca15e',
	facetAddressesSelector: '0x6352ef6b2c',
	notDiamond: '0x6001600201',
	selectorInPush32: `0x7f1f931c1c${'00'.repeat(28)}`,
};

export const BALANCE_DRAIN_CONTRACTS = {
	balanceCompareCall: '0x3114f1',
	balanceGtCall: '0x3111f1',
	balanceCompareSelfdestruct: '0x3114ff',
	balanceOnly: '0x3100',
	balanceNoCompare: '0x31f1',
	balanceInPushData: '0x603100',
	selfbalanceNotBalance: '0x4714f1',
};

export const EXTCODECOPY_CONTRACTS = {
	minimal: '0x3c',
	withCreate2: '0x3cf5',
	withCreate2AndSelfdestruct: '0x3cf5ff',
	inPushData: '0x603c00',
};

export const CALLCODE_CONTRACTS = {
	minimal: '0xf2',
	withSetup: '0x6000600060006000945af2',
	f2AsPushData: '0x60f200',
	bothCallcodeAndDelegatecall: '0xf2f4',
};

export const PERMIT2_CONTRACTS = {
	permit2NoAuth: '0x6330f28b7a',
	permit2BatchNoAuth: '0x63edd9444b',
	permit2WithAuth: '0x6330f28b7a6001fa3360001014600054600100015500',
};

export const REENTRANCY_CONTRACTS = {
	// CALL (0xF1) followed by SSTORE (0x55) — state change after external call
	callThenSstore: '0xf160015500',
	// STATICCALL (0xFA) followed by SSTORE — read-only, NOT reentrancy
	staticcallThenSstore: '0xfa60015500',
	// DELEGATECALL (0xF4) followed by SSTORE
	delegatecallThenSstore: '0xf460015500',
	// CALLCODE (0xF2) followed by SSTORE
	callcodeThenSstore: '0xf260015500',
	// SSTORE before CALL — correct pattern (checks-effects-interactions)
	sstoreBeforeCall: '0x60015500f1',
	// CALL only, no SSTORE after
	callOnly: '0xf100',
	// SSTORE only, no CALL before
	sstoreOnly: '0x60015500',
	// CALL with SSTORE at exactly 14 instructions (inside LOOK_AHEAD.address=15 window)
	atBoundaryInside: `0xf1${'6001'.repeat(13)}5500`,
	// CALL with SSTORE at exactly 15 instructions (boundary of LOOK_AHEAD.address window)
	atBoundaryEdge: `0xf1${'6001'.repeat(14)}5500`,
	// CALL with SSTORE far beyond proximity window (16+ instructions apart)
	beyondProximity: `0xf1${'6001'.repeat(16)}5500`,
};

export const GAS_MANIPULATION_CONTRACTS = {
	// GAS (0x5A) + comparison + JUMPI
	withComparisonAndBranch: '0x5a60011460105700',
	// GAS + GT + JUMPI
	withGtAndBranch: '0x5a6001116010570054',
	// GAS alone
	gasOnly: '0x5a00',
	// GAS without comparison
	gasNoComparison: '0x5a600157',
	// GAS in PUSH data
	inPushData: '0x605a00',
};

export const EXTCODEHASH_CONTRACTS = {
	minimal: '0x3f',
	withComparison: '0x3f14',
	inPushData: '0x603f00',
};

export const DRAINER_PATTERNS = {
	infernoStyle: '0x63a22cb46573deadbeefdeadbeefdeadbeefdeadbeefdeadbeeef1',
	crimeEnjoyerWithToken: '0x3663a9059cbb60006000f1',
	safeWalletPattern: '0x63a9059cbb6001fa600054600100015500',
	legitimateWithAuth: '0x63a9059cbb3360001014600054600100015500',
};
