export const OPCODES = {
	'10': 'LT',
	'11': 'GT',
	'12': 'SLT',
	'13': 'SGT',
	'14': 'EQ',
	'20': 'KECCAK256',
	'33': 'CALLER',
	'36': 'CALLDATASIZE',
	'46': 'CHAINID',
	'47': 'SELFBALANCE',
	'54': 'SLOAD',
	'55': 'SSTORE',
	'57': 'JUMPI',
	'7F': 'PUSH32',
	F1: 'CALL',
	F4: 'DELEGATECALL',
	F5: 'CREATE2',
	FA: 'STATICCALL',
	FF: 'SELFDESTRUCT',
} as const;

export const COMPARISON_OPCODES = ['LT', 'GT', 'SLT', 'SGT', 'EQ'] as const;

export const TOKEN_SELECTORS = {
	// ERC20
	transfer: 'a9059cbb',
	transferFrom: '23b872dd',
	approve: '095ea7b3',
	increaseAllowance: '39509351',
	// ERC721
	safeTransferFrom: '42842e0e',
	safeTransferFromWithData: 'b88d4fde',
	setApprovalForAll: 'a22cb465',
	// ERC1155
	safeTransferFrom1155: 'f242432a',
	safeBatchTransferFrom: '2eb2c2d6',
} as const;

export const APPROVAL_SELECTORS = [
	TOKEN_SELECTORS.approve,
	TOKEN_SELECTORS.increaseAllowance,
	TOKEN_SELECTORS.setApprovalForAll,
] as const;

export const BATCH_SELECTORS = [TOKEN_SELECTORS.safeBatchTransferFrom] as const;
