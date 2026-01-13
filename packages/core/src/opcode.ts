export const OPCODES = {
	'10': 'LT',
	'11': 'GT',
	'12': 'SLT',
	'13': 'SGT',
	'14': 'EQ',
	'20': 'KECCAK256',
	'46': 'CHAINID',
	'47': 'SELFBALANCE',
	'57': 'JUMPI',
	'7F': 'PUSH32',
	F1: 'CALL',
	F4: 'DELEGATECALL',
	F5: 'CREATE2',
	FF: 'SELFDESTRUCT',
} as const;

export const COMPARISON_OPCODES = ['LT', 'GT', 'SLT', 'SGT', 'EQ'] as const;
