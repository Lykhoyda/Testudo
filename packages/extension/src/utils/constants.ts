export const APPROVAL_SELECTORS = {
	approve: '0x095ea7b3',
	increaseAllowance: '0x39509351',
	decreaseAllowance: '0xa457c2d7',
} as const;

export const NFT_APPROVAL_SELECTORS = {
	setApprovalForAll: '0xa22cb465',
} as const;

export const KNOWN_MARKETPLACES: Record<string, string> = {
	'0x1e0049783f008a0085193e00003d00cd54003c71': 'OpenSea Seaport 1.1',
	'0x00000000000001ad428e4906ae43d8f9852d0dd6': 'OpenSea Seaport 1.4',
	'0x00000000000000adc04c56bf30ac9d3c0aaf14dc': 'OpenSea Seaport 1.5',
	'0x00000000000000adc04c56bf30ac9d3c0aaf14dd': 'OpenSea Seaport 1.6',
	'0x000000000000ad05ccc4f10045630fb830b95127': 'Blur',
	'0x59728544b08ab483533076417fbbb2fd0b17ce3a': 'LooksRare Exchange',
	'0x74312363e45dcaba76c59ec49a7aa8a65a67eed3': 'X2Y2 Exchange',
	'0x2b2e8cda09bba9660dca5cb6233787738ad68329': 'Sudoswap',
};

export const MAX_UINT256 = '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
export const MAX_UINT160 = '0xffffffffffffffffffffffffffffffffffffffff';
