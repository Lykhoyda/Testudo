import { describe, expect, it } from 'vitest';
import {
	buildApprovalIntent,
	buildBlindSignatureIntent,
	buildDelegationIntent,
	buildEthSignIntent,
	buildNftApprovalIntent,
	buildPermitIntent,
	buildTransactionIntent,
	buildTypedDataScanIntent,
} from '../../src/decoder/intent-builder';
import { MAX_UINT256 } from '../../src/utils/constants';
import type {
	ApprovalInfo,
	BlindSignatureInfo,
	NftApprovalInfo,
	PermitInfo,
	TokenInfo,
	TypedDataScanInfo,
} from '../../src/utils/types';

const USDC_TOKEN: TokenInfo = {
	address: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
	symbol: 'USDC',
	decimals: 6,
	name: 'USD Coin',
};

const SPENDER = '0x1234567890abcdef1234567890abcdef12345678';

describe('buildPermitIntent', () => {
	it('builds intent for unlimited permit', () => {
		const info: PermitInfo = {
			type: 'permit',
			spender: SPENDER,
			value: MAX_UINT256,
			deadline: MAX_UINT256,
			token: USDC_TOKEN.address,
			tokenName: 'USD Coin',
		};

		const intent = buildPermitIntent(info, USDC_TOKEN);
		expect(intent.headline).toContain('Unlimited');
		expect(intent.headline).toContain('USDC');
		expect(intent.action).toContain('Unlimited USDC');
		expect(intent.details.find((d) => d.label === 'Spender')).toBeTruthy();
		expect(intent.details.find((d) => d.label === 'Expires')?.value).toBe('Never');
	});

	it('builds intent for limited permit with token info', () => {
		const info: PermitInfo = {
			type: 'permit',
			spender: SPENDER,
			value: '1000000',
			token: USDC_TOKEN.address,
		};

		const intent = buildPermitIntent(info, USDC_TOKEN);
		expect(intent.action).toContain('1 USDC');
	});

	it('builds intent without token info', () => {
		const info: PermitInfo = {
			type: 'permit',
			spender: SPENDER,
			value: '1000000',
		};

		const intent = buildPermitIntent(info);
		expect(intent.headline).toContain('Token');
		expect(intent.action).toContain(info.value!);
	});

	it('handles batch permit', () => {
		const info: PermitInfo = {
			type: 'permit2-batch',
			spender: SPENDER,
			value: 'batch',
		};

		const intent = buildPermitIntent(info);
		expect(intent.action).toContain('Multiple tokens');
	});

	it('marks spender with danger emphasis', () => {
		const info: PermitInfo = { type: 'permit', spender: SPENDER, value: '100' };
		const intent = buildPermitIntent(info);
		const spenderDetail = intent.details.find((d) => d.label === 'Spender');
		expect(spenderDetail?.emphasis).toBe('danger');
		expect(spenderDetail?.mono).toBe(true);
	});

	it('uses tokenName when no tokenInfo provided', () => {
		const info: PermitInfo = {
			type: 'permit',
			spender: SPENDER,
			value: MAX_UINT256,
			tokenName: 'MyToken',
		};

		const intent = buildPermitIntent(info);
		expect(intent.action).toContain('Unlimited MyToken');
	});
});

describe('buildApprovalIntent', () => {
	it('builds intent for unlimited approval', () => {
		const info: ApprovalInfo = {
			type: 'approve',
			spender: SPENDER,
			amount: MAX_UINT256,
			tokenAddress: USDC_TOKEN.address,
		};

		const intent = buildApprovalIntent(info, USDC_TOKEN);
		expect(intent.headline).toContain('Unlimited');
		expect(intent.headline).toContain('USDC');
		expect(intent.action).toContain('Unlimited USDC');
	});

	it('builds intent for limited approval', () => {
		const info: ApprovalInfo = {
			type: 'approve',
			spender: SPENDER,
			amount: '1000000',
			tokenAddress: USDC_TOKEN.address,
		};

		const intent = buildApprovalIntent(info, USDC_TOKEN);
		expect(intent.action).toContain('1 USDC');
	});

	it('includes operation type', () => {
		const info: ApprovalInfo = {
			type: 'increaseAllowance',
			spender: SPENDER,
			amount: '100',
			tokenAddress: '0x1234',
		};

		const intent = buildApprovalIntent(info);
		const opDetail = intent.details.find((d) => d.label === 'Operation');
		expect(opDetail?.value).toBe('increaseAllowance()');
	});

	it('includes token contract address', () => {
		const info: ApprovalInfo = {
			type: 'approve',
			spender: SPENDER,
			amount: '100',
			tokenAddress: USDC_TOKEN.address,
		};

		const intent = buildApprovalIntent(info);
		const tokenDetail = intent.details.find((d) => d.label === 'Token Contract');
		expect(tokenDetail).toBeTruthy();
		expect(tokenDetail?.mono).toBe(true);
	});

	it('handles decreaseAllowance', () => {
		const info: ApprovalInfo = {
			type: 'decreaseAllowance',
			spender: SPENDER,
			amount: '100',
			tokenAddress: '0x1234',
		};

		const intent = buildApprovalIntent(info);
		const opDetail = intent.details.find((d) => d.label === 'Operation');
		expect(opDetail?.value).toBe('decreaseAllowance()');
	});
});

describe('buildNftApprovalIntent', () => {
	it('builds intent with collection name', () => {
		const info: NftApprovalInfo = {
			type: 'setApprovalForAll',
			operator: SPENDER,
			approved: true,
			collectionAddress: '0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d',
			collectionName: 'Bored Ape Yacht Club',
		};

		const intent = buildNftApprovalIntent(info);
		expect(intent.headline).toBe('NFT Collection Approval');
		expect(intent.action).toContain('Bored Ape Yacht Club');
		expect(intent.action).toContain('full access');
	});

	it('falls back to truncated address when no collection name', () => {
		const info: NftApprovalInfo = {
			type: 'setApprovalForAll',
			operator: SPENDER,
			approved: true,
			collectionAddress: '0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d',
		};

		const intent = buildNftApprovalIntent(info);
		expect(intent.action).toContain('0xbc4ca0ed');
	});

	it('marks access level as danger', () => {
		const info: NftApprovalInfo = {
			type: 'setApprovalForAll',
			operator: SPENDER,
			approved: true,
			collectionAddress: '0x1234',
		};

		const intent = buildNftApprovalIntent(info);
		const accessDetail = intent.details.find((d) => d.label === 'Access Level');
		expect(accessDetail?.emphasis).toBe('danger');
	});
});

describe('buildDelegationIntent', () => {
	it('builds basic delegation intent', () => {
		const intent = buildDelegationIntent(SPENDER);
		expect(intent.headline).toBe('Wallet Delegation Request');
		expect(intent.action).toContain('Delegate wallet control');
	});

	it('includes chain name when provided', () => {
		const intent = buildDelegationIntent(SPENDER, 1);
		expect(intent.action).toContain('on Ethereum');
		expect(intent.chainName).toBe('Ethereum');
	});

	it('works without chainId', () => {
		const intent = buildDelegationIntent(SPENDER);
		expect(intent.chainName).toBeUndefined();
	});

	it('handles string chainId', () => {
		const intent = buildDelegationIntent(SPENDER, '137');
		expect(intent.chainName).toBe('Polygon');
	});

	it('marks delegate as danger with mono', () => {
		const intent = buildDelegationIntent(SPENDER);
		const delegate = intent.details.find((d) => d.label === 'Delegate');
		expect(delegate?.emphasis).toBe('danger');
		expect(delegate?.mono).toBe(true);
	});
});

describe('buildTransactionIntent', () => {
	it('builds transaction intent', () => {
		const intent = buildTransactionIntent(SPENDER);
		expect(intent.headline).toBe('Suspicious Transaction');
		expect(intent.action).toContain('Send funds');
	});

	it('marks recipient as danger', () => {
		const intent = buildTransactionIntent(SPENDER);
		const recipient = intent.details.find((d) => d.label === 'Recipient');
		expect(recipient?.emphasis).toBe('danger');
	});
});

describe('buildBlindSignatureIntent', () => {
	it('builds blind signature intent', () => {
		const info: BlindSignatureInfo = {
			type: 'personal_sign',
			message: '0xdeadbeef',
			decodedMessage: 'Hello World',
			messagePreview: 'Hello World',
			signer: SPENDER,
			isHex: false,
		};

		const intent = buildBlindSignatureIntent(info);
		expect(intent.headline).toBe('Blind Signature Request');
		expect(intent.action).toContain('personal_sign');
	});

	it('includes hex indicator for hex messages', () => {
		const info: BlindSignatureInfo = {
			type: 'personal_sign',
			message: '0xdeadbeef',
			decodedMessage: '0xdeadbeef',
			messagePreview: '0xdeadbeef',
			signer: SPENDER,
			isHex: true,
		};

		const intent = buildBlindSignatureIntent(info);
		const msgDetail = intent.details.find((d) => d.label.includes('hex'));
		expect(msgDetail).toBeTruthy();
	});

	it('marks message as mono', () => {
		const info: BlindSignatureInfo = {
			type: 'personal_sign',
			message: 'test',
			decodedMessage: 'test',
			messagePreview: 'test',
			signer: SPENDER,
			isHex: false,
		};

		const intent = buildBlindSignatureIntent(info);
		const msgDetail = intent.details.find((d) => d.label.includes('Message'));
		expect(msgDetail?.mono).toBe(true);
	});
});

describe('buildTypedDataScanIntent', () => {
	it('builds typed data scan intent with malicious addresses', () => {
		const info: TypedDataScanInfo = {
			maliciousAddresses: [
				{ address: SPENDER, fieldPath: 'message.to' },
			],
			primaryType: 'Transfer',
			domainName: 'FakeDAO',
		};

		const intent = buildTypedDataScanIntent(info);
		expect(intent.headline).toBe('Malicious Address in Signed Data');
		expect(intent.action).toContain('Transfer');
		expect(intent.details.find((d) => d.label === 'Domain')?.value).toBe('FakeDAO');
	});

	it('limits displayed addresses to 3', () => {
		const info: TypedDataScanInfo = {
			maliciousAddresses: [
				{ address: SPENDER, fieldPath: 'a' },
				{ address: SPENDER, fieldPath: 'b' },
				{ address: SPENDER, fieldPath: 'c' },
				{ address: SPENDER, fieldPath: 'd' },
			],
			primaryType: 'Batch',
		};

		const intent = buildTypedDataScanIntent(info);
		const addrDetails = intent.details.filter((d) => d.label.startsWith('Found in'));
		expect(addrDetails.length).toBe(3);
	});

	it('omits domain when not provided', () => {
		const info: TypedDataScanInfo = {
			maliciousAddresses: [{ address: SPENDER, fieldPath: 'msg.to' }],
			primaryType: 'Swap',
		};

		const intent = buildTypedDataScanIntent(info);
		expect(intent.details.find((d) => d.label === 'Domain')).toBeUndefined();
	});
});

describe('buildEthSignIntent', () => {
	it('builds eth_sign intent', () => {
		const info: BlindSignatureInfo = {
			type: 'eth_sign',
			message: '0xdeadbeef',
			decodedMessage: '0xdeadbeef',
			messagePreview: '0xdeadbeef...',
			signer: SPENDER,
			isHex: true,
		};

		const intent = buildEthSignIntent(info);
		expect(intent.headline).toContain('eth_sign');
		expect(intent.action).toContain('deprecated');
	});

	it('marks method as danger', () => {
		const info: BlindSignatureInfo = {
			type: 'eth_sign',
			message: '0xabcd',
			decodedMessage: '0xabcd',
			messagePreview: '0xabcd',
			signer: SPENDER,
			isHex: true,
		};

		const intent = buildEthSignIntent(info);
		const methodDetail = intent.details.find((d) => d.label === 'Method');
		expect(methodDetail?.emphasis).toBe('danger');
	});
});
