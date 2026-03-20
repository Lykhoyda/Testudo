import type { Warning } from '@testudo/core';

export type { ScanRecord, Settings, WhitelistEntry } from '../storage';

export interface TypedDataDomain {
	name?: string;
	version?: string;
	chainId?: number;
	verifyingContract?: string;
}

export interface TypedDataMessage {
	types: {
		Authorization?: unknown;
		[key: string]: unknown;
	};
	primaryType: string;
	domain: TypedDataDomain;
	message: Record<string, unknown>;
}

export interface PermitInfo {
	type:
		| 'permit'
		| 'permit2-single'
		| 'permit2-batch'
		| 'permit2-transfer'
		| 'permit2-witness-transfer'
		| 'dai-permit';
	spender: string;
	value?: string;
	deadline?: string;
	token?: string;
	tokenName?: string;
}

export interface ApprovalInfo {
	type: 'approve' | 'increaseAllowance' | 'decreaseAllowance';
	spender: string;
	amount: string;
	tokenAddress: string;
}

export interface NftApprovalInfo {
	type: 'setApprovalForAll';
	operator: string;
	approved: boolean;
	collectionAddress: string;
	collectionName?: string;
}

export interface BlindSignatureInfo {
	type: 'personal_sign' | 'eth_sign';
	message: string;
	decodedMessage: string;
	messagePreview: string;
	signer: string;
	isHex: boolean;
}

export interface ExtractedAddress {
	address: string;
	fieldPath: string;
}

export interface TypedDataScanInfo {
	maliciousAddresses: ExtractedAddress[];
	primaryType: string;
	domainName?: string;
}

export interface AnalysisResult {
	risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
	threats: string[];
	warnings?: Warning[];
	address: string;
	blocked: boolean;
	whitelisted?: boolean;
	deployerRisk?: {
		risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
		contractAge: number;
		deployerNonce: number;
		reasons: string[];
	};
}

export interface RecentScan {
	address: string;
	risk: string;
	timestamp: number;
}

export type WarningContext =
	| 'delegation'
	| 'transaction'
	| 'permit'
	| 'approval'
	| 'nft-approval'
	| 'blind-signature'
	| 'typed-data-scan'
	| 'eth-sign-danger';

export interface TokenInfo {
	address: string;
	symbol: string | null;
	decimals: number | null;
	name: string | null;
	isVerified?: boolean;
}

export interface IntentDetail {
	label: string;
	value: string;
	emphasis?: 'danger' | 'warning' | 'info';
	mono?: boolean;
}

export interface HumanReadableIntent {
	headline: string;
	action: string;
	details: IntentDetail[];
	chainName?: string;
}

export interface WarningOptions {
	analysis: AnalysisResult;
	context?: WarningContext;
	permitInfo?: PermitInfo;
	approvalInfo?: ApprovalInfo;
	nftApprovalInfo?: NftApprovalInfo;
	blindSignatureInfo?: BlindSignatureInfo;
	typedDataScanInfo?: TypedDataScanInfo;
	chainId?: number | string;
	intent?: HumanReadableIntent;
}
