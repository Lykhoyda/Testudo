import type { Address } from 'viem';

export type WarningType =
	| 'AUTO_FORWARDER'
	| 'DELEGATE_CALL'
	| 'SELF_DESTRUCT'
	| 'METAMORPHIC'
	| 'CREATE2'
	| 'UNLIMITED_APPROVAL'
	| 'CHAINID_BRANCHING'
	| 'CHAINID_COMPARISON'
	| 'CHAINID_READ'
	| 'TOKEN_DRAIN_FALLBACK'
	| 'TOKEN_HARDCODED_DEST'
	| 'TOKEN_NO_AUTH'
	| 'TOKEN_REPLAY_RISK'
	| 'TOKEN_APPROVAL_NO_AUTH'
	| 'TOKEN_WITH_AUTH'
	| 'EIP712_SAFE';

export type WarningSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface Warning {
	type: WarningType;
	severity: WarningSeverity;
	title: string;
	description: string;
	technical?: string;
}

export interface Instruction {
	opcode: string;
	byteIndex: number;
	data?: Uint8Array;
	size?: number;
}

export interface DetectionResults {
	isDelegatedCall: boolean;
	hasAutoForwarder: boolean;
	hasUnlimitedApprovals: boolean;
	hasSelfDestruct: boolean;
	hasCreate2: boolean;
	hasChainId: boolean;
	hasChainIdBranching: boolean;
	hasChainIdComparison: boolean;
	isEip712Pattern: boolean;
	tokenTransfer: TokenTransferAnalysis;
}

export interface ChainIdDetectionResult {
	hasChainId: boolean;
	hasBranching: boolean;
	hasComparison: boolean;
	isEip712Pattern: boolean;
}

export interface AnalysisResult {
	address: Address;
	risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
	threats: string[];
	warnings?: Warning[];
	blocked: boolean;
	cached?: boolean;
	source?: string;
	error?: string;
}

export interface KnownMaliciousContract {
	type: string;
	source: string;
	stolen: string;
	description: string;
}

export interface TokenSelector {
	selector: string;
	name: string;
	standard: 'ERC20' | 'ERC721' | 'ERC1155';
	type: 'transfer' | 'approval' | 'batch';
}

export interface TokenTransferAnalysis {
	hasTokenTransfer: boolean;
	hasTokenApproval: boolean;
	hasBatchOperations: boolean;
	detectedSelectors: TokenSelector[];
	hasAuthorizationPattern: boolean;
	hasEcrecover: boolean;
	hasNonceTracking: boolean;
	appearsInFallback: boolean;
	hasHardcodedDestination: boolean;
	contextualRisk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
	riskReason: string;
}
