import type { Address } from 'viem';

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
	warnings?: string[];
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
