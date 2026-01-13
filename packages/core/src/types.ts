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
