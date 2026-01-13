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
}

export interface AnalysisResult {
	address: Address;
	risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
	threats: string[];
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
