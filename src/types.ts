import type { Address } from 'viem';

export interface Instruction {
	opcode: string;
	byteIndex: number;
	data?: Uint8Array;
	size?: number;
}

export interface ContractAnalysisResults {
	address: Address;
	risk: 'CRITICAL' | 'LOW' | 'UNKNOWN';
	detectedThreats: Array<string>;
	source?: string;
	error?: Error | string;
}
