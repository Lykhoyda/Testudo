import { COMPARISON_OPCODES, OPCODES } from './opcode';
import type { ChainIdDetectionResult, DetectionResults, Instruction } from './types';

export function detectAutoForwarder(instructions: Instruction[]): boolean {
	let hasSelfBalance = false;
	let hasCall = false;

	for (const instruction of instructions) {
		if (instruction.opcode === OPCODES['47']) {
			hasSelfBalance = true;
		}
		if (instruction.opcode === OPCODES.F1) {
			hasCall = true;
		}
	}

	return hasSelfBalance && hasCall;
}

export function detectUnlimitedApproval(instructions: Instruction[]): boolean {
	for (const instruction of instructions) {
		if (instruction.opcode === OPCODES['7F']) {
			if (instruction.data?.every((byte) => byte === 0xff)) {
				return true;
			}
		}
	}

	return false;
}

export function detectDelegateCall(instructions: Instruction[]): boolean {
	for (const instruction of instructions) {
		if (instruction.opcode === OPCODES.F4) {
			return true;
		}
	}

	return false;
}

export function detectSelfDestruct(instructions: Instruction[]): boolean {
	for (const instruction of instructions) {
		if (instruction.opcode === OPCODES.FF) {
			return true;
		}
	}
	return false;
}

export function detectCreate2(instructions: Instruction[]): boolean {
	for (const instruction of instructions) {
		if (instruction.opcode === OPCODES.F5) {
			return true;
		}
	}
	return false;
}

export function detectChainId(instructions: Instruction[]): ChainIdDetectionResult {
	let hasChainId = false;
	let hasBranching = false;
	let hasComparison = false;
	let isEip712Pattern = false;

	for (let i = 0; i < instructions.length; i++) {
		const instruction = instructions[i];
		if (instruction.opcode === OPCODES['46']) {
			hasChainId = true;

			const lookAheadLimit = Math.min(i + 10, instructions.length);
			for (let j = i + 1; j < lookAheadLimit; j++) {
				const nextOpcode = instructions[j].opcode;

				if (nextOpcode === OPCODES['57']) {
					hasBranching = true;
				}

				if (COMPARISON_OPCODES.includes(nextOpcode as (typeof COMPARISON_OPCODES)[number])) {
					hasComparison = true;
				}

				if (nextOpcode === OPCODES['20']) {
					isEip712Pattern = true;
				}
			}
		}
	}

	return { hasChainId, hasBranching, hasComparison, isEip712Pattern };
}

export function runAllDetectors(instructions: Instruction[]): DetectionResults {
	const chainIdResult = detectChainId(instructions);

	return {
		isDelegatedCall: detectDelegateCall(instructions),
		hasAutoForwarder: detectAutoForwarder(instructions),
		hasUnlimitedApprovals: detectUnlimitedApproval(instructions),
		hasSelfDestruct: detectSelfDestruct(instructions),
		hasCreate2: detectCreate2(instructions),
		hasChainId: chainIdResult.hasChainId,
		hasChainIdBranching: chainIdResult.hasBranching,
		hasChainIdComparison: chainIdResult.hasComparison,
		isEip712Pattern: chainIdResult.isEip712Pattern,
	};
}
