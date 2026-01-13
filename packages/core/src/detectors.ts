import { OPCODES } from './opcode';
import type { DetectionResults, Instruction } from './types';

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

export function detectChainId(instructions: Instruction[]): {
	hasChainId: boolean;
	hasBranching: boolean;
} {
	let hasChainId = false;
	let hasBranching = false;

	for (let i = 0; i < instructions.length; i++) {
		const instruction = instructions[i];
		if (instruction.opcode === OPCODES['46']) {
			hasChainId = true;

			for (let j = i + 1; j < Math.min(i + 10, instructions.length); j++) {
				if (instructions[j].opcode === OPCODES['57']) {
					hasBranching = true;
					break;
				}
			}
		}
	}

	return { hasChainId, hasBranching };
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
	};
}
