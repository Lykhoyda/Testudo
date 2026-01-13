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

export function runAllDetectors(instructions: Instruction[]): DetectionResults {
	return {
		isDelegatedCall: detectDelegateCall(instructions),
		hasAutoForwarder: detectAutoForwarder(instructions),
		hasUnlimitedApprovals: detectUnlimitedApproval(instructions),
		hasSelfDestruct: detectSelfDestruct(instructions),
	};
}
