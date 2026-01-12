import { OPCODES } from './config/opcode';
import type { Instruction } from './types';

export function detectAutoForwarder(instructions: Instruction[]): boolean {
	let hasSelfBalance = false;
	let hasCall = false;

	instructions.forEach((instruction: Instruction) => {
		if (instruction.opcode === OPCODES['47']) {
			hasSelfBalance = true;
		}

		if (instruction.opcode === OPCODES.F1) {
			hasCall = true;
		}
	});

	return hasSelfBalance && hasCall;
}

export function detectUnlimitedApproval(instructions: Instruction[]): boolean {
	let hasUnlimitedSpendingData = false;

	for (const instruction of instructions) {
		if (instruction.opcode === OPCODES['7F']) {
			if (instruction.data?.every((byte) => byte === 0xff)) {
				hasUnlimitedSpendingData = true;
			}
		}
	}

	return hasUnlimitedSpendingData;
}

export function detectDelegateCall(instructions: Instruction[]): boolean {
	let hasDelegateCall = false;

	for (const instruction of instructions) {
		if (instruction.opcode === OPCODES.F4) {
			hasDelegateCall = true;
		}
	}

	return hasDelegateCall;
}

export function detectSelfDestruct(instructions: Instruction[]): boolean {
	for (const instruction of instructions) {
		if (instruction.opcode === OPCODES.FF) {
			return true;
		}
	}
	return false;
}

export function runAllDetectors(instructions: Instruction[]) {
	const isDelegatedCall = detectDelegateCall(instructions);
	const hasAutoForwarder = detectAutoForwarder(instructions);
	const hasUnlimitedApprovals = detectUnlimitedApproval(instructions);
	const hasSelfDestruct = detectSelfDestruct(instructions);

	return {
		isDelegatedCall,
		hasAutoForwarder,
		hasUnlimitedApprovals,
		hasSelfDestruct,
	};
}
