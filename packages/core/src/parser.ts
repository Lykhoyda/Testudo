import { OPCODES } from './opcode';
import type { Instruction } from './types';

export class InvalidBytecodeError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'InvalidBytecodeError';
	}
}

const HEX_CHARS = /^[0-9a-fA-F]*$/;

export function parseBytecode(bytecode: string): Instruction[] {
	if (typeof bytecode !== 'string') {
		throw new InvalidBytecodeError(`Bytecode must be a string, got ${typeof bytecode}`);
	}

	const cleanBytecode =
		bytecode.startsWith('0x') || bytecode.startsWith('0X') ? bytecode.slice(2) : bytecode;

	if (!HEX_CHARS.test(cleanBytecode)) {
		const preview = cleanBytecode.length > 20 ? `${cleanBytecode.slice(0, 20)}…` : cleanBytecode;
		throw new InvalidBytecodeError(`Bytecode contains non-hex characters: "${preview}"`);
	}
	if (cleanBytecode.length % 2 !== 0) {
		throw new InvalidBytecodeError(
			`Bytecode has odd length (${cleanBytecode.length} chars); valid hex must be even-length`,
		);
	}

	const bytes = new Uint8Array(cleanBytecode.length / 2);
	for (let i = 0; i < cleanBytecode.length; i += 2) {
		bytes[i / 2] = parseInt(cleanBytecode.substring(i, i + 2), 16);
	}

	let byteIndex = 0;
	const instructions: Instruction[] = [];

	while (byteIndex < bytes.length) {
		const byte = bytes[byteIndex] as number;
		const code = byte.toString(16).padStart(2, '0').toUpperCase();

		if (byte >= 0x60 && byte <= 0x7f) {
			const pushSize = byte - 0x5f;
			const data = bytes.slice(byteIndex + 1, byteIndex + 1 + pushSize);
			const instruction: Instruction = {
				opcode: `PUSH${pushSize}`,
				byteIndex,
				data,
				size: pushSize + 1,
			};
			if (data.length < pushSize) {
				instruction.truncated = true;
			}
			instructions.push(instruction);
			byteIndex += pushSize + 1;
		} else {
			const opcode = OPCODES[code as keyof typeof OPCODES] || code;
			instructions.push({
				opcode,
				byteIndex,
				size: 1,
			});
			byteIndex += 1;
		}
	}

	return instructions;
}
