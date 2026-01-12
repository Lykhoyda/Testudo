import { OPCODES } from './config/opcode';
import type { Instruction } from './types';

export function parseBytecode(bytecode: string): Instruction[] {
	// Clean hex prefix if present
	const cleanBytecode = bytecode.startsWith('0x') ? bytecode.slice(2) : bytecode;
	// Convert hex string to byte array
	const bytes = new Uint8Array(
		cleanBytecode.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || [],
	);

	let byteIndex = 0;
	const instructions: Instruction[] = [];

	while (byteIndex < bytes.length) {
		const byte = bytes[byteIndex] as number;
		const code = byte.toString(16).padStart(2, '0').toUpperCase();

		// PUSH bytes OP codes range from 0x60 (PUSH1) to 0x7f (PUSH32)
		if (byte >= 0x60 && byte <= 0x7f) {
			const pushSize = byte - 0x5f; // 0x5f is 95 in decimal
			const data = bytes.slice(byteIndex + 1, byteIndex + 1 + pushSize);
			instructions.push({
				opcode: `PUSH${pushSize}`,
				byteIndex,
				data,
				size: pushSize + 1,
			});
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
