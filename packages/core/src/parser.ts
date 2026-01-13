import { OPCODES } from './opcode';
import type { Instruction } from './types';

export function parseBytecode(bytecode: string): Instruction[] {
	const cleanBytecode = bytecode.startsWith('0x') ? bytecode.slice(2) : bytecode;
	const bytes = new Uint8Array(
		cleanBytecode.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || [],
	);

	let byteIndex = 0;
	const instructions: Instruction[] = [];

	while (byteIndex < bytes.length) {
		const byte = bytes[byteIndex] as number;
		const code = byte.toString(16).padStart(2, '0').toUpperCase();

		if (byte >= 0x60 && byte <= 0x7f) {
			const pushSize = byte - 0x5f;
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
