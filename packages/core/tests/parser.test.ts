import { describe, expect, it } from 'vitest';
import { InvalidBytecodeError, parseBytecode } from '../src/parser';

describe('parseBytecode', () => {
	it('should parse empty bytecode', () => {
		const result = parseBytecode('0x');
		expect(result).toEqual([]);
	});

	it('should handle bytecode without 0x prefix', () => {
		const result = parseBytecode('60');
		expect(result).toHaveLength(1);
	});

	it('should parse PUSH1 instruction', () => {
		const result = parseBytecode('0x6001');
		expect(result).toHaveLength(1);
		expect(result[0]).toMatchObject({
			opcode: 'PUSH1',
			byteIndex: 0,
			size: 2,
		});
		expect(result[0]?.data).toEqual(new Uint8Array([0x01]));
	});

	it('should parse PUSH32 instruction with max value', () => {
		const maxBytes = 'ff'.repeat(32);
		const result = parseBytecode(`0x7f${maxBytes}`);
		expect(result).toHaveLength(1);
		expect(result[0]).toMatchObject({
			opcode: 'PUSH32',
			byteIndex: 0,
			size: 33,
		});
		expect(result[0]?.data).toEqual(new Uint8Array(32).fill(0xff));
	});

	it('should parse multiple instructions', () => {
		const result = parseBytecode('0x6001600247');
		expect(result).toHaveLength(3);
		expect(result[0]?.opcode).toBe('PUSH1');
		expect(result[1]?.opcode).toBe('PUSH1');
		expect(result[2]?.opcode).toBe('SELFBALANCE');
	});

	it('should parse CALL opcode', () => {
		const result = parseBytecode('0xf1');
		expect(result).toHaveLength(1);
		expect(result[0]?.opcode).toBe('CALL');
	});

	it('should parse DELEGATECALL opcode', () => {
		const result = parseBytecode('0xf4');
		expect(result).toHaveLength(1);
		expect(result[0]?.opcode).toBe('DELEGATECALL');
	});

	it('should parse SELFDESTRUCT opcode', () => {
		const result = parseBytecode('0xff');
		expect(result).toHaveLength(1);
		expect(result[0]?.opcode).toBe('SELFDESTRUCT');
	});

	it('should handle unknown opcodes', () => {
		const result = parseBytecode('0x0c');
		expect(result).toHaveLength(1);
		expect(result[0]?.opcode).toBe('0C');
	});

	it('should handle truncated PUSH instruction at end of bytecode', () => {
		// PUSH2 (0x61) expects 2 bytes but only 1 is available
		const result = parseBytecode('0x61ff');
		expect(result).toHaveLength(1);
		expect(result[0]?.opcode).toBe('PUSH2');
		expect(result[0]?.data).toHaveLength(1);
	});

	it('should handle PUSH1 with zero bytes remaining', () => {
		// PUSH1 (0x60) at end with no data byte
		const result = parseBytecode('0x60');
		expect(result).toHaveLength(1);
		expect(result[0]?.opcode).toBe('PUSH1');
		expect(result[0]?.data).toHaveLength(0);
	});

	it('should parse PUSH0 (EIP-3855) correctly', () => {
		const result = parseBytecode('0x5f');
		expect(result).toHaveLength(1);
		expect(result[0]?.opcode).toBe('PUSH0');
		expect(result[0]?.data).toBeUndefined();
		expect(result[0]?.size).toBe(1);
	});

	it('should throw InvalidBytecodeError on odd-length hex string', () => {
		// Previously silently parsed '0x6' as a single byte via regex greed; now rejected.
		expect(() => parseBytecode('0x6')).toThrow(InvalidBytecodeError);
		expect(() => parseBytecode('0x6')).toThrow(/odd length/i);
	});

	it('should throw InvalidBytecodeError on non-hex characters', () => {
		expect(() => parseBytecode('0xZZ')).toThrow(InvalidBytecodeError);
		expect(() => parseBytecode('0x60GG')).toThrow(InvalidBytecodeError);
		expect(() => parseBytecode('not-hex-at-all')).toThrow(InvalidBytecodeError);
	});

	it('should accept uppercase 0X prefix', () => {
		const result = parseBytecode('0X60FF');
		expect(result).toHaveLength(1);
		expect(result[0]?.opcode).toBe('PUSH1');
		expect(result[0]?.data).toEqual(new Uint8Array([0xff]));
	});

	it('should mark truncated PUSH as truncated', () => {
		// PUSH2 with only 1 byte of data
		const result = parseBytecode('0x61ff');
		expect(result).toHaveLength(1);
		expect(result[0]?.opcode).toBe('PUSH2');
		expect(result[0]?.truncated).toBe(true);
		expect(result[0]?.data?.length).toBe(1);
	});

	it('should mark PUSH with zero data bytes as truncated', () => {
		// PUSH1 at EOF with no data byte at all
		const result = parseBytecode('0x60');
		expect(result).toHaveLength(1);
		expect(result[0]?.opcode).toBe('PUSH1');
		expect(result[0]?.truncated).toBe(true);
	});

	it('should not mark complete PUSH as truncated', () => {
		const result = parseBytecode('0x6001');
		expect(result).toHaveLength(1);
		expect(result[0]?.opcode).toBe('PUSH1');
		expect(result[0]?.truncated).toBeUndefined();
	});

	it('should throw on non-string input', () => {
		expect(() => parseBytecode(null as unknown as string)).toThrow(InvalidBytecodeError);
		expect(() => parseBytecode(undefined as unknown as string)).toThrow(InvalidBytecodeError);
		expect(() => parseBytecode(123 as unknown as string)).toThrow(InvalidBytecodeError);
	});

	it('should parse consecutive PUSH instructions consuming all bytes', () => {
		// PUSH1 x5: each consumes 2 bytes
		const result = parseBytecode('0x60016002600360046005');
		expect(result).toHaveLength(5);
		for (const instr of result) {
			expect(instr.opcode).toBe('PUSH1');
			expect(instr.data).toHaveLength(1);
		}
	});

	it('should track byte indices correctly across PUSH sizes', () => {
		// PUSH1(0x60, 1 data) + PUSH2(0x61, 2 data) + STOP
		const result = parseBytecode('0x60ff61aabb00');
		expect(result).toHaveLength(3);
		expect(result[0]?.byteIndex).toBe(0);
		expect(result[0]?.opcode).toBe('PUSH1');
		expect(result[1]?.byteIndex).toBe(2);
		expect(result[1]?.opcode).toBe('PUSH2');
		expect(result[1]?.data).toEqual(new Uint8Array([0xaa, 0xbb]));
		expect(result[2]?.byteIndex).toBe(5);
		expect(result[2]?.opcode).toBe('STOP');
	});

	it('should parse CALLCODE opcode', () => {
		const result = parseBytecode('0xf2');
		expect(result).toHaveLength(1);
		expect(result[0]?.opcode).toBe('CALLCODE');
	});

	it('should parse CREATE2 opcode', () => {
		const result = parseBytecode('0xf5');
		expect(result).toHaveLength(1);
		expect(result[0]?.opcode).toBe('CREATE2');
	});

	it('should parse STATICCALL opcode', () => {
		const result = parseBytecode('0xfa');
		expect(result).toHaveLength(1);
		expect(result[0]?.opcode).toBe('STATICCALL');
	});
});
