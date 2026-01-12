import { describe, it, expect } from 'vitest';
import {parseBytecode} from "../src/parser";

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
		const result = parseBytecode('0x00');
		expect(result).toHaveLength(1);
		expect(result[0]?.opcode).toBe('00');
	});
});
