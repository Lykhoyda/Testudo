import { describe, expect, it, vi } from 'vitest';

vi.mock('../../src/db/index.js', () => ({
	db: {},
}));

import { calculateConfidence } from '../../src/sync/aggregator.js';

describe('aggregator', () => {
	describe('calculateConfidence', () => {
		it('returns 0.65 for 1 source', () => {
			expect(calculateConfidence(1)).toBe('0.65');
		});

		it('returns 0.80 for 2 sources', () => {
			expect(calculateConfidence(2)).toBe('0.80');
		});

		it('returns 0.95 for 3 sources', () => {
			expect(calculateConfidence(3)).toBe('0.95');
		});

		it('caps at 1.00 for 4+ sources', () => {
			expect(calculateConfidence(4)).toBe('1.00');
			expect(calculateConfidence(5)).toBe('1.00');
			expect(calculateConfidence(10)).toBe('1.00');
		});

		it('returns 0.50 for 0 sources', () => {
			expect(calculateConfidence(0)).toBe('0.50');
		});
	});
});
