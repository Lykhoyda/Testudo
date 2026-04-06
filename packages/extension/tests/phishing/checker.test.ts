import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { DomainApiResult } from '../../src/api-client';
import { createDomainChecker } from '../../src/phishing/checker';

function makeApiResult(isMalicious: boolean, domain = 'evil.com'): DomainApiResult {
	return {
		success: true,
		data: { isMalicious, domain },
	};
}

const apiUnavailable: DomainApiResult = {
	success: false,
	error: 'Timeout',
	errorCategory: 'timeout',
};

describe('createDomainChecker', () => {
	const bloom = { has: vi.fn<[string], boolean>() };
	const checkDomainApi = vi.fn<[string], Promise<DomainApiResult>>();
	const isKnownSafeDomain = vi.fn<[string], boolean>();
	const isOverridden = vi.fn<[string], boolean>();

	beforeEach(() => {
		vi.resetAllMocks();
		bloom.has.mockReturnValue(false);
		checkDomainApi.mockResolvedValue(apiUnavailable);
		isKnownSafeDomain.mockReturnValue(false);
		isOverridden.mockReturnValue(false);
	});

	function makeChecker() {
		return createDomainChecker({ bloom, checkDomainApi, isKnownSafeDomain, isOverridden });
	}

	it('returns allow for overridden domains', async () => {
		isOverridden.mockReturnValue(true);
		const result = await makeChecker().check('evil.com', 'evil.com');
		expect(result).toEqual({ action: 'allow', reason: 'overridden' });
		expect(checkDomainApi).not.toHaveBeenCalled();
	});

	it('returns allow for Safe Filter domains', async () => {
		isKnownSafeDomain.mockReturnValue(true);
		const result = await makeChecker().check('uniswap.org', 'uniswap.org');
		expect(result).toEqual({ action: 'allow', reason: 'safe-filter' });
		expect(checkDomainApi).not.toHaveBeenCalled();
	});

	it('returns hard-block when bloom matches and API confirms malicious', async () => {
		bloom.has.mockReturnValue(true);
		checkDomainApi.mockResolvedValue(makeApiResult(true));
		const result = await makeChecker().check('evil.com', 'evil.com');
		expect(result.action).toBe('hard-block');
		expect(result.reason).toBe('bloom-confirmed');
		expect(result.metadata).toBeDefined();
		expect(result.metadata?.isMalicious).toBe(true);
	});

	it('returns soft-allow when bloom matches but API says clean', async () => {
		bloom.has.mockReturnValue(true);
		checkDomainApi.mockResolvedValue(makeApiResult(false));
		const result = await makeChecker().check('evil.com', 'evil.com');
		expect(result.action).toBe('soft-allow');
		expect(result.reason).toBe('bloom-fp');
		expect(result.metadata).toBeDefined();
		expect(result.metadata?.isMalicious).toBe(false);
	});

	it('returns soft-block when bloom matches and API times out', async () => {
		bloom.has.mockReturnValue(true);
		checkDomainApi.mockResolvedValue(apiUnavailable);
		const result = await makeChecker().check('evil.com', 'evil.com');
		expect(result.action).toBe('soft-block');
		expect(result.reason).toBe('api-unavailable');
		expect(result.metadata).toBeUndefined();
	});

	it('checks both hostname and registrable against bloom', async () => {
		bloom.has.mockReturnValue(false);
		checkDomainApi.mockResolvedValue(makeApiResult(false, 'sub.evil.com'));
		await makeChecker().check('sub.evil.com', 'evil.com');
		expect(bloom.has).toHaveBeenCalledWith('sub.evil.com');
		expect(bloom.has).toHaveBeenCalledWith('evil.com');
	});

	it('triggers API zero-day check when not in bloom and not safe', async () => {
		bloom.has.mockReturnValue(false);
		checkDomainApi.mockResolvedValue(makeApiResult(true, 'newphish.com'));
		const result = await makeChecker().check('newphish.com', 'newphish.com');
		expect(checkDomainApi).toHaveBeenCalledWith('newphish.com');
		expect(result.action).toBe('hard-block');
		expect(result.reason).toBe('api-zero-day');
		expect(result.metadata?.isMalicious).toBe(true);
	});

	it('returns allow when not in bloom and API says clean', async () => {
		bloom.has.mockReturnValue(false);
		checkDomainApi.mockResolvedValue(makeApiResult(false, 'legit.com'));
		const result = await makeChecker().check('legit.com', 'legit.com');
		expect(result.action).toBe('allow');
		expect(result.reason).toBe('api-clean');
	});

	it('returns allow when not in bloom and API times out', async () => {
		bloom.has.mockReturnValue(false);
		checkDomainApi.mockResolvedValue(apiUnavailable);
		const result = await makeChecker().check('unknown.com', 'unknown.com');
		expect(result.action).toBe('allow');
		expect(result.reason).toBe('api-unavailable-no-bloom');
	});
});
