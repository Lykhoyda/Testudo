import type { DomainApiResult, DomainThreatResponse } from '../api-client';

export type BlockAction = 'hard-block' | 'soft-block' | 'soft-allow' | 'allow';

export interface CheckDomainResult {
	action: BlockAction;
	reason: string;
	metadata?: DomainThreatResponse;
}

interface BloomLike {
	has(domain: string): boolean;
}

interface DomainCheckerDeps {
	bloom: BloomLike;
	checkDomainApi: (domain: string) => Promise<DomainApiResult>;
	isKnownSafeDomain: (domain: string) => boolean;
	isOverridden: (domain: string) => boolean;
}

interface DomainChecker {
	check(hostname: string, registrable: string): Promise<CheckDomainResult>;
}

export function createDomainChecker(deps: DomainCheckerDeps): DomainChecker {
	const { bloom, checkDomainApi, isKnownSafeDomain, isOverridden } = deps;

	return {
		async check(hostname: string, registrable: string): Promise<CheckDomainResult> {
			if (isOverridden(hostname)) {
				return { action: 'allow', reason: 'overridden' };
			}

			if (isKnownSafeDomain(hostname)) {
				return { action: 'allow', reason: 'safe-filter' };
			}

			const inBloom = bloom.has(hostname) || bloom.has(registrable);

			const apiResult = await checkDomainApi(hostname);

			if (inBloom) {
				if (apiResult.success && apiResult.data != null) {
					if (apiResult.data.isMalicious) {
						return { action: 'hard-block', reason: 'bloom-confirmed', metadata: apiResult.data };
					}
					return { action: 'soft-allow', reason: 'bloom-fp', metadata: apiResult.data };
				}
				return { action: 'soft-block', reason: 'api-unavailable' };
			}

			if (apiResult.success && apiResult.data != null) {
				if (apiResult.data.isMalicious) {
					return { action: 'hard-block', reason: 'api-zero-day', metadata: apiResult.data };
				}
				return { action: 'allow', reason: 'api-clean' };
			}

			return { action: 'allow', reason: 'api-unavailable-no-bloom' };
		},
	};
}
