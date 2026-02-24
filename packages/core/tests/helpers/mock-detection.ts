import type { DetectionResults, Warning } from '../../src';

export function createMockDetectionResults(
	overrides: Partial<DetectionResults> = {},
): DetectionResults {
	return {
		isDelegatedCall: false,
		hasCallcode: false,
		hasAutoForwarder: false,
		hasUnlimitedApprovals: false,
		hasSelfDestruct: false,
		hasCreate2: false,
		hasChainId: false,
		hasChainIdBranching: false,
		hasChainIdComparison: false,
		isEip712Pattern: false,
		tokenTransfer: {
			hasTokenTransfer: false,
			hasTokenApproval: false,
			hasBatchOperations: false,
			detectedSelectors: [],
			hasAuthorizationPattern: false,
			hasEcrecover: false,
			hasNonceTracking: false,
			appearsInFallback: false,
			hasHardcodedDestination: false,
			contextualRisk: 'LOW',
			riskReason: '',
		},
		proxy: {
			isProxy: false,
			hasImplementationSlot: false,
			hasAdminSlot: false,
			hasBeaconSlot: false,
		},
		hasTxOrigin: false,
		isEip7702Delegation: false,
		hasTimestampDependence: false,
		hasMulticall: false,
		hasExtcodesizeGuard: false,
		hasErc4337Pattern: false,
		hasCoinbaseDependence: false,
		hasExtcodecopy: false,
		hasBalanceDrain: false,
		hasReentrancyRisk: false,
		hasGasManipulation: false,
		hasExtcodehash: false,
		hasMinimalProxy: false,
		hasDiamondProxy: false,
		...overrides,
	};
}

export function createMockWarning(
	severity: Warning['severity'],
	type: Warning['type'] = 'AUTO_FORWARDER',
): Warning {
	return {
		type,
		severity,
		title: 'Test Warning',
		description: 'Test description',
	};
}
