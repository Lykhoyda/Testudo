import type { Address } from 'viem';

export type WarningType =
	| 'AUTO_FORWARDER'
	| 'DELEGATE_CALL'
	| 'SELF_DESTRUCT'
	| 'METAMORPHIC'
	| 'CREATE2'
	| 'UNLIMITED_APPROVAL'
	| 'CHAINID_BRANCHING'
	| 'CHAINID_COMPARISON'
	| 'CHAINID_READ'
	| 'TOKEN_DRAIN_FALLBACK'
	| 'TOKEN_HARDCODED_DEST'
	| 'TOKEN_NO_AUTH'
	| 'TOKEN_REPLAY_RISK'
	| 'TOKEN_APPROVAL_NO_AUTH'
	| 'TOKEN_PERMIT2_NO_AUTH'
	| 'TOKEN_WITH_AUTH'
	| 'EIP712_SAFE'
	| 'BLIND_SIGNATURE'
	| 'PHISHING_PATTERN'
	| 'TYPED_DATA_MALICIOUS_ADDRESS'
	| 'ETH_SIGN_DEPRECATED'
	| 'DEPLOYER_FRESH'
	| 'DEPLOYER_LOW_NONCE'
	| 'DEPLOYER_NEW_CONTRACT'
	| 'PROXY_PATTERN'
	| 'TX_ORIGIN_PHISHING'
	| 'EIP7702_DELEGATION'
	| 'TIMESTAMP_DEPENDENCE'
	| 'MULTICALL_CAPABILITY'
	| 'EXTCODESIZE_GUARD'
	| 'ERC4337_PATTERN'
	| 'COINBASE_DEPENDENCE'
	| 'MINIMAL_PROXY'
	| 'DIAMOND_PROXY'
	| 'CALLCODE'
	| 'EXTCODECOPY_USAGE'
	| 'BALANCE_DRAIN'
	| 'REENTRANCY_RISK'
	| 'GAS_MANIPULATION'
	| 'EXTCODEHASH_CHECK'
	| 'EIP7702_REPLAY_RISK';

export type WarningSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface Warning {
	type: WarningType;
	severity: WarningSeverity;
	title: string;
	description: string;
	technical?: string;
}

export interface Instruction {
	opcode: string;
	byteIndex: number;
	data?: Uint8Array;
	size?: number;
}

export interface ProxyDetectionResult {
	isProxy: boolean;
	hasImplementationSlot: boolean;
	hasAdminSlot: boolean;
	hasBeaconSlot: boolean;
}

export interface DetectionResults {
	isDelegatedCall: boolean;
	hasCallcode: boolean;
	hasAutoForwarder: boolean;
	hasUnlimitedApprovals: boolean;
	hasSelfDestruct: boolean;
	hasCreate2: boolean;
	hasChainId: boolean;
	hasChainIdBranching: boolean;
	hasChainIdComparison: boolean;
	isEip712Pattern: boolean;
	tokenTransfer: TokenTransferAnalysis;
	proxy: ProxyDetectionResult;
	hasTxOrigin: boolean;
	isEip7702Delegation: boolean;
	hasTimestampDependence: boolean;
	hasMulticall: boolean;
	hasExtcodesizeGuard: boolean;
	hasErc4337Pattern: boolean;
	hasCoinbaseDependence: boolean;
	hasExtcodecopy: boolean;
	hasBalanceDrain: boolean;
	hasReentrancyRisk: boolean;
	hasGasManipulation: boolean;
	hasExtcodehash: boolean;
	hasMinimalProxy: boolean;
	hasDiamondProxy: boolean;
}

export interface ChainIdDetectionResult {
	hasChainId: boolean;
	hasBranching: boolean;
	hasComparison: boolean;
	isEip712Pattern: boolean;
}

export interface DeployerInfo {
	deployerAddress: string;
	deployerNonce: number;
	contractCreationTimestamp: number;
	currentTimestamp: number;
}

export interface DeployerRiskAssessment {
	risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
	contractAge: number;
	deployerNonce: number;
	reasons: string[];
}

export interface AnalysisResult {
	address: Address;
	risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
	threats: string[];
	warnings?: Warning[];
	blocked: boolean;
	cached?: boolean;
	source?: string;
	error?: string;
	deployerRisk?: DeployerRiskAssessment;
	implementationAddress?: Address;
	implementationAnalysis?: AnalysisResult;
}

export interface KnownMaliciousContract {
	type: string;
	source: string;
	stolen: string;
	description: string;
}

export interface TokenSelector {
	selector: string;
	name: string;
	standard: 'ERC20' | 'ERC721' | 'ERC1155' | 'Permit2';
	type: 'transfer' | 'approval' | 'batch' | 'permit';
}

export interface TokenTransferAnalysis {
	hasTokenTransfer: boolean;
	hasTokenApproval: boolean;
	hasBatchOperations: boolean;
	detectedSelectors: TokenSelector[];
	hasAuthorizationPattern: boolean;
	hasEcrecover: boolean;
	hasNonceTracking: boolean;
	appearsInFallback: boolean;
	hasHardcodedDestination: boolean;
	contextualRisk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
	riskReason: string;
}
