import type { Address } from 'viem';
import { runAllDetectors } from './detectors';
import { fetchBytecode } from './fetcher';
import { checkKnownMalicious, isKnownSafe } from './malicious-db';
import { parseBytecode } from './parser';
import type { AnalysisResult } from './types';

export interface AnalyzeOptions {
	rpcUrl?: string;
}

export async function analyzeContract(
	address: Address,
	options?: AnalyzeOptions,
): Promise<AnalysisResult> {
	const normalizedAddress = address.toLowerCase() as Address;

	if (isKnownSafe(normalizedAddress)) {
		return {
			address: normalizedAddress,
			risk: 'LOW',
			threats: [],
			blocked: false,
		};
	}

	const knownMalicious = checkKnownMalicious(normalizedAddress);
	if (knownMalicious) {
		return {
			address: normalizedAddress,
			risk: 'CRITICAL',
			threats: [knownMalicious.type],
			blocked: true,
			source: knownMalicious.source,
		};
	}

	try {
		const bytecode = await fetchBytecode(normalizedAddress, options?.rpcUrl);

		if (!bytecode) {
			return {
				address: normalizedAddress,
				risk: 'UNKNOWN',
				threats: ['No bytecode found'],
				blocked: false,
			};
		}

		const instructions = parseBytecode(bytecode);
		const detectionResults = runAllDetectors(instructions);

		const threats: string[] = [];
		const warnings: string[] = [];
		const isMetamorphic = detectionResults.hasCreate2 && detectionResults.hasSelfDestruct;

		if (isMetamorphic) {
			threats.push('metamorphicPattern');
			warnings.push(
				'Contract can redeploy different code at the same address. Your delegation could become malicious after you sign.',
			);
		} else {
			if (detectionResults.hasCreate2) {
				threats.push('hasCreate2');
				warnings.push(
					'Contract uses CREATE2. May deploy additional contracts at predictable addresses.',
				);
			}
			if (detectionResults.hasSelfDestruct) {
				threats.push('hasSelfDestruct');
				warnings.push('Contract can self-destruct. Your delegation would become invalid.');
			}
		}

		if (detectionResults.hasAutoForwarder) {
			threats.push('hasAutoForwarder');
			warnings.push(
				'Contract automatically forwards ETH. Funds sent to your wallet could be stolen.',
			);
		}
		if (detectionResults.isDelegatedCall) {
			threats.push('isDelegatedCall');
			warnings.push(
				'Contract uses DELEGATECALL. Can execute arbitrary code in your wallet context.',
			);
		}
		if (detectionResults.hasUnlimitedApprovals) {
			threats.push('hasUnlimitedApprovals');
			warnings.push(
				'Contract requests unlimited token approvals. Could drain all approved tokens.',
			);
		}
		if (detectionResults.hasChainId && !detectionResults.isEip712Pattern) {
			threats.push('crossChainPolymorphism');
			if (detectionResults.hasChainIdBranching && detectionResults.hasChainIdComparison) {
				warnings.push(
					'Contract uses CHAINID with comparison and branching. Behavior will differ across chains - may be safe on Mainnet but malicious on L2s. Avoid signing with chainId=0.',
				);
			} else if (detectionResults.hasChainIdBranching) {
				warnings.push(
					'Contract uses CHAINID with conditional branching. Behavior may differ across chains. Avoid signing with chainId=0.',
				);
			} else if (detectionResults.hasChainIdComparison) {
				warnings.push(
					'Contract compares CHAINID value. May restrict or alter behavior on specific chains.',
				);
			} else {
				warnings.push(
					'Contract reads CHAINID. Behavior may vary by chain. Consider restricting delegation to a specific chain.',
				);
			}
		}

		const tokenAnalysis = detectionResults.tokenTransfer;
		if (tokenAnalysis.contextualRisk !== 'LOW') {
			if (tokenAnalysis.contextualRisk === 'CRITICAL') {
				threats.push('unprotectedTokenTransfer');
				if (tokenAnalysis.appearsInFallback) {
					warnings.push(
						'Automatic Fund Drain Detected: Contract automatically forwards your tokens in fallback function. This is a known attack pattern.',
					);
				} else if (tokenAnalysis.hasHardcodedDestination) {
					warnings.push(
						'Unsecured Token Access: Contract can transfer tokens to a hardcoded address without your approval.',
					);
				} else if (tokenAnalysis.detectedSelectors.some((s) => s.name === 'setApprovalForAll')) {
					warnings.push(
						'Full Collection Drain Risk: Contract can approve unlimited access to your NFT collections without security controls.',
					);
				}
			} else if (tokenAnalysis.contextualRisk === 'HIGH') {
				threats.push('missingTokenAuth');
				if (!tokenAnalysis.hasNonceTracking && tokenAnalysis.hasEcrecover) {
					warnings.push(
						'Replay Attack Risk: Contract verifies signatures but lacks nonce tracking. Same signature could be reused.',
					);
				} else {
					warnings.push(
						'Missing Security Controls: Contract can transfer your tokens but has no signature verification. Legitimate wallets require your approval for each transfer.',
					);
				}
			} else if (tokenAnalysis.contextualRisk === 'MEDIUM') {
				threats.push('tokenTransferCapability');
				warnings.push(
					`Token Transfer Capability: Contract can move your tokens. Security features detected: ${tokenAnalysis.hasEcrecover ? '✓ Signature verification' : ''}${tokenAnalysis.hasAuthorizationPattern ? ' ✓ Access controls' : ''}. Verify this is a trusted wallet.`,
				);
			}
		}

		let risk: AnalysisResult['risk'] = 'LOW';
		let blocked = false;

		if (threats.length > 0) {
			if (
				isMetamorphic ||
				detectionResults.hasAutoForwarder ||
				tokenAnalysis.contextualRisk === 'CRITICAL' ||
				threats.length >= 2
			) {
				risk = 'CRITICAL';
				blocked = true;
			} else if (
				detectionResults.hasSelfDestruct ||
				detectionResults.isDelegatedCall ||
				(detectionResults.hasChainIdBranching && detectionResults.hasChainIdComparison) ||
				tokenAnalysis.contextualRisk === 'HIGH'
			) {
				risk = 'HIGH';
				blocked = true;
			} else if (detectionResults.hasChainIdBranching) {
				risk = 'HIGH';
				blocked = true;
			} else {
				risk = 'MEDIUM';
			}
		}

		return {
			address: normalizedAddress,
			risk,
			threats,
			warnings: warnings.length > 0 ? warnings : undefined,
			blocked,
		};
	} catch (error) {
		return {
			address: normalizedAddress,
			risk: 'UNKNOWN',
			threats: ['Analysis failed'],
			blocked: false,
			error: String(error),
		};
	}
}
