import type { Address } from 'viem';
import { runAllDetectors } from './detectors';
import { fetchBytecode } from './fetcher';
import { isKnownSafe } from './malicious-db';
import { parseBytecode } from './parser';
import type { AnalysisResult, DetectionResults, Warning } from './types';

export interface AnalyzeOptions {
	rpcUrl?: string;
}

export function generateWarnings(detectionResults: DetectionResults): Warning[] {
	const warnings: Warning[] = [];
	const isMetamorphic = detectionResults.hasCreate2 && detectionResults.hasSelfDestruct;

	if (isMetamorphic) {
		warnings.push({
			type: 'METAMORPHIC',
			severity: 'CRITICAL',
			title: 'Metamorphic Contract Detected',
			description:
				'Contract can redeploy different code at the same address. Your delegation could become malicious after you sign.',
			technical: 'CREATE2 + SELFDESTRUCT pattern enables code replacement at same address',
		});
	} else {
		if (detectionResults.hasCreate2) {
			warnings.push({
				type: 'CREATE2',
				severity: 'MEDIUM',
				title: 'CREATE2 Deployment Capability',
				description:
					'Contract uses CREATE2. May deploy additional contracts at predictable addresses.',
				technical: 'CREATE2 opcode (0xF5) detected - deterministic address deployment',
			});
		}
		if (detectionResults.hasSelfDestruct) {
			warnings.push({
				type: 'SELF_DESTRUCT',
				severity: 'HIGH',
				title: 'Self-Destruct Capability',
				description: 'Contract can self-destruct. Your delegation would become invalid.',
				technical: 'SELFDESTRUCT opcode (0xFF) detected',
			});
		}
	}

	if (detectionResults.hasAutoForwarder) {
		warnings.push({
			type: 'AUTO_FORWARDER',
			severity: 'CRITICAL',
			title: 'Automatic Fund Drain Detected',
			description:
				'Contract automatically forwards ETH. Funds sent to your wallet could be stolen.',
			technical: 'SELFBALANCE + CALL pattern - auto-forwards incoming ETH',
		});
	}

	if (detectionResults.isDelegatedCall) {
		warnings.push({
			type: 'DELEGATE_CALL',
			severity: 'HIGH',
			title: 'Arbitrary Code Execution',
			description: 'Contract uses DELEGATECALL. Can execute arbitrary code in your wallet context.',
			technical: 'DELEGATECALL opcode (0xF4) detected',
		});
	}

	if (detectionResults.hasUnlimitedApprovals) {
		warnings.push({
			type: 'UNLIMITED_APPROVAL',
			severity: 'HIGH',
			title: 'Unlimited Token Approval',
			description: 'Contract requests unlimited token approvals. Could drain all approved tokens.',
			technical: 'PUSH32 with max uint256 (0xFF...FF) detected',
		});
	}

	if (detectionResults.hasChainId && !detectionResults.isEip712Pattern) {
		if (detectionResults.hasChainIdBranching && detectionResults.hasChainIdComparison) {
			warnings.push({
				type: 'CHAINID_BRANCHING',
				severity: 'HIGH',
				title: 'Network-Dependent Behavior',
				description:
					'Contract uses CHAINID with comparison and branching. Behavior will differ across chains - may be safe on Mainnet but malicious on L2s. Avoid signing with chainId=0.',
				technical: 'CHAINID (0x46) + comparison opcodes (EQ/LT/GT) + JUMPI branching',
			});
		} else if (detectionResults.hasChainIdBranching) {
			warnings.push({
				type: 'CHAINID_BRANCHING',
				severity: 'HIGH',
				title: 'Network-Dependent Branching',
				description:
					'Contract uses CHAINID with conditional branching. Behavior may differ across chains. Avoid signing with chainId=0.',
				technical: 'CHAINID (0x46) + JUMPI (0x57) branching pattern',
			});
		} else if (detectionResults.hasChainIdComparison) {
			warnings.push({
				type: 'CHAINID_COMPARISON',
				severity: 'MEDIUM',
				title: 'Network ID Comparison',
				description:
					'Contract compares CHAINID value. May restrict or alter behavior on specific chains.',
				technical: 'CHAINID (0x46) + comparison opcodes (EQ/LT/GT/SLT/SGT)',
			});
		} else {
			warnings.push({
				type: 'CHAINID_READ',
				severity: 'MEDIUM',
				title: 'Network ID Access',
				description:
					'Contract reads CHAINID. Behavior may vary by chain. Consider restricting delegation to a specific chain.',
				technical: 'CHAINID opcode (0x46) detected',
			});
		}
	}

	const tokenAnalysis = detectionResults.tokenTransfer;
	if (tokenAnalysis.contextualRisk !== 'LOW') {
		if (tokenAnalysis.contextualRisk === 'CRITICAL') {
			if (tokenAnalysis.appearsInFallback) {
				warnings.push({
					type: 'TOKEN_DRAIN_FALLBACK',
					severity: 'CRITICAL',
					title: 'Automatic Token Drain',
					description:
						'Contract automatically forwards your tokens in fallback function. This is a known attack pattern.',
					technical: 'Token transfer selector in fallback/receive - no function dispatcher',
				});
			} else if (tokenAnalysis.hasHardcodedDestination) {
				warnings.push({
					type: 'TOKEN_HARDCODED_DEST',
					severity: 'CRITICAL',
					title: 'Unsecured Token Access',
					description: 'Contract can transfer tokens to a hardcoded address without your approval.',
					technical: 'PUSH20 hardcoded address + token transfer without auth checks',
				});
			} else if (tokenAnalysis.detectedSelectors.some((s) => s.name === 'setApprovalForAll')) {
				warnings.push({
					type: 'TOKEN_APPROVAL_NO_AUTH',
					severity: 'CRITICAL',
					title: 'Full Collection Drain Risk',
					description:
						'Contract can approve unlimited access to your NFT collections without security controls.',
					technical: 'setApprovalForAll (0xa22cb465) without ecrecover or CALLER check',
				});
			}
		} else if (tokenAnalysis.contextualRisk === 'HIGH') {
			if (!tokenAnalysis.hasNonceTracking && tokenAnalysis.hasEcrecover) {
				warnings.push({
					type: 'TOKEN_REPLAY_RISK',
					severity: 'HIGH',
					title: 'Replay Attack Risk',
					description:
						'Contract verifies signatures but lacks nonce tracking. Same signature could be reused.',
					technical: 'ecrecover (precompile 0x01) present but no SLOAD+SSTORE nonce pattern',
				});
			} else {
				warnings.push({
					type: 'TOKEN_NO_AUTH',
					severity: 'HIGH',
					title: 'Missing Security Controls',
					description:
						'Contract can transfer your tokens but has no signature verification. Legitimate wallets require your approval for each transfer.',
					technical: 'Token selectors present without ecrecover or CALLER check',
				});
			}
		} else if (tokenAnalysis.contextualRisk === 'MEDIUM') {
			const features: string[] = [];
			if (tokenAnalysis.hasEcrecover) features.push('Signature verification');
			if (tokenAnalysis.hasAuthorizationPattern) features.push('Access controls');

			warnings.push({
				type: 'TOKEN_WITH_AUTH',
				severity: 'MEDIUM',
				title: 'Token Transfer Capability',
				description: `Contract can move your tokens. Security features detected: ${features.map((f) => `✓ ${f}`).join(' ')}. Verify this is a trusted wallet.`,
				technical: `Token selectors with auth: ${tokenAnalysis.hasEcrecover ? 'ecrecover' : ''}${tokenAnalysis.hasAuthorizationPattern ? ' CALLER check' : ''}`,
			});
		}
	}

	if (detectionResults.isEip712Pattern && detectionResults.hasChainId) {
		warnings.push({
			type: 'EIP712_SAFE',
			severity: 'INFO',
			title: 'Standard Security Pattern',
			description:
				'Contract uses network ID for secure signatures (EIP-712). This is expected behavior.',
			technical: 'CHAINID (0x46) followed by KECCAK256 (0x20) - EIP-712 domain separator',
		});
	}

	return warnings;
}

export function deriveRiskFromWarnings(warnings: Warning[]): {
	risk: AnalysisResult['risk'];
	blocked: boolean;
} {
	const actionableWarnings = warnings.filter((w) => w.severity !== 'INFO');

	if (actionableWarnings.length === 0) {
		return { risk: 'LOW', blocked: false };
	}

	const hasCritical = actionableWarnings.some((w) => w.severity === 'CRITICAL');
	const hasHigh = actionableWarnings.some((w) => w.severity === 'HIGH');
	const multipleThreats = actionableWarnings.length >= 2;

	// CRITICAL: Any CRITICAL warning OR (HIGH + multiple threats)
	if (hasCritical) {
		return { risk: 'CRITICAL', blocked: true };
	}

	if (hasHigh && multipleThreats) {
		return { risk: 'CRITICAL', blocked: true };
	}

	// HIGH: Single HIGH warning OR multiple MEDIUM warnings
	// (2+ MEDIUMs = HIGH, not CRITICAL - avoids false positives on smart wallets)
	if (hasHigh) {
		return { risk: 'HIGH', blocked: true };
	}

	if (multipleThreats) {
		return { risk: 'HIGH', blocked: true };
	}

	// MEDIUM: Single MEDIUM warning (not blocked)
	return { risk: 'MEDIUM', blocked: false };
}

export async function analyzeContract(
	address: Address,
	options?: AnalyzeOptions,
): Promise<AnalysisResult> {
	const normalizedAddress = address.toLowerCase() as Address;

	// Fast-path for known safe addresses (legacy, will be merged with Safe Filter)
	if (isKnownSafe(normalizedAddress)) {
		return {
			address: normalizedAddress,
			risk: 'LOW',
			threats: [],
			blocked: false,
		};
	}

	// Note: Malicious address checks are now handled by the API layer (ANT-194)
	// The core analyzer focuses on pure bytecode analysis

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
		const warnings = generateWarnings(detectionResults);

		const threats: string[] = warnings
			.filter((w) => w.severity !== 'INFO')
			.map((w) => w.type.toLowerCase());

		const { risk, blocked } = deriveRiskFromWarnings(warnings);

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
