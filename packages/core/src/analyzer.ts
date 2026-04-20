import type { Address } from 'viem';
import { extractMinimalProxyTarget, runAllDetectors } from './detectors';
import { BytecodeFetchError, fetchBytecode, resolveProxyImplementation } from './fetcher';
import { isKnownSafe } from './malicious-db';
import { InvalidBytecodeError, parseBytecode } from './parser';
import type { AnalysisResult, DetectionResults, Warning } from './types';

const MAX_PROXY_DEPTH = 2;

export interface AnalyzeOptions {
	rpcUrl?: string;
	/** @internal Used to prevent infinite proxy resolution loops */
	_proxyDepth?: number;
	/** @internal Visited addresses (normalized, lowercase) for proxy-chain cycle detection */
	_visitedAddresses?: ReadonlySet<string>;
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
				description:
					'Contract contains SELFDESTRUCT. Post-Dencun (EIP-6780), this sends the entire ETH balance to a target address without destroying the contract.',
				technical:
					'SELFDESTRUCT opcode (0xFF) detected - post-EIP-6780: sends balance only, no code destruction unless same-tx creation',
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
		const isExpectedDelegatecall =
			detectionResults.proxy?.isProxy ||
			detectionResults.hasMinimalProxy ||
			detectionResults.hasDiamondProxy ||
			detectionResults.hasErc4337Pattern;

		warnings.push({
			type: 'DELEGATE_CALL',
			severity: isExpectedDelegatecall ? 'MEDIUM' : 'HIGH',
			title: isExpectedDelegatecall ? 'Delegated Execution (Proxy)' : 'Arbitrary Code Execution',
			description: isExpectedDelegatecall
				? 'Contract uses DELEGATECALL as part of a known proxy or smart wallet pattern. The implementation contract should be verified separately.'
				: 'Contract uses DELEGATECALL. Can execute arbitrary code in your wallet context.',
			technical: isExpectedDelegatecall
				? 'DELEGATECALL opcode (0xF4) detected - expected for proxy/smart wallet architecture'
				: 'DELEGATECALL opcode (0xF4) detected',
		});
	}

	if (detectionResults.hasCallcode) {
		const isExpectedCallcode =
			detectionResults.proxy?.isProxy ||
			detectionResults.hasMinimalProxy ||
			detectionResults.hasDiamondProxy ||
			detectionResults.hasErc4337Pattern;

		warnings.push({
			type: 'CALLCODE',
			severity: isExpectedCallcode ? 'MEDIUM' : 'HIGH',
			title: isExpectedCallcode
				? 'Legacy Delegated Execution (Proxy)'
				: 'Legacy Arbitrary Code Execution',
			description: isExpectedCallcode
				? 'Contract uses CALLCODE (deprecated) as part of a known proxy pattern. The implementation contract should be verified separately.'
				: 'Contract uses CALLCODE (deprecated equivalent of DELEGATECALL). Can execute arbitrary code in your wallet context. Use of this deprecated opcode is suspicious.',
			technical: isExpectedCallcode
				? 'CALLCODE opcode (0xF2) detected - deprecated variant of DELEGATECALL, expected for legacy proxy'
				: 'CALLCODE opcode (0xF2) detected - deprecated variant of DELEGATECALL, suspicious in modern contracts',
		});
	}

	if (detectionResults.hasUnlimitedApprovals) {
		warnings.push({
			type: 'UNLIMITED_APPROVAL',
			severity: 'MEDIUM',
			title: 'Unlimited Token Approval',
			description:
				'Contract contains max uint256 value, commonly used for unlimited token approvals. Standard in DeFi but allows full token spending if approved.',
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
			} else if (tokenAnalysis.detectedSelectors.some((s) => s.type === 'permit')) {
				warnings.push({
					type: 'TOKEN_PERMIT2_NO_AUTH',
					severity: 'CRITICAL',
					title: 'Gasless Token Drain Risk',
					description:
						'Contract uses Permit2 gasless transfers without access controls. Tokens can be moved without your direct approval.',
					technical:
						'Permit2 permitTransferFrom selector without ecrecover or CALLER check - immediate drain risk',
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

	if (detectionResults.proxy?.isProxy) {
		const slots: string[] = [];
		if (detectionResults.proxy?.hasImplementationSlot) slots.push('implementation');
		if (detectionResults.proxy?.hasBeaconSlot) slots.push('beacon');
		if (detectionResults.proxy?.hasAdminSlot) slots.push('admin');
		warnings.push({
			type: 'PROXY_PATTERN',
			severity: 'MEDIUM',
			title: 'Upgradeable Proxy Contract',
			description:
				'Contract is an EIP-1967 proxy. The implementation can be upgraded, meaning behavior may change after you delegate.',
			technical: `EIP-1967 storage slots detected: ${slots.join(', ')}`,
		});
	}

	if (detectionResults.hasTxOrigin) {
		warnings.push({
			type: 'TX_ORIGIN_PHISHING',
			severity: 'HIGH',
			title: 'tx.origin Phishing Risk',
			description:
				'Contract checks tx.origin for authorization. This enables phishing attacks where a malicious contract relays your transaction.',
			technical: 'ORIGIN (0x32) + EQ comparison pattern - vulnerable to relay attacks',
		});
	}

	if (detectionResults.hasTimestampDependence) {
		warnings.push({
			type: 'TIMESTAMP_DEPENDENCE',
			severity: 'MEDIUM',
			title: 'Time-Dependent Behavior',
			description:
				'Contract uses block timestamp with conditional logic. May implement time-locked operations or delayed drains.',
			technical: 'TIMESTAMP (0x42) + comparison + JUMPI branching pattern',
		});
	}

	if (detectionResults.hasMulticall) {
		warnings.push({
			type: 'MULTICALL_CAPABILITY',
			severity: 'MEDIUM',
			title: 'Batch Execution Capability',
			description:
				'Contract supports multicall or aggregate operations. Multiple calls can be executed in a single transaction, which may include token transfers or approvals.',
			technical: 'Multicall/aggregate selector detected - enables batched arbitrary calls',
		});
	}

	if (detectionResults.hasExtcodesizeGuard) {
		warnings.push({
			type: 'EXTCODESIZE_GUARD',
			severity: 'INFO',
			title: 'Contract Size Check',
			description:
				'Contract checks EXTCODESIZE to determine if an address is a contract or EOA. With EIP-7702 delegations, EOAs can have code, which may bypass this check.',
			technical: 'EXTCODESIZE (0x3B) + comparison pattern - may be bypassed by EIP-7702 EOAs',
		});
	}

	if (detectionResults.hasErc4337Pattern) {
		warnings.push({
			type: 'ERC4337_PATTERN',
			severity: 'INFO',
			title: 'Account Abstraction Pattern',
			description:
				'Contract interacts with ERC-4337 EntryPoint. This is standard account abstraction infrastructure used by smart wallets.',
			technical: 'ERC-4337 EntryPoint address or handleOps/validateUserOp selector detected',
		});
	}

	if (detectionResults.hasCoinbaseDependence) {
		warnings.push({
			type: 'COINBASE_DEPENDENCE',
			severity: 'MEDIUM',
			title: 'Validator-Dependent Behavior',
			description:
				'Contract uses block coinbase with conditional logic. Behavior may vary by block validator, which could enable MEV-related manipulation.',
			technical: 'COINBASE (0x41) + comparison + JUMPI branching pattern',
		});
	}

	if (detectionResults.hasMinimalProxy) {
		warnings.push({
			type: 'MINIMAL_PROXY',
			severity: 'INFO',
			title: 'EIP-1167 Minimal Proxy',
			description:
				'Contract is an EIP-1167 minimal proxy that delegates all calls to a fixed implementation address. The implementation cannot be changed, but the implementation contract should be analyzed separately.',
			technical:
				'EIP-1167 bytecode pattern: 363d3d373d3d3d363d73{addr}5af43d82803e903d91602b57fd5bf3',
		});
	}

	if (detectionResults.hasBalanceDrain) {
		warnings.push({
			type: 'BALANCE_DRAIN',
			severity: 'HIGH',
			title: 'Balance Check Before Transfer',
			description:
				'Contract checks an address balance then makes an external call. This pattern is used to drain funds by checking the victim balance before stealing.',
			technical:
				'BALANCE (0x31) + comparison + CALL/SELFDESTRUCT pattern - checks target balance before transferring',
		});
	}

	if (detectionResults.hasExtcodecopy) {
		const isMetamorphicVariant = detectionResults.hasCreate2 && !detectionResults.hasSelfDestruct;
		warnings.push({
			type: 'EXTCODECOPY_USAGE',
			severity: isMetamorphicVariant ? 'MEDIUM' : 'INFO',
			title: isMetamorphicVariant ? 'External Code Deployment' : 'External Code Read',
			description: isMetamorphicVariant
				? 'Contract copies external bytecode and uses CREATE2 for deployment. This pattern can deploy arbitrary code at predictable addresses.'
				: 'Contract reads bytecode from an external address. This is common in factory and deployment patterns.',
			technical: isMetamorphicVariant
				? 'EXTCODECOPY (0x3C) + CREATE2 (0xF5) without SELFDESTRUCT - code injection deployment pattern'
				: 'EXTCODECOPY opcode (0x3C) detected - reads external contract bytecode',
		});
	}

	if (detectionResults.hasReentrancyRisk) {
		warnings.push({
			type: 'REENTRANCY_RISK',
			severity: 'HIGH',
			title: 'Reentrancy Vulnerability Pattern',
			description:
				'Contract writes to storage after an external call. This violates the checks-effects-interactions pattern and may allow reentrancy attacks that drain funds.',
			technical:
				'CALL/DELEGATECALL/CALLCODE followed by SSTORE within proximity window — state change after external call',
		});
	}

	if (detectionResults.hasGasManipulation) {
		warnings.push({
			type: 'GAS_MANIPULATION',
			severity: 'MEDIUM',
			title: 'Gas-Dependent Behavior',
			description:
				'Contract branches based on remaining gas. Behavior may differ depending on gas limits, which can be exploited for gas griefing or conditional execution attacks.',
			technical: 'GAS (0x5A) + comparison + JUMPI branching pattern',
		});
	}

	if (detectionResults.hasExtcodehash) {
		warnings.push({
			type: 'EXTCODEHASH_CHECK',
			severity: 'INFO',
			title: 'Code Hash Verification',
			description:
				'Contract reads EXTCODEHASH to verify contract integrity. With EIP-7702 delegations, EOA code hashes change when delegation is active, which may affect compatibility.',
			technical:
				'EXTCODEHASH opcode (0x3F) detected — code identity check that may interact with EIP-7702',
		});
	}

	if (detectionResults.hasDiamondProxy) {
		warnings.push({
			type: 'DIAMOND_PROXY',
			severity: 'MEDIUM',
			title: 'Diamond Proxy Pattern (EIP-2535)',
			description:
				'Contract implements the Diamond standard with upgradeable facets. Functions can be added, replaced, or removed by the owner, meaning behavior may change after you delegate.',
			technical: 'Diamond Loupe selectors detected (diamondCut/facets/facetAddress)',
		});
	}

	if (detectionResults.isEip7702Delegation) {
		warnings.push({
			type: 'EIP7702_DELEGATION',
			severity: 'INFO',
			title: 'EIP-7702 Delegation Pointer',
			description:
				'This address has an EIP-7702 delegation. Code is executed from the delegate contract, not stored here.',
			technical: 'Bytecode starts with 0xEF0100 prefix - EIP-7702 delegation pointer',
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

	const currentDepth = options?._proxyDepth ?? 0;
	const visited = options?._visitedAddresses ?? new Set<string>();

	// Proxy-chain cycle guard: A → B → A would loop forever otherwise.
	if (visited.has(normalizedAddress)) {
		return {
			address: normalizedAddress,
			risk: 'UNKNOWN',
			threats: ['proxy_cycle_detected'],
			blocked: false,
			error: `Proxy delegation cycle detected at ${normalizedAddress}`,
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
		const detectionResults = runAllDetectors(instructions, bytecode);
		const warnings = generateWarnings(detectionResults);

		// Resolve proxy implementation if detected and within depth limit
		let implementationAddress: Address | undefined;
		let implementationAnalysis: AnalysisResult | undefined;

		if (currentDepth < MAX_PROXY_DEPTH) {
			const implAddr = await resolveImplementation(
				detectionResults,
				bytecode,
				normalizedAddress,
				options?.rpcUrl,
			);

			if (implAddr) {
				implementationAddress = implAddr.toLowerCase() as Address;
				const nextVisited = new Set(visited);
				nextVisited.add(normalizedAddress);
				implementationAnalysis = await analyzeContract(implementationAddress, {
					rpcUrl: options?.rpcUrl,
					_proxyDepth: currentDepth + 1,
					_visitedAddresses: nextVisited,
				});
			}
		}

		// Merge implementation warnings into proxy result
		const allWarnings = mergeImplementationWarnings(warnings, implementationAnalysis);
		const threats: string[] = allWarnings
			.filter((w) => w.severity !== 'INFO')
			.map((w) => w.type.toLowerCase());

		const { risk, blocked } = deriveRiskFromWarnings(allWarnings);

		return {
			address: normalizedAddress,
			risk,
			threats,
			warnings: allWarnings.length > 0 ? allWarnings : undefined,
			blocked,
			implementationAddress,
			implementationAnalysis,
		};
	} catch (error) {
		// Classify known error types so callers can distinguish transient
		// network failures from malformed bytecode. Both stay fail-open
		// (risk: UNKNOWN) so the extension's decision matrix decides what to
		// do — see ADR-006 / ADR-013.
		let threatTag = 'Analysis failed';
		if (error instanceof BytecodeFetchError) {
			threatTag = 'bytecode_fetch_failed';
		} else if (error instanceof InvalidBytecodeError) {
			threatTag = 'invalid_bytecode';
		}
		return {
			address: normalizedAddress,
			risk: 'UNKNOWN',
			threats: [threatTag],
			blocked: false,
			error: error instanceof Error ? error.message : String(error),
		};
	}
}

async function resolveImplementation(
	detectionResults: DetectionResults,
	bytecode: string,
	proxyAddress: Address,
	rpcUrl?: string,
): Promise<string | null> {
	// EIP-1167 minimal proxy: address embedded in bytecode (no RPC needed)
	if (detectionResults.hasMinimalProxy) {
		return extractMinimalProxyTarget(bytecode);
	}

	// EIP-1967 proxy: resolve implementation from storage slot
	if (detectionResults.proxy?.isProxy && detectionResults.proxy.hasImplementationSlot) {
		return resolveProxyImplementation(proxyAddress, rpcUrl);
	}

	return null;
}

function mergeImplementationWarnings(
	proxyWarnings: Warning[],
	implAnalysis?: AnalysisResult,
): Warning[] {
	if (!implAnalysis?.warnings?.length) return proxyWarnings;

	// Tag implementation warnings so users know where they came from
	const implWarnings = implAnalysis.warnings
		.filter((w) => w.severity !== 'INFO')
		.map((w) => ({
			...w,
			title: `[Implementation] ${w.title}`,
			technical: w.technical ? `${w.technical} (via proxy implementation)` : undefined,
		}));

	return [...proxyWarnings, ...implWarnings];
}
