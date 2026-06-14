import { describe, expect, it } from 'vitest';
import { parseBytecode } from '../src';
import {
	analyzeTokenTransfers,
	detectAutoForwarder,
	detectBalanceDrain,
	detectCallcode,
	detectChainId,
	detectCoinbaseDependence,
	detectCreate2,
	detectDelegateCall,
	detectDiamondProxy,
	detectEcrecover,
	detectEip7702Delegation,
	detectErc4337Pattern,
	detectExtcodecopy,
	detectExtcodehash,
	detectExtcodesizeGuard,
	detectFallbackLocation,
	detectGasManipulation,
	detectHardcodedDestination,
	detectMinimalProxy,
	detectMsgSenderCheck,
	detectMulticall,
	detectNonceTracking,
	detectProxyPattern,
	detectReentrancyRisk,
	detectSelfDestruct,
	detectTimestampDependence,
	detectTokenSelectors,
	detectTxOrigin,
	detectUnlimitedApproval,
	runAllDetectors,
} from '../src/detectors';

import {
	AUTHORIZATION_CONTRACTS,
	AUTO_FORWARDER_CONTRACTS,
	BALANCE_DRAIN_CONTRACTS,
	CALLCODE_CONTRACTS,
	CHAINID_CONTRACTS,
	COINBASE_CONTRACTS,
	CREATE2_CONTRACTS,
	DECREASE_ALLOWANCE_CONTRACTS,
	DELEGATECALL_CONTRACTS,
	DIAMOND_PROXY_CONTRACTS,
	DRAINER_PATTERNS,
	EIP7702_CONTRACTS,
	ERC4337_CONTRACTS,
	EXTCODECOPY_CONTRACTS,
	EXTCODEHASH_CONTRACTS,
	EXTCODESIZE_CONTRACTS,
	FALLBACK_CONTRACTS,
	FALSE_POSITIVE_CONTRACTS,
	GAS_MANIPULATION_CONTRACTS,
	HARDCODED_DESTINATION_CONTRACTS,
	MINIMAL_PROXY_CONTRACTS,
	MULTI_THREAT_CONTRACTS,
	MULTICALL_CONTRACTS,
	NONCE_TRACKING_CONTRACTS,
	PROXY_CONTRACTS,
	REENTRANCY_CONTRACTS,
	SAFE_CONTRACTS,
	SELFDESTRUCT_CONTRACTS,
	TIMESTAMP_CONTRACTS,
	TOKEN_TRANSFER_CONTRACTS,
	TX_ORIGIN_CONTRACTS,
	UNLIMITED_APPROVAL_CONTRACTS,
} from './fixtures/contracts';

describe('detectSelfDestruct', () => {
	describe('should detect SELFDESTRUCT opcode', () => {
		it('detects minimal SELFDESTRUCT', () => {
			const instructions = parseBytecode(SELFDESTRUCT_CONTRACTS.minimal);
			expect(detectSelfDestruct(instructions)).toBe(true);
		});

		it('detects SELFDESTRUCT with PUSH setup', () => {
			const instructions = parseBytecode(SELFDESTRUCT_CONTRACTS.withPush);
			expect(detectSelfDestruct(instructions)).toBe(true);
		});

		it('detects SELFDESTRUCT(msg.sender) pattern', () => {
			const instructions = parseBytecode(SELFDESTRUCT_CONTRACTS.toMsgSender);
			expect(detectSelfDestruct(instructions)).toBe(true);
		});

		it('detects SELFDESTRUCT in complex bytecode', () => {
			const instructions = parseBytecode(SELFDESTRUCT_CONTRACTS.complex);
			expect(detectSelfDestruct(instructions)).toBe(true);
		});
	});

	describe('should NOT false positive on 0xFF as data', () => {
		it('ignores 0xFF inside PUSH1 data', () => {
			const instructions = parseBytecode(FALSE_POSITIVE_CONTRACTS.ffAsPush1Data);
			expect(detectSelfDestruct(instructions)).toBe(false);
		});

		it('ignores 0xFF inside PUSH2 data', () => {
			const instructions = parseBytecode(FALSE_POSITIVE_CONTRACTS.ffAsPush2Data);
			expect(detectSelfDestruct(instructions)).toBe(false);
		});

		it('ignores max uint256 (32 bytes of 0xFF)', () => {
			const instructions = parseBytecode(FALSE_POSITIVE_CONTRACTS.maxUint256);
			expect(detectSelfDestruct(instructions)).toBe(false);
		});

		it('ignores multiple PUSH with 0xFF data', () => {
			const instructions = parseBytecode(FALSE_POSITIVE_CONTRACTS.multiplePushFF);
			expect(detectSelfDestruct(instructions)).toBe(false);
		});
	});
});

describe('detectDelegateCall', () => {
	describe('should detect DELEGATECALL opcode', () => {
		it('detects minimal DELEGATECALL', () => {
			const instructions = parseBytecode(DELEGATECALL_CONTRACTS.minimal);
			expect(detectDelegateCall(instructions)).toBe(true);
		});

		it('detects DELEGATECALL with setup', () => {
			const instructions = parseBytecode(DELEGATECALL_CONTRACTS.withSetup);
			expect(detectDelegateCall(instructions)).toBe(true);
		});
	});

	describe('should NOT false positive', () => {
		it('ignores 0xF4 inside PUSH data', () => {
			const instructions = parseBytecode(DELEGATECALL_CONTRACTS.f4AsPushData);
			expect(detectDelegateCall(instructions)).toBe(false);
		});

		it('returns false for safe contract', () => {
			const instructions = parseBytecode(SAFE_CONTRACTS.simpleAdd);
			expect(detectDelegateCall(instructions)).toBe(false);
		});
	});
});

describe('detectCallcode', () => {
	describe('should detect CALLCODE opcode', () => {
		it('detects minimal CALLCODE', () => {
			const instructions = parseBytecode(CALLCODE_CONTRACTS.minimal);
			expect(detectCallcode(instructions)).toBe(true);
		});

		it('detects CALLCODE with setup', () => {
			const instructions = parseBytecode(CALLCODE_CONTRACTS.withSetup);
			expect(detectCallcode(instructions)).toBe(true);
		});

		it('detects both CALLCODE and DELEGATECALL', () => {
			const instructions = parseBytecode(CALLCODE_CONTRACTS.bothCallcodeAndDelegatecall);
			expect(detectCallcode(instructions)).toBe(true);
			expect(detectDelegateCall(instructions)).toBe(true);
		});
	});

	describe('should NOT false positive', () => {
		it('ignores 0xF2 inside PUSH data', () => {
			const instructions = parseBytecode(CALLCODE_CONTRACTS.f2AsPushData);
			expect(detectCallcode(instructions)).toBe(false);
		});

		it('returns false for safe contract', () => {
			const instructions = parseBytecode(SAFE_CONTRACTS.simpleAdd);
			expect(detectCallcode(instructions)).toBe(false);
		});
	});

	describe('via runAllDetectors', () => {
		it('sets hasCallcode flag', () => {
			const instructions = parseBytecode(CALLCODE_CONTRACTS.minimal);
			const result = runAllDetectors(instructions);
			expect(result.hasCallcode).toBe(true);
		});

		it('does not set hasCallcode for safe contracts', () => {
			const instructions = parseBytecode(SAFE_CONTRACTS.simpleAdd);
			const result = runAllDetectors(instructions);
			expect(result.hasCallcode).toBe(false);
		});
	});
});

describe('detectExtcodecopy', () => {
	it('detects minimal EXTCODECOPY', () => {
		const instructions = parseBytecode(EXTCODECOPY_CONTRACTS.minimal);
		expect(detectExtcodecopy(instructions)).toBe(true);
	});

	it('detects EXTCODECOPY + CREATE2 pattern', () => {
		const instructions = parseBytecode(EXTCODECOPY_CONTRACTS.withCreate2);
		expect(detectExtcodecopy(instructions)).toBe(true);
		expect(detectCreate2(instructions)).toBe(true);
	});

	it('detects EXTCODECOPY + CREATE2 + SELFDESTRUCT', () => {
		const instructions = parseBytecode(EXTCODECOPY_CONTRACTS.withCreate2AndSelfdestruct);
		expect(detectExtcodecopy(instructions)).toBe(true);
		expect(detectCreate2(instructions)).toBe(true);
		expect(detectSelfDestruct(instructions)).toBe(true);
	});

	it('ignores 0x3C inside PUSH data', () => {
		const instructions = parseBytecode(EXTCODECOPY_CONTRACTS.inPushData);
		expect(detectExtcodecopy(instructions)).toBe(false);
	});

	it('returns false for safe contract', () => {
		const instructions = parseBytecode(SAFE_CONTRACTS.simpleAdd);
		expect(detectExtcodecopy(instructions)).toBe(false);
	});

	it('sets hasExtcodecopy via runAllDetectors', () => {
		const instructions = parseBytecode(EXTCODECOPY_CONTRACTS.minimal);
		const result = runAllDetectors(instructions);
		expect(result.hasExtcodecopy).toBe(true);
	});
});

describe('detectBalanceDrain', () => {
	it('detects BALANCE + EQ + CALL pattern', () => {
		const instructions = parseBytecode(BALANCE_DRAIN_CONTRACTS.balanceCompareCall);
		expect(detectBalanceDrain(instructions)).toBe(true);
	});

	it('detects BALANCE + GT + CALL pattern', () => {
		const instructions = parseBytecode(BALANCE_DRAIN_CONTRACTS.balanceGtCall);
		expect(detectBalanceDrain(instructions)).toBe(true);
	});

	it('detects BALANCE + EQ + SELFDESTRUCT pattern', () => {
		const instructions = parseBytecode(BALANCE_DRAIN_CONTRACTS.balanceCompareSelfdestruct);
		expect(detectBalanceDrain(instructions)).toBe(true);
	});

	it('ignores BALANCE without comparison', () => {
		const instructions = parseBytecode(BALANCE_DRAIN_CONTRACTS.balanceNoCompare);
		expect(detectBalanceDrain(instructions)).toBe(false);
	});

	it('ignores BALANCE alone', () => {
		const instructions = parseBytecode(BALANCE_DRAIN_CONTRACTS.balanceOnly);
		expect(detectBalanceDrain(instructions)).toBe(false);
	});

	it('ignores 0x31 inside PUSH data', () => {
		const instructions = parseBytecode(BALANCE_DRAIN_CONTRACTS.balanceInPushData);
		expect(detectBalanceDrain(instructions)).toBe(false);
	});

	it('does not trigger on SELFBALANCE (0x47) — different opcode', () => {
		const instructions = parseBytecode(BALANCE_DRAIN_CONTRACTS.selfbalanceNotBalance);
		expect(detectBalanceDrain(instructions)).toBe(false);
	});

	it('sets hasBalanceDrain via runAllDetectors', () => {
		const instructions = parseBytecode(BALANCE_DRAIN_CONTRACTS.balanceCompareCall);
		const result = runAllDetectors(instructions);
		expect(result.hasBalanceDrain).toBe(true);
	});
});

describe('detectCreate2', () => {
	describe('should detect CREATE2 opcode', () => {
		it('detects minimal CREATE2', () => {
			const instructions = parseBytecode(CREATE2_CONTRACTS.minimal);
			expect(detectCreate2(instructions)).toBe(true);
		});

		it('detects CREATE2 with setup code', () => {
			const instructions = parseBytecode(CREATE2_CONTRACTS.withSetup);
			expect(detectCreate2(instructions)).toBe(true);
		});

		it('detects CREATE2 in complex bytecode', () => {
			const instructions = parseBytecode(CREATE2_CONTRACTS.inComplexCode);
			expect(detectCreate2(instructions)).toBe(true);
		});

		it('detects metamorphic pattern (CREATE2 + SELFDESTRUCT)', () => {
			const instructions = parseBytecode(CREATE2_CONTRACTS.metamorphic);
			expect(detectCreate2(instructions)).toBe(true);
		});
	});

	describe('should NOT false positive on 0xF5 as data', () => {
		it('ignores 0xF5 inside PUSH1 data', () => {
			const instructions = parseBytecode(CREATE2_CONTRACTS.f5AsPushData);
			expect(detectCreate2(instructions)).toBe(false);
		});

		it('ignores 0xF5 inside PUSH2 data', () => {
			const instructions = parseBytecode(CREATE2_CONTRACTS.f5AsPush2Data);
			expect(detectCreate2(instructions)).toBe(false);
		});
	});

	describe('should return false for safe contracts', () => {
		it('returns false for simple arithmetic', () => {
			const instructions = parseBytecode(SAFE_CONTRACTS.simpleAdd);
			expect(detectCreate2(instructions)).toBe(false);
		});

		it('returns false for empty bytecode', () => {
			const instructions = parseBytecode(SAFE_CONTRACTS.empty);
			expect(detectCreate2(instructions)).toBe(false);
		});
	});
});

describe('detectAutoForwarder', () => {
	describe('should detect SELFBALANCE + CALL pattern', () => {
		it('detects minimal pattern', () => {
			const instructions = parseBytecode(AUTO_FORWARDER_CONTRACTS.minimal);
			expect(detectAutoForwarder(instructions)).toBe(true);
		});

		it('detects realistic sweeper pattern', () => {
			const instructions = parseBytecode(AUTO_FORWARDER_CONTRACTS.realistic);
			expect(detectAutoForwarder(instructions)).toBe(true);
		});

		it('detects pattern even when spaced apart', () => {
			const instructions = parseBytecode(AUTO_FORWARDER_CONTRACTS.spaced);
			expect(detectAutoForwarder(instructions)).toBe(true);
		});
	});

	describe('should require BOTH opcodes', () => {
		it('rejects SELFBALANCE only', () => {
			const instructions = parseBytecode(AUTO_FORWARDER_CONTRACTS.selfBalanceOnly);
			expect(detectAutoForwarder(instructions)).toBe(false);
		});

		it('rejects CALL only', () => {
			const instructions = parseBytecode(AUTO_FORWARDER_CONTRACTS.callOnly);
			expect(detectAutoForwarder(instructions)).toBe(false);
		});
	});

	describe('proximity enforcement', () => {
		it('rejects SELFBALANCE + CALL beyond 15-instruction window', () => {
			const instructions = parseBytecode(AUTO_FORWARDER_CONTRACTS.beyondProximity);
			expect(detectAutoForwarder(instructions)).toBe(false);
		});

		it('rejects CALL before SELFBALANCE (wrong order)', () => {
			const instructions = parseBytecode(AUTO_FORWARDER_CONTRACTS.reversedOrder);
			expect(detectAutoForwarder(instructions)).toBe(false);
		});

		it('rejects SELFBALANCE at end without trailing CALL', () => {
			const instructions = parseBytecode(AUTO_FORWARDER_CONTRACTS.selfBalanceAtEnd);
			expect(detectAutoForwarder(instructions)).toBe(false);
		});
	});
});

describe('detectUnlimitedApproval', () => {
	describe('should detect PUSH32 with all 0xFF', () => {
		it('detects max uint256', () => {
			const instructions = parseBytecode(UNLIMITED_APPROVAL_CONTRACTS.maxUint256);
			expect(detectUnlimitedApproval(instructions)).toBe(true);
		});
	});

	describe('should NOT detect partial patterns', () => {
		it('rejects partial 0xFF bytes', () => {
			const instructions = parseBytecode(UNLIMITED_APPROVAL_CONTRACTS.partialFF);
			expect(detectUnlimitedApproval(instructions)).toBe(false);
		});

		it('rejects all zeros', () => {
			const instructions = parseBytecode(UNLIMITED_APPROVAL_CONTRACTS.allZeros);
			expect(detectUnlimitedApproval(instructions)).toBe(false);
		});

		it('rejects almost-max (one byte different)', () => {
			const instructions = parseBytecode(UNLIMITED_APPROVAL_CONTRACTS.almostMax);
			expect(detectUnlimitedApproval(instructions)).toBe(false);
		});

		it('rejects truncated PUSH32 with only 0xFF bytes at EOF', () => {
			// PUSH32 opcode (0x7f) followed by only 3 bytes of 0xFF — truncated.
			// Previous implementation would return true via Array.every on the short slice;
			// the hardened detector now requires data.length === 32.
			const instructions = parseBytecode('0x7fffffff');
			expect(instructions[0]?.opcode).toBe('PUSH32');
			expect(instructions[0]?.truncated).toBe(true);
			expect(detectUnlimitedApproval(instructions)).toBe(false);
		});
	});
});

describe('detectChainId', () => {
	describe('should detect CHAINID opcode', () => {
		it('detects minimal CHAINID', () => {
			const instructions = parseBytecode(CHAINID_CONTRACTS.minimal);
			const result = detectChainId(instructions);
			expect(result.hasChainId).toBe(true);
			expect(result.hasBranching).toBe(false);
			expect(result.hasComparison).toBe(false);
			expect(result.isEip712Pattern).toBe(false);
		});

		it('detects CHAINID with no branching', () => {
			const instructions = parseBytecode(CHAINID_CONTRACTS.noBranching);
			const result = detectChainId(instructions);
			expect(result.hasChainId).toBe(true);
			expect(result.hasBranching).toBe(false);
		});
	});

	describe('should detect CHAINID with branching pattern', () => {
		it('detects CHAINID followed by JUMPI', () => {
			const instructions = parseBytecode(CHAINID_CONTRACTS.withBranching);
			const result = detectChainId(instructions);
			expect(result.hasChainId).toBe(true);
			expect(result.hasBranching).toBe(true);
		});

		it('detects branching even when spaced apart', () => {
			const instructions = parseBytecode(CHAINID_CONTRACTS.branchingSpaced);
			const result = detectChainId(instructions);
			expect(result.hasChainId).toBe(true);
			expect(result.hasBranching).toBe(true);
		});
	});

	describe('should detect CHAINID with comparison opcodes', () => {
		it('detects CHAINID with EQ', () => {
			const instructions = parseBytecode(CHAINID_CONTRACTS.withComparison);
			const result = detectChainId(instructions);
			expect(result.hasChainId).toBe(true);
			expect(result.hasComparison).toBe(true);
		});

		it('detects CHAINID with LT', () => {
			const instructions = parseBytecode(CHAINID_CONTRACTS.withComparisonLT);
			const result = detectChainId(instructions);
			expect(result.hasChainId).toBe(true);
			expect(result.hasComparison).toBe(true);
		});

		it('detects CHAINID with GT', () => {
			const instructions = parseBytecode(CHAINID_CONTRACTS.withComparisonGT);
			const result = detectChainId(instructions);
			expect(result.hasChainId).toBe(true);
			expect(result.hasComparison).toBe(true);
		});

		it('detects CHAINID with SLT', () => {
			const instructions = parseBytecode(CHAINID_CONTRACTS.withComparisonSLT);
			const result = detectChainId(instructions);
			expect(result.hasChainId).toBe(true);
			expect(result.hasComparison).toBe(true);
		});

		it('detects CHAINID with SGT', () => {
			const instructions = parseBytecode(CHAINID_CONTRACTS.withComparisonSGT);
			const result = detectChainId(instructions);
			expect(result.hasChainId).toBe(true);
			expect(result.hasComparison).toBe(true);
		});

		it('detects CHAINID with both branching and comparison', () => {
			const instructions = parseBytecode(CHAINID_CONTRACTS.withBranchingAndComparison);
			const result = detectChainId(instructions);
			expect(result.hasChainId).toBe(true);
			expect(result.hasBranching).toBe(true);
			expect(result.hasComparison).toBe(true);
		});
	});

	describe('should detect EIP-712 pattern (CHAINID -> KECCAK256)', () => {
		it('detects EIP-712 pattern with setup code', () => {
			const instructions = parseBytecode(CHAINID_CONTRACTS.eip712Pattern);
			const result = detectChainId(instructions);
			expect(result.hasChainId).toBe(true);
			expect(result.isEip712Pattern).toBe(true);
		});

		it('detects direct CHAINID -> KECCAK256', () => {
			const instructions = parseBytecode(CHAINID_CONTRACTS.eip712PatternDirect);
			const result = detectChainId(instructions);
			expect(result.hasChainId).toBe(true);
			expect(result.isEip712Pattern).toBe(true);
		});

		it('detects EIP-712 in complex bytecode', () => {
			const instructions = parseBytecode(CHAINID_CONTRACTS.eip712Complex);
			const result = detectChainId(instructions);
			expect(result.hasChainId).toBe(true);
			expect(result.isEip712Pattern).toBe(true);
		});
	});

	describe('should NOT false positive on 0x46 as data', () => {
		it('ignores 0x46 inside PUSH2 data', () => {
			const instructions = parseBytecode(CHAINID_CONTRACTS.x46AsPushData);
			const result = detectChainId(instructions);
			expect(result.hasChainId).toBe(false);
		});

		it('ignores 0x46 inside PUSH1 data', () => {
			const instructions = parseBytecode(CHAINID_CONTRACTS.x46AsPush1Data);
			const result = detectChainId(instructions);
			expect(result.hasChainId).toBe(false);
		});
	});

	describe('should return false for safe contracts', () => {
		it('returns false for simple arithmetic', () => {
			const instructions = parseBytecode(SAFE_CONTRACTS.simpleAdd);
			const result = detectChainId(instructions);
			expect(result.hasChainId).toBe(false);
		});

		it('returns false for empty bytecode', () => {
			const instructions = parseBytecode(SAFE_CONTRACTS.empty);
			const result = detectChainId(instructions);
			expect(result.hasChainId).toBe(false);
		});
	});
});

describe('metamorphic pattern detection', () => {
	it('detects CREATE2 + SELFDESTRUCT combination', () => {
		const instructions = parseBytecode(CREATE2_CONTRACTS.metamorphic);
		const result = runAllDetectors(instructions);

		expect(result.hasCreate2).toBe(true);
		expect(result.hasSelfDestruct).toBe(true);
	});

	it('detects pattern regardless of order (SELFDESTRUCT first)', () => {
		const instructions = parseBytecode(CREATE2_CONTRACTS.metamorphicReverse);
		const result = runAllDetectors(instructions);

		expect(result.hasCreate2).toBe(true);
		expect(result.hasSelfDestruct).toBe(true);
	});

	it('detects metamorphic pattern in complex code', () => {
		const instructions = parseBytecode(CREATE2_CONTRACTS.metamorphicWithCode);
		const result = runAllDetectors(instructions);

		expect(result.hasCreate2).toBe(true);
		expect(result.hasSelfDestruct).toBe(true);
	});
});

describe('runAllDetectors', () => {
	describe('multi-threat contracts', () => {
		it('detects all threats in combined contract', () => {
			const instructions = parseBytecode(MULTI_THREAT_CONTRACTS.allThreats);
			const result = runAllDetectors(instructions);

			expect(result.hasSelfDestruct).toBe(true);
			expect(result.isDelegatedCall).toBe(true);
			expect(result.hasAutoForwarder).toBe(true);
		});

		it('detects delegatecall + selfdestruct combo', () => {
			const instructions = parseBytecode(MULTI_THREAT_CONTRACTS.delegateAndDestruct);
			const result = runAllDetectors(instructions);

			expect(result.hasSelfDestruct).toBe(true);
			expect(result.isDelegatedCall).toBe(true);
			expect(result.hasAutoForwarder).toBe(false);
		});

		it('detects sweeper + unlimited approval combo', () => {
			const instructions = parseBytecode(MULTI_THREAT_CONTRACTS.sweeperWithApproval);
			const result = runAllDetectors(instructions);

			expect(result.hasAutoForwarder).toBe(true);
			expect(result.hasUnlimitedApprovals).toBe(true);
		});
	});

	describe('safe contracts', () => {
		it('returns all false for simple add', () => {
			const instructions = parseBytecode(SAFE_CONTRACTS.simpleAdd);
			const result = runAllDetectors(instructions);

			expect(result.hasSelfDestruct).toBe(false);
			expect(result.isDelegatedCall).toBe(false);
			expect(result.hasCallcode).toBe(false);
			expect(result.hasAutoForwarder).toBe(false);
			expect(result.hasUnlimitedApprovals).toBe(false);
			expect(result.hasCreate2).toBe(false);
			expect(result.hasChainId).toBe(false);
			expect(result.hasChainIdBranching).toBe(false);
			expect(result.hasChainIdComparison).toBe(false);
			expect(result.isEip712Pattern).toBe(false);
			expect(result.hasTxOrigin).toBe(false);
			expect(result.hasTimestampDependence).toBe(false);
			expect(result.hasMulticall).toBe(false);
			expect(result.hasExtcodesizeGuard).toBe(false);
			expect(result.hasErc4337Pattern).toBe(false);
			expect(result.hasCoinbaseDependence).toBe(false);
			expect(result.hasMinimalProxy).toBe(false);
			expect(result.hasDiamondProxy).toBe(false);
			expect(result.proxy.isProxy).toBe(false);
			expect(result.tokenTransfer.contextualRisk).toBe('LOW');
		});

		it('handles empty bytecode', () => {
			const instructions = parseBytecode(SAFE_CONTRACTS.empty);
			const result = runAllDetectors(instructions);

			expect(result.hasSelfDestruct).toBe(false);
			expect(result.isDelegatedCall).toBe(false);
			expect(result.hasCallcode).toBe(false);
			expect(result.hasAutoForwarder).toBe(false);
			expect(result.hasUnlimitedApprovals).toBe(false);
			expect(result.hasCreate2).toBe(false);
			expect(result.hasChainId).toBe(false);
			expect(result.hasChainIdBranching).toBe(false);
			expect(result.hasChainIdComparison).toBe(false);
			expect(result.isEip712Pattern).toBe(false);
			expect(result.hasTxOrigin).toBe(false);
			expect(result.hasTimestampDependence).toBe(false);
			expect(result.hasMulticall).toBe(false);
			expect(result.hasExtcodesizeGuard).toBe(false);
			expect(result.hasErc4337Pattern).toBe(false);
			expect(result.hasCoinbaseDependence).toBe(false);
			expect(result.hasMinimalProxy).toBe(false);
			expect(result.hasDiamondProxy).toBe(false);
			expect(result.proxy.isProxy).toBe(false);
			expect(result.tokenTransfer.contextualRisk).toBe('LOW');
		});

		it('handles just STOP', () => {
			const instructions = parseBytecode(SAFE_CONTRACTS.justStop);
			const result = runAllDetectors(instructions);

			expect(result.hasSelfDestruct).toBe(false);
			expect(result.isDelegatedCall).toBe(false);
			expect(result.hasCreate2).toBe(false);
			expect(result.hasChainId).toBe(false);
			expect(result.hasChainIdComparison).toBe(false);
			expect(result.isEip712Pattern).toBe(false);
			expect(result.hasErc4337Pattern).toBe(false);
			expect(result.hasCoinbaseDependence).toBe(false);
		});
	});

	describe('chainid detection', () => {
		it('detects CHAINID with branching via runAllDetectors', () => {
			const instructions = parseBytecode(CHAINID_CONTRACTS.withBranching);
			const result = runAllDetectors(instructions);

			expect(result.hasChainId).toBe(true);
			expect(result.hasChainIdBranching).toBe(true);
		});

		it('detects CHAINID without branching via runAllDetectors', () => {
			const instructions = parseBytecode(CHAINID_CONTRACTS.minimal);
			const result = runAllDetectors(instructions);

			expect(result.hasChainId).toBe(true);
			expect(result.hasChainIdBranching).toBe(false);
		});

		it('detects CHAINID with comparison via runAllDetectors', () => {
			const instructions = parseBytecode(CHAINID_CONTRACTS.withComparison);
			const result = runAllDetectors(instructions);

			expect(result.hasChainId).toBe(true);
			expect(result.hasChainIdComparison).toBe(true);
		});

		it('detects CHAINID with branching and comparison via runAllDetectors', () => {
			const instructions = parseBytecode(CHAINID_CONTRACTS.withBranchingAndComparison);
			const result = runAllDetectors(instructions);

			expect(result.hasChainId).toBe(true);
			expect(result.hasChainIdBranching).toBe(true);
			expect(result.hasChainIdComparison).toBe(true);
		});

		it('detects EIP-712 pattern via runAllDetectors', () => {
			const instructions = parseBytecode(CHAINID_CONTRACTS.eip712Pattern);
			const result = runAllDetectors(instructions);

			expect(result.hasChainId).toBe(true);
			expect(result.isEip712Pattern).toBe(true);
		});
	});
});

describe('parseBytecode', () => {
	it('correctly separates PUSH data from opcodes', () => {
		const instructions = parseBytecode('0x60ff00');

		expect(instructions).toHaveLength(2);
		expect(instructions[0].opcode).toBe('PUSH1');
		expect(instructions[0].data?.[0]).toBe(0xff);
		expect(instructions[1].opcode).toBe('STOP');
	});

	it('handles PUSH32 correctly', () => {
		const bytecode = `0x7f${'ab'.repeat(32)}`;
		const instructions = parseBytecode(bytecode);

		expect(instructions).toHaveLength(1);
		expect(instructions[0].opcode).toBe('PUSH32');
		expect(instructions[0].data).toHaveLength(32);
	});

	it('handles bytecode without 0x prefix', () => {
		const instructions = parseBytecode('ff');
		expect(instructions).toHaveLength(1);
		expect(instructions[0].opcode).toBe('SELFDESTRUCT');
	});

	it('tracks correct byte indices', () => {
		const instructions = parseBytecode('0x60016002');

		expect(instructions[0].byteIndex).toBe(0);
		expect(instructions[1].byteIndex).toBe(2);
	});
});

describe('detectTokenSelectors', () => {
	describe('should detect ERC20 selectors', () => {
		it('detects transfer selector', () => {
			const instructions = parseBytecode(TOKEN_TRANSFER_CONTRACTS.erc20Transfer);
			const result = detectTokenSelectors(instructions);
			expect(result).toHaveLength(1);
			expect(result[0].name).toBe('transfer');
			expect(result[0].standard).toBe('ERC20');
			expect(result[0].type).toBe('transfer');
		});

		it('detects transferFrom selector', () => {
			const instructions = parseBytecode(TOKEN_TRANSFER_CONTRACTS.erc20TransferFrom);
			const result = detectTokenSelectors(instructions);
			expect(result).toHaveLength(1);
			expect(result[0].name).toBe('transferFrom');
			expect(result[0].standard).toBe('ERC20');
		});

		it('detects approve selector', () => {
			const instructions = parseBytecode(TOKEN_TRANSFER_CONTRACTS.erc20Approve);
			const result = detectTokenSelectors(instructions);
			expect(result).toHaveLength(1);
			expect(result[0].name).toBe('approve');
			expect(result[0].type).toBe('approval');
		});

		it('detects increaseAllowance selector', () => {
			const instructions = parseBytecode(TOKEN_TRANSFER_CONTRACTS.erc20IncreaseAllowance);
			const result = detectTokenSelectors(instructions);
			expect(result).toHaveLength(1);
			expect(result[0].name).toBe('increaseAllowance');
			expect(result[0].type).toBe('approval');
		});
	});

	describe('should detect ERC721 selectors', () => {
		it('detects safeTransferFrom selector', () => {
			const instructions = parseBytecode(TOKEN_TRANSFER_CONTRACTS.erc721SafeTransfer);
			const result = detectTokenSelectors(instructions);
			expect(result).toHaveLength(1);
			expect(result[0].name).toBe('safeTransferFrom');
			expect(result[0].standard).toBe('ERC721');
		});

		it('detects setApprovalForAll selector', () => {
			const instructions = parseBytecode(TOKEN_TRANSFER_CONTRACTS.erc721SetApprovalForAll);
			const result = detectTokenSelectors(instructions);
			expect(result).toHaveLength(1);
			expect(result[0].name).toBe('setApprovalForAll');
			expect(result[0].type).toBe('approval');
		});
	});

	describe('should detect Permit/Permit2 selectors', () => {
		it('detects ERC20 permit selector (EIP-2612)', () => {
			const instructions = parseBytecode(TOKEN_TRANSFER_CONTRACTS.erc20Permit);
			const result = detectTokenSelectors(instructions);
			expect(result).toHaveLength(1);
			expect(result[0].name).toBe('permit');
			expect(result[0].standard).toBe('ERC20');
			expect(result[0].type).toBe('approval');
		});

		it('detects Permit2 permitTransferFrom selector', () => {
			const instructions = parseBytecode(TOKEN_TRANSFER_CONTRACTS.permit2TransferFrom);
			const result = detectTokenSelectors(instructions);
			expect(result).toHaveLength(1);
			expect(result[0].name).toBe('permitTransferFrom');
			expect(result[0].standard).toBe('Permit2');
			expect(result[0].type).toBe('permit');
		});

		it('detects Permit2 permitTransferFromBatch selector', () => {
			const instructions = parseBytecode(TOKEN_TRANSFER_CONTRACTS.permit2TransferFromBatch);
			const result = detectTokenSelectors(instructions);
			expect(result).toHaveLength(1);
			expect(result[0].name).toBe('permitTransferFromBatch');
			expect(result[0].standard).toBe('Permit2');
			expect(result[0].type).toBe('permit');
		});
	});

	describe('should detect ERC1155 selectors', () => {
		it('detects ERC1155 safeTransferFrom selector', () => {
			const instructions = parseBytecode(TOKEN_TRANSFER_CONTRACTS.erc1155SafeTransfer);
			const result = detectTokenSelectors(instructions);
			expect(result).toHaveLength(1);
			expect(result[0].standard).toBe('ERC1155');
		});

		it('detects safeBatchTransferFrom selector', () => {
			const instructions = parseBytecode(TOKEN_TRANSFER_CONTRACTS.erc1155BatchTransfer);
			const result = detectTokenSelectors(instructions);
			expect(result).toHaveLength(1);
			expect(result[0].name).toBe('safeBatchTransferFrom');
			expect(result[0].type).toBe('batch');
		});
	});

	describe('should handle multiple selectors', () => {
		it('detects multiple selectors in one contract', () => {
			const instructions = parseBytecode(TOKEN_TRANSFER_CONTRACTS.multipleSelectors);
			const result = detectTokenSelectors(instructions);
			expect(result).toHaveLength(3);
		});
	});

	describe('should NOT false positive', () => {
		it('ignores selector in PUSH32 data', () => {
			const instructions = parseBytecode(TOKEN_TRANSFER_CONTRACTS.selectorInPush32NotDetected);
			const result = detectTokenSelectors(instructions);
			expect(result).toHaveLength(0);
		});

		it('returns empty for no token selectors', () => {
			const instructions = parseBytecode(TOKEN_TRANSFER_CONTRACTS.noTokenSelectors);
			const result = detectTokenSelectors(instructions);
			expect(result).toHaveLength(0);
		});
	});
});

describe('detectEcrecover', () => {
	it('detects ecrecover with KECCAK256 + PUSH1 0x01 + STATICCALL', () => {
		const instructions = parseBytecode(AUTHORIZATION_CONTRACTS.withEcrecover);
		expect(detectEcrecover(instructions)).toBe(true);
	});

	it('detects ecrecover with STATICCALL + PUSH20 address 0x01', () => {
		const instructions = parseBytecode(AUTHORIZATION_CONTRACTS.withEcrecoverPush20);
		expect(detectEcrecover(instructions)).toBe(true);
	});

	it('detects ecrecover with KECCAK256 + PUSH1 0x01 + CALL (older contracts)', () => {
		const instructions = parseBytecode(AUTHORIZATION_CONTRACTS.withEcrecoverCall);
		expect(detectEcrecover(instructions)).toBe(true);
	});

	it('detects ecrecover with CALL + PUSH20 address 0x01 (older contracts)', () => {
		const instructions = parseBytecode(AUTHORIZATION_CONTRACTS.withEcrecoverCallPush20);
		expect(detectEcrecover(instructions)).toBe(true);
	});

	it('returns false without ecrecover', () => {
		const instructions = parseBytecode(AUTHORIZATION_CONTRACTS.noAuth);
		expect(detectEcrecover(instructions)).toBe(false);
	});

	// AUDIT-3: a bare `PUSH1 0x01` is ubiquitous (loop counters, booleans, lengths).
	// It must NOT alone signal an ecrecover auth pattern, or an attacker can suppress
	// CRITICAL drainer warnings by inserting one stray opcode before any CALL.
	it('does NOT treat bare PUSH1 0x01 + CALL as ecrecover (drainer bypass)', () => {
		const instructions = parseBytecode('0x6001f1'); // PUSH1 0x01; CALL
		expect(detectEcrecover(instructions)).toBe(false);
	});

	it('does NOT treat bare PUSH1 0x01 + STATICCALL as ecrecover (no hash)', () => {
		const instructions = parseBytecode('0x6001fa'); // PUSH1 0x01; STATICCALL
		expect(detectEcrecover(instructions)).toBe(false);
	});

	it('detects real ecrecover: KECCAK256 + PUSH1 0x01 + STATICCALL', () => {
		// PUSH1 0x00; PUSH1 0x00; KECCAK256; PUSH1 0x01; STATICCALL
		const instructions = parseBytecode('0x60006000206001fa');
		expect(detectEcrecover(instructions)).toBe(true);
	});
});

describe('detectMsgSenderCheck', () => {
	it('detects CALLER + EQ pattern', () => {
		const instructions = parseBytecode(AUTHORIZATION_CONTRACTS.withMsgSenderCheck);
		expect(detectMsgSenderCheck(instructions)).toBe(true);
	});

	it('returns false without msg.sender check', () => {
		const instructions = parseBytecode(AUTHORIZATION_CONTRACTS.noAuth);
		expect(detectMsgSenderCheck(instructions)).toBe(false);
	});
});

describe('detectNonceTracking', () => {
	it('detects SLOAD + SSTORE pattern', () => {
		const instructions = parseBytecode(AUTHORIZATION_CONTRACTS.withNonceTracking);
		expect(detectNonceTracking(instructions)).toBe(true);
	});

	it('returns false without nonce tracking', () => {
		const instructions = parseBytecode(AUTHORIZATION_CONTRACTS.noAuth);
		expect(detectNonceTracking(instructions)).toBe(false);
	});
});

describe('detectFallbackLocation', () => {
	it('detects CALL after CALLDATASIZE without dispatcher', () => {
		const instructions = parseBytecode(FALLBACK_CONTRACTS.callInFallback);
		expect(detectFallbackLocation(instructions)).toBe(true);
	});

	it('returns false when dispatcher present', () => {
		const instructions = parseBytecode(FALLBACK_CONTRACTS.callWithDispatcher);
		expect(detectFallbackLocation(instructions)).toBe(false);
	});

	it('returns false without CALLDATASIZE', () => {
		const instructions = parseBytecode(FALLBACK_CONTRACTS.noCalldatasize);
		expect(detectFallbackLocation(instructions)).toBe(false);
	});
});

describe('detectHardcodedDestination', () => {
	it('detects hardcoded address before CALL', () => {
		const instructions = parseBytecode(HARDCODED_DESTINATION_CONTRACTS.hardcodedAddress);
		expect(detectHardcodedDestination(instructions)).toBe(true);
	});

	it('ignores zero address', () => {
		const instructions = parseBytecode(HARDCODED_DESTINATION_CONTRACTS.callerDestination);
		expect(detectHardcodedDestination(instructions)).toBe(false);
	});

	it('ignores precompile addresses', () => {
		const instructions = parseBytecode(HARDCODED_DESTINATION_CONTRACTS.precompileDestination);
		expect(detectHardcodedDestination(instructions)).toBe(false);
	});

	it('returns false without hardcoded address', () => {
		const instructions = parseBytecode(HARDCODED_DESTINATION_CONTRACTS.noHardcodedAddr);
		expect(detectHardcodedDestination(instructions)).toBe(false);
	});
});

describe('analyzeTokenTransfers', () => {
	describe('risk classification', () => {
		it('returns LOW for contracts without token operations', () => {
			const instructions = parseBytecode(SAFE_CONTRACTS.simpleAdd);
			const result = analyzeTokenTransfers(instructions);
			expect(result.contextualRisk).toBe('LOW');
			expect(result.hasTokenTransfer).toBe(false);
		});

		it('returns CRITICAL for transfer in fallback', () => {
			const instructions = parseBytecode(DRAINER_PATTERNS.crimeEnjoyerWithToken);
			const result = analyzeTokenTransfers(instructions);
			expect(result.contextualRisk).toBe('CRITICAL');
			expect(result.appearsInFallback).toBe(true);
		});

		it('returns HIGH for token ops without auth', () => {
			const instructions = parseBytecode(AUTHORIZATION_CONTRACTS.noAuth);
			const result = analyzeTokenTransfers(instructions);
			expect(result.contextualRisk).toBe('HIGH');
			expect(result.hasAuthorizationPattern).toBe(false);
		});

		it('returns HIGH for ecrecover without nonce tracking', () => {
			const instructions = parseBytecode(AUTHORIZATION_CONTRACTS.ecrecoverWithoutNonce);
			const result = analyzeTokenTransfers(instructions);
			expect(result.contextualRisk).toBe('HIGH');
			expect(result.hasEcrecover).toBe(true);
			expect(result.hasNonceTracking).toBe(false);
		});

		it('returns MEDIUM for token ops with auth', () => {
			const instructions = parseBytecode(DRAINER_PATTERNS.legitimateWithAuth);
			const result = analyzeTokenTransfers(instructions);
			expect(result.contextualRisk).toBe('MEDIUM');
			expect(result.hasAuthorizationPattern).toBe(true);
		});

		it('returns MEDIUM for safe wallet pattern', () => {
			const instructions = parseBytecode(DRAINER_PATTERNS.safeWalletPattern);
			const result = analyzeTokenTransfers(instructions);
			expect(result.contextualRisk).toBe('MEDIUM');
			expect(result.hasEcrecover).toBe(true);
			expect(result.hasNonceTracking).toBe(true);
		});

		it('returns CRITICAL for Permit2 without auth', () => {
			const instructions = parseBytecode(TOKEN_TRANSFER_CONTRACTS.permit2TransferFrom);
			const result = analyzeTokenTransfers(instructions);
			expect(result.contextualRisk).toBe('CRITICAL');
			expect(result.hasAuthorizationPattern).toBe(false);
			expect(result.detectedSelectors[0]?.type).toBe('permit');
		});
	});

	describe('integration with runAllDetectors', () => {
		it('includes token transfer analysis in detection results', () => {
			const instructions = parseBytecode(TOKEN_TRANSFER_CONTRACTS.erc20Transfer);
			const result = runAllDetectors(instructions);
			expect(result.tokenTransfer).toBeDefined();
			expect(result.tokenTransfer.hasTokenTransfer).toBe(true);
		});

		it('detects safe contracts correctly', () => {
			const instructions = parseBytecode(SAFE_CONTRACTS.simpleAdd);
			const result = runAllDetectors(instructions);
			expect(result.tokenTransfer.contextualRisk).toBe('LOW');
		});
	});
});

describe('detectProxyPattern', () => {
	it('detects EIP-1967 implementation slot', () => {
		const instructions = parseBytecode(PROXY_CONTRACTS.eip1967Implementation);
		const result = detectProxyPattern(instructions);
		expect(result.isProxy).toBe(true);
		expect(result.hasImplementationSlot).toBe(true);
		expect(result.hasAdminSlot).toBe(false);
		expect(result.hasBeaconSlot).toBe(false);
	});

	it('detects EIP-1967 admin slot', () => {
		const instructions = parseBytecode(PROXY_CONTRACTS.eip1967Admin);
		const result = detectProxyPattern(instructions);
		expect(result.isProxy).toBe(false);
		expect(result.hasAdminSlot).toBe(true);
	});

	it('detects EIP-1967 beacon slot', () => {
		const instructions = parseBytecode(PROXY_CONTRACTS.eip1967Beacon);
		const result = detectProxyPattern(instructions);
		expect(result.isProxy).toBe(true);
		expect(result.hasBeaconSlot).toBe(true);
	});

	it('detects full proxy with multiple slots', () => {
		const instructions = parseBytecode(PROXY_CONTRACTS.eip1967Full);
		const result = detectProxyPattern(instructions);
		expect(result.isProxy).toBe(true);
		expect(result.hasImplementationSlot).toBe(true);
		expect(result.hasAdminSlot).toBe(true);
	});

	it('returns false for non-proxy contracts', () => {
		const instructions = parseBytecode(PROXY_CONTRACTS.notProxy);
		const result = detectProxyPattern(instructions);
		expect(result.isProxy).toBe(false);
		expect(result.hasImplementationSlot).toBe(false);
	});
});

describe('detectTxOrigin', () => {
	it('detects ORIGIN + EQ pattern', () => {
		const instructions = parseBytecode(TX_ORIGIN_CONTRACTS.originEq);
		expect(detectTxOrigin(instructions)).toBe(true);
	});

	it('detects ORIGIN + CALLER + EQ pattern', () => {
		const instructions = parseBytecode(TX_ORIGIN_CONTRACTS.originCallerEq);
		expect(detectTxOrigin(instructions)).toBe(true);
	});

	it('returns false for ORIGIN without EQ', () => {
		const instructions = parseBytecode(TX_ORIGIN_CONTRACTS.originOnly);
		expect(detectTxOrigin(instructions)).toBe(false);
	});

	it('returns false when EQ is beyond lookahead window', () => {
		const instructions = parseBytecode(TX_ORIGIN_CONTRACTS.originFarFromEq);
		expect(detectTxOrigin(instructions)).toBe(false);
	});

	it('ignores ORIGIN opcode in PUSH data', () => {
		const instructions = parseBytecode(TX_ORIGIN_CONTRACTS.originInPushData);
		expect(detectTxOrigin(instructions)).toBe(false);
	});
});

describe('detectEip7702Delegation', () => {
	it('detects valid EIP-7702 delegation pointer', () => {
		expect(detectEip7702Delegation(EIP7702_CONTRACTS.validDelegation)).toBe(true);
	});

	it('rejects wrong prefix', () => {
		expect(detectEip7702Delegation(EIP7702_CONTRACTS.wrongPrefix)).toBe(false);
	});

	it('rejects too short bytecode', () => {
		expect(detectEip7702Delegation(EIP7702_CONTRACTS.tooShort)).toBe(false);
	});

	it('rejects too long bytecode', () => {
		expect(detectEip7702Delegation(EIP7702_CONTRACTS.tooLong)).toBe(false);
	});

	it('rejects normal bytecode', () => {
		expect(detectEip7702Delegation(EIP7702_CONTRACTS.normalBytecode)).toBe(false);
	});
});

describe('detectTimestampDependence', () => {
	it('detects TIMESTAMP + comparison + branching', () => {
		const instructions = parseBytecode(TIMESTAMP_CONTRACTS.withComparisonAndBranch);
		expect(detectTimestampDependence(instructions)).toBe(true);
	});

	it('detects TIMESTAMP + GT + branching', () => {
		const instructions = parseBytecode(TIMESTAMP_CONTRACTS.withGtAndBranch);
		expect(detectTimestampDependence(instructions)).toBe(true);
	});

	it('returns false for TIMESTAMP alone', () => {
		const instructions = parseBytecode(TIMESTAMP_CONTRACTS.timestampOnly);
		expect(detectTimestampDependence(instructions)).toBe(false);
	});

	it('returns false for TIMESTAMP without comparison', () => {
		const instructions = parseBytecode(TIMESTAMP_CONTRACTS.timestampNoComparison);
		expect(detectTimestampDependence(instructions)).toBe(false);
	});

	it('ignores TIMESTAMP in PUSH data', () => {
		const instructions = parseBytecode(TIMESTAMP_CONTRACTS.inPushData);
		expect(detectTimestampDependence(instructions)).toBe(false);
	});
});

describe('improved detectNonceTracking', () => {
	it('detects SLOAD + ADD + SSTORE increment pattern', () => {
		const instructions = parseBytecode(NONCE_TRACKING_CONTRACTS.incrementPattern);
		expect(detectNonceTracking(instructions)).toBe(true);
	});

	it('detects SLOAD + SUB + SSTORE decrement pattern', () => {
		const instructions = parseBytecode(NONCE_TRACKING_CONTRACTS.subtractPattern);
		expect(detectNonceTracking(instructions)).toBe(true);
	});

	it('returns false for SLOAD without arithmetic before SSTORE', () => {
		const instructions = parseBytecode(NONCE_TRACKING_CONTRACTS.sloadWithoutArithmetic);
		expect(detectNonceTracking(instructions)).toBe(false);
	});

	it('returns false for SSTORE without prior SLOAD', () => {
		const instructions = parseBytecode(NONCE_TRACKING_CONTRACTS.sstoreWithoutSload);
		expect(detectNonceTracking(instructions)).toBe(false);
	});
});

describe('decreaseAllowance selector', () => {
	it('detects decreaseAllowance as approval type', () => {
		const instructions = parseBytecode(DECREASE_ALLOWANCE_CONTRACTS.decreaseAllowance);
		const result = detectTokenSelectors(instructions);
		expect(result).toHaveLength(1);
		expect(result[0].name).toBe('decreaseAllowance');
		expect(result[0].standard).toBe('ERC20');
		expect(result[0].type).toBe('approval');
	});
});

describe('detectMulticall', () => {
	it('detects multicall(bytes[]) selector', () => {
		const instructions = parseBytecode(MULTICALL_CONTRACTS.multicall);
		expect(detectMulticall(instructions)).toBe(true);
	});

	it('detects aggregate() selector', () => {
		const instructions = parseBytecode(MULTICALL_CONTRACTS.aggregate);
		expect(detectMulticall(instructions)).toBe(true);
	});

	it('detects tryAggregate() selector', () => {
		const instructions = parseBytecode(MULTICALL_CONTRACTS.tryAggregate);
		expect(detectMulticall(instructions)).toBe(true);
	});

	it('detects aggregate3() selector', () => {
		const instructions = parseBytecode(MULTICALL_CONTRACTS.aggregate3);
		expect(detectMulticall(instructions)).toBe(true);
	});

	it('returns false for contracts without multicall', () => {
		const instructions = parseBytecode(MULTICALL_CONTRACTS.noMulticall);
		expect(detectMulticall(instructions)).toBe(false);
	});

	it('ignores selector inside PUSH32 data', () => {
		const instructions = parseBytecode(MULTICALL_CONTRACTS.selectorInPush32);
		expect(detectMulticall(instructions)).toBe(false);
	});
});

describe('detectExtcodesizeGuard', () => {
	it('detects EXTCODESIZE + ISZERO pattern', () => {
		const instructions = parseBytecode(EXTCODESIZE_CONTRACTS.withIszero);
		expect(detectExtcodesizeGuard(instructions)).toBe(true);
	});

	it('detects EXTCODESIZE + EQ pattern', () => {
		const instructions = parseBytecode(EXTCODESIZE_CONTRACTS.withEq);
		expect(detectExtcodesizeGuard(instructions)).toBe(true);
	});

	it('detects EXTCODESIZE + GT pattern', () => {
		const instructions = parseBytecode(EXTCODESIZE_CONTRACTS.withGt);
		expect(detectExtcodesizeGuard(instructions)).toBe(true);
	});

	it('returns false for EXTCODESIZE without comparison', () => {
		const instructions = parseBytecode(EXTCODESIZE_CONTRACTS.alone);
		expect(detectExtcodesizeGuard(instructions)).toBe(false);
	});

	it('ignores EXTCODESIZE opcode in PUSH data', () => {
		const instructions = parseBytecode(EXTCODESIZE_CONTRACTS.inPushData);
		expect(detectExtcodesizeGuard(instructions)).toBe(false);
	});
});

describe('detectErc4337Pattern', () => {
	it('detects handleOps selector', () => {
		const instructions = parseBytecode(ERC4337_CONTRACTS.handleOpsSelector);
		expect(detectErc4337Pattern(instructions)).toBe(true);
	});

	it('detects handleAggregatedOps selector', () => {
		const instructions = parseBytecode(ERC4337_CONTRACTS.handleAggregatedOpsSelector);
		expect(detectErc4337Pattern(instructions)).toBe(true);
	});

	it('detects validateUserOp selector', () => {
		const instructions = parseBytecode(ERC4337_CONTRACTS.validateUserOpSelector);
		expect(detectErc4337Pattern(instructions)).toBe(true);
	});

	it('detects EntryPoint v0.6 address', () => {
		const instructions = parseBytecode(ERC4337_CONTRACTS.entryPointV06);
		expect(detectErc4337Pattern(instructions)).toBe(true);
	});

	it('detects EntryPoint v0.7 address', () => {
		const instructions = parseBytecode(ERC4337_CONTRACTS.entryPointV07);
		expect(detectErc4337Pattern(instructions)).toBe(true);
	});

	it('returns false for non-ERC-4337 contracts', () => {
		const instructions = parseBytecode(ERC4337_CONTRACTS.notErc4337);
		expect(detectErc4337Pattern(instructions)).toBe(false);
	});

	it('ignores selector inside PUSH32 data', () => {
		const instructions = parseBytecode(ERC4337_CONTRACTS.selectorInPush32);
		expect(detectErc4337Pattern(instructions)).toBe(false);
	});
});

describe('detectCoinbaseDependence', () => {
	it('detects COINBASE + comparison + branching', () => {
		const instructions = parseBytecode(COINBASE_CONTRACTS.withComparisonAndBranch);
		expect(detectCoinbaseDependence(instructions)).toBe(true);
	});

	it('detects COINBASE + GT + branching', () => {
		const instructions = parseBytecode(COINBASE_CONTRACTS.withGtAndBranch);
		expect(detectCoinbaseDependence(instructions)).toBe(true);
	});

	it('returns false for COINBASE alone', () => {
		const instructions = parseBytecode(COINBASE_CONTRACTS.coinbaseOnly);
		expect(detectCoinbaseDependence(instructions)).toBe(false);
	});

	it('returns false for COINBASE without comparison', () => {
		const instructions = parseBytecode(COINBASE_CONTRACTS.coinbaseNoComparison);
		expect(detectCoinbaseDependence(instructions)).toBe(false);
	});

	it('ignores COINBASE in PUSH data', () => {
		const instructions = parseBytecode(COINBASE_CONTRACTS.inPushData);
		expect(detectCoinbaseDependence(instructions)).toBe(false);
	});
});

describe('detectMinimalProxy', () => {
	it('detects canonical EIP-1167 minimal proxy', () => {
		expect(detectMinimalProxy(MINIMAL_PROXY_CONTRACTS.canonical)).toBe(true);
	});

	it('detects EIP-1167 with different implementation address', () => {
		expect(detectMinimalProxy(MINIMAL_PROXY_CONTRACTS.uniswapImpl)).toBe(true);
	});

	it('rejects wrong prefix', () => {
		expect(detectMinimalProxy(MINIMAL_PROXY_CONTRACTS.wrongPrefix)).toBe(false);
	});

	it('rejects wrong suffix', () => {
		expect(detectMinimalProxy(MINIMAL_PROXY_CONTRACTS.wrongSuffix)).toBe(false);
	});

	it('rejects too short bytecode', () => {
		expect(detectMinimalProxy(MINIMAL_PROXY_CONTRACTS.tooShort)).toBe(false);
	});

	it('rejects too long bytecode', () => {
		expect(detectMinimalProxy(MINIMAL_PROXY_CONTRACTS.tooLong)).toBe(false);
	});

	it('rejects normal bytecode', () => {
		expect(detectMinimalProxy(MINIMAL_PROXY_CONTRACTS.normalBytecode)).toBe(false);
	});

	it('returns false for undefined bytecode', () => {
		expect(detectMinimalProxy(undefined)).toBe(false);
	});

	it('detects via runAllDetectors with bytecode', () => {
		const instructions = parseBytecode(MINIMAL_PROXY_CONTRACTS.canonical);
		const result = runAllDetectors(instructions, MINIMAL_PROXY_CONTRACTS.canonical);
		expect(result.hasMinimalProxy).toBe(true);
		expect(result.isDelegatedCall).toBe(true);
	});
});

describe('detectDiamondProxy', () => {
	it('detects diamondCut selector', () => {
		const instructions = parseBytecode(DIAMOND_PROXY_CONTRACTS.diamondCutSelector);
		expect(detectDiamondProxy(instructions)).toBe(true);
	});

	it('detects facets selector', () => {
		const instructions = parseBytecode(DIAMOND_PROXY_CONTRACTS.facetsSelector);
		expect(detectDiamondProxy(instructions)).toBe(true);
	});

	it('detects facetAddress selector', () => {
		const instructions = parseBytecode(DIAMOND_PROXY_CONTRACTS.facetAddressSelector);
		expect(detectDiamondProxy(instructions)).toBe(true);
	});

	it('detects facetFunctionSelectors selector', () => {
		const instructions = parseBytecode(DIAMOND_PROXY_CONTRACTS.facetFunctionSelectorsSelector);
		expect(detectDiamondProxy(instructions)).toBe(true);
	});

	it('detects facetAddresses selector', () => {
		const instructions = parseBytecode(DIAMOND_PROXY_CONTRACTS.facetAddressesSelector);
		expect(detectDiamondProxy(instructions)).toBe(true);
	});

	it('returns false for non-diamond contracts', () => {
		const instructions = parseBytecode(DIAMOND_PROXY_CONTRACTS.notDiamond);
		expect(detectDiamondProxy(instructions)).toBe(false);
	});

	it('ignores selector inside PUSH32 data', () => {
		const instructions = parseBytecode(DIAMOND_PROXY_CONTRACTS.selectorInPush32);
		expect(detectDiamondProxy(instructions)).toBe(false);
	});
});

describe('detectReentrancyRisk', () => {
	it('detects CALL followed by SSTORE', () => {
		const instructions = parseBytecode(REENTRANCY_CONTRACTS.callThenSstore);
		expect(detectReentrancyRisk(instructions)).toBe(true);
	});

	it('returns false for STATICCALL followed by SSTORE (read-only)', () => {
		const instructions = parseBytecode(REENTRANCY_CONTRACTS.staticcallThenSstore);
		expect(detectReentrancyRisk(instructions)).toBe(false);
	});

	it('detects DELEGATECALL followed by SSTORE', () => {
		const instructions = parseBytecode(REENTRANCY_CONTRACTS.delegatecallThenSstore);
		expect(detectReentrancyRisk(instructions)).toBe(true);
	});

	it('detects CALLCODE followed by SSTORE', () => {
		const instructions = parseBytecode(REENTRANCY_CONTRACTS.callcodeThenSstore);
		expect(detectReentrancyRisk(instructions)).toBe(true);
	});

	it('returns false when SSTORE is before CALL (correct pattern)', () => {
		const instructions = parseBytecode(REENTRANCY_CONTRACTS.sstoreBeforeCall);
		expect(detectReentrancyRisk(instructions)).toBe(false);
	});

	it('returns false for CALL without SSTORE after', () => {
		const instructions = parseBytecode(REENTRANCY_CONTRACTS.callOnly);
		expect(detectReentrancyRisk(instructions)).toBe(false);
	});

	it('returns false for SSTORE without CALL before', () => {
		const instructions = parseBytecode(REENTRANCY_CONTRACTS.sstoreOnly);
		expect(detectReentrancyRisk(instructions)).toBe(false);
	});

	it('detects SSTORE at 14 instructions after CALL (inside window)', () => {
		const instructions = parseBytecode(REENTRANCY_CONTRACTS.atBoundaryInside);
		expect(detectReentrancyRisk(instructions)).toBe(true);
	});

	it('returns false when SSTORE is at boundary edge (15 instructions)', () => {
		const instructions = parseBytecode(REENTRANCY_CONTRACTS.atBoundaryEdge);
		expect(detectReentrancyRisk(instructions)).toBe(false);
	});

	it('returns false when SSTORE is beyond proximity window', () => {
		const instructions = parseBytecode(REENTRANCY_CONTRACTS.beyondProximity);
		expect(detectReentrancyRisk(instructions)).toBe(false);
	});

	it('sets hasReentrancyRisk in runAllDetectors', () => {
		const instructions = parseBytecode(REENTRANCY_CONTRACTS.callThenSstore);
		const results = runAllDetectors(instructions);
		expect(results.hasReentrancyRisk).toBe(true);
	});
});

describe('detectGasManipulation', () => {
	it('detects GAS with comparison and branch', () => {
		const instructions = parseBytecode(GAS_MANIPULATION_CONTRACTS.withComparisonAndBranch);
		expect(detectGasManipulation(instructions)).toBe(true);
	});

	it('detects GAS with GT and branch', () => {
		const instructions = parseBytecode(GAS_MANIPULATION_CONTRACTS.withGtAndBranch);
		expect(detectGasManipulation(instructions)).toBe(true);
	});

	it('returns false for GAS alone', () => {
		const instructions = parseBytecode(GAS_MANIPULATION_CONTRACTS.gasOnly);
		expect(detectGasManipulation(instructions)).toBe(false);
	});

	it('returns false for GAS without comparison', () => {
		const instructions = parseBytecode(GAS_MANIPULATION_CONTRACTS.gasNoComparison);
		expect(detectGasManipulation(instructions)).toBe(false);
	});

	it('ignores GAS in PUSH data', () => {
		const instructions = parseBytecode(GAS_MANIPULATION_CONTRACTS.inPushData);
		expect(detectGasManipulation(instructions)).toBe(false);
	});

	it('sets hasGasManipulation in runAllDetectors', () => {
		const instructions = parseBytecode(GAS_MANIPULATION_CONTRACTS.withComparisonAndBranch);
		const results = runAllDetectors(instructions);
		expect(results.hasGasManipulation).toBe(true);
	});
});

describe('detectExtcodehash', () => {
	it('detects EXTCODEHASH opcode', () => {
		const instructions = parseBytecode(EXTCODEHASH_CONTRACTS.minimal);
		expect(detectExtcodehash(instructions)).toBe(true);
	});

	it('detects EXTCODEHASH with comparison', () => {
		const instructions = parseBytecode(EXTCODEHASH_CONTRACTS.withComparison);
		expect(detectExtcodehash(instructions)).toBe(true);
	});

	it('ignores EXTCODEHASH in PUSH data', () => {
		const instructions = parseBytecode(EXTCODEHASH_CONTRACTS.inPushData);
		expect(detectExtcodehash(instructions)).toBe(false);
	});

	it('sets hasExtcodehash in runAllDetectors', () => {
		const instructions = parseBytecode(EXTCODEHASH_CONTRACTS.minimal);
		const results = runAllDetectors(instructions);
		expect(results.hasExtcodehash).toBe(true);
	});
});
