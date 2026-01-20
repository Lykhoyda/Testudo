import { describe, expect, it } from 'vitest';
import { parseBytecode } from '../src';
import {
	analyzeTokenTransfers,
	detectAutoForwarder,
	detectChainId,
	detectCreate2,
	detectDelegateCall,
	detectEcrecover,
	detectFallbackLocation,
	detectHardcodedDestination,
	detectMsgSenderCheck,
	detectNonceTracking,
	detectSelfDestruct,
	detectTokenSelectors,
	detectUnlimitedApproval,
	runAllDetectors,
} from '../src/detectors';

import {
	AUTHORIZATION_CONTRACTS,
	AUTO_FORWARDER_CONTRACTS,
	CHAINID_CONTRACTS,
	CREATE2_CONTRACTS,
	DELEGATECALL_CONTRACTS,
	DRAINER_PATTERNS,
	FALLBACK_CONTRACTS,
	FALSE_POSITIVE_CONTRACTS,
	HARDCODED_DESTINATION_CONTRACTS,
	MULTI_THREAT_CONTRACTS,
	SAFE_CONTRACTS,
	SELFDESTRUCT_CONTRACTS,
	TOKEN_TRANSFER_CONTRACTS,
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
			expect(result.hasAutoForwarder).toBe(false);
			expect(result.hasUnlimitedApprovals).toBe(false);
			expect(result.hasCreate2).toBe(false);
			expect(result.hasChainId).toBe(false);
			expect(result.hasChainIdBranching).toBe(false);
			expect(result.hasChainIdComparison).toBe(false);
			expect(result.isEip712Pattern).toBe(false);
		});

		it('handles empty bytecode', () => {
			const instructions = parseBytecode(SAFE_CONTRACTS.empty);
			const result = runAllDetectors(instructions);

			expect(result.hasSelfDestruct).toBe(false);
			expect(result.isDelegatedCall).toBe(false);
			expect(result.hasAutoForwarder).toBe(false);
			expect(result.hasUnlimitedApprovals).toBe(false);
			expect(result.hasCreate2).toBe(false);
			expect(result.hasChainId).toBe(false);
			expect(result.hasChainIdBranching).toBe(false);
			expect(result.hasChainIdComparison).toBe(false);
			expect(result.isEip712Pattern).toBe(false);
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
		expect(instructions[1].opcode).toBe('00');
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
	it('detects ecrecover with STATICCALL + PUSH1 0x01', () => {
		const instructions = parseBytecode(AUTHORIZATION_CONTRACTS.withEcrecover);
		expect(detectEcrecover(instructions)).toBe(true);
	});

	it('detects ecrecover with STATICCALL + PUSH20 address 0x01', () => {
		const instructions = parseBytecode(AUTHORIZATION_CONTRACTS.withEcrecoverPush20);
		expect(detectEcrecover(instructions)).toBe(true);
	});

	it('detects ecrecover with CALL + PUSH1 0x01 (older contracts)', () => {
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
