import {
	APPROVAL_SELECTORS,
	BATCH_SELECTORS,
	COMPARISON_OPCODES,
	OPCODES,
	TOKEN_SELECTORS,
} from './opcode';
import type {
	ChainIdDetectionResult,
	DetectionResults,
	Instruction,
	TokenSelector,
	TokenTransferAnalysis,
} from './types';

export function detectAutoForwarder(instructions: Instruction[]): boolean {
	let hasSelfBalance = false;
	let hasCall = false;

	for (const instruction of instructions) {
		if (instruction.opcode === OPCODES['47']) {
			hasSelfBalance = true;
		}
		if (instruction.opcode === OPCODES.F1) {
			hasCall = true;
		}
	}

	return hasSelfBalance && hasCall;
}

export function detectUnlimitedApproval(instructions: Instruction[]): boolean {
	for (const instruction of instructions) {
		if (instruction.opcode === OPCODES['7F']) {
			if (instruction.data?.every((byte) => byte === 0xff)) {
				return true;
			}
		}
	}

	return false;
}

export function detectDelegateCall(instructions: Instruction[]): boolean {
	for (const instruction of instructions) {
		if (instruction.opcode === OPCODES.F4) {
			return true;
		}
	}

	return false;
}

export function detectSelfDestruct(instructions: Instruction[]): boolean {
	for (const instruction of instructions) {
		if (instruction.opcode === OPCODES.FF) {
			return true;
		}
	}
	return false;
}

export function detectCreate2(instructions: Instruction[]): boolean {
	for (const instruction of instructions) {
		if (instruction.opcode === OPCODES.F5) {
			return true;
		}
	}
	return false;
}

export function detectChainId(instructions: Instruction[]): ChainIdDetectionResult {
	let hasChainId = false;
	let hasBranching = false;
	let hasComparison = false;
	let isEip712Pattern = false;

	for (let i = 0; i < instructions.length; i++) {
		const instruction = instructions[i];
		if (instruction.opcode === OPCODES['46']) {
			hasChainId = true;

			const lookAheadLimit = Math.min(i + 10, instructions.length);
			for (let j = i + 1; j < lookAheadLimit; j++) {
				const nextOpcode = instructions[j].opcode;

				if (nextOpcode === OPCODES['57']) {
					hasBranching = true;
				}

				if (COMPARISON_OPCODES.includes(nextOpcode as (typeof COMPARISON_OPCODES)[number])) {
					hasComparison = true;
				}

				if (nextOpcode === OPCODES['20']) {
					isEip712Pattern = true;
				}
			}
		}
	}

	return { hasChainId, hasBranching, hasComparison, isEip712Pattern };
}

const SELECTOR_NAME_MAP: Record<
	string,
	{ name: string; standard: 'ERC20' | 'ERC721' | 'ERC1155' }
> = {
	[TOKEN_SELECTORS.transfer]: { name: 'transfer', standard: 'ERC20' },
	[TOKEN_SELECTORS.transferFrom]: { name: 'transferFrom', standard: 'ERC20' },
	[TOKEN_SELECTORS.approve]: { name: 'approve', standard: 'ERC20' },
	[TOKEN_SELECTORS.increaseAllowance]: { name: 'increaseAllowance', standard: 'ERC20' },
	[TOKEN_SELECTORS.safeTransferFrom]: { name: 'safeTransferFrom', standard: 'ERC721' },
	[TOKEN_SELECTORS.safeTransferFromWithData]: {
		name: 'safeTransferFrom',
		standard: 'ERC721',
	},
	[TOKEN_SELECTORS.setApprovalForAll]: { name: 'setApprovalForAll', standard: 'ERC721' },
	[TOKEN_SELECTORS.safeTransferFrom1155]: { name: 'safeTransferFrom', standard: 'ERC1155' },
	[TOKEN_SELECTORS.safeBatchTransferFrom]: {
		name: 'safeBatchTransferFrom',
		standard: 'ERC1155',
	},
};

export function detectTokenSelectors(instructions: Instruction[]): TokenSelector[] {
	const detectedSelectors: TokenSelector[] = [];
	const allSelectors = Object.values(TOKEN_SELECTORS);

	for (const instruction of instructions) {
		if (instruction.opcode === 'PUSH4' && instruction.data) {
			const selectorHex = Array.from(instruction.data)
				.map((b) => b.toString(16).padStart(2, '0'))
				.join('');

			if (allSelectors.includes(selectorHex as (typeof allSelectors)[number])) {
				const info = SELECTOR_NAME_MAP[selectorHex];
				let type: 'transfer' | 'approval' | 'batch' = 'transfer';
				if (APPROVAL_SELECTORS.includes(selectorHex as (typeof APPROVAL_SELECTORS)[number])) {
					type = 'approval';
				} else if (BATCH_SELECTORS.includes(selectorHex as (typeof BATCH_SELECTORS)[number])) {
					type = 'batch';
				}

				detectedSelectors.push({
					selector: selectorHex,
					name: info?.name || 'unknown',
					standard: info?.standard || 'ERC20',
					type,
				});
			}
		}
	}

	return detectedSelectors;
}

export function detectEcrecover(instructions: Instruction[]): boolean {
	for (let i = 0; i < instructions.length; i++) {
		const instruction = instructions[i];
		// Check for both STATICCALL (0xFA) and CALL (0xF1) - older contracts use CALL for precompiles
		if (
			instruction.opcode === OPCODES.FA ||
			instruction.opcode === 'STATICCALL' ||
			instruction.opcode === OPCODES.F1 ||
			instruction.opcode === 'CALL'
		) {
			const lookBackLimit = Math.max(0, i - 10);
			for (let j = i - 1; j >= lookBackLimit; j--) {
				const prevInstruction = instructions[j];
				if (prevInstruction.opcode === 'PUSH1' && prevInstruction.data) {
					const value = prevInstruction.data[0];
					if (value === 0x01) {
						return true;
					}
				}
				if (prevInstruction.opcode === 'PUSH20' && prevInstruction.data) {
					const allZerosExceptLast =
						prevInstruction.data.slice(0, 19).every((b) => b === 0) &&
						prevInstruction.data[19] === 0x01;
					if (allZerosExceptLast) {
						return true;
					}
				}
			}
		}
	}

	return false;
}

export function detectMsgSenderCheck(instructions: Instruction[]): boolean {
	for (let i = 0; i < instructions.length; i++) {
		const instruction = instructions[i];
		if (instruction.opcode === OPCODES['33'] || instruction.opcode === 'CALLER') {
			const lookAheadLimit = Math.min(i + 5, instructions.length);
			for (let j = i + 1; j < lookAheadLimit; j++) {
				const nextOpcode = instructions[j].opcode;
				if (nextOpcode === OPCODES['14'] || nextOpcode === 'EQ') {
					return true;
				}
			}
		}
	}

	return false;
}

export function detectNonceTracking(instructions: Instruction[]): boolean {
	let hasSload = false;
	let hasSstore = false;

	for (const instruction of instructions) {
		if (instruction.opcode === OPCODES['54'] || instruction.opcode === 'SLOAD') {
			hasSload = true;
		}
		if (instruction.opcode === OPCODES['55'] || instruction.opcode === 'SSTORE') {
			hasSstore = true;
		}
	}

	return hasSload && hasSstore;
}

export function detectFallbackLocation(instructions: Instruction[]): boolean {
	const calldataSizeIdx = instructions.findIndex(
		(i) => i.opcode === OPCODES['36'] || i.opcode === 'CALLDATASIZE',
	);

	if (calldataSizeIdx === -1) {
		return false;
	}

	const callIdx = instructions.findIndex(
		(i, idx) => idx > calldataSizeIdx && (i.opcode === OPCODES.F1 || i.opcode === 'CALL'),
	);

	if (callIdx === -1) {
		return false;
	}

	const betweenInstructions = instructions.slice(calldataSizeIdx, callIdx);
	const hasDispatcher = betweenInstructions.some((i, idx, arr) => {
		if (i.opcode === 'PUSH4') {
			const nextInstruction = arr[idx + 1];
			if (
				nextInstruction &&
				(nextInstruction.opcode === OPCODES['14'] || nextInstruction.opcode === 'EQ')
			) {
				return true;
			}
		}
		return false;
	});

	return !hasDispatcher;
}

export function detectHardcodedDestination(instructions: Instruction[]): boolean {
	for (let i = 0; i < instructions.length; i++) {
		const instruction = instructions[i];
		if (instruction.opcode === OPCODES.F1 || instruction.opcode === 'CALL') {
			const lookBackLimit = Math.max(0, i - 15);
			for (let j = i - 1; j >= lookBackLimit; j--) {
				const prevInstruction = instructions[j];
				if (prevInstruction.opcode === 'PUSH20' && prevInstruction.data) {
					const isAllZeros = prevInstruction.data.every((b) => b === 0);
					const isCallerPattern =
						prevInstruction.data.slice(0, 19).every((b) => b === 0) &&
						prevInstruction.data[19] <= 0x09;
					if (!isAllZeros && !isCallerPattern) {
						return true;
					}
				}
			}
		}
	}

	return false;
}

export function analyzeTokenTransfers(instructions: Instruction[]): TokenTransferAnalysis {
	const detectedSelectors = detectTokenSelectors(instructions);
	const hasTokenTransfer = detectedSelectors.some((s) => s.type === 'transfer');
	const hasTokenApproval = detectedSelectors.some((s) => s.type === 'approval');
	const hasBatchOperations = detectedSelectors.some((s) => s.type === 'batch');

	const hasEcrecover = detectEcrecover(instructions);
	const hasMsgSenderCheck = detectMsgSenderCheck(instructions);
	const hasNonceTracking = detectNonceTracking(instructions);
	const hasAuthorizationPattern = hasEcrecover || hasMsgSenderCheck;

	const appearsInFallback = detectFallbackLocation(instructions);
	const hasHardcodedDestination = detectHardcodedDestination(instructions);

	const hasAnyTokenOps = hasTokenTransfer || hasTokenApproval || hasBatchOperations;
	let contextualRisk: TokenTransferAnalysis['contextualRisk'] = 'LOW';
	let riskReason = '';

	if (!hasAnyTokenOps) {
		contextualRisk = 'LOW';
		riskReason = 'No token transfer capabilities detected';
	} else if (hasTokenTransfer && appearsInFallback) {
		contextualRisk = 'CRITICAL';
		riskReason = 'Token transfer in fallback/receive function - automatic drain pattern';
	} else if (
		(hasTokenTransfer || hasTokenApproval) &&
		hasHardcodedDestination &&
		!hasAuthorizationPattern
	) {
		contextualRisk = 'CRITICAL';
		riskReason = 'Token operations to hardcoded address without authorization';
	} else if (
		hasTokenApproval &&
		detectedSelectors.some((s) => s.name === 'setApprovalForAll') &&
		!hasAuthorizationPattern
	) {
		contextualRisk = 'CRITICAL';
		riskReason = 'setApprovalForAll without access control - full collection drain risk';
	} else if (hasAnyTokenOps && !hasAuthorizationPattern) {
		contextualRisk = 'HIGH';
		riskReason = 'Token operations without signature verification or access controls';
	} else if (hasEcrecover && !hasNonceTracking) {
		contextualRisk = 'HIGH';
		riskReason = 'Signature verification present but no nonce tracking - replay attack risk';
	} else if (hasAnyTokenOps && hasAuthorizationPattern) {
		contextualRisk = 'MEDIUM';
		riskReason =
			'Token operations with authorization patterns detected - standard smart wallet behavior';
	}

	return {
		hasTokenTransfer,
		hasTokenApproval,
		hasBatchOperations,
		detectedSelectors,
		hasAuthorizationPattern,
		hasEcrecover,
		hasNonceTracking,
		appearsInFallback,
		hasHardcodedDestination,
		contextualRisk,
		riskReason,
	};
}

export function runAllDetectors(instructions: Instruction[]): DetectionResults {
	const chainIdResult = detectChainId(instructions);
	const tokenTransferResult = analyzeTokenTransfers(instructions);

	return {
		isDelegatedCall: detectDelegateCall(instructions),
		hasAutoForwarder: detectAutoForwarder(instructions),
		hasUnlimitedApprovals: detectUnlimitedApproval(instructions),
		hasSelfDestruct: detectSelfDestruct(instructions),
		hasCreate2: detectCreate2(instructions),
		hasChainId: chainIdResult.hasChainId,
		hasChainIdBranching: chainIdResult.hasBranching,
		hasChainIdComparison: chainIdResult.hasComparison,
		isEip712Pattern: chainIdResult.isEip712Pattern,
		tokenTransfer: tokenTransferResult,
	};
}
