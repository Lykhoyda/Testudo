import {
	APPROVAL_SELECTORS,
	BATCH_SELECTORS,
	COMPARISON_OPCODES,
	DIAMOND_SELECTORS,
	EIP1967_SLOTS,
	ERC4337_ENTRYPOINTS,
	ERC4337_SELECTORS,
	MULTICALL_SELECTORS,
	PERMIT2_SELECTORS,
	TOKEN_SELECTORS,
} from './opcode';
import type {
	ChainIdDetectionResult,
	DetectionResults,
	Instruction,
	ProxyDetectionResult,
	TokenSelector,
	TokenTransferAnalysis,
} from './types';

// Pre-computed Sets for O(1) lookups in hot paths (ReadonlySet prevents accidental mutation)
const COMPARISON_SET: ReadonlySet<string> = new Set(COMPARISON_OPCODES);
const TOKEN_SELECTOR_SET: ReadonlySet<string> = new Set(Object.values(TOKEN_SELECTORS));
const APPROVAL_SELECTOR_SET: ReadonlySet<string> = new Set(APPROVAL_SELECTORS);
const PERMIT2_SELECTOR_SET: ReadonlySet<string> = new Set(PERMIT2_SELECTORS);
const BATCH_SELECTOR_SET: ReadonlySet<string> = new Set(BATCH_SELECTORS);
const MULTICALL_SELECTOR_SET: ReadonlySet<string> = new Set(Object.values(MULTICALL_SELECTORS));
const DIAMOND_SELECTOR_SET: ReadonlySet<string> = new Set(Object.values(DIAMOND_SELECTORS));
const ERC4337_SELECTOR_SET: ReadonlySet<string> = new Set(Object.values(ERC4337_SELECTORS));
const ERC4337_ENTRYPOINT_SET: ReadonlySet<string> = new Set(ERC4337_ENTRYPOINTS);

/** Window sizes for opcode pattern look-ahead/look-back searches (instruction count). */
export const LOOK_AHEAD = {
	/** Trigger opcode → comparison opcodes → JUMPI branching (CHAINID, TIMESTAMP, COINBASE) */
	branching: 10,
	/** Tight auth checks: CALLER/ORIGIN/EXTCODESIZE → stack ops → EQ (usually immediate) */
	auth: 5,
	/** Nonce increment pattern: SLOAD → arithmetic (ADD/SUB) → SSTORE */
	nonce: 8,
	/** Address preparation: PUSH20 address → stack arg setup → CALL/STATICCALL */
	address: 15,
} as const;

function pushDataToHex(data: Uint8Array): string {
	return Array.from(data)
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

function hasPush4Selector(instructions: Instruction[], selectors: ReadonlySet<string>): boolean {
	for (const instruction of instructions) {
		if (instruction.opcode === 'PUSH4' && instruction.data) {
			const hex = pushDataToHex(instruction.data);
			if (selectors.has(hex)) {
				return true;
			}
		}
	}
	return false;
}

function detectComparisonBranching(instructions: Instruction[], triggerOpcode: string): boolean {
	for (let i = 0; i < instructions.length; i++) {
		if (instructions[i].opcode === triggerOpcode) {
			const lookAheadLimit = Math.min(i + LOOK_AHEAD.branching, instructions.length);
			let hasComparison = false;
			let hasBranching = false;
			for (let j = i + 1; j < lookAheadLimit; j++) {
				const op = instructions[j].opcode;
				if (COMPARISON_SET.has(op)) {
					hasComparison = true;
				}
				if (op === 'JUMPI') {
					hasBranching = true;
				}
			}
			if (hasComparison && hasBranching) {
				return true;
			}
		}
	}
	return false;
}

function hasOpcode(instructions: Instruction[], opcodeName: string): boolean {
	for (const instruction of instructions) {
		if (instruction.opcode === opcodeName) {
			return true;
		}
	}
	return false;
}

export function detectAutoForwarder(instructions: Instruction[]): boolean {
	for (let i = 0; i < instructions.length; i++) {
		if (instructions[i].opcode === 'SELFBALANCE') {
			const lookAheadLimit = Math.min(i + LOOK_AHEAD.address, instructions.length);
			for (let j = i + 1; j < lookAheadLimit; j++) {
				if (instructions[j].opcode === 'CALL') {
					return true;
				}
			}
		}
	}
	return false;
}

export function detectUnlimitedApproval(instructions: Instruction[]): boolean {
	for (const instruction of instructions) {
		if (
			instruction.opcode === 'PUSH32' &&
			!instruction.truncated &&
			instruction.data?.length === 32 &&
			instruction.data.every((byte) => byte === 0xff)
		) {
			return true;
		}
	}

	return false;
}

export function detectDelegateCall(instructions: Instruction[]): boolean {
	return hasOpcode(instructions, 'DELEGATECALL');
}

export function detectCallcode(instructions: Instruction[]): boolean {
	return hasOpcode(instructions, 'CALLCODE');
}

export function detectSelfDestruct(instructions: Instruction[]): boolean {
	return hasOpcode(instructions, 'SELFDESTRUCT');
}

export function detectCreate2(instructions: Instruction[]): boolean {
	return hasOpcode(instructions, 'CREATE2');
}

export function detectChainId(instructions: Instruction[]): ChainIdDetectionResult {
	let hasChainId = false;
	let hasBranching = false;
	let hasComparison = false;
	let isEip712Pattern = false;

	for (let i = 0; i < instructions.length; i++) {
		const instruction = instructions[i];
		if (instruction.opcode === 'CHAINID') {
			hasChainId = true;

			const lookAheadLimit = Math.min(i + LOOK_AHEAD.branching, instructions.length);
			for (let j = i + 1; j < lookAheadLimit; j++) {
				const nextOpcode = instructions[j].opcode;

				if (nextOpcode === 'JUMPI') {
					hasBranching = true;
				}

				if (COMPARISON_SET.has(nextOpcode)) {
					hasComparison = true;
				}

				if (nextOpcode === 'KECCAK256') {
					isEip712Pattern = true;
				}
			}
		}
	}

	return { hasChainId, hasBranching, hasComparison, isEip712Pattern };
}

const SELECTOR_NAME_MAP: Record<
	string,
	{ name: string; standard: 'ERC20' | 'ERC721' | 'ERC1155' | 'Permit2' }
> = {
	[TOKEN_SELECTORS.transfer]: { name: 'transfer', standard: 'ERC20' },
	[TOKEN_SELECTORS.transferFrom]: { name: 'transferFrom', standard: 'ERC20' },
	[TOKEN_SELECTORS.approve]: { name: 'approve', standard: 'ERC20' },
	[TOKEN_SELECTORS.increaseAllowance]: { name: 'increaseAllowance', standard: 'ERC20' },
	[TOKEN_SELECTORS.decreaseAllowance]: { name: 'decreaseAllowance', standard: 'ERC20' },
	[TOKEN_SELECTORS.permit]: { name: 'permit', standard: 'ERC20' },
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
	[TOKEN_SELECTORS.permitTransferFrom]: { name: 'permitTransferFrom', standard: 'Permit2' },
	[TOKEN_SELECTORS.permitTransferFromBatch]: {
		name: 'permitTransferFromBatch',
		standard: 'Permit2',
	},
};

export function detectTokenSelectors(instructions: Instruction[]): TokenSelector[] {
	const detectedSelectors: TokenSelector[] = [];

	for (const instruction of instructions) {
		if (instruction.opcode === 'PUSH4' && instruction.data) {
			const selectorHex = pushDataToHex(instruction.data);

			if (TOKEN_SELECTOR_SET.has(selectorHex)) {
				const info = SELECTOR_NAME_MAP[selectorHex];
				let type: 'transfer' | 'approval' | 'batch' | 'permit' = 'transfer';
				if (PERMIT2_SELECTOR_SET.has(selectorHex)) {
					type = 'permit';
				} else if (APPROVAL_SELECTOR_SET.has(selectorHex)) {
					type = 'approval';
				} else if (BATCH_SELECTOR_SET.has(selectorHex)) {
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
		if (instruction.opcode === 'STATICCALL' || instruction.opcode === 'CALL') {
			const lookBackLimit = Math.max(0, i - LOOK_AHEAD.address);
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
		if (instruction.opcode === 'CALLER') {
			const lookAheadLimit = Math.min(i + LOOK_AHEAD.branching, instructions.length);
			for (let j = i + 1; j < lookAheadLimit; j++) {
				const nextOpcode = instructions[j].opcode;
				if (nextOpcode === 'EQ') {
					return true;
				}
			}
		}
	}

	return false;
}

export function detectNonceTracking(instructions: Instruction[]): boolean {
	for (let i = 0; i < instructions.length; i++) {
		if (instructions[i].opcode !== 'SLOAD') continue;

		const afterSload = Math.min(i + LOOK_AHEAD.nonce, instructions.length);
		let hasArithmetic = false;
		let hasSstore = false;

		for (let j = i + 1; j < afterSload; j++) {
			const op = instructions[j].opcode;
			if (op === 'ADD' || op === 'SUB') {
				hasArithmetic = true;
			}
			if (op === 'SSTORE' && hasArithmetic) {
				hasSstore = true;
				break;
			}
		}

		if (hasArithmetic && hasSstore) {
			return true;
		}
	}

	return false;
}

export function detectFallbackLocation(instructions: Instruction[]): boolean {
	const calldataSizeIdx = instructions.findIndex((i) => i.opcode === 'CALLDATASIZE');

	if (calldataSizeIdx === -1) {
		return false;
	}

	const callIdx = instructions.findIndex((i, idx) => idx > calldataSizeIdx && i.opcode === 'CALL');

	if (callIdx === -1) {
		return false;
	}

	const betweenInstructions = instructions.slice(calldataSizeIdx, callIdx);
	const hasDispatcher = betweenInstructions.some((i, idx, arr) => {
		if (i.opcode === 'PUSH4') {
			const nextInstruction = arr[idx + 1];
			if (nextInstruction && nextInstruction.opcode === 'EQ') {
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
		if (instruction.opcode === 'CALL') {
			const lookBackLimit = Math.max(0, i - LOOK_AHEAD.address);
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
	const hasPermit2 = detectedSelectors.some((s) => s.type === 'permit');

	const hasEcrecover = detectEcrecover(instructions);
	const hasMsgSenderCheck = detectMsgSenderCheck(instructions);
	const hasNonceTracking = detectNonceTracking(instructions);
	const hasAuthorizationPattern = hasEcrecover || hasMsgSenderCheck;

	const appearsInFallback = detectFallbackLocation(instructions);
	const hasHardcodedDestination = detectHardcodedDestination(instructions);

	const hasAnyTokenOps = hasTokenTransfer || hasTokenApproval || hasBatchOperations || hasPermit2;
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
	} else if (hasPermit2 && !hasAuthorizationPattern) {
		contextualRisk = 'CRITICAL';
		riskReason = 'Permit2 gasless transfer without access control - immediate drain risk';
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

export function detectProxyPattern(instructions: Instruction[]): ProxyDetectionResult {
	let hasImplementationSlot = false;
	let hasAdminSlot = false;
	let hasBeaconSlot = false;

	for (const instruction of instructions) {
		if (instruction.opcode === 'PUSH32' && instruction.data) {
			const hex = pushDataToHex(instruction.data);
			if (hex === EIP1967_SLOTS.implementation) {
				hasImplementationSlot = true;
			} else if (hex === EIP1967_SLOTS.admin) {
				hasAdminSlot = true;
			} else if (hex === EIP1967_SLOTS.beacon) {
				hasBeaconSlot = true;
			}
		}
	}

	return {
		isProxy: hasImplementationSlot || hasBeaconSlot,
		hasImplementationSlot,
		hasAdminSlot,
		hasBeaconSlot,
	};
}

export function detectTxOrigin(instructions: Instruction[]): boolean {
	for (let i = 0; i < instructions.length; i++) {
		const instruction = instructions[i];
		if (instruction.opcode === 'ORIGIN') {
			const lookAheadLimit = Math.min(i + LOOK_AHEAD.auth, instructions.length);
			for (let j = i + 1; j < lookAheadLimit; j++) {
				if (instructions[j].opcode === 'EQ') {
					return true;
				}
			}
		}
	}
	return false;
}

export function detectTimestampDependence(instructions: Instruction[]): boolean {
	return detectComparisonBranching(instructions, 'TIMESTAMP');
}

export function detectMulticall(instructions: Instruction[]): boolean {
	return hasPush4Selector(instructions, MULTICALL_SELECTOR_SET);
}

export function detectExtcodesizeGuard(instructions: Instruction[]): boolean {
	for (let i = 0; i < instructions.length; i++) {
		if (instructions[i].opcode === 'EXTCODESIZE') {
			const lookAheadLimit = Math.min(i + LOOK_AHEAD.auth, instructions.length);
			for (let j = i + 1; j < lookAheadLimit; j++) {
				const op = instructions[j].opcode;
				if (op === 'ISZERO' || op === 'EQ' || op === 'GT') {
					return true;
				}
			}
		}
	}

	return false;
}

export function detectErc4337Pattern(instructions: Instruction[]): boolean {
	for (const instruction of instructions) {
		if (instruction.opcode === 'PUSH4' && instruction.data) {
			const hex = pushDataToHex(instruction.data);
			if (ERC4337_SELECTOR_SET.has(hex)) {
				return true;
			}
		}

		if (instruction.opcode === 'PUSH20' && instruction.data) {
			const addressHex = pushDataToHex(instruction.data);
			if (ERC4337_ENTRYPOINT_SET.has(addressHex)) {
				return true;
			}
		}
	}

	return false;
}

export function detectBalanceDrain(instructions: Instruction[]): boolean {
	for (let i = 0; i < instructions.length; i++) {
		if (instructions[i].opcode === 'BALANCE') {
			const lookAheadLimit = Math.min(i + LOOK_AHEAD.address, instructions.length);
			let hasComparison = false;
			for (let j = i + 1; j < lookAheadLimit; j++) {
				const op = instructions[j].opcode;
				if (COMPARISON_SET.has(op)) {
					hasComparison = true;
				}
				if (hasComparison && (op === 'CALL' || op === 'SELFDESTRUCT')) {
					return true;
				}
			}
		}
	}
	return false;
}

export function detectExtcodecopy(instructions: Instruction[]): boolean {
	return hasOpcode(instructions, 'EXTCODECOPY');
}

export function detectCoinbaseDependence(instructions: Instruction[]): boolean {
	return detectComparisonBranching(instructions, 'COINBASE');
}

// STATICCALL excluded: read-only by EVM spec, cannot cause reentrancy
const MUTABLE_CALL_SET: ReadonlySet<string> = new Set(['CALL', 'DELEGATECALL', 'CALLCODE']);

export function detectReentrancyRisk(instructions: Instruction[]): boolean {
	for (let i = 0; i < instructions.length; i++) {
		const op = instructions[i].opcode;
		if (MUTABLE_CALL_SET.has(op)) {
			const lookAheadLimit = Math.min(i + LOOK_AHEAD.address, instructions.length);
			for (let j = i + 1; j < lookAheadLimit; j++) {
				if (instructions[j].opcode === 'SSTORE') {
					return true;
				}
			}
		}
	}
	return false;
}

export function detectGasManipulation(instructions: Instruction[]): boolean {
	return detectComparisonBranching(instructions, 'GAS');
}

export function detectExtcodehash(instructions: Instruction[]): boolean {
	return hasOpcode(instructions, 'EXTCODEHASH');
}

export function detectMinimalProxy(bytecode?: string): boolean {
	if (!bytecode) return false;
	const clean = (bytecode.startsWith('0x') ? bytecode.slice(2) : bytecode).toLowerCase();
	const prefix = '363d3d373d3d3d363d73';
	const suffix = '5af43d82803e903d91602b57fd5bf3';
	return clean.startsWith(prefix) && clean.endsWith(suffix) && clean.length === 90;
}

export function extractMinimalProxyTarget(bytecode?: string): string | null {
	if (!bytecode) return null;
	const clean = (bytecode.startsWith('0x') ? bytecode.slice(2) : bytecode).toLowerCase();
	const prefix = '363d3d373d3d3d363d73';
	const suffix = '5af43d82803e903d91602b57fd5bf3';
	if (!(clean.startsWith(prefix) && clean.endsWith(suffix) && clean.length === 90)) return null;
	return `0x${clean.slice(prefix.length, prefix.length + 40)}`;
}

export function detectDiamondProxy(instructions: Instruction[]): boolean {
	return hasPush4Selector(instructions, DIAMOND_SELECTOR_SET);
}

export function detectEip7702Delegation(bytecode: string): boolean {
	const clean = bytecode.startsWith('0x') ? bytecode.slice(2) : bytecode;
	return clean.toLowerCase().startsWith('ef0100') && clean.length === 46;
}

export function runAllDetectors(instructions: Instruction[], bytecode?: string): DetectionResults {
	const chainIdResult = detectChainId(instructions);
	const tokenTransferResult = analyzeTokenTransfers(instructions);

	return {
		isDelegatedCall: detectDelegateCall(instructions),
		hasCallcode: detectCallcode(instructions),
		hasAutoForwarder: detectAutoForwarder(instructions),
		hasUnlimitedApprovals: detectUnlimitedApproval(instructions),
		hasSelfDestruct: detectSelfDestruct(instructions),
		hasCreate2: detectCreate2(instructions),
		hasChainId: chainIdResult.hasChainId,
		hasChainIdBranching: chainIdResult.hasBranching,
		hasChainIdComparison: chainIdResult.hasComparison,
		isEip712Pattern: chainIdResult.isEip712Pattern,
		tokenTransfer: tokenTransferResult,
		proxy: detectProxyPattern(instructions),
		hasTxOrigin: detectTxOrigin(instructions),
		isEip7702Delegation: bytecode ? detectEip7702Delegation(bytecode) : false,
		hasTimestampDependence: detectTimestampDependence(instructions),
		hasMulticall: detectMulticall(instructions),
		hasExtcodesizeGuard: detectExtcodesizeGuard(instructions),
		hasErc4337Pattern: detectErc4337Pattern(instructions),
		hasCoinbaseDependence: detectCoinbaseDependence(instructions),
		hasExtcodecopy: detectExtcodecopy(instructions),
		hasBalanceDrain: detectBalanceDrain(instructions),
		hasReentrancyRisk: detectReentrancyRisk(instructions),
		hasGasManipulation: detectGasManipulation(instructions),
		hasExtcodehash: detectExtcodehash(instructions),
		hasMinimalProxy: detectMinimalProxy(bytecode),
		hasDiamondProxy: detectDiamondProxy(instructions),
	};
}
