import type { Address } from 'viem';
import { runAllDetectors } from './detectors';
import { fetchBytecode } from './fetcher';
import { checkKnownMalicious, isKnownSafe } from './malicious-db';
import { parseBytecode } from './parser';
import type { AnalysisResult } from './types';

export async function analyzeContract(address: Address): Promise<AnalysisResult> {
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
		const bytecode = await fetchBytecode(normalizedAddress);

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
		if (detectionResults.hasChainId) {
			threats.push('crossChainPolymorphism');
			if (detectionResults.hasChainIdBranching) {
				warnings.push(
					'Contract uses CHAINID with conditional branching. Behavior may differ across chains - safe on Mainnet but malicious on L2s. Avoid signing with chainId=0.',
				);
			} else {
				warnings.push(
					'Contract reads CHAINID. Behavior may vary by chain. Consider restricting delegation to a specific chain.',
				);
			}
		}

		let risk: AnalysisResult['risk'] = 'LOW';
		let blocked = false;

		if (threats.length > 0) {
			if (isMetamorphic || detectionResults.hasAutoForwarder || threats.length >= 2) {
				risk = 'CRITICAL';
				blocked = true;
			} else if (
				detectionResults.hasSelfDestruct ||
				detectionResults.isDelegatedCall ||
				detectionResults.hasChainIdBranching
			) {
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
