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
		if (detectionResults.hasAutoForwarder) threats.push('hasAutoForwarder');
		if (detectionResults.isDelegatedCall) threats.push('isDelegatedCall');
		if (detectionResults.hasSelfDestruct) threats.push('hasSelfDestruct');
		if (detectionResults.hasUnlimitedApprovals) threats.push('hasUnlimitedApprovals');

		let risk: AnalysisResult['risk'] = 'LOW';
		let blocked = false;

		if (threats.length > 0) {
			if (detectionResults.hasAutoForwarder || threats.length >= 2) {
				risk = 'CRITICAL';
				blocked = true;
			} else if (detectionResults.hasSelfDestruct || detectionResults.isDelegatedCall) {
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
