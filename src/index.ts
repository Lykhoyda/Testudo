import type { Address } from 'viem';
import { runAllDetectors } from './detectors';
import { parseBytecode } from './parser';
import type { ContractAnalysisResults } from './types';
import { fetchContractBytecode } from './utils/fetcher';
import { checkKnownMalicious } from './utils/malicious-db';

async function analyzeContract(address: Address): Promise<ContractAnalysisResults> {
	// // 1. Check if known malicious
	// const maliciousContract = checkKnownMalicious(address);
	//
	// if (maliciousContract) {
	// 	return {
	// 		address,
	// 		risk: 'CRITICAL',
	// 		detectedThreats: [maliciousContract.type],
	// 		source: maliciousContract.source,
	// 	};
	// }

	// 2. Fetch bytecode
	const contractBytecode = await fetchContractBytecode(address);
	if (!contractBytecode) {
		return {
			address,
			risk: 'UNKNOWN',
			detectedThreats: [],
			error: 'No byte code found.',
		};
	}

	// 3. Parse bytecode
	const instructions = parseBytecode(contractBytecode);

	// 4. Run detectors
	const threats = runAllDetectors(instructions);
	const detectedThreats = Object.entries(threats)
		.filter((threat) => threat[1])
		.map((threat) => threat[0]);

	// 5. Calculate risk
	const risk = detectedThreats.length > 0 ? 'CRITICAL' : 'LOW';
	return {
		address,
		risk,
		detectedThreats,
	};
}

// For testing:
//     0x63c0c19a282a1b52b07dd5a65b58948a07dae32b

const contract = await analyzeContract('0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b');
console.log(contract);
