export { analyzeContract } from './analyzer';
export {
	detectAutoForwarder,
	detectDelegateCall,
	detectSelfDestruct,
	detectUnlimitedApproval,
	runAllDetectors,
} from './detectors';
export { fetchBytecode } from './fetcher';
export {
	checkKnownMalicious,
	isKnownSafe,
	KNOWN_MALICIOUS,
	KNOWN_SAFE,
} from './malicious-db';
export { OPCODES } from './opcode';
export { parseBytecode } from './parser';
export type {
	AnalysisResult,
	DetectionResults,
	Instruction,
	KnownMaliciousContract,
} from './types';
