import type { DeployerInfo, DeployerRiskAssessment, Warning } from './types';

const NONCE_SUSPICIOUS = 5;
const NONCE_ESTABLISHED = 50;
const AGE_24H = 24 * 60 * 60;

export function assessDeployerRisk(info: DeployerInfo): DeployerRiskAssessment {
	const contractAge = Math.max(0, info.currentTimestamp - info.contractCreationTimestamp);
	const nonce = info.deployerNonce;
	const reasons: string[] = [];

	let risk: DeployerRiskAssessment['risk'] = 'LOW';

	if (nonce < NONCE_SUSPICIOUS && contractAge < AGE_24H) {
		risk = 'CRITICAL';
		reasons.push(`Deployer has only ${nonce} transactions and contract is less than 24h old`);
	} else if (nonce < NONCE_SUSPICIOUS) {
		risk = 'HIGH';
		reasons.push(`Deployer has only ${nonce} transactions`);
	} else if (nonce < NONCE_ESTABLISHED && contractAge < AGE_24H) {
		risk = 'MEDIUM';
		reasons.push(`Contract deployed less than 24h ago by account with ${nonce} transactions`);
	}

	return { risk, contractAge, deployerNonce: nonce, reasons };
}

export function generateDeployerWarnings(assessment: DeployerRiskAssessment): Warning[] {
	if (assessment.risk === 'LOW') return [];

	const warnings: Warning[] = [];

	if (assessment.risk === 'CRITICAL') {
		warnings.push({
			type: 'DEPLOYER_FRESH',
			severity: 'CRITICAL',
			title: 'Freshly Deployed by New Account',
			description: `Contract deployed by a brand-new account with only ${assessment.deployerNonce} transactions. This is a strong indicator of disposable deployer wallets used in scam campaigns.`,
			technical: `Deployer nonce: ${assessment.deployerNonce}, contract age: ${formatAge(assessment.contractAge)}`,
		});
	} else if (assessment.risk === 'HIGH') {
		warnings.push({
			type: 'DEPLOYER_LOW_NONCE',
			severity: 'HIGH',
			title: 'Low-Activity Deployer',
			description: `Contract was deployed by an account with very few transactions (${assessment.deployerNonce}). Legitimate contracts are typically deployed by established accounts.`,
			technical: `Deployer nonce: ${assessment.deployerNonce}`,
		});
	} else if (assessment.risk === 'MEDIUM') {
		warnings.push({
			type: 'DEPLOYER_NEW_CONTRACT',
			severity: 'MEDIUM',
			title: 'Recently Deployed Contract',
			description:
				'This contract was deployed less than 24 hours ago. Exercise caution with newly deployed contracts.',
			technical: `Deployer nonce: ${assessment.deployerNonce}, contract age: ${formatAge(assessment.contractAge)}`,
		});
	}

	return warnings;
}

function formatAge(seconds: number): string {
	if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
	if (seconds < AGE_24H) return `${Math.floor(seconds / 3600)}h`;
	return `${Math.floor(seconds / AGE_24H)}d`;
}
