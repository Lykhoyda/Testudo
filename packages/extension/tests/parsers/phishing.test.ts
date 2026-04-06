import { describe, expect, it } from 'vitest';
import { detectPhishingPatterns } from '../../src/parsers/phishing';

describe('detectPhishingPatterns', () => {
	describe('clean messages', () => {
		it('returns INFO with score 0 for empty string', () => {
			const result = detectPhishingPatterns('');
			expect(result).toEqual({ score: 0, patterns: [], risk: 'INFO' });
		});

		it('returns INFO for benign message', () => {
			const result = detectPhishingPatterns('Hello, please sign this transaction to swap tokens.');
			expect(result).toEqual({ score: 0, patterns: [], risk: 'INFO' });
		});

		it('returns INFO for random text', () => {
			const result = detectPhishingPatterns('The quick brown fox jumps over the lazy dog');
			expect(result.risk).toBe('INFO');
			expect(result.score).toBe(0);
			expect(result.patterns).toHaveLength(0);
		});
	});

	describe('airdrop_scam category', () => {
		it('detects "claim your airdrop"', () => {
			const result = detectPhishingPatterns('Claim your airdrop now');
			expect(result.patterns).toContain('airdrop_scam');
			expect(result.score).toBe(3);
			expect(result.risk).toBe('HIGH');
		});

		it('detects "claim airdrop" without "your"', () => {
			const result = detectPhishingPatterns('claim airdrop');
			expect(result.patterns).toContain('airdrop_scam');
		});

		it('detects "free tokens"', () => {
			const result = detectPhishingPatterns('Get your free tokens here');
			expect(result.patterns).toContain('airdrop_scam');
			expect(result.score).toBe(3);
		});

		it('detects "free token" singular', () => {
			const result = detectPhishingPatterns('Receive a free token');
			expect(result.patterns).toContain('airdrop_scam');
		});

		it('detects "claim your reward"', () => {
			const result = detectPhishingPatterns('Claim your reward before it expires');
			expect(result.patterns).toContain('airdrop_scam');
		});
	});

	describe('verification_scam category', () => {
		it('detects "verify your wallet"', () => {
			const result = detectPhishingPatterns('Please verify your wallet to continue');
			expect(result.patterns).toContain('verification_scam');
			expect(result.score).toBe(3);
		});

		it('detects "verify wallet" without "your"', () => {
			const result = detectPhishingPatterns('verify wallet');
			expect(result.patterns).toContain('verification_scam');
		});

		it('detects "confirm ownership"', () => {
			const result = detectPhishingPatterns('Confirm your ownership of this wallet');
			expect(result.patterns).toContain('verification_scam');
		});

		it('detects "security check"', () => {
			const result = detectPhishingPatterns('Complete a security check');
			expect(result.patterns).toContain('verification_scam');
		});

		it('detects "security verification"', () => {
			const result = detectPhishingPatterns('security verification required');
			expect(result.patterns).toContain('verification_scam');
		});
	});

	describe('urgency category', () => {
		it('detects "expires in"', () => {
			const result = detectPhishingPatterns('This offer expires in 24 hours');
			expect(result.patterns).toContain('urgency');
			expect(result.score).toBe(2);
		});

		it('detects "act now"', () => {
			const result = detectPhishingPatterns('Act now before it is too late');
			expect(result.patterns).toContain('urgency');
		});

		it('detects "limited time"', () => {
			const result = detectPhishingPatterns('Limited time offer');
			expect(result.patterns).toContain('urgency');
		});

		it('detects "within N hours/minutes"', () => {
			const result = detectPhishingPatterns('Must respond within 2 hours');
			expect(result.patterns).toContain('urgency');

			const result2 = detectPhishingPatterns('Complete within 30 minute');
			expect(result2.patterns).toContain('urgency');
		});
	});

	describe('impersonation category', () => {
		it('detects "opensea"', () => {
			const result = detectPhishingPatterns('OpenSea collection verification');
			expect(result.patterns).toContain('impersonation');
			expect(result.score).toBe(2);
		});

		it('detects "metamask"', () => {
			const result = detectPhishingPatterns('MetaMask security update');
			expect(result.patterns).toContain('impersonation');
		});

		it('detects "uniswap"', () => {
			const result = detectPhishingPatterns('Uniswap token migration');
			expect(result.patterns).toContain('impersonation');
		});

		it('detects "coinbase"', () => {
			const result = detectPhishingPatterns('Coinbase account action required');
			expect(result.patterns).toContain('impersonation');
		});
	});

	describe('financial_lure category', () => {
		it('detects "you won"', () => {
			const result = detectPhishingPatterns('Congratulations, you won 5 ETH!');
			expect(result.patterns).toContain('financial_lure');
			expect(result.score).toBe(2);
		});

		it('detects "you have won"', () => {
			const result = detectPhishingPatterns('You have won a special reward');
			expect(result.patterns).toContain('financial_lure');
		});

		it('detects "prize"', () => {
			const result = detectPhishingPatterns('Claim your prize');
			expect(result.patterns).toContain('financial_lure');
		});

		it('detects "bonus token"', () => {
			const result = detectPhishingPatterns('Receive a bonus token for signing');
			expect(result.patterns).toContain('financial_lure');
		});
	});

	describe('score accumulation within same category', () => {
		it('adds score for multiple patterns in same category but deduplicates category', () => {
			const result = detectPhishingPatterns('Claim your airdrop and get free tokens');
			expect(result.score).toBe(6);
			expect(result.patterns).toEqual(['airdrop_scam']);
		});

		it('accumulates all three airdrop patterns', () => {
			const result = detectPhishingPatterns('Claim your airdrop! Free tokens! Claim your reward!');
			expect(result.score).toBe(9);
			expect(result.patterns).toEqual(['airdrop_scam']);
		});

		it('accumulates urgency patterns', () => {
			const result = detectPhishingPatterns('Act now! Limited time! Expires in 1 hour');
			expect(result.score).toBe(6);
			expect(result.patterns).toEqual(['urgency']);
		});
	});

	describe('multiple categories', () => {
		it('detects airdrop + urgency', () => {
			const result = detectPhishingPatterns('Claim your airdrop! Act now!');
			expect(result.score).toBe(5);
			expect(result.patterns).toContain('airdrop_scam');
			expect(result.patterns).toContain('urgency');
		});

		it('detects impersonation + verification', () => {
			const result = detectPhishingPatterns('MetaMask: verify your wallet');
			expect(result.score).toBe(5);
			expect(result.patterns).toContain('impersonation');
			expect(result.patterns).toContain('verification_scam');
		});

		it('detects all five categories simultaneously', () => {
			const msg = 'Claim your airdrop on OpenSea! Verify your wallet. You won a prize! Act now!';
			const result = detectPhishingPatterns(msg);
			expect(result.patterns).toContain('airdrop_scam');
			expect(result.patterns).toContain('impersonation');
			expect(result.patterns).toContain('verification_scam');
			expect(result.patterns).toContain('financial_lure');
			expect(result.patterns).toContain('urgency');
			expect(result.patterns).toHaveLength(5);
		});
	});

	describe('risk thresholds', () => {
		it('returns MEDIUM for score 1-2', () => {
			const result = detectPhishingPatterns('Expires in 5 minutes');
			expect(result.score).toBe(2);
			expect(result.risk).toBe('MEDIUM');
		});

		it('returns MEDIUM for score 2 (impersonation)', () => {
			const result = detectPhishingPatterns('Sign this OpenSea message');
			expect(result.score).toBe(2);
			expect(result.risk).toBe('MEDIUM');
		});

		it('returns HIGH for score exactly 3', () => {
			const result = detectPhishingPatterns('Claim your airdrop');
			expect(result.score).toBe(3);
			expect(result.risk).toBe('HIGH');
		});

		it('returns HIGH for score above 3', () => {
			const result = detectPhishingPatterns('Claim your airdrop! Act now! MetaMask verification');
			expect(result.score).toBeGreaterThan(3);
			expect(result.risk).toBe('HIGH');
		});
	});

	describe('case insensitivity', () => {
		it('matches uppercase', () => {
			const result = detectPhishingPatterns('CLAIM YOUR AIRDROP');
			expect(result.patterns).toContain('airdrop_scam');
		});

		it('matches mixed case', () => {
			const result = detectPhishingPatterns('cLaIm YoUr AiRdRoP');
			expect(result.patterns).toContain('airdrop_scam');
		});

		it('matches lowercase', () => {
			const result = detectPhishingPatterns('verify your wallet');
			expect(result.patterns).toContain('verification_scam');
		});
	});

	describe('realistic phishing messages', () => {
		it('detects classic airdrop phishing', () => {
			const msg =
				'Congratulations! You have won 1000 USDT. Claim your airdrop within 24 hours before it expires in 1 hour.';
			const result = detectPhishingPatterns(msg);
			expect(result.risk).toBe('HIGH');
			expect(result.patterns).toContain('airdrop_scam');
			expect(result.patterns).toContain('financial_lure');
			expect(result.patterns).toContain('urgency');
		});

		it('detects wallet verification phishing', () => {
			const msg =
				'MetaMask security verification required. Verify your wallet to confirm ownership. Act now!';
			const result = detectPhishingPatterns(msg);
			expect(result.risk).toBe('HIGH');
			expect(result.patterns).toContain('impersonation');
			expect(result.patterns).toContain('verification_scam');
			expect(result.patterns).toContain('urgency');
		});

		it('detects NFT marketplace phishing', () => {
			const msg = 'OpenSea: Your NFT has a new offer. Claim your reward. Limited time only!';
			const result = detectPhishingPatterns(msg);
			expect(result.risk).toBe('HIGH');
			expect(result.patterns).toContain('impersonation');
			expect(result.patterns).toContain('airdrop_scam');
			expect(result.patterns).toContain('urgency');
		});

		it('detects token bonus scam', () => {
			const msg =
				'Uniswap bonus token distribution! Free tokens for early users. Expires in 2 hours.';
			const result = detectPhishingPatterns(msg);
			expect(result.risk).toBe('HIGH');
			expect(result.patterns).toContain('impersonation');
			expect(result.patterns).toContain('airdrop_scam');
			expect(result.patterns).toContain('financial_lure');
			expect(result.patterns).toContain('urgency');
		});
	});
});
