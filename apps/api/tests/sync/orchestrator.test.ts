import { describe, expect, it, vi, beforeEach } from 'vitest';

vi.mock('../../src/db/index.js', () => ({
	db: {
		insert: vi.fn().mockReturnValue({ values: vi.fn().mockResolvedValue(undefined) }),
	},
}));

vi.mock('../../src/sync/adapters/scam-sniffer.js', () => ({
	fetchAddresses: vi.fn(),
	fetchDomains: vi.fn(),
}));

vi.mock('../../src/sync/adapters/eth-phishing-detect.js', () => ({
	fetchDomains: vi.fn(),
}));

vi.mock('../../src/sync/aggregator.js', () => ({
	upsertAddresses: vi.fn(),
	upsertDomains: vi.fn(),
}));

import { runSync, runSyncSafe } from '../../src/sync/orchestrator.js';
import * as scamSniffer from '../../src/sync/adapters/scam-sniffer.js';
import * as ethPhishingDetect from '../../src/sync/adapters/eth-phishing-detect.js';
import { upsertAddresses, upsertDomains } from '../../src/sync/aggregator.js';

beforeEach(() => {
	vi.clearAllMocks();
});

describe('orchestrator', () => {
	describe('runSync', () => {
		it('calls all adapters and aggregator functions', async () => {
			vi.mocked(scamSniffer.fetchAddresses).mockResolvedValue({
				source: 'scam-sniffer',
				entries: [{ address: '0x1234', threatType: 'SCAM', threatLevel: 'HIGH' }],
				fetchedAt: new Date(),
			});
			vi.mocked(scamSniffer.fetchDomains).mockResolvedValue({
				source: 'scam-sniffer',
				entries: [{ domain: 'evil.com', threatType: 'PHISHING' }],
				fetchedAt: new Date(),
			});
			vi.mocked(ethPhishingDetect.fetchDomains).mockResolvedValue({
				source: 'eth-phishing-detect',
				entries: [{ domain: 'phish.io', threatType: 'PHISHING' }],
				fetchedAt: new Date(),
			});
			vi.mocked(upsertAddresses).mockResolvedValue({ added: 1, updated: 0 });
			vi.mocked(upsertDomains).mockResolvedValue({ added: 1, updated: 0 });

			await runSync();

			expect(scamSniffer.fetchAddresses).toHaveBeenCalledOnce();
			expect(scamSniffer.fetchDomains).toHaveBeenCalledOnce();
			expect(ethPhishingDetect.fetchDomains).toHaveBeenCalledOnce();
			expect(upsertAddresses).toHaveBeenCalledOnce();
			expect(upsertDomains).toHaveBeenCalledTimes(2);
		});

		it('continues syncing other sources when one adapter fails', async () => {
			vi.mocked(scamSniffer.fetchAddresses).mockRejectedValue(new Error('Network error'));
			vi.mocked(scamSniffer.fetchDomains).mockResolvedValue({
				source: 'scam-sniffer',
				entries: [{ domain: 'evil.com', threatType: 'PHISHING' }],
				fetchedAt: new Date(),
			});
			vi.mocked(ethPhishingDetect.fetchDomains).mockResolvedValue({
				source: 'eth-phishing-detect',
				entries: [{ domain: 'phish.io', threatType: 'PHISHING' }],
				fetchedAt: new Date(),
			});
			vi.mocked(upsertDomains).mockResolvedValue({ added: 1, updated: 0 });

			await runSync();

			expect(scamSniffer.fetchDomains).toHaveBeenCalledOnce();
			expect(ethPhishingDetect.fetchDomains).toHaveBeenCalledOnce();
			expect(upsertDomains).toHaveBeenCalledTimes(2);
		});
	});

	describe('runSyncSafe', () => {
		it('does not throw on unhandled errors', async () => {
			vi.mocked(scamSniffer.fetchAddresses).mockRejectedValue(new Error('Fatal'));
			vi.mocked(scamSniffer.fetchDomains).mockRejectedValue(new Error('Fatal'));
			vi.mocked(ethPhishingDetect.fetchDomains).mockRejectedValue(new Error('Fatal'));

			await expect(runSyncSafe()).resolves.toBeUndefined();
		});
	});
});
