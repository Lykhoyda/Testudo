import { defineWalletSetup } from '@synthetixio/synpress';
import { MetaMask } from '@synthetixio/synpress/playwright';

const WALLET_PASSWORD = 'TestudoE2E2026!!';

export default defineWalletSetup(WALLET_PASSWORD, async (context, walletPage) => {
	const metamask = new MetaMask(context, walletPage, WALLET_PASSWORD);

	await metamask.importWallet(
		'test test test test test test test test test test test junk',
	);
});

export { WALLET_PASSWORD };
