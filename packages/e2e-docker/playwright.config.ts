import { defineConfig } from '@playwright/test';

export default defineConfig({
	testDir: './tests',
	fullyParallel: false,
	forbidOnly: !!process.env.CI,
	retries: process.env.CI ? 2 : 0,
	workers: 1,
	timeout: 120_000,
	reporter: 'html',
	use: {
		trace: 'on-first-retry',
		video: 'retain-on-failure',
		headless: false,
		baseURL: 'http://localhost:4174',
	},
	projects: [
		{
			name: 'chromium',
			use: {},
		},
	],
	webServer: {
		command: 'npx serve ../../apps/synpress-dapp -l 4174 --no-clipboard',
		url: 'http://localhost:4174',
		reuseExistingServer: !process.env.CI,
	},
});
