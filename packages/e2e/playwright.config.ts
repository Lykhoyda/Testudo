import { defineConfig } from '@playwright/test';

export default defineConfig({
	testDir: './tests',
	fullyParallel: false,
	forbidOnly: !!process.env.CI,
	retries: process.env.CI ? 2 : 0,
	workers: 1,
	timeout: process.env.CI ? 60_000 : 30_000,
	reporter: 'html',
	use: {
		trace: 'on-first-retry',
		video: 'retain-on-failure',
	},
	projects: [
		{
			name: 'chromium',
			use: {},
		},
	],
	// API server must be running separately (see testudo-api repo)
	webServer: [
		{
			command: 'yarn workspace @testudo/mock-dapp run preview --port 4173',
			url: 'http://localhost:4173',
			reuseExistingServer: !process.env.CI,
			cwd: '../..',
		},
	],
});
