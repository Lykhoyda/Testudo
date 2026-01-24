import { defineConfig } from '@playwright/test';

export default defineConfig({
	testDir: './tests',
	fullyParallel: false,
	forbidOnly: !!process.env.CI,
	retries: process.env.CI ? 2 : 0,
	workers: 1,
	reporter: 'html',
	use: {
		trace: 'on-first-retry',
	},
	projects: [
		{
			name: 'chromium',
			use: {},
		},
	],
	webServer: [
		{
			command: 'yarn workspace @testudo/mock-dapp run preview --port 4173',
			url: 'http://localhost:4173',
			reuseExistingServer: !process.env.CI,
			cwd: '../..',
		},
		{
			command: 'yarn workspace @testudo/api run dev',
			url: 'http://localhost:3001/health',
			reuseExistingServer: !process.env.CI,
			cwd: '../..',
			timeout: 30000,
		},
	],
});
