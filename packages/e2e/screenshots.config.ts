import { defineConfig } from '@playwright/test';

// Standalone Playwright config for generating store/marketing screenshots.
// Kept separate from playwright.config.ts so the screenshot run owns its viewport
// and starts the mock-dapp itself. Uses `dev` (no mock-dapp build required) — only
// the EXTENSION must be built first (the fixture loads packages/extension/dist).
export default defineConfig({
	testDir: './screenshots',
	workers: 1,
	fullyParallel: false,
	forbidOnly: !!process.env.CI,
	timeout: 60_000,
	reporter: 'list',
	use: {
		viewport: { width: 1280, height: 800 },
		deviceScaleFactor: 1,
	},
	webServer: [
		{
			command: 'yarn workspace @testudo/mock-dapp run dev --port 4173 --strictPort',
			url: 'http://localhost:4173',
			reuseExistingServer: !process.env.CI,
			cwd: '../..',
			timeout: 120_000,
		},
	],
});
