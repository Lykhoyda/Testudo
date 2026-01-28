import { defineConfig } from 'rolldown';
import { copyFileSync, existsSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const distDir = join(__dirname, 'dist');

if (!existsSync(distDir)) {
	mkdirSync(distDir);
}

copyFileSync(join(__dirname, 'manifest.json'), join(distDir, 'manifest.json'));
copyFileSync(join(__dirname, 'popup.html'), join(distDir, 'popup.html'));
copyFileSync(join(__dirname, 'options.html'), join(distDir, 'options.html'));
console.log('Copied manifest.json, popup.html, and options.html to dist/');

const apiUrl = process.env.TESTUDO_API_URL || 'https://api.testudo.security';
console.log(`[Testudo Build] API URL: ${apiUrl}`);

const shared = {
	output: {
		dir: 'dist',
		format: 'esm' as const,
		minify: true,
		inlineDynamicImports: true,
	},
	define: {
		'process.env.TESTUDO_API_URL': JSON.stringify(apiUrl),
	},
};

export default defineConfig([
	{
		input: 'src/injected.ts',
		...shared,
	},
	{
		input: 'src/content.ts',
		...shared,
	},
	{
		input: 'src/background.ts',
		...shared,
	},
	{
		input: 'src/popup.ts',
		...shared,
	},
	{
		input: 'src/options.ts',
		...shared,
	},
]);
