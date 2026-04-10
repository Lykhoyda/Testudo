import { defineConfig } from 'rolldown';
import { copyFileSync, existsSync, mkdirSync, readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const distDir = join(__dirname, 'dist');
const fontsDir = join(distDir, 'fonts');

if (!existsSync(distDir)) {
	mkdirSync(distDir);
}
if (!existsSync(fontsDir)) {
	mkdirSync(fontsDir);
}

copyFileSync(join(__dirname, 'manifest.json'), join(distDir, 'manifest.json'));
copyFileSync(join(__dirname, 'popup.html'), join(distDir, 'popup.html'));
copyFileSync(join(__dirname, 'options.html'), join(distDir, 'options.html'));
copyFileSync(join(__dirname, 'blocked.html'), join(distDir, 'blocked.html'));

const fontsSrc = join(__dirname, 'fonts');
for (const file of readdirSync(fontsSrc)) {
	copyFileSync(join(fontsSrc, file), join(fontsDir, file));
}
console.log('Copied manifest.json, popup.html, options.html, blocked.html, and fonts/ to dist/');

const apiUrl = process.env.TESTUDO_API_URL || 'https://testudo-api-production.up.railway.app';
const apiKey = process.env.TESTUDO_API_KEY || '';
console.log(`[Testudo Build] API URL: ${apiUrl}`);
console.log(`[Testudo Build] API Key: ${apiKey ? '[SET]' : '[NOT SET]'}`);

const shared = {
	output: {
		dir: 'dist',
		format: 'esm' as const,
		minify: true,
		inlineDynamicImports: true,
	},
	define: {
		'process.env.TESTUDO_API_URL': JSON.stringify(apiUrl),
		'process.env.TESTUDO_API_KEY': JSON.stringify(apiKey),
	},
	transform: {
		jsx: { mode: 'automatic' as const, importSource: 'preact' },
	},
};

export default defineConfig([
	{
		input: 'src/injected.tsx',
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
		input: 'src/popup.tsx',
		...shared,
	},
	{
		input: 'src/options.tsx',
		...shared,
	},
	{
		input: 'src/blocked.tsx',
		...shared,
	},
]);
