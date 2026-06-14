import { defineConfig } from 'rolldown';
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const distDir = join(__dirname, 'dist');
const fontsDir = join(distDir, 'fonts');

// Load `.env.local` (gitignored) into process.env so developers don't have to
// re-export TESTUDO_API_KEY on every build. Explicit env vars win over the file.
function loadEnvFile(path: string): void {
	if (!existsSync(path)) return;
	const content = readFileSync(path, 'utf-8');
	for (const rawLine of content.split('\n')) {
		const line = rawLine.trim();
		if (!line || line.startsWith('#')) continue;
		const eq = line.indexOf('=');
		if (eq === -1) continue;
		const key = line.slice(0, eq).trim();
		let value = line.slice(eq + 1).trim();
		if (
			(value.startsWith('"') && value.endsWith('"')) ||
			(value.startsWith("'") && value.endsWith("'"))
		) {
			value = value.slice(1, -1);
		}
		if (process.env[key] === undefined) {
			process.env[key] = value;
		}
	}
	console.log(`[Testudo Build] Loaded env from ${path.replace(__dirname, '.')}`);
}

loadEnvFile(join(__dirname, '.env.local'));

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
if (!apiKey) {
	console.warn('[Testudo Build] WARNING: TESTUDO_API_KEY is not set. API calls will be unauthenticated and may return 401.');
}

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
		// injected.js is a MAIN-world content script (ADR-016): it must be a single
		// classic self-contained bundle (no ESM import/export, no chunks) because it
		// runs under the page's CSP. IIFE guarantees that.
		input: 'src/injected.tsx',
		...shared,
		output: { ...shared.output, format: 'iife' as const },
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
