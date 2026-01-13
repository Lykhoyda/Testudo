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
console.log('Copied manifest.json and popup.html to dist/');

const shared = {
	output: {
		dir: 'dist',
		format: 'esm' as const,
		minify: true,
		inlineDynamicImports: true,
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
]);
