import { defineConfig } from 'rolldown';

export default defineConfig({
	input: {
		index: './src/index.ts',
		background: './src/background.ts',
		injector: './src/injector.ts',
		pageHook: './src/pageHook.ts',
	},
	output: {
		dir: './dist',
		format: 'esm',
		entryFileNames: '[name].js',
		sourcemap: true,
	},
	resolve: {
		extensions: ['.ts', '.js'],
	},
	external: [],
	platform: 'browser',
	treeshake: true,
});
