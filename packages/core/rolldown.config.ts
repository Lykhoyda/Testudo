import { defineConfig } from 'rolldown';

export default defineConfig({
	input: 'src/index.ts',
	external: [/^viem/],
	output: {
		dir: 'dist',
		format: 'esm',
	},
});
