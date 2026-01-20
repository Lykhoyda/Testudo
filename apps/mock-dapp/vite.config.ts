import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

export default defineConfig({
	plugins: [react()],
	base: './', // Use relative paths for file:// protocol compatibility
	server: {
		port: 3000,
		open: true,
	},
	build: {
		outDir: 'dist',
	},
});
