#!/usr/bin/env node
/**
 * Generate extension icons from source PNG
 */

import sharp from 'sharp';
import { mkdirSync, existsSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const assetsDir = join(__dirname, '..', 'assets');
const distDir = join(__dirname, '..', 'dist');

const sizes = [16, 32, 48, 128];

async function generateIcons() {
	// Ensure dist directory exists
	if (!existsSync(distDir)) {
		mkdirSync(distDir, { recursive: true });
	}

	// Find source file (prefer SVG)
	const svgFile = join(assetsDir, 'icon-testudo.svg');
	const pngFile = join(assetsDir, 'icon-testudo.png');
	const sourceFile = existsSync(svgFile) ? svgFile : pngFile;

	if (!existsSync(sourceFile)) {
		console.error('✗ Source file not found: icon-testudo.svg or icon-testudo.png');
		process.exit(1);
	}

	// Render SVG at high density, trim transparent edges
	const isSvg = sourceFile.endsWith('.svg');
	const input = isSvg ? sharp(sourceFile, { density: 300 }) : sharp(sourceFile);
	const trimmed = await input.trim().toBuffer();

	// Generate all sizes to dist
	for (const size of sizes) {
		await sharp(trimmed)
			.resize(size, size, { fit: 'fill' })
			.png({ compressionLevel: 9 })
			.toFile(join(distDir, `icon-${size}.png`));
		console.log(`✓ icon-${size}.png`);
	}
}

generateIcons().catch(console.error);
