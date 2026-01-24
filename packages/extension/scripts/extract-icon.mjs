#!/usr/bin/env node
/**
 * Generate extension icons - extract PNG from SVG to preserve transparency
 */

import sharp from 'sharp';
import { readFileSync, mkdirSync, existsSync } from 'fs';
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

	let sourceBuffer;
	const extractedPng = join(assetsDir, 'extracted-raw.png');
	const svgFile = join(assetsDir, 'icon-testudo.svg');

	if (existsSync(extractedPng)) {
		// Use pre-extracted PNG with transparency
		sourceBuffer = readFileSync(extractedPng);
		console.log('Using: extracted-raw.png');
	} else if (existsSync(svgFile)) {
		// Extract embedded PNG from SVG to preserve transparency
		const svgContent = readFileSync(svgFile, 'utf-8');
		const match = svgContent.match(/data:image\/png;base64,([A-Za-z0-9+/=]+)/);
		if (match) {
			sourceBuffer = Buffer.from(match[1], 'base64');
			console.log('Using: extracted from SVG');
		} else {
			console.error('✗ No embedded PNG in SVG');
			process.exit(1);
		}
	} else {
		console.error('✗ No source file found');
		process.exit(1);
	}

	// Generate all sizes
	for (const size of sizes) {
		await sharp(sourceBuffer)
			.resize(size, size)
			.png({ compressionLevel: 9 })
			.toFile(join(distDir, `icon-${size}.png`));
		console.log(`✓ icon-${size}.png`);
	}
}

generateIcons().catch(console.error);
