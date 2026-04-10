#!/usr/bin/env node
/**
 * Generate extension icons from SVG source.
 *
 * Priority:
 *   1. Pure-vector SVG at assets/icon-testudo.svg (preferred — rasterize via sharp)
 *   2. Legacy: embedded base64 PNG inside an SVG (old scan-based icon)
 *   3. Fallback: assets/extracted-raw.png
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
	if (!existsSync(distDir)) {
		mkdirSync(distDir, { recursive: true });
	}

	const svgFile = join(assetsDir, 'icon-testudo.svg');
	const extractedPng = join(assetsDir, 'extracted-raw.png');

	let sourceBuffer;
	let isSvg = false;

	if (existsSync(svgFile)) {
		const svgContent = readFileSync(svgFile, 'utf-8');
		const embeddedMatch = svgContent.match(/data:image\/png;base64,([A-Za-z0-9+/=]+)/);
		if (embeddedMatch) {
			sourceBuffer = Buffer.from(embeddedMatch[1], 'base64');
			console.log('Using: embedded PNG from SVG');
		} else {
			sourceBuffer = Buffer.from(svgContent, 'utf-8');
			isSvg = true;
			console.log('Using: pure vector SVG');
		}
	} else if (existsSync(extractedPng)) {
		sourceBuffer = readFileSync(extractedPng);
		console.log('Using: extracted-raw.png (fallback)');
	} else {
		console.error('✗ No source file found');
		process.exit(1);
	}

	for (const size of sizes) {
		const pipeline = isSvg
			? sharp(sourceBuffer, { density: size * 4 })
			: sharp(sourceBuffer);

		await pipeline
			.resize(size, size)
			.png({ compressionLevel: 9 })
			.toFile(join(distDir, `icon-${size}.png`));
		console.log(`✓ icon-${size}.png`);
	}
}

generateIcons().catch((err) => {
	console.error(err);
	process.exit(1);
});
