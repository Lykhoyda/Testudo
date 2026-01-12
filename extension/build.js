import * as esbuild from 'esbuild';
import * as fs from 'fs';
import * as path from 'path';

const isWatch = process.argv.includes('--watch');

const distDir = path.join(import.meta.dirname, 'dist');
if (!fs.existsSync(distDir)) {
  fs.mkdirSync(distDir);
}

fs.copyFileSync(
  path.join(import.meta.dirname, 'manifest.json'),
  path.join(distDir, 'manifest.json')
);

fs.copyFileSync(
  path.join(import.meta.dirname, 'popup.html'),
  path.join(distDir, 'popup.html')
);

console.log('Copied manifest.json and popup.html to dist/');

const buildOptions = {
  entryPoints: [
    'src/injected.ts',
    'src/content.ts',
    'src/background.ts',
    'src/popup.ts',
  ],
  bundle: true,
  outdir: 'dist',
  format: 'esm',
  target: 'chrome110',
  sourcemap: isWatch,
  minify: !isWatch,
  logLevel: 'info',
};

if (isWatch) {
  const ctx = await esbuild.context(buildOptions);
  await ctx.watch();
  console.log('Watching for changes...');
} else {
  await esbuild.build(buildOptions);
  console.log('Build complete!');
}
