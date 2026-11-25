// Bundles the PWA into one self-contained HTML file (dist/chip-id-reader.html) for sharing as a
// single-file demo. The single file runs the simulator; real chip reads need the Android shell.
import { build } from 'esbuild';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';

const html = readFileSync('index.html', 'utf8');
const css = readFileSync('styles.css', 'utf8');
const js = (await build({ entryPoints: ['js/app.js'], bundle: true, format: 'iife', minify: true, write: false, target: 'es2020' })).outputFiles[0].text;

const title = html.match(/<title>[\s\S]*?<\/title>/)[0];
const viewportSides = '<meta name="claude:viewport-fit-sides" content="cover">';
const fonts = html.match(/<link rel="stylesheet" href="https:\/\/fonts[^>]+>/)[0];
const body = html.match(/<body>([\s\S]*)<\/body>/)[1].replace(/<script type="module" src="js\/app.js"><\/script>/, '');
const iconLink = `<link rel="icon" href="data:image/svg+xml;base64,${Buffer.from(readFileSync('icons/icon.svg')).toString('base64')}">`;

// Artifact flavour: no doctype/head (the host adds them). Standalone flavour: full document.
// The artifact viewer blocks file downloads, so that flavour offers Copy JSON only.
const artifact = `${title}\n${viewportSides}\n${fonts}\n<style>\n${css}\n#btn-download { display: none !important; }\n</style>\n${body}\n<script>\n${js.replace(/<\/script/g, '<\\/script')}\n</script>\n`;
const standalone = `<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n${artifact.replace(/(<\/style>)/, '$1').split('\n<style>')[0]}\n${iconLink}\n<style>\n${css}\n</style>\n</head>\n<body>\n${body}\n<script>\n${js.replace(/<\/script/g, '<\\/script')}\n</script>\n</body>\n</html>\n`;
mkdirSync('dist', { recursive: true });
writeFileSync('dist/chip-id-reader.artifact.html', artifact);
writeFileSync('dist/chip-id-reader.html', standalone);
console.log(`dist/chip-id-reader.html ${(standalone.length / 1024).toFixed(0)} KB, artifact ${(artifact.length / 1024).toFixed(0)} KB`);
