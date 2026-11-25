// Renders PNG app icons from icons/icon.svg.
import { createRequire } from 'node:module';
import { readFileSync, writeFileSync } from 'node:fs';
const { chromium } = createRequire(import.meta.url)('playwright');
const svg = readFileSync('icons/icon.svg', 'utf8');
const browser = await chromium.launch();
const page = await browser.newPage();
for (const [file, size, maskable] of [['icon-192.png', 192, false], ['icon-512.png', 512, false], ['icon-maskable-512.png', 512, true]]) {
  await page.setViewportSize({ width: size, height: size });
  const inner = maskable ? svg.replace('rx="112"', 'rx="0"').replace('<svg ', '<svg style="transform:scale(1)" ') : svg;
  await page.setContent(`<body style="margin:0;background:${maskable ? '#0b5d45' : 'transparent'}"><div style="width:${size}px;height:${size}px;${maskable ? 'padding:' + size * 0.1 + 'px;box-sizing:border-box' : ''}">${inner.replace('<svg ', `<svg width="100%" height="100%" `)}</div></body>`);
  writeFileSync('icons/' + file, await page.screenshot({ omitBackground: !maskable, clip: { x: 0, y: 0, width: size, height: size } }));
}
await browser.close();
console.log('icons written');
