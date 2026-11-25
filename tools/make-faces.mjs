// Renders the two fictional specimen portraits used by the simulator to small JPEGs.
import { createRequire } from 'node:module';
const { chromium } = createRequire(import.meta.url)('playwright');
import { writeFileSync } from 'node:fs';

const face = (skin, hair, shirt, bg, longHair) => `
<svg xmlns="http://www.w3.org/2000/svg" width="240" height="300" viewBox="0 0 240 300">
  <rect width="240" height="300" fill="${bg}"/>
  ${longHair ? `<path d="M52 130 Q48 50 120 44 Q192 50 188 130 L196 250 L44 250 Z" fill="${hair}"/>` : ''}
  <path d="M30 300 Q34 222 120 214 Q206 222 210 300 Z" fill="${shirt}"/>
  <rect x="102" y="178" width="36" height="44" rx="14" fill="${skin}"/>
  <ellipse cx="120" cy="128" rx="56" ry="68" fill="${skin}"/>
  ${longHair ? `<path d="M64 112 Q70 56 120 54 Q170 56 176 112 Q150 82 120 84 Q90 82 64 112 Z" fill="${hair}"/>`
             : `<path d="M64 112 Q62 58 120 56 Q178 58 176 112 Q170 84 120 80 Q70 84 64 112 Z" fill="${hair}"/>`}
  <ellipse cx="98" cy="128" rx="7" ry="5" fill="#2b1d16"/><ellipse cx="142" cy="128" rx="7" ry="5" fill="#2b1d16"/>
  <path d="M88 114 Q98 108 108 113" stroke="#2b1d16" stroke-width="3" fill="none"/><path d="M132 113 Q142 108 152 114" stroke="#2b1d16" stroke-width="3" fill="none"/>
  <path d="M120 132 Q114 152 120 156 Q126 156 128 152" stroke="#00000033" stroke-width="3" fill="none"/>
  <path d="M104 170 Q120 178 136 170" stroke="#5a2e22" stroke-width="4" fill="none" stroke-linecap="round"/>
  <text x="120" y="290" font-family="Arial, sans-serif" font-size="18" font-weight="700" fill="#ffffffcc" text-anchor="middle" letter-spacing="3">SPECIMEN</text>
</svg>`;

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 240, height: 300 } });
for (const [name, svg] of [
  ['face-passport', face('#8d5a3b', '#1d1411', '#2f6f73', '#dfe6ea', true)],
  ['face-idcard', face('#6e4329', '#151010', '#7a3b2e', '#e8e3d8', false)],
]) {
  await page.setContent(`<body style="margin:0">${svg}</body>`);
  writeFileSync(`tools/assets/${name}.jpg`, await page.screenshot({ type: 'jpeg', quality: 72, clip: { x: 0, y: 0, width: 240, height: 300 } }));
}
await browser.close();
console.log('faces written');
