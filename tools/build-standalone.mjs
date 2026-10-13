#!/usr/bin/env node
/*
 * Собирает dist/encryptory-standalone.html — всё приложение в одном файле.
 * Никаких зависимостей: читаем index.html, вклеиваем CSS, JS и иконку внутрь.
 *
 * Запуск: npm run build
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = (relative) => readFileSync(join(root, relative), 'utf8');

const html = read('index.html');
const css = read('styles.css');
const core = read('src/encryptory-core.js');
const app = read('app.js');
const icon = read('icon.svg');

for (const [name, source] of [['styles.css', css], ['encryptory-core.js', core], ['app.js', app]]) {
  if (source.includes('</script')) {
    throw new Error(`${name}: внутри кода есть «</script» — такую строку нельзя вклеить в <script> без экранирования.`);
  }
}

const replacements = [
  [
    '<link rel="stylesheet" href="styles.css">',
    `<style>\n${css.trim()}\n</style>`,
  ],
  [
    '<link rel="icon" href="icon.svg" type="image/svg+xml">',
    `<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,${encodeURIComponent(icon.trim())}">`,
  ],
  [
    '<script src="src/encryptory-core.js"></script>',
    `<script>\n${core.trim()}\n</script>`,
  ],
  [
    '<script src="app.js"></script>',
    `<script>\n${app.trim()}\n</script>`,
  ],
];

let output = html;
for (const [needle, replacement] of replacements) {
  if (!output.includes(needle)) throw new Error(`В index.html не найдено: ${needle}`);
  output = output.replace(needle, () => replacement);
}

// В автономной сборке ссылка на саму себя не нужна.
output = output.replace(/[ \t]*<!-- standalone-link:start -->[\s\S]*?<!-- standalone-link:end -->\n?/, '');

if (/\b(src|href)="(\.\/)?(styles\.css|app\.js|src\/|icon\.svg)/.test(output)) {
  throw new Error('В сборке остались внешние ссылки на файлы проекта.');
}

mkdirSync(join(root, 'dist'), { recursive: true });
const target = join(root, 'dist', 'encryptory-standalone.html');
writeFileSync(target, output, 'utf8');

const kb = (Buffer.byteLength(output, 'utf8') / 1024).toFixed(1);
console.log(`Готово: dist/encryptory-standalone.html (${kb} КБ). Открывается двойным кликом, интернет не нужен.`);
