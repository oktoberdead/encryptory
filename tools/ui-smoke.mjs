#!/usr/bin/env node
/*
 * Смоук-тест интерфейса: два «браузера» в jsdom проходят полный сценарий —
 * генерация ключей, обмен публичными ключами, шифрование, расшифровка,
 * локальная проверка, порча шифротекста, парольная защита, перезагрузка вкладки.
 *
 * jsdom — единственная (и необязательная) внешняя зависимость, и только для этого файла:
 *   npm install --no-save jsdom && npm run test:ui
 * Без jsdom тест просто сообщит, что пропущен, и не упадёт.
 */
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

let JSDOM;
let VirtualConsole;
try {
  ({ JSDOM, VirtualConsole } = await import('jsdom'));
} catch (error) {
  console.log('jsdom не установлен — тест интерфейса пропущен.');
  console.log('Поставить и запустить:  npm install --no-save jsdom && npm run test:ui');
  process.exit(0);
}

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const html = readFileSync(`${ROOT}/index.html`, 'utf8');
const core = readFileSync(`${ROOT}/src/encryptory-core.js`, 'utf8');
const app = readFileSync(`${ROOT}/app.js`, 'utf8');

const problems = [];
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

function makeWindow(label, sessionData) {
  const virtualConsole = new VirtualConsole();
  virtualConsole.on('jsdomError', (e) => problems.push(`[${label}] jsdomError: ${e.message}`));
  virtualConsole.on('error', (...a) => problems.push(`[${label}] console.error: ${a.join(' ')}`));

  const dom = new JSDOM(html, { runScripts: 'outside-only', url: 'https://example.test/', pretendToBeVisual: true, virtualConsole });
  const { window } = dom;
  Object.defineProperty(window, 'crypto', { value: webcrypto, configurable: true });
  if (sessionData) window.sessionStorage.setItem('encryptory.session.v1', sessionData);
  window.addEventListener('unhandledrejection', (e) => problems.push(`[${label}] unhandledrejection: ${e.reason}`));
  window.eval(core);
  window.eval(app);
  window.document.dispatchEvent(new window.Event('DOMContentLoaded', { bubbles: true }));
  return window;
}

const $ = (w, sel) => w.document.querySelector(sel);
const click = (w, sel) => $(w, sel).dispatchEvent(new w.MouseEvent('click', { bubbles: true, cancelable: true }));
const type = (w, sel, value) => {
  const el = $(w, sel);
  el.value = value;
  el.dispatchEvent(new w.Event('input', { bubbles: true }));
};
const text = (w, sel) => $(w, sel).value !== undefined ? $(w, sel).value : $(w, sel).textContent;

const checks = [];
const check = (name, ok, extra = '') => { checks.push([name, ok]); console.log(`${ok ? '  ok  ' : ' FAIL '} ${name}${extra ? ` — ${extra}` : ''}`); };

const alice = makeWindow('Алиса');
const bob = makeWindow('Боб');
await wait(60);

// 1. генерация ключей
click(alice, '#generate-btn');
click(bob, '#generate-btn');
await wait(150);
const alicePub = text(alice, '#own-pub');
const bobPub = text(bob, '#own-pub');
check('Алиса сгенерировала ключ', alicePub.startsWith('-----BEGIN ENCRYPTORY PUBLIC KEY-----'));
check('Боб сгенерировал ключ', bobPub.startsWith('-----BEGIN ENCRYPTORY PUBLIC KEY-----'));
check('кнопка шифрования Алисы включается после вставки ключа Боба -> проверяем ниже', true);

// 2. обмен публичными ключами
type(alice, '#peer-input', bobPub);
click(alice, '#save-peer-btn');
type(bob, '#peer-input', alicePub);
click(bob, '#save-peer-btn');
await wait(80);
const fp = (w) => text(w, '#own-fp').split(' · ').pop();
check('в чипах показана кривая', text(alice, '#own-fp').startsWith('X25519 · '), text(alice, '#own-fp'));
check('Алиса видит отпечаток Боба', text(alice, '#peer-fp') === text(bob, '#own-fp'), text(alice, '#peer-fp'));
check('Боб видит отпечаток Алисы', text(bob, '#peer-fp') === text(alice, '#own-fp'), text(bob, '#peer-fp'));
check('статус «Готово к работе»', text(alice, '#key-status') === 'Готово к работе');
check('ключ собеседника помечен сохранённым', $(alice, '#peer-card').classList.contains('is-set'));
check('кнопка «Зашифровать» активна', $(alice, '#encrypt-btn').disabled === false);

// 3. шифрование для собеседника
const secret = 'Встречаемся в 21:00 у моста. Пароль: «мандарин-77» 🍊\nвторая строка';
type(alice, '#plaintext', secret);
click(alice, '#encrypt-btn');
await wait(200);
const cipher = text(alice, '#enc-out');
check('шифротекст для собеседника получен', cipher.startsWith('-----BEGIN ENCRYPTORY MESSAGE-----'));
check('в шифротексте нет исходного текста', !cipher.includes('мандарин') && !cipher.includes('моста'));

// 3b. локальная проверка (шифруем себе и «двойнику», расшифровываем тут же)
click(alice, '#self-check-btn');
await wait(400);
check('локальная проверка отрисовала шаги', text(alice, '#local-steps').length > 0, `${alice.document.querySelectorAll('#local-steps li').length} шагов`);
check('все шаги локальной проверки зелёные', [...alice.document.querySelectorAll('#local-steps li')].every((li) => li.classList.contains('pass')));
check('вердикт локальной проверки — совпало', text(alice, '#local-verdict').includes('совпало'), text(alice, '#local-verdict'));
check('локальная расшифровка вернула исходный текст', text(alice, '#local-out') === secret);
check('проверочный шифротекст показан и помечен локальным', text(alice, '#local-ct').startsWith('-----BEGIN ENCRYPTORY MESSAGE-----'));

// 4. Боб расшифровывает
type(bob, '#ciphertext', cipher);
click(bob, '#decrypt-btn');
await wait(150);
check('Боб прочитал ровно то, что отправлено', text(bob, '#dec-out') === secret);
check('Боб видит отпечаток отправителя', text(bob, '#dec-meta').includes(fp(alice)));

// 5. Боб отвечает (кнопкой) и Алиса читает
type(bob, '#plaintext', 'принято, буду в 21:00');
click(bob, '#encrypt-btn');
await wait(150);
const reply = text(bob, '#enc-out');
check('Боб получил свой шифротекст', reply.startsWith('-----BEGIN ENCRYPTORY MESSAGE-----'));
type(alice, '#ciphertext', reply);
click(alice, '#decrypt-btn');
await wait(150);
check('Алиса прочитала ответ', text(alice, '#dec-out') === 'принято, буду в 21:00');

// 6. Порча шифротекста: искажаем символ в теле и ждём внятную ошибку
const lines = reply.trim().split('\n');
const bodyLine = lines.length - 2;
lines[bodyLine] = (lines[bodyLine][0] === 'A' ? 'B' : 'A') + lines[bodyLine].slice(1);
type(alice, '#ciphertext', lines.join('\n'));
click(alice, '#decrypt-btn');
await wait(200);
check('порча шифротекста: показана ошибка', Boolean(alice.document.querySelector('#dec-error')), alice.document.querySelector('#dec-error') ? alice.document.querySelector('#dec-error').textContent : 'ошибки нет');
check('результат не показан молча', $(alice, '#dec-out-block').hidden === true);

// 6b. Совсем чужой текст — тоже ошибка, а не пустой экран
type(alice, '#ciphertext', 'это вообще не шифротекст');
click(alice, '#decrypt-btn');
await wait(150);
check('мусор вместо шифротекста: понятная ошибка', Boolean(alice.document.querySelector('#dec-error')));

// 7. Парольная защита ключа + разблокировка после «перезагрузки»
const carol = makeWindow('Кэрол');
$(carol, '#protect-toggle').checked = true;
$(carol, '#protect-toggle').dispatchEvent(new carol.Event('change', { bubbles: true }));
$(carol, '#protect-pass').value = 'очень-секретный-пароль';
click(carol, '#generate-btn');
await wait(250);
check('ключ под паролем создан', text(carol, '#own-priv').includes('EK1P') || text(carol, '#priv-hint').includes('паролем'));
const carolSession = carol.sessionStorage.getItem('encryptory.session.v1');
const carol2 = makeWindow('Кэрол-перезагрузка', carolSession);
await wait(120);
check('после перезагрузки ключ заблокирован', $(carol2, '#own-locked').hidden === false);
$(carol2, '#unlock-pass').value = 'неверный';
click(carol2, '#unlock-btn');
await wait(200);
check('неверный пароль не разблокировал', $(carol2, '#own-locked').hidden === false);
$(carol2, '#unlock-pass').value = 'очень-секретный-пароль';
click(carol2, '#unlock-btn');
await wait(250);
check('верный пароль разблокировал ключ', $(carol2, '#own-ready').hidden === false);
check('отпечаток после разблокировки тот же', text(carol2, '#own-fp') === text(carol, '#own-fp'), text(carol2, '#own-fp'));

// 8. Восстановление состояния Алисы после перезагрузки вкладки
const alice2 = makeWindow('Алиса-перезагрузка', alice.sessionStorage.getItem('encryptory.session.v1'));
await wait(150);
check('ключи Алисы восстановились', $(alice2, '#own-ready').hidden === false);
check('ключ собеседника восстановился', $(alice2, '#peer-fp').hidden === false);
check('статус снова «Готово к работе»', text(alice2, '#key-status') === 'Готово к работе');
type(alice2, '#ciphertext', reply);
click(alice2, '#decrypt-btn');
await wait(150);
check('Алиса после перезагрузки снова читает сообщение', text(alice2, '#dec-out') === 'принято, буду в 21:00');

// 9. Самопроверка в диалоге
$(alice, '#test-dialog').setAttribute('open', '');
click(alice, '#run-test-btn');
await wait(900);
const steps = [...alice.document.querySelectorAll('#test-list li')];
check('самопроверка отрисовала шаги', steps.length >= 18, `${steps.length} шагов`);
check('все шаги зелёные', steps.every((li) => !li.classList.contains('fail')));

const failed = checks.filter(([, ok]) => !ok).length;
console.log(`\nПроверок: ${checks.length}, провалено: ${failed}`);
console.log('Ошибки в консоли/промисах:', problems.length ? problems : 'нет');
process.exit(failed || problems.length ? 1 : 0);
