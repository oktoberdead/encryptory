#!/usr/bin/env node
/*
 * Encryptory CLI — тот же протокол, что и в браузере. Полезно, чтобы:
 *   • прогнать шифрование в терминале;
 *   • проверить, что браузер и терминал понимают друг друга (один и тот же формат em1.…).
 *
 * Запуск: node tools/cli.mjs <команда> [ключи]
 *   keygen    [--name bob] [--pass «пароль»] [--out .]
 *   encrypt   --key bob-private.txt [--pass «пароль»] --to bob-public.txt [--text «…» | --in файл]
 *   decrypt   --key bob-private.txt [--pass «пароль»] [--text «…» | --in файл]
 *   inspect   [--text «…» | --in файл]
 *   fingerprint --key bob-public.txt
 *   selftest
 *
 * Если не указать --text и --in, данные читаются из stdin.
 */
import { readFileSync, writeFileSync } from 'node:fs';

import { fileURLToPath } from 'node:url';
import { dirname, join, basename } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(here, '..', 'src', 'encryptory-core.js'), 'utf8');
const module_ = { exports: {} };
new Function('module', 'globalThis', source)(module_, globalThis);
const core = module_.exports;

/* ------------------------------------------------------------------ */
/* Разбор аргументов                                                   */
/* ------------------------------------------------------------------ */

function parseArgs(argv) {
  const options = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith('--')) {
      options._.push(token);
      continue;
    }
    const [name, inlineValue] = token.slice(2).split('=');
    if (inlineValue !== undefined) {
      options[name] = inlineValue;
    } else if (argv[i + 1] && !argv[i + 1].startsWith('--')) {
      options[name] = argv[i + 1];
      i += 1;
    } else {
      options[name] = true;
    }
  }
  return options;
}

const options = parseArgs(process.argv.slice(2));
const command = options._[0] || 'help';

function die(message) {
  process.stderr.write(`Ошибка: ${message}\n`);
  process.exit(1);
}

/** Читает stdin целиком (fs.readFile дескриптор не принимает). */
async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
}

/**
 * Читает текст: --text, потом --in, потом stdin (если он не терминал).
 * Возвращает { text, fromStream } — для файлов и потока отбрасываем один
 * завершающий перевод строки, который дописывают редакторы и echo.
 */
async function inputText(label) {
  if (typeof options.text === 'string') return { text: options.text, fromStream: false };
  if (typeof options.in === 'string') return { text: readFileSync(options.in, 'utf8'), fromStream: true };
  if (!process.stdin.isTTY) return { text: await readStdin(), fromStream: true };
  return die(`укажите ${label} через --text, --in <файл> или передайте данные на stdin`);
}

function outputText(text, fallbackName) {
  if (typeof options.out === 'string') {
    writeFileSync(options.out, text.endsWith('\n') ? text : `${text}\n`, 'utf8');
    process.stderr.write(`Записано в ${options.out}\n`);
    return;
  }
  process.stdout.write(text.endsWith('\n') ? text : `${text}\n`);
}

/** Принимает путь к файлу или сам ключ текстом. */
async function resolveKey(value, what) {
  if (!value) die(`не указан ${what}`);
  if (typeof value === 'string' && !value.includes('epk1.') && !value.includes('BEGIN')) {
    try {
      return readFileSync(value, 'utf8');
    } catch (error) {
      die(`не удалось прочитать ${what} «${value}»: ${error.message}`);
    }
  }
  return value === true ? die(`не указан ${what}`) : value;
}

const passphrase = typeof options.pass === 'string' ? options.pass : null;

async function privateKey() {
  const armor = await resolveKey(options.key, 'приватный ключ (--key <файл>)');
  return core.importPrivateKey(armor, passphrase);
}

/* ------------------------------------------------------------------ */
/* Команды                                                             */
/* ------------------------------------------------------------------ */

async function cmdKeygen() {
  const name = typeof options.name === 'string' ? options.name : 'encryptory';
  const dir = typeof options.out === 'string' ? options.out : '.';
  const identity = await core.generateIdentity(passphrase);

  const privatePath = join(dir, `${name}-private.txt`);
  const publicPath = join(dir, `${name}-public.txt`);
  writeFileSync(privatePath, `${identity.privateKeyArmor.trim()}\n`, 'utf8');
  writeFileSync(publicPath, `${core.publicKeyArmor(identity.publicKeyText).trim()}\n`, 'utf8');

  process.stdout.write([
    `Пара ключей создана (${identity.curveLabel}).`,
    `Отпечаток:   ${identity.fingerprint}`,
    `Публичный:   ${publicPath}  ← этот файл можно отдавать`,
    `Приватный:   ${privatePath}${identity.encryptedAtRest ? '  (защищён паролем)' : '  ← никому не передавайте'}`,
    ``,
    `${core.publicKeyArmor(identity.publicKeyText).trim()}`,
    '',
  ].join('\n'));
}

async function cmdEncrypt() {
  const identity = await privateKey();
  const recipient = await resolveKey(options.to, 'публичный ключ собеседника (--to <файл|ключ>)');
  const { text, fromStream } = await inputText('текст для шифрования');
  const plaintext = fromStream ? text.replace(/\n$/, '') : text;
  const message = await core.encrypt({ plaintext, recipient, identity });
  outputText(message.trim(), 'message');
}

async function cmdDecrypt() {
  const identity = await privateKey();
  const { text } = await inputText('шифротекст');
  const opened = await core.decrypt({ message: text, identity });
  process.stderr.write(
    `Отправитель: ${opened.senderFingerprint}` +
    (opened.timestamp ? `, время: ${new Date(opened.timestamp).toISOString()}` : '') +
    ` [${core.CURVES[opened.curve].label}]\n`
  );
  outputText(opened.plaintext, 'plaintext');
}

async function cmdInspect() {
  const { text } = await inputText('шифротекст');
  const info = await core.inspect(text);
  process.stdout.write([
    `Отправитель:   ${info.senderFingerprint}`,
    `Кривая:        ${info.curveLabel} (${info.version})`,
    `Ключ:          ${info.senderPublicKeyText}`,
    `Время сборки:  ${info.timestamp ? new Date(info.timestamp).toISOString() : 'не указано'}`,
    `Алгоритм:      ${info.algorithm}`,
    '',
  ].join('\n'));
}

async function cmdFingerprint() {
  const key = await resolveKey(options.key, 'публичный ключ (--key <файл|ключ>)');
  process.stdout.write(`${await core.fingerprint(core.parsePublicKey(key).raw)}\n`);
}

async function cmdSelftest() {
  let failed = 0;
  const results = await core.selfTest((step) => {
    if (!step.ok) failed += 1;
    process.stdout.write(`${step.ok ? '  ok  ' : ' FAIL '} ${step.name}${step.detail ? ` — ${step.detail}` : ''} (${step.ms} мс)\n`);
  });
  process.stdout.write(`\n${results.length - failed} из ${results.length} проверок пройдено.\n`);
  process.exit(failed === 0 ? 0 : 1);
}

function help() {
  const [self] = [basename(process.argv[1])];
  process.stdout.write(`Encryptory CLI — ${core.ALGO_LABEL}

Использование: node ${self} <команда> [параметры]

  keygen       создать пару ключей
               --name bob               имя файлов (по умолчанию encryptory)
               --out ./keys             куда положить файлы (по умолчанию .)
               --pass «пароль»          защитить приватный ключ паролем

  encrypt      зашифровать текст для собеседника
               --key <мой приватный ключ> [--pass «пароль»]
               --to  <его публичный ключ — файл или строка>
               --text «…» | --in файл | stdin
               [--out файл]

  decrypt      расшифровать присланный шифротекст
               --key <мой приватный ключ> [--pass «пароль»]
               --text «…» | --in файл | stdin
               [--out файл]

  inspect      посмотреть, от кого сообщение, без расшифровки
  fingerprint  посчитать отпечаток публичного ключа (для сверки голосом)
  selftest     прогнать проверки криптоядра

Пример:
  node ${self} keygen --name alice
  node ${self} keygen --name bob
  node ${self} encrypt --key alice-private.txt --to bob-public.txt --text "привет"
  node ${self} decrypt --key bob-private.txt --in message.txt
`);
}

switch (command) {
  case 'keygen': await cmdKeygen(); break;
  case 'encrypt': await cmdEncrypt(); break;
  case 'decrypt': await cmdDecrypt(); break;
  case 'inspect': await cmdInspect(); break;
  case 'fingerprint': await cmdFingerprint(); break;
  case 'selftest': await cmdSelftest(); break;
  default: help();
}
