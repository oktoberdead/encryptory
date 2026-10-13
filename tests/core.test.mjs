/*
 * Тесты криптоядра. Запуск: npm test  (= node --test tests/*.test.mjs)
 * Тестируется ровно тот же файл, который подключает веб-страница.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(here, '..', 'src', 'encryptory-core.js'), 'utf8');
// Ядро — UMD-файл: грузим его как обычный скрипт в текущий контекст.
const module_ = { exports: {} };
new Function('module', 'globalThis', source)(module_, globalThis);
const core = module_.exports;

const SAMPLE = 'Съешь ещё этих мягких французских булок, да выпей чаю. 🔐 42';
const X25519 = core.CURVES.X25519;
const P256 = core.CURVES['P-256'];

test('ядро экспортирует ожидаемый API', () => {
  for (const name of [
    'generateIdentity', 'encrypt', 'decrypt', 'selfTest', 'fingerprint',
    'parsePublicKey', 'exportPrivateKey', 'importPrivateKey', 'inspect',
    'isCurveSupported', 'parseMessage',
  ]) {
    assert.equal(typeof core[name], 'function', `нет функции ${name}`);
  }
  assert.equal(core.VERSION, 'em2');
  assert.equal(core.DEFAULT_CURVE, 'X25519');
});

test('по умолчанию генерируются ключи X25519 (32 байта)', async () => {
  const alice = await core.generateIdentity();
  assert.equal(alice.curve, 'X25519');
  assert.equal(alice.publicKeyRaw.length, 32);
  assert.match(alice.publicKeyText, /^epk2\./);
  assert.match(alice.privateKeyArmor, /^-----BEGIN ENCRYPTORY PRIVATE KEY-----/);
  assert.ok(core.stripArmor(alice.privateKeyArmor).payload.startsWith('ek2.'));
});

test('X25519 и P-256 поддерживаются этим окружением', async () => {
  assert.equal(await core.isCurveSupported('X25519'), true);
  assert.equal(await core.isCurveSupported('P-256'), true);
});

test('полный цикл: Алиса шифрует, Боб читает', async () => {
  const alice = await core.generateIdentity();
  const bob = await core.generateIdentity();

  const message = await core.encrypt({ plaintext: SAMPLE, recipient: bob.publicKeyText, identity: alice });
  assert.match(message, /^-----BEGIN ENCRYPTORY MESSAGE-----/);
  assert.match(message, /em2\./);
  assert.ok(!message.includes('булок'), 'в шифротексте не должно быть исходного текста');

  const opened = await core.decrypt({ message, identity: bob });
  assert.equal(opened.plaintext, SAMPLE);
  assert.equal(opened.senderFingerprint, alice.fingerprint);
  assert.equal(opened.senderPublicKeyText, alice.publicKeyText);
  assert.equal(opened.curve, 'X25519');
});

test('обратное направление работает теми же ключами', async () => {
  const alice = await core.generateIdentity();
  const bob = await core.generateIdentity();
  const reply = await core.encrypt({ plaintext: 'ответ', recipient: alice.publicKeyText, identity: bob });
  const opened = await core.decrypt({ message: reply, identity: alice });
  assert.equal(opened.plaintext, 'ответ');
  assert.equal(opened.senderFingerprint, bob.fingerprint);
});

test('посылка самому себе шифруется и читается своим же ключом', async () => {
  const alice = await core.generateIdentity();
  const note = await core.encrypt({ plaintext: 'заметка себе', recipient: alice.publicKeyText, identity: alice });
  const opened = await core.decrypt({ message: note, identity: alice });
  assert.equal(opened.plaintext, 'заметка себе');
  assert.equal(opened.senderFingerprint, alice.fingerprint);
});

test('отправитель не читает свою же посылку, адресованную другому (так и должно быть)', async () => {
  const alice = await core.generateIdentity();
  const bob = await core.generateIdentity();
  const message = await core.encrypt({ plaintext: SAMPLE, recipient: bob.publicKeyText, identity: alice });
  await assert.rejects(() => core.decrypt({ message, identity: alice }), /расшифровать не удалось/i);
});

test('третий участник расшифровать не может', async () => {
  const [alice, bob, carol] = await Promise.all([
    core.generateIdentity(), core.generateIdentity(), core.generateIdentity(),
  ]);
  const message = await core.encrypt({ plaintext: SAMPLE, recipient: bob.publicKeyText, identity: alice });
  await assert.rejects(() => core.decrypt({ message, identity: carol }), /расшифровать не удалось/i);
});

test('порча шифротекста ломает расшифровку (AES-GCM аутентификация)', async () => {
  const alice = await core.generateIdentity();
  const bob = await core.generateIdentity();
  const message = await core.encrypt({ plaintext: SAMPLE, recipient: bob.publicKeyText, identity: alice });

  const payload = core.stripArmor(message).payload.split('.');
  const body = Buffer.from(payload[5].replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  body[4] ^= 0x01;
  payload[5] = body.toString('base64url');
  await assert.rejects(() => core.decrypt({ message: payload.join('.'), identity: bob }), /расшифровать не удалось/i);
});

test('подмена ключа отправителя обнаруживается (привязка через HKDF info)', async () => {
  const alice = await core.generateIdentity();
  const bob = await core.generateIdentity();
  const carol = await core.generateIdentity();
  const message = await core.encrypt({ plaintext: SAMPLE, recipient: bob.publicKeyText, identity: alice });

  const payload = core.stripArmor(message).payload.split('.');
  payload[1] = core.parsePublicKey(carol.publicKeyText).text.slice(X25519.publicPrefix.length);
  await assert.rejects(() => core.decrypt({ message: payload.join('.'), identity: bob }), /расшифровать не удалось/i);
});

test('подмена nonce и подмена времени в заголовке обнаруживаются', async () => {
  const alice = await core.generateIdentity();
  const bob = await core.generateIdentity();
  const message = await core.encrypt({ plaintext: SAMPLE, recipient: bob.publicKeyText, identity: alice });

  const withNonce = core.stripArmor(message).payload.split('.');
  withNonce[3] = Buffer.from(crypto.getRandomValues(new Uint8Array(12))).toString('base64url');
  await assert.rejects(() => core.decrypt({ message: withNonce.join('.'), identity: bob }), /расшифровать не удалось/i);

  const withTime = core.stripArmor(message).payload.split('.');
  withTime[4] = String(Number(withTime[4]) + 86400);
  await assert.rejects(() => core.decrypt({ message: withTime.join('.'), identity: bob }), /расшифровать не удалось/i);
});

test('шифрование требует непустой текст', async () => {
  const alice = await core.generateIdentity();
  const bob = await core.generateIdentity();
  await assert.rejects(() => core.encrypt({ plaintext: '', recipient: bob.publicKeyText, identity: alice }), /текст пуст/i);
});

test('inspect показывает отправителя, время и кривую без расшифровки', async () => {
  const alice = await core.generateIdentity();
  const bob = await core.generateIdentity();
  const message = await core.encrypt({ plaintext: SAMPLE, recipient: bob.publicKeyText, identity: alice });
  const info = await core.inspect(message);
  assert.equal(info.senderFingerprint, alice.fingerprint);
  assert.equal(info.curve, 'X25519');
  assert.ok(info.timestamp > 0);
  assert.match(info.algorithm, /X25519/);
});

test('публичный ключ переживает форматы: armor, префикс, raw, JWK', async () => {
  const alice = await core.generateIdentity();
  const armored = core.publicKeyArmor(alice.publicKeyText);
  assert.equal(core.parsePublicKey(armored).text, alice.publicKeyText);
  assert.equal(core.parsePublicKey(alice.publicKeyText).text, alice.publicKeyText);

  const rawB64u = alice.publicKeyText.slice(X25519.publicPrefix.length);
  assert.equal(core.parsePublicKey(rawB64u).text, alice.publicKeyText);

  const jwk = await crypto.subtle.exportKey('jwk', await crypto.subtle.importKey(
    'raw',
    Buffer.from(rawB64u, 'base64url'),
    { name: 'X25519' },
    true,
    []
  ));
  assert.equal(jwk.kty, 'OKP');
  assert.equal(core.parsePublicKey(JSON.stringify(jwk)).text, alice.publicKeyText);

  assert.throws(() => core.parsePublicKey('не-ключ-вообще'), /base64url|Публичный ключ|непонятной длины/i);
});

test('старый формат ECDH P-256 (epk1/ek1, контейнер em1) продолжает работать', async () => {
  const alice = await core.generateIdentity(null, 'P-256');
  const bob = await core.generateIdentity(null, 'P-256');
  assert.equal(alice.curve, 'P-256');
  assert.equal(alice.publicKeyRaw.length, 65);
  assert.match(alice.publicKeyText, /^epk1\./);

  const restored = await core.importPrivateKey(alice.privateKeyArmor);
  assert.equal(restored.curve, 'P-256');
  assert.equal(restored.publicKeyText, alice.publicKeyText);

  const message = await core.encrypt({ plaintext: 'старый формат', recipient: bob.publicKeyText, identity: alice });
  assert.match(core.stripArmor(message).payload, /^em1\./);
  const opened = await core.decrypt({ message, identity: bob });
  assert.equal(opened.plaintext, 'старый формат');
  assert.equal(opened.curve, 'P-256');
});

test('ключи разных кривых не смешиваются (понятная ошибка вместо мусора)', async () => {
  const modern = await core.generateIdentity();               // X25519
  const legacy = await core.generateIdentity(null, 'P-256');  // P-256

  await assert.rejects(
    () => core.encrypt({ plaintext: 'x', recipient: legacy.publicKeyText, identity: modern }),
    (error) => error.code === 'CURVE_MISMATCH' && /X25519/.test(error.message) && /P-256/.test(error.message)
  );

  const legacyMessage = await core.encrypt({ plaintext: 'x', recipient: legacy.publicKeyText, identity: legacy });
  await assert.rejects(
    () => core.decrypt({ message: legacyMessage, identity: modern }),
    (error) => error.code === 'CURVE_MISMATCH'
  );
});

test('защита ключа паролем работает на обеих кривых', async () => {
  for (const curveId of ['X25519', 'P-256']) {
    const identity = await core.generateIdentity('пароль-' + curveId, curveId);
    assert.equal(identity.encryptedAtRest, true);
    assert.equal(core.isPrivateKeyProtected(identity.privateKeyArmor), true);

    const restored = await core.importPrivateKey(identity.privateKeyArmor, 'пароль-' + curveId);
    assert.equal(restored.curve, curveId);
    assert.equal(restored.publicKeyText, identity.publicKeyText);

    await assert.rejects(() => core.importPrivateKey(identity.privateKeyArmor, 'не тот пароль'), /неверный пароль/i);
    await assert.rejects(() => core.importPrivateKey(identity.privateKeyArmor), /паролем/i);
  }
});

test('парольная защита приватного ключа (подробно, X25519)', async () => {
  const alice = await core.generateIdentity();
  const protectedArmor = await core.exportPrivateKey(alice.privateKeyPkcs8, 'котики-42', alice.curve);
  assert.equal(core.isPrivateKeyProtected(protectedArmor), true);

  const restored = await core.importPrivateKey(protectedArmor, 'котики-42');
  assert.equal(restored.publicKeyText, alice.publicKeyText);
  assert.equal(restored.fingerprint, alice.fingerprint);
  assert.equal(restored.encryptedAtRest, true);
});

test('незащищённый приватный ключ читается и совпадает с публичным', async () => {
  const alice = await core.generateIdentity();
  const restored = await core.importPrivateKey(alice.privateKeyArmor);
  assert.equal(restored.publicKeyText, alice.publicKeyText);
  assert.equal(restored.encryptedAtRest, false);

  // и таким импортированным ключом можно расшифровать чужое сообщение
  const bob = await core.generateIdentity();
  const message = await core.encrypt({ plaintext: 'проверка', recipient: core.publicKeyToText(alice.publicKeyRaw), identity: bob });
  const opened = await core.decrypt({ message, identity: restored });
  assert.equal(opened.plaintext, 'проверка');
});

test('ключ в формате с переносами строк и пробелами читается', async () => {
  const alice = await core.generateIdentity();
  const messy = '\n\n' + core.publicKeyArmor(alice.publicKeyText).split('\n').join('  \n') + '\n\n';
  assert.equal(core.parsePublicKey(messy).text, alice.publicKeyText);
});

test('большой текст (200 КБ) шифруется и читается на X25519', async () => {
  const alice = await core.generateIdentity();
  const bob = await core.generateIdentity();
  const big = 'Строка проверки целостности 🔐\n'.repeat(7500);
  const message = await core.encrypt({ plaintext: big, recipient: bob.publicKeyText, identity: alice });
  const opened = await core.decrypt({ message, identity: bob });
  assert.equal(opened.plaintext, big);
});

test('две одинаковые посылки дают разный шифротекст (случайная соль и nonce)', async () => {
  const alice = await core.generateIdentity();
  const bob = await core.generateIdentity();
  const a = await core.encrypt({ plaintext: SAMPLE, recipient: bob.publicKeyText, identity: alice });
  const b = await core.encrypt({ plaintext: SAMPLE, recipient: bob.publicKeyText, identity: alice });
  assert.notEqual(a, b);
});

test('строка тела с ведущими дефисами не считается разделителем брони', () => {
  const tricky = '-----BEGIN ENCRYPTORY MESSAGE-----\nem2.aaa.bbb.ccc.123.---abc--def\n-----END ENCRYPTORY MESSAGE-----';
  const { payload, type } = core.stripArmor(tricky);
  assert.equal(type, 'ENCRYPTORY MESSAGE');
  assert.equal(payload, 'em2.aaa.bbb.ccc.123.---abc--def');
});

test('сообщение с дефисами в начале строки тела расшифровывается', async () => {
  const alice = await core.generateIdentity();
  const bob = await core.generateIdentity();
  // Чем больше текст, тем длиннее тело в base64url — и тем вероятнее, что какая-то
  // строка начнётся с «---». Раньше такие строки молча выкидывались как разделители.
  const big = 'проверка'.repeat(150000);
  const message = await core.encrypt({ plaintext: big, recipient: bob.publicKeyText, identity: alice });
  const parts = core.stripArmor(message).payload.split('.');
  const body = parts[5];
  const at = body.indexOf('---');
  if (at < 0) return; // редкая случайность — гоняем в следующий раз
  const rewrapped = [
    '-----BEGIN ENCRYPTORY MESSAGE-----',
    `${parts.slice(0, 5).join('.')}.${body.slice(0, at)}`,
    body.slice(at),
    '-----END ENCRYPTORY MESSAGE-----',
  ].join('\n');
  const opened = await core.decrypt({ message: rewrapped, identity: bob });
  assert.equal(opened.plaintext, big);
});

test('шифротекст, процитированный в письме («> »), всё ещё читается', async () => {
  const alice = await core.generateIdentity();
  const bob = await core.generateIdentity();
  const message = await core.encrypt({ plaintext: SAMPLE, recipient: bob.publicKeyText, identity: alice });
  const quoted = message.trim().split('\n').map((line) => `> ${line}`).join('\n');
  const opened = await core.decrypt({ message: quoted, identity: bob });
  assert.equal(opened.plaintext, SAMPLE);
});

test('битая броня и чужая версия контейнера дают понятные ошибки', async () => {
  const bob = await core.generateIdentity();
  await assert.rejects(() => core.decrypt({ message: 'просто текст', identity: bob }), /повреждено|не сообщение/i);

  const alice = await core.generateIdentity();
  const message = await core.encrypt({ plaintext: 'x', recipient: bob.publicKeyText, identity: alice });
  const payload = core.stripArmor(message).payload.split('.');
  payload[0] = 'em99';
  await assert.rejects(() => core.decrypt({ message: payload.join('.'), identity: bob }), /версия/i);

  // Старый парсер v1 без поддержки em2 тоже должен ругаться на версию, а не падать
  assert.throws(() => core.parseMessage(payload.join('.')), /версия/i);
});

test('отпечаток стабилен и различается у разных ключей', async () => {
  const alice = await core.generateIdentity();
  const bob = await core.generateIdentity();
  const again = await core.fingerprint(alice.publicKeyText);
  assert.equal(again, alice.fingerprint);
  assert.match(alice.fingerprint, /^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){4}$/);
  assert.notEqual(alice.fingerprint, bob.fingerprint);
  // отпечаток не зависит от кривой как от «соли»: это хэш самих байт ключа
  const legacy = await core.generateIdentity(null, 'P-256');
  assert.equal(await core.fingerprint(legacy.publicKeyText), legacy.fingerprint);
});

test('selfTest проходит целиком (обе кривые)', async () => {
  const steps = [];
  const results = await core.selfTest((step) => steps.push(step.name));
  const failed = results.filter((r) => !r.ok);
  assert.deepEqual(failed, [], `упавшие шаги: ${JSON.stringify(failed, null, 2)}`);
  assert.ok(results.length >= 20, 'ожидалось не меньше 20 проверок');
  assert.equal(steps.length, results.length);
  assert.ok(results.some((r) => /P-256/.test(r.name)), 'должны быть проверки старого формата');
});
