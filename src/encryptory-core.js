/*
 * Encryptory core — асимметричное шифрование текста.
 *
 * Схема (гибридная, на двух парах ключей):
 *  1. У каждого участника своя пара ключей ECDH P-256 (публичный + приватный).
 *  2. Общий секрет = ECDH(мой_приватный, публичный_ключ_собеседника).
 *     У обоих участников он получается одинаковым, по проводам никогда не идёт.
 *  3. Из общего секрета через HKDF-SHA256 выводится ключ AES-256-GCM.
 *     В HKDF "info" зашиты оба публичных ключа, поэтому чужой ключ не подойдёт.
 *  4. Текст шифруется AES-256-GCM (аутентифицированное шифрование: подделка
 *     или порча шифротекста приводит к ошибке, а не к мусору на выходе).
 *
 * Файл написан без зависимостей и работает и в браузере (window.EncryptoryCore),
 * и в Node.js (module.exports) — на одном и том же WebCrypto API.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (typeof globalThis !== 'undefined') globalThis.EncryptoryCore = api;
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const CURVE = 'P-256';
  const VERSION = 'em1';
  const PUBLIC_PREFIX = 'epk1.';
  const PRIVATE_PREFIX = 'ek1.';
  const PRIVATE_PROTECTED_PREFIX = 'ek1p.';
  const HKDF_INFO_PREFIX = 'encryptory/v1|';
  const PBKDF2_ITERATIONS = 310000;

  const ALGO_LABEL = 'ECDH P-256 + HKDF-SHA256 + AES-256-GCM';
  const ALGO_DETAILS =
    'Публичный ключ каждого участника + ECDH → общий секрет → HKDF-SHA256 → AES-256-GCM. ' +
    'Приватные ключи никогда не покидают устройство.';

  const ARMOR_TYPES = {
    MESSAGE: 'ENCRYPTORY MESSAGE',
    PUBLIC_KEY: 'ENCRYPTORY PUBLIC KEY',
    PRIVATE_KEY: 'ENCRYPTORY PRIVATE KEY',
  };

  const BASE32_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  const textEncoder = new TextEncoder();
  const textDecoder = new TextDecoder();

  /* ------------------------------------------------------------------ */
  /* Ошибки                                                              */
  /* ------------------------------------------------------------------ */

  class EncryptoryError extends Error {
    constructor(code, message) {
      super(message);
      this.name = 'EncryptoryError';
      this.code = code;
    }
  }

  const fail = (code, message) => {
    throw new EncryptoryError(code, message);
  };

  /* ------------------------------------------------------------------ */
  /* Низкоуровневые помощники                                            */
  /* ------------------------------------------------------------------ */

  function getSubtle() {
    const c = globalThis.crypto;
    if (!c || !c.subtle || typeof c.subtle.generateKey !== 'function') {
      fail(
        'NO_WEBCRYPTO',
        'WebCrypto недоступен. Откройте страницу по https:// или на localhost, либо запустите Node.js 20+.'
      );
    }
    return c.subtle;
  }

  function randomBytes(length) {
    const c = globalThis.crypto;
    if (!c || typeof c.getRandomValues !== 'function') {
      fail('NO_RANDOM', 'Источник криптостойкой случайности недоступен в этом окружении.');
    }
    const out = new Uint8Array(length);
    c.getRandomValues(out);
    return out;
  }

  /**
   * Приводит значение к Uint8Array.
   * Проверки намеренно не используют instanceof по границе realm: данные могут
   * прийти из воркера, iframe или другого контекста, где свои конструкторы.
   */
  function toBytes(value) {
    if (value !== null && typeof value === 'object') {
      if (ArrayBuffer.isView(value)) {
        return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
      }
      const tag = Object.prototype.toString.call(value);
      if (tag === '[object ArrayBuffer]' || tag === '[object SharedArrayBuffer]') {
        return new Uint8Array(value);
      }
    }
    fail('BAD_INPUT', 'Ожидались байты (Uint8Array или ArrayBuffer).');
  }

  function concatBytes(...chunks) {
    let total = 0;
    for (const chunk of chunks) total += chunk.length;
    const out = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      out.set(chunk, offset);
      offset += chunk.length;
    }
    return out;
  }

  function bytesToB64u(value) {
    const bytes = toBytes(value);
    let base64;
    if (typeof Buffer !== 'undefined' && typeof Buffer.from === 'function') {
      base64 = Buffer.from(bytes).toString('base64');
    } else {
      let binary = '';
      for (let i = 0; i < bytes.length; i += 0x8000) {
        binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
      }
      base64 = btoa(binary);
    }
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function b64uToBytes(text, what) {
    const label = what || 'данные';
    const clean = String(text == null ? '' : text).replace(/\s+/g, '');
    if (!clean) fail('BAD_BASE64', `Пустая строка вместо ${label}.`);
    if (!/^[A-Za-z0-9\-_]+$/.test(clean)) {
      fail('BAD_BASE64', `В ${label} есть символы, не похожие на base64url.`);
    }
    const base64 = clean.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (clean.length % 4)) % 4);
    try {
      if (typeof Buffer !== 'undefined' && typeof Buffer.from === 'function') {
        return new Uint8Array(Buffer.from(base64, 'base64'));
      }
      const binary = atob(base64);
      const out = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
      return out;
    } catch (error) {
      fail('BAD_BASE64', `Не удалось разобрать ${label}: строка не является корректным base64url.`);
    }
  }

  function base32(bytes) {
    let bits = 0;
    let value = 0;
    let out = '';
    for (const byte of bytes) {
      value = (value << 8) | byte;
      bits += 8;
      while (bits >= 5) {
        out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }
    if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
    return out;
  }

  function encodeUtf8(text) {
    return textEncoder.encode(text);
  }

  function decodeUtf8(bytes) {
    return textDecoder.decode(bytes);
  }

  /* ------------------------------------------------------------------ */
  /* Бронирование (armor) — читаемый текстовый контейнер                 */
  /* ------------------------------------------------------------------ */

  function wrapLines(text, width) {
    const limit = width || 76;
    if (text.length <= limit) return text;
    const lines = [];
    for (let i = 0; i < text.length; i += limit) lines.push(text.slice(i, i + limit));
    return lines.join('\n');
  }

  function armor(type, payload, width) {
    const begin = `-----BEGIN ${type}-----`;
    const end = `-----END ${type}-----`;
    return `${begin}\n${wrapLines(payload, width)}\n${end}\n`;
  }

  /**
   * Снимает броню (если есть) и склеивает тело в одну строку.
   * Заодно переживает цитирование из писем и чатов (ведущие «>»).
   */
  /**
   * Разделитель брони. Требуем и дефисы, и слово BEGIN/END, и пробел после него:
   * обычная строка base64url под это не подходит (пробелы в алфавит не входят),
   * поэтому тело сообщения нельзя потерять по ошибке — даже если строка
   * случайно начинается с «---».
   */
  const ARMOR_BEGIN = /^-{3,}\s*BEGIN\s+([A-Za-z0-9 ]+?)\s*-{3,}$/i;
  const ARMOR_END = /^-{3,}\s*END\s+[A-Za-z0-9 ]+?\s*-{3,}$/i;

  function stripArmor(text) {
    const lines = String(text == null ? '' : text).replace(/\r/g, '').split('\n');
    let type = null;
    const body = [];
    for (const rawLine of lines) {
      // «> » в начале — следы цитирования в почте и мессенджерах.
      const line = rawLine.replace(/^\s*>+\s*/, '').trim();
      if (!line) continue;
      const begin = ARMOR_BEGIN.exec(line);
      if (begin) {
        type = begin[1].replace(/\s+/g, ' ').toUpperCase();
        continue;
      }
      if (ARMOR_END.test(line)) continue;
      body.push(line);
    }
    return { type, payload: body.join('') };
  }

  function isArmored(text, type) {
    const { type: found } = stripArmor(text);
    return type ? found === type : Boolean(found);
  }

  /* ------------------------------------------------------------------ */
  /* Публичные ключи                                                     */
  /* ------------------------------------------------------------------ */

  function rawFromJwk(jwk) {
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) {
      fail('BAD_PUBLIC_KEY', 'Ключ не является ключом ECDH на кривой P-256.');
    }
    const x = b64uToBytes(jwk.x, 'координате X ключа');
    const y = b64uToBytes(jwk.y, 'координате Y ключа');
    if (x.length !== 32 || y.length !== 32) {
      fail('BAD_PUBLIC_KEY', 'Координаты ключа P-256 должны быть длиной 32 байта.');
    }
    return concatBytes(Uint8Array.of(0x04), x, y);
  }

  function assertPublicRaw(raw, what) {
    if (raw.length !== 65 || raw[0] !== 0x04) {
      fail('BAD_PUBLIC_KEY', `${what || 'Публичный ключ'} должен быть несжатой точкой P-256 (65 байт).`);
    }
    return raw;
  }

  /**
   * Разбирает публичный ключ из текста.
   * Принимает: epk1.<base64url>, голый base64url, JWK (JSON), с бронёй или без.
   */
  function parsePublicKey(input) {
    const { payload } = stripArmor(input);
    if (!payload) fail('BAD_PUBLIC_KEY', 'Публичный ключ не найден. Вставьте ключ, полученный от собеседника.');
    let raw;
    if (payload.startsWith(PUBLIC_PREFIX)) {
      raw = b64uToBytes(payload.slice(PUBLIC_PREFIX.length), 'публичном ключе');
    } else if (payload.startsWith('{')) {
      let jwk;
      try {
        jwk = JSON.parse(payload);
      } catch (error) {
        fail('BAD_PUBLIC_KEY', 'Похоже на JSON, но разобрать его не получилось.');
      }
      raw = rawFromJwk(jwk);
    } else {
      raw = b64uToBytes(payload, 'публичном ключе');
    }
    assertPublicRaw(raw, 'Публичный ключ');
    return { raw, text: PUBLIC_PREFIX + bytesToB64u(raw) };
  }

  function publicKeyToText(rawOrJwk) {
    if (rawOrJwk && typeof rawOrJwk === 'object' && typeof rawOrJwk.kty === 'string') {
      return PUBLIC_PREFIX + bytesToB64u(rawFromJwk(rawOrJwk));
    }
    return PUBLIC_PREFIX + bytesToB64u(assertPublicRaw(toBytes(rawOrJwk), 'Публичный ключ'));
  }

  function publicKeyToArmor(rawOrText) {
    const text = typeof rawOrText === 'string' && rawOrText.includes('.')
      ? parsePublicKey(rawOrText).text
      : publicKeyToText(rawOrText);
    return armor(ARMOR_TYPES.PUBLIC_KEY, text);
  }

  /** Короткий отпечаток ключа — чтобы глазами сверять, что ключ «тот самый». */
  async function fingerprint(rawOrText) {
    const raw = typeof rawOrText === 'string'
      ? parsePublicKey(rawOrText).raw
      : assertPublicRaw(toBytes(rawOrText), 'Публичный ключ');
    const digest = new Uint8Array(await getSubtle().digest('SHA-256', raw));
    const b32 = base32(digest.subarray(0, 12));
    return (b32.match(/.{1,4}/g) || []).slice(0, 5).join('-');
  }

  /* ------------------------------------------------------------------ */
  /* Приватные ключи                                                     */
  /* ------------------------------------------------------------------ */

  async function importPrivateKeyBytes(pkcs8) {
    try {
      return await getSubtle().importKey(
        'pkcs8',
        toBytes(pkcs8),
        { name: 'ECDH', namedCurve: CURVE },
        true,
        ['deriveBits']
      );
    } catch (error) {
      fail('BAD_PRIVATE_KEY', 'Не удалось прочитать приватный ключ: файл повреждён или это не ключ Encryptory.');
    }
  }

  async function pbkdf2Key(passphrase, salt, iterations) {
    const base = await getSubtle().importKey('raw', encodeUtf8(passphrase), 'PBKDF2', false, ['deriveKey']);
    return getSubtle().deriveKey(
      { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
      base,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Собирает бронированный приватный ключ.
   * Без пароля — как есть (ek1.), с паролем — PBKDF2-SHA256 + AES-256-GCM (ek1p.).
   */
  async function exportPrivateKey(pkcs8OrIdentity, passphrase) {
    const pkcs8 = toBytes(
      pkcs8OrIdentity && pkcs8OrIdentity.privateKeyPkcs8
        ? pkcs8OrIdentity.privateKeyPkcs8
        : pkcs8OrIdentity
    );
    if (!passphrase) {
      return armor(ARMOR_TYPES.PRIVATE_KEY, PRIVATE_PREFIX + bytesToB64u(pkcs8));
    }
    const salt = randomBytes(16);
    const iv = randomBytes(12);
    const key = await pbkdf2Key(passphrase, salt, PBKDF2_ITERATIONS);
    const ct = await getSubtle().encrypt({ name: 'AES-GCM', iv }, key, pkcs8);
    const envelope = {
      v: 1,
      kdf: 'PBKDF2-SHA256',
      iter: PBKDF2_ITERATIONS,
      salt: bytesToB64u(salt),
      iv: bytesToB64u(iv),
      ct: bytesToB64u(ct),
    };
    return armor(ARMOR_TYPES.PRIVATE_KEY, PRIVATE_PROTECTED_PREFIX + bytesToB64u(encodeUtf8(JSON.stringify(envelope))));
  }

  /** Разбирает бронированный приватный ключ (при необходимости — с паролем). */
  async function importPrivateKey(armoredText, passphrase) {
    const { type, payload } = stripArmor(armoredText);
    if (type && type !== ARMOR_TYPES.PRIVATE_KEY) {
      fail('BAD_PRIVATE_KEY', 'Это не приватный ключ Encryptory, а что-то другое.');
    }
    let pkcs8;
    if (payload.startsWith(PRIVATE_PROTECTED_PREFIX)) {
      if (!passphrase) {
        fail('PASSPHRASE_REQUIRED', 'Приватный ключ защищён паролем — укажите пароль.');
      }
      let envelope;
      try {
        envelope = JSON.parse(decodeUtf8(b64uToBytes(payload.slice(PRIVATE_PROTECTED_PREFIX.length), 'приватном ключе')));
      } catch (error) {
        fail('BAD_PRIVATE_KEY', 'Не удалось разобрать контейнер защищённого ключа.');
      }
      const salt = b64uToBytes(envelope.salt, 'соли ключа');
      const iv = b64uToBytes(envelope.iv, 'nonce ключа');
      const ct = b64uToBytes(envelope.ct, 'шифротекста ключа');
      const iterations = Number(envelope.iter) || PBKDF2_ITERATIONS;
      const key = await pbkdf2Key(passphrase, salt, iterations);
      try {
        pkcs8 = new Uint8Array(await getSubtle().decrypt({ name: 'AES-GCM', iv }, key, ct));
      } catch (error) {
        fail('BAD_PASSPHRASE', 'Неверный пароль или повреждённый ключ.');
      }
    } else if (payload.startsWith(PRIVATE_PREFIX)) {
      pkcs8 = b64uToBytes(payload.slice(PRIVATE_PREFIX.length), 'приватном ключе');
    } else {
      fail('BAD_PRIVATE_KEY', 'Не похоже на приватный ключ Encryptory.');
    }

    const privateKey = await importPrivateKeyBytes(pkcs8);
    let jwk;
    try {
      jwk = await getSubtle().exportKey('jwk', privateKey);
    } catch (error) {
      fail('BAD_PRIVATE_KEY', 'Ключ прочитан, но извлечь публичную часть не получилось.');
    }
    const raw = rawFromJwk(jwk);
    return {
      publicKeyText: PUBLIC_PREFIX + bytesToB64u(raw),
      publicKeyRaw: raw,
      fingerprint: await fingerprint(raw),
      privateKey,
      privateKeyPkcs8: pkcs8,
      privateKeyArmor: String(armoredText).trim() + '\n',
      encryptedAtRest: payload.startsWith(PRIVATE_PROTECTED_PREFIX),
    };
  }

  function isPrivateKeyProtected(armoredText) {
    return stripArmor(armoredText).payload.startsWith(PRIVATE_PROTECTED_PREFIX);
  }

  /* ------------------------------------------------------------------ */
  /* Идентичность                                                        */
  /* ------------------------------------------------------------------ */

  /** Генерирует новую пару ключей. */
  async function generateIdentity(passphrase) {
    const subtle = getSubtle();
    const pair = await subtle.generateKey({ name: 'ECDH', namedCurve: CURVE }, true, ['deriveBits']);
    const raw = new Uint8Array(await subtle.exportKey('raw', pair.publicKey));
    const pkcs8 = new Uint8Array(await subtle.exportKey('pkcs8', pair.privateKey));
    return {
      publicKeyText: PUBLIC_PREFIX + bytesToB64u(raw),
      publicKeyRaw: raw,
      fingerprint: await fingerprint(raw),
      privateKey: pair.privateKey,
      privateKeyPkcs8: pkcs8,
      privateKeyArmor: await exportPrivateKey(pkcs8, passphrase || null),
      encryptedAtRest: Boolean(passphrase),
    };
  }

  function publicKeyArmor(identityOrText) {
    const text = typeof identityOrText === 'string' ? identityOrText : identityOrText.publicKeyText;
    return publicKeyToArmor(text);
  }

  async function getPrivateKey(identity) {
    if (!identity) fail('NO_IDENTITY', 'Сначала сгенерируйте или импортируйте свою пару ключей.');
    if (identity.privateKey) return identity.privateKey;
    if (identity.privateKeyPkcs8) return importPrivateKeyBytes(identity.privateKeyPkcs8);
    if (identity.privateKeyArmor) {
      const parsed = await importPrivateKey(identity.privateKeyArmor, identity.passphrase);
      return parsed.privateKey;
    }
    fail('NO_IDENTITY', 'У идентичности нет приватного ключа.');
  }

  function getPublicRaw(identity) {
    if (!identity) fail('NO_IDENTITY', 'Нет идентичности.');
    if (identity.publicKeyRaw) return assertPublicRaw(toBytes(identity.publicKeyRaw), 'Публичный ключ');
    if (identity.publicKeyText) return parsePublicKey(identity.publicKeyText).raw;
    fail('NO_IDENTITY', 'У идентичности нет публичного ключа.');
  }

  /* ------------------------------------------------------------------ */
  /* Вывод ключа шифрования                                              */
  /* ------------------------------------------------------------------ */

  function compareBytes(a, b) {
    const len = Math.min(a.length, b.length);
    for (let i = 0; i < len; i += 1) {
      if (a[i] !== b[i]) return a[i] - b[i];
    }
    return a.length - b.length;
  }

  /**
   * ECDH + HKDF → ключ AES-256-GCM.
   * myPrivateKey      — приватный ключ своей пары
   * peerPublicRaw     — публичный ключ собеседника
   * salt              — случайная соль сообщения
   * myPublicRaw / peerPublicRaw передаются ещё раз для привязки ключа к паре участников.
   */
  async function deriveAesKey(myPrivateKey, peerPublicRaw, salt, pubA, pubB) {
    const subtle = getSubtle();
    const peerKey = await subtle.importKey(
      'raw',
      assertPublicRaw(toBytes(peerPublicRaw), 'Публичный ключ собеседника'),
      { name: 'ECDH', namedCurve: CURVE },
      false,
      []
    );
    let shared;
    try {
      shared = await subtle.deriveBits({ name: 'ECDH', public: peerKey }, myPrivateKey, 256);
    } catch (error) {
      fail('ECDH_FAILED', 'Не удалось выработать общий секрет — проверьте, что ключи относятся к кривой P-256.');
    }
    const ordered = [toBytes(pubA), toBytes(pubB)].sort(compareBytes);
    const info = concatBytes(encodeUtf8(HKDF_INFO_PREFIX), ordered[0], ordered[1]);
    const hkdfKey = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
    return subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: toBytes(salt), info },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /* ------------------------------------------------------------------ */
  /* Шифрование / расшифровка                                            */
  /* ------------------------------------------------------------------ */

  /**
   * Шифрует текст для получателя.
   *   { plaintext, recipient (ключ-текст), identity }  →  бронированный текст
   */
  async function encrypt({ plaintext, recipient, identity, now }) {
    if (typeof plaintext !== 'string' || plaintext.length === 0) {
      fail('EMPTY_TEXT', 'Нечего шифровать: текст пуст.');
    }
    const recipientKey = parsePublicKey(recipient);
    const senderRaw = getPublicRaw(identity);
    const myPrivateKey = await getPrivateKey(identity);

    const salt = randomBytes(32);
    const iv = randomBytes(12);
    const timestamp = Math.floor((now ? Number(now) : Date.now()) / 1000);
    const header = [VERSION, bytesToB64u(senderRaw), bytesToB64u(salt), bytesToB64u(iv), String(timestamp)].join('.');

    const aesKey = await deriveAesKey(myPrivateKey, recipientKey.raw, salt, senderRaw, recipientKey.raw);
    const ciphertext = await getSubtle().encrypt(
      { name: 'AES-GCM', iv, additionalData: encodeUtf8(header), tagLength: 128 },
      aesKey,
      encodeUtf8(plaintext)
    );
    return armor(ARMOR_TYPES.MESSAGE, `${header}.${bytesToB64u(ciphertext)}`);
  }

  /** Читает «конверт» без расшифровки: от кого и когда. */
  function parseMessage(armoredText) {
    const { type, payload } = stripArmor(armoredText);
    if (type && type !== ARMOR_TYPES.MESSAGE) {
      fail('BAD_MESSAGE', 'Это не сообщение Encryptory.');
    }
    const parts = payload.split('.');
    if (parts.length !== 6) {
      fail('BAD_MESSAGE', 'Сообщение повреждено: не совпадает число частей контейнера.');
    }
    const [version, senderB64, saltB64, ivB64, timestamp, body] = parts;
    if (version !== VERSION) {
      fail('UNSUPPORTED_VERSION', `Неизвестная версия контейнера «${version}» — возможно, шифровано более новой версией Encryptory.`);
    }
    const senderRaw = assertPublicRaw(b64uToBytes(senderB64, 'ключе отправителя'), 'Ключ отправителя');
    return {
      version,
      senderRaw,
      senderPublicKeyText: PUBLIC_PREFIX + bytesToB64u(senderRaw),
      senderB64,
      salt: b64uToBytes(saltB64, 'соли сообщения'),
      iv: b64uToBytes(ivB64, 'nonce сообщения'),
      ciphertext: b64uToBytes(body, 'шифротексте'),
      timestamp: Number(timestamp) * 1000 || null,
      header: [version, senderB64, saltB64, ivB64, timestamp].join('.'),
    };
  }

  /** Метаданные сообщения без расшифровки. */
  async function inspect(armoredText) {
    const parsed = parseMessage(armoredText);
    return {
      senderPublicKeyText: parsed.senderPublicKeyText,
      senderFingerprint: await fingerprint(parsed.senderRaw),
      timestamp: parsed.timestamp,
      algorithm: ALGO_LABEL,
    };
  }

  function looksLikeMessage(text) {
    const { type, payload } = stripArmor(text);
    if (type === ARMOR_TYPES.MESSAGE) return true;
    return payload.startsWith(`${VERSION}.`);
  }

  /** Расшифровывает сообщение своим приватным ключом. */
  async function decrypt({ message, identity }) {
    const parsed = parseMessage(message);
    const myPrivateKey = await getPrivateKey(identity);
    const myPublicRaw = getPublicRaw(identity);

    const aesKey = await deriveAesKey(myPrivateKey, parsed.senderRaw, parsed.salt, parsed.senderRaw, myPublicRaw);
    let plaintextBytes;
    try {
      plaintextBytes = await getSubtle().decrypt(
        { name: 'AES-GCM', iv: parsed.iv, additionalData: encodeUtf8(parsed.header), tagLength: 128 },
        aesKey,
        parsed.ciphertext
      );
    } catch (error) {
      fail(
        'DECRYPT_FAILED',
        'Расшифровать не удалось. Сообщение повреждено, подделано или зашифровано не для вашего ключа.'
      );
    }
    return {
      plaintext: decodeUtf8(plaintextBytes),
      senderPublicKeyText: parsed.senderPublicKeyText,
      senderFingerprint: await fingerprint(parsed.senderRaw),
      timestamp: parsed.timestamp,
    };
  }

  /* ------------------------------------------------------------------ */
  /* Самопроверка                                                        */
  /* ------------------------------------------------------------------ */

  /**
   * Прогоняет полный цикл «зашифровал → расшифровал» и набор негативных проверок.
   * Возвращает список { name, ok, detail, ms }.
   */
  async function selfTest(onStep) {
    const results = [];
    const run = async (name, fn) => {
      const started = Date.now();
      try {
        const detail = await fn();
        results.push({ name, ok: true, detail: detail || '', ms: Date.now() - started });
      } catch (error) {
        results.push({ name, ok: false, detail: error && error.message ? error.message : String(error), ms: Date.now() - started });
      }
      if (typeof onStep === 'function') onStep(results[results.length - 1]);
      return results[results.length - 1];
    };
    const expectFailure = async (fn, expectedCode) => {
      try {
        await fn();
      } catch (error) {
        if (expectedCode && error.code !== expectedCode) {
          fail('SELFTEST', `ожидалась ошибка ${expectedCode}, получена ${error.code}`);
        }
        return null;
      }
      fail('SELFTEST', 'операция завершилась успешно, хотя должна была упасть');
    };

    let alice;
    let bob;
    let carol;

    await run('Генерация пары ключей (Алиса)', async () => {
      alice = await generateIdentity();
      return `отпечаток ${alice.fingerprint}`;
    });
    await run('Генерация пары ключей (Боб)', async () => {
      bob = await generateIdentity();
      return `отпечаток ${bob.fingerprint}`;
    });
    await run('Генерация третьей пары (Кэрол, для негативных проверок)', async () => {
      carol = await generateIdentity();
      return `отпечаток ${carol.fingerprint}`;
    });
    await run('Ключи различаются', async () => {
      if (alice.publicKeyText === bob.publicKeyText) fail('SELFTEST', 'публичные ключи совпали');
      return 'Алиса ≠ Боб';
    });

    let message;
    const sample = 'Привет, Боб! Это секретное сообщение от Алисы. 🐈 42.';
    await run('Шифрование Алиса → Боб', async () => {
      message = await encrypt({ plaintext: sample, recipient: bob.publicKeyText, identity: alice });
      return `${message.length} символов на выходе`;
    });
    await run('Шифротекст не содержит исходного текста', async () => {
      if (message.includes('Боб') || message.includes('секретн')) fail('SELFTEST', 'исходный текст виден в шифротексте');
      return 'совпадений нет';
    });
    await run('Расшифровка Бобом', async () => {
      const opened = await decrypt({ message, identity: bob });
      if (opened.plaintext !== sample) fail('SELFTEST', 'расшифрованный текст не совпал с исходным');
      return `текст совпал, отправитель ${opened.senderFingerprint}`;
    });
    await run('Отпечаток отправителя определяется верно', async () => {
      const opened = await decrypt({ message, identity: bob });
      if (opened.senderFingerprint !== alice.fingerprint) fail('SELFTEST', 'отпечаток отправителя не совпадает');
      return opened.senderFingerprint;
    });
    await run('Ответ в обратную сторону (Боб → Алиса)', async () => {
      const reply = await encrypt({ plaintext: 'Привет, Алиса!', recipient: alice.publicKeyText, identity: bob });
      const opened = await decrypt({ message: reply, identity: alice });
      if (opened.plaintext !== 'Привет, Алиса!') fail('SELFTEST', 'текст не совпал');
      return 'OK';
    });
    await run('Чужой ключ (Кэрол) не расшифровывает', () =>
      expectFailure(() => decrypt({ message, identity: carol }), 'DECRYPT_FAILED'));
    await run('Посылка самому себе шифруется и читается', async () => {
      const note = await encrypt({ plaintext: 'заметка себе', recipient: alice.publicKeyText, identity: alice });
      const opened = await decrypt({ message: note, identity: alice });
      if (opened.plaintext !== 'заметка себе') fail('SELFTEST', 'текст не совпал');
      if (opened.senderFingerprint !== alice.fingerprint) fail('SELFTEST', 'отпечаток отправителя не совпал');
      return 'OK';
    });
    await run('Отправитель не может прочитать посылку, адресованную другому', () =>
      expectFailure(() => decrypt({ message, identity: alice }), 'DECRYPT_FAILED'));
    await run('Порча шифротекста обнаруживается', async () => {
      const parts = stripArmor(message).payload.split('.');
      const body = b64uToBytes(parts[5], 'шифротексте');
      body[3] ^= 0x01;
      parts[5] = bytesToB64u(body);
      return expectFailure(() => decrypt({ message: parts.join('.'), identity: bob }), 'DECRYPT_FAILED');
    });
    await run('Подмена ключа отправителя обнаруживается', async () => {
      const parts = stripArmor(message).payload.split('.');
      parts[1] = bytesToB64u(carol.publicKeyRaw);
      return expectFailure(() => decrypt({ message: parts.join('.'), identity: bob }), 'DECRYPT_FAILED');
    });
    await run('Ключ не защищён паролем и читается', async () => {
      const again = await importPrivateKey(alice.privateKeyArmor);
      if (again.publicKeyText !== alice.publicKeyText) fail('SELFTEST', 'публичный ключ не восстановился');
      return `отпечаток ${again.fingerprint}`;
    });
    await run('Парольная защита ключа: экспорт → импорт', async () => {
      const protectedArmor = await exportPrivateKey(alice.privateKeyPkcs8, 'мой-пароль-42');
      if (!isPrivateKeyProtected(protectedArmor)) fail('SELFTEST', 'ключ не помечен как защищённый');
      const wrong = await expectFailure(() => importPrivateKey(protectedArmor, 'неверный-пароль'), 'BAD_PASSPHRASE');
      const restored = await importPrivateKey(protectedArmor, 'мой-пароль-42');
      if (restored.publicKeyText !== alice.publicKeyText) fail('SELFTEST', 'ключ после расшифровки не совпал');
      return 'верный пароль — ок, неверный — отказ';
    });
    await run('Чужой публичный ключ не подходит для расшифровки', () =>
      expectFailure(
        () => decrypt({ message, identity: { publicKeyText: carol.publicKeyText, privateKeyPkcs8: carol.privateKeyPkcs8 } }),
        'DECRYPT_FAILED'
      ));
    await run('Пустой текст не шифруется', () => expectFailure(() => encrypt({ plaintext: '', recipient: bob.publicKeyText, identity: alice }), 'EMPTY_TEXT'));
    await run('Броня устойчива к переносам строк, пробелам и цитированию', async () => {
      const messy = '  ' + message.trim().split('\n').map((line) => `> ${line}`).join('\n   \n') + '\n\n';
      const opened = await decrypt({ message: messy, identity: bob });
      if (opened.plaintext !== sample) fail('SELFTEST', 'текст не совпал');
      return 'OK';
    });
    await run('Дефисы в теле не путаются с разделителем брони', async () => {
      const tricky = '-----BEGIN ENCRYPTORY MESSAGE-----\n---abc--def\n-----END ENCRYPTORY MESSAGE-----';
      const { payload, type } = stripArmor(tricky);
      if (payload !== '---abc--def') fail('SELFTEST', `тело искажено: «${payload}»`);
      if (type !== ARMOR_TYPES.MESSAGE) fail('SELFTEST', `тип брони не распознан: «${type}»`);
      return 'OK';
    });
    await run('Большой текст (100 КБ) шифруется и читается', async () => {
      const big = 'Ячейка №' .repeat(10000);
      const packed = await encrypt({ plaintext: big, recipient: bob.publicKeyText, identity: alice });
      const opened = await decrypt({ message: packed, identity: bob });
      if (opened.plaintext !== big) fail('SELFTEST', 'текст не совпал');
      return `${(big.length / 1024).toFixed(0)} КБ, контейнер ${(packed.length / 1024).toFixed(0)} КБ`;
    });

    return results;
  }

  return {
    CURVE,
    VERSION,
    ALGO_LABEL,
    ALGO_DETAILS,
    ARMOR_TYPES,
    PBKDF2_ITERATIONS,
    EncryptoryError,
    generateIdentity,
    exportPrivateKey,
    importPrivateKey,
    isPrivateKeyProtected,
    parsePublicKey,
    publicKeyToText,
    publicKeyToArmor,
    publicKeyArmor,
    fingerprint,
    encrypt,
    decrypt,
    inspect,
    parseMessage,
    looksLikeMessage,
    isArmored,
    stripArmor,
    selfTest,
  };
});
