/*
 * Encryptory core — асимметричное шифрование текста.
 *
 * Схема (гибридная, на двух парах ключей):
 *  1. У каждого участника своя пара ключей (по умолчанию X25519; старые ключи
 *     на ECDH P-256 продолжают читаться — см. таблицу CURVES).
 *  2. Общий секрет = ECDH(мой_приватный, публичный_ключ_собеседника).
 *     У обоих участников он получается одинаковым, по проводам никогда не идёт.
 *  3. Из общего секрета через HKDF-SHA256 выводится ключ AES-256-GCM.
 *     В HKDF "info" зашиты название кривой и оба публичных ключа, поэтому
 *     чужой ключ или ключ с другой кривой не подойдёт.
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

  /* ------------------------------------------------------------------ */
  /* Кривые и версии формата                                             */
  /* ------------------------------------------------------------------ */

  /**
   * Формат контейнеров и префиксов однозначно указывает на кривую, поэтому
   * «старые» сообщения и ключи остаются читаемыми, а новые по умолчанию
   * используют X25519 (компактнее, быстрее, современный стандарт).
   */
  const CURVES = {
    X25519: {
      id: 'X25519',
      label: 'X25519',
      webcrypto: { name: 'X25519' },
      publicLength: 32,
      version: 'em2',
      infoPrefix: 'encryptory/v2|X25519|',
      publicPrefix: 'epk2.',
      privatePrefix: 'ek2.',
      protectedPrefix: 'ek2p.',
      legacy: false,
    },
    'P-256': {
      id: 'P-256',
      label: 'ECDH P-256',
      webcrypto: { name: 'ECDH', namedCurve: 'P-256' },
      publicLength: 65, // несжатая точка: 0x04 || X || Y
      version: 'em1',
      infoPrefix: 'encryptory/v1|', // менять нельзя: так читаются старые сообщения
      publicPrefix: 'epk1.',
      privatePrefix: 'ek1.',
      protectedPrefix: 'ek1p.',
      legacy: true,
    },
  };

  const DEFAULT_CURVE = 'X25519';
  const CURVE_ORDER = ['X25519', 'P-256'];

  const VERSION = CURVES[DEFAULT_CURVE].version;
  const ALGO_LABEL = `${CURVES[DEFAULT_CURVE].label} + HKDF-SHA256 + AES-256-GCM`;
  const ALGO_DETAILS =
    'Публичный ключ каждого участника + ECDH → общий секрет → HKDF-SHA256 → AES-256-GCM. ' +
    'Приватные ключи никогда не покидают устройство.';

  const curveByVersion = (version) => CURVE_ORDER.map((id) => CURVES[id]).find((c) => c.version === version) || null;
  const curveByPublicPrefix = (text) => CURVE_ORDER.map((id) => CURVES[id]).find((c) => text.startsWith(c.publicPrefix)) || null;
  const curveByPrivatePrefix = (text) =>
    CURVE_ORDER.map((id) => CURVES[id]).find((c) => text.startsWith(c.privatePrefix) || text.startsWith(c.protectedPrefix)) || null;

  const HKDF_INFO_PREFIX = CURVES[DEFAULT_CURVE].infoPrefix; // оставлено для совместимости с прежним API
  const PBKDF2_ITERATIONS = 600000; // OWASP 2025 для PBKDF2-HMAC-SHA256 (было 310000)

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

  const encodeUtf8 = (text) => textEncoder.encode(text);
  const decodeUtf8 = (bytes) => textDecoder.decode(bytes);

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
   * Разделитель брони. Требуем и дефисы, и слово BEGIN/END, и пробел после него:
   * обычная строка base64url под это не подходит (пробелы в алфавит не входят),
   * поэтому тело сообщения нельзя потерять по ошибке — даже если строка
   * случайно начинается с «---».
   */
  const ARMOR_BEGIN = /^-{3,}\s*BEGIN\s+([A-Za-z0-9 ]+?)\s*-{3,}$/i;
  const ARMOR_END = /^-{3,}\s*END\s+[A-Za-z0-9 ]+?\s*-{3,}$/i;

  /**
   * Снимает броню (если есть) и склеивает тело в одну строку.
   * Заодно переживает цитирование из писем и чатов (ведущие «>»).
   */
  function stripArmor(text) {
    const lines = String(text == null ? '' : text).replace(/\r/g, '').split('\n');
    let type = null;
    const body = [];
    for (const rawLine of lines) {
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

  /* ------------------------------------------------------------------ */
  /* Операции с ключами: общее для всех кривых                           */
  /* ------------------------------------------------------------------ */

  const supportCache = new Map();

  /** Проверяет, умеет ли это окружение работать с кривой. */
  async function isCurveSupported(curveId) {
    const curve = CURVES[curveId];
    if (!curve) fail('BAD_CURVE', `Неизвестная кривая «${curveId}».`);
    if (supportCache.has(curveId)) return supportCache.get(curveId);
    const check = (async () => {
      try {
        const pair = await getSubtle().generateKey(curve.webcrypto, true, ['deriveBits']);
        if (!pair || !pair.privateKey) return false;
        const raw = new Uint8Array(await getSubtle().exportKey('raw', pair.publicKey));
        return raw.length === curve.publicLength;
      } catch (error) {
        return false;
      }
    })();
    supportCache.set(curveId, check);
    return check;
  }

  async function generateKeyPairFor(curve) {
    try {
      return await getSubtle().generateKey(curve.webcrypto, true, ['deriveBits']);
    } catch (error) {
      fail(
        'UNSUPPORTED_CURVE',
        `Это окружение не умеет работать с кривой ${curve.label}. Обновите браузер или используйте другой.`
      );
    }
  }

  async function importPeerPublicKey(rawBytes, curve) {
    const raw = toBytes(rawBytes);
    if (raw.length !== curve.publicLength) {
      fail(
        'BAD_PUBLIC_KEY',
        `Публичный ключ ${curve.label} должен быть длиной ${curve.publicLength} байт, а тут ${raw.length}.`
      );
    }
    if (curve.id === 'P-256' && raw[0] !== 0x04) {
      fail('BAD_PUBLIC_KEY', 'Публичный ключ P-256 должен быть несжатой точкой (первый байт 0x04).');
    }
    try {
      return await getSubtle().importKey('raw', raw, curve.webcrypto, false, []);
    } catch (error) {
      fail('BAD_PUBLIC_KEY', `Не удалось объяснить системе публичный ключ ${curve.label}.`);
    }
  }

  async function importPrivateKeyBytes(pkcs8, curve) {
    try {
      return await getSubtle().importKey('pkcs8', toBytes(pkcs8), curve.webcrypto, true, ['deriveBits']);
    } catch (error) {
      fail('BAD_PRIVATE_KEY', 'Не удалось прочитать приватный ключ: файл повреждён или это не ключ Encryptory.');
    }
  }

  /** ECDH: общий секрет из моего приватного и его публичного. */
  async function deriveSecretBits(myPrivateKey, peerPublicKey, curve) {
    try {
      return await getSubtle().deriveBits({ name: curve.webcrypto.name, public: peerPublicKey }, myPrivateKey, 256);
    } catch (error) {
      fail('ECDH_FAILED', `Не удалось выработать общий секрет на кривой ${curve.label}.`);
    }
  }

  function detectCurveFromPublicBytes(raw) {
    const bytes = toBytes(raw);
    const found = CURVE_ORDER.map((id) => CURVES[id]).find((c) => c.publicLength === bytes.length);
    if (!found) {
      fail('BAD_PUBLIC_KEY', `Публичный ключ непонятной длины (${bytes.length} байт) — ни X25519, ни P-256 не подходят.`);
    }
    if (found.id === 'P-256' && bytes[0] !== 0x04) {
      fail('BAD_PUBLIC_KEY', 'Похоже на ключ P-256, но он не является несжатой точкой (первый байт должен быть 0x04).');
    }
    return found;
  }

  /* ------------------------------------------------------------------ */
  /* Публичные ключи                                                     */
  /* ------------------------------------------------------------------ */

  /** Достаёт публичный ключ из JWK: поддержаны OKP/X25519 и EC/P-256. */
  function rawFromJwk(jwk) {
    if (!jwk || typeof jwk !== 'object') fail('BAD_PUBLIC_KEY', 'Ожидался JSON-объект ключа.');
    if (jwk.kty === 'OKP' && jwk.crv === 'X25519' && jwk.x) {
      return b64uToBytes(jwk.x, 'координате X ключа');
    }
    if (jwk.kty === 'EC' && jwk.crv === 'P-256' && jwk.x && jwk.y) {
      const x = b64uToBytes(jwk.x, 'координате X ключа');
      const y = b64uToBytes(jwk.y, 'координате Y ключа');
      if (x.length !== 32 || y.length !== 32) {
        fail('BAD_PUBLIC_KEY', 'Координаты ключа P-256 должны быть длиной 32 байта.');
      }
      return concatBytes(Uint8Array.of(0x04), x, y);
    }
    fail('BAD_PUBLIC_KEY', 'Поддерживаются ключи X25519 (OKP) и ECDH P-256 (EC).');
  }

  /**
   * Разбирает публичный ключ из текста.
   * Принимает: epk2./epk1.<base64url>, голый base64url, JWK (JSON),
   * с бронёй или без, с переносами строк и цитированием.
   */
  function parsePublicKey(input) {
    const { payload } = stripArmor(input);
    if (!payload) fail('BAD_PUBLIC_KEY', 'Публичный ключ не найден. Вставьте ключ, полученный от собеседника.');

    let raw;
    let curve = curveByPublicPrefix(payload);
    if (curve) {
      raw = b64uToBytes(payload.slice(curve.publicPrefix.length), 'публичном ключе');
    } else if (payload.startsWith('{')) {
      let jwk;
      try {
        jwk = JSON.parse(payload);
      } catch (error) {
        fail('BAD_PUBLIC_KEY', 'Похоже на JSON, но разобрать его не получилось.');
      }
      raw = rawFromJwk(jwk);
      curve = detectCurveFromPublicBytes(raw);
    } else {
      raw = b64uToBytes(payload, 'публичном ключе');
      curve = detectCurveFromPublicBytes(raw);
    }

    if (raw.length !== curve.publicLength) {
      fail('BAD_PUBLIC_KEY', `Публичный ключ ${curve.label} должен быть длиной ${curve.publicLength} байт.`);
    }
    return { raw, curve: curve.id, curveLabel: curve.label, text: curve.publicPrefix + bytesToB64u(raw) };
  }

  function publicKeyToText(rawOrJwk) {
    if (rawOrJwk && typeof rawOrJwk === 'object' && typeof rawOrJwk.kty === 'string') {
      const raw = rawFromJwk(rawOrJwk);
      const curve = detectCurveFromPublicBytes(raw);
      return curve.publicPrefix + bytesToB64u(raw);
    }
    const raw = toBytes(rawOrJwk);
    const curve = detectCurveFromPublicBytes(raw);
    return curve.publicPrefix + bytesToB64u(raw);
  }

  function publicKeyToArmor(rawOrText) {
    const text = typeof rawOrText === 'string' && /\./.test(rawOrText)
      ? parsePublicKey(rawOrText).text
      : publicKeyToText(rawOrText);
    return armor(ARMOR_TYPES.PUBLIC_KEY, text);
  }

  /** Короткий отпечаток ключа — чтобы глазами сверять, что ключ «тот самый». */
  async function fingerprint(rawOrText) {
    const raw = typeof rawOrText === 'string'
      ? parsePublicKey(rawOrText).raw
      : toBytes(rawOrText);
    const digest = new Uint8Array(await getSubtle().digest('SHA-256', raw));
    const b32 = base32(digest.subarray(0, 12));
    return (b32.match(/.{1,4}/g) || []).slice(0, 5).join('-');
  }

  /* ------------------------------------------------------------------ */
  /* Приватные ключи                                                     */
  /* ------------------------------------------------------------------ */

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
   * curve — кривая ключа (по умолчанию X25519).
   * Без пароля — как есть; с паролем — PBKDF2-SHA256 + AES-256-GCM.
   */
  async function exportPrivateKey(pkcs8OrIdentity, passphrase, curveId) {
    const source = pkcs8OrIdentity && pkcs8OrIdentity.privateKeyPkcs8 ? pkcs8OrIdentity : null;
    const pkcs8 = toBytes(source ? source.privateKeyPkcs8 : pkcs8OrIdentity);
    const curve = CURVES[(source && source.curve) || curveId || DEFAULT_CURVE];
    if (!curve) fail('BAD_CURVE', 'Неизвестная кривая приватного ключа.');

    if (!passphrase) {
      return armor(ARMOR_TYPES.PRIVATE_KEY, curve.privatePrefix + bytesToB64u(pkcs8));
    }
    const salt = randomBytes(16);
    const iv = randomBytes(12);
    const key = await pbkdf2Key(passphrase, salt, PBKDF2_ITERATIONS);
    const ct = await getSubtle().encrypt({ name: 'AES-GCM', iv }, key, pkcs8);
    const envelope = {
      v: 1,
      kdf: 'PBKDF2-SHA256',
      iter: PBKDF2_ITERATIONS,
      curve: curve.id,
      salt: bytesToB64u(salt),
      iv: bytesToB64u(iv),
      ct: bytesToB64u(ct),
    };
    return armor(ARMOR_TYPES.PRIVATE_KEY, curve.protectedPrefix + bytesToB64u(encodeUtf8(JSON.stringify(envelope))));
  }

  /** Угадывает кривую приватного ключа, если префикс неизвестен (например, чужой формат). */
  async function sniffPrivateCurve(pkcs8) {
    for (const id of CURVE_ORDER) {
      try {
        await importPrivateKeyBytes(pkcs8, CURVES[id]);
        return CURVES[id];
      } catch (error) {
        /* пробуем следующую */
      }
    }
    fail('BAD_PRIVATE_KEY', 'Приватный ключ не подходит ни под X25519, ни под ECDH P-256.');
  }

  /** Разбирает бронированный приватный ключ (при необходимости — с паролем). */
  async function importPrivateKey(armoredText, passphrase) {
    const { type, payload } = stripArmor(armoredText);
    if (type && type !== ARMOR_TYPES.PRIVATE_KEY) {
      fail('BAD_PRIVATE_KEY', 'Это не приватный ключ Encryptory, а что-то другое.');
    }

    let curve = curveByPrivatePrefix(payload);
    let pkcs8;
    let protectedAtRest = false;

    if (curve && payload.startsWith(curve.protectedPrefix)) {
      protectedAtRest = true;
      if (!passphrase) {
        fail('PASSPHRASE_REQUIRED', 'Приватный ключ защищён паролем — укажите пароль.');
      }
      let envelope;
      try {
        envelope = JSON.parse(decodeUtf8(b64uToBytes(payload.slice(curve.protectedPrefix.length), 'приватном ключе')));
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
    } else if (curve) {
      pkcs8 = b64uToBytes(payload.slice(curve.privatePrefix.length), 'приватном ключе');
    } else {
      // Неизвестный префикс: пробуем понять по содержимому.
      pkcs8 = b64uToBytes(payload, 'приватном ключе');
      curve = await sniffPrivateCurve(pkcs8);
    }

    const privateKey = await importPrivateKeyBytes(pkcs8, curve);
    let jwk;
    try {
      jwk = await getSubtle().exportKey('jwk', privateKey);
    } catch (error) {
      fail('BAD_PRIVATE_KEY', 'Ключ прочитан, но извлечь публичную часть не получилось.');
    }
    const raw = rawFromJwk(jwk);
    const actualCurve = detectCurveFromPublicBytes(raw);
    if (actualCurve.id !== curve.id) {
      fail('BAD_PRIVATE_KEY', `Ключ оказался на кривой ${actualCurve.label}, а помечен как ${curve.label}.`);
    }
    return {
      publicKeyText: actualCurve.publicPrefix + bytesToB64u(raw),
      publicKeyRaw: raw,
      curve: actualCurve.id,
      curveLabel: actualCurve.label,
      fingerprint: await fingerprint(raw),
      privateKey,
      privateKeyPkcs8: pkcs8,
      privateKeyArmor: String(armoredText).trim() + '\n',
      encryptedAtRest: protectedAtRest,
    };
  }

  function isPrivateKeyProtected(armoredText) {
    const { payload } = stripArmor(armoredText);
    return CURVE_ORDER.some((id) => payload.startsWith(CURVES[id].protectedPrefix));
  }

  /* ------------------------------------------------------------------ */
  /* Идентичность                                                        */
  /* ------------------------------------------------------------------ */

  /**
   * Генерирует новую пару ключей.
   * По умолчанию X25519; если окружение его не умеет — откатывается на P-256.
   */
  async function generateIdentity(passphrase, curveId) {
    let curve;
    if (curveId) {
      curve = CURVES[curveId];
      if (!curve) fail('BAD_CURVE', `Неизвестная кривая «${curveId}».`);
      if (!(await isCurveSupported(curveId))) {
        fail('UNSUPPORTED_CURVE', `Это окружение не поддерживает ${curve.label}.`);
      }
    } else {
      curve = CURVES[DEFAULT_CURVE];
      if (!(await isCurveSupported(DEFAULT_CURVE))) {
        curve = CURVES['P-256'];
      }
    }

    const pair = await generateKeyPairFor(curve);
    const raw = new Uint8Array(await getSubtle().exportKey('raw', pair.publicKey));
    const pkcs8 = new Uint8Array(await getSubtle().exportKey('pkcs8', pair.privateKey));
    return {
      publicKeyText: curve.publicPrefix + bytesToB64u(raw),
      publicKeyRaw: raw,
      curve: curve.id,
      curveLabel: curve.label,
      fingerprint: await fingerprint(raw),
      privateKey: pair.privateKey,
      privateKeyPkcs8: pkcs8,
      privateKeyArmor: await exportPrivateKey(pkcs8, passphrase || null, curve.id),
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
    if (identity.privateKeyPkcs8) return importPrivateKeyBytes(identity.privateKeyPkcs8, CURVES[identity.curve || DEFAULT_CURVE]);
    if (identity.privateKeyArmor) {
      const parsed = await importPrivateKey(identity.privateKeyArmor, identity.passphrase);
      return parsed.privateKey;
    }
    fail('NO_IDENTITY', 'У идентичности нет приватного ключа.');
  }

  function getPublicRaw(identity) {
    if (!identity) fail('NO_IDENTITY', 'Нет идентичности.');
    if (identity.publicKeyRaw) return toBytes(identity.publicKeyRaw);
    if (identity.publicKeyText) return parsePublicKey(identity.publicKeyText).raw;
    fail('NO_IDENTITY', 'У идентичности нет публичного ключа.');
  }

  /** Кривая идентичности — по явному полю или по длине публичного ключа. */
  function getIdentityCurve(identity) {
    if (identity && identity.curve && CURVES[identity.curve]) return CURVES[identity.curve];
    return detectCurveFromPublicBytes(getPublicRaw(identity));
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
   * myPrivateKey  — приватный ключ своей пары
   * peerPublicRaw — публичный ключ собеседника
   * salt          — случайная соль сообщения
   * pubA / pubB   — оба публичных ключа: попадают в HKDF info, поэтому ключ
   *                 привязан к конкретной паре участников.
   * curve         — кривая обеих сторон (X25519 или P-256).
   */
  async function deriveAesKey(myPrivateKey, peerPublicRaw, salt, pubA, pubB, curve) {
    const subtle = getSubtle();
    const peerKey = await importPeerPublicKey(peerPublicRaw, curve);
    const shared = await deriveSecretBits(myPrivateKey, peerKey, curve);
    const ordered = [toBytes(pubA), toBytes(pubB)].sort(compareBytes);
    const info = concatBytes(encodeUtf8(curve.infoPrefix), ordered[0], ordered[1]);
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

  /** Понятное объяснение, когда ключи собеседников на разных кривых. */
  function curveMismatchError(mine, theirs) {
    fail(
      'CURVE_MISMATCH',
      `Ваш ключ — ${mine.label}, а ключ собеседника — ${theirs.label}. Обмен на разных кривых невозможен: ` +
        'попросите собеседника создать новую пару ключей в актуальной версии Encryptory (X25519) ' +
        'или сами импортируйте ключ нужной кривой.'
    );
  }

  /**
   * Шифрует текст для получателя.
   *   { plaintext, recipient (ключ-текст), identity }  →  бронированный текст
   * Кривая посылки определяется ключом получателя.
   */
  async function encrypt({ plaintext, recipient, identity, now }) {
    if (typeof plaintext !== 'string' || plaintext.length === 0) {
      fail('EMPTY_TEXT', 'Нечего шифровать: текст пуст.');
    }
    const recipientKey = parsePublicKey(recipient);
    const recipientCurve = CURVES[recipientKey.curve];
    const myPublicRaw = getPublicRaw(identity);
    const myCurve = getIdentityCurve(identity);
    if (myCurve.id !== recipientCurve.id) curveMismatchError(myCurve, recipientCurve);

    const myPrivateKey = await getPrivateKey(identity);

    const salt = randomBytes(32);
    const iv = randomBytes(12);
    const timestamp = Math.floor((now ? Number(now) : Date.now()) / 1000);
    const header = [
      recipientCurve.version,
      bytesToB64u(myPublicRaw),
      bytesToB64u(salt),
      bytesToB64u(iv),
      String(timestamp),
    ].join('.');

    const aesKey = await deriveAesKey(myPrivateKey, recipientKey.raw, salt, myPublicRaw, recipientKey.raw, recipientCurve);
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
    const curve = curveByVersion(version);
    if (!curve) {
      fail(
        'UNSUPPORTED_VERSION',
        `Неизвестная версия контейнера «${version}» — возможно, шифровано более новой версией Encryptory.`
      );
    }
    const senderRaw = b64uToBytes(senderB64, 'ключе отправителя');
    if (senderRaw.length !== curve.publicLength) {
      fail('BAD_MESSAGE', `Ключ отправителя не подходит под заявленную кривую ${curve.label}.`);
    }
    return {
      version,
      curve: curve.id,
      curveLabel: curve.label,
      senderRaw,
      senderPublicKeyText: curve.publicPrefix + bytesToB64u(senderRaw),
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
      version: parsed.version,
      curve: parsed.curve,
      curveLabel: parsed.curveLabel,
      senderPublicKeyText: parsed.senderPublicKeyText,
      senderFingerprint: await fingerprint(parsed.senderRaw),
      timestamp: parsed.timestamp,
      algorithm: `${parsed.curveLabel} + HKDF-SHA256 + AES-256-GCM`,
    };
  }

  function looksLikeMessage(text) {
    const { type, payload } = stripArmor(text);
    if (type === ARMOR_TYPES.MESSAGE) return true;
    return CURVE_ORDER.some((id) => payload.startsWith(`${CURVES[id].version}.`));
  }

  /** Расшифровывает сообщение своим приватным ключом. */
  async function decrypt({ message, identity }) {
    const parsed = parseMessage(message);
    const messageCurve = CURVES[parsed.curve];
    const myPublicRaw = getPublicRaw(identity);
    const myCurve = getIdentityCurve(identity);
    if (myCurve.id !== messageCurve.id) {
      fail(
        'CURVE_MISMATCH',
        `Сообщение зашифровано на кривой ${messageCurve.label}, а ваш ключ — ${myCurve.label}. ` +
          'Похоже, посылка адресована не вашему ключу (или ключ создан другой версией утилиты).'
      );
    }
    const myPrivateKey = await getPrivateKey(identity);

    const aesKey = await deriveAesKey(myPrivateKey, parsed.senderRaw, parsed.salt, parsed.senderRaw, myPublicRaw, messageCurve);
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
      curve: parsed.curve,
      timestamp: parsed.timestamp,
    };
  }

  /* ------------------------------------------------------------------ */
  /* Самопроверка                                                        */
  /* ------------------------------------------------------------------ */

  /**
   * Прогоняет полный цикл «зашифровал → расшифровал» на обеих кривых
   * и набор негативных проверок. Возвращает список { name, ok, detail, ms }.
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

    await run(`Поддержка кривых (${CURVE_ORDER.join(', ')})`, async () => {
      const support = [];
      for (const id of CURVE_ORDER) support.push(`${id}: ${(await isCurveSupported(id)) ? 'да' : 'нет'}`);
      return support.join(', ');
    });
    await run(`Генерация пары ключей ${CURVES[DEFAULT_CURVE].label} (Алиса)`, async () => {
      alice = await generateIdentity();
      if (alice.curve !== DEFAULT_CURVE) fail('SELFTEST', `ожидалась кривая ${DEFAULT_CURVE}, получена ${alice.curve}`);
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
    await run(`Длина публичного ключа ${CURVES[DEFAULT_CURVE].label}`, async () => {
      if (alice.publicKeyRaw.length !== CURVES[DEFAULT_CURVE].publicLength) {
        fail('SELFTEST', `ожидалось ${CURVES[DEFAULT_CURVE].publicLength} байт, получено ${alice.publicKeyRaw.length}`);
      }
      return `${alice.publicKeyRaw.length} байт`;
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
    await run('Посылка самому себе шифруется и читается', async () => {
      const note = await encrypt({ plaintext: 'заметка себе', recipient: alice.publicKeyText, identity: alice });
      const opened = await decrypt({ message: note, identity: alice });
      if (opened.plaintext !== 'заметка себе') fail('SELFTEST', 'текст не совпал');
      return 'OK';
    });
    await run('Чужой ключ (Кэрол) не расшифровывает', () =>
      expectFailure(() => decrypt({ message, identity: carol }), 'DECRYPT_FAILED'));
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
    await run('Пропущенный nonce (повтор) не проходит', async () => {
      const parts = stripArmor(message).payload.split('.');
      parts[3] = bytesToB64u(randomBytes(12));
      return expectFailure(() => decrypt({ message: parts.join('.'), identity: bob }), 'DECRYPT_FAILED');
    });
    await run('Ключ не защищён паролем и читается', async () => {
      const again = await importPrivateKey(alice.privateKeyArmor);
      if (again.publicKeyText !== alice.publicKeyText) fail('SELFTEST', 'публичный ключ не восстановился');
      return `отпечаток ${again.fingerprint}`;
    });
    await run('Парольная защита ключа: экспорт → импорт', async () => {
      const protectedArmor = await exportPrivateKey(alice.privateKeyPkcs8, 'мой-пароль-42', alice.curve);
      if (!isPrivateKeyProtected(protectedArmor)) fail('SELFTEST', 'ключ не помечен как защищённый');
      await expectFailure(() => importPrivateKey(protectedArmor, 'неверный-пароль'), 'BAD_PASSPHRASE');
      const restored = await importPrivateKey(protectedArmor, 'мой-пароль-42');
      if (restored.publicKeyText !== alice.publicKeyText) fail('SELFTEST', 'ключ после расшифровки не совпал');
      return 'верный пароль — ок, неверный — отказ';
    });
    await run('Пустой текст не шифруется', () =>
      expectFailure(() => encrypt({ plaintext: '', recipient: bob.publicKeyText, identity: alice }), 'EMPTY_TEXT'));
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
      const big = 'Ячейка №'.repeat(10000);
      const packed = await encrypt({ plaintext: big, recipient: bob.publicKeyText, identity: alice });
      const opened = await decrypt({ message: packed, identity: bob });
      if (opened.plaintext !== big) fail('SELFTEST', 'текст не совпал');
      return `${(big.length / 1024).toFixed(0)} КБ, контейнер ${(packed.length / 1024).toFixed(0)} КБ`;
    });

    // Совместимость со старой кривой P-256 (контейнеры em1/epk1/ek1).
    if (await isCurveSupported('P-256')) {
      let legacy;
      await run('Старый формат ECDH P-256: генерация ключа', async () => {
        legacy = await generateIdentity(null, 'P-256');
        if (!legacy.publicKeyText.startsWith('epk1.')) fail('SELFTEST', 'ожидался префикс epk1.');
        return `отпечаток ${legacy.fingerprint}`;
      });
      await run('Старый формат ECDH P-256: цикл шифрования', async () => {
        const legacyBob = await generateIdentity(null, 'P-256');
        const legacyMessage = await encrypt({ plaintext: 'старый формат', recipient: legacyBob.publicKeyText, identity: legacy });
        if (!legacyMessage.includes('em1.')) fail('SELFTEST', 'ожидалась версия контейнера em1');
        const opened = await decrypt({ message: legacyMessage, identity: legacyBob });
        if (opened.plaintext !== 'старый формат') fail('SELFTEST', 'текст не совпал');
        return 'em1 читается';
      });
      await run('Ключи разных кривых не смешиваются', () =>
        expectFailure(() => encrypt({ plaintext: 'x', recipient: legacy.publicKeyText, identity: alice }), 'CURVE_MISMATCH'));
    }

    return results;
  }

  return {
    DEFAULT_CURVE,
    CURVES,
    VERSION,
    ALGO_LABEL,
    ALGO_DETAILS,
    ARMOR_TYPES,
    PBKDF2_ITERATIONS,
    HKDF_INFO_PREFIX,
    EncryptoryError,
    isCurveSupported,
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
    isArmored: (text, type) => {
      const { type: found } = stripArmor(text);
      return type ? found === type : Boolean(found);
    },
    stripArmor,
    selfTest,
  };
});
