/*
 * Encryptory — интерфейс. Вся криптография — в src/encryptory-core.js.
 * Ничего не отправляется по сети: только WebCrypto, буфер обмена и файлы по клику.
 */
(function () {
  'use strict';

  const core = window.EncryptoryCore;
  const $ = (selector) => document.querySelector(selector);
  const SESSION_KEY = 'encryptory.session.v1';

  /** Состояние вкладки. Приватный ключ живёт только в памяти и в sessionStorage. */
  const state = {
    identity: null,      // { publicKeyText, fingerprint, privateKey, privateKeyArmor, ... }
    ownArmor: null,      // бронированный приватный ключ (для скачивания/сохранения)
    ownProtected: false, // защищён ли ключ паролем
    lockedArmor: null,   // ключ, который ждёт ввода пароля
    peer: null,          // { text, fingerprint }
    peerText: null,      // именно тот текст ключа собеседника, что сохранён
    pendingFileTarget: null,
  };

  /* ------------------------------------------------------------------ */
  /* Мелкие утилиты                                                      */
  /* ------------------------------------------------------------------ */

  const errText = (error) => (error && error.message ? error.message : String(error));

  function toast(message, kind, ms) {
    const el = document.createElement('div');
    el.className = `toast ${kind || ''}`.trim();
    el.textContent = message;
    $('#toasts').appendChild(el);
    const life = ms || (kind === 'err' ? 7000 : 3800);
    setTimeout(() => {
      el.style.transition = 'opacity .25s, transform .25s';
      el.style.opacity = '0';
      el.style.transform = 'translateY(6px)';
      setTimeout(() => el.remove(), 260);
    }, life);
  }

  async function copyFrom(selector, button) {
    const source = $(selector);
    const text = source.value != null ? source.value : source.textContent;
    if (!text || !text.trim()) {
      toast('Тут пока нечего копировать.', 'warn');
      return;
    }
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
      } else {
        selectAndCopy(source);
      }
      flash(button, 'Скопировано');
    } catch (error) {
      selectAndCopy(source);
      toast('Скопировано выделением — нажмите Ctrl/Cmd+C.', 'warn');
    }
  }

  function selectAndCopy(source) {
    source.focus();
    source.select();
    try {
      document.execCommand('copy');
    } catch (error) {
      /* ничего: останется выделенный текст */
    }
  }

  /** Прокрутка к элементу — если окружение это умеет. Ошибка прокрутки не должна ломать операцию. */
  function scrollTo(target, options) {
    const el = typeof target === 'string' ? $(target) : target;
    if (el && typeof el.scrollIntoView === 'function') el.scrollIntoView(options);
  }

  function flash(button, label) {
    if (!button) return;
    if (!button.dataset.original) button.dataset.original = button.innerHTML;
    button.textContent = label;
    button.disabled = true;
    setTimeout(() => {
      button.innerHTML = button.dataset.original;
      button.disabled = false;
    }, 1100);
  }

  function download(filename, text) {
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }

  function formatTime(ms) {
    if (!ms) return null;
    try {
      return new Intl.DateTimeFormat('ru-RU', { dateStyle: 'short', timeStyle: 'short' }).format(new Date(ms));
    } catch (error) {
      return new Date(ms).toISOString();
    }
  }

  function formatSize(text) {
    const bytes = new TextEncoder().encode(text).length;
    if (bytes < 1024) return `${bytes} Б`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} КБ`;
    return `${(bytes / 1024 / 1024).toFixed(2)} МБ`;
  }

  /** Блокирует кнопку на время асинхронной операции, чтобы не жали дважды. */
  async function withBusy(button, busyLabel, fn) {
    if (!button) return fn();
    const original = button.innerHTML;
    button.disabled = true;
    if (busyLabel) button.textContent = busyLabel;
    try {
      return await fn();
    } finally {
      button.innerHTML = original;
      updateAvailability();
    }
  }

  /* ------------------------------------------------------------------ */
  /* Хранилище вкладки                                                   */
  /* ------------------------------------------------------------------ */

  function saveSession() {
    try {
      sessionStorage.setItem(SESSION_KEY, JSON.stringify({
        ownArmor: state.ownArmor,
        ownProtected: state.ownProtected,
        peer: state.peer ? state.peer.text : null,
      }));
    } catch (error) {
      /* приватный режим и т.п. — просто не сохраняем */
    }
  }

  function loadSession() {
    let raw = null;
    try {
      raw = sessionStorage.getItem(SESSION_KEY);
    } catch (error) {
      return null;
    }
    if (!raw) return null;
    try {
      return JSON.parse(raw);
    } catch (error) {
      return null;
    }
  }

  /* ------------------------------------------------------------------ */
  /* Отрисовка                                                           */
  /* ------------------------------------------------------------------ */

  function updateAvailability() {
    const hasOwn = Boolean(state.identity);
    const hasPeer = Boolean(state.peer);
    const busy = new Set(
      Array.from(document.querySelectorAll('button[data-busy="1"]')).map((btn) => btn.id)
    );
    const setDisabled = (selector, value) => {
      const btn = $(selector);
      if (btn && !busy.has(btn.id)) btn.disabled = value;
    };

    setDisabled('#encrypt-btn', !(hasOwn && hasPeer));
    // для локальной проверки ключ собеседника не нужен: она работает на своих ключах
    setDisabled('#self-check-btn', !hasOwn);
    setDisabled('#decrypt-btn', !hasOwn || !$('#ciphertext').value.trim());
    setDisabled('#save-peer-btn', !$('#peer-input').value.trim());

    $('#enc-chip').textContent = hasOwn && hasPeer ? 'готово' : (hasPeer ? 'нужен мой ключ' : 'нужен ключ собеседника');
    $('#enc-chip').dataset.state = hasOwn && hasPeer ? 'ok' : 'warn';

    $('#dec-chip').textContent = hasOwn ? 'готово' : 'нужен мой приватный ключ';
    $('#dec-chip').dataset.state = hasOwn ? 'ok' : 'warn';

    const status = $('#key-status');
    if (!hasOwn) {
      status.textContent = 'Ключей пока нет';
      status.dataset.state = 'warn';
    } else if (!hasPeer) {
      status.textContent = 'Осталось вставить ключ собеседника';
      status.dataset.state = 'warn';
      } else {
        status.textContent = 'Готово к работе';
        status.dataset.state = 'ok';
      }
  }

  function renderOwn() {
    const identity = state.identity;
    $('#own-empty').hidden = Boolean(identity) || Boolean(state.lockedArmor);
    $('#own-ready').hidden = !identity;
    $('#own-locked').hidden = !state.lockedArmor;

    if (identity) {
      $('#own-fp').hidden = false;
      $('#own-fp').textContent = identity.fingerprint;
      $('#own-pub').value = core.publicKeyArmor(identity.publicKeyText).trim();
      $('#own-priv').value = identity.privateKeyArmor || state.ownArmor || '';
      $('#priv-hint').textContent = identity.encryptedAtRest
        ? 'Ключ защищён паролем: без пароля этот файл бесполезен, но пароль лучше не забывать — восстановить его нельзя.'
        : 'Ключ не защищён паролем: файл с ним = ваша личность. Храните его отдельно от переписки и не отправляйте никому.';
    } else {
      $('#own-fp').hidden = true;
      $('#own-fp').textContent = '';
    }
  }

  function renderPeer() {
    const peer = state.peer;
    $('#peer-fp').hidden = !peer;
    if (peer) {
      $('#peer-fp').textContent = peer.fingerprint;
      $('#peer-card').classList.add('is-set');
    } else {
      $('#peer-card').classList.remove('is-set');
    }
  }

  function render() {
    renderOwn();
    renderPeer();
    updateAvailability();
  }

  /* ------------------------------------------------------------------ */
  /* Ключи: свои                                                         */
  /* ------------------------------------------------------------------ */

  async function generateOwn() {
    const protect = $('#protect-toggle').checked;
    const passphrase = $('#protect-pass').value;
    if (protect && passphrase.length < 8) {
      toast('Пароль короче 8 символов — придумайте длиннее (лучше фразу из нескольких слов).', 'warn');
      return;
    }
    await withBusy($('#generate-btn'), 'Генерирую…', async () => {
      try {
        const identity = await core.generateIdentity(protect ? passphrase : null);
        state.identity = identity;
        state.ownArmor = identity.privateKeyArmor;
        state.ownProtected = identity.encryptedAtRest;
        state.lockedArmor = null;
        $('#protect-pass').value = '';
        saveSession();
        render();
        toast('Пара ключей создана. Передайте собеседнику публичный ключ — и сверьте отпечаток.', 'ok');
      } catch (error) {
        toast(errText(error), 'err');
      }
    });
  }

  function resetOwn() {
    if (state.identity && !window.confirm('Удалить эту пару ключей из вкладки? Старые сообщения, зашифрованные на неё, перестанут расшифровываться.')) {
      return;
    }
    state.identity = null;
    state.ownArmor = null;
    state.ownProtected = false;
    state.lockedArmor = null;
    $('#own-priv').classList.add('hidden');
    $('#protect-pass').value = '';
    saveSession();
    render();
    toast('Ключи убраны из вкладки. Если файл сохранён — его можно импортировать снова.', 'warn');
  }

  async function importOwnFromText(text, passphrase) {
    const trimmed = String(text || '').trim();
    if (!trimmed) {
      toast('Пусто: вставьте содержимое файла с приватным ключом.', 'warn');
      return;
    }
    if (trimmed.includes('ENCRYPTORY PUBLIC KEY') || trimmed.startsWith('epk1.')) {
      toast('Это публичный ключ. Для работы нужен приватный (файл начинается с EK1/EK1P).', 'err');
      return;
    }
    try {
      const identity = await core.importPrivateKey(trimmed, passphrase || null);
      state.identity = identity;
      state.ownArmor = trimmed.endsWith('\n') ? trimmed : `${trimmed}\n`;
      state.ownProtected = identity.encryptedAtRest;
      state.lockedArmor = null;
      saveSession();
      render();
      toast(`Ключ импортирован. Отпечаток: ${identity.fingerprint}`, 'ok');
    } catch (error) {
      if (error && error.code === 'PASSPHRASE_REQUIRED') {
        state.lockedArmor = trimmed;
        render();
        $('#unlock-pass').focus();
        toast('Ключ защищён паролем — введите его, чтобы разблокировать.', 'warn');
        return;
      }
      toast(errText(error), 'err');
    }
  }

  async function unlockOwn() {
    const passphrase = $('#unlock-pass').value;
    if (!state.lockedArmor) return;
    await withBusy($('#unlock-btn'), 'Проверяю…', async () => {
      try {
        const identity = await core.importPrivateKey(state.lockedArmor, passphrase);
        state.identity = identity;
        state.ownArmor = state.lockedArmor;
        state.ownProtected = true;
        state.lockedArmor = null;
        $('#unlock-pass').value = '';
        saveSession();
        render();
        toast(`Ключ разблокирован. Отпечаток: ${identity.fingerprint}`, 'ok');
      } catch (error) {
        toast(errText(error), 'err');
      }
    });
  }

  /* ------------------------------------------------------------------ */
  /* Ключи: собеседника                                                  */
  /* ------------------------------------------------------------------ */

  async function savePeerKey(text) {
    const value = String(text == null ? $('#peer-input').value : text).trim();
    if (!value) {
      toast('Вставьте публичный ключ собеседника.', 'warn');
      return;
    }
    try {
      const parsed = core.parsePublicKey(value);
      if (state.identity && parsed.text === state.identity.publicKeyText) {
        toast('Это ваш собственный публичный ключ. Нужен ключ собеседника.', 'warn');
        return;
      }
      const fp = await core.fingerprint(parsed.raw);
      state.peer = { text: parsed.text, fingerprint: fp };
      state.peerText = parsed.text;
      $('#peer-input').value = core.publicKeyArmor(parsed.text).trim();
      saveSession();
      render();
      toast(`Ключ собеседника сохранён. Отпечаток: ${fp}`, 'ok');
    } catch (error) {
      toast(errText(error), 'err');
    }
  }

  function clearPeerKey() {
    state.peer = null;
    state.peerText = null;
    $('#peer-input').value = '';
    saveSession();
    render();
  }

  /* ------------------------------------------------------------------ */
  /* Шифрование и расшифровка                                            */
  /* ------------------------------------------------------------------ */

  function showEncryptError(message) {
    removeError('#enc-error');
    const box = document.createElement('div');
    box.className = 'error-box';
    box.id = 'enc-error';
    box.textContent = message;
    $('#enc-out-block').before(box);
  }

  function showDecryptError(message) {
    removeError('#dec-error');
    const box = document.createElement('div');
    box.className = 'error-box';
    box.id = 'dec-error';
    box.textContent = message;
    $('#dec-out-block').before(box);
    $('#dec-out-block').hidden = true;
  }

  function removeError(selector) {
    const el = $(selector);
    if (el) el.remove();
  }

  async function doEncrypt(button) {
    const plaintext = $('#plaintext').value;
    if (!plaintext) {
      toast('Введите текст, который нужно зашифровать.', 'warn');
      $('#plaintext').focus();
      return;
    }
    if (!state.identity || !state.peer) {
      toast('Нужны и ваш ключ, и ключ собеседника.', 'warn');
      return;
    }
    button.dataset.busy = '1';
    button.disabled = true;
    try {
      removeError('#enc-error');
      const message = await core.encrypt({ plaintext, recipient: state.peer.text, identity: state.identity });
      $('#enc-out').value = message.trim();
      $('#enc-out-block').hidden = false;
      $('#enc-meta').textContent = `на выходе ${formatSize(message)}`;
      toast('Готово. Шифротекст можно отдавать собеседнику по любому каналу.', 'ok');
    } catch (error) {
      showEncryptError(errText(error));
      $('#enc-out-block').hidden = true;
      toast(errText(error), 'err');
    } finally {
      button.dataset.busy = '';
      updateAvailability();
    }
  }

  /**
   * Локальная проверка работоспособности: убеждаемся, что «каша» превращается
   * обратно в текст, не выходя из этой вкладки.
   *
   * Расшифровать собственную посылку адресату нельзя — для этого нужен приватный
   * ключ получателя, которого у отправителя нет и быть не должно. Поэтому проверяем
   * на двух временных получателях, ключи которых живут только здесь:
   *   • самому себе — свой ключ участвует и со стороны отправителя, и со стороны получателя;
   *   • временному «двойнику» — полная симуляция обмена, ключи у сторон разные.
   * Плюс контрольные проверки: посторонний ключ не должен ничего прочитать,
   * а исходный текст не должен угадываться в шифротексте.
   */
  async function doSelfCheck(button) {
    const plaintext = $('#plaintext').value;
    if (!plaintext) {
      toast('Введите текст — его и проверим.', 'warn');
      $('#plaintext').focus();
      return;
    }
    if (!state.identity) {
      toast('Сначала создайте или импортируйте свою пару ключей.', 'warn');
      scrollTo('#own-card', { behavior: 'smooth', block: 'center' });
      return;
    }
    button.dataset.busy = '1';
    button.disabled = true;
    const steps = [];
    try {
      // 1. Посылка самому себе: шифруем своим публичным ключом, читаем своим приватным.
      const toSelf = await core.encrypt({ plaintext, recipient: state.identity.publicKeyText, identity: state.identity });
      const selfOpened = await core.decrypt({ message: toSelf, identity: state.identity });
      steps.push({ name: 'Самому себе: зашифровать и прочитать своим ключом', ok: selfOpened.plaintext === plaintext });

      // 2. Посылка временному «двойнику»: это уже настоящий обмен между разными ключами.
      const twin = await core.generateIdentity();
      const toTwin = await core.encrypt({ plaintext, recipient: twin.publicKeyText, identity: state.identity });
      const twinOpened = await core.decrypt({ message: toTwin, identity: twin });
      steps.push({ name: 'Двойнику: зашифровать одним ключом и прочитать другим', ok: twinOpened.plaintext === plaintext });

      // 3. Посторонний ключ не должен прочитать эту посылку.
      const stranger = await core.generateIdentity();
      let rejected = false;
      try {
        await core.decrypt({ message: toTwin, identity: stranger });
      } catch (error) {
        rejected = true;
      }
      steps.push({ name: 'Чужой ключ посылку не читает', ok: rejected });

      // 4. Исходный текст не должен угадываться в шифротексте.
      steps.push({ name: 'В шифротексте нет исходного текста', ok: !toTwin.includes(plaintext) });

      const allOk = steps.every((step) => step.ok);
      $('#local-out').value = (twinOpened ? twinOpened.plaintext : selfOpened.plaintext);
      $('#local-ct').value = toTwin.trim();
      $('#local-steps').innerHTML = '';
      for (const step of steps) {
        const li = document.createElement('li');
        li.className = step.ok ? 'pass' : 'fail';
        li.innerHTML = `<span class="mark">${step.ok ? '✓' : '✗'}</span><span>${step.name}</span>`;
        $('#local-steps').appendChild(li);
      }
      $('#local-check').hidden = false;
      $('#local-check').classList.toggle('mismatch', !allOk);
      const verdict = $('#local-verdict');
      verdict.textContent = allOk ? `${steps.length} из ${steps.length} — совпало ✓` : 'есть расхождения ✗';
      verdict.className = allOk ? 'badge-ok' : 'badge-err';
      toast(
        allOk
          ? 'Локальная проверка пройдена: шифрование на этой машине работает, текст возвращается без потерь.'
          : 'Локальная проверка нашла расхождения — не отправляйте секреты, пока не разберётесь.',
        allOk ? 'ok' : 'err'
      );
    } catch (error) {
      showEncryptError(errText(error));
      toast(errText(error), 'err');
    } finally {
      button.dataset.busy = '';
      updateAvailability();
    }
  }

  async function doDecrypt() {
    const ciphertext = $('#ciphertext').value;
    if (!ciphertext.trim()) {
      toast('Вставьте шифротекст, который вам прислали.', 'warn');
      return;
    }
    if (!state.identity) {
      toast('Сначала создайте или импортируйте свою пару ключей.', 'warn');
      scrollTo('#own-card', { behavior: 'smooth', block: 'center' });
      return;
    }
    const button = $('#decrypt-btn');
    button.dataset.busy = '1';
    button.disabled = true;
    try {
      removeError('#dec-error');
      const info = await core.inspect(ciphertext).catch(() => null);
      const opened = await core.decrypt({ message: ciphertext, identity: state.identity });
      $('#dec-out').value = opened.plaintext;
      $('#dec-out-block').hidden = false;

      const bits = [`от отправителя ${opened.senderFingerprint}`];
      const when = formatTime(opened.timestamp);
      if (when) bits.push(when);
      if (info) bits.push(`${opened.plaintext.length} символов`);
      $('#dec-meta').textContent = bits.join(' · ');

      const knownSender = state.peer && state.peer.text === opened.senderPublicKeyText;
      if (!knownSender) {
        toast(`Текст расшифрован, но это ключ не того собеседника, чей ключ вы сохранили. Отпечаток отправителя: ${opened.senderFingerprint}`, 'warn', 9000);
      } else {
        toast('Расшифровано. Отправитель совпадает с сохранённым ключом.', 'ok');
      }
    } catch (error) {
      showDecryptError(errText(error));
      toast(errText(error), 'err');
    } finally {
      button.dataset.busy = '';
      updateAvailability();
    }
  }

  /* ------------------------------------------------------------------ */
  /* Файлы                                                               */
  /* ------------------------------------------------------------------ */

  function pickFile(target) {
    state.pendingFileTarget = target;
    $('#file-input').value = '';
    $('#file-input').click();
  }

  async function handleFile(file) {
    const text = await file.text();
    if (state.pendingFileTarget === 'peer') {
      $('#peer-input').value = text.trim();
      await savePeerKey(text);
    } else {
      if (!$('#peer-input').value && /PUBLIC KEY/.test(text)) {
        $('#peer-input').value = text.trim();
        await savePeerKey(text);
      } else {
        await importOwnFromText(text, null);
      }
    }
  }

  /* ------------------------------------------------------------------ */
  /* Диалоги                                                             */
  /* ------------------------------------------------------------------ */

  function openDialog(selector) {
    const dialog = $(selector);
    if (typeof dialog.showModal === 'function') dialog.showModal();
    else dialog.setAttribute('open', '');
  }

  async function runSelfTest() {
    const list = $('#test-list');
    const summary = $('#test-summary');
    list.innerHTML = '';
    summary.textContent = 'Идёт проверка…';
    const started = Date.now();
    const seen = new Map();

    const onStep = (step) => {
      let li = seen.get(step.name);
      if (!li) {
        li = document.createElement('li');
        li.innerHTML = '<span class="mark">…</span><span class="name"></span><span class="ms"></span>';
        list.appendChild(li);
        seen.set(step.name, li);
      }
      li.className = step.ok ? 'pass' : 'fail';
      li.querySelector('.mark').textContent = step.ok ? '✓' : '✗';
      li.querySelector('.name').textContent = step.name;
      li.querySelector('.name').innerHTML = `${step.name}${step.detail ? `<span class="detail"> — ${step.detail}</span>` : ''}`;
      li.querySelector('.ms').textContent = `${step.ms} мс`;
      scrollTo(li, { block: 'nearest' });
    };

    const button = $('#run-test-btn');
    button.disabled = true;
    try {
      const results = await core.selfTest(onStep);
      const failed = results.filter((r) => !r.ok).length;
      const total = Date.now() - started;
      summary.innerHTML = failed === 0
        ? `<span class="ok-text">Все ${results.length} проверок пройдены за ${total} мс.</span> Шифрование на этом устройстве работает: секрет доходит до адресата, чужой ключ и подделка — отклоняются.`
        : `<span class="danger-text">Упало проверок: ${failed} из ${results.length}.</span> Не используйте этот браузер для секретов до выяснения причин.`;
      toast(failed === 0 ? 'Самопроверка пройдена полностью.' : `Самопроверка: ошибок ${failed}.`, failed === 0 ? 'ok' : 'err');
    } catch (error) {
      summary.textContent = errText(error);
      toast(errText(error), 'err');
    } finally {
      button.disabled = false;
    }
  }

  /* ------------------------------------------------------------------ */
  /* Привязка событий                                                    */
  /* ------------------------------------------------------------------ */

  function bind() {
    $('#self-test-btn').addEventListener('click', () => openDialog('#test-dialog'));
    $('#help-btn').addEventListener('click', () => openDialog('#help-dialog'));
    $('#run-test-btn').addEventListener('click', runSelfTest);

    document.querySelectorAll('dialog [data-close], dialog').forEach((el) => {
      if (el.tagName === 'DIALOG') {
        el.addEventListener('click', (event) => {
          if (event.target === el) el.close();
        });
      } else {
        el.addEventListener('click', () => el.closest('dialog').close());
      }
    });

    $('#protect-toggle').addEventListener('change', (event) => {
      $('#protect-field').classList.toggle('hidden', !event.target.checked);
      if (event.target.checked) $('#protect-pass').focus();
    });

    $('#generate-btn').addEventListener('click', generateOwn);
    $('#reset-own-btn').addEventListener('click', resetOwn);
    $('#import-own-btn').addEventListener('click', () => pickFile('own'));
    $('#unlock-btn').addEventListener('click', unlockOwn);
    $('#unlock-pass').addEventListener('keydown', (event) => {
      if (event.key === 'Enter') unlockOwn();
    });

    $('#download-pub-btn').addEventListener('click', () => {
      if (!state.identity) return;
      download('encryptory-public-key.txt', `${core.publicKeyArmor(state.identity.publicKeyText)}`);
      toast('Файл с публичным ключом сохранён — его можно отдавать кому угодно.', 'ok');
    });

    $('#download-priv-btn').addEventListener('click', () => {
      if (!state.ownArmor) return;
      download('encryptory-private-key.txt', state.ownArmor.trim() + '\n');
      toast(state.ownProtected
        ? 'Приватный ключ сохранён (защищён паролем). Держите файл отдельно от переписки.'
        : 'Приватный ключ сохранён. Никому не передавайте этот файл!', 'warn', 6000);
    });

    $('#show-priv-btn').addEventListener('click', () => {
      const box = $('#own-priv');
      box.classList.toggle('hidden');
      if (!box.classList.contains('hidden')) box.focus();
    });

    $('#save-peer-btn').addEventListener('click', () => savePeerKey());
    $('#import-peer-btn').addEventListener('click', () => pickFile('peer'));
    $('#clear-peer-btn').addEventListener('click', clearPeerKey);

    // Правка текста ключа: если он всё ещё читается как тот же ключ — ничего не меняем,
    // если превратился в другое ключе или мусор — снимаем «сохранён» и просим сохранить заново.
    $('#peer-input').addEventListener('input', () => {
      const value = $('#peer-input').value.trim();
      if (!state.peer) return updateAvailability();
      let keep = false;
      if (value) {
        try {
          keep = core.parsePublicKey(value).text === state.peer.text;
        } catch (error) {
          keep = false;
        }
      }
      if (!keep) {
        state.peer = null;
        state.peerText = null;
        renderPeer();
        saveSession();
      }
      updateAvailability();
    });

    $('#encrypt-btn').addEventListener('click', (event) => doEncrypt(event.currentTarget, false));
    $('#self-check-btn').addEventListener('click', (event) => doSelfCheck(event.currentTarget));
    $('#decrypt-btn').addEventListener('click', doDecrypt);

    $('#paste-btn').addEventListener('click', async (event) => {
      try {
        const text = await navigator.clipboard.readText();
        $('#ciphertext').value = text.trim();
        updateAvailability();
        toast('Вставлено из буфера.', 'ok');
      } catch (error) {
        toast('Браузер не дал доступ к буферу — вставьте вручную (Ctrl/Cmd+V).', 'warn');
      }
    });

    $('#clear-in-btn').addEventListener('click', () => {
      $('#ciphertext').value = '';
      $('#dec-out-block').hidden = true;
      $('#dec-meta').textContent = '';
      removeError('#dec-error');
      updateAvailability();
    });

    $('#clear-out-btn').addEventListener('click', () => {
      $('#dec-out').value = '';
      $('#dec-out-block').hidden = true;
      $('#dec-meta').textContent = '';
    });

    $('#file-input').addEventListener('change', async (event) => {
      const file = event.target.files && event.target.files[0];
      if (!file) return;
      try {
        await handleFile(file);
      } catch (error) {
        toast(errText(error), 'err');
      }
    });

    document.addEventListener('click', (event) => {
      const copyBtn = event.target.closest('[data-copy]');
      if (copyBtn) copyFrom(copyBtn.dataset.copy, copyBtn);
      const selectBtn = event.target.closest('[data-select]');
      if (selectBtn) {
        const target = $(selectBtn.dataset.select);
        target.focus();
        target.select();
      }
    });

    $('#plaintext').addEventListener('keydown', (event) => {
      if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) doEncrypt($('#encrypt-btn'), false);
    });
    $('#ciphertext').addEventListener('keydown', (event) => {
      if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) doDecrypt();
    });
    $('#ciphertext').addEventListener('input', updateAvailability);
    $('#plaintext').addEventListener('input', () => {
      $('#local-check').hidden = true;
      const length = $('#plaintext').value.length;
      $('#enc-meta').textContent = length ? `${length} симв.` : '';
      removeError('#enc-error');
    });
  }

  /* ------------------------------------------------------------------ */
  /* Старт                                                               */
  /* ------------------------------------------------------------------ */

  async function restoreSession() {
    const saved = loadSession();
    if (!saved) return;
    if (saved.peer) {
      try {
        const parsed = core.parsePublicKey(saved.peer);
        state.peer = { text: parsed.text, fingerprint: await core.fingerprint(parsed.raw) };
        state.peerText = parsed.text;
        $('#peer-input').value = core.publicKeyArmor(parsed.text).trim();
      } catch (error) {
        /* ключ собеседника был битый — молча начинаем заново */
      }
    }
    if (saved.ownArmor) {
      if (saved.ownProtected || core.isPrivateKeyProtected(saved.ownArmor)) {
        state.lockedArmor = saved.ownArmor;
      } else {
        try {
          const identity = await core.importPrivateKey(saved.ownArmor, null);
          state.identity = identity;
          state.ownArmor = saved.ownArmor;
        } catch (error) {
          state.lockedArmor = saved.ownArmor;
        }
      }
    }
  }

  async function main() {
    if (!core) {
      toast('Не загрузилось ядро шифрования (src/encryptory-core.js).', 'err', 120000);
      return;
    }
    $('#algo-label').textContent = core.ALGO_LABEL;
    bind();
    await restoreSession();
    render();
    $('#enc-meta').textContent = '';
    if (state.lockedArmor) toast('Приватный ключ защищён паролем — введите его, чтобы начать.', 'warn', 8000);
  }

  document.addEventListener('DOMContentLoaded', main);
})();
