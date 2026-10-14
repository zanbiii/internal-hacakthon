/**
 * CyberSeal — UI controller
 */
document.addEventListener('DOMContentLoaded', () => {
  'use strict';

  const $ = (id) => document.getElementById(id);

  const escapeHtml = (str) => String(str === null || str === undefined ? '' : str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

  // ------------------------------------------------------------------ setup

  checkLibraries();

  const detector = new ThreatDetector();
  const seal = new KaagazSeal();
  const auth = new CyberAuth();
  let verifiedOriginalText = null;
  let isScanning = false;
  let lastSealedData = null;
  let ocrFile = null;
  let toastTimer = null;
  let docScanToken = 0;
  let pdfjsLoading = null;

  // ---------------------------------------------------------------- helpers

  /** Markup for an icon from the inline SVG sprite in index.html. */
  function icon(name, cls) {
    return `<svg class="icon${cls ? ' ' + cls : ''}" aria-hidden="true"><use href="#i-${name}"></use></svg>`;
  }

  function checkLibraries() {
    const missing = [];
    if (typeof pako === 'undefined') missing.push('pako (compression)');
    if (typeof Diff === 'undefined') missing.push('jsdiff (text comparison)');
    if (typeof QRCode === 'undefined') missing.push('qrcode (QR generation)');
    if (typeof Html5Qrcode === 'undefined') missing.push('html5-qrcode (QR scanning)');
    if (typeof Tesseract === 'undefined') missing.push('tesseract.js (OCR)');
    if (missing.length) {
      const banner = $('lib-warning');
      banner.textContent = `Some libraries failed to load: ${missing.join(', ')}. Threat detection still works; related KaagazSeal features need an internet connection. Reload to retry.`;
      banner.classList.remove('hidden');
    }
  }

  function reveal(el) {
    if (!el) return;
    el.classList.remove('hidden', 'animate-fade');
    void el.offsetWidth; // restart the animation
    el.classList.add('animate-fade');
  }

  function revealTab(el) {
    if (!el) return;
    el.classList.remove('hidden', 'animate-tab');
    void el.offsetWidth;
    el.classList.add('animate-tab');
  }

  function scrollIntoViewIfNeeded(el) {
    if (!el) return;
    const rect = el.getBoundingClientRect();
    if (rect.top < 0 || rect.top > window.innerHeight * 0.6) {
      el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }

  function toast(message, duration = 3200) {
    const el = $('toast');
    el.textContent = message;
    el.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove('show'), duration);
  }

  function setBusy(button, busy, busyLabel) {
    if (!button) return;
    if (busy) {
      if (!button.dataset.label) button.dataset.label = button.innerHTML;
      button.disabled = true;
      button.classList.add('is-loading');
      if (busyLabel) button.innerHTML = `<span class="spinner" aria-hidden="true"></span>${escapeHtml(busyLabel)}`;
    } else {
      button.disabled = false;
      button.classList.remove('is-loading');
      if (button.dataset.label) {
        button.innerHTML = button.dataset.label;
        delete button.dataset.label;
      }
    }
  }

  function formatDate(iso) {
    if (!iso) return 'Unknown';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    try {
      return d.toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' });
    } catch (err) {
      return d.toLocaleString();
    }
  }

  function formatAmount(amount) {
    if (amount === '' || amount === null || amount === undefined) return '';
    const n = Number(amount);
    if (!Number.isFinite(n)) return String(amount);
    try {
      return new Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR', maximumFractionDigits: 2 }).format(n);
    } catch (err) {
      return '₹' + n.toFixed(2);
    }
  }

  function slugify(str) {
    return String(str || 'document').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40) || 'document';
  }

  function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  // ------------------------------------------------------------------- tabs

  function setTabState(activeBtn, inactiveBtn) {
    activeBtn.classList.add('active');
    activeBtn.setAttribute('aria-selected', 'true');
    inactiveBtn.classList.remove('active');
    inactiveBtn.setAttribute('aria-selected', 'false');
  }

  async function stopCameraIfRunning() {
    if (!isScanning) return;
    await seal.stopScanner();
    isScanning = false;
    updateScanButton();
    setScanStatus('');
  }

  $('tab-threat').addEventListener('click', async () => {
    if ($('tab-threat').classList.contains('active')) return;
    await stopCameraIfRunning();
    setTabState($('tab-threat'), $('tab-seal'));
    $('seal-section').classList.add('hidden');
    revealTab($('threat-section'));
  });

  $('tab-seal').addEventListener('click', () => {
    if ($('tab-seal').classList.contains('active')) return;
    setTabState($('tab-seal'), $('tab-threat'));
    $('threat-section').classList.add('hidden');
    revealTab($('seal-section'));
  });

  $('seal-mode-btn').addEventListener('click', async () => {
    if ($('seal-mode-btn').classList.contains('active')) return;
    await stopCameraIfRunning();
    setTabState($('seal-mode-btn'), $('verify-mode-btn'));
    $('verify-panel').classList.add('hidden');
    revealTab($('seal-panel'));
  });

  $('verify-mode-btn').addEventListener('click', () => {
    if ($('verify-mode-btn').classList.contains('active')) return;
    setTabState($('verify-mode-btn'), $('seal-mode-btn'));
    $('seal-panel').classList.add('hidden');
    revealTab($('verify-panel'));
  });

  // ======================================================= THREAT DETECTOR

  const threatType = $('threat-type');
  const threatInput = $('threat-input');
  const analyzeBtn = $('analyze-btn');

  const typeButtons = document.querySelectorAll('[data-threat-type]');

  threatType.addEventListener('change', () => {
    threatInput.placeholder = threatType.value === 'url'
      ? 'Paste a URL to analyze, e.g. https://example.com/login'
      : 'Paste a suspicious SMS, email or chat message...';
    typeButtons.forEach((btn) => {
      const active = btn.dataset.threatType === threatType.value;
      btn.classList.toggle('active', active);
      btn.setAttribute('aria-checked', String(active));
    });
  });

  // The visible URL / Message switch drives the (hidden) select the rest of the code reads.
  typeButtons.forEach((btn) => {
    btn.addEventListener('click', () => {
      if (threatType.value === btn.dataset.threatType) return;
      threatType.value = btn.dataset.threatType;
      threatType.dispatchEvent(new Event('change'));
      threatInput.focus();
    });
  });

  document.querySelectorAll('.example-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      threatType.value = btn.dataset.type === 'message' ? 'message' : 'url';
      threatType.dispatchEvent(new Event('change'));
      threatInput.value = btn.dataset.value || '';
      runAnalysis();
    });
  });

  analyzeBtn.addEventListener('click', runAnalysis);

  threatInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      runAnalysis();
    }
  });

  function runAnalysis() {
    const value = threatInput.value.trim();
    if (!value) {
      toast('Paste a URL or message first.');
      threatInput.focus();
      return;
    }

    // Help users who picked the wrong input type.
    let type = threatType.value;
    const wordCount = value.split(/\s+/).length;
    if (type === 'url' && wordCount >= 3) {
      type = 'message';
      threatType.value = 'message';
      threatType.dispatchEvent(new Event('change'));
      toast('That looks like a message, so it was analyzed as a message.');
    } else if (type === 'message' && wordCount === 1 && /^(https?:\/\/|www\.)|^[\w-]+(\.[\w-]+)+(\/|$)/i.test(value)) {
      type = 'url';
      threatType.value = 'url';
      threatType.dispatchEvent(new Event('change'));
      toast('That looks like a URL, so it was analyzed as a URL.');
    }

    let result;
    try {
      result = detector.analyze(value, type);
    } catch (err) {
      console.error(err);
      toast('Analysis failed. Please try again.');
      return;
    }
    renderThreatResult(result);
  }

  const RISK_HEADLINES = {
    'risk-safe': 'No significant threats found',
    'risk-low': 'A few minor warning signs',
    'risk-medium': 'Proceed with caution',
    'risk-high': 'This looks like a scam',
    'risk-critical': 'Dangerous. Do not interact.'
  };
  const RING_CIRCUMFERENCE = 2 * Math.PI * 52;
  let scoreCountTimer = null;
  let lastThreatResult = null;

  function renderThreatResult(result) {
    lastThreatResult = result;
    const levelEl = $('risk-level');
    const fill = $('risk-score-fill');
    const ring = $('risk-score-bar');
    const numEl = $('risk-score-num');

    levelEl.className = 'risk-pill ' + result.levelClass;
    levelEl.textContent = result.level;
    $('risk-headline').textContent = RISK_HEADLINES[result.levelClass] || '';
    const warnings = result.reasons.length;
    const positives = (result.positives || []).length;
    $('risk-score-text').textContent = warnings
      ? `${warnings} warning sign${warnings === 1 ? '' : 's'} found${positives ? ` · ${positives} reassuring sign${positives === 1 ? '' : 's'}` : ''}`
      : 'No warning signs found';
    ring.setAttribute('aria-valuenow', String(result.score));

    // Animate the ring and the number from zero each time.
    fill.style.transition = 'none';
    fill.style.strokeDashoffset = String(RING_CIRCUMFERENCE);
    fill.setAttribute('class', 'ring-fill fill-' + result.levelClass.replace('risk-', ''));
    void fill.getBoundingClientRect();
    fill.style.transition = '';
    requestAnimationFrame(() => {
      fill.style.strokeDashoffset = String(RING_CIRCUMFERENCE * (1 - Math.max(result.score, 1) / 100));
    });

    clearInterval(scoreCountTimer);
    const start = performance.now();
    const duration = 900;
    numEl.textContent = '0';
    scoreCountTimer = setInterval(() => {
      const t = Math.min(1, (performance.now() - start) / duration);
      numEl.textContent = String(Math.round(result.score * (1 - Math.pow(1 - t, 3))));
      if (t >= 1) clearInterval(scoreCountTimer);
    }, 16);

    const reasons = $('reasons-list');
    reasons.innerHTML = '';
    if (!result.reasons.length) {
      const li = document.createElement('li');
      li.className = 'reason-good';
      li.textContent = 'No threat indicators detected';
      reasons.appendChild(li);
    }
    result.reasons.forEach((r) => {
      const li = document.createElement('li');
      li.textContent = r;
      reasons.appendChild(li);
    });
    (result.positives || []).forEach((p) => {
      const li = document.createElement('li');
      li.className = 'reason-good';
      li.textContent = p;
      reasons.appendChild(li);
    });

    const recs = $('recommendations-list');
    recs.innerHTML = '';
    result.recommendations.forEach((r) => {
      const li = document.createElement('li');
      li.textContent = r;
      recs.appendChild(li);
    });

    const container = $('threat-results');
    reveal(container);
    scrollIntoViewIfNeeded(container);
  }

  // ============================================================ KAAGAZSEAL

  const sealBtn = $('seal-btn');
  const keyStatus = $('key-status');

  function showKeyReady() {
    if (!seal.fingerprint) return;
    const signer = activeSignerName();
    const who = signer ? `Signing as <strong>${escapeHtml(signer)}</strong> · ` : '';
    keyStatus.className = 'key-status ready';
    keyStatus.innerHTML = `${icon('shield-check')}<span>${who}Key <span class="fingerprint">${escapeHtml(seal.fingerprint)}</span></span>`
      + (seal.keyPersisted ? '' : '<span title="This browser blocked key storage, so a new key is created each visit.">· session-only key</span>');
    sealBtn.disabled = false;
  }

  function showKeyError(message) {
    keyStatus.className = 'key-status error';
    keyStatus.innerHTML = `${icon('x-circle')}<span>${escapeHtml(message || 'Could not create a signing key.')}</span>`;
    sealBtn.disabled = true;
  }

  function showKeyLoading() {
    keyStatus.className = 'key-status';
    keyStatus.innerHTML = '<span class="spinner" aria-hidden="true"></span><span>Preparing your signing key…</span>';
    sealBtn.disabled = true;
  }

  document.addEventListener('keysReady', showKeyReady);
  document.addEventListener('keysError', (e) => {
    if (auth.currentUser) showKeyError(e.detail && e.detail.message);
  });

  // ================================================================ ACCOUNTS

  const authDialog = $('auth-dialog');
  const deleteDialog = $('delete-dialog');
  const userDropdown = $('user-dropdown');
  const userMenuBtn = $('user-menu-btn');

  function initials(name) {
    const parts = String(name || '?').trim().split(/\s+/).filter(Boolean);
    const letters = parts.length > 1 ? parts[0][0] + parts[parts.length - 1][0] : (parts[0] || '?').slice(0, 2);
    return letters.toUpperCase();
  }

  function openModal(dialog) {
    if (dialog.open) return;
    if (typeof dialog.showModal === 'function') dialog.showModal();
    else dialog.setAttribute('open', '');
  }

  function closeModal(dialog) {
    if (!dialog.open) return;
    if (typeof dialog.close === 'function') dialog.close();
    else dialog.removeAttribute('open');
  }

  function clearFormErrors(form) {
    form.querySelectorAll('.invalid').forEach((el) => el.classList.remove('invalid'));
    form.querySelectorAll('.form-error').forEach((el) => { el.textContent = ''; });
  }

  function showFormError(form, errorEl, err, fieldMap) {
    errorEl.textContent = err && err.message ? err.message : 'Something went wrong. Please try again.';
    const input = err && err.field && fieldMap[err.field];
    if (input) {
      input.classList.add('invalid');
      input.focus();
    }
  }

  function setAuthMode(mode) {
    const signup = mode === 'signup';
    setTabState(signup ? $('auth-signup-tab') : $('auth-login-tab'), signup ? $('auth-login-tab') : $('auth-signup-tab'));
    $('login-form').classList.toggle('hidden', signup);
    $('signup-form').classList.toggle('hidden', !signup);
    $('auth-title').textContent = signup ? 'Create your account' : 'Welcome back';
    clearFormErrors($('login-form'));
    clearFormErrors($('signup-form'));
    setTimeout(() => (signup ? $('signup-name') : $('login-username')).focus(), 50);
  }

  function openAuth(mode) {
    closeUserMenu();
    openModal(authDialog);
    setAuthMode(mode);
  }

  $('login-open-btn').addEventListener('click', () => openAuth('login'));
  $('locked-login-btn').addEventListener('click', () => openAuth('login'));
  $('locked-signup-btn').addEventListener('click', () => openAuth('signup'));
  $('auth-login-tab').addEventListener('click', () => setAuthMode('login'));
  $('auth-signup-tab').addEventListener('click', () => setAuthMode('signup'));
  document.querySelectorAll('[data-auth-mode]').forEach((btn) => {
    btn.addEventListener('click', () => setAuthMode(btn.dataset.authMode));
  });
  $('auth-close').addEventListener('click', () => closeModal(authDialog));

  // Close dialogs when the backdrop is clicked.
  [authDialog, deleteDialog].forEach((dialog) => {
    dialog.addEventListener('click', (e) => {
      if (e.target === dialog) closeModal(dialog);
    });
  });

  document.querySelectorAll('.pw-toggle').forEach((btn) => {
    btn.addEventListener('click', () => {
      const input = $(btn.dataset.target);
      const show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      btn.setAttribute('aria-pressed', String(show));
      btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
      btn.innerHTML = icon(show ? 'eye-off' : 'eye');
    });
  });

  // Clear a field's error state as soon as the user edits it.
  document.querySelectorAll('.auth-form input, #delete-form input').forEach((input) => {
    input.addEventListener('input', () => {
      input.classList.remove('invalid');
      const error = input.closest('form').querySelector('.form-error');
      if (error) error.textContent = '';
    });
  });

  const STRENGTH_COLORS = ['var(--danger)', 'var(--danger)', 'var(--warning)', 'var(--low)', 'var(--success)'];
  $('signup-password').addEventListener('input', () => {
    const pw = $('signup-password').value;
    const s = auth.passwordStrength(pw);
    $('strength-fill').style.width = pw ? `${Math.max(1, s.score) * 25}%` : '0';
    $('strength-fill').style.backgroundColor = STRENGTH_COLORS[s.score];
    $('strength-label').textContent = pw ? (s.message || s.label) : 'At least 8 characters, with a letter and a number';
  });

  $('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.currentTarget;
    const submit = form.querySelector('button[type="submit"]');
    clearFormErrors(form);
    setBusy(submit, true, 'Checking…');
    try {
      const user = await auth.logIn($('login-username').value, $('login-password').value, $('login-remember').checked);
      form.reset();
      closeModal(authDialog);
      toast(`Welcome back, ${user.name.split(' ')[0]}!`);
    } catch (err) {
      showFormError(form, $('login-error'), err, { username: $('login-username'), password: $('login-password') });
      $('login-password').value = '';
    } finally {
      setBusy(submit, false);
    }
  });

  $('signup-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.currentTarget;
    const submit = form.querySelector('button[type="submit"]');
    clearFormErrors(form);
    setBusy(submit, true, 'Creating account…');
    try {
      const user = await auth.signUp({
        name: $('signup-name').value,
        organization: $('signup-org').value,
        username: $('signup-username').value,
        password: $('signup-password').value,
        confirm: $('signup-confirm').value
      });
      form.reset();
      $('signup-password').dispatchEvent(new Event('input'));
      closeModal(authDialog);
      toast(`Account created. Welcome, ${user.name.split(' ')[0]}!`);
    } catch (err) {
      showFormError(form, $('signup-error'), err, {
        name: $('signup-name'),
        organization: $('signup-org'),
        username: $('signup-username'),
        password: $('signup-password'),
        confirm: $('signup-confirm')
      });
    } finally {
      setBusy(submit, false);
    }
  });

  // ----- user menu

  function closeUserMenu() {
    userDropdown.classList.add('hidden');
    userMenuBtn.setAttribute('aria-expanded', 'false');
  }

  userMenuBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    const open = userDropdown.classList.contains('hidden');
    userDropdown.classList.toggle('hidden', !open);
    userMenuBtn.setAttribute('aria-expanded', String(open));
  });

  document.addEventListener('click', (e) => {
    if (!userDropdown.classList.contains('hidden') && !e.target.closest('#user-menu')) closeUserMenu();
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !userDropdown.classList.contains('hidden')) {
      closeUserMenu();
      userMenuBtn.focus();
    }
  });

  $('logout-btn').addEventListener('click', () => {
    closeUserMenu();
    auth.logOut();
    toast('You have been logged out.');
  });

  $('delete-account-btn').addEventListener('click', () => {
    closeUserMenu();
    $('delete-form').reset();
    clearFormErrors($('delete-form'));
    openModal(deleteDialog);
    setTimeout(() => $('delete-password').focus(), 50);
  });

  $('delete-close').addEventListener('click', () => closeModal(deleteDialog));
  $('delete-cancel').addEventListener('click', () => closeModal(deleteDialog));

  $('delete-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.currentTarget;
    const submit = form.querySelector('button[type="submit"]');
    clearFormErrors(form);
    setBusy(submit, true, 'Deleting…');
    try {
      const deletedId = await auth.deleteAccount($('delete-password').value);
      await seal.deleteIdentityKey(deletedId);
      closeModal(deleteDialog);
      toast('Your account and signing key were deleted.');
    } catch (err) {
      showFormError(form, $('delete-error'), err, { password: $('delete-password') });
    } finally {
      setBusy(submit, false);
    }
  });

  // ----- react to sign-in state

  function resetSealOutput() {
    lastSealedData = null;
    $('sealed-doc').innerHTML = '';
    $('sealed-output').classList.add('hidden');
    $('download-btn').classList.add('hidden');
    $('download-qr-btn').classList.add('hidden');
  }

  function applyUser(user) {
    const signedIn = !!user;
    $('login-open-btn').classList.toggle('hidden', signedIn);
    $('user-menu').classList.toggle('hidden', !signedIn);
    $('seal-locked').classList.toggle('hidden', signedIn);
    $('seal-form-card').classList.toggle('hidden', !signedIn);
    closeUserMenu();
    resetSealOutput();
    resetDocScan();

    if (signedIn) {
      $('user-avatar').textContent = initials(user.name);
      $('user-chip-name').textContent = user.name;
      $('ud-name').textContent = user.name;
      $('ud-meta').textContent = `@${user.username}` + (user.organization ? ` · ${user.organization}` : '');
      $('issuer-name').value = user.organization || user.name;
      showKeyLoading();
      seal.useIdentity(user.id).then((ok) => {
        if (ok) showKeyReady();
        else if (auth.currentUser && auth.currentUser.id === user.id) {
          showKeyError(seal.initError && seal.initError.message);
        }
      });
    } else {
      $('issuer-name').value = '';
      seal.clearIdentity();
      keyStatus.className = 'key-status';
      keyStatus.textContent = '';
      sealBtn.disabled = true;
    }
  }

  // ================================================================ DEMO MODE
  // A guided tour that drives the real UI: nothing is faked, every step runs the actual feature.

  const DEMO_IDENTITY = 'demo-issuer';
  const DEMO_ISSUER = 'Sharma Properties';
  const DEMO_RECEIPT = 'Received a sum of Rs 15000 from Ravi Kumar towards rent for October 2026 for Flat 4B, Green Park, New Delhi.';
  const DEMO_PHISH = document.querySelector('.example-btn[data-type="message"]').dataset.value;
  const demo = { active: false, step: 0, running: false, runId: 0, focusEl: null };
  let ocrWarmup = null;

  class DemoCancelled extends Error {}

  function activeSignerName() {
    if (demo.active) return `${DEMO_ISSUER} (demo)`;
    return auth.currentUser ? auth.currentUser.name : '';
  }

  function demoCheck(runId) {
    if (!demo.active || runId !== demo.runId) throw new DemoCancelled();
  }

  async function demoSleep(ms, runId) {
    await new Promise((resolve) => setTimeout(resolve, ms));
    demoCheck(runId);
  }

  async function demoWaitFor(condition, runId, timeout = 30000) {
    const start = Date.now();
    while (!condition()) {
      if (Date.now() - start > timeout) throw new Error('This step took too long.');
      await demoSleep(120, runId);
    }
  }

  async function demoType(el, text, runId) {
    el.value = '';
    const frames = Math.min(45, text.length);
    const chunk = Math.ceil(text.length / frames);
    for (let i = chunk; i < text.length; i += chunk) {
      el.value = text.slice(0, i);
      el.dispatchEvent(new Event('input'));
      await demoSleep(28, runId);
    }
    el.value = text;
    el.dispatchEvent(new Event('input'));
  }

  function demoFocus(el) {
    if (demo.focusEl) demo.focusEl.classList.remove('demo-focus');
    demo.focusEl = el || null;
    if (el) {
      el.classList.add('demo-focus');
      el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }

  async function demoTab(btn, runId) {
    if (!btn.classList.contains('active')) btn.click();
    await demoSleep(400, runId);
  }

  async function useDemoIdentity(runId) {
    $('seal-locked').classList.add('hidden');
    $('seal-form-card').classList.remove('hidden');
    resetSealOutput();
    $('issuer-name').value = DEMO_ISSUER;
    showKeyLoading();
    const ok = await seal.useIdentity(DEMO_IDENTITY);
    demoCheck(runId);
    if (!ok) throw new Error(seal.initError ? seal.initError.message : 'Could not create the demo signing key.');
    showKeyReady();
  }

  /** Re-encodes a seal's payload with the amount changed but keeps the original signature. */
  function demoTamperQr(qrData, from, to) {
    const obj = JSON.parse(qrData);
    const payload = JSON.parse(new TextDecoder().decode(pako.inflate(seal._base64ToUint8(obj.p))));
    payload.t = payload.t.split(from).join(to);
    payload.a = String(payload.a).split(from).join(to);
    obj.p = seal._uint8ToBase64(pako.deflate(new TextEncoder().encode(JSON.stringify(payload))));
    return JSON.stringify(obj);
  }

  /** Renders a "photo" of a printed copy of the receipt with forged text. */
  async function demoForgedPrintout(issuer, title, bodyText) {
    const W = 1400;
    const pad = 90;
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    const bodyFont = '34px Georgia, "Times New Roman", serif';

    ctx.font = bodyFont;
    const lines = [];
    let line = '';
    bodyText.split(/\s+/).forEach((word) => {
      const test = line ? `${line} ${word}` : word;
      if (ctx.measureText(test).width > W - pad * 2 && line) {
        lines.push(line);
        line = word;
      } else {
        line = test;
      }
    });
    if (line) lines.push(line);

    canvas.width = W;
    canvas.height = pad * 2 + 250 + lines.length * 56;
    ctx.fillStyle = '#FFFFFF';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = '#1F1A16';
    let y = pad + 40;
    ctx.font = 'bold 40px Georgia, "Times New Roman", serif';
    ctx.fillText(issuer, pad, y);
    y += 30;
    ctx.fillRect(pad, y, W - pad * 2, 3);
    y += 90;
    ctx.font = 'bold 44px Georgia, "Times New Roman", serif';
    ctx.textAlign = 'center';
    ctx.fillText(title.toUpperCase(), W / 2, y);
    ctx.textAlign = 'left';
    y += 90;
    ctx.font = bodyFont;
    lines.forEach((l) => {
      ctx.fillText(l, pad, y);
      y += 56;
    });

    const blob = await new Promise((resolve) => canvas.toBlob(resolve, 'image/png'));
    return new File([blob], 'forged-printout.png', { type: 'image/png' });
  }

  /** Downloads the OCR language model in the background so the OCR step is quick on stage. */
  function warmUpOcr() {
    if (ocrWarmup || typeof Tesseract === 'undefined') return;
    ocrWarmup = Tesseract.createWorker('eng').then((w) => w.terminate()).catch(() => {});
  }

  const DEMO_STEPS = [
    {
      title: 'See CyberSeal in action',
      text: 'A one-minute guided tour: catch a phishing scam, seal a rent receipt, then catch two different forgeries. Everything runs on this device, and your own account is not touched.'
    },
    {
      title: 'Catch a phishing SMS',
      text: 'A typical bank-scam message arrives. CyberSeal checks it for urgency, threats, requests for personal data and dangerous links.',
      async run(runId) {
        await demoTab($('tab-threat'), runId);
        threatType.value = 'message';
        threatType.dispatchEvent(new Event('change'));
        demoFocus(threatInput.closest('.card'));
        await demoType(threatInput, DEMO_PHISH, runId);
        await demoSleep(300, runId);
        runAnalysis();
        await demoSleep(250, runId);
        demoFocus($('threat-results'));
        await demoSleep(900, runId);
        return `Scored ${lastThreatResult.score}/100: ${lastThreatResult.level}. Every red flag is listed with a reason, plus what to do next.`;
      }
    },
    {
      title: 'A real link stays clean',
      text: 'Not everything is a scam. A genuine link to google.com should pass without a false alarm.',
      async run(runId) {
        threatType.value = 'url';
        threatType.dispatchEvent(new Event('change'));
        demoFocus(threatInput.closest('.card'));
        await demoType(threatInput, 'https://google.com', runId);
        await demoSleep(300, runId);
        runAnalysis();
        await demoSleep(250, runId);
        demoFocus($('threat-results'));
        await demoSleep(900, runId);
        return `Scored ${lastThreatResult.score}/100: ${lastThreatResult.level}. No false alarm.`;
      }
    },
    {
      title: 'Seal a rent receipt',
      text: `${DEMO_ISSUER} issues a ₹15,000 rent receipt. Sealing signs the text with a private key that never leaves the device and packs the text and signature into a QR code.`,
      async run(runId) {
        await demoTab($('tab-seal'), runId);
        await demoTab($('seal-mode-btn'), runId);
        await useDemoIdentity(runId);
        demoFocus($('seal-form-card'));
        await demoType($('doc-title'), 'Rent Receipt', runId);
        await demoType($('doc-text'), DEMO_RECEIPT, runId);
        await demoType($('doc-amount'), '15000', runId);
        await demoSleep(300, runId);
        sealBtn.click();
        await demoWaitFor(() => lastSealedData !== null && !$('sealed-output').classList.contains('hidden'), runId);
        await demoSleep(200, runId);
        demoFocus($('sealed-output'));
        await demoSleep(900, runId);
        return 'Sealed. The QR code carries the signed original, and the key fingerprint identifies the signer.';
      }
    },
    {
      title: 'Verify the genuine document',
      text: 'The tenant scans the QR code on the receipt. CyberSeal checks the digital signature against the content.',
      async run(runId) {
        const canvas = $('sealed-qr-canvas');
        if (!canvas || !lastSealedData) throw new Error('Run the sealing step first.');
        const blob = await new Promise((resolve) => canvas.toBlob(resolve, 'image/png'));
        demoCheck(runId);
        await demoTab($('verify-mode-btn'), runId);
        demoFocus($('verify-panel').querySelector('.card'));
        setScanStatus('Scanning the QR code on the document…');
        const decoded = await seal.scanFile(new File([blob], 'receipt-qr.png', { type: 'image/png' }));
        demoCheck(runId);
        setScanStatus('QR code read from image');
        await handleQRResult(decoded);
        demoCheck(runId);
        demoFocus($('verify-results'));
        await demoSleep(900, runId);
        const verdict = $('verify-status').querySelector('.vs-title');
        return `${verdict ? verdict.textContent : 'Done'}: the signature is valid and the content is exactly as sealed.`;
      }
    },
    {
      title: 'Catch a forged printout',
      text: 'A forger prints a copy with the rent changed from 15000 to 75000 but keeps the original QR code. CyberSeal reads the paper with OCR and compares it with the signed text. The first run downloads the OCR model, so this can take a few seconds.',
      async run(runId) {
        if (!verifiedOriginalText || !lastSealedData) throw new Error('Run the verify step first.');
        const p = lastSealedData.payload;
        const forged = await demoForgedPrintout(p.i, p.d, p.t.replace('15000', '75000'));
        demoCheck(runId);
        ocrFile = forged;
        $('ocr-file-label').textContent = forged.name;
        ocrInput.closest('.file-drop').classList.add('has-file');
        ocrBtn.disabled = false;
        demoFocus($('ocr-section'));
        await demoSleep(600, runId);
        ocrBtn.click();
        await demoWaitFor(
          () => !ocrBtn.classList.contains('is-loading') && ($('ocr-diff-output').innerHTML.trim() || $('ocr-status').classList.contains('error')),
          runId,
          180000
        );
        if ($('ocr-status').classList.contains('error')) throw new Error($('ocr-status').textContent);
        const changed = $('ocr-diff-output').querySelector('.diff-changed-word');
        if (changed) {
          changed.scrollIntoView({ behavior: 'smooth', block: 'center' });
          changed.focus({ preventScroll: true }); // shows the "signed: …" tooltip
        }
        await demoSleep(900, runId);
        return $('ocr-diff-output').querySelector('.diff-summary.mismatch')
          ? 'Caught: the changed amount is highlighted. Hover over it to see the value that was actually signed.'
          : 'OCR finished. Check the comparison above.';
      }
    },
    {
      title: 'Catch a tampered QR code',
      text: 'A smarter forger edits the amount inside the QR code itself and keeps the old signature.',
      async run(runId) {
        if (!lastSealedData) throw new Error('Run the sealing step first.');
        const tampered = demoTamperQr(lastSealedData.qrData, '15000', '75000');
        const details = $('verify-panel').querySelector('.manual-entry');
        details.open = true;
        demoFocus(details);
        $('manual-qr-input').value = tampered;
        await demoSleep(900, runId);
        $('manual-verify-btn').click();
        await demoSleep(500, runId);
        demoFocus($('verify-results'));
        await demoSleep(900, runId);
        const verdict = $('verify-status').querySelector('.vs-title');
        return `${verdict ? verdict.textContent : 'Done'}: the signature no longer matches the content, so the edit is exposed.`;
      }
    },
    {
      title: "That's CyberSeal",
      text: 'A phishing scam caught, a document sealed, and both forgeries exposed, with no server and no data leaving the device. Exit the demo to try it yourself.'
    }
  ];

  function renderDemo(state, result) {
    const last = DEMO_STEPS.length - 1;
    const step = DEMO_STEPS[demo.step];
    $('demo-step-count').textContent = demo.step === 0 || demo.step === last ? 'Guided tour' : `Step ${demo.step} of ${last - 1}`;
    $('demo-progress-fill').style.width = `${(demo.step / last) * 100}%`;
    $('demo-title').textContent = step.title;
    $('demo-text').textContent = step.text;
    const resultEl = $('demo-result');
    resultEl.textContent = result || '';
    resultEl.classList.toggle('error', state === 'error');

    const next = $('demo-next');
    if (state === 'running') {
      next.disabled = true;
      next.innerHTML = '<span class="spinner" aria-hidden="true"></span>Running…';
    } else {
      next.disabled = false;
      next.innerHTML = demo.step === 0
        ? `Start tour${icon('arrow-right')}`
        : demo.step === last
          ? `Finish${icon('check')}`
          : `${state === 'error' ? 'Skip' : 'Next'}${icon('arrow-right')}`;
    }
  }

  async function runDemoStep(index) {
    demo.step = index;
    const runId = ++demo.runId;
    const step = DEMO_STEPS[index];
    if (!step.run) {
      demoFocus(null);
      renderDemo('done');
      return;
    }

    demo.running = true;
    renderDemo('running');
    try {
      const result = await step.run(runId);
      demoCheck(runId);
      demo.running = false;
      renderDemo('done', result);
      if ($('demo-autoplay').checked && index < DEMO_STEPS.length - 1) {
        await demoSleep(3000, runId);
        runDemoStep(index + 1);
      }
    } catch (err) {
      if (err instanceof DemoCancelled) return;
      console.error('[Demo] step failed:', err);
      demo.running = false;
      renderDemo('error', `${err && err.message ? err.message : 'This step failed.'} You can skip ahead.`);
    }
  }

  function startDemo() {
    if (demo.active) return;
    closeUserMenu();
    closeModal(authDialog);
    closeModal(deleteDialog);
    stopCameraIfRunning();
    demo.active = true;
    demo.running = false;
    demo.runId++;
    document.body.classList.add('demo-running');
    reveal($('demo-panel'));
    runDemoStep(0);
    $('demo-next').focus();
    warmUpOcr();
  }

  function exitDemo() {
    if (!demo.active) return;
    demo.active = false;
    demo.running = false;
    demo.runId++;
    demoFocus(null);
    document.body.classList.remove('demo-running');
    $('demo-panel').classList.add('hidden');

    // Leave the app the way the user had it.
    $('verify-results').classList.add('hidden');
    $('ocr-section').classList.add('hidden');
    verifiedOriginalText = null;
    resetOcr();
    $('manual-qr-input').value = '';
    $('verify-panel').querySelector('.manual-entry').open = false;
    setScanStatus('');
    ['doc-title', 'doc-text', 'doc-amount'].forEach((id) => { $(id).value = ''; });
    $('doc-char-count').textContent = '0';
    applyUser(auth.currentUser);
    $('demo-btn').focus();
  }

  $('demo-btn').addEventListener('click', startDemo);
  $('demo-exit').addEventListener('click', exitDemo);
  $('demo-next').addEventListener('click', () => {
    if (demo.running) return;
    if (demo.step >= DEMO_STEPS.length - 1) exitDemo();
    else runDemoStep(demo.step + 1);
  });
  $('demo-autoplay').addEventListener('change', () => {
    if ($('demo-autoplay').checked && demo.active && !demo.running && demo.step < DEMO_STEPS.length - 1) {
      runDemoStep(demo.step + 1);
    }
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && demo.active && !authDialog.open && !deleteDialog.open) exitDemo();
  });

  auth.onChange((user) => {
    if (!demo.active) applyUser(user);
  });
  applyUser(null);
  auth.restoreSession().then(() => {
    try {
      if (new URLSearchParams(location.search).get('demo') === '1') startDemo();
    } catch (err) { /* ignore malformed URL */ }
  });

  $('doc-text').addEventListener('input', () => {
    $('doc-char-count').textContent = $('doc-text').value.length.toLocaleString();
    $('doc-text').classList.remove('just-scanned');
  });

  // ----- scan an existing document into the seal form

  const PDFJS_URL = 'https://cdn.jsdelivr.net/npm/pdfjs-dist@3.11.174/build/pdf.min.js';
  const PDFJS_WORKER_URL = 'https://cdn.jsdelivr.net/npm/pdfjs-dist@3.11.174/build/pdf.worker.min.js';
  const MAX_PDF_PAGES = 5;

  function resetDocScan() {
    docScanToken++;
    $('doc-scan-input').value = '';
    $('doc-scan-label').textContent = 'Upload a photo, image or PDF';
    $('doc-scan-input').closest('.file-drop').classList.remove('has-file');
    $('doc-scan-status').innerHTML = '';
    $('doc-scan-status').className = 'ocr-status';
    $('doc-text').classList.remove('just-scanned');
  }

  function setDocScanStatus(html, kind) {
    const el = $('doc-scan-status');
    el.innerHTML = html;
    el.className = 'ocr-status' + (kind ? ' ' + kind : '');
  }

  function setDocScanProgress(label, fraction) {
    const pct = Math.round(Math.max(0, Math.min(1, fraction || 0)) * 100);
    setDocScanStatus(`${escapeHtml(label)} (${pct}%)<div class="progress"><div class="progress-fill" style="width:${pct}%"></div></div>`);
  }

  /** Loads pdf.js only when a PDF is actually chosen. */
  function loadPdfJs() {
    if (window.pdfjsLib) return Promise.resolve(window.pdfjsLib);
    if (!pdfjsLoading) {
      pdfjsLoading = new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = PDFJS_URL;
        script.onload = () => {
          if (!window.pdfjsLib) {
            reject(new Error('PDF library failed to initialise.'));
            return;
          }
          window.pdfjsLib.GlobalWorkerOptions.workerSrc = PDFJS_WORKER_URL;
          resolve(window.pdfjsLib);
        };
        script.onerror = () => {
          pdfjsLoading = null;
          reject(new Error('PDF library failed to load. Check your internet connection.'));
        };
        document.head.appendChild(script);
      });
    }
    return pdfjsLoading;
  }

  /** OCR one image/canvas. onProgress gets 0–1. */
  async function ocrImage(image, onProgress) {
    if (typeof Tesseract === 'undefined') {
      throw new Error('OCR library failed to load. Check your internet connection and reload.');
    }
    const worker = await Tesseract.createWorker('eng', 1, {
      logger: (m) => {
        if (m.status === 'recognizing text' && onProgress) onProgress(m.progress);
      }
    });
    try {
      const { data } = await worker.recognize(image);
      return { text: (data && data.text) || '', confidence: (data && data.confidence) || 0 };
    } finally {
      try { await worker.terminate(); } catch (e) { /* ignore */ }
    }
  }

  /** Photos are downscaled (speed) and small images upscaled (accuracy) before OCR. */
  async function prepareImageForOcr(file) {
    const img = await seal._loadImage(file);
    try {
      const longEdge = Math.max(img.width, img.height);
      const target = Math.max(1400, Math.min(longEdge, 2200));
      return seal._drawScaled(img, target);
    } finally {
      if (typeof img.close === 'function') img.close();
    }
  }

  async function extractPdfText(file, token) {
    const pdfjs = await loadPdfJs();
    const data = new Uint8Array(await file.arrayBuffer());
    const pdf = await pdfjs.getDocument({ data }).promise;
    const pageCount = Math.min(pdf.numPages, MAX_PDF_PAGES);
    const pages = [];
    let usedOcr = false;
    let confidenceSum = 0;

    for (let n = 1; n <= pageCount; n++) {
      if (token !== docScanToken) return null;
      setDocScanProgress(`Reading PDF page ${n} of ${pageCount}`, (n - 1) / pageCount);
      const page = await pdf.getPage(n);
      const content = await page.getTextContent();
      let text = content.items.map((item) => item.str + (item.hasEOL ? '\n' : ' ')).join('');

      // Scanned PDFs have no text layer — render the page and OCR it instead.
      if (text.replace(/\s/g, '').length < 20) {
        usedOcr = true;
        const viewport = page.getViewport({ scale: 2 });
        const canvas = document.createElement('canvas');
        canvas.width = Math.floor(viewport.width);
        canvas.height = Math.floor(viewport.height);
        await page.render({ canvasContext: canvas.getContext('2d'), viewport }).promise;
        const result = await ocrImage(canvas, (p) => setDocScanProgress(`Reading scanned page ${n} of ${pageCount} with OCR`, (n - 1 + p) / pageCount));
        text = result.text;
        confidenceSum += result.confidence;
      }
      pages.push(text);
    }

    return {
      text: pages.join('\n\n'),
      pages: pageCount,
      totalPages: pdf.numPages,
      usedOcr,
      confidence: usedOcr ? confidenceSum / pageCount : null
    };
  }

  function cleanScannedText(text) {
    return String(text || '')
      .replace(/\r\n?/g, '\n')
      .split('\n')
      .map((line) => line.replace(/[ \t]+/g, ' ').trim())
      .join('\n')
      .replace(/\n{3,}/g, '\n\n')
      .trim();
  }

  /** First short, wordy line looks like a title ("RENT RECEIPT"). */
  function guessTitle(text) {
    const line = text.split('\n').map((l) => l.trim()).find((l) => l.length >= 3);
    if (!line || line.length > 60) return '';
    const letters = (line.match(/[A-Za-z]/g) || []).length;
    return letters >= line.length * 0.6 ? line : '';
  }

  /** Finds a rupee amount, preferring lines that mention total / amount / received. */
  function guessAmount(text) {
    const pattern = /(?:₹|\brs\.?|\binr)\s*([\d,]+(?:\.\d{1,2})?)/gi;
    let fallback = '';
    for (const line of text.split('\n')) {
      pattern.lastIndex = 0;
      const m = pattern.exec(line);
      if (!m) continue;
      const value = m[1].replace(/,/g, '');
      if (!Number.isFinite(Number(value)) || Number(value) <= 0) continue;
      if (/total|amount|received|paid|sum/i.test(line)) return value;
      if (!fallback) fallback = value;
    }
    return fallback;
  }

  $('doc-scan-input').addEventListener('change', async () => {
    const input = $('doc-scan-input');
    const file = input.files && input.files[0];
    if (!file) return;

    const isPdf = file.type === 'application/pdf' || /\.pdf$/i.test(file.name);
    if (!isPdf && file.type && !/^image\//.test(file.type)) {
      setDocScanStatus('Please choose an image (JPG, PNG…) or a PDF.', 'error');
      input.value = '';
      return;
    }
    if (file.size > 25 * 1024 * 1024) {
      setDocScanStatus('That file is over 25 MB. Please use a smaller photo or PDF.', 'error');
      input.value = '';
      return;
    }

    const token = ++docScanToken;
    $('doc-scan-label').textContent = file.name;
    input.closest('.file-drop').classList.add('has-file');
    sealBtn.disabled = true;

    try {
      let result;
      if (isPdf) {
        setDocScanProgress('Loading PDF reader', 0);
        result = await extractPdfText(file, token);
      } else {
        setDocScanProgress('Loading OCR engine (the first run downloads the English language model)', 0);
        const canvas = await prepareImageForOcr(file);
        const ocr = await ocrImage(canvas, (p) => setDocScanProgress('Reading the document', p));
        result = { text: ocr.text, usedOcr: true, confidence: ocr.confidence };
      }
      if (!result || token !== docScanToken) return; // a newer scan or reset took over

      const text = cleanScannedText(result.text);
      if (text.length < 5) {
        setDocScanStatus(isPdf
          ? 'No readable text was found in this PDF.'
          : 'No text was found. Try a sharper, well-lit, straight-on photo.', 'error');
        return;
      }

      const docText = $('doc-text');
      docText.value = text;
      docText.dispatchEvent(new Event('input'));
      docText.classList.add('just-scanned');

      const filled = [];
      const title = guessTitle(text);
      if (title && !$('doc-title').value.trim()) {
        $('doc-title').value = title === title.toUpperCase()
          ? title.charAt(0) + title.slice(1).toLowerCase()
          : title;
        filled.push('title');
      }
      const amount = guessAmount(text);
      if (amount && !$('doc-amount').value.trim()) {
        $('doc-amount').value = amount;
        filled.push('amount');
      }

      const pageWord = result.pages === 1 ? 'page' : 'pages';
      const source = isPdf
        ? (result.usedOcr ? `scanned PDF (${result.pages} ${pageWord}, using OCR)` : `PDF (${result.pages} ${pageWord})`)
        : 'photo (using OCR)';
      const confidence = result.confidence !== null && result.confidence !== undefined
        ? ` · OCR confidence ${Math.round(result.confidence)}%` : '';
      const more = isPdf && result.totalPages > result.pages ? ` · only the first ${result.pages} of ${result.totalPages} pages were read` : '';
      const autofill = filled.length ? ` · filled in ${filled.join(' and ')}` : '';
      setDocScanStatus(
        `${icon('check-circle')}Read ${text.length.toLocaleString()} characters from the ${escapeHtml(source)}${confidence}${more}${autofill}.<br>`
          + '<strong>Review and correct the text below before sealing.</strong> Whatever is in the box is exactly what gets signed.',
        'success'
      );
      docText.focus();
      docText.setSelectionRange(0, 0);
      docText.scrollTop = 0;
    } catch (err) {
      if (token !== docScanToken) return;
      console.error(err);
      const message = err && err.name === 'PasswordException'
        ? 'This PDF is password-protected. Remove the password and try again.'
        : (err && err.message ? err.message : 'Could not read this document.');
      setDocScanStatus(escapeHtml(message), 'error');
    } finally {
      if (token === docScanToken) {
        sealBtn.disabled = !seal.fingerprint;
        input.value = ''; // allow re-selecting the same file
      }
    }
  });

  sealBtn.addEventListener('click', async () => {
    const issuer = $('issuer-name').value.trim();
    const title = $('doc-title').value.trim();
    const text = $('doc-text').value;
    const amountRaw = $('doc-amount').value.trim();

    if (!text.trim()) {
      toast('Enter the document text to seal.');
      $('doc-text').focus();
      return;
    }
    if (amountRaw && (!Number.isFinite(Number(amountRaw)) || Number(amountRaw) < 0)) {
      toast('Amount must be a positive number.');
      $('doc-amount').focus();
      return;
    }
    if (typeof QRCode === 'undefined') {
      toast('QR library failed to load. Check your connection and reload.');
      return;
    }

    setBusy(sealBtn, true, 'Sealing…');
    try {
      const result = await seal.sealDocument(text, issuer, title, amountRaw);
      lastSealedData = result;
      await renderSealedDocument(result);
      toast('Document sealed. Print it or download the QR.');
    } catch (err) {
      console.error(err);
      toast(err && err.message ? err.message : 'Sealing failed.');
    } finally {
      setBusy(sealBtn, false);
    }
  });

  function sealedDocumentHtml(payload, fingerprint) {
    const amount = formatAmount(payload.a);
    return `
      <div class="sealed-document" id="sealed-doc-page">
        <div class="sd-header">
          <div class="sd-issuer">${escapeHtml(payload.i)}</div>
          <div class="sd-meta">Issued ${escapeHtml(formatDate(payload.ts))}<br>Key: <span class="sd-fp">${escapeHtml(fingerprint)}</span></div>
        </div>
        <h2 class="sd-title">${escapeHtml(payload.d)}</h2>
        <div class="sd-body">${escapeHtml(payload.t)}</div>
        ${amount ? `<div class="sd-amount"><span>Amount</span><strong>${escapeHtml(amount)}</strong></div>` : ''}
        <div class="sd-footer">
          <div class="sd-qr"><canvas id="sealed-qr-canvas" aria-label="KaagazSeal verification QR code"></canvas></div>
          <div class="sd-seal-info">
            <strong><svg class="sd-seal-mark" viewBox="0 0 24 24" fill="none" stroke="#1F1A16" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>Digitally sealed with KaagazSeal</strong>
            This document carries an ECDSA P-256 digital signature. Scan the QR code with CyberSeal → Verify to confirm the text has not been altered.<br>
            Signing key fingerprint: <b class="sd-fp">${escapeHtml(fingerprint)}</b>
          </div>
        </div>
      </div>`;
  }

  async function renderSealedDocument(result) {
    const holder = $('sealed-doc');
    holder.innerHTML = sealedDocumentHtml(result.payload, result.fingerprint);

    const canvas = $('sealed-qr-canvas');
    await QRCode.toCanvas(canvas, result.qrData, {
      errorCorrectionLevel: 'L',
      margin: 4,
      width: 480,
      color: { dark: '#000000', light: '#FFFFFF' }
    });

    const warning = $('seal-warning');
    if (result.warning) {
      warning.innerHTML = `${icon('alert')}<span>${escapeHtml(result.warning)}</span>`;
      warning.classList.remove('hidden');
    } else {
      warning.classList.add('hidden');
    }

    $('download-btn').classList.remove('hidden');
    $('download-qr-btn').classList.remove('hidden');
    const output = $('sealed-output');
    reveal(output);
    scrollIntoViewIfNeeded(output);
  }

  // ----- print

  const PRINT_CSS = `
    @page { margin: 18mm; }
    * { box-sizing: border-box; }
    body { margin: 0; background: #fff; color: #1F1A16; font-family: Georgia, 'Times New Roman', serif; }
    .sealed-document { max-width: 760px; margin: 0 auto; }
    .sd-header { display: flex; justify-content: space-between; gap: 1rem; padding-bottom: 0.85rem; border-bottom: 2px solid #1F1A16; margin-bottom: 1.5rem; }
    .sd-issuer { font-size: 1.3rem; font-weight: 700; }
    .sd-meta { font-size: 0.8rem; color: #5A5048; text-align: right; line-height: 1.5; }
    .sd-title { font-size: 1.45rem; text-align: center; text-transform: uppercase; letter-spacing: 0.08em; margin: 0 0 1.5rem; }
    .sd-body { font-size: 1.05rem; line-height: 1.75; white-space: pre-wrap; word-wrap: break-word; margin-bottom: 1.5rem; }
    .sd-amount { display: flex; justify-content: space-between; padding: 0.75rem 1rem; border: 1px solid #1F1A16; margin-bottom: 1.75rem; font-size: 1.05rem; }
    .sd-footer { display: flex; align-items: center; gap: 1.5rem; padding-top: 1.25rem; border-top: 1px dashed #8C8178; page-break-inside: avoid; }
    .sd-qr img { width: 62mm; height: 62mm; image-rendering: pixelated; }
    .sd-seal-info { font-size: 0.82rem; color: #4A423B; line-height: 1.55; font-family: 'Segoe UI', system-ui, sans-serif; }
    .sd-seal-info strong { display: flex; align-items: center; gap: 0.4rem; font-size: 0.95rem; color: #1F1A16; margin-bottom: 0.25rem; }
    .sd-seal-mark { width: 18px; height: 18px; }
    .sd-fp { font-family: ui-monospace, Consolas, monospace; font-size: 0.92em; }
  `;

  $('print-btn').addEventListener('click', () => {
    if (!lastSealedData) {
      toast('Seal a document first.');
      return;
    }
    const canvas = $('sealed-qr-canvas');
    let qrUrl = '';
    try {
      qrUrl = canvas ? canvas.toDataURL('image/png') : '';
    } catch (err) {
      qrUrl = '';
    }

    const docHtml = sealedDocumentHtml(lastSealedData.payload, lastSealedData.fingerprint)
      .replace(/<canvas[^>]*><\/canvas>/, `<img src="${qrUrl}" alt="Verification QR code">`);

    const win = window.open('', '_blank', 'width=900,height=1000');
    if (!win) {
      // Pop-up blocked: fall back to printing this page (print CSS isolates the document).
      window.print();
      return;
    }

    win.document.open();
    win.document.write(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>${escapeHtml(lastSealedData.payload.d)}</title><style>${PRINT_CSS}</style></head><body>${docHtml}</body></html>`);
    win.document.close();

    const doPrint = () => {
      try {
        win.focus();
        win.print();
      } catch (err) {
        console.error(err);
      }
    };
    const img = win.document.querySelector('img');
    if (img && !img.complete) {
      img.onload = doPrint;
      img.onerror = doPrint;
    } else {
      setTimeout(doPrint, 150);
    }
  });

  // ----- downloads

  $('download-btn').addEventListener('click', () => {
    if (!lastSealedData) return;
    const name = `kaagazseal-${slugify(lastSealedData.payload.d)}-${lastSealedData.payload.ts.slice(0, 10)}.json`;
    downloadBlob(new Blob([lastSealedData.qrData], { type: 'application/json' }), name);
    toast('Seal data downloaded. Paste it into Verify to check it later.');
  });

  $('download-qr-btn').addEventListener('click', async () => {
    if (!lastSealedData) return;
    try {
      const dataUrl = await QRCode.toDataURL(lastSealedData.qrData, {
        errorCorrectionLevel: 'L',
        margin: 4,
        width: 1024,
        color: { dark: '#000000', light: '#FFFFFF' }
      });
      const blob = await (await fetch(dataUrl)).blob();
      downloadBlob(blob, `kaagazseal-${slugify(lastSealedData.payload.d)}-qr.png`);
    } catch (err) {
      console.error(err);
      toast('Could not create the QR image.');
    }
  });

  // =============================================================== VERIFY

  const scanBtn = $('scan-btn');
  const fileInput = $('file-input');

  function setScanStatus(message, isError) {
    const el = $('scan-status');
    el.textContent = message || '';
    el.classList.toggle('error', !!isError);
  }

  function updateScanButton() {
    scanBtn.classList.toggle('is-active', isScanning);
    scanBtn.innerHTML = isScanning
      ? `<span class="option-icon">${icon('stop')}</span><span class="option-text"><strong>Stop camera</strong><small>Scanning… hold the QR code steady</small></span>`
      : `<span class="option-icon">${icon('camera')}</span><span class="option-text"><strong>Scan with camera</strong><small>Point your camera at the QR code</small></span>`;
  }

  scanBtn.addEventListener('click', async () => {
    if (isScanning) {
      await stopCameraIfRunning();
      return;
    }

    scanBtn.disabled = true;
    setScanStatus('Starting camera…');
    const started = await seal.startScanner(
      'qr-reader',
      (decodedText) => {
        isScanning = false;
        updateScanButton();
        setScanStatus('QR code captured');
        handleQRResult(decodedText);
      },
      (message) => setScanStatus(message, true)
    );
    scanBtn.disabled = false;
    isScanning = started;
    updateScanButton();
    if (started) setScanStatus('Point the camera at the QR code on the document. Hold steady and fill the frame.');
  });

  fileInput.addEventListener('change', async () => {
    const file = fileInput.files && fileInput.files[0];
    if (!file) return;
    if (isScanning) await stopCameraIfRunning();
    setScanStatus('Reading QR code from image…');
    try {
      const decoded = await seal.scanFile(file);
      setScanStatus('QR code read from image');
      await handleQRResult(decoded);
    } catch (err) {
      setScanStatus(err && err.message ? err.message : 'Could not read a QR code from this image.', true);
    } finally {
      fileInput.value = ''; // allow choosing the same file again
    }
  });

  // The upload "button" is a <label>; make it keyboard-operable too.
  const fileLabel = document.querySelector('label[for="file-input"]');
  if (fileLabel) {
    fileLabel.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        fileInput.click();
      }
    });
  }

  $('manual-verify-btn').addEventListener('click', () => {
    const data = $('manual-qr-input').value.trim();
    if (!data) {
      toast('Paste the QR data first.');
      $('manual-qr-input').focus();
      return;
    }
    handleQRResult(data);
  });

  async function handleQRResult(data) {
    let result;
    try {
      result = await seal.verifyQRData(data);
    } catch (err) {
      console.error(err);
      result = { valid: false, error: 'FAKE_QR', message: 'Invalid or corrupted QR code' };
    }

    verifiedOriginalText = null;
    resetOcr();
    $('ocr-section').classList.add('hidden');

    const statusEl = $('verify-status');
    const detailsEl = $('verify-details');
    const textEl = $('diff-output');

    let state;
    if (result.valid) {
      state = {
        cls: 'verified',
        icon: 'check-circle',
        title: 'VERIFIED',
        desc: 'The signature is valid. The content below is exactly what was sealed.'
          + (result.signedByThisDevice ? ' It was sealed with your account\'s key.' : '')
      };
    } else if (result.error === 'TAMPERED') {
      state = { cls: 'tampered', icon: 'alert', title: 'TAMPERED', desc: result.message };
    } else {
      state = { cls: 'fake', icon: 'x-circle', title: 'FAKE / INVALID SEAL', desc: result.message || 'Invalid or corrupted QR code' };
    }

    statusEl.innerHTML = `
      <div class="verify-status ${state.cls}">
        <div class="vs-icon" aria-hidden="true">${icon(state.icon)}</div>
        <div>
          <div class="vs-title">${state.title}</div>
          <div class="vs-desc">${escapeHtml(state.desc)}</div>
        </div>
      </div>`;

    if (result.payload) {
      const p = result.payload;
      const amount = formatAmount(p.amount);
      detailsEl.innerHTML = `
        <table class="details-table">
          <tbody>
            <tr><th>Issuer</th><td>${escapeHtml(p.issuer)}</td></tr>
            <tr><th>Document</th><td>${escapeHtml(p.title)}</td></tr>
            ${amount ? `<tr><th>Amount</th><td>${escapeHtml(amount)}</td></tr>` : ''}
            <tr><th>Sealed on</th><td>${escapeHtml(formatDate(p.timestamp))}</td></tr>
            <tr><th>Key fingerprint</th><td><span class="fingerprint">${escapeHtml(result.fingerprint || 'Unknown')}</span></td></tr>
            <tr><th>Signature</th><td>${result.valid
              ? `<span class="sig-valid">${icon('check-circle')}Valid</span> · ECDSA P-256 / SHA-256`
              : `<span class="sig-invalid">${icon('x-circle')}Does not match the content</span>`}</td></tr>
          </tbody>
        </table>
        ${result.valid ? `<p class="trust-note">${icon('info')}<span>The signature proves the text hasn't changed since sealing. To confirm <em>who</em> sealed it, check that this fingerprint matches the one the issuer publishes.</span></p>` : ''}`;

      textEl.innerHTML = `
        <div class="original-text-label">${result.valid ? `${icon('file-text')}Signed original text` : `${icon('alert')}Text claimed by the QR (not trustworthy)`}</div>
        <div class="original-text">${escapeHtml(p.text)}</div>`;
    } else {
      detailsEl.innerHTML = '';
      textEl.innerHTML = '';
    }

    const container = $('verify-results');
    reveal(container);

    if (result.valid) {
      verifiedOriginalText = result.payload.text;
      reveal($('ocr-section'));
    }
    scrollIntoViewIfNeeded(container);
  }

  // ================================================================== OCR

  const ocrInput = $('ocr-file-input');
  const ocrBtn = $('ocr-btn');

  function resetOcr() {
    ocrFile = null;
    ocrInput.value = '';
    ocrBtn.disabled = true;
    $('ocr-file-label').textContent = 'Choose a photo of the printed document';
    ocrInput.closest('.file-drop').classList.remove('has-file');
    $('ocr-status').innerHTML = '';
    $('ocr-status').classList.remove('error');
    $('ocr-diff-output').innerHTML = '';
  }

  ocrInput.addEventListener('change', () => {
    const file = ocrInput.files && ocrInput.files[0];
    if (!file) return;
    if (file.type && !/^image\//.test(file.type)) {
      toast('Please choose an image file.');
      ocrInput.value = '';
      return;
    }
    ocrFile = file;
    $('ocr-file-label').textContent = file.name;
    ocrInput.closest('.file-drop').classList.add('has-file');
    ocrBtn.disabled = false;
  });

  function setOcrProgress(label, fraction) {
    const pct = Math.round(Math.max(0, Math.min(1, fraction || 0)) * 100);
    $('ocr-status').classList.remove('error');
    $('ocr-status').innerHTML = `${escapeHtml(label)}${fraction !== null ? ` (${pct}%)` : ''}
      <div class="progress"><div class="progress-fill" style="width:${pct}%"></div></div>`;
  }

  ocrBtn.addEventListener('click', async () => {
    if (!verifiedOriginalText) {
      toast('Verify a sealed document first.');
      return;
    }
    if (!ocrFile) {
      toast('Choose a photo of the printed document.');
      return;
    }
    if (typeof Tesseract === 'undefined') {
      $('ocr-status').textContent = 'OCR library failed to load. Check your internet connection and reload.';
      $('ocr-status').classList.add('error');
      return;
    }

    setBusy(ocrBtn, true, 'Reading document…');
    $('ocr-diff-output').innerHTML = '';
    setOcrProgress('Loading OCR engine (the first run downloads the English language model)', 0);

    let worker = null;
    try {
      worker = await Tesseract.createWorker('eng', 1, {
        logger: (m) => {
          if (m.status === 'recognizing text') setOcrProgress('Recognizing text', m.progress);
          else if (m.status && typeof m.progress === 'number') setOcrProgress(m.status.charAt(0).toUpperCase() + m.status.slice(1), m.progress);
        }
      });
      const { data } = await worker.recognize(ocrFile);
      const ocrText = (data && data.text ? data.text : '').trim();

      if (!ocrText) {
        $('ocr-status').textContent = 'No text was found in the photo. Try a sharper, well-lit, straight-on picture.';
        $('ocr-status').classList.add('error');
        return;
      }

      const body = seal.extractBodyFromOcr(ocrText, verifiedOriginalText);
      const diff = seal.compareTexts(verifiedOriginalText, body);
      $('ocr-status').textContent = `OCR complete · confidence ${Math.round(data.confidence || 0)}%`;

      const summary = diff.changed
        ? `<div class="diff-summary mismatch">${icon('x-circle')}<span>${diff.changeCount} difference${diff.changeCount === 1 ? '' : 's'} between the printed text and the signed original. Hover or tap highlighted words to see what was signed.</span></div>`
        : `<div class="diff-summary match">${icon('check-circle')}<span>The printed text matches the signed original.</span></div>`;

      $('ocr-diff-output').innerHTML = `
        ${summary}
        <div class="diff-text">${diff.html}</div>
        <div class="diff-legend">
          <span><span class="diff-changed-word" style="cursor:default">word</span> changed</span>
          <span><span class="diff-removed">gone</span> missing from print</span>
          <span><span class="diff-added">extra</span> not in signed text</span>
        </div>
        <p class="hint">OCR can misread blurry or stylized text. Check any highlighted word against the paper before concluding it was forged.</p>
        <details class="ocr-raw">
          <summary>Show raw OCR text</summary>
          <pre>${escapeHtml(ocrText)}</pre>
        </details>`;
      reveal($('ocr-diff-output'));
    } catch (err) {
      console.error(err);
      $('ocr-status').textContent = 'OCR failed: ' + (err && err.message ? err.message : 'unknown error') + '. Check your connection and try again.';
      $('ocr-status').classList.add('error');
    } finally {
      if (worker) {
        try { await worker.terminate(); } catch (e) { /* ignore */ }
      }
      setBusy(ocrBtn, false);
    }
  });

  // Release the camera if the page is hidden or closed.
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) stopCameraIfRunning();
  });
  window.addEventListener('pagehide', () => {
    if (isScanning) seal.stopScanner();
  });
});
