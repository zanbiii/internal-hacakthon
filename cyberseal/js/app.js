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
  let verifiedOriginalText = null;
  let isScanning = false;
  let lastSealedData = null;
  let ocrFile = null;
  let toastTimer = null;

  // ---------------------------------------------------------------- helpers

  function checkLibraries() {
    const missing = [];
    if (typeof pako === 'undefined') missing.push('pako (compression)');
    if (typeof Diff === 'undefined') missing.push('jsdiff (text comparison)');
    if (typeof QRCode === 'undefined') missing.push('qrcode (QR generation)');
    if (typeof Html5Qrcode === 'undefined') missing.push('html5-qrcode (QR scanning)');
    if (typeof Tesseract === 'undefined') missing.push('tesseract.js (OCR)');
    if (missing.length) {
      const banner = $('lib-warning');
      banner.textContent = `⚠️ Some libraries failed to load: ${missing.join(', ')}. Threat detection still works; related KaagazSeal features need an internet connection. Reload to retry.`;
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
      if (busyLabel) button.textContent = busyLabel;
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

  threatType.addEventListener('change', () => {
    threatInput.placeholder = threatType.value === 'url'
      ? 'Paste a URL to analyze, e.g. https://example.com/login'
      : 'Paste a suspicious SMS, email or chat message...';
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

  function renderThreatResult(result) {
    const levelEl = $('risk-level');
    const fill = $('risk-score-fill');
    const bar = $('risk-score-bar');

    levelEl.className = '';
    levelEl.classList.add(result.levelClass);
    levelEl.textContent = result.level;
    $('risk-score-text').textContent = `Risk score: ${result.score} / 100`;
    bar.setAttribute('aria-valuenow', String(result.score));

    // Animate from zero each time.
    fill.style.transition = 'none';
    fill.style.width = '0%';
    fill.className = 'fill-' + result.levelClass.replace('risk-', '');
    void fill.offsetWidth;
    fill.style.transition = '';
    requestAnimationFrame(() => {
      fill.style.width = Math.max(result.score, 2) + '%';
    });

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
    keyStatus.className = 'key-status ready';
    keyStatus.innerHTML = `✅ Signing key ready · Fingerprint <span class="fingerprint">${escapeHtml(seal.fingerprint)}</span>`
      + (seal.keyPersisted ? '' : ' · <span title="This browser blocked key storage, so a new key is created each visit.">session-only key</span>');
    sealBtn.disabled = false;
  }

  function showKeyError(message) {
    keyStatus.className = 'key-status error';
    keyStatus.textContent = '❌ ' + (message || 'Could not create a signing key.');
    sealBtn.disabled = true;
  }

  document.addEventListener('keysReady', showKeyReady);
  document.addEventListener('keysError', (e) => showKeyError(e.detail && e.detail.message));
  // In case the key was ready before the listeners were attached.
  seal.ready.then((ok) => {
    if (ok) showKeyReady();
    else showKeyError(seal.initError && seal.initError.message);
  });

  $('doc-text').addEventListener('input', () => {
    $('doc-char-count').textContent = $('doc-text').value.length.toLocaleString();
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

    setBusy(sealBtn, true, '⏳ Sealing…');
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
            <strong>🔏 Digitally sealed with KaagazSeal</strong>
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
      warning.textContent = '⚠️ ' + result.warning;
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
    .sd-seal-info strong { display: block; font-size: 0.95rem; color: #1F1A16; margin-bottom: 0.25rem; }
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
    scanBtn.textContent = isScanning ? '⏹️ Stop Camera' : '📷 Start Camera Scan';
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
        setScanStatus('✅ QR code captured');
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
      setScanStatus('✅ QR code read from image');
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
        icon: '✅',
        title: 'VERIFIED',
        desc: 'The signature is valid. The content below is exactly what was sealed.'
          + (result.signedByThisDevice ? ' It was sealed on this device.' : '')
      };
    } else if (result.error === 'TAMPERED') {
      state = { cls: 'tampered', icon: '⚠️', title: 'TAMPERED', desc: result.message };
    } else {
      state = { cls: 'fake', icon: '❌', title: 'FAKE / INVALID SEAL', desc: result.message || 'Invalid or corrupted QR code' };
    }

    statusEl.innerHTML = `
      <div class="verify-status ${state.cls}">
        <div class="vs-icon" aria-hidden="true">${state.icon}</div>
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
            <tr><th>Signature</th><td>${result.valid ? '✅ Valid (ECDSA P-256 / SHA-256)' : '❌ Does not match content'}</td></tr>
          </tbody>
        </table>
        ${result.valid ? `<p class="hint" style="margin:-0.5rem 0 1.25rem">The signature proves the text hasn't changed since sealing. To confirm <em>who</em> sealed it, check that this fingerprint matches the one the issuer publishes.</p>` : ''}`;

      textEl.innerHTML = `
        <div class="original-text-label">${result.valid ? '📜 Signed original text' : '⚠️ Text claimed by the QR (not trustworthy)'}</div>
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
    $('ocr-file-label').textContent = '📄 Choose a photo of the printed document';
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
    $('ocr-file-label').textContent = `📄 ${file.name}`;
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

    setBusy(ocrBtn, true, '⏳ Reading document…');
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
        ? `<div class="diff-summary mismatch">❌ ${diff.changeCount} difference${diff.changeCount === 1 ? '' : 's'} between the printed text and the signed original. Hover or tap highlighted words to see what was signed.</div>`
        : '<div class="diff-summary match">✅ The printed text matches the signed original.</div>';

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
