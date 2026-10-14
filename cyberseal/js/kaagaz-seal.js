/**
 * CyberSeal — KaagazSeal
 * Tamper-evident documents: ECDSA P-256 signatures + deflate-compressed payloads in a QR code.
 * Exposes window.KaagazSeal.
 *
 * QR format (JSON):
 *   { v: 1, p: base64(deflate(payloadJson)), s: base64(signature), k: publicKeyJwk }
 * payloadJson = { t: text, i: issuer, d: title, a: amount, ts: ISO timestamp }
 * The signature covers the exact UTF-8 bytes of payloadJson, so verification needs no re-serialization.
 */
(function () {
  'use strict';

  const ECDSA_PARAMS = { name: 'ECDSA', namedCurve: 'P-256' };
  const SIGN_PARAMS = { name: 'ECDSA', hash: { name: 'SHA-256' } };

  // QR version 40 at error-correction level L holds 2953 bytes; keep headroom.
  const MAX_QR_CHARS = 2800;

  const DB_NAME = 'cyberseal';
  const DB_STORE = 'keys';
  const KEY_ID = 'issuer-signing-key-v1';

  class KaagazSeal {
    constructor() {
      this.keyPair = null;
      this.publicKeyJwk = null;
      this.fingerprint = null;
      this.keyPersisted = false;
      this.initError = null;
      this.identityId = null;
      this.scanner = null;
      this.scanning = false;
      this.fileReaderElementId = 'qr-file-reader';
      this._identityToken = 0;
      this.ready = Promise.resolve(false);
    }

    /**
     * Loads the signing key for an account (or creates one on first use).
     * Each account has its own key; the private key is non-extractable, so it can sign but never be read out.
     * Resolves true when the key is ready.
     */
    useIdentity(identityId) {
      const token = ++this._identityToken;
      this.ready = this.init(identityId, token);
      return this.ready;
    }

    /** Forgets the active key (on log-out). */
    clearIdentity() {
      this._identityToken++;
      this.keyPair = null;
      this.publicKeyJwk = null;
      this.fingerprint = null;
      this.identityId = null;
      this.initError = null;
      this.ready = Promise.resolve(false);
      document.dispatchEvent(new CustomEvent('keysCleared'));
    }

    /** Permanently removes an account's signing key (on account deletion). */
    async deleteIdentityKey(identityId) {
      let db;
      try {
        db = await this._openDb();
        await new Promise((resolve, reject) => {
          const tx = db.transaction(DB_STORE, 'readwrite');
          tx.objectStore(DB_STORE).delete(this._keyId(identityId));
          tx.oncomplete = () => resolve();
          tx.onerror = () => reject(tx.error);
        });
      } catch (err) {
        console.warn('[KaagazSeal] could not delete key:', err);
      } finally {
        if (db) db.close();
      }
    }

    async init(identityId, token) {
      const stale = () => token !== this._identityToken;
      try {
        if (!identityId) throw new Error('Sign in to create a signing key.');
        if (!window.crypto || !window.crypto.subtle) {
          throw new Error('Web Crypto is unavailable. Open the app over HTTPS or on localhost.');
        }

        let persisted = false;
        let pair = await this._loadKeyPair(identityId);
        if (pair) {
          persisted = true;
        } else {
          pair = await crypto.subtle.generateKey(ECDSA_PARAMS, false, ['sign', 'verify']);
          persisted = await this._saveKeyPair(identityId, pair);
        }

        const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
        const publicKeyJwk = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
        const fingerprint = await this._fingerprint(publicKeyJwk);
        if (stale()) return false; // user switched accounts meanwhile

        this.identityId = identityId;
        this.keyPair = pair;
        this.keyPersisted = persisted;
        this.publicKeyJwk = publicKeyJwk;
        this.fingerprint = fingerprint;
        this.initError = null;

        document.dispatchEvent(new CustomEvent('keysReady', {
          detail: { fingerprint: this.fingerprint, persisted: this.keyPersisted }
        }));
        return true;
      } catch (err) {
        if (stale()) return false;
        console.error('[KaagazSeal] key initialisation failed:', err);
        this.initError = err;
        document.dispatchEvent(new CustomEvent('keysError', {
          detail: { message: err && err.message ? err.message : 'Could not create a signing key.' }
        }));
        return false;
      }
    }

    /**
     * Signs the document and packs it into a QR-ready string.
     * Text that would overflow a single QR code is trimmed (and the trimmed version is what gets signed).
     */
    async sealDocument(text, issuer, title, amount) {
      const ok = await this.ready;
      if (!ok || !this.keyPair) {
        throw new Error(this.initError ? this.initError.message : 'Signing key is not ready yet.');
      }
      if (typeof pako === 'undefined') {
        throw new Error('Compression library (pako) failed to load. Check your internet connection and reload.');
      }

      const original = String(text || '').replace(/\r\n?/g, '\n').trim();
      if (!original) throw new Error('Document text is required.');

      const cleanIssuer = String(issuer || '').trim() || 'Unknown';
      const cleanTitle = String(title || '').trim() || 'Document';
      const cleanAmount = amount === null || amount === undefined || amount === '' ? '' : String(amount).trim();
      const timestamp = new Date().toISOString();

      let keepLength = original.length;
      let warning = null;

      for (let attempt = 0; attempt < 15; attempt++) {
        const truncated = keepLength < original.length;
        const body = truncated ? original.slice(0, keepLength).trimEnd() + '…' : original;

        const payload = { t: body, i: cleanIssuer, d: cleanTitle, a: cleanAmount, ts: timestamp };
        const payloadBytes = new TextEncoder().encode(JSON.stringify(payload));
        const signature = await crypto.subtle.sign(SIGN_PARAMS, this.keyPair.privateKey, payloadBytes);
        const compressed = pako.deflate(payloadBytes, { level: 9 });

        const qrObject = {
          v: 1,
          p: this._uint8ToBase64(compressed),
          s: this._arrayBufferToBase64(signature),
          k: this.publicKeyJwk
        };
        const qrData = JSON.stringify(qrObject);

        if (qrData.length <= MAX_QR_CHARS) {
          if (truncated) {
            warning = `The document was too long for one QR code, so only the first ${keepLength.toLocaleString()} of ${original.length.toLocaleString()} characters were sealed. Shorten the text to seal it in full.`;
          }
          return {
            qrData,
            payload,
            signature: qrObject.s,
            fingerprint: this.fingerprint,
            truncated,
            warning
          };
        }

        // Shrink proportionally to the overflow, with a margin because compression isn't linear.
        const ratio = MAX_QR_CHARS / qrData.length;
        const next = Math.floor(keepLength * ratio * 0.92);
        keepLength = Math.max(0, Math.min(next, keepLength - 20));
        if (keepLength <= 0) break;
      }

      throw new Error('The issuer name or title is too long to fit in a QR code. Please shorten them.');
    }

    /**
     * Returns
     *   { valid: true,  payload, fingerprint, signedByThisDevice }
     *   { valid: false, error: 'TAMPERED', message, payload, fingerprint }
     *   { valid: false, error: 'FAKE_QR', message }
     */
    async verifyQRData(qrDataString) {
      const fake = (message) => ({
        valid: false,
        error: 'FAKE_QR',
        message: message || 'Invalid or corrupted QR code'
      });

      try {
        if (!window.crypto || !window.crypto.subtle) {
          return fake('Web Crypto is unavailable. Open the app over HTTPS or on localhost to verify.');
        }
        if (typeof pako === 'undefined') {
          return fake('Compression library (pako) failed to load. Check your internet connection and reload.');
        }

        let obj;
        try {
          obj = JSON.parse(String(qrDataString || '').trim());
        } catch (err) {
          return fake("This QR code doesn't contain KaagazSeal data. It may be a regular QR code or a forgery.");
        }

        const hasFields = obj && typeof obj === 'object'
          && typeof obj.p === 'string' && typeof obj.s === 'string'
          && obj.k && typeof obj.k === 'object'
          && typeof obj.k.x === 'string' && typeof obj.k.y === 'string';
        if (!hasFields) {
          return fake('The QR code is missing required seal fields (payload, signature or key).');
        }

        let payloadBytes;
        let raw;
        try {
          payloadBytes = pako.inflate(this._base64ToUint8(obj.p));
          raw = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(payloadBytes));
        } catch (err) {
          return fake('The sealed payload is corrupted and could not be decoded.');
        }
        if (!raw || typeof raw.t !== 'string') {
          return fake('The sealed payload has an unexpected format.');
        }

        const payload = {
          text: raw.t,
          issuer: typeof raw.i === 'string' ? raw.i : 'Unknown',
          title: typeof raw.d === 'string' ? raw.d : 'Document',
          amount: raw.a === undefined || raw.a === null ? '' : String(raw.a),
          timestamp: typeof raw.ts === 'string' ? raw.ts : ''
        };

        const jwk = { kty: 'EC', crv: 'P-256', x: obj.k.x, y: obj.k.y, ext: true };
        let publicKey;
        try {
          publicKey = await crypto.subtle.importKey('jwk', jwk, ECDSA_PARAMS, false, ['verify']);
        } catch (err) {
          return fake('The public key inside the QR code is invalid.');
        }

        let valid = false;
        try {
          valid = await crypto.subtle.verify(SIGN_PARAMS, publicKey, this._base64ToUint8(obj.s), payloadBytes);
        } catch (err) {
          valid = false;
        }

        const fingerprint = await this._fingerprint(jwk);

        if (!valid) {
          return {
            valid: false,
            error: 'TAMPERED',
            message: "The signature doesn't match the content. This document was altered after it was sealed.",
            payload,
            fingerprint
          };
        }

        return {
          valid: true,
          payload,
          fingerprint,
          signedByThisDevice: !!this.fingerprint && fingerprint === this.fingerprint
        };
      } catch (err) {
        console.error('[KaagazSeal] verification failed:', err);
        return fake();
      }
    }

    /**
     * Word-level diff between the signed original and another text (e.g. OCR output).
     * Substitutions get a hover tooltip showing the signed word.
     */
    compareTexts(original, current) {
      if (typeof Diff === 'undefined' || typeof Diff.diffWords !== 'function') {
        throw new Error('Diff library failed to load. Check your internet connection and reload.');
      }

      const a = this._normalizeForDiff(original);
      const b = this._normalizeForDiff(current);
      const parts = Diff.diffWords(a, b);
      const changes = [];
      let html = '';

      const wrap = (value, render) => {
        // Keep surrounding whitespace outside the highlight so spacing reads naturally.
        const lead = value.match(/^\s*/)[0];
        const trail = value.slice(lead.length).match(/\s*$/)[0];
        const core = value.slice(lead.length, value.length - trail.length);
        return core ? lead + render(core) + trail : value;
      };

      for (let i = 0; i < parts.length; i++) {
        const part = parts[i];
        const next = parts[i + 1];

        if (!part.added && !part.removed) {
          html += this._escapeHtml(part.value);
          continue;
        }

        const isPair = next && ((part.removed && next.added) || (part.added && next.removed));
        if (isPair) {
          const removed = part.removed ? part.value : next.value;
          const added = part.added ? part.value : next.value;
          html += wrap(added, (core) =>
            `<span class="diff-changed-word" tabindex="0" data-original="${this._escapeHtml('signed: ' + removed.trim())}">${this._escapeHtml(core)}</span>`
          );
          changes.push({ type: 'changed', original: removed.trim(), current: added.trim() });
          i++;
          continue;
        }

        if (part.removed) {
          html += wrap(part.value, (core) => `<span class="diff-removed">[removed: ${this._escapeHtml(core)}]</span>`);
          changes.push({ type: 'removed', original: part.value.trim(), current: '' });
        } else {
          html += wrap(part.value, (core) => `<span class="diff-added">[added: ${this._escapeHtml(core)}]</span>`);
          changes.push({ type: 'added', original: '', current: part.value.trim() });
        }
      }

      return { html, changed: changes.length > 0, changeCount: changes.length, changes };
    }

    /**
     * OCR picks up the whole printed page (header, amount, footer). Cut it down to the
     * span that corresponds to the signed body, using the body's first and last words as anchors.
     */
    extractBodyFromOcr(ocrText, original) {
      const ocr = this._normalizeForDiff(ocrText);
      const orig = this._normalizeForDiff(original).replace(/…$/, '');
      if (!ocr || !orig) return ocr;

      const lowerOcr = ocr.toLowerCase();
      const words = orig.split(' ').filter(Boolean);
      const findPhrase = (phraseWords, fromIndex, last) => {
        const phrase = phraseWords.join(' ').toLowerCase();
        if (!phrase) return -1;
        return last ? lowerOcr.lastIndexOf(phrase) : lowerOcr.indexOf(phrase, fromIndex);
      };

      let start = -1;
      for (const n of [4, 3, 2, 1]) {
        if (words.length < n) continue;
        if (n === 1 && words[0].length < 4) break;
        start = findPhrase(words.slice(0, n), 0, false);
        if (start !== -1) break;
      }

      let end = -1;
      for (const n of [4, 3, 2, 1]) {
        if (words.length < n) continue;
        const tail = words.slice(-n);
        if (n === 1 && tail[0].length < 4) break;
        const idx = findPhrase(tail, 0, true);
        if (idx !== -1 && idx >= Math.max(start, 0)) {
          end = idx + tail.join(' ').length;
          break;
        }
      }

      if (start === -1 && end === -1) return ocr;

      let slice = ocr.slice(start === -1 ? 0 : start, end === -1 ? ocr.length : end);
      if (end === -1) {
        // No tail anchor: stop at the printed seal footer / amount box if present.
        const stop = slice.search(/\b(amount|digitally sealed|kaagazseal|scan (the )?qr)\b/i);
        if (stop > 0) slice = slice.slice(0, stop);
      }
      return slice.trim();
    }

    // -------------------------------------------------------------- SCANNING

    async startScanner(elementId, onSuccess, onError) {
      const fail = (message) => {
        if (typeof onError === 'function') onError(message);
        return false;
      };

      if (typeof Html5Qrcode === 'undefined') {
        return fail('QR scanner library failed to load. Check your internet connection and reload.');
      }
      if (!window.isSecureContext) {
        return fail('Camera access needs HTTPS or localhost. Upload a QR image instead.');
      }
      if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        return fail("This browser doesn't support camera access. Upload a QR image instead.");
      }

      if (this.scanning) await this.stopScanner();

      let handled = false;
      try {
        this.scanner = new Html5Qrcode(elementId, {
          verbose: false,
          experimentalFeatures: { useBarCodeDetectorIfSupported: true }
        });

        const config = {
          fps: 10,
          aspectRatio: 1.0,
          qrbox: (width, height) => {
            const size = Math.max(160, Math.floor(Math.min(width, height) * 0.8));
            return { width: size, height: size };
          }
        };

        await this.scanner.start(
          { facingMode: 'environment' },
          config,
          async (decodedText) => {
            if (handled) return;
            handled = true;
            await this.stopScanner();
            if (typeof onSuccess === 'function') onSuccess(decodedText);
          },
          () => { /* per-frame "no QR found" — expected, ignore */ }
        );

        this.scanning = true;
        return true;
      } catch (err) {
        console.warn('[KaagazSeal] camera start failed:', err);
        this.scanning = false;
        if (this.scanner) {
          try { this.scanner.clear(); } catch (e) { /* ignore */ }
        }
        this.scanner = null;
        return fail(this._cameraErrorMessage(err));
      }
    }

    async stopScanner() {
      const scanner = this.scanner;
      this.scanning = false;
      this.scanner = null;
      if (!scanner) return;
      try {
        await scanner.stop();
      } catch (err) {
        /* already stopped */
      }
      try {
        scanner.clear();
      } catch (err) {
        /* element may already be gone */
      }
    }

    /**
     * Decodes a QR code from an image file. Seal QR codes are dense (up to ~2.8 KB), and no single
     * decoder reads them reliably at every resolution, so this tries several decoders at several scales:
     *   1. native BarcodeDetector (Chrome on Android / macOS)
     *   2. jsQR
     *   3. html5-qrcode (zxing)
     */
    async scanFile(file) {
      if (!file) throw new Error('No file selected.');
      if (file.type && !/^image\//.test(file.type)) throw new Error('Please choose an image file (PNG, JPG…).');
      if (this.scanning) await this.stopScanner();

      let img;
      try {
        img = await this._loadImage(file);
      } catch (err) {
        throw new Error("This image couldn't be opened. Try a PNG or JPG file.");
      }

      try {
        if ('BarcodeDetector' in window) {
          try {
            const detector = new BarcodeDetector({ formats: ['qr_code'] });
            const codes = await detector.detect(img);
            if (codes && codes.length && codes[0].rawValue) return codes[0].rawValue;
          } catch (err) { /* unsupported on this platform — fall through */ }
        }

        const sizes = this._candidateSizes(img.width, img.height);

        if (typeof jsQR === 'function') {
          for (const size of sizes) {
            const canvas = this._drawScaled(img, size);
            const ctx = canvas.getContext('2d', { willReadFrequently: true });
            const data = ctx.getImageData(0, 0, canvas.width, canvas.height);
            const code = jsQR(data.data, data.width, data.height, { inversionAttempts: 'attemptBoth' });
            if (code && code.data) return code.data;
          }
        }

        if (typeof Html5Qrcode !== 'undefined') {
          for (const size of sizes) {
            const canvas = this._drawScaled(img, size);
            const blob = await new Promise((resolve) => canvas.toBlob(resolve, 'image/png'));
            if (!blob) continue;
            const reader = new Html5Qrcode(this.fileReaderElementId, { verbose: false });
            try {
              const result = await reader.scanFileV2(new File([blob], 'qr.png', { type: 'image/png' }), false);
              if (result && result.decodedText) return result.decodedText;
            } catch (err) {
              /* try the next size */
            } finally {
              try { reader.clear(); } catch (e) { /* ignore */ }
            }
          }
        }

        if (typeof jsQR !== 'function' && typeof Html5Qrcode === 'undefined') {
          throw new Error('QR scanner libraries failed to load. Check your internet connection and reload.');
        }
        throw new Error('No QR code found in this image. Try a sharper, well-lit, straight-on photo.');
      } finally {
        if (img && typeof img.close === 'function') img.close();
      }
    }

    // -------------------------------------------------------------- HELPERS

    async _loadImage(file) {
      if (typeof createImageBitmap === 'function') {
        try {
          return await createImageBitmap(file);
        } catch (err) { /* fall back to <img> */ }
      }
      const url = URL.createObjectURL(file);
      try {
        return await new Promise((resolve, reject) => {
          const img = new Image();
          img.onload = () => resolve(img);
          img.onerror = () => reject(new Error('Image failed to load'));
          img.src = url;
        });
      } finally {
        setTimeout(() => URL.revokeObjectURL(url), 0);
      }
    }

    /** Long-edge sizes to try, starting near the original resolution. */
    _candidateSizes(width, height) {
      const longEdge = Math.max(width, height) || 600;
      const raw = [Math.min(longEdge, 1600), 1000, 800, 600, 450, 1300, 700, 520, 900, 350];
      const sizes = [];
      for (const s of raw) {
        if (s > longEdge * 2) continue;
        if (sizes.some((x) => Math.abs(x - s) / x < 0.08)) continue;
        sizes.push(Math.round(s));
      }
      return sizes;
    }

    /** Draws the image scaled to the given long edge on a white canvas with a quiet-zone border. */
    _drawScaled(img, longEdge) {
      const scale = longEdge / Math.max(img.width, img.height);
      const w = Math.max(1, Math.round(img.width * scale));
      const h = Math.max(1, Math.round(img.height * scale));
      const pad = Math.round(longEdge * 0.06);
      const canvas = document.createElement('canvas');
      canvas.width = w + pad * 2;
      canvas.height = h + pad * 2;
      const ctx = canvas.getContext('2d', { willReadFrequently: true });
      ctx.fillStyle = '#FFFFFF';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.imageSmoothingEnabled = true;
      ctx.imageSmoothingQuality = 'high';
      ctx.drawImage(img, pad, pad, w, h);
      return canvas;
    }

    _arrayBufferToBase64(buffer) {
      return this._uint8ToBase64(new Uint8Array(buffer));
    }

    _base64ToArrayBuffer(b64) {
      const bytes = this._base64ToUint8(b64);
      return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    }

    _uint8ToBase64(bytes) {
      let binary = '';
      const chunk = 0x8000;
      for (let i = 0; i < bytes.length; i += chunk) {
        binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
      }
      return btoa(binary);
    }

    _base64ToUint8(b64) {
      const clean = String(b64).replace(/[^A-Za-z0-9+/=]/g, '');
      const binary = atob(clean);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      return bytes;
    }

    _escapeHtml(str) {
      return String(str === null || str === undefined ? '' : str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }

    _normalizeForDiff(str) {
      return String(str || '')
        .replace(/[‘’‚′]/g, "'")
        .replace(/[“”„″]/g, '"')
        .replace(/[–—]/g, '-')
        .replace(/\s+/g, ' ')
        .trim();
    }

    /** Short, human-comparable SHA-256 fingerprint of a P-256 public key. */
    async _fingerprint(jwk) {
      try {
        const data = new TextEncoder().encode(`${jwk.crv}|${jwk.x}|${jwk.y}`);
        const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', data));
        const hex = Array.from(digest.slice(0, 8), (b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
        return hex.match(/.{4}/g).join('-');
      } catch (err) {
        return 'UNKNOWN';
      }
    }

    _cameraErrorMessage(err) {
      const text = String((err && (err.name || '')) + ' ' + (err && err.message ? err.message : err));
      if (/NotAllowed|Permission|denied/i.test(text)) {
        return 'Camera permission was denied. Allow camera access in your browser settings, or upload a QR image instead.';
      }
      if (/NotFound|DevicesNotFound|no camera|Requested device not found/i.test(text)) {
        return 'No camera was found on this device. Upload a QR image instead.';
      }
      if (/NotReadable|TrackStart|in use|Could not start video/i.test(text)) {
        return 'The camera is in use by another app. Close it and try again.';
      }
      if (/Overconstrained/i.test(text)) {
        return "The camera doesn't support the requested settings. Upload a QR image instead.";
      }
      return 'Could not start the camera. Upload a QR image instead.';
    }

    // --- IndexedDB key storage (CryptoKey objects are structured-cloneable) ---

    _openDb() {
      return new Promise((resolve, reject) => {
        if (!window.indexedDB) {
          reject(new Error('IndexedDB unavailable'));
          return;
        }
        const req = indexedDB.open(DB_NAME, 1);
        req.onupgradeneeded = () => {
          if (!req.result.objectStoreNames.contains(DB_STORE)) req.result.createObjectStore(DB_STORE);
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
        req.onblocked = () => reject(new Error('IndexedDB blocked'));
      });
    }

    _keyId(identityId) {
      return `${KEY_ID}:${identityId}`;
    }

    async _loadKeyPair(identityId) {
      let db;
      try {
        db = await this._openDb();
        const pair = await new Promise((resolve, reject) => {
          const tx = db.transaction(DB_STORE, 'readonly');
          const req = tx.objectStore(DB_STORE).get(this._keyId(identityId));
          req.onsuccess = () => resolve(req.result || null);
          req.onerror = () => reject(req.error);
        });
        if (pair && pair.privateKey && pair.publicKey) return pair;
        return null;
      } catch (err) {
        return null;
      } finally {
        if (db) db.close();
      }
    }

    async _saveKeyPair(identityId, pair) {
      let db;
      try {
        db = await this._openDb();
        await new Promise((resolve, reject) => {
          const tx = db.transaction(DB_STORE, 'readwrite');
          tx.objectStore(DB_STORE).put({ privateKey: pair.privateKey, publicKey: pair.publicKey }, this._keyId(identityId));
          tx.oncomplete = () => resolve();
          tx.onerror = () => reject(tx.error);
          tx.onabort = () => reject(tx.error);
        });
        return true;
      } catch (err) {
        console.warn('[KaagazSeal] key could not be persisted; it will last for this session only.', err);
        return false;
      } finally {
        if (db) db.close();
      }
    }
  }

  window.KaagazSeal = KaagazSeal;
})();
