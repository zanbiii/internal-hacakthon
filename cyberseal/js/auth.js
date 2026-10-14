/**
 * CyberSeal — device-only accounts
 * Users live in this browser's IndexedDB. Passwords are never stored: only a salted
 * PBKDF2-SHA256 hash is kept. Nothing is sent to a server.
 * Exposes window.CyberAuth.
 */
(function () {
  'use strict';

  const DB_NAME = 'cyberseal-auth';
  const DB_STORE = 'users';
  const SESSION_KEY = 'cyberseal.session';
  const LOCKOUT_PREFIX = 'cyberseal.lockout.';
  const PBKDF2_ITERATIONS = 310000;
  const REMEMBER_MS = 7 * 24 * 60 * 60 * 1000;
  const MAX_ATTEMPTS = 5;

  class AuthError extends Error {
    constructor(message, field) {
      super(message);
      this.name = 'AuthError';
      this.field = field || null;
    }
  }

  class CyberAuth {
    constructor() {
      this.currentUser = null;
      this._listeners = new Set();
    }

    onChange(callback) {
      this._listeners.add(callback);
      return () => this._listeners.delete(callback);
    }

    /** Returns the signed-in user from a saved session, or null. */
    async restoreSession() {
      try {
        const raw = localStorage.getItem(SESSION_KEY) || sessionStorage.getItem(SESSION_KEY);
        if (!raw) return null;
        const session = JSON.parse(raw);
        if (!session || !session.username || (session.exp && Date.now() > session.exp)) {
          this._clearSession();
          return null;
        }
        const record = await this._getUser(session.username);
        if (!record || record.id !== session.id) {
          this._clearSession();
          return null;
        }
        this._setUser(record);
        return this.currentUser;
      } catch (err) {
        console.warn('[CyberAuth] session restore failed:', err);
        return null;
      }
    }

    async signUp({ name, organization, username, password, confirm }) {
      this._assertCrypto();
      const cleanName = String(name || '').trim();
      const cleanOrg = String(organization || '').trim();
      const id = this.normalizeUsername(username);

      if (cleanName.length < 2) throw new AuthError('Enter your full name.', 'name');
      if (cleanName.length > 80) throw new AuthError('Name is too long (max 80 characters).', 'name');
      if (cleanOrg.length > 120) throw new AuthError('Organization name is too long (max 120 characters).', 'organization');
      if (!/^[a-z0-9._@+-]{3,64}$/.test(id)) {
        throw new AuthError('Use 3–64 characters: letters, numbers, or . _ @ + -', 'username');
      }
      const strength = this.passwordStrength(password);
      if (!strength.ok) throw new AuthError(strength.message, 'password');
      if (confirm !== undefined && password !== confirm) throw new AuthError("Passwords don't match.", 'confirm');

      if (await this._getUser(id)) {
        throw new AuthError('An account with this username already exists on this device.', 'username');
      }

      const salt = crypto.getRandomValues(new Uint8Array(16));
      const hash = await this._hash(password, salt, PBKDF2_ITERATIONS);
      const record = {
        id: this._uuid(),
        username: id,
        name: cleanName,
        organization: cleanOrg,
        salt: this._toB64(salt),
        hash: this._toB64(hash),
        iterations: PBKDF2_ITERATIONS,
        createdAt: new Date().toISOString()
      };
      await this._putUser(record);
      this._saveSession(record, false);
      this._setUser(record);
      return this.currentUser;
    }

    async logIn(username, password, remember) {
      this._assertCrypto();
      const id = this.normalizeUsername(username);
      if (!id) throw new AuthError('Enter your username.', 'username');
      if (!password) throw new AuthError('Enter your password.', 'password');

      const wait = this._lockoutRemaining(id);
      if (wait > 0) {
        throw new AuthError(`Too many failed attempts. Try again in ${Math.ceil(wait / 1000)} seconds.`, 'password');
      }

      const record = await this._getUser(id);
      // Hash even when the user doesn't exist so both paths take the same time.
      const salt = record ? this._fromB64(record.salt) : new Uint8Array(16);
      const iterations = record ? record.iterations : PBKDF2_ITERATIONS;
      const hash = await this._hash(password, salt, iterations);

      if (!record || !this._constantTimeEqual(hash, this._fromB64(record.hash))) {
        this._registerFailure(id);
        throw new AuthError('Incorrect username or password.', 'password');
      }

      this._clearFailures(id);
      this._saveSession(record, !!remember);
      this._setUser(record);
      return this.currentUser;
    }

    logOut() {
      this._clearSession();
      this._setUser(null);
    }

    /** Deletes the signed-in account after re-checking the password. Returns the deleted user's id. */
    async deleteAccount(password) {
      if (!this.currentUser) throw new AuthError('You are not signed in.');
      const record = await this._getUser(this.currentUser.username);
      if (!record) throw new AuthError('Account not found.');
      const hash = await this._hash(password || '', this._fromB64(record.salt), record.iterations);
      if (!this._constantTimeEqual(hash, this._fromB64(record.hash))) {
        throw new AuthError('Incorrect password.', 'password');
      }
      await this._deleteUser(record.username);
      this._clearSession();
      this._setUser(null);
      return record.id;
    }

    normalizeUsername(username) {
      return String(username || '').trim().toLowerCase();
    }

    /** { ok, score 0–4, label, message } */
    passwordStrength(password) {
      const pw = String(password || '');
      let score = 0;
      if (pw.length >= 8) score++;
      if (pw.length >= 12) score++;
      if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
      if (/\d/.test(pw) && /[^A-Za-z0-9]/.test(pw)) score++;
      if (/^(.)\1+$/.test(pw) || /^(password|12345678|qwerty)/i.test(pw)) score = 0;

      const labels = ['Too weak', 'Weak', 'Fair', 'Good', 'Strong'];
      let message = '';
      if (pw.length < 8) message = 'Password must be at least 8 characters.';
      else if (!/[A-Za-z]/.test(pw) || !/\d/.test(pw)) message = 'Use at least one letter and one number.';
      else if (score === 0) message = 'That password is too easy to guess.';
      return { ok: !message, score, label: labels[score], message };
    }

    // ------------------------------------------------------------ internals

    _setUser(record) {
      this.currentUser = record
        ? { id: record.id, username: record.username, name: record.name, organization: record.organization, createdAt: record.createdAt }
        : null;
      this._listeners.forEach((cb) => {
        try { cb(this.currentUser); } catch (err) { console.error(err); }
      });
    }

    _saveSession(record, remember) {
      this._clearSession();
      const session = { id: record.id, username: record.username, exp: remember ? Date.now() + REMEMBER_MS : null };
      try {
        (remember ? localStorage : sessionStorage).setItem(SESSION_KEY, JSON.stringify(session));
      } catch (err) {
        /* storage blocked — session lasts until reload */
      }
    }

    _clearSession() {
      try { localStorage.removeItem(SESSION_KEY); } catch (err) { /* ignore */ }
      try { sessionStorage.removeItem(SESSION_KEY); } catch (err) { /* ignore */ }
    }

    _lockoutRemaining(id) {
      try {
        const data = JSON.parse(localStorage.getItem(LOCKOUT_PREFIX + id) || 'null');
        return data && data.until ? Math.max(0, data.until - Date.now()) : 0;
      } catch (err) {
        return 0;
      }
    }

    _registerFailure(id) {
      try {
        const key = LOCKOUT_PREFIX + id;
        const data = JSON.parse(localStorage.getItem(key) || 'null') || { fails: 0, until: 0 };
        data.fails += 1;
        if (data.fails >= MAX_ATTEMPTS) {
          // 30s, 60s, 120s … capped at 15 minutes
          const delay = Math.min(15 * 60 * 1000, 30000 * Math.pow(2, data.fails - MAX_ATTEMPTS));
          data.until = Date.now() + delay;
        }
        localStorage.setItem(key, JSON.stringify(data));
      } catch (err) {
        /* ignore */
      }
    }

    _clearFailures(id) {
      try { localStorage.removeItem(LOCKOUT_PREFIX + id); } catch (err) { /* ignore */ }
    }

    _assertCrypto() {
      if (!window.crypto || !window.crypto.subtle) {
        throw new AuthError('Accounts need Web Crypto. Open the app over HTTPS or on localhost.');
      }
    }

    async _hash(password, salt, iterations) {
      const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
      const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, material, 256);
      return new Uint8Array(bits);
    }

    _constantTimeEqual(a, b) {
      if (a.length !== b.length) return false;
      let diff = 0;
      for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
      return diff === 0;
    }

    _uuid() {
      if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
      const b = crypto.getRandomValues(new Uint8Array(16));
      return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
    }

    _toB64(bytes) {
      let s = '';
      for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
      return btoa(s);
    }

    _fromB64(b64) {
      const s = atob(b64);
      const out = new Uint8Array(s.length);
      for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
      return out;
    }

    // --- IndexedDB ---

    _openDb() {
      return new Promise((resolve, reject) => {
        if (!window.indexedDB) {
          reject(new AuthError('This browser blocks local storage, so accounts are unavailable (private mode?).'));
          return;
        }
        const req = indexedDB.open(DB_NAME, 1);
        req.onupgradeneeded = () => {
          if (!req.result.objectStoreNames.contains(DB_STORE)) req.result.createObjectStore(DB_STORE, { keyPath: 'username' });
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(new AuthError('Could not open account storage.'));
        req.onblocked = () => reject(new AuthError('Account storage is busy. Close other CyberSeal tabs and retry.'));
      });
    }

    async _tx(mode, fn) {
      const db = await this._openDb();
      try {
        return await new Promise((resolve, reject) => {
          const tx = db.transaction(DB_STORE, mode);
          const req = fn(tx.objectStore(DB_STORE));
          let result;
          if (req) req.onsuccess = () => { result = req.result; };
          tx.oncomplete = () => resolve(result);
          tx.onerror = () => reject(tx.error);
          tx.onabort = () => reject(tx.error);
        });
      } finally {
        db.close();
      }
    }

    _getUser(username) {
      return this._tx('readonly', (store) => store.get(username)).then((r) => r || null);
    }

    _putUser(record) {
      return this._tx('readwrite', (store) => store.put(record));
    }

    _deleteUser(username) {
      return this._tx('readwrite', (store) => store.delete(username));
    }
  }

  CyberAuth.AuthError = AuthError;
  window.CyberAuth = CyberAuth;
})();
