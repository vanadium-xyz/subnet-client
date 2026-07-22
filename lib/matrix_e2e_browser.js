'use strict';
/**
 * Browser implementation of E2EMatrixClient backed by matrix-js-sdk
 * (the same library Element Web uses). matrix-js-sdk pulls in
 * @matrix-org/matrix-sdk-crypto-wasm internally — that's the WASM build of
 * the Rust OlmMachine the Node version drives directly. Cross-signing,
 * megolm session management, key sharing, and timeline decryption are all
 * handled by the SDK; this file is a thin adapter that:
 *
 *   1. presents the same external API as lib/matrix_e2e.js so callers
 *      (index.js, subnet.js, downstream apps) don't care which backend
 *      is loaded;
 *   2. injects the EIP-191 accountability signature into outbound
 *      m.room.message events;
 *   3. persists session metadata + per-room read checkpoints + agent
 *      KV memory in localStorage instead of session.json + SQLite.
 *
 * The SDK is loaded via a dynamic import inside login() so this file
 * itself stays CJS-friendly, and bundlers don't need to interop ESM at
 * module-evaluation time.
 *
 * NOTE: this is best-effort against matrix-js-sdk's current public API.
 * Rough edges to expect when first integrating:
 *   - cross-signing bootstrap may need a UIA callback (set up an
 *     authUploadDeviceSigningKeys handler if the homeserver requires it);
 *   - older history events may take a tick to finish decrypting after
 *     scrollback resolves; readMessages waits a short while but heavy
 *     traffic may need a longer settle window;
 *   - the SDK does not run in a worker by default — running it in a
 *     SharedWorker if you want multi-tab safety is left to the caller.
 */

const { signMessage } = require('./accountability');
// marked v18 is ESM-only; load it lazily via import() (cached) to avoid the
// require(ESM) ExperimentalWarning. Bundlers resolve dynamic import fine.
let _markedPromise;
const getMarked = () => (_markedPromise ??= import('marked').then(m => m.marked));

const ACCOUNTABILITY_FIELD = 'xyz.vanadium.accountability';
const DEFAULT_STATE_NS = 'subnet-client-state';

// Homeserver host (e.g. "matrix.bottles.dev") — distinguishes subnets, used to
// give each one its own localStorage session namespace so switching subnets
// doesn't load the wrong session.
function matrix_host(url) {
  try { return new URL(url).host; } catch { return url; }
}

// Best-effort delete of the matrix-js-sdk Rust crypto IndexedDB databases whose
// name starts with `prefix` (the per-subnet store prefix). Resolves even if a
// delete is blocked by an open connection. Only needed for the rare device
// rotation below — switching subnets never wipes, since each subnet has its own
// crypto store (see _cryptoStorePrefix + the patched initRustCrypto storePrefix).
async function delete_rust_crypto_dbs(prefix) {
  if (typeof indexedDB === 'undefined' || !indexedDB.databases) return;
  const dbs = await indexedDB.databases().catch(() => []);
  await Promise.all(dbs.map((db) => new Promise((resolve) => {
    if (!db.name || !db.name.startsWith(prefix)) { resolve(); return; }
    const req = indexedDB.deleteDatabase(db.name);
    req.onsuccess = () => resolve();
    req.onerror = () => resolve();
    req.onblocked = () => resolve();
  })));
}

// ── localStorage-backed session/checkpoint/memory store ─────────────────────
//
// We don't try to recreate better-sqlite3 in the browser. The persisted state
// is small (session metadata, sync token, a row per room for last-read,
// agent KV) and naturally fits localStorage with one JSON-encoded key per
// logical table. All three live under the same namespace prefix so a single
// state directory equivalent maps to a single prefix.

class BrowserKVStore {
  constructor(namespace) {
    this.ns = namespace || DEFAULT_STATE_NS;
  }
  _key(name) { return `${this.ns}::${name}`; }
  _readJSON(name, fallback) {
    try {
      const raw = globalThis.localStorage?.getItem(this._key(name));
      if (!raw) return fallback;
      return JSON.parse(raw);
    } catch {
      return fallback;
    }
  }
  _writeJSON(name, value) {
    try {
      globalThis.localStorage?.setItem(this._key(name), JSON.stringify(value));
    } catch {
      // Quota/disabled storage — ignored, matching the Node version's
      // best-effort posture for the sync_token file.
    }
  }
  _delete(name) {
    try {
      globalThis.localStorage?.removeItem(this._key(name));
    } catch {}
  }

  // Session: { userId, deviceId, accessToken }
  loadSession() { return this._readJSON('session', null); }
  saveSession(s) { this._writeJSON('session', s); }

  // Wallet-derived secret-storage (4S) key, stored as a raw byte array. Persisted
  // (and surviving the crypto-store wipe) so a subnet switch — which reloads the
  // page — doesn't re-prompt the wallet to re-derive it.
  loadBackupKey() { const a = this._readJSON('ss_key', null); return Array.isArray(a) ? new Uint8Array(a) : null; }
  saveBackupKey(key) { this._writeJSON('ss_key', Array.from(key)); }

  // The device id this subnet's Rust crypto store was built for. Used to decide
  // whether reusing the stored device is safe (reusing a device on a fresh/empty
  // crypto store causes one-time-key collisions on the server).
  loadCryptoDevice() { return this._readJSON('crypto_device', null); }
  saveCryptoDevice(deviceId) { this._writeJSON('crypto_device', deviceId); }

  // Per-room checkpoint table
  getCheckpoint(roomId) {
    const all = this._readJSON('checkpoints', {}) || {};
    return Object.prototype.hasOwnProperty.call(all, roomId) ? all[roomId] : null;
  }
  setCheckpoint(roomId, ts) {
    const all = this._readJSON('checkpoints', {}) || {};
    const prior = Object.prototype.hasOwnProperty.call(all, roomId) ? all[roomId] : -Infinity;
    if (ts <= prior) return;
    all[roomId] = ts;
    this._writeJSON('checkpoints', all);
  }

  // Agent scratchpad memory
  setMemory(key, value) {
    if (typeof key !== 'string' || key.length === 0) {
      throw new Error('memory key must be a non-empty string');
    }
    const all = this._readJSON('memory', {}) || {};
    all[key] = { value, updated_at: Date.now() };
    this._writeJSON('memory', all);
  }
  getMemory(key) {
    const all = this._readJSON('memory', {}) || {};
    return Object.prototype.hasOwnProperty.call(all, key) ? all[key].value : null;
  }
  listMemory() {
    const all = this._readJSON('memory', {}) || {};
    return Object.entries(all)
      .map(([k, v]) => ({ key: k, value: v.value, updated_at: v.updated_at }))
      .sort((a, b) => b.updated_at - a.updated_at);
  }
  deleteMemory(key) {
    const all = this._readJSON('memory', {}) || {};
    if (!Object.prototype.hasOwnProperty.call(all, key)) return false;
    delete all[key];
    this._writeJSON('memory', all);
    return true;
  }

  // Timeline /sync cursor (mirrors MemoryStore.{get,set,clear}TimelineSyncToken)
  getTimelineSyncToken() { return this._readJSON('timeline_sync_token', null); }
  setTimelineSyncToken(token) { if (token) this._writeJSON('timeline_sync_token', token); }
  clearTimelineSyncToken() { this._delete('timeline_sync_token'); }

  // Per-room snapshot for old_context (mirrors MemoryStore.{get,set}RoomSnapshot)
  getRoomSnapshot(roomId) {
    const all = this._readJSON('room_snapshots', {}) || {};
    const row = all[roomId];
    return row ? { messages: row.messages || [], status: row.status || [] } : { messages: [], status: [] };
  }
  setRoomSnapshot(roomId, snapshot) {
    const all = this._readJSON('room_snapshots', {}) || {};
    all[roomId] = { messages: snapshot.messages || [], status: snapshot.status || [] };
    this._writeJSON('room_snapshots', all);
  }

  close() { /* no-op */ }
}

// ── Browser E2EMatrixClient ─────────────────────────────────────────────────

class E2EMatrixClient {
  /**
   * @param {object} opts
   * @param {string} opts.matrixUrl
   * @param {string} [opts.privateKey] - Ethereum private key for
   *   accountability. Either this or `signer` is required.
   * @param {object} [opts.signer] - External signer (e.g.
   *   `ethers.JsonRpcSigner` from MetaMask) with async
   *   `signMessage(text): Promise<string>`. Used as a drop-in for the
   *   wallet built from `privateKey`. Note: each `sendMessage()` triggers
   *   three signatures (prev/with/reply), so the user will see three
   *   MetaMask popups per message — fine for a demo, painful for prod.
   * @param {string} [opts.userAddress] - The signer's Ethereum address.
   *   Optional, but lets us avoid a `getAddress()` round-trip when the
   *   caller already has it.
   * @param {string} [opts.storePath] - localStorage namespace prefix. Same
   *   semantic role as the directory path on Node; using a stable string
   *   here keeps multiple tabs of the same app from stomping each other's
   *   crypto store. Defaults to `subnet-client-state`.
   * @param {object} [opts.delegation] - Optional delegation envelope attached
   *   to outbound message accountability fields. When set, `privateKey`/
   *   `signer` should be the delegate's, not the main account.
   */
  constructor({ matrixUrl, privateKey, signer, userAddress, storePath, delegation, deriveSecretStorageKey }) {
    if (!privateKey && !signer) {
      throw new Error('E2EMatrixClient requires either privateKey or signer');
    }
    this.matrixUrl = matrixUrl.replace(/\/$/, '');
    this.privateKey = privateKey || null;
    // Normalize signer: if a privateKey was given, accountability.signMessage
    // will build the wallet itself; if a signer was given, hold onto it.
    this._signer = signer || null;
    this.delegation = delegation || null;
    this.userAddress = userAddress || null;
    // Derives the wallet-based secret-storage (4S) key for key backup. Must use
    // the MAIN wallet (not the ephemeral delegate) so every device for this wallet
    // derives the same key. Optional — without it, key backup is skipped.
    this._deriveSecretStorageKey = deriveSecretStorageKey || null;
    this._ssKey = null; // cached 4S key (Uint8Array)
    this._ssKeyPromise = null; // in-flight derivation, so we prompt the wallet once
    // Per-subnet session namespace: the homeserver host distinguishes subnets,
    // so each keeps its own session/sync token. Without this, switching subnets
    // loads the previous subnet's session and trips a device/account mismatch.
    this.storePath = storePath || `${DEFAULT_STATE_NS}::${matrix_host(this.matrixUrl)}`;
    this.kv = new BrowserKVStore(this.storePath);
    // Per-subnet Rust crypto store prefix, passed to the (patched) initRustCrypto.
    // Each subnet gets its own IndexedDB crypto store, so switching never wipes
    // and the device + Olm account persist together — no account/device mismatch,
    // no one-time-key collisions, no device proliferation.
    this._cryptoStorePrefix = `${this.storePath}::crypto`;
    this.accessToken = null;
    this.userId = null;
    this.deviceId = null;
    this.client = null; // matrix-js-sdk MatrixClient
    this._sdk = null;   // cached matrix-js-sdk module
    this._cryptoExtrasPromise = null; // single-flight guard for crypto bootstrap
    // Same shape as the Node variant. matrix-js-sdk owns the truth here; we
    // refresh from CryptoApi on demand in getCrossSigningStatus().
    this._crossSigningStatus = { state: 'unknown' };
  }

  /** Internal helper: what to hand to accountability.signMessage. */
  _signingHandle() {
    return this._signer ? this._signer : this.privateKey;
  }

  // ── matrix-js-sdk loader ──────────────────────────────────────────────────

  async _loadSdk() {
    if (this._sdk) return this._sdk;
    // matrix-js-sdk ships as ESM. Dynamic import keeps this file CJS so
    // bundlers don't need a hybrid module graph at evaluation time.
    this._sdk = await import('matrix-js-sdk');
    return this._sdk;
  }

  // The wallet-derived secret-storage (4S) key as a 32-byte Uint8Array, used to
  // encrypt/decrypt the homeserver-side key backup. Cached in memory and in the
  // per-subnet KV (which survives the crypto-store wipe) so a subnet switch
  // doesn't re-prompt the wallet. Returns null if no deriver was wired in.
  async _getSecretStorageKey() {
    if (this._ssKey) return this._ssKey;
    const cached = this.kv.loadBackupKey();
    if (cached) { this._ssKey = cached; return this._ssKey; }
    if (!this._deriveSecretStorageKey) return null;
    // Dedup concurrent callers (the SDK may ask for several secrets at once) so
    // the wallet is prompted to derive the key exactly once.
    if (!this._ssKeyPromise) {
      this._ssKeyPromise = Promise.resolve(this._deriveSecretStorageKey()).then((key) => {
        this._ssKey = key;
        this.kv.saveBackupKey(key);
        return key;
      });
    }
    return this._ssKeyPromise;
  }

  // The agent memory store sits behind the same getter the Node version
  // exposes so subnet.js's setMemory/getMemory/listMemory/deleteMemory
  // delegations work unchanged.
  _getMemoryStore() {
    return this.kv;
  }

  // ── Login + crypto bootstrap ──────────────────────────────────────────────

  async login(username, password, opts = {}) {
    const sdk = await this._loadSdk();
    if (opts.bootstrapSession && !this.kv.loadSession()) {
      this.kv.saveSession({
        userId: opts.bootstrapSession.userId,
        deviceId: opts.bootstrapSession.deviceId,
        accessToken: opts.bootstrapSession.accessToken,
      });
    }
    const stored = this.kv.loadSession();

    let userId = stored?.userId || null;
    let deviceId = stored?.deviceId || null;
    let accessToken = stored?.accessToken || null;
    let usedStoredToken = false;

    // Only reuse the stored device if THIS subnet's crypto store was actually built
    // for it. Otherwise (a fresh store, or a migrated one under a new prefix) the
    // reused device would get a brand-new Olm account and re-upload one-time keys
    // that already exist on the server for that device (M_UNKNOWN "One time key …
    // already exists"). In that case we force a fresh device so the new crypto store
    // and the device are created together.
    const cryptoMatchesSession = !!deviceId && this.kv.loadCryptoDevice() === deviceId;

    if (cryptoMatchesSession && accessToken && userId) {
      try {
        const probe = sdk.createClient({ baseUrl: this.matrixUrl, accessToken, userId, deviceId });
        const who = await probe.whoami();
        if (who?.user_id === userId) {
          usedStoredToken = true;
        }
      } catch (_e) {
        usedStoredToken = false;
      }
    }

    if (!usedStoredToken) {
      const tmp = sdk.createClient({ baseUrl: this.matrixUrl });
      const loginBody = {
        identifier: { type: 'm.id.user', user: username },
        password,
        initial_device_display_name: 'subnet-client',
      };
      // Reuse our device id ONLY when this subnet's crypto store matches it;
      // otherwise let the server mint a fresh device so the fresh crypto store
      // can't collide on one-time keys.
      if (deviceId && cryptoMatchesSession) loginBody.device_id = deviceId;
      const res = await tmp.login('m.login.password', loginBody);
      accessToken = res.access_token;
      userId = res.user_id;
      deviceId = res.device_id;
      this.kv.saveSession({ userId, deviceId, accessToken });
    }

    // Build the long-lived client. matrix-js-sdk owns its own IndexedDB
    // stores for sync state and crypto — we don't have to wire them up
    // explicitly when using the default in-memory + IndexedDB Rust store.
    this.client = sdk.createClient({
      baseUrl: this.matrixUrl,
      accessToken,
      userId,
      deviceId,
      timelineSupport: true,
      // Lets the crypto stack unlock secret storage (cross-signing keys + the key
      // backup decryption key) with our wallet-derived 4S key, on any device.
      cryptoCallbacks: {
        getSecretStorageKey: async ({ keys }) => {
          const key = await this._getSecretStorageKey();
          if (!key) return null;
          let keyId = await this.client.secretStorage.getDefaultKeyId().catch(() => null);
          if (!keyId || !keys[keyId]) keyId = Object.keys(keys)[0];
          return keyId ? [keyId, key] : null;
        },
        cacheSecretStorageKey: (_keyId, _keyInfo, key) => { this._ssKey = key; },
      },
    });

    // The crypto store must have been built for the device we're about to run.
    // A store orphaned from its marker (interrupted first login, partial wipe,
    // server-side device rotation) would make the rust OlmMachine reject its
    // mismatched olm account on EVERY login — an unrecoverable loop that mints a
    // new server device per retry. Wipe it; key backup restores history keys.
    if (this.kv.loadCryptoDevice() !== deviceId) {
      await delete_rust_crypto_dbs(this._cryptoStorePrefix);
    }
    // Initialize the Rust crypto module before startClient so the first /sync's
    // to-device events are decrypted in place. The per-subnet storePrefix (via our
    // matrix-js-sdk patch) gives each subnet its OWN crypto IndexedDB through the
    // client's own single crypto/WASM instance — so switching subnets never wipes
    // or collides, and there's no WASM duplication (which a deep import would cause).
    await this.client.initRustCrypto({ storePrefix: this._cryptoStorePrefix });
    // Record which device this subnet's crypto store now belongs to, so a later
    // login knows it's safe to reuse this device (and not collide on one-time keys).
    this.kv.saveCryptoDevice(deviceId);

    await this.client.startClient({ initialSyncLimit: 30 });
    // Wait for the first PREPARED state so subsequent calls see rooms.
    await new Promise((resolve) => {
      const onSync = (state) => {
        if (state === 'PREPARED' || state === 'SYNCING') {
          this.client.removeListener(sdk.ClientEvent.Sync, onSync);
          resolve();
        }
      };
      this.client.on(sdk.ClientEvent.Sync, onSync);
    });

    this.accessToken = accessToken;
    this.userId = userId;
    this.deviceId = deviceId;
    // Cross-signing, secret storage and key backup run in the BACKGROUND: they
    // can require a wallet signature (the backup key) or a slow homeserver, and
    // must NOT block getting into chat. initRustCrypto already ran above, so
    // messages decrypt meanwhile; this only adds cross-device trust + history
    // backup/restore as it completes.
    this._bootstrapCryptoExtras(userId, password).catch((e) => console.warn('[E2E] crypto bootstrap skipped:', e?.message));
    return { userId, deviceId };
  }

  /**
   * Mint a fresh, independent Matrix session for this account via a new
   * password /login — does NOT touch the current client/session. Returns
   * { user_id, access_token, device_id }. Browser counterpart to the Node
   * client's mintSession; used by the QR sign-in handoff.
   */
  async mintSession(username, password, displayName) {
    const sdk = await this._loadSdk();
    const tmp = sdk.createClient({ baseUrl: this.matrixUrl });
    const res = await tmp.login('m.login.password', {
      identifier: { type: 'm.id.user', user: username },
      password,
      initial_device_display_name: displayName,
    });
    return { user_id: res.user_id, access_token: res.access_token, device_id: res.device_id };
  }

  // Background crypto setup (off the login critical path): cross-signing marks
  // your devices as "you"; secret storage (SSSS/4S) holds the cross-signing +
  // backup keys encrypted with the wallet-derived key; key backup stores Megolm
  // room keys (encrypted) on the homeserver so history decrypts on any device.
  //
  // The whole sequence is CREATE-ONCE / NEVER-RESET so that N independent
  // browsers (and an Element session entering the Security Key) converge on ONE
  // cross-signing identity and ONE backup version instead of clobbering each
  // other. Resetting either is what orphans uploaded keys / splits the identity,
  // so we only ever create when the account genuinely has none, and import/enable
  // otherwise. Single-flighted so one client never runs it twice concurrently.
  async _bootstrapCryptoExtras(userId, password) {
    if (this._cryptoExtrasPromise) return this._cryptoExtrasPromise;
    this._cryptoExtrasPromise = this._doBootstrapCryptoExtras(userId, password)
      .finally(() => { this._cryptoExtrasPromise = null; });
    return this._cryptoExtrasPromise;
  }

  async _doBootstrapCryptoExtras(userId, password) {
    const crypto = this.client.getCrypto();
    if (!crypto) return;
    const ssKey = await this._getSecretStorageKey();
    if (!ssKey) return; // no wallet 4S key wired in → nothing to bootstrap

    const authUploadDeviceSigningKeys = async (makeRequest) => {
      await makeRequest({
        type: 'm.login.password',
        identifier: { type: 'm.id.user', user: userId },
        password,
      });
    };

    // ── Phase 1: secret storage (4S) — create once, never reset ─────────────
    // Sets up the wallet-derived 4S key only if the account has none yet. If 4S
    // already exists (this or another device made it), isNewSecretStorageKeyNeeded
    // is false inside the SDK, so createSecretStorageKey is never called and the
    // existing key/secrets are left untouched. setupNewKeyBackup is deliberately
    // OMITTED (defaults false) — passing it true makes bootstrapSecretStorage call
    // resetKeyBackup → deleteAllKeyBackupVersions, which would wipe history.
    await crypto.bootstrapSecretStorage({
      createSecretStorageKey: async () => ({
        privateKey: ssKey,
        keyInfo: { name: 'Subnet message history (wallet)' },
      }),
    });

    // ── Phase 2: cross-signing — import-or-create, NEVER clobber ────────────
    // Decide from authoritative server state so two browsers share ONE identity:
    //   - server has no identity         → safe to create
    //   - private keys reachable in 4S   → safe to import + self-sign
    //   - identity exists but unreachable → DO NOT bootstrap (that branch resets
    //                                       and overwrites the shared identity);
    //                                       wait for 4S to sync, else leave intact.
    const serverHasIdentity = await crypto
      .userHasCrossSigningKeys(userId, true)
      .catch(() => false);
    let csStatus = await crypto.getCrossSigningStatus().catch(() => null);
    const haveKeys = (s) =>
      !!s &&
      (s.privateKeysInSecretStorage ||
        (s.privateKeysCachedLocally?.masterKey &&
          s.privateKeysCachedLocally?.selfSigningKey &&
          s.privateKeysCachedLocally?.userSigningKey));

    if (!serverHasIdentity) {
      // Fresh account: create the identity. 4S exists from phase 1, so the new
      // private keys get exported into it for other devices to import.
      await crypto.bootstrapCrossSigning({ authUploadDeviceSigningKeys });
    } else {
      // Identity exists. Only import if we can actually read the keys from 4S;
      // retry briefly in case account_data is still syncing in on a fresh device.
      for (let i = 0; i < 5 && !haveKeys(csStatus); i++) {
        await new Promise((r) => setTimeout(r, 1000));
        csStatus = await crypto.getCrossSigningStatus().catch(() => null);
      }
      if (haveKeys(csStatus)) {
        // Import branch + self-sign this device. No reset possible here.
        await crypto.bootstrapCrossSigning({ authUploadDeviceSigningKeys });
      }
      // else: keys not reachable (e.g. an Element-style session that must enter
      // the Security Key). Leave the server identity untouched — never reset.
    }

    const csReady = await crypto.isCrossSigningReady().catch(() => false);

    // ── Phase 3: key backup — adopt / create-once, never reset a TRUSTED one ──
    // This device must both restore history AND start uploading the room keys it
    // already holds locally. The SDK's upload loop only runs once a *trusted*
    // backup is active, so we make sure one is.
    const backupInfo = await crypto.getKeyBackupInfo().catch(() => null);
    let needNewBackup = !backupInfo;
    if (backupInfo) {
      // A backup exists: pull its decryption key from 4S and try to enable it.
      await crypto.loadSessionBackupPrivateKeyFromSecretStorage().catch(() => {});
      const check = await crypto.checkKeyBackupAndEnable().catch(() => null);
      // If it's orphaned/untrusted (e.g. signed by a cross-signing identity that
      // was since replaced), the SDK won't enable it and our local keys would
      // never upload. Replace it from this device — safe because we hold those
      // keys locally and will re-upload them into the fresh, trusted version.
      if (!check?.trustInfo?.trusted) needNewBackup = true;
    }
    if (needNewBackup && csReady) {
      // Create only when cross-signing is available so the new backup's auth_data
      // is cross-signed and trusted by every device. deleteAllKeyBackupVersions
      // removes nothing when none exists, or only an already-untrusted version.
      await crypto
        .resetKeyBackup()
        .catch((e) => console.warn('[E2E] key backup (re)create failed:', e?.message));
    }
    // Restore whatever backup is now active so history decrypts; the SDK uploads
    // our existing local room keys into it in the background once it's enabled.
    await crypto
      .restoreKeyBackup()
      .catch((e) => console.warn('[E2E] key backup restore failed:', e?.message));

    this._crossSigningStatus = { state: csReady ? 'ready' : 'awaiting_verification' };
  }

  // ── Internals: rooms, decryption, history fetch ───────────────────────────

  _requireClient() {
    if (!this.client) throw new Error('Not logged in — call login() first');
  }

  async _isRoomEncrypted(roomId) {
    this._requireClient();
    const room = this.client.getRoom(roomId);
    if (!room) return false;
    // matrix-js-sdk exposes both isEncrypted (sync-state-derived) and
    // getCrypto().isEncryptionEnabledInRoom (server-truth). The latter is
    // more reliable right after a fresh join.
    try {
      const crypto = this.client.getCrypto();
      if (crypto?.isEncryptionEnabledInRoom) {
        return await crypto.isEncryptionEnabledInRoom(roomId);
      }
    } catch {}
    return !!room.hasEncryptionStateEvent?.();
  }

  /**
   * Joined-member Matrix user ids for a room, read from the local sync cache.
   * The browser counterpart to the Node client's /members fetch; used by the
   * SubnetClient room-trust gate. Returns [] when the room isn't in cache yet.
   */
  async _getRoomMembers(roomId) {
    const room = this.client.getRoom(roomId);
    if (!room) return [];
    return (room.getJoinedMembers?.() || []).map((m) => m.userId).filter(Boolean);
  }

  /**
   * Build the `displayName` map used by readMessages projection. Matches the
   * Node version's behaviour: best-effort from the room's joined members.
   */
  _getRoomDisplayNames(roomId) {
    const room = this.client.getRoom(roomId);
    const map = new Map();
    if (!room) return map;
    const members = room.getJoinedMembers?.() || [];
    for (const m of members) {
      if (m.userId) map.set(m.userId, m.rawDisplayName || m.name || null);
    }
    return map;
  }

  _computeCutoffMs(opts) {
    if (typeof opts.sinceCutoffMs === 'number') return opts.sinceCutoffMs;
    if (typeof opts.sinceMinsAgo === 'number') {
      return Date.now() - opts.sinceMinsAgo * 60_000;
    }
    return null;
  }

  /**
   * Project a matrix-js-sdk MatrixEvent that's an `m.room.member` change into
   * the status-event shape (mirrors _projectMembershipEvent in matrix_e2e.js).
   * Returns null for transitions we don't surface.
   */
  _projectMatrixMembershipEvent(ev, displayNames) {
    if (ev.getType() !== 'm.room.member') return null;
    const target = ev.getStateKey();
    const content = ev.getContent() || {};
    const prev = ev.getPrevContent?.() || {};
    const newMembership = content.membership;
    const prevMembership = prev.membership;
    if (!target || !newMembership) return null;

    let kind = null;
    if (newMembership === 'join' && prevMembership !== 'join') kind = 'join';
    else if (newMembership === 'invite') kind = 'invite';
    else if (newMembership === 'ban') kind = 'ban';
    else if (newMembership === 'leave') {
      if (prevMembership === 'ban') kind = 'unban';
      else if (prevMembership === 'invite' && ev.getSender() === target) kind = 'invite_rejected';
      else if (ev.getSender() !== target) kind = 'kick';
      else kind = 'leave';
    }
    if (!kind) return null;

    return {
      event_type: 'membership',
      kind,
      event_id: ev.getId(),
      sender: ev.getSender(),
      sender_display_name: displayNames.get(ev.getSender()) || null,
      target_user: target,
      target_display_name: content.displayname || displayNames.get(target) || null,
      reason: content.reason || null,
      timestamp: ev.getTs(),
    };
  }

  /**
   * Project a matrix-js-sdk MatrixEvent (already decrypted by the SDK if it
   * could be) into the same message shape lib/matrix_e2e.js produces.
   */
  _projectMatrixEvent(ev, displayNames) {
    const type = ev.getType();
    const content = ev.getContent() || {};
    const sender = ev.getSender();
    const ts = ev.getTs();
    const eventId = ev.getId();

    // A redacted (deleted) event has its content stripped. For encrypted rooms
    // it reverts to a bare m.room.encrypted event, so without this guard it would
    // be projected as an "[unable to decrypt]" placeholder instead of vanishing.
    if (ev.isRedacted?.()) return null;

    // An m.replace (edit) event is aggregation metadata, not a timeline row —
    // matrix-js-sdk folds its m.new_content into the original event's getContent().
    if (content['m.relates_to']?.rel_type === 'm.replace') return null;

    // Encrypted-but-undecrypted: matrix-js-sdk surfaces this as a
    // type === 'm.room.encrypted' event with a decryption error.
    if (type === 'm.room.encrypted' || ev.isDecryptionFailure?.()) {
      return {
        event_id: eventId,
        sender,
        display_name: displayNames.get(sender) || null,
        body: '[unable to decrypt]',
        timestamp: ts,
      };
    }
    if (type !== 'm.room.message') return null;

    const msgtype = content.msgtype;
    // m.notice (bots/automation) and m.emote render the same as m.text — a body
    // with optional thread/reply relations. Without this they'd be dropped to
    // null and vanish from the timeline and threads entirely.
    if (msgtype === 'm.text' || msgtype === 'm.notice' || msgtype === 'm.emote') {
      const result = {
        event_id: eventId,
        sender,
        display_name: displayNames.get(sender) || null,
        body: content.body,
        msgtype,
        timestamp: ts,
      };
      const rel = content['m.relates_to'];
      if (rel) {
        if (rel.rel_type === 'm.thread') {
          result.thread_id = rel.event_id;
          if (rel['m.in_reply_to']?.event_id) result.reply_to = rel['m.in_reply_to'].event_id;
        } else if (rel['m.in_reply_to']?.event_id) {
          result.reply_to = rel['m.in_reply_to'].event_id;
        }
      }
      return result;
    }

    const FILE_TYPES = ['m.file', 'm.image', 'm.video', 'm.audio'];
    if (FILE_TYPES.includes(msgtype)) {
      const mxcUrl = content.url || content.file?.url || null;
      const filename = content.filename || content.body || 'file';
      const mimetype = content.info?.mimetype || content.file?.mimetype || null;
      const isEncrypted = !content.url && !!content.file;
      const attachment = { msgtype, mxc_url: mxcUrl, filename, mimetype, encrypted: isEncrypted };
      if (isEncrypted && content.file) attachment.encrypt_info = content.file;
      const fileResult = {
        event_id: eventId,
        sender,
        display_name: displayNames.get(sender) || null,
        body: `[${msgtype.replace('m.', '')}: ${filename}]`,
        timestamp: ts,
        attachment,
      };
      const rel = content['m.relates_to'];
      if (rel) {
        if (rel.rel_type === 'm.thread') {
          fileResult.thread_id = rel.event_id;
          if (rel['m.in_reply_to']?.event_id) fileResult.reply_to = rel['m.in_reply_to'].event_id;
        } else if (rel['m.in_reply_to']?.event_id) {
          fileResult.reply_to = rel['m.in_reply_to'].event_id;
        }
      }
      return fileResult;
    }
    return null;
  }

  /**
   * Walk a room's timeline backward, calling scrollback() until we have
   * enough events to satisfy the requested limit/cutoff. matrix-js-sdk
   * decrypts events in place as they enter the timeline; we still wait a
   * short settle interval per page to give the megolm pipeline a chance
   * before we project.
   */
  async _collectTimelineEvents(roomId, opts) {
    const SAFETY_CAP_EVENTS = 5000;
    const PAGE_SIZE = 100;
    const sdk = await this._loadSdk();
    const { TimelineWindow, EventTimeline } = sdk;
    const room = this.client.getRoom(roomId);
    if (!room) throw new Error(`Unknown room: ${roomId}`);

    const userLimit = opts.limit && opts.limit > 0 ? opts.limit : null;
    const cutoffMs = this._computeCutoffMs(opts);
    const oldContextCount = opts.oldContextCount && opts.oldContextCount > 0 ? opts.oldContextCount : 0;
    const wantOldContext = oldContextCount > 0 && cutoffMs !== null;

    // Walk history through a TimelineWindow rather than scrollback(). scrollback()
    // only ever grows room.getLiveTimeline(); when a "limited" sync splits the room
    // into multiple timelines — the root cause of a chunk going missing in the
    // middle of a channel — the older segment is stranded in a detached timeline
    // that getLiveTimeline().getEvents() never returns, and scrollback reports "no
    // more history" at the seam. A TimelineWindow paginates across those joins via
    // paginateEventTimeline, so the span it returns is contiguous across gaps.
    // windowLimit is raised to the safety cap so extending backwards never evicts
    // the newest events off the front.
    const win = new TimelineWindow(this.client, room.getUnfilteredTimelineSet(), {
      windowLimit: SAFETY_CAP_EVENTS,
    });
    await win.load(undefined, PAGE_SIZE);

    while (win.getEvents().length < SAFETY_CAP_EVENTS) {
      const events = win.getEvents();
      let textCount = 0;
      let oldTextCount = 0;
      let oldestTs = Infinity;
      for (const ev of events) {
        const t = ev.getType();
        if (t === 'm.room.message' || t === 'm.room.encrypted') {
          textCount++;
          const ts = ev.getTs();
          if (cutoffMs !== null && ts < cutoffMs) oldTextCount++;
          if (ts < oldestTs) oldestTs = ts;
        }
      }

      if (cutoffMs !== null) {
        if (wantOldContext) {
          if (oldTextCount >= oldContextCount) break;
        } else if (oldestTs < cutoffMs) {
          break;
        }
      } else if (userLimit === null) {
        // No cutoff and no limit isn't a real request shape, but guard against an
        // unbounded walk just in case.
        break;
      }
      if (userLimit !== null && textCount >= userLimit) break;

      if (!win.canPaginate(EventTimeline.BACKWARDS)) break;
      const grew = await win.paginate(EventTimeline.BACKWARDS, PAGE_SIZE);
      if (!grew) break;
    }

    // Give straggler decryption a moment to land before projecting.
    await new Promise((r) => setTimeout(r, 250));
    return win.getEvents();
  }

  // ── Public API: reads ─────────────────────────────────────────────────────

  async readMessages(roomId, opts = {}) {
    this._requireClient();
    const cutoffMs = this._computeCutoffMs(opts);
    const oldContextCount = opts.oldContextCount && opts.oldContextCount > 0 ? opts.oldContextCount : 0;
    const wantOldContext = oldContextCount > 0 && cutoffMs !== null;

    const events = await this._collectTimelineEvents(roomId, opts);
    const displayNames = this._getRoomDisplayNames(roomId);

    // Aggregate reactions (m.reaction / m.annotation) by the event they target,
    // so each projected message carries its current reaction tallies. Redacted
    // (removed) reactions are skipped. my_event_id lets the caller un-react.
    const reactionsByTarget = new Map();
    for (const ev of events) {
      if (ev.getType() !== 'm.reaction' || ev.isRedacted?.()) continue;
      const rel = (ev.getContent() || {})['m.relates_to'];
      if (!rel || rel.rel_type !== 'm.annotation' || !rel.event_id || !rel.key) continue;
      let byKey = reactionsByTarget.get(rel.event_id);
      if (!byKey) { byKey = new Map(); reactionsByTarget.set(rel.event_id, byKey); }
      let agg = byKey.get(rel.key);
      if (!agg) { agg = { key: rel.key, count: 0, mine: false, my_event_id: null }; byKey.set(rel.key, agg); }
      agg.count += 1;
      if (ev.getSender() === this.userId) { agg.mine = true; agg.my_event_id = ev.getId(); }
    }

    const newMessages = [];
    const olderMessages = [];
    const statusEvents = [];
    const olderStatusEvents = [];
    for (const ev of events) {
      const isOlder = cutoffMs !== null && ev.getTs() < cutoffMs;
      if (isOlder && !wantOldContext) continue;
      if (ev.getType() === 'm.room.member') {
        const status = this._projectMatrixMembershipEvent(ev, displayNames);
        if (!status) continue;
        if (isOlder) olderStatusEvents.push(status);
        else statusEvents.push(status);
        continue;
      }
      const msg = this._projectMatrixEvent(ev, displayNames);
      if (!msg) continue;
      const rx = reactionsByTarget.get(msg.event_id);
      if (rx && rx.size > 0) msg.reactions = Array.from(rx.values());
      if (isOlder) olderMessages.push(msg);
      else newMessages.push(msg);
    }

    // Trim to userLimit (newest-first cut, matching the Node version).
    const userLimit = opts.limit && opts.limit > 0 ? opts.limit : null;
    const trimmed = userLimit !== null ? newMessages.slice(-userLimit) : newMessages;

    if (wantOldContext) {
      return {
        messages: trimmed,
        old_context: olderMessages.slice(-oldContextCount),
        status_events: statusEvents,
        old_status_context: olderStatusEvents.slice(-oldContextCount),
        end: null, // matrix-js-sdk hides the pagination token; callers don't typically need it
      };
    }
    return { messages: trimmed, status_events: statusEvents, end: null };
  }

  async readAllMessages(opts = {}) {
    const roomIds = await this.listJoinedRooms();
    const rooms = {};
    for (const roomId of roomIds) {
      try {
        rooms[roomId] = await this.readMessages(roomId, opts);
      } catch (e) {
        rooms[roomId] = { messages: [], error: e.message };
      }
    }
    return { rooms };
  }

  // Register a Matrix read marker (fully-read + public read receipt) up to
  // `eventId`. Best-effort: a homeserver that rejects it (or is briefly down)
  // must never break the read flow, so failures are swallowed.
  async _sendReadMarker(roomId, eventId) {
    try {
      await this.client.http.authedRequest(
        'POST',
        `/rooms/${encodeURIComponent(roomId)}/read_markers`,
        undefined,
        { 'm.fully_read': eventId, 'm.read': eventId },
      );
    } catch (e) {
      // non-fatal — the local checkpoint is still the source of truth
    }
  }

  async readAllNewMessages(opts = {}) {
    const OLD_CONTEXT_COUNT = 10;
    const defaultLookbackDays = opts.defaultLookbackDays ?? 2;
    const markAsRead =
      opts.markAsRead ?? opts.mark_as_read ?? opts.advanceCheckpoint;
    const advanceCheckpoint = markAsRead !== false;
    // The local fetch cursor and the server-side read marker are separate
    // concerns: a background poll wants to advance the cursor (so it only
    // re-fetches truly new events) WITHOUT claiming the user has read them.
    // Callers that mean "the user has seen everything up to now" leave
    // sendReadMarker default (true); a poll passes sendReadMarker:false and
    // drives the read marker explicitly via markRoomRead instead.
    const sendReadMarker = opts.sendReadMarker !== false;
    const defaultLookbackMs = defaultLookbackDays * 24 * 60 * 60 * 1000;

    const roomIds = await this.listJoinedRooms();
    const rooms = {};

    for (const roomId of roomIds) {
      try {
        const checkpoint = this.kv.getCheckpoint(roomId);
        const cutoffMs = checkpoint !== null ? checkpoint : Date.now() - defaultLookbackMs;
        const {
          messages: newMessages,
          old_context: oldContext,
          status_events: statusEvents = [],
          old_status_context: oldStatusContext = [],
        } = await this.readMessages(roomId, {
          sinceCutoffMs: cutoffMs + 1,
          oldContextCount: OLD_CONTEXT_COUNT,
        });
        const newestMsg = newMessages.length ? newMessages[newMessages.length - 1] : null;
        const newestStatus = statusEvents.length ? statusEvents[statusEvents.length - 1] : null;
        const newestTs = Math.max(newestMsg?.timestamp || 0, newestStatus?.timestamp || 0);
        if (advanceCheckpoint && newestTs > 0) {
          this.kv.setCheckpoint(roomId, newestTs);
          // Mirror the checkpoint as a Matrix read marker so the homeserver's
          // own unread/notification counts track what we consider read. The
          // event whose timestamp defined newestTs is the newest one read.
          if (sendReadMarker) {
            const newestEvent = (newestStatus?.timestamp || 0) > (newestMsg?.timestamp || 0) ? newestStatus : newestMsg;
            if (newestEvent?.event_id) await this._sendReadMarker(roomId, newestEvent.event_id);
          }
        } else if (advanceCheckpoint && checkpoint === null) {
          this.kv.setCheckpoint(roomId, cutoffMs);
        }
        const room = this.client.getRoom(roomId);
        const name = room?.name || null;
        const topic = room?.currentState?.getStateEvents?.('m.room.topic', '')?.getContent()?.topic || null;
        rooms[roomId] = {
          room_id: roomId,
          name,
          topic,
          checkpoint_ms: cutoffMs,
          new_messages: newMessages,
          old_context: oldContext,
          status_events: statusEvents,
          old_status_context: oldStatusContext,
        };
      } catch (e) {
        rooms[roomId] = {
          room_id: roomId,
          name: null,
          topic: null,
          new_messages: [],
          old_context: [],
          status_events: [],
          old_status_context: [],
          error: e.message,
        };
      }
    }

    let pending_invites = [];
    try {
      pending_invites = await this.listInvites();
    } catch {}

    return { rooms, pending_invites };
  }

  // Mark a room read up to `eventId` server-side (fully-read + read receipt), so
  // the read position follows the account across devices. When `eventId` is
  // omitted the newest event currently in the room's live timeline is used.
  async markRoomRead(roomId, eventId) {
    let target = eventId;
    if (!target) {
      const room = this.client.getRoom(roomId);
      const events = room?.getLiveTimeline?.()?.getEvents?.() || [];
      target = events.length ? events[events.length - 1].getId() : null;
    }
    if (!target) return;
    await this._sendReadMarker(roomId, target);
  }

  // Read back each joined room's server read marker. Returns a map keyed by room
  // id of { event_id, timestamp } where timestamp is the marked event's
  // origin_server_ts if it is loaded in the timeline (null otherwise). Used at
  // login to seed local unread state from server-side read receipts.
  async getRoomReadMarkers() {
    const roomIds = await this.listJoinedRooms();
    const out = {};
    for (const roomId of roomIds) {
      const room = this.client.getRoom(roomId);
      if (!room) continue;
      const eventId = room.getEventReadUpTo(this.userId);
      if (!eventId) continue;
      // The local timeline only holds the most recent events, so a marker that
      // points further back (the user is well behind) won't resolve there;
      // fall back to fetching the event. origin_server_ts is cleartext even in
      // encrypted rooms, so this works without decryption.
      let timestamp = room.findEventById?.(eventId)?.getTs?.() ?? null;
      if (timestamp === null) {
        try {
          const raw = await this.client.fetchRoomEvent(roomId, eventId);
          timestamp = raw?.origin_server_ts ?? null;
        } catch {
          timestamp = null;
        }
      }
      out[roomId] = { event_id: eventId, timestamp };
    }
    return out;
  }

  // ── Public API: sends ─────────────────────────────────────────────────────

  async sendMessage(roomId, text, opts = {}) {
    this._requireClient();
    const historyLimit = opts.historyLimit || 50;

    // Pull recent text history to build the accountability transcript. We
    // hit /messages directly so the result mirrors the Node side exactly
    // (timeline-derived history can include events that haven't decrypted
    // yet, which would silently corrupt the signed transcript).
    const params = { dir: 'b', limit: String(historyLimit) };
    const historyData = await this.client.http.authedRequest(
      'GET',
      `/rooms/${encodeURIComponent(roomId)}/messages`,
      params,
    );
    const historyEvents = (historyData.chunk || [])
      .filter((e) => e.type === 'm.room.message' && e.content?.msgtype === 'm.text')
      .reverse()
      .map((e) => ({ sender: e.sender, body: e.content.body }));

    const signed = await signMessage(this._signingHandle(), historyEvents, text, this.userId);
    const htmlBody = (await getMarked()).parse(text);
    const accountability = {
      prev_conv: signed.prev_conv_sign,
      with_reply: signed.with_reply_sign,
      reply_only: signed.reply_only_sign,
    };
    if (this.delegation) accountability.delegation = this.delegation;
    const content = {
      msgtype: opts.msgtype || 'm.text',
      body: text,
      format: 'org.matrix.custom.html',
      formatted_body: htmlBody,
      [ACCOUNTABILITY_FIELD]: accountability,
    };

    if (opts.threadRootId) {
      // Threads are flat (MSC3440): a thread root must not itself be a threaded
      // message. If the caller targets a message that is already in a thread,
      // walk up to that thread's canonical root so we post into the existing
      // thread instead of creating a "thread within a thread". in_reply_to still
      // points at the message the caller actually replied to.
      let rootId = opts.threadRootId;
      const room = this.client.getRoom(roomId);
      const seen = new Set();
      for (let i = 0; i < 20 && rootId && !seen.has(rootId); i++) {
        seen.add(rootId);
        const ev = room && room.findEventById ? room.findEventById(rootId) : null;
        const rel = ev ? (ev.getContent() || {})['m.relates_to'] : null;
        if (rel && rel.rel_type === 'm.thread' && rel.event_id) rootId = rel.event_id;
        else break;
      }
      content['m.relates_to'] = {
        rel_type: 'm.thread',
        event_id: rootId,
        is_falling_back: true,
        'm.in_reply_to': { event_id: opts.replyToEventId || opts.threadRootId },
      };
    } else if (opts.replyToEventId) {
      content['m.relates_to'] = {
        'm.in_reply_to': { event_id: opts.replyToEventId },
      };
    }

    // matrix-js-sdk encrypts transparently for rooms with m.room.encryption.
    const result = await this.client.sendEvent(roomId, 'm.room.message', content);
    return {
      event_id: result.event_id,
      accountability: { message: signed.message, message_with_sign: signed.message_with_sign },
    };
  }

  async sendReaction(roomId, eventId, key) {
    this._requireClient();
    if (!roomId || !eventId || !key) {
      throw new Error('sendReaction requires roomId, eventId, and key');
    }
    const content = {
      'm.relates_to': { rel_type: 'm.annotation', event_id: eventId, key },
    };
    const result = await this.client.sendEvent(roomId, 'm.reaction', content);
    return { event_id: result.event_id };
  }

  // ── Public API: rooms ─────────────────────────────────────────────────────

  async listPublicRooms() {
    this._requireClient();
    return this.client.publicRooms({});
  }

  async listJoinedRooms() {
    this._requireClient();
    const res = await this.client.getJoinedRooms();
    return res.joined_rooms || [];
  }

  /**
   * Like listJoinedRooms() but also includes a clear-text name and topic
   * for each room. The browser variant reads from matrix-js-sdk's local
   * Room cache (populated on the first /sync), so this is a single
   * round-trip cost regardless of room count.
   *
   * @returns {Promise<Array<{room_id: string, name: string|null, topic: string|null}>>}
   */
  async listJoinedRoomsWithNames() {
    this._requireClient();
    const ids = await this.listJoinedRooms();
    return ids.map((roomId) => {
      const room = this.client.getRoom(roomId);
      const topic = room?.currentState?.getStateEvents?.('m.room.topic', '')?.getContent?.()?.topic || null;
      const createEv = room?.currentState?.getStateEvents?.('m.room.create', '');
      const createType = createEv?.getContent?.()?.type || null;
      const avatarEv = room?.currentState?.getStateEvents?.('m.room.avatar', '');
      const avatarUrl = avatarEv?.getContent?.()?.url || null;
      const parentEvents = room?.currentState?.getStateEvents?.('m.space.parent') || [];
      const parentSpaces = (Array.isArray(parentEvents) ? parentEvents : [parentEvents])
        .filter(Boolean)
        .filter((ev) => ev.getContent && Object.keys(ev.getContent() || {}).length > 0)
        .map((ev) => ev.getStateKey?.() || null)
        .filter(Boolean);
      return {
        room_id: roomId,
        name: room?.name || null,
        topic,
        avatar_url: avatarUrl,
        is_space: createType === 'm.space',
        room_type: createType || null,
        parent_spaces: parentSpaces,
      };
    });
  }

  /**
   * Fetch a Matrix profile (displayname + avatar mxc) for any user.
   * @param {string} userId
   */
  async getProfile(userId) {
    this._requireClient();
    try {
      const data = await this.client.getProfileInfo(userId);
      return {
        displayname: data?.displayname || null,
        avatar_url: data?.avatar_url || null,
      };
    } catch (e) {
      if (e?.errcode === 'M_NOT_FOUND' || e?.httpStatus === 404) {
        return { displayname: null, avatar_url: null };
      }
      throw e;
    }
  }

  /**
   * Search the homeserver's user directory.
   * Browser variant delegates to matrix-js-sdk's `searchUserDirectory`.
   *
   * @param {string} searchTerm
   * @param {number} [limit=20]
   * @returns {Promise<{results: Array, limited: boolean}>}
   */
  async searchUserDirectory(searchTerm, limit = 20) {
    this._requireClient();
    return this.client.searchUserDirectory({ term: String(searchTerm || ''), limit });
  }

  async listInvites() {
    this._requireClient();
    const rooms = this.client.getRooms?.() || [];
    const invites = [];
    for (const room of rooms) {
      const myMembership = room.getMyMembership?.();
      if (myMembership !== 'invite') continue;
      const inviteState = room.currentState?.getStateEvents?.('m.room.member', this.userId);
      const inviter = inviteState?.getSender?.() || null;
      const isDirect = inviteState?.getContent?.()?.is_direct === true
        || (typeof room.getDMInviter === 'function' && !!room.getDMInviter());
      const name = room.name || null;
      const topicEv = room.currentState?.getStateEvents?.('m.room.topic', '');
      const topic = topicEv?.getContent?.()?.topic || null;
      const createEv = room.currentState?.getStateEvents?.('m.room.create', '');
      const createType = createEv?.getContent?.()?.type || null;
      invites.push({
        roomId: room.roomId,
        name,
        topic,
        inviter,
        is_space: createType === 'm.space',
        room_type: createType || null,
        is_direct: isDirect,
      });
    }
    return invites;
  }

  async joinRoom(roomId) {
    this._requireClient();
    const room = await this.client.joinRoom(roomId);
    // No explicit key-share priming step needed — matrix-js-sdk's
    // background sync drains to_device events and tracks devices for
    // E2E rooms automatically.
    return { room_id: room.roomId };
  }

  async acceptInvite(roomId, opts = {}) {
    let isDirect = !!opts.is_direct;
    let peerUserId = opts.peerUserId || null;
    if (!opts.skipDirectSync) {
      try {
        const invites = await this.listInvites();
        const match = invites.find((i) => i.roomId === roomId);
        if (match) {
          if (match.is_direct) isDirect = true;
          if (!peerUserId && match.inviter) peerUserId = match.inviter;
        }
      } catch (_e) {
        // best-effort
      }
    }
    const result = await this.joinRoom(roomId);
    if (isDirect && peerUserId) {
      try {
        await this._addDirect(peerUserId, roomId);
      } catch (_e) {
        // non-fatal
      }
    }
    return result;
  }

  async rejectInvite(roomId) {
    this._requireClient();
    return this.client.leave(roomId);
  }

  async createRoom(opts = {}) {
    this._requireClient();
    const visibility = opts.visibility || 'private';
    const preset = opts.preset || (visibility === 'public' ? 'public_chat' : 'private_chat');
    const encrypted = opts.encrypted !== false;
    const body = { visibility, preset };
    if (opts.name) body.name = opts.name;
    if (opts.topic) body.topic = opts.topic;
    if (Array.isArray(opts.invite) && opts.invite.length) body.invite = opts.invite;
    if (opts.is_direct) body.is_direct = true;
    if (encrypted) {
      body.initial_state = [
        { type: 'm.room.encryption', state_key: '', content: { algorithm: 'm.megolm.v1.aes-sha2' } },
      ];
    }
    return this.client.createRoom(body);
  }

  async getDirects() {
    this._requireClient();
    const ev = this.client.getAccountData?.('m.direct');
    const content = ev?.getContent ? ev.getContent() : (ev || {});
    const out = {};
    for (const [peer, rooms] of Object.entries(content || {})) {
      if (Array.isArray(rooms)) out[peer] = rooms.filter((r) => typeof r === 'string');
    }
    return out;
  }

  async setDirects(directs) {
    this._requireClient();
    const body = {};
    for (const [peer, rooms] of Object.entries(directs || {})) {
      if (Array.isArray(rooms) && rooms.length) {
        body[peer] = Array.from(new Set(rooms.filter((r) => typeof r === 'string')));
      }
    }
    return this.client.setAccountData('m.direct', body);
  }

  async _addDirect(peerUserId, roomId) {
    const directs = await this.getDirects();
    const list = directs[peerUserId] || [];
    if (!list.includes(roomId)) {
      directs[peerUserId] = [...list, roomId];
      await this.setDirects(directs);
    }
    return directs;
  }

  async openDmWith(peerUserId, opts = {}) {
    if (!peerUserId || !peerUserId.startsWith('@')) {
      throw new Error('openDmWith: peerUserId must be a full Matrix ID like @bob:server');
    }
    const directs = await this.getDirects();
    const existing = directs[peerUserId] || [];
    for (const roomId of existing) {
      const room = this.client.getRoom?.(roomId);
      const membership = room?.getMyMembership?.();
      if (membership === 'join' || membership === 'invite') {
        return { room_id: roomId, reused: true };
      }
    }
    const created = await this.createRoom({
      visibility: 'private',
      preset: 'trusted_private_chat',
      invite: [peerUserId],
      encrypted: opts.encrypted !== false,
      is_direct: true,
    });
    await this._addDirect(peerUserId, created.room_id);
    return { room_id: created.room_id, reused: false };
  }

  async createSpace(opts = {}) {
    this._requireClient();
    const visibility = opts.visibility || 'private';
    const body = {
      visibility,
      preset: visibility === 'public' ? 'public_chat' : 'private_chat',
      creation_content: { type: 'm.space' },
    };
    if (opts.name) body.name = opts.name;
    if (opts.topic) body.topic = opts.topic;
    if (Array.isArray(opts.invite) && opts.invite.length) body.invite = opts.invite;
    if (Array.isArray(opts.children) && opts.children.length) {
      const serverName = this._serverNameFromUserId();
      body.initial_state = opts.children.map((childId) => ({
        type: 'm.space.child',
        state_key: childId,
        content: { via: [serverName] },
      }));
    }
    return this.client.createRoom(body);
  }

  async inviteUser(roomId, userId) {
    this._requireClient();
    return this.client.invite(roomId, userId);
  }

  // ── Room administration (rename / kick) ──────────────────────────────────

  /**
   * Rename a room by writing its `m.room.name` state event. Requires power
   * level >= the room's `m.room.name` event level (see getRoomManagementInfo).
   */
  async setRoomName(roomId, name) {
    this._requireClient();
    return this.client.setRoomName(roomId, name);
  }

  /**
   * Kick a user from a room. Requires power level >= the room's `kick` level
   * and strictly greater than the target's level.
   */
  async kickUser(roomId, userId, reason) {
    this._requireClient();
    return this.client.kick(roomId, userId, reason);
  }

  /**
   * Snapshot of a room's manageable state for a "manage channel" UI: the
   * current name, your effective power level, and each joined/invited member
   * with their power level plus whether *you* may rename the room or kick
   * them. Read entirely from the local sync cache — no round trips.
   *
   * @returns {Promise<{room_id: string, name: string|null, my_user_id: string|null,
   *   my_power_level: number, kick_level: number, name_level: number,
   *   can_rename: boolean, can_kick_any: boolean,
   *   members: Array<{user_id: string, display_name: string|null, avatar_url: string|null,
   *     membership: string, power_level: number, can_kick: boolean}>}>}
   */
  async getRoomManagementInfo(roomId) {
    this._requireClient();
    const room = this.client.getRoom(roomId);
    if (!room) throw new Error(`Room not found in local state: ${roomId}`);
    const plEvent = room.currentState?.getStateEvents?.('m.room.power_levels', '');
    const pl = plEvent?.getContent?.() || {};
    const users = pl.users || {};
    const usersDefault = Number.isFinite(pl.users_default) ? pl.users_default : 0;
    const stateDefault = Number.isFinite(pl.state_default) ? pl.state_default : 50;
    const kickLevel = Number.isFinite(pl.kick) ? pl.kick : 50;
    const nameLevel = Number.isFinite(pl.events?.['m.room.name']) ? pl.events['m.room.name'] : stateDefault;
    const myId = this.userId;
    const levelOf = (uid) => (Number.isFinite(users[uid]) ? users[uid] : usersDefault);
    const myLevel = levelOf(myId);
    const members = (room.getMembers?.() || [])
      .filter((m) => m.membership === 'join' || m.membership === 'invite')
      .map((m) => {
        const level = levelOf(m.userId);
        return {
          user_id: m.userId,
          display_name: m.name || m.rawDisplayName || null,
          avatar_url: m.getMxcAvatarUrl?.() || null,
          membership: m.membership,
          power_level: level,
          can_kick: m.userId !== myId && myLevel >= kickLevel && myLevel > level,
        };
      })
      .sort((a, b) => b.power_level - a.power_level
        || (a.display_name || a.user_id).localeCompare(b.display_name || b.user_id));
    return {
      room_id: roomId,
      name: room.name || null,
      my_user_id: myId,
      my_power_level: myLevel,
      kick_level: kickLevel,
      name_level: nameLevel,
      can_rename: myLevel >= nameLevel,
      can_kick_any: myLevel >= kickLevel,
      members,
    };
  }

  async addRoomToSpace(spaceId, childRoomId, opts = {}) {
    this._requireClient();
    const content = { via: opts.via || [this._serverNameFromUserId()] };
    if (opts.suggested) content.suggested = true;
    if (opts.order) content.order = opts.order;
    return this.client.sendStateEvent(spaceId, 'm.space.child', content, childRoomId);
  }

  async removeRoomFromSpace(spaceId, childRoomId) {
    this._requireClient();
    return this.client.sendStateEvent(spaceId, 'm.space.child', {}, childRoomId);
  }

  async listSpaceChildren(spaceId) {
    this._requireClient();
    const room = this.client.getRoom(spaceId);
    if (!room) return [];
    const events = room.currentState?.getStateEvents?.('m.space.child') || [];
    const arr = Array.isArray(events) ? events : [events];
    const out = [];
    for (const ev of arr) {
      if (!ev) continue;
      const content = ev.getContent?.() || {};
      if (!Object.keys(content).length) continue;
      const stateKey = ev.getStateKey?.();
      if (!stateKey) continue;
      out.push({
        room_id: stateKey,
        via: content.via || [],
        suggested: !!content.suggested,
        order: content.order || null,
      });
    }
    return out;
  }

  _serverNameFromUserId() {
    if (!this.userId) return '';
    const at = this.userId.indexOf(':');
    return at === -1 ? '' : this.userId.slice(at + 1);
  }

  async leaveRoom(roomId) {
    this._requireClient();
    await this.client.leave(roomId);
    try {
      await this.client.forget(roomId);
    } catch (e) {
      if (e.httpStatus !== 404 && e.errcode !== 'M_NOT_FOUND') throw e;
    }
    return { room_id: roomId, left: true };
  }

  /**
   * matrix-js-sdk syncs continuously in the background, so an explicit
   * "sync now" is mostly a no-op. Returning a small status object keeps
   * the API symmetric with the Node version.
   */
  async sync() {
    this._requireClient();
    return { ok: true, syncState: this.client.getSyncState?.() || null };
  }

  // ── Public API: profile ───────────────────────────────────────────────────

  async setDisplayName(displayName) {
    this._requireClient();
    return this.client.setDisplayName(displayName);
  }

  async setAvatarUrl(mxcUrl) {
    this._requireClient();
    return this.client.setAvatarUrl(mxcUrl);
  }

  // ── Public API: media ─────────────────────────────────────────────────────

  /**
   * Upload bytes to the media repository.
   * Accepts Blob, File, ArrayBuffer, or Uint8Array. (Buffer is a Uint8Array
   * subclass on Node, which would also work — but on browser, callers
   * typically have a Blob/File from <input type=file>.)
   */
  async uploadMedia(data, contentType, filename) {
    this._requireClient();
    let body = data;
    if (data instanceof ArrayBuffer) body = new Blob([data], { type: contentType });
    else if (data && data.buffer instanceof ArrayBuffer && !(data instanceof Blob)) {
      body = new Blob([data], { type: contentType });
    }
    const res = await this.client.uploadContent(body, {
      type: contentType,
      name: filename,
      rawResponse: false,
    });
    // matrix-js-sdk normalizes to { content_uri }
    return { content_uri: res.content_uri };
  }

  async downloadMedia(mxcUrl) {
    this._requireClient();
    // Prefer the authenticated media endpoint (Matrix 1.11 / MSC3916,
    // /_matrix/client/v1/media/download). Servers like Tuwunel always enable
    // it and disable the legacy /_matrix/media/v3/download by default. The 7th
    // arg of mxcUrlToHttp is useAuthentication. Fall back to the legacy
    // endpoint for older homeservers that lack the v1 route.
    const authUrl = this.client.mxcUrlToHttp(mxcUrl, undefined, undefined, undefined, false, true, true);
    const headers = { Authorization: `Bearer ${this.accessToken}` };
    let res = await fetch(authUrl, { headers });
    if (!res.ok && (res.status === 404 || res.status === 400)) {
      const legacyUrl = this.client.mxcUrlToHttp(mxcUrl, undefined, undefined, undefined, false, true, false);
      res = await fetch(legacyUrl, { headers });
    }
    if (!res.ok) throw new Error(`Download failed: ${res.status}`);
    return new Uint8Array(await res.arrayBuffer());
  }

  /**
   * Decrypt a megolm-encrypted file. matrix-js-sdk ships an attachment
   * decryptor that handles AES-CTR + the SHA-256 verification the Node
   * version does by hand.
   */
  async downloadMediaDecrypted(mxcUrl, encryptInfo) {
    this._requireClient();
    const sdk = await this._loadSdk();
    // The attachment decrypt helper lives at different paths across SDK
    // versions; try the modern entry point first, then fall back to the
    // legacy one. Either way it returns a decrypted ArrayBuffer/Uint8Array.
    const attachmentsApi = sdk.attachments || sdk.utils?.attachments || null;
    const ciphertext = await this.downloadMedia(mxcUrl);
    const file = { ...encryptInfo, url: mxcUrl };
    if (attachmentsApi?.decryptAttachment) {
      const out = await attachmentsApi.decryptAttachment(ciphertext.buffer, file);
      return new Uint8Array(out);
    }
    // Last-resort fallback: WebCrypto AES-CTR. Matches the Node version's
    // behaviour 1:1, with sha256 hash verification.
    const b64urlDecode = (s) => {
      const norm = s.replace(/-/g, '+').replace(/_/g, '/');
      const pad = norm.length % 4 === 0 ? '' : '='.repeat(4 - (norm.length % 4));
      const bin = atob(norm + pad);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    };
    if (encryptInfo.hashes?.sha256) {
      const digest = await crypto.subtle.digest('SHA-256', ciphertext);
      const got = btoa(String.fromCharCode(...new Uint8Array(digest)))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      const expected = encryptInfo.hashes.sha256
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      if (got !== expected) throw new Error(`SHA256 hash mismatch: got ${got}, expected ${expected}`);
    }
    const keyBytes = b64urlDecode(encryptInfo.key.k);
    const iv = b64urlDecode(encryptInfo.iv);
    const cryptoKey = await crypto.subtle.importKey(
      'raw', keyBytes, { name: 'AES-CTR' }, false, ['decrypt'],
    );
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-CTR', counter: iv, length: 64 }, cryptoKey, ciphertext,
    );
    return new Uint8Array(plaintext);
  }

  /**
   * Encrypt a file for an E2E room. matrix-js-sdk no longer ships an
   * attachment encryptor (it was split out into matrix-encrypt-attachment),
   * so we do the AES-CTR + SHA-256 here with WebCrypto. This is the inverse of
   * downloadMediaDecrypted() above and produces the spec EncryptedFile info
   * that goes in the event's `file` field (the `url` is filled in after upload).
   *
   * @param {ArrayBuffer|Uint8Array} data - plaintext bytes
   * @returns {Promise<{data: ArrayBuffer, info: object}>}
   */
  async encryptAttachment(data) {
    const plaintext = data instanceof Uint8Array ? data : new Uint8Array(data);
    const keyBytes = crypto.getRandomValues(new Uint8Array(32));
    // 16-byte AES-CTR initial counter: 8 random bytes, low 8 bytes start at 0.
    const iv = new Uint8Array(16);
    iv.set(crypto.getRandomValues(new Uint8Array(8)), 0);
    const cryptoKey = await crypto.subtle.importKey(
      'raw', keyBytes, { name: 'AES-CTR' }, true, ['encrypt'],
    );
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-CTR', counter: iv, length: 64 }, cryptoKey, plaintext,
    ));
    const digest = await crypto.subtle.digest('SHA-256', ciphertext);
    const b64 = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/=+$/, '');
    const b64url = (bytes) => b64(bytes).replace(/\+/g, '-').replace(/\//g, '_');
    const info = {
      v: 'v2',
      key: { kty: 'oct', alg: 'A256CTR', ext: true, k: b64url(keyBytes), key_ops: ['encrypt', 'decrypt'] },
      iv: b64(iv),
      hashes: { sha256: b64(digest) },
    };
    return { data: ciphertext.buffer, info };
  }

  // ── Devices + Verification ────────────────────────────────────────────────
  //
  // Browser path: lean on matrix-js-sdk's full CryptoApi. The Verifier object
  // returned by `requestSelfVerification` follows matrix-js-sdk's contract —
  // the caller (agora) listens for `VerifierEvent.ShowSas` / `ShowReciprocateQr`,
  // calls `getShowSasCallbacks().confirm()` on match, and awaits `verify()`
  // for completion. After SAS confirmation matrix-js-sdk gossips the
  // cross-signing secrets automatically via m.secret.send.

  /**
   * List every Matrix device the logged-in user owns, with verification
   * status. Useful for the "Sessions" UI.
   *
   * Each entry: { deviceId, displayName, lastSeenTs, lastSeenIp,
   *               isThisDevice, verified, crossSigningTrusted, signedByOwner }
   */
  async listOwnDevices() {
    this._requireClient();
    const crypto = this.client.getCrypto?.();
    if (!crypto) return [];
    const map = await crypto.getUserDeviceInfo([this.userId], true).catch(() => null);
    const devices = map?.get?.(this.userId);
    if (!devices) return [];
    const out = [];
    for (const [deviceId, info] of devices.entries()) {
      const status = await crypto.getDeviceVerificationStatus(this.userId, deviceId).catch(() => null);
      out.push({
        deviceId,
        displayName: info.displayName || null,
        isThisDevice: deviceId === this.deviceId,
        verified: !!status?.isVerified?.(),
        crossSigningTrusted: !!status?.crossSigningVerified,
        signedByOwner: !!status?.signedByOwner,
        lastSeenTs: info.lastSeen || null,
      });
    }
    return out.sort((a, b) => (b.isThisDevice ? 1 : 0) - (a.isThisDevice ? 1 : 0));
  }

  /**
   * Initiate a verification with another device of the *same user*. Returns
   * the matrix-js-sdk `VerificationRequest` directly so the UI can drive it
   * (listen for the `Change` event, then `startVerification('m.sas.v1')`
   * or `generateQRCode()` / `scanQRCode()` once the other side is Ready).
   */
  async requestSelfVerification(deviceId) {
    this._requireClient();
    const crypto = this.client.getCrypto?.();
    if (!crypto?.requestDeviceVerification) {
      throw new Error('Crypto unavailable: matrix-js-sdk Rust crypto did not initialize');
    }
    return crypto.requestDeviceVerification(this.userId, deviceId);
  }

  /**
   * Subscribe to incoming verification requests (other devices asking to
   * verify us). Handler is called with the matrix-js-sdk VerificationRequest.
   * Returns an unsubscribe function.
   */
  onIncomingVerification(handler) {
    this._requireClient();
    const crypto = this.client.getCrypto?.();
    if (!crypto?.on) return () => {};
    const evt = 'crypto.verificationRequestReceived';
    const wrapped = (req) => { try { handler(req); } catch (e) { console.warn('[E2E] verification handler threw:', e); } };
    crypto.on(evt, wrapped);
    return () => { try { crypto.off?.(evt, wrapped); } catch {} };
  }

  /**
   * Auto-approve another of our own devices by signing it with our
   * self-signing key — the non-interactive equivalent of completing an SAS
   * verification. Requires this device to already hold the cross-signing
   * private keys (it does once bootstrapCrossSigning has run off SSSS).
   */
  async crossSignDevice(deviceId) {
    this._requireClient();
    const crypto = this.client.getCrypto?.();
    if (!crypto?.crossSignDevice) {
      throw new Error('Crypto unavailable: cannot cross-sign device');
    }
    return crypto.crossSignDevice(deviceId);
  }

  // ── Cross-signing ─────────────────────────────────────────────────────────

  /**
   * The wallet-derived 4S key encoded as a standard Matrix "Security Key" (the
   * base58 string Element's "Enter Security Key" prompt accepts). Paste it into
   * another client — e.g. Element — to unlock secret storage, import this
   * account's cross-signing identity, and restore message-history backup,
   * without needing a second device online. Returns null if no wallet-key
   * deriver is wired in.
   */
  async getSecurityKey() {
    const key = await this._getSecretStorageKey();
    if (!key) return null;
    const sdk = await this._loadSdk();
    return sdk.Crypto.encodeRecoveryKey(key);
  }

  /**
   * Mirror of the Node E2EMatrixClient surface. Re-queries matrix-js-sdk
   * each call so the answer is fresh — `isCrossSigningReady` flips to true
   * as soon as gossip from another device imports the master/SSK/USK
   * private bytes into matrix-js-sdk's crypto store.
   */
  async getCrossSigningStatus() {
    if (!this.client) return { state: 'unknown' };
    const crypto = this.client.getCrypto?.();
    if (!crypto) return this._crossSigningStatus;
    try {
      const hasServerKeys = await crypto.userHasCrossSigningKeys?.(this.userId, true).catch(() => false);
      const ready = await crypto.isCrossSigningReady?.().catch(() => false);
      if (ready) return { state: 'ready' };
      if (hasServerKeys) return { state: 'awaiting_verification' };
      return { state: 'not_set_up' };
    } catch {
      return this._crossSigningStatus;
    }
  }

  // ── Cleanup ───────────────────────────────────────────────────────────────

  async close() {
    if (this.client) {
      try { this.client.stopClient(); } catch {}
      this.client = null;
    }
  }
}

module.exports = { E2EMatrixClient };
