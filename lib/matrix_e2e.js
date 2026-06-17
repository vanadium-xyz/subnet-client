'use strict';
/**
 * E2E-capable Matrix client with persistent device identity.
 *
 * Uses @matrix-org/matrix-sdk-crypto-nodejs (native Rust OlmMachine with SQLite)
 * for E2E encryption/decryption. Session state (userId, deviceId, accessToken)
 * is stored in a JSON file. Crypto state (Olm account, session keys) is stored
 * in a SQLite database — both in storePath.
 *
 * On first run: fresh login, keys uploaded to Synapse.
 * On subsequent runs: same device_id + access_token reused, crypto state loaded.
 */

const path = require('path');
const fs = require('fs');
const os = require('os');
const { signMessage } = require('./accountability');
const { MemoryStore } = require('./memory');
// marked v18 is ESM-only; load it via dynamic import() (cached) so a plain
// require() doesn't emit Node's require(ESM) ExperimentalWarning on every run.
let _markedPromise;
const getMarked = () => (_markedPromise ??= import('marked').then(m => m.marked));
const {
  generateEd25519Keypair,
  loadEd25519Keypair,
  buildSignedCrossSigningKey,
  signDeviceKeys,
} = require('./cross_signing');

const DEFAULT_STATE_DIR = path.join(os.homedir(), '.subnet-client-state');

// How long a whoami-verified session token is trusted before we re-probe
// /account/whoami on cold-spawn. The hot path is "spawn-and-exit per tick";
// re-running whoami every spawn is the dominant login round-trip, but we
// must still notice token revocation eventually. 60 min is a balance: if a
// token is revoked mid-window the next real API call will 401 and the
// caller can clear session.json. Override with SUBNET_WHOAMI_TTL_MS.
const WHOAMI_TTL_MS = (() => {
  const raw = parseInt(process.env.SUBNET_WHOAMI_TTL_MS || '', 10);
  return Number.isFinite(raw) && raw >= 0 ? raw : 60 * 60 * 1000;
})();

// Field name used when sending. The SDK does not inspect this field on
// read — callers can do their own verification if they need to.
const ACCOUNTABILITY_FIELD = 'xyz.vanadium.accountability';

const {
  OlmMachine,
  UserId,
  DeviceId,
  RoomId,
  DeviceLists,
  RequestType,
  EncryptionSettings,
  HistoryVisibility,
} = require('@matrix-org/matrix-sdk-crypto-nodejs');

class E2EMatrixClient {
  /**
   * @param {object} opts
   * @param {string} opts.matrixUrl - Matrix homeserver URL
   * @param {string} opts.privateKey  - Ethereum private key (for accountability signing).
   *   When delegation is enabled at the SubnetClient layer, this is the
   *   delegate's private key, not the main account key.
   * @param {string} [opts.storePath] - Directory for session + crypto state.
   *   Defaults to `$SUBNET_CLIENT_STATE_PATH` or `~/.subnet-client-state`
   *   so the location is stable across working directories.
   * @param {object} [opts.delegation] - Optional delegation envelope attached
   *   to outbound message accountability fields so verifiers can walk back
   *   from the per-message signer to the delegator.
   */
  constructor({ matrixUrl, privateKey, storePath, delegation }) {
    this.matrixUrl = matrixUrl.replace(/\/$/, '');
    this.privateKey = privateKey;
    this.delegation = delegation || null;
    this.storePath = path.resolve(
      storePath || process.env.SUBNET_CLIENT_STATE_PATH || DEFAULT_STATE_DIR,
    );
    this.sessionFile = path.join(this.storePath, 'session.json');
    this.cryptoPath = path.join(this.storePath, 'crypto.sqlite3');
    this.accessToken = null;
    this.userId = null;
    this.deviceId = null;
    this.olmMachine = null;
    this.memoryStore = null;
    // { state: 'unknown'|'ready'|'awaiting_verification'|'mismatch', ... }
    // Filled in by _ensureCrossSigning; read by getCrossSigningStatus().
    this._crossSigningStatus = { state: 'unknown' };
  }

  /**
   * Lazily open the agent memory store (memory.sqlite3 in storePath).
   * Returns the same instance on subsequent calls.
   */
  _getMemoryStore() {
    if (!this.memoryStore) {
      this.memoryStore = new MemoryStore(this.storePath);
    }
    return this.memoryStore;
  }

  // ── On-disk state helpers ────────────────────────────────────────────────────
  // Three small files live in `storePath`:
  //   session.json         — userId / deviceId / accessToken / verifiedAt
  //   cross_signing.json   — the three master/SSK/USK keypairs (mode 0600)
  //   sync_token           — the to-device /sync next_batch (text, one line)

  _readJsonFile(filePath, defaultVal = null) {
    try {
      if (fs.existsSync(filePath)) {
        return JSON.parse(fs.readFileSync(filePath, 'utf8'));
      }
    } catch {}
    return defaultVal;
  }

  _writeJsonFile(filePath, data, opts = {}) {
    fs.mkdirSync(this.storePath, { recursive: true });
    const writeOpts = opts.mode !== undefined ? { mode: opts.mode } : undefined;
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), writeOpts);
  }

  _loadSession() {
    return this._readJsonFile(this.sessionFile);
  }

  _saveSession(data) {
    this._writeJsonFile(this.sessionFile, data);
  }

  // The sync_token is plain text (Synapse next_batch — opaque string), not
  // JSON. Without persisting it, every CLI invocation does a fresh /sync
  // from scratch and can miss to_device events delivered between calls.
  _syncTokenFile() {
    return path.join(this.storePath, 'sync_token');
  }

  _loadSyncToken() {
    try {
      const f = this._syncTokenFile();
      if (fs.existsSync(f)) {
        const t = fs.readFileSync(f, 'utf8').trim();
        return t || null;
      }
    } catch {}
    return null;
  }

  _saveSyncToken(token) {
    if (!token) return;
    try {
      fs.mkdirSync(this.storePath, { recursive: true });
      fs.writeFileSync(this._syncTokenFile(), token);
    } catch {}
  }

  // ── HTTP helpers ─────────────────────────────────────────────────────────────

  /**
   * Single Matrix HTTP transport. Handles auth header, JSON content-type
   * (when not raw), 429 backoff with Retry-After / retry_after_ms, and
   * structured errors (.status, .errcode) on non-2xx.
   *
   * Pass `{ raw: true }` to skip the JSON content-type default and return
   * the raw Response (for binary uploads/downloads). Otherwise the parsed
   * JSON body is returned.
   */
  async _request(urlPath, opts = {}, { raw = false } = {}) {
    const url = `${this.matrixUrl}${urlPath}`;
    const headers = raw
      ? { ...opts.headers }
      : { 'Content-Type': 'application/json', ...opts.headers };
    if (this.accessToken) headers['Authorization'] = `Bearer ${this.accessToken}`;
    const res = await fetch(url, { ...opts, headers });

    if (res.status === 429) {
      const headerSecs = Number(res.headers.get('retry-after'));
      const headerMs = Number.isFinite(headerSecs) ? headerSecs * 1000 : 0;
      let bodyMs = 0;
      try { bodyMs = Number((await res.json()).retry_after_ms) || 0; } catch {}
      const waitMs = Math.min(Math.max(headerMs, bodyMs, 1000) + 500, 60_000);
      await new Promise(r => setTimeout(r, waitMs));
      return this._request(urlPath, opts, { raw });
    }
    if (!res.ok) {
      let data = {};
      try { data = await res.json(); } catch {}
      const err = new Error(data.error || `Matrix API error ${res.status} on ${urlPath}`);
      err.status = res.status;
      err.errcode = data.errcode;
      throw err;
    }
    if (raw) return res;
    try { return await res.json(); } catch { return {}; }
  }

  async _fetch(urlPath, opts = {}) {
    return this._request(urlPath, opts);
  }

  async _fetchRaw(urlPath, opts = {}) {
    return this._request(urlPath, opts, { raw: true });
  }

  // Register a Matrix read marker (fully-read + public read receipt) up to
  // `eventId`. Best-effort: a homeserver that rejects it (or is briefly down)
  // must never break the read flow, so failures are swallowed.
  async _sendReadMarker(roomId, eventId) {
    try {
      await this._fetch(`/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/read_markers`, {
        method: 'POST',
        body: JSON.stringify({ 'm.fully_read': eventId, 'm.read': eventId }),
      });
    } catch (e) {
      // non-fatal — the local checkpoint is still the source of truth
    }
  }

  // Mark a room read up to `eventId` server-side. The node impl has no live
  // timeline to fall back on, so `eventId` is required.
  async markRoomRead(roomId, eventId) {
    if (!eventId) return;
    await this._sendReadMarker(roomId, eventId);
  }

  // Read back server read markers. The node impl keeps no synced Room state, so
  // there is nothing to read locally; callers seed from the checkpoint store.
  async getRoomReadMarkers() {
    return {};
  }

  /**
   * Mint a fresh, independent Matrix session for this account via a new
   * password /login — does NOT touch the current session. Returns
   * { user_id, access_token, device_id }. Used by the QR sign-in handoff
   * to hand a brand-new device its own session.
   */
  async mintSession(username, password, displayName) {
    return this._fetch('/_matrix/client/v3/login', {
      method: 'POST',
      body: JSON.stringify({
        type: 'm.login.password',
        identifier: { type: 'm.id.user', user: username },
        password,
        initial_device_display_name: displayName,
      }),
    });
  }

  /**
   * Build a unique transaction id for client→server PUTs (sendMessage,
   * sendReaction, sendToDevice). Matrix uses txn ids for idempotency:
   * resending the same txn id returns the original event_id rather than
   * creating a duplicate.
   */
  _makeTxnId() {
    return `${Date.now()}_${Math.random().toString(36).slice(2)}`;
  }

  // ── Login & crypto init ──────────────────────────────────────────────────────

  /**
   * Login to Matrix and initialize the OlmMachine.
   *
   * Three states:
   *   1. Stored session is still valid (whoami succeeds) → reuse it as-is.
   *   2. Stored session's access token is dead but we know our device_id →
   *      re-login with `device_id` set so Synapse keeps the same device,
   *      preserving the SQLite crypto store.
   *   3. No prior session at all → fresh login (Synapse mints a new device).
   *
   * The crypto store at `cryptoPath` is permanently bound to the
   * (user_id, device_id) tuple it was first initialized with. If we ever
   * reach OlmMachine.initialize with a *different* device_id than the one
   * the SQLite was created for, the binding throws "the account in the
   * store doesn't match the account in the constructor". This flow exists
   * to make sure that never happens during normal operation.
   */
  async login(username, password, opts = {}) {
    // QR sign-in: caller has obtained a fresh access_token + device_id for
    // this Matrix account on another device. Seed session.json so the
    // existing reuse-stored-token branch picks it up; we won't need
    // the password at all.
    if (opts.bootstrapSession && !this._loadSession()) {
      this._saveSession({
        userId: opts.bootstrapSession.userId,
        deviceId: opts.bootstrapSession.deviceId,
        accessToken: opts.bootstrapSession.accessToken,
        verifiedAt: Date.now(),
      });
    }
    const session = this._loadSession();
    const cryptoStoreExists = fs.existsSync(this.cryptoPath);
    const priorDeviceId = session?.deviceId || null;
    let usedStoredToken = false;
    let isFreshDevice = false;

    // ── 1. Try the stored access token first.
    if (session?.accessToken) {
      this.accessToken = session.accessToken;
      this.userId = session.userId;
      this.deviceId = session.deviceId;

      // Warm-path skip: if whoami succeeded recently (within WHOAMI_TTL_MS),
      // trust the token without re-probing. This is the dominant login
      // round-trip on the per-tick cold-spawn path. If the token has in
      // fact been revoked since verifiedAt, the next real API call will
      // 401 — the caller is expected to discard session.json and retry.
      const verifiedAt = Number(session.verifiedAt) || 0;
      if (WHOAMI_TTL_MS > 0 && verifiedAt && Date.now() - verifiedAt < WHOAMI_TTL_MS) {
        usedStoredToken = true;
      }
      try {
        if (!usedStoredToken) {
          await this._fetch('/_matrix/client/v3/account/whoami');
          usedStoredToken = true;
          this._saveSession({
            userId: this.userId,
            deviceId: this.deviceId,
            accessToken: this.accessToken,
            verifiedAt: Date.now(),
          });
        }
      } catch (e) {
        // Only treat hard-auth failures as "token is dead". Anything else
        // (network blip, 429, 5xx) is transient — propagate it so we never
        // accidentally rotate the device identity over a temporary failure.
        // That rotation is exactly what poisons the SQLite crypto store.
        const tokenDead =
          e.status === 401 ||
          e.status === 403 ||
          e.errcode === 'M_UNKNOWN_TOKEN' ||
          e.errcode === 'M_MISSING_TOKEN' ||
          e.errcode === 'M_UNKNOWN_ACCESS_TOKEN';
        if (!tokenDead) throw e;
        this.accessToken = null;
      }
    }

    // ── 2. If we couldn't reuse the stored token, log in again — but
    //      preserve the device identity when we know it.
    if (!usedStoredToken) {
      // Defensive guard: a SQLite store with no session.json means we
      // can't tell which device the store was created for. Doing a fresh
      // login here would mint a new device and the very next
      // OlmMachine.initialize would fail with a cryptic
      // "account in store doesn't match" error. Fail loudly instead.
      if (cryptoStoreExists && !priorDeviceId) {
        throw new Error(
          `Crypto store exists at ${this.cryptoPath} but session.json is missing — ` +
          `cannot determine which device this store belongs to. Delete the entire ` +
          `state directory (${this.storePath}) to recover. You will lose decryption ` +
          `keys for past encrypted messages.`,
        );
      }

      isFreshDevice = !priorDeviceId;

      const loginBody = {
        type: 'm.login.password',
        identifier: { type: 'm.id.user', user: username },
        password,
        initial_device_display_name: 'subnet-client',
      };
      // Reuse the existing device when we have one. Synapse will rotate
      // the access token but keep the device_id and its uploaded keys.
      if (priorDeviceId) loginBody.device_id = priorDeviceId;

      const data = await this._fetch('/_matrix/client/v3/login', {
        method: 'POST',
        body: JSON.stringify(loginBody),
      });
      this.accessToken = data.access_token;
      this.userId = data.user_id;
      this.deviceId = data.device_id;

      // Sanity check: if we asked the server to reuse our device but it
      // gave us a different one, the SQLite store would be unusable. Bail
      // out before we touch OlmMachine so we don't make things worse.
      if (priorDeviceId && this.deviceId !== priorDeviceId) {
        throw new Error(
          `Login returned device_id ${this.deviceId} but we requested ${priorDeviceId}. ` +
          `The existing crypto store at ${this.cryptoPath} cannot be used with a ` +
          `different device. Delete ${this.storePath} to recover (you will lose ` +
          `decryption keys for past encrypted messages).`,
        );
      }

      this._saveSession({
        userId: this.userId,
        deviceId: this.deviceId,
        accessToken: this.accessToken,
        verifiedAt: Date.now(),
      });
    }

    // Initialize OlmMachine (loads from SQLite if it exists, creates fresh
    // otherwise). By construction, (this.userId, this.deviceId) now matches
    // whatever the SQLite was created for — either because we reused the
    // stored session, or because we forced /login to honor priorDeviceId.
    this.olmMachine = await OlmMachine.initialize(
      new UserId(this.userId),
      new DeviceId(this.deviceId),
      this.cryptoPath,
    );

    // Upload device keys only on a genuinely new device. Refreshing an
    // access token on an existing device leaves the keys in place on the
    // server — the local OlmMachine knows they're already uploaded.
    if (isFreshDevice) {
      // Drains the OlmMachine's initial KeysUpload (device identity keys +
      // one-time keys). _processOutgoing is the same path used for every
      // other key upload; a fresh device queues KeysUpload immediately.
      await this._processOutgoing();
    }

    // Ensure the bot has a cross-signing identity on the server and that
    // this device is signed by it. Without this, Element shows an
    // "unverified device" warning shield next to every message we send.
    // Best-effort: a failure here doesn't break message send/receive,
    // it only leaves the warning shield in place. We swallow the error
    // so a homeserver that requires SSO UIA (or a transient network
    // blip) can't take down the whole client.
    try {
      await this._ensureCrossSigning(password);
    } catch (e) {
      console.warn('[E2E] cross-signing setup skipped:', e.message);
    }

    return { userId: this.userId, deviceId: this.deviceId };
  }

  // ── Key management ───────────────────────────────────────────────────────────

  /**
   * Process all pending outgoing requests from OlmMachine.
   * Handles key uploads, key queries, key claims, and to-device sends.
   */
  async _processOutgoing() {
    const requests = await this.olmMachine.outgoingRequests();
    for (const req of requests) {
      try {
        await this._handleOutgoingRequest(req);
      } catch (e) {
        console.warn('[E2E] outgoing request failed:', e.message);
      }
    }
  }

  async _handleOutgoingRequest(req) {
    // Most outgoing requests are simple POSTs that pass `req.body` straight
    // through. ToDevice is the one shape that needs reformatting.
    const SIMPLE_POST_PATHS = {
      [RequestType.KeysUpload]: '/_matrix/client/v3/keys/upload',
      [RequestType.KeysQuery]: '/_matrix/client/v3/keys/query',
      [RequestType.KeysClaim]: '/_matrix/client/v3/keys/claim',
      [RequestType.SignatureUpload]: '/_matrix/client/v3/keys/signatures/upload',
    };

    let response;
    const simplePath = SIMPLE_POST_PATHS[req.type];
    if (simplePath) {
      response = await this._fetch(simplePath, { method: 'POST', body: req.body });
    } else if (req.type === RequestType.ToDevice) {
      const parsed = JSON.parse(req.body);
      const eventType = encodeURIComponent(req.eventType);
      response = await this._fetch(`/_matrix/client/v3/sendToDevice/${eventType}/${this._makeTxnId()}`, {
        method: 'PUT',
        body: JSON.stringify({ messages: parsed.messages }),
      });
    } else {
      // Unknown request type — skip
      return;
    }
    await this.olmMachine.markRequestAsSent(req.id, req.type, JSON.stringify(response));
  }

  // ── Cross-signing ────────────────────────────────────────────────────────────
  //
  // The matrix-sdk-crypto-nodejs napi binding's `bootstrapCrossSigning`
  // is incomplete: it generates the master/self-signing/user-signing
  // keypairs locally but never queues an upload request via
  // `outgoingRequests`, so the keys never reach the server. Without
  // those keys uploaded, Element shows an "unverified device" warning
  // shield next to every message the bot sends.
  //
  // We work around this by generating the cross-signing keypairs
  // ourselves with Node's crypto module and uploading them through the
  // standard Matrix REST endpoints. Private keys live in
  // `<storePath>/cross_signing.json` so subsequent runs of the same bot
  // reuse the same identity.

  _crossSigningFile() {
    return path.join(this.storePath, 'cross_signing.json');
  }

  _loadCrossSigningKeys() {
    return this._readJsonFile(this._crossSigningFile());
  }

  _saveCrossSigningKeys(stored) {
    this._writeJsonFile(this._crossSigningFile(), stored, { mode: 0o600 });
  }

  /**
   * POST `body` to `urlPath`, transparently completing the
   * `m.login.password` user-interactive-auth challenge if the server
   * demands one. The bot has its Matrix password from login(), so it
   * can satisfy the password stage on its own.
   *
   * Throws if the server requires a flow we can't satisfy with a
   * password (e.g. an SSO-only deployment) — at which point cross
   * signing has to be set up out of band by the human operator.
   */
  async _fetchWithUIA(urlPath, body, password) {
    let res;
    try {
      return await this._fetch(urlPath, {
        method: 'POST',
        body: JSON.stringify(body),
      });
    } catch (e) {
      if (e.status !== 401) throw e;
      // _fetch throws on non-2xx but doesn't expose the response body.
      // Re-issue the request directly so we can see the UIA challenge.
      res = await fetch(`${this.matrixUrl}${urlPath}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.accessToken}`,
        },
        body: JSON.stringify(body),
      });
    }
    const challenge = await res.json();
    if (!challenge.session) {
      throw new Error(`UIA challenge had no session token: ${JSON.stringify(challenge)}`);
    }
    const flows = challenge.flows || [];
    const passwordFlow = flows.find(f =>
      Array.isArray(f.stages) && f.stages.length === 1 && f.stages[0] === 'm.login.password',
    );
    if (!passwordFlow) {
      throw new Error(
        `Server requires a UIA flow we can't satisfy with a password. ` +
        `Available flows: ${JSON.stringify(flows)}. Set up cross-signing ` +
        `out-of-band (e.g. via Element) and copy cross_signing.json into the ` +
        `state directory.`,
      );
    }
    const authedBody = {
      ...body,
      auth: {
        type: 'm.login.password',
        session: challenge.session,
        identifier: { type: 'm.id.user', user: this.userId },
        password,
      },
    };
    return this._fetch(urlPath, {
      method: 'POST',
      body: JSON.stringify(authedBody),
    });
  }

  /**
   * Ensure the bot has a server-side cross-signing identity AND that
   * its current device is signed by that identity's self-signing key.
   *
   * The flow has to be careful not to clobber an existing identity. If
   * the user previously set up cross-signing through Element (with a
   * recovery key), uploading new master/self/user keys here would break
   * their entire trust web. So we always check the server first.
   *
   *   server_has_master ? local_keys ?    action
   *   ─────────────────────────────────────────────────────────────────
   *   no                  no              generate, upload, sign device
   *   no                  yes             upload local keys, sign device
   *                                       (server lost them, recover)
   *   yes (matches local) yes             sign device only
   *   yes (mismatch)      yes/no          do nothing, warn — manual
   *                                       intervention needed
   *
   * The `sign device` step itself is idempotent on the server but we
   * skip it if the device already carries an SSK signature, to avoid an
   * unnecessary round-trip on every cold start.
   */
  async _ensureCrossSigning(password) {
    // Step 1: ask the server what it knows about our user.
    const queryRes = await this._fetch('/_matrix/client/v3/keys/query', {
      method: 'POST',
      body: JSON.stringify({ device_keys: { [this.userId]: [] } }),
    });
    const serverMasterKey = queryRes?.master_keys?.[this.userId] || null;
    const serverMasterEd25519 = serverMasterKey
      ? Object.values(serverMasterKey.keys || {})[0] || null
      : null;

    let stored = this._loadCrossSigningKeys();
    let master, selfSigning, userSigning;

    if (stored) {
      // Local cross-signing keys exist. Make sure they line up with
      // whatever the server has before we trust them.
      if (serverMasterEd25519 && serverMasterEd25519 !== stored.master.public) {
        this._crossSigningStatus = {
          state: 'mismatch',
          localMasterKey: stored.master.public,
          serverMasterKey: serverMasterEd25519,
        };
        console.warn(
          '[E2E] cross-signing skipped: server has a different master key than ' +
          `cross_signing.json. Local master ${stored.master.public} vs. server ` +
          `${serverMasterEd25519}. Verify this device manually in Element, or ` +
          `delete cross_signing.json after copying the right master key in.`,
        );
        return;
      }
      master = loadEd25519Keypair(stored.master);
      selfSigning = loadEd25519Keypair(stored.self_signing);
      userSigning = loadEd25519Keypair(stored.user_signing);

      // Server doesn't have our keys yet (e.g. fresh server, restored
      // from a backup that lost cross-signing) — re-upload from local.
      if (!serverMasterEd25519) {
        await this._uploadCrossSigningTriple(master, selfSigning, userSigning, password);
      }
    } else {
      // No local cross-signing keys. Either the server has nothing (fresh
      // account) or another of our devices already set up a different
      // cross-signing identity we don't have the secrets for.
      //
      // Design choice: ALWAYS mint fresh and (re)upload, even when this
      // means replacing an existing server-side identity. Rationale: the
      // user has just proven wallet ownership via the EIP-191 sign-in
      // flow, so they're authorized to reset cross-signing for their
      // account. The downside is that this device's other sessions stop
      // appearing as "verified" until they sign in again (or are
      // verified from this device) — but sign-in always working takes
      // priority over the trust web, and an unverified-but-functional
      // session is much better than a stuck-can't-bootstrap session.
      //
      // The "local exists but differs from server" branch above is left
      // intentionally strict — that's the case where someone has hand-
      // copied a cross_signing.json that doesn't belong here, and silent
      // replacement could destroy the operator's keys.
      if (serverMasterEd25519) {
        console.warn(
          `[E2E] cross-signing: resetting server identity (was ${serverMasterEd25519}). ` +
          `Any other devices on this account will need to sign in again — or be ` +
          `verified from this one — before they appear trusted to peers.`,
        );
      }
      master = generateEd25519Keypair();
      selfSigning = generateEd25519Keypair();
      userSigning = generateEd25519Keypair();
      await this._uploadCrossSigningTriple(master, selfSigning, userSigning, password);
      stored = {
        master: { public: master.publicBase64, private: master.privateBase64 },
        self_signing: { public: selfSigning.publicBase64, private: selfSigning.privateBase64 },
        user_signing: { public: userSigning.publicBase64, private: userSigning.privateBase64 },
      };
      this._saveCrossSigningKeys(stored);
    }
    this._crossSigningStatus = {
      state: 'ready',
      masterKey: master.publicBase64,
      selfSigningKey: selfSigning.publicBase64,
      userSigningKey: userSigning.publicBase64,
    };

    // Step 2: sign THIS device with the self-signing key (skip if the
    // server already has the signature). Re-use queryRes when possible
    // — its device_keys map already contains what we need on a warm
    // start.
    let deviceKeys = queryRes?.device_keys?.[this.userId]?.[this.deviceId];
    if (!deviceKeys) {
      // We didn't ask for the device explicitly the first time round.
      // Re-query for just our device.
      const second = await this._fetch('/_matrix/client/v3/keys/query', {
        method: 'POST',
        body: JSON.stringify({ device_keys: { [this.userId]: [this.deviceId] } }),
      });
      deviceKeys = second?.device_keys?.[this.userId]?.[this.deviceId];
    }
    if (!deviceKeys) return;

    const sskKeyId = `ed25519:${selfSigning.publicBase64}`;
    if (deviceKeys.signatures?.[this.userId]?.[sskKeyId]) return;

    const signedDeviceKeys = signDeviceKeys({
      deviceKeys,
      sskPublicBase64: selfSigning.publicBase64,
      sskPrivateKey: selfSigning.privateKey,
    });
    await this._fetch('/_matrix/client/v3/keys/signatures/upload', {
      method: 'POST',
      body: JSON.stringify({
        [this.userId]: { [this.deviceId]: signedDeviceKeys },
      }),
    });
  }

  /**
   * Snapshot of this device's cross-signing state. Populated by
   * `_ensureCrossSigning` during login; meaningful values are:
   *   - { state: 'unknown' }           — login() hasn't completed yet.
   *   - { state: 'ready', masterKey }  — we hold the master/SSK/USK private
   *                                       bytes and the device is signed.
   *   - { state: 'awaiting_verification', serverMasterKey }
   *       Another of the user's devices created the cross-signing identity
   *       and we don't have the secrets yet. Have that device verify us
   *       (see Verification API) — once SAS/QR completes it will gossip the
   *       secrets back to us via m.secret.send.
   *   - { state: 'mismatch', localMasterKey, serverMasterKey }
   *       Our cross_signing.json doesn't match the server. Manual fix:
   *       delete the local file or re-key out of band.
   */
  getCrossSigningStatus() {
    return this._crossSigningStatus;
  }

  /**
   * Build & upload the three CrossSigningKey JSON objects to
   * `/_matrix/client/v3/keys/device_signing/upload`. Completes the
   * m.login.password UIA challenge inline.
   */
  async _uploadCrossSigningTriple(master, selfSigning, userSigning, password) {
    const masterKeyId = `ed25519:${master.publicBase64}`;
    const masterKey = buildSignedCrossSigningKey({
      userId: this.userId,
      usage: ['master'],
      publicBase64: master.publicBase64,
      signers: [{ keyId: masterKeyId, privateKey: master.privateKey }],
    });
    const selfSigningKey = buildSignedCrossSigningKey({
      userId: this.userId,
      usage: ['self_signing'],
      publicBase64: selfSigning.publicBase64,
      signers: [{ keyId: masterKeyId, privateKey: master.privateKey }],
    });
    const userSigningKey = buildSignedCrossSigningKey({
      userId: this.userId,
      usage: ['user_signing'],
      publicBase64: userSigning.publicBase64,
      signers: [{ keyId: masterKeyId, privateKey: master.privateKey }],
    });
    await this._fetchWithUIA(
      '/_matrix/client/v3/keys/device_signing/upload',
      {
        master_key: masterKey,
        self_signing_key: selfSigningKey,
        user_signing_key: userSigningKey,
      },
      password,
    );
  }

  /**
   * Do a one-shot /sync to retrieve to-device events and process key exchanges.
   * This is needed before reading from or sending to encrypted rooms.
   *
   * Resumes from the persisted next_batch token if one exists, and writes
   * the new next_batch back on success. This is what tells Synapse "I
   * received those to_device events" — without it, room keys delivered
   * between CLI invocations can be silently dropped.
   *
   * The /sync filter intentionally lets state events through so the
   * OlmMachine sees m.room.encryption (rotation params) and m.room.member
   * changes (new joins). Those are what keep outbound megolm sessions
   * addressed to the right device set.
   */
  async _syncOnce(since) {
    const sinceToken = since ?? this._loadSyncToken();
    const params = new URLSearchParams({ timeout: '0', filter: JSON.stringify({
      room: { timeline: { limit: 0 }, ephemeral: { limit: 0 } },
      presence: { limit: 0 },
    }) });
    if (sinceToken) params.set('since', sinceToken);

    const sync = await this._fetch(`/_matrix/client/v3/sync?${params}`);

    const toDeviceEvents = sync.to_device?.events || [];
    const changedUsers = (sync.device_lists?.changed || []).map(u => new UserId(u));
    const leftUsers = (sync.device_lists?.left || []).map(u => new UserId(u));
    const deviceLists = new DeviceLists(changedUsers, leftUsers);
    const oneTimeKeyCounts = sync.device_one_time_keys_count || {};
    const unusedFallback = sync.device_unused_fallback_key_types || [];

    // Always call receiveSyncChanges — the OlmMachine relies on the OTK count
    // and unused-fallback-key snapshot to know when to top up keys, even when
    // there are no to-device events or device list changes.
    // Capture the decrypted to-device event stream so verification handshake
    // events (m.key.verification.*) and gossiped secrets (m.secret.send) can
    // be dispatched to listeners.
    const decryptedJson = await this.olmMachine.receiveSyncChanges(
      JSON.stringify(toDeviceEvents),
      deviceLists,
      oneTimeKeyCounts,
      unusedFallback,
    );
    await this._processOutgoing();
    this._dispatchDecryptedToDevice(decryptedJson);

    if (sync.next_batch) this._saveSyncToken(sync.next_batch);
    return sync.next_batch;
  }

  // ── Verification (receiver-only) ─────────────────────────────────────────
  //
  // The Matrix SAS / QR verification protocol travels over to-device events
  // (m.key.verification.{request,ready,start,accept,key,mac,done,cancel}).
  // We detect incoming requests here and surface them to a listener; the
  // full SAS handshake / MAC computation is intentionally NOT implemented
  // in this Node code path yet — see verify-listen CLI hint below. The
  // recommended path today is: verify the Node CLI device from an agora
  // (browser) session, which drives the protocol end-to-end via matrix-js-sdk.
  //
  // What IS wired up here:
  //   1. Capture decrypted to-device events from receiveSyncChanges
  //   2. Detect verification-flow events + m.secret.send (cross-signing gossip)
  //   3. Fire `onIncomingVerification` for incoming requests
  //   4. Persist gossiped cross-signing secrets into cross_signing.json so
  //      that once another device DOES verify us (via a future full Node
  //      implementation OR matrix-js-sdk), the secrets land in the right
  //      place and _ensureCrossSigning picks them up on the next login.

  /**
   * Register a handler for incoming verification requests from other
   * devices of the same user. Returns an unsubscribe function.
   *
   * Handler receives: { transactionId, fromDeviceId, fromUserId, methods,
   *                     receivedAt, status }
   */
  onIncomingVerification(handler) {
    if (!this._verificationListeners) this._verificationListeners = new Set();
    this._verificationListeners.add(handler);
    return () => this._verificationListeners.delete(handler);
  }

  /**
   * List own Matrix devices via /devices. Includes display name and
   * last-seen metadata when the homeserver exposes them.
   */
  async listOwnDevices() {
    const data = await this._fetch('/_matrix/client/v3/devices');
    const devices = Array.isArray(data?.devices) ? data.devices : [];
    return devices.map((d) => ({
      deviceId: d.device_id,
      displayName: d.display_name || null,
      isThisDevice: d.device_id === this.deviceId,
      verified: false,                     // not tracked by /devices; query keys for ground truth
      crossSigningTrusted: false,
      signedByOwner: false,
      lastSeenTs: d.last_seen_ts || null,
      lastSeenIp: d.last_seen_ip || null,
    }));
  }

  _dispatchDecryptedToDevice(decryptedJson) {
    if (!decryptedJson) return;
    let events = [];
    try {
      const parsed = JSON.parse(decryptedJson);
      events = Array.isArray(parsed) ? parsed : (Array.isArray(parsed?.events) ? parsed.events : []);
    } catch {
      return;
    }
    for (const ev of events) {
      const t = ev?.type || ev?.event?.type;
      const content = ev?.content || ev?.event?.content || {};
      const sender = ev?.sender || ev?.event?.sender;
      if (t === 'm.key.verification.request' && sender === this.userId) {
        this._emitVerificationRequest({
          transactionId: content.transaction_id,
          fromDeviceId: content.from_device,
          fromUserId: sender,
          methods: Array.isArray(content.methods) ? content.methods : [],
          receivedAt: Date.now(),
          status: 'pending',
        });
      } else if (t === 'm.secret.send') {
        this._handleSecretSend(content);
      }
    }
  }

  _emitVerificationRequest(req) {
    if (!this._verificationListeners) return;
    for (const h of this._verificationListeners) {
      try { h(req); } catch (e) { console.warn('[E2E] verification handler threw:', e.message); }
    }
  }

  /**
   * Persist a gossiped cross-signing secret (m.secret.send) when one
   * arrives. Stores the base64 private bytes alongside the existing
   * cross_signing.json shape; on the next login, _ensureCrossSigning sees
   * the full triple and signs this device with its SSK.
   *
   * Secrets get gossiped by a trusted device only AFTER a successful
   * verification — this method is the receive endpoint for that gossip,
   * regardless of which side drove the SAS handshake.
   */
  _handleSecretSend(content) {
    const name = content?.name;
    const secret = content?.secret;
    if (!name || !secret) return;
    const SECRET_KEY_MAP = {
      'm.cross_signing.master': 'master',
      'm.cross_signing.self_signing': 'self_signing',
      'm.cross_signing.user_signing': 'user_signing',
    };
    const slot = SECRET_KEY_MAP[name];
    if (!slot) return;
    const stored = this._loadCrossSigningKeys() || {};
    // Public bytes are derived from the private — but we keep them as-is
    // for whatever already-stored slot exists. If we have no entry for
    // this slot, leave public empty (the next /keys/query response gives
    // us the public bytes; we don't strictly need them locally beyond
    // signing operations).
    stored[slot] = { ...(stored[slot] || {}), private: secret };
    this._saveCrossSigningKeys(stored);
    console.warn(`[E2E] received gossiped secret ${name} — will be wired up on next loginMatrix()`);
  }

  // ── Room membership ──────────────────────────────────────────────────────────

  async _getRoomMembers(roomId) {
    const data = await this._fetch(`/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/members`);
    return (data.chunk || [])
      .filter(e => e.content?.membership === 'join')
      .map(e => e.state_key);
  }

  /**
   * One-shot fetch of every currently-joined member's display name for a
   * room. Returns a Map<userId, displayName> — display name is `null` when
   * the member hasn't set one. Users who left the room will not appear.
   */
  async _getRoomDisplayNames(roomId) {
    const data = await this._fetch(
      `/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/joined_members`,
    );
    const out = new Map();
    for (const [userId, info] of Object.entries(data.joined || {})) {
      out.set(userId, info?.display_name || null);
    }
    return out;
  }

  /**
   * Fetch the room's m.room.history_visibility setting and map it to the
   * OlmMachine HistoryVisibility enum. Defaults to Shared (the Matrix spec
   * default) when the state event is missing.
   */
  async _getRoomHistoryVisibility(roomId) {
    let raw = 'shared';
    try {
      const data = await this._fetch(
        `/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/state/m.room.history_visibility`,
      );
      if (data.history_visibility) raw = data.history_visibility;
    } catch (e) {
      if (e.status !== 404 && e.errcode !== 'M_NOT_FOUND') throw e;
    }
    switch (raw) {
      case 'invited': return HistoryVisibility.Invited;
      case 'joined': return HistoryVisibility.Joined;
      case 'world_readable': return HistoryVisibility.WorldReadable;
      case 'shared':
      default:
        return HistoryVisibility.Shared;
    }
  }

  /**
   * Fetch a single state event from a room. Returns `defaultVal` on 404
   * (state event not set); rethrows everything else so callers don't
   * silently treat auth/network/5xx errors as "absent".
   */
  async _getRoomState(roomId, type, defaultVal = null) {
    try {
      return await this._fetch(
        `/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/state/${encodeURIComponent(type)}`,
      );
    } catch (e) {
      if (e.status === 404 || e.errcode === 'M_NOT_FOUND') return defaultVal;
      throw e;
    }
  }

  async _isRoomEncrypted(roomId) {
    // Only a 404 means "no encryption state event" → not encrypted. Anything
    // else (auth, rate limit, network, 5xx) is unsafe to interpret as
    // "plaintext is OK", because we'd risk leaking plaintext into an
    // encrypted room — `_getRoomState` rethrows those.
    const data = await this._getRoomState(roomId, 'm.room.encryption');
    return !!(data && data.algorithm);
  }

  // ── Read messages ────────────────────────────────────────────────────────────

  /**
   * Compute a unix-ms cutoff from `sinceMinsAgo` (minutes ago) or
   * `sinceCutoffMs` (absolute unix-ms). Returns null when neither is set.
   * `sinceCutoffMs` takes precedence — use it when you need millisecond
   * precision (e.g. resuming from a stored checkpoint).
   */
  _computeCutoffMs(opts) {
    if (opts.sinceCutoffMs !== undefined && opts.sinceCutoffMs !== null) {
      return Number(opts.sinceCutoffMs);
    }
    if (opts.sinceMinsAgo !== undefined && opts.sinceMinsAgo !== null) {
      return Date.now() - Number(opts.sinceMinsAgo) * 60_000;
    }
    return null;
  }

  /**
   * Send an m.room_key_request to-device event asking peers (and our own
   * other devices) to re-share the megolm session that decryption just
   * failed for. The reply arrives as an m.forwarded_room_key in a future
   * /sync's to_device events, which `receiveSyncChanges` handles
   * automatically — so the next decryptRoomEvent on this session can
   * succeed.
   *
   * NOTE: matrix-sdk-crypto-nodejs v0.4.0 does not expose
   * `olmMachine.requestRoomKey`, so this builds the to-device event by
   * hand. Per-invocation dedupe avoids spamming peers when many events
   * share the same megolm session.
   */
  async _requestRoomKey(event, roomId) {
    const senderKey = event?.content?.sender_key;
    const sessionId = event?.content?.session_id;
    if (!senderKey || !sessionId || !event?.sender) return;

    if (!this._roomKeyRequestsSent) this._roomKeyRequestsSent = new Set();
    const dedupKey = `${roomId}|${sessionId}|${senderKey}`;
    if (this._roomKeyRequestsSent.has(dedupKey)) return;
    this._roomKeyRequestsSent.add(dedupKey);

    const requestId = `mrkr_${this._makeTxnId()}`;
    const txnId = this._makeTxnId();
    const requestBody = {
      action: 'request',
      body: {
        algorithm: 'm.megolm.v1.aes-sha2',
        room_id: roomId,
        sender_key: senderKey,
        session_id: sessionId,
      },
      request_id: requestId,
      requesting_device_id: this.deviceId,
    };
    // Address the original sender's devices AND our own other devices —
    // either may be holding the session and able to forward it.
    const messages = {
      [event.sender]: { '*': requestBody },
    };
    if (event.sender !== this.userId) {
      messages[this.userId] = { '*': requestBody };
    }
    try {
      await this._fetch(
        `/_matrix/client/v3/sendToDevice/m.room_key_request/${txnId}`,
        { method: 'PUT', body: JSON.stringify({ messages }) },
      );
    } catch {
      // Best-effort: never let a failed key request break the read.
    }
  }

  /**
   * Project an `m.room.member` event into a status-event shape. Returns null
   * for membership transitions we don't want to surface (e.g. profile-only
   * displayname/avatar churn that doesn't change membership).
   *
   * Surfaced kinds: `join` (first-time or re-joins), `invite`, `leave` (incl.
   * kicks/invite-rejections — distinguishable by sender != state_key), `ban`,
   * `unban` (ban -> leave by a third party). The shape is intentionally small
   * and stable so callers can render a one-line "Alice joined" or
   * "Bob invited Carol" without needing to re-parse Matrix internals.
   */
  _projectMembershipEvent(event, displayNames) {
    if (event.type !== 'm.room.member') return null;
    const target = event.state_key;
    const newMembership = event.content?.membership;
    const prevMembership = event.unsigned?.prev_content?.membership;
    if (!target || !newMembership) return null;

    let kind = null;
    if (newMembership === 'join' && prevMembership !== 'join') kind = 'join';
    else if (newMembership === 'invite') kind = 'invite';
    else if (newMembership === 'ban') kind = 'ban';
    else if (newMembership === 'leave') {
      if (prevMembership === 'ban') kind = 'unban';
      else if (prevMembership === 'invite' && event.sender === target) kind = 'invite_rejected';
      else if (event.sender !== target) kind = 'kick';
      else kind = 'leave';
    }
    if (!kind) return null;

    return {
      event_type: 'membership',
      kind,
      event_id: event.event_id,
      sender: event.sender,
      sender_display_name: displayNames.get(event.sender) || null,
      target_user: target,
      target_display_name:
        event.content?.displayname || displayNames.get(target) || null,
      reason: event.content?.reason || null,
      timestamp: event.origin_server_ts,
    };
  }

  /**
   * Decrypt + project a single raw timeline event into the SDK's message
   * shape. Returns a message object on success, or null if the event isn't
   * a text message at all (and so should be silently dropped). For
   * encrypted events that fail to decrypt, returns a placeholder message
   * with body `[unable to decrypt]` so the caller still sees something.
   */
  async _projectEvent(event, encrypted, displayNames, roomId) {
    let msgEvent = event;
    if (event.type === 'm.room.encrypted' && encrypted) {
      try {
        const decryptedJson = await this.olmMachine.decryptRoomEvent(
          JSON.stringify(event),
          new RoomId(roomId),
        );
        const decrypted = JSON.parse(decryptedJson.event);
        msgEvent = { ...event, type: decrypted.type, content: decrypted.content };
      } catch (e) {
        // Fire (don't await) an m.room_key_request so peers can re-share
        // this megolm session. The forwarded key will arrive on a future
        // /sync and the next read of the same event will decrypt cleanly.
        this._requestRoomKey(event, roomId).catch(() => {});
        return {
          event_id: event.event_id,
          sender: event.sender,
          display_name: displayNames.get(event.sender) || null,
          body: '[unable to decrypt]',
          timestamp: event.origin_server_ts,
        };
      }
    }
    if (msgEvent.type !== 'm.room.message') return null;

    const msgtype = msgEvent.content?.msgtype;
    if (msgtype === 'm.text') {
      const result = {
        event_id: msgEvent.event_id,
        sender: msgEvent.sender,
        display_name: displayNames.get(msgEvent.sender) || null,
        body: msgEvent.content.body,
        timestamp: event.origin_server_ts,
      };
      const rel = msgEvent.content['m.relates_to'];
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

    // File-like messages: expose attachment info so callers can download them
    const FILE_TYPES = ['m.file', 'm.image', 'm.video', 'm.audio'];
    if (FILE_TYPES.includes(msgtype)) {
      const c = msgEvent.content;
      // Unencrypted: url is in c.url. E2E-encrypted: url is in c.file.url (needs decryption).
      const mxcUrl = c.url || c.file?.url || null;
      const filename = c.filename || c.body || 'file';
      const mimetype = c.info?.mimetype || c.file?.mimetype || null;
      const isEncrypted = !c.url && !!c.file;
      const attachment = { msgtype, mxc_url: mxcUrl, filename, mimetype, encrypted: isEncrypted };
      // Pass through the EncryptedFile object (key, iv, hashes) so callers can decrypt
      if (isEncrypted && c.file) attachment.encrypt_info = c.file;
      return {
        event_id: msgEvent.event_id,
        sender: msgEvent.sender,
        display_name: displayNames.get(msgEvent.sender) || null,
        body: `[${msgtype.replace('m.', '')}: ${filename}]`,
        timestamp: event.origin_server_ts,
        attachment,
      };
    }

    return null;
  }

  /**
   * Read messages from a room with automatic E2E decryption.
   *
   * Returns ALL messages in the room by default — paginates backwards until
   * the room's history is exhausted. An internal safety cap (~5000 events)
   * exists to prevent runaway memory use on extremely large rooms; it is not
   * configurable by callers. When `sinceMinsAgo` is set, pagination stops
   * once messages older than the cutoff are reached. When `limit` is set,
   * pagination stops once that many text messages have been collected and
   * the newest `limit` are returned.
   *
   * When `oldContextCount` is set together with `sinceMinsAgo`, pagination
   * keeps going past the cutoff until it has collected that many
   * text-bearing events older than the cutoff. The return shape gains an
   * `old_context` array containing the (up to `oldContextCount`) most
   * recent messages from before the cutoff. Use this to give callers a
   * little prior context without an extra round-trip.
   *
   * @param {string} roomId
   * @param {object} [opts]
   * @param {number} [opts.limit] - Optional max number of text messages to return (newest first cut)
   * @param {string} [opts.from] - Matrix pagination token to resume from
   * @param {number} [opts.sinceMinsAgo] - Only return messages from the last N minutes
   * @param {number} [opts.sinceCutoffMs] - Absolute unix-ms cutoff. Takes
   *   precedence over `sinceMinsAgo`. Use when you need ms-precision (e.g.
   *   resuming from a checkpoint).
   * @param {number} [opts.oldContextCount] - When set together with a
   *   cutoff (`sinceMinsAgo` / `sinceCutoffMs`), also return up to N
   *   messages older than the cutoff under `old_context`. Pagination
   *   stops as soon as this many are collected.
   */
  async readMessages(roomId, opts = {}) {
    const SAFETY_CAP_EVENTS = 5000;
    const PAGE_SIZE = 100;
    const userLimit = opts.limit && opts.limit > 0 ? opts.limit : null;
    const cutoffMs = this._computeCutoffMs(opts);
    const oldContextCount =
      opts.oldContextCount && opts.oldContextCount > 0 ? opts.oldContextCount : 0;
    const wantOldContext = oldContextCount > 0 && cutoffMs !== null;
    const encrypted = await this._isRoomEncrypted(roomId);

    if (encrypted) {
      // Sync to get any pending room keys (_syncOnce already drains
      // outgoing requests internally).
      await this._syncOnce();
    }

    // One-shot: every currently-joined member's display name. Used to
    // attach a `display_name` field to each message below.
    let displayNames;
    try {
      displayNames = await this._getRoomDisplayNames(roomId);
    } catch {
      displayNames = new Map();
    }

    const allRawNewestFirst = [];
    let from = opts.from;
    let end = null;
    let textCount = 0;
    let oldTextCount = 0;

    while (allRawNewestFirst.length < SAFETY_CAP_EVENTS) {
      let reqPath = `/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/messages?dir=b&limit=${PAGE_SIZE}`;
      if (from) reqPath += `&from=${encodeURIComponent(from)}`;

      const data = await this._fetch(reqPath);
      const chunk = data.chunk || [];
      end = data.end || end;

      if (chunk.length === 0) break;
      allRawNewestFirst.push(...chunk);

      // Track text-bearing events so userLimit / oldContextCount can
      // short-circuit. We can't know exactly how many of these will
      // actually decrypt to text, but it's a fine upper bound for "stop
      // fetching more pages".
      for (const e of chunk) {
        if (e.type === 'm.room.message' || e.type === 'm.room.encrypted') {
          textCount++;
          if (cutoffMs !== null && e.origin_server_ts < cutoffMs) oldTextCount++;
        }
      }

      if (!data.end) break;
      if (cutoffMs !== null) {
        if (wantOldContext) {
          // Keep going until we've seen enough older events to fill
          // old_context. Once we have, the caller has everything they
          // asked for and we can stop.
          if (oldTextCount >= oldContextCount) break;
        } else {
          const oldest = chunk[chunk.length - 1];
          if (oldest && oldest.origin_server_ts < cutoffMs) break;
        }
      }
      if (userLimit !== null && textCount >= userLimit) break;
      from = data.end;
    }

    const events = allRawNewestFirst.reverse();

    const newMessages = [];
    const olderMessages = [];
    const statusEvents = [];
    const olderStatusEvents = [];

    for (const event of events) {
      const isOlder = cutoffMs !== null && event.origin_server_ts < cutoffMs;
      if (isOlder && !wantOldContext) continue;

      if (event.type === 'm.room.member') {
        const status = this._projectMembershipEvent(event, displayNames);
        if (status === null) continue;
        if (isOlder) olderStatusEvents.push(status);
        else statusEvents.push(status);
        continue;
      }

      const msg = await this._projectEvent(event, encrypted, displayNames, roomId);
      if (msg === null) continue;

      if (isOlder) olderMessages.push(msg);
      else newMessages.push(msg);
    }

    if (wantOldContext) {
      // olderMessages is oldest-first; tail is the most recent ones,
      // which are the most useful as immediate context.
      return {
        messages: newMessages,
        old_context: olderMessages.slice(-oldContextCount),
        status_events: statusEvents,
        old_status_context: olderStatusEvents.slice(-oldContextCount),
        end,
      };
    }
    return { messages: newMessages, status_events: statusEvents, end };
  }

  /**
   * Read messages from every room the user has joined.
   *
   * Accepts the same options as `readMessages` (limit, sinceMinsAgo, maxPages,
   * from). Returns a map of roomId -> per-room result. Failures on a single
   * room are captured per-room and do not abort the others.
   */
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

  async _getRoomName(roomId) {
    const data = await this._getRoomState(roomId, 'm.room.name');
    return data?.name || null;
  }

  async _getRoomTopic(roomId) {
    const data = await this._getRoomState(roomId, 'm.room.topic');
    return data?.topic || null;
  }

  /**
   * Returns the `type` field of `m.room.create`. For a Matrix Space this is
   * the literal string "m.space"; for a regular room it is undefined/null.
   * Used to distinguish spaces from rooms when listing.
   */
  async _getRoomCreateType(roomId) {
    const data = await this._getRoomState(roomId, 'm.room.create');
    return data?.type || null;
  }

  /**
   * Returns the mxc:// URI stored in `m.room.avatar`'s `content.url`, or
   * null if no avatar is set. Use the result with `downloadMedia()` (or
   * expose it directly to UI clients).
   */
  async _getRoomAvatar(roomId) {
    const data = await this._getRoomState(roomId, 'm.room.avatar');
    return data?.url || null;
  }

  /**
   * Read all `m.space.parent` state events for the given room and return the
   * parent space room IDs (the state_keys). A room can declare multiple
   * parent spaces; spaces themselves can also be nested.
   */
  async _getRoomParentSpaces(roomId) {
    try {
      const events = await this._fetch(
        `/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/state`,
      );
      const out = [];
      for (const ev of events || []) {
        if (ev.type === 'm.space.parent' && ev.state_key && ev.content && Object.keys(ev.content).length > 0) {
          out.push(ev.state_key);
        }
      }
      return out;
    } catch (e) {
      if (e.status === 404 || e.errcode === 'M_NOT_FOUND') return [];
      // /state requires membership; if we don't have it, give up gracefully.
      if (e.status === 403) return [];
      throw e;
    }
  }

  /**
   * Checkpoint-aware variant of `readAllMessages`.
   *
   * For every joined room, splits the room's recent text messages into:
   *   - `new_messages`: messages strictly newer than the persisted
   *                     checkpoint (or, on first read, newer than 2 days
   *                     ago)
   *   - `old_context`:  the 10 most recent text messages from before the
   *                     checkpoint, so the agent always has a little
   *                     prior context to anchor the new ones. Always 10,
   *                     not configurable.
   *
   * On first read for a room (no checkpoint yet), the cutoff defaults to
   * `defaultLookbackDays` (2) days ago. After a successful read the
   * checkpoint is advanced to the timestamp of the newest message returned,
   * so subsequent calls only surface genuinely new traffic. Pagination
   * uses the `oldContextCount` mode of `readMessages`, so we stop walking
   * history as soon as we have 10 events older than the cutoff — bounded
   * cost regardless of how active the room is.
   *
   * Each room entry includes `room_id` (verbatim Matrix room ID, suitable
   * for `sendMessage`) plus `name`/`topic` so the agent can recognise which
   * room it's looking at when deciding where to reply.
   *
   * The top-level return object contains two keys:
   *   - `rooms`:           map of roomId -> per-room result (unchanged)
   *   - `pending_invites`: array of pending room invites, each with
   *                        { roomId, name, topic, inviter }. Empty array
   *                        if there are no pending invites.
   *
   * @param {object} [opts]
   * @param {number} [opts.defaultLookbackDays=2] - Lookback window when no
   *   checkpoint exists yet for a room.
   * @param {boolean} [opts.markAsRead=true] - Whether to persist the new
   *   checkpoint after reading (i.e. mark the surfaced messages as read).
   *   Set to false for a peek — messages will be re-surfaced on the next
   *   call. Also accepted as `mark_as_read` or the original
   *   `advanceCheckpoint`.
   */
  async readAllNewMessages(opts = {}) {
    const OLD_CONTEXT_COUNT = 10;
    const markAsRead = opts.markAsRead ?? opts.mark_as_read ?? opts.advanceCheckpoint;
    const advanceCheckpoint = markAsRead !== false;
    const memory = this._getMemoryStore();

    // Single transport for both warm (delta from stored next_batch) and
    // cold (no token / 4xx fallback) paths. On bootstrap the timeline
    // contains the most recent ~50 events Synapse retains; on a delta
    // call it contains only events newer than the token. Either way
    // every event in this batch is "new" relative to the previous read.
    // `old_context` comes from the per-room snapshot seeded by previous
    // calls — the bootstrap-trade-off George3d6 accepted on 2026-05-08.
    const filter = JSON.stringify({
      room: {
        timeline: { limit: 50, types: ['m.room.message', 'm.room.encrypted', 'm.room.member'] },
        state: { lazy_load_members: true },
        ephemeral: { limit: 0 },
      },
      presence: { limit: 0 },
    });

    let token = memory.getTimelineSyncToken?.() || null;
    let sync;
    try {
      sync = await this._timelineSync(filter, token);
    } catch (e) {
      // Stale or unknown token: drop it and retry without `since`.
      // Anything else (network, 5xx) propagates — callers see real errors.
      if (token && e?.status >= 400 && e?.status < 500) {
        memory.clearTimelineSyncToken?.();
        token = null;
        sync = await this._timelineSync(filter, null);
      } else {
        throw e;
      }
    }

    // Drain to-device + device-list changes so room keys delivered in this
    // batch are usable when we decrypt the timeline events below.
    const toDeviceEvents = sync.to_device?.events || [];
    if (toDeviceEvents.length || sync.device_lists || sync.device_one_time_keys_count) {
      const changedUsers = (sync.device_lists?.changed || []).map(u => new UserId(u));
      const leftUsers = (sync.device_lists?.left || []).map(u => new UserId(u));
      const deviceLists = new DeviceLists(changedUsers, leftUsers);
      const oneTimeKeyCounts = sync.device_one_time_keys_count || {};
      const unusedFallback = sync.device_unused_fallback_key_types || [];
      const decryptedJson = await this.olmMachine.receiveSyncChanges(
        JSON.stringify(toDeviceEvents),
        deviceLists,
        oneTimeKeyCounts,
        unusedFallback,
      );
      await this._processOutgoing();
      this._dispatchDecryptedToDevice(decryptedJson);
    }

    const joinMap = sync.rooms?.join || {};
    const roomIds = await this.listJoinedRooms();
    const rooms = {};

    for (const roomId of roomIds) {
      try {
        const join = joinMap[roomId] || {};
        let timeline = join.timeline?.events || [];

        // Belt + suspenders: in cold-bootstrap mode (no token) Synapse may
        // hand us events older than a checkpoint we still hold from a
        // previous run whose token was lost. Filter those so we don't
        // re-deliver. In warm/delta mode the filter is a no-op because
        // every event is post-token by construction.
        const checkpoint = memory.getCheckpoint(roomId);
        if (!token && checkpoint) {
          timeline = timeline.filter(e => (e.origin_server_ts || 0) > checkpoint);
        }

        const encrypted = timeline.some(e => e.type === 'm.room.encrypted')
          ? true
          : await this._isRoomEncrypted(roomId);
        const displayNames = await this._getRoomDisplayNames(roomId).catch(() => new Map());

        const newMessages = [];
        const statusEvents = [];
        for (const event of timeline) {
          if (event.type === 'm.room.member') {
            const status = this._projectMembershipEvent(event, displayNames);
            if (status) statusEvents.push(status);
            continue;
          }
          const msg = await this._projectEvent(event, encrypted, displayNames, roomId);
          if (msg) newMessages.push(msg);
        }

        // old_context: cached snapshot from previous calls, then fold new
        // events back into the snapshot for next time.
        const snapshot = memory.getRoomSnapshot
          ? memory.getRoomSnapshot(roomId)
          : { messages: [], status: [] };
        const oldContext = (snapshot.messages || []).slice(-OLD_CONTEXT_COUNT);
        const oldStatusContext = (snapshot.status || []).slice(-OLD_CONTEXT_COUNT);

        if (advanceCheckpoint && (newMessages.length || statusEvents.length) && memory.setRoomSnapshot) {
          const mergedMsgs = [...(snapshot.messages || []), ...newMessages].slice(-OLD_CONTEXT_COUNT);
          const mergedStatus = [...(snapshot.status || []), ...statusEvents].slice(-OLD_CONTEXT_COUNT);
          memory.setRoomSnapshot(roomId, { messages: mergedMsgs, status: mergedStatus });
        }

        // Advance the per-room timestamp checkpoint — used by has_new probes
        // and as the bootstrap re-delivery filter above.
        const newestMsg = newMessages.length ? newMessages[newMessages.length - 1] : null;
        const newestStatus = statusEvents.length ? statusEvents[statusEvents.length - 1] : null;
        const newestTs = Math.max(newestMsg?.timestamp || 0, newestStatus?.timestamp || 0);
        if (advanceCheckpoint && newestTs > 0) {
          memory.setCheckpoint(roomId, newestTs);
          // Mirror the checkpoint as a Matrix read marker so the homeserver's
          // own unread/notification counts track what we consider read. The
          // event whose timestamp defined newestTs is the newest one read.
          const newestEvent = (newestStatus?.timestamp || 0) > (newestMsg?.timestamp || 0) ? newestStatus : newestMsg;
          if (newestEvent?.event_id) await this._sendReadMarker(roomId, newestEvent.event_id);
        } else if (advanceCheckpoint && checkpoint === null) {
          // Quiet bootstrap: stamp at "now" so subsequent has_new probes
          // don't always say "yes" until traffic arrives.
          memory.setCheckpoint(roomId, Date.now());
        }

        const [name, topicStr] = await Promise.all([
          this._getRoomName(roomId).catch(() => null),
          this._getRoomTopic(roomId).catch(() => null),
        ]);

        rooms[roomId] = {
          room_id: roomId,
          name,
          topic: topicStr,
          checkpoint_ms: memory.getCheckpoint(roomId) || 0,
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

    if (advanceCheckpoint && sync.next_batch) {
      memory.setTimelineSyncToken?.(sync.next_batch);
    }

    let pending_invites = [];
    try {
      pending_invites = await this.listInvites();
    } catch {}

    return { rooms, pending_invites };
  }

  async _timelineSync(filter, since) {
    const params = new URLSearchParams({ timeout: '0', filter });
    if (since) params.set('since', since);
    return this._fetch(`/_matrix/client/v3/sync?${params}`);
  }

  // ── Send messages ────────────────────────────────────────────────────────────

  /**
   * Send a signed message to a room with automatic E2E encryption.
   */
  async sendMessage(roomId, text, opts = {}) {
    const historyLimit = opts.historyLimit || 50;
    const encrypted = await this._isRoomEncrypted(roomId);

    if (encrypted) {
      // Pull any pending to-device events / device-list changes so that
      // _ensureRoomKeysShared sees the current member device set. Without
      // this, peers who joined or rotated devices since the last sync
      // would silently miss the room key for this message.
      await this._syncOnce();
    }

    // Build accountability signature
    const historyData = await this._fetch(
      `/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/messages?dir=b&limit=${historyLimit}`,
    );
    const historyEvents = (historyData.chunk || [])
      .filter(e => e.type === 'm.room.message' && e.content?.msgtype === 'm.text')
      .reverse()
      .map(e => ({ sender: e.sender, body: e.content.body }));

    const signed = await signMessage(this.privateKey, historyEvents, text, this.userId);
    const htmlBody = (await getMarked()).parse(text);
    const accountability = {
      prev_conv: signed.prev_conv_sign,
      with_reply: signed.with_reply_sign,
      reply_only: signed.reply_only_sign,
    };
    if (this.delegation) accountability.delegation = this.delegation;
    const content = {
      msgtype: 'm.text',
      body: text,
      format: 'org.matrix.custom.html',
      formatted_body: htmlBody,
      [ACCOUNTABILITY_FIELD]: accountability,
    };

    // Thread and/or reply support (MSC3440 / m.thread)
    if (opts.threadRootId) {
      content['m.relates_to'] = {
        rel_type: 'm.thread',
        event_id: opts.threadRootId,
        is_falling_back: true,
        'm.in_reply_to': { event_id: opts.replyToEventId || opts.threadRootId },
      };
    } else if (opts.replyToEventId) {
      content['m.relates_to'] = {
        'm.in_reply_to': { event_id: opts.replyToEventId },
      };
    }

    let eventType, body;
    if (encrypted) {
      await this._ensureRoomKeysShared(roomId);
      eventType = 'm.room.encrypted';
      body = await this.olmMachine.encryptRoomEvent(
        new RoomId(roomId),
        'm.room.message',
        JSON.stringify(content),
      );
    } else {
      eventType = 'm.room.message';
      body = JSON.stringify(content);
    }

    const result = await this._fetch(
      `/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/send/${eventType}/${this._makeTxnId()}`,
      { method: 'PUT', body },
    );
    return {
      event_id: result.event_id,
      accountability: { message: signed.message, message_with_sign: signed.message_with_sign },
    };
  }

  /**
   * Send a reaction (m.reaction / m.annotation) to an existing event.
   *
   * Always sent cleartext — m.relates_to must be server-visible so peers and
   * servers can tally annotations. Works in both encrypted and unencrypted
   * rooms; Synapse does not enforce encryption on m.reaction events.
   *
   * @param {string} roomId  - target room
   * @param {string} eventId - event_id to react to
   * @param {string} key     - reaction key (typically a single emoji, e.g. "👎")
   * @returns {Promise<{event_id: string}>}
   */
  async sendReaction(roomId, eventId, key) {
    if (!roomId || !eventId || !key) {
      throw new Error('sendReaction requires roomId, eventId, and key');
    }
    const content = {
      'm.relates_to': {
        rel_type: 'm.annotation',
        event_id: eventId,
        key,
      },
    };
    const result = await this._fetch(
      `/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/send/m.reaction/${this._makeTxnId()}`,
      { method: 'PUT', body: JSON.stringify(content) },
    );
    return { event_id: result.event_id };
  }

  /**
   * Ensure room keys are shared with all current room members.
   *
   * Sequence (per matrix-sdk-crypto lifecycle):
   *   1. Synthetically mark every member as device-list-changed so the
   *      OlmMachine queues a KeysQuery for each on the next outgoing pass.
   *      This is necessary because `updateTrackedUsers` is a no-op for any
   *      user the OlmMachine has already auto-tracked from an inbound
   *      to_device event — that user ends up "tracked but not dirty," with
   *      zero devices in the local store, and `shareRoomKey` then silently
   *      produces zero to_device requests for them. Forcing them into
   *      `device_lists.changed` via `receiveSyncChanges` is the
   *      napi-binding-safe way to mark them dirty and trigger the query.
   *   2. updateTrackedUsers — register users we care about (idempotent).
   *   3. KeysQuery (via _processOutgoing) — fetch their device lists.
   *   4. getMissingSessions — claim OTKs for any user/device we don't yet
   *      have an Olm session with, then run the resulting KeysClaim.
   *   5. shareRoomKey — produce to-device messages with the Megolm key.
   *   6. send those to-device messages.
   */
  async _ensureRoomKeysShared(roomId) {
    const members = await this._getRoomMembers(roomId);
    const memberIds = members.map(m => new UserId(m));

    // Force every current room member to be re-queried. We hand the
    // OlmMachine a synthetic `device_lists.changed` containing each
    // member, which marks them dirty even if they were previously
    // auto-tracked from an inbound message and have no device records yet.
    const forcedDeviceLists = new DeviceLists(
      members.map(m => new UserId(m)),
      [],
    );
    await this.olmMachine.receiveSyncChanges(
      JSON.stringify([]),
      forcedDeviceLists,
      {},
      [],
    );

    await this.olmMachine.updateTrackedUsers(memberIds);
    await this._processOutgoing(); // KeysQuery for member devices

    // Claim one-time keys for any (user, device) we don't yet have an Olm
    // session with. shareRoomKey would otherwise fail to deliver the room
    // key to those devices.
    const claimRequest = await this.olmMachine.getMissingSessions(memberIds);
    if (claimRequest) {
      await this._handleOutgoingRequest(claimRequest);
    }

    const settings = new EncryptionSettings();
    settings.historyVisibility = await this._getRoomHistoryVisibility(roomId);

    const toDeviceRequests = await this.olmMachine.shareRoomKey(
      new RoomId(roomId),
      memberIds,
      settings,
    );

    for (const req of toDeviceRequests) {
      await this._handleOutgoingRequest(req);
    }

    // Process any additional outgoing requests queued after sharing.
    await this._processOutgoing();
  }

  // ── Misc Matrix API helpers ──────────────────────────────────────────────────

  async listPublicRooms() {
    return this._fetch('/_matrix/client/v3/publicRooms');
  }

  /**
   * List rooms the current user has joined.
   * @returns {Promise<string[]>}
   */
  async listJoinedRooms() {
    const data = await this._fetch('/_matrix/client/v3/joined_rooms');
    return data.joined_rooms || [];
  }

  /**
   * Like listJoinedRooms() but also includes a clear-text name and topic
   * for each room. Costs N+1 HTTP round-trips (one /joined_rooms plus one
   * state read per room) — the browser variant is much cheaper because it
   * uses matrix-js-sdk's local Room cache.
   *
   * @returns {Promise<Array<{room_id: string, name: string|null, topic: string|null}>>}
   */
  async listJoinedRoomsWithNames() {
    const ids = await this.listJoinedRooms();
    const out = [];
    for (const room_id of ids) {
      const [name, topic, createType, parentSpaces, avatarUrl] = await Promise.all([
        this._getRoomName(room_id).catch(() => null),
        this._getRoomTopic(room_id).catch(() => null),
        this._getRoomCreateType(room_id).catch(() => null),
        this._getRoomParentSpaces(room_id).catch(() => []),
        this._getRoomAvatar(room_id).catch(() => null),
      ]);
      out.push({
        room_id,
        name,
        topic,
        avatar_url: avatarUrl,
        is_space: createType === 'm.space',
        room_type: createType || null,
        parent_spaces: parentSpaces,
      });
    }
    return out;
  }

  /**
   * List rooms the current user has been invited to but has not yet joined.
   *
   * Uses a one-shot, zero-timeline `/sync` to fetch the `rooms.invite` map,
   * then extracts a friendly name/topic/inviter from the invite_state events
   * when available.
   *
   * @returns {Promise<Array<{roomId: string, name: string|null, topic: string|null, inviter: string|null}>>}
   */
  async listInvites() {
    const filter = JSON.stringify({
      room: {
        timeline: { limit: 0 },
        ephemeral: { limit: 0 },
        state: { limit: 0 },
        account_data: { limit: 0 },
      },
      presence: { limit: 0 },
    });
    const params = new URLSearchParams({ timeout: '0', filter });
    const sync = await this._fetch(`/_matrix/client/v3/sync?${params}`);
    const invitesObj = sync.rooms?.invite || {};
    const invites = [];
    for (const [roomId, room] of Object.entries(invitesObj)) {
      const events = room.invite_state?.events || [];
      let name = null;
      let topic = null;
      let inviter = null;
      let createType = null;
      let isDirect = false;
      for (const ev of events) {
        if (ev.type === 'm.room.name' && ev.content?.name) name = ev.content.name;
        else if (ev.type === 'm.room.topic' && ev.content?.topic) topic = ev.content.topic;
        else if (ev.type === 'm.room.create' && ev.content?.type) createType = ev.content.type;
        else if (
          ev.type === 'm.room.member' &&
          ev.state_key === this.userId &&
          ev.content?.membership === 'invite'
        ) {
          inviter = ev.sender || null;
          if (ev.content?.is_direct === true) isDirect = true;
        }
      }
      invites.push({
        roomId,
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

  /**
   * Join a room (also used to accept a pending invite — the Matrix endpoint
   * is the same in both cases).
   *
   * After the /join POST we run one /sync and, if the room is encrypted, an
   * _ensureRoomKeysShared pass. This gives the OlmMachine a chance to:
   *   - drain to_device events peers may have queued for us (megolm keys),
   *   - mark peer devices as tracked so KeysQuery fetches their lists, and
   *   - establish outbound Olm sessions so subsequent sends don't race the
   *     first message through an empty key store.
   *
   * Without this, a fresh join left the device in a "zero inbound megolm
   * sessions" state and peers only re-shared the room key on their next
   * outbound message, which for low-traffic rooms meant new messages read
   * as "[unable to decrypt]" until a peer happened to rotate. The extra
   * work is wrapped in try/catch so transient sync/key failures never
   * block the join itself — callers can still recover by sending or
   * receiving a message, which re-runs the same plumbing.
   */
  async joinRoom(roomId) {
    const result = await this._fetch(
      `/_matrix/client/v3/join/${encodeURIComponent(roomId)}`,
      { method: 'POST', body: '{}' },
    );
    try {
      await this._syncOnce();
      if (await this._isRoomEncrypted(roomId)) {
        await this._ensureRoomKeysShared(roomId);
      }
    } catch (_e) {
      // Non-fatal — /join succeeded. Key setup retries on next send/read.
    }
    return result;
  }

  /**
   * Accept a pending invite. Equivalent to `joinRoom`, plus an `m.direct`
   * sync when the invite carried `is_direct: true` — so DM rooms created
   * by a peer end up recorded in the receiver's m.direct account-data
   * (matching Element's accept-invite behavior).
   *
   * Caller can pass `peerUserId` explicitly; otherwise we resolve it from
   * the pending invite list (the `inviter` field).
   */
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
        // Fall through — m.direct sync is best-effort.
      }
    }
    const result = await this.joinRoom(roomId);
    if (isDirect && peerUserId) {
      try {
        await this._addDirect(peerUserId, roomId);
      } catch (_e) {
        // Non-fatal — DM still joined; m.direct can be re-synced later.
      }
    }
    return result;
  }

  /**
   * Reject a pending room invite. In Matrix, declining an invite is just
   * `leave` on the invited room.
   */
  async rejectInvite(roomId) {
    return this._leaveRoomRaw(roomId);
  }

  /**
   * Create a new Matrix room.
   *
   * @param {object} [opts]
   * @param {string} [opts.name] - Room display name
   * @param {string} [opts.topic] - Room topic
   * @param {string[]} [opts.invite] - User IDs to invite
   * @param {boolean} [opts.encrypted=true] - Enable E2E encryption (m.room.encryption)
   * @param {'public'|'private'} [opts.visibility='private'] - Directory visibility
   * @param {'public_chat'|'private_chat'|'trusted_private_chat'} [opts.preset]
   *   - Defaults to `private_chat` for `private` and `public_chat` for `public`
   * @param {boolean} [opts.is_direct] - Mark this as a 1:1 DM. Sets the
   *   `is_direct` flag on the createRoom request (which Synapse forwards to
   *   the invitee's m.room.member event) so the receiving client can detect
   *   the invite as a DM via `room.getDMInviter()`. Note: this does NOT write
   *   the caller's own m.direct account-data — use `openDmWith()` for that.
   * @returns {Promise<{room_id: string}>}
   */
  async createRoom(opts = {}) {
    const visibility = opts.visibility || 'private';
    const preset = opts.preset || (visibility === 'public' ? 'public_chat' : 'private_chat');
    const encrypted = opts.encrypted !== false;

    const body = {
      visibility,
      preset,
    };
    if (opts.name) body.name = opts.name;
    if (opts.topic) body.topic = opts.topic;
    if (Array.isArray(opts.invite) && opts.invite.length) body.invite = opts.invite;
    if (opts.is_direct) body.is_direct = true;
    if (encrypted) {
      body.initial_state = [
        {
          type: 'm.room.encryption',
          state_key: '',
          content: { algorithm: 'm.megolm.v1.aes-sha2' },
        },
      ];
    }

    return this._fetch('/_matrix/client/v3/createRoom', {
      method: 'POST',
      body: JSON.stringify(body),
    });
  }

  // ── DMs (m.direct account-data) ─────────────────────────────────────────
  // Matrix marks DMs via two cooperating signals: the per-invite `is_direct`
  // flag (wire hint, captured on the m.room.member invite) and the
  // `m.direct` account-data event (the source of truth: a global per-user
  // map of peer userId -> [roomId, ...]). Element classifies rooms as DMs
  // purely by membership in m.direct — member count is irrelevant.

  /**
   * Read the caller's `m.direct` account-data — a map of peer userId to the
   * list of room IDs the caller treats as DMs with that peer.
   *
   * Returns an empty object if no m.direct event has ever been written for
   * this user, or if the server returns 404 (Synapse's behavior for missing
   * account-data).
   *
   * @returns {Promise<Object<string, string[]>>}
   */
  async getDirects() {
    if (!this.userId) throw new Error('Not logged in');
    try {
      const data = await this._fetch(
        `/_matrix/client/v3/user/${encodeURIComponent(this.userId)}/account_data/m.direct`,
      );
      const out = {};
      for (const [peer, rooms] of Object.entries(data || {})) {
        if (Array.isArray(rooms)) out[peer] = rooms.filter((r) => typeof r === 'string');
      }
      return out;
    } catch (e) {
      // Account-data missing -> Synapse returns 404 with M_NOT_FOUND. Treat as empty.
      if (e.status === 404 || e.errcode === 'M_NOT_FOUND') return {};
      throw e;
    }
  }

  /**
   * Overwrite the caller's `m.direct` account-data with the supplied map.
   * Callers should usually go through `_addDirect(peer, roomId)` instead,
   * which performs a read-merge-write so concurrent updates don't clobber
   * each other.
   */
  async setDirects(directs) {
    if (!this.userId) throw new Error('Not logged in');
    const body = {};
    for (const [peer, rooms] of Object.entries(directs || {})) {
      if (Array.isArray(rooms) && rooms.length) {
        body[peer] = Array.from(new Set(rooms.filter((r) => typeof r === 'string')));
      }
    }
    return this._fetch(
      `/_matrix/client/v3/user/${encodeURIComponent(this.userId)}/account_data/m.direct`,
      { method: 'PUT', body: JSON.stringify(body) },
    );
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

  /**
   * Open a 1:1 DM with `peerUserId`. If an existing DM is already recorded
   * in our `m.direct` account-data and we're still joined to it, that room
   * is reused. Otherwise a fresh `trusted_private_chat` is created with
   * `is_direct: true` and the inviter's `m.direct` is updated to record it.
   *
   * The receiving side is responsible for its own m.direct update on
   * accept (see `acceptInvite` / `listInvites` `is_direct` field). DMs are
   * E2E-encrypted by default; pass `encrypted: false` to opt out.
   *
   * @param {string} peerUserId - Full Matrix ID, e.g. `@bob:matrix.example`
   * @param {object} [opts]
   * @param {boolean} [opts.encrypted=true]
   * @returns {Promise<{room_id: string, reused: boolean}>}
   */
  async openDmWith(peerUserId, opts = {}) {
    if (!peerUserId || !peerUserId.startsWith('@')) {
      throw new Error('openDmWith: peerUserId must be a full Matrix ID like @bob:server');
    }
    const directs = await this.getDirects();
    const existing = directs[peerUserId] || [];
    for (const roomId of existing) {
      try {
        const membership = await this._getMyMembership(roomId);
        if (membership === 'join' || membership === 'invite') {
          return { room_id: roomId, reused: true };
        }
      } catch (_e) {
        // Room may have been forgotten on the server side; fall through.
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

  async _getMyMembership(roomId) {
    if (!this.userId) throw new Error('Not logged in');
    try {
      const ev = await this._fetch(
        `/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/state/m.room.member/${encodeURIComponent(this.userId)}`,
      );
      return ev?.membership || null;
    } catch (e) {
      if (e.status === 404 || e.errcode === 'M_NOT_FOUND') return null;
      throw e;
    }
  }

  /**
   * Create a Matrix Space (a room with `creation_content.type = m.space`).
   *
   * Spaces are never E2E-encrypted (they only carry membership + child
   * pointers, not message content) — `opts.encrypted` is ignored.
   *
   * @param {object} [opts]
   * @param {string} [opts.name]
   * @param {string} [opts.topic]
   * @param {string[]} [opts.invite] - User IDs to invite at creation
   * @param {'public'|'private'} [opts.visibility='private']
   * @param {string[]} [opts.children] - Room IDs to add as m.space.child entries
   * @returns {Promise<{room_id: string}>}
   */
  async createSpace(opts = {}) {
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
      body.initial_state = opts.children.map((childId) => ({
        type: 'm.space.child',
        state_key: childId,
        content: { via: [this._serverNameFromUserId()] },
      }));
    }
    return this._fetch('/_matrix/client/v3/createRoom', {
      method: 'POST',
      body: JSON.stringify(body),
    });
  }

  /**
   * Invite a user to a room or space. Matrix uses the same endpoint for
   * both — spaces are just rooms with a special creation type.
   */
  async inviteUser(roomId, userId) {
    return this._fetch(
      `/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/invite`,
      { method: 'POST', body: JSON.stringify({ user_id: userId }) },
    );
  }

  // ── Room administration (rename / kick) ──────────────────────────────────

  /**
   * Rename a room by writing its `m.room.name` state event. Requires power
   * level >= the room's `m.room.name` event level (see getRoomManagementInfo).
   */
  async setRoomName(roomId, name) {
    return this._fetch(
      `/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/state/m.room.name/`,
      { method: 'PUT', body: JSON.stringify({ name }) },
    );
  }

  /**
   * Kick a user from a room. Requires power level >= the room's `kick` level
   * and strictly greater than the target's level.
   */
  async kickUser(roomId, userId, reason) {
    const body = { user_id: userId };
    if (reason) body.reason = reason;
    return this._fetch(
      `/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/kick`,
      { method: 'POST', body: JSON.stringify(body) },
    );
  }

  /**
   * Snapshot of a room's manageable state for a "manage channel" UI: the
   * current name, your effective power level, and each joined/invited member
   * with their power level plus whether *you* may rename the room or kick
   * them. Mirrors the browser client's getRoomManagementInfo over REST.
   */
  async getRoomManagementInfo(roomId) {
    const pl = (await this._getRoomState(roomId, 'm.room.power_levels', {})) || {};
    const nameState = (await this._getRoomState(roomId, 'm.room.name', {})) || {};
    const users = pl.users || {};
    const usersDefault = Number.isFinite(pl.users_default) ? pl.users_default : 0;
    const stateDefault = Number.isFinite(pl.state_default) ? pl.state_default : 50;
    const kickLevel = Number.isFinite(pl.kick) ? pl.kick : 50;
    const nameLevel = Number.isFinite(pl.events?.['m.room.name']) ? pl.events['m.room.name'] : stateDefault;
    const myId = this.userId;
    const levelOf = (uid) => (Number.isFinite(users[uid]) ? users[uid] : usersDefault);
    const myLevel = levelOf(myId);
    const data = await this._fetch(`/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/members`);
    const members = (data.chunk || [])
      .filter((e) => e.content?.membership === 'join' || e.content?.membership === 'invite')
      .map((e) => {
        const uid = e.state_key;
        const level = levelOf(uid);
        return {
          user_id: uid,
          display_name: e.content?.displayname || null,
          avatar_url: e.content?.avatar_url || null,
          membership: e.content.membership,
          power_level: level,
          can_kick: uid !== myId && myLevel >= kickLevel && myLevel > level,
        };
      })
      .sort((a, b) => b.power_level - a.power_level
        || (a.display_name || a.user_id).localeCompare(b.display_name || b.user_id));
    return {
      room_id: roomId,
      name: nameState.name || null,
      my_user_id: myId,
      my_power_level: myLevel,
      kick_level: kickLevel,
      name_level: nameLevel,
      can_rename: myLevel >= nameLevel,
      can_kick_any: myLevel >= kickLevel,
      members,
    };
  }

  /**
   * Add a child room to a space by writing an `m.space.child` state event
   * on the space room. Requires the caller to have power level to send
   * state in the space.
   */
  async addRoomToSpace(spaceId, childRoomId, opts = {}) {
    const content = {
      via: opts.via || [this._serverNameFromUserId()],
    };
    if (opts.suggested) content.suggested = true;
    if (opts.order) content.order = opts.order;
    return this._fetch(
      `/_matrix/client/v3/rooms/${encodeURIComponent(spaceId)}/state/m.space.child/${encodeURIComponent(childRoomId)}`,
      { method: 'PUT', body: JSON.stringify(content) },
    );
  }

  /**
   * Remove a child room from a space (sends an empty m.space.child content,
   * which Matrix treats as a tombstone for the child relationship).
   */
  async removeRoomFromSpace(spaceId, childRoomId) {
    return this._fetch(
      `/_matrix/client/v3/rooms/${encodeURIComponent(spaceId)}/state/m.space.child/${encodeURIComponent(childRoomId)}`,
      { method: 'PUT', body: JSON.stringify({}) },
    );
  }

  /**
   * List the children of a space by reading its `m.space.child` state events.
   * Returns an array of `{ room_id, via, suggested, order }`.
   */
  async listSpaceChildren(spaceId) {
    try {
      const events = await this._fetch(
        `/_matrix/client/v3/rooms/${encodeURIComponent(spaceId)}/state`,
      );
      const out = [];
      for (const ev of events || []) {
        if (
          ev.type === 'm.space.child' &&
          ev.state_key &&
          ev.content &&
          Object.keys(ev.content).length > 0
        ) {
          out.push({
            room_id: ev.state_key,
            via: ev.content.via || [],
            suggested: !!ev.content.suggested,
            order: ev.content.order || null,
          });
        }
      }
      return out;
    } catch (e) {
      if (e.status === 404 || e.errcode === 'M_NOT_FOUND') return [];
      if (e.status === 403) return [];
      throw e;
    }
  }

  _serverNameFromUserId() {
    if (!this.userId) return '';
    const at = this.userId.indexOf(':');
    return at === -1 ? '' : this.userId.slice(at + 1);
  }

  /**
   * Leave a room and forget it. Matrix has no "delete room" operation for
   * regular users — leaving + forgetting removes the room from your own
   * view, which is the closest user-facing equivalent. Other members keep
   * their copies until they leave too.
   */
  async leaveRoom(roomId) {
    await this._leaveRoomRaw(roomId);
    try {
      await this._fetch(`/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/forget`, {
        method: 'POST',
        body: '{}',
      });
    } catch (e) {
      // Forget can fail if the server already cleaned up — non-fatal.
      if (e.status !== 404 && e.errcode !== 'M_NOT_FOUND') throw e;
    }
    return { room_id: roomId, left: true };
  }

  async _leaveRoomRaw(roomId) {
    return this._fetch(`/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/leave`, {
      method: 'POST',
      body: '{}',
    });
  }

  async sync(opts = {}) {
    const timeout = opts.timeout || 30000;
    let reqPath = `/_matrix/client/v3/sync?timeout=${timeout}`;
    if (opts.since) reqPath += `&since=${encodeURIComponent(opts.since)}`;
    return this._fetch(reqPath);
  }

  // ── Profile management ───────────────────────────────────────────────────────

  /**
   * Fetch a Matrix profile (displayname + avatar mxc URI) for any user.
   * Unauthenticated on most homeservers; works for any visible userId.
   * Returns {displayname, avatar_url} with null fields when unset.
   *
   * @param {string} userId - full Matrix user id, e.g. "@alice:server"
   */
  async getProfile(userId) {
    try {
      const data = await this._fetch(
        `/_matrix/client/v3/profile/${encodeURIComponent(userId)}`,
      );
      return {
        displayname: data.displayname || null,
        avatar_url: data.avatar_url || null,
      };
    } catch (e) {
      if (e.status === 404 || e.errcode === 'M_NOT_FOUND') {
        return { displayname: null, avatar_url: null };
      }
      throw e;
    }
  }

  /**
   * Search the homeserver's user directory.
   * Wraps `POST /_matrix/client/v3/user_directory/search`. Note the server may
   * return only users it considers "visible" to the caller (rooms in common,
   * public profile, etc.) — for an exhaustive subnet roster prefer
   * `Subnet.listSubnetUsers()`.
   *
   * @param {string} searchTerm - substring of userId or displayname
   * @param {number} [limit=20]
   * @returns {Promise<{results: Array<{user_id: string, display_name: string|null, avatar_url: string|null}>, limited: boolean}>}
   */
  async searchUserDirectory(searchTerm, limit = 20) {
    return this._fetch('/_matrix/client/v3/user_directory/search', {
      method: 'POST',
      body: JSON.stringify({ search_term: String(searchTerm || ''), limit }),
    });
  }

  /**
   * Set the Matrix display name for the logged-in user.
   * @param {string} displayName
   */
  async setDisplayName(displayName) {
    return this._fetch(
      `/_matrix/client/v3/profile/${encodeURIComponent(this.userId)}/displayname`,
      { method: 'PUT', body: JSON.stringify({ displayname: displayName }) },
    );
  }

  /**
   * Set the Matrix avatar URL (must be an mxc:// URI).
   * Use uploadMedia() first to get the mxc:// URI from a local file.
   * @param {string} mxcUrl
   */
  async setAvatarUrl(mxcUrl) {
    return this._fetch(
      `/_matrix/client/v3/profile/${encodeURIComponent(this.userId)}/avatar_url`,
      { method: 'PUT', body: JSON.stringify({ avatar_url: mxcUrl }) },
    );
  }

  // ── Media upload / download ──────────────────────────────────────────────────

  /**
   * Upload binary data to the Matrix media repository.
   * @param {Buffer} buffer - File data
   * @param {string} contentType - MIME type (e.g. "image/png")
   * @param {string} [filename] - Optional filename hint
   * @returns {Promise<{content_uri: string}>} mxc:// URI of the uploaded file
   */
  async uploadMedia(buffer, contentType, filename) {
    const qs = filename ? `?filename=${encodeURIComponent(filename)}` : '';
    const res = await this._fetchRaw(`/_matrix/media/v3/upload${qs}`, {
      method: 'POST',
      headers: { 'Content-Type': contentType },
      body: buffer,
    });
    return res.json();
  }

  /**
   * Download a file from the Matrix media repository.
   * @param {string} mxcUrl - mxc:// URI (e.g. from an attachment)
   * @returns {Promise<Buffer>} Raw file bytes
   *
   * Note: files shared in E2E-encrypted rooms have their payload encrypted
   * with AES-CTR. This method downloads the raw (still-encrypted) bytes.
   * The attachment object returned by readMessages() includes an `encrypted`
   * flag when the file needs client-side decryption.
   */
  async downloadMedia(mxcUrl) {
    const match = mxcUrl.match(/^mxc:\/\/([^/]+)\/(.+)$/);
    if (!match) throw new Error(`Invalid mxc URL: ${mxcUrl}`);
    const [, serverName, mediaId] = match;
    const encodedServer = encodeURIComponent(serverName);
    const encodedMedia = encodeURIComponent(mediaId);
    // Try the authenticated media endpoint (Synapse ≥1.95 / Matrix 1.11)
    // and fall back to the unauthenticated v3 endpoint.
    let res;
    try {
      res = await this._fetchRaw(
        `/_matrix/client/v1/media/download/${encodedServer}/${encodedMedia}`,
      );
    } catch (e) {
      if (e.status !== 404 && e.errcode !== 'M_UNRECOGNIZED') throw e;
      res = await this._fetchRaw(
        `/_matrix/media/v3/download/${encodedServer}/${encodedMedia}`,
      );
    }
    return Buffer.from(await res.arrayBuffer());
  }

  /**
   * Download and decrypt an E2E-encrypted file shared in a Matrix room.
   *
   * @param {string} mxcUrl - mxc:// URI (from attachment.mxc_url)
   * @param {object} encryptInfo - EncryptedFile object from attachment.encrypt_info
   *   { url, key: {k, alg, ...}, iv, hashes: {sha256}, v }
   * @returns {Promise<Buffer>} Decrypted file bytes
   */
  async downloadMediaDecrypted(mxcUrl, encryptInfo) {
    const crypto = require('crypto');
    const ciphertext = await this.downloadMedia(mxcUrl);

    // Verify SHA-256 of ciphertext before decryption
    if (encryptInfo.hashes?.sha256) {
      const actualHash = crypto.createHash('sha256').update(ciphertext).digest('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      const expectedHash = encryptInfo.hashes.sha256
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      if (actualHash !== expectedHash) {
        throw new Error(`SHA256 hash mismatch: got ${actualHash}, expected ${expectedHash}`);
      }
    }

    // base64url → Buffer
    const b64urlDecode = s => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    const key = b64urlDecode(encryptInfo.key.k);
    const iv = b64urlDecode(encryptInfo.iv);

    const decipher = crypto.createDecipheriv('aes-256-ctr', key, iv);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  }

  // ── Cleanup ──────────────────────────────────────────────────────────────────

  async close() {
    if (this.olmMachine) {
      try { await this.olmMachine.close(); } catch {}
      this.olmMachine = null;
    }
    if (this.memoryStore) {
      this.memoryStore.close();
      this.memoryStore = null;
    }
  }
}

module.exports = { E2EMatrixClient };
