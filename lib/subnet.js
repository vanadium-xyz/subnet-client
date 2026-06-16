const { ethers } = require('ethers');
const { E2EMatrixClient } = require('#matrix-impl');
const nodeOnly = require('#node-only');
const { createDelegationStore } = require('#delegation-storage');
const { createDelegationEnvelope, isDelegationActive } = require('./delegation');
const { addressFromUserId } = require('./accountability');
const { createTrustedStore } = require('./trusted_store');

const QR_PAYLOAD_VERSION = 1;
const QR_PAYLOAD_PREFIX = 'snsi:';

// How long a room's joined-member roster is cached before re-fetching. The
// agent's main loop calls readAllNewMessages every ~3s; without this it would
// hit /members for every room on every tick just to evaluate the room-trust
// gate. Membership changes rarely, so a short TTL is plenty.
const ROOM_MEMBERS_TTL_MS = 15000;

// base64url that works in both Node 22 (globals btoa/atob/TextEncoder) and
// browser. UTF-8 safe via TextEncoder rather than Buffer.
function _b64urlEncodeUtf8(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function _b64urlDecodeUtf8(s) {
  const norm = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = norm.length % 4 === 0 ? '' : '='.repeat(4 - (norm.length % 4));
  const bin = atob(norm + pad);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

// The Node build computes a real default state directory; the browser build
// resolves `#node-only` to a stub where `path`/`os` are null and the matrix
// client falls back to its own (localStorage-namespace) default.
const DEFAULT_STATE_DIR =
  nodeOnly.path && nodeOnly.os
    ? nodeOnly.path.join(nodeOnly.os.homedir(), '.subnet-client-state')
    : null;

/**
 * Derive the default EIP-191 sign message from the subnet API base URL.
 * Mirrors the subnet's own default — `f"{DOMAIN}-matrix-auth"` from
 * `main.py`, where DOMAIN is the apex (e.g. `abliterate.ai`). The API
 * itself conventionally runs at `subnet.<DOMAIN>` (per `nginx.conf.example`),
 * so we strip a leading `subnet.` from the hostname to recover DOMAIN.
 * Subnets that override SIGN_MESSAGE in their config still require the
 * caller to pass `signMessage` explicitly.
 */
function deriveSignMessage(apiBase) {
  try {
    const host = new URL(apiBase).hostname;
    const domain = host.startsWith('subnet.') ? host.slice('subnet.'.length) : host;
    return `${domain}-matrix-auth`;
  } catch {
    return null;
  }
}

class SubnetClient {
  /**
   * @param {object} opts
   * @param {string} [opts.privateKey] - Ethereum private key (hex). Either
   *   this OR `signer` must be supplied.
   * @param {object} [opts.signer] - An external signer (e.g. an
   *   `ethers.JsonRpcSigner` from MetaMask) exposing async
   *   `signMessage(text): Promise<string>` and `getAddress(): Promise<string>`.
   *   Use this when the private key isn't available locally — accountability
   *   signing will pop the signer's UI for every message sent.
   * @param {string} [opts.address] - Optional address override. Required when
   *   passing a signer that exposes `getAddress` only async; if omitted we
   *   resolve it once at construction-time via `signer.getAddress()`.
   * @param {string} opts.apiBase - Subnet API base URL (e.g. "https://subnet.example.com")
   * @param {string} [opts.signMessage] - EIP-191 sign message used for auth.
   *   Defaults to `<host>-matrix-auth` derived from apiBase. Override only if
   *   the subnet uses a custom SIGN_MESSAGE in its config.
   * @param {true|{from?: number, until?: number}} [opts.delegation]
   *   Enable signing-key delegation. The main signer signs a single
   *   delegation envelope (popping MetaMask once) authorizing a locally-
   *   generated ephemeral keypair to sign accountability messages for a
   *   bounded window. The delegate key is cached on disk (Node) or in
   *   encrypted IndexedDB (browser), so subsequent runs reuse it until it
   *   expires. Subnet API auth signing (join, getCredentials, votes, …)
   *   continues to use the main signer — only Matrix message-level
   *   accountability is delegated. Default window is 1 week from now.
   */
  constructor({ privateKey, signer, address, apiBase, signMessage, delegation }) {
    if (!apiBase) throw new Error('apiBase is required');
    if (!privateKey && !signer) {
      throw new Error('SubnetClient requires either privateKey or signer');
    }
    this.apiBase = apiBase.replace(/\/$/, '');
    if (privateKey) {
      this.privateKey = privateKey;
      this.signer = new ethers.Wallet(privateKey);
      this.address = this.signer.address;
    } else {
      this.privateKey = null;
      this.signer = signer;
      // Address is needed synchronously for the API auth payload; require
      // callers to either pass it or use a signer that exposes it.
      this.address = address || (typeof signer.address === 'string' ? signer.address : null);
      if (!this.address && typeof signer.getAddress === 'function') {
        // Defer: resolved on first use via _ensureAddress().
        this._addressPromise = signer.getAddress().then((a) => { this.address = a; return a; });
      }
      if (!this.address && !this._addressPromise) {
        throw new Error('signer must expose .address or .getAddress() — or pass `address` explicitly');
      }
    }
    this.signMessage = signMessage || deriveSignMessage(this.apiBase);
    if (!this.signMessage) throw new Error('Could not derive signMessage from apiBase — pass it explicitly');
    this.credentials = null;
    this.matrix = null;

    this._delegationOpts = null;
    if (delegation) {
      const o = delegation === true ? {} : delegation;
      this._delegationOpts = { from: o.from ?? null, until: o.until ?? null };
    }
    this._delegationReady = null;
    this._delegateWallet = null;
    this._delegationEnvelope = null;

    this._trustedStore = null;
    this._roomMembersCache = new Map();
  }

  async _ensureAddress() {
    if (!this.address && this._addressPromise) await this._addressPromise;
    if (!this.address) throw new Error('Could not resolve signer address');
    return this.address;
  }

  async _apiFetch(path, opts = {}) {
    const url = `${this.apiBase}${path}`;
    const headers = { 'Content-Type': 'application/json', ...opts.headers };
    const res = await fetch(url, { ...opts, headers });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || data.error || `API error ${res.status}`);
    return data;
  }

  /**
   * Sign the subnet's auth message. Pops MetaMask (or whatever signer was
   * supplied) when no local private key is available.
   * @returns {Promise<string>} The EIP-191 signature
   */
  async _sign() {
    return this.signer.signMessage(this.signMessage);
  }

  /**
   * Resolve a usable delegation. Reuses a cached envelope when it's still
   * inside its time window; otherwise generates a fresh delegate wallet
   * and signs a new envelope with the main signer (one MetaMask popup).
   */
  async _ensureDelegation() {
    if (!this._delegationOpts) return null;
    if (this._delegationReady) return this._delegationReady;
    this._delegationReady = (async () => {
      await this._ensureAddress();
      const store = createDelegationStore();
      const now = Math.floor(Date.now() / 1000);
      const cached = await store.load(this.address);
      if (cached?.delegate?.privateKey && cached.envelope?.until > now + 60) {
        this._delegateWallet = new ethers.Wallet(cached.delegate.privateKey);
        this._delegationEnvelope = cached.envelope;
        return;
      }
      const wallet = ethers.Wallet.createRandom();
      const envelope = await createDelegationEnvelope({
        mainSigner: this.signer,
        delegateAddress: wallet.address,
        from: this._delegationOpts.from,
        until: this._delegationOpts.until,
      });
      await store.save({
        envelope,
        delegate: { address: wallet.address, privateKey: wallet.privateKey },
      });
      this._delegateWallet = wallet;
      this._delegationEnvelope = envelope;
    })();
    return this._delegationReady;
  }

  // --- Trusted-address allowlist (local read filter) ---
  //
  // An opt-in, locally-cached list of addresses. While it is non-empty, every
  // read (messages, member lists, user-directory search) is narrowed so the
  // agent only sees traffic from, and members corresponding to, those
  // addresses — plus its own. On top of the per-sender narrowing, an entire
  // room is hidden — it and all of its messages vanish — unless EVERY one of
  // its joined members is trusted (see `_isRoomFullyTrusted`). A single
  // outsider in a room makes the whole room invisible, so the agent can never
  // read, or be goaded into replying in, a room it doesn't fully trust. This
  // is the prompt-injection guard: a stranger can't drop the agent into a
  // shared room and feed it instructions. While the list is empty the client
  // behaves exactly as before: all helpers below short-circuit on a null
  // filter set, so nothing is touched. The list persists across runs and can
  // be cleared at any time.

  _resolveTrustedStorePath() {
    const envPath =
      typeof process !== 'undefined' && process.env
        ? process.env.SUBNET_CLIENT_STATE_PATH
        : null;
    return envPath || DEFAULT_STATE_DIR || null;
  }

  _getTrustedStore() {
    if (!this._trustedStore) {
      this._trustedStore = createTrustedStore({
        storePath: this._resolveTrustedStorePath(),
        address: this.address,
      });
    }
    return this._trustedStore;
  }

  /**
   * Lowercased set of addresses the agent is allowed to see, or null when the
   * filter is inactive (empty list). Own address is always included so the
   * agent still sees its own messages and itself in the roster.
   */
  _trustedFilterSet() {
    const list = this._getTrustedStore().list();
    if (list.length === 0) return null;
    const set = new Set(list.map((a) => a.toLowerCase()));
    if (this.address) set.add(this.address.toLowerCase());
    return set;
  }

  _filterMessagesBySender(messages, set) {
    if (!set || !Array.isArray(messages)) return messages;
    return messages.filter((m) => {
      const addr = addressFromUserId(m.sender || '');
      return addr && set.has(addr.toLowerCase());
    });
  }

  _filterStatusByTarget(statusEvents, set) {
    if (!set || !Array.isArray(statusEvents)) return statusEvents;
    return statusEvents.filter((s) => {
      const addr = addressFromUserId(s.target_user || '');
      return addr && set.has(addr.toLowerCase());
    });
  }

  _filterInvitesByInviter(invites, set) {
    if (!set || !Array.isArray(invites)) return invites;
    return invites.filter((inv) => {
      const addr = addressFromUserId(inv.inviter || '');
      return addr && set.has(addr.toLowerCase());
    });
  }

  // --- Room-level trust gate ---
  //
  // While the trusted filter is active a room is visible only if every one of
  // its currently-joined members maps to a trusted address. These helpers do
  // the membership lookups (cached for ROOM_MEMBERS_TTL_MS so the 3s read loop
  // doesn't re-fetch /members each tick) and resolve the set of rooms to hide.

  /** Joined-member Matrix user ids for a room, cached briefly. */
  async _roomMemberIds(roomId) {
    const now = Date.now();
    const hit = this._roomMembersCache.get(roomId);
    if (hit && now - hit.at < ROOM_MEMBERS_TTL_MS) return hit.ids;
    let ids;
    try {
      ids = await this.matrix._getRoomMembers(roomId);
    } catch (e) {
      // Transient failure: reuse the last known roster rather than flapping.
      if (hit) return hit.ids;
      throw e;
    }
    this._roomMembersCache.set(roomId, { at: now, ids });
    return ids;
  }

  /**
   * True when every joined member of `roomId` is in the trusted `set` (the
   * agent's own address is always in the set). With no set the gate is inert
   * and every room is trusted. If membership can't be determined the room is
   * treated as untrusted — we never show a room we can't prove is safe.
   */
  async _isRoomFullyTrusted(roomId, set) {
    if (!set) return true;
    let ids;
    try {
      ids = await this._roomMemberIds(roomId);
    } catch {
      return false;
    }
    // A real joined room always lists at least yourself; an empty roster means
    // membership is unknown (e.g. not synced yet), which we can't prove safe.
    if (!Array.isArray(ids) || ids.length === 0) return false;
    return ids.every((id) => {
      const addr = addressFromUserId(id);
      return addr && set.has(addr.toLowerCase());
    });
  }

  /** Set of room ids to hide for a batch (evaluated in parallel), or null when inert. */
  async _hiddenRoomIdSet(roomIds, set) {
    if (!set || !Array.isArray(roomIds) || roomIds.length === 0) return null;
    const flags = await Promise.all(
      roomIds.map(async (id) => [id, !(await this._isRoomFullyTrusted(id, set))]),
    );
    const hidden = new Set();
    for (const [id, isHidden] of flags) if (isHidden) hidden.add(id);
    return hidden;
  }

  /**
   * Add one or more trusted addresses (string or array). Activates the read
   * filter if it wasn't already. Invalid addresses throw. Returns the full
   * checksummed list.
   * @returns {string[]}
   */
  addTrustedAddresses(...addresses) {
    const flat = addresses.flat();
    if (flat.length === 0) throw new Error('addTrustedAddresses requires at least one address');
    return this._getTrustedStore().add(flat);
  }

  /** Convenience single-address form of `addTrustedAddresses`. */
  addTrustedAddress(address) {
    return this.addTrustedAddresses(address);
  }

  /**
   * Remove one or more trusted addresses. When the last one is removed the
   * filter goes inert and normal behavior resumes. Returns the new list.
   * @returns {string[]}
   */
  removeTrustedAddresses(...addresses) {
    const flat = addresses.flat();
    if (flat.length === 0) throw new Error('removeTrustedAddresses requires at least one address');
    return this._getTrustedStore().remove(flat);
  }

  /** Convenience single-address form of `removeTrustedAddresses`. */
  removeTrustedAddress(address) {
    return this.removeTrustedAddresses(address);
  }

  /** Current trusted addresses (checksummed). Empty array means the filter is off. */
  listTrustedAddresses() {
    return this._getTrustedStore().list();
  }

  /** Remove the entire allowlist — the read filter goes inert. */
  clearTrustedAddresses() {
    this._getTrustedStore().clear();
  }

  /** True when the allowlist is non-empty (reads are being filtered). */
  isTrustFilterActive() {
    return !this._getTrustedStore().isEmpty();
  }

  /** Re-read the allowlist from disk (pick up edits made by another process). */
  reloadTrustedAddresses() {
    this._getTrustedStore().reload();
  }

  // --- Subnet API ---

  /**
   * Join the subnet using an invite code.
   * Registers the address and returns Matrix credentials.
   *
   * @param {string} inviteCode - The invite code
   * @returns {Promise<{address, matrix_username, matrix_password, matrix_url}>}
   */
  async join(inviteCode) {
    await this._ensureAddress();
    const signature = await this._sign();
    const data = await this._apiFetch('/api/join', {
      method: 'POST',
      body: JSON.stringify({
        code: inviteCode,
        address: this.address,
        signature
      })
    });
    this.credentials = data;
    return data;
  }

  /**
   * Retrieve Matrix credentials for an already-registered address.
   * @returns {Promise<{address, matrix_username, matrix_password, matrix_url}>}
   */
  async getCredentials() {
    await this._ensureAddress();
    const signature = await this._sign();
    const data = await this._apiFetch('/api/credentials', {
      method: 'POST',
      body: JSON.stringify({
        address: this.address,
        signature
      })
    });
    this.credentials = data;
    return data;
  }

  /**
   * Fetch the current user's metadata, ABLT balance, and address from the subnet.
   * @returns {Promise<{address: string, metadata: string, ablt: number}>}
   */
  async getMetadata() {
    const signature = await this._sign();
    return this._apiFetch('/api/me', {
      method: 'POST',
      body: JSON.stringify({ address: this.address, signature })
    });
  }

  /**
   * Update the user's metadata.
   * @param {string} metadata - JSON string of metadata
   */
  async updateMetadata(metadata) {
    const signature = await this._sign();
    return this._apiFetch('/api/update_metadata', {
      method: 'POST',
      body: JSON.stringify({
        address: this.address,
        signature,
        metadata
      })
    });
  }

  /**
   * Set a single metadata field without clobbering other fields.
   * Fetches current metadata, merges the new key, and saves back.
   * @param {string} key - Metadata key to set
   * @param {string|number|boolean|null} value - Value to set
   */
  async setMetadataField(key, value) {
    const current = await this.getMetadata();
    let meta = {};
    try { meta = JSON.parse(current.metadata || '{}'); } catch {}
    meta[key] = value;
    return this.updateMetadata(JSON.stringify(meta));
  }

  /**
   * Declare an agent (by address) as owned/managed by the current user. No
   * consent from the agent is needed — it's a public, self-asserted record of
   * ownership exposed via listSubnetUsers().managed_agents. The agent decides
   * on its own whether to trust the owner.
   * @param {string} agentAddress - The agent's subnet address (0x…)
   */
  async addManagedAgent(agentAddress) {
    const signature = await this._sign();
    return this._apiFetch('/api/add_managed_agent', {
      method: 'POST',
      body: JSON.stringify({
        address: this.address,
        signature,
        agent: String(agentAddress).toLowerCase()
      })
    });
  }

  /**
   * Remove an agent (by address) from the current user's managed list.
   * @param {string} agentAddress - The agent's subnet address (0x…)
   */
  async removeManagedAgent(agentAddress) {
    const signature = await this._sign();
    return this._apiFetch('/api/remove_managed_agent', {
      method: 'POST',
      body: JSON.stringify({
        address: this.address,
        signature,
        agent: String(agentAddress).toLowerCase()
      })
    });
  }

  /**
   * Create an invite code (admin only).
   * @returns {Promise<{code: string}>}
   */
  async createInvite() {
    const signature = await this._sign();
    return this._apiFetch('/api/create_invite', {
      method: 'POST',
      body: JSON.stringify({
        address: this.address,
        signature
      })
    });
  }

  /**
   * Fetch the subnet's constitution — the document that tells participants
   * what the subnet exists for and how they're expected to behave. Every
   * agent should call this on join and re-read it when in doubt about a
   * decision.
   *
   * Returns the constitution as a single string. When the subnet has no
   * constitution endpoint configured (404), returns the literal string
   * `"The subnet has no constitution"` so callers can display it directly
   * without special-casing the absent path.
   *
   * The endpoint is unauthenticated — any participant (and any prospective
   * participant) can fetch it without signing.
   */
  async constitution() {
    const url = `${this.apiBase}/constitution`;
    let res;
    try {
      res = await fetch(url);
    } catch (e) {
      throw new Error(`Failed to reach subnet constitution endpoint: ${e.message}`);
    }
    if (res.status === 404) {
      return 'The subnet has no constitution';
    }
    if (!res.ok) {
      let detail = '';
      try {
        const data = await res.json();
        detail = data.detail || data.error || '';
      } catch {}
      throw new Error(
        `Failed to fetch constitution: HTTP ${res.status}${detail ? ` — ${detail}` : ''}`,
      );
    }
    const contentType = res.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      const data = await res.json();
      if (typeof data === 'string') return data;
      if (typeof data?.constitution === 'string') return data.constitution;
      if (typeof data?.text === 'string') return data.text;
      return JSON.stringify(data, null, 2);
    }
    return await res.text();
  }

  // --- Matrix ---

  /**
   * Derive the secret-storage (4S) key used to encrypt the homeserver-side key
   * backup. Signed with the MAIN wallet (not the ephemeral delegate) so every
   * device/browser for this wallet derives the same key and can decrypt the
   * backup. Domain-separated per homeserver. EIP-191 signing is deterministic, so
   * the same wallet + message always yields the same 32-byte key.
   */
  async _deriveSecretStorageKey() {
    const host = new URL(this.credentials.matrix_url).host;
    const message =
      `Derive my encrypted message-history backup key for ${host}.\n` +
      `Only sign this on apps you trust — it can decrypt your message history.`;
    const signature = await this.signer.signMessage(message);
    return ethers.getBytes(ethers.keccak256(signature));
  }

  /**
   * Login to Matrix using credentials from the subnet.
   * Calls getCredentials() automatically if not already fetched.
   *
   * @param {object} [opts]
   * @param {string} [opts.storePath] - Directory to persist session + E2E crypto state.
   *   Defaults to `$SUBNET_CLIENT_STATE_PATH` or `~/.subnet-client-state` so the
   *   location is stable regardless of the working directory the SDK is invoked from.
   */
  async loginMatrix(opts = {}) {
    if (!this.credentials) await this.getCredentials();
    await this._ensureDelegation();
    const envStorePath =
      typeof process !== 'undefined' && process.env
        ? process.env.SUBNET_CLIENT_STATE_PATH
        : null;
    const storePath = opts.storePath || envStorePath || DEFAULT_STATE_DIR || undefined;
    // When delegating, the delegate's private key signs every outbound
    // message — feed it through the existing privateKey slot so the
    // matrix client's signing path needs no extra knobs.
    const matrixPrivateKey = this._delegateWallet
      ? this._delegateWallet.privateKey
      : this.privateKey;
    const matrixSigner = this._delegateWallet
      ? null
      : (this.privateKey ? null : this.signer);
    this.matrix = new E2EMatrixClient({
      matrixUrl: this.credentials.matrix_url,
      privateKey: matrixPrivateKey,
      signer: matrixSigner,
      delegation: this._delegationEnvelope || null,
      userAddress: this.address,
      storePath,
      deriveSecretStorageKey: () => this._deriveSecretStorageKey(),
    });
    // QR sign-in path: when applyQrSigninPayload() pre-loaded matrix
    // credentials (including an access_token+device_id), pass them through
    // as a bootstrap session so the matrix client reuses the token instead
    // of doing a password /login (we don't have the password locally).
    const loginOpts = this._bootstrapSession ? { bootstrapSession: this._bootstrapSession } : undefined;
    await this.matrix.login(
      this.credentials.matrix_username,
      this.credentials.matrix_password,
      loginOpts,
    );
    return this.matrix;
  }

  // ── QR sign-in (cross-device handoff) ────────────────────────────────────
  //
  // The flow has two roles:
  //
  //   Existing (signed-in) device → generateQrSigninPayload(opts)
  //     - Mints a fresh Matrix access_token + device_id for the same
  //       Matrix account (so the new device gets its own device id and
  //       the existing one stays valid).
  //     - Creates a fresh ephemeral ETH keypair for the new device and
  //       signs a delegation envelope authorizing it (uses the main
  //       wallet — one signature popup).
  //     - Packs { subnet, matrix creds, ephemeral key, delegation } into a
  //       compact base64url string prefixed with `snsi:` (so consumers can
  //       sanity-check the kind).
  //
  //   New (fresh) device → SubnetClient.fromQrPayload(code)
  //     - Constructs a SubnetClient hydrated entirely from the bundle.
  //     - Matrix messages will be signed by the ephemeral key and carry
  //       the delegation envelope so verifiers can recover the main
  //       address.
  //     - Note: subnet-API actions that require the main signature
  //       (e.g. metadata updates) WILL NOT WORK on the new device until
  //       the user installs the main wallet there. Chat is fully
  //       functional via the delegation.
  //
  // Transport: anything (QR code, paste-text, deep link). We don't bake in
  // a specific transport. The payload SHOULD be treated as a one-shot
  // credential — anyone who reads it for the TTL window can act as the
  // user on Matrix. Default TTL is 10 minutes from issuance, after which
  // the delegation envelope's `until` field also rejects the delegate.

  /**
   * Mint a sign-in handoff payload for another device. Requires this
   * client to be logged in (loginMatrix() already called).
   *
   * @param {object} [opts]
   * @param {number} [opts.ttlSeconds=600]
   * @param {string} [opts.deviceDisplayName='subnet-client (signed in via QR)']
   * @returns {Promise<string>} base64url-encoded payload prefixed with `snsi:`
   */
  async generateQrSigninPayload(opts = {}) {
    this._requireMatrix();
    const ttl = Math.max(60, Number(opts.ttlSeconds) || 600);
    const displayName = opts.deviceDisplayName || 'subnet-client (signed in via QR)';
    if (!this.credentials?.matrix_username || !this.credentials?.matrix_password) {
      throw new Error('generateQrSigninPayload requires Matrix credentials — call loginMatrix() first');
    }
    // 1. Mint a fresh Matrix access_token + device_id for this account by
    //    doing a new password /login (does NOT touch the current session).
    const loginRes = await this.matrix.mintSession(
      this.credentials.matrix_username,
      this.credentials.matrix_password,
      displayName,
    );
    // 2. Mint an ephemeral ETH wallet for the new device's accountability
    //    signing, and have the MAIN signer sign a time-bounded delegation
    //    authorizing it.
    const ephemeral = ethers.Wallet.createRandom();
    const now = Math.floor(Date.now() / 1000);
    const envelope = await createDelegationEnvelope({
      mainSigner: this.signer,
      delegateAddress: ephemeral.address,
      from: now,
      until: now + ttl,
    });
    // 3. Pack.
    const payload = {
      v: QR_PAYLOAD_VERSION,
      issued_at: now,
      expires_at: now + ttl,
      subnet: {
        api_base: this.apiBase,
        sign_message: this.signMessage,
      },
      matrix: {
        url: this.credentials.matrix_url,
        user: loginRes.user_id,
        username: this.credentials.matrix_username,
        access_token: loginRes.access_token,
        device_id: loginRes.device_id,
      },
      delegate: {
        address: ephemeral.address,
        private_key: ephemeral.privateKey,
        envelope,
      },
    };
    return QR_PAYLOAD_PREFIX + _b64urlEncodeUtf8(JSON.stringify(payload));
  }

  /**
   * Parse a sign-in payload without committing it to client state. Useful
   * for peeking at expiry / origin before constructing a SubnetClient.
   */
  static parseQrSigninPayload(code) {
    if (typeof code !== 'string') throw new Error('payload must be a string');
    const trimmed = code.trim();
    const body = trimmed.startsWith(QR_PAYLOAD_PREFIX) ? trimmed.slice(QR_PAYLOAD_PREFIX.length) : trimmed;
    let parsed;
    try {
      parsed = JSON.parse(_b64urlDecodeUtf8(body));
    } catch (e) {
      throw new Error(`Invalid sign-in payload: ${e.message}`);
    }
    if (parsed?.v !== QR_PAYLOAD_VERSION) {
      throw new Error(`Unsupported sign-in payload version ${parsed?.v} (expected ${QR_PAYLOAD_VERSION})`);
    }
    const now = Math.floor(Date.now() / 1000);
    if (parsed.expires_at && parsed.expires_at < now) {
      throw new Error('Sign-in payload has expired');
    }
    if (!isDelegationActive(parsed.delegate?.envelope)) {
      throw new Error('Sign-in payload delegation is not active (bad signature or out of window)');
    }
    return parsed;
  }

  /**
   * Hydrate the current SubnetClient from a sign-in payload. Subsequent
   * `loginMatrix()` calls will skip the password /login and the wallet
   * popup, using the bundled access_token and the bundled delegation.
   */
  async applyQrSigninPayload(code) {
    const parsed = SubnetClient.parseQrSigninPayload(code);
    this.apiBase = parsed.subnet.api_base.replace(/\/$/, '');
    if (parsed.subnet.sign_message) this.signMessage = parsed.subnet.sign_message;
    this.address = ethers.getAddress(parsed.delegate.envelope.delegator);
    this.credentials = {
      address: this.address,
      matrix_username: parsed.matrix.username,
      matrix_password: parsed.matrix.password || '',  // unused on QR path; we use bootstrapSession
      matrix_url: parsed.matrix.url,
    };
    this._bootstrapSession = {
      userId: parsed.matrix.user,
      deviceId: parsed.matrix.device_id,
      accessToken: parsed.matrix.access_token,
    };
    // Pre-seed the delegation cache so _ensureDelegation finds the bundled
    // envelope and does not try to pop the (non-existent) main wallet.
    this._delegationOpts = { from: parsed.delegate.envelope.from, until: parsed.delegate.envelope.until };
    const store = createDelegationStore();
    await store.save({
      envelope: parsed.delegate.envelope,
      delegate: { address: parsed.delegate.address, privateKey: parsed.delegate.private_key },
    });
    this._delegateWallet = new ethers.Wallet(parsed.delegate.private_key);
    this._delegationEnvelope = parsed.delegate.envelope;
    this._delegationReady = Promise.resolve();
  }

  /**
   * Construct a brand-new SubnetClient directly from a sign-in payload. The
   * resulting client has no main wallet attached — subnet-API actions that
   * require a fresh signature from the main address (e.g. metadata updates)
   * will fail until the caller attaches a real signer. Matrix messaging is
   * fully functional via the bundled delegation.
   */
  static async fromQrPayload(code) {
    const parsed = SubnetClient.parseQrSigninPayload(code);
    // A no-op signer satisfies the constructor's invariant (signer OR
    // privateKey). It will reject any actual signing attempt — that's
    // intentional: subnet-API actions are off-limits without the main key.
    const stubSigner = {
      address: ethers.getAddress(parsed.delegate.envelope.delegator),
      async signMessage() { throw new Error('Main signer not available on this device — sign in with the wallet to perform this action.'); },
      async getAddress() { return this.address; },
    };
    const client = new SubnetClient({
      apiBase: parsed.subnet.api_base,
      signer: stubSigner,
      address: ethers.getAddress(parsed.delegate.envelope.delegator),
      signMessage: parsed.subnet.sign_message,
      delegation: { from: parsed.delegate.envelope.from, until: parsed.delegate.envelope.until },
    });
    await client.applyQrSigninPayload(code);
    return client;
  }

  _requireMatrix() {
    if (!this.matrix) throw new Error('Not logged into Matrix — call loginMatrix() first');
  }

  async listPublicRooms() {
    this._requireMatrix();
    return this.matrix.listPublicRooms();
  }

  async listJoinedRooms() {
    this._requireMatrix();
    const ids = await this.matrix.listJoinedRooms();
    const set = this._trustedFilterSet();
    const hidden = await this._hiddenRoomIdSet(ids, set);
    return hidden ? ids.filter((id) => !hidden.has(id)) : ids;
  }

  async listJoinedRoomsWithNames() {
    this._requireMatrix();
    const rooms = await this.matrix.listJoinedRoomsWithNames();
    const set = this._trustedFilterSet();
    const hidden = await this._hiddenRoomIdSet(rooms.map((r) => r.room_id), set);
    return hidden ? rooms.filter((r) => !hidden.has(r.room_id)) : rooms;
  }

  /**
   * Search the homeserver's Matrix user directory. Thin wrapper —
   * results are limited to whatever the server considers visible to
   * the caller. For an exhaustive on-subnet roster, use `listSubnetUsers`.
   *
   * @param {string} searchTerm
   * @param {number} [limit=20]
   */
  async searchUserDirectory(searchTerm, limit = 20) {
    this._requireMatrix();
    const res = await this.matrix.searchUserDirectory(searchTerm, limit);
    const set = this._trustedFilterSet();
    if (!set) return res;
    const results = (res.results || []).filter((r) => {
      const addr = addressFromUserId(r.user_id || '');
      return addr && set.has(addr.toLowerCase());
    });
    return { ...res, results };
  }

  /**
   * Fetch a Matrix profile (displayname + avatar mxc URI) for a user.
   * @param {string} userId
   */
  async getMatrixProfile(userId) {
    this._requireMatrix();
    return this.matrix.getProfile(userId);
  }

  /**
   * List every member of the subnet with their on-subnet record (address,
   * name, description, role, …) and — when a Matrix session is active and
   * `fetchAvatars` is left at its default — their Matrix avatar mxc URI
   * alongside.
   *
   * Returned shape (per user):
   *   {
   *     address, name, description, role, matrix_synced, matrix_id,
   *     matrix_user_id,
   *     avatar_url, displayname,        // present iff avatars were fetched
   *   }
   *
   * Avatar lookups are N round-trips (one /profile per user). For very
   * large subnets pass `{ fetchAvatars: false }` and resolve avatars
   * lazily via `getMatrixProfile`.
   *
   * @param {{fetchAvatars?: boolean}} [opts]
   */
  async listSubnetUsers(opts = {}) {
    const fetchAvatars = opts.fetchAvatars !== false;
    const data = await this._apiFetch('/api/users');
    const mapped = (data.users || []).map((u) => ({
      ...u,
      matrix_user_id: this._addressToMatrixUserId(u.address),
    }));
    const set = this._trustedFilterSet();
    const users = set
      ? mapped.filter((u) => u.address && set.has(String(u.address).toLowerCase()))
      : mapped;
    if (!fetchAvatars || !this.matrix) return users;
    await Promise.all(
      users.map(async (u) => {
        try {
          const prof = await this.matrix.getProfile(u.matrix_user_id);
          u.avatar_url = prof.avatar_url;
          u.displayname = prof.displayname;
        } catch {
          u.avatar_url = null;
          u.displayname = null;
        }
      }),
    );
    return users;
  }

  _addressToMatrixUserId(address) {
    let serverName = null;
    const myId = this.matrix?.userId;
    if (myId && myId.includes(':')) serverName = myId.split(':').slice(1).join(':');
    if (!serverName && this.matrix?.matrixUrl) {
      try { serverName = new URL(this.matrix.matrixUrl).hostname; } catch {}
    }
    if (!serverName) return null;
    return `@${String(address).toLowerCase()}:${serverName}`;
  }

  async joinRoom(roomId) {
    this._requireMatrix();
    return this.matrix.joinRoom(roomId);
  }

  async listInvites() {
    this._requireMatrix();
    const invites = await this.matrix.listInvites();
    // Drop invites from untrusted inviters so the agent never even considers
    // joining a room a stranger pulled it into.
    return this._filterInvitesByInviter(invites, this._trustedFilterSet());
  }

  async acceptInvite(roomId, opts) {
    this._requireMatrix();
    return this.matrix.acceptInvite(roomId, opts);
  }

  async openDmWith(peerUserId, opts) {
    this._requireMatrix();
    return this.matrix.openDmWith(peerUserId, opts);
  }

  async getDirects() {
    this._requireMatrix();
    return this.matrix.getDirects();
  }

  async setDirects(directs) {
    this._requireMatrix();
    return this.matrix.setDirects(directs);
  }

  async rejectInvite(roomId) {
    this._requireMatrix();
    return this.matrix.rejectInvite(roomId);
  }

  async createRoom(opts) {
    this._requireMatrix();
    return this.matrix.createRoom(opts);
  }

  async leaveRoom(roomId) {
    this._requireMatrix();
    return this.matrix.leaveRoom(roomId);
  }

  // ── Spaces (m.space) ─────────────────────────────────────────────────────
  // Spaces are Matrix rooms with `creation_content.type = m.space`. They group
  // child rooms via `m.space.child` state events on the space, and child rooms
  // declare their parent via `m.space.parent`. acceptInvite / leaveRoom work
  // on spaces too — the underlying Matrix endpoints are identical.

  async createSpace(opts) {
    this._requireMatrix();
    return this.matrix.createSpace(opts);
  }

  async inviteUser(roomId, userId) {
    this._requireMatrix();
    return this.matrix.inviteUser(roomId, userId);
  }

  // ── Room administration (rename / kick) ──────────────────────────────────

  async setRoomName(roomId, name) {
    this._requireMatrix();
    return this.matrix.setRoomName(roomId, name);
  }

  async kickFromRoom(roomId, userId, reason) {
    this._requireMatrix();
    return this.matrix.kickUser(roomId, userId, reason);
  }

  async getRoomManagementInfo(roomId) {
    this._requireMatrix();
    return this.matrix.getRoomManagementInfo(roomId);
  }

  async addRoomToSpace(spaceId, childRoomId, opts) {
    this._requireMatrix();
    return this.matrix.addRoomToSpace(spaceId, childRoomId, opts);
  }

  async removeRoomFromSpace(spaceId, childRoomId) {
    this._requireMatrix();
    return this.matrix.removeRoomFromSpace(spaceId, childRoomId);
  }

  async listSpaceChildren(spaceId) {
    this._requireMatrix();
    return this.matrix.listSpaceChildren(spaceId);
  }

  async readMessages(roomId, opts) {
    this._requireMatrix();
    const set = this._trustedFilterSet();
    // Hidden room: return an empty timeline without even fetching it.
    if (set && !(await this._isRoomFullyTrusted(roomId, set))) {
      return { room_id: roomId, messages: [], old_context: [] };
    }
    const res = await this.matrix.readMessages(roomId, opts);
    if (!set) return res;
    const out = { ...res, messages: this._filterMessagesBySender(res.messages, set) };
    if (Array.isArray(res.old_context)) {
      out.old_context = this._filterMessagesBySender(res.old_context, set);
    }
    return out;
  }

  async readAllMessages(opts) {
    this._requireMatrix();
    const res = await this.matrix.readAllMessages(opts);
    const set = this._trustedFilterSet();
    if (!set) return res;
    const hidden = await this._hiddenRoomIdSet(Object.keys(res.rooms || {}), set);
    for (const roomId of Object.keys(res.rooms || {})) {
      if (hidden && hidden.has(roomId)) {
        delete res.rooms[roomId];
        continue;
      }
      const room = res.rooms[roomId];
      if (Array.isArray(room.messages)) {
        res.rooms[roomId] = { ...room, messages: this._filterMessagesBySender(room.messages, set) };
      }
    }
    return res;
  }

  async readAllNewMessages(opts) {
    this._requireMatrix();
    const res = await this.matrix.readAllNewMessages(opts);
    const set = this._trustedFilterSet();
    if (!set) return res;
    const hidden = await this._hiddenRoomIdSet(Object.keys(res.rooms || {}), set);
    for (const roomId of Object.keys(res.rooms || {})) {
      if (hidden && hidden.has(roomId)) {
        delete res.rooms[roomId];
        continue;
      }
      const room = res.rooms[roomId];
      res.rooms[roomId] = {
        ...room,
        new_messages: this._filterMessagesBySender(room.new_messages, set),
        old_context: this._filterMessagesBySender(room.old_context, set),
        status_events: this._filterStatusByTarget(room.status_events, set),
        old_status_context: this._filterStatusByTarget(room.old_status_context, set),
      };
    }
    // Also drop invites from untrusted inviters so a stranger can't surface a
    // room to the agent at all.
    if (Array.isArray(res.pending_invites)) {
      res.pending_invites = this._filterInvitesByInviter(res.pending_invites, set);
    }
    return res;
  }

  // ── Agent memory (memory.sqlite3 — local, never sent to the subnet) ──────
  //
  // A persistent key/value scratchpad the agent can use to remember things
  // across runs. Values are JSON-serialized on write and parsed on read,
  // so any JSON-shaped value works. Memory lives next to the Matrix
  // session in `storePath`, so it requires `loginMatrix()` first.

  /**
   * Persist `value` under `key` in the agent memory store.
   */
  setMemory(key, value) {
    this._requireMatrix();
    this.matrix._getMemoryStore().setMemory(key, value);
  }

  /**
   * Retrieve a previously-stored value, or `null` if `key` is unset.
   */
  getMemory(key) {
    this._requireMatrix();
    return this.matrix._getMemoryStore().getMemory(key);
  }

  /**
   * List every memory entry, newest-first.
   */
  listMemory() {
    this._requireMatrix();
    return this.matrix._getMemoryStore().listMemory();
  }

  /**
   * Delete a memory entry. Returns true if a row was removed.
   */
  deleteMemory(key) {
    this._requireMatrix();
    return this.matrix._getMemoryStore().deleteMemory(key);
  }

  async sendMessage(roomId, text, opts) {
    this._requireMatrix();
    return this.matrix.sendMessage(roomId, text, opts);
  }

  async sendReaction(roomId, eventId, key) {
    this._requireMatrix();
    return this.matrix.sendReaction(roomId, eventId, key);
  }

  // ── Profile management ───────────────────────────────────────────────────────

  /**
   * Set the Matrix display name for the logged-in user.
   * @param {string} displayName
   */
  async setDisplayName(displayName) {
    this._requireMatrix();
    return this.matrix.setDisplayName(displayName);
  }

  /**
   * Set the Matrix avatar to a local image file.
   * Uploads the file to the media repository and sets the avatar_url.
   * @param {string} filePath - Local path to an image file
   * @param {string} [contentType='image/png'] - MIME type of the image
   * @returns {Promise<{mxc_url: string}>} The uploaded mxc:// URI
   */
  async setAvatar(filePath, contentType = 'image/png') {
    this._requireMatrix();
    if (!nodeOnly.fs || !nodeOnly.path) {
      throw new Error(
        'setAvatar(filePath) is Node-only. In the browser, upload the file ' +
        'with uploadMedia(blob, contentType, filename) and pass the returned ' +
        'mxc_url to setAvatarUrl().',
      );
    }
    const buffer = nodeOnly.fs.readFileSync(filePath);
    const filename = nodeOnly.path.basename(filePath);
    const { content_uri } = await this.matrix.uploadMedia(buffer, contentType, filename);
    await this.matrix.setAvatarUrl(content_uri);
    return { mxc_url: content_uri };
  }

  /**
   * Set the Matrix avatar to an already-uploaded mxc:// URI.
   * Use this in the browser: uploadMedia(blob, contentType, filename) to get the
   * mxc_url, then pass it here. (setAvatar(filePath) is the Node convenience that
   * does both steps for a local file.)
   * @param {string} mxcUrl
   */
  async setAvatarUrl(mxcUrl) {
    this._requireMatrix();
    return this.matrix.setAvatarUrl(mxcUrl);
  }

  // ── Media ────────────────────────────────────────────────────────────────────

  /**
   * Upload binary data to the Matrix media repository.
   * @param {Buffer} buffer
   * @param {string} contentType
   * @param {string} [filename]
   * @returns {Promise<{content_uri: string}>}
   */
  async uploadMedia(buffer, contentType, filename) {
    this._requireMatrix();
    return this.matrix.uploadMedia(buffer, contentType, filename);
  }

  /**
   * Download a file from the Matrix media repository.
   * @param {string} mxcUrl - mxc:// URI
   * @returns {Promise<Buffer>}
   */
  async downloadMedia(mxcUrl) {
    this._requireMatrix();
    return this.matrix.downloadMedia(mxcUrl);
  }

  /**
   * Download and decrypt an E2E-encrypted file from the Matrix media repository.
   * Pass the encrypt_info object from the attachment returned by readMessages().
   * @param {string} mxcUrl - mxc:// URI
   * @param {object} encryptInfo - EncryptedFile object (key, iv, hashes)
   * @returns {Promise<Buffer>} Decrypted file bytes
   */
  async downloadMediaDecrypted(mxcUrl, encryptInfo) {
    this._requireMatrix();
    return this.matrix.downloadMediaDecrypted(mxcUrl, encryptInfo);
  }

  async sync(opts) {
    this._requireMatrix();
    return this.matrix.sync(opts);
  }

  // ── Cross-signing status / multi-device ──────────────────────────────────
  //
  // Returns a snapshot describing where this device sits in the cross-signing
  // trust web. See E2EMatrixClient.getCrossSigningStatus for the shape.
  //
  // After login, expect:
  //   { state: 'ready' }                — single-device or already verified
  //   { state: 'awaiting_verification' } — multi-device, this is a new device
  //                                        that hasn't been verified yet. UX
  //                                        cue: prompt the user to verify it
  //                                        from a trusted session.
  //   { state: 'mismatch' }              — local + server disagree (manual fix)
  //   { state: 'unknown' }               — loginMatrix() not called yet
  async getCrossSigningStatus() {
    this._requireMatrix();
    return this.matrix.getCrossSigningStatus();
  }

  // ── Devices & verification ───────────────────────────────────────────────
  //
  // Browser only for active flows; Node exposes the receiver-only path via
  // E2EMatrixClient.onIncomingVerification + completeIncomingVerification.

  /** List own Matrix devices (one per active subnet-client install). */
  async listOwnDevices() {
    this._requireMatrix();
    if (typeof this.matrix.listOwnDevices !== 'function') {
      throw new Error('listOwnDevices() is not available on this build');
    }
    return this.matrix.listOwnDevices();
  }

  /**
   * Browser only: auto-approve another of our own devices by cross-signing it
   * (no interactive SAS). Best-effort; requires this device to hold the
   * cross-signing keys (true once it has bootstrapped off SSSS).
   */
  async crossSignDevice(deviceId) {
    this._requireMatrix();
    if (typeof this.matrix.crossSignDevice !== 'function') {
      throw new Error('crossSignDevice() is not available on this build');
    }
    return this.matrix.crossSignDevice(deviceId);
  }

  /**
   * Browser only: kick off a self-verification with another of our own
   * devices. Returns matrix-js-sdk's VerificationRequest; drive the UI from
   * its `change` events. After SAS confirmation the cross-signing private
   * bytes are automatically gossiped via m.secret.send.
   */
  async requestSelfVerification(deviceId) {
    this._requireMatrix();
    if (typeof this.matrix.requestSelfVerification !== 'function') {
      throw new Error('requestSelfVerification() is browser-only');
    }
    return this.matrix.requestSelfVerification(deviceId);
  }

  /**
   * Subscribe to incoming verification requests from our other devices.
   * Returns an unsubscribe function. Handler argument shape depends on
   * backend (matrix-js-sdk VerificationRequest in browser; an internal
   * VerificationSession in Node).
   */
  onIncomingVerification(handler) {
    this._requireMatrix();
    if (typeof this.matrix.onIncomingVerification !== 'function') {
      return () => {};
    }
    return this.matrix.onIncomingVerification(handler);
  }

  /**
   * Browser only: the wallet-derived secret-storage key as a Matrix "Security
   * Key" (base58). Show this to the user so they can paste it into another
   * client — e.g. Element's "Enter Security Key" prompt — to unlock secret
   * storage, join this account's cross-signing identity, and restore message
   * history, without needing a second device online. Returns null if the build
   * can't derive it.
   */
  async getSecurityKey() {
    this._requireMatrix();
    if (typeof this.matrix.getSecurityKey !== 'function') {
      throw new Error('getSecurityKey() is browser-only');
    }
    return this.matrix.getSecurityKey();
  }

  async close() {
    if (this.matrix) {
      await this.matrix.close();
    }
  }
}

module.exports = { SubnetClient, deriveSignMessage };
