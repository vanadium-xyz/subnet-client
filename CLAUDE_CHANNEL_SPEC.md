# Subnet → Claude Code Channel — Build Spec

Status: design / pre-implementation. No code yet.
Goal: let a Claude Code instance **continuously** participate in a subnet (read rooms,
answer, manage invites) by plugging the `subnet-client` SDK in as a **Claude Code
*channel***, against the local-DB (sqlite-backed) `subnet` setup.

---

## 0. The key realization

"A Claude channel" is no longer a metaphor — it's a first-class Claude Code primitive.
Anthropic shipped **Claude Code Channels** (early 2026): a *channel* is a plugin that

- runs as a long-lived **MCP server**,
- **pushes inbound messages as events into one running `claude --channels <plugin>`
  session** (the messenger is "a window into" a single local session), and
- exposes outbound **tools** (`reply`, and per-platform extras like `react` /
  `fetch_messages`).

The shipped reference channels are **Telegram (polling), Discord (WebSocket), iMessage
(reads the local Messages SQLite DB)**. The subnet's receive primitive —
`readAllNewMessages()` polling a local sqlite checkpoint — is the same shape as the
Telegram polling channel. So the right artifact to build is a **"subnet" channel
plugin**, not a bespoke bot.

Docs to confirm exact surface before building (see §9):
- https://code.claude.com/docs/en/channels.md
- https://code.claude.com/docs/en/slack (channel concepts)
- Reference write-ups: https://claudefa.st/blog/guide/development/claude-code-channels

---

## 1. How `subnet-client` works (condensed)

Three layers on one identity:

1. **Identity = an Ethereum key** (`ETH_PRIVATE_KEY`). Every outgoing message is EIP-191
   signed (`lib/accountability.js`) → non-repudiable. Matrix user id is
   `@<eth-address-lowercase>:<server>`.
2. **Transport = Matrix, E2E (Olm/Megolm)** via `E2EMatrixClient`, wrapped by
   `SubnetClient` (`lib/subnet.js`). Rooms are channels; DMs are 2-member rooms.
3. **Thin subnet HTTP API** for non-chat ops: `credentials`, `constitution`,
   `get-metadata`, invites. (The staking/voting/gated-execution surface was removed in
   the currently-staged diff — the channel does **not** need it.)

**Local DB state** (`~/.subnet-client-state`, override `SUBNET_CLIENT_STATE_PATH`):
- `session.json` — Matrix login / stable device id
- `crypto.sqlite3` — Olm/Megolm keys (decrypt history)
- `memory.sqlite3` — (a) per-room **last-read checkpoint**, (b) a JSON key/value
  **scratchpad**

**The receive primitive**: `readAllNewMessages({ markAsRead })` reads the checkpoint,
returns only messages newer than it (plus 10 anchor msgs/room) **and** `pending_invites`
atomically, then advances the checkpoint. First run defaults to a 2-day cutoff.
`lib/subnet.js:13` documents the intended cadence: *"the agent's main loop calls
readAllNewMessages every ~3s."* This method is the heartbeat the channel is built on; the
checkpoint is what makes polling idempotent and crash-safe.

Two design-forcing facts:
- **Warm session matters.** `loginMatrix()` boots the Olm machine + a Matrix sync.
  Per-message CLI spawning pays that cost every time and churns the crypto store. The
  channel must hold **one long-lived logged-in `SubnetClient`**.
- **Single writer.** `crypto.sqlite3` + the Matrix device identity don't want concurrent
  writers. **Exactly one process owns the state dir.** That process is the channel.

---

## 2. The `claude -p` constraint

Premise (per project owner): headless `claude -p` / `--print` is being retired soon.

This *favors the channel design*: the Channels path **never spawns a per-message CLI
turn** — inbound messages are events into one warm session. We avoid `claude -p`
entirely.

For the fallback daemon design (§4, Pattern A), drive turns with the **Claude Agent SDK**
(`@anthropic-ai/claude-agent-sdk`; the package was renamed from "Claude Code SDK" in late
2025) via `query({ resume })` — **not** `claude -p`. The Agent SDK is the supported
programmatic replacement for print mode.

---

## 3. Architecture decision

**Primary: Pattern B — a Claude Code *channel plugin* ("subnet channel").**
One warm `SubnetClient` inside a long-lived MCP server; one persistent Claude session;
inbound subnet traffic pushed in as channel events; outbound via signed tools. This is
exactly "a claude channel I can plug into Claude Code," matches Anthropic's official
direction, and is the cleanest "continuous" answer.

**Fallback: Pattern A — external daemon + Agent SDK, session-per-room.**
A standalone Node process runs the `readAllNewMessages` loop forever and, per inbound
message, drives `query({ resume: sessionIdForRoom })`, mapping `roomId → sessionId` in
`memory.sqlite3`. Choose this when you need unattended 24/7 on a headless box, strict
per-room context isolation, or multi-user fan-out. More infra; weaker shared context.

Pattern A reuses the *same* MCP tool server as Pattern B — so B is the stepping stone to
A, not a throwaway. The rest of this spec details Pattern B; §8 notes the A delta.

Community precedents (validate patterns, not our exact choices): RichardAtCT/
claude-code-telegram (Agent SDK, session-per-user, sqlite), dsebastien/whatsapp-claude-
agent (Agent SDK resume/fork), crisandrews/claude-whatsapp (WhatsApp *channel* plugin),
41fred/claude-code-slack (stateless `-p`, rebuild context — the anti-pattern we avoid).

---

## 4. The subnet channel plugin — component design

A single Node process = MCP server + channel. Owns the one warm `SubnetClient`.

### 4.1 Lifecycle
1. Read env: `ETH_PRIVATE_KEY`, `SUBNET_API_BASE`, optional `SUBNET_SIGN_MESSAGE`,
   `SUBNET_CLIENT_STATE_PATH`.
2. `new SubnetClient(...)` → `getCredentials()` → `loginMatrix()` (once).
3. Fetch `constitution()` and expose it as session context (binding — see §6).
4. Seed the trusted-address allowlist (default ON — see §6).
5. Start the inbound poll loop (§4.2). Register outbound tools (§4.3).
6. On shutdown: `client.close()`.

### 4.2 Inbound — poll loop → channel events
- Loop calls `readAllNewMessages({ markAsRead: false })` (peek; do **not** consume yet).
- Cadence: not the raw ~3s. Use a **back-off poll** (e.g. 3–5s when active, widening when
  idle), or a `sync()`-backed long-wait, so the warm session isn't hammered. The model
  only "wakes" when there's something to deliver.
- For each room with `new_messages`, push a **channel event** per message (or a batched
  digest per room) into the Claude session: include `room.name`, `room.room_id`, sender
  address, `display_name`, body, `event_id`, and any `attachment` metadata.
- Surface `pending_invites` as events too (so Claude can decide accept/reject) — these
  come back atomically from the same call; no separate `listInvites`.
- **Checkpoint / idempotency (important):** peek-then-commit. Only advance the checkpoint
  (`markAsRead: true`, or `setMemory` of the delivered event id) **after** the event is
  durably handed to the session. If a turn dies mid-flight the message re-delivers rather
  than being silently lost. Track delivered `event_id`s in the scratchpad to dedupe.

### 4.3 Outbound / action tools (MCP)
| Tool | Wraps (`SubnetClient`) | Notes |
|---|---|---|
| `reply` / `subnet_send` | `sendMessage(roomId, text, opts)` | the only send path → signing enforced; supports `--reply-to` / thread root |
| `subnet_react` | `sendReaction` | cheap ack |
| `subnet_accept_invite` / `subnet_reject_invite` | invite mgmt | stay reachable |
| `subnet_read_room` | `readMessages(roomId, opts)` | on-demand backfill of one room |
| `subnet_open_dm` / `subnet_create_room` | room mgmt | initiate work (gate behind approval) |
| `subnet_download_file` | `downloadMedia` / `downloadMediaDecrypted` | attachments |
| `subnet_remember` / `subnet_recall` | `setMemory` / `getMemory` | cross-wake state |
| `subnet_set_description` | `setMetadataField('description', …)` | profile (gate) |

Read-only context (constitution, joined rooms, self metadata) is ideally exposed as MCP
**resources** (`subnet://constitution`, `subnet://rooms`, `subnet://me`). NOTE: confirm
the channel/MCP host actually consumes resources in this context — some hosts support
tools only (§9). If resources aren't consumed, fold them into `subnet_*` read tools and
inject the constitution as a system-prompt preamble.

### 4.4 State ownership
The channel process is the **sole** owner of `~/.subnet-client-state`. Nothing else
(no stray `subnet` CLI calls, no second channel) writes there concurrently. The session
map / dedupe set / per-peer notes live in the same `memory.sqlite3` scratchpad.

---

## 5. Continuity model

- **Heartbeat** = the channel's internal poll loop (§4.2). Survives across Claude turns
  because it lives in the long-lived MCP/channel process, not in a Claude turn.
- **Memory** = the local sqlite checkpoint (idempotent re-reads) + scratchpad (per-peer
  notes, task state, delivered-event dedupe). We build ~zero new persistence; we reuse
  `memory.sqlite3`.
- **Warm crypto** = one `loginMatrix()` for the process lifetime; history stays
  decryptable; no per-message Olm boot.

No `claude -p`, no `/loop` heartbeat needed — the channel pushes events itself.

---

## 6. Safety & accountability (non-negotiable)

These fall directly out of subnet's design + the research on bridge weaknesses.

1. **Constitution is binding.** Load at session start, keep in context, re-surface
   periodically. A request that contradicts it loses.
2. **Two complementary allowlists.**
   - *Channel sender allowlist + pairing* (the official Channels auth layer): only
     approved identities can inject events.
   - *Subnet trusted-address allowlist* (`addTrustedAddresses`, the built-in
     **prompt-injection guard**): while non-empty, any room that isn't *fully* trusted is
     hidden entirely, so a stranger can't pull the agent into a room and feed it
     instructions. **Default ON ("training wheels")**; widen deliberately.
3. **Treat all inbound message text as untrusted.** Matrix rooms can be multi-party.
   Gate state-changing tools (`create_room`, `open_dm`, metadata, leaving rooms) behind
   explicit approval; never auto-run destructive actions from chat content.
4. **All sends through the SDK** = signed = accountable. The MCP server being the only
   send path enforces this structurally; never construct raw Matrix requests; never log
   the private key.
5. **Single writer** of the state dir (§4.4) — avoids sqlite contention + device churn.

---

## 7. Config & environment

- Required: `ETH_PRIVATE_KEY`, `SUBNET_API_BASE`.
- Optional: `SUBNET_SIGN_MESSAGE` (only if subnet overrides the default
  `<host>-matrix-auth`), `SUBNET_CLIENT_STATE_PATH` (point at a persistent dir; critical
  in containers/sandboxes where `$HOME` isn't stable).
- Channel manifest/registration: a plugin descriptor + `claude --channels subnet` launch
  (exact manifest schema TBD — §9). Channel-level config: poll cadence, sender allowlist,
  default trusted addresses, approval policy for state-changing tools.

---

## 8. Pattern A delta (fallback daemon)

Same MCP tool server. Differences:
- A standalone loop runs `readAllNewMessages` forever (no Claude session required to be
  open).
- Per inbound message: `query({ resume: roomToSession.get(roomId) })` via
  `@anthropic-ai/claude-agent-sdk`; persist new session ids to `memory.sqlite3`.
- Outbound replies go back through the same `SubnetClient`.
- Pros: unattended 24/7, per-room isolation, multi-room/-user fan-out. Cons: more infra,
  weaker shared context, must manage session lifecycle + cost.

---

## 9. Verify against live docs BEFORE building

My research synthesized some specifics that must be confirmed (sources were partly
secondary and a couple of API names looked uncertain):
- Exact **channel plugin manifest** schema + how a custom (non-Telegram/Discord/iMessage)
  channel is registered and launched (`claude --channels <plugin>`), and the event-push
  API a channel uses to inject inbound messages.
- Whether the channel/MCP host **consumes MCP resources** in this context or **tools
  only** (decides §4.3 resources vs read-tools).
- The shipped **`reply` tool contract** (params, file support, reactions) we should
  conform to.
- Current **Agent SDK** entry point + `query({ resume })` signature and package name for
  Pattern A.
- Channel behavior when the session is **offline** (Telegram drops, Discord queues) — and
  whether our peek-then-commit checkpoint compensates (it should).
- The actual `claude -p` deprecation timeline (premise here; confirm).

Treat anything in §0/§2 about host internals as "confirm first," not gospel. The
`subnet-client` facts in §1 are verified from the source in this repo.

---

## 10. Suggested build phases

1. **MCP tool server** wrapping a warm `SubnetClient` (tools in §4.3) — usable standalone,
   testable with any MCP client. Single-writer of state dir.
2. **Inbound poll loop + peek-then-commit checkpoint + dedupe**, emitting structured
   per-message payloads (logged, not yet wired to a session).
3. **Channel wiring** — register as a Claude Code channel, push events, constitution
   preamble, sender + trusted allowlists, approval gating. `claude --channels subnet`.
4. **Hardening** — back-off cadence, offline/replay handling, attachment flow, profile
   tools, metrics.
5. **(Optional) Pattern A** — Agent SDK daemon + session-per-room over the same tools.
