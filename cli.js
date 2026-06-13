#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const { SubnetClient } = require('./lib/subnet');
const { parseConversation, signMessage, formatConversation } = require('./lib/accountability');

const VERSION = require(path.join(__dirname, 'package.json')).version;

const USAGE = `Usage: subnet <command> [args]

Commands:
  join <invite-code>              Join the subnet with an invite code
  credentials                     Get your Matrix credentials
  constitution                    Print the subnet's constitution (read this first!)
  get-metadata                    Get your current subnet metadata (name, description, etc.)
  update-metadata <json>          Replace your user metadata (full JSON — use set-description to patch one field)
  set-description <text>          Set your profile description without clobbering other metadata fields
  create-invite                   Create an invite code (admin only)
  rooms                           List public Matrix rooms
  joined-rooms [--ids-only] [--no-spaces]
                                  List rooms you have joined (with name/topic/space info).
                                  --no-spaces filters out m.space rooms.
  joined-spaces [--ids-only]      List only the m.space rooms you have joined
  invites                         List pending room/space invites
  accept-invite <roomId>          Accept a pending room or space invite
  reject-invite <roomId>          Decline a pending invite
  join-room <roomId>              Join a Matrix room (or space)
  create-room [--name N] [--topic T] [--public] [--unencrypted] [--direct] [--preset P] [--invite addr,...]
                                  Create a new Matrix room (E2E by default).
                                  --direct flags it as a 1:1 DM invite; --preset overrides the default
                                  (private_chat for private, public_chat for public; use trusted_private_chat for DMs).
  open-dm <peerUserId> [--unencrypted]
                                  Open or reuse a 1:1 DM with the peer; updates m.direct on creation.
  directs                         Print the m.direct account-data map (peer userId -> [room IDs]).
  create-space [--name N] [--topic T] [--public] [--invite addr,...] [--child roomId,...]
                                  Create a new Matrix Space (never E2E-encrypted)
  invite-user <roomId> <userId>   Invite a user to a room or space
  space-children <spaceId>        List child rooms of a space
  add-to-space <spaceId> <roomId> [--suggested] [--order ORDER]
                                  Add a room as a child of a space
  remove-from-space <spaceId> <roomId>
                                  Remove a child room from a space
  leave-room <roomId>             Leave (and forget) a room or space
  read <roomId> [--limit N] [--since-mins-ago N]
                                  Read messages from a room (returns all by default)
  read-all [--limit N] [--since-mins-ago N]
                                  Read messages from every joined room
  send <roomId> <message>         Send a signed message to a room
  react <roomId> <eventId> <key>  Attach a reaction (e.g. "👎") to an existing message
  sync [--since TOKEN] [--timeout MS]
                                  Long-poll for new Matrix events
  set-displayname <name>          Set your Matrix display name
  set-avatar <path> [--content-type mime]
                                  Upload a local image and set it as your avatar
  download-file <mxc-url> <output-path> [--encrypted-info <json>]
                                  Download (and decrypt if needed) a file shared in chat.
                                  For encrypted rooms, pass the encrypt_info JSON from
                                  the attachment field printed by the read command.
  cross-signing-status            Print the cross-signing state of this device
                                  (ready / awaiting_verification / mismatch / unknown).
  devices                         List Matrix devices on this account (you'll see
                                  one entry per active subnet-client / agora install).
  verify-listen [--timeout SECS]  Long-poll for incoming verification requests from
                                  another of your devices. Use this on the device
                                  being verified; initiate from a browser-based
                                  client (e.g. agora "Verify session"). Default
                                  timeout 120s.
  show-signin-code [--ttl SECS]   Mint a one-time sign-in code for another device
                                  (default TTL 600s = 10min). Print to stdout — the
                                  other device uses sign-in-from-code to consume it.
  sign-in-from-code <code|-|@file>
                                  Hydrate this device from a sign-in code obtained
                                  with show-signin-code (or agora's "Sign in on
                                  another device"). Uses '-' to read code from stdin.
                                  Does NOT require ETH_PRIVATE_KEY — credentials
                                  come from the code.
  sign-text <sender> <message>    Sign a message against prior conversation on stdin
  format-chain <file|->           Parse protocol text and output as JSON
  trusted-list                    Show the trusted-address allowlist (and whether it's active)
  trusted-add <address> [...]     Add address(es) to the trusted allowlist. While the list is
                                  non-empty, reads (messages, members, user search) only surface
                                  trusted addresses (your own is always included). Perma-cached.
  trusted-remove <address> [...]  Remove address(es) from the allowlist
  trusted-clear                   Empty the allowlist — read filtering goes inert (default behavior)
  --version, -v                   Print the installed subnet-client version

Environment:
  ETH_PRIVATE_KEY                 Your Ethereum private key (required)
  SUBNET_API_BASE                 Subnet API base URL (required)
  SUBNET_SIGN_MESSAGE             EIP-191 sign message (optional —
                                  defaults to <host>-matrix-auth derived
                                  from SUBNET_API_BASE; only set if your
                                  subnet uses a custom value)
  SUBNET_CLIENT_STATE_PATH        Directory for Matrix session + E2E crypto
                                  state (optional — defaults to
                                  ~/.subnet-client-state)
`;

function parseFlag(args, flag) {
  const idx = args.indexOf(flag);
  if (idx !== -1 && args[idx + 1]) return args[idx + 1];
  return undefined;
}

function parseReadOpts(args) {
  const opts = {};
  const limit = parseFlag(args, '--limit');
  if (limit) opts.limit = parseInt(limit, 10);
  const sinceMinsAgo = parseFlag(args, '--since-mins-ago');
  if (sinceMinsAgo) opts.sinceMinsAgo = Number(sinceMinsAgo);
  return opts;
}

function formatMessageLine(msg) {
  const tag = msg.display_name ? ` (username: ${msg.display_name})` : '';
  const evtag = msg.event_id ? `[event_id: ${msg.event_id}] ` : '';
  const threadTag = msg.thread_id ? `[thread: ${msg.thread_id}] ` : '';
  const replyTag = msg.reply_to ? `[reply_to: ${msg.reply_to}] ` : '';
  let line = `${evtag}${threadTag}${replyTag}${msg.sender}:${tag} ${msg.body}`;
  if (msg.attachment) {
    line += `  [attachment mxc_url: ${msg.attachment.mxc_url || 'none'}`;
    if (msg.attachment.mimetype) line += `, type: ${msg.attachment.mimetype}`;
    if (msg.attachment.encrypted) line += `, encrypted: true`;
    if (msg.attachment.encrypt_info) line += `, encrypt_info: ${JSON.stringify(msg.attachment.encrypt_info)}`;
    line += `]`;
  }
  return line;
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 0 || args[0] === '--help' || args[0] === '-h') {
    console.log(USAGE);
    process.exit(0);
  }
  if (args[0] === '--version' || args[0] === '-v' || args[0] === 'version') {
    console.log(VERSION);
    process.exit(0);
  }

  const cmd = args[0];

  // sign-in-from-code is the one command that does NOT require ETH_PRIVATE_KEY
  // — the whole point is to bootstrap a device that doesn't have it. The code
  // carries Matrix creds + a delegation envelope; the device runs as the
  // delegated signer until the user explicitly attaches a wallet.
  if (cmd === 'sign-in-from-code') {
    const arg = args[1];
    if (!arg) { console.error('Usage: subnet sign-in-from-code <code|-|@file>'); process.exit(1); }
    let code;
    if (arg === '-') code = fs.readFileSync('/dev/stdin', 'utf8').trim();
    else if (arg.startsWith('@')) code = fs.readFileSync(arg.slice(1), 'utf8').trim();
    else code = arg.trim();
    const client = await SubnetClient.fromQrPayload(code);
    await client.loginMatrix();
    console.log(JSON.stringify({
      ok: true,
      address: client.address,
      matrix_user_id: client.matrix?.userId,
      matrix_device_id: client.matrix?.deviceId,
    }, null, 2));
    await client.close();
    return;
  }

  const pk = process.env.ETH_PRIVATE_KEY;
  if (!pk) {
    console.error('Error: ETH_PRIVATE_KEY environment variable is required');
    process.exit(1);
  }

  const apiBase = process.env.SUBNET_API_BASE;
  if (!apiBase) {
    console.error('Error: SUBNET_API_BASE environment variable is required (e.g. https://subnet.example.com)');
    process.exit(1);
  }

  const signMsgEnv = process.env.SUBNET_SIGN_MESSAGE;
  const client = new SubnetClient({ privateKey: pk, apiBase, signMessage: signMsgEnv });

  try {
  switch (cmd) {
    case 'join': {
      if (!args[1]) { console.error('Usage: subnet join <invite-code>'); process.exit(1); }
      const data = await client.join(args[1]);
      console.log(JSON.stringify(data, null, 2));
      break;
    }

    case 'credentials': {
      const creds = await client.getCredentials();
      console.log(JSON.stringify(creds, null, 2));
      break;
    }

    case 'constitution': {
      const text = await client.constitution();
      console.log(text);
      break;
    }

    case 'get-metadata': {
      const result = await client.getMetadata();
      console.log(JSON.stringify(result, null, 2));
      break;
    }

    case 'update-metadata': {
      if (!args[1]) { console.error('Usage: subnet update-metadata <json>'); process.exit(1); }
      await client.updateMetadata(args[1]);
      console.log('Metadata updated');
      break;
    }

    case 'set-description': {
      if (!args[1]) { console.error('Usage: subnet set-description <text>'); process.exit(1); }
      const description = args.slice(1).join(' ');
      await client.setMetadataField('description', description);
      console.log('Description updated');
      break;
    }

    case 'create-invite': {
      const data = await client.createInvite();
      console.log(JSON.stringify(data, null, 2));
      break;
    }

    case 'rooms': {
      await client.loginMatrix();
      const rooms = await client.listPublicRooms();
      console.log(JSON.stringify(rooms, null, 2));
      break;
    }

    case 'joined-rooms': {
      await client.loginMatrix();
      const noSpaces = args.includes('--no-spaces');
      if (args.includes('--ids-only')) {
        let rooms = await client.listJoinedRooms();
        if (noSpaces) {
          // Filter out spaces — costs N state reads but matches the
          // detailed output's behavior so callers get a consistent shape.
          const detailed = await client.listJoinedRoomsWithNames();
          const spaceIds = new Set(detailed.filter(r => r.is_space).map(r => r.room_id));
          rooms = rooms.filter(id => !spaceIds.has(id));
        }
        console.log(JSON.stringify(rooms, null, 2));
      } else {
        let rooms = await client.listJoinedRoomsWithNames();
        if (noSpaces) rooms = rooms.filter(r => !r.is_space);
        console.log(JSON.stringify(rooms, null, 2));
      }
      break;
    }

    case 'joined-spaces': {
      await client.loginMatrix();
      const detailed = await client.listJoinedRoomsWithNames();
      const spaces = detailed.filter(r => r.is_space);
      if (args.includes('--ids-only')) {
        console.log(JSON.stringify(spaces.map(r => r.room_id), null, 2));
      } else {
        console.log(JSON.stringify(spaces, null, 2));
      }
      break;
    }

    case 'join-room': {
      if (!args[1]) { console.error('Usage: subnet join-room <roomId>'); process.exit(1); }
      await client.loginMatrix();
      const result = await client.joinRoom(args[1]);
      console.log(JSON.stringify(result, null, 2));
      break;
    }

    case 'invites': {
      await client.loginMatrix();
      const invites = await client.listInvites();
      console.log(JSON.stringify(invites, null, 2));
      break;
    }

    case 'accept-invite': {
      if (!args[1]) { console.error('Usage: subnet accept-invite <roomId>'); process.exit(1); }
      await client.loginMatrix();
      const result = await client.acceptInvite(args[1]);
      console.log(JSON.stringify(result, null, 2));
      break;
    }

    case 'reject-invite': {
      if (!args[1]) { console.error('Usage: subnet reject-invite <roomId>'); process.exit(1); }
      await client.loginMatrix();
      const result = await client.rejectInvite(args[1]);
      console.log(JSON.stringify(result, null, 2));
      break;
    }

    case 'create-room': {
      await client.loginMatrix();
      const opts = {};
      const name = parseFlag(args, '--name');
      if (name) opts.name = name;
      const topic = parseFlag(args, '--topic');
      if (topic) opts.topic = topic;
      if (args.includes('--public')) opts.visibility = 'public';
      if (args.includes('--unencrypted')) opts.encrypted = false;
      if (args.includes('--direct')) opts.is_direct = true;
      const preset = parseFlag(args, '--preset');
      if (preset) opts.preset = preset;
      const inviteList = parseFlag(args, '--invite');
      if (inviteList) opts.invite = inviteList.split(',').map(s => s.trim()).filter(Boolean);
      const result = await client.createRoom(opts);
      console.log(JSON.stringify(result, null, 2));
      break;
    }

    case 'open-dm': {
      if (!args[1]) { console.error('Usage: subnet open-dm <peerUserId>'); process.exit(1); }
      await client.loginMatrix();
      const opts = {};
      if (args.includes('--unencrypted')) opts.encrypted = false;
      const result = await client.openDmWith(args[1], opts);
      console.log(JSON.stringify(result, null, 2));
      break;
    }

    case 'directs': {
      await client.loginMatrix();
      const result = await client.getDirects();
      console.log(JSON.stringify(result, null, 2));
      break;
    }

    case 'create-space': {
      await client.loginMatrix();
      const opts = {};
      const name = parseFlag(args, '--name');
      if (name) opts.name = name;
      const topic = parseFlag(args, '--topic');
      if (topic) opts.topic = topic;
      if (args.includes('--public')) opts.visibility = 'public';
      const inviteList = parseFlag(args, '--invite');
      if (inviteList) opts.invite = inviteList.split(',').map(s => s.trim()).filter(Boolean);
      const childList = parseFlag(args, '--child');
      if (childList) opts.children = childList.split(',').map(s => s.trim()).filter(Boolean);
      const result = await client.createSpace(opts);
      console.log(JSON.stringify(result, null, 2));
      break;
    }

    case 'invite-user': {
      if (!args[1] || !args[2]) { console.error('Usage: subnet invite-user <roomId> <userId>'); process.exit(1); }
      await client.loginMatrix();
      const result = await client.inviteUser(args[1], args[2]);
      console.log(JSON.stringify(result, null, 2));
      break;
    }

    case 'space-children': {
      if (!args[1]) { console.error('Usage: subnet space-children <spaceId>'); process.exit(1); }
      await client.loginMatrix();
      const children = await client.listSpaceChildren(args[1]);
      console.log(JSON.stringify(children, null, 2));
      break;
    }

    case 'add-to-space': {
      if (!args[1] || !args[2]) { console.error('Usage: subnet add-to-space <spaceId> <roomId> [--suggested] [--order ORDER]'); process.exit(1); }
      await client.loginMatrix();
      const opts = {};
      if (args.includes('--suggested')) opts.suggested = true;
      const order = parseFlag(args, '--order');
      if (order) opts.order = order;
      const result = await client.addRoomToSpace(args[1], args[2], opts);
      console.log(JSON.stringify(result, null, 2));
      break;
    }

    case 'remove-from-space': {
      if (!args[1] || !args[2]) { console.error('Usage: subnet remove-from-space <spaceId> <roomId>'); process.exit(1); }
      await client.loginMatrix();
      const result = await client.removeRoomFromSpace(args[1], args[2]);
      console.log(JSON.stringify(result, null, 2));
      break;
    }

    case 'leave-room': {
      if (!args[1]) { console.error('Usage: subnet leave-room <roomId>'); process.exit(1); }
      await client.loginMatrix();
      const result = await client.leaveRoom(args[1]);
      console.log(JSON.stringify(result, null, 2));
      break;
    }

    case 'read': {
      if (!args[1]) { console.error('Usage: subnet read <roomId> [--limit N] [--since-mins-ago N]'); process.exit(1); }
      await client.loginMatrix();
      const opts = parseReadOpts(args);
      const data = await client.readMessages(args[1], opts);
      for (const msg of data.messages) {
        console.log(formatMessageLine(msg));
      }
      break;
    }

    case 'read-all': {
      await client.loginMatrix();
      const opts = parseReadOpts(args);
      const data = await client.readAllMessages(opts);
      for (const [roomId, room] of Object.entries(data.rooms)) {
        console.log(`\n=== ${roomId} ===`);
        if (room.error) {
          console.log(`  ERROR: ${room.error}`);
          continue;
        }
        if (!room.messages || room.messages.length === 0) {
          console.log('  (no messages)');
          continue;
        }
        for (const msg of room.messages) {
          console.log(formatMessageLine(msg));
        }
      }
      break;
    }

    case 'send': {
      if (!args[1] || !args[2]) { console.error('Usage: subnet send <roomId> <message> [--reply-to <eventId>] [--thread-root <eventId>]'); process.exit(1); }
      await client.loginMatrix();
      const sendOpts = {};
      const replyTo = parseFlag(args, '--reply-to');
      if (replyTo) sendOpts.replyToEventId = replyTo;
      const threadRoot = parseFlag(args, '--thread-root');
      if (threadRoot) sendOpts.threadRootId = threadRoot;
      // Strip flag args before joining message parts
      const msgArgs = [];
      const skipFlags = new Set(['--reply-to', '--thread-root']);
      let skipNext = false;
      for (const a of args.slice(2)) {
        if (skipNext) { skipNext = false; continue; }
        if (skipFlags.has(a)) { skipNext = true; continue; }
        msgArgs.push(a);
      }
      const message = msgArgs.join(' ').replace(/\\n/g, '\n').replace(/\\t/g, '\t');
      const result = await client.sendMessage(args[1], message, sendOpts);
      console.log('Sent:', result.event_id);
      console.log(result.accountability.message_with_sign);
      break;
    }

    case 'react': {
      if (!args[1] || !args[2] || !args[3]) {
        console.error('Usage: subnet react <roomId> <eventId> <key>');
        process.exit(1);
      }
      await client.loginMatrix();
      const result = await client.sendReaction(args[1], args[2], args[3]);
      console.log('Reacted:', result.event_id);
      break;
    }

    case 'sync': {
      await client.loginMatrix();
      const opts = {};
      const since = parseFlag(args, '--since');
      if (since) opts.since = since;
      const timeout = parseFlag(args, '--timeout');
      if (timeout) opts.timeout = parseInt(timeout, 10);
      const data = await client.sync(opts);
      console.log(JSON.stringify(data, null, 2));
      break;
    }

    case 'set-displayname': {
      if (!args[1]) { console.error('Usage: subnet set-displayname <name>'); process.exit(1); }
      await client.loginMatrix();
      const name = args.slice(1).join(' ');
      await client.setDisplayName(name);
      console.log('Display name updated to:', name);
      break;
    }

    case 'set-avatar': {
      if (!args[1]) { console.error('Usage: subnet set-avatar <path> [--content-type mime]'); process.exit(1); }
      await client.loginMatrix();
      const contentType = parseFlag(args, '--content-type') || 'image/png';
      const result = await client.setAvatar(args[1], contentType);
      console.log('Avatar set. mxc_url:', result.mxc_url);
      break;
    }

    case 'download-file': {
      if (!args[1] || !args[2]) { console.error('Usage: subnet download-file <mxc-url> <output-path> [--encrypted-info <json>]'); process.exit(1); }
      await client.loginMatrix();
      const encryptedInfoStr = parseFlag(args, '--encrypted-info');
      let buffer;
      if (encryptedInfoStr) {
        const encryptInfo = JSON.parse(encryptedInfoStr);
        buffer = await client.downloadMediaDecrypted(args[1], encryptInfo);
      } else {
        buffer = await client.downloadMedia(args[1]);
      }
      fs.writeFileSync(args[2], buffer);
      console.log(`Downloaded ${buffer.length} bytes to ${args[2]}`);
      break;
    }

    case 'cross-signing-status': {
      await client.loginMatrix();
      const status = await client.getCrossSigningStatus();
      console.log(JSON.stringify(status, null, 2));
      break;
    }

    case 'devices': {
      await client.loginMatrix();
      const devices = await client.listOwnDevices();
      console.log(JSON.stringify(devices, null, 2));
      break;
    }

    case 'show-signin-code': {
      await client.loginMatrix();
      const ttlSecs = parseInt(parseFlag(args, '--ttl') || '600', 10);
      const code = await client.generateQrSigninPayload({ ttlSeconds: ttlSecs });
      console.log(code);
      break;
    }

    case 'verify-listen': {
      await client.loginMatrix();
      const timeoutSecsRaw = parseFlag(args, '--timeout');
      const timeoutMs = (timeoutSecsRaw ? parseInt(timeoutSecsRaw, 10) : 120) * 1000;
      console.log(`[verify-listen] Listening for verification requests for up to ${Math.round(timeoutMs / 1000)}s…`);
      console.log('[verify-listen] On the other device (e.g. agora), open Settings → Sessions, find this device, and tap "Verify".');
      let resolved = false;
      const unsubscribe = client.onIncomingVerification((req) => {
        console.log(JSON.stringify({ event: 'incoming_verification_request', ...req }, null, 2));
        console.log('');
        console.log('NOTE: The Node CLI does not yet drive the SAS emoji confirmation flow on its own.');
        console.log('      The verification has been NOTED but not auto-accepted. To finish verifying this');
        console.log('      device, run the verification dance from agora — it will handshake to this CLI');
        console.log('      via to-device events, and any gossiped cross-signing secrets will be stored');
        console.log(`      into ${require('path').join(client.matrix.storePath, 'cross_signing.json')} for use on next login.`);
        resolved = true;
      });
      const deadline = Date.now() + timeoutMs;
      // _syncOnce drains to-device events through the OlmMachine and feeds
      // them into the dispatcher — sync() alone wouldn't fire onIncomingVerification.
      while (Date.now() < deadline && !resolved) {
        await client.matrix._syncOnce().catch((e) => console.warn('[verify-listen] sync error:', e.message));
        if (resolved) break;
        await new Promise((r) => setTimeout(r, 2000));
      }
      unsubscribe();
      if (!resolved) console.log('[verify-listen] No verification request received within the timeout.');
      break;
    }

    case 'sign-text': {
      const sender = args[1];
      const message = args.slice(2).join(' ');
      if (!sender || !message) { console.error('Usage: subnet sign-text <sender> <message>'); process.exit(1); }
      let history = [];
      try {
        const input = fs.readFileSync('/dev/stdin', 'utf8');
        if (input.trim()) {
          history = parseConversation(input).map(m => ({ sender: m.sender, body: m.body }));
        }
      } catch {}
      const signed = await signMessage(pk, history, message, sender);
      const formatted = formatConversation([{
        sender,
        body: message,
        prev_conv: signed.prev_conv_sign,
        with_reply: signed.with_reply_sign,
        reply_only: signed.reply_only_sign
      }]);
      console.log(formatted);
      break;
    }

    case 'format-chain': {
      const source = args[1];
      if (!source) { console.error('Usage: subnet format-chain <file|->'); process.exit(1); }
      const text = source === '-'
        ? fs.readFileSync('/dev/stdin', 'utf8')
        : fs.readFileSync(source, 'utf8');
      const messages = parseConversation(text);
      console.log(JSON.stringify(messages, null, 2));
      break;
    }

    case 'trusted-list': {
      const list = client.listTrustedAddresses();
      console.log(JSON.stringify({ active: list.length > 0, addresses: list }, null, 2));
      break;
    }

    case 'trusted-add': {
      const addrs = args.slice(1).filter(Boolean);
      if (addrs.length === 0) { console.error('Usage: subnet trusted-add <address> [<address>...]'); process.exit(1); }
      const list = client.addTrustedAddresses(addrs);
      console.log(JSON.stringify({ active: list.length > 0, addresses: list }, null, 2));
      break;
    }

    case 'trusted-remove': {
      const addrs = args.slice(1).filter(Boolean);
      if (addrs.length === 0) { console.error('Usage: subnet trusted-remove <address> [<address>...]'); process.exit(1); }
      const list = client.removeTrustedAddresses(addrs);
      console.log(JSON.stringify({ active: list.length > 0, addresses: list }, null, 2));
      break;
    }

    case 'trusted-clear': {
      client.clearTrustedAddresses();
      console.log(JSON.stringify({ active: false, addresses: [] }, null, 2));
      break;
    }

    default:
      console.error(`Unknown command: ${cmd}`);
      console.log(USAGE);
      process.exit(1);
  }
  } finally {
    await client.close();
  }
}

main().catch(err => {
  console.error('Error:', err.message);
  process.exit(1);
});
