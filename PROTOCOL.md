# AnyDrop protocol

One WebSocket per device: `ws(s)://<server>/ws`. All frames are JSON with a `type`.

## Identity and login
Each device makes two P-256 key pairs on first launch and keeps them on the device:
- **identity**: signs the login challenge. `id = hex(sha256(raw public key)[0..16])`.
- **box**: ECDH key for sealing messages. `boxSig = sign("anydrop-box:" + box)` with the identity key.

Keys and signatures are base64url without padding. Public keys are raw uncompressed points (65 bytes) and signatures are raw `r||s` (64 bytes).

```
server → {type:"challenge", nonce}
client → {type:"auth", pub, sig: sign("anydrop-auth:"+nonce), box, boxSig, watch:[ids]}
server → {type:"welcome", id, time}   then any waiting {type:"msgs"} frames
```

## Presence
`{type:"watch", ids}` sets the contacts you care about. Two devices see each other online only if each watches the other. The server sends `{type:"online", ids}` when the list changes.

## Pairing
`pair-open {name, device}` → `pair-open {token, code, ttl}`. The other device sends `pair-join {code | token, name, device}`. Both then receive `paired {peer:{id, pub, box, boxSig, name, device}}`. Clients must check `id == sha256(pub)` and verify `boxSig` against `pub`.

QR code content: `<server>/#pair=<token>.<id>`.

## Sealed messages (the server's mailbox)
```
key = HKDF-SHA256(ikm = ECDH(myBox, peerBox).x, salt = "anydrop", info = "anydrop-msg-v1", 32 bytes)
box = base64url(iv[12] || AES-256-GCM(key, iv, aad = "<from>><to>:<mid>", utf8(json)))
```
- `send {to, mid, box}` → the server stores it and forwards it if the recipient is online, then replies `sent {mid, to, ts}` (✓). A retransmit with the same `mid` is deduplicated.
- `send {to, mid, box, live:true}`: forwarded only if both devices are online and watch each other. Never stored (typing).
- The recipient gets `msgs {items:[{mid, from, box, ts}]}` (or `live {msg}`). It stores the messages, then sends `ack {mids}`, and the server deletes them. Unacked mail is kept for 30 days and saved to `DATA_DIR/mailbox.json`.

Sealed JSON bodies:
| `k` | fields | |
|---|---|---|
| `text` | `text, ts` | message; its id is the `mid` |
| `rcpt` | `st: "delivered" \| "read", mids` | ✓✓ / blue ✓✓ |
| `typing` | | sent with `live:true` |
| `profile` | `name, device` | name or type changed |

## WebRTC link (files)
`signal {to, data}` is forwarded between online mutual contacts. Each pair of devices keeps one
`RTCPeerConnection` with an ordered data channel labelled `chat`. The device with the lower id
dials; the other sends `{hey:1}` to ask to be dialed. Offers and answers carry
`sig = sign("anydrop-sdp:<sid>:<from>><to>:<type>:<sdp>")`; ICE is `{sid, ice}`.
On the `chat` channel: `{t:"hello", name, device}`, `{t:"ping"}` / `{t:"pong"}` (heartbeat).

## Drops: files and photo collections, AirDrop-style
Nothing is sent until the receiver says yes. The request travels sealed through the mailbox,
so it reaches a device that is offline; the bytes go only over WebRTC, so both must be online.

Sealed bodies (the drop id is the `mid` of the `drop` message):
| `k` | fields | |
|---|---|---|
| `drop` | `ts, items:[{name, size, mime}]` (1..100 items) | "X wants to send 5 photos". Gets ✓ / ✓✓ like text. |
| `drop-ok` | `id` | receiver accepted |
| `drop-no` | `id` | receiver declined |
| `drop-cancel` | `id` | sender withdrew it (before or during the transfer) |
| `drop-done` | `id` | receiver has every file |

After `drop-ok`, when the link is open, the sender opens one data channel per item, labelled
`file:<id>:<i>`, one at a time in order. Frames: a JSON header `{drop:id, i, name, size, mime}`,
binary chunks (64 KiB), then the string `end`. The receiver answers the string `ok` once the item
is stored, then the channel closes. The receiver refuses (closes) channels for drops it hasn't
accepted, unknown indices and size mismatches. If the link breaks, the sender resumes from the
first item without `ok`; the receiver discards a partial item and takes it again from byte 0.

States: sender `asking → sending → done` or `declined | canceled | failed`;
receiver `asking → receiving → done` or `declined | canceled`.
A device may auto-accept drops from a contact if the user turned that on for that contact.

## Calls (voice and video)
One extra `RTCPeerConnection` per call, signalled with `signal` frames (both must be online):
| `op` | fields | |
|---|---|---|
| `ring` | `call, video, sdp:{type:"offer", sdp}, sig` | caller starts; sig as above with `sid = call` |
| `ringing` | `call` | callee is showing the call |
| `answer` | `call, sdp:{type:"answer", sdp}, sig` | callee picked up |
| `ice` | `call, ice` | |
| `cam` | `call, on` | the sender turned its camera off/on |
| `end` | `call, why: "hangup" \| "decline" \| "busy" \| "cancel" \| "timeout"` | |

The caller gives up after 45 s without an answer (`end` with `why:"timeout"`). A device already
in a call answers `end` with `why:"busy"`. Each side keeps its own call log; nothing about calls
is stored on the server.
