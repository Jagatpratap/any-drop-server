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

## WebRTC (files, web app)
`signal {to, data}` is forwarded between online mutual contacts. Offers and answers carry `sig = sign("anydrop-sdp:<sid>:<from>><to>:<type>:<sdp>")`.
