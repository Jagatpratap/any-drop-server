# AnyDrop

AirDrop-style file sharing that works between any devices: Mac, Android, iOS, Windows, Linux.

## Run it

Needs [Bun](https://bun.sh) (`brew install oven-sh/bun/bun`).

```sh
./run.sh            # or: bun install && bun run start
```

1. On the Mac, open http://localhost:8080 and tap the **QR icon** (Add a device).
2. Point the phone's camera at the QR code. It opens AnyDrop on the phone and the two devices pair.
   No camera? Use **Enter code** with the 6-digit code instead.
3. Chat, call (voice or video) and send photos and files. Files are AirDrop-style: the other device gets **Accept / Decline** first, and a selection of photos arrives as one collection. Name each device and pick its type (Android phone, MacBook, …) by tapping your own name at the top left.

If the phone can't connect, allow `bun` through the macOS firewall (System Settings → Network → Firewall).

## Android app (React Native)

`dist/AnyDrop-android.apk`: copy it to the phone and install it (allow "install unknown apps"). On first launch, scan the QR code the server prints (or type its address). Then go to **Add a device** and scan the web app's QR code, or enter its 6-digit code.

- Runs on 64-bit ARM phones (nearly all phones from 2017 on).
- **Tabs:** Chats, Calls (call log), Files (everything shared, with incoming requests first) and Settings (name, device type, permissions, background connection).
- **Files and photos:** tap **+** in a chat. The other device must accept before any bytes move; then they go directly over WebRTC (`src/rtc.ts`). Received photos and videos go to the gallery (`Pictures/AnyDrop`), other files to `Downloads/AnyDrop`. Auto-accept can be turned on per device (Device info). A broken transfer resumes from the first unfinished file.
- **Calls:** voice and video over WebRTC, with mute, speaker, camera off and flip. Incoming calls ring and show a full-screen call notification with Answer / Decline, even when the app is closed. During a call the service also holds the microphone/camera so the call keeps working when you leave the app.
- **Chat:** reply (swipe a message right, or long-press), react, pin a message, forward, delete for yourself or for both devices, voice messages (tap the mic), drafts, and search across messages. Long-press a chat to pin or mute it. Light, dark or automatic theme and the doodle wallpaper are in Settings.
- **Background:** a foreground service keeps the WebSocket open, so messages, file requests and calls arrive with the app closed. Android requires a notification for this ("Ready for messages and calls"); it's silent, and Settings → *Hide this notification* turns that category off while AnyDrop keeps working. If the system kills the app, it restarts in a few seconds. It also reconnects after a reboot and when the phone switches between Wi-Fi and mobile data. On Xiaomi, Oppo, Vivo or Samsung, set battery to **Unrestricted** (Settings in the app has a button).
- Build it yourself:
  ```sh
  cd mobile && npm install
  cd android && JAVA_HOME=$(brew --prefix openjdk@17) ./gradlew assembleRelease
  ```
  For development, run `npx react-native start` and `./gradlew installDebug`. `npm install` also applies `patches/react-native-webrtc+*.patch` (a fix so the first message on a data channel opened by the other side isn't lost).
- Code: `mobile/App.tsx` (screens), `mobile/src/core.ts` (chat logic, drops, call log), `mobile/src/rtc.ts` (WebRTC links, file transfer, calls), and Kotlin in `mobile/android/app/src/main/java/app/anydrop/` (`core/Core.kt` connection and inbox, `core/Crypto.kt` keys and sealing, `core/ConnectionService.kt`, `core/Files.kt` file bytes and saving, `core/Calls.kt` ringing and audio, `AnyDropModule.kt` bridge).

## How it works

```
 Phone ──ws──┐                          ┌──ws── Web app / phone
             ├── Bun + Elysia server ──┤   login, presence, pairing,
             │   (sealed mailbox)       │   sealed messages, WebRTC signaling
             └──── WebRTC: files and calls, direct ────┘
```

- **No signup.** Each device makes its own P-256 keys and keeps them on the device. Its ID is `sha256(public key)`, and it logs in by signing a challenge.
- **Messages go through the server, end-to-end encrypted** (ECDH P-256 → HKDF → AES-256-GCM, see `PROTOCOL.md`). The server stores the sealed message until the receiver confirms it has it, then deletes it. The sender can be offline and messages survive a server restart. The server can't read them.
- **Ticks:** 🕓 not on the server yet · ✓ server has it · ✓✓ delivered · blue ✓✓ read. Also typing, online/last seen, and name/type changes.
- **Files and calls** go device-to-device over WebRTC, with offers and answers signed by the device key. A file request travels sealed through the server, so it reaches an offline device; the bytes only move after the receiver accepts, while both are online.
- Chats are stored only on the devices.

Testing several devices in one browser: add `?profile=a`, `?profile=b` to the URL.

### Server code
Plain JavaScript on Bun + Elysia, no build step:
- `server/index.js`: HTTP routes (`/ws`, `/api/config`, `/api/qr`, `/api/health`, static web app) and startup.
- `server/hub.js`: the protocol (login, presence, pairing, signaling, sealed mailbox).
- `server/mailbox.js`: saves waiting messages to `DATA_DIR/mailbox.json`.

`bun run dev` restarts the server when a file changes.

### Config (env vars)
| Var | Default | |
|---|---|---|
| `PORT` | 8080 | |
| `DATA_DIR` | `data` | where sealed undelivered messages are saved |
| `WEB_DIR` | `../web` | static files |
| `PUBLIC_URL` | LAN IP | base URL put in pairing QR codes when the page is opened on localhost |
| `STUN_URL` | Google STUN | |
| `TURN_URL`, `TURN_USER`, `TURN_PASS` | none | **recommended across networks:** with no relay on the server, strict NATs need TURN for P2P |

## Deploy (works anywhere)
```sh
docker build -t anydrop . && docker run -p 8080:8080 anydrop
```
Put it behind HTTPS (Caddy, Cloudflare, Fly.io, a VPS). HTTPS is needed for "Install app" on Android and for iOS.

**Auto-deploy from this repo:** Any host that builds a `Dockerfile` works (Render, Railway, Fly.io, Koyeb, a VPS…). Nixpacks hosts (Coolify, Railway) also work with no config file: they detect Bun from `bun.lock`, and `engines.node` in `package.json` keeps Nixpacks off the removed Node 18. If the host asks:

| Setting | Value |
|---|---|
| Install / build command | `bun install` |
| Start command | `bun run start` |
| Port | `8080` (or whatever the host puts in `$PORT`) |

- **Port:** the server listens on `$PORT` (default 8080). Most hosts set it for you.
- **HTTPS is required** for the web app's crypto and camera, and the host's HTTPS proxy must allow WebSocket upgrades on `/ws` (all of the above do).
- **Health check:** `GET /api/health` returns `ok`.
- **Persistent disk:** mount a volume at `/data` (`DATA_DIR`). It holds only sealed, unreadable messages waiting for delivery. Without a volume, waiting messages are lost on redeploy.
- **Optional:** `PUBLIC_URL=https://your-domain` so pairing QR codes point at the public address. `STUN_URL`, `TURN_URL`, `TURN_USER`, `TURN_PASS` for WebRTC.

## Roadmap
1. TURN server, so files and calls also connect on strict networks (some mobile carriers, office Wi-Fi).
2. iOS app: same React Native code, with Apple push (APNs) instead of the background connection, since iOS doesn't allow one.
3. Firebase push as a backup on Android, and Web Push for the web app.
4. Share sheet ("Share → AnyDrop"), groups.
