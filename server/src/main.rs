//! AnyDrop server. A switchboard and a mailbox of sealed boxes: it never sees message text or file bytes.
//!
//! What it does:
//!   * identity   - each device owns a P-256 key pair. The server sends a random
//!                  challenge, the device signs it, and its id is sha256(public key).
//!                  No accounts, no signup, nothing stored on disk.
//!   * presence   - a device lists the ids it knows (`watch`). Two devices see each
//!                  other online only if both list each other.
//!   * signaling  - forwards WebRTC offers/answers/ICE between mutual contacts. The
//!                  chat itself then runs device-to-device over a data channel.
//!   * mailbox    - text messages, sealed end-to-end by the sender (ECDH P-256 +
//!                  AES-GCM, see PROTOCOL.md). The server holds the sealed box until
//!                  the receiving device acks it, then deletes it. It cannot read
//!                  them. Saved to DATA_DIR so a restart loses nothing.
//!   * pairing    - one device opens a short-lived pairing (QR code + 6-digit code),
//!                  the other joins it, both receive each other's id and public key.

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr, UdpSocket},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::header,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use futures_util::{SinkExt, StreamExt};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use rand::{Rng, RngCore};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, Mutex};
use tower_http::services::ServeDir;

const PAIR_TTL: Duration = Duration::from_secs(600);
const MAX_PAIR_ATTEMPTS: u32 = 10;
const MAIL_TTL_MS: u64 = 30 * 24 * 3600 * 1000;
const MAX_MAILBOX: usize = 5000;
const MAX_BOX: usize = 48 * 1024;
const MAX_KEY: usize = 200;
const BATCH: usize = 100;
const MAX_WATCH: usize = 1000;

struct Client {
    conn: u64,
    pubkey: String,
    /// ECDH public key for sealed messages, and the identity key's signature over it.
    box_key: String,
    box_sig: String,
    watch: HashSet<String>,
    tx: mpsc::Sender<Message>,
    last_online: Vec<String>,
}

struct Pairing {
    owner: String,
    code: String,
    card: Value,
    created: Instant,
}

#[derive(Default)]
struct Hub {
    clients: HashMap<String, Client>,
    pairings: HashMap<String, Pairing>, // token -> pairing
    codes: HashMap<String, String>,     // 6-digit code -> token
    /// recipient id -> sealed messages waiting for an ack
    mail: HashMap<String, Vec<Mail>>,
    mail_dirty: bool,
}

#[derive(Clone)]
struct Mail {
    mid: String,
    from: String,
    sealed: String,
    ts: u64,
}

impl Mail {
    fn json(&self) -> Value {
        json!({ "mid": self.mid, "from": self.from, "box": self.sealed, "ts": self.ts })
    }
}

#[derive(Clone)]
struct AppState {
    hub: Arc<Mutex<Hub>>,
    config: Value,
}

type Outbox = Vec<(mpsc::Sender<Message>, Message)>;

static CONN_IDS: AtomicU64 = AtomicU64::new(1);

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_target(false).init();

    let port: u16 = env("PORT").and_then(|p| p.parse().ok()).unwrap_or(8080);
    let web_dir = env("WEB_DIR").unwrap_or_else(|| concat!(env!("CARGO_MANIFEST_DIR"), "/../web").into());

    let mut ice = vec![json!({ "urls": env("STUN_URL").unwrap_or("stun:stun.l.google.com:19302".into()) })];
    if let Some(url) = env("TURN_URL") {
        ice.push(json!({ "urls": url, "username": env("TURN_USER"), "credential": env("TURN_PASS") }));
    }
    let lan_url = env("PUBLIC_URL").or_else(|| lan_ip().map(|ip| format!("http://{ip}:{port}")));

    let data_dir = std::path::PathBuf::from(env("DATA_DIR").unwrap_or_else(|| "data".into()));
    let mail_file = data_dir.join("mailbox.json");
    let hub = Hub { mail: load_mail(&mail_file), ..Default::default() };
    let state = AppState { hub: Arc::new(Mutex::new(hub)), config: json!({ "iceServers": ice, "lanUrl": lan_url }) };
    tokio::spawn(save_mail_loop(state.hub.clone(), data_dir, mail_file));

    let app = Router::new()
        .route("/ws", get(ws_handler))
        .route("/api/config", get(|State(s): State<AppState>| async move { Json(s.config) }))
        .route("/api/qr", get(qr_svg))
        .route("/api/health", get(|| async { "ok" }))
        .fallback_service(ServeDir::new(&web_dir))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await.expect("bind port");
    print_banner(port, lan_url.as_deref());
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
}

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

fn load_mail(path: &std::path::Path) -> HashMap<String, Vec<Mail>> {
    let Ok(raw) = std::fs::read(path) else { return HashMap::new() };
    let Ok(v) = serde_json::from_slice::<Value>(&raw) else {
        tracing::warn!("ignoring unreadable {}", path.display());
        return HashMap::new();
    };
    let cutoff = now_ms().saturating_sub(MAIL_TTL_MS);
    let mut out: HashMap<String, Vec<Mail>> = HashMap::new();
    for (to, items) in v.as_object().into_iter().flatten() {
        let list: Vec<Mail> = items
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|m| {
                Some(Mail {
                    mid: m["mid"].as_str()?.into(),
                    from: m["from"].as_str()?.into(),
                    sealed: m["box"].as_str()?.into(),
                    ts: m["ts"].as_u64()?,
                })
            })
            .filter(|m| m.ts >= cutoff)
            .collect();
        if !list.is_empty() {
            out.insert(to.clone(), list);
        }
    }
    let n: usize = out.values().map(Vec::len).sum();
    if n > 0 {
        tracing::info!("loaded {n} sealed messages waiting for delivery");
    }
    out
}

/// Writes the mailbox to disk (atomically) at most every 2 seconds, when it changed.
async fn save_mail_loop(hub: Arc<Mutex<Hub>>, dir: std::path::PathBuf, file: std::path::PathBuf) {
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    let mut prune = Instant::now();
    loop {
        tick.tick().await;
        let snapshot = {
            let mut hub = hub.lock().await;
            if prune.elapsed() > Duration::from_secs(3600) {
                prune = Instant::now();
                let cutoff = now_ms().saturating_sub(MAIL_TTL_MS);
                for list in hub.mail.values_mut() {
                    list.retain(|m| m.ts >= cutoff);
                }
                hub.mail.retain(|_, l| !l.is_empty());
                hub.mail_dirty = true;
            }
            if !hub.mail_dirty {
                continue;
            }
            hub.mail_dirty = false;
            let map: serde_json::Map<String, Value> =
                hub.mail.iter().map(|(k, l)| (k.clone(), Value::Array(l.iter().map(Mail::json).collect()))).collect();
            Value::Object(map).to_string()
        };
        let tmp = file.with_extension("json.tmp");
        let res = tokio::fs::create_dir_all(&dir).await;
        let res = match res {
            Ok(()) => match tokio::fs::write(&tmp, snapshot).await {
                Ok(()) => tokio::fs::rename(&tmp, &file).await,
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        };
        if let Err(e) = res {
            tracing::warn!("could not save mailbox: {e}");
            hub.lock().await.mail_dirty = true;
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn lan_ip() -> Option<IpAddr> {
    // Connecting a UDP socket sends nothing; it only picks the outgoing interface.
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| s.connect("8.8.8.8:80").map(|_| s))
        .and_then(|s| s.local_addr())
        .map(|a| a.ip())
        .ok()
}

fn qr(data: &str) -> Option<qrcode::QrCode> {
    qrcode::QrCode::new(data.as_bytes()).ok()
}

fn print_banner(port: u16, lan: Option<&str>) {
    println!("\n  AnyDrop server running on port {port}");
    println!("  This computer: http://localhost:{port}");
    if let Some(url) = lan {
        println!("  Phone:         {url}   (same Wi-Fi - scan this)\n");
        if let Some(code) = qr(url) {
            use qrcode::render::unicode::Dense1x2;
            println!("{}\n", code.render::<Dense1x2>().dark_color(Dense1x2::Light).light_color(Dense1x2::Dark).build());
        }
    }
}

async fn qr_svg(Query(q): Query<HashMap<String, String>>) -> Response {
    let data = q.get("d").map(String::as_str).unwrap_or_default();
    match (data.len() <= 1024).then(|| qr(data)).flatten() {
        Some(code) => {
            let svg = code
                .render::<qrcode::render::svg::Color>()
                .min_dimensions(240, 240)
                .quiet_zone(true)
                .build();
            ([(header::CONTENT_TYPE, "image/svg+xml"), (header::CACHE_CONTROL, "no-store")], svg).into_response()
        }
        None => (axum::http::StatusCode::BAD_REQUEST, "bad data").into_response(),
    }
}

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> Response {
    ws.max_message_size(64 * 1024).on_upgrade(move |socket| handle_socket(socket, state)).into_response()
}

fn text(v: Value) -> Message {
    Message::Text(v.to_string().into())
}

fn random_b64(n: usize) -> String {
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    B64.encode(buf)
}

/// Device id = first 16 bytes of sha256(raw public key), hex.
fn device_id(pubkey: &[u8]) -> String {
    Sha256::digest(pubkey)[..16].iter().map(|b| format!("{b:02x}")).collect()
}

fn valid_id(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Checks the signed challenge and returns (id, public key b64).
fn verify_auth(v: &Value, nonce: &str) -> Option<(String, String)> {
    let pub_b64 = v["pub"].as_str()?;
    let pubkey = B64.decode(pub_b64).ok()?;
    let sig = B64.decode(v["sig"].as_str()?).ok()?;
    let key = VerifyingKey::from_sec1_bytes(&pubkey).ok()?;
    let sig = Signature::from_slice(&sig).ok()?;
    key.verify(format!("anydrop-auth:{nonce}").as_bytes(), &sig).ok()?;
    Some((device_id(&pubkey), pub_b64.to_string()))
}

fn clean(v: &Value, max: usize, fallback: &str) -> String {
    let s: String = v.as_str().unwrap_or_default().trim().chars().filter(|c| !c.is_control()).take(max).collect();
    if s.is_empty() { fallback.into() } else { s }
}

/// A base64url public key or signature, or "" if absent/invalid.
fn clean_key(v: &Value) -> String {
    let s = v.as_str().unwrap_or_default();
    if s.len() <= MAX_KEY && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') { s.into() } else { String::new() }
}

fn valid_mid(s: &str) -> bool {
    (1..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Pending mail for `id`, in frames of at most BATCH messages.
fn mail_frames(hub: &Hub, id: &str) -> Vec<Message> {
    hub.mail
        .get(id)
        .map(|l| l.chunks(BATCH).map(|c| text(json!({ "type": "msgs", "items": c.iter().map(Mail::json).collect::<Vec<_>>() }))).collect())
        .unwrap_or_default()
}

fn card(hub: &Hub, id: &str, v: &Value) -> Value {
    let c = &hub.clients[id];
    json!({
        "id": id,
        "pub": c.pubkey,
        "box": c.box_key,
        "boxSig": c.box_sig,
        "name": clean(&v["name"], 40, "Device"),
        "device": clean(&v["device"], 16, "other"),
    })
}

fn parse_watch(v: &Value) -> HashSet<String> {
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|s| valid_id(s))
        .take(MAX_WATCH)
        .map(String::from)
        .collect()
}

async fn handle_socket(socket: WebSocket, state: AppState) {
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::channel::<Message>(64);
    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if sink.send(msg).await.is_err() {
                break;
            }
        }
    });

    let conn = CONN_IDS.fetch_add(1, Ordering::Relaxed);
    let nonce = random_b64(32);
    let _ = tx.send(text(json!({ "type": "challenge", "nonce": nonce }))).await;

    let mut me: Option<String> = None;
    let mut pair_attempts = 0u32;

    while let Some(Ok(msg)) = stream.next().await {
        let out = match msg {
            Message::Text(t) => match serde_json::from_str::<Value>(t.as_str()) {
                Ok(v) => on_json(&state, &mut me, &mut pair_attempts, conn, &nonce, &tx, v).await,
                Err(_) => vec![],
            },
            Message::Close(_) => break,
            _ => vec![],
        };
        deliver(out).await;
    }

    if let Some(id) = me {
        let out = {
            let mut hub = state.hub.lock().await;
            match hub.clients.get(&id) {
                Some(c) if c.conn == conn => {
                    let affected: Vec<String> = c.watch.iter().cloned().collect();
                    hub.clients.remove(&id);
                    tracing::info!("offline: {id}");
                    presence_updates(&mut hub, affected)
                }
                _ => vec![],
            }
        };
        deliver(out).await;
    }
    writer.abort();
}

async fn deliver(out: Outbox) {
    for (tx, msg) in out {
        let _ = tx.send(msg).await;
    }
}

fn mutual(hub: &Hub, a: &str, b: &str) -> bool {
    a != b
        && hub.clients.get(a).is_some_and(|c| c.watch.contains(b))
        && hub.clients.get(b).is_some_and(|c| c.watch.contains(a))
}

/// Sends each affected online client its list of online mutual contacts, if it changed.
fn presence_updates(hub: &mut Hub, affected: impl IntoIterator<Item = String>) -> Outbox {
    let mut out = vec![];
    let ids: HashSet<String> = affected.into_iter().collect();
    for id in ids {
        let Some(c) = hub.clients.get(&id) else { continue };
        let mut online: Vec<String> = c.watch.iter().filter(|w| mutual(hub, &id, w)).cloned().collect();
        online.sort();
        let c = hub.clients.get_mut(&id).unwrap();
        if c.last_online != online {
            out.push((c.tx.clone(), text(json!({ "type": "online", "ids": online }))));
            c.last_online = online;
        }
    }
    out
}

async fn on_json(
    state: &AppState,
    me: &mut Option<String>,
    pair_attempts: &mut u32,
    conn: u64,
    nonce: &str,
    tx: &mpsc::Sender<Message>,
    v: Value,
) -> Outbox {
    let kind = v["type"].as_str().unwrap_or_default();
    let mut hub = state.hub.lock().await;
    let mut out: Outbox = vec![];
    let reply = |out: &mut Outbox, v: Value| out.push((tx.clone(), text(v)));

    if kind == "auth" {
        if me.is_some() {
            return out;
        }
        let Some((id, pubkey)) = verify_auth(&v, nonce) else {
            reply(&mut out, json!({ "type": "error", "message": "auth failed" }));
            return out;
        };
        // One live connection per identity: the newest wins, the old tab is told why.
        if let Some(old) = hub.clients.remove(&id) {
            out.push((old.tx, text(json!({ "type": "replaced" }))));
        }
        let watch = parse_watch(&v["watch"]);
        let mut affected: Vec<String> = watch.iter().cloned().collect();
        affected.push(id.clone());
        let (box_key, box_sig) = (clean_key(&v["box"]), clean_key(&v["boxSig"]));
        hub.clients.insert(id.clone(), Client { conn, pubkey, box_key, box_sig, watch, tx: tx.clone(), last_online: vec![] });

        tracing::info!("online: {id}");
        *me = Some(id.clone());
        reply(&mut out, json!({ "type": "welcome", "id": id, "time": now_ms() }));
        for frame in mail_frames(&hub, &id) {
            out.push((tx.clone(), frame));
        }
        out.extend(presence_updates(&mut hub, affected));
        return out;
    }

    let Some(id) = me.clone() else { return out };
    if !hub.clients.get(&id).is_some_and(|c| c.conn == conn) {
        return out; // superseded by a newer connection
    }

    match kind {
        "ping" => reply(&mut out, json!({ "type": "pong" })),
        "watch" => {
            let watch = parse_watch(&v["ids"]);
            let c = hub.clients.get_mut(&id).unwrap();
            let mut affected: Vec<String> = c.watch.union(&watch).cloned().collect();
            affected.push(id.clone());
            c.watch = watch;
            out.extend(presence_updates(&mut hub, affected));
        }
        "signal" => {
            let to = v["to"].as_str().unwrap_or_default();
            if mutual(&hub, &id, to) {
                let fwd = json!({ "type": "signal", "from": id, "data": v["data"] });
                out.push((hub.clients[to].tx.clone(), text(fwd)));
            }
        }
        // A sealed message. `live` ones (typing) are only passed to an online contact.
        // Others are kept until the recipient acks them, and forwarded now if it is online.
        "send" => {
            let to = v["to"].as_str().unwrap_or_default();
            let mid = v["mid"].as_str().unwrap_or_default();
            let sealed = v["box"].as_str().unwrap_or_default();
            if !valid_id(to) || to == id || !valid_mid(mid) || sealed.is_empty() || sealed.len() > MAX_BOX {
                reply(&mut out, json!({ "type": "send-error", "mid": mid, "message": "invalid message" }));
                return out;
            }
            if v["live"].as_bool() == Some(true) {
                if mutual(&hub, &id, to) {
                    let m = Mail { mid: mid.into(), from: id.clone(), sealed: sealed.into(), ts: now_ms() };
                    out.push((hub.clients[to].tx.clone(), text(json!({ "type": "live", "msg": m.json() }))));
                }
                return out;
            }
            let ts = now_ms();
            let list = hub.mail.entry(to.to_string()).or_default();
            if let Some(m) = list.iter().find(|m| m.mid == mid && m.from == id) {
                // Retransmit of something we already hold: just confirm again.
                let ts = m.ts;
                reply(&mut out, json!({ "type": "sent", "mid": mid, "to": to, "ts": ts }));
                return out;
            }
            if list.len() >= MAX_MAILBOX {
                reply(&mut out, json!({ "type": "send-error", "mid": mid, "message": "recipient mailbox is full" }));
                return out;
            }
            let m = Mail { mid: mid.into(), from: id.clone(), sealed: sealed.into(), ts };
            list.push(m.clone());
            hub.mail_dirty = true;
            if let Some(c) = hub.clients.get(to) {
                out.push((c.tx.clone(), text(json!({ "type": "msgs", "items": [m.json()] }))));
            }
            reply(&mut out, json!({ "type": "sent", "mid": mid, "to": to, "ts": ts }));
        }
        "ack" => {
            let mids: HashSet<&str> = v["mids"].as_array().into_iter().flatten().filter_map(Value::as_str).take(1000).collect();
            let hub = &mut *hub;
            if let Some(list) = hub.mail.get_mut(&id) {
                let before = list.len();
                list.retain(|m| !mids.contains(m.mid.as_str()));
                hub.mail_dirty |= list.len() != before;
                if list.is_empty() {
                    hub.mail.remove(&id);
                }
            }
        }
        "pair-open" => {
            hub.pairings.retain(|_, p| p.created.elapsed() < PAIR_TTL && p.owner != id);
            let live: HashSet<String> = hub.pairings.keys().cloned().collect();
            hub.codes.retain(|_, t| live.contains(t));
            let mut rng = rand::thread_rng();
            let code = loop {
                let c = format!("{:06}", rng.gen_range(0..1_000_000));
                if !hub.codes.contains_key(&c) {
                    break c;
                }
            };
            let token = random_b64(18);
            let card = card(&hub, &id, &v);
            hub.codes.insert(code.clone(), token.clone());
            hub.pairings.insert(token.clone(), Pairing { owner: id.clone(), code: code.clone(), card, created: Instant::now() });
            reply(&mut out, json!({ "type": "pair-open", "token": token, "code": code, "ttl": PAIR_TTL.as_secs() }));
        }
        "pair-join" => {
            *pair_attempts += 1;
            let token = match v["code"].as_str() {
                Some(code) => hub.codes.get(code.trim()).cloned(),
                None => v["token"].as_str().map(String::from),
            };
            let ok = token.as_ref().and_then(|t| hub.pairings.get(t)).is_some_and(|p| {
                p.created.elapsed() < PAIR_TTL && p.owner != id && hub.clients.contains_key(&p.owner)
            });
            if *pair_attempts > MAX_PAIR_ATTEMPTS || !ok {
                let message = if *pair_attempts > MAX_PAIR_ATTEMPTS {
                    "Too many attempts. Reload and try again."
                } else {
                    "That code is invalid or expired, or the other device went offline."
                };
                reply(&mut out, json!({ "type": "pair-error", "message": message }));
                return out;
            }
            let p = hub.pairings.remove(&token.unwrap()).unwrap();
            hub.codes.remove(&p.code);
            let mine = card(&hub, &id, &v);
            out.push((hub.clients[&p.owner].tx.clone(), text(json!({ "type": "paired", "peer": mine }))));
            reply(&mut out, json!({ "type": "paired", "peer": p.card }));
        }
        "pair-close" => {
            if let Some(token) = v["token"].as_str() {
                if hub.pairings.get(token).is_some_and(|p| p.owner == id) {
                    let p = hub.pairings.remove(token).unwrap();
                    hub.codes.remove(&p.code);
                }
            }
        }
        _ => {}
    }
    out
}
