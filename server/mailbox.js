// Saves the sealed mailbox to DATA_DIR/mailbox.json so a restart or redeploy loses nothing.
// Format: { "<recipient id>": [{ mid, from, box, ts }, ...] }

import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { MAIL_TTL_MS } from './hub.js';

export function loadMail(dir, log = console.log) {
  const mail = new Map();
  let data;
  try {
    data = JSON.parse(readFileSync(join(dir, 'mailbox.json'), 'utf8'));
  } catch (e) {
    if (e.code !== 'ENOENT') log(`ignoring unreadable mailbox.json: ${e.message}`);
    return mail;
  }
  const cutoff = Date.now() - MAIL_TTL_MS;
  let n = 0;
  for (const [to, items] of Object.entries(data ?? {})) {
    if (!Array.isArray(items)) continue;
    const list = items.filter((m) =>
      typeof m?.mid === 'string' && typeof m.from === 'string' && typeof m.box === 'string' &&
      Number.isInteger(m.ts) && m.ts >= cutoff);
    if (list.length) {
      mail.set(to, list.map(({ mid, from, box, ts }) => ({ mid, from, box, ts })));
      n += list.length;
    }
  }
  if (n) log(`loaded ${n} sealed messages waiting for delivery`);
  return mail;
}

/** Writes the file atomically if the mailbox changed. Returns false on failure. */
export function saveMail(hub, dir, log = console.log) {
  if (!hub.mailDirty) return true;
  hub.mailDirty = false;
  const file = join(dir, 'mailbox.json');
  try {
    mkdirSync(dir, { recursive: true });
    writeFileSync(`${file}.tmp`, JSON.stringify(Object.fromEntries(hub.mail)));
    renameSync(`${file}.tmp`, file);
    return true;
  } catch (e) {
    log(`could not save mailbox: ${e.message}`);
    hub.mailDirty = true;
    return false;
  }
}
