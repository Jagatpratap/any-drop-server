// Local storage (IndexedDB). Everything about you, your contacts and your chats
// lives only on this device.
//   kv        identity, profile
//   contacts  { id, pub, name, device, addedAt, lastSeen, unread, last, waiting }
//   messages  { key: chat:id, id, chat, dir, kind, text|file+blob, ts, status, rs }

// ?profile=x keeps a separate identity, so one browser can act as several devices (testing).
export const PROFILE = (new URLSearchParams(location.search).get('profile') || '').replace(/[^\w-]/g, '').slice(0, 32);

let dbp;
function open() {
  return (dbp ||= new Promise((resolve, reject) => {
    const r = indexedDB.open(PROFILE ? `anydrop-${PROFILE}` : 'anydrop', 1);
    r.onupgradeneeded = () => {
      const db = r.result;
      db.createObjectStore('kv');
      db.createObjectStore('contacts', { keyPath: 'id' });
      db.createObjectStore('messages', { keyPath: 'key' }).createIndex('chat', ['chat', 'ts']);
    };
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  }));
}

const done = (r) => new Promise((resolve, reject) => {
  r.onsuccess = () => resolve(r.result);
  r.onerror = () => reject(r.error);
});
const os = async (name, mode = 'readonly') => (await open()).transaction(name, mode).objectStore(name);
const chatRange = (chat) => IDBKeyRange.bound([chat, -Infinity], [chat, Infinity]);

export const db = {
  get: async (store, key) => done((await os(store)).get(key)),
  put: async (store, value, key) => done((await os(store, 'readwrite')).put(value, key)),
  del: async (store, key) => done((await os(store, 'readwrite')).delete(key)),
  all: async (store) => done((await os(store)).getAll()),
  chat: async (chat) => done((await os('messages')).index('chat').getAll(chatRange(chat))),
  async clearChat(chat) {
    const store = await os('messages', 'readwrite');
    return new Promise((resolve, reject) => {
      const cur = store.index('chat').openKeyCursor(chatRange(chat));
      cur.onsuccess = () => {
        const c = cur.result;
        if (!c) return resolve();
        store.delete(c.primaryKey);
        c.continue();
      };
      cur.onerror = () => reject(cur.error);
    });
  },
};
