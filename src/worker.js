// Agent Relay v2 — RelayHub Durable Object + SQLite + R2 files
// Phase 1: seq/ack delivery, hashed keys, default-deny ACL, loop limits,
// secret-pattern blocking, R2 file exchange with type guards.

const MAX_MSG = 8000;
const MAX_FILE = 10 * 1024 * 1024;
const HOP_LIMIT = 6;
const PAIR_WINDOW_MS = 10 * 60 * 1000;
const PAIR_MAX = 20;
const DUP_MAX = 3;
const DAY_MAX = 2000;
const ALLOWED_EXT = ['md','txt','json','yaml','yml','toml','csv','log','diff','patch','png','jpg','jpeg','webp','pdf','zip','gz'];
const SECRET_PATTERNS = [/ghp_[A-Za-z0-9]{20,}/, /github_pat_[A-Za-z0-9_]{20,}/, /sk-[A-Za-z0-9-_]{16,}/, /AKIA[0-9A-Z]{16}/, /ark_[a-f0-9]{32}/, /-----BEGIN [A-Z ]*PRIVATE KEY-----/];

const j = (data, status = 200, extra = {}) =>
  new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...extra } });

const sha256hex = async (s) => {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join('');
};

const NAME_RE = /^[a-z0-9_-]{1,32}$/;

export class RelayHub {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.sql = state.storage.sql;
    this._migrate();
    state.storage.setAlarm(Date.now() + 60_000);
  }

  _migrate() {
    let v = null;
    try { v = this.sql.exec("SELECT value FROM meta WHERE key='schema_version'").toArray()[0]; } catch (e) {}
    if (v) return;
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS agents(name TEXT PRIMARY KEY, key_hash TEXT UNIQUE, status TEXT DEFAULT 'active', last_seen INTEGER, created_at INTEGER, revoked_at INTEGER);
      CREATE TABLE IF NOT EXISTS acl(from_agent TEXT, to_agent TEXT, kind TEXT, PRIMARY KEY(from_agent, to_agent, kind));
      CREATE TABLE IF NOT EXISTS messages(seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE, from_agent TEXT, to_agent TEXT, kind TEXT DEFAULT 'text', body TEXT, thread_id TEXT, reply_to TEXT, hop INTEGER DEFAULT 0, idem_key TEXT, ts INTEGER, UNIQUE(from_agent, idem_key));
      CREATE TABLE IF NOT EXISTS cursors(agent TEXT PRIMARY KEY, delivered_seq INTEGER DEFAULT 0, acked_seq INTEGER DEFAULT 0, updated_at INTEGER);
      CREATE TABLE IF NOT EXISTS counters(scope TEXT, window INTEGER, n INTEGER DEFAULT 0, PRIMARY KEY(scope, window));
      CREATE TABLE IF NOT EXISTS files(id TEXT PRIMARY KEY, owner TEXT, to_agent TEXT, name TEXT, size INTEGER, sha256 TEXT, status TEXT DEFAULT 'pending', r2_key TEXT, created_at INTEGER, expires_at INTEGER);
      CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
      INSERT INTO meta(key, value) VALUES('schema_version','1');
    `);
  }

  async _agentByToken(token) {
    if (!token) return null;
    if (token === this.env.ADMIN_KEY) return '__admin__';
    const h = await sha256hex(token);
    const r = this.sql.exec("SELECT name, status FROM agents WHERE key_hash=? AND status='active'", h).toArray()[0];
    return r ? r.name : null;
  }

  _bump(scope, windowMs, max) {
    const w = Math.floor(Date.now() / windowMs);
    const cur = this.sql.exec("SELECT n FROM counters WHERE scope=? AND window=?", scope, w).toArray()[0];
    const n = cur ? cur.n : 0;
    if (n >= max) return false;
    this.sql.exec("INSERT INTO counters(scope,window,n) VALUES(?,?,1) ON CONFLICT(scope,window) DO UPDATE SET n=n+1", scope, w);
    return true;
  }

  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const token = (request.headers.get('Authorization') || '').replace('Bearer ', '');
    const me = await this._agentByToken(token);
    if (!me) return j({ error: 'unauthorized' }, 401);
    this.sql.exec("UPDATE agents SET last_seen=? WHERE name=?", Date.now(), me);
    const isAdmin = me === '__admin__';
    let body = {};
    if ((method === 'POST' || method === 'PUT') && !path.endsWith('/content')) body = await request.json().catch(() => ({}));

    try {
      // ---------- admin ----------
      if (path === '/v2/join' && isAdmin && method === 'POST') {
        const name = String(body.agent || '').trim().toLowerCase();
        if (!NAME_RE.test(name) || name === '__admin__' || name === '__all__') return j({ error: 'invalid agent name' }, 400);
        if (this.sql.exec("SELECT 1 FROM agents WHERE name=?", name).toArray()[0]) return j({ error: 'agent exists' }, 409);
        const key = 'ark_' + crypto.randomUUID().replace(/-/g, '');
        this.sql.exec("INSERT INTO agents(name, key_hash, created_at) VALUES(?,?,?)", name, await sha256hex(key), Date.now());
        return j({ ok: true, agent: name, key }); // shown ONCE
      }
      if (path === '/v2/revoke' && isAdmin && method === 'POST') {
        this.sql.exec("UPDATE agents SET status='revoked', revoked_at=? WHERE name=?", Date.now(), String(body.agent || ''));
        return j({ ok: true });
      }
      if (path === '/v2/acl' && isAdmin && method === 'POST') {
        const { from, to, kind, allow } = body;
        if (!NAME_RE.test(String(from)) || !NAME_RE.test(String(to)) || !['msg', 'file', 'broadcast'].includes(kind))
          return j({ error: 'invalid acl args' }, 400);
        if (allow === false) this.sql.exec("DELETE FROM acl WHERE from_agent=? AND to_agent=? AND kind=?", from, to, kind);
        else this.sql.exec("INSERT OR IGNORE INTO acl(from_agent,to_agent,kind) VALUES(?,?,?)", from, to, kind);
        return j({ ok: true });
      }
      if (path === '/v2/agents' && isAdmin && method === 'GET') {
        const rows = this.sql.exec("SELECT name, status, last_seen FROM agents WHERE name != '__admin__' ORDER BY name").toArray();
        return j({ agents: rows });
      }
      if (path === '/v2/log' && isAdmin && method === 'GET') {
        const after = Number(url.searchParams.get('after') || 0);
        const rows = this.sql.exec("SELECT seq, id, from_agent, to_agent, kind, body, ts FROM messages WHERE seq > ? ORDER BY seq LIMIT 200", after).toArray();
        return j({ messages: rows });
      }

      // ---------- messages ----------
      if (path === '/v2/messages' && method === 'POST') {
        const to = String(body.to || '');
        const text = body.text;
        if (typeof text !== 'string' || !text.trim()) return j({ error: 'text required' }, 400);
        if (text.length > MAX_MSG) return j({ error: 'message too large', max: MAX_MSG }, 413);
        for (const p of SECRET_PATTERNS) if (p.test(text)) return j({ error: 'rejected: looks like a secret — pass a reference/file instead' }, 422);

        let toAgent;
        if (to === '__all__') toAgent = '__all__';
        else {
          if (!NAME_RE.test(to)) return j({ error: 'invalid recipient' }, 400);
          if (!this.sql.exec("SELECT name FROM agents WHERE name=? AND status='active'", to).toArray()[0])
            return j({ error: 'unknown recipient: ' + to }, 400);
          toAgent = to;
        }
        if (!isAdmin) {
          const kind = toAgent === '__all__' ? 'broadcast' : 'msg';
          if (!this.sql.exec("SELECT 1 FROM acl WHERE from_agent=? AND to_agent=? AND kind=?", me, toAgent, kind).toArray()[0])
            return j({ error: 'acl denies ' + me + ' -> ' + toAgent + ' (' + kind + ')' }, 403);
        }
        if (!isAdmin) {
          if (!this._bump('pair:' + me + '>' + toAgent, PAIR_WINDOW_MS, PAIR_MAX)) return j({ error: 'rate limit: too many messages to ' + toAgent }, 429);
          if (!this._bump('day:' + me, 24 * 3600 * 1000, DAY_MAX)) return j({ error: 'daily quota exceeded' }, 429);
          if (!this._bump('dup:' + me + ':' + await sha256hex(text.trim()), PAIR_WINDOW_MS, DUP_MAX - 1)) return j({ error: 'duplicate text flooded — rejected' }, 429);
        }
        let hop = 0, thread = body.thread_id || null;
        if (body.reply_to) {
          const p = this.sql.exec("SELECT hop, thread_id, to_agent, from_agent FROM messages WHERE id=?", String(body.reply_to)).toArray()[0];
          if (!p) return j({ error: 'reply_to not found' }, 400);
          if (me !== p.to_agent && me !== p.from_agent) return j({ error: 'cannot reply to a message you cannot see' }, 403);
          hop = p.hop + 1;
          if (hop > HOP_LIMIT) return j({ error: 'conversation too deep (loop guard)' }, 429);
          thread = thread || p.thread_id || p.id;
        }
        const id = Date.now() + '-' + crypto.randomUUID().slice(0, 8);
        const ts = Date.now();
        const idem = body.idem_key ? String(body.idem_key).slice(0, 100) : null;
        if (idem) {
          const dup = this.sql.exec("SELECT seq, id, body FROM messages WHERE from_agent=? AND idem_key=?", me, idem).toArray()[0];
          if (dup) {
            if (dup.body !== text) return j({ error: 'idem_key reused with different content' }, 409);
            return j({ ok: true, msg: { seq: dup.seq, id: dup.id }, deduplicated: true });
          }
        }
        this.sql.exec("INSERT INTO messages(id, from_agent, to_agent, kind, body, thread_id, reply_to, hop, idem_key, ts) VALUES(?,?,?,?,?,?,?,?,?,?)",
          id, me, toAgent, 'text', text, thread, body.reply_to || null, hop, idem, ts);
        const seq = this.sql.exec("SELECT seq FROM messages WHERE id=?", id).toArray()[0].seq;
        return j({ ok: true, msg: { seq, id, from: me, to: toAgent, ts } });
      }

      if (path === '/v2/inbox' && method === 'GET') {
        const after = Number(url.searchParams.get('after') || 0);
        const rows = this.sql.exec(
          "SELECT seq, id, from_agent, to_agent, kind, body, thread_id, reply_to, hop, ts FROM messages WHERE seq > ? AND (to_agent=? OR (to_agent='__all__' AND from_agent != ?)) ORDER BY seq LIMIT 100",
          after, me, me).toArray();
        if (rows.length) {
          const maxSeq = rows[rows.length - 1].seq;
          this.sql.exec("INSERT INTO cursors(agent, delivered_seq, updated_at) VALUES(?,?,?) ON CONFLICT(agent) DO UPDATE SET delivered_seq=MAX(delivered_seq, ?), updated_at=?",
            me, maxSeq, Date.now(), maxSeq, Date.now());
        }
        const recent = this.sql.exec("SELECT MAX(ts) AS m FROM messages").toArray()[0].m || 0;
        const gap = Date.now() - recent;
        const suggested = gap < 120000 ? 5000 : gap < 600000 ? 15000 : 30000;
        return j({ agent: me, messages: rows, next_after: rows.length ? rows[rows.length - 1].seq : after, suggested_poll_ms: suggested });
      }

      if (path === '/v2/ack' && method === 'POST') {
        const seq = Number(body.seq || 0);
        if (!seq) return j({ error: 'seq required' }, 400);
        this.sql.exec("INSERT INTO cursors(agent, acked_seq, updated_at) VALUES(?,?,?) ON CONFLICT(agent) DO UPDATE SET acked_seq=MAX(acked_seq, ?), updated_at=?",
          me, seq, Date.now(), seq, Date.now());
        return j({ ok: true, acked: seq });
      }

      if (path === '/v2/receipts' && method === 'GET') {
        const id = url.searchParams.get('id');
        const m = this.sql.exec("SELECT seq, to_agent FROM messages WHERE id=? AND from_agent=?", id, me).toArray()[0];
        if (!m) return j({ error: 'not found' }, 404);
        const c = this.sql.exec("SELECT agent, delivered_seq, acked_seq FROM cursors WHERE agent=?", m.to_agent).toArray()[0];
        return j({ id, to: m.to_agent, seq: m.seq, delivered: c ? c.delivered_seq >= m.seq : false, read: c ? c.acked_seq >= m.seq : false });
      }

      // ---------- files ----------
      if (path === '/v2/files' && method === 'POST') {
        const to = String(body.to || '');
        const name = String(body.name || 'file').replace(/[\u0000-\u001f\u202e]/g, '');
        const size = Number(body.size || 0);
        const sha = String(body.sha256 || '');
        if (!NAME_RE.test(to)) return j({ error: 'invalid recipient' }, 400);
        if (!this.sql.exec("SELECT 1 FROM agents WHERE name=? AND status='active'", to).toArray()[0]) return j({ error: 'unknown recipient' }, 400);
        if (!isAdmin && !this.sql.exec("SELECT 1 FROM acl WHERE from_agent=? AND to_agent=? AND kind='file'", me, to).toArray()[0])
          return j({ error: 'acl denies file to ' + to }, 403);
        const ext = name.includes('.') ? name.split('.').pop().toLowerCase() : '';
        if (!ALLOWED_EXT.includes(ext)) return j({ error: 'extension not allowed: ' + ext }, 415);
        if (size <= 0 || size > MAX_FILE) return j({ error: 'size out of range (max 10MB)' }, 413);
        if (!/^[a-f0-9]{64}$/.test(sha)) return j({ error: 'sha256 required' }, 400);
        const id = 'f' + crypto.randomUUID().replace(/-/g, '').slice(0, 16);
        this.sql.exec("INSERT INTO files(id, owner, to_agent, name, size, sha256, status, r2_key, created_at, expires_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
          id, me, to, name, size, sha, 'pending', 'relay/' + id, Date.now(), Date.now() + 14 * 86400 * 1000);
        return j({ ok: true, id, upload_url: '/v2/files/' + id + '/content' });
      }

      const fm = path.match(/^\/v2\/files\/([a-z0-9]+)\/content$/);
      if (fm) {
        const f = this.sql.exec("SELECT * FROM files WHERE id=?", fm[1]).toArray()[0];
        if (!f) return j({ error: 'not found' }, 404);
        if (method === 'PUT') {
          if (me !== f.owner) return j({ error: 'forbidden' }, 403);
          if (f.status !== 'pending') return j({ error: 'already uploaded' }, 409);
          const buf = await request.arrayBuffer();
          if (buf.byteLength !== f.size) return j({ error: 'size mismatch' }, 400);
          const head = new Uint8Array(buf.slice(0, 256));
          const headTxt = new TextDecoder().decode(head).toLowerCase();
          if (headTxt.startsWith('<!doctype html') || headTxt.startsWith('<svg') || headTxt.startsWith('#!') || headTxt.startsWith('<?php'))
            return j({ error: 'content type not allowed' }, 415);
          if (head[0] === 0x7f && head[1] === 0x45) return j({ error: 'ELF executable not allowed' }, 415);
          if (head[0] === 0x4d && head[1] === 0x5a) return j({ error: 'PE executable not allowed' }, 415);
          const d = await crypto.subtle.digest('SHA-256', buf);
          const actual = [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join('');
          if (actual !== f.sha256) { await this.env.RELAY_FILES.delete(f.r2_key); return j({ error: 'sha256 mismatch' }, 400); }
          await this.env.RELAY_FILES.put(f.r2_key, buf);
          this.sql.exec("UPDATE files SET status='ready' WHERE id=?", f.id);
          return j({ ok: true, id: f.id });
        }
        if (method === 'GET') {
          if (me !== f.to_agent && me !== f.owner && !isAdmin) return j({ error: 'forbidden' }, 403);
          if (f.status !== 'ready') return j({ error: 'not ready' }, 409);
          const obj = await this.env.RELAY_FILES.get(f.r2_key);
          if (!obj) return j({ error: 'gone' }, 410);
          return new Response(obj.body, { headers: {
            'Content-Type': 'application/octet-stream', 'Content-Disposition': 'attachment; filename="' + f.name.replace(/"/g, '') + '"',
            'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store' } });
        }
      }
      if (path === '/v2/files' && method === 'GET') {
        const rows = this.sql.exec("SELECT id, owner, to_agent, name, size, status, created_at, expires_at FROM files WHERE to_agent=? OR owner=? ORDER BY created_at DESC LIMIT 100", me, me).toArray();
        return j({ files: rows });
      }

      return j({ error: 'not found' }, 404);
    } catch (e) {
      return j({ error: 'internal', detail: String(e).slice(0, 200) }, 500);
    }
  }

  async alarm() {
    const now = Date.now();
    const expired = this.sql.exec("SELECT id, r2_key FROM files WHERE expires_at < ? OR (status='pending' AND created_at < ?)", now, now - 3600 * 1000).toArray();
    for (const f of expired) {
      await this.env.RELAY_FILES.delete(f.r2_key);
      this.sql.exec("DELETE FROM files WHERE id=?", f.id);
    }
    this.sql.exec("DELETE FROM counters WHERE window < ?", Math.floor((now - 25 * 3600 * 1000) / 60000));
    this.state.storage.setAlarm(now + 3600 * 1000);
  }
}

import PAGE_HTML from './page.html';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/' && request.method === 'GET')
      return new Response(PAGE_HTML, { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });

    if (url.pathname.startsWith('/v2/')) {
      const id = env.RELAY_DO.idFromName('hub');
      return env.RELAY_DO.get(id).fetch(request);
    }

    if (url.pathname === '/send' || url.pathname === '/messages')
      return j({ error: 'v1 retired — use /v2 endpoints (keys rotated)' }, 410);

    return j({ error: 'not found' }, 404);
  },
};
