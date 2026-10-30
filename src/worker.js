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
const MAX_JSON = 100 * 1024;
const PAGE_RATE_MAX = 60;
// \b on sk- matters: without it ordinary words like "task-management-workflow" match.
const SECRET_PATTERNS = [/gh[pousr]_[A-Za-z0-9]{20,}/, /github_pat_[A-Za-z0-9_]{20,}/, /\bsk-[A-Za-z0-9-_]{16,}/, /AKIA[0-9A-Z]{16}/, /ark_[a-f0-9]{32}/, /inv_[a-f0-9]{64}/, /-----BEGIN [A-Z ]*PRIVATE KEY-----/];

const j = (data, status = 200, extra = {}) =>
  new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...extra } });

const sha256hex = async (s) => {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join('');
};

// Reads at most max bytes even when Content-Length is missing or wrong (chunked uploads). Returns null if over.
async function readCapped(request, max) {
  if (Number(request.headers.get('Content-Length') || 0) > max || !request.body) return request.body ? null : new Uint8Array(0);
  const chunks = [];
  let total = 0;
  const reader = request.body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) { await reader.cancel(); return null; }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) { out.set(c, at); at += c.byteLength; }
  return out;
}

// Returns the parsed object, or a Response to send back.
async function readJson(request) {
  const raw = await readCapped(request, MAX_JSON);
  if (raw === null) return j({ error: 'request body too large', max: MAX_JSON }, 413);
  if (!raw.byteLength) return {};
  try {
    const v = JSON.parse(new TextDecoder().decode(raw));
    return v && typeof v === 'object' && !Array.isArray(v) ? v : j({ error: 'body must be a JSON object' }, 400);
  } catch (e) { return j({ error: 'invalid JSON' }, 400); }
}

const NAME_RE = /^[a-z0-9_-]{1,32}$/;
const TYPE_RE = /^[a-z0-9_.-]{1,64}$/;
const LEASE_MS = 5 * 60 * 1000;
const MAX_TASK_DEPTH = 2;
const MAX_TASK_JSON = 32 * 1024;
const TASK_COLS = "id, type, from_agent, to_agent, params_json, params_sha256, status, parent_task_id, depth, attempts, max_attempts, risk, result_json, error, approved_at, created_at, expires_at";
// `admin` is left out on purpose: an agent-initiated invite should never grant repo ownership.
const GITHUB_INVITE_SCHEMA = {
  type: 'object', additionalProperties: false, required: ['repo', 'username', 'permission'],
  properties: {
    repo: { type: 'string', maxLength: 140, pattern: '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' },
    username: { type: 'string', pattern: '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$' },
    permission: { type: 'string', enum: ['pull', 'triage', 'push', 'maintain'] },
  },
};

const hasSecret = (s) => SECRET_PATTERNS.some(p => p.test(s));
const aclKindOk = (k) => ['msg', 'file', 'broadcast'].includes(k) || /^task:[a-z0-9_.-]{1,64}$/.test(String(k));

// JSON-Schema subset. Errors name paths, never values, so they are safe to return and store.
function validate(schema, v, path = '$', errs = []) {
  const t = Array.isArray(v) ? 'array' : v === null ? 'null' : Number.isInteger(v) ? 'integer' : typeof v;
  if (schema.type && schema.type !== t && !(schema.type === 'number' && t === 'integer')) { errs.push(path + ': expected ' + schema.type); return errs; }
  if (schema.enum && !schema.enum.includes(v)) errs.push(path + ': not an allowed value');
  if (t === 'string') {
    if (schema.minLength != null && v.length < schema.minLength) errs.push(path + ': too short');
    if (schema.maxLength != null && v.length > schema.maxLength) errs.push(path + ': too long');
    if (schema.pattern && !new RegExp(schema.pattern).test(v)) errs.push(path + ': bad format');
  }
  if (t === 'number' || t === 'integer') {
    if (schema.minimum != null && v < schema.minimum) errs.push(path + ': below minimum');
    if (schema.maximum != null && v > schema.maximum) errs.push(path + ': above maximum');
  }
  if (t === 'array') {
    if (schema.maxItems != null && v.length > schema.maxItems) errs.push(path + ': too many items');
    if (schema.items) v.forEach((x, i) => validate(schema.items, x, path + '[' + i + ']', errs));
  }
  if (t === 'object') {
    for (const k of schema.required || []) if (!Object.hasOwn(v, k)) errs.push(path + '.' + k + ': required');
    for (const [k, x] of Object.entries(v)) {
      if (schema.properties && Object.hasOwn(schema.properties, k)) validate(schema.properties[k], x, path + '.' + k, errs);
      else if (schema.additionalProperties === false) errs.push(path + '.' + k + ': unknown property');
    }
  }
  return errs;
}

function schemaProblem(s, top = true) {
  if (!s || typeof s !== 'object' || Array.isArray(s)) return 'schema must be an object';
  if (top && s.type !== 'object') return 'top-level schema type must be object';
  if (s.pattern != null) { try { new RegExp(s.pattern); } catch (e) { return 'invalid pattern'; } }
  for (const sub of [...Object.values(s.properties || {}), ...(s.items ? [s.items] : [])]) {
    const p = schemaProblem(sub, false);
    if (p) return p;
  }
  return null;
}

export class RelayHub {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.sql = state.storage.sql;
    this.leaseMs = Number(env.LEASE_MS) || LEASE_MS;
    state.blockConcurrencyWhile(async () => {
      this._migrate();
      if (await state.storage.getAlarm() === null) await state.storage.setAlarm(Date.now() + 60_000);
    });
  }

  _migrate() {
    let v = null;
    try { v = this.sql.exec("SELECT value FROM meta WHERE key='schema_version'").toArray()[0]; } catch (e) {}
    if (!v) this._migrateV1();
    if (!v || Number(v.value) < 2) this.state.storage.transactionSync(() => this._migrateV2());
  }

  _migrateV2() {
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS task_types(name TEXT PRIMARY KEY, executor TEXT, schema_json TEXT NOT NULL, risk TEXT NOT NULL DEFAULT 'low', max_attempts INTEGER NOT NULL DEFAULT 3, ttl_s INTEGER NOT NULL DEFAULT 86400);
      CREATE TABLE IF NOT EXISTS tasks(id TEXT PRIMARY KEY, type TEXT NOT NULL, from_agent TEXT NOT NULL, to_agent TEXT NOT NULL, params_json TEXT NOT NULL, params_sha256 TEXT NOT NULL, status TEXT NOT NULL, parent_task_id TEXT, depth INTEGER NOT NULL DEFAULT 0, lease_token TEXT, lease_until INTEGER, attempts INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL, risk TEXT NOT NULL, result_json TEXT, error TEXT, approved_sha256 TEXT, approved_at INTEGER, idem_key TEXT, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, UNIQUE(from_agent, idem_key));
      CREATE INDEX IF NOT EXISTS tasks_status ON tasks(status, lease_until);
      CREATE INDEX IF NOT EXISTS tasks_to ON tasks(to_agent, status);
      CREATE TRIGGER IF NOT EXISTS tasks_immutable BEFORE UPDATE OF params_json, params_sha256, type, from_agent, to_agent, parent_task_id, depth ON tasks
        BEGIN SELECT RAISE(ABORT, 'task params are immutable'); END;
      CREATE TABLE IF NOT EXISTS invites(code_sha256 TEXT PRIMARY KEY, agent_name TEXT NOT NULL, acl_template TEXT NOT NULL DEFAULT '[]', expires_at INTEGER NOT NULL, redeemed_at INTEGER);
      ALTER TABLE counters ADD COLUMN expires_at INTEGER;
      ALTER TABLE messages ADD COLUMN redacted_at INTEGER;
    `);
    this.sql.exec("INSERT OR IGNORE INTO task_types(name, executor, schema_json, risk, max_attempts, ttl_s) VALUES('github.invite', 'github-bot', ?, 'high', 1, 86400)", JSON.stringify(GITHUB_INVITE_SCHEMA));
    this.sql.exec("UPDATE meta SET value='2' WHERE key='schema_version'");
  }

  _migrateV1() {
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
    const h = await sha256hex(token);
    if (this.env.ADMIN_KEY && h === await sha256hex(this.env.ADMIN_KEY)) return '__admin__';
    const r = this.sql.exec("SELECT name, status FROM agents WHERE key_hash=? AND status='active'", h).toArray()[0];
    return r ? r.name : null;
  }

  _bump(scope, windowMs, max) {
    const w = Math.floor(Date.now() / windowMs);
    const cur = this.sql.exec("SELECT n FROM counters WHERE scope=? AND window=?", scope, w).toArray()[0];
    const n = cur ? cur.n : 0;
    if (n >= max) return false;
    this.sql.exec("INSERT INTO counters(scope,window,n,expires_at) VALUES(?,?,1,?) ON CONFLICT(scope,window) DO UPDATE SET n=n+1", scope, w, (w + 1) * windowMs);
    return true;
  }

  // Invite redemption is the one unauthenticated write, so it is throttled per IP and uses one generic failure.
  async _redeem(request) {
    const ip = request.headers.get('CF-Connecting-IP') || 'local';
    if (!this._bump('join-ip:' + ip, 60 * 1000, 10)) return j({ error: 'rate limit: too many join attempts' }, 429);
    const body = await readJson(request);
    if (body instanceof Response) return body;
    const denied = () => j({ error: 'invalid or expired invite' }, 401);
    if (!body.invite_code) return denied();
    const code_sha256 = await sha256hex(String(body.invite_code));
    const key = 'ark_' + crypto.randomUUID().replace(/-/g, '');
    const key_hash = await sha256hex(key);
    const now = Date.now();
    const inv = this.sql.exec("SELECT agent_name, acl_template FROM invites WHERE code_sha256=? AND redeemed_at IS NULL AND expires_at>?", code_sha256, now).toArray()[0];
    if (!inv) return denied();
    if (this.sql.exec("SELECT 1 FROM agents WHERE name=?", inv.agent_name).toArray()[0]) return j({ error: 'agent exists' }, 409);
    return this.state.storage.transactionSync(() => {
      if (!this.sql.exec("UPDATE invites SET redeemed_at=? WHERE code_sha256=? AND redeemed_at IS NULL RETURNING code_sha256", now, code_sha256).toArray()[0]) return denied();
      this.sql.exec("INSERT INTO agents(name, key_hash, created_at) VALUES(?,?,?)", inv.agent_name, key_hash, now);
      for (const a of JSON.parse(inv.acl_template)) this.sql.exec("INSERT OR IGNORE INTO acl(from_agent,to_agent,kind) VALUES(?,?,?)", a.from, a.to, a.kind);
      return j({ ok: true, agent: inv.agent_name, key }); // shown ONCE
    });
  }

  async _wakeAt(t) {
    const cur = await this.state.storage.getAlarm();
    if (cur === null || cur > t) await this.state.storage.setAlarm(t);
  }

  _closeTask(id, status, error) {
    this.sql.exec("UPDATE tasks SET status=?, error=?, lease_until=NULL WHERE id=? AND status IN ('awaiting_approval','pending','leased')", status, error, id);
  }

  _sweepTasks(now) {
    for (const t of this.sql.exec("SELECT id, attempts, max_attempts, expires_at FROM tasks WHERE status='leased' AND lease_until<=?", now).toArray()) {
      // max_attempts=1 means not idempotent: the executor may have acted, so never retry and never claim success.
      if (t.max_attempts <= 1) this._closeTask(t.id, 'failed', 'lease_lost_outcome_unknown');
      else if (t.attempts >= t.max_attempts) this._closeTask(t.id, 'dead', 'max_attempts_exhausted');
      else if (t.expires_at <= now) this._closeTask(t.id, 'expired', 'ttl_elapsed');
      else this.sql.exec("UPDATE tasks SET status='pending', lease_token=NULL, lease_until=NULL WHERE id=? AND status='leased'", t.id);
    }
    this.sql.exec("UPDATE tasks SET status='expired', error='ttl_elapsed' WHERE status IN ('awaiting_approval','pending') AND expires_at<=?", now);
  }

  async _tasks(url, path, method, me, isAdmin, body) {
    const now = Date.now();
    if (path === '/v2/task-types' && method === 'GET') return j({ task_types: this.sql.exec("SELECT * FROM task_types ORDER BY name").toArray() });
    if (path === '/v2/task-types' && method === 'POST') {
      if (!isAdmin) return j({ error: 'admin only' }, 403);
      const { name, executor = null, schema, risk = 'low', max_attempts = 3, ttl_s = 86400 } = body;
      if (!TYPE_RE.test(String(name))) return j({ error: 'invalid task type name' }, 400);
      if (executor !== null && !NAME_RE.test(String(executor))) return j({ error: 'invalid executor' }, 400);
      if (!['low', 'medium', 'high'].includes(risk)) return j({ error: 'invalid risk' }, 400);
      if (!Number.isInteger(max_attempts) || max_attempts < 1 || max_attempts > 10) return j({ error: 'max_attempts must be 1-10' }, 400);
      if (!Number.isInteger(ttl_s) || ttl_s < 1 || ttl_s > 30 * 86400) return j({ error: 'ttl_s out of range' }, 400);
      const bad = schemaProblem(schema);
      if (bad) return j({ error: bad }, 400);
      this.sql.exec("INSERT INTO task_types(name, executor, schema_json, risk, max_attempts, ttl_s) VALUES(?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET executor=excluded.executor, schema_json=excluded.schema_json, risk=excluded.risk, max_attempts=excluded.max_attempts, ttl_s=excluded.ttl_s",
        name, executor, JSON.stringify(schema), risk, max_attempts, ttl_s);
      return j({ ok: true, name });
    }
    const tt = path.match(/^\/v2\/task-types\/([a-z0-9_.-]{1,64})$/);
    if (tt && method === 'DELETE') {
      if (!isAdmin) return j({ error: 'admin only' }, 403);
      if (this.sql.exec("SELECT 1 FROM tasks WHERE type=? AND status IN ('awaiting_approval','pending','leased') LIMIT 1", tt[1]).toArray()[0]) return j({ error: 'type has open tasks' }, 409);
      this.sql.exec("DELETE FROM task_types WHERE name=?", tt[1]);
      return j({ ok: true });
    }

    if (path === '/v2/tasks' && method === 'POST') {
      const type = this.sql.exec("SELECT * FROM task_types WHERE name=?", String(body.type || '')).toArray()[0];
      if (!type) return j({ error: 'unknown task type' }, 400);
      if (body.to && type.executor && String(body.to) !== type.executor) return j({ error: 'task type is bound to executor ' + type.executor }, 400);
      const to = type.executor || String(body.to || '');
      if (!NAME_RE.test(to) || !this.sql.exec("SELECT 1 FROM agents WHERE name=? AND status='active'", to).toArray()[0]) return j({ error: 'executor not active: ' + to }, 400);
      if (!isAdmin && !this.sql.exec("SELECT 1 FROM acl WHERE from_agent=? AND to_agent=? AND kind=?", me, to, 'task:' + type.name).toArray()[0])
        return j({ error: 'acl denies ' + me + ' -> ' + to + ' (task:' + type.name + ')' }, 403);
      if (me === to) return j({ error: 'cycle: agent cannot task itself' }, 409);
      const params = body.params;
      if (!params || typeof params !== 'object' || Array.isArray(params)) return j({ error: 'params must be an object' }, 400);
      const errors = validate(JSON.parse(type.schema_json), params);
      if (errors.length) return j({ error: 'params failed schema validation', errors }, 400);
      const params_json = JSON.stringify(params);
      if (params_json.length > MAX_TASK_JSON) return j({ error: 'params too large', max: MAX_TASK_JSON }, 413);
      if (hasSecret(params_json)) return j({ error: 'rejected: looks like a secret — pass a reference instead' }, 422);
      const sha = await sha256hex(params_json);
      const idem = body.idem_key ? String(body.idem_key).slice(0, 100) : null;
      if (idem) {
        const dup = this.sql.exec("SELECT id, status, params_sha256, expires_at FROM tasks WHERE from_agent=? AND idem_key=?", me, idem).toArray()[0];
        if (dup) {
          if (dup.params_sha256 !== sha) return j({ error: 'idem_key reused with different params' }, 409);
          return j({ ok: true, task: { id: dup.id, status: dup.status, params_sha256: sha, expires_at: dup.expires_at }, deduplicated: true });
        }
      }
      let depth = 0, parent = null;
      if (body.parent_task_id) {
        parent = String(body.parent_task_id);
        const chain = [];
        for (let cur = parent; cur && chain.length <= MAX_TASK_DEPTH;) {
          const row = this.sql.exec("SELECT from_agent, to_agent, parent_task_id, depth, status FROM tasks WHERE id=?", cur).toArray()[0];
          if (!row) break;
          chain.push(row);
          cur = row.parent_task_id;
        }
        if (!chain.length) return j({ error: 'parent task not found' }, 400);
        if (chain[0].to_agent !== me) return j({ error: 'only the executor of the parent may spawn a child' }, 403);
        if (chain[0].status !== 'leased') return j({ error: 'parent task is not in progress' }, 409);
        depth = chain[0].depth + 1;
        if (depth > MAX_TASK_DEPTH) return j({ error: 'task chain too deep', max: MAX_TASK_DEPTH }, 422);
        if (chain.some(r => r.from_agent === to || r.to_agent === to)) return j({ error: 'cycle: ' + to + ' is already in this task chain' }, 409);
      }
      if (!isAdmin && !this._bump('task:' + me, 3600 * 1000, 200)) return j({ error: 'rate limit: too many tasks' }, 429);
      const id = 't' + crypto.randomUUID().replace(/-/g, '').slice(0, 24);
      const status = type.risk === 'high' ? 'awaiting_approval' : 'pending';
      const expires_at = now + type.ttl_s * 1000;
      this.sql.exec("INSERT INTO tasks(id, type, from_agent, to_agent, params_json, params_sha256, status, parent_task_id, depth, max_attempts, risk, idem_key, created_at, expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        id, type.name, me, to, params_json, sha, status, parent, depth, type.max_attempts, type.risk, idem, now, expires_at);
      return j({ ok: true, task: { id, status, params_sha256: sha, expires_at } });
    }

    if (path === '/v2/tasks' && method === 'GET') {
      const status = url.searchParams.get('status');
      const filter = status ? " AND status=?" : "";
      const args = status ? [status] : [];
      // Executors do not see a task until it has been approved.
      const rows = isAdmin
        ? this.sql.exec("SELECT " + TASK_COLS + " FROM tasks WHERE 1=1" + filter + " ORDER BY created_at DESC LIMIT 100", ...args).toArray()
        : this.sql.exec("SELECT " + TASK_COLS + " FROM tasks WHERE (from_agent=? OR (to_agent=? AND status!='awaiting_approval'))" + filter + " ORDER BY created_at DESC LIMIT 100", me, me, ...args).toArray();
      return j({ tasks: rows });
    }

    const tm = path.match(/^\/v2\/tasks\/([a-z0-9]+)(?:\/(claim|heartbeat|complete|reject|approve))?$/);
    if (!tm) return null;
    const t = this.sql.exec("SELECT * FROM tasks WHERE id=?", tm[1]).toArray()[0];
    if (!t) return j({ error: 'not found' }, 404);
    const action = tm[2];

    if (!action && method === 'GET') {
      if (!isAdmin && me !== t.from_agent && !(me === t.to_agent && t.status !== 'awaiting_approval')) return j({ error: 'forbidden' }, 403);
      return j({ task: this.sql.exec("SELECT " + TASK_COLS + " FROM tasks WHERE id=?", t.id).toArray()[0] });
    }
    if (!action || method !== 'POST') return null;

    if (action === 'approve') {
      if (!isAdmin) return j({ error: 'admin only' }, 403);
      if (t.status !== 'awaiting_approval') return j({ error: 'task is not awaiting approval', status: t.status }, 409);
      if (t.expires_at <= now) return j({ error: 'task expired' }, 409);
      // The approval binds to the hash the approver was shown, recomputed from the stored params.
      if (String(body.params_sha256 || '') !== t.params_sha256 || await sha256hex(t.params_json) !== t.params_sha256)
        return j({ error: 'params_sha256 does not match stored params' }, 409);
      const r = this.sql.exec("UPDATE tasks SET status='pending', approved_sha256=?, approved_at=? WHERE id=? AND status='awaiting_approval' RETURNING id", t.params_sha256, now, t.id).toArray()[0];
      if (!r) return j({ error: 'task is not awaiting approval' }, 409);
      return j({ ok: true, id: t.id, status: 'pending', params_sha256: t.params_sha256 });
    }

    if (action === 'reject') {
      const reason = String(body.reason || 'rejected').slice(0, 500);
      if (hasSecret(reason)) return j({ error: 'rejected: looks like a secret' }, 422);
      if (t.status === 'leased') {
        if (me !== t.to_agent || String(body.lease_token || '') !== t.lease_token || t.lease_until <= now) return j({ error: 'lease required to reject a task in progress' }, 409);
      } else if (!(isAdmin && t.status === 'awaiting_approval') && !((isAdmin || me === t.to_agent) && t.status === 'pending')) {
        return j({ error: 'cannot reject task in this state', status: t.status }, isAdmin || me === t.to_agent ? 409 : 403);
      }
      this._closeTask(t.id, 'rejected', reason);
      return j({ ok: true, id: t.id, status: 'rejected' });
    }

    if (me !== t.to_agent) return j({ error: 'only the executor may ' + action }, 403);

    if (action === 'claim') {
      if (t.status !== 'pending') return j({ error: 'task is not claimable', status: t.status }, 409);
      if (t.expires_at <= now) return j({ error: 'task expired' }, 409);
      if (t.risk === 'high' && t.approved_sha256 !== t.params_sha256) return j({ error: 'approval missing' }, 409);
      if (await sha256hex(t.params_json) !== t.params_sha256) { this._closeTask(t.id, 'failed', 'params_integrity'); return j({ error: 'params integrity check failed' }, 409); }
      const lease_token = crypto.randomUUID().replace(/-/g, '');
      const lease_until = now + this.leaseMs;
      const r = this.sql.exec("UPDATE tasks SET status='leased', lease_token=?, lease_until=?, attempts=attempts+1 WHERE id=? AND status='pending' AND lease_token IS NULL RETURNING attempts", lease_token, lease_until, t.id).toArray()[0];
      if (!r) return j({ error: 'already claimed' }, 409);
      await this._wakeAt(lease_until);
      return j({ ok: true, lease_token, lease_until, attempt: r.attempts, task: { id: t.id, type: t.type, from: t.from_agent, params: JSON.parse(t.params_json), params_sha256: t.params_sha256, depth: t.depth } });
    }

    const lease = String(body.lease_token || '');
    if (action === 'heartbeat') {
      const lease_until = now + this.leaseMs;
      const r = this.sql.exec("UPDATE tasks SET lease_until=? WHERE id=? AND status='leased' AND lease_token=? AND lease_until>? RETURNING id", lease_until, t.id, lease, now).toArray()[0];
      if (!r) return j({ error: 'lease_lost' }, 409);
      return j({ ok: true, lease_until });
    }

    if (action === 'complete') {
      if (t.status === 'done' && lease && t.lease_token === lease) return j({ ok: true, id: t.id, status: 'done', deduplicated: true });
      const result_json = JSON.stringify(body.result === undefined ? null : body.result);
      if (result_json.length > MAX_TASK_JSON) return j({ error: 'result too large', max: MAX_TASK_JSON }, 413);
      if (hasSecret(result_json)) return j({ error: 'rejected: looks like a secret — pass a reference instead' }, 422);
      const r = this.sql.exec("UPDATE tasks SET status='done', result_json=?, lease_until=NULL WHERE id=? AND status='leased' AND lease_token=? AND lease_until>? RETURNING id", result_json, t.id, lease, now).toArray()[0];
      if (!r) return j({ error: 'lease_lost' }, 409);
      return j({ ok: true, id: t.id, status: 'done' });
    }
    return null;
  }

  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const token = (request.headers.get('Authorization') || '').replace('Bearer ', '');
    if (path === '/v2/join' && method === 'POST' && !token) return this._redeem(request);
    const me = await this._agentByToken(token);
    if (!me) return j({ error: 'unauthorized' }, 401);
    this.sql.exec("UPDATE agents SET last_seen=? WHERE name=?", Date.now(), me);
    const isAdmin = me === '__admin__';
    let body = {};
    if ((method === 'POST' || method === 'PUT') && !path.endsWith('/content')) {
      body = await readJson(request);
      if (body instanceof Response) return body;
    }

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
      if (path === '/v2/invites' && method === 'POST') {
        if (!isAdmin) return j({ error: 'admin only' }, 403);
        const name = String(body.agent || '').trim().toLowerCase();
        if (!NAME_RE.test(name) || name === '__admin__' || name === '__all__') return j({ error: 'invalid agent name' }, 400);
        if (this.sql.exec("SELECT 1 FROM agents WHERE name=?", name).toArray()[0]) return j({ error: 'agent exists' }, 409);
        const template = body.acl_template === undefined ? [] : body.acl_template;
        if (!Array.isArray(template) || template.length > 50) return j({ error: 'acl_template must be a list' }, 400);
        for (const a of template) {
          if (!a || !NAME_RE.test(String(a.from)) || !NAME_RE.test(String(a.to)) || !aclKindOk(a.kind) || (a.from !== name && a.to !== name))
            return j({ error: 'each acl_template entry needs from, to, kind and must involve ' + name }, 400);
        }
        const ttl = body.ttl_s === undefined ? 3600 : Number(body.ttl_s);
        if (!Number.isInteger(ttl) || ttl < 1 || ttl > 3600) return j({ error: 'ttl_s must be 1-3600' }, 400);
        const code = 'inv_' + crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, '');
        const expires_at = Date.now() + ttl * 1000;
        const acl_template = JSON.stringify(template.map(a => ({ from: a.from, to: a.to, kind: a.kind })));
        this.sql.exec("INSERT INTO invites(code_sha256, agent_name, acl_template, expires_at) VALUES(?,?,?,?)", await sha256hex(code), name, acl_template, expires_at);
        return j({ ok: true, agent: name, invite_code: code, expires_at }); // shown ONCE
      }
      if (path === '/v2/revoke' && isAdmin && method === 'POST') {
        this.sql.exec("UPDATE agents SET status='revoked', revoked_at=? WHERE name=?", Date.now(), String(body.agent || ''));
        return j({ ok: true });
      }
      if (path === '/v2/acl' && isAdmin && method === 'POST') {
        const { from, to, kind, allow } = body;
        if (!NAME_RE.test(String(from)) || !NAME_RE.test(String(to)) || !aclKindOk(kind))
          return j({ error: 'invalid acl args' }, 400);
        if (allow === false) this.sql.exec("DELETE FROM acl WHERE from_agent=? AND to_agent=? AND kind=?", from, to, kind);
        else this.sql.exec("INSERT OR IGNORE INTO acl(from_agent,to_agent,kind) VALUES(?,?,?)", from, to, kind);
        return j({ ok: true });
      }
      if (path === '/v2/acl' && isAdmin && method === 'GET') {
        return j({ acl: this.sql.exec("SELECT from_agent, to_agent, kind FROM acl ORDER BY from_agent, to_agent, kind").toArray() });
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
        if (hasSecret(text) || (this.env.ADMIN_KEY && text.includes(this.env.ADMIN_KEY))) return j({ error: 'rejected: looks like a secret — pass a reference/file instead' }, 422);

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
        // Before the rate limits: a retry of a message that already landed must not burn quota or hit 429.
        const idem = body.idem_key ? String(body.idem_key).slice(0, 100) : null;
        if (idem) {
          const dup = this.sql.exec("SELECT seq, id, body, redacted_at FROM messages WHERE from_agent=? AND idem_key=?", me, idem).toArray()[0];
          if (dup) {
            if (!dup.redacted_at && dup.body !== text) return j({ error: 'idem_key reused with different content' }, 409);
            return j({ ok: true, msg: { seq: dup.seq, id: dup.id }, deduplicated: true });
          }
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
          if (me !== p.to_agent && me !== p.from_agent && p.to_agent !== '__all__') return j({ error: 'cannot reply to a message you cannot see' }, 403);
          hop = p.hop + 1;
          if (hop > HOP_LIMIT) return j({ error: 'conversation too deep (loop guard)' }, 429);
          thread = thread || p.thread_id || p.id;
        }
        const id = Date.now() + '-' + crypto.randomUUID().slice(0, 8);
        const ts = Date.now();
        if (body.thread_id !== undefined && String(body.thread_id).length > 100) return j({ error: 'thread_id too long' }, 400);
        this.sql.exec("INSERT INTO messages(id, from_agent, to_agent, kind, body, thread_id, reply_to, hop, idem_key, ts) VALUES(?,?,?,?,?,?,?,?,?,?)",
          id, me, toAgent, 'text', text, thread, body.reply_to || null, hop, idem, ts);
        const seq = this.sql.exec("SELECT seq FROM messages WHERE id=?", id).toArray()[0].seq;
        return j({ ok: true, msg: { seq, id, from: me, to: toAgent, ts } });
      }

      if (path === '/v2/redact' && method === 'POST') {
        const m = this.sql.exec("SELECT id, from_agent FROM messages WHERE id=?", String(body.id || '')).toArray()[0];
        if (!m) return j({ error: 'not found' }, 404);
        if (!isAdmin && m.from_agent !== me) return j({ error: 'only the sender or admin may redact' }, 403);
        this.sql.exec("UPDATE messages SET body='redacted', redacted_at=COALESCE(redacted_at, ?) WHERE id=?", Date.now(), m.id);
        return j({ ok: true, id: m.id, redacted: true });
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
        if (m.to_agent === '__all__') {
          const recipients = this.sql.exec("SELECT a.name AS agent, COALESCE(c.delivered_seq,0) >= ? AS delivered, COALESCE(c.acked_seq,0) >= ? AS read FROM agents a LEFT JOIN cursors c ON c.agent=a.name WHERE a.status='active' AND a.name != ? ORDER BY a.name", m.seq, m.seq, me).toArray();
          return j({ id, to: m.to_agent, seq: m.seq, recipients: recipients.map(r => ({ agent: r.agent, delivered: !!r.delivered, read: !!r.read })) });
        }
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
          const raw = await readCapped(request, f.size);
          if (raw === null) return j({ error: 'file larger than declared size' }, 413);
          const buf = raw.buffer;
          if (buf.byteLength !== f.size) return j({ error: 'size mismatch' }, 400);
          const head = new Uint8Array(buf.slice(0, 256));
          const headTxt = new TextDecoder().decode(head).trimStart().toLowerCase();
          if (['<!doctype html', '<html', '<script', '<svg', '#!', '<?php'].some(s => headTxt.startsWith(s)))
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
            'Content-Type': 'application/octet-stream', 'Content-Disposition': "attachment; filename*=UTF-8''" + encodeURIComponent(f.name),
            'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store' } });
        }
      }
      if (path === '/v2/files' && method === 'GET') {
        const rows = this.sql.exec("SELECT id, owner, to_agent, name, size, status, created_at, expires_at FROM files WHERE to_agent=? OR owner=? ORDER BY created_at DESC LIMIT 100", me, me).toArray();
        return j({ files: rows });
      }

      if (path === '/v2/task-types' || path.startsWith('/v2/task-types/') || path === '/v2/tasks' || path.startsWith('/v2/tasks/')) {
        const res = await this._tasks(url, path, method, me, isAdmin, body);
        if (res) return res;
      }

      return j({ error: 'not found' }, 404);
    } catch (e) {
      // Never log the request or the error message: either could carry message content.
      console.error('internal error', method, path.split('/').slice(0, 3).join('/'), e && e.name);
      return j({ error: 'internal' }, 500);
    }
  }

  async alarm() {
    const now = Date.now();
    this._sweepTasks(now);
    const expired = this.sql.exec("SELECT id, r2_key FROM files WHERE expires_at < ? OR (status='pending' AND created_at < ?)", now, now - 3600 * 1000).toArray();
    for (const f of expired) {
      await this.env.RELAY_FILES.delete(f.r2_key);
      this.sql.exec("DELETE FROM files WHERE id=?", f.id);
    }
    this.sql.exec("DELETE FROM counters WHERE expires_at IS NULL OR expires_at < ?", now);
    this.sql.exec("DELETE FROM invites WHERE expires_at < ?", now - 7 * 86400 * 1000);
    const next = this.sql.exec("SELECT MIN(lease_until) AS m FROM tasks WHERE status='leased'").toArray()[0].m;
    await this.state.storage.setAlarm(Math.min(now + 3600 * 1000, next ? Math.max(next, now + 1000) : Infinity));
  }
}

import PAGE_HTML from './page.html';

// Best effort: per-isolate, so it dampens floods of the public page rather than enforcing an exact quota.
const pageHits = new Map();
function pageAllowed(ip) {
  const minute = Math.floor(Date.now() / 60000);
  if (pageHits.size > 5000) pageHits.clear();
  const h = pageHits.get(ip);
  if (!h || h.minute !== minute) { pageHits.set(ip, { minute, n: 1 }); return true; }
  return ++h.n <= PAGE_RATE_MAX;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/' && request.method === 'GET') {
      if (!pageAllowed(request.headers.get('CF-Connecting-IP') || 'local')) return new Response('rate limited', { status: 429, headers: { 'Retry-After': '60' } });
      const nonce = crypto.randomUUID().replace(/-/g, '');
      return new Response(PAGE_HTML.replaceAll('__CSP_NONCE__', nonce), { headers: {
        'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store',
        'Content-Security-Policy': "default-src 'none'; script-src 'nonce-" + nonce + "'; style-src 'nonce-" + nonce + "'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' } });
    }

    if (url.pathname.startsWith('/v2/')) {
      // Reject before waking the Durable Object. The DO re-checks actual bytes for chunked bodies.
      const limit = url.pathname.endsWith('/content') ? MAX_FILE : MAX_JSON;
      if (Number(request.headers.get('Content-Length') || 0) > limit) return j({ error: 'request body too large', max: limit }, 413);
      const id = env.RELAY_DO.idFromName('hub');
      return env.RELAY_DO.get(id).fetch(request);
    }

    if (url.pathname === '/send' || url.pathname === '/messages')
      return j({ error: 'v1 retired — use /v2 endpoints (keys rotated)' }, 410);

    return j({ error: 'not found' }, 404);
  },
};
