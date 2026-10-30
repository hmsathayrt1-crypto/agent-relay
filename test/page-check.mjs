// Runs the real inline script from src/page.html against a small fake DOM, with hostile data.
// Not a browser: it proves the script's behaviour, not CSP enforcement or layout.
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const html = readFileSync(new URL('../src/page.html', import.meta.url), 'utf8');
const script = html.match(/<script nonce="__CSP_NONCE__">([\s\S]*)<\/script>/)[1];
const XSS = '<img src=x onerror="globalThis.pwned=1"><script>globalThis.pwned=2</script>';
const SHA = 'a'.repeat(64);
const PARAMS = JSON.stringify({ repo: 'acme/widgets', username: 'octocat', permission: 'pull', note: XSS });

class El {
  constructor(tag) { this.tag = tag; this.children = []; this.handlers = {}; this.textContent = ''; this.value = ''; this.hidden = false; this.className = ''; }
  set innerHTML(_) { throw new Error('innerHTML must not be used'); }
  appendChild(c) { this.children.push(c); return c; }
  replaceChildren(...c) { this.children = c; }
  addEventListener(n, f) { this.handlers[n] = f; }
  walk() { return [this, ...this.children.flatMap(c => c.walk())]; }
}
const byId = Object.fromEntries(['key', 'login', 'approvals', 'apl', 'log', 'to', 'txt', 'send'].map(id => [id, new El('div')]));
const calls = [];
const respond = (data, status = 200) => ({ status, ok: status < 400, json: async () => data });
let approved = false;
const fetchStub = async (url, opts = {}) => {
  calls.push({ url, method: opts.method || 'GET', body: opts.body });
  if (url.startsWith('/v2/inbox')) return respond({ agent: '__admin__', messages: [{ seq: 1, from_agent: XSS, to_agent: '__all__', body: XSS, ts: 1 }], next_after: 1, suggested_poll_ms: 5000 });
  if (url.startsWith('/v2/agents')) return respond({ agents: [{ name: 'alice' }] });
  if (url.startsWith('/v2/tasks?')) return respond({ tasks: approved ? [] : [{ id: 't1', type: 'github.invite', from_agent: XSS, to_agent: 'bot', params_json: PARAMS, params_sha256: SHA }] });
  if (url.endsWith('/approve')) { approved = true; return respond({ ok: true }); }
  return respond({ ok: true });
};
const ctx = vm.createContext({
  document: { getElementById: id => byId[id], createElement: t => new El(t) },
  sessionStorage: { getItem: () => 'admin-key', setItem() {} },
  fetch: fetchStub, confirm: () => true, setTimeout: () => 0, clearTimeout() {},
  JSON, Date, encodeURIComponent, console,
});
vm.runInContext(script, ctx);
await new Promise(r => setTimeout(r, 50));

let failed = 0;
const check = (name, cond) => { console.log((cond ? '  ✓ ' : '  ✗ ') + name); if (!cond) failed++; };
const log = byId.log.walk();
const panel = byId.apl.walk();
check('hostile message body stays literal text', log.some(e => e.textContent === XSS));
check('hostile payload creates no element', ![...log, ...panel].some(e => ['img', 'script'].includes(e.tag)));
check('hostile payload never executes', ctx.pwned === undefined);
check('approval panel opens for admin', byId.approvals.hidden === false && byId.apl.children.length === 1);
check('approver sees the stored params', panel.some(e => e.tag === 'pre' && JSON.parse(e.textContent).repo === 'acme/widgets'));
check('approver sees the full hash', panel.some(e => e.textContent === 'sha256: ' + SHA));
panel.find(e => e.className === 'ok').handlers.click();
await new Promise(r => setTimeout(r, 50));
const call = calls.find(c => c.url === '/v2/tasks/t1/approve');
check('approve posts the stored hash', call && call.method === 'POST' && JSON.parse(call.body).params_sha256 === SHA);
check('panel closes once nothing is pending', byId.approvals.hidden === true);
process.exit(failed ? 1 : 0);
