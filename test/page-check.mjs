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
const byId = Object.fromEntries(['key', 'login', 'approvals', 'apl', 'log', 'to', 'txt', 'send',
  'tab-chat', 'tab-wiki', 'chat', 'wiki', 'wbar', 'wkind', 'wq', 'wnew', 'wmsg', 'wlist', 'wview', 'wback', 'wedit', 'wtitle', 'wtags', 'wmeta', 'wbody', 'whist',
  'wform', 'fslug', 'ftitle', 'fkind', 'ftags', 'fbody', 'fsave', 'fcancel'].map(id => [id, new El('div')]));
byId.wiki.hidden = true;
const calls = [];
const respond = (data, status = 200) => ({ status, ok: status < 400, json: async () => data });
let approved = false;
const WIKI_PAGE = { slug: 'evil', title: XSS, kind: 'note', body: XSS, tags: [XSS], version: 2, updated_by: XSS, updated_at: 1 };
let wikiSaved = false;
const fetchStub = async (url, opts = {}) => {
  calls.push({ url, method: opts.method || 'GET', body: opts.body });
  if (url.startsWith('/v2/wiki?')) return respond({ pages: [{ slug: 'evil', title: XSS, kind: 'note', tags: [XSS], version: 2 }], quota: {} });
  if (url === '/v2/wiki/taken') return respond(WIKI_PAGE);
  if (url === '/v2/wiki/fresh' && opts.method !== 'PUT') return wikiSaved ? respond({ ...WIKI_PAGE, slug: 'fresh' }) : respond({ error: 'not found' }, 404);
  if (url === '/v2/wiki/fresh') { wikiSaved = true; return respond({ ok: true, version: 1 }); }
  if (url === '/v2/wiki/fresh/history') return respond({ slug: 'fresh', current_version: 1, total: 0, versions: [] });
  if (url === '/v2/wiki/secret') return opts.method === 'PUT' ? respond({ error: 'x' }, 422) : respond({ error: 'not found' }, 404);
  if (url === '/v2/wiki/evil/history') return respond({ slug: 'evil', current_version: 2, total: 1, versions: [{ version: 1, updated_by: XSS, updated_at: 1, size: 9, deleted: false }] });
  if (url === '/v2/wiki/evil/history/1') return respond({ slug: 'evil', version: 1, body: 'old ' + XSS, updated_by: XSS, updated_at: 1 });
  if (url === '/v2/wiki/evil' && opts.method === 'PUT') return respond({ ok: true, version: 3 });
  if (url === '/v2/wiki/evil') return respond(WIKI_PAGE);
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
const used = [...new Set([...script.matchAll(/\$\("([\w-]+)"\)/g)].map(m => m[1]))];
check('every id the script uses exists in the markup', used.every(id => html.includes('id="' + id + '"')));
check('the [hidden] attribute beats display:flex', html.includes('[hidden]{display:none!important}'));
check('no inline style attribute, which the CSP would block', !/\sstyle=/.test(html));
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

const tick = () => new Promise(r => setTimeout(r, 30));
const fill = (o) => { for (const [k, v] of Object.entries(o)) byId[k].value = v; };
const clickFirst = (root, cls) => root.walk().find(e => e.className === cls).handlers.click();
check('chat is the default tab', byId.chat.hidden === false && byId.wiki.hidden === true);
byId['tab-wiki'].handlers.click(); await tick();
check('wiki tab hides the chat and lists pages', byId.chat.hidden === true && byId.wiki.hidden === false && byId.wlist.children.length === 1);
check('hostile title stays literal in the list', byId.wlist.walk().some(e => e.textContent === XSS));
fill({ wq: 'مهام & x', wkind: 'skill' }); byId.wq.handlers.keydown({ key: 'Enter' }); await tick();
check('search and kind filter are URL-encoded', calls.at(-1).url === '/v2/wiki?kind=skill&q=' + encodeURIComponent('مهام & x'));
clickFirst(byId.wlist, 'wi'); await tick();
check('opening a page shows it as text', byId.wview.hidden === false && byId.wlist.hidden === true && byId.wbody.textContent === XSS && byId.wtitle.textContent === XSS);
check('admin sees the version count', byId.wtags.walk().some(e => e.className === 'chip badge' && e.textContent === '2 نسخة'));
const old = byId.whist.children[1];
check('admin sees history entries', byId.whist.hidden === false && byId.whist.children.length === 2);
old.handlers.click(); await tick();
check('old version loads as text', byId.wbody.textContent === 'old ' + XSS);
byId.wedit.handlers.click();
check('editing starts from the current version', byId.wform.hidden === false && byId.fbody.value === XSS && byId.fslug.disabled === true);
fill({ fbody: 'edited', ftags: ' A , b,, ' }); byId.fsave.handlers.click(); await tick();
const put = calls.findLast(c => c.method === 'PUT');
check('save sends PUT with the edited text', put.url === '/v2/wiki/evil' && JSON.parse(put.body).body === 'edited' && JSON.parse(put.body).tags.join() === 'A,b');
const puts = () => calls.filter(c => c.method === 'PUT').length;
byId.wnew.handlers.click(); const before = puts();
fill({ fslug: 'taken', ftitle: 't', fbody: 'b' }); byId.fsave.handlers.click(); await tick();
check('new page refuses a slug already in use', puts() === before && byId.wmsg.textContent !== '');
fill({ fslug: 'secret', ftitle: 't', fbody: 'b' }); byId.fsave.handlers.click(); await tick();
check('server refusal is shown and the form stays open', byId.wform.hidden === false && byId.wmsg.textContent !== '');
fill({ fslug: 'fresh', ftitle: 't', fbody: 'b', fkind: 'skill' }); byId.fsave.handlers.click(); await tick();
const made = calls.findLast(c => c.method === 'PUT');
check('new page is created with slug, title and kind', made.url === '/v2/wiki/fresh' && JSON.parse(made.body).kind === 'skill' && byId.wview.hidden === false);
const everything = Object.values(byId).flatMap(e => e.walk());
check('hostile wiki data creates no element', !everything.some(e => ['img', 'script'].includes(e.tag)));
check('hostile wiki data never executes', ctx.pwned === undefined);
byId['tab-chat'].handlers.click();
check('chat tab comes back', byId.chat.hidden === false && byId.wiki.hidden === true);
process.exit(failed ? 1 : 0);
