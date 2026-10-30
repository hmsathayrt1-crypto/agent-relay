// Parses src/page.html in jsdom and runs its real script against a fake server, with hostile data.
// Not a browser: it proves markup and behaviour, not CSP enforcement or layout.
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

let jsdom;
try { jsdom = createRequire(import.meta.url)('jsdom'); } catch (e) { console.error('jsdom is missing: run npm install'); process.exit(1); }

const html = readFileSync(new URL('../src/page.html', import.meta.url), 'utf8');
const script = html.match(/<script nonce="__CSP_NONCE__">([\s\S]*)<\/script>/)[1];
const XSS = '<img src=x onerror="globalThis.pwned=1"><script>globalThis.pwned=2</script>';
const SHA = 'a'.repeat(64);
const PARAMS = JSON.stringify({ repo: 'acme/widgets', username: 'octocat', permission: 'pull', note: XSS });
const FUTURE = Date.now() + 3600e3;
const ADMIN_ME = { agent: '__admin__', is_admin: true, peers: ['alice', 'bob'], can_broadcast: true, can_write_context: true };
const AGENT_ME = { agent: 'alice', is_admin: false, peers: ['bob'], can_broadcast: false, can_write_context: false };
const PAGE = { slug: 'evil', title: XSS, kind: 'note', body: XSS, tags: [XSS], version: 2, updated_by: XSS, updated_at: 1700000000000 };
const task = (id, extra = {}) => ({ id, type: 'github.invite', from_agent: XSS, to_agent: 'bot', risk: 'high', params_json: PARAMS, params_sha256: SHA, expires_at: FUTURE, ...extra });

let failed = 0;
const check = (name, cond) => { console.log((cond ? '  ✓ ' : '  ✗ ') + name); if (!cond) failed++; };
const tick = (ms = 30) => new Promise(r => setTimeout(r, ms));
const respond = (data, status = 200) => ({ status, ok: status < 400, json: async () => data });

// over(url, opts) answers first, and anything it leaves undefined goes to the default fake server.
function boot({ key = '', me = ADMIN_ME, over = () => undefined, messages = [], tasks = [] } = {}) {
  const calls = []; const errors = []; const copied = [];
  const server = { messages, tasks };
  const route = async (url, opts = {}) => {
    const method = opts.method || 'GET';
    calls.push({ url, method, body: opts.body ? JSON.parse(opts.body) : undefined, auth: opts.headers && opts.headers.Authorization });
    const o = await over(url, opts);
    if (o !== undefined) return o;
    if (url === '/v2/me') return respond(me);
    if (url.startsWith('/v2/inbox') || url.startsWith('/v2/log')) {
      const after = Number(new URL(url, 'http://x').searchParams.get('after'));
      const rows = server.messages.filter(m => m.seq > after).slice(0, url.startsWith('/v2/log') ? 200 : 100);
      return respond({ agent: me.agent, messages: rows, next_after: rows.length ? rows.at(-1).seq : after, suggested_poll_ms: 5000 });
    }
    if (url.startsWith('/v2/tasks?')) return respond({ tasks: server.tasks });
    if (url.startsWith('/v2/wiki?')) return respond({ pages: [{ ...PAGE }], quota: { pages: 1, bytes: 2048, max_pages: 200, max_bytes: 5242880 } });
    if (url === '/v2/wiki/evil/history') return respond({ slug: 'evil', current_version: 2, total: 1, versions: [{ version: 1, updated_by: XSS, updated_at: 1, size: 9, deleted: false }] });
    if (url === '/v2/wiki/evil/history/1') return respond({ slug: 'evil', version: 1, body: 'old ' + XSS, updated_by: XSS, updated_at: 1 });
    if (url === '/v2/wiki/evil' && method === 'GET') return respond(PAGE);
    if (url.endsWith('/history')) return respond({ slug: 'x', current_version: 1, total: 0, versions: [] });
    if (url.startsWith('/v2/wiki/') && method === 'PUT') return respond({ ok: true, version: 3 });
    if (url.startsWith('/v2/wiki/')) return respond({ ...PAGE, slug: url.split('/').pop(), title: 'made', kind: 'skill', tags: [], version: 1 });
    return respond({ ok: true });
  };
  const virtualConsole = new jsdom.VirtualConsole();
  virtualConsole.on('jsdomError', e => { if (!/stylesheet/i.test(e.message)) errors.push(e.message); });
  const dom = new jsdom.JSDOM(html, {
    url: 'http://relay.test/', runScripts: 'dangerously', pretendToBeVisual: true, virtualConsole,
    beforeParse(w) {
      w.fetch = route;
      if (key) w.sessionStorage.setItem('rk', key);
      w.matchMedia = () => ({ matches: true });
      w.confirm = () => { throw new Error('confirm() must not be used'); };
      Object.defineProperty(w.navigator, 'clipboard', { value: { writeText: async t => { copied.push(t); } } });
      w.addEventListener('error', e => errors.push(e.message));
      w.addEventListener('unhandledrejection', e => errors.push(String(e.reason)));
    },
  });
  const w = dom.window;
  return { w, calls, errors, copied, server, $: id => w.document.getElementById(id), all: sel => [...w.document.querySelectorAll(sel)] };
}
const hostile = (app) => app.all('img, script:not([nonce])').length === 0 && app.w.pwned === undefined;
const enter = (app, id) => app.$(id).dispatchEvent(new app.w.KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
const type = (app, o) => { for (const [id, v] of Object.entries(o)) app.$(id).value = v; };

console.log('static');
check('viewport is set for phones', /<meta name="viewport" content="width=device-width, initial-scale=1/.test(html));
check('color-scheme meta is light', html.includes('<meta name="color-scheme" content="light">'));
check('theme-color meta exists', /<meta name="theme-color" content="#[0-9a-f]{6}">/.test(html));
check('full height uses 100dvh, never 100vh', html.includes('100dvh') && !html.includes('100vh'));
check('RTL Arabic document', html.includes('lang="ar" dir="rtl"'));
check('no backticks in the imported HTML', !html.includes('`'));
const dir = mkdtempSync(join(tmpdir(), 'page-check-'));
let parses = true;
try { writeFileSync(join(dir, 'page.js'), script); execFileSync(process.execPath, ['--check', join(dir, 'page.js')], { stdio: 'pipe' }); } catch (e) { parses = false; }
rmSync(dir, { recursive: true });
check('node --check accepts the script', parses);
check('no markup built from strings', !/innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(/.test(script));
check('no inline style or handler attribute, which the CSP would block', !/\s(style|on[a-z]+)=/.test(html.replace(script, '')));
check('nothing external is loaded', !/https?:\/\/|<link\b|\ssrc=|@import|url\(/.test(html));
check('style and script both carry the nonce', html.includes('<style nonce="__CSP_NONCE__">') && html.includes('<script nonce="__CSP_NONCE__">'));
const used = [...new Set([...script.matchAll(/\$\("([\w-]+)"\)/g)].map(m => m[1]))];
check('every id the script names exists in the markup', used.length > 30 && used.every(id => html.includes('id="' + id + '"')));
check('the [hidden] attribute beats display:flex', html.includes('[hidden]{display:none!important}'));
check('44px touch target is the base size for controls', html.includes('--tap:44px') && /\nbutton\{min-height:var\(--tap\)/.test(html) && /\ninput,select,textarea\{[^}]*min-height:var\(--tap\)/.test(html));
check('tabs are taller than the minimum', /nav button\{[^}]*min-height:50px/.test(html));
check('16px inputs, so iOS does not zoom on focus', /\ninput,select,textarea\{[^}]*font-size:16px/.test(html));

console.log('login');
{
  const app = boot({ over: (url, o) => (o.headers.Authorization === 'Bearer bad' ? respond({ error: 'unauthorized' }, 401) : undefined) });
  await tick();
  check('no key: only the login screen shows', !app.$('login-view').hidden && app.$('app-view').hidden && app.calls.length === 0);
  app.$('login').click(); await tick();
  check('empty key asks for one in Arabic', app.$('login-msg').textContent === 'أدخل المفتاح أولاً.' && app.calls.length === 0);
  type(app, { key: 'bad' }); app.$('login').click(); await tick();
  check('bad key is refused with an Arabic message', !app.$('login-view').hidden && app.$('login-msg').textContent.includes('غير صالح'));
  check('  and it reads no inbox', !app.calls.some(c => c.url.includes('inbox') || c.url.includes('log')));
  check('  and is not stored', app.w.sessionStorage.getItem('rk') === null);
  type(app, { key: 'good' }); enter(app, 'key'); await tick();
  check('good key opens the app with Enter', app.$('login-view').hidden && !app.$('app-view').hidden && app.w.sessionStorage.getItem('rk') === 'good');
  check('  key field is emptied', app.$('key').value === '');
  app.$('logout').click(); await tick();
  check('logout forgets the key and goes back', app.w.sessionStorage.getItem('rk') === null && !app.$('login-view').hidden && app.$('log').children.length === 0);
  check('no script errors', app.errors.length === 0);
  app.w.close();
}

console.log('admin: tabs, chat and approvals');
const msgs = [
  { seq: 1, from_agent: XSS, to_agent: '__all__', body: XSS, ts: Date.now() },
  { seq: 2, from_agent: 'alice', to_agent: 'bob', body: 'between agents', ts: 1700000000000 },
  { seq: 3, from_agent: '__admin__', to_agent: 'bob', body: 'from me', ts: Date.now() },
];
{
  let refuse = 0;
  const app = boot({
    key: 'admin-key', messages: msgs, tasks: [task('t1'), task('stale', { expires_at: 1 })],
    over: (url, o) => {
      if (url === '/v2/messages' && refuse === 1) { refuse = 0; throw new Error('network'); }
      if (url === '/v2/messages' && refuse) { const r = refuse; refuse = 0; return respond({ error: 'x' }, r); }
      if (url === '/v2/tasks/t9/approve') return respond({ error: 'expired' }, 409);
      if (url.endsWith('/approve') || url.endsWith('/reject')) { app.server.tasks = []; return respond({ ok: true }); }
      return undefined;
    },
  });
  await tick();
  check('stored key logs in', !app.$('app-view').hidden && app.calls[0].url === '/v2/me' && app.calls[0].auth === 'Bearer admin-key');
  const tabs = app.all('[role=tab]');
  check('three tabs for the admin', tabs.length === 3 && tabs.every(t => !t.hidden) && !!app.$('tab-chat') && !!app.$('tab-wiki') && !!app.$('tab-approvals'));
  check('chat is the default tab', !app.$('chat').hidden && app.$('wiki').hidden && app.$('approvals').hidden && app.$('tab-chat').getAttribute('aria-selected') === 'true');
  check('admin reads the log, not its own inbox', app.calls.some(c => c.url === '/v2/log?after=0') && !app.calls.some(c => c.url.includes('inbox')));
  const bubbles = app.all('#log .m');
  check('messages render as bubbles', bubbles.length === 3);
  check('own message is marked mine', bubbles[2].classList.contains('mine') && !bubbles[1].classList.contains('mine'));
  check('hostile message stays literal text', bubbles[0].querySelector('.b').textContent === XSS && bubbles[0].querySelector('bdi').textContent === XSS);
  check('  sender and recipient are both named', bubbles[1].querySelector('.w').textContent === 'alice إلى bob');
  check('  a message from another day shows its date', bubbles[1].querySelector('.t').textContent.length > bubbles[2].querySelector('.t').textContent.length);
  check('  message text keeps its own direction', bubbles[1].querySelector('.b').dir === 'auto');
  check('hostile data creates no element', hostile(app));
  check('recipients come from /v2/me plus everyone', [...app.$('to').options].map(o => o.value).join() === 'alice,bob,__all__' && app.$('to').options[2].textContent === 'الكل');
  check('admin sends no ack', !app.calls.some(c => c.url === '/v2/ack'));

  bubbles[1].querySelector('.copy').click(); await tick();
  check('copy button copies the message', app.copied[0] === 'between agents' && !app.$('toast').hidden);

  const sends = () => app.calls.filter(c => c.url === '/v2/messages');
  type(app, { txt: '  ' }); app.$('send').click(); await tick();
  check('blank text is not sent', sends().length === 0);
  type(app, { txt: 'hello', to: 'bob' }); refuse = 422; app.$('send').click(); await tick();
  check('refused send keeps the text and explains in Arabic', app.$('txt').value === 'hello' && app.$('chatmsg').textContent.includes('يشبه سراً'));
  refuse = 403; app.$('send').click(); await tick();
  check('ACL refusal has its own message', app.$('chatmsg').textContent.includes('إذن'));
  refuse = 1; const k1 = sends().at(-1).body.idem_key; app.$('send').click(); await tick();
  check('network failure keeps the text', app.$('txt').value === 'hello' && app.$('chatmsg').textContent.includes('الاتصال'));
  app.$('send').click(); await tick();
  const retry = sends().at(-1).body;
  check('retry reuses the idempotency key', retry.idem_key === k1 && retry.to === 'bob' && retry.text === 'hello');
  check('success clears the box and the error', app.$('txt').value === '' && app.$('chatmsg').textContent === '');
  type(app, { txt: 'by keyboard' }); enter(app, 'txt'); await tick();
  check('Enter sends with a physical keyboard', sends().at(-1).body.text === 'by keyboard' && sends().at(-1).body.idem_key !== k1);

  app.server.messages = [...msgs, { seq: 4, from_agent: 'bob', to_agent: 'alice', body: 'dup', ts: Date.now() }];
  app.w.poll(); app.w.poll(); await tick();
  check('overlapping polls never draw a message twice', app.all('#log .m').length === 4);

  check('badge counts pending tasks and skips expired ones', app.$('badge-approvals').textContent === '1' && !app.$('badge-approvals').hidden);
  check('tab title shows the count', app.w.document.title === '(1) Agent Relay');
  check('new task raises a notice', app.calls.some(c => c.url.startsWith('/v2/tasks?')));
  app.$('tab-approvals').click(); await tick();
  check('approvals tab shows one card', !app.$('approvals').hidden && app.$('chat').hidden && app.all('#apl .task').length === 1);
  const card = app.$('apl').firstChild;
  check('approver sees the stored params', JSON.parse(card.querySelector('pre').textContent).repo === 'acme/widgets');
  check('approver sees the full hash', card.querySelector('.sha').textContent === 'sha256: ' + SHA);
  check('approver sees the risk', card.querySelector('.chip').textContent === 'خطر عالٍ');
  check('hostile task data stays literal', card.querySelector('bdi').textContent === XSS && hostile(app));
  card.querySelector('.approve').click(); await tick();
  check('first tap only asks, nothing is posted', !app.calls.some(c => c.url.endsWith('/approve')) && card.querySelector('.q').textContent.includes('github.invite'));
  app.w.loadApprovals(); await tick();
  check('a poll does not close an open confirmation', app.$('apl').firstChild === card && !card.querySelector('.q').hidden);
  [...card.querySelectorAll('.acts')][1].querySelector('button:last-child').click();
  check('cancel goes back', card.querySelector('.q').hidden && !card.querySelector('.acts').hidden);
  card.querySelector('.approve').click(); [...card.querySelectorAll('.acts')][1].querySelector('.approve').click(); await tick();
  const call = app.calls.find(c => c.url === '/v2/tasks/t1/approve');
  check('second tap posts the stored hash', call && call.method === 'POST' && call.body.params_sha256 === SHA);
  check('card leaves and the empty state returns', app.all('#apl .task').length === 0 && !app.$('aplempty').hidden && app.$('badge-approvals').hidden && app.w.document.title === 'Agent Relay');

  app.server.tasks = [task('t9')]; app.$('tab-chat').click(); app.w.loadApprovals(); await tick();
  check('task arriving on another tab shows a tappable notice', !app.$('toast').hidden && app.$('toast').textContent.includes('موافقتك'));
  app.$('toast').click(); await tick();
  check('tapping the notice opens approvals', !app.$('approvals').hidden && app.$('toast').hidden);
  const c9 = app.$('apl').firstChild;
  c9.querySelector('.approve').click(); [...c9.querySelectorAll('.acts')][1].querySelector('.approve').click(); await tick();
  check('a refused approval explains in Arabic', c9.querySelector('.msg').textContent.includes('انتهت'));
  app.server.tasks = [task('t10')]; app.w.loadApprovals(); await tick();
  const c10 = app.$('apl').firstChild;
  c10.querySelector('.reject').click(); [...c10.querySelectorAll('.acts')][1].querySelector('.reject').click(); await tick();
  check('reject posts a reason', app.calls.find(c => c.url === '/v2/tasks/t10/reject').body.reason === 'rejected by admin');
  check('no script errors', app.errors.length === 0);
  app.w.close();
}

console.log('agent: inbox, grants and paging');
{
  const many = Array.from({ length: 130 }, (_, i) => ({ seq: i + 1, from_agent: i % 2 ? 'alice' : 'bob', to_agent: i % 2 ? 'bob' : 'alice', body: 'm' + i, ts: Date.now() }));
  const app = boot({ key: 'agent-key', me: AGENT_ME, messages: many });
  await tick(80);
  check('approvals tab is hidden from an agent', app.$('tab-approvals').hidden);
  check('agent asks for both sides of the conversation', app.calls.some(c => c.url === '/v2/inbox?sent=1&after=0'));
  check('agent makes no admin calls', !app.calls.some(c => /\/v2\/(tasks|log|agents)/.test(c.url)));
  check('a full page fetches the rest right away', app.all('#log .m').length === 130 && app.calls.some(c => c.url === '/v2/inbox?sent=1&after=100'));
  check('agent acks what it read', app.calls.filter(c => c.url === '/v2/ack').at(-1).body.seq === 130);
  check('recipients are its grants only', [...app.$('to').options].map(o => o.value).join() === 'bob');
  app.$('tab-wiki').click(); await tick();
  app.server.messages = [...many, { seq: 131, from_agent: 'bob', to_agent: 'alice', body: 'new', ts: Date.now() }];
  app.w.poll(); await tick();
  check('message on another tab raises the chat badge', app.$('badge-chat').textContent === '1');
  app.$('tab-chat').click();
  check('  and opening chat clears it', app.$('badge-chat').hidden);
  app.w.close();

  const alone = boot({ key: 'k', me: { ...AGENT_ME, peers: [] } });
  await tick();
  check('no grants: send is off and the reason is shown', alone.$('send').disabled && alone.$('to').disabled && alone.$('chatmsg').textContent.includes('الأدمن'));
  alone.w.close();

  let gone = false; let down = false;
  const flaky = boot({ key: 'k', me: AGENT_ME, over: (url) => { if (down && url.includes('inbox')) throw new Error('offline'); return gone && url.includes('inbox') ? respond({ error: 'unauthorized' }, 401) : undefined; } });
  await tick();
  down = true; flaky.w.poll(); await tick();
  check('lost connection shows a banner and keeps the session', !flaky.$('net').hidden && !flaky.$('app-view').hidden);
  down = false; flaky.w.poll(); await tick();
  check('  the banner leaves once it is back', flaky.$('net').hidden);
  gone = true; flaky.w.poll(); await tick();
  check('revoked key returns to login with a reason', !flaky.$('login-view').hidden && flaky.$('login-msg').textContent.includes('لم يعد صالحاً'));
  flaky.w.close();
}

console.log('wiki');
{
  let conflict = false;
  const app = boot({
    key: 'k',
    over: (url, o) => {
      if (url === '/v2/wiki/taken' && o.method === 'PUT') return respond({ error: 'changed', current_version: 4 }, 409);
      if (url === '/v2/wiki/secret' && o.method === 'PUT') return respond({ error: 'x' }, 422);
      if (url === '/v2/wiki/evil' && o.method === 'PUT' && conflict) return respond({ error: 'changed', current_version: 9 }, 409);
      return undefined;
    },
  });
  await tick();
  app.$('tab-wiki').click(); await tick();
  check('wiki tab hides the chat and lists pages', app.$('chat').hidden && !app.$('wiki').hidden && app.$('wlist').children.length === 1);
  check('hostile title stays literal in the list', app.$('wlist').querySelector('.t').textContent === XSS);
  const line = app.$('wlist').querySelector('.d').textContent;
  check('list shows version and date', line.includes('v2') && line.includes('2023'));
  check('list shows quota use', !app.$('wquota').hidden && app.$('wquota').textContent.includes('5.0MB'));
  type(app, { wq: 'مهام & x', wkind: 'skill' }); enter(app, 'wq'); await tick();
  check('search and kind filter are URL-encoded', app.calls.at(-1).url === '/v2/wiki?kind=skill&q=' + encodeURIComponent('مهام & x'));
  const n = app.calls.length;
  type(app, { wq: 'نص' }); ['n', 'نص'].forEach(() => app.$('wq').dispatchEvent(new app.w.Event('input'))); await tick(420);
  check('typing searches once, after a pause', app.calls.length === n + 1 && app.calls.at(-1).url.endsWith(encodeURIComponent('نص')));
  app.$('wlist').querySelector('button').click(); await tick();
  check('opening a page shows it as text', !app.$('wview').hidden && app.$('wlist').hidden && app.$('wbar').hidden && app.$('wbody').textContent === XSS && app.$('wtitle').textContent === XSS);
  check('page shows version, editor and date', app.$('wmeta').textContent.includes('النسخة 2') && app.$('wmeta').textContent.includes(XSS) && app.$('wmeta').textContent.includes('2023'));
  check('admin sees the version count', app.all('#wtags .badge2').some(e => e.textContent === '2 نسخة'));
  check('admin sees history entries', !app.$('whistbox').hidden && app.$('whist').children.length === 2);
  app.$('wcopy').click(); await tick();
  check('copy button copies the page', app.copied.at(-1) === XSS);
  app.$('whist').children[1].click(); await tick();
  check('old version loads as text', app.$('wbody').textContent === 'old ' + XSS && app.$('wmsg').textContent.includes('قديمة'));
  app.$('whist').children[0].click();
  check('current version comes back with its badge', app.$('wbody').textContent === XSS && app.all('#wtags .badge2').length === 1);
  app.$('wedit').click();
  check('editing starts from the current version', !app.$('wform').hidden && app.$('fbody').value === XSS && app.$('fslug').disabled === true);
  type(app, { fbody: 'half written' }); app.$('tab-chat').click(); app.$('tab-wiki').click(); await tick();
  check('switching tabs keeps a draft', !app.$('wform').hidden && app.$('fbody').value === 'half written');
  const puts = () => app.calls.filter(c => c.method === 'PUT');
  type(app, { ftitle: '  ' }); app.$('fsave').click(); await tick();
  check('empty title is caught before the server', puts().length === 0 && app.$('wmsg').textContent.includes('العنوان'));
  type(app, { ftitle: 'T', fbody: 'edited', ftags: ' A , b،، c, ' }); conflict = true; app.$('fsave').click(); await tick();
  check('edit sends the version it started from', puts().at(-1).body.if_version === 2);
  check('someone else\'s newer edit is reported and the form stays', !app.$('wform').hidden && app.$('fbody').value === 'edited' && app.$('wmsg').textContent.includes('تغيّرت'));
  conflict = false; app.$('fsave').click(); await tick();
  const put = puts().at(-1);
  check('save sends PUT with the edited text', put.url === '/v2/wiki/evil' && put.body.body === 'edited' && put.body.tags.join() === 'A,b,c' && !app.$('wview').hidden);
  app.$('wback').click(); await tick();
  app.$('wnew').click();
  check('new page form is empty', app.$('fslug').disabled === false && app.$('fbody').value === '');
  const before = puts().length;
  type(app, { fslug: 'Bad Slug', ftitle: 't', fbody: 'b' }); app.$('fsave').click(); await tick();
  check('bad slug is caught before the server', puts().length === before && app.$('wmsg').textContent.includes('المعرّف'));
  type(app, { fslug: 'taken', ftitle: 't', fbody: 'b' }); app.$('fsave').click(); await tick();
  check('new page cannot overwrite: if_version is 0', puts().at(-1).body.if_version === 0 && app.$('wmsg').textContent.includes('مستخدم') && !app.$('wform').hidden);
  type(app, { fslug: 'secret' }); app.$('fsave').click(); await tick();
  check('server refusal is shown in Arabic and the form stays open', !app.$('wform').hidden && app.$('wmsg').textContent.includes('سراً'));
  type(app, { fslug: 'fresh', fkind: 'skill' }); app.$('fsave').click(); await tick();
  check('new page is created and opened', puts().at(-1).url === '/v2/wiki/fresh' && puts().at(-1).body.kind === 'skill' && !app.$('wview').hidden);
  check('hostile wiki data creates no element', hostile(app));
  check('no script errors', app.errors.length === 0);
  app.w.close();

  const agent = boot({ key: 'k', me: AGENT_ME, over: url => (url === '/v2/wiki/ctx' ? respond({ ...PAGE, slug: 'ctx', kind: 'context' }) : url === '/v2/wiki/evil/history' ? respond({}, 500) : undefined) });
  await tick();
  agent.$('tab-wiki').click(); await tick();
  agent.w.openPage('ctx'); await tick();
  check('no grant: context pages offer no edit button', agent.$('wedit').hidden && agent.$('whistbox').hidden);
  agent.w.openPage('evil'); await tick();
  check('  other pages do', !agent.$('wedit').hidden);
  agent.$('wedit').click();
  check('  and context cannot be picked in the form', agent.$('fkind').querySelector('option[value=context]').disabled);
  agent.w.close();
}
process.exit(failed ? 1 : 0);
