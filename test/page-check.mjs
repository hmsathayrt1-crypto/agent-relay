// Parses src/page.html in jsdom and runs its real script, with the real pinned libraries, against a fake server and hostile data.
// Not a browser: it proves markup and behaviour. test/browser-check.mjs covers CSP enforcement and layout.
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

let jsdom;
try { jsdom = createRequire(import.meta.url)('jsdom'); } catch (e) { console.error('jsdom is missing: run npm install'); process.exit(1); }

const root = new URL('../', import.meta.url);
const html = readFileSync(new URL('src/page.html', root), 'utf8');
const worker = readFileSync(new URL('src/worker.js', root), 'utf8');
const pkg = JSON.parse(readFileSync(new URL('package.json', root), 'utf8'));
const script = html.match(/<script nonce="__CSP_NONCE__">([\s\S]*)<\/script>/)[1];
const css = html.match(/<style nonce="__CSP_NONCE__">([\s\S]*?)<\/style>/)[1];
const CDN_TAG = /<script src="https:\/\/cdn\.jsdelivr\.net\/npm\/([^@"]+)@([^/"]+)\/([^"]+)" integrity="(sha384-[^"]+)" crossorigin="anonymous"><\/script>\n?/g;
const cdn = [...html.matchAll(CDN_TAG)].map(m => ({ tag: m[0], pkg: m[1], version: m[2], path: m[3], integrity: m[4], url: `https://cdn.jsdelivr.net/npm/${m[1]}@${m[2]}/${m[3]}`, code: readFileSync(new URL(`node_modules/${m[1]}/${m[3]}`, root), 'utf8') }));
const bare = cdn.reduce((s, c) => s.replace(c.tag, ''), html);
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
// libs picks which CDN packages "loaded", and motion:true makes the browser report no reduced-motion preference.
function boot({ key = '', me = ADMIN_ME, over = () => undefined, messages = [], tasks = [], libs = null, motion = false } = {}) {
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
  virtualConsole.on('error', (...a) => errors.push('console.error: ' + a.join(' ')));
  const dom = new jsdom.JSDOM(bare, {
    url: 'http://relay.test/', runScripts: 'dangerously', pretendToBeVisual: true, virtualConsole,
    beforeParse(w) {
      w.fetch = route;
      if (key) w.sessionStorage.setItem('rk', key);
      w.matchMedia = q => ({ matches: q.includes('reduced-motion') ? !motion : true });
      w.confirm = () => { throw new Error('confirm() must not be used'); };
      Object.defineProperty(w.navigator, 'clipboard', { value: { writeText: async t => { copied.push(t); } } });
      w.addEventListener('error', e => errors.push(e.message));
      w.addEventListener('unhandledrejection', e => errors.push(String(e.reason)));
      for (const c of cdn) if (!libs || libs.includes(c.pkg + ':' + c.path) || libs.includes(c.pkg)) w.eval(c.code);
    },
  });
  const w = dom.window;
  return { w, calls, errors, copied, server, $: id => w.document.getElementById(id), all: sel => [...w.document.querySelectorAll(sel)] };
}
const hostile = (app) => app.all('img, script:not([nonce]), iframe').length === 0 && app.w.pwned === undefined;
const key = (app, target, name) => target.dispatchEvent(new app.w.KeyboardEvent('keydown', { key: name, bubbles: true, cancelable: true }));
const enter = (app, id) => key(app, app.$(id), 'Enter');
const type = (app, o) => { for (const [id, v] of Object.entries(o)) { const e = app.$(id); e.value = v; e.dispatchEvent(new app.w.Event('input', { bubbles: true })); } };
const options = (app, id) => app.all(`#${id}-list [role=option]`);
const pick = async (app, id, value) => {
  app.$(id).click(); await tick(5);
  options(app, id).find(o => o.dataset.value === String(value)).click(); await tick(5);
};
const search = (app, id, text) => { const s = app.$(id + '-list').parentElement.querySelector('input'); s.value = text; s.dispatchEvent(new app.w.Event('input', { bubbles: true })); return s; };
const toneOf = e => [...e.classList].find(c => /^c\d+$/.test(c));

console.log('static');
check('viewport is set for phones', /<meta name="viewport" content="width=device-width, initial-scale=1/.test(html));
check('color-scheme meta is light', html.includes('<meta name="color-scheme" content="light">'));
check('theme-color meta exists', /<meta name="theme-color" content="#[0-9a-f]{6}">/.test(html));
check('full height uses 100dvh, never 100vh', html.includes('100dvh') && !html.includes('100vh'));
check('RTL Arabic document', html.includes('lang="ar" dir="rtl"'));
const dir = mkdtempSync(join(tmpdir(), 'page-check-'));
let parses = true;
try { writeFileSync(join(dir, 'page.js'), script); execFileSync(process.execPath, ['--check', join(dir, 'page.js')], { stdio: 'pipe' }); } catch (e) { parses = false; }
rmSync(dir, { recursive: true });
check('node --check accepts the script', parses);
check('no markup built from strings', !/innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|srcdoc/.test(script));
check('no inline style or handler attribute in the static markup, which the CSP would block', !/\s(style|on[a-z]+)=/.test(html.replace(script, '')));
check('no style attribute set as a string, which the CSP would block', !/setAttribute\("style"|\sstyle="/.test(script));
check('style and script both carry the nonce', html.includes('<style nonce="__CSP_NONCE__">') && html.includes('<script nonce="__CSP_NONCE__">'));
check('nothing external except the pinned scripts', !/https?:\/\/|<link\b|\ssrc=|@import|url\(/.test(bare));
check('five pinned CDN scripts: Preact, hooks, htm, marked, DOMPurify', cdn.length === 5 && ['preact', 'htm', 'marked', 'dompurify'].every(p => cdn.some(c => c.pkg === p)));
check('  each one has an exact version equal to package.json', cdn.every(c => /^\d+\.\d+\.\d+$/.test(c.version) && pkg.devDependencies[c.pkg] === c.version));
check('  each integrity hash matches the file these tests run', cdn.every(c => c.integrity === 'sha384-' + createHash('sha384').update(readFileSync(new URL(`node_modules/${c.pkg}/${c.path}`, root))).digest('base64')));
const allowed = [...worker.matchAll(/'(https:\/\/cdn\.jsdelivr\.net\/[^']+)'/g)].map(m => m[1]);
check('  the Worker CSP allows exactly these files', allowed.join() === cdn.map(c => c.url).join());
check('  and still has default-src none and a nonce', worker.includes(`"default-src 'none'; script-src 'nonce-" + nonce + "' " + PAGE_SCRIPTS + "; style-src 'nonce-" + nonce + "'; connect-src 'self';`));
check('libraries load before the page script', html.lastIndexOf('cdn.jsdelivr.net') < html.indexOf('<script nonce='));
check('no native select anywhere', !/<select|<option/.test(html));
const used = [...new Set([...script.matchAll(/\$\("([\w-]+)"\)/g)].map(m => m[1]))];
check('every id the script names exists in a template', used.length >= 3 && used.every(id => html.includes('id="' + id + '"')));
check('the [hidden] attribute beats display:flex', html.includes('[hidden]{display:none!important}'));
check('44px touch target is the base size for controls', html.includes('--tap:44px') && /\nbutton\{min-height:var\(--tap\)/.test(html) && /\ninput,textarea\{[^}]*min-height:var\(--tap\)/.test(html) && /\.cb-o\{[^}]*min-height:var\(--tap\)/.test(html));
check('tabs are taller than the minimum', /nav button\{[^}]*min-height:50px/.test(html));
check('16px inputs, so iOS does not zoom on focus', /\ninput,textarea\{[^}]*font-size:16px/.test(html));
check('message text is 15-16px with a roomy line height', /\.b\{font-size:16px;line-height:1\.7\}/.test(css));
check('bubbles are spaced apart', /#log\{[^}]*gap:16px/.test(css));

console.log('palette and motion');
const hex = s => [1, 3, 5].map(i => parseInt(s.slice(i, i + 2), 16));
const lum = c => { const [r, g, b] = hex(c).map(v => { v /= 255; return v <= .03928 ? v / 12.92 : ((v + .055) / 1.055) ** 2.4; }); return .2126 * r + .7152 * g + .0722 * b; };
const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + .05) / (y + .05); };
const hue = c => { const [r, g, b] = hex(c).map(v => v / 255); const M = Math.max(r, g, b), d = M - Math.min(r, g, b); if (!d) return -1; return ((M === r ? (g - b) / d + 6 : M === g ? (b - r) / d + 2 : (r - g) / d + 4) % 6) * 60; };
const tones = [...css.matchAll(/\.c(\d+)\{--c:(#[0-9a-f]{6});--cs:(#[0-9a-f]{6});--cl:(#[0-9a-f]{6})\}/g)];
check('12 agent tones', tones.length === 12 && script.includes('var TONES=12;'));
check('white letters on each avatar pass AA', tones.every(t => ratio(t[2], '#ffffff') >= 4.5));
check('each name passes AA on its own bubble colour', tones.every(t => ratio(t[2], t[3]) >= 4.5));
check('no purple', tones.flatMap(t => [t[2], t[3], t[4]]).concat([...css.matchAll(/--(?:accent|accent-dark|accent-soft):(#[0-9a-f]{6})/g)].map(m => m[1])).every(c => { const h = hue(c); return h < 250 || h > 320; }));
const times = [...css.matchAll(/(?:animation|transition):[^;}]*/g)].filter(m => !m[0].includes('shimmer')).flatMap(m => [...m[0].matchAll(/\.(\d+)s/g)].map(x => Number('0.' + x[1]) * 1000));
check('every transition and animation is 150-250ms', times.length > 10 && times.every(t => t >= 150 && t <= 250));
check('reduced motion turns all of it off', /@media \(prefers-reduced-motion:reduce\)\{\*,\*::before,\*::after\{animation:none!important;transition:none!important\}/.test(css));
check('mine goes right and others left in this RTL page', /\.m\.mine\{flex-direction:row\}/.test(css) && /\.m\.other\{flex-direction:row-reverse\}/.test(css));

console.log('CDN failure');
{
  const app = boot({ libs: [] });
  await tick();
  check('no libraries: a clear message, no exception', app.$('boot-msg').textContent.includes('تعذر تحميل') && app.errors.length === 0 && app.calls.length === 0);
  app.w.close();
  const noMd = boot({ key: 'k', me: AGENT_ME, libs: ['preact', 'htm'], messages: [{ seq: 1, from_agent: 'bob', to_agent: 'alice', body: '**bold** ' + XSS, ts: Date.now() }] });
  await tick();
  const b = noMd.$('log').querySelector('.b');
  check('no marked or DOMPurify: text stays literal', b.textContent === '**bold** ' + XSS && b.classList.contains('plain') && b.dir === 'auto' && b.children.length === 0 && noMd.errors.length === 0 && hostile(noMd));
  noMd.w.close();
  const noPurify = boot({ key: 'k', me: AGENT_ME, libs: ['preact', 'htm', 'marked'], messages: [{ seq: 1, from_agent: 'bob', to_agent: 'alice', body: '**bold** ' + XSS, ts: Date.now() }] });
  await tick();
  const c = noPurify.$('log').querySelector('.b');
  check('marked without DOMPurify never renders: fails closed', c.textContent === '**bold** ' + XSS && c.children.length === 0 && hostile(noPurify));
  noPurify.w.close();
}

console.log('login');
{
  const app = boot({ over: (url, o) => (o.headers.Authorization === 'Bearer bad' ? respond({ error: 'unauthorized' }, 401) : undefined) });
  await tick();
  check('no key: only the login screen shows', !!app.$('login-view') && !app.$('app-view') && app.calls.length === 0);
  check('the boot placeholder is gone', !app.$('boot'));
  app.$('login').click(); await tick();
  check('empty key asks for one in Arabic', app.$('login-msg').textContent === 'أدخل المفتاح أولاً.' && app.calls.length === 0);
  type(app, { key: 'bad' }); app.$('login').click(); await tick();
  check('bad key is refused with an Arabic message', !!app.$('login-view') && app.$('login-msg').textContent.includes('غير صالح'));
  check('  and it reads no inbox', !app.calls.some(c => c.url.includes('inbox') || c.url.includes('log')));
  check('  and is not stored', app.w.sessionStorage.getItem('rk') === null);
  type(app, { key: 'good' }); enter(app, 'key'); await tick();
  check('good key opens the app with Enter', !app.$('login-view') && !!app.$('app-view') && app.w.sessionStorage.getItem('rk') === 'good');
  app.$('logout').click(); await tick();
  check('logout forgets the key and goes back', app.w.sessionStorage.getItem('rk') === null && !!app.$('login-view') && !app.$('log'));
  check('  key field is emptied', app.$('key').value === '');
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
    over: (url) => {
      if (url === '/v2/messages' && refuse === 1) { refuse = 0; throw new Error('network'); }
      if (url === '/v2/messages' && refuse) { const r = refuse; refuse = 0; return respond({ error: 'x' }, r); }
      if (url === '/v2/tasks/t9/approve') return respond({ error: 'expired' }, 409);
      if (url.endsWith('/approve') || url.endsWith('/reject')) { app.server.tasks = []; return respond({ ok: true }); }
      return undefined;
    },
  });
  await tick();
  check('stored key logs in', !!app.$('app-view') && app.calls[0].url === '/v2/me' && app.calls[0].auth === 'Bearer admin-key');
  const tabs = app.all('[role=tab]');
  check('three tabs for the admin', tabs.length === 3 && tabs.every(t => !t.hidden) && !!app.$('tab-chat') && !!app.$('tab-wiki') && !!app.$('tab-approvals'));
  check('chat is the default tab', !app.$('chat').hidden && app.$('wiki').hidden && app.$('approvals').hidden && app.$('tab-chat').getAttribute('aria-selected') === 'true');
  check('admin reads the log, not its own inbox', app.calls.some(c => c.url === '/v2/log?after=0') && !app.calls.some(c => c.url.includes('inbox')));
  const bubbles = app.all('#log .m');
  check('messages render as bubbles', bubbles.length === 3);
  check('own message is marked mine, others are not', bubbles[2].classList.contains('mine') && bubbles[1].classList.contains('other') && !bubbles[1].classList.contains('mine'));
  const nameAt = bubbles[1].querySelector('.h');
  check('sender and time sit above the bubble', nameAt.nextElementSibling.querySelector('.bb') !== null && nameAt.querySelector('.w') && nameAt.querySelector('.t'));
  check('hostile sender stays literal text', bubbles[0].querySelector('bdi').textContent === XSS);
  check('hostile body is sanitized away', bubbles[0].querySelectorAll('.b img, .b script').length === 0 && bubbles[0].querySelector('.b').textContent.trim() === '');
  bubbles[0].querySelector('.rawbtn').click(); await tick(5);
  check('  and the reader can still see the original, as text', bubbles[0].querySelector('.b').textContent === XSS && bubbles[0].querySelector('.b').children.length === 0 && hostile(app));
  check('  sender and recipient are both named', bubbles[1].querySelector('.w').textContent === 'alice إلى bob');
  check('  a message from another day shows its date', bubbles[1].querySelector('.t').textContent.length > bubbles[2].querySelector('.t').textContent.length);
  check('  message text keeps its own direction', bubbles[1].querySelector('.b p').getAttribute('dir') === 'ltr');
  check('hostile data creates no element', hostile(app));
  app.$('to').click(); await tick(5);
  check('recipients come from /v2/me plus everyone', options(app, 'to').map(o => o.dataset.value).join() === 'alice,bob,__all__' && options(app, 'to')[2].textContent.includes('الكل'));
  key(app, app.$('to'), 'Escape'); await tick(5);
  check('admin sends no ack', !app.calls.some(c => c.url === '/v2/ack'));

  bubbles[1].querySelector('.copy').click(); await tick();
  check('copy button copies the message', app.copied[0] === 'between agents' && !app.$('toast').hidden);

  const sends = () => app.calls.filter(c => c.url === '/v2/messages');
  type(app, { txt: '  ' }); app.$('send').click(); await tick();
  check('blank text is not sent', sends().length === 0);
  await pick(app, 'to', 'bob');
  type(app, { txt: 'hello' }); refuse = 422; app.$('send').click(); await tick();
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
  check('  the selected tab moves with it', app.$('tab-approvals').getAttribute('aria-selected') === 'true' && app.$('tab-chat').getAttribute('aria-selected') === 'false');
  const card = app.$('apl').firstElementChild;
  check('approver sees the stored params', JSON.parse(card.querySelector('pre').textContent).repo === 'acme/widgets');
  check('approver sees the full hash', card.querySelector('.sha').textContent === 'sha256: ' + SHA);
  check('approver sees the risk', card.querySelector('.chip').textContent === 'خطر عالٍ');
  check('hostile task data stays literal', card.querySelector('bdi').textContent === XSS && hostile(app));
  card.querySelector('.approve').click(); await tick();
  check('first tap only asks, nothing is posted', !app.calls.some(c => c.url.endsWith('/approve')) && card.querySelector('.q').textContent.includes('github.invite'));
  app.w.loadApprovals(); await tick();
  check('a poll does not close an open confirmation', app.$('apl').firstElementChild === card && !card.querySelector('.q').hidden);
  [...card.querySelectorAll('.acts')][1].querySelector('button:last-child').click(); await tick();
  check('cancel goes back', card.querySelector('.q').hidden && !card.querySelector('.acts').hidden);
  card.querySelector('.approve').click(); await tick(); [...card.querySelectorAll('.acts')][1].querySelector('.approve').click(); await tick();
  const call = app.calls.find(c => c.url === '/v2/tasks/t1/approve');
  check('second tap posts the stored hash', call && call.method === 'POST' && call.body.params_sha256 === SHA);
  check('card leaves and the empty state returns', app.all('#apl .task').length === 0 && !app.$('aplempty').hidden && app.$('badge-approvals').hidden && app.w.document.title === 'Agent Relay');

  app.server.tasks = [task('t9')]; app.$('tab-chat').click(); await tick(); app.w.loadApprovals(); await tick();
  check('task arriving on another tab shows a tappable notice', !app.$('toast').hidden && app.$('toast').textContent.includes('موافقتك'));
  app.$('toast').click(); await tick();
  check('tapping the notice opens approvals', !app.$('approvals').hidden && app.$('toast').hidden);
  const c9 = app.$('apl').firstElementChild;
  c9.querySelector('.approve').click(); await tick(); [...c9.querySelectorAll('.acts')][1].querySelector('.approve').click(); await tick();
  check('a refused approval explains in Arabic', c9.querySelector('.msg').textContent.includes('انتهت'));
  app.server.tasks = [task('t10')]; app.w.loadApprovals(); await tick();
  const c10 = app.$('apl').firstElementChild;
  c10.querySelector('.reject').click(); await tick(); [...c10.querySelectorAll('.acts')][1].querySelector('.reject').click(); await tick();
  check('reject posts a reason', app.calls.find(c => c.url === '/v2/tasks/t10/reject').body.reason === 'rejected by admin');
  check('no script errors', app.errors.length === 0);
  app.w.close();
}

console.log('duplicate messages');
{
  const now = Date.now();
  const rows = [
    { seq: 1, from_agent: 'bob', to_agent: 'alice', body: 'ping', ts: now - 3000 },
    { seq: 2, from_agent: 'bob', to_agent: 'alice', body: 'ping', ts: now - 2000 },
    { seq: 3, from_agent: 'carol', to_agent: 'alice', body: 'ping', ts: now - 1500 },
    { seq: 4, from_agent: 'bob', to_agent: 'alice', body: 'other', ts: now - 1000 },
    { seq: 5, from_agent: 'bob', to_agent: 'alice', body: 'ping', ts: now - 500 },
    { seq: 6, from_agent: 'alice', to_agent: 'bob', body: 'solo', ts: now - 100 },
  ];
  const app = boot({ key: 'k', me: AGENT_ME, messages: rows });
  await tick();
  const texts = () => app.all('#log .m').map(m => m.querySelector('.w').textContent + ':' + m.querySelector('.b').textContent.trim());
  check('same sender and text collapse, even when not consecutive', app.all('#log .m').length === 4);
  check('the same text from someone else stays separate', texts().includes('carol:ping'));
  const rep = () => app.all('#log .m').find(m => m.querySelector('.rep'));
  check('one badge reads ×3 beside the bubble', app.all('.rep').length === 1 && rep().querySelector('.rep').textContent === '×3' && rep().querySelector('.bw .bb') !== null);
  check('the group sits at its newest copy', texts().indexOf('bob:ping') > texts().indexOf('bob:other'));
  check('single messages have no badge', !app.all('#log .m').at(-1).querySelector('.rep'));
  check('collapsed list starts closed', !app.$('log').querySelector('.copies') && rep().querySelector('.rep').getAttribute('aria-expanded') === 'false');
  rep().querySelector('.rep').click(); await tick();
  const lines = () => [...rep().querySelectorAll('.copies li')];
  check('tapping the badge lists every copy with its time', lines().length === 3 && lines().every(l => /\d\d:\d\d:\d\d/.test(l.querySelector('.ct').textContent)));
  check('  newest first', lines()[0].querySelector('.ct').textContent === app.w.fmtTime(now - 500, true));
  app.server.messages = [...rows, { seq: 7, from_agent: 'bob', to_agent: 'alice', body: 'ping', ts: now }];
  app.w.poll(); await tick();
  check('a new repeat counts up and keeps the list open', rep().querySelector('.rep').textContent === '×4' && lines().length === 4);
  check('  and moves the bubble to the bottom', app.all('#log .m').at(-1) === rep());
  rep().querySelector('.rep').click(); await tick();
  check('tapping again closes the list', !app.$('log').querySelector('.copies'));
  check('copies do not grow the log', app.all('#log .m').length === 4 && app.errors.length === 0);
  app.w.close();

  const loop = Array.from({ length: 150 }, (_, i) => ({ seq: i + 1, from_agent: 'bot', to_agent: 'alice', body: 'stuck', ts: now + i }));
  const many = boot({ key: 'k', me: AGENT_ME, messages: loop });
  await tick(80);
  const b = many.$('log').querySelector('.rep');
  check('an agent stuck in a loop is one bubble', many.all('#log .m').length === 1 && b.textContent === '×150');
  b.click(); await tick();
  check('  and the copy list is capped, saying so', many.all('.copies li').length === 101 && many.all('.copies li')[0].textContent.includes('100') && many.all('.copies li')[0].textContent.includes('150'));
  many.w.close();
}

console.log('agent identity');
{
  const app = boot({
    key: 'k', me: { ...AGENT_ME, peers: ['bob', 'muse', 'claude-code'], can_broadcast: true },
    messages: [
      { seq: 1, from_agent: 'bob', to_agent: 'alice', body: 'hi', ts: Date.now() },
      { seq: 2, from_agent: 'alice', to_agent: 'muse', body: 'mine', ts: Date.now() },
      { seq: 3, from_agent: 'alice', to_agent: '__all__', body: 'to all', ts: Date.now() },
    ],
    over: url => (url.startsWith('/v2/wiki?') ? respond({ pages: [{ ...PAGE, slug: 'p', title: 'T', tags: [], updated_by: 'bob' }], quota: null }) : url === '/v2/wiki/p' ? respond({ ...PAGE, slug: 'p', title: 'T', tags: [], body: 'x', updated_by: 'bob' }) : undefined),
  });
  await tick();
  const [bob, mine, all] = app.all('#log .m');
  const av = bob.querySelector('svg.av');
  check('every bubble has an inline SVG avatar, no image', !!av && av.querySelector('circle') && av.querySelector('text').textContent === 'B' && app.all('image,img').length === 0);
  check('two-part names get two letters', app.w.initials('claude-code') === 'CC' && app.w.initials('hermes') === 'H');
  const t = toneOf(bob);
  check('the bubble and the avatar take the agent colour', !!t && toneOf(av) === t);
  check('the name is drawn in that colour', !!bob.querySelector('.w .nm') && /\.nm\{color:var\(--c\)/.test(css));
  check('the bubble background comes from that colour', /\.bb\{[^}]*background:var\(--cs\);border:1px solid var\(--cl\)/.test(css));
  check('colour depends only on the name', app.w.tone('bob') === t && app.w.tone('bob') === app.w.tone('bob'));
  check('your real agents all differ', new Set(['hermes', 'claude-code', 'muse', 'github-bot', 'carol', '__admin__'].map(app.w.tone)).size === 6);
  check('your own name is in the header with its avatar', app.$('who').querySelector('svg.av') && app.$('who').textContent.includes('alice') && toneOf(app.$('who').querySelector('.ag')) === app.w.tone('alice'));
  check('your own bubble says أنت', mine.querySelector('.w').textContent === 'أنت');
  const okLine = mine.querySelector('.ok');
  check('sent message confirms the recipient by name', okLine.textContent.includes('✓') && okLine.textContent.includes('وصلت إلى') && okLine.textContent.includes('muse'));
  check('  with the recipient avatar and colour, not yours', toneOf(okLine.querySelector('.ag')) === app.w.tone('muse') && toneOf(okLine.querySelector('svg.av')) === app.w.tone('muse'));
  check('  a broadcast confirms everyone', all.querySelector('.ok').textContent.includes('الكل'));
  check('other people\'s messages have no confirmation', !bob.querySelector('.ok'));
  check('composer shows the recipient avatar and colour', toneOf(app.$('bar')) === app.w.tone(app.$('to').dataset.value) && !!app.$('to').querySelector('svg.av') && app.$('to').classList.contains('tone'));
  app.$('to').click(); await tick(5);
  check('every recipient in the list has its avatar and colour', options(app, 'to').every(o => o.querySelector('svg.av') && (toneOf(o) || o.dataset.value === '__all__') && toneOf(o) === (app.w.tone(o.dataset.value) || undefined)));
  key(app, app.$('to'), 'Escape'); await tick(5);
  await pick(app, 'to', 'muse');
  check('choosing a recipient recolours the composer on the spot', toneOf(app.$('bar')) === app.w.tone('muse') && app.$('to').querySelector('text').textContent === 'M');
  app.$('tab-wiki').click(); await tick();
  check('the wiki list colours the last editor', toneOf(app.$('wlist').querySelector('.ag')) === app.w.tone('bob'));
  app.$('wlist').querySelector('button').click(); await tick();
  check('the page header colours the editor', toneOf(app.$('wmeta').querySelector('.ag')) === app.w.tone('bob') && !!app.$('wmeta').querySelector('svg.av'));
  check('no script errors', app.errors.length === 0);
  app.w.close();
}

console.log('to: in the composer');
{
  const app = boot({ key: 'k', me: { ...AGENT_ME, peers: ['bob', 'muse', 'mark'], can_broadcast: true } });
  await tick();
  const sends = () => app.calls.filter(c => c.url === '/v2/messages');
  check('starts on the first recipient', app.$('to').dataset.value === 'bob');
  type(app, { txt: 'to:' }); await tick(5);
  check('typing to: offers every recipient with an avatar', app.all('#tohints .hint').length === 4 && app.all('#tohints svg.av').length === 4);
  type(app, { txt: 'to:m' }); await tick(5);
  check('  and narrows as you type', app.all('#tohints .hint').map(h => h.textContent.trim().slice(-4)).join() === 'muse,mark');
  type(app, { txt: 'to:muse' }); await tick(5);
  check('a full name switches recipient, avatar and colour at once', app.$('to').dataset.value === 'muse' && toneOf(app.$('bar')) === app.w.tone('muse') && !app.$('tohints'));
  type(app, { txt: 'to:muse hello there' }); await tick(5); app.$('send').click(); await tick();
  check('the prefix selects the recipient and leaves the text', sends().at(-1).body.to === 'muse' && sends().at(-1).body.text === 'hello there' && app.$('txt').value === '');
  type(app, { txt: 'to:all' }); await tick(5);
  check('to:all means everyone', app.$('to').dataset.value === '__all__');
  type(app, { txt: 'to:b' }); await tick(5);
  app.all('#tohints .hint')[0].click(); await tick(5);
  check('tapping a hint completes the name', app.$('txt').value === 'to:bob ' && app.$('to').dataset.value === 'bob');
  const n = sends().length;
  type(app, { txt: 'to:muze secret plan' }); await tick(5); app.$('send').click(); await tick();
  check('a mistyped recipient is refused, not sent to whoever is selected', sends().length === n && app.$('chatmsg').textContent.includes('muze') && app.$('txt').value === 'to:muze secret plan');
  type(app, { txt: 'to:muse' }); await tick(5); app.$('send').click(); await tick();
  check('a prefix with no text sends nothing', sends().length === n);
  type(app, { txt: 'to: everyone, please read this' }); await tick(5); app.$('send').click(); await tick();
  check('"to: words" stays plain text', sends().at(-1).body.text === 'to: everyone, please read this');
  check('no script errors', app.errors.length === 0);
  app.w.close();
}

console.log('combobox');
{
  const app = boot({ key: 'k', me: { ...AGENT_ME, peers: ['alice2', 'bob', 'carol', 'muse'], can_broadcast: true }, motion: false });
  await tick();
  const to = app.$('to');
  const box = () => app.$('to-list');
  const active = () => app.w.document.querySelector('#to-list .on');
  const input = () => box().parentElement.querySelector('input');
  check('closed: a combobox button and no list', to.getAttribute('role') === 'combobox' && to.getAttribute('aria-expanded') === 'false' && !box());
  to.click(); await tick(5);
  check('opens with a listbox of options', to.getAttribute('aria-expanded') === 'true' && box().getAttribute('role') === 'listbox' && options(app, 'to').length === 5);
  check('search box takes focus with a physical keyboard', app.w.document.activeElement === input());
  check('the current value is marked and active', active().dataset.value === 'alice2' && active().getAttribute('aria-selected') === 'true');
  search(app, 'to', 'MU'); await tick(5);
  check('search filters at once, ignoring case', options(app, 'to').map(o => o.dataset.value).join() === 'muse' && active().dataset.value === 'muse');
  check('  and no request was needed', !app.calls.some(c => c.url.includes('muse')));
  check('  the input points at the active option', input().getAttribute('aria-activedescendant') === active().id);
  search(app, 'to', 'zzz'); await tick(5);
  check('no match says so', options(app, 'to').length === 0 && box().textContent.includes('لا نتائج'));
  key(app, input(), 'Enter'); await tick(5);
  check('  and Enter with no match does nothing', to.getAttribute('aria-expanded') === 'true' && to.dataset.value === 'alice2');
  search(app, 'to', 'الك'); await tick(5);
  check('Arabic labels are searchable', options(app, 'to').map(o => o.dataset.value).join() === '__all__');
  search(app, 'to', ''); await tick(5);
  key(app, input(), 'ArrowDown'); await tick(5);
  check('ArrowDown moves the active option', options(app, 'to').filter(o => o.classList.contains('on')).length === 1);
  const n0 = active().dataset.value;
  key(app, input(), 'End'); await tick(5);
  check('End goes to the last', active().dataset.value === '__all__');
  key(app, input(), 'ArrowDown'); await tick(5);
  check('  and ArrowDown wraps to the first', active().dataset.value === 'alice2');
  key(app, input(), 'ArrowUp'); await tick(5);
  check('  and ArrowUp wraps back', active().dataset.value === '__all__');
  key(app, input(), 'Home'); await tick(5); key(app, input(), 'ArrowDown'); await tick(5);
  check('Home goes to the first', active().dataset.value === n0);
  const row = options(app, 'to')[3];
  ['pointermove', 'PointerMove'].forEach(n => row.dispatchEvent(new app.w.Event(n, { bubbles: true }))); await tick(5);
  check('hover moves the active option', active() === row);
  key(app, input(), 'Enter'); await tick(5);
  check('Enter picks it and closes', to.dataset.value === row.dataset.value && to.getAttribute('aria-expanded') === 'false' && !box());
  check('  focus returns to the button', app.w.document.activeElement === to);
  key(app, to, 'ArrowDown'); await tick(5);
  check('ArrowDown on the button opens it', to.getAttribute('aria-expanded') === 'true');
  const was = to.dataset.value;
  key(app, input(), 'ArrowDown'); await tick(5); key(app, input(), 'Escape'); await tick(5);
  check('Escape closes without changing the value', !box() && to.dataset.value === was && app.w.document.activeElement === to);
  key(app, to, 'm'); await tick(5);
  check('typing on the button opens and searches', input().value === 'm' && options(app, 'to').map(o => o.dataset.value).join() === 'muse');
  key(app, input(), 'Tab'); await tick(5);
  check('Tab closes', !box());
  to.click(); await tick(5);
  app.w.document.body.dispatchEvent(new app.w.Event('pointerdown', { bubbles: true })); await tick(5);
  check('tapping elsewhere closes', !box());
  to.click(); await tick(5); to.click(); await tick(5);
  check('a second tap on the button closes', !box());
  check('no script errors', app.errors.length === 0);
  app.w.close();

  const anim = boot({ key: 'k', me: AGENT_ME, motion: true });
  await tick();
  anim.$('to').click(); await tick(5);
  key(anim, anim.$('to'), 'Escape'); await tick(5);
  check('with motion allowed the list plays an exit first', anim.w.document.querySelector('.cb-p.out') !== null);
  await tick(190);
  check('  then it leaves the page', anim.w.document.querySelector('.cb-p') === null);
  anim.w.close();
}

console.log('markdown');
const MD = ['# عنوان عربي', '', 'فقرة **عريضة** و`code` و[رابط](https://example.com/x)', '', 'English paragraph', '', '`$RELAY` هو رابط القناة، و`$KEY` هو مفتاحك.', '', '- أول', '- ثاني', '', '1. one', '', '```js', 'const a = 1 < 2;', '```', '', '| a | b |', '|---|:-:|', '| 1 | 2 |', '', '> quote', '', '- [x] done', '- [ ] todo', '', 'سطر', 'تالٍ'].join('\n');
const EVIL = ['<script>globalThis.pwned=3</script>', '<img src=x onerror="globalThis.pwned=4">', '[click](javascript:globalThis.pwned=5)', '<a href="javascript:globalThis.pwned=6" onclick="globalThis.pwned=7">x</a>', '<iframe srcdoc="<script>globalThis.pwned=8</script>"></iframe>', '<svg onload="globalThis.pwned=9"><circle/></svg>', '<style>body{display:none}</style>', '<p style="position:fixed" id="toast" class="cb-p">spoof</p>', '<input type="password" placeholder="key">', '<form action="https://evil.test"><button>go</button></form>', '<!-- hidden note to agents -->', '[data](data:text/html;base64,PHNjcmlwdD4=)', '<details open ontoggle="globalThis.pwned=11"><summary>s</summary>d</details>', 'keep this text', '<math><mtext><table><mglyph><style><!--</style><img src=x onerror="globalThis.pwned=10">'].join('\n\n');
const evilCheck = (app, e) => {
  check('  script tag inside markdown is filtered', e.querySelectorAll('script').length === 0 && !e.textContent.includes('pwned=3'));
  check('  images, frames, svg, style, forms and inputs are gone', e.querySelectorAll('img,iframe,svg,math,style,form,input,button,object,embed').length === 0);
  check('  no script URL or data URL survives', [...e.querySelectorAll('[href]')].every(a => /^https?:|^mailto:/.test(a.getAttribute('href'))));
  const attrs = [...e.querySelectorAll('*')].flatMap(n => [...n.attributes].map(a => a.name));
  check('  no handler, style, id or class attribute survives', attrs.every(a => !/^on|^style$|^id$/.test(a)) && [...e.querySelectorAll('[class]')].every(n => n.className === 'tw'));
  check('  no spoofed second #toast', app.all('[id=toast]').length === 1);
  check('  ordinary text survives', e.textContent.includes('keep this text'));
  check('  nothing executed', app.w.pwned === undefined);
};
{
  const app = boot({
    key: 'k', me: AGENT_ME,
    messages: [{ seq: 1, from_agent: 'bob', to_agent: 'alice', body: MD, ts: Date.now() }, { seq: 2, from_agent: 'bob', to_agent: 'alice', body: EVIL, ts: Date.now() }],
    over: url => {
      if (url === '/v2/wiki/md') return respond({ ...PAGE, slug: 'md', title: 'T', tags: [], body: MD, updated_by: 'bob' });
      if (url === '/v2/wiki/bad') return respond({ ...PAGE, slug: 'bad', title: 'T', tags: [], body: EVIL, updated_by: 'bob' });
      return undefined;
    },
  });
  await tick();
  const shape = (e, where) => {
    check(where + ': heading', e.querySelector('h1').textContent === 'عنوان عربي');
    check(where + ': bold and inline code', e.querySelector('strong').textContent === 'عريضة' && e.querySelector('p code').textContent === 'code');
    const a = e.querySelector('a');
    check(where + ': link opens safely', a.getAttribute('href') === 'https://example.com/x' && a.target === '_blank' && a.rel.includes('noopener') && a.rel.includes('noreferrer'));
    check(where + ': lists', e.querySelectorAll('ul li').length >= 2 && e.querySelector('ol li').textContent.trim() === 'one');
    check(where + ': code block keeps its text', e.querySelector('pre code').textContent === 'const a = 1 < 2;\n' && e.querySelector('pre').getAttribute('dir') === 'ltr');
    const tw = e.querySelector('.tw');
    check(where + ': table scrolls in its own wrapper', !!tw && tw.querySelector('table thead th').textContent === 'a' && tw.querySelector('tbody td').textContent === '1' && tw.querySelectorAll('th')[1].getAttribute('align') === 'center');
    check(where + ': each block finds its own direction', e.querySelector('h1').getAttribute('dir') === 'rtl' && [...e.querySelectorAll('p')].find(p => p.textContent.includes('English')).getAttribute('dir') === 'ltr' && e.querySelector('li').getAttribute('dir') === 'rtl' && e.querySelector('th').getAttribute('dir') === 'ltr');
    check(where + ': Arabic that opens with an English word stays right to left', [...e.querySelectorAll('p')].find(p => p.textContent.includes('RELAY')).getAttribute('dir') === 'rtl');
    check(where + ': lists and tables take their direction from their text', e.querySelector('ul').getAttribute('dir') === 'rtl' && e.querySelector('ol').getAttribute('dir') === 'ltr' && e.querySelector('table').getAttribute('dir') === 'ltr' && e.querySelector('.tw').getAttribute('dir') === 'ltr');
    check(where + ': inline code isolates itself', e.querySelector('p code').getAttribute('dir') === 'auto');
    check(where + ': task lists show a mark instead of a live input', e.textContent.includes('☑') && e.textContent.includes('☐') && !e.querySelector('input'));
    check(where + ': a single line break is kept', e.querySelectorAll('br').length >= 1);
    check(where + ': a harmless language class raises no warning', !e.parentElement.querySelector('.rawbtn'));
  };
  const [good, bad] = app.all('#log .m .b');
  shape(good, 'message');
  console.log('  hostile message:');
  evilCheck(app, bad);
  check('  the reader is told something was hidden', !!bad.parentElement.querySelector('.rawbtn'));
  const quiet = boot({ key: 'k', me: AGENT_ME, messages: [{ seq: 1, from_agent: 'bob', to_agent: 'alice', body: '<!-- only agents read this -->\n\nvisible', ts: Date.now() }] });
  await tick();
  check('  a hidden HTML comment at the very start is flagged too', !!quiet.$('log').querySelector('.rawbtn'));
  quiet.w.close();
  bad.parentElement.querySelector('.rawbtn').click(); await tick(5);
  check('  and can read all of it, inert', bad.textContent === EVIL && bad.children.length === 0 && app.w.pwned === undefined && bad.classList.contains('plain'));
  bad.parentElement.querySelector('.rawbtn').click(); await tick(5);
  check('  and go back', bad.classList.contains('plain') === false && bad.textContent.includes('keep this text') && bad.querySelectorAll('script').length === 0);
  app.all('#log .m')[0].querySelector('.copy').click(); await tick();
  check('copying a message gives the markdown source', app.copied.at(-1) === MD);

  app.$('tab-wiki').click(); await tick();
  app.w.openPage('md'); await tick();
  shape(app.$('wbody'), 'wiki');
  app.$('wcopy').click(); await tick();
  check('copying a page gives the markdown source', app.copied.at(-1) === MD);
  app.$('wedit').click(); await tick();
  check('editing starts from the markdown source', app.$('fbody').value === MD);
  app.$('fcancel').click(); await tick();
  app.w.openPage('bad'); await tick();
  console.log('  hostile wiki page:');
  evilCheck(app, app.$('wbody'));
  check('no script errors', app.errors.length === 0);
  app.w.close();
}

console.log('text direction');
{
  const app = boot({ libs: ['preact', 'htm', 'marked', 'dompurify'] });
  const dir = app.w.textDir;
  check('Arabic is right to left', dir('مرحبا بالجميع') === 'rtl');
  check('English is left to right', dir('hello everyone') === 'ltr');
  check('Arabic opening with an identifier is right to left', dir('$RELAY هو رابط القناة') === 'rtl');
  check('Arabic around a long identifier is right to left', dir('راجع suggested_poll_ms') === 'rtl');
  check('English with one Arabic word is left to right', dir('The agent named مرحبا answered every question quickly') === 'ltr');
  check('digits and symbols alone follow the page', dir('123 + 456') === 'rtl');
  app.w.close();
}

console.log('markdown under attack');
{
  const wall = '*a '.repeat(33000);
  const deep = '> '.repeat(4000) + 'x';
  const table = '| a_b | c_d |\n|---|---|\n' + '| snake_case_name | other_name_here |\n'.repeat(400);
  const app = boot({ key: 'k', me: AGENT_ME, messages: [{ seq: 1, from_agent: 'bob', to_agent: 'alice', body: deep, ts: Date.now() }, { seq: 2, from_agent: 'bob', to_agent: 'alice', body: table, ts: Date.now() }, { seq: 3, from_agent: 'bob', to_agent: 'alice', body: '*a '.repeat(1500), ts: Date.now() }], over: url => (url === '/v2/wiki/wall' ? respond({ ...PAGE, slug: 'wall', title: 'T', tags: [], body: wall, updated_by: 'bob' }) : undefined) });
  await tick(100);
  const [a, b, c] = app.all('#log .m .b');
  check('nesting that overflows the parser falls back to plain text', a.classList.contains('plain') && a.textContent === deep);
  check('a table full of snake_case still renders', !!b.querySelector('table') && b.querySelectorAll('tr').length === 401);
  check('a wall of emphasis marks stays plain', c.classList.contains('plain') && !c.querySelector('em'));
  const t = Date.now(); app.w.mdBuild(wall);
  check('a 100KB wall of marks costs no time', Date.now() - t < 200);
  app.$('tab-wiki').click(); await tick();
  app.w.openPage('wall'); await tick(100);
  check('  and such a page opens as text', app.$('wbody').textContent === wall && app.$('wbody').children.length === 0);
  check('no script errors', app.errors.length === 0);
  app.w.close();
}

console.log('loading states');
{
  let release; const gate = new Promise(r => { release = r; });
  let pageRelease; const pageGate = new Promise(r => { pageRelease = r; });
  let wikiRelease; const wikiGate = new Promise(r => { wikiRelease = r; });
  const app = boot({
    key: 'k', me: AGENT_ME, messages: [{ seq: 1, from_agent: 'bob', to_agent: 'alice', body: 'hi', ts: Date.now() }],
    over: async url => {
      if (url.startsWith('/v2/inbox')) await gate;
      if (url.startsWith('/v2/wiki?')) await wikiGate;
      if (url === '/v2/wiki/evil') await pageGate;
      return undefined;
    },
  });
  await tick();
  check('chat shows a skeleton while fetching', !!app.$('chat').querySelector('.sk-chat') && app.$('logempty').hidden);
  release(); await tick();
  check('  and it leaves when messages arrive', !app.$('chat').querySelector('.sk') && app.all('#log .m').length === 1);
  check('the first load of bubbles does not animate', !app.all('#log .m')[0].classList.contains('enter'));
  app.server.messages = [...app.server.messages, { seq: 2, from_agent: 'bob', to_agent: 'alice', body: 'next', ts: Date.now() }];
  app.w.poll(); await tick();
  check('a new bubble does', app.all('#log .m').at(-1).classList.contains('enter'));
  app.$('tab-wiki').click(); await tick();
  check('wiki list shows a skeleton while fetching', !!app.$('wiki').querySelector('.sk-cards'));
  wikiRelease(); await tick();
  check('  and it leaves', !app.$('wiki').querySelector('.sk') && app.$('wlist').children.length === 1);
  app.w.openPage('evil'); await tick();
  check('opening a page shows a skeleton', !app.$('wview').hidden && !!app.$('wview').querySelector('.sk-lines'));
  pageRelease(); await tick();
  check('  and it leaves', !app.$('wview').querySelector('.sk') && !!app.$('wbody'));
  app.w.close();
  const empty = boot({ key: 'k', me: AGENT_ME });
  await tick();
  check('an empty inbox says so instead of loading forever', !empty.$('logempty').hidden && !empty.$('chat').querySelector('.sk'));
  empty.w.close();
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
  app.$('to').click(); await tick(5);
  check('recipients are its grants only', options(app, 'to').map(o => o.dataset.value).join() === 'bob');
  key(app, app.$('to'), 'Escape'); await tick(5);
  app.$('tab-wiki').click(); await tick();
  app.server.messages = [...many, { seq: 131, from_agent: 'bob', to_agent: 'alice', body: 'new', ts: Date.now() }];
  app.w.poll(); await tick();
  check('message on another tab raises the chat badge', app.$('badge-chat').textContent === '1');
  app.$('tab-chat').click(); await tick();
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
  check('lost connection shows a banner and keeps the session', !flaky.$('net').hidden && !!flaky.$('app-view'));
  down = false; flaky.w.poll(); await tick();
  check('  the banner leaves once it is back', flaky.$('net').hidden);
  gone = true; flaky.w.poll(); await tick();
  check('revoked key returns to login with a reason', !!flaky.$('login-view') && flaky.$('login-msg').textContent.includes('لم يعد صالحاً'));
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
      if (url.startsWith('/v2/wiki?')) return respond({ pages: [{ ...PAGE }, { ...PAGE, slug: 'two', title: 'صفحة ثانية', tags: ['ops', 'infra'], updated_by: 'bob' }], quota: { pages: 2, bytes: 2048, max_pages: 200, max_bytes: 5242880 } });
      return undefined;
    },
  });
  await tick();
  app.$('tab-wiki').click(); await tick();
  check('wiki tab hides the chat and lists pages', app.$('chat').hidden && !app.$('wiki').hidden && app.$('wlist').children.length === 2);
  check('hostile title stays literal in the list', app.$('wlist').querySelector('.t').textContent === XSS);
  const line = app.$('wlist').querySelector('.d').textContent;
  check('list shows version and date', line.includes('v2') && line.includes('2023'));
  check('list shows quota use', !app.$('wquota').hidden && app.$('wquota').textContent.includes('5.0MB'));
  type(app, { wq: 'مهام & x' }); await pick(app, 'wkind', 'skill'); await tick();
  check('search and kind filter are URL-encoded', app.calls.at(-1).url === '/v2/wiki?kind=skill&q=' + encodeURIComponent('مهام & x'));
  check('the kind filter shows its choice', app.$('wkind').textContent.includes('مهارة') && app.$('wkind').dataset.value === 'skill');
  await tick(400);
  const n = app.calls.length;
  type(app, { wq: 'نص' }); ['n', 'نص'].forEach(() => app.$('wq').dispatchEvent(new app.w.Event('input', { bubbles: true }))); await tick(420);
  check('typing searches once, after a pause', app.calls.length === n + 1 && app.calls.at(-1).url.endsWith(encodeURIComponent('نص')));
  type(app, { wq: 'x' }); enter(app, 'wq'); await tick();
  check('Enter searches at once', app.calls.at(-1).url.endsWith('q=x'));
  await tick(400);
  await pick(app, 'wtag', 'ops'); await tick();
  check('tag filter goes to the server', app.calls.at(-1).url.endsWith('&tag=ops'));
  app.$('wtag').click(); await tick(5);
  check('tags stay offered after filtering', ['infra', 'ops', ''].every(t => options(app, 'wtag').some(o => o.dataset.value === t)));
  key(app, app.$('wtag'), 'Escape'); await tick(5);
  await pick(app, 'wtag', ''); await pick(app, 'wkind', ''); await tick();
  check('clearing the filters drops the tag parameter', !app.calls.at(-1).url.includes('tag='));
  app.$('wpage').click(); await tick(5);
  check('the page picker lists loaded pages', options(app, 'wpage').length === 2);
  search(app, 'wpage', 'ثانية'); await tick(5);
  check('  and finds one by title', options(app, 'wpage').map(o => o.dataset.value).join() === 'two');
  key(app, app.$('wpage'), 'Escape'); await tick(5);
  app.$('wlist').querySelector('button').click(); await tick();
  check('opening a page hides the list and bar', !app.$('wview').hidden && app.$('wlist').hidden && app.$('wbar').hidden);
  check('hostile title stays literal and hostile body is filtered', app.$('wtitle').textContent === XSS && app.$('wbody').textContent.trim() === '' && hostile(app));
  check('page shows version, editor and date', app.$('wmeta').textContent.includes('النسخة 2') && app.$('wmeta').textContent.includes(XSS) && app.$('wmeta').textContent.includes('2023'));
  check('admin sees the version count', app.all('#wtags .badge2').some(e => e.textContent === '2 نسخة'));
  app.$('whist').click(); await tick(5);
  check('admin picks a version from the same control', !app.$('whistbox').hidden && options(app, 'whist').length === 2);
  key(app, app.$('whist'), 'Escape'); await tick(5);
  app.$('wcopy').click(); await tick();
  check('copy button copies the page', app.copied.at(-1) === XSS);
  await pick(app, 'whist', 1); await tick();
  check('old version loads, filtered', app.$('wbody').textContent.trim() === 'old' && app.$('wmsg').textContent.includes('قديمة') && hostile(app));
  app.$('wcopy').click(); await tick();
  check('  copy gives that old version', app.copied.at(-1) === 'old ' + XSS);
  await pick(app, 'whist', 2); await tick();
  check('current version comes back with its badge', app.$('wbody').textContent.trim() === '' && app.all('#wtags .badge2').length === 1 && app.$('wmsg').textContent === '');
  app.$('wedit').click(); await tick();
  check('editing starts from the current version', !app.$('wform').hidden && app.$('fbody').value === XSS && app.$('fslug').disabled === true);
  type(app, { fbody: 'half written' }); app.$('tab-chat').click(); await tick(); app.$('tab-wiki').click(); await tick();
  check('switching tabs keeps a draft', !app.$('wform').hidden && app.$('fbody').value === 'half written');
  app.w.poll(); await tick();
  check('a poll does not wipe the draft', app.$('fbody').value === 'half written');
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
  app.$('wnew').click(); await tick();
  check('new page form is empty', app.$('fslug').disabled === false && app.$('fbody').value === '');
  const before = puts().length;
  type(app, { fslug: 'Bad Slug', ftitle: 't', fbody: 'b' }); app.$('fsave').click(); await tick();
  check('bad slug is caught before the server', puts().length === before && app.$('wmsg').textContent.includes('المعرّف'));
  type(app, { fslug: 'taken', ftitle: 't', fbody: 'b' }); app.$('fsave').click(); await tick();
  check('new page cannot overwrite: if_version is 0', puts().at(-1).body.if_version === 0 && app.$('wmsg').textContent.includes('مستخدم') && !app.$('wform').hidden);
  type(app, { fslug: 'secret' }); app.$('fsave').click(); await tick();
  check('server refusal is shown in Arabic and the form stays open', !app.$('wform').hidden && app.$('wmsg').textContent.includes('سراً'));
  type(app, { fslug: 'fresh' }); await pick(app, 'fkind', 'skill'); app.$('fsave').click(); await tick();
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
  agent.$('wedit').click(); await tick();
  agent.$('fkind').click(); await tick(5);
  const ctx = options(agent, 'fkind').find(o => o.dataset.value === 'context');
  check('  and context cannot be picked in the form', ctx.getAttribute('aria-disabled') === 'true');
  ctx.click(); await tick(5);
  check('  even by tapping it', agent.$('fkind').dataset.value === 'note' && agent.$('fkind').getAttribute('aria-expanded') === 'true');
  key(agent, agent.$('fkind'), 'End'); await tick(5);
  check('  and the keyboard skips it', agent.w.document.querySelector('#fkind-list .on').dataset.value === 'skill');
  check('no script errors', agent.errors.length === 0);
  agent.w.close();
}

console.log('one combobox everywhere');
{
  const app = boot({ key: 'k' });
  await tick();
  app.$('tab-wiki').click(); await tick();
  const sel = () => ['to', 'wkind', 'wtag', 'wpage'].map(id => app.$(id));
  check('recipient, kind, tag and page all use it', sel().every(e => e && e.getAttribute('role') === 'combobox' && e.classList.contains('cb-t')));
  app.w.openPage('evil'); await tick();
  check('so does the version picker', app.$('whist').classList.contains('cb-t'));
  app.$('wedit').click(); await tick();
  check('and the kind field in the form', app.$('fkind').classList.contains('cb-t'));
  check('and the page has no native select', app.all('select').length === 0);
  app.w.close();
}
process.exit(failed ? 1 : 0);
