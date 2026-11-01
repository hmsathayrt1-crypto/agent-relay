// Drives real headless Chrome over the DevTools protocol against a running relay. Covers what jsdom can't:
// CSP and integrity enforcement, real CDN loading, computed colours, layout and touch.
//
//   BASE=https://relay.example RELAY_KEY=ark_... [SHOTS=dir] [WRITES=1] node test/browser-check.mjs
//
// Safe on production by default: the key logs in and reads /v2/me and the wiki, the chat shows made-up messages,
// and every other /v2 call is stopped inside the browser, so no cursor, ack or message changes on the relay.
// WRITES=1 lets everything through and sends real messages. Use it only against a throwaway local relay.
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

const BASE = (process.env.BASE || '').replace(/\/$/, ''); const KEY = process.env.RELAY_KEY || '';
const SHOTS = process.env.SHOTS || ''; const WRITES = process.env.WRITES === '1';
const CHROME = process.env.CHROME || '/usr/bin/google-chrome';
if (!BASE || !KEY) { console.error('set BASE and RELAY_KEY'); process.exit(2); }
if (SHOTS) mkdirSync(SHOTS, { recursive: true });

let failed = 0; let passed = 0;
const check = (name, cond, extra) => { if (cond) passed++; else failed++; console.log((cond ? '  ✓ ' : '  ✗ ') + name + (!cond && extra !== undefined ? ' -> ' + JSON.stringify(extra).slice(0, 300) : '')); };

const profile = mkdtempSync(join(tmpdir(), 'browser-check-'));
const proc = spawn(CHROME, ['--headless=new', '--no-sandbox', '--disable-gpu', '--no-first-run', '--remote-debugging-port=0', '--user-data-dir=' + profile, 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] });
const wsUrl = await new Promise((res, rej) => {
  let err = ''; const t = setTimeout(() => rej(new Error('chrome did not start: ' + err)), 20000);
  proc.stderr.on('data', d => { err += d; const m = err.match(/DevTools listening on (ws:\S+)/); if (m) { clearTimeout(t); res(m[1]); } });
});
const ws = new WebSocket(wsUrl);
await new Promise(r => ws.addEventListener('open', r));
let seq = 0; const waiting = new Map(); const handlers = new Map();
ws.addEventListener('message', e => {
  const m = JSON.parse(e.data);
  if (m.id) { const w = waiting.get(m.id); waiting.delete(m.id); if (m.error) w.rej(new Error(m.error.message)); else w.res(m.result); return; }
  (handlers.get(m.method) || []).forEach(f => f(m.params));
});
const raw = (method, params = {}, sessionId) => new Promise((res, rej) => { const id = ++seq; waiting.set(id, { res, rej }); ws.send(JSON.stringify({ id, method, params, sessionId })); });
const on = (method, f) => handlers.set(method, [...(handlers.get(method) || []), f]);
const { targetId } = await raw('Target.createTarget', { url: 'about:blank' });
const { sessionId } = await raw('Target.attachToTarget', { targetId, flatten: true });
const cdp = (method, params) => raw(method, params, sessionId);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const js = async expr => {
  const r = await cdp('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true });
  if (r.exceptionDetails) throw new Error(expr.slice(0, 80) + ': ' + JSON.stringify(r.exceptionDetails).slice(0, 300));
  return r.result.value;
};
const until = async (expr, ms = 8000) => { const end = Date.now() + ms; while (Date.now() < end) { if (await js(expr)) return true; await sleep(40); } return false; };
const shot = async name => { if (!SHOTS) return; const { data } = await cdp('Page.captureScreenshot', { format: 'png' }); writeFileSync(join(SHOTS, name + '.png'), Buffer.from(data, 'base64')); };
const center = sel => js(`(()=>{const e=document.querySelector(${JSON.stringify(sel)});if(!e)return null;e.scrollIntoView({block:'nearest'});const r=e.getBoundingClientRect();return {x:r.left+r.width/2,y:r.top+r.height/2};})()`);
const tap = async sel => { const p = await center(sel); if (!p) throw new Error('nothing to tap: ' + sel); await cdp('Input.dispatchTouchEvent', { type: 'touchStart', touchPoints: [p] }); await cdp('Input.dispatchTouchEvent', { type: 'touchEnd', touchPoints: [] }); await sleep(60); };
const click = async sel => { const p = await center(sel); if (!p) throw new Error('nothing to click: ' + sel); for (const type of ['mouseMoved', 'mousePressed', 'mouseReleased']) await cdp('Input.dispatchMouseEvent', { type, ...p, button: type === 'mouseMoved' ? 'none' : 'left', clickCount: type === 'mouseMoved' ? 0 : 1 }); await sleep(60); };
const press = async (key, code = key, vk = 0) => { for (const type of ['keyDown', 'keyUp']) await cdp('Input.dispatchKeyEvent', { type, key, code, windowsVirtualKeyCode: vk, nativeVirtualKeyCode: vk }); await sleep(40); };
const insert = async text => { await cdp('Input.insertText', { text }); await sleep(40); };
const setValue = (sel, v) => js(`(()=>{const e=document.querySelector(${JSON.stringify(sel)});e.value=${JSON.stringify(v)};e.dispatchEvent(new Event('input',{bubbles:true}));})()`);

// Everything the page complains about while a stage runs.
let complaints = [];
on('Runtime.exceptionThrown', p => complaints.push('exception: ' + (p.exceptionDetails.exception?.description || p.exceptionDetails.text)));
on('Runtime.consoleAPICalled', p => { if (p.type === 'error') complaints.push('console: ' + p.args.map(a => a.value || a.description).join(' ')); });
on('Log.entryAdded', p => { if (p.entry.level === 'error' && !/favicon/.test(p.entry.url || '')) complaints.push('log: ' + p.entry.text + ' ' + (p.entry.url || '')); });
await cdp('Page.enable'); await cdp('Runtime.enable'); await cdp('Log.enable'); await cdp('Network.enable');

const SAMPLE = ['## عنوان الرسالة', '', 'فقرة عربية فيها **عريض** و`code` ورابط [هنا](https://example.com/a).', '', 'An English paragraph keeps its own direction.', '', '`$RELAY` هو رابط القناة، و`$KEY` هو مفتاحك.', '', '- بند أول', '- second item', '', '```js', 'const longLine = "a code block with a line far wider than any phone screen, which must scroll on its own";', '```', '', '| الاسم | القيمة | الحالة | المسؤول | الإصدار | التاريخ | الملاحظات |', '|---|---|---|---|---|---|---|', '| claude-code | 1 | مكتملة | hermes | 10.29.8 | 2026-11-01 | تتجاوز عرض الهاتف |'].join('\n');
const STYLE = 'body{display:none}';
const HOSTILE = `<script>window.pwned=1</script><img src=x onerror="window.pwned=2"><style>${STYLE}</style>\n\n[x](javascript:window.pwned=3) ظاهر`;
// DOMPurify parses that <style> in a detached document, and Chrome reports the CSP refusing it there. The block is the point, so it is the one report allowed.
const styleHash = 'sha256-' + createHash('sha256').update(STYLE).digest('base64');
const realComplaints = () => complaints.filter(c => !c.includes(styleHash));
let me = '';
const sample = () => { const t = Date.now(); const m = (seq, from, to, body, ago) => ({ seq, from_agent: from, to_agent: to, body, ts: t - ago, kind: 'msg' }); return [
  m(1, 'muse', me, 'صباح الخير، هل انتهت المهمة؟', 900000), m(2, me, 'muse', 'نعم، انتهت قبل قليل.', 800000),
  m(3, 'claude-code', me, SAMPLE, 700000), m(4, 'github-bot', me, 'build failed on main', 600000), m(5, 'github-bot', me, 'build failed on main', 500000),
  m(6, me, 'claude-code', 'راجع `src/page.html` رجاءً', 450000), m(7, 'github-bot', me, 'build failed on main', 400000), m(8, 'carol', me, HOSTILE, 300000), m(9, me, '__all__', 'تنبيه للجميع', 200000),
]; };
let stopped = 0; let synth = true;
// Fetch interception is what keeps this read-only on production.
on('Fetch.requestPaused', async p => {
  const u = new URL(p.request.url); const id = p.requestId;
  const reply = (body, status = 200) => cdp('Fetch.fulfillRequest', { requestId: id, responseCode: status, responseHeaders: [{ name: 'Content-Type', value: 'application/json' }], body: Buffer.from(JSON.stringify(body)).toString('base64') });
  if (u.origin !== new URL(BASE).origin) {
    if (tamper && u.pathname.includes('preact.min.umd')) return cdp('Fetch.fulfillRequest', { requestId: id, responseCode: 200, responseHeaders: [{ name: 'Content-Type', value: 'application/javascript' }, { name: 'Access-Control-Allow-Origin', value: '*' }], body: Buffer.from('window.tampered=1;').toString('base64') });
    return cdp('Fetch.continueRequest', { requestId: id });
  }
  if (!u.pathname.startsWith('/v2/') || WRITES) return cdp('Fetch.continueRequest', { requestId: id });
  if (u.pathname === '/v2/inbox' || u.pathname === '/v2/log') { const after = Number(u.searchParams.get('after')) || 0; const rows = synth ? sample().filter(m => m.seq > after) : []; return reply({ agent: me, messages: rows, next_after: rows.length ? rows.at(-1).seq : after, suggested_poll_ms: 60000 }); }
  if (p.request.method !== 'GET') { stopped++; return reply({ ok: true }); }
  return cdp('Fetch.continueRequest', { requestId: id });
});
let tamper = false;
await cdp('Fetch.enable', { patterns: [{ urlPattern: '*' }] });
// A fresh tab is still committing about:blank, and that can cancel or stall the first navigation, so this retries.
const load = async () => {
  for (let i = 0; i < 4; i++) {
    await Promise.race([cdp('Page.navigate', { url: BASE + '/' }), sleep(4000)]);
    if (await until(`location.href.startsWith(${JSON.stringify(BASE)})`, 4000)) return;
  }
  throw new Error('navigation never committed');
};
const phone = async () => { await cdp('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 2, mobile: true }); await cdp('Emulation.setTouchEmulationEnabled', { enabled: true, maxTouchPoints: 1 }); };
const desktop = async () => { await cdp('Emulation.setTouchEmulationEnabled', { enabled: false }); await cdp('Emulation.setDeviceMetricsOverride', { width: 1280, height: 860, deviceScaleFactor: 1, mobile: false }); };
const login = async () => {
  await until(`!!document.querySelector('#key')`);
  await setValue('#key', KEY);
  await js(`document.querySelector('#login').click()`);
  return until(`!!document.querySelector('#app-view')`);
};

try {
  console.log('real browser: load and CSP');
  await phone();
  const res = await fetch(BASE + '/'); const csp = res.headers.get('content-security-policy') || ''; const page = await res.text();
  const nonce = (csp.match(/script-src 'nonce-([0-9a-f]+)'/) || [])[1];
  check('CSP has a nonce and names the CDN files', !!nonce && /cdn\.jsdelivr\.net\/npm\/preact@/.test(csp) && csp.startsWith("default-src 'none'; script-src 'nonce-"));
  check('CSP names exact files, not the whole CDN', !/cdn\.jsdelivr\.net(\/npm\/)?( |;)/.test(csp));
  check('the page carries that nonce and the CDN tags', page.includes(`<style nonce="${nonce}">`) && page.includes(`<script nonce="${nonce}">`) && (page.match(/<script src="https:\/\/cdn\.jsdelivr\.net[^>]+integrity="sha384-/g) || []).length === 5);
  await load();
  check('libraries pass integrity and load under CSP', await until(`!!(window.preact&&window.preactHooks&&window.htm&&window.marked&&window.DOMPurify)`, 15000));
  check('the login screen renders', await until(`!!document.querySelector('#login-view')`));
  check('no console errors or CSP violations on load', complaints.length === 0, complaints);
  await shot('01-login-phone');

  console.log('login and chat on a phone');
  const who = await fetch(BASE + '/v2/me', { headers: { Authorization: 'Bearer ' + KEY } });
  me = who.ok ? (await who.json()).agent : '';
  check('the key is valid', !!me);
  const logged = await login();
  check('the key logs in', logged, complaints);
  check('touch device reports a coarse pointer', await js(`matchMedia('(pointer:coarse)').matches`));
  if (!WRITES) {
    await until(`document.querySelectorAll('#log .m').length>=7`);
    await sleep(350);
    check('messages render as bubbles', await js(`document.querySelectorAll('#log .m').length`) === 7);
    const layout = await js(`(()=>{const W=document.documentElement.clientWidth;const rows=[...document.querySelectorAll('#log .m')];const box=s=>s.getBoundingClientRect();
      const side=m=>{const r=box(m.querySelector('.bb'));return {left:r.left,right:r.right,mine:m.classList.contains('mine')};};const s=rows.map(side);
      return {W,mines:s.filter(x=>x.mine).length,others:s.filter(x=>!x.mine).length,minesRight:s.filter(x=>x.mine).every(x=>W-x.right<70),othersLeft:s.filter(x=>!x.mine).every(x=>x.left<70),
        avatarsOut:rows.every(m=>{const a=box(m.querySelector('svg.av')),b=box(m.querySelector('.bb'));return m.classList.contains('mine')?a.left>=b.right-1:a.right<=b.left+1;}),
        namesAbove:rows.every(m=>box(m.querySelector('.h')).bottom<=box(m.querySelector('.bb')).top+1),
        over:document.documentElement.scrollWidth-W,logOver:document.querySelector('#logbox').scrollWidth-document.querySelector('#logbox').clientWidth,
        gaps:rows.slice(1).map((m,i)=>box(m).top-box(rows[i]).bottom)};})()`);
    check('your bubbles sit on the right', layout.mines === 3 && layout.minesRight, layout);
    check('everyone else sits on the left', layout.others === 4 && layout.othersLeft, layout);
    check('avatars sit on the outer edge', layout.avatarsOut);
    check('name and time sit above each bubble', layout.namesAbove);
    check('bubbles are spaced apart', layout.gaps.every(g => g >= 14), layout.gaps);
    check('no sideways scrolling, even with long code and tables', layout.over <= 0 && layout.logOver <= 0, layout);
    const type = await js(`(()=>{const c=getComputedStyle(document.querySelector('#log .b'));return {size:parseFloat(c.fontSize),lh:parseFloat(c.lineHeight)};})()`);
    check('message text is 16px with a roomy line height', type.size === 16 && type.lh >= 24, type);
    const paint = await js(`(()=>{const rgb=(s,p)=>getComputedStyle(s)[p];const by=n=>[...document.querySelectorAll('#log .m')].find(m=>m.querySelector('.w bdi')?.textContent===n);
      const row=n=>{const m=by(n);return {bg:rgb(m.querySelector('.bb'),'backgroundColor'),border:rgb(m.querySelector('.bb'),'borderTopColor'),name:rgb(m.querySelector('.w .nm'),'color'),disc:rgb(m.querySelector('svg.av circle'),'fill')};};
      return {muse:row('muse'),code:row('claude-code'),bot:row('github-bot')};})()`);
    check('each agent has its own bubble, name and avatar colour', new Set([paint.muse.bg, paint.code.bg, paint.bot.bg]).size === 3 && new Set([paint.muse.disc, paint.code.disc, paint.bot.disc]).size === 3 && new Set([paint.muse.name, paint.code.name, paint.bot.name]).size === 3, paint);
    check('name and avatar use the same colour', paint.muse.name === paint.muse.disc && paint.code.name === paint.code.disc, paint);
    const md = await js(`(()=>{const b=[...document.querySelectorAll('#log .b')].find(e=>e.querySelector('h2'));const dir=e=>getComputedStyle(e).direction;const ps=[...b.querySelectorAll('p')];const tw=b.querySelector('.tw');const pre=b.querySelector('pre');
      return {mixed:dir(ps[2]),ul:dir(b.querySelector('ul')),h2:parseFloat(getComputedStyle(b.querySelector('h2')).fontSize),ar:dir(ps[0]),en:dir(ps[1]),pre:dir(pre),cellLines:(()=>{const th=b.querySelector('th');const c=getComputedStyle(th);return Math.round((th.clientHeight-parseFloat(c.paddingTop)-parseFloat(c.paddingBottom))/parseFloat(c.lineHeight));})(),preScrolls:pre.scrollWidth>pre.clientWidth,twScrolls:tw.scrollWidth>tw.clientWidth,tableDir:dir(tw.querySelector('table')),codeBg:getComputedStyle(b.querySelector('p code')).backgroundColor};})()`);
    check('Markdown heading is bigger than the text', md.h2 > 16, md);
    check('an Arabic paragraph runs right to left, an English one left to right', md.ar === 'rtl' && md.en === 'ltr', md);
    check('Arabic that opens with an English word stays right to left', md.mixed === 'rtl', md);
    check('code stays left to right and scrolls by itself', md.pre === 'ltr' && md.preScrolls, md);
    check('a wide table scrolls by itself and keeps Arabic direction', md.twScrolls && md.tableDir === 'rtl', md);
    check('  its words are not broken into letters', md.cellLines <= 1, md);
    check('an Arabic list stays right to left, marker included', md.ul === 'rtl' && await js(`(()=>{const u=[...document.querySelectorAll('#log .b ul')][0];const b=u.closest('.bb').getBoundingClientRect();const l=u.getBoundingClientRect();return l.left>=b.left&&l.right<=b.right;})()`), md);
    check('hostile message: nothing ran, no element, the text around it shows', await js(`window.pwned===undefined&&document.querySelectorAll('#log img,#log script,#log style').length===0&&getComputedStyle(document.body).display!=='none'&&[...document.querySelectorAll('#log .b')].some(b=>b.textContent.includes('ظاهر'))`));
    check('  its bad link has no href', await js(`[...document.querySelectorAll('#log .b a')].every(a=>!/^javascript/i.test(a.getAttribute('href')||''))`));
    await shot('02-chat-phone');
    const scrollTop = await js(`document.querySelector('#logbox').scrollTop=0`); void scrollTop;
    await sleep(50); await shot('03-chat-phone-top');
    await js(`document.querySelector('#logbox').scrollTop=1e6`);

    console.log('duplicates and confirmation');
    check('a repeated message shows one bubble with ×3', await js(`[...document.querySelectorAll('#log .rep')].map(b=>b.textContent).join()`) === '×3');
    await tap('#log .rep');
    check('tapping the badge lists the copies with times', await until(`document.querySelectorAll('#log .copies li').length===3`));
    await shot('04-duplicates-phone');
    await tap('#log .rep');
    check('the confirmation names the recipient with an avatar', await js(`[...document.querySelectorAll('#log .mine .ok')].some(o=>o.textContent.includes('وصلت إلى')&&o.textContent.includes('muse')&&o.querySelector('svg.av'))`));
  }

  console.log('combobox by touch');
  const peers = await js(`S.recipients.length`);
  if (peers) {
    await tap('#to');
    check('tapping opens the list', await until(`document.querySelector('#to').getAttribute('aria-expanded')==='true'`));
    check('on touch the search box waits, so no keyboard jumps up', await js(`document.activeElement!==document.querySelector('.cb-s')`));
    await sleep(220);
    const geo = await js(`(()=>{const p=document.querySelector('.cb-p').getBoundingClientRect();return {top:p.top,bottom:p.bottom,left:p.left,right:p.right,W:innerWidth,H:innerHeight,up:document.querySelector('.cb-p').classList.contains('up')};})()`);
    check('the list opens upward and stays on screen', geo.up && geo.top >= 0 && geo.bottom <= geo.H && geo.left >= 0 && geo.right <= geo.W, geo);
    await shot('05-combobox-phone');
    const n = await js(`document.querySelectorAll('#to-list [role=option]').length`);
    const name = await js(`document.querySelector('#to-list [role=option]').dataset.value`);
    await tap('.cb-s'); await insert(name.slice(0, 3));
    check('search narrows the list', await until(`document.querySelectorAll('#to-list [role=option]').length<=${n}&&[...document.querySelectorAll('#to-list [role=option]')].some(o=>o.dataset.value===${JSON.stringify(name)})`));
    await tap(`#to-list [data-value="${name}"]`);
    check('tapping an option picks it', await until(`document.querySelector('#to').dataset.value===${JSON.stringify(name)}&&!document.querySelector('.cb-p')`));
    check('the composer takes the recipient colour', await js(`getComputedStyle(document.querySelector('#bar')).borderTopColor===getComputedStyle(document.querySelector('#to svg.av circle')).fill`));
    await setValue('#txt', 'to:'); await sleep(60);
    check('typing to: offers recipients with avatars', await js(`document.querySelectorAll('#tohints .hint svg.av').length>0`));
    await shot('06-to-hints-phone');
    await setValue('#txt', 'to:' + (name === '__all__' ? 'all' : name) + ' مرحبا'); await sleep(60);
    check('a full name selects the recipient and hides the hints', await js(`document.querySelector('#to').dataset.value===${JSON.stringify(name)}&&!document.querySelector('#tohints')`));
    await setValue('#txt', ''); await sleep(30);
  } else console.log('  - this key has no recipients, so the recipient list stays disabled');

  console.log('wiki on a phone');
  await tap('#tab-wiki');
  check('the tab opens with a transition', await until(`!document.querySelector('#wiki').hidden&&getComputedStyle(document.querySelector('#wiki')).animationName==='panel-in'`));
  check('pages load', await until(`document.querySelectorAll('#wlist .wi').length>0||(document.querySelector('#wmsg').textContent||'').length>0`));
  const pages = await js(`document.querySelectorAll('#wlist .wi').length`);
  await sleep(240);
  await shot('07-wiki-list-phone');
  if (pages) {
    check('each page shows its editor in colour', await js(`[...document.querySelectorAll('#wlist .wi')].every(w=>w.querySelector('svg.av')&&w.querySelector('.nm'))`));
    await tap('#wkind');
    await until(`!!document.querySelector('#wkind-list')`); await sleep(220);
    await shot('08-wiki-filter-phone');
    check('the kind filter opens inside the screen', await js(`(()=>{const r=document.querySelector('#wkind').closest('.cb').querySelector('.cb-p').getBoundingClientRect();return r.left>=0&&r.right<=innerWidth&&r.bottom<=innerHeight;})()`));
    await tap('#wkind');
    await until(`!document.querySelector('#wkind-list')`);
    const best = await js(`(()=>{const w=[...document.querySelectorAll('#wlist .wi')];const i=w.findIndex(b=>/getting-started|conventions/.test(b.textContent));return i<0?0:i;})()`);
    await tap(`#wlist .wi:nth-child(${best + 1})`);
    check('opening a page renders Markdown', await until(`!!document.querySelector('#wbody')`));
    const wiki = await js(`(()=>{const b=document.querySelector('#wbody');const els=[...b.querySelectorAll('*')];return {tags:[...new Set(els.map(e=>e.nodeName))].join(),len:b.textContent.length,raw:!!document.querySelector('.rawbtn'),bad:b.querySelectorAll('script,img,style,iframe').length,over:document.querySelector('#wscroll').scrollWidth-document.querySelector('#wscroll').clientWidth,blocksDir:[...b.querySelectorAll('p,li,h1,h2,h3')].every(e=>['rtl','ltr'].includes(e.getAttribute('dir')))};})()`);
    check('the page has rendered blocks and text', wiki.len > 0 && wiki.tags.length > 0, wiki);
    check('every block sets its own direction', wiki.blocksDir, wiki);
    check('nothing unsafe and no sideways scrolling', wiki.bad === 0 && wiki.over <= 0, wiki);
    console.log('    rendered tags: ' + wiki.tags);
    await sleep(200);
    await shot('09-wiki-page-phone');
  }
  check('no console errors or CSP violations on a phone', realComplaints().length === 0, realComplaints());
  complaints = [];

  console.log('reduced motion');
  await cdp('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: 'reduce' }] });
  check('animations are off', await js(`getComputedStyle(document.querySelector('.panel:not([hidden])')).animationName==='none'&&getComputedStyle(document.querySelector('#logout')).transitionDuration==='0s'`));
  await cdp('Emulation.setEmulatedMedia', { features: [] });

  console.log('desktop and keyboard');
  await desktop();
  await js(`sessionStorage.setItem('rk',${JSON.stringify(KEY)})`);
  await load();
  await until(`!!document.querySelector('#app-view')`);
  await sleep(300);
  // Headless Linux has no mouse and reports pointer:none, so the search box only autofocuses on a machine that reports a fine pointer.
  const fine = await js(`matchMedia('(pointer:fine)').matches`);
  if (peers) {
    await click('#to');
    if (fine) check('the search box takes focus', await until(`document.activeElement===document.querySelector('.cb-s')`));
    const hoverable = await js(`document.querySelectorAll('#to-list [role=option]').length`);
    if (hoverable > 1) {
      const before = await js(`document.querySelector('#to-list .on')?.dataset.value`);
      await press('ArrowDown', 'ArrowDown', 40);
      check('arrow keys move the active option', await js(`document.querySelector('#to-list .on')?.dataset.value`) !== before);
      await click('#to-list [role=option]:last-child');
      await sleep(120);
    } else await press('Escape', 'Escape', 27);
    await sleep(200);
    await click('#to'); await sleep(200);
    await press('Escape', 'Escape', 27);
    check('Escape closes and focus returns', await until(`!document.querySelector('.cb-p')&&document.activeElement===document.querySelector('#to')`));
    await click('#to'); await sleep(40);
    await click('#to-list [role=option]');
    check('a mouse click picks an option and closes', await until(`!document.querySelector('.cb-p')`));
  }
  await shot('10-chat-desktop');
  if (!WRITES) check('no message or ack reached the relay', stopped >= 1 && await js(`document.querySelectorAll('#log .m').length`) >= 7, stopped);
  check('no console errors or CSP violations on desktop', realComplaints().length === 0, realComplaints());
  complaints = [];

  if (WRITES && peers) {
    console.log('real round trip');
    const to = await js(`S.recipients[0]`);
    await click('#txt');
    await insert('to:' + (to === '__all__' ? 'all' : to) + ' **رسالة** تجريبية'); await sleep(50);
    await click('#send');
    check('a sent message comes back as my bubble', await until(`[...document.querySelectorAll('#log .m.mine .b strong')].some(e=>e.textContent==='رسالة')`));
    check('  confirming the recipient', await until(`[...document.querySelectorAll('#log .m.mine .ok')].some(o=>o.textContent.includes(${JSON.stringify(to === '__all__' ? 'الكل' : to)}))`));
    check('  and the box is empty', await js(`document.querySelector('#txt').value===''`));
    await click('#txt'); await insert('تكرار'); await click('#send'); await sleep(300);
    await click('#txt'); await insert('تكرار'); await click('#send');
    check('the same text twice is one bubble with ×2', await until(`[...document.querySelectorAll('#log .rep')].some(b=>b.textContent==='×2')`));
    await shot('11-roundtrip-desktop');
    check('no console errors in the round trip', complaints.length === 0, complaints);
    complaints = [];
  }

  console.log('CSP really blocks');
  await js(`window.__csp=[];document.addEventListener('securitypolicyviolation',e=>window.__csp.push(e.effectiveDirective+' '+e.blockedURI))`);
  await js(`(()=>{const s=document.createElement('script');s.textContent='window.inlineRan=1';document.body.appendChild(s);})()`);
  await sleep(80);
  check('an inline script without the nonce does not run', await js(`window.inlineRan===undefined&&window.__csp.some(v=>v.startsWith('script-src'))`));
  await js(`new Promise(r=>{const s=document.createElement('script');s.src='https://cdn.jsdelivr.net/npm/htm@3.1.0/dist/htm.umd.js';s.onload=()=>{window.otherLoaded=1;r();};s.onerror=()=>r();document.body.appendChild(s);})`);
  check('another file on the same CDN is refused', await js(`window.otherLoaded===undefined&&window.__csp.some(v=>v.includes('htm@3.1.0'))`));
  check('a request to another origin is refused', await js(`fetch('https://example.com/').then(()=>false,()=>true)`));
  await js(`(()=>{const d=document.createElement('div');d.id='t-style';d.setAttribute('style','color:rgb(1,2,3)');document.body.appendChild(d);})()`);
  check('a style attribute parsed from markup is refused', await js(`getComputedStyle(document.querySelector('#t-style')).color!=='rgb(1, 2, 3)'`));
  complaints = [];

  console.log('a tampered or missing CDN file');
  await cdp('Network.setCacheDisabled', { cacheDisabled: true });
  tamper = true; await js(`sessionStorage.clear()`); await load();
  check('a changed file fails its integrity check and does not run', await until(`document.querySelector('#boot-msg')?.textContent.includes('تعذر تحميل')`) && await js(`window.tampered===undefined&&!window.preact`));
  check('  and no key field is offered to a broken page', await js(`!document.querySelector('#key')`));
  check('  the browser reported the integrity failure', complaints.some(c => /integrity/i.test(c)), complaints);
  await shot('12-cdn-failure');
  tamper = false; complaints = [];
  await cdp('Network.setBlockedURLs', { urls: ['*cdn.jsdelivr.net*'] });
  await load();
  check('a blocked CDN shows the same clear message', await until(`document.querySelector('#boot-msg')?.textContent.includes('تعذر تحميل')`));
  await cdp('Network.setBlockedURLs', { urls: [] });
  complaints = [];
  await load();
  check('it recovers once the CDN is back', await until(`!!document.querySelector('#login-view')`, 15000));
} catch (e) {
  failed++; console.log('  ✗ the run stopped: ' + e.message);
} finally {
  await Promise.race([raw('Browser.close').catch(() => {}), sleep(800)]);
  proc.kill('SIGKILL');
  await sleep(100);
  rmSync(profile, { recursive: true, force: true });
}
console.log(`\nbrowser-check: ${passed} passed, ${failed} failed${WRITES ? '' : `, ${stopped} writes stopped inside the browser`}`);
process.exit(failed ? 1 : 0);
