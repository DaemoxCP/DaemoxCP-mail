// Sessions last for one start of the jar, with Strict cookies (reperto 184): with the real Chrome and the
// real server (HomePanelE2EServer, on the test VM), which the test restarts.
//
//  1. The pre-login cookie and the language cookie, as the server sets them: SameSite=Strict, and the
//     first one a browser-session cookie (no expiry).
//  2. Strict: a link from another site reaches the panel WITHOUT the session (sign-in page, without
//     saying the session has ended, because it has not); a typed address carries it.
//  3. The jar started again: the open page, at its first request, goes to the sign-in page and says
//     why; the old cookie, on a new page, leads to the sign-in page with the message and leaves the
//     browser; the new session (of the new start) opens the dashboard; the old rows removed at start.
//  4. No CSP violation and no page error.
//
// Usage: START is a command that (re)starts the server on the VM and prints its SESSION and CLOSED lines.
//   REMOTE=https://panel.localhost:2097 MAP=<VM address> START="ssh root@<vm> sh /var/tmp/sessions/serve.sh" \
//   CHROMIUM=".../Google Chrome" NODE_PATH=... node tests/session-restart-browser-test.js [screenshot-folder]
const { chromium } = require('playwright');
const { execSync } = require('child_process');
const path = require('path');
const csp = require('./browser-csp');

const E = process.env;
const shots = process.argv[2];
const url = new URL(E.REMOTE);
const UA = 'HomePanelE2EServer';   // the test session is valid only with this User-Agent (WebSessions)
let failed = 0;
function check(what, ok) {
    console.log((ok ? '  OK   ' : '  FAILED ') + what);
    if (!ok) failed++;
}

// Starts (or restarts) the server on the VM: the new session's token and how many sessions it closed.
function start() {
    const out = execSync(E.START, { encoding: 'utf8', timeout: 180000 });
    const session = (out.match(/^SESSION (\S+)$/m) || [])[1];
    const closed = Number((out.match(/^CLOSED (-?\d+)$/m) || [])[1]);
    if (!session) throw new Error('the server did not start:\n' + out);
    return { session, closed };
}

async function context(browser, token) {
    const ctx = await browser.newContext({ ignoreHTTPSErrors: true, userAgent: UA, timezoneId: 'Europe/Rome', locale: 'en-GB', viewport: { width: 1280, height: 900 } });
    if (token) await ctx.addCookies([{ name: '__Host-MailPanel', value: token, url: E.REMOTE, secure: true, httpOnly: true, sameSite: 'Strict' }]);
    return ctx;
}

async function watched(ctx, errors) {
    const page = await ctx.newPage();
    page.on('pageerror', e => errors.push(String(e)));
    csp.watch(page, errors);
    return page;
}

const ended = page => page.waitForFunction(() => {
    const a = document.getElementById('successAlert');
    return a && !a.classList.contains('d-none') && /session/i.test(a.textContent);
}, null, { timeout: 15000 }).then(() => true, () => false);

(async () => {
    const browser = await chromium.launch({ executablePath: E.CHROMIUM || undefined, args: ['--host-resolver-rules=MAP ' + url.hostname + ' ' + E.MAP] });
    const errors = [];

    console.log('== 1. The cookies the server sets ==');
    const first = start();
    const anon = await context(browser, null);
    let page = await watched(anon, errors);
    await page.goto(E.REMOTE + '/index');
    let jar = await anon.cookies();
    const pre = jar.find(c => c.name === '__Host-MailPanelPre');
    check('the pre-login cookie: Strict, HttpOnly, Secure, no expiry (' + (pre && pre.sameSite + ' ' + pre.expires) + ')',
        pre && pre.sameSite === 'Strict' && pre.httpOnly && pre.secure && pre.expires === -1);
    // The language that is not the page's: clicking the current one does nothing.
    await Promise.all([page.waitForNavigation(), page.click('button[data-set-lang][aria-pressed="false"]')]);
    jar = await anon.cookies();
    const lang = jar.find(c => c.name === '__Host-lang');
    check('the language one: Strict (' + (lang && lang.sameSite) + ')', lang && lang.sameSite === 'Strict' && lang.httpOnly && lang.secure);
    await anon.close();

    console.log('\n== 2. Strict: a link from another site ==');
    const ctxA = await context(browser, first.session);
    await ctxA.route('https://other.test/**', route => route.fulfill({ status: 200, contentType: 'text/html',
        body: '<!doctype html><title>other</title><a id="go" href="' + E.REMOTE + '/home">panel</a>' }));
    page = await watched(ctxA, errors);
    await page.goto('https://other.test/');
    await Promise.all([page.waitForNavigation(), page.click('#go')]);
    await page.waitForLoadState('load');
    check('it arrives without the session: the sign-in page (' + new URL(page.url()).pathname + ')', new URL(page.url()).pathname === '/index');
    check('  and it does not say the session has ended, because it has not', !(await page.$eval('#successAlert', a => !a.classList.contains('d-none'))));
    await page.goto(E.REMOTE + '/home');
    check('typed by hand, the same address opens the dashboard (the session is there)', new URL(page.url()).pathname === '/home'
        && await page.$('#panelInfoUptime') !== null);
    await page.waitForFunction(() => document.getElementById('panelInfoUptime').textContent.trim() !== '–', null, { timeout: 15000 });

    console.log('\n== 3. The jar started again ==');
    const second = start();
    check('at the new start the old sessions are removed from the database (' + second.closed + ')', second.closed >= 1);
    const navigated = page.waitForURL(u => new URL(u).pathname === '/index', { timeout: 15000 }).then(() => true, () => false);
    // Without waiting for the promise: the page leaves while the request comes back.
    await page.evaluate(() => { panelInfoLoad(); });
    check('the open page, at its first request, goes to the sign-in page', await navigated);
    check('  and says why: ' + (await page.$eval('#successAlert', a => a.textContent.trim()).catch(() => '')), await ended(page));
    check('  the address goes back to /index', new URL(page.url()).search === '');
    if (shots) await page.screenshot({ path: path.join(shots, 'session-ended.png') });
    await ctxA.close();

    const old = await context(browser, first.session);
    page = await watched(old, errors);
    await page.goto(E.REMOTE + '/home');
    check('the old cookie on a new page: to the sign-in page, with the message', new URL(page.url()).pathname === '/index' && await ended(page));
    check('  and the browser no longer has that cookie', !(await old.cookies()).some(c => c.name === '__Host-MailPanel'));
    await old.close();

    const fresh = await context(browser, second.session);
    page = await watched(fresh, errors);
    await page.goto(E.REMOTE + '/home');
    check('the session of the new start opens the dashboard', new URL(page.url()).pathname === '/home' && await page.$('#panelInfoUptime') !== null);
    await fresh.close();

    console.log('\n== 4. The policy ==');
    // While the server is down for the restart, the requests the dashboard makes on its own fail
    // (Failed to fetch): that happened before too, and it is not what this test is about. Counted apart.
    const down = errors.filter(e => /Failed to fetch/.test(e));
    if (down.length) console.log('    (requests failed while the server was down for the restart: ' + down.length + ')');
    const real = errors.filter(e => !/Failed to fetch/.test(e));
    check('no CSP violation and no page error' + (real.length ? ': ' + real.slice(0, 3).join(' | ') : ''), real.length === 0);
    await browser.close();
    console.log(failed === 0 ? '\nALL GREEN' : '\n' + failed + ' CHECKS FAILED');
    process.exit(failed === 0 ? 0 : 1);
})().catch(e => { console.error(e); process.exit(1); });
