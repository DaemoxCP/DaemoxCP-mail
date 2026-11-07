// Le sessioni valgono per un avvio solo del jar, coi cookie Strict (reperto 184): col Chrome vero e il
// server vero (HomePanelE2EServer, sulla VM), che la prova riavvia.
//
//  1. Il cookie di prima dell'accesso e quello della lingua, come li mette il server: SameSite=Strict,
//     e il primo di sessione del browser (nessuna scadenza).
//  2. Strict: un link da un altro sito arriva al pannello SENZA sessione (pagina d'accesso, senza
//     dire che la sessione e' finita, perche' non lo e'); un indirizzo scritto a mano la porta.
//  3. Il jar riavviato: la pagina aperta, alla prima richiesta, va all'accesso e dice perche'; il
//     cookie di prima, su una pagina nuova, porta all'accesso col messaggio e se ne va dal browser;
//     la sessione nuova (del nuovo avvio) apre la dashboard; le righe di prima tolte all'avvio.
//  4. Nessuna violazione della CSP e nessun errore nelle pagine.
//
// Uso: START e' un comando che (ri)avvia il server sulla VM e stampa le sue righe SESSION e CLOSED.
//   REMOTE=https://panel.localhost:2097 MAP=<indirizzo della VM> START="ssh root@<vm> sh /var/tmp/sessions/serve.sh" \
//   CHROMIUM=".../Google Chrome" NODE_PATH=... node tests/session-restart-browser-test.js [cartella-per-le-immagini]
const { chromium } = require('playwright');
const { execSync } = require('child_process');
const path = require('path');
const csp = require('./browser-csp');

const E = process.env;
const shots = process.argv[2];
const url = new URL(E.REMOTE);
const UA = 'HomePanelE2EServer';   // la sessione di prova vale solo con questo User-Agent (WebSessions)
let failed = 0;
function check(what, ok) {
    console.log((ok ? '  OK   ' : '  FALLITO ') + what);
    if (!ok) failed++;
}

// Avvia (o riavvia) il server sulla VM: il token della sessione nuova e quante ne ha tolte.
function start() {
    const out = execSync(E.START, { encoding: 'utf8', timeout: 180000 });
    const session = (out.match(/^SESSION (\S+)$/m) || [])[1];
    const closed = Number((out.match(/^CLOSED (-?\d+)$/m) || [])[1]);
    if (!session) throw new Error('il server non e\' partito:\n' + out);
    return { session, closed };
}

async function context(browser, token) {
    const ctx = await browser.newContext({ ignoreHTTPSErrors: true, userAgent: UA, timezoneId: 'Europe/Rome', viewport: { width: 1280, height: 900 } });
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

    console.log('== 1. I cookie che mette il server ==');
    const first = start();
    const anon = await context(browser, null);
    let page = await watched(anon, errors);
    await page.goto(E.REMOTE + '/index');
    let jar = await anon.cookies();
    const pre = jar.find(c => c.name === '__Host-MailPanelPre');
    check('il cookie di prima dell\'accesso: Strict, HttpOnly, Secure, senza scadenza (' + (pre && pre.sameSite + ' ' + pre.expires) + ')',
        pre && pre.sameSite === 'Strict' && pre.httpOnly && pre.secure && pre.expires === -1);
    await page.click('button[data-set-lang="en"]');
    await page.waitForLoadState('load');
    jar = await anon.cookies();
    const lang = jar.find(c => c.name === '__Host-lang');
    check('quello della lingua: Strict (' + (lang && lang.sameSite) + ')', lang && lang.sameSite === 'Strict' && lang.httpOnly && lang.secure);
    await anon.close();

    console.log('\n== 2. Strict: un link da un altro sito ==');
    const ctxA = await context(browser, first.session);
    await ctxA.route('https://other.test/**', route => route.fulfill({ status: 200, contentType: 'text/html',
        body: '<!doctype html><title>altro</title><a id="go" href="' + E.REMOTE + '/home">pannello</a>' }));
    page = await watched(ctxA, errors);
    await page.goto('https://other.test/');
    await Promise.all([page.waitForNavigation(), page.click('#go')]);
    await page.waitForLoadState('load');
    check('arriva senza sessione: la pagina d\'accesso (' + new URL(page.url()).pathname + ')', new URL(page.url()).pathname === '/index');
    check('  e non dice che la sessione e\' finita, perche\' non lo e\'', !(await page.$eval('#successAlert', a => !a.classList.contains('d-none'))));
    await page.goto(E.REMOTE + '/home');
    check('scritto a mano, lo stesso indirizzo apre la dashboard (la sessione c\'e\')', new URL(page.url()).pathname === '/home'
        && await page.$('#panelInfoUptime') !== null);
    await page.waitForFunction(() => document.getElementById('panelInfoUptime').textContent.trim() !== '–', null, { timeout: 15000 });

    console.log('\n== 3. Il jar riavviato ==');
    const second = start();
    check('al nuovo avvio le sessioni di prima tolte dal database (' + second.closed + ')', second.closed >= 1);
    const navigated = page.waitForURL(u => new URL(u).pathname === '/index', { timeout: 15000 }).then(() => true, () => false);
    // Senza aspettare la promessa: la pagina se ne va mentre la richiesta torna.
    await page.evaluate(() => { panelInfoLoad(); });
    check('la pagina aperta, alla prima richiesta, va all\'accesso', await navigated);
    check('  e dice perche\': ' + (await page.$eval('#successAlert', a => a.textContent.trim()).catch(() => '')), await ended(page));
    check('  l\'indirizzo torna /index', new URL(page.url()).search === '');
    if (shots) await page.screenshot({ path: path.join(shots, 'session-ended.png') });
    await ctxA.close();

    const old = await context(browser, first.session);
    page = await watched(old, errors);
    await page.goto(E.REMOTE + '/home');
    check('il cookie di prima su una pagina nuova: all\'accesso, col messaggio', new URL(page.url()).pathname === '/index' && await ended(page));
    check('  e il browser non ha piu\' quel cookie', !(await old.cookies()).some(c => c.name === '__Host-MailPanel'));
    await old.close();

    const fresh = await context(browser, second.session);
    page = await watched(fresh, errors);
    await page.goto(E.REMOTE + '/home');
    check('la sessione del nuovo avvio apre la dashboard', new URL(page.url()).pathname === '/home' && await page.$('#panelInfoUptime') !== null);
    await fresh.close();

    console.log('\n== 4. La politica ==');
    check('nessuna violazione della CSP ne\' errore nelle pagine' + (errors.length ? ': ' + errors.slice(0, 3).join(' | ') : ''), errors.length === 0);
    await browser.close();
    console.log(failed === 0 ? '\nTUTTO VERDE' : '\n' + failed + ' CONTROLLI FALLITI');
    process.exit(failed === 0 ? 0 : 1);
})().catch(e => { console.error(e); process.exit(1); });
