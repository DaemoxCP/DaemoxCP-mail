// La scheda del pannello in cima alla dashboard (reperto 183), in Chromium col server simulato e la
// stessa Content-Security-Policy del pannello.
//
//  1. Da quando gira: la durata e la data d'avvio, col fuso scritto; contata con l'ora del SERVER
//     (qui due ore avanti al browser: la durata non deve prenderle), e che avanza da sola.
//  2. L'occhio: chiuso all'inizio, i dettagli non sono nella pagina e nessuno li ha chiesti; si apre
//     col mouse e con la tastiera (aria-expanded, l'icona, il testo), e si richiude.
//  3. I dettagli: versione e build, commit, data, jar e impronta (copiabile), Java, sistema,
//     macchina, processo, memoria.
//  4. Chi non puo' vedere i dettagli non ha l'occhio; un 403 lo dice; un jar senza build registrata
//     e uno con modifiche fuori dal commit lo dicono.
//  5. In inglese, a 375 px senza scorrimento orizzontale, e senza violazioni della politica.
//
// Uso (dalla radice del progetto, con le pagine di PageGenerator in $D, vedi csp-browser-test.js):
//   NODE_PATH=$(npm root -g) node tests/home-panel-browser-test.js $D [cartella-per-le-immagini]
// Sul Mac col Chrome installato: CHROMIUM="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".
//
// Modo REMOTE: il server vero (HomePanelE2EServer, sulla VM FreeBSD) al posto di quello simulato,
// con i dati veri della macchina. Il server stampa SESSION, SHA256 e PORT:
//   REMOTE=https://panel.localhost:PORT MAP=<indirizzo della VM> SESSION=<token> SHA256=<impronta> \
//   COMMIT=<commit del jar> NODE_PATH=... node tests/home-panel-browser-test.js - [cartella-per-le-immagini]
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const csp = require('./browser-csp');

const pages = process.argv[2];
const shots = process.argv[3];
const resources = path.join(__dirname, '..', 'src', 'main', 'resources');
const BASE = 'https://panel.test';
let failed = 0;
function check(what, ok) {
    console.log((ok ? '  OK   ' : '  FALLITO ') + what);
    if (!ok) failed++;
}

const SKEW = 2 * 3600 * 1000;               // il server e' due ore avanti al browser
const UP = ((3 * 24 + 4) * 60 + 12) * 60;   // 3 giorni, 4 ore e 12 minuti
const SHA = 'a'.repeat(32) + '0123456789abcdef'.repeat(2);
const COMMIT = 'ca5c22430963bcd278bfdcc80e2e973642c07eb5';

function uptimeReply(o) {
    const now = Date.now() + SKEW;
    return { success: true, startedAt: new Date(now - (o.up ?? UP) * 1000).toISOString(), now: new Date(now).toISOString(),
             uptimeSeconds: o.up ?? UP, details: o.details ?? true };
}
function detailsReply(o) {
    return Object.assign({ success: true, version: '1.0', build: '408', commit: COMMIT, modified: false, builtAt: '2026-11-07T14:50:43Z',
        jarPath: '/home/panel/panel.jar', jarSha256: SHA,
        java: { version: '25.0.1+8-LTS', vendor: 'FreeBSD', vm: 'OpenJDK 64-Bit Server VM', home: '/usr/local/openjdk25' },
        os: { userland: '15.1-RELEASE-p2', kernel: '15.1-RELEASE-p2', arch: 'amd64' },
        hostname: 'mailserver1.example.test', bootedAt: new Date(Date.now() + SKEW - (9 * 86400 + 30) * 1000).toISOString(),
        pid: 85114, user: 'panel', heapUsed: 212 * 1024 * 1024, heapMax: 1024 * 1024 * 1024, processors: 4, port: 2096 }, o.details || {});
}

// Una pagina col suo server simulato; o dice come risponde /api/panel_info.
async function open(ctx, lang, o = {}) {
    const page = await ctx.newPage();
    const seen = [], errors = [];
    page.on('pageerror', e => errors.push(String(e)));
    csp.watch(page, errors);
    await page.route('**/*', async route => {
        const req = route.request();
        const url = new URL(req.url());
        const p = url.pathname;
        if (p.startsWith('/assets/')) return csp.asset(route, pages, p);
        if (p.startsWith('/i18n/')) return route.fulfill({ status: 200, contentType: 'text/javascript', body: fs.readFileSync(path.join(pages, p)) });
        if (p.startsWith('/vendor/') || p.startsWith('/fa/')) {
            const f = path.join(resources, p);
            if (!fs.existsSync(f)) return route.fulfill({ status: 404, body: '' });
            const type = p.endsWith('.css') ? 'text/css' : p.endsWith('.js') ? 'text/javascript' : p.endsWith('.woff2') ? 'font/woff2' : 'application/octet-stream';
            return route.fulfill({ status: 200, contentType: type, body: fs.readFileSync(f) });
        }
        if (p === '/api/panel_info') {
            const action = url.searchParams.get('action');
            seen.push(req.method() + ' ' + action);
            if (action === 'details' && o.forbidden) return route.fulfill({ status: 403, contentType: 'application/json', body: '{"error":"Forbidden","forbidden":true}' });
            const body = action === 'uptime' ? uptimeReply(o) : detailsReply(o);
            return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
        }
        if (p.startsWith('/api/')) return route.fulfill({ status: 200, contentType: 'application/json', body: '{"success":false,"error":"mock"}' });
        const f = path.join(pages, 'home' + (lang === 'it' ? '' : '.' + lang) + '.html');
        const html = fs.readFileSync(f, 'utf8').replace(/\{\{CSRF_TOKEN\}\}/g, 'csrf-test')
            .replace(/\{\{THEME\}\}/g, o.theme || 'light').replace(/\{\{COLOR_SCHEME\}\}/g, o.theme || 'light').replace(/\{\{[A-Z_]+\}\}/g, 'x');
        return route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: html, headers: csp.headers(pages) });
    });
    await page.goto(BASE + '/home');
    await page.waitForFunction(() => document.getElementById('panelInfoUptime').textContent.trim() !== '\u2013'
        || document.getElementById('panelInfoState').textContent.includes('mock'));
    return { page, seen, errors };
}

const text = (page, sel) => page.$eval(sel, el => el.textContent.replace(/\s+/g, ' ').trim());

// La scheda sul server vero: niente di simulato, i valori sono quelli della VM.
async function remote() {
    const E = process.env, url = new URL(E.REMOTE);
    const launch = { executablePath: E.CHROMIUM || '/opt/pw-browsers/chromium', args: ['--host-resolver-rules=MAP ' + url.hostname + ' ' + E.MAP] };
    const browser = await chromium.launch(launch).catch(() => chromium.launch({ args: launch.args }));
    for (const [lang, width] of [['it', 1280], ['en', 375]]) {
        console.log('\n== Il server vero, ' + lang + ', ' + width + ' px ==');
        // La sessione vale solo con lo User-Agent con cui e' nata (WebSessions): quello di HomePanelE2EServer.
        const ctx = await browser.newContext({ viewport: { width, height: 900 }, ignoreHTTPSErrors: true, timezoneId: 'Europe/Rome',
                                               userAgent: 'HomePanelE2EServer' });
        await ctx.addCookies([{ name: '__Host-MailPanel', value: E.SESSION, url: E.REMOTE, secure: true, httpOnly: true, sameSite: 'Strict' },
                              { name: '__Host-lang', value: lang, url: E.REMOTE, secure: true, sameSite: 'Strict' }]);
        const page = await ctx.newPage();
        const errors = [];
        page.on('pageerror', e => errors.push(String(e)));
        csp.watch(page, errors);
        const res = await page.goto(E.REMOTE + '/home');
        check('la dashboard risponde 200, con la CSP del pannello', res.status() === 200 && new URL(page.url()).pathname === '/home'
            && /script-src 'self';/.test(res.headers()['content-security-policy'] || ''));
        await page.waitForFunction(() => document.getElementById('panelInfoUptime').textContent.trim() !== '\u2013', null, { timeout: 15000 });
        const up = await text(page, '#panelInfoUptime');
        check('da quanto gira: ' + up, lang === 'it' ? /^(meno di un minuto|\d+ (minut|or|giorn).*)$/.test(up) : /^(less than a minute|\d+ (minute|hour|day).*)$/.test(up));
        const started = await page.$eval('#panelInfoStarted', el => ({ text: el.textContent, datetime: el.getAttribute('datetime') }));
        check('avviato: ' + started.text + ' (' + started.datetime + ')', /20\d\d/.test(started.text) && Date.now() - Date.parse(started.datetime) < 3600 * 1000);
        await page.click('#panelInfoToggle');
        await page.waitForSelector('#panelInfoList dt', { timeout: 15000 });
        const rows = await page.$$eval('#panelInfoList dt', dts => dts.map(dt => [dt.textContent.trim(), dt.nextElementSibling.textContent.replace(/\s+/g, ' ').trim()]));
        console.log('    ' + rows.map(r => r[0] + ': ' + r[1]).join('\n    '));
        const row = i => (rows[i] || ['', ''])[1];
        check('dieci righe', rows.length === 10);
        check('versione e numero di build', /^1\.0, build [1-9][0-9]*/.test(row(0)));
        if (E.COMMIT) check('il commit del jar', row(1) === E.COMMIT.slice(0, 12));
        check('l\'impronta del jar che gira', row(4).startsWith(E.SHA256) && E.SHA256.length === 64);
        check('FreeBSD vero', /^FreeBSD 1[0-9]\.[0-9]+-/.test(row(6)));
        check('il processo, sulla porta ' + url.port, new RegExp('^PID [0-9]+, (utente|user) [a-z]+, (porta|port) ' + url.port + '$').test(row(8)));
        check('la memoria', /(MB|GB)/.test(row(9)));
        const scroll = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
        check('nessuno scorrimento orizzontale (' + scroll + ')', scroll <= 0);
        check('nessuna violazione della politica ne\' errore' + (errors.length ? ': ' + errors.slice(0, 3).join(' | ') : ''), errors.length === 0);
        if (shots) await page.locator('section[aria-labelledby="panelInfoTitle"]').screenshot({ path: path.join(shots, 'remote-' + lang + '-' + width + '.png') });
        await ctx.close();
    }
    await browser.close();
}

(async () => {
    if (process.env.REMOTE) {
        await remote();
        console.log(failed === 0 ? '\nTUTTO VERDE' : '\n' + failed + ' CONTROLLI FALLITI');
        process.exit(failed === 0 ? 0 : 1);
    }
    const browser = await chromium.launch({ executablePath: process.env.CHROMIUM || '/opt/pw-browsers/chromium' }).catch(() => chromium.launch());
    // Europe/Rome come il server di posta: la data d'avvio deve portare il fuso.
    const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 }, timezoneId: 'Europe/Rome', locale: 'it-IT' });
    await ctx.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: BASE });

    console.log('== 1. Da quando gira ==');
    let { page, seen, errors } = await open(ctx, 'it');
    check('la durata, con l\'ora del server e non del browser: ' + await text(page, '#panelInfoUptime'),
        await text(page, '#panelInfoUptime') === '3 giorni, 4 ore e 12 minuti');
    const started = await page.$eval('#panelInfoStarted', el => ({ text: el.textContent, datetime: el.getAttribute('datetime'), title: el.title }));
    check('la data d\'avvio in italiano, col fuso: ' + started.text, /20\d\d/.test(started.text) && /CET|CEST|GMT\+/.test(started.text)
        && /(luned|marted|mercoled|gioved|venerd|sabato|domenica)/.test(started.text));
    check('  e in <time datetime> l\'istante UTC', /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$/.test(started.datetime) && started.title === started.datetime);
    check('lo stato non dice niente quando tutto e\' andato', await text(page, '#panelInfoState') === '');
    await page.evaluate(() => { panelInfo.offsetMs += 2 * 60 * 1000; panelInfoTick(); });
    check('avanza da sola (due minuti dopo): ' + await text(page, '#panelInfoUptime'), await text(page, '#panelInfoUptime') === '3 giorni, 4 ore e 14 minuti');
    await page.evaluate(() => { panelInfo.offsetMs -= 2 * 60 * 1000; panelInfoTick(); });

    console.log('\n== 2. L\'occhio ==');
    const closed = await page.$eval('#panelInfoToggle', b => ({ hidden: b.hidden, expanded: b.getAttribute('aria-expanded'), controls: b.getAttribute('aria-controls'),
        icon: document.getElementById('panelInfoEye').className, text: b.textContent.trim(), box: document.getElementById('panelInfoDetails').hidden,
        rows: document.querySelectorAll('#panelInfoList dt').length }));
    check('c\'e\', chiuso: aria-expanded=false, occhio aperto, "Mostra i dettagli"', !closed.hidden && closed.expanded === 'false'
        && closed.controls === 'panelInfoDetails' && /fa-eye(?!-)/.test(closed.icon) && closed.text === 'Mostra i dettagli');
    check('i dettagli non sono nella pagina, e nessuno li ha chiesti', closed.box && closed.rows === 0 && !seen.includes('GET details'));
    if (shots) await page.locator('section[aria-labelledby="panelInfoTitle"]').screenshot({ path: path.join(shots, 'panel-card-closed.png') });
    await page.click('#panelInfoToggle');
    await page.waitForSelector('#panelInfoList dt');
    const opened = await page.$eval('#panelInfoToggle', b => ({ expanded: b.getAttribute('aria-expanded'), icon: document.getElementById('panelInfoEye').className,
        text: b.textContent.trim(), box: document.getElementById('panelInfoDetails').hidden }));
    check('aperto: aria-expanded=true, occhio barrato, "Nascondi i dettagli", la lista si vede', opened.expanded === 'true'
        && /fa-eye-slash/.test(opened.icon) && opened.text === 'Nascondi i dettagli' && !opened.box);
    check('i dettagli si chiedono solo adesso, con GET', seen.filter(s => s === 'GET details').length === 1 && !seen.some(s => s.startsWith('POST')));

    console.log('\n== 3. I dettagli ==');
    const rows = await page.$$eval('#panelInfoList dt', dts => dts.map(dt => [dt.textContent.trim(), dt.nextElementSibling.textContent.replace(/\s+/g, ' ').trim()]));
    const row = name => (rows.find(r => r[0] === name) || [name, ''])[1];
    console.log('    ' + rows.map(r => r[0] + ': ' + r[1]).join('\n    '));
    check('dieci righe, una dd per ogni dt', rows.length === 10 && await page.$$eval('#panelInfoList dd', d => d.length) === 10);
    check('versione e build', row('Versione') === '1.0, build 408');
    check('il commit, corto, intero nel titolo', row('Commit') === COMMIT.slice(0, 12) && await page.$eval('#panelInfoCommit', c => c.title) === COMMIT);
    check('costruito il, col fuso', /novembre 2026/.test(row('Costruito il')) && /CET|GMT\+1/.test(row('Costruito il')));
    check('il file e l\'impronta intera', row('File del pannello') === '/home/panel/panel.jar' && row('Impronta SHA-256').startsWith(SHA));
    check('Java, sistema', row('Java').startsWith('25.0.1+8-LTS (FreeBSD, OpenJDK 64-Bit Server VM)')
        && row('Sistema') === 'FreeBSD 15.1-RELEASE-p2, kernel 15.1-RELEASE-p2, amd64');
    check('la macchina: nome, accesa da 9 giorni, dal ...', /^mailserver1\.example\.test, accesa da 9 giorni\s*dal .*2026/.test(row('Macchina')));
    check('processo e memoria', row('Processo') === 'PID 85114, utente panel, porta 2096' && row('Memoria di Java') === '212 MB in uso, al massimo 1 GB, 4 processori');
    await page.click('button[aria-label="Copia l\'impronta"]');
    await page.waitForFunction(() => document.getElementById('panelInfoState').textContent !== '');
    check('l\'impronta si copia negli appunti, e lo dice', await page.evaluate(() => navigator.clipboard.readText()) === SHA
        && await text(page, '#panelInfoState') === 'Copiato negli appunti.');
    if (shots) await page.locator('section[aria-labelledby="panelInfoTitle"]').screenshot({ path: path.join(shots, 'panel-card-open.png') });
    await page.focus('#panelInfoToggle');
    await page.keyboard.press('Enter');
    check('con la tastiera (Invio) si richiude', await page.$eval('#panelInfoToggle', b => b.getAttribute('aria-expanded')) === 'false'
        && await page.$eval('#panelInfoDetails', d => d.hidden));
    await page.keyboard.press('Space');
    await page.waitForSelector('#panelInfoList dt');
    check('e con lo spazio si riapre, rileggendo', await page.$eval('#panelInfoToggle', b => b.getAttribute('aria-expanded')) === 'true'
        && seen.filter(s => s === 'GET details').length === 2);
    check('nessuna violazione della politica ne\' errore' + (errors.length ? ': ' + errors.slice(0, 3).join(' | ') : ''), errors.length === 0);
    await page.close();

    console.log('\n== 4. Permessi e jar diversi ==');
    ({ page, seen, errors } = await open(ctx, 'it', { details: false }));
    check('chi non puo\' vedere i dettagli non ha l\'occhio', await page.$eval('#panelInfoToggle', b => b.hidden) && !seen.includes('GET details'));
    await page.close();
    ({ page, seen, errors } = await open(ctx, 'it', { forbidden: true }));
    await page.click('#panelInfoToggle');
    await page.waitForFunction(() => /ruolo/.test(document.getElementById('panelInfoList').textContent), null, { timeout: 5000 }).catch(() => {});
    const refusal = await text(page, '#panelInfoList');
    check('un 403 lo dice: ' + refusal, refusal === 'Il tuo ruolo non può vedere i dettagli tecnici.');
    await page.close();
    ({ page, seen, errors } = await open(ctx, 'it', { details: { build: '', commit: '' }, up: 20 }));
    check('meno di un minuto: ' + await text(page, '#panelInfoUptime'), await text(page, '#panelInfoUptime') === 'meno di un minuto');
    await page.click('#panelInfoToggle');
    await page.waitForSelector('#panelInfoList dt');
    check('un jar senza build registrata lo dice, e perche\'', /^1\.0, build non registrata\s*Il jar è stato costruito senza tools\/build-jar\.sh/.test(await text(page, '#panelInfoList dd'))
        && await page.$$eval('#panelInfoList dd', d => d[1].textContent.trim()) === 'non disponibile');
    await page.close();
    ({ page, seen, errors } = await open(ctx, 'it', { details: { modified: true } }));
    await page.click('#panelInfoToggle');
    await page.waitForSelector('#panelInfoList dt');
    check('un jar con modifiche fuori dal commit lo dice, a parole', /con modifiche fuori dal commit/.test(await text(page, '#panelInfoList dd'))
        && await page.$$eval('#panelInfoList dd .badge', b => b.length) === 1);
    await page.close();

    console.log('\n== 5. In inglese, stretto, scuro ==');
    const en = await browser.newContext({ viewport: { width: 375, height: 812 }, timezoneId: 'Europe/Rome', locale: 'en-GB', isMobile: true, hasTouch: true });
    ({ page, seen, errors } = await open(en, 'en', { theme: 'dark' }));
    check('la durata in inglese: ' + await text(page, '#panelInfoUptime'), await text(page, '#panelInfoUptime') === '3 days, 4 hours and 12 minutes'
        || await text(page, '#panelInfoUptime') === '3 days, 4 hours, and 12 minutes');
    await page.click('#panelInfoToggle');
    await page.waitForSelector('#panelInfoList dt');
    const card = await text(page, 'section[aria-labelledby="panelInfoTitle"]');
    check('nessuna parola italiana nella scheda', !/(^|[^\p{L}])(il|della|non|da|dal|accesa|giorni|utente|porta|Versione|Mostra|Nascondi|in funzione)(?=$|[^\p{L}])/iu.test(card));
    const layout = await page.evaluate(() => {
        const dt = document.querySelector('#panelInfoList dt'), dd = dt.nextElementSibling;
        return { scroll: document.documentElement.scrollWidth - window.innerWidth, stacked: dd.getBoundingClientRect().top >= dt.getBoundingClientRect().bottom - 1,
                 button: [...document.querySelectorAll('#panelInfoToggle, #panelInfoList button')].map(b => Math.round(Math.min(b.getBoundingClientRect().height, b.getBoundingClientRect().width))) };
    });
    check('a 375 px nessuno scorrimento orizzontale (' + layout.scroll + ' px in piu\')', layout.scroll <= 0);
    check('  nome e valore uno sopra l\'altro', layout.stacked);
    check('  col dito l\'occhio e la copia sono grandi almeno 44 px (r9): ' + layout.button.join(' e '), layout.button.every(h => h >= 44));
    if (shots) await page.screenshot({ path: path.join(shots, 'panel-card-mobile-dark.png'), fullPage: false,
        clip: await page.locator('section[aria-labelledby="panelInfoTitle"]').boundingBox() });
    check('nessuna violazione della politica ne\' errore' + (errors.length ? ': ' + errors.slice(0, 3).join(' | ') : ''), errors.length === 0);

    await browser.close();
    console.log(failed === 0 ? '\nTUTTO VERDE' : '\n' + failed + ' CONTROLLI FALLITI');
    process.exit(failed === 0 ? 0 : 1);
})();
