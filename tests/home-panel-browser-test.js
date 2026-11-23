// The panel card at the top of the dashboard (finding 183), in Chromium with a simulated server and the
// panel's Content-Security-Policy.
//
//  1. How long it has been running: the duration and the start date, with the time zone; counted with
//     the SERVER's clock (here two hours ahead of the browser: the duration must not take them), and
//     moving on its own.
//  2. The eye: closed at first, the details are not in the page and nobody asked for them; it opens
//     with the mouse and the keyboard (aria-expanded, the icon, the text), and closes again.
//  3. The details: version and build, commit, date, jar and fingerprint (copyable), Java, system,
//     machine, process, memory.
//  4. Whoever cannot see the details has no eye; a 403 says so; a jar without a recorded build and one
//     with changes outside the commit say so.
//  5. On the Italian page the texts of it.json; at 375 px no horizontal scrolling; no policy violation.
//
// Usage (from the project root, with the pages of PageGenerator in $D, see csp-browser-test.js):
//   NODE_PATH=$(npm root -g) node tests/home-panel-browser-test.js $D [screenshot-folder]
// On the Mac with the installed Chrome: CHROMIUM="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".
//
// REMOTE mode: the real server (HomePanelE2EServer, on the test VM) instead of the simulated one, with
// the machine's real data. The server prints SESSION, SHA256 and PORT:
//   REMOTE=https://panel.localhost:PORT MAP=<VM address> SESSION=<token> SHA256=<fingerprint> \
//   COMMIT=<jar commit> NODE_PATH=... node tests/home-panel-browser-test.js - [screenshot-folder]
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const csp = require('./browser-csp');

const pages = process.argv[2];
const shots = process.argv[3];
const resources = path.join(__dirname, '..', 'src', 'main', 'resources');
const IT = JSON.parse(fs.readFileSync(path.join(resources, 'lang', 'it.json'), 'utf8'));
const BASE = 'https://panel.test';
let failed = 0;
function check(what, ok) {
    console.log((ok ? '  OK   ' : '  FAILED ') + what);
    if (!ok) failed++;
}

const SKEW = 2 * 3600 * 1000;               // the server is two hours ahead of the browser
const UP = ((3 * 24 + 4) * 60 + 12) * 60;   // 3 days, 4 hours and 12 minutes
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

// A page with its simulated server; o says how /api/panel_info answers.
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
const DURATION = /^3 days, 4 hours,? and 12 minutes$/;

// The card on the real server: nothing simulated, the values are the VM's.
async function remote() {
    const E = process.env, url = new URL(E.REMOTE);
    const launch = { executablePath: E.CHROMIUM || '/opt/pw-browsers/chromium', args: ['--host-resolver-rules=MAP ' + url.hostname + ' ' + E.MAP] };
    const browser = await chromium.launch(launch).catch(() => chromium.launch({ args: launch.args }));
    for (const [lang, width] of [['en', 1280], ['en', 375]]) {
        console.log('\n== The real server, ' + lang + ', ' + width + ' px ==');
        // The session is valid only with the User-Agent it was created with (WebSessions): HomePanelE2EServer's.
        const ctx = await browser.newContext({ viewport: { width, height: 900 }, ignoreHTTPSErrors: true, timezoneId: 'Europe/Rome',
                                               userAgent: 'HomePanelE2EServer' });
        await ctx.addCookies([{ name: '__Host-DaemoxCPMail', value: E.SESSION, url: E.REMOTE, secure: true, httpOnly: true, sameSite: 'Strict' },
                              { name: '__Host-lang', value: lang, url: E.REMOTE, secure: true, sameSite: 'Strict' }]);
        const page = await ctx.newPage();
        const errors = [];
        page.on('pageerror', e => errors.push(String(e)));
        csp.watch(page, errors);
        const res = await page.goto(E.REMOTE + '/home');
        check('the dashboard answers 200, with the panel\'s CSP', res.status() === 200 && new URL(page.url()).pathname === '/home'
            && /script-src 'self';/.test(res.headers()['content-security-policy'] || ''));
        await page.waitForFunction(() => document.getElementById('panelInfoUptime').textContent.trim() !== '\u2013', null, { timeout: 15000 });
        const up = await text(page, '#panelInfoUptime');
        check('running for: ' + up, /^(less than a minute|\d+ (minute|hour|day).*)$/.test(up));
        const started = await page.$eval('#panelInfoStarted', el => ({ text: el.textContent, datetime: el.getAttribute('datetime') }));
        check('started: ' + started.text + ' (' + started.datetime + ')', /20\d\d/.test(started.text) && Date.now() - Date.parse(started.datetime) < 3600 * 1000);
        await page.click('#panelInfoToggle');
        await page.waitForSelector('#panelInfoList dt', { timeout: 15000 });
        const rows = await page.$$eval('#panelInfoList dt', dts => dts.map(dt => [dt.textContent.trim(), dt.nextElementSibling.textContent.replace(/\s+/g, ' ').trim()]));
        console.log('    ' + rows.map(r => r[0] + ': ' + r[1]).join('\n    '));
        const row = i => (rows[i] || ['', ''])[1];
        check('ten rows', rows.length === 10);
        check('version and build number', /^1\.0, build [1-9][0-9]*/.test(row(0)));
        if (E.COMMIT) check('the jar\'s commit', row(1) === E.COMMIT.slice(0, 12));
        check('the fingerprint of the running jar', row(4).startsWith(E.SHA256) && E.SHA256.length === 64);
        check('real FreeBSD', /^FreeBSD 1[0-9]\.[0-9]+-/.test(row(6)));
        check('the process, on port ' + url.port, new RegExp('^PID [0-9]+, user [a-z]+, port ' + url.port + '$').test(row(8)));
        check('the memory', /(MB|GB)/.test(row(9)));
        const scroll = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
        check('no horizontal scrolling (' + scroll + ')', scroll <= 0);
        check('no policy violation or error' + (errors.length ? ': ' + errors.slice(0, 3).join(' | ') : ''), errors.length === 0);
        if (shots) await page.locator('section[aria-labelledby="panelInfoTitle"]').screenshot({ path: path.join(shots, 'remote-' + lang + '-' + width + '.png') });
        await ctx.close();
    }
    await browser.close();
}

(async () => {
    if (process.env.REMOTE) {
        await remote();
        console.log(failed === 0 ? '\nALL GREEN' : '\n' + failed + ' CHECKS FAILED');
        process.exit(failed === 0 ? 0 : 1);
    }
    const browser = await chromium.launch({ executablePath: process.env.CHROMIUM || '/opt/pw-browsers/chromium' }).catch(() => chromium.launch());
    // Europe/Rome like the mail server: the start date must carry the time zone.
    const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 }, timezoneId: 'Europe/Rome', locale: 'en-GB' });
    await ctx.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: BASE });

    console.log('== 1. How long it has been running ==');
    let { page, seen, errors } = await open(ctx, 'en');
    check('the duration, with the server\'s clock and not the browser\'s: ' + await text(page, '#panelInfoUptime'), DURATION.test(await text(page, '#panelInfoUptime')));
    const started = await page.$eval('#panelInfoStarted', el => ({ text: el.textContent, datetime: el.getAttribute('datetime'), title: el.title }));
    check('the start date, with the time zone: ' + started.text, /20\d\d/.test(started.text) && /CET|CEST|GMT\+/.test(started.text)
        && /(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday)/.test(started.text));
    check('  and the UTC instant in <time datetime>', /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$/.test(started.datetime) && started.title === started.datetime);
    check('the status line says nothing when all went well', await text(page, '#panelInfoState') === '');
    await page.evaluate(() => { panelInfo.offsetMs += 2 * 60 * 1000; panelInfoTick(); });
    check('it moves on its own (two minutes later): ' + await text(page, '#panelInfoUptime'), /^3 days, 4 hours,? and 14 minutes$/.test(await text(page, '#panelInfoUptime')));
    await page.evaluate(() => { panelInfo.offsetMs -= 2 * 60 * 1000; panelInfoTick(); });

    console.log('\n== 2. The eye ==');
    const closed = await page.$eval('#panelInfoToggle', b => ({ hidden: b.hidden, expanded: b.getAttribute('aria-expanded'), controls: b.getAttribute('aria-controls'),
        icon: document.getElementById('panelInfoEye').className, text: b.textContent.trim(), box: document.getElementById('panelInfoDetails').hidden,
        rows: document.querySelectorAll('#panelInfoList dt').length }));
    check('it is there, closed: aria-expanded=false, open eye, "Show details"', !closed.hidden && closed.expanded === 'false'
        && closed.controls === 'panelInfoDetails' && /fa-eye(?!-)/.test(closed.icon) && closed.text === 'Show details');
    check('the details are not in the page, and nobody asked for them', closed.box && closed.rows === 0 && !seen.includes('GET details'));
    if (shots) await page.locator('section[aria-labelledby="panelInfoTitle"]').screenshot({ path: path.join(shots, 'panel-card-closed.png') });
    await page.click('#panelInfoToggle');
    await page.waitForSelector('#panelInfoList dt');
    const opened = await page.$eval('#panelInfoToggle', b => ({ expanded: b.getAttribute('aria-expanded'), icon: document.getElementById('panelInfoEye').className,
        text: b.textContent.trim(), box: document.getElementById('panelInfoDetails').hidden }));
    check('open: aria-expanded=true, crossed eye, "Hide details", the list is shown', opened.expanded === 'true'
        && /fa-eye-slash/.test(opened.icon) && opened.text === 'Hide details' && !opened.box);
    check('the details are asked for only now, with GET', seen.filter(s => s === 'GET details').length === 1 && !seen.some(s => s.startsWith('POST')));

    console.log('\n== 3. The details ==');
    const rows = await page.$$eval('#panelInfoList dt', dts => dts.map(dt => [dt.textContent.trim(), dt.nextElementSibling.textContent.replace(/\s+/g, ' ').trim()]));
    const row = name => (rows.find(r => r[0] === name) || [name, ''])[1];
    console.log('    ' + rows.map(r => r[0] + ': ' + r[1]).join('\n    '));
    check('ten rows, one dd for each dt', rows.length === 10 && await page.$$eval('#panelInfoList dd', d => d.length) === 10);
    check('version and build', row('Version') === '1.0, build 408');
    check('the commit, short, in full in the title', row('Commit') === COMMIT.slice(0, 12) && await page.$eval('#panelInfoCommit', c => c.title) === COMMIT);
    check('built on, with the time zone', /November \d+, 2026/.test(row('Built on')) && /CET|GMT\+1/.test(row('Built on')));
    check('the file and the full fingerprint', row('Panel file') === '/home/panel/panel.jar' && row('SHA-256 fingerprint').startsWith(SHA));
    check('Java, system', row('Java').startsWith('25.0.1+8-LTS (FreeBSD, OpenJDK 64-Bit Server VM)')
        && row('System') === 'FreeBSD 15.1-RELEASE-p2, kernel 15.1-RELEASE-p2, amd64');
    check('the machine: name, up for 9 days, since ...', /^mailserver1\.example\.test, up for 9 days\s*since .*2026/.test(row('Machine')));
    check('process and memory', row('Process') === 'PID 85114, user panel, port 2096' && /^212 MB in use, at most 1 GB, 4 processors$/.test(row('Java memory')));
    await page.click('button[aria-label="Copy the fingerprint"]');
    await page.waitForFunction(() => document.getElementById('panelInfoState').textContent !== '');
    check('the fingerprint is copied to the clipboard, and it says so', await page.evaluate(() => navigator.clipboard.readText()) === SHA
        && await text(page, '#panelInfoState') === 'Copied to the clipboard.');
    if (shots) await page.locator('section[aria-labelledby="panelInfoTitle"]').screenshot({ path: path.join(shots, 'panel-card-open.png') });
    await page.focus('#panelInfoToggle');
    await page.keyboard.press('Enter');
    check('with the keyboard (Enter) it closes', await page.$eval('#panelInfoToggle', b => b.getAttribute('aria-expanded')) === 'false'
        && await page.$eval('#panelInfoDetails', d => d.hidden));
    await page.keyboard.press('Space');
    await page.waitForSelector('#panelInfoList dt');
    check('and with Space it opens again, reading again', await page.$eval('#panelInfoToggle', b => b.getAttribute('aria-expanded')) === 'true'
        && seen.filter(s => s === 'GET details').length === 2);
    check('no policy violation or error' + (errors.length ? ': ' + errors.slice(0, 3).join(' | ') : ''), errors.length === 0);
    await page.close();

    console.log('\n== 4. Permissions and other jars ==');
    ({ page, seen, errors } = await open(ctx, 'en', { details: false }));
    check('whoever cannot see the details has no eye', await page.$eval('#panelInfoToggle', b => b.hidden) && !seen.includes('GET details'));
    await page.close();
    ({ page, seen, errors } = await open(ctx, 'en', { forbidden: true }));
    await page.click('#panelInfoToggle');
    await page.waitForFunction(() => /role/.test(document.getElementById('panelInfoList').textContent), null, { timeout: 5000 }).catch(() => {});
    const refusal = await text(page, '#panelInfoList');
    check('a 403 says so: ' + refusal, refusal === 'Your role cannot see the technical details.');
    await page.close();
    ({ page, seen, errors } = await open(ctx, 'en', { details: { build: '', commit: '' }, up: 20 }));
    check('less than a minute: ' + await text(page, '#panelInfoUptime'), await text(page, '#panelInfoUptime') === 'less than a minute');
    await page.click('#panelInfoToggle');
    await page.waitForSelector('#panelInfoList dt');
    check('a jar without a recorded build says so, and why', /^1\.0, build not recorded\s*The jar was built without tools\/build-jar\.sh/.test(await text(page, '#panelInfoList dd'))
        && await page.$$eval('#panelInfoList dd', d => d[1].textContent.trim()) === 'not available');
    await page.close();
    ({ page, seen, errors } = await open(ctx, 'en', { details: { modified: true } }));
    await page.click('#panelInfoToggle');
    await page.waitForSelector('#panelInfoList dt');
    check('a jar with changes outside the commit says so, in words', /with changes outside the commit/.test(await text(page, '#panelInfoList dd'))
        && await page.$$eval('#panelInfoList dd .badge', b => b.length) === 1);
    await page.close();

    console.log('\n== 5. Italian, narrow, dark ==');
    ({ page, seen, errors } = await open(ctx, 'it'));
    check('on the Italian page the texts of it.json', await text(page, '#panelInfoToggleText') === IT['hp.show']
        && (await text(page, '#panelInfoUptime')).startsWith(IT['hp.days.other'].replace('{n}', '3')));
    await page.close();
    const narrow = await browser.newContext({ viewport: { width: 375, height: 812 }, timezoneId: 'Europe/Rome', locale: 'en-GB', isMobile: true, hasTouch: true });
    ({ page, seen, errors } = await open(narrow, 'en', { theme: 'dark' }));
    await page.click('#panelInfoToggle');
    await page.waitForSelector('#panelInfoList dt');
    const layout = await page.evaluate(() => {
        const dt = document.querySelector('#panelInfoList dt'), dd = dt.nextElementSibling;
        return { scroll: document.documentElement.scrollWidth - window.innerWidth, stacked: dd.getBoundingClientRect().top >= dt.getBoundingClientRect().bottom - 1,
                 button: [...document.querySelectorAll('#panelInfoToggle, #panelInfoList button')].map(b => Math.round(Math.min(b.getBoundingClientRect().height, b.getBoundingClientRect().width))) };
    });
    check('at 375 px no horizontal scrolling (' + layout.scroll + ' px more)', layout.scroll <= 0);
    check('  name and value one above the other', layout.stacked);
    check('  with a finger the eye and the copy buttons are at least 44 px (r9): ' + layout.button.join(', '), layout.button.every(h => h >= 44));
    if (shots) await page.screenshot({ path: path.join(shots, 'panel-card-mobile-dark.png'), fullPage: false,
        clip: await page.locator('section[aria-labelledby="panelInfoTitle"]').boundingBox() });
    check('no policy violation or error' + (errors.length ? ': ' + errors.slice(0, 3).join(' | ') : ''), errors.length === 0);

    await browser.close();
    console.log(failed === 0 ? '\nALL GREEN' : '\n' + failed + ' CHECKS FAILED');
    process.exit(failed === 0 ? 0 : 1);
})();
