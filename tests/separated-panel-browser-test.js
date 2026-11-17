// The separated panel in Chromium, against the real service on the
// test machine: the web part as daemoxcp_mail on 2096, the root part behind the unix socket.
//
//   1. sign-in with a one-time console code (--access-code, run over ssh);
//   2. every page of the menu, and Account: no page sends back to the sign-in, no API call the pages make
//      answers 5xx (a 502 or 503 is the root part not answering), no script error; and enough API calls
//      answered 2xx to be sure the forwarding was really used;
//   3. the service users, as the Updates page asks for them: the panel runs as root and daemoxcp_mail, with
//      the reason root stays, and no warning that it runs entirely as root.
//
// The panel answers to its configured name or to 127.0.0.1 (the port does not count, HostCheck), so the
// browser reaches it through an ssh tunnel from 127.0.0.1 on the Mac.
//
// Usage (from the project root, with the panel installed as a service on the remote machine):
//   REMOTE=root@192.168.1.20 REMOTE_KEY=~/.ssh/freebsd_test_vm NODE_PATH=$(npm root -g) \
//     node tests/separated-panel-browser-test.js /home/panel
const { chromium } = require('playwright');
const { spawn, execFileSync } = require('child_process');
const net = require('net');
const fs = require('fs');
const path = require('path');

const PANEL_DIR = process.argv[2] || '/home/panel';
const REMOTE = process.env.REMOTE;
if (!REMOTE) { console.log('REMOTE=root@<host> is needed'); process.exit(2); }
const SSH = ['-o', 'BatchMode=yes'].concat(process.env.REMOTE_KEY ? ['-i', process.env.REMOTE_KEY.replace(/^~/, process.env.HOME)] : []);
const PORT = 22000 + Math.floor(Math.random() * 1000);
const BASE = 'https://127.0.0.1:' + PORT;
const en = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'src', 'main', 'resources', 'lang', 'en.json'), 'utf8'));
const PAGES = ['/home', '/domains', '/mailboxes', '/aliases', '/queue', '/ratelimits', '/statistics', '/dns', '/ssl',
    '/cloudflare', '/security', '/firewall', '/updates', '/logs', '/paths', '/admins', '/settings', '/account'];

let failures = 0;
function check(what, ok) {
    console.log((ok ? '  OK     ' : '  FAILED ') + what);
    if (!ok) failures++;
}

function remote(cmd) { return execFileSync('ssh', SSH.concat([REMOTE, cmd]), { encoding: 'utf8' }); }

function portOpen(port) {
    return new Promise(resolve => {
        const s = net.connect(port, '127.0.0.1', () => { s.destroy(); resolve(true); });
        s.on('error', () => resolve(false));
    });
}

(async () => {
    const tunnel = spawn('ssh', SSH.concat(['-N', '-o', 'ExitOnForwardFailure=yes', '-L', PORT + ':127.0.0.1:2096', REMOTE]),
        { stdio: 'ignore' });
    let up = false;
    for (let i = 0; i < 40 && !up; i++) { await new Promise(r => setTimeout(r, 250)); up = await portOpen(PORT); }
    check('ssh tunnel to the panel on 127.0.0.1:' + PORT, up);
    const browser = await chromium.launch({ executablePath: process.env.CHROMIUM || undefined });
    try {
        const context = await browser.newContext({ locale: 'en-US', ignoreHTTPSErrors: true, viewport: { width: 1280, height: 900 } });
        const page = await context.newPage();
        const api = [];
        const scriptErrors = [];
        page.on('response', r => {
            const u = new URL(r.url());
            if (u.pathname.startsWith('/api/')) api.push({ path: u.pathname + u.search, status: r.status(), page: new URL(page.url()).pathname });
        });
        page.on('pageerror', e => scriptErrors.push(new URL(page.url()).pathname + ': ' + e.message));

        console.log('== 1. Sign-in ==');
        const out = remote('cd ' + PANEL_DIR + ' && /usr/local/openjdk25/bin/java -jar daemoxcp-mail-1.0.jar --access-code');
        const m = out.match(/One-time access code for [^:]*: (\d{4} \d{4})/);
        check('a one-time code from the console', !!m);
        await page.goto(BASE + '/index');
        await page.click('#linkConsole');
        await page.fill('#consoleCode', m ? m[1] : '');
        await Promise.all([page.waitForURL('**/account**', { timeout: 30000 }).catch(() => {}), page.click('#btnConsole')]);
        check('signed in: on Account (' + new URL(page.url()).pathname + ')', new URL(page.url()).pathname === '/account');

        console.log('\n== 2. Every page ==');
        for (const p of PAGES) {
            const before = api.length;
            await page.goto(BASE + p);
            await page.waitForLoadState('networkidle', { timeout: 45000 }).catch(() => {});
            const mine = api.slice(before);
            const bad = mine.filter(c => c.status >= 500);
            const where = new URL(page.url()).pathname;
            check(p + ': stays on the page, ' + mine.length + ' API calls, none 5xx' + (bad.length ? ' (' + bad.map(c => c.status + ' ' + c.path).join(', ') + ')' : ''),
                where === p && bad.length === 0);
        }
        const ok2xx = api.filter(c => c.status >= 200 && c.status < 300).length;
        const others = api.filter(c => c.status >= 400 && c.status < 500);
        check('enough API calls answered 2xx through the root part (' + ok2xx + ')', ok2xx >= 20);
        if (others.length) console.log('         4xx (handlers that refuse, not the channel): ' + others.map(c => c.status + ' ' + c.path).join(', '));
        check('no script error on any page' + (scriptErrors.length ? ' (' + scriptErrors.join('; ') + ')' : ''), scriptErrors.length === 0);

        console.log('\n== 3. The service users ==');
        await page.goto(BASE + '/updates');
        const su = await page.evaluate(async () => {
            const r = await fetch('/api/updates', { method: 'POST', headers: { 'Content-Type': 'application/json',
                'X-CSRF-Token': document.getElementById('csrf_token').value }, body: JSON.stringify({ action: 'service_users' }) });
            return { status: r.status, body: await r.json() };
        });
        const panel = (su.body.services || []).find(s => s.service === 'mail-panel') || {};
        check('the panel runs as root and daemoxcp_mail (' + (panel.users || []).join(', ') + ')',
            (panel.users || []).includes('daemoxcp_mail') && (panel.users || []).includes('root'));
        check('with the reason root stays', panel.rootWhy === en['server.su.rootWhy.daemoxcpMail']);
        check('and no warning that it runs entirely as root', !(su.body.problems || []).some(p => p.code === 'panelLegacy'));
        await context.close();
    } finally {
        await browser.close();
        tunnel.kill();
    }
    console.log(failures === 0 ? '\nALL OK' : '\n' + failures + ' CHECKS FAILED');
    process.exit(failures === 0 ? 0 : 1);
})().catch(e => { console.error(e); process.exit(1); });
