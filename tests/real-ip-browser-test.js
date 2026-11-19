// Whose address the panel believes, and which names it answers to, end to end on the FreeBSD test machine (r18).
// Here only the browser runs; the panel is the test machine's own, reached DIRECTLY on its port (no tunnel), so
// the connection comes from this computer's address in the test machine's private network: the case that used to
// be trusted like Cloudflare.
//
//   1. Another name, with Cloudflare's headers: 421 (before, any name passed with CF-RAY or CF-Connecting-IP
//      from a private network or the loopback).
//   2. The panel's own name: it answers.
//   3. A sign-in with a console code and a forged CF-Connecting-IP: the session in Account shows this
//      computer's real address, not the forged one.
//
// ONLY on the test machine. Usage:
//   HOST=<panel name> CHROMIUM=<chrome binary> REMOTE=root@<test machine> REMOTE_KEY=<ssh key> \
//     NODE_PATH=$(npm root -g) node tests/real-ip-browser-test.js
const { chromium } = require('playwright');
const { execFileSync } = require('child_process');
const https = require('https');

const REMOTE = process.env.REMOTE, HOST = process.env.HOST, PORT = process.env.PORT || '2096';
const SSH = ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-i', process.env.REMOTE_KEY.replace(/^~/, process.env.HOME)];
const MACHINE = REMOTE.split('@')[1];
const FORGED = '203.0.113.66';
let failures = 0;
function check(what, ok) { console.log((ok ? '  OK     ' : '  FAILED ') + what); if (!ok) failures++; }
function remote(cmd) { return execFileSync('ssh', SSH.concat([REMOTE, cmd]), { encoding: 'utf8' }); }
function status(hostHeader, extra) {
    return new Promise(resolve => {
        const req = https.request({ host: MACHINE, port: Number(PORT), path: '/index', method: 'GET', rejectUnauthorized: false,
            headers: Object.assign({ Host: hostHeader + ':' + PORT }, extra || {}), timeout: 15000 }, res => { res.resume(); resolve(res.statusCode); });
        req.on('timeout', () => { req.destroy(); resolve(-1); });
        req.on('error', () => resolve(-1));
        req.end();
    });
}

(async () => {
    console.log('== 1. Another name, with the headers Cloudflare sends ==');
    const other = await status('evil.example', { 'CF-RAY': '8a1b2c3d4e5f-FRA', 'CF-Connecting-IP': FORGED });
    check('421 Misdirected Request (' + other + ')', other === 421);
    const otherPlain = await status('evil.example');
    check('and 421 without them too (' + otherPlain + ')', otherPlain === 421);

    console.log('\n== 2. The panel\'s own name ==');
    const own = await status(HOST, { 'CF-RAY': '8a1b2c3d4e5f-FRA' });
    check('it answers (' + own + ')', own === 200 || own === 302);

    console.log('\n== 3. A forged CF-Connecting-IP at sign-in ==');
    const browser = await chromium.launch({ executablePath: process.env.CHROMIUM, args: ['--host-resolver-rules=MAP ' + HOST + ' ' + MACHINE] });
    try {
        const context = await browser.newContext({ ignoreHTTPSErrors: true, extraHTTPHeaders: { 'CF-Connecting-IP': FORGED, 'X-Forwarded-For': FORGED, 'X-Real-IP': FORGED } });
        const page = await context.newPage();
        const m = remote('cd /home/panel && /usr/local/openjdk25/bin/java -jar daemoxcp-mail.jar --lang en --access-code 2>/dev/null').match(/One-time access code for [^:]*: (\d{4} \d{4})/);
        await page.goto('https://' + HOST + ':' + PORT + '/index');
        await page.click('#linkConsole');
        await page.fill('#consoleCode', m ? m[1] : '');
        await Promise.all([page.waitForURL(u => !u.pathname.endsWith('/index'), { timeout: 30000 }), page.click('#btnConsole')]);
        // The panel sends to Account only an administrator without a passkey; with one, to the home page.
        await page.goto('https://' + HOST + ':' + PORT + '/account');
        await page.waitForFunction(() => /this one/.test(document.getElementById('sessionsList').innerText), null, { timeout: 15000 });
        const line = (await page.locator('#sessionsList').innerText()).split('\n').filter(l => l.trim()).join(' | ');
        const mine = remote("echo $SSH_CLIENT | cut -d' ' -f1").trim();
        check('the session does not carry the forged address', !line.includes(FORGED));
        check('it carries this computer\'s address in the private network (' + mine + ')', mine !== '' && line.includes(mine));
        await Promise.all([page.waitForURL('**/index', { timeout: 15000 }).catch(() => {}), page.click('#logoutButton').catch(() => {})]);
    } finally {
        await browser.close();
    }
    console.log(failures === 0 ? '\nALL OK' : '\n' + failures + ' CHECKS FAILED');
    process.exit(failures === 0 ? 0 : 1);
})();
