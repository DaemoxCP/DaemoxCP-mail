// The confirmation of a sensitive operation with a code from the server console, end to end on the FreeBSD test
// machine: the way out for an administrator without a passkey on a server that cannot send mail yet. Here only the
// browser runs; the panel is the test machine's own, through an ssh tunnel.
//
//   1. Signed in with a console code and no passkey, a sensitive change (Settings, IPv4 and IPv6, the family
//      already in use, so nothing changes) opens the confirmation window.
//   2. It offers "Use a code from the server console", with the command to run and the administrator's name in it.
//   3. A wrong code: refused, the window stays open.
//   4. The command shown, run on the server: its code confirms, the window closes, the change goes through.
//   5. The same code a second time: refused (single use).
//
// ONLY on the test machine. Usage:
//   HOST=<panel name> CHROMIUM=<chrome binary> REMOTE=root@<test machine> REMOTE_KEY=<ssh key> \
//     NODE_PATH=$(npm root -g) node tests/console-confirmation-browser-test.js
const { chromium } = require('playwright');
const { spawn, execFileSync } = require('child_process');
const net = require('net');

const REMOTE = process.env.REMOTE, HOST = process.env.HOST;
const SSH = ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-i', process.env.REMOTE_KEY.replace(/^~/, process.env.HOME)];
const PORT = 25000 + Math.floor(Math.random() * 1000);
const BASE = 'https://' + HOST + ':' + PORT;
let failures = 0;
function check(what, ok) { console.log((ok ? '  OK     ' : '  FAILED ') + what); if (!ok) failures++; }
function remote(cmd) { return execFileSync('ssh', SSH.concat([REMOTE, cmd]), { encoding: 'utf8' }); }
function code(out) { const m = out.match(/One-time access code for [^:]*: (\d{4} \d{4})/); return m ? m[1] : ''; }
function portOpen(port) {
    return new Promise(resolve => { const s = net.connect(port, '127.0.0.1', () => { s.destroy(); resolve(true); }); s.on('error', () => resolve(false)); });
}

(async () => {
    const tunnel = spawn('ssh', SSH.concat(['-N', '-o', 'ExitOnForwardFailure=yes', '-L', PORT + ':127.0.0.1:2096', REMOTE]), { stdio: 'ignore' });
    let up = false;
    for (let i = 0; i < 40 && !up; i++) { await new Promise(r => setTimeout(r, 250)); up = await portOpen(PORT); }
    const browser = await chromium.launch({ executablePath: process.env.CHROMIUM, args: ['--host-resolver-rules=MAP ' + HOST + ' 127.0.0.1'] });
    try {
        const page = await (await browser.newContext({ ignoreHTTPSErrors: true })).newPage();
        page.on('dialog', d => d.accept());
        await page.goto(BASE + '/index');
        await page.click('#linkConsole');
        await page.fill('#consoleCode', code(remote('cd /home/panel && /usr/local/openjdk25/bin/java -jar daemoxcp-mail.jar --access-code 2>/dev/null')));
        await Promise.all([page.waitForURL(u => !u.pathname.endsWith('/index'), { timeout: 30000 }), page.click('#btnConsole')]);
        const account = await page.evaluate(() => fetch('/api/account').then(r => r.json()));
        check('signed in with a console code (' + account.username + ', ' + (account.passkeys || []).length + ' passkeys)', account.success === true);

        console.log('\n== 1. A sensitive change asks for the confirmation ==');
        await page.goto(BASE + '/settings');
        await page.waitForLoadState('networkidle').catch(() => {});
        const effective = (await page.evaluate(() => fetch('/api/ip-family').then(r => r.json()))).effective;
        const csrf = await page.$eval('#csrf_token', e => e.value);
        // Through the page's fetch, as the Settings card does: it waits for the window and repeats itself after it.
        const change = page.evaluate(({ f, csrf }) => fetch('/api/ip-family', { method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ family: f, confirmed: true, csrf_token: csrf }) }).then(r => r.json()), { f: effective, csrf })
            .catch(e => ({ success: false, error: 'page: ' + e.message.split('\n')[0] }));
        await page.waitForSelector('#panelConfirmModal.show', { timeout: 20000 });
        check('the confirmation window opened', true);

        console.log('\n== 2. The console way, with the command ==');
        const button = page.locator('#panelConfirmModal [data-confirm="console"]');
        check('"Use a code from the server console" is there', await button.isVisible());
        if (!(await button.isVisible())) throw new Error('no console way in the window');
        await button.click();
        await page.waitForSelector('#panelConfirmConsoleCode', { state: 'visible' });
        const command = (await page.locator('#panelConfirmConsoleCommand').innerText()).trim();
        check('it shows the command with the name (' + command + ')',
            command === 'java -jar daemoxcp-mail.jar --access-code ' + account.username);
        check('the field has focus', await page.evaluate(() => document.activeElement && document.activeElement.id === 'panelConfirmConsoleCode'));

        console.log('\n== 3. A wrong code ==');
        await page.fill('#panelConfirmConsoleCode', '0000 0000');
        await page.click('#panelConfirmModal [data-confirm="console-verify"]');
        await page.waitForFunction(() => /text-danger/.test(document.getElementById('panelConfirmMsg').className), null, { timeout: 15000 });
        check('refused, with a message (' + (await page.locator('#panelConfirmMsg').innerText()).trim() + ')', true);
        check('the window is still open', await page.locator('#panelConfirmModal.show').count() === 1);

        console.log('\n== 4. The command shown, run on the server ==');
        const good = code(remote('cd /home/panel && /usr/local/openjdk25/bin/' + command.replace(/^java /, 'java ') + ' 2>/dev/null'));
        check('the command prints a code', good !== '');
        await page.fill('#panelConfirmConsoleCode', good);
        await page.click('#panelConfirmModal [data-confirm="console-verify"]');
        const result = await change;
        check('confirmed: the window closed', await page.locator('#panelConfirmModal.show').count() === 0);
        check('the change went through (' + (result.error || 'ok') + ')', result.success === true);

        console.log('\n== 5. The same code again ==');
        const again = await page.evaluate(({ c, csrf }) => fetch('/api/account', { method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'stepup_console_verify', code: c, csrf_token: csrf }) }).then(r => r.status), { c: good, csrf });
        check('refused, single use (HTTP ' + again + ')', again === 401);
        await Promise.all([page.waitForURL('**/index', { timeout: 15000 }).catch(() => {}), page.click('#logoutButton').catch(() => {})]);
    } catch (e) {
        check('the run went to the end (' + e.message.split('\n')[0] + ')', false);
    } finally {
        await browser.close();
        tunnel.kill();
    }
    console.log(failures === 0 ? '\nALL OK' : '\n' + failures + ' CHECKS FAILED');
    process.exit(failures === 0 ? 0 : 1);
})();
