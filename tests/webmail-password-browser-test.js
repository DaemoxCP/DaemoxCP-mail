// Changing a mailbox's password from the webmail, end to end on the FreeBSD test machine: the password plugin the
// panel turns on (WebmailPasswordConfig), Roundcube's own page, the panel behind it (httpapi), and Dovecot after.
// Here only the browser runs; the panel and the webmail are the test machine's own, through ssh tunnels.
//
//   1. A domain and a mailbox of this run (wp-<token>.test), made with the panel's API.
//   2. Roundcube: signed in with the mailbox's password, and the SSO plugin's password copy request reached the panel
//      (Roundcube's log has no new "did not answer"); Settings has "Password", and its page has the form with the
//      current password too (the panel checks it).
//   3. A new password that is too short: refused, the old one still works.
//   4. A good new password: saved; IMAP takes the new one and refuses the old one.
//   5. Everything removed: mailbox, domain, mail folder.
//
// ONLY on the test machine. Usage:
//   HOST=<panel name> WEBMAIL=<webmail name> CHROMIUM=<chrome binary> REMOTE=root@<test machine> REMOTE_KEY=<ssh key> \
//     NODE_PATH=$(npm root -g) node tests/webmail-password-browser-test.js
// The webmail's port on the machine is 8443 (the panel's nginx, behind Cloudflare); WEBMAIL_PORT for another one.
const { chromium } = require('playwright');
const { spawn, execFileSync } = require('child_process');
const net = require('net');

const REMOTE = process.env.REMOTE, HOST = process.env.HOST, WEBMAIL = process.env.WEBMAIL;
const SSH = ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-i', process.env.REMOTE_KEY.replace(/^~/, process.env.HOME)];
const PORT = 25000 + Math.floor(Math.random() * 1000), WPORT = PORT + 1000;
const BASE = 'https://' + HOST + ':' + PORT, WBASE = 'https://' + WEBMAIL + ':' + WPORT;
const TOKEN = 'wp' + Date.now().toString(36);
const P1 = 'First' + TOKEN + 'Pw7Kd2', P2 = 'Second' + TOKEN + 'Pw9Qz4';
let failures = 0;
function check(what, ok) { console.log((ok ? '  OK     ' : '  FAILED ') + what); if (!ok) failures++; }
function remote(cmd, input) { return execFileSync('ssh', SSH.concat([REMOTE, cmd]), { encoding: 'utf8', input: input }); }
function code(out) { const m = out.match(/One-time access code for [^:]*: (\d{4} \d{4})/); return m ? m[1] : ''; }
function portOpen(port) {
    return new Promise(resolve => { const s = net.connect(port, '127.0.0.1', () => { s.destroy(); resolve(true); }); s.on('error', () => resolve(false)); });
}
const sleep = ms => new Promise(r => setTimeout(r, ms));

// An IMAP login on the test machine (993, Dovecot): "ok" or "refused". The password goes on stdin, not on a command line.
const IMAP = `
import imaplib, ssl, sys
user, password = sys.argv[1], sys.stdin.read()
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
try:
    m = imaplib.IMAP4_SSL('127.0.0.1', 993, ssl_context=ctx); m.login(user, password); m.logout(); print('ok')
except imaplib.IMAP4.error:
    print('refused')
`;
function imap(user, password) {
    const f = '/tmp/imap-check-' + TOKEN + '.py';
    remote('cat > ' + f, IMAP);
    try { return remote('/usr/local/bin/python3.12 ' + f + ' ' + user, password).trim(); }
    finally { remote('rm -f ' + f); }
}

(async () => {
    const tunnels = [
        spawn('ssh', SSH.concat(['-N', '-o', 'ExitOnForwardFailure=yes', '-L', PORT + ':127.0.0.1:2096', REMOTE]), { stdio: 'ignore' }),
        spawn('ssh', SSH.concat(['-N', '-o', 'ExitOnForwardFailure=yes', '-L', WPORT + ':127.0.0.1:' + (process.env.WEBMAIL_PORT || '8443'), REMOTE]), { stdio: 'ignore' })];
    for (let i = 0; i < 40 && !(await portOpen(PORT) && await portOpen(WPORT)); i++) await sleep(250);
    const browser = await chromium.launch({ executablePath: process.env.CHROMIUM,
        args: ['--host-resolver-rules=MAP ' + HOST + ' 127.0.0.1, MAP ' + WEBMAIL + ' 127.0.0.1'] });
    const made = { mailbox: 0, domain: 0, folder: '' };
    let panel;
    const api = (path, method, body) => panel.evaluate(({ path, method, body }) => fetch(path, {
        method, headers: { 'Content-Type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(Object.assign({ csrf_token: document.getElementById('csrf_token').value }, body))
    }).then(r => r.json()), { path, method, body });
    try {
        const context = await browser.newContext({ ignoreHTTPSErrors: true, locale: 'en-GB' });
        panel = await context.newPage();
        await panel.goto(BASE + '/index');
        await panel.click('#linkConsole');
        await panel.fill('#consoleCode', code(remote('cd /home/panel && /usr/local/openjdk25/bin/java -jar daemoxcp-mail.jar --lang en --access-code 2>/dev/null')));
        await Promise.all([panel.waitForURL(u => !u.pathname.endsWith('/index'), { timeout: 30000 }), panel.click('#btnConsole')]);
        await panel.goto(BASE + '/mailboxes');

        console.log('== 1. A domain and a mailbox of this run (' + TOKEN + ') ==');
        const D = TOKEN + '.test', USER = 'user-' + TOKEN + '@' + D;
        const dom = await api('/api/domains', 'POST', { domain: D, description: 'webmail password test' });
        check('domain ' + D + ' created', dom.success === true);
        made.domain = dom.id || 0;
        made.folder = '/var/vmail/' + D;
        const mb = await api('/api/mailboxes', 'POST', { email: USER, password: P1, name: 'Webmail test', quota_mb: 50, receive_enabled: true });
        check('mailbox ' + USER + ' created' + (mb.success ? '' : ' (' + mb.error + ')'), mb.success === true);
        const box = ((await api('/api/mailboxes', 'GET')).mailboxes || []).find(b => b.email === USER);
        made.mailbox = box ? box.id : 0;
        check('IMAP takes its first password', imap(USER, P1) === 'ok');

        console.log('\n== 2. Roundcube ==');
        // After a sign-in with the mailbox's own password the panel's SSO plugin sends the panel the password copy;
        // when that request fails it writes one line in Roundcube's log (it did after every sign-in, 17-18/11/2026).
        const RC_LOG = '/usr/local/www/roundcube/logs/errors.log';
        const notAnswered = () => Number(remote('grep -c "did not answer the password copy request" ' + RC_LOG + ' 2>/dev/null || true').trim() || 0);
        const notAnsweredBefore = notAnswered();
        const page = await context.newPage();
        const errors = [];
        page.on('pageerror', e => errors.push(e.message));
        await page.goto(WBASE + '/');
        await page.fill('#rcmloginuser', USER);
        await page.fill('#rcmloginpwd', P1);
        await Promise.all([page.waitForURL(u => /_task=mail/.test(u.search), { timeout: 30000 }), page.click('#rcmloginsubmit')]);
        check('signed in to the webmail', true);
        await sleep(2000);
        check('the password copy request reached the panel (no new "did not answer" in Roundcube\'s log)', notAnswered() === notAnsweredBefore);
        await page.goto(WBASE + '/?_task=settings');
        check('Settings has "Password"', await page.locator('a[href*="_action=plugin.password"]').count() > 0);
        await page.goto(WBASE + '/?_task=settings&_action=plugin.password');
        // The current password is asked for (password_confirm_current): the panel checks it before the change.
        check('its page has the form, with the current password', await page.locator('#curpasswd').count() === 1
            && await page.locator('#newpasswd').count() === 1 && await page.locator('#confpasswd').count() === 1);

        console.log('\n== 3. Too short ==');
        await page.fill('#curpasswd', P1);
        await page.fill('#newpasswd', 'Short1a');
        await page.fill('#confpasswd', 'Short1a');
        await page.locator('button.mainaction, input.mainaction').first().click();
        // Roundcube's messages are in the user's language: their class says what they are.
        await page.waitForSelector('#messagestack .error, #messagestack .warning', { timeout: 15000 });
        const short = (await page.locator('#messagestack').innerText()).trim();
        check('refused (' + short + ')', /12/.test(short));
        check('the first password still works', imap(USER, P1) === 'ok');

        console.log('\n== 4. A good new password ==');
        await page.goto(WBASE + '/?_task=settings&_action=plugin.password');
        await page.fill('#curpasswd', P1);
        await page.fill('#newpasswd', P2);
        await page.fill('#confpasswd', P2);
        await page.locator('button.mainaction, input.mainaction').first().click();
        await page.waitForSelector('#messagestack .confirmation, #messagestack .error', { timeout: 30000 });
        const saved = (await page.locator('#messagestack').innerText()).trim();
        check('saved (' + saved + ')', await page.locator('#messagestack .confirmation').count() > 0
            && await page.locator('#messagestack .error').count() === 0);
        check('IMAP takes the new password', imap(USER, P2) === 'ok');
        check('IMAP refuses the old one', imap(USER, P1) === 'refused');
        check('no script errors in the webmail (' + errors.join(' | ').slice(0, 160) + ')', errors.length === 0);
    } catch (e) {
        check('the run went to the end (' + e.message.split('\n')[0] + ')', false);
    } finally {
        console.log('\n== 5. Everything removed ==');
        try {
            if (made.mailbox) await api('/api/mailboxes?id=' + made.mailbox, 'DELETE', {});
            if (made.domain) await api('/api/domains?id=' + made.domain, 'DELETE', {});
            if (made.folder.includes(TOKEN)) remote('rm -rf -- "' + made.folder + '"');
            const left = ((await api('/api/mailboxes', 'GET')).mailboxes || []).filter(b => b.email.includes(TOKEN));
            const leftDomains = ((await api('/api/domains', 'GET')).domains || []).filter(d => d.domain.includes(TOKEN));
            check('mailbox, domain and mail folder of this run removed', left.length === 0 && leftDomains.length === 0
                && remote('test -e "' + made.folder + '" && echo there || true').trim() === '');
        } catch (e) {
            check('the cleanup went to the end (' + e.message.split('\n')[0] + ')', false);
        }
        await browser.close();
        tunnels.forEach(t => t.kill());
    }
    console.log(failures ? '\n' + failures + ' CHECKS FAILED' : '\nALL OK');
    process.exit(failures ? 1 : 0);
})();
