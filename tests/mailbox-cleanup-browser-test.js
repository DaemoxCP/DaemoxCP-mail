// Automatic emptying of Junk and Trash, end to end on the FreeBSD test machine: the panel's mailbox window, the
// webmail's settings (the daemoxcp_mail_cleanup plugin the panel installs), and Dovecot after each change. Here only
// the browser runs; the panel and the webmail are the test machine's own, through ssh tunnels.
//
//   1. A domain and a mailbox of this run (mc-<token>.test), made with the panel's API: never, by default.
//   2. The panel: the mailbox's window has the two choices (never, 7-90 days) with their labels; Junk 30 and Trash 14
//      saved; opened again it shows them; Dovecot's userdb gives 30d and 14d.
//   3. The webmail: signed in with the mailbox's password; the mail view has the spam button (markasjunk); Settings,
//      Preferences has «Automatic emptying», which shows the panel's 30 and 14; Junk 7 and Trash never saved; the
//      panel reads 7 and 0, Dovecot gives 7d for Junk and nothing for Trash. No script errors.
//   4. Everything removed: mailbox, domain, mail folder.
//
// ONLY on the test machine. Usage:
//   HOST=<panel name> WEBMAIL=<webmail name> CHROMIUM=<chrome binary> REMOTE=root@<test machine> REMOTE_KEY=<ssh key> \
//     NODE_PATH=$(npm root -g) node tests/mailbox-cleanup-browser-test.js
// The webmail's port on the machine is 8443 (the panel's nginx, behind Cloudflare); WEBMAIL_PORT for another one.
const { chromium } = require('playwright');
const { spawn, execFileSync } = require('child_process');
const net = require('net');

const REMOTE = process.env.REMOTE, HOST = process.env.HOST, WEBMAIL = process.env.WEBMAIL;
const SSH = ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-i', process.env.REMOTE_KEY.replace(/^~/, process.env.HOME)];
const PORT = 26000 + Math.floor(Math.random() * 1000), WPORT = PORT + 1000;
const BASE = 'https://' + HOST + ':' + PORT, WBASE = 'https://' + WEBMAIL + ':' + WPORT;
const TOKEN = 'mc' + Date.now().toString(36);
const PASSWORD = 'Cleanup' + TOKEN + 'Pw7Kd2';
let failures = 0;
function check(what, ok) { console.log((ok ? '  OK     ' : '  FAILED ') + what); if (!ok) failures++; }
function remote(cmd, input) { return execFileSync('ssh', SSH.concat([REMOTE, cmd]), { encoding: 'utf8', input: input }); }
function code(out) { const m = out.match(/One-time access code for [^:]*: (\d{4} \d{4})/); return m ? m[1] : ''; }
function portOpen(port) {
    return new Promise(resolve => { const s = net.connect(port, '127.0.0.1', () => { s.destroy(); resolve(true); }); s.on('error', () => resolve(false)); });
}
const sleep = ms => new Promise(r => setTimeout(r, ms));
// Dovecot's view of the mailbox: the two autoexpunge fields its userdb gives, or '' for none.
function userdb(user) {
    return remote('doveadm user ' + user).split('\n').filter(l => l.includes('mailbox_autoexpunge'))
        .map(l => l.trim().replace(/\s+/g, ' ')).sort().join('; ');
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
        const panelErrors = [];
        panel.on('pageerror', e => panelErrors.push(e.message));
        await panel.goto(BASE + '/index');
        await panel.click('#linkConsole');
        await panel.fill('#consoleCode', code(remote('cd /home/panel && /usr/local/openjdk25/bin/java -jar daemoxcp-mail.jar --lang en --access-code 2>/dev/null')));
        await Promise.all([panel.waitForURL(u => !u.pathname.endsWith('/index'), { timeout: 30000 }), panel.click('#btnConsole')]);
        await panel.goto(BASE + '/mailboxes');

        console.log('== 1. A domain and a mailbox of this run (' + TOKEN + ') ==');
        const D = TOKEN + '.test', USER = 'user-' + TOKEN + '@' + D;
        const dom = await api('/api/domains', 'POST', { domain: D, description: 'automatic emptying test' });
        check('domain ' + D + ' created', dom.success === true);
        made.domain = dom.id || 0;
        made.folder = '/var/vmail/' + D;
        const mb = await api('/api/mailboxes', 'POST', { email: USER, password: PASSWORD, name: 'Cleanup test', quota_mb: 50, receive_enabled: true });
        check('mailbox ' + USER + ' created' + (mb.success ? '' : ' (' + mb.error + ')'), mb.success === true);
        const box = ((await api('/api/mailboxes', 'GET')).mailboxes || []).find(b => b.email === USER);
        made.mailbox = box ? box.id : 0;
        check('never, by default (' + (box ? box.junk_expunge_days + '/' + box.trash_expunge_days : '-') + ')', box && box.junk_expunge_days === 0 && box.trash_expunge_days === 0);
        check('  Dovecot gets nothing', userdb(USER) === '');

        console.log('\n== 2. The panel ==');
        await panel.reload();
        await panel.evaluate(id => editMailbox(id), made.mailbox);
        await panel.waitForFunction(() => document.getElementById('editMailboxModal').classList.contains('show')
            && document.getElementById('editMbEmail').value !== '', null, { timeout: 15000 });
        const options = await panel.locator('#editMbJunkDays option').evaluateAll(os => os.map(o => o.value + '=' + o.textContent.trim()));
        check('Junk: never and 7-90 days (' + options.join(', ') + ')', options.join(',') === '0=Never,7=After 7 days,14=After 14 days,30=After 30 days,60=After 60 days,90=After 90 days');
        check('both have their label, the group its help', await panel.locator('label[for=editMbJunkDays]').count() === 1
            && await panel.locator('label[for=editMbTrashDays]').count() === 1 && (await panel.locator('#editMbCleanupHelp').innerText()).length > 20);
        check('opened: never and never', await panel.inputValue('#editMbJunkDays') === '0' && await panel.inputValue('#editMbTrashDays') === '0');
        await panel.selectOption('#editMbJunkDays', '30');
        await panel.selectOption('#editMbTrashDays', '14');
        const saved = panel.waitForResponse(r => r.url().endsWith('/api/mailboxes') && r.request().method() === 'PUT');
        await panel.locator('#editMailboxModal .modal-footer .btn-mail').click();
        check('saved', (await (await saved).json()).success === true);
        await panel.waitForFunction(() => !document.getElementById('editMailboxModal').classList.contains('show'), null, { timeout: 15000 });
        await panel.evaluate(id => editMailbox(id), made.mailbox);
        await panel.waitForFunction(() => document.getElementById('editMbJunkDays').value === '30', null, { timeout: 15000 }).catch(() => {});
        check('opened again: 30 and 14', await panel.inputValue('#editMbJunkDays') === '30' && await panel.inputValue('#editMbTrashDays') === '14');
        await panel.keyboard.press('Escape');
        const after2 = userdb(USER);
        check('Dovecot: Junk 30d, Trash 14d (' + after2 + ')', after2 === 'namespace/inbox/mailbox/Junk/mailbox_autoexpunge 30d; namespace/inbox/mailbox/Trash/mailbox_autoexpunge 14d');
        check('no script errors in the panel (' + panelErrors.join(' | ').slice(0, 160) + ')', panelErrors.length === 0);

        console.log('\n== 3. The webmail ==');
        const page = await context.newPage();
        const errors = [];
        page.on('pageerror', e => errors.push(e.message));
        await page.goto(WBASE + '/');
        await page.fill('#rcmloginuser', USER);
        await page.fill('#rcmloginpwd', PASSWORD);
        await Promise.all([page.waitForURL(u => /_task=mail/.test(u.search), { timeout: 30000 }), page.click('#rcmloginsubmit')]);
        check('signed in to the webmail', true);
        check('the mail view has the spam button (markasjunk)', await page.locator('a.junk, a.button.junk, [data-command=plugin\\.markasjunk\\.junk]').count() > 0
            || await page.locator('a[onclick*="markasjunk"], a[href*="markasjunk"]').count() > 0
            || await page.evaluate(() => !!(window.rcmail && rcmail.commands && ('plugin.markasjunk.junk' in rcmail.commands || 'plugin.markasjunk' in rcmail.commands))));
        await page.goto(WBASE + '/?_task=settings&_action=preferences');
        check('Preferences has «Automatic emptying»', await page.locator('#rcmrowdaemoxcp_cleanup, tr#rcmrowdaemoxcp_cleanup').count() > 0);
        const prefs = await context.newPage();
        prefs.on('pageerror', e => errors.push(e.message));
        await prefs.goto(WBASE + '/?_task=settings&_action=edit-prefs&_section=daemoxcp_cleanup&_framed=1');
        check('it shows the panel\'s 30 and 14', await prefs.inputValue('#rcmfd_daemoxcp_junk') === '30' && await prefs.inputValue('#rcmfd_daemoxcp_trash') === '14');
        check('  with labels', await prefs.locator('label[for=rcmfd_daemoxcp_junk]').count() === 1 && await prefs.locator('label[for=rcmfd_daemoxcp_trash]').count() === 1);
        await prefs.selectOption('#rcmfd_daemoxcp_junk', '7');
        await prefs.selectOption('#rcmfd_daemoxcp_trash', '0');
        await Promise.all([prefs.waitForLoadState('load'), prefs.locator('.formbuttons .mainaction, .formbuttons button.submit').first().click()]);
        await prefs.waitForSelector('#rcmfd_daemoxcp_junk', { timeout: 30000 });
        check('saved: the page shows 7 and never', await prefs.inputValue('#rcmfd_daemoxcp_junk') === '7' && await prefs.inputValue('#rcmfd_daemoxcp_trash') === '0');
        const box3 = ((await api('/api/mailboxes', 'GET')).mailboxes || []).find(b => b.email === USER);
        check('the panel reads 7 and 0', box3 && box3.junk_expunge_days === 7 && box3.trash_expunge_days === 0);
        const after3 = userdb(USER);
        check('Dovecot: Junk 7d, nothing for Trash (' + after3 + ')', after3 === 'namespace/inbox/mailbox/Junk/mailbox_autoexpunge 7d');
        check('no script errors in the webmail (' + errors.join(' | ').slice(0, 160) + ')', errors.length === 0);
    } catch (e) {
        check('the run went to the end (' + e.message.split('\n')[0] + ')', false);
    } finally {
        console.log('\n== 4. Everything removed ==');
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
