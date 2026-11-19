// Mailbox quotas applied for real, end to end on the FreeBSD test machine (Dovecot 2.4, DovecotQuota): real messages
// over SMTP, and what Postfix, Dovecot, IMAP and the panel's page say. Here only the browser runs; the panel is the test
// machine's own, through an ssh tunnel.
//
//   1. A domain of this run (q-<token>.test), a mailbox with a 1 MB quota and one without a limit; Dovecot gives the
//      first its limit (doveadm user).
//   2. Empty: from outside (the machine's own address, not in mynetworks) Postfix accepts the recipient.
//   3. A 2 MB message from the machine itself fills it (Dovecot lets the delivery that crosses the limit through, its
//      grace); then from outside the recipient gets 452 4.2.2 from quota-status, the mailbox without a limit 250.
//   4. One more message from the machine itself: LMTP refuses it (the quota plugin is on for LMTP), and the bounce
//      reaches the sender, the other mailbox, saying the quota.
//   5. IMAP: GETQUOTAROOT gives the limit (imap_quota).
//   6. The Mailboxes page: the full mailbox says so, with a bar at 100 %, the other one how much it uses.
//   7. The limit taken away from the panel (0 = no limit): from outside the recipient is accepted again at once.
//   8. Everything removed: mailboxes, domain, mail folder.
//
// ONLY on the test machine. Usage:
//   HOST=<panel name> CHROMIUM=<chrome binary> REMOTE=root@<test machine> REMOTE_KEY=<ssh key> \
//     NODE_PATH=$(npm root -g) node tests/quota-browser-test.js
const { chromium } = require('playwright');
const { spawn, execFileSync } = require('child_process');
const net = require('net');

const REMOTE = process.env.REMOTE, HOST = process.env.HOST;
const SSH = ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-i', process.env.REMOTE_KEY.replace(/^~/, process.env.HOME)];
const PORT = 25000 + Math.floor(Math.random() * 1000);
const BASE = 'https://' + HOST + ':' + PORT;
const TOKEN = 'q' + Date.now().toString(36);
const OUTSIDE = REMOTE.split('@').pop();
const PW = 'Quota' + TOKEN + 'Pw8Mz3';
let failures = 0;
function check(what, ok) { console.log((ok ? '  OK     ' : '  FAILED ') + what); if (!ok) failures++; }
function remote(cmd, input) { return execFileSync('ssh', SSH.concat([REMOTE, cmd]), { encoding: 'utf8', input: input, maxBuffer: 16 * 1024 * 1024 }); }
function code(out) { const m = out.match(/One-time access code for [^:]*: (\d{4} \d{4})/); return m ? m[1] : ''; }
function portOpen(port) {
    return new Promise(resolve => { const s = net.connect(port, '127.0.0.1', () => { s.destroy(); resolve(true); }); s.on('error', () => resolve(false)); });
}
const sleep = ms => new Promise(r => setTimeout(r, ms));

// The helpers run on the test machine with its Python, from a file of this run.
const HELPER = `
import imaplib, os, smtplib, ssl, sys
from email.message import EmailMessage
what = sys.argv[1]
if what == 'send':
    sender, rcpt, subject, size = sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])
    m = EmailMessage(); m['From'] = sender; m['To'] = rcpt; m['Subject'] = subject
    m.set_content('quota test ' + subject)
    if size:
        m.add_attachment(os.urandom(size), maintype='application', subtype='octet-stream', filename='fill.bin')
    with smtplib.SMTP('127.0.0.1', 25, timeout=60) as s:
        s.send_message(m)
    print('sent')
elif what == 'rcpt':
    host, sender, rcpt = sys.argv[2], sys.argv[3], sys.argv[4]
    with smtplib.SMTP(host, 25, timeout=30) as s:
        s.ehlo('probe.example.net'); s.mail(sender); code, msg = s.rcpt(rcpt); s.rset()
    print(code, msg.decode())
elif what == 'quotaroot':
    user, password = sys.argv[2], sys.stdin.read()
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    m = imaplib.IMAP4_SSL('127.0.0.1', 993, ssl_context=ctx); m.login(user, password)
    typ, data = m.getquotaroot('INBOX'); m.logout()
    print(' '.join(x.decode() if isinstance(x, bytes) else str(x) for x in sum(data, [])))
`;
const HELPER_FILE = '/tmp/quota-test-' + TOKEN + '.py';
const py = (args, input) => remote('/usr/local/bin/python3.12 ' + HELPER_FILE + ' ' + args, input).trim();
const has = (mailbox, header, value) => remote('doveadm search -u ' + mailbox + ' mailbox INBOX header ' + header + ' "' + value + '" 2>/dev/null || true').trim() !== '';
async function waitFor(fn, seconds) { for (let i = 0; i < seconds; i++) { if (fn()) return true; await sleep(1000); } return false; }

(async () => {
    const tunnel = spawn('ssh', SSH.concat(['-N', '-o', 'ExitOnForwardFailure=yes', '-L', PORT + ':127.0.0.1:2096', REMOTE]), { stdio: 'ignore' });
    for (let i = 0; i < 40 && !(await portOpen(PORT)); i++) await sleep(250);
    const browser = await chromium.launch({ executablePath: process.env.CHROMIUM, args: ['--host-resolver-rules=MAP ' + HOST + ' 127.0.0.1'] });
    const made = { mailboxes: [], domain: 0, folder: '' };
    let page;
    const api = (path, method, body) => page.evaluate(({ path, method, body }) => fetch(path, {
        method, headers: { 'Content-Type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(Object.assign({ csrf_token: document.getElementById('csrf_token').value }, body))
    }).then(r => r.json()), { path, method, body });
    try {
        remote('cat > ' + HELPER_FILE, HELPER);
        page = await (await browser.newContext({ ignoreHTTPSErrors: true, locale: 'en-GB' })).newPage();
        const errors = [];
        page.on('pageerror', e => errors.push(e.message));
        await page.goto(BASE + '/index');
        await page.click('#linkConsole');
        await page.fill('#consoleCode', code(remote('cd /home/panel && /usr/local/openjdk25/bin/java -jar daemoxcp-mail.jar --lang en --access-code 2>/dev/null')));
        await Promise.all([page.waitForURL(u => !u.pathname.endsWith('/index'), { timeout: 30000 }), page.click('#btnConsole')]);
        await page.goto(BASE + '/mailboxes');

        console.log('== 1. The mailboxes of this run (' + TOKEN + ') ==');
        const D = TOKEN + '.test', SMALL = 'small-' + TOKEN + '@' + D, FREE = 'free-' + TOKEN + '@' + D;
        const dom = await api('/api/domains', 'POST', { domain: D, description: 'quota test' });
        check('domain ' + D + ' created', dom.success === true);
        made.domain = dom.id || 0;
        made.folder = '/var/vmail/' + D;
        for (const [email, quota] of [[SMALL, 1], [FREE, 0]]) {
            const r = await api('/api/mailboxes', 'POST', { email, password: PW, name: 'Quota test', quota_mb: quota, receive_enabled: true });
            check('mailbox ' + email + ' (' + (quota ? quota + ' MB' : 'no limit') + ')' + (r.success ? '' : ' (' + r.error + ')'), r.success === true);
        }
        const boxes = ((await api('/api/mailboxes', 'GET')).mailboxes || []).filter(b => b.email.includes(TOKEN));
        boxes.forEach(b => made.mailboxes.push(b.id));
        check('Dovecot gives the small one its limit (' + remote('doveadm user -f quota_storage_size ' + SMALL).trim() + ')',
            remote('doveadm user -f quota_storage_size ' + SMALL).trim() === '1M');

        console.log('\n== 2. Empty ==');
        check('from outside, the recipient is accepted (' + py('rcpt ' + OUTSIDE + ' ' + FREE + ' ' + SMALL) + ')',
            py('rcpt ' + OUTSIDE + ' ' + FREE + ' ' + SMALL).startsWith('250'));

        console.log('\n== 3. Full ==');
        console.log('  (sent: ' + py('send ' + FREE + ' ' + SMALL + ' FILL' + TOKEN + ' 2097152') + ')');
        check('the 2 MB message is delivered (it crosses the limit once: Dovecot\'s grace)', await waitFor(() => has(SMALL, 'subject', 'FILL' + TOKEN), 40));
        const used = remote('doveadm -f tab quota get -u ' + SMALL);
        console.log('  (' + used.trim().split('\n').slice(1).join(' | ') + ')');
        const outside = py('rcpt ' + OUTSIDE + ' ' + FREE + ' ' + SMALL);
        check('from outside, the full mailbox: 452 4.2.2, the sender retries (' + outside + ')', /^452 4\.2\.2/.test(outside));
        check('the mailbox without a limit: 250', py('rcpt ' + OUTSIDE + ' ' + SMALL + ' ' + FREE).startsWith('250'));

        console.log('\n== 4. LMTP ==');
        console.log('  (sent: ' + py('send ' + FREE + ' ' + SMALL + ' MORE' + TOKEN + ' 0') + ')');
        check('the bounce reaches the sender', await waitFor(() => has(FREE, 'subject', 'Undelivered'), 40));
        await sleep(2000);
        check('the message did not land in the full mailbox', !has(SMALL, 'subject', 'MORE' + TOKEN));
        const bounce = remote('doveadm fetch -u ' + FREE + ' text mailbox INBOX header subject Undelivered 2>/dev/null | head -60 || true');
        check('the bounce says the quota (LMTP applies it)', /quota|mailbox is full/i.test(bounce));

        console.log('\n== 5. IMAP ==');
        const root = py('quotaroot ' + SMALL, PW);
        check('GETQUOTAROOT gives the limit, 1024 KB (' + root + ')', /STORAGE \d+ 1024/.test(root));

        console.log('\n== 6. The Mailboxes page ==');
        await page.reload();
        await page.waitForFunction(e => { const c = document.querySelector('.mbx-usage[data-quota-of="' + e + '"]'); return c && c.textContent.trim() !== ''; }, SMALL, { timeout: 30000 });
        const cell = page.locator('.mbx-usage[data-quota-of="' + SMALL + '"]');
        const cellText = (await cell.innerText()).trim();
        check('the full mailbox says so (' + cellText + ')', /^Full \(/.test(cellText));
        check('with a bar at 100 % that says it in words', await cell.locator('[role="progressbar"][aria-valuenow="100"]').count() === 1
            && ((await cell.locator('[role="progressbar"]').getAttribute('aria-label')) || '').includes('100'));
        const freeText = (await page.locator('.mbx-usage[data-quota-of="' + FREE + '"]').innerText()).trim();
        check('the one without a limit says how much it uses (' + freeText + ')', / used$/.test(freeText));
        check('no note that quotas are not applied', await page.locator('#mbQuotaNote').isHidden());

        console.log('\n== 7. No limit ==');
        const small = ((await api('/api/mailboxes', 'GET')).mailboxes || []).find(b => b.email === SMALL);
        const upd = await api('/api/mailboxes', 'PUT', { id: small.id, name: small.name || 'Quota test', quota_mb: 0, active: true, receive_enabled: true });
        check('the limit taken away from the panel', upd.success === true);
        check('from outside, the recipient is accepted again at once (' + py('rcpt ' + OUTSIDE + ' ' + FREE + ' ' + SMALL) + ')',
            py('rcpt ' + OUTSIDE + ' ' + FREE + ' ' + SMALL).startsWith('250'));
        check('no script errors (' + errors.join(' | ').slice(0, 160) + ')', errors.length === 0);
    } catch (e) {
        check('the run went to the end (' + e.message.split('\n')[0] + ')', false);
    } finally {
        console.log('\n== 8. Everything removed ==');
        try {
            for (const id of made.mailboxes) await api('/api/mailboxes?id=' + id, 'DELETE', {});
            if (made.domain) await api('/api/domains?id=' + made.domain, 'DELETE', {});
            if (made.folder.includes(TOKEN)) remote('rm -rf -- "' + made.folder + '"');
            remote('rm -f ' + HELPER_FILE);
            const left = ((await api('/api/mailboxes', 'GET')).mailboxes || []).filter(b => b.email.includes(TOKEN));
            const leftDomains = ((await api('/api/domains', 'GET')).domains || []).filter(d => d.domain.includes(TOKEN));
            check('mailboxes, domain and mail folder of this run removed', left.length === 0 && leftDomains.length === 0
                && remote('test -e "' + made.folder + '" && echo there || true').trim() === '');
        } catch (e) {
            check('the cleanup went to the end (' + e.message.split('\n')[0] + ')', false);
        }
        await browser.close();
        tunnel.kill();
    }
    console.log(failures ? '\n' + failures + ' CHECKS FAILED' : '\nALL OK');
    process.exit(failures ? 1 : 0);
})();
