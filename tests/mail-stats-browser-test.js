// The sent and received counts, end to end on the FreeBSD test machine (MailLogStats reads Postfix's log every
// minute into email_statistics, the Statistics page reads it): real messages, then what the page says. Here only the
// browser runs; the panel is the test machine's own, through an ssh tunnel.
//
//   1. A domain of this run (ms-<token>.test), mailboxes A and B; the counts of today before.
//   2. Real mail: A sends B two messages (587, signed in); a message from outside reaches B; A sends to an address of
//      the domain that does not exist (it bounces, and Postfix's notice reaches A); GTUBE from outside to B (Rspamd
//      refuses it as spam). The senders from outside are addresses of the run's domain: example.org has a null MX, and
//      Postfix refuses it as a sender (measured).
//   3. Within two minutes the counts of today grow by exactly that: 2 sent, 4 received (3 for B, the notice for A),
//      1 bounced, 1 spam; and the domain's row says the same.
//   4. The Statistics page shows them, with the note that says what each number counts.
//   5. Everything removed: mailboxes, domain, mail folder.
//
// ONLY on the test machine. Usage:
//   HOST=<panel name> CHROMIUM=<chrome binary> REMOTE=root@<test machine> REMOTE_KEY=<ssh key> \
//     NODE_PATH=$(npm root -g) node tests/mail-stats-browser-test.js
const { chromium } = require('playwright');
const { spawn, execFileSync } = require('child_process');
const net = require('net');

const REMOTE = process.env.REMOTE, HOST = process.env.HOST;
const SSH = ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-i', process.env.REMOTE_KEY.replace(/^~/, process.env.HOME)];
const PORT = 25000 + Math.floor(Math.random() * 1000);
const BASE = 'https://' + HOST + ':' + PORT;
const TOKEN = 'ms' + Date.now().toString(36);
const OUTSIDE = REMOTE.split('@').pop();
const PW = 'Stats' + TOKEN + 'Pw5Ln2';
const GTUBE = 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X';
let failures = 0;
function check(what, ok) { console.log((ok ? '  OK     ' : '  FAILED ') + what); if (!ok) failures++; }
function remote(cmd, input) { return execFileSync('ssh', SSH.concat([REMOTE, cmd]), { encoding: 'utf8', input: input }); }
function code(out) { const m = out.match(/One-time access code for [^:]*: (\d{4} \d{4})/); return m ? m[1] : ''; }
function portOpen(port) {
    return new Promise(resolve => { const s = net.connect(port, '127.0.0.1', () => { s.destroy(); resolve(true); }); s.on('error', () => resolve(false)); });
}
const sleep = ms => new Promise(r => setTimeout(r, ms));

// On the test machine: a submission with authentication (587), or a message from outside (25). It prints 250 or the
// refusal. The password, when there is one, goes on stdin; the body is the 5th argument.
const HELPER = `
import smtplib, ssl, sys
from email.message import EmailMessage
what, sender, rcpt, subject, body = sys.argv[1:6]
m = EmailMessage(); m['From'] = sender; m['To'] = rcpt; m['Subject'] = subject; m.set_content(body)
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
try:
    if what == 'submit':
        with smtplib.SMTP('127.0.0.1', 587, timeout=60) as s:
            s.starttls(context=ctx); s.login(sender, sys.stdin.read()); s.send_message(m)
    else:
        with smtplib.SMTP(what, 25, timeout=60) as s:
            s.ehlo('probe.example.net'); s.send_message(m)
    print('250')
except smtplib.SMTPResponseException as e:
    print(e.smtp_code, e.smtp_error.decode())
except smtplib.SMTPRecipientsRefused as e:
    c, t = list(e.recipients.values())[0]; print(c, t.decode())
`;
const HELPER_FILE = '/tmp/mail-stats-' + TOKEN + '.py';

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
    const send = (how, from, to, subject, body) => remote('/usr/local/bin/python3.12 ' + HELPER_FILE + ' ' + how + ' ' + from + ' ' + to + ' ' + subject + " '" + body + "'", how === 'submit' ? PW : '').trim();
    try {
        remote('cat > ' + HELPER_FILE, HELPER);
        page = await (await browser.newContext({ ignoreHTTPSErrors: true, locale: 'en-GB' })).newPage();
        const errors = [];
        page.on('pageerror', e => errors.push(e.message));
        await page.goto(BASE + '/index');
        await page.click('#linkConsole');
        await page.fill('#consoleCode', code(remote('cd /home/panel && /usr/local/openjdk25/bin/java -jar daemoxcp-mail.jar --access-code 2>/dev/null')));
        await Promise.all([page.waitForURL(u => !u.pathname.endsWith('/index'), { timeout: 30000 }), page.click('#btnConsole')]);
        await page.goto(BASE + '/statistics');

        console.log('== 1. The mailboxes of this run (' + TOKEN + ') ==');
        const D = TOKEN + '.test', A = 'a-' + TOKEN + '@' + D, B = 'b-' + TOKEN + '@' + D;
        const dom = await api('/api/domains', 'POST', { domain: D, description: 'statistics test' });
        check('domain ' + D + ' created', dom.success === true);
        made.domain = dom.id || 0;
        made.folder = '/var/vmail/' + D;
        for (const email of [A, B]) {
            const r = await api('/api/mailboxes', 'POST', { email, password: PW, name: 'Stats test', quota_mb: 50, receive_enabled: true });
            check('mailbox ' + email + (r.success ? '' : ' (' + r.error + ')'), r.success === true);
        }
        ((await api('/api/mailboxes', 'GET')).mailboxes || []).filter(b => b.email.includes(TOKEN)).forEach(b => made.mailboxes.push(b.id));
        const before = (await api('/api/statistics?days=1', 'GET')).totals || {};
        console.log('  (today before: ' + JSON.stringify(before) + ')');

        console.log('\n== 2. Real mail ==');
        console.log('  A to B: ' + send('submit', A, B, 'S1' + TOKEN, 'one') + ', ' + send('submit', A, B, 'S2' + TOKEN, 'two'));
        console.log('  outside to B: ' + send(OUTSIDE, 'news-' + TOKEN + '@' + D, B, 'IN' + TOKEN, 'hello'));
        console.log('  A to a missing address: ' + send('submit', A, 'ghost-' + TOKEN + '@' + D, 'G' + TOKEN, 'nobody'));
        console.log('  GTUBE to B: ' + send(OUTSIDE, 'spam-' + TOKEN + '@' + D, B, 'SP' + TOKEN, GTUBE));

        console.log('\n== 3. The counts ==');
        let now = {}, domain = {};
        const want = { sent: 2, received: 4, bounced: 1, spam: 1 };
        const delta = k => (now[k] || 0) - (before[k] || 0);
        for (let i = 0; i < 100; i++) {
            const s = await api('/api/statistics?days=1', 'GET');
            now = s.totals || {};
            domain = (s.domains || []).find(d => d.domain === D) || {};
            if (Object.keys(want).every(k => delta(k) >= want[k])) break;
            await sleep(1000);
        }
        console.log('  (today after: ' + JSON.stringify(now) + '; the domain: ' + JSON.stringify(domain) + ')');
        for (const k of Object.keys(want))
            check(k + ': +' + want[k] + ' (' + delta(k) + ')', delta(k) === want[k]);
        check('the domain\'s row says the same', Object.keys(want).every(k => domain[k] === want[k]));

        console.log('\n== 4. The Statistics page ==');
        await page.reload();
        await page.waitForFunction(() => document.getElementById('totalSent').textContent.trim() !== '-', null, { timeout: 30000 });
        const shown = await page.evaluate(() => ['totalSent', 'totalReceived', 'totalSpam', 'totalBounced'].map(id => document.getElementById(id).textContent.trim()));
        check('the cards show the counts (' + shown.join(', ') + ')', Number(shown[0].replace(/\D/g, '')) >= 2 && Number(shown[1].replace(/\D/g, '')) >= 3);
        const note = (await page.locator('.alert-info[role="note"]').first().innerText()).trim();
        check('the note says what each number counts (' + note.slice(0, 60) + '...)', /Postfix's log/.test(note) && /UTC/.test(note));
        check('no warning that nothing is collected', await page.locator('.alert-warning[role="note"]').count() === 0);
        check('no script errors (' + errors.join(' | ').slice(0, 160) + ')', errors.length === 0);
    } catch (e) {
        check('the run went to the end (' + e.message.split('\n')[0] + ')', false);
    } finally {
        console.log('\n== 5. Everything removed ==');
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
