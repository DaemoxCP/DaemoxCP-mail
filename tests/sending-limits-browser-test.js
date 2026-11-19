// The sending limits applied for real, end to end on the FreeBSD test machine (SendingLimits: the panel as Postfix's
// policy service): real submissions with authentication on 587, and what Postfix answers. Here only the browser runs;
// the panel is the test machine's own, through an ssh tunnel.
//
//   1. A domain of this run (sl-<token>.test), a sender and a receiver; Postfix asks the panel (smtpd_data_restrictions).
//   2. The sender gets a limit of 3 messages per hour, from the panel.
//   3. Three messages go; the fourth gets 450 4.7.1 at DATA, saying the hourly limit.
//   4. Incoming mail for the sender (no authentication, from outside mynetworks) is not counted and goes.
//   5. The Sending limits page: "Applied", the sender's row says 3 in the hour, and it is among the senders of the day.
//   6. The limit raised to 10 from the panel: the fourth goes at once.
//   7. The counts are saved on disk within a minute.
//   8. The panel stopped: Postfix gets no answer and lets the mail pass (default_action=DUNNO). Started again, the
//      counts are back from the disk.
//   9. Everything removed: the limit, mailboxes, domain, mail folder.
//
// ONLY on the test machine: it stops and starts the panel. Usage:
//   HOST=<panel name> CHROMIUM=<chrome binary> REMOTE=root@<test machine> REMOTE_KEY=<ssh key> \
//     NODE_PATH=$(npm root -g) node tests/sending-limits-browser-test.js
const { chromium } = require('playwright');
const { spawn, execFileSync } = require('child_process');
const net = require('net');

const REMOTE = process.env.REMOTE, HOST = process.env.HOST;
const SSH = ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-i', process.env.REMOTE_KEY.replace(/^~/, process.env.HOME)];
const PORT = 25000 + Math.floor(Math.random() * 1000);
const BASE = 'https://' + HOST + ':' + PORT;
const TOKEN = 'sl' + Date.now().toString(36);
const OUTSIDE = REMOTE.split('@').pop();
const PW = 'Limit' + TOKEN + 'Pw4Rt6';
const STATE = '/var/db/daemoxcp-mail/sending-counts.txt';
let failures = 0;
function check(what, ok) { console.log((ok ? '  OK     ' : '  FAILED ') + what); if (!ok) failures++; }
function remote(cmd, input) { return execFileSync('ssh', SSH.concat([REMOTE, cmd]), { encoding: 'utf8', input: input }); }
function code(out) { const m = out.match(/One-time access code for [^:]*: (\d{4} \d{4})/); return m ? m[1] : ''; }
function portOpen(port) {
    return new Promise(resolve => { const s = net.connect(port, '127.0.0.1', () => { s.destroy(); resolve(true); }); s.on('error', () => resolve(false)); });
}
const sleep = ms => new Promise(r => setTimeout(r, ms));

// On the test machine: a submission with authentication (587, STARTTLS), or a message from outside (25, no
// authentication). It prints "250" or the code and text of the refusal. The password goes on stdin.
const HELPER = `
import smtplib, ssl, sys
from email.message import EmailMessage
what, sender, rcpt, subject = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
m = EmailMessage(); m['From'] = sender; m['To'] = rcpt; m['Subject'] = subject; m.set_content('sending limits test')
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
try:
    if what == 'submit':
        with smtplib.SMTP('127.0.0.1', 587, timeout=60) as s:
            s.starttls(context=ctx); s.login(sender, sys.stdin.read()); s.send_message(m)
    else:
        with smtplib.SMTP(what, 25, timeout=60) as s:
            s.ehlo('probe.example.net'); s.send_message(m)
    print('250')
except smtplib.SMTPDataError as e:
    print(e.smtp_code, e.smtp_error.decode())
except smtplib.SMTPRecipientsRefused as e:
    c, t = list(e.recipients.values())[0]; print(c, t.decode())
`;
const HELPER_FILE = '/tmp/sending-limits-' + TOKEN + '.py';

(async () => {
    let tunnel = spawn('ssh', SSH.concat(['-N', '-o', 'ExitOnForwardFailure=yes', '-L', PORT + ':127.0.0.1:2096', REMOTE]), { stdio: 'ignore' });
    for (let i = 0; i < 40 && !(await portOpen(PORT)); i++) await sleep(250);
    const browser = await chromium.launch({ executablePath: process.env.CHROMIUM, args: ['--host-resolver-rules=MAP ' + HOST + ' 127.0.0.1'] });
    const context = await browser.newContext({ ignoreHTTPSErrors: true, locale: 'en-GB' });
    const made = { mailboxes: [], domain: 0, folder: '', limit: 0 };
    let page;
    const api = (path, method, body) => page.evaluate(({ path, method, body }) => fetch(path, {
        method, headers: { 'Content-Type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(Object.assign({ csrf_token: document.getElementById('csrf_token').value }, body))
    }).then(r => r.json()), { path, method, body });
    async function signIn(where) {
        page = await context.newPage();
        await page.goto(BASE + '/index');
        await page.click('#linkConsole');
        await page.fill('#consoleCode', code(remote('cd /home/panel && /usr/local/openjdk25/bin/java -jar daemoxcp-mail.jar --lang en --access-code 2>/dev/null')));
        await Promise.all([page.waitForURL(u => !u.pathname.endsWith('/index'), { timeout: 30000 }), page.click('#btnConsole')]);
        await page.goto(BASE + where);
    }
    const submit = (from, to, subject) => remote('/usr/local/bin/python3.12 ' + HELPER_FILE + ' submit ' + from + ' ' + to + ' ' + subject, PW).trim();
    const fromOutside = (from, to, subject) => remote('/usr/local/bin/python3.12 ' + HELPER_FILE + ' ' + OUTSIDE + ' ' + from + ' ' + to + ' ' + subject).trim();
    let SENDER = '', RCV = '';
    const setLimit = async (hourly) => {
        const box = ((await api('/api/mailboxes', 'GET')).mailboxes || []).find(b => b.email === SENDER);
        return api('/api/ratelimits', 'POST', { action: 'save_mailbox', mailbox_id: box.id, hourly: hourly, daily: 100, enabled: true });
    };
    try {
        remote('cat > ' + HELPER_FILE, HELPER);
        await signIn('/ratelimits');
        const errors = [];
        page.on('pageerror', e => errors.push(e.message));

        console.log('== 1. The mailboxes of this run (' + TOKEN + ') ==');
        const D = TOKEN + '.test';
        SENDER = 'sender-' + TOKEN + '@' + D; RCV = 'rcv-' + TOKEN + '@' + D;
        const dom = await api('/api/domains', 'POST', { domain: D, description: 'sending limits test' });
        check('domain ' + D + ' created', dom.success === true);
        made.domain = dom.id || 0;
        made.folder = '/var/vmail/' + D;
        for (const email of [SENDER, RCV]) {
            const r = await api('/api/mailboxes', 'POST', { email, password: PW, name: 'Limits test', quota_mb: 50, receive_enabled: true });
            check('mailbox ' + email + (r.success ? '' : ' (' + r.error + ')'), r.success === true);
        }
        ((await api('/api/mailboxes', 'GET')).mailboxes || []).filter(b => b.email.includes(TOKEN)).forEach(b => made.mailboxes.push(b.id));
        check('Postfix asks the panel at DATA (' + remote('postconf -h smtpd_data_restrictions').trim() + ')',
            remote('postconf -h smtpd_data_restrictions').includes('private/daemoxcp-sending-limits'));

        console.log('\n== 2. A limit of 3 per hour ==');
        const saved = await setLimit(3);
        check('saved from the panel', saved.success === true);
        const lim = ((await api('/api/ratelimits', 'GET')).limits || []).find(l => l.email === SENDER);
        made.limit = lim ? lim.id : 0;

        console.log('\n== 3. Real submissions ==');
        const sent = [1, 2, 3].map(i => submit(SENDER, RCV, 'M' + i + TOKEN));
        check('three messages go (' + sent.join(', ') + ')', sent.every(s => s === '250'));
        const fourth = submit(SENDER, RCV, 'M4' + TOKEN);
        check('the fourth: 450 4.7.1, the hourly limit (' + fourth + ')', /^450 4\.7\.1 .*3 messages per hour/.test(fourth));

        console.log('\n== 4. Incoming mail ==');
        const inbound = fromOutside(RCV, SENDER, 'IN' + TOKEN);
        check('mail for the sender from outside is not counted and goes (' + inbound + ')', inbound === '250');

        console.log('\n== 5. The Sending limits page ==');
        await page.reload();
        await page.waitForSelector('#rlEnforcement:not([hidden])', { timeout: 30000 });
        const enf = (await page.locator('#rlEnforcement').innerText()).trim();
        check('"Applied" (' + enf.slice(0, 60) + '...)', /^Applied/.test(enf) && /alert-success/.test(await page.locator('#rlEnforcement').getAttribute('class')));
        const row = page.locator('#limitsBody tr', { hasText: SENDER });
        const sentCell = (await row.locator('td').nth(4).innerText()).trim();
        check('the sender\'s row: 3 in the hour, 3 in the day (' + sentCell + ')', sentCell === '3 / 3');
        const top = (await page.locator('#rlTopSenders').innerText()).trim();
        check('among the senders of the day (' + top + ')', top.includes(SENDER + ' (3)'));

        console.log('\n== 6. Raised to 10 ==');
        await setLimit(10);
        check('the fourth goes at once (' + submit(SENDER, RCV, 'M5' + TOKEN) + ')', submit(SENDER, RCV, 'M6' + TOKEN) === '250');

        console.log('\n== 7. Saved on disk ==');
        let onDisk = false;
        for (let i = 0; i < 75 && !onDisk; i++) { onDisk = remote('grep -c "^' + SENDER + ' " ' + STATE + ' 2>/dev/null || true').trim() !== '0' && remote('test -f ' + STATE + ' && echo y || true').trim() === 'y'; if (!onDisk) await sleep(1000); }
        check('the counts are in ' + STATE + ' within a minute', onDisk);
        check('only root reads them (' + remote('stat -f "%Sp %Su" ' + STATE).trim() + ')', remote('stat -f "%Sp %Su" ' + STATE).trim() === '-rw------- root');

        console.log('\n== 8. The panel stopped ==');
        await setLimit(5);
        const blocked = submit(SENDER, RCV, 'M7' + TOKEN);
        check('with the panel running, over the limit: refused (' + blocked + ')', blocked.startsWith('450'));
        remote('service daemoxcp_mail stop >/dev/null 2>&1 || true');
        const passed = submit(SENDER, RCV, 'M8' + TOKEN);
        check('stopped: Postfix gets no answer and lets it pass (' + passed + ')', passed === '250');
        remote('service daemoxcp_mail start >/dev/null 2>&1 || true');
        tunnel.kill();
        let back = false;
        for (let i = 0; i < 120 && !back; i++) { await sleep(1000); back = remote('test -S /var/spool/postfix/private/daemoxcp-sending-limits && sockstat -l | grep -c ":2096 " || true').trim() !== '' && remote('sockstat -l | grep -c ":2096 " || true').trim() !== '0'; }
        check('the panel is back', back);
        tunnel = spawn('ssh', SSH.concat(['-N', '-o', 'ExitOnForwardFailure=yes', '-L', PORT + ':127.0.0.1:2096', REMOTE]), { stdio: 'ignore' });
        for (let i = 0; i < 40 && !(await portOpen(PORT)); i++) await sleep(250);
        await sleep(3000);
        await signIn('/ratelimits');
        const after = await api('/api/ratelimits', 'GET');
        const u = ((after.enforcement || {}).usage || {})[SENDER] || {};
        check('the counts are back from the disk (' + JSON.stringify(u) + ': the 5 counted before the stop)', u.hour === 5);
        const again = submit(SENDER, RCV, 'M9' + TOKEN);
        check('and the limit holds again (' + again + ')', again.startsWith('450'));
        check('no script errors (' + errors.join(' | ').slice(0, 160) + ')', errors.length === 0);
    } catch (e) {
        check('the run went to the end (' + e.message.split('\n')[0] + ')', false);
    } finally {
        console.log('\n== 9. Everything removed ==');
        try {
            if (made.limit) await api('/api/ratelimits', 'POST', { action: 'delete', id: made.limit });
            for (const id of made.mailboxes) await api('/api/mailboxes?id=' + id, 'DELETE', {});
            if (made.domain) await api('/api/domains?id=' + made.domain, 'DELETE', {});
            if (made.folder.includes(TOKEN)) remote('rm -rf -- "' + made.folder + '"');
            remote('rm -f ' + HELPER_FILE);
            const left = ((await api('/api/mailboxes', 'GET')).mailboxes || []).filter(b => b.email.includes(TOKEN));
            const leftLimits = ((await api('/api/ratelimits', 'GET')).limits || []).filter(l => String(l.email).includes(TOKEN));
            check('limit, mailboxes, domain and mail folder of this run removed', left.length === 0 && leftLimits.length === 0
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
