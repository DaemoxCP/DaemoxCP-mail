// The catch-all, end to end on the FreeBSD test machine: created from the Aliases page, then real messages over SMTP
// to 127.0.0.1:25 and a look with doveadm at where each one landed. Here only the browser runs; the panel is the test
// machine's own, through an ssh tunnel.
//
//   1. A domain of this run (ca-<token>.test), three mailboxes (the catch-all's destination, a mailbox, a mailbox that
//      does not receive) and an alias.
//   2. Aliases page: "Every other address of the domain" empties and disables the name; the catch-all is created, the
//      page says what it does, and the table shows it with its badge. A destination of the same domain that is not a
//      mailbox is refused, saying why.
//   3. Before the catch-all, from outside (the machine's own address, not in mynetworks): an invented address and the
//      mailbox that does not receive are refused at RCPT, the mailbox is accepted. The mailbox map changes nothing
//      while there is no catch-all (with every mailbox in it, the one that does not receive was accepted: measured).
//   4. With the catch-all: from outside every address is accepted. Mail for an invented address goes to the catch-all;
//      the mailbox and the alias keep theirs; the mailbox that does not receive counts as an address that does not
//      exist, and its mail goes to the catch-all.
//   5. The control: without the mailbox map in Postfix (put back right after), the mailbox's mail goes to the
//      catch-all. That is what the map prevents; and meanwhile the panel refuses to create a catch-all.
//   6. Everything removed: aliases, mailboxes, the domain, its mail folder; virtual_alias_maps as before.
//
// ONLY on the test machine. Usage:
//   HOST=<panel name> CHROMIUM=<chrome binary> REMOTE=root@<test machine> REMOTE_KEY=<ssh key> \
//     NODE_PATH=$(npm root -g) node tests/catch-all-browser-test.js
const { chromium } = require('playwright');
const { spawn, execFileSync } = require('child_process');
const net = require('net');

const REMOTE = process.env.REMOTE, HOST = process.env.HOST;
const SSH = ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-i', process.env.REMOTE_KEY.replace(/^~/, process.env.HOME)];
const PORT = 25000 + Math.floor(Math.random() * 1000);
const BASE = 'https://' + HOST + ':' + PORT;
const TOKEN = 'ca' + Date.now().toString(36);
const MAPS_FILE = '/usr/local/etc/postfix/mysql-virtual-aliases.cf';
let failures = 0;
function check(what, ok) { console.log((ok ? '  OK     ' : '  FAILED ') + what); if (!ok) failures++; }
function remote(cmd, input) { return execFileSync('ssh', SSH.concat([REMOTE, cmd]), { encoding: 'utf8', input: input }); }
function code(out) { const m = out.match(/One-time access code for [^:]*: (\d{4} \d{4})/); return m ? m[1] : ''; }
function portOpen(port) {
    return new Promise(resolve => { const s = net.connect(port, '127.0.0.1', () => { s.destroy(); resolve(true); }); s.on('error', () => resolve(false)); });
}
const sleep = ms => new Promise(r => setTimeout(r, ms));

// One message over SMTP on the test machine, with its own subject. "sent", or "refused <code>" at RCPT.
const SENDER = `
import smtplib, sys
from email.message import EmailMessage
rcpt, subject = sys.argv[1], sys.argv[2]
m = EmailMessage()
m['From'] = 'catch-all-test@' + rcpt.split('@')[1]
m['To'] = rcpt
m['Subject'] = subject
m.set_content('catch-all test ' + subject)
try:
    with smtplib.SMTP('127.0.0.1', 25, timeout=30) as s:
        s.send_message(m)
    print('sent')
except smtplib.SMTPRecipientsRefused as e:
    print('refused ' + str(list(e.recipients.values())[0][0]))
`;
function send(rcpt, subject) {
    return remote('/usr/local/bin/python3.12 - ' + rcpt + ' ' + subject, SENDER).trim();
}
// What Postfix answers at RCPT to a client that is not in mynetworks: the machine's own address, from the machine.
// No message is sent (RSET and QUIT after RCPT).
const PROBE = `
import smtplib, sys
host, rcpt = sys.argv[1], sys.argv[2]
with smtplib.SMTP(host, 25, timeout=30) as s:
    s.ehlo('probe.example.net')
    s.mail('catch-all-test@' + rcpt.split('@')[1])
    code, _ = s.rcpt(rcpt)
    s.rset()
    print(code)
`;
const OUTSIDE = REMOTE.split('@').pop();
function rcptFromOutside(rcpt) {
    return Number(remote('/usr/local/bin/python3.12 - ' + OUTSIDE + ' ' + rcpt, PROBE).trim());
}
// Whether a mailbox has a message with that subject (doveadm search).
function has(mailbox, subject) {
    return remote('doveadm search -u ' + mailbox + ' mailbox INBOX header subject ' + subject + ' 2>/dev/null || true').trim() !== '';
}
async function landsIn(mailbox, subject, seconds) {
    for (let i = 0; i < seconds; i++) { if (has(mailbox, subject)) return true; await sleep(1000); }
    return false;
}

(async () => {
    const tunnel = spawn('ssh', SSH.concat(['-N', '-o', 'ExitOnForwardFailure=yes', '-L', PORT + ':127.0.0.1:2096', REMOTE]), { stdio: 'ignore' });
    let up = false;
    for (let i = 0; i < 40 && !up; i++) { await sleep(250); up = await portOpen(PORT); }
    const browser = await chromium.launch({ executablePath: process.env.CHROMIUM, args: ['--host-resolver-rules=MAP ' + HOST + ' 127.0.0.1'] });
    const mapsBefore = remote('postconf -h virtual_alias_maps').trim();
    const made = { mailboxes: [], aliases: [], folders: [], domain: 0 };
    let page;
    const api = (path, method, body) => page.evaluate(({ path, method, body }) => fetch(path, {
        method, headers: { 'Content-Type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(Object.assign({ csrf_token: document.getElementById('csrf_token').value }, body))
    }).then(r => r.json()), { path, method, body });
    try {
        page = await (await browser.newContext({ ignoreHTTPSErrors: true, locale: 'en-GB' })).newPage();
        const errors = [];
        page.on('pageerror', e => errors.push(e.message));
        await page.goto(BASE + '/index');
        await page.click('#linkConsole');
        await page.fill('#consoleCode', code(remote('cd /home/panel && /usr/local/openjdk25/bin/java -jar daemoxcp-mail.jar --lang en --access-code 2>/dev/null')));
        await Promise.all([page.waitForURL(u => !u.pathname.endsWith('/index'), { timeout: 30000 }), page.click('#btnConsole')]);
        await page.goto(BASE + '/aliases');
        await page.waitForLoadState('networkidle').catch(() => {});
        check('Postfix has the mailbox map after the aliases (' + mapsBefore + ')', /mysql-virtual-aliases\.cf, .*mysql-virtual-mailbox-addresses\.cf$/.test(mapsBefore));

        console.log('\n== 1. The mailboxes and the alias of this run (' + TOKEN + ') ==');
        // A domain of its own (.test is reserved): nothing of the machine's real mail is touched.
        const D = TOKEN + '.test';
        const dom = await api('/api/domains', 'POST', { domain: D, description: 'catch-all test' });
        check('domain ' + D + ' created' + (dom.success ? '' : ' (' + dom.error + ')'), dom.success === true && dom.id > 0);
        if (!dom.success) throw new Error('the test domain was not created');
        made.domain = dom.id;
        made.folders.push('/var/vmail/' + D);
        const box = n => n + '-' + TOKEN + '@' + D;
        const CATCHER = box('catcher'), KEPT = box('kept'), DEAF = box('deaf'), ALIAS = box('alias');
        for (const [email, receive] of [[CATCHER, true], [KEPT, true], [DEAF, false]]) {
            const r = await api('/api/mailboxes', 'POST', { email, password: 'Ct' + TOKEN + 'Xy9Kq2Wm7Rz4', name: 'Catch-all test',
                quota_mb: 50, receive_enabled: receive });
            check('mailbox ' + email + (receive ? '' : ' (does not receive)') + ' created' + (r.success ? '' : ' (' + r.error + ')'), r.success === true);
        }
        const boxes = (await api('/api/mailboxes', 'GET')).mailboxes || [];
        for (const e of [CATCHER, KEPT, DEAF]) { const m = boxes.find(b => b.email === e); if (m) made.mailboxes.push(m.id); }
        const al = await api('/api/aliases', 'POST', { source: ALIAS, destination: KEPT });
        check('alias ' + ALIAS + ' -> ' + KEPT + ' created', al.success === true);
        if (al.id) made.aliases.push(al.id);

        console.log('\n== 2. Before the catch-all, from outside (' + OUTSIDE + ', not in mynetworks) ==');
        const before = { nobody: rcptFromOutside(box('nobody')), deaf: rcptFromOutside(DEAF), kept: rcptFromOutside(KEPT) };
        console.log('  (RCPT: ' + JSON.stringify(before) + ')');
        check('an invented address: refused', before.nobody >= 500);
        check('the mailbox that does not receive: refused, as without the map', before.deaf >= 500);
        check('the mailbox: accepted', before.kept === 250);

        console.log('\n== 3. The catch-all, from the page ==');
        // The page reads the domains when it opens: again, now that the run's domain exists.
        await page.reload();
        await page.waitForFunction(d => [...document.querySelectorAll('#alDomain option')].some(o => o.value === d), D, { timeout: 20000 });
        await page.click('button[data-bs-target="#addAliasModal"]');
        await page.waitForSelector('#addAliasModal.show');
        await page.selectOption('#alDomain', D);
        await page.check('#alCatchAll');
        check('"Every other address" empties and disables the name', await page.locator('#alLocal').isDisabled()
            && (await page.locator('#alLocal').inputValue()) === '');
        await page.fill('#alDest', CATCHER);
        await page.click('#addAliasModal button[data-on-click="addAlias()"]');
        await page.waitForFunction(() => document.getElementById('aliasMsg').textContent.trim() !== '', null, { timeout: 20000 });
        const said = (await page.locator('#aliasMsg').innerText()).trim();
        check('created, and the page says what it does (' + said + ')', /Catch-all created/.test(said) && said.includes(CATCHER));
        await page.waitForFunction(d => [...document.querySelectorAll('#aliasesTable td')].some(td => td.textContent.includes('every other address @' + d)), D, { timeout: 20000 });
        const row = page.locator('#aliasesTable tr', { hasText: 'every other address @' + D });
        check('the table shows it as "every other address @' + D + '", with its badge', await row.locator('.badge', { hasText: 'catch-all' }).count() === 1);
        const all = (await api('/api/aliases', 'GET')).aliases || [];
        const catchAll = all.find(a => a.source === '@' + D && a.destination === CATCHER);
        check('saved as @' + D + ' -> ' + CATCHER, !!catchAll);
        if (catchAll) made.aliases.push(catchAll.id);
        const loop = await api('/api/aliases', 'POST', { source: '@' + D, destination: box('ghost') });
        check('a destination of the same domain that is not a mailbox: refused (' + loop.error + ')',
            loop.success === false && /come back to the catch-all/.test(loop.error || ''));
        if (loop.id) made.aliases.push(loop.id);

        console.log('\n== 4. Real mail, with the catch-all ==');
        const after = { nobody: rcptFromOutside(box('nobody')), deaf: rcptFromOutside(DEAF) };
        console.log('  (RCPT from outside: ' + JSON.stringify(after) + ')');
        check('from outside, an invented address and the mailbox that does not receive are accepted now', after.nobody === 250 && after.deaf === 250);
        const s1 = 'S1' + TOKEN, s2 = 'S2' + TOKEN, s3 = 'S3' + TOKEN, s4 = 'S4' + TOKEN;
        console.log('  (sent: ' + [send(box('nobody'), s1), send(KEPT, s2), send(ALIAS, s3), send(DEAF, s4)].join(', ') + ')');
        check('an invented address: in the catch-all', await landsIn(CATCHER, s1, 30));
        check('the mailbox: in the mailbox', await landsIn(KEPT, s2, 30));
        check('the alias: in its destination', await landsIn(KEPT, s3, 30));
        await sleep(3000);
        check('the catch-all got neither the mailbox\'s nor the alias\'s mail', !has(CATCHER, s2) && !has(CATCHER, s3));
        check('the mailbox that does not receive: in the catch-all, not in the mailbox', await landsIn(CATCHER, s4, 30) && !has(DEAF, s4));

        console.log('\n== 5. The control: Postfix without the mailbox map ==');
        try {
            remote('postconf -e "virtual_alias_maps = mysql:' + MAPS_FILE + '" && postfix reload >/dev/null 2>&1');
            const s5 = 'S5' + TOKEN;
            console.log('  (sent: ' + send(KEPT, s5) + ')');
            check('the mailbox\'s mail goes to the catch-all: what the map prevents', await landsIn(CATCHER, s5, 30) && !has(KEPT, s5));
            const refused = await api('/api/aliases', 'POST', { source: '@' + D, destination: KEPT });
            check('and the panel refuses to create a catch-all (' + refused.error + ')',
                refused.success === false && /cannot be created on this server/.test(refused.error || ''));
            if (refused.id) made.aliases.push(refused.id);
        } finally {
            remote('postconf -e "virtual_alias_maps = ' + mapsBefore + '" && postfix reload >/dev/null 2>&1');
        }
        check('virtual_alias_maps as before', remote('postconf -h virtual_alias_maps').trim() === mapsBefore);
        check('no script errors (' + errors.join(' | ').slice(0, 160) + ')', errors.length === 0);
    } catch (e) {
        check('the run went to the end (' + e.message.split('\n')[0] + ')', false);
    } finally {
        console.log('\n== 6. Everything removed ==');
        try {
            if (remote('postconf -h virtual_alias_maps').trim() !== mapsBefore)
                remote('postconf -e "virtual_alias_maps = ' + mapsBefore + '" && postfix reload >/dev/null 2>&1');
            for (const id of made.aliases) await api('/api/aliases?id=' + id, 'DELETE', {});
            for (const id of made.mailboxes) await api('/api/mailboxes?id=' + id, 'DELETE', {});
            if (made.domain) await api('/api/domains?id=' + made.domain, 'DELETE', {});
            const left = ((await api('/api/aliases', 'GET')).aliases || []).filter(a => (a.source + a.destination).includes(TOKEN));
            const leftBoxes = ((await api('/api/mailboxes', 'GET')).mailboxes || []).filter(b => b.email.includes(TOKEN));
            const leftDomains = ((await api('/api/domains', 'GET')).domains || []).filter(d => d.domain.includes(TOKEN));
            check('aliases, mailboxes and the domain of this run removed', left.length === 0 && leftBoxes.length === 0 && leftDomains.length === 0);
            // The mail folders, by their exact path (the run's token is in each name).
            for (const f of made.folders) if (f.includes(TOKEN)) remote('rm -rf -- "' + f + '"');
            check('its mail folder removed', made.folders.every(f => remote('test -e "' + f + '" && echo there || true').trim() === ''));
            check('virtual_alias_maps as before', remote('postconf -h virtual_alias_maps').trim() === mapsBefore);
        } catch (e) {
            check('the cleanup went to the end (' + e.message.split('\n')[0] + ')', false);
        }
        await browser.close();
        tunnel.kill();
    }
    console.log(failures ? '\n' + failures + ' CHECKS FAILED' : '\nALL OK');
    process.exit(failures ? 1 : 0);
})();
