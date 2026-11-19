// The server's addresses and their guide (Settings, "Server addresses": ServerAddresses, AddressGuide), end to end on
// the FreeBSD test machine, through the real panel that runs there as a service. Here only the browser runs (Chrome,
// with a virtual authenticator): the panel, ifconfig, route and rc.conf are the test machine's own.
//
//   0. The card: a row for IPv4 and one for IPv6 (with words, not only colours), the three goals, the steps numbered
//      with exactly one step "now".
//   1. Goal IPv6 only: the first step is the IPv6 address, with its form (the test machine is not on Hetzner: no
//      suggestion from the provider, the fields to fill).
//   2. A documentation address (2001:db8::/32): refused before anything changes, with the reason.
//   3. A benchmarking address (2001:2::/48, RFC 5180: global in form, never routed): the panel adds it live, the probe
//      cannot reach the internet over IPv6 (the test machine has none), and everything goes back: no address, no IPv6
//      default route, /etc/rc.conf unchanged, and the operation's log on disk says so.
//   4. Goals IPv4 only and both: the steps change, and only looking changes nothing.
//   5. The console: --addresses show answers, as root.
// The change needs a recent confirmation (the console code does not count): the run creates a passkey in a virtual
// authenticator and removes it at the end.
//
// ONLY on the test machine: step 3 adds an address and a route for a few seconds. It needs the panel's name mapped to
// 127.0.0.1 (an ssh tunnel to the panel's port carries it).
//
// Usage:
//   HOST=<panel name> CHROMIUM=<chrome binary> REMOTE=root@<test machine> REMOTE_KEY=<ssh key> \
//     NODE_PATH=$(npm root -g) node tests/address-guide-browser-test.js
const { chromium } = require('playwright');
const { spawn, execFileSync } = require('child_process');
const net = require('net');
const fs = require('fs');
const path = require('path');

const REMOTE = process.env.REMOTE, HOST = process.env.HOST;
const SSH = ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-i', process.env.REMOTE_KEY.replace(/^~/, process.env.HOME)];
const PORT = 24000 + Math.floor(Math.random() * 1000);
const BASE = 'https://' + HOST + ':' + PORT;
const PASSKEY = 'E2E ' + PORT;
const LANG = {
    en: JSON.parse(fs.readFileSync(path.join(__dirname, '../src/main/resources/lang/en.json'), 'utf8')),
    it: JSON.parse(fs.readFileSync(path.join(__dirname, '../src/main/resources/lang/it.json'), 'utf8'))
};
let failures = 0, confirmations = 0, page = null;
function check(what, ok) { console.log((ok ? '  OK     ' : '  FAILED ') + what); if (!ok) failures++; }
function remote(cmd) { return execFileSync('ssh', SSH.concat([REMOTE, cmd]), { encoding: 'utf8' }); }
function portOpen(port) {
    return new Promise(resolve => { const s = net.connect(port, '127.0.0.1', () => { s.destroy(); resolve(true); }); s.on('error', () => resolve(false)); });
}
// The text of a key in either language, without its placeholders: what the page shows starts with it.
function said(text, key) {
    return ['en', 'it'].some(l => LANG[l][key] && text.includes(LANG[l][key].split('{')[0].trim().slice(0, 40)));
}

(async () => {
    const tunnel = spawn('ssh', SSH.concat(['-N', '-o', 'ExitOnForwardFailure=yes', '-L', PORT + ':127.0.0.1:2096', REMOTE]), { stdio: 'ignore' });
    let up = false;
    for (let i = 0; i < 40 && !up; i++) { await new Promise(r => setTimeout(r, 250)); up = await portOpen(PORT); }
    const browser = await chromium.launch({ executablePath: process.env.CHROMIUM, args: ['--host-resolver-rules=MAP ' + HOST + ' 127.0.0.1'] });
    const iface = remote("netstat -rn -f inet | awk '$1==\"default\" {print $NF; exit}'").trim();
    const live = () => remote('ifconfig ' + iface + " inet6 | grep 'inet6 ' | sed -E 's/ pltime [0-9]+ vltime [0-9]+//'; netstat -rn -f inet6 | grep '^default' || true");
    const rcSha = () => remote('sha256 -q /etc/rc.conf').trim();
    const before = live(), rcBefore = rcSha();
    try {
        const context = await browser.newContext({ ignoreHTTPSErrors: true });
        page = await context.newPage();
        page.on('dialog', d => d.accept());
        const cdp = await context.newCDPSession(page);
        await cdp.send('WebAuthn.enable');
        await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
            protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true,
            isUserVerified: true, automaticPresenceSimulation: true } });
        const m = remote('cd /home/panel && /usr/local/openjdk25/bin/java -jar daemoxcp-mail.jar --access-code').match(/One-time access code for [^:]*: (\d{4} \d{4})/);
        await page.goto(BASE + '/index');
        await page.click('#linkConsole');
        await page.fill('#consoleCode', m[1]);
        await Promise.all([page.waitForURL(u => !u.pathname.endsWith('/index'), { timeout: 30000 }), page.click('#btnConsole')]);
        await page.goto(BASE + '/account');
        await page.waitForSelector('#addPasskeyBtn:not([disabled])');
        await page.click('#addPasskeyBtn');
        await page.waitForSelector('#passkeyNameModal.show');
        await page.fill('#passkeyName', PASSKEY);
        await page.click('#passkeyNameModal .btn-primary');
        await page.waitForFunction(n => document.getElementById('passkeysList').innerText.includes(n), PASSKEY, { timeout: 15000 });
        check('a passkey for this run (' + PASSKEY + ')', true);

        // Waits for a condition on the page, answering the recent confirmation with the passkey when it is asked.
        const until = async (fn, arg, ms) => {
            const end = Date.now() + ms;
            while (Date.now() < end) {
                if (await page.locator('#panelConfirmModal.show').count()) {
                    await page.click('#panelConfirmModal [data-confirm="passkey"]').catch(() => {});
                    confirmations++;
                    await page.waitForTimeout(1500);
                }
                if (await page.evaluate(fn, arg).catch(() => false)) return true;
                await page.waitForTimeout(300);
            }
            return false;
        };
        const steps = () => page.$$eval('#addrSteps li', ls => ls.map(l => l.dataset.step + '/' + l.dataset.status));
        const loaded = () => until(() => document.querySelectorAll('#addrRows th').length === 2 && !/…/.test(document.getElementById('addrStatus').textContent), null, 60000);

        console.log('\n== 0. The card ==');
        await page.goto(BASE + '/settings');
        check('the card loads the state', await loaded());
        const rows = await page.$$eval('#addrRows tr', trs => trs.map(t => t.innerText.replace(/\s+/g, ' ').trim()));
        check('a row for IPv4 and one for IPv6, with words (' + rows.map(r => r.split(' ')[0]).join(', ') + ')',
            rows.length === 2 && rows[0].startsWith('IPv4') && rows[1].startsWith('IPv6')
            && rows.every(r => /(Yes|No|Sì|Not checked|Non controllato)/.test(r)));
        check('the table has a caption and column headers', await page.$eval('#addrCard table', t => !!t.caption && t.querySelectorAll('thead th[scope=col]').length === 5));
        check('three goals, "both" chosen first', await page.$$eval('input[name=addrGoal]', rs => rs.length === 3 && rs.find(r => r.checked).value === 'both'));
        // «Mail also comes in over IPv6» starts as the server is: on when mail already comes in over IPv6 (the test
        // machine's mail is on both), off otherwise (the recommended choice). Off: mail over IPv6 only going out. One
        // name for everything: the same steps as towards both, only the last one changes.
        const sw0 = await page.$eval('#addrInbound6', i => ({ type: i.type, checked: i.checked, disabled: i.disabled,
            hint: !!document.getElementById(i.getAttribute('aria-describedby')) }));
        const mailNow = await page.evaluate(() => addrData && addrData.mail);
        check('the switch «mail also comes in over IPv6»: there, with its explanation, as the server is (mail ' + mailNow + ', switch '
            + (sw0.checked ? 'on' : 'off') + ')', sw0.type === 'checkbox' && !sw0.disabled && sw0.hint && sw0.checked === (mailNow === 'both'));
        await page.uncheck('#addrInbound6');
        await until(() => !!document.querySelector('#addrSteps li[data-step="mailSend6"]'), null, 60000);
        let s = await steps();
        check('switch off, the steps for mail over IPv6 only going out: ' + s.join(' '), s.length === 8 && s.includes('mailSend6/next')
            && s.includes('v6Firewall/next') && s.includes('v6Ptr/next') && !s.some(x => /PtrSend|SendDns|spf6/.test(x)));
        await page.check('#addrInbound6');
        await until(() => document.querySelectorAll('#addrSteps li').length === 8 && !!document.querySelector('#addrSteps li[data-step="mailBoth"]'), null, 60000);
        s = await steps();
        check('the steps towards both: ' + s.join(' '), s.length === 8 && s.filter(x => /\/(now|blocked)$/.test(x)).length === 1
            && (await page.$$('#addrSteps li[aria-current=step]')).length === 1 && s.includes('v6Firewall/next'));
        // On the test machine the IPv4 reverse DNS is not the mail name: that is the step now, the administrator's.
        if (s.includes('v4Ptr/now')) {
            const copies = await page.$$eval('#addrSteps li[data-status=now] button[data-copy]', bs => bs.map(b => b.dataset.copy));
            check('the reverse DNS step: the address and the name ready to copy (' + copies.length + ' values), what it gives now, the automatic check',
                copies.length >= 2 && await page.$eval('#addrSteps li[data-status=now]', li => li.querySelectorAll('p').length >= 3));
            // «Check again» always says how it went, next to the button, and keeps the focus there. Before, with nothing
            // changed the page was drawn again the same and said nothing: the button seemed to do nothing (seen on the
            // real server, waiting for the reverse DNS).
            check('the time of the last check is shown under the button', said(await page.innerText('#addrLastCheck'), 'addr.lastCheck'));
            const outcomes = ['addr.checkedSame', 'addr.checkedChanged'].flatMap(k => ['en', 'it'].map(l => LANG[l][k].split('{')[0]));
            await page.click('#addrSteps li[data-status=now] button[data-recheck]');
            await page.waitForFunction(p => {
                const e = document.getElementById('addrLastCheck');
                return e && p.some(x => e.textContent.startsWith(x));
            }, outcomes, { timeout: 60000 });
            const after = await page.evaluate(() => ({
                near: document.getElementById('addrLastCheck').textContent,
                status: document.getElementById('addrStatus').textContent,
                hidden: document.getElementById('addrStatus').className === 'visually-hidden',
                focus: !!document.activeElement && document.activeElement.dataset.recheck === '1'
            }));
            check('«Check again» says the outcome with the time (' + after.near + '), screen readers hear it too, the focus stays on the button',
                /\d{1,2}[:.]\d{2}[:.]\d{2}/.test(after.near) && after.status === after.near && after.hidden && after.focus);
        }

        console.log('\n== 1. Goal IPv6 only ==');
        await page.check('#addrGoalV6');
        await until(() => document.querySelector('#addrSteps li[data-step="v6Address"]') && !/…/.test(document.getElementById('addrStatus').textContent), null, 60000);
        s = await steps();
        check('the first step is the IPv6 address, now: ' + s.join(' '), s[0] === 'v6Address/now');
        check('its form: address empty (no provider here), prefix 64, gateway fe80::1, each with its label',
            await page.$eval('#addrV6Address', e => e.value === '' && !!document.querySelector('label[for=addrV6Address]'))
            && await page.$eval('#addrV6Prefix', e => e.value === '64') && await page.$eval('#addrV6Gateway', e => e.value === 'fe80::1'));

        console.log('\n== 2. A documentation address: refused, nothing changes ==');
        await page.fill('#addrV6Address', '2001:db8::7');
        await page.click('#addrSteps li[data-step="v6Address"] button');
        const refused = await until(() => document.getElementById('addrStatus').className.includes('text-danger'), null, 60000);
        const t2 = await page.textContent('#addrStatus');
        check('refused with the reason (' + t2.slice(0, 70) + '…)', refused && said(t2, 'server.addr.notGlobal'));
        check('  the interface and the routes as before', live() === before);

        console.log('\n== 3. An address that cannot reach the internet: added, probed, everything back ==');
        await page.check('#addrGoalV6');
        await until(() => !!document.getElementById('addrV6Address'), null, 30000);
        await page.fill('#addrV6Address', '2001:2::7');
        await page.click('#addrSteps li[data-step="v6Address"] button');
        const back = await until(() => document.getElementById('addrStatus').className.includes('text-danger'), null, 120000);
        const t3 = await page.textContent('#addrStatus');
        check('the probe failed and it says so (' + t3.slice(0, 70) + '…)', back && said(t3, 'server.addr.probeFailedV6'));
        const journal = (t3.match(/[0-9]{8}-[0-9]{6}-server-addresses__[A-Za-z0-9._-]+\.log/) || [])[0];
        check('  the log of the operation is named (' + journal + ')', !!journal);
        check('  the interface and the routes exactly as before', live() === before);
        check('  /etc/rc.conf unchanged', rcSha() === rcBefore);
        const log = journal ? remote('cat /var/db/daemoxcp-mail/jobs/' + journal) : '';
        check('  the log: the address added live, the probe, the way back, the end', /inet6 2001:2::7 prefixlen 64 alias -> ok/.test(log)
            && /going back: nothing stays/.test(log) && /=== end: failed/.test(log) && !/sysrc -f \S+ ifconfig_/.test(log));

        console.log('\n== 4. Goals IPv4 only and both: only looking ==');
        await page.check('#addrGoalV4');
        await until(() => document.querySelector('#addrSteps li[data-step="v4Address"]') && !document.querySelector('#addrSteps li[data-step="v6Address"]'), null, 60000);
        s = await steps();
        check('towards IPv4 only, with the switch grey: ' + s.join(' '), s.length === 7 && s[0].startsWith('v4Address/')
            && s.includes('v6AddressRemove/done') && await page.$eval('#addrInbound6', i => i.disabled));
        await page.check('#addrGoalBoth');
        await until(() => document.querySelectorAll('#addrSteps li').length === 8 && !!document.querySelector('#addrSteps li[data-step="mailBoth"]'), null, 60000);
        check('towards both again', (await steps()).length === 8);
        check('  nothing changed by looking', live() === before && rcSha() === rcBefore);

        console.log('\n== 5. The console ==');
        const show = remote('cd /home/panel && /usr/local/openjdk25/bin/java -jar daemoxcp-mail.jar --addresses show');
        check('--addresses show: the interface, IPv4, IPv6, the mail family', /Interface: \S+/.test(show) && /IPv4: /.test(show)
            && /IPv6: /.test(show) && /Mail answers on: (both|ipv4|ipv6)/.test(show));
        let usage = '';
        try { remote('cd /home/panel && /usr/local/openjdk25/bin/java -jar daemoxcp-mail.jar --addresses everything'); } catch (e) { usage = String(e.stderr || ''); }
        check('a wrong value gets the usage', /Usage: .*--addresses show\|ipv6-off\|ipv4-dhcp/.test(usage));
        check('the recent confirmation was asked by the panel (' + confirmations + ' times)', confirmations >= 1);
    } catch (e) {
        check('unexpected: ' + e.message.split('\n')[0], false);
    } finally {
        if (page) {
            const gone = await page.evaluate(async name => {
                const a = await (await fetch('/api/account')).json();
                const k = (a.passkeys || []).find(p => p.name === name);
                if (!k) return 'not found';
                const csrf = document.getElementById('csrf_token') ? document.getElementById('csrf_token').value : '';
                const r = await (await fetch('/api/account', { method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action: 'passkey_delete', id: k.id, csrf_token: csrf }) })).json();
                return r.success ? 'removed' : 'not removed: ' + r.error;
            }, PASSKEY).catch(e => 'not removed: ' + e.message);
            check('the passkey of this run ' + gone, gone === 'removed');
        }
        await browser.close();
        tunnel.kill();
        check('at the end: the interface, the routes and /etc/rc.conf as at the start', live() === before && rcSha() === rcBefore);
        console.log(failures === 0 ? '\nALL OK' : '\n' + failures + ' CHECKS FAILED');
        process.exit(failures === 0 ? 0 : 1);
    }
})();
