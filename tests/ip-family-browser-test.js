// IPv4 only, IPv6 only, or both (IpFamily), end to end on the FreeBSD test machine, through the real panel that
// runs there as a service. Here only the browser runs (Chrome, with a virtual authenticator): the panel, the
// services and pf are the test machine's own.
//
//   0. The state the panel reports.
//   1. IPv6 only without an IPv6 default route: refused with the reason, nothing changes.
//   2. IPv4 only: pf lets the mail in only as inet and refuses IPv6 at once (block return), mail does not go out over
//      IPv6, and from this computer the ports answer over IPv4 and not over IPv6. Then IPv6 only going out (ipv6out):
//      the same from outside, but mail may go out over IPv6.
// The services listen over IPv4 and IPv6 whatever the choice (universal configurations, written once): the family is
// pf's, so in every step 25, 993 and 8443 listen on both, and the reach checks from this computer are the proof.
//   3. IPv6 only, with a temporary IPv6 default route on the test machine: first the warnings, then the change;
//      the opposite of step 2 from outside, while on 127.0.0.1 Dovecot and Postfix still answer (the webmail, the
//      antispam and the sending limits use it).
//   4. Both again, from the Settings card as a person does it (the confirmation window answered by the passkey).
//   5. The console command, as root, the way back for whoever cut themselves off: --ip-family ipv4, then both;
//      a wrong value gets the usage.
// In every step the SSH rule has no family and SSH still answers. The changes need a recent confirmation (the
// console code does not count): the run creates a passkey in a virtual authenticator and removes it at the end.
//
// ONLY on the test machine: it changes the services and adds, then removes, an IPv6 default route. It needs the
// panel's name mapped to 127.0.0.1 (an ssh tunnel to the panel's port carries it), and an IPv6 address of the
// test machine reachable from here (the same ULA network).
//
// Usage:
//   HOST=<panel name> CHROMIUM=<chrome binary> REMOTE=root@<test machine> REMOTE_KEY=<ssh key> \
//     NODE_PATH=$(npm root -g) node tests/ip-family-browser-test.js
const { chromium } = require('playwright');
const { spawn, execFileSync } = require('child_process');
const net = require('net');

const REMOTE = process.env.REMOTE, HOST = process.env.HOST;
const SSH = ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-i', process.env.REMOTE_KEY.replace(/^~/, process.env.HOME)];
const PORT = 24000 + Math.floor(Math.random() * 1000);
const BASE = 'https://' + HOST + ':' + PORT;
const V4 = REMOTE.split('@')[1];
let failures = 0, confirmations = 0, page = null;
const PASSKEY = 'E2E ' + PORT;
function check(what, ok) { console.log((ok ? '  OK     ' : '  FAILED ') + what); if (!ok) failures++; }
function remote(cmd) { return execFileSync('ssh', SSH.concat([REMOTE, cmd]), { encoding: 'utf8' }); }
function portOpen(port) {
    return new Promise(resolve => { const s = net.connect(port, '127.0.0.1', () => { s.destroy(); resolve(true); }); s.on('error', () => resolve(false)); });
}
function reach(host, port) {
    return new Promise(resolve => {
        const s = net.connect({ host, port, timeout: 3000 }, () => { s.destroy(); resolve(true); });
        s.on('timeout', () => { s.destroy(); resolve(false); });
        s.on('error', () => resolve(false));
    });
}
function families(sock, port) {
    let v4 = false, v6 = false;
    for (const l of sock.split('\n')) {
        const c = l.trim().split(/\s+/);
        if (c.length < 6 || !c[5].endsWith(':' + port)) continue;
        if (c[4] === 'tcp4' || c[4] === 'tcp46') v4 = true;
        if (c[4] === 'tcp6' || c[4] === 'tcp46') v6 = true;
    }
    return (v4 ? '4' : '') + (v6 ? '6' : '');
}

(async () => {
    const V6 = remote("ifconfig -a inet6 | awk '/inet6 / && $2 !~ /^(fe80|::1)/ {print $2; exit}'").trim();
    const tunnel = spawn('ssh', SSH.concat(['-N', '-o', 'ExitOnForwardFailure=yes', '-L', PORT + ':127.0.0.1:2096', REMOTE]), { stdio: 'ignore' });
    let up = false;
    for (let i = 0; i < 40 && !up; i++) { await new Promise(r => setTimeout(r, 250)); up = await portOpen(PORT); }
    const browser = await chromium.launch({ executablePath: process.env.CHROMIUM, args: ['--host-resolver-rules=MAP ' + HOST + ' 127.0.0.1'] });
    try {
        const context = await browser.newContext({ ignoreHTTPSErrors: true });
        page = await context.newPage();
        page.on('dialog', d => d.accept());
        // The panel wants a recent confirmation before it changes settings, and the console code does not count:
        // a virtual passkey, created for this run and removed at the end.
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
        // The panel sends to Account only an administrator without a passkey; with one, to the home page.
        await page.goto(BASE + '/account');
        await page.waitForSelector('#addPasskeyBtn:not([disabled])');
        await page.click('#addPasskeyBtn');
        await page.waitForSelector('#passkeyNameModal.show');
        await page.fill('#passkeyName', PASSKEY);
        await page.click('#passkeyNameModal .btn-primary');
        await page.waitForFunction(n => document.getElementById('passkeysList').innerText.includes(n), PASSKEY, { timeout: 15000 });
        check('a passkey for this run (' + PASSKEY + ')', true);
        await page.goto(BASE + '/settings');
        await page.waitForLoadState('networkidle').catch(() => {});
        const csrf = await page.$eval('#csrf_token', e => e.value);
        // Through the page's own fetch: when the server asks for the confirmation the shared window opens, and the
        // passkey answers it; then the page sends the request again by itself.
        const api = async (body) => {
            let over = false;
            const call = page.evaluate(async ({ body, csrf }) => {
                const r = await fetch('/api/ip-family', body ? { method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(Object.assign({ csrf_token: csrf }, body)) } : {});
                const text = await r.text();
                try { return JSON.parse(text); } catch (e) { return { success: false, error: 'HTTP ' + r.status + ': ' + text.slice(0, 200) }; }
            }, { body, csrf }).catch(e => ({ success: false, error: 'page: ' + e.message.split('\n')[0] })).finally(() => { over = true; });
            while (!over) {
                if (await page.locator('#panelConfirmModal.show').count()) {
                    await page.click('#panelConfirmModal [data-confirm="passkey"]').catch(() => {});
                    confirmations++;
                    await page.waitForSelector('#panelConfirmModal.show', { state: 'detached', timeout: 15000 }).catch(() => {});
                    await page.waitForFunction(() => !document.querySelector('#panelConfirmModal.show'), null, { timeout: 15000 }).catch(() => {});
                }
                await page.waitForTimeout(300);
            }
            return call;
        };

        async function looks(family, label) {
            const sock = remote('sockstat -46l -P tcp');
            const pf = remote('pfctl -sr 2>/dev/null');
            // Universal configurations: every service listens over IPv4 and IPv6 whatever the choice; pf decides.
            for (const p of [25, 993, 8443]) {
                const f = families(sock, p);
                check(label + ': port ' + p + ' listens over IPv4 and IPv6, the choice is pf\'s (' + f + ')', f === '46');
            }
            if (family === 'ipv6')
                check(label + ': the local services still reach Dovecot (993) and Postfix (587) on 127.0.0.1',
                    (() => { try { return remote('nc -z -w 3 127.0.0.1 993 && nc -z -w 3 127.0.0.1 587 && echo reached').includes('reached'); } catch (e) { return false; } })());
            const svc = pf.split('\n').filter(l => l.startsWith('pass in') && / port = (smtp|25)\b/.test(l));
            const kw = family === 'ipv4' || family === 'ipv6out' ? ' inet ' : family === 'ipv6' ? ' inet6 ' : null;
            check(label + ': pf lets the mail in only as ' + family + ' (' + svc.map(l => l.replace(/\s+/g, ' ')).join(' | ') + ')',
                svc.length > 0 && svc.every(l => kw ? l.includes(kw) : !/ inet6? /.test(l)));
            // The closed family: an immediate refusal, not silence. Only IPv4: mail kept from going out over IPv6.
            const closed = family === 'ipv4' || family === 'ipv6out' ? 'inet6' : family === 'ipv6' ? 'inet' : null;
            const refusals = pf.split('\n').filter(l => l.startsWith('block return in') && / port = (smtp|25)\b/.test(l));
            check(label + ': the closed family is refused at once (' + refusals.map(l => l.replace(/\s+/g, ' ')).join(' | ') + ')',
                closed ? refusals.length > 0 && refusals.every(l => l.includes(' ' + closed + ' ')) : refusals.length === 0);
            const out6 = pf.split('\n').some(l => l.startsWith('block return out') && l.includes(' inet6 ') && / port = (smtp|25)\b/.test(l));
            check(label + ': mail ' + (family === 'ipv4' ? 'kept from going out' : 'free to go out') + ' over IPv6', out6 === (family === 'ipv4'));
            const ssh = pf.split('\n').filter(l => l.startsWith('pass in') && / port = (ssh|22)\b/.test(l));
            check(label + ': the SSH rule has no family', ssh.length > 0 && ssh.every(l => !/ inet6? /.test(l)));
            for (const p of [25, 993, 8443]) {
                const r4 = await reach(V4, p), r6 = await reach(V6, p);
                check(label + ': from the Mac, port ' + p + ' over IPv4 ' + (r4 ? 'answers' : 'does not') + ', over IPv6 ' + (r6 ? 'answers' : 'does not'),
                    r4 === (family !== 'ipv6') && r6 === (family === 'both' || family === 'ipv6'));
            }
            check(label + ': SSH still answers over IPv4', remote('echo alive').trim() === 'alive');
        }

        console.log('== 0. What the panel reports ==');
        let d = await api(null);
        check('GET: chosen ' + d.chosen + ', in use ' + d.effective, d.success && ['both', 'ipv4', 'ipv6', 'ipv6out'].includes(d.effective)
            && (d.chosen === null || ['both', 'ipv4', 'ipv6', 'ipv6out'].includes(d.chosen)));

        console.log('\n== 1. IPv6 only without an IPv6 default route: refused, nothing changes ==');
        // Since the Mac has IPv6 its network gives the test machine an IPv6 default route: then this cannot be tried.
        if (remote('netstat -rn -f inet6 | grep -c ^default || true').trim() !== '0') {
            console.log('  (skipped: the test machine has an IPv6 default route from its network)');
        } else {
            d = await api({ family: 'ipv6' });
            check('refused, with the reason (' + d.error + ')', !d.success && !d.confirm && /IPv6/.test(d.error || ''));
        }

        console.log('\n== 2. IPv4 only ==');
        d = await api({ family: 'ipv4' });
        if (d.confirm) { console.log('  (warnings: ' + d.warnings.join(' / ') + ')'); d = await api({ family: 'ipv4', confirmed: true }); }
        check('done (' + (d.error || 'ok') + ')', d.success);
        await looks('ipv4', 'IPv4 only');

        console.log('\n== 2b. IPv6 only going out ==');
        d = await api({ family: 'ipv6out' });
        if (d.confirm) { console.log('  (warnings: ' + d.warnings.join(' / ') + ')'); d = await api({ family: 'ipv6out', confirmed: true }); }
        check('done (' + (d.error || 'ok') + ')', d.success);
        await looks('ipv6out', 'IPv6 only going out');

        console.log('\n== 3. IPv6 only, with a temporary IPv6 default route ==');
        remote('route -6 add default ' + V6.replace(/:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+$/, '::1') + ' >/dev/null 2>&1; netstat -rn -f inet6 | grep -c ^default');
        d = await api({ family: 'ipv6' });
        check('first it asks to confirm, with the warnings (' + (d.warnings || []).length + ')', d.confirm && (d.warnings || []).length >= 2);
        d = await api({ family: 'ipv6', confirmed: true });
        check('confirmed: done (' + (d.error || 'ok') + ')', d.success);
        await looks('ipv6', 'IPv6 only');

        console.log('\n== 4. Both again, from the Settings card as a person does it ==');
        await page.goto(BASE + '/settings');
        await page.waitForLoadState('networkidle').catch(() => {});
        await page.check('input[name="ipFamily"][value="both"]');
        await page.click('#ipfApply');
        for (let i = 0; i < 600; i++) {
            if (await page.locator('#panelConfirmModal.show').count()) { await page.click('#panelConfirmModal [data-confirm="passkey"]').catch(() => {}); confirmations++; await page.waitForTimeout(2000); }
            if (await page.locator('#ipfWarnings:not(.d-none)').count()) { await page.click('button[data-on-click="ipfApply(true)"]'); await page.waitForTimeout(1000); }
            if (!(await page.locator('#ipfApply').isDisabled())) break;
            await page.waitForTimeout(500);
        }
        const said = await page.locator('#ipfMessage, #ipfStatus').first().innerText().catch(() => '');
        check('the card says it is done (' + said.replace(/\s+/g, ' ').slice(0, 120) + ')', !(await page.locator('#ipfApply').isDisabled()));
        await looks('both', 'Both');
        d = await api(null);
        check('GET: chosen both', d.chosen === 'both' && d.effective === 'both');
        console.log('  (confirmations asked: ' + confirmations + ')');

        console.log('\n== 5. From the console, as root: the way back when a choice cut you off ==');
        const anchor = () => remote('pfctl -a panel-fw -sr 2>/dev/null | wc -l').trim();
        const anchorBefore = anchor();
        const consoleRun = v => remote('cd /home/panel && /usr/local/openjdk25/bin/java -jar daemoxcp-mail.jar --ip-family ' + v + ' 2>&1; echo "rc=$?"');
        let out = consoleRun('ipv4');
        let auditOut = out;
        check('--ip-family ipv4: done (' + out.trim().split('\n')[0] + ')', /rc=0/.test(out) && /^Done/m.test(out));
        await looks('ipv4', 'Console IPv4');
        d = await api(null);
        check('the running panel sees the console choice (' + d.chosen + ')', d.chosen === 'ipv4');
        check('the firewall anchor keeps its ' + anchorBefore + ' rules (' + anchor() + ')', anchor() === anchorBefore);
        out = consoleRun('both');
        auditOut += out;
        check('--ip-family both: done (' + out.trim().split('\n')[0] + ')', /rc=0/.test(out) && /^Done/m.test(out));
        await looks('both', 'Console both');
        out = consoleRun('v6');
        check('a wrong value: the usage, exit 2', /rc=2/.test(out) && /Usage/.test(out));
        check('the audit log took both console changes (no "Failed to log audit event")', !/Failed to log audit event|audit log was not written/.test(auditOut));
    } finally {
        if (page) {
            const gone = await page.evaluate(async ({ name, csrf }) => {
                const a = await (await fetch('/api/account')).json();
                const k = (a.passkeys || []).find(p => p.name === name);
                if (!k) return 'not found';
                const r = await (await fetch('/api/account', { method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action: 'passkey_delete', id: k.id, csrf_token: csrf }) })).json();
                return r.success ? 'removed' : 'not removed: ' + r.error;
            }, { name: PASSKEY, csrf: await page.$eval('#csrf_token', e => e.value).catch(() => '') }).catch(e => 'page: ' + e.message.split('\n')[0]);
            check('the passkey of this run ' + gone, gone === 'removed');
        }
        try { remote('route -6 delete default >/dev/null 2>&1; true'); } catch (e) {}
        await browser.close();
        tunnel.kill();
    }
    console.log(failures === 0 ? '\nALL OK' : '\n' + failures + ' CHECKS FAILED');
    process.exit(failures === 0 ? 0 : 1);
})();
