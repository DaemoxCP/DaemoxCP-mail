// Blocking by country over IPv4 AND IPv6, end to end on the FreeBSD test machine, through the real panel's Firewall
// API (as its page does) and the real pf. Here only the browser runs; the panel is reached through an ssh tunnel.
//
//   1. Sync a country: its file has the IPv4 list and the IPv6 one.
//   2. This computer's IPv6 /64 is added to that file (the only way to send traffic "from" the country).
//   3. Blacklist: the pf table has IPv4 and IPv6 entries, the rule has no family; from here the IMAP port (993)
//      does not answer over IPv6 and answers over IPv4.
//   4. Whitelist: the opposite: over IPv6 it answers, over IPv4 it does not.
//   In every step SSH still answers (the country rules only cover the mail ports).
//   5. Everything back as it was: the firewall state file, the panel restarted on it, the anchor empty again,
//      the country folder removed if the run created it.
//
// The change needs a recent confirmation: the run creates a passkey in a virtual authenticator and removes it.
// ONLY on the test machine (it changes pf). Usage:
//   HOST=<panel name> CHROMIUM=<chrome binary> REMOTE=root@<test machine> REMOTE_KEY=<ssh key> COUNTRY=it \
//     NODE_PATH=$(npm root -g) node tests/geo-ipv6-browser-test.js
const { chromium } = require('playwright');
const { spawn, execFileSync } = require('child_process');
const net = require('net');

const REMOTE = process.env.REMOTE, HOST = process.env.HOST, CC = (process.env.COUNTRY || 'it').toLowerCase();
const SSH = ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-i', process.env.REMOTE_KEY.replace(/^~/, process.env.HOME)];
const PORT = 26000 + Math.floor(Math.random() * 1000);
const BASE = 'https://' + HOST + ':' + PORT;
const V4 = REMOTE.split('@')[1];
const STATE = '/usr/local/etc/daemoxcp-mail/firewall.json', GEO = '/var/db/daemoxcp-mail/geoip';
const SAVED = '/var/tmp/geo-ipv6-test-firewall.json';
let failures = 0, page = null;
const PASSKEY = 'Geo ' + PORT;
function check(what, ok) { console.log((ok ? '  OK     ' : '  FAILED ') + what); if (!ok) failures++; }
function remote(cmd) { return execFileSync('ssh', SSH.concat([REMOTE, cmd]), { encoding: 'utf8' }); }
function portOpen(port) {
    return new Promise(resolve => { const s = net.connect(port, '127.0.0.1', () => { s.destroy(); resolve(true); }); s.on('error', () => resolve(false)); });
}
function reach(host, port) {
    return new Promise(resolve => {
        const s = net.connect({ host, port, timeout: 4000 }, () => { s.destroy(); resolve(true); });
        s.on('timeout', () => { s.destroy(); resolve(false); });
        s.on('error', () => resolve(false));
    });
}

(async () => {
    const V6 = remote("ifconfig -a inet6 | awk '/inet6 / && $2 !~ /^(fe80|::1)/ {print $2; exit}'").trim();
    // This computer's IPv6 address as the test machine sees it, from an ssh connection over IPv6.
    // The same machine: its host key is the one already known for the IPv4 address.
    const mine6 = execFileSync('ssh', SSH.concat(['-o', 'HostKeyAlias=' + V4, 'root@' + V6, "echo $SSH_CLIENT | cut -d' ' -f1"]), { encoding: 'utf8' }).trim();
    const net64 = mine6.split(':').slice(0, 4).join(':') + '::/64';
    const hadGeo = remote('test -d ' + GEO + ' && echo yes || echo no').trim() === 'yes';
    remote('cp -p ' + STATE + ' ' + SAVED);
    const tunnel = spawn('ssh', SSH.concat(['-N', '-o', 'ExitOnForwardFailure=yes', '-L', PORT + ':127.0.0.1:2096', REMOTE]), { stdio: 'ignore' });
    let up = false;
    for (let i = 0; i < 40 && !up; i++) { await new Promise(r => setTimeout(r, 250)); up = await portOpen(PORT); }
    const browser = await chromium.launch({ executablePath: process.env.CHROMIUM, args: ['--host-resolver-rules=MAP ' + HOST + ' 127.0.0.1'] });
    try {
        const context = await browser.newContext({ ignoreHTTPSErrors: true });
        page = await context.newPage();
        page.on('dialog', d => d.accept());
        const cdp = await context.newCDPSession(page);
        await cdp.send('WebAuthn.enable');
        await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
            hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
        const m = remote('cd /home/panel && /usr/local/openjdk25/bin/java -jar daemoxcp-mail.jar --access-code 2>/dev/null').match(/One-time access code for [^:]*: (\d{4} \d{4})/);
        await page.goto(BASE + '/index');
        await page.click('#linkConsole');
        await page.fill('#consoleCode', m ? m[1] : '');
        await Promise.all([page.waitForURL(u => !u.pathname.endsWith('/index'), { timeout: 30000 }), page.click('#btnConsole')]);
        // The panel sends to Account only an administrator without a passkey; with one, to the home page.
        await page.goto(BASE + '/account');
        await page.waitForSelector('#addPasskeyBtn:not([disabled])');
        await page.click('#addPasskeyBtn');
        await page.waitForSelector('#passkeyNameModal.show');
        await page.fill('#passkeyName', PASSKEY);
        await page.click('#passkeyNameModal .btn-primary');
        await page.waitForFunction(n => document.getElementById('passkeysList').innerText.includes(n), PASSKEY, { timeout: 15000 });
        await page.goto(BASE + '/firewall');
        await page.waitForLoadState('networkidle').catch(() => {});
        const csrf = await page.$eval('#csrf_token', e => e.value);
        const fw = async (body) => {
            let over = false;
            const call = page.evaluate(async ({ body, csrf }) => {
                const r = await fetch('/api/firewall', { method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(Object.assign({ csrf_token: csrf }, body)) });
                const t = await r.text();
                try { return JSON.parse(t); } catch (e) { return { success: false, error: 'HTTP ' + r.status + ': ' + t.slice(0, 200) }; }
            }, { body, csrf }).catch(e => ({ success: false, error: 'page: ' + e.message.split('\n')[0] })).finally(() => { over = true; });
            while (!over) {
                if (await page.locator('#panelConfirmModal.show').count()) {
                    await page.click('#panelConfirmModal [data-confirm="passkey"]').catch(() => {});
                    await page.waitForFunction(() => !document.querySelector('#panelConfirmModal.show'), null, { timeout: 15000 }).catch(() => {});
                }
                await page.waitForTimeout(300);
            }
            return call;
        };
        const traffic = async (label, v6open, v4open) => {
            const r6 = await reach(V6, 993), r4 = await reach(V4, 993);
            check(label + ': from here 993 over IPv6 ' + (r6 ? 'answers' : 'does not') + ', over IPv4 ' + (r4 ? 'answers' : 'does not'),
                r6 === v6open && r4 === v4open);
            check(label + ': SSH still answers', remote('echo alive').trim() === 'alive');
        };
        const table = name => remote('pfctl -a panel-fw -t ' + name + ' -T show 2>/dev/null').split('\n').map(l => l.trim()).filter(Boolean);

        console.log('== 1. Sync ' + CC + ' ==');
        let d = await fw({ action: 'add_country', country: CC });
        check('country added (' + (d.message || d.error) + ')', d.success === true);
        d = await fw({ action: 'sync_geo', country: CC });
        check('synced (' + (d.message || d.error) + ')', d.success === true);
        const zone = remote('cat ' + GEO + '/' + CC + '.zone');
        const v4lines = zone.split('\n').filter(l => /^[0-9.]+\/\d+$/.test(l.trim())).length;
        const v6lines = zone.split('\n').filter(l => /^[0-9a-fA-F:]+\/\d+$/.test(l.trim())).length;
        check('the file has the IPv4 list (' + v4lines + ') and the IPv6 one (' + v6lines + ')', v4lines > 100 && v6lines > 100);
        const sample6 = zone.split('\n').map(l => l.trim()).find(l => /^[0-9a-fA-F:]+\/\d+$/.test(l)).split('/')[0];

        console.log('\n== 2. This computer\'s IPv6 network in the file (' + net64.replace(/:[0-9a-f]*:[0-9a-f]*::/, ':…::') + ') ==');
        remote('printf "%s\\n" "' + net64 + '" >> ' + GEO + '/' + CC + '.zone');

        console.log('\n== 3. Blacklist ==');
        d = await fw({ action: 'set_mode', mode: 'GEO_BLACKLIST' });
        check('mode set', d.success === true);
        d = await fw({ action: 'apply' });
        check('applied (' + (d.message || d.error) + ')', d.success === true);
        let rows = table('panel_geo_bl');
        check('the pf table has IPv4 (' + rows.filter(r => !r.includes(':')).length + ') and IPv6 (' + rows.filter(r => r.includes(':')).length + ') entries',
            rows.filter(r => !r.includes(':')).length > 100 && rows.filter(r => r.includes(':')).length > 100);
        check('an address of the country\'s IPv6 list is in the table', /match/.test(remote('pfctl -a panel-fw -t panel_geo_bl -T test ' + sample6 + ' 2>&1')));
        const rule = remote('pfctl -a panel-fw -sr 2>/dev/null').split('\n').filter(l => l.includes('panel_geo_bl'));
        check('the rule has no family, so it covers IPv6 too (' + rule.map(l => l.trim()).join(' | ') + ')',
            rule.length > 0 && rule.every(l => !/ inet6? /.test(l)));
        await traffic('blacklist', false, true);

        console.log('\n== 4. Whitelist ==');
        d = await fw({ action: 'set_mode', mode: 'GEO_WHITELIST' });
        check('mode set', d.success === true);
        d = await fw({ action: 'apply' });
        check('applied (' + (d.message || d.error) + ')', d.success === true);
        rows = table('panel_geo_wl');
        check('the whitelist table has IPv6 entries too (' + rows.filter(r => r.includes(':')).length + ')', rows.filter(r => r.includes(':')).length > 100);
        await traffic('whitelist', true, false);
    } catch (e) {
        check('the run went to the end (' + e.message.split('\n')[0] + ')', false);
    } finally {
        console.log('\n== 5. Everything back as it was ==');
        try {
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
        } catch (e) { check('passkey removal (' + e.message + ')', false); }
        await browser.close();
        tunnel.kill();
        // The state file as it was, the panel restarted on it, the anchor empty as before, the folder the run made.
        remote('cp -p ' + SAVED + ' ' + STATE + ' && rm -f ' + SAVED + ' && service daemoxcp_mail restart >/dev/null 2>&1 </dev/null; '
            + 'pfctl -a panel-fw -F all >/dev/null 2>&1; ' + (hadGeo ? '' : 'rm -rf ' + GEO + '; ') + 'true');
        check('the anchor is empty again', remote('pfctl -a panel-fw -sr 2>/dev/null | wc -l').trim() === '0');
        check('SSH still answers', remote('echo alive').trim() === 'alive');
        console.log(failures === 0 ? '\nALL OK' : '\n' + failures + ' CHECKS FAILED');
        process.exit(failures === 0 ? 0 : 1);
    }
})();
