// The move to Dovecot 2.4 (finding 213), on the real panel of the TEST VM, from the page, as the owner would do it:
//
//  1. Diagnostics before: Dovecot's configuration not ready for 2.4, to look at (not a problem), pointing to Updates.
//  2. Updates: the row "Dovecot 2.4" with Prepare; the checks (nothing stops), the exact plan with 2.3 removed first
//     and 2.4 installed, the tests that will run, one button.
//  3. The move: one confirmation in the panel's window; the job runs to its end; its log has the eight steps, the same
//     mail tests passing before (on 2.3) and after (on 2.4), and no way back taken; the outcome stays under the row.
//  4. Diagnostics after: Dovecot fine, the compatibility card says 2.4 is installed.
//
// It CHANGES the VM: Dovecot goes from 2.3 to 2.4. Run it only on the test VM, with Dovecot 2.3 installed.
// Through an SSH tunnel to the VM's port 2096 (self-signed certificate: errors ignored, for this test machine only).
// Sign-in with a console code; the fresh confirmation with the "confirm" mode of tests/signed-jobs-setup.sh, copied to
// /root/signed on the VM.
// The plan must not bring a second MySQL client (mysql267-client next to mysql84-client, measured on 09/11/2026).
//
// Usage:
//   ssh -i ~/.ssh/freebsd_test_vm -N -L 127.0.0.1:2096:127.0.0.1:2096 root@192.168.1.20 &
//   NODE_PATH=<playwright node_modules> node tests/dovecot24-move-browser-test.js [screenshot-folder]
const { chromium } = require('playwright');
const { execSync } = require('child_process');
// The panel's name (HOST=panel.rehearsal.test on the test VM): once the panel has a name it refuses any other Host
// (HostCheck), so the browser resolves that name to the tunnel. Without HOST, 127.0.0.1 as before.
const HOST = process.env.HOST || '127.0.0.1';
const BASE = 'https://' + HOST + ':2096';
const OUT = process.argv[2];
const VM = 'ssh -i ' + process.env.HOME + '/.ssh/freebsd_test_vm -o IdentitiesOnly=yes -o ConnectTimeout=10 root@192.168.1.20';
let failed = 0;
const check = (what, ok) => { console.log((ok ? '  OK     ' : '  FAILED ') + what); if (!ok) failed++; };

async function diagnostics(page) {
    await page.goto(BASE + '/diagnostics');
    await page.click('#diagAllGo');
    await page.waitForFunction(() => /things? to look at|checks are fine/.test(document.getElementById('diagAllState').textContent), null, { timeout: 900000 });
    const all = await page.$$eval('#diagAllList > li, #diagAllOk > li', lis => lis.map(li => ({ key: li.dataset.diag,
        level: li.closest('#diagAllOk') ? 'ok' : li.dataset.level, text: li.textContent.replace(/\s+/g, ' ').trim() })));
    return all.find(x => x.key === 'compat') || { level: '?', text: '' };
}

(async () => {
    const browser = await chromium.launch({ headless: true, channel: 'chrome', args: HOST === '127.0.0.1' ? [] : ['--host-resolver-rules=MAP ' + HOST + ' 127.0.0.1'] });
    const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1400, height: 1000 }, locale: 'en-US' });
    const page = await context.newPage();
    const errors = [], dialogs = [];
    page.on('pageerror', e => errors.push(String(e)));
    page.on('dialog', async d => { dialogs.push(d.message()); await d.dismiss(); });
    const code = execSync(VM + " 'cd /home/panel && /usr/local/openjdk25/bin/java -jar daemoxcp-mail.jar --lang en --access-code 2>/dev/null' </dev/null")
        .toString().match(/([0-9]{4} [0-9]{4})/)[1];
    await page.goto(BASE + '/index');
    await page.click('#linkConsole');
    await page.fill('#consoleCode', code);
    await page.click('#btnConsole');
    await page.waitForURL(u => !String(u).includes('/index'), { timeout: 30000 });
    check('signed in with a console code', !page.url().includes('/index'));
    // The fresh confirmation that a dangerous operation asks (passkey or e-mail code): the "confirm" mode of the helper.
    console.log('  ' + execSync(VM + " 'sh /root/signed/signed-jobs-setup.sh confirm' </dev/null").toString().trim());

    console.log('\n== 1. Diagnostics before ==');
    const before = await diagnostics(page);
    console.log('    ' + before.level + ': ' + before.text.slice(0, 300));
    check('Dovecot not ready for 2.4: to look at, not a problem, and the move is guided in Updates',
        before.level === 'warn' && /not ready for 2\.4 yet/.test(before.text) && /The move is guided in Updates \(Dovecot 2\.4\)/.test(before.text));

    console.log('\n== 2. Updates: the row and its checks ==');
    await page.goto(BASE + '/updates');
    await page.waitForSelector('#uc-dovecot:not([hidden]) .uc-head button', { timeout: 300000 });
    check('the row "Dovecot 2.4", to do, with Prepare', /Dovecot 2\.4/.test(await page.innerText('#uc-dovecot .uc-head'))
        && await page.$$eval('#uc-dovecot .uc-head button', b => b.length === 1 && b[0].getAttribute('data-on-click') === 'ucDovecot()'));
    await page.click('#uc-dovecot .uc-head button');
    await page.waitForFunction(() => !/Running checks/.test(document.getElementById('dc24-pre').innerText)
        && document.getElementById('dc24-pre').innerText.length > 50, null, { timeout: 300000 });
    const pre = await page.innerText('#dc24-pre');
    console.log('    ' + pre.replace(/\s+/g, ' ').slice(0, 1500));
    if (OUT) await page.locator('#uc-dovecot').screenshot({ path: OUT + '/dovecot24-prepare-vm.png' });
    check('nothing stops it', !/cannot start|blocked/i.test(pre) && await page.$('#dc24-pre button[data-on-click="dc24Run()"]') !== null);
    check('  the plan: 2.3 removed first, 2.4 installed', /remove\s+dovecot-mysql/.test(pre) && /remove\s+dovecot-pigeonhole-mysql/.test(pre)
        && /install\s+dovecot24-mysql/.test(pre) && /install\s+dovecot24-pigeonhole-mysql/.test(pre));
    check('  the tests that will run, on which mailbox', /IMAP login on 993 into \S+@\S+ with the master user/.test(pre));
    check('  no second MySQL client: mysql84-client used as it is, unlocked for pkg only', !/mysql267/.test(pre)
        && /pkg uses mysql84-client as they are, but only without protection/.test(pre) && !/must also change mysql84-client/.test(pre));

    console.log('\n== 3. The move ==');
    await page.click('#dc24-pre button[data-on-click="dc24Run()"]');
    await page.waitForSelector('#panelAskModal.show', { timeout: 10000 });
    check('one confirmation in the panel\'s window, with the plan', /Move to Dovecot 2\.4\?/.test(await page.innerText('#panelAskModal'))
        && /dovecot24-mysql: - → 2\.4/.test(await page.innerText('#panelAskModal')));
    await page.click('#panelAskGo');
    const t0 = Date.now();
    await page.waitForFunction(() => (/Done\./.test(document.getElementById('dc24-pre').innerText) || document.querySelector('#dc24-pre .alert-danger'))
        && !/fa-spin/.test(document.getElementById('dc24-pre').innerHTML), null, { timeout: 1800000 });
    const outcome = await page.innerText('#dc24-pre');
    console.log('    after ' + Math.round((Date.now() - t0) / 1000) + ' s: ' + outcome.replace(/\s+/g, ' ').slice(0, 600));
    const log = await page.textContent('#dc24-log');
    console.log(log.split('\n').map(l => '    | ' + l).join('\n'));
    check('the outcome: Dovecot 2.4 installed, the mail passes the same tests', /Dovecot 2\.4\.\S+ installed: the mail passes the same tests as before/.test(outcome));
    check('  the log: the eight steps', [1, 2, 3, 4, 5, 6, 7, 8].every(n => log.includes('[' + n + '/8]')));
    // The tests, each up to its «Dovecot listens on» line: after it on 2.4 comes the check of every listening address.
    const testsFrom = mark => { const i = log.indexOf(mark); return i < 0 ? '' : log.slice(i, log.indexOf('Dovecot listens on', i)); };
    const firstTests = testsFrom('The mail tests now, on 2.3:'), lastTests = testsFrom('[7/8]');
    const step7 = log.slice(log.indexOf('[7/8]'), log.indexOf('[8/8]'));
    // The page's log has the time first on every line: «[19:13:20]     ok  doveconf -n».
    const oks = s => (s.match(/^\[[0-9:]+\]\s+ok\s{2}/gm) || []).length;
    check('  the same tests before and after, all passing (' + oks(firstTests) + ' and ' + oks(lastTests) + ')',
        oks(firstTests) >= 5 && oks(firstTests) === oks(lastTests) && !/^\[[0-9:]+\]\s+NO\s{2}/m.test(firstTests + lastTests));
    check('  the IMAP login and the LMTP delivery among them', /ok\s+IMAP login on 993/.test(lastTests) && /ok\s+LMTP delivery to/.test(lastTests));
    check('  the password process still not root, the database user still Dovecot\'s',
        /auth-worker\) runs as dovecot/.test(step7) && /now daemoxcp_mail_dovecot/.test(log));
    check('  no way back taken', !/Putting Dovecot 2\.3 back/.test(log));
    if (OUT) await page.locator('#uc-dovecot').screenshot({ path: OUT + '/dovecot24-done-vm.png' });

    console.log('\n== 4. Diagnostics after ==');
    const after = await diagnostics(page);
    console.log('    ' + after.level + ': ' + after.text.slice(0, 300));
    check('Dovecot fine: nothing about 2.4 left to look at', after.level === 'ok' || !/Dovecot/.test(after.text));
    await page.evaluate(() => { const b = document.querySelector('#diagAllOk li[data-diag="compat"] button, #diagAllList li[data-diag="compat"] button'); if (b) b.click(); });
    await page.waitForTimeout(3000);
    const card = await page.textContent('#diag-compat').catch(() => '');
    check('the compatibility card: 2.4 installed, the configuration in its format', /Dovecot 2\.4 is installed, and the configuration is in 2\.4 format/.test(card));
    if (OUT) await page.locator('#diag-compat').screenshot({ path: OUT + '/dovecot24-diagnostics-vm.png' }).catch(() => {});

    check('no browser dialog, no page error' + (errors.length + dialogs.length ? ': ' + errors.concat(dialogs).join(' | ') : ''), !errors.length && !dialogs.length);
    await browser.close();
    execSync(VM + " 'sh /root/signed/signed-jobs-setup.sh confirm-stop || true' </dev/null");
    console.log('\n' + (failed === 0 ? 'ALL OK' : failed + ' CHECKS FAILED'));
    process.exit(failed ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
