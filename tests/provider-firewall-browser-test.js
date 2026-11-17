// The provider firewall card and the two new Diagnostics checks (reperti 245, 246), on the real panel of the TEST
// VM, from the page:
//
//  1. Firewall: the card "Your provider's firewall" with the rules from this server's real ports (SSH, mail, panel and
//     webmail), Cloudflare's official list ready to paste, not confirmed yet; "I have put this list..." asks once in
//     the panel's window, then the card says the list is the current one and the button is off.
//  2. Diagnostics, "Check everything": the provider firewall fine after the confirmation, and outgoing port 25 with a
//     verdict (on this VM the Mac's network closes port 25, so: closed).
//
// It writes /var/db/daemoxcp-mail/provider-firewall.json on the VM (removed before and after).
// Through an SSH tunnel to the VM's port 2096 (self-signed certificate: errors ignored, for this test machine only).
// Sign-in with a console code; the fresh confirmation with the "confirm" mode of tests/signed-jobs-setup.sh, copied to
// /root/signed on the VM.
//
// Usage:
//   ssh -i ~/.ssh/freebsd_test_vm -N -L 127.0.0.1:2096:127.0.0.1:2096 root@192.168.1.20 &
//   NODE_PATH=<playwright node_modules> node tests/provider-firewall-browser-test.js [screenshot-folder]
const { chromium } = require('playwright');
const { execSync } = require('child_process');
const BASE = 'https://127.0.0.1:2096';
const OUT = process.argv[2];
const VM = 'ssh -i ' + process.env.HOME + '/.ssh/freebsd_test_vm -o IdentitiesOnly=yes -o ConnectTimeout=10 root@192.168.1.20';
let failed = 0;
const check = (what, ok) => { console.log((ok ? '  OK     ' : '  FAILED ') + what); if (!ok) failed++; };

(async () => {
    execSync(VM + " 'rm -f /var/db/daemoxcp-mail/provider-firewall.json' </dev/null");
    const browser = await chromium.launch({ headless: true, channel: 'chrome' });
    const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1400, height: 1000 }, locale: 'en-US' });
    const page = await context.newPage();
    const errors = [], dialogs = [];
    page.on('pageerror', e => errors.push(String(e)));
    page.on('dialog', async d => { dialogs.push(d.message()); await d.dismiss(); });
    const code = execSync(VM + " 'cd /home/panel && /usr/local/openjdk25/bin/java -jar daemoxcp-mail.jar --access-code 2>/dev/null' </dev/null")
        .toString().match(/([0-9]{4} [0-9]{4})/)[1];
    await page.goto(BASE + '/index');
    await page.click('#linkConsole');
    await page.fill('#consoleCode', code);
    await page.click('#btnConsole');
    await page.waitForURL(u => !String(u).includes('/index'), { timeout: 30000 });
    check('signed in with a console code', !page.url().includes('/index'));
    console.log('  ' + execSync(VM + " 'sh /root/signed/signed-jobs-setup.sh confirm' </dev/null").toString().trim());

    console.log('\n== 1. Firewall: the provider firewall card ==');
    await page.goto(BASE + '/firewall');
    await page.waitForFunction(() => /Not confirmed yet|current list|changed its list|could not be downloaded/
        .test(document.getElementById('pfw-state').innerText), null, { timeout: 120000 });
    const rows = await page.$$eval('#pfw-rules tr', trs => trs.map(tr => [...tr.children].map(c => c.innerText.trim())));
    console.log('    ' + JSON.stringify(rows));
    check('three rules: SSH from your IP, mail from anyone, panel and webmail from Cloudflare', rows.length === 3
        && /SSH/.test(rows[0][0]) && /22/.test(rows[0][1]) && /your IP/.test(rows[0][2])
        && rows[1][1] === '25, 80, 143, 443, 465, 587, 993' && /Any IPv4, any IPv6/.test(rows[1][2])
        && rows[2][1] === '2096, 8443' && /Cloudflare/.test(rows[2][2]));
    const list = await page.inputValue('#pfw-list');
    check('Cloudflare\'s official list, comma separated, ready to paste (' + list.split(', ').length + ' ranges)',
        list.split(', ').length >= 22 && list.includes('173.245.48.0/20') && list.includes('2400:cb00::/32'));
    check('not confirmed yet, and the button is on', /Not confirmed yet/.test(await page.innerText('#pfw-state'))
        && !(await page.isDisabled('#pfw-ack')));
    check('it says why by hand (Hetzner tokens cover the whole project)', /whole project/.test(await page.innerText('#provider-firewall')));
    if (OUT) await page.locator('#provider-firewall').screenshot({ path: OUT + '/provider-firewall-before.png' });
    await page.click('#pfw-ack');
    await page.waitForSelector('#panelAskModal.show', { timeout: 10000 });
    check('one confirmation in the panel\'s window', /exactly this list/.test(await page.innerText('#panelAskModal')));
    await page.click('#panelAskGo');
    await page.waitForFunction(() => /current list/.test(document.getElementById('pfw-state').innerText), null, { timeout: 60000 });
    check('then: the current list, the button off', /current list/.test(await page.innerText('#pfw-state'))
        && await page.isDisabled('#pfw-ack'));
    const state = execSync(VM + " 'stat -f %Sp /var/db/daemoxcp-mail/provider-firewall.json' </dev/null").toString().trim();
    check('the confirmation on disk, root only (' + state + ')', state === '-rw-------');
    if (OUT) await page.locator('#provider-firewall').screenshot({ path: OUT + '/provider-firewall-after.png' });

    console.log('\n== 2. Diagnostics: Check everything ==');
    await page.goto(BASE + '/diagnostics');
    await page.click('#diagAllGo');
    await page.waitForFunction(() => /things? to look at|checks are fine/.test(document.getElementById('diagAllState').textContent), null, { timeout: 900000 });
    const all = await page.$$eval('#diagAllList > li, #diagAllOk > li', lis => lis.map(li => ({ key: li.dataset.diag,
        level: li.closest('#diagAllOk') ? 'ok' : li.dataset.level, text: li.textContent.replace(/\s+/g, ' ').trim() })));
    const pfw = all.find(x => x.key === 'pfw') || {}, so = all.find(x => x.key === 'smtpout') || {};
    console.log('    pfw: ' + pfw.level + ': ' + (pfw.text || '').slice(0, 200));
    console.log('    smtpout: ' + so.level + ': ' + (so.text || '').slice(0, 300));
    check('the provider firewall: fine after the confirmation', pfw.level === 'ok' && /current one/.test(pfw.text));
    check('outgoing port 25: a verdict (closed on this VM, with what to ask the provider)', so.level === 'problem'
        && /closed/.test(so.text) && /Hetzner/.test(so.text));
    if (OUT) await page.locator('#diagAllBox, #diagAllList').first().screenshot({ path: OUT + '/diagnostics-new-checks.png' }).catch(() => {});

    check('no browser dialog, no page error' + (errors.length + dialogs.length ? ': ' + errors.concat(dialogs).join(' | ') : ''), !errors.length && !dialogs.length);
    await browser.close();
    execSync(VM + " 'sh /root/signed/signed-jobs-setup.sh confirm-stop || true; rm -f /var/db/daemoxcp-mail/provider-firewall.json' </dev/null");
    console.log('\n' + (failed === 0 ? 'ALL OK' : failed + ' CHECKS FAILED'));
    process.exit(failed ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
