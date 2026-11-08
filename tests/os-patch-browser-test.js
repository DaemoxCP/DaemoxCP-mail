// The FreeBSD patches on the TEST VM panel, as a person would do them, one step at a time (reperto 196).
//
// Phase "install": sign in, Updates; if no patch is waiting, "Search for updates" at the top; the FreeBSD row then says
// which patches are ready and has one button, "Install the FreeBSD updates"; the panel's confirmation; the progress in
// one line, the details closed; at the end the outcome with the one step left (the restart, with its button), and the
// row says it too. Diagnostics, Operation logs: the search and the patches, completed, with their log on disk. Then the
// restart from the panel's window, in one minute.
// Phase "after" (once the VM is back): sign in again, the FreeBSD row says the patches are in and nothing is left, and
// the operation logs written before the restart are still there.
//
// It changes the VM (patches, a boot environment, a restart): on the test VM only. Through an SSH tunnel to the VM's
// port 2096 (self-signed certificate: errors ignored, for this test machine only). Sign-in with a console code; the
// fresh confirmation with the "confirm" mode of tests/signed-jobs-setup.sh copied to /root/signed (VM only).
//
// Usage:
//   ssh -i ~/.ssh/freebsd_test_vm -N -L 127.0.0.1:2096:127.0.0.1:2096 root@192.168.1.20 &
//   NODE_PATH=<playwright node_modules> node tests/os-patch-browser-test.js install|after <screenshot-folder>
const { chromium } = require('playwright');
const { execSync } = require('child_process');
const BASE = 'https://127.0.0.1:2096';
const PHASE = process.argv[2];
const OUT = process.argv[3];
const VM = 'ssh -i ' + process.env.HOME + '/.ssh/freebsd_test_vm -o IdentitiesOnly=yes -o ConnectTimeout=10 root@192.168.1.20';
let failed = 0;
const check = (what, ok) => { console.log((ok ? '  OK     ' : '  FAILED ') + what); if (!ok) failed++; };
const text = async (page, sel) => (await page.locator(sel).innerText().catch(() => '')).replace(/\s+/g, ' ').trim();

async function signIn(page) {
    const code = execSync(VM + " 'cd /home/panel && /usr/local/openjdk25/bin/java -jar freebsd-mail-panel-1.0.jar --access-code 2>/dev/null'")
        .toString().match(/([0-9]{4} [0-9]{4})/)[1];
    await page.goto(BASE + '/index');
    await page.click('#linkConsole');
    await page.fill('#consoleCode', code);
    await page.click('#btnConsole');
    await page.waitForURL(u => !String(u).includes('/index'), { timeout: 30000 });
}

async function osRow(page) {
    await page.goto(BASE + '/updates');
    await page.waitForFunction(() => document.getElementById('ucState') && document.getElementById('ucState').textContent === ''
        && !/Reading/.test(document.querySelector('#uc-os .uc-head').innerText), null, { timeout: 300000 });
    return text(page, '#uc-os .uc-head');
}

async function logs(page) {
    await page.goto(BASE + '/diagnostics');
    await page.click('button[data-on-click="jrList()"]');
    await page.waitForSelector('#jr-list table, #jr-list p', { timeout: 60000 });
    return page.$$eval('#jr-list tbody tr', trs => trs.map(tr => tr.innerText.replace(/\s+/g, ' ').trim()));
}

(async () => {
    const browser = await chromium.launch({ headless: true, channel: 'chrome' });
    const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1400, height: 1000 }, locale: 'en-US' });
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', e => errors.push(String(e)));
    page.on('dialog', d => { errors.push('browser dialog: ' + d.message()); d.dismiss(); });
    await signIn(page);
    check('signed in with a console code', !page.url().includes('/index'));

    if (PHASE === 'install') {
        console.log('  ' + execSync(VM + " 'sh /root/signed/signed-jobs-setup.sh confirm'").toString().trim().split('\n').join('\n  '));
        let row = await osRow(page);
        console.log('  FreeBSD row: ' + row);
        if (!(await page.$('#uc-os button[data-on-click="ucOsInstall()"]'))) {
            check('no patch known yet: the row says to check for updates, with no button of its own', /Check for updates/.test(row));
            await page.click('#ucSearchButton');
            await page.waitForFunction(() => document.getElementById('ucOutcome').innerText.trim().length > 0, null, { timeout: 1800000 });
            console.log('  search: ' + await text(page, '#ucOutcome'));
            await page.waitForSelector('#uc-os button[data-on-click="ucOsInstall()"]', { timeout: 300000 });
            row = await text(page, '#uc-os .uc-head');
            console.log('  FreeBSD row: ' + row);
        }
        check('the row says which patches are ready, with one button', /patches up to 15\.1-RELEASE-p[0-9]+ are ready/.test(row)
            && await page.$$eval('#uc-os .uc-head button', b => b.length) === 1);
        if (OUT) await page.locator('#uc-os').screenshot({ path: OUT + '/patch-1-ready.png' });
        await page.click('#uc-os button[data-on-click="ucOsInstall()"]');
        await page.waitForSelector('#panelAskModal.show');
        await page.click('#panelAskGo');
        await page.waitForFunction(() => /Installing the patches/.test(document.getElementById('os-body').innerText), null, { timeout: 30000 });
        check('the progress in one line, the details closed', await page.$eval('#os-log-box', d => !d.hidden && !d.open));
        await page.waitForFunction(() => /Patches installed|did not|failed/i.test(document.getElementById('os-body').innerText), null, { timeout: 3600000 });
        const outcome = await text(page, '#os-body');
        console.log('  outcome: ' + outcome);
        check('the outcome: what is installed and the restart left, with its button', /Patches installed: FreeBSD 15\.1-RELEASE-p[0-9]+/.test(outcome)
            && /One step left: restart the server/.test(outcome) && await page.$('#os-body button[data-on-click="panelRebootOpen()"]') !== null);
        await page.waitForFunction(() => /One step left/.test(document.querySelector('#uc-os .uc-head').innerText), null, { timeout: 120000 });
        check('the FreeBSD row says it too, with the restart button', await page.$('#uc-os .uc-head button[data-on-click="panelRebootOpen()"]') !== null);
        if (OUT) await page.locator('#uc-os').screenshot({ path: OUT + '/patch-2-done.png' });
        const done = await logs(page);
        console.log('  operation logs:\n    ' + done.slice(0, 4).join('\n    '));
        check('Operation logs: the patches, completed', done.some(r => /FreeBSD patches/.test(r) && /completed/.test(r)));
        await page.click('#jr-list tbody tr:first-child button');
        await page.waitForFunction(() => /=== end:/.test(document.getElementById('jr-text').textContent), null, { timeout: 30000 });
        const journal = await page.locator('#jr-text').textContent();
        check('  its log on disk, with UTC times and the end', /=== job .* started 20.*Z ===/.test(journal) && /Z === end: completed/.test(journal));
        console.log('  ' + execSync(VM + " 'sh /root/signed/signed-jobs-setup.sh confirm-stop'").toString().trim());
        // The restart, from the panel's window, in one minute.
        await page.goto(BASE + '/updates');
        await page.waitForSelector('#uc-os .uc-head button[data-on-click="panelRebootOpen()"]', { timeout: 300000 });
        await page.click('#uc-os .uc-head button[data-on-click="panelRebootOpen()"]');
        await page.waitForFunction(() => !document.getElementById('panelRebootGo').disabled, null, { timeout: 30000 });
        await page.check('#panelRebootIn1');
        await page.click('#panelRebootGo');
        await page.waitForFunction(() => /restarts at/.test(document.getElementById('panelRebootBody').innerText), null, { timeout: 30000 });
        check('the restart is scheduled from the panel', true);
    } else {
        const row = await osRow(page);
        console.log('  FreeBSD row: ' + row);
        check('after the restart: the patches are in, nothing left', /no patch waiting/.test(row) && !/One step left/.test(row));
        const kept = await logs(page);
        console.log('  operation logs:\n    ' + kept.slice(0, 4).join('\n    '));
        check('the operation logs written before the restart are still there', kept.some(r => /FreeBSD patches/.test(r) && /completed/.test(r)));
        if (OUT) await page.screenshot({ path: OUT + '/patch-3-after.png', fullPage: true });
    }
    check('no page errors, no browser dialog' + (errors.length ? ': ' + errors.join(' | ') : ''), errors.length === 0);
    await browser.close();
    console.log('\n' + (failed === 0 ? 'ALL OK' : failed + ' CHECKS FAILED'));
    process.exit(failed ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
