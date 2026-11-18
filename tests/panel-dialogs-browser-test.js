// No browser dialog on the real panel of the TEST VM (reperto 198): every page of the menu loads without errors and
// without alert/confirm/prompt; on Domains and Mailboxes "Delete" opens the panel's window with the red button, and
// cancelling it changes nothing (the same domains and mailboxes as before). Read only: nothing is confirmed.
//
// Through an SSH tunnel to the VM's port 2096 (self-signed certificate: errors ignored, for this test machine only).
// Sign-in with a console code.
//
// Usage:
//   ssh -i ~/.ssh/freebsd_test_vm -N -L 127.0.0.1:2096:127.0.0.1:2096 root@192.168.1.20 &
//   NODE_PATH=<playwright node_modules> node tests/panel-dialogs-browser-test.js [screenshot-folder]
const { chromium } = require('playwright');
const { execSync } = require('child_process');
const BASE = 'https://127.0.0.1:2096';
const OUT = process.argv[2];
const VM = 'ssh -i ' + process.env.HOME + '/.ssh/freebsd_test_vm -o IdentitiesOnly=yes -o ConnectTimeout=10 root@192.168.1.20';
let failed = 0;
const check = (what, ok) => { console.log((ok ? '  OK     ' : '  FAILED ') + what); if (!ok) failed++; };

(async () => {
    const browser = await chromium.launch({ headless: true, channel: 'chrome' });
    const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1400, height: 1000 }, locale: 'en-US' });
    const page = await context.newPage();
    const errors = [], dialogs = [];
    page.on('pageerror', e => errors.push(page.url() + ': ' + String(e)));
    page.on('dialog', async d => { dialogs.push(page.url() + ': ' + d.type() + ': ' + d.message()); await d.dismiss(); });

    const code = execSync(VM + " 'cd /home/panel && /usr/local/openjdk25/bin/java -jar daemoxcp-mail.jar --access-code 2>/dev/null'")
        .toString().match(/([0-9]{4} [0-9]{4})/)[1];
    await page.goto(BASE + '/index');
    await page.click('#linkConsole');
    await page.fill('#consoleCode', code);
    await page.click('#btnConsole');
    await page.waitForURL(u => !String(u).includes('/index'), { timeout: 30000 });
    check('signed in with a console code', !page.url().includes('/index'));

    console.log('\n== every page of the menu ==');
    const links = await page.$$eval('.sidebar-link', a => a.map(x => x.getAttribute('href')));
    for (const href of links) {
        await page.goto(BASE + href);
        await page.waitForLoadState('networkidle').catch(() => {});
        await page.waitForTimeout(500);
    }
    check(links.length + ' pages visited, no page error' + (errors.length ? ': ' + errors.slice(0, 3).join(' | ') : ''), links.length >= 15 && errors.length === 0);

    // "Delete", then "Cancel" in the panel's window: what it says, the red button, and nothing changed.
    const cancelDelete = async (what, list, open) => {
        console.log('\n== ' + what + ' ==');
        const before = await list();
        await open();
        await page.waitForSelector('#panelAskModal.show', { timeout: 10000 });
        const asked = (await page.innerText('#panelAskModal .modal-content')).replace(/\s+/g, ' ');
        console.log('    ' + asked.slice(0, 200));
        check(what + ': the panel\'s window, with the red button', await page.$eval('#panelAskGo', b => b.classList.contains('btn-danger')));
        if (OUT) await page.screenshot({ path: OUT + '/dialogs-' + what.toLowerCase().replace(/\W+/g, '-') + '.png' });
        await page.click('#panelAskModal .modal-footer [data-bs-dismiss="modal"]');
        await page.waitForFunction(() => !document.getElementById('panelAskModal').classList.contains('show'), null, { timeout: 5000 });
        await page.waitForTimeout(800);
        const after = await list();
        check(what + ': cancelled, nothing changed (' + before.length + ' before, ' + after.length + ' after)', before.length > 0 && JSON.stringify(before) === JSON.stringify(after));
    };
    await page.goto(BASE + '/domains');
    await page.waitForSelector('button[data-on-click^="deleteDomain("]', { timeout: 30000 });
    await cancelDelete('Delete a domain',
        () => page.$$eval('button[data-on-click^="deleteDomain("]', b => b.map(x => x.getAttribute('data-on-click'))),
        () => page.click('button[data-on-click^="deleteDomain("]'));
    await page.goto(BASE + '/mailboxes');
    await page.waitForSelector('#mailboxesTable .dropdown-toggle', { timeout: 30000 });
    await cancelDelete('Delete a mailbox',
        // The table's text, every mailbox in it: the same after the cancel.
        () => page.$eval('#mailboxesTable', t => [t.innerText.replace(/\s+/g, ' ').trim()]).then(x => x[0].includes('@') ? x : []),
        async () => { await page.click('#mailboxesTable .dropdown-toggle'); await page.click('#mailboxesTable .dropdown-item.text-danger'); });

    check('no browser dialog anywhere' + (dialogs.length ? ': ' + dialogs.join(' | ') : ''), dialogs.length === 0);
    check('no page error' + (errors.length ? ': ' + errors.slice(0, 3).join(' | ') : ''), errors.length === 0);
    await browser.close();
    console.log('\n' + (failed === 0 ? 'ALL OK' : failed + ' CHECKS FAILED'));
    process.exit(failed ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
