// The Java update of the Updates page on the TEST VM panel, as a person would do it (reperto 195): sign in, open the
// Java row, "Prepare", read the checks and the exact plan with its fingerprint, "Upgrade the JVM and restart the
// panel", type the word, wait for the panel to go down and come back, sign in again (a restart ends every session,
// reperto 184), read the last report where the page says it is (Diagnostics, The panel's Java). Then, on the VM:
// the service sees the panel again (its pidfile is the root part), the web part runs as mailpanel and holds the
// port, the JVM is the new one and protected again.
//
// It needs the VM with a JVM update waiting. After a run the JVM is the new one: the way back the script leaves
// puts the old one back (stop the panel first, it runs on that JVM):
//   service mailpanel stop; pkg unlock -y openjdk25; pkg add -f /var/db/mailpanel/jdk/<folder>/openjdk25-<old>.pkg
//   pkg lock -y openjdk25; service mailpanel start
// Through an SSH tunnel to the VM's port 2096 (the VM's certificate is self-signed: certificate errors are ignored,
// for this test machine only). Sign-in with a console code; the fresh confirmation with the "confirm" mode of
// tests/signed-jobs-setup.sh (VM only, never on a real server). Both helpers copied to /root/signed on the VM:
// tests/signed-jobs-setup.sh and tests/java-update-state.sh.
//
// Usage:
//   ssh -i ~/.ssh/freebsd_test_vm -N -L 127.0.0.1:2096:127.0.0.1:2096 root@192.168.1.20 &
//   NODE_PATH=<playwright node_modules> node tests/java-update-browser-test.js <screenshot-folder>
const { chromium } = require('playwright');
const { execSync } = require('child_process');
const BASE = 'https://127.0.0.1:2096';
const OUT = process.argv[2];
const VM = 'ssh -i ' + process.env.HOME + '/.ssh/freebsd_test_vm -o IdentitiesOnly=yes -o ConnectTimeout=10 root@192.168.1.20';
let failed = 0;
const check = (what, ok) => { console.log((ok ? '  OK     ' : '  FAILED ') + what); if (!ok) failed++; };
const text = async (page, sel) => (await page.locator(sel).innerText().catch(() => '')).replace(/\s+\n/g, '\n').trim();

async function signIn(page) {
    const code = execSync(VM + " 'cd /home/panel && /usr/local/openjdk25/bin/java -jar freebsd-mail-panel-1.0.jar --access-code 2>/dev/null'")
        .toString().match(/([0-9]{4} [0-9]{4})/)[1];
    await page.goto(BASE + '/index');
    await page.click('#linkConsole');
    await page.fill('#consoleCode', code);
    await page.click('#btnConsole');
    await page.waitForURL(u => !String(u).includes('/index'), { timeout: 30000 });
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
    console.log('  ' + execSync(VM + " 'sh /root/signed/signed-jobs-setup.sh confirm'").toString().trim().split('\n').join('\n  '));

    await page.goto(BASE + '/updates');
    await page.waitForSelector('#uc-java:not([hidden]) button[data-on-click="ucJava()"]', { timeout: 180000 });
    console.log('  Java row: ' + (await text(page, '#uc-java .uc-head')).replace(/\n/g, ' | '));
    await page.click('#uc-java button[data-on-click="ucJava()"]');
    await page.waitForFunction(() => { const el = document.getElementById('jv-pre'); return el && el.querySelector('table') && !el.querySelector('.fa-spinner'); }, null, { timeout: 180000 });
    console.log('  checks:\n    ' + (await text(page, '#jv-pre')).split('\n').join('\n    '));
    await page.screenshot({ path: OUT + '/java-1-prepared.png', fullPage: true });
    const prepared = await text(page, '#jv-pre');
    check('the exact plan is shown, with its fingerprint', /openjdk25/.test(prepared) && /[0-9a-f]{16}/.test(prepared));
    check('it says the panel starts again with its service', /starts again with its service/.test(prepared));
    const run = page.locator('#jv-pre button[data-on-click="jvRun()"]');
    check('the run button is there', await run.count() === 1);
    if (await run.count() !== 1) { await browser.close(); process.exit(1); }

    const t0 = Date.now();
    await run.click();
    // The panel's window (reperto 197), with what stops and the plan.
    await page.waitForSelector('#panelAskModal.show');
    console.log('  confirmation: ' + (await page.innerText('#panelAskModal .modal-body')).replace(/\s+/g, ' ').slice(0, 200));
    await page.click('#panelAskGo');
    await page.waitForFunction(() => /Started/.test(document.getElementById('jv-pre').innerText), null, { timeout: 120000 });
    console.log('  after the click: ' + (await text(page, '#jv-pre')).replace(/\n/g, ' | '));
    await page.screenshot({ path: OUT + '/java-2-started.png', fullPage: true });

    // The panel stops and comes back: wait until /index stops answering, then until it answers again.
    let down = false, back = false;
    for (let i = 0; i < 400 && !back; i++) {
        let st = 0;
        try { st = (await page.request.get(BASE + '/index', { timeout: 5000 })).status(); } catch (e) { st = 0; }
        if (st !== 200) { if (!down) console.log('  panel down after ' + Math.round((Date.now() - t0) / 1000) + ' s'); down = true; }
        else if (down) { back = true; console.log('  panel back after ' + Math.round((Date.now() - t0) / 1000) + ' s'); }
        await new Promise(r => setTimeout(r, 1500));
    }
    check('the panel went down', down);
    check('the panel came back', back);

    await page.goto(BASE + '/updates');
    if (page.url().includes('/index')) { console.log('  the restart ended the session (by design): signing in again'); await signIn(page); await page.goto(BASE + '/updates'); }
    check('signed in again after the restart', !page.url().includes('/index'));
    await page.waitForFunction(() => !/Reading/i.test(document.getElementById('ucState').innerText), null, { timeout: 180000 }).catch(() => {});
    check('the Java row is gone (nothing left to do)', await page.locator('#uc-java').isHidden());
    // Where the page said the report is: Diagnostics, The panel's Java, Last report.
    await page.goto(BASE + '/diagnostics');
    await page.click('button[data-on-click="jvState()"]');
    await page.waitForFunction(() => { const p = document.getElementById('jv-log'); return p && p.textContent && !/^Reading/.test(p.textContent); }, null, { timeout: 60000 });
    const report = await page.locator('#jv-log').textContent();
    console.log('  report:\n    ' + report.trim().split('\n').filter(l => !/^\s*\[[0-9]+\/[0-9]+\] (Fetching|Extracting|Upgrading)|^(Updating|All repositories|FreeBSD-ports)/.test(l)).join('\n    '));
    check('the report says it succeeded', /RESULT: SUCCEEDED/.test(report));
    check('the report names the way back', /way back: \/var\/db\/mailpanel\/jdk\/[0-9]{8}-[0-9]{6}\/openjdk25-/.test(report));
    check('no placeholder left in the report', !/\{[A-Za-z_]+\}/.test(report));
    check('the download came before the stop', report.indexOf('Downloading') >= 0 && report.indexOf('Downloading') < report.indexOf('Stopping the panel'));
    check('it checked the panel answers on its port', /the panel answers on port 2096/.test(report));
    check('dates in UTC', / UTC ===/.test(report));
    await page.screenshot({ path: OUT + '/java-3-after.png', fullPage: true });
    const state = execSync(VM + " 'sh /root/signed/java-update-state.sh'").toString();
    console.log('  VM:\n    ' + state.trim().split('\n').slice(0, 10).join('\n    '));
    const pidfile = (state.match(/^pidfile: ([0-9]+)/m) || [])[1];
    check('the service sees the panel again', /^service: mailpanel is running as pid [0-9]+/m.test(state));
    check('the pidfile is the root part', pidfile && new RegExp('^\\s*' + pidfile + '\\s+[0-9]+\\s+root\\s+.*--web$', 'm').test(state));
    check('the web part runs as mailpanel and holds the port', /port 2096: mailpanel java/.test(state));
    check('Java is the new one, protected again', /openjdk25: 25\.0\.5[^,]*, repo 25\.0\.5[^,]*, locked: 1/.test(state));
    check('no page errors' + (errors.length ? ': ' + errors.join(' | ') : ''), errors.length === 0);
    console.log('  ' + execSync(VM + " 'sh /root/signed/signed-jobs-setup.sh confirm-stop'").toString().trim());
    await browser.close();
    console.log('\n' + (failed === 0 ? 'ALL OK' : failed + ' CHECKS FAILED'));
    process.exit(failed ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
