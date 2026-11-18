// The procedures of the Updates page with a row of their own on the VM panel, in a real browser, as a person would use
// them (reperto 190): Python's move and the move to MySQL 8.4. Roundcube was the third: since reperto 207 it is a step
// of "Update everything", tested by everything-browser-test.js.
// "Check prerequisites", the exact plan and its fingerprint in the card, start, the confirmation word, the log to
// the end. It checks that the card shows the plan, that the start request carries the fingerprint the card showed,
// and that the job ran that one and changed nothing outside it.
//
// Against the panel of the TEST VM, through an SSH tunnel to its port 2096 (the panel answers only to its name,
// 127.0.0.1 there), with the old situations prepared by tests/signed-jobs-setup.sh (python, mysql84). It signs in with a console code taken from the VM, and gives its session the fresh confirmation with
// the "confirm" mode of tests/signed-jobs-setup.sh, copied to /root/signed on the VM (MySQL, as
// separation-service-test.sh does: on the VM only, never on a real server); "confirm-stop" ends it.
// The VM's certificate is self-signed: certificate errors are ignored here, for this test machine only.
//
// Usage:
//   ssh -i ~/.ssh/freebsd_test_vm -N -L 127.0.0.1:2096:127.0.0.1:2096 root@192.168.1.20 &
//   NODE_PATH=<playwright node_modules> node tests/signed-jobs-browser-test.js <screenshot-folder> [python,mysql]
const { chromium } = require('playwright');
const { execSync } = require('child_process');
const fs = require('fs');
// The panel's name (HOST=panel.rehearsal.test on the test VM): once the panel has a name it refuses any other Host
// (HostCheck), so the browser resolves that name to the tunnel. Without HOST, 127.0.0.1 as before.
const HOST = process.env.HOST || '127.0.0.1';
const BASE = 'https://' + HOST + ':2096';
const OUT = process.argv[2];
const ONLY = (process.argv[3] || 'python,mysql').split(',');
const VM = 'ssh -i ' + process.env.HOME + '/.ssh/freebsd_test_vm -o IdentitiesOnly=yes -o ConnectTimeout=10 root@192.168.1.20';
// The rows of "Update the server" (reperti 193, 197): the row's one button, "Prepare", opens the guided panel under it.
const CARDS = [
    { key: 'python', pre: 'ucPython()', run: 'pyRun()', box: '#py-pre', log: '#py-log', word: 'MOVE PYTHON' },
    { key: 'mysql', pre: 'ucMysql()', run: 'my84Run()', box: '#my84-pre', log: '#my84-log', word: 'MIGRATE TO 8.4' },
];
let failed = 0;
const check = (what, ok) => { console.log((ok ? '  OK     ' : '  FAILED ') + what); if (!ok) failed++; };

(async () => {
    const code = execSync(VM + " 'cd /home/panel && /usr/local/openjdk25/bin/java -jar daemoxcp-mail.jar --access-code 2>/dev/null'")
        .toString().match(/([0-9]{4} [0-9]{4})/)[1];
    const browser = await chromium.launch({ headless: true, channel: 'chrome', args: HOST === '127.0.0.1' ? [] : ['--host-resolver-rules=MAP ' + HOST + ' 127.0.0.1'] })   // the Chrome installed on the Mac, with an empty profile;
    const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1400, height: 1000 }, locale: 'en-US' });
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', e => errors.push(String(e)));
    page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });

    await page.goto(BASE + '/index');
    await page.click('#linkConsole');
    await page.fill('#consoleCode', code);
    await page.click('#btnConsole');
    await page.waitForURL(u => !String(u).includes('/index'), { timeout: 30000 });
    check('signed in with a console code', !page.url().includes('/index'));
    // The fresh confirmation, on the VM only, for this new session (the newest): see confirm-loop.sh.
    console.log('  ' + execSync(VM + " 'sh /root/signed/signed-jobs-setup.sh confirm'").toString().trim().split('\n').join('\n  '));

    await page.goto(BASE + '/updates');
    await page.waitForLoadState('networkidle');
    for (const c of CARDS.filter(c => ONLY.includes(c.key))) {
        console.log('\n== ' + c.key + ' ==');
        const box = page.locator(c.box);
        // The procedure's row of "Update the server" (a <li> in a <section class="card">): its pictures.
        const card = box.locator('xpath=ancestor::li[1]');
        // The row appears when the packages have been read and the procedure applies.
        await page.waitForSelector(`button[data-on-click="${c.pre}"]`, { timeout: 300000 });
        await page.click(`button[data-on-click="${c.pre}"]`);
        await page.waitForFunction(sel => {
            const el = document.querySelector(sel);
            return el && !el.querySelector('.fa-spinner') && el.querySelector('table');
        }, c.box, { timeout: 600000 });
        await card.scrollIntoViewIfNeeded();
        await card.screenshot({ path: `${OUT}/${c.key}-1-plan.png` });
        const text = await box.innerText();
        fs.writeFileSync(`${OUT}/${c.key}-1-plan.txt`, text);
        const fp = (text.match(/fingerprint[^0-9a-f]*([0-9a-f]{16})/i) || [])[1];
        // The plan's table comes first; all the checks are closed below it (reperto 197).
        const planRows = await box.locator('table').first().locator('tbody tr').allInnerTexts().catch(() => []);
        console.log('  plan:\n    ' + planRows.map(r => r.replace(/\s+/g, ' ').trim()).join('\n    '));
        console.log('  ' + (text.split('\n').find(l => /worked out with/i.test(l)) || "(no \"worked out with\" line)"));
        check(c.key + ': the plan is in the card', planRows.length > 0);
        check(c.key + ': with its fingerprint (' + fp + ')', !!fp);
        const runButton = box.locator(`button[data-on-click="${c.run}"]`);
        check(c.key + ': the start button is there', await runButton.count() === 1);
        if (!fp || await runButton.count() !== 1) continue;

        // The request that starts the job: it must carry the fingerprint shown in the card.
        const sent = page.waitForRequest(r => r.url().includes('/api/updates') && (r.postData() || '').includes('"confirm"'));
        // The panel's window, not the browser's (reperto 197): the word goes to the server in the request.
        await runButton.click();
        await page.waitForSelector('#panelAskModal.show');
        await page.click('#panelAskGo');
        const body = JSON.parse((await sent).postData());
        check(c.key + ': the page sends the fingerprint it showed', body.signature === fp);
        await page.waitForFunction(sel => {
            const el = document.querySelector(sel);
            return el && (el.querySelector('.alert-success') || el.querySelector('.alert-danger'));
        }, c.box, { timeout: 1800000 });
        const outcome = await box.innerText();
        const log = await page.locator(c.log).textContent();
        fs.writeFileSync(`${OUT}/${c.key}-2-log.txt`, log);
        await card.scrollIntoViewIfNeeded();
        await card.screenshot({ path: `${OUT}/${c.key}-2-done.png` });
        console.log('  outcome: ' + outcome.replace(/\s+/g, ' ').trim());
        check(c.key + ': completed', /Done\./.test(outcome) && !/failed/i.test(outcome));
        check(c.key + ': the confirmation went with its word', body.confirm === c.word);
        check(c.key + ': the job ran the fingerprint shown', log.includes('exact plan (fingerprint ' + fp + ')'));
        check(c.key + ': nothing changed outside the plan', log.includes('ok  no change outside the plan') && !/NO  /.test(log));
        // planPoll reloads the plan list after a success: wait for it before the next card.
        await page.waitForTimeout(3000);
    }
    check('no JavaScript error on the page (' + errors.length + ')', errors.length === 0);
    errors.slice(0, 5).forEach(e => console.log('    ' + e.slice(0, 200)));
    await browser.close();
    console.log(failed === 0 ? '\nALL OK' : '\n' + failed + ' CHECKS FAILED');
    process.exit(failed ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
