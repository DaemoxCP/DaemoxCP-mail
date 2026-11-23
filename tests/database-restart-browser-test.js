// MySQL stopped for a while on the TEST VM, with the panel open in a browser (finding 209). On the real server, on
// 09/11/2026, MySQL restarted inside "Update everything": for 9 seconds every request got "401 not authorized", the
// Updates card lost the job in progress and filled with errors, and a page opened in that moment led to the sign-in
// page with a session that was still good. Now:
//  - a read asked while the database is down waits, with the strip that says so, and gets its answer when it is back;
//  - a page opened in that moment says "the database is restarting" and reloads by itself into the page, not the
//    sign-in;
//  - afterwards the session is the same, signed in, nothing ended; the panel's log has no "session ended".
// It stops MySQL on the VM for about 25 seconds (mail on the VM waits in that time). Through an SSH tunnel to the
// VM's port 2096 (self-signed certificate: errors ignored, for this test machine only). Sign-in with a console code.
//
// Usage:
//   ssh -i ~/.ssh/freebsd_test_vm -N -L 127.0.0.1:2096:127.0.0.1:2096 root@192.168.1.20 &
//   NODE_PATH=<playwright node_modules> node tests/database-restart-browser-test.js [screenshot-folder]
const { chromium } = require('playwright');
const { execSync } = require('child_process');
// The panel's name (HOST=panel.rehearsal.test on the test VM): once the panel has a name it refuses any other Host
// (HostCheck), so the browser resolves that name to the tunnel. Without HOST, 127.0.0.1 as before.
const HOST = process.env.HOST || '127.0.0.1';
const BASE = 'https://' + HOST + ':2096';
const OUT = process.argv[2];
const VM = 'ssh -i ' + process.env.HOME + '/.ssh/freebsd_test_vm -o IdentitiesOnly=yes -o ConnectTimeout=10 root@192.168.1.20';
const vm = cmd => { try { return execSync(VM + " '" + cmd + "'").toString().trim(); } catch (e) { return String(e.stdout || '').trim(); } };
let failed = 0;
const check = (what, ok) => { console.log((ok ? '  OK     ' : '  FAILED ') + what); if (!ok) failed++; };
const sleep = ms => new Promise(r => setTimeout(r, ms));

(async () => {
    const browser = await chromium.launch({ headless: true, channel: 'chrome', args: HOST === '127.0.0.1' ? [] : ['--host-resolver-rules=MAP ' + HOST + ' 127.0.0.1'] });
    const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1300, height: 1000 }, locale: 'en-US' });
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', e => errors.push(String(e)));
    let mysqlStopped = false;
    try {
        const code = vm('cd /home/panel && /usr/local/openjdk25/bin/java -jar daemoxcp-mail.jar --lang en --access-code 2>/dev/null').match(/([0-9]{4} [0-9]{4})/)[1];
        await page.goto(BASE + '/index');
        await page.click('#linkConsole');
        await page.fill('#consoleCode', code);
        await page.click('#btnConsole');
        await page.waitForURL(u => !String(u).includes('/index'), { timeout: 30000 });
        check('signed in with a console code', !page.url().includes('/index'));
        await page.goto(BASE + '/updates');
        await page.waitForSelector('#uc-all .uc-head', { timeout: 120000 });
        await page.waitForFunction(() => !/Reading/.test(document.getElementById('ucList').innerText), null, { timeout: 180000 });
        const logLines = Number(vm('wc -l < /var/db/daemoxcp-mail/panel-web.log'));

        console.log('\n== MySQL stopped ==');
        vm('service mysql-server stop >/dev/null 2>&1');
        mysqlStopped = true;
        const t0 = Date.now();
        console.log('    ' + vm('service mysql-server status 2>&1 | head -1'));
        // A read of the card while the database is down: "Reread" asks again for every row.
        await page.click('button[data-on-click="ucLoad(true)"]').catch(() => page.evaluate(() => ucLoad(true)));
        await page.waitForSelector('#panelDbWait', { timeout: 20000 }).catch(() => {});
        const strip = await page.$('#panelDbWait') ? await page.innerText('#panelDbWait') : '';
        console.log('    strip: ' + strip);
        check('the read waits, with the strip that says it', /The database is restarting: the panel waits and tries again/.test(strip));
        if (OUT) await page.screenshot({ path: OUT + '/database-1-waiting.png' });
        // A page opened in that moment.
        const other = await context.newPage();
        const res = await other.goto(BASE + '/diagnostics');
        const waitPage = await other.innerText('body');
        console.log('    a page opened now: ' + res.status() + ' ' + other.url() + ' — ' + waitPage.replace(/\s+/g, ' ').slice(0, 160));
        check('a page opened now: 503 "the database is restarting", not the sign-in', res.status() === 503
            && /The database is restarting/.test(waitPage) && !other.url().includes('/index') && (await other.title()) === 'The database is restarting');
        if (OUT) await other.screenshot({ path: OUT + '/database-2-page.png' });
        await sleep(Math.max(0, 20000 - (Date.now() - t0)));

        console.log('\n== MySQL started again ==');
        vm('service mysql-server start >/dev/null 2>&1');
        mysqlStopped = false;
        console.log('    ' + vm('service mysql-server status 2>&1 | head -1') + ' after ' + Math.round((Date.now() - t0) / 1000) + ' s');
        await page.waitForSelector('#panelDbWait', { state: 'detached', timeout: 90000 }).catch(() => {});
        await page.waitForFunction(() => !/Reading/.test(document.getElementById('ucList').innerText), null, { timeout: 120000 }).catch(() => {});
        const card = await page.innerText('#update-center');
        check('when it is back: the strip goes, the card is read, no error in it, still signed in', await page.$('#panelDbWait') === null
            && page.url().includes('/updates') && !/not answering|Unauthorized|not authorized/i.test(card) && /Update everything/.test(card));
        await other.waitForURL(u => String(u).includes('/diagnostics'), { timeout: 60000 }).catch(() => {});
        await other.waitForSelector('#main, main', { timeout: 60000 }).catch(() => {});
        await sleep(6000);
        const otherTitle = await other.title();
        check('the page opened during the stop reloaded by itself into Diagnostics, signed in (' + otherTitle + ')',
            other.url().includes('/diagnostics') && !/restarting/i.test(otherTitle) && !(await other.innerText('body')).includes('The database is restarting'));
        if (OUT) await page.screenshot({ path: OUT + '/database-3-after.png' });
        const added = vm('tail -n +' + (logLines + 1) + ' /var/db/daemoxcp-mail/panel-web.log | grep -cE "Session check failed"');
        console.log('    session checks that failed while it was down: ' + added);
        const ended = await page.evaluate(async () => (await fetch('/api/updates', { method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'package_turn' }) })).status);
        check('the session is the same, and it still answers (' + ended + ')', ended === 200);
        check('no page error' + (errors.length ? ': ' + errors.join(' | ') : ''), errors.length === 0);
    } catch (e) { console.error(e); failed++; }
    finally {
        if (mysqlStopped) vm('service mysql-server start >/dev/null 2>&1');
        console.log('    services: ' + vm('for s in daemoxcp_mail mysql-server dovecot postfix; do service $s status >/dev/null 2>&1 && printf "%s up, " $s || printf "%s DOWN, " $s; done'));
        await browser.close();
    }
    console.log('\n' + (failed === 0 ? 'ALL OK' : failed + ' CHECKS FAILED'));
    process.exit(failed ? 1 : 0);
})();
