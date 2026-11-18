// "Update everything" on the TEST VM panel, as a person would do it (reperto 207): sign in, Updates, the one row at the
// top with the steps in order and one button; "Cancel" leaves the button where it is; then the confirmation with every
// step numbered, the one job to its end, and, with the panel's Java last, the page that reloads by itself on the sign-in
// page when the panel comes back (a restart ends every session, reperto 184). Then, signed in again: nothing left to
// update, the job's log on disk ends with its end (Diagnostics lists it as completed), and on the VM:
//  - every service up, nothing left to update, the protected packages protected again;
//  - postfix's inet_protocols written in main.cf, and postfix listening on the same addresses as before;
//  - with the Java: the Java report says it succeeded, the service sees the panel again (its pidfile is the root
//    part), the web part runs as daemoxcp_mail and holds the port, Java is the new one and protected again.
// It takes the place of java-update-browser-test.js: the Java row and its "Prepare" are gone, the Java is the last step.
// With the Java, the page is reloaded while its script works (reperto 210): it must say the Java is being updated, with
// the script's log, offer nothing, and still reload by itself when the panel comes back.
//
// It needs updates waiting on the VM, and it changes it (packages, a boot environment, the panel's restart). The way
// back is the boot environment the job makes before the first step (packages-before-...-update-everything): activate it
// and restart the VM to run the test again. Through an SSH tunnel to the VM's port 2096 (self-signed certificate:
// errors ignored, for this test machine only). Sign-in with a console code; the fresh confirmation with the "confirm"
// mode of tests/signed-jobs-setup.sh; both helpers copied to /root/signed on the VM: tests/signed-jobs-setup.sh and
// tests/java-update-state.sh. /root is inside the boot environment: after going back to the way back, copy them again.
//
// Usage:
//   ssh -i ~/.ssh/freebsd_test_vm -N -L 127.0.0.1:2096:127.0.0.1:2096 root@192.168.1.20 &
//   NODE_PATH=<playwright node_modules> node tests/everything-browser-test.js [screenshot-folder]
const { chromium } = require('playwright');
const { execSync } = require('child_process');
// The panel's name (HOST=panel.rehearsal.test on the test VM): once the panel has a name it refuses any other Host
// (HostCheck), so the browser resolves that name to the tunnel. Without HOST, 127.0.0.1 as before.
const HOST = process.env.HOST || '127.0.0.1';
const BASE = 'https://' + HOST + ':2096';
const OUT = process.argv[2];
const VM = 'ssh -i ' + process.env.HOME + '/.ssh/freebsd_test_vm -o IdentitiesOnly=yes -o ConnectTimeout=10 root@192.168.1.20';
// A command on the VM; its output even when it ends with a code other than 0 (grep -c that counts 0, for one).
const vm = cmd => { try { return execSync(VM + " '" + cmd + "'").toString().trim(); } catch (e) { return String(e.stdout || '').trim(); } };
let failed = 0;
const check = (what, ok) => { console.log((ok ? '  OK     ' : '  FAILED ') + what); if (!ok) failed++; };
const sleep = ms => new Promise(r => setTimeout(r, ms));
const POSTFIX_PORTS = 'sockstat -l -P tcp | awk "\\$2==\\"master\\" {print \\$5, \\$6}" | sort -u | tr "\\n" " "';

async function signIn(page) {
    const code = vm('cd /home/panel && /usr/local/openjdk25/bin/java -jar daemoxcp-mail.jar --access-code 2>/dev/null').match(/([0-9]{4} [0-9]{4})/)[1];
    await page.goto(BASE + '/index');
    await page.click('#linkConsole');
    await page.fill('#consoleCode', code);
    await page.click('#btnConsole');
    await page.waitForURL(u => !String(u).includes('/index'), { timeout: 30000 });
}

async function topRow(page) {
    await page.goto(BASE + '/updates');
    await page.waitForSelector('#uc-all .uc-head', { timeout: 120000 });
    await page.waitForFunction(() => !/Reading/.test(document.querySelector('#uc-all .uc-head').innerText), null, { timeout: 300000 });
    return page.innerText('#uc-all .uc-head');
}

(async () => {
    const browser = await chromium.launch({ headless: true, channel: 'chrome', args: HOST === '127.0.0.1' ? [] : ['--host-resolver-rules=MAP ' + HOST + ' 127.0.0.1'] });
    const page = await (await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1300, height: 1000 }, locale: 'en-US' })).newPage();
    const errors = [];
    page.on('pageerror', e => errors.push(String(e)));
    page.on('dialog', d => { errors.push('browser dialog: ' + d.message()); d.dismiss(); });
    try {
        await signIn(page);
        check('signed in with a console code', !page.url().includes('/index'));
        console.log('  ' + vm('sh /root/signed/signed-jobs-setup.sh confirm'));
        const portsBefore = vm(POSTFIX_PORTS);
        const lockedBefore = vm('pkg lock -l 2>/dev/null | tail -n +2 | wc -l').trim();

        console.log('\n== The row at the top: the steps in order, one button ==');
        await topRow(page);
        await page.waitForSelector('#uc-all .uc-head button[data-on-click="ucEverything()"]', { timeout: 60000 });
        const steps = await page.$$eval('#uc-all .uc-head li', l => l.map(x => x.textContent.trim()));
        console.log('    ' + steps.map((s, i) => (i + 1) + '. ' + s).join('\n    '));
        check('the steps listed, one button', steps.length > 0 && await page.$$eval('#uc-all .uc-head button', b => b.length === 1));
        const java = steps.some(s => /The panel's Java/.test(s));
        check('the panel\'s Java, if there, is the last step', !java || /The panel's Java/.test(steps[steps.length - 1]));
        const packagesRow = await page.innerText('#uc-packages .uc-head');
        check('the Packages row does not count the same updates again, nor says "all up to date"', /Their updates are steps of «Update everything», above/.test(packagesRow)
            && !/packages to update, all together in one plan/.test(packagesRow) && !/All up to date/.test(packagesRow));
        check('no row of its own for Roundcube or the Java, no button on the FreeBSD row', await page.locator('#uc-roundcube').isHidden()
            && await page.locator('#uc-java').isHidden() && await page.$$eval('#uc-os .uc-head button[data-on-click]', b => b.every(x => /panelRebootOpen|ucRelease/.test(x.dataset.onClick))));
        if (OUT) await page.locator('#update-center').screenshot({ path: OUT + '/everything-1-before.png' });

        console.log('\n== Cancel leaves the button where it is ==');
        const jobsBefore = vm('ls /var/db/daemoxcp-mail/jobs | grep -c update_everything');
        await page.click('#uc-all .uc-head button[data-on-click="ucEverything()"]');
        await page.waitForSelector('#panelAskModal.show', { timeout: 900000 });
        await page.click('#panelAskModal .modal-footer [data-bs-dismiss="modal"]');
        await page.waitForSelector('#panelAskModal', { state: 'hidden' });
        check('after Cancel: the same button, enabled, and nothing started', await page.$$eval('#uc-all .uc-head button[data-on-click="ucEverything()"]',
            b => b.length === 1 && !b[0].disabled) && vm('ls /var/db/daemoxcp-mail/jobs | grep -c update_everything') === jobsBefore);

        console.log('\n== The confirmation, the one job ==');
        await page.click('#uc-all .uc-head button[data-on-click="ucEverything()"]');
        await page.waitForSelector('#panelAskModal.show', { timeout: 900000 });
        const ask = await page.innerText('#panelAskModal .modal-content');
        console.log('    ' + ask.replace(/\n+/g, '\n    '));
        check('every step numbered, in order, the way back said', /1\. /.test(ask) && /A way back is made before the first/.test(ask));
        if (java) check('  with the Java: the page reloads on the sign-in page, sign in again', /reloads by itself on the sign-in page: sign in again/.test(ask));
        if (OUT) await page.locator('#panelAskModal .modal-content').screenshot({ path: OUT + '/everything-2-confirm.png' });
        const sent = page.waitForRequest(r => r.url().includes('/api/updates') && (r.postData() || '').includes('"update_everything"'));
        const t0 = Date.now();
        await page.evaluate(() => { window.__sameLoad = true; });
        await page.click('#panelAskGo');
        const body = JSON.parse((await sent).postData());
        check('the request: the steps with the fingerprints read, and the changes shown', Array.isArray(body.steps) && body.steps.length > 0
            && body.steps.every(s => s.kind === 'os' ? s.signature === '' : /^([0-9a-f]{16})?$/.test(s.signature))
            && Array.isArray(body.approved) && body.approved.length > 0 && body.confirm === 'UPDATE');

        let outcome = '';
        for (let i = 0; i < 360 && !/steps? done|Stopped at/.test(outcome); i++) {
            await sleep(5000);
            outcome = await page.evaluate(() => (document.getElementById('all-run') || {}).innerText || '').catch(() => '');
        }
        console.log('    after ' + Math.round((Date.now() - t0) / 1000) + ' s: ' + outcome.replace(/\s+/g, ' '));
        const log = vm('ls -t /var/db/daemoxcp-mail/jobs | grep update_everything | head -1');
        check('a new log on disk for the job', Number(vm('ls /var/db/daemoxcp-mail/jobs | grep -c update_everything')) === Number(jobsBefore) + 1);
        const last = vm('tail -1 /var/db/daemoxcp-mail/jobs/' + log);
        console.log('    ' + vm('grep -E "=== Step " /var/db/daemoxcp-mail/jobs/' + log + ' | cut -c22-110').replace(/\n/g, '\n    '));
        const confirmed = (ask.match(/^[0-9]+\. /gm) || []).length;
        check('every step of the confirmation done (' + confirmed + '), and the end is the last line of its log', /steps? done/.test(outcome)
            && /=== end: completed/.test(last) && confirmed > 0 && Number(vm('grep -c "=== Step " /var/db/daemoxcp-mail/jobs/' + log)) === confirmed);

        if (java) {
            // The Java script copies the JDK, stops the panel, updates it and starts it again (two or three minutes on the
            // VM, four on the real server). The owner reloaded the page meanwhile and saw "1 step to do: the Java" and a
            // warning about a job "that did not finish" (reperto 210): reloaded, the page must say what is happening.
            await page.reload();
            await page.waitForSelector('#ucRunning:not([hidden])', { timeout: 60000 }).catch(() => {});
            const during = await page.innerText('#ucRunning').catch(() => '');
            const allDuring = await page.innerText('#uc-all .uc-head').catch(() => '');
            console.log('    reloaded during the Java: ' + during.replace(/\s+/g, ' ').slice(0, 300));
            check('reloaded while the Java script works: "In progress: the update of the panel\'s Java", with what the script is doing',
                /In progress: the update of the panel's Java/.test(during) && /\[[1-7]\/7\]/.test(await page.textContent('#ucRunningLog').catch(() => '')));
            check('  and where it is, without opening the log ("Now: [n/7] ...")', /Now: \[[1-7]\/7\] /.test(await page.innerText('#ucRunningNow').catch(() => '')));
            check('  Update everything says it, offers nothing, and no warning about a job that did not finish',
                /The panel's Java is being updated now/.test(allDuring) && await page.$('#uc-all .uc-head button[data-on-click="ucEverything()"]') === null
                && !/did not finish|restart the panel/.test(await page.innerText('#update-center')));
            if (OUT) await page.locator('#update-center').screenshot({ path: OUT + '/everything-2b-java-running.png' });
            await page.evaluate(() => { window.__sameLoad = true; });
            const tj = Date.now();
            let state = '';
            for (let i = 0; i < 180 && state !== 'reloaded'; i++) {
                await sleep(5000);
                try { state = await page.evaluate(() => window.__sameLoad === true ? 'same' : (document.querySelector('#uc-all .uc-head') || location.pathname === '/index' ? 'reloaded' : 'loading')); }
                catch (e) { state = 'navigating'; }
            }
            console.log('    the page after the Java: ' + state + ' after ' + Math.round((Date.now() - tj) / 1000) + ' s, at ' + page.url());
            check('the page reloaded by itself when the panel came back, on the sign-in page', state === 'reloaded' && page.url().includes('/index'));
            await signIn(page);
            check('signed in again', !page.url().includes('/index'));
            await page.goto(BASE + '/diagnostics');
            await page.click('button[data-on-click="jvState()"]');
            await page.waitForFunction(() => { const p = document.getElementById('jv-log'); return p && p.textContent && !/^Reading/.test(p.textContent); }, null, { timeout: 60000 });
            const report = await page.locator('#jv-log').textContent();
            check('the Java report says it succeeded, with its way back, in UTC', /RESULT: SUCCEEDED/.test(report)
                && /\/var\/db\/daemoxcp-mail\/jdk\/[0-9]{8}-[0-9]{6}/.test(report) && / UTC ===/.test(report) && !/\{[A-Za-z_]+\}/.test(report));
            const state2 = vm('sh /root/signed/java-update-state.sh');
            console.log('    VM:\n      ' + state2.split('\n').slice(0, 9).join('\n      '));
            const pidfile = (state2.match(/^pidfile: ([0-9]+)/m) || [])[1];
            check('the service sees the panel again, its pidfile the root part', /^service: daemoxcp_mail is running as pid [0-9]+/m.test(state2)
                && !!pidfile && new RegExp('^\\s*' + pidfile + '\\s+[0-9]+\\s+root\\s+.*--web$', 'm').test(state2));
            check('the web part runs as daemoxcp_mail and holds the port', /port 2096: daemoxcp_mail java/.test(state2));
            check('Java is the new one, protected again', /openjdk25: ([^,]+), repo \1, locked: 1/.test(state2));
        }

        console.log('\n== Afterwards ==');
        const top = await topRow(page);
        console.log('    ' + top.replace(/\s+/g, ' '));
        if (OUT) await page.locator('#update-center').screenshot({ path: OUT + '/everything-3-after.png' });
        check('nothing left to update', /Nothing to update/.test(top) && vm('pkg version -vRL= 2>/dev/null | grep -c "needs updating"') === '0');
        await page.goto(BASE + '/diagnostics');
        await page.click('button[data-on-click="jrList()"]');
        await page.waitForSelector('#jr-list table', { timeout: 60000 });
        const rows = await page.$$eval('#jr-list tbody tr', trs => trs.map(tr => tr.innerText.replace(/\s+/g, ' ').trim()));
        check('Operation logs: Update everything, completed (not "without an end")', rows.some(r => /Update everything/.test(r) && /completed/i.test(r) && !/without/i.test(r)));
        const services = vm('for s in daemoxcp_mail dovecot postfix rspamd mysql-server nginx php_fpm redis clamav_clamd fail2ban; do service $s status >/dev/null 2>&1 && printf "%s up, " $s || printf "%s DOWN, " $s; done');
        console.log('    services: ' + services);
        check('every service up', !/DOWN/.test(services));
        check('the protected packages protected again (' + lockedBefore + ')', vm('pkg lock -l 2>/dev/null | tail -n +2 | wc -l').trim() === lockedBefore);
        check('postfix: inet_protocols written in main.cf, listening as before (' + portsBefore + ')',
            vm('postconf -nh inet_protocols') !== '' && vm(POSTFIX_PORTS) === portsBefore);
        check('no page error' + (errors.length ? ': ' + errors.join(' | ') : ''), errors.length === 0);
    } catch (e) { console.error(e); failed++; }
    finally { await browser.close(); vm('sh /root/signed/signed-jobs-setup.sh confirm-stop || true'); }
    console.log('\n' + (failed === 0 ? 'ALL OK' : failed + ' CHECKS FAILED'));
    process.exit(failed ? 1 : 0);
})();
