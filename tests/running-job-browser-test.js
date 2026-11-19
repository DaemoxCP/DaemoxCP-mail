// A package job in progress, on the real panel of the TEST VM (reperto 206). On the real server two "Update the packages"
// pressed during a search were refused, rightly, and the page did not say what was running; each refusal also left a
// log with its start and no end.
//
//  1. "Check for updates" started in one tab; in a second tab the Updates page says what is running and since when,
//     shows what it is doing, and the buttons of the steps and "Check for updates" wait.
//  2. A job asked meanwhile (the update of the other packages, with a signature of the right shape) is refused, and
//     leaves no log in /var/db/daemoxcp-mail/jobs.
//  3. When the search ends: the line goes, the buttons come back, the card reads itself again.
// The search only downloads the lists (pkg update, pkg audit -F, freebsd-update fetch): nothing is installed.
//
// Through an SSH tunnel to the VM's port 2096 (self-signed certificate: errors ignored, for this test machine only).
// Sign-in with a console code; the session's fresh confirmation with the "confirm" mode of tests/signed-jobs-setup.sh.
//
// Usage:
//   ssh -i ~/.ssh/freebsd_test_vm -N -L 127.0.0.1:2096:127.0.0.1:2096 root@192.168.1.20 &
//   NODE_PATH=<playwright node_modules> node tests/running-job-browser-test.js [screenshot-folder]
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
const vm = cmd => execSync(VM + " '" + cmd + "'").toString().trim();
const journals = () => vm('ls /var/db/daemoxcp-mail/jobs').split('\n').filter(Boolean);

(async () => {
    const browser = await chromium.launch({ headless: true, channel: 'chrome', args: HOST === '127.0.0.1' ? [] : ['--host-resolver-rules=MAP ' + HOST + ' 127.0.0.1'] });
    const errors = [], dialogs = [];
    try {
        if (vm('pgrep -x shutdown || true') !== '') { console.error('A restart is scheduled on the VM: not starting.'); process.exit(2); }
        const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1400, height: 1000 }, locale: 'en-US' });
        const one = await context.newPage(), two = await context.newPage();
        for (const p of [one, two]) {
            p.on('pageerror', e => errors.push(String(e)));
            p.on('dialog', async d => { dialogs.push(d.message()); await d.dismiss(); });
        }
        const code = vm('cd /home/panel && /usr/local/openjdk25/bin/java -jar daemoxcp-mail.jar --lang en --access-code 2>/dev/null')
            .match(/([0-9]{4} [0-9]{4})/)[1];
        await one.goto(BASE + '/index');
        await one.click('#linkConsole');
        await one.fill('#consoleCode', code);
        await one.click('#btnConsole');
        await one.waitForURL(u => !String(u).includes('/index'), { timeout: 30000 });
        console.log('    ' + vm('sh /root/signed/signed-jobs-setup.sh confirm'));
        await one.goto(BASE + '/updates');
        await one.waitForFunction(() => document.getElementById('ucState').textContent === '', null, { timeout: 60000 });

        console.log('\n== 1. A search in one tab, the line in the other ==');
        await one.click('#ucSearchButton');
        await two.goto(BASE + '/updates');
        await two.waitForSelector('#ucRunning:not([hidden])', { timeout: 30000 });
        const line = await two.innerText('#ucRunning');
        console.log('    ' + line.replace(/\s+/g, ' ').slice(0, 200));
        check('the other tab says what is running and since when', /In progress: check for updates, (just started|running for)/.test(line));
        await two.waitForFunction(() => /\S/.test(document.getElementById('ucRunningLog').textContent), null, { timeout: 15000 }).catch(() => {});
        check('  with what it is doing', /pkg update|catalog|repository/i.test(await two.textContent('#ucRunningLog')));
        check('  and the steps wait, saying why', await two.$$eval('#ucList .uc-head button, #ucSearchButton',
            b => b.length > 0 && b.every(x => x.disabled && x.title === 'After the job in progress')));
        if (OUT) await two.locator('#update-center').screenshot({ path: OUT + '/running-job-vm.png' });

        console.log('\n== 2. A job asked meanwhile: refused, and no log left ==');
        const before = journals();
        const r = await two.evaluate(() => fetch('/api/updates', { method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'updates_apply', confirm: 'UPDATE', signature: '0123456789abcdef',
                csrf_token: document.getElementById('csrf_token').value }) }).then(x => x.json()));
        console.log('    ' + String(r.error || '').slice(0, 160));
        check('refused because a package job is running', r.success === false && /already running/i.test(r.error || ''));
        const after = journals();
        check('  no new log in the jobs folder (' + before.length + ' before, ' + after.length + ' after)', after.length === before.length
            && !after.some(f => !before.includes(f) && /update__upd-/.test(f)));

        console.log('\n== 3. When the search ends ==');
        await two.waitForSelector('#ucRunning', { state: 'hidden', timeout: 180000 });
        await two.waitForFunction(() => !document.getElementById('ucSearchButton').disabled, null, { timeout: 10000 }).catch(() => {});
        check('the line goes, the buttons are back', await two.$$eval('#ucList .uc-head button, #ucSearchButton', b => b.every(x => !x.disabled)));
        check('  and the search\'s own log ended well', /=== end: completed/.test(vm('tail -1 /var/db/daemoxcp-mail/jobs/$(ls -t /var/db/daemoxcp-mail/jobs | grep search__ | head -1)')));
        check('no browser dialog, no page error' + (errors.length + dialogs.length ? ': ' + errors.concat(dialogs).join(' | ') : ''),
            !errors.length && !dialogs.length);
    } catch (e) {
        console.error(e);
        failed++;
    } finally {
        await browser.close();
        vm('sh /root/signed/signed-jobs-setup.sh confirm-stop || true');
    }
    console.log('\n' + (failed === 0 ? 'ALL OK' : failed + ' CHECKS FAILED'));
    process.exit(failed ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
