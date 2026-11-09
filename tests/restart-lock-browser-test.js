// A restart scheduled, on the real panel of the TEST VM (reperto 200): until it happens the panel changes nothing.
//
// The restart is a stand-in: a program called "shutdown" that only sleeps (compiled here with cc), started as root with
// the arguments the panel uses ("-r +7 ..."). The panel sees it as the real one (pgrep -x shutdown, its command line in
// ps), and nothing can restart the VM: the test never asks for reboot_now, and "Cancel the restart" ends the stand-in.
//
//  1. The strip on every page: the time (+7 minutes, read from ps) and that the panel only reads; the page content
//     locked. A button of the page does nothing and says why.
//  2. The server refuses every change with 409, before any confirmation: a route the web part serves itself (it asks
//     the root), a route the root serves, a route that asks for a recent confirmation (no passkey request first).
//  3. Reads still work: a GET, and a POST action that only reads.
//  4. "Cancel the restart" from the strip: the stand-in is gone, the strip goes, and the same change is no longer refused.
//
// Through an SSH tunnel to the VM's port 2096 (self-signed certificate: errors ignored, for this test machine only).
// Sign-in with a console code; before cancelling, the session's fresh confirmation with the "confirm" mode of
// tests/signed-jobs-setup.sh (copied to /root/signed on the VM). The stand-in is ended by its exact PID in any case.
//
// Usage:
//   ssh -i ~/.ssh/freebsd_test_vm -N -L 127.0.0.1:2096:127.0.0.1:2096 root@192.168.1.20 &
//   NODE_PATH=<playwright node_modules> node tests/restart-lock-browser-test.js [screenshot-folder]
const { chromium } = require('playwright');
const { execSync } = require('child_process');
const BASE = 'https://127.0.0.1:2096';
const OUT = process.argv[2];
const VM = 'ssh -i ' + process.env.HOME + '/.ssh/freebsd_test_vm -o IdentitiesOnly=yes -o ConnectTimeout=10 root@192.168.1.20';
const DIR = '/var/tmp/restart-lock-test';
let failed = 0;
const check = (what, ok) => { console.log((ok ? '  OK     ' : '  FAILED ') + what); if (!ok) failed++; };
const vm = cmd => execSync(VM + " '" + cmd + "'").toString().trim();

// The PID of the stand-in, only if the shutdown process running is ours (its path is DIR).
function standIn() {
    const pid = vm('pgrep -x shutdown || true');
    if (!/^[0-9]+$/.test(pid)) return null;
    return vm('ps -o command= -p ' + pid).startsWith(DIR + '/shutdown ') ? pid : 'other';
}

(async () => {
    if (standIn() !== null) { console.error('A shutdown process is already running on the VM: not starting.'); process.exit(2); }
    vm('mkdir -p ' + DIR + ' && cd ' + DIR + ' && printf "#include <unistd.h>\\nint main(void){sleep(1800);return 0;}\\n" > fake.c'
        + ' && cc -o shutdown fake.c && daemon -f ' + DIR + '/shutdown -r +7 restart-lock-test');
    const browser = await chromium.launch({ headless: true, channel: 'chrome' });
    try {
        const pid = standIn();
        check('the stand-in runs as "shutdown -r +7" (pid ' + pid + ')', /^[0-9]+$/.test(pid || ''));
        const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1400, height: 1000 }, locale: 'en-US' });
        const page = await context.newPage();
        const errors = [], dialogs = [];
        page.on('pageerror', e => errors.push(String(e)));
        page.on('dialog', async d => { dialogs.push(d.message()); await d.dismiss(); });
        const code = vm('cd /home/panel && /usr/local/openjdk25/bin/java -jar freebsd-mail-panel-1.0.jar --access-code 2>/dev/null')
            .match(/([0-9]{4} [0-9]{4})/)[1];
        await page.goto(BASE + '/index');
        await page.click('#linkConsole');
        await page.fill('#consoleCode', code);
        await page.click('#btnConsole');
        await page.waitForURL(u => !String(u).includes('/index'), { timeout: 30000 });
        check('signed in with a console code', !page.url().includes('/index'));

        console.log('\n== 1. The strip and the page ==');
        await page.goto(BASE + '/domains');
        await page.waitForFunction(() => document.body.classList.contains('panel-restart-locked'), null, { timeout: 30000 });
        const strip = await page.innerText('#panelRebootBanner');
        console.log('    ' + strip.replace(/\s+/g, ' '));
        check('the time (+7 minutes, from ps) and "only reads"', /restarts at \d\d:\d\d/.test(strip) && /only reads/.test(strip));
        if (OUT) await page.screenshot({ path: OUT + '/restart-lock-vm.png' });
        const button = page.locator('#main button[data-on-click]:not([data-bs-toggle])').first();
        await button.click();
        await page.waitForSelector('#panelNotices .alert-warning', { timeout: 5000 }).catch(() => {});
        check('a button of the page does nothing, and says why', /Not now: a server restart is scheduled/.test(await page.innerText('body')));

        console.log('\n== 2. The server refuses every change ==');
        const post = (url, body) => page.evaluate(([u, b]) => fetch(u, { method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(b) }).then(async r => ({ status: r.status, header: r.headers.get('X-Panel-Restart'), body: await r.json().catch(() => ({})) })), [url, body]);
        const web = await post('/api/domains', {});
        check('a route of the web part (it asks the root): 409 (' + web.status + ')', web.status === 409 && web.header === 'scheduled'
            && web.body.restart_scheduled === true && /restart is scheduled/.test(web.body.error || ''));
        const root = await post('/api/aliases', {});
        check('a route of the root: 409 (' + root.status + ')', root.status === 409 && root.header === 'scheduled');
        const confirmed = await post('/api/pop3', {});
        check('a route that asks for a recent confirmation: 409, not the passkey request first (' + confirmed.status + ')',
            confirmed.status === 409 && !confirmed.body.needs_reauth);
        check('  the time travels with the refusal', web.body.restart_at > Date.now());

        console.log('\n== 3. Reads still work ==');
        const get = await page.evaluate(() => fetch('/api/domains').then(r => r.status));
        const read = await post('/api/updates', { action: 'os_status', csrf_token: await page.inputValue('#csrf_token') });
        check('a GET (' + get + ') and a POST that only reads (' + read.status + ')', get === 200 && read.status === 200 && read.body.success === true);

        console.log('\n== 4. Cancel the restart ==');
        // Cancelling is a system action: it asks for a recent confirmation like the others. Given here, after section 2
        // (which shows that a refused change does not ask for it first), with the "confirm" mode of signed-jobs-setup.sh.
        console.log('    ' + vm('sh /root/signed/signed-jobs-setup.sh confirm'));
        await page.click('#panelRebootBanner button[data-on-click="panelRebootCancel()"]');
        await page.waitForFunction(() => !document.body.classList.contains('panel-restart-locked'), null, { timeout: 30000 });
        check('the stand-in is gone', standIn() === null);
        const again = await post('/api/domains', {});
        check('the same change is no longer refused (' + again.status + ')', again.status !== 409 && again.header === null);
        check('no browser dialog, no page error' + (errors.length + dialogs.length ? ': ' + errors.concat(dialogs).join(' | ') : ''),
            !errors.length && !dialogs.length);
    } finally {
        await browser.close();
        vm('sh /root/signed/signed-jobs-setup.sh confirm-stop || true');
        const left = standIn();
        if (left && left !== 'other') vm('kill ' + left);
        vm('rm -f ' + DIR + '/shutdown ' + DIR + '/fake.c && rmdir ' + DIR + ' 2>/dev/null || true');
    }
    console.log('\n' + (failed === 0 ? 'ALL OK' : failed + ' CHECKS FAILED'));
    process.exit(failed ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
