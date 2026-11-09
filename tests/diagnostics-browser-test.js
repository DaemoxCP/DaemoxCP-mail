// Diagnostics, "Check everything", on the real panel of the TEST VM (reperto 199): one button runs every read-only
// check, the list puts first what needs a look, each item has its state in words and at most one button; what is fine
// is closed below. Read only: no item's button is pressed here except "Open the details", which only reads too.
//
// Through an SSH tunnel to the VM's port 2096 (self-signed certificate: errors ignored, for this test machine only).
// Sign-in with a console code.
//
// Usage:
//   ssh -i ~/.ssh/freebsd_test_vm -N -L 127.0.0.1:2096:127.0.0.1:2096 root@192.168.1.20 &
//   NODE_PATH=<playwright node_modules> node tests/diagnostics-browser-test.js [screenshot-folder]
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
    page.on('pageerror', e => errors.push(String(e)));
    page.on('dialog', async d => { dialogs.push(d.message()); await d.dismiss(); });
    const code = execSync(VM + " 'cd /home/panel && /usr/local/openjdk25/bin/java -jar freebsd-mail-panel-1.0.jar --access-code 2>/dev/null'")
        .toString().match(/([0-9]{4} [0-9]{4})/)[1];
    await page.goto(BASE + '/index');
    await page.click('#linkConsole');
    await page.fill('#consoleCode', code);
    await page.click('#btnConsole');
    await page.waitForURL(u => !String(u).includes('/index'), { timeout: 30000 });
    check('signed in with a console code', !page.url().includes('/index'));

    await page.goto(BASE + '/diagnostics');
    await page.click('#diagAllGo');
    const t0 = Date.now();
    await page.waitForFunction(() => /things? to look at|checks are fine/.test(document.getElementById('diagAllState').textContent), null, { timeout: 600000 });
    console.log('  done in ' + Math.round((Date.now() - t0) / 1000) + ' s: ' + await page.textContent('#diagAllState'));
    const items = await page.$$eval('#diagAllList > li', lis => lis.map(li => ({ key: li.dataset.diag, level: li.dataset.level,
        text: li.innerText.replace(/\s+/g, ' '), buttons: li.querySelectorAll('button, a.btn').length })));
    items.forEach(x => console.log('    ' + x.level + ' ' + x.key + ': ' + x.text.slice(0, 160)));
    const fine = await page.$$eval('#diagAllOk > li', lis => lis.map(li => li.dataset.diag + ': ' + li.innerText.replace(/\s+/g, ' ').slice(0, 100)));
    fine.forEach(x => console.log('    ok ' + x));
    check('ten checks, every one with a verdict', items.length + fine.length === 10);
    const order = { problem: 0, warn: 1, todo: 2, info: 3 };
    check('the most important first', items.every((x, i) => i === 0 || order[items[i - 1].level] <= order[x.level]));
    check('every item: its state in words, at most one button', items.every(x => /\(([a-z ]+)\)/.test(x.text) && x.buttons <= 1));
    if (OUT) await page.locator('#diag-all').screenshot({ path: OUT + '/diagnostics-check-all-vm.png' });
    const open = items.find(x => x.buttons === 1 && /Open the details/.test(x.text));
    if (open) {
        await page.click('#diagAllList li[data-diag="' + open.key + '"] button');
        await page.waitForTimeout(3000);
        check('"Open the details" (' + open.key + '): its card is where the page is', await page.evaluate(k => {
            const id = { svc: 'diag-svc', watch: 'diag-watch', libs: 'diag-libs', compat: 'diag-compat', java: 'diag-java', web: 'diag-web',
                defaults: 'diag-defaults', env: 'diag-env', os: 'diag-os' }[k];
            const r = document.getElementById(id).getBoundingClientRect();
            return r.top < window.innerHeight && r.bottom > 0;
        }, open.key));
    }
    check('no browser dialog, no page error' + (errors.length + dialogs.length ? ': ' + errors.concat(dialogs).join(' | ') : ''), !errors.length && !dialogs.length);
    await browser.close();
    console.log('\n' + (failed === 0 ? 'ALL OK' : failed + ' CHECKS FAILED'));
    process.exit(failed ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
