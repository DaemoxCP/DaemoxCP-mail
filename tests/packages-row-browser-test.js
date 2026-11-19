// The packages on the Updates page of the real panel of the TEST VM (reperto 202): ONE row in "Update the server", with
// the list one by one closed under it, and no separate Packages card. Only reads: no update, no lock, no unlock.
//
//  1. The row says, in words, what there is to do for the packages (or that all is up to date), with at most one
//     button, the step after; no separate row for the mail server packages, no separate card.
//  2. The list under the row is closed; opened, it shows the packages that need attention or says nothing does, and
//     "Show all" lists every package of the list (the mail server ones, the vulnerable ones) with version and lock in
//     words, without any update button.
//  3. At 375 px: no horizontal scrolling with the list open, and every visible button of the card is 44 px.
//
// Through an SSH tunnel to the VM's port 2096 (self-signed certificate: errors ignored, for this test machine only).
// Sign-in with a console code.
//
// Usage:
//   ssh -i ~/.ssh/freebsd_test_vm -N -L 127.0.0.1:2096:127.0.0.1:2096 root@192.168.1.20 &
//   NODE_PATH=<playwright node_modules> node tests/packages-row-browser-test.js [screenshot-folder]
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

async function signIn(page) {
    const code = vm('cd /home/panel && /usr/local/openjdk25/bin/java -jar daemoxcp-mail.jar --lang en --access-code 2>/dev/null')
        .match(/([0-9]{4} [0-9]{4})/)[1];
    await page.goto(BASE + '/index');
    await page.click('#linkConsole');
    await page.fill('#consoleCode', code);
    await page.click('#btnConsole');
    await page.waitForURL(u => !String(u).includes('/index'), { timeout: 30000 });
}

// The row has its data: not "Reading..." any more.
const rowReady = page => page.waitForFunction(() => {
    const h = document.querySelector('#uc-packages .uc-head');
    return h && h.innerText.trim() !== '' && !h.innerText.includes(t('uc.reading'));
}, null, { timeout: 60000 });

(async () => {
    const browser = await chromium.launch({ headless: true, channel: 'chrome', args: HOST === '127.0.0.1' ? [] : ['--host-resolver-rules=MAP ' + HOST + ' 127.0.0.1'] });
    const errors = [], dialogs = [];
    const watch = page => {
        page.on('pageerror', e => errors.push(String(e)));
        page.on('dialog', async d => { dialogs.push(d.message()); await d.dismiss(); });
    };
    const requests = [];
    try {
        const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1400, height: 1000 }, locale: 'en-US' });
        const page = await context.newPage();
        watch(page);
        page.on('request', r => { if (r.method() === 'POST' && r.url().includes('/api/')) requests.push(r.postData() || ''); });
        await signIn(page);
        check('signed in with a console code', !page.url().includes('/index'));

        console.log('\n== 1. The row ==');
        await page.goto(BASE + '/updates');
        await rowReady(page);
        const row = (await page.innerText('#uc-packages .uc-head')).replace(/\s+/g, ' ');
        console.log('    ' + row);
        check('no separate Packages card, no separate row for the mail server packages',
            await page.$('#packages') === null && await page.$('#uc-stack') === null);
        check('the row says what there is to do, in words', /All up to date|to update|has an update|have an update|not locked/.test(row));
        check('  and the state in words, not only by colour', /\((up to date|to do|error|information)\)/.test(row));
        const buttons = await page.$$eval('#uc-packages .uc-head button', b => b.map(x => x.textContent.trim()));
        check('at most one button, the step after' + (buttons.length ? ': ' + buttons.join(', ') : ''), buttons.length <= 1);
        if (OUT) await page.locator('#uc-packages').screenshot({ path: OUT + '/packages-row-vm.png' });

        console.log('\n== 2. The list under it ==');
        check('the list is under the row, closed', await page.$eval('#uc-packages #pk-list', d => !d.open));
        await page.click('#pk-list summary');
        await page.waitForFunction(() => !document.getElementById('pk-body').innerText.includes(t('pkgs.loading')), null, { timeout: 60000 });
        const body = await page.innerText('#pk-body');
        check('opened: what needs attention, or that nothing does', /updates? available|locked|nothing|need/i.test(body));
        await page.click('#pk-all');
        await page.waitForSelector('#pk-body table tbody tr');
        const rows = await page.$$eval('#pk-body tbody tr:not([id])', r => r.length);
        check('"Show all": every package of the list, the mail server ones and the vulnerable ones (' + rows + ')', rows > 20);
        check('  version and lock in words in every row', await page.$$eval('#pk-body tbody tr:not([id])',
            r => r.every(x => /locked|unlocked/i.test(x.innerText))));
        check('  no update button in the list (the row has the step)', await page.locator('#pk-body button', { hasText: /^Update/ }).count() === 0);
        if (OUT) await page.locator('#uc-packages').screenshot({ path: OUT + '/packages-list-vm.png' });
        check('nothing changed: no update, lock or unlock requested', !requests.some(b => /packages_lock|updates_apply|package_update/.test(b)));
        await context.close();

        console.log('\n== 3. At 375 px ==');
        const phone = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 375, height: 812 }, isMobile: true, hasTouch: true, locale: 'en-GB' });
        const small = await phone.newPage();
        watch(small);
        await signIn(small);
        await small.goto(BASE + '/updates');
        await rowReady(small);
        await small.click('#pk-list summary');
        await small.waitForFunction(() => !document.getElementById('pk-body').innerText.includes(t('pkgs.loading')), null, { timeout: 60000 });
        const lay = await small.evaluate(() => ({ scroll: document.documentElement.scrollWidth - window.innerWidth,
            tiny: [...document.querySelectorAll('#update-center button')].filter(b => b.offsetParent)
                .map(b => Math.round(Math.min(b.getBoundingClientRect().height, b.getBoundingClientRect().width))).filter(h => h < 44) }));
        check('no horizontal scrolling with the list open (' + lay.scroll + ')', lay.scroll <= 0);
        check('every visible button of the card is 44 px' + (lay.tiny.length ? ': ' + lay.tiny.join(', ') : ''), lay.tiny.length === 0);
        if (OUT) await small.screenshot({ path: OUT + '/packages-row-phone-vm.png', fullPage: false });
        await phone.close();
        check('no browser dialog, no page error' + (errors.length + dialogs.length ? ': ' + errors.concat(dialogs).join(' | ') : ''),
            !errors.length && !dialogs.length);
    } finally {
        await browser.close();
    }
    console.log('\n' + (failed === 0 ? 'ALL OK' : failed + ' CHECKS FAILED'));
    process.exit(failed ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
