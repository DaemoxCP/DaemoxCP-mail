// The Apple Mail configuration profile, where people look for it: in a mailbox's "Client configuration" window, tab
// iPhone/Mac, and no longer in a separate card at the bottom of Mailboxes (22/11/2026). On the real panel of the TEST
// VM; it only reads and downloads: nothing changes on the server.
//
//  1. Mailboxes has no separate profile card any more.
//  2. The window of a mailbox, tab iPhone/Mac: the profile comes first, before the steps by hand; its buttons turn on
//     once the panel has checked the profile can be made, and the line under them names the IMAP and SMTP ports.
//  3. "Download the profile" downloads that mailbox's .mobileconfig: its address, IMAP 993 and SMTP 465 with SSL, and
//     no password inside. "See what it contains" shows the same profile.
//  4. The window opened for another mailbox gives that mailbox's profile, not the previous one.
//  5. At 375 px: no horizontal scrolling in the window, and the profile buttons are 44 px.
//
// Through an SSH tunnel to the VM's port 2096 (self-signed certificate: errors ignored, for this test machine only).
// Sign-in with a console code.
//
// Usage:
//   ssh -i ~/.ssh/freebsd_test_vm -N -L 127.0.0.1:2096:127.0.0.1:2096 root@192.168.1.20 &
//   HOST=panel.rehearsal.test NODE_PATH=<playwright node_modules> node tests/apple-profile-browser-test.js [screenshot-folder]
const { chromium } = require('playwright');
const { execSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
// The panel's name: once the panel has a name it refuses any other Host (HostCheck), so the browser resolves that name
// to the tunnel. Without HOST, 127.0.0.1.
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

// Opens the client window of the mailbox in row n, on the iPhone/Mac tab, and waits for the profile check.
async function openApple(page, n) {
    const open = page.locator('button[data-on-click^="showMailConfig("]').nth(n);
    const email = (await open.getAttribute('data-on-click')).match(/showMailConfig\('([^']+)'/)[1];
    await open.click();
    await page.waitForSelector('#mailConfigModal.show');
    await page.click('#mailConfigModal [data-bs-target="#configApple"]');
    await page.waitForSelector('#configApple.active.show');
    await page.waitForFunction(() => !document.getElementById('cfgAppleProfileBtn').disabled
        || document.getElementById('cfgAppleProfileOutcome').innerText.trim() !== '', null, { timeout: 30000 });
    return email;
}

async function closeWindow(page) {
    await page.click('#mailConfigModal .btn-close');
    await page.waitForSelector('#mailConfigModal', { state: 'hidden' });
}

// The values of a key in the profile (plist: <key>K</key> then the value element).
const plistValue = (xml, key) => {
    const m = xml.match(new RegExp('<key>' + key + '</key>\\s*<(string|integer|true|false)\\s*/?>([^<]*)'));
    return m ? (m[1] === 'true' || m[1] === 'false' ? m[1] : m[2]) : null;
};

(async () => {
    const browser = await chromium.launch({ headless: true, channel: 'chrome', args: HOST === '127.0.0.1' ? [] : ['--host-resolver-rules=MAP ' + HOST + ' 127.0.0.1'] });
    const errors = [], dialogs = [];
    const watch = page => {
        page.on('pageerror', e => errors.push(String(e)));
        page.on('dialog', async d => { dialogs.push(d.message()); await d.dismiss(); });
    };
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'apple-profile-'));
    try {
        const context = await browser.newContext({ ignoreHTTPSErrors: true, acceptDownloads: true, viewport: { width: 1400, height: 1000 }, locale: 'en-US' });
        const page = await context.newPage();
        watch(page);
        await signIn(page);
        check('signed in with a console code', !page.url().includes('/index'));

        console.log('\n== 1. Mailboxes ==');
        await page.goto(BASE + '/mailboxes');
        await page.waitForSelector('button[data-on-click^="showMailConfig("]', { timeout: 30000 });
        const rows = await page.locator('button[data-on-click^="showMailConfig("]').count();
        check('mailboxes to try (' + rows + ')', rows > 0);
        check('no separate profile card at the bottom of the page', await page.$('#paBody') === null && await page.$('#paMailbox') === null);

        console.log('\n== 2. The window, tab iPhone/Mac ==');
        const email = await openApple(page, 0);
        const order = await page.evaluate(() => {
            const tab = document.getElementById('configApple');
            const btn = document.getElementById('cfgAppleProfileBtn'), steps = tab.querySelector('ol');
            return !!(btn && steps && (btn.compareDocumentPosition(steps) & Node.DOCUMENT_POSITION_FOLLOWING));
        });
        check('the profile comes first, the steps by hand after it', order);
        check('the download button is on', !(await page.$eval('#cfgAppleProfileBtn', b => b.disabled)));
        const sets = await page.innerText('#cfgAppleProfileSets');
        check('the line under it names IMAP 993 and SMTP 465', /:993\b/.test(sets) && /:465\b/.test(sets));
        if (OUT) await page.locator('#mailConfigModal .modal-content').screenshot({ path: OUT + '/apple-profile-window.png' });

        console.log('\n== 3. Download and preview ==');
        const [dl] = await Promise.all([page.waitForEvent('download'), page.click('#cfgAppleProfileBtn')]);
        const file = path.join(tmp, 'first.mobileconfig');
        await dl.saveAs(file);
        const xml = fs.readFileSync(file, 'utf8');
        check('the file is a .mobileconfig named after the mailbox', dl.suggestedFilename() === email.toLowerCase().replace(/[^a-z0-9._-]/g, '-') + '.mobileconfig');
        check('  its address is the mailbox', plistValue(xml, 'EmailAddress') === email);
        check('  IMAP 993 with SSL', plistValue(xml, 'IncomingMailServerPortNumber') === '993' && plistValue(xml, 'IncomingMailServerUseSSL') === 'true');
        check('  SMTP 465 with SSL', plistValue(xml, 'OutgoingMailServerPortNumber') === '465' && plistValue(xml, 'OutgoingMailServerUseSSL') === 'true');
        check('  no password inside', !/<key>(IncomingPassword|OutgoingPassword)<\/key>/.test(xml));
        if (process.platform === 'darwin') {
            let lint = '';
            try { lint = execSync('plutil -lint "' + file + '"').toString(); } catch (e) { lint = String(e.stdout || e); }
            check('  plutil accepts it', /: OK\s*$/.test(lint.trim()));
        }
        await page.click('#cfgAppleProfileLookBtn');
        await page.waitForSelector('#cfgAppleProfileOutcome pre', { timeout: 30000 });
        const shown = await page.innerText('#cfgAppleProfileOutcome pre');
        check('"See what it contains" shows the same profile', shown.includes('<string>' + email + '</string>'));
        await closeWindow(page);

        console.log('\n== 4. Another mailbox ==');
        if (rows > 1) {
            const other = await openApple(page, 1);
            check('the window was reset: no preview left from the other mailbox', await page.$('#cfgAppleProfileOutcome pre') === null);
            const [dl2] = await Promise.all([page.waitForEvent('download'), page.click('#cfgAppleProfileBtn')]);
            const file2 = path.join(tmp, 'second.mobileconfig');
            await dl2.saveAs(file2);
            check('the profile is the one of ' + (other === email ? 'the same' : 'the other') + ' mailbox', other !== email
                && plistValue(fs.readFileSync(file2, 'utf8'), 'EmailAddress') === other);
            await closeWindow(page);
        } else {
            console.log('  (only one mailbox: skipped)');
        }
        await context.close();

        console.log('\n== 5. At 375 px ==');
        const phone = await browser.newContext({ ignoreHTTPSErrors: true, acceptDownloads: true, viewport: { width: 375, height: 812 }, isMobile: true, hasTouch: true, locale: 'en-GB' });
        const small = await phone.newPage();
        watch(small);
        await signIn(small);
        await small.goto(BASE + '/mailboxes');
        await small.waitForSelector('button[data-on-click^="showMailConfig("]', { timeout: 30000 });
        await openApple(small, 0);
        const lay = await small.evaluate(() => {
            const content = document.querySelector('#mailConfigModal .modal-content');
            return {
                scroll: Math.max(document.documentElement.scrollWidth - window.innerWidth, content.scrollWidth - content.clientWidth),
                tiny: ['cfgAppleProfileBtn', 'cfgAppleProfileLookBtn'].map(id => document.getElementById(id).getBoundingClientRect())
                    .map(r => Math.round(Math.min(r.height, r.width))).filter(h => h < 44)
            };
        });
        check('no horizontal scrolling in the window (' + lay.scroll + ')', lay.scroll <= 0);
        check('the profile buttons are 44 px' + (lay.tiny.length ? ': ' + lay.tiny.join(', ') : ''), lay.tiny.length === 0);
        if (OUT) await small.screenshot({ path: OUT + '/apple-profile-phone.png', fullPage: false });
        await phone.close();
        check('no browser dialog, no page error' + (errors.length + dialogs.length ? ': ' + errors.concat(dialogs).join(' | ') : ''),
            !errors.length && !dialogs.length);
    } finally {
        await browser.close();
        fs.rmSync(tmp, { recursive: true, force: true });
    }
    console.log('\n' + (failed === 0 ? 'ALL OK' : failed + ' CHECKS FAILED'));
    process.exit(failed ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
