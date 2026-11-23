// The page tells when the mail server did not get the rules (finding 223), in Chromium against the REAL server
// (SieveRulesE2EServer on the test VM: the Java handlers, the generated pages, the test MySQL and the real
// SieveGenerator, which writes as root under /var/mail/sieve).
//
// PHASE=refused (the default), with /var/mail at FreeBSD's 0775, so root refuses to write any rule (finding 221):
//  1. Mailboxes, "Forwarding" of alice: a forward added. The notice says the change is saved in the panel but the
//     mail server did not get it (server.sieve.notWritten), it stays until closed, it is on top of the dialog; the
//     forward is in the list (saved in the panel) and the field is empty, so nobody adds it twice.
//  2. "Auto-Responder" of alice: saved. The same notice; the dialog stays open to try again.
//  3. Aliases, "To mailbox" of bob, who left filters as a mailbox of before: the dialog closes, the alias list says
//     bob is a mailbox now but the old filters still apply (server.convert.oldFiltersKept), in red.
// PHASE=written, with /var/mail at 1775 as the panel leaves it at start: a second forward of alice is added with no
// notice at all (whoever runs it checks on the VM that alice's rules file now has both forwards and the auto-reply).
// Always: the Italian texts of it.json, no page error, no policy violation.
//
// Usage: SieveRulesE2EServer on the VM prints SESSION and PORT; with a tunnel from this machine to its port:
//   REMOTE=https://panel.localhost:PORT MAP=127.0.0.1 SESSION=<token> [PHASE=written] \
//   CHROMIUM="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" NODE_PATH=... \
//   node tests/sieve-rules-browser-test.js [screenshot-folder]
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const csp = require('./browser-csp');

const shots = process.argv[2];
const IT = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'src', 'main', 'resources', 'lang', 'it.json'), 'utf8'));
const DOMAIN = 'sieve-rules-shown.test';
const PHASE = process.env.PHASE || 'refused';
let failed = 0;
function check(what, ok) {
    console.log((ok ? '  OK   ' : '  FAILED ') + what);
    if (!ok) failed++;
}
function fill(s, v) { return s.replace(/\{(\w+)\}/g, (m, k) => (k in v ? String(v[k]) : m)); }

async function shown(page, id) {
    await page.waitForSelector('#' + id + '.show');
    await page.waitForFunction(i => getComputedStyle(document.getElementById(i)).opacity === '1'
        && getComputedStyle(document.querySelector('#' + i + ' .modal-dialog')).transform === 'none', id);
}

async function photo(page, name) {
    if (shots) await page.screenshot({ path: path.join(shots, PHASE + '-' + name + '.png') });
}

// The notices of panelSay: their texts, and whether the last one is on top of everything at its middle.
async function notices(page) {
    return page.evaluate(() => [...document.querySelectorAll('#panelNotices .alert')].map(n => {
        const r = n.getBoundingClientRect();
        const top = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
        return { kind: n.className, role: n.getAttribute('role'), text: [...n.querySelectorAll('p')].map(p => p.textContent).join('\n'),
                 onTop: !!top && n.contains(top) };
    }));
}

// Waits up to 5 s: what does not come is a failed check below, not the end of the test.
function soon(promise) {
    return promise.then(() => true, () => false);
}

async function closeNotices(page) {
    for (const b of await page.locator('#panelNotices .btn-close').all()) await b.click();
}

async function menuOf(page, address, item) {
    const row = page.locator('tr', { hasText: address });
    await row.locator('button[aria-label="' + IT['mbx.more'] + '"]').click();
    await row.locator('a.dropdown-item', { hasText: item }).click();
}

(async () => {
    const E = process.env;
    if (!E.REMOTE || !E.SESSION) {
        console.log('REMOTE and SESSION are needed: this test runs only against SieveRulesE2EServer.');
        process.exit(2);
    }
    const url = new URL(E.REMOTE);
    const browser = await chromium.launch({ executablePath: E.CHROMIUM || '/opt/pw-browsers/chromium',
        args: ['--host-resolver-rules=MAP ' + url.hostname + ' ' + (E.MAP || '127.0.0.1')] });
    const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 }, ignoreHTTPSErrors: true, userAgent: 'SieveRulesE2EServer' });
    await ctx.addCookies([{ name: '__Host-DaemoxCPMail', value: E.SESSION, url: E.REMOTE, secure: true, httpOnly: true, sameSite: 'Strict' },
                          { name: '__Host-lang', value: 'it', url: E.REMOTE, secure: true, sameSite: 'Strict' }]);
    const page = await ctx.newPage();
    const errorList = [];
    page.on('pageerror', e => errorList.push(String(e)));
    csp.watch(page, errorList);
    page.on('console', m => { if (m.type() === 'error') errorList.push(m.text()); });
    const alice = 'alice@' + DOMAIN, bob = 'bob@' + DOMAIN;

    if (PHASE === 'refused') {
        console.log('\n== Forwarding of alice, rules refused by root ==');
        await page.goto(E.REMOTE + '/mailboxes');
        await page.waitForSelector('tr:has-text("' + alice + '")');
        await menuOf(page, alice, IT['mbx.forwarding']);
        await shown(page, 'forwardingModal');
        await page.fill('#fwDestination', 'far@elsewhere.example');
        await page.click('#forwardingModal button.btn-success');
        await soon(page.waitForSelector('#panelNotices .alert-danger', { timeout: 5000 }));
        await soon(page.waitForFunction(() => document.getElementById('forwardingRules').textContent.includes('far@elsewhere.example'),
            null, { timeout: 5000 }));
        let n = await notices(page);
        check('the notice says it, in Italian: ' + JSON.stringify(n.map(x => x.text)),
            n.length === 1 && n[0].text === IT['server.sieve.notWritten'] && n[0].kind.includes('alert-danger') && n[0].role === 'alert');
        check('it is on top of the dialog, not behind it', n.length === 1 && n[0].onTop);
        check('the forward is in the list: it is saved in the panel', (await page.textContent('#forwardingRules')).includes('far@elsewhere.example'));
        check('the field is empty: adding it again is not the next thing', (await page.inputValue('#fwDestination')) === '');
        await photo(page, 'forwarding');
        await page.waitForTimeout(10500);
        check('after 10 s the notice is still there (errors stay until closed)', (await notices(page)).length === 1);
        await closeNotices(page);
        await page.keyboard.press('Escape');
        await page.waitForSelector('#forwardingModal', { state: 'hidden' });

        console.log('\n== Auto-reply of alice, rules refused by root ==');
        await menuOf(page, alice, 'Auto-Responder');
        await shown(page, 'autoResponderModal');
        await page.check('#arEnabled');
        await page.fill('#arSubject', 'Out of office');
        await page.fill('#arBody', 'Torno lunedi.');
        await page.click('#autoResponderModal .modal-footer button.btn-primary');
        await soon(page.waitForSelector('#panelNotices .alert-danger', { timeout: 5000 }));
        n = await notices(page);
        check('the same notice: ' + JSON.stringify(n.map(x => x.text)), n.length === 1 && n[0].text === IT['server.sieve.notWritten']);
        check('on top of the dialog', n.length === 1 && n[0].onTop);
        check('the dialog stays open, to try again', await page.isVisible('#autoResponderModal'));
        await photo(page, 'autoresponder');
        await closeNotices(page);
        if (await page.isVisible('#autoResponderModal')) {
            await page.keyboard.press('Escape');
            await page.waitForSelector('#autoResponderModal', { state: 'hidden' });
        }

        console.log('\n== bob, alias to mailbox, his old filters not rewritten ==');
        await page.goto(E.REMOTE + '/aliases');
        const button = 'button[aria-label="' + fill(IT['al.toMailboxOf'], { source: bob }) + '"]';
        await page.waitForSelector(button);
        await page.click(button);
        await page.waitForSelector('#acSi:not(.d-none)');
        await page.waitForFunction(() => document.getElementById('acPass').value.length > 0 && !document.getElementById('acVia').disabled);
        await shown(page, 'aMailboxModal');
        await page.click('#acVia');
        const closed = await soon(page.waitForSelector('#aMailboxModal', { state: 'hidden', timeout: 5000 }));
        await soon(page.waitForSelector('#aliasMsg .alert', { timeout: 5000 }));
        const alert = page.locator('#aliasMsg .alert');
        const msg = (await alert.count()) ? await alert.textContent() : '';
        const cls = (await alert.count()) ? await alert.getAttribute('class') : '';
        check('the dialog closed: bob is a mailbox now', closed);
        check('the alias page says so, and that the old filters still apply: ' + msg,
            msg === fill(IT['server.convert.nowMailbox'], { address: bob }) + ' ' + IT['server.convert.oldFiltersKept']);
        check('in red', cls.includes('alert-danger'));
        await photo(page, 'alias-to-mailbox');
    } else {
        console.log('\n== Forwarding of alice, rules written ==');
        await page.goto(E.REMOTE + '/mailboxes');
        await page.waitForSelector('tr:has-text("' + alice + '")');
        await menuOf(page, alice, IT['mbx.forwarding']);
        await shown(page, 'forwardingModal');
        await page.fill('#fwDestination', 'near@elsewhere.example');
        await page.click('#forwardingModal button.btn-success');
        await page.waitForFunction(() => document.getElementById('forwardingRules').textContent.includes('near@elsewhere.example'));
        await page.waitForTimeout(1000);
        const n = await notices(page);
        check('no notice: ' + JSON.stringify(n.map(x => x.text)), n.length === 0);
        check('both forwards in the list', (await page.textContent('#forwardingRules')).includes('far@elsewhere.example'));
        await photo(page, 'forwarding');
    }

    check('no page error and no policy violation: ' + JSON.stringify(errorList), errorList.length === 0);
    await browser.close();
    console.log(failed === 0 ? '\nALL OK' : '\n' + failed + ' FAILED');
    process.exit(failed === 0 ? 0 : 1);
})().catch(e => { console.error(e); process.exit(1); });
