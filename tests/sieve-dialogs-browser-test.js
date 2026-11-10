// The Sieve dialogs of the Mailboxes page work from the browser (reperto 224), in Chromium against the REAL server
// (SieveDialogsE2EServer on the test VM: the Java handlers, the generated pages, the test MySQL and the real
// SieveGenerator, which writes as root under /var/mail/sieve).
//
// Before: the Filters dialog sent conditions and actions as JSON text, and the server answered with the English text
// of a NullPointerException: no filter could be created. Editing asked a route that did not know ?id=, and deleting a
// forward sent id where the server reads rule_id. And there was no way to delete a filter at all.
//
// PHASE=written (the default), with /var/mail at 1775 as the panel leaves it at start:
//  1. "Filters" of alice: a new filter (subject contains fattura-224 -> move to INBOX.Fatture). No notice; the filter
//     is in the list, as a button; alice's rules file on the VM has it, and the seeded forward.
//  2. The filter opened from the keyboard (Tab to it, Enter): the dialog shows its name and condition; the condition
//     changed to bolletta-224 and saved. The rules file has the new one, not the old one.
//  3. The filter opened again and deleted ("Delete filter", confirmed). Gone from the list and from the rules file.
//  4. "Forwarding" of alice: the seeded forward deleted. Gone from the list and from the rules file. No notice.
// PHASE=refused, with /var/mail at FreeBSD's 0775, so root refuses to write any rule (reperto 221): a filter created
// and a forward deleted each show server.sieve.notWritten on top of the dialog (reperto 223), and the list shows the
// panel as it is (the filter there, the forward gone).
// Always: the texts of the language files (it.json, or en.json when the page is in English), no page error, no policy
// violation. Each phase on a freshly started server (it seeds the forward and clears the filters).
//
// Usage: SieveDialogsE2EServer on the VM prints SESSION and PORT; with a tunnel from this machine to its port:
//   REMOTE=https://panel.localhost:PORT MAP=127.0.0.1 SESSION=<token> [PHASE=refused] \
//   RULES="ssh -i ~/.ssh/freebsd_test_vm root@192.168.1.20 cat /var/mail/sieve/sieve-dialog-fields.test/alice/.dovecot.sieve" \
//   CHROMIUM="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" NODE_PATH=... \
//   node tests/sieve-dialogs-browser-test.js [screenshot-folder]
//
// On the REAL panel of the VM (the separated panel, with RootGate between its two parts), signing in with a console
// code instead of SESSION, on a mailbox alice@DOMAIN that has no filters and one forward FORWARD:
//   REMOTE=https://127.0.0.1:2096 VM_LOGIN="ssh -i ~/.ssh/freebsd_test_vm root@192.168.1.20" DOMAIN=rehearsal.test \
//   FORWARD=bob@rehearsal.test RULES="ssh ... cat /var/mail/sieve/rehearsal.test/alice/.dovecot.sieve" ... node ...
const { chromium } = require('playwright');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const csp = require('./browser-csp');

const shots = process.argv[2];
const LANG = path.join(__dirname, '..', 'src', 'main', 'resources', 'lang');
const IT = JSON.parse(fs.readFileSync(path.join(LANG, 'it.json'), 'utf8'));
const EN = JSON.parse(fs.readFileSync(path.join(LANG, 'en.json'), 'utf8'));
// The texts of the page's language: Italian with SESSION (the cookie says so), the administrator's own on the real panel.
let T = IT;
const DOMAIN = process.env.DOMAIN || 'sieve-dialog-fields.test';
const FORWARD = process.env.FORWARD || 'seeded@elsewhere.example';
const PHASE = process.env.PHASE || 'written';
let failed = 0;
function check(what, ok) {
    console.log((ok ? '  OK   ' : '  FAILED ') + what);
    if (!ok) failed++;
}

// alice's rules file on the VM, as root reads it ('' if it is not there).
function rules() {
    try {
        return execSync(process.env.RULES, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    } catch (e) {
        return '';
    }
}

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
    await row.locator('button[aria-label="' + T['mbx.more'] + '"]').click();
    await row.locator('a.dropdown-item', { hasText: item }).click();
}

// The Mailboxes page loaded again, and a dialog of alice opened: each part starts from a clean page, whatever the
// part before it left open.
async function openOfAlice(page, item, modal) {
    await page.goto(process.env.REMOTE + '/mailboxes');
    await page.waitForSelector('tr:has-text("alice@' + DOMAIN + '")');
    await menuOf(page, 'alice@' + DOMAIN, item);
    await shown(page, modal);
}

async function confirmDanger(page) {
    await page.waitForSelector('#panelAskModal.show', { timeout: 5000 });
    await shown(page, 'panelAskModal');
    await page.click('#panelAskGo');
    await page.waitForSelector('#panelAskModal', { state: 'hidden' });
}

// A new filter in the open dialog: one condition (subject contains value), one action (move to folder).
async function newFilter(page, name, value, folder) {
    await page.click('#sieveModal button:has-text("' + T['mbx.svNew'] + '")');
    await page.waitForSelector('#sieveEditor', { state: 'visible' });
    await page.fill('#svName', name);
    await page.click('#sieveEditor button:has-text("' + T['mbx.svAddCondition'] + '")');
    const cond = page.locator('#svConditions .condition-row').first();
    await cond.locator('select').nth(0).selectOption('subject');
    await cond.locator('select').nth(1).selectOption('contains');
    await cond.locator('input[type=text]').fill(value);
    await cond.locator('input[type=text]').press('Tab');
    await page.click('#sieveEditor button:has-text("' + T['mbx.svAddAction'] + '")');
    const act = page.locator('#svActions .action-row').first();
    await act.locator('select').selectOption('move');
    await act.locator('input[type=text]').fill(folder);
    await act.locator('input[type=text]').press('Tab');
    await page.click('#sieveEditor button.btn-success');
}

function listed(page, name) {
    return page.waitForFunction(n => [...document.querySelectorAll('#sieveFiltersList button.filter-rule')]
        .some(b => b.textContent.includes(n)), name, { timeout: 5000 });
}

// One part of the test: what goes wrong in it (a step that times out) is a failed check, and the next part runs.
async function part(title, steps) {
    console.log('\n== ' + title + ' ==');
    try {
        await steps();
    } catch (e) {
        check('this part ran to the end: ' + String(e.message || e).split('\n')[0], false);
    }
}

function unlisted(page, selector, text) {
    return page.waitForFunction(([s, t]) => !document.querySelector(s).textContent.includes(t), [selector, text], { timeout: 5000 });
}

(async () => {
    const E = process.env;
    if (!E.REMOTE || !(E.SESSION || E.VM_LOGIN)) {
        console.log('REMOTE and SESSION (or VM_LOGIN) are needed: this test runs only against SieveDialogsE2EServer or the VM.');
        process.exit(2);
    }
    if (PHASE === 'written' && !E.RULES) {
        console.log('RULES is needed: the command that prints alice\'s rules file on the VM.');
        process.exit(2);
    }
    const url = new URL(E.REMOTE);
    const browser = await chromium.launch({ executablePath: E.CHROMIUM || '/opt/pw-browsers/chromium',
        args: ['--host-resolver-rules=MAP ' + url.hostname + ' ' + (E.MAP || '127.0.0.1')] });
    const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 }, ignoreHTTPSErrors: true, userAgent: 'SieveDialogsE2EServer' });
    if (E.SESSION)
        await ctx.addCookies([{ name: '__Host-MailPanel', value: E.SESSION, url: E.REMOTE, secure: true, httpOnly: true, sameSite: 'Strict' },
                              { name: '__Host-lang', value: 'it', url: E.REMOTE, secure: true, sameSite: 'Strict' }]);
    const page = await ctx.newPage();
    const errorList = [];
    page.on('pageerror', e => errorList.push(String(e)));
    csp.watch(page, errorList);
    page.on('console', m => { if (m.type() === 'error') errorList.push(m.text()); });
    const alice = 'alice@' + DOMAIN;

    if (!E.SESSION) {
        // The real panel: a one-time code from its console, as an administrator who lost access would do.
        const code = execSync(E.VM_LOGIN + " 'cd /home/panel && /usr/local/openjdk25/bin/java -jar freebsd-mail-panel-1.0.jar --access-code 2>/dev/null'")
            .toString().match(/([0-9]{4} [0-9]{4})/)[1];
        await page.goto(E.REMOTE + '/index');
        await page.click('#linkConsole');
        await page.fill('#consoleCode', code);
        await page.click('#btnConsole');
        await page.waitForURL(u => !String(u).includes('/index'), { timeout: 30000 });
    }
    await page.goto(E.REMOTE + '/mailboxes');
    await page.waitForSelector('tr:has-text("' + alice + '")');
    if ((await page.evaluate(() => document.documentElement.lang)).startsWith('en')) T = EN;

    if (PHASE === 'written') {
      await part('A new filter for alice', async () => {
        await openOfAlice(page, T['mbx.filters'], 'sieveModal');
        await newFilter(page, 'Fatture', 'fattura-224', 'INBOX.Fatture');
        check('the filter is in the list', await soon(listed(page, 'Fatture')));
        await page.waitForTimeout(500);
        let n = await notices(page);
        check('no notice: ' + JSON.stringify(n.map(x => x.text)), n.length === 0);
        check('the editor closed', !(await page.isVisible('#sieveEditor')));
        let r = rules();
        check('alice\'s rules file has the filter', r.includes('"fattura-224"') && r.includes('fileinto "INBOX.Fatture"'));
        check('and the forward that was in the panel already', r.includes(FORWARD));
        await photo(page, 'created');
      });

      await part('The filter changed, opened from the keyboard', async () => {
        await openOfAlice(page, T['mbx.filters'], 'sieveModal');
        await page.waitForSelector('#sieveFiltersList button.filter-rule');
        await page.focus('#sieveFiltersList button.filter-rule');
        await page.keyboard.press('Enter');
        const opened = await soon(page.waitForFunction(() => document.getElementById('svName').value === 'Fatture'
            && document.getElementById('sieveEditor').style.display === 'block', null, { timeout: 5000 }));
        check('Enter on the list row opens the filter: it is a button', opened);
        const cond = page.locator('#svConditions .condition-row').first();
        check('its condition is back in the dialog', opened && (await cond.locator('input[type=text]').inputValue()) === 'fattura-224'
            && (await cond.locator('select').nth(0).inputValue()) === 'subject');
        check('its action too', opened
            && (await page.locator('#svActions .action-row input[type=text]').first().inputValue()) === 'INBOX.Fatture');
        check('"Delete filter" is there for an existing filter', await page.isVisible('#svDelete'));
        await cond.locator('input[type=text]').fill('bolletta-224');
        await cond.locator('input[type=text]').press('Tab');
        await page.click('#sieveEditor button.btn-success');
        await soon(page.waitForSelector('#sieveEditor', { state: 'hidden', timeout: 5000 }));
        await page.waitForTimeout(500);
        n = await notices(page);
        check('saved, no notice: ' + JSON.stringify(n.map(x => x.text)), n.length === 0);
        check('still one filter in the list', (await page.locator('#sieveFiltersList button.filter-rule').count()) === 1);
        r = rules();
        check('the rules file has the change, not the old condition', r.includes('"bolletta-224"') && !r.includes('fattura-224'));
        await photo(page, 'changed');
      });

      await part('The filter deleted', async () => {
        await openOfAlice(page, T['mbx.filters'], 'sieveModal');
        await page.waitForSelector('#sieveFiltersList button.filter-rule');
        await page.click('#sieveFiltersList button.filter-rule');
        await soon(page.waitForSelector('#svDelete', { state: 'visible', timeout: 5000 }));
        await page.click('#svDelete');
        await confirmDanger(page);
        check('gone from the list', await soon(unlisted(page, '#sieveFiltersList', 'Fatture')));
        await page.waitForTimeout(500);
        n = await notices(page);
        check('no notice: ' + JSON.stringify(n.map(x => x.text)), n.length === 0);
        r = rules();
        check('gone from the rules file, the forward still there', !r.includes('bolletta-224') && r.includes(FORWARD));
      });

      await part('The forward of alice deleted', async () => {
        await openOfAlice(page, T['mbx.forwarding'], 'forwardingModal');
        await page.waitForFunction(f => document.getElementById('forwardingRules').textContent.includes(f), FORWARD);
        await page.click('#forwardingRules button.btn-outline-danger');
        await confirmDanger(page);
        check('gone from the list', await soon(unlisted(page, '#forwardingRules', FORWARD)));
        await page.waitForTimeout(500);
        n = await notices(page);
        check('no notice: ' + JSON.stringify(n.map(x => x.text)), n.length === 0);
        r = rules();
        check('gone from the rules file', r !== '' && !r.includes(FORWARD));
        await photo(page, 'forward-deleted');
      });
    } else {
        console.log('\n== A new filter for alice, rules refused by root ==');
        const before = E.RULES ? rules() : '';
        await menuOf(page, alice, T['mbx.filters']);
        await shown(page, 'sieveModal');
        await newFilter(page, 'Rifiutato', 'rifiutato-224', 'INBOX.Rifiutato');
        await soon(page.waitForSelector('#panelNotices .alert-danger', { timeout: 5000 }));
        let n = await notices(page);
        check('the notice says it, in Italian: ' + JSON.stringify(n.map(x => x.text)),
            n.length === 1 && n[0].text === T['server.sieve.notWritten'] && n[0].kind.includes('alert-danger') && n[0].role === 'alert');
        check('it is on top of the dialog, not behind it', n.length === 1 && n[0].onTop);
        check('the filter is in the list: it is saved in the panel', await soon(listed(page, 'Rifiutato')));
        if (E.RULES) check('the rules file did not change', rules() === before);
        await photo(page, 'created');
        await closeNotices(page);

        console.log('\n== The filter deleted, rules refused ==');
        await page.click('#sieveFiltersList button.filter-rule');
        await soon(page.waitForSelector('#svDelete', { state: 'visible', timeout: 5000 }));
        await page.click('#svDelete');
        await confirmDanger(page);
        await soon(page.waitForSelector('#panelNotices .alert-danger', { timeout: 5000 }));
        n = await notices(page);
        check('the same notice: ' + JSON.stringify(n.map(x => x.text)), n.length === 1 && n[0].text === T['server.sieve.notWritten']);
        check('gone from the list: deleted in the panel', await soon(unlisted(page, '#sieveFiltersList', 'Rifiutato')));
        await closeNotices(page);
        await page.click('#sieveModal .btn-close');
        await page.waitForSelector('#sieveModal', { state: 'hidden' });

        console.log('\n== The forward of alice deleted, rules refused ==');
        await menuOf(page, alice, T['mbx.forwarding']);
        await shown(page, 'forwardingModal');
        await page.waitForFunction(f => document.getElementById('forwardingRules').textContent.includes(f), FORWARD);
        await page.click('#forwardingRules button.btn-outline-danger');
        await confirmDanger(page);
        await soon(page.waitForSelector('#panelNotices .alert-danger', { timeout: 5000 }));
        n = await notices(page);
        check('the same notice: ' + JSON.stringify(n.map(x => x.text)), n.length === 1 && n[0].text === T['server.sieve.notWritten']);
        check('on top of the dialog', n.length === 1 && n[0].onTop);
        check('gone from the list: deleted in the panel', await soon(unlisted(page, '#forwardingRules', FORWARD)));
        await photo(page, 'forward-deleted');
    }

    check('no page error and no policy violation: ' + JSON.stringify(errorList), errorList.length === 0);
    await browser.close();
    console.log(failed === 0 ? '\nALL OK' : '\n' + failed + ' FAILED');
    process.exit(failed === 0 ? 0 : 1);
})().catch(e => { console.error(e); process.exit(1); });
