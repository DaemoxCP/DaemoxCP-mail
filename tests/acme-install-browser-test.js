// acme.sh and its Let's Encrypt account from the SSL page (reperto 247), on the real panel of the TEST VM:
//
//  1. without acme.sh, or with acme.sh but without an account, the card "Let's Encrypt is not ready" is shown, with
//     the email field; a malformed address is refused in the page;
//  2. "Install acme.sh" installs the FreeBSD package (user acme) when it is missing, then asks Let's Encrypt for the
//     account with a TEST address (.test): Let's Encrypt refuses it, and the panel must SAY so, with Let's Encrypt's
//     reason, never "account created"; the card stays, to try again. (Creating the account for real needs a real
//     address: not done here.)
//
// It CHANGES the VM: the package security/acme.sh stays installed (as on any server that issues certificates).
// Through an SSH tunnel to the VM's port 2096. Sign-in with a console code; the fresh confirmation with the "confirm"
// mode of tests/signed-jobs-setup.sh, copied to /root/signed on the VM.
//
// Usage:
//   ssh -i ~/.ssh/freebsd_test_vm -N -L 127.0.0.1:2096:127.0.0.1:2096 root@192.168.1.20 &
//   NODE_PATH=<playwright node_modules> node tests/acme-install-browser-test.js [screenshot-folder]
const { chromium } = require('playwright');
const { execSync } = require('child_process');
const BASE = 'https://127.0.0.1:2096';
const OUT = process.argv[2];
const VM = 'ssh -i ' + process.env.HOME + '/.ssh/freebsd_test_vm -o IdentitiesOnly=yes -o ConnectTimeout=10 root@192.168.1.20';
let failed = 0;
const check = (what, ok) => { console.log((ok ? '  OK     ' : '  FAILED ') + what); if (!ok) failed++; };

(async () => {
    const before = execSync(VM + " 'pkg info -e acme.sh && echo yes || echo no; test -f /var/db/acme/.acme.sh/ca/acme-v02.api.letsencrypt.org/directory/account.json && echo account || echo noaccount' </dev/null").toString();
    if (/\baccount\b/.test(before.replace('noaccount', ''))) { console.log('acme.sh already has an account on the VM: this test needs a server without one.'); process.exit(2); }
    console.log('  before: acme.sh ' + (/yes/.test(before) ? 'installed, no account' : 'not installed'));
    const browser = await chromium.launch({ headless: true, channel: 'chrome' });
    const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1400, height: 1000 }, locale: 'en-US' });
    const page = await context.newPage();
    const errors = [], dialogs = [];
    page.on('pageerror', e => errors.push(String(e)));
    page.on('dialog', async d => { dialogs.push(d.message()); await d.dismiss(); });
    const code = execSync(VM + " 'cd /home/panel && /usr/local/openjdk25/bin/java -jar daemoxcp-mail.jar --access-code 2>/dev/null' </dev/null")
        .toString().match(/([0-9]{4} [0-9]{4})/)[1];
    await page.goto(BASE + '/index');
    await page.click('#linkConsole');
    await page.fill('#consoleCode', code);
    await page.click('#btnConsole');
    await page.waitForURL(u => !String(u).includes('/index'), { timeout: 30000 });
    check('signed in with a console code', !page.url().includes('/index'));
    console.log('  ' + execSync(VM + " 'sh /root/signed/signed-jobs-setup.sh confirm' </dev/null").toString().trim());

    console.log('\n== 1. The card, on a server without acme.sh or without its account ==');
    await page.goto(BASE + '/ssl');
    await page.waitForSelector('#acmeCard:not(.d-none)', { timeout: 30000 });
    check('the card "Let\'s Encrypt is not ready" is shown', /Let's Encrypt is not ready/.test(await page.innerText('#acmeCard')));
    if (OUT) await page.locator('#acmeCard').screenshot({ path: OUT + '/acme-card.png' });
    await page.fill('#acmeEmail', 'not-an-address');
    await page.click('#acmeGo');
    check('a malformed address refused in the page', /valid email address/.test(await page.innerText('#acmeOutcome')));

    console.log('\n== 2. Install acme.sh, and the account with a test address ==');
    await page.fill('#acmeEmail', 'postmaster@rehearsal.test');
    await page.click('#acmeGo');
    await page.waitForFunction(() => /installed|could not/.test(document.getElementById('acmeOutcome').innerText)
        && !/fa-spin/.test(document.getElementById('acmeOutcome').innerHTML), null, { timeout: 900000 });
    const outcome = await page.innerText('#acmeOutcome');
    console.log('    ' + outcome.replace(/\s+/g, ' ').slice(0, 300));
    const after = execSync(VM + " 'pkg info -e acme.sh && echo yes || echo no; id acme >/dev/null 2>&1 && echo user || echo nouser' </dev/null").toString();
    check('the package and its user acme are on the VM', /yes/.test(after) && /user/.test(after));
    check('the refused account is SAID, with Let\'s Encrypt\'s reason, never "account is created"',
        /did not create the account \(.+\)/.test(outcome) && !/account is created/.test(outcome));
    await page.reload();
    await page.waitForSelector('#acmeCard:not(.d-none)', { timeout: 30000 });
    check('the card stays, to try again with a real address', true);

    check('no browser dialog, no page error' + (errors.length + dialogs.length ? ': ' + errors.concat(dialogs).join(' | ') : ''), !errors.length && !dialogs.length);
    await browser.close();
    execSync(VM + " 'sh /root/signed/signed-jobs-setup.sh confirm-stop || true' </dev/null");
    console.log('\n' + (failed === 0 ? 'ALL OK' : failed + ' CHECKS FAILED'));
    process.exit(failed ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
