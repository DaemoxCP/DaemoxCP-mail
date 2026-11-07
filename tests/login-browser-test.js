// The passwordless login of the mail panel, end to end, in Chromium with a virtual authenticator.
// The real Java server runs (LoginE2EServer): pages, MySQL, sessions, CSRF, WebAuthn checks.
//
//   1. First start: no administrator. The page does not create one: it shows the console
//      command. java ... Main --create-admin creates it (a second time it refuses) and prints a
//      code; --access-code prints a new one that replaces it; the page goes to Account to
//      create a passkey.
//   2. Account: a passkey with the browser's authenticator, the login email with a code sent to
//      it, the open sessions.
//   3. Settings: the vault key asks for a confirmation, the passkey gives it.
//   4. Logout, then the passkey alone (no name, no password): straight to /home.
//   5. Administrators: a new one with an email, no password field.
//   6. Logout, then a code by email; a wrong code is refused.
//   7. Roles: a viewer signs in with an email code, sees a reduced menu, "Read only" and
//      refusals; promoted to operator, the mailboxes become editable; deleted, the session ends.
//
// Usage (from the project root, after mvn package, with the test MySQL of README.md):
//   D=$(mktemp -d) && cp target/freebsd-mail-panel-1.0.jar $D/
//   MYSQL="-Dmysql.port=33062 -Dmysql.user=mailpanel -Dmysql.password=... -Dmysql.database=mailpanel_prova" \
//     NODE_PATH=$(npm root -g) node tests/login-browser-test.js $D [screenshots-dir]
const { chromium } = require('playwright');
const { spawn, execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const dir = process.argv[2];
const shots = process.argv[3];
const root = path.join(__dirname, '..');
const PORT = 19000 + Math.floor(Math.random() * 1000);
const BASE = 'https://panel.localhost:' + PORT;
const JAR = path.join(dir, 'freebsd-mail-panel-1.0.jar');
const PROPS = (process.env.MYSQL || '').split(' ').filter(Boolean)
    .concat(['-Dmailpanel.secrets.dir=' + path.join(dir, 'secrets'), '-Dmailpanel.vault.key=' + path.join(dir, 'master.key')]);
let failures = 0;
function check(what, ok) {
    console.log((ok ? '  OK     ' : '  FAILED ') + what);
    if (!ok) failures++;
}

function mails() {
    const f = path.join(dir, 'mail.log');
    if (!fs.existsSync(f)) return [];
    return fs.readFileSync(f, 'utf8').split('\n.\n').filter(m => m.trim()).map(m => ({
        to: (m.match(/^TO (.*)$/m) || [])[1], subject: (m.match(/^SUBJECT (.*)$/m) || [])[1],
        code: (m.match(/\b(\d{6})\b/) || [])[1] }));
}

function startServer() {
    const server = spawn('java', PROPS.concat(['-cp', path.join(root, 'tests') + ':' + JAR,
        'org.mail_panel.webserver.LoginE2EServer', String(PORT)]), { cwd: dir, stdio: ['ignore', 'ignore', 'pipe'] });
    let log = '';
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('server did not start:\n' + log)), 90000);
        server.stderr.on('data', d => {
            log += d;
            if (log.includes('READY')) { clearTimeout(timer); resolve(server); }
        });
        server.on('exit', c => reject(new Error('server exited ' + c + ':\n' + log)));
    });
}

// The certificate is trusted by its public key, as a real one would be: WebAuthn refuses pages
// with a certificate error, so "ignore HTTPS errors" would not do.
function spki() {
    const pub = execFileSync('openssl', ['x509', '-in', path.join(dir, 'c.pem'), '-pubkey', '-noout']);
    const der = execFileSync('openssl', ['pkey', '-pubin', '-outform', 'der'], { input: pub });
    return execFileSync('openssl', ['dgst', '-sha256', '-binary'], { input: der }).toString('base64');
}

// A console command of the panel, run where the server runs (same SQLite, MySQL and keys).
function console_(...args) {
    try {
        const out = execFileSync('java', PROPS.concat(['-cp', JAR, 'org.mail_panel.Main'], args),
            { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
        return { status: 0, out: out, err: '' };
    } catch (e) {
        return { status: e.status, out: String(e.stdout || ''), err: String(e.stderr || '') };
    }
}

async function shot(page, name) {
    if (shots) await page.screenshot({ path: path.join(shots, name + '.png'), fullPage: true });
}

(async () => {
    const server = await startServer();
    const browser = await chromium.launch({ args: ['--host-resolver-rules=MAP panel.localhost 127.0.0.1',
        '--ignore-certificate-errors-spki-list=' + spki()] });
    try {
        const context = await browser.newContext({ locale: 'en-US', viewport: { width: 1280, height: 900 } });
        const page = await context.newPage();
        const errors = [];
        page.on('pageerror', e => errors.push(e.message));
        page.on('dialog', d => d.accept());
        const cdp = await context.newCDPSession(page);
        await cdp.send('WebAuthn.enable');
        const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
            protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true,
            isUserVerified: true, automaticPresenceSimulation: true } });

        console.log('== 1. First start: the administrator comes from the console ==');
        await page.goto(BASE + '/');
        check('no administrator: the address opens /setup', new URL(page.url()).pathname === '/setup');
        const setupText = await page.locator('main').innerText();
        check('/setup has no form: it shows the console command', await page.locator('main input, main form').count() === 0
            && setupText.includes('--create-admin'));
        await shot(page, 'setup');
        await page.goto(BASE + '/index');
        check('the login page is not reachable yet', new URL(page.url()).pathname === '/setup');
        const created = console_('--create-admin', 'Admin', 'first@example.org');
        const first = created.out.match(/One-time access code for Admin: (\d{4} \d{4})/);
        check('--create-admin creates the administrator and prints an eight-digit code', created.status === 0 && !!first);
        const again = console_('--create-admin', 'Other', 'other@example.org');
        check('a second time it refuses: there is already an administrator', again.status === 2 && /already an administrator/.test(again.err));
        const access = console_('--access-code');
        const m = access.out.match(/One-time access code for Admin: (\d{4} \d{4})/);
        check('--access-code prints a new code for the only admin', access.status === 0 && !!m);
        await Promise.all([page.waitForURL('**/index'), page.click('#setupDone')]);
        check('"Done": the running panel noticed the administrator, here is the login page', new URL(page.url()).pathname === '/index');
        check('no password field, no username', await page.locator('input[type=password]').count() === 0
            && await page.locator('#username').count() === 0);
        check('it offers a passkey and an email code', await page.locator('#btnPasskey').isVisible() && await page.locator('#email').isVisible());
        await shot(page, 'login');
        await page.click('#linkConsole');
        check('"Code from the server console" shows the command to run',
            await page.locator('#step-console').isVisible() && (await page.locator('#step-console').innerText()).includes('--access-code'));
        await page.fill('#consoleCode', first ? first[1] : '0000 0000');
        await page.click('#btnConsole');
        await page.waitForSelector('#errorAlert:not(.d-none)');
        check('the code replaced by a newer one: an error, still on the login page', new URL(page.url()).pathname === '/index');
        await page.fill('#consoleCode', m ? m[1] : '');
        await Promise.all([page.waitForURL('**/account?setup=passkey'), page.click('#btnConsole')]);
        check('the right code: signed in, sent to Account to create a passkey', new URL(page.url()).pathname === '/account');
        await page.waitForSelector('#passkeySetupNotice:not(.d-none)');
        check('Account explains why: no passkey yet', await page.locator('#passkeySetupNotice').isVisible());
        check('no password or 2FA card left', await page.locator('input[type=password]').count() === 0
            && await page.locator('[id="2faStatus"]').count() === 0);

        console.log('\n== 2. Account: a passkey, the login email, the sessions ==');
        await page.waitForSelector('#addPasskeyBtn:not([disabled])');
        await page.click('#addPasskeyBtn');
        await page.waitForSelector('#passkeyNameModal.show');
        await page.fill('#passkeyName', 'Laptop');
        await page.click('#passkeyNameModal .btn-primary');
        await page.waitForFunction(() => document.getElementById('passkeysList').innerText.includes('Laptop'), null, { timeout: 15000 });
        const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
        check('the passkey is created in the authenticator, discoverable, and listed on the page',
            credentials.length === 1 && credentials[0].isResidentCredential && credentials[0].rpId === 'panel.localhost');
        await page.waitForSelector('#passkeySetupNotice.d-none', { state: 'attached' });
        check('the notice goes away', await page.locator('#passkeySetupNotice').isHidden());
        await page.fill('#accEmailNew', 'admin@example.org');
        await page.click('#accEmailSend');
        await page.waitForSelector('#accEmailCodeBox:not(.d-none)');
        const change = mails().pop();
        check('a code goes to the new address', change && change.to === 'admin@example.org' && /^\d{6}$/.test(change.code || ''));
        await page.fill('#accEmailCode', change ? change.code : '');
        await page.click('#accEmailCodeBox .btn-primary');
        await page.waitForFunction(() => document.getElementById('accEmailCurrent').textContent.includes('admin@example.org'), null, { timeout: 10000 });
        check('confirmed: the page shows the login email', true);
        const sessionsText = await page.locator('#sessionsList').innerText();
        check('the open sessions: this one, with the browser and the IP address', /this one/.test(sessionsText) && /Chrome/.test(sessionsText)
            && /127\.0\.0\.1/.test(sessionsText));
        await shot(page, 'account');

        console.log('\n== 3. Settings: the vault key asks for a confirmation ==');
        check('Account has no vault card (it is in Settings, for the superadmin)', await page.locator('button[onclick="vaultBackupKey()"]').count() === 0);
        await page.goto(BASE + '/settings');
        await page.click('button[onclick="vaultBackupKey()"]');
        await page.waitForSelector('#stepUpModal.show');
        check('the confirmation window offers the passkey and an email code', await page.locator('#stepUpPasskeyBtn').isEnabled()
            && await page.locator('#stepUpEmailBtn').isEnabled());
        await shot(page, 'step-up');
        await page.click('#stepUpPasskeyBtn');
        await page.waitForSelector('#vaultBackupKeyValue', { timeout: 15000 });
        const key = await page.locator('#vaultBackupKeyValue').inputValue();
        check('with the passkey: the key is exported', /^[A-Za-z0-9+/=]{40,}$/.test(key));

        console.log('\n== 4. Logout, then the passkey alone ==');
        await Promise.all([page.waitForURL(u => ['/', '/index'].includes(new URL(u).pathname)), page.click('#logoutButton')]);
        await page.goto(BASE + '/index');
        check('logout: back on the login page', await page.locator('#btnPasskey').isVisible());
        await Promise.all([page.waitForURL('**/home'), page.click('#btnPasskey')]);
        check('"Use passkey": no name, no password, straight to /home', new URL(page.url()).pathname === '/home');
        const after = (await cdp.send('WebAuthn.getCredentials', { authenticatorId })).credentials;
        check('the authenticator signed (its counter moved)', after.length === 1 && after[0].signCount > credentials[0].signCount);

        console.log('\n== 5. Administrators: email, no password ==');
        await page.goto(BASE + '/admins');
        await page.waitForFunction(() => document.getElementById('adminsBody').innerText.includes('admin@example.org'), null, { timeout: 10000 });
        check('the list shows the login email and the passkeys', (await page.locator('#adminsBody').innerText()).includes('admin@example.org'));
        await page.click('button[data-bs-target="#addAdminModal"]');
        await page.waitForSelector('#addAdminModal.show');
        check('the new administrator form has an email and no password', await page.locator('#newEmail').isVisible()
            && await page.locator('#addAdminModal input[type=password]').count() === 0);
        await page.fill('#newUsername', 'second');
        await page.fill('#newEmail', 'second@example.org');
        await page.click('#addAdminModal .btn-primary');
        await page.waitForFunction(() => document.getElementById('adminsBody').innerText.includes('second@example.org'), null, { timeout: 10000 });
        check('created: listed with its email', true);
        await shot(page, 'admins');

        console.log('\n== 6. Logout, then a code by email ==');
        await page.goto(BASE + '/home');
        await Promise.all([page.waitForURL(u => ['/', '/index'].includes(new URL(u).pathname)), page.click('#logoutButton')]);
        await page.goto(BASE + '/index');
        const before = mails().length;
        await page.fill('#email', 'ADMIN@example.org');
        await page.click('#btnSendCode');
        await page.waitForSelector('#step-code.active');
        const login = mails().slice(before).pop();
        check('one email, to the stored address, subject in English', login && login.to === 'admin@example.org' && /^\[[a-z0-9.-]+\] Your sign-in code for the mail control panel$/.test(login.subject));
        await page.fill('#emailCode', login && login.code === '000000' ? '111111' : '000000');
        await page.click('#btnVerifyCode');
        await page.waitForSelector('#errorAlert:not(.d-none)');
        check('a wrong code: an error, no session', new URL(page.url()).pathname === '/index');
        await page.fill('#emailCode', login ? login.code : '');
        await Promise.all([page.waitForURL('**/home'), page.click('#btnVerifyCode')]);
        check('the right code: /home (a passkey exists, no setup notice)', new URL(page.url()).pathname === '/home');

        console.log('\n== 7. Roles: what a viewer sees and can do ==');
        const other = await browser.newContext({ locale: 'en-US', ignoreHTTPSErrors: true });
        const viewer = await other.newPage();
        viewer.on('pageerror', e => errors.push('viewer: ' + e.message));
        await viewer.goto(BASE + '/index');
        const sentBefore = mails().length;
        await viewer.fill('#email', 'second@example.org');
        await viewer.click('#btnSendCode');
        await viewer.waitForSelector('#step-code.active');
        const viewerCode = mails().slice(sentBefore).pop();
        await viewer.fill('#emailCode', viewerCode ? viewerCode.code : '');
        await Promise.all([viewer.waitForURL('**/account?setup=passkey'), viewer.click('#btnVerifyCode')]);
        check('"second" (created as viewer) signs in with an email code and lands on Account', new URL(viewer.url()).pathname === '/account');
        const top = await viewer.locator('.topbar-actions').innerText();
        check('the top bar shows the name and the role', top.includes('second') && top.includes('Viewer'));
        const menu = await viewer.$$eval('.sidebar-link', l => l.map(a => a.getAttribute('href')));
        check('the viewer menu: mail, DNS, security and system yes; administrators and settings no',
            menu.includes('/mailboxes') && menu.includes('/dns') && menu.includes('/firewall') && menu.includes('/updates')
            && !menu.includes('/admins') && !menu.includes('/settings'));
        const denied = await viewer.goto(BASE + '/settings');
        check('opening /settings anyway: 403 with "Access denied" inside the panel frame',
            denied.status() === 403 && (await viewer.locator('h2').innerText()).includes('Access denied') && await viewer.locator('.sidebar').count() === 1);
        await viewer.goto(BASE + '/mailboxes');
        check('the mailboxes page says "Read only" in the top bar', await viewer.locator('.topbar-readonly').isVisible());
        const refused = await viewer.evaluate(async () => {
            const reveal = await fetch('/api/mailboxes', { method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'reveal_password', id: 1 }) });
            const message = await fetch('/api/queue?action=message&id=ABC123');
            return [reveal.status, (await reveal.json()).forbidden, message.status];
        });
        check('revealing a mailbox password or reading a queued message: 403', refused[0] === 403 && refused[1] === true && refused[2] === 403);
        await shot(viewer, 'viewer-mailboxes');

        await page.goto(BASE + '/admins');
        await page.waitForFunction(() => document.getElementById('adminsBody').innerText.includes('second@example.org'));
        check('the roles table comes from the real permissions', (await page.locator('#roleMatrix thead .role-badge').count()) === 4
            && (await page.locator('#roleMatrix td[data-role="viewer"] .fa-pen').count()) === 0);
        await page.locator('#adminsBody tr', { hasText: 'second' }).locator('button[onclick^="editAdmin"]').click();
        await page.waitForSelector('#editAdminModal.show');
        await page.selectOption('#editRole', 'operator');
        await page.click('#editAdminModal .btn-primary');
        await page.waitForFunction(() => document.querySelector('#adminsBody .role-badge.operator') !== null);
        await viewer.goto(BASE + '/mailboxes');
        check('promoted to operator: the mailboxes are editable at the next page, no new sign-in',
            await viewer.locator('.topbar-readonly').count() === 0);
        await page.locator('#adminsBody tr', { hasText: 'second' }).locator('button[onclick^="deleteAdmin"]').click();
        await page.waitForFunction(() => !document.getElementById('adminsBody').innerText.includes('second@example.org'));
        await viewer.goto(BASE + '/home');
        check('deleted: the next page is the sign-in page', ['/', '/index'].includes(new URL(viewer.url()).pathname));
        await other.close();

        const phone = await browser.newContext({ locale: 'it-IT', viewport: { width: 375, height: 800 } });
        const small = await phone.newPage();
        await small.goto(BASE + '/index');
        check('on a phone, in Italian: no horizontal scroll', await small.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)
            && (await small.locator('#btnSendCode').innerText()).includes('Mandami un codice'));
        await shot(small, 'login-phone-it');
        check('no JavaScript errors on any page', errors.length === 0);
        if (errors.length) console.log(errors.join('\n'));
    } catch (e) {
        failures++;
        console.log('  FAILED ' + e.message.split('\n')[0]);
    } finally {
        await browser.close();
        server.kill();
    }
    console.log(failures === 0 ? '\nAll checks passed.' : '\nFailed checks: ' + failures);
    process.exit(failures === 0 ? 0 : 1);
})();
