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
// With REMOTE=root@<host> (and REMOTE_KEY=<ssh key>) the server and the panel's console commands run
// on that machine over ssh, in the folder given as argument (with the jar and, in TESTS_CLASSES, the
// compiled tests): here only the browser runs. That is how it runs against the FreeBSD test
// machine (reperto 178): servers and Java do not run on the Mac. PORT picks the port (the test
// machine's firewall lets the panel's 2096 through).
//
// Usage (from the project root, after mvn package, with the test MySQL of README.md):
//   D=$(mktemp -d) && cp target/daemoxcp-mail-1.0.jar $D/
//   MYSQL="-Dmysql.port=33062 -Dmysql.user=daemoxcp_mail -Dmysql.password=... -Dmysql.database=daemoxcp_mail_test" \
//     NODE_PATH=$(npm root -g) node tests/login-browser-test.js $D [screenshots-dir]
const { chromium } = require('playwright');
const { spawn, execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const csp = require('./browser-csp');

const dir = process.argv[2];
const shots = process.argv[3];
const root = path.join(__dirname, '..');
const REMOTE = process.env.REMOTE || '';
const SSH = ['-o', 'BatchMode=yes'].concat(process.env.REMOTE_KEY ? ['-i', process.env.REMOTE_KEY] : []);
const HOST_IP = REMOTE ? REMOTE.replace(/^.*@/, '') : '127.0.0.1';
const PORT = Number(process.env.PORT) || 19000 + Math.floor(Math.random() * 1000);
// A command for the remote shell, with every argument in single quotes.
const q = a => "'" + String(a).replace(/'/g, "'\\''") + "'";
// The address the server sees the browser come from: locally the loopback, remotely the Mac's as the
// test machine sees it (the same one ssh comes from).
const CLIENT_IP_OF = () => REMOTE ? remote('echo "${SSH_CLIENT%% *}"').trim() : '127.0.0.1';
let CLIENT_IP = '127.0.0.1';
function remote(cmd, opts) { return execFileSync('ssh', SSH.concat([REMOTE, cmd]), Object.assign({ encoding: 'utf8' }, opts || {})); }
const BASE = 'https://panel.localhost:' + PORT;
const JAR = path.join(dir, 'daemoxcp-mail-1.0.jar');
const PROPS = (process.env.MYSQL || '').split(' ').filter(Boolean)
    .concat(['-Ddaemoxcp.mail.secrets.dir=' + path.join(dir, 'secrets'), '-Ddaemoxcp.mail.vault.key=' + path.join(dir, 'master.key')]);
let failures = 0;
function check(what, ok) {
    console.log((ok ? '  OK     ' : '  FAILED ') + what);
    if (!ok) failures++;
}

function mails() {
    const f = path.join(dir, 'mail.log');
    const text = REMOTE ? remote('cat ' + q(f) + ' 2>/dev/null || true') : (fs.existsSync(f) ? fs.readFileSync(f, 'utf8') : '');
    if (!text) return [];
    return text.split('\n.\n').filter(m => m.trim()).map(m => ({
        to: (m.match(/^TO (.*)$/m) || [])[1], subject: (m.match(/^SUBJECT (.*)$/m) || [])[1],
        code: (m.match(/\b(\d{6})\b/) || [])[1] }));
}

function startServer() {
    // TESTS_CLASSES: the test classes compiled elsewhere, so as not to leave them in tests/.
    const javaArgs = PROPS.concat(['-cp', (process.env.TESTS_CLASSES || path.join(root, 'tests')) + ':' + JAR,
        'org.daemoxcp.mail.webserver.LoginE2EServer', String(PORT)]);
    const server = REMOTE
        ? spawn('ssh', SSH.concat([REMOTE, 'cd ' + q(dir) + ' && exec java ' + javaArgs.map(q).join(' ')]), { stdio: ['ignore', 'ignore', 'pipe'] })
        : spawn('java', javaArgs, { cwd: dir, stdio: ['ignore', 'ignore', 'pipe'] });
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
    if (REMOTE) return remote('openssl x509 -in ' + q(path.join(dir, 'c.pem')) + ' -pubkey -noout | openssl pkey -pubin -outform der'
        + ' | openssl dgst -sha256 -binary | openssl base64 -A').trim();
    const pub = execFileSync('openssl', ['x509', '-in', path.join(dir, 'c.pem'), '-pubkey', '-noout']);
    const der = execFileSync('openssl', ['pkey', '-pubin', '-outform', 'der'], { input: pub });
    return execFileSync('openssl', ['dgst', '-sha256', '-binary'], { input: der }).toString('base64');
}

// A console command of the panel, run where the server runs (same SQLite, MySQL and keys).
function console_(...args) {
    try {
        const javaArgs = PROPS.concat(['-cp', JAR, 'org.daemoxcp.mail.Main'], args);
        const out = REMOTE
            ? remote('cd ' + q(dir) + ' && java ' + javaArgs.map(q).join(' '), { stdio: ['ignore', 'pipe', 'pipe'] })
            : execFileSync('java', javaArgs, { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
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
    CLIENT_IP = CLIENT_IP_OF();
    const browser = await chromium.launch({ executablePath: process.env.CHROMIUM || undefined, args: ['--host-resolver-rules=MAP panel.localhost ' + HOST_IP,
        '--ignore-certificate-errors-spki-list=' + spki()] });
    try {
        const context = await browser.newContext({ locale: 'en-US', viewport: { width: 1280, height: 900 } });
        const page = await context.newPage();
        const errors = [];
        page.on('pageerror', e => errors.push(e.message));
        // The Content-Security-Policy violations the real server sends (reperto 178).
        csp.watch(page, errors);
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
        // The cookie as the server sets it at sign-in (reperto 184): Strict, and a browser-session cookie.
        const sessionCookie = (await context.cookies()).find(c => c.name === '__Host-DaemoxCPMail');
        check('the session cookie the server set: SameSite=Strict, HttpOnly, Secure, gone when the browser closes ('
            + (sessionCookie ? sessionCookie.sameSite + ' ' + sessionCookie.expires : 'none') + ')', !!sessionCookie
            && sessionCookie.sameSite === 'Strict' && sessionCookie.httpOnly && sessionCookie.secure && sessionCookie.expires === -1);
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
            && sessionsText.includes(CLIENT_IP));
        await shot(page, 'account');

        console.log('\n== 3. Settings: the vault key asks for a confirmation ==');
        check('Account has no vault card (it is in Settings, for the superadmin)', await page.locator('button[data-on-click="vaultBackupKey()"]').count() === 0);
        await page.goto(BASE + '/settings');
        await page.click('button[data-on-click="vaultBackupKey()"]');
        // The shared confirmation window (panel-confirm.js), the same on every page: the server asked it (403 with
        // X-Panel-Confirmation), and once confirmed the request is sent again by itself.
        await page.waitForSelector('#panelConfirmModal.show');
        check('the confirmation window offers the passkey and an email code (the account has both)',
            await page.locator('#panelConfirmModal [data-confirm="passkey"]').isVisible()
            && await page.locator('#panelConfirmModal [data-confirm="email"]').isVisible()
            && await page.locator('#panelConfirmModal [data-confirm="choose"]').isVisible());
        await shot(page, 'step-up');
        await page.click('#panelConfirmModal [data-confirm="passkey"]');
        await page.waitForSelector('#vaultBackupKeyValue', { timeout: 15000 });
        const key = await page.locator('#vaultBackupKeyValue').inputValue();
        check('with the passkey: the request is sent again and the key is exported', /^[A-Za-z0-9+/=]{40,}$/.test(key));
        check('  the window closed and focus came back to the page', await page.locator('#panelConfirmModal.show').count() === 0);

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
        csp.watch(viewer, errors);
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
        await page.locator('#adminsBody tr', { hasText: 'second' }).locator('button[data-on-click^="editAdmin"]').click();
        await page.waitForSelector('#editAdminModal.show');
        await page.selectOption('#editRole', 'operator');
        await page.click('#editAdminModal .btn-primary');
        await page.waitForFunction(() => document.querySelector('#adminsBody .role-badge.operator') !== null);
        await viewer.goto(BASE + '/mailboxes');
        check('promoted to operator: the mailboxes are editable at the next page, no new sign-in',
            await viewer.locator('.topbar-readonly').count() === 0);
        await page.locator('#adminsBody tr', { hasText: 'second' }).locator('button[data-on-click^="deleteAdmin"]').click();
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
        // Closing ssh does not stop the server on the other side.
        if (REMOTE) { try { remote('pkill -f ' + q('LoginE2EServer ' + PORT) + ' || true'); } catch (e) { } }
    }
    console.log(failures === 0 ? '\nAll checks passed.' : '\nFailed checks: ' + failures);
    process.exit(failures === 0 ? 0 : 1);
})();
