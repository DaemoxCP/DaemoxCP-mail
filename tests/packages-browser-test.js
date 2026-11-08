// The "Packages" card of the Updates page in Chromium, on the English page, with the simulated
// server: the real reads (pkg version, pkg query, pkg audit) are tested by PackagePlanTest. Here it
// is checked that the card reads itself, that every row says version, vulnerability and lock as
// text, that the Update button opens the window with the exact plan and asks for the package name
// before starting, that it follows the job to its outcome, that Lock/Unlock send the right name,
// that the panel's JDK points to its procedure and that a vulnerability's header gives the same
// verdict as the detail (it was "the update fixes it" above an "the update is not enough").
//
// Usage (from the project root, after mvn package):
//   D=$(mktemp -d) && javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/content/PageGenerator.java \
//     && java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.content.PageGenerator $D >/dev/null
//   NODE_PATH=$(npm root -g) node tests/packages-browser-test.js $D [screenshot-folder]
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const csp = require('./browser-csp');

const pageList = process.argv[2];
const photos = process.argv[3];
const resourceList = path.join(__dirname, '..', 'src', 'main', 'resources');
const BASE = 'http://panel.test';
let failedOnes = 0;
function real(whatItem, ok) {
    console.log((ok ? '  OK   ' : '  FAILED ') + whatItem);
    if (!ok) failedOnes++;
}

const requests = [];
let rounds = 0, readings = 0;

const VULN_NGINX = { verdict: 'fixed-by-upgrade', installedVersion: '1.30.4,3', catalog: '1.30.5_1,3', firstFixed: '1.30.5,3',
    explanation: 'Yes: upgrading to 1.30.5_1,3, which your catalog offers, fixes the problem.',
    issues: [{ description: 'nginx -- buffer overflow <img src=x onerror="window.injectedRan=1">', cve: ['CVE-2026-90439'],
                 url: 'https://vuxml.FreeBSD.org/freebsd/7dc8fd4b.html' }] };
const VULN_EXPAT = { verdict: 'upgrade-not-enough', installedVersion: '2.8.1', catalog: '2.8.4', firstFixed: '2.8.5',
    explanation: 'The catalog offers 2.8.4, but VuXML still considers it vulnerable. The fix is from 2.8.5.',
    issues: [{ description: 'libexpat -- Improper Handling of Unicode Encoding', cve: ['CVE-2026-93990'], url: 'https://vuxml.FreeBSD.org/freebsd/7fed71c4.html' }] };

function overview() {
    return { success: true,
        summary: { updates: 7, stackUpdates: 4, vulnerable: 2, fixable: 1, locked: 3, stackUnlocked: 1, panelRestart: false },
        packages: [
            { name: 'nginx', installed: '1.30.4,3', available: '1.30.5_1,3', update: true, locked: true, stack: true, role: 'Webmail web server',
              majorJump: false, canUpdate: true, whyNot: '', vuln: VULN_NGINX },
            { name: 'dovecot-mysql', installed: '2.3.21.1_3', available: '2.4.2', update: true, locked: true, stack: true, role: 'Dovecot component',
              majorJump: true, canUpdate: false, whyNot: 'Dovecot 2.4 rewrites the configuration: wait for the dedicated procedure.',
              advisory: { level: 'wait', text: 'Dovecot 2.4 rewrites the configuration: wait for the dedicated procedure.' } },
            { name: 'openjdk25', installed: '25.0.3+9.f.1', available: '25.0.4+7.f.1_1', update: true, locked: true, stack: true, role: 'Java runtime',
              inUse: 'the panel runs on this', panelRuntime: true, javaFlow: true, canUpdate: false,
              whyNot: 'The panel runs on this Java: it is updated with its own procedure.' },
            { name: 'clamav', installed: '1.5.4_1,1', available: '', update: false, locked: false, stack: true, role: 'Antivirus', canUpdate: false, whyNot: '' },
            { name: 'expat', installed: '2.8.1', available: '2.8.4', update: true, locked: false, stack: false, role: '', canUpdate: true, whyNot: '', vuln: VULN_EXPAT },
        ],
        others: [{ name: 'curl', installed: '8.20.0', available: '8.22.0' }, { name: 'pcre2', installed: '10.47_1', available: '10.49' }] };
}

function json(route, bodyText) { return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(bodyText) }); }

async function served(route) {
    const req = route.request();
    const url = new URL(req.url());
    const p = url.pathname;
    if (p === '/updates') {
        const html = fs.readFileSync(path.join(pageList, 'updates.en.html'), 'utf8').replace(/\{\{CSRF_TOKEN\}\}/g, 'csrf-test');
        return route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: html, headers: csp.headers(pageList) });
    }
    if (p.startsWith('/assets/')) return csp.asset(route, pageList, p);
    if (p.startsWith('/i18n/')) return route.fulfill({ status: 200, contentType: 'application/javascript', body: fs.readFileSync(path.join(pageList, p)) });
    if (p.startsWith('/vendor/') || p.startsWith('/fa/')) {
        const f = path.join(resourceList, p);
        if (!fs.existsSync(f)) return route.fulfill({ status: 404, body: '' });
        const kindValue = p.endsWith('.css') ? 'text/css' : p.endsWith('.js') ? 'application/javascript' : p.endsWith('.woff2') ? 'font/woff2' : 'application/octet-stream';
        return route.fulfill({ status: 200, contentType: kindValue, body: fs.readFileSync(f) });
    }
    const bodyText = req.postData() ? JSON.parse(req.postData()) : null;
    requests.push({ method: req.method(), path: p, body: bodyText });
    if (p !== '/api/updates' || !bodyText) return json(route, { success: true });
    switch (bodyText.action) {
        case 'packages_overview': readings++; return json(route, overview());
        case 'packages_lock': return json(route, { success: true, changed: 1, output: '  ' + bodyText.package + ': ' + (bodyText.lock ? 'locked' : 'unlocked') + '\n' });
        case 'package_preflight': return json(route, { success: true, name: bodyText.package, current: '1.30.4,3', available: '1.30.5_1,3',
            signature: '0123456789abcdef', blocked: false, canProceed: true, cve: ['CVE-2026-90439'],
            services: [{ name: 'nginx', running: true }],
            checks: [{ level: 'ok', label: 'Package installed', detail: 'nginx 1.30.4,3' },
                     { level: 'review', label: 'Warning', detail: 'Check the virtual hosts again after the restart.' }],
            plan: { measured: true, unlockedPackages: ['nginx'], command: 'pkg upgrade -n -U nginx', onBackup: true,
                     changes: [{ type: 'upgrade', name: 'nginx', from: '1.30.4,3', to: '1.30.5_1,3', reason: '', repo: 'FreeBSD-ports' }], blockers: [] } });
        case 'package_update':
            rounds = 0;
            return json(route, { success: true, jobId: 'guid-1', async: true });
        case 'job_status':
            rounds++;
            if (rounds < 2) return json(route, { success: true, job: { status: 'running', percent: 50, consoleLog: '[3/6] Upgrading...\n' } });
            return json(route, { success: true, job: { status: 'completed', percent: 100, elapsedSeconds: 12, errorMessage: '',
                consoleLog: '[3/6] Upgrading...\n[6/6] Locking again...\n=== nginx 1.30.5_1,3 in service ===\n' } });
        case 'updates_status': return json(route, { success: true, dryRun: 'Your packages are up to date.', upToDate: false,
            vulnerable: [
                { name: 'expat', role: '', locked: false, fixedByUpgrade: true, updateAvailable: true, cve: ['CVE-2026-93990'], fix: VULN_EXPAT },
                { name: 'nginx', role: 'Webmail web server', locked: true, fixedByUpgrade: false, updateAvailable: true, cve: ['CVE-2026-90439'], fix: VULN_NGINX },
            ], lockedUpdates: [], affectedMailPackages: [] });
        default: return json(route, { success: true });
    }
}

(async () => {
    const browser = await chromium.launch({ executablePath: process.env.CHROMIUM || '/opt/pw-browsers/chromium-1194/chrome-linux/chrome' }).catch(() => chromium.launch());
    const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
    await ctx.route('**/*', served);
    const page = await ctx.newPage();
    const errorList = [];
    page.on('pageerror', e => errorList.push(String(e)));
    csp.watch(page, errorList);
    page.on('console', m => { if (m.type() === 'error') errorList.push(m.text()); });

    console.log('\n== The card reads itself ==');
    await page.goto(BASE + '/updates');
    await page.waitForSelector('#pk-body table');
    real('one read when the page opens', readings === 1);
    const head = await page.textContent('#pk-body');
    real('summary: updates, vulnerable, fixable, locked', head.includes('7 updates available') && head.includes('2 vulnerable packages')
        && head.includes('1 can be fixed now') && head.includes('3 locked'));
    real('warning about the mail stack package that is not locked, with the button to lock them', head.includes('1 mail stack package is not locked')
        && await page.locator('#pk-body .alert button', { hasText: 'Lock all mail stack packages' }).count() === 1);
    const lineItems = await page.$$eval('#pk-body tbody tr:not([hidden])', tr => tr.map(r => r.cells[0].querySelector('code').textContent));
    real('one row per package: ' + lineItems.join(', '), lineItems.join(',') === 'nginx,dovecot-mysql,openjdk25,clamav,expat');
    const nginx = await page.textContent('#pk-body tbody tr:nth-child(1)');
    real('nginx: versions, "the update fixes it", locked', nginx.includes('1.30.4,3') && nginx.includes('1.30.5_1,3')
        && nginx.includes('vulnerable · the update fixes it') && nginx.includes('locked'));
    real('locked nginx still has the Update button (unlock, update, lock again) and Unlock',
        await page.locator('#pk-body button[data-pkg="nginx"]', { hasText: 'Update to 1.30.5_1,3' }).count() === 1
        && await page.locator('#pk-body button[data-pkg="nginx"]', { hasText: 'Unlock' }).count() === 1);
    real('dovecot with the "wait" advisory: no Update, only "held back"',
        await page.locator('#pk-body button[data-pkg="dovecot-mysql"]', { hasText: 'Update' }).count() === 0
        && (await page.textContent('#pk-body tbody tr:nth-of-type(3)')).includes('held back'));
    // Its own procedure is a row of "Update the server", above: here it is said, without a button that jumps there (reperto 193).
    real('the panel\'s JDK says it has its own procedure, without a button', await page.locator('#pk-body .badge', { hasText: 'own procedure' }).count() === 1
        && await page.locator('#pk-body button', { hasText: 'Java update procedure' }).count() === 0);
    real('clamav up to date and not locked: Lock button', (await page.textContent('#pk-body tbody tr:has(code:text-is("clamav"))')).includes('up to date')
        && await page.locator('#pk-body button[data-pkg="clamav"]', { hasText: 'Lock' }).count() === 1);
    real('expat: "the update is not enough"', (await page.textContent('#pk-body tbody tr:has(code:text-is("expat"))')).includes('the update is not enough'));
    real('the other packages, at the end and closed', (await page.textContent('#pk-body details summary')).includes('2 other packages have an update'));
    await page.click('#pk-body tbody tr:nth-child(1) button.btn-link');
    const detailInfo = await page.textContent('#pk-det-0');
    real('nginx details: explanation and CVE with the link to VuXML', detailInfo.includes('fixes the problem') && detailInfo.includes('CVE-2026-90439')
        && await page.getAttribute('#pk-det-0 a', 'href') === 'https://vuxml.FreeBSD.org/freebsd/7dc8fd4b.html');
    real('the description with HTML in it stays text', await page.locator('#pk-body img').count() === 0 && await page.evaluate(() => window.injectedRan) === undefined);
    real('every cell has its label for the phone', await page.locator('#pk-body tbody tr:not([id]) td:not([data-label]):not(.text-end)').count() === 0);
    if (photos) await page.locator('#packages').screenshot({ path: path.join(photos, 'packages-card.png') });

    console.log('\n== Lock and unlock a package ==');
    let beforeValue = requests.length;
    await page.click('#pk-body button[data-pkg="clamav"]:has-text("Lock")');
    await page.waitForFunction(() => document.getElementById('pk-result').textContent.includes('clamav'));
    const lock = requests.slice(beforeValue).find(r => r.body && r.body.action === 'packages_lock');
    real('Lock clamav: sends name, lock=true and CSRF token', lock && lock.body.package === 'clamav' && lock.body.lock === true && lock.body.csrf_token === 'csrf-test');
    await page.waitForSelector('#pk-body table');
    real('and the table reads itself again', readings >= 2);

    console.log('\n== Updating a package: the window ==');
    await page.click('#pk-body button[data-pkg="nginx"]:has-text("Update")');
    await page.waitForSelector('#pkUpdConfirm:not([hidden])');
    const finalText = await page.textContent('#pkUpdModal .modal-content');
    real('title, versions and CVEs closed', finalText.includes('Update nginx') && finalText.includes('1.30.4,3') && finalText.includes('CVE-2026-90439'));
    real('the steps spelled out: unlock, update, restart of nginx, lock again', finalText.includes('Unlock nginx for the duration') && finalText.includes('Restart nginx')
        && finalText.includes('Lock the packages again'));
    real('pkg\'s exact plan and the warning', finalText.includes('pkg upgrade -n -U nginx') && finalText.includes('Check the virtual hosts'));
    real('the button stays off until the name is right', await page.isDisabled('#pkUpdGo'));
    await page.fill('#pkUpdName', 'ngin');
    real('with a wrong name it stays off', await page.isDisabled('#pkUpdGo'));
    await page.fill('#pkUpdName', 'nginx');
    real('with the right name it turns on', !(await page.isDisabled('#pkUpdGo')));
    beforeValue = requests.length;
    await page.click('#pkUpdGo');
    await page.waitForSelector('#pkUpdResult .alert-success', { timeout: 15000 });
    const upd = requests.slice(beforeValue).find(r => r.body && r.body.action === 'package_update');
    real('package_update with package, confirmation, fingerprint and CSRF', upd && upd.body.package === 'nginx' && upd.body.confirm === 'nginx'
        && upd.body.signature === '0123456789abcdef' && upd.body.csrf_token === 'csrf-test');
    real('the job log and the outcome', (await page.textContent('#pkUpdLog')).includes('in service')
        && (await page.textContent('#pkUpdResult')).includes('nginx is updated'));
    if (photos) await page.locator('#pkUpdModal .modal-content').screenshot({ path: path.join(photos, 'packages-window.png') });
    await page.click('#pkUpdModal .btn-close');
    await page.waitForSelector('#pkUpdModal', { state: 'hidden' });

    console.log('\n== Vulnerabilities: the header says the verdict ==');
    // The plan of the packages opens under the row of "Update the server" that asks for it (reperto 193).
    await page.evaluate(() => { ucOpen('packages', 'uc-updates-panel'); updStatus(); });
    await page.waitForSelector('#upd-status li');
    const lis = await page.$$eval('#upd-status li', l => l.map(x => x.textContent));
    real('expat: "not enough" in the header, not "fixes it"', lis[0].includes('the update is not enough') && !lis[0].includes('the update fixes it'));
    real('locked nginx: "fixes it", the lock apart and the Update button', lis[1].includes('the update fixes it') && lis[1].includes('locked')
        && await page.locator('#upd-status li button[data-pkg="nginx"]', { hasText: 'Update to 1.30.5_1,3' }).count() === 1);

    real('no error in the page' + (errorList.length ? ': ' + errorList.join(' | ') : ''), errorList.length === 0);
    await browser.close();
    console.log(failedOnes === 0 ? '\nALL GREEN' : '\n' + failedOnes + ' CHECKS FAILED');
    process.exit(failedOnes === 0 ? 0 : 1);
})();
