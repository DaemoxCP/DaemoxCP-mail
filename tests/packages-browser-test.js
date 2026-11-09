// The packages of the Updates page in Chromium, on the English page, with the simulated server: the real reads (pkg
// version, pkg query, pkg audit) are tested by PackagePlanTest. Since reperto 202 the packages are ONE row of "Update
// the server" (no separate card, no separate row for the mail server ones): it says how many go in one plan and how many
// of the mail server one at a time, and has one button, the step after: first protect the mail server packages that are
// not locked, then the plan of the others, then the mail server ones one at a time. Under it, closed, the list one by
// one: every row says version, vulnerability and lock as text, with Lock/Unlock and no update button (the row has it).
// Checked: the order of the steps; a plan that cannot run hands the step to the mail server packages; the window of a
// package shows the exact plan and asks for its name before starting, and follows the job to its outcome; Lock sends
// the right name; the panel's JDK points to its procedure; a vulnerability's header gives the same verdict as the
// detail (it was "the update fixes it" above an "the update is not enough").
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
// Locking clamav (or all) protects the only mail server package without protection.
let clamavLocked = false;
// nginx updated from its window, the PHP family with "Update all" (reperto 205); allJob: the job is the update-all one.
let nginxDone = false, phpDone = false, allJob = false;

const VULN_NGINX = { verdict: 'fixed-by-upgrade', installedVersion: '1.30.4,3', catalog: '1.30.5_1,3', firstFixed: '1.30.5,3',
    explanation: 'Yes: upgrading to 1.30.5_1,3, which your catalog offers, fixes the problem.',
    issues: [{ description: 'nginx -- buffer overflow <img src=x onerror="window.injectedRan=1">', cve: ['CVE-2026-90439'],
                 url: 'https://vuxml.FreeBSD.org/freebsd/7dc8fd4b.html' }] };
const VULN_EXPAT = { verdict: 'upgrade-not-enough', installedVersion: '2.8.1', catalog: '2.8.4', firstFixed: '2.8.5',
    explanation: 'The catalog offers 2.8.4, but VuXML still considers it vulnerable. The fix is from 2.8.5.',
    issues: [{ description: 'libexpat -- Improper Handling of Unicode Encoding', cve: ['CVE-2026-93990'], url: 'https://vuxml.FreeBSD.org/freebsd/7fed71c4.html' }] };

function overview() {
    return { success: true,
        summary: { updates: 10 - (nginxDone ? 1 : 0) - (phpDone ? 3 : 0), stackUpdates: 7 - (nginxDone ? 1 : 0) - (phpDone ? 3 : 0), vulnerable: 2, fixable: 1, locked: clamavLocked ? 7 : 6, stackUnlocked: clamavLocked ? 0 : 1, panelRestart: false },
        packages: [
            { name: 'nginx', installed: nginxDone ? '1.30.5_1,3' : '1.30.4,3', available: nginxDone ? '' : '1.30.5_1,3', update: !nginxDone, locked: true, stack: true, role: 'Webmail web server',
              majorJump: false, canUpdate: true, whyNot: '', vuln: VULN_NGINX },
            { name: 'dovecot-mysql', installed: '2.3.21.1_3', available: '2.4.2', update: true, locked: true, stack: true, role: 'Dovecot component',
              majorJump: true, canUpdate: false, whyNot: 'Dovecot 2.4 rewrites the configuration: wait for the dedicated procedure.',
              advisory: { level: 'wait', text: 'Dovecot 2.4 rewrites the configuration: wait for the dedicated procedure.' } },
            { name: 'openjdk25', installed: '25.0.3+9.f.1', available: '25.0.4+7.f.1_1', update: true, locked: true, stack: true, role: 'Java runtime',
              inUse: 'the panel runs on this', panelRuntime: true, javaFlow: true, canUpdate: false,
              whyNot: 'The panel runs on this Java: it is updated with its own procedure.' },
            { name: 'clamav', installed: '1.5.4_1,1', available: '', update: false, locked: clamavLocked, stack: true, role: 'Antivirus', canUpdate: false, whyNot: '' },
            { name: 'expat', installed: '2.8.1', available: '2.8.4', update: true, locked: false, stack: false, role: '', canUpdate: true, whyNot: '', vuln: VULN_EXPAT },
            // A family (reperto 203): php84 and its extensions go together, so they are ONE step of the row.
            ...['php84', 'php84-ctype', 'php84-curl'].map(n => ({ name: n, installed: phpDone ? '8.4.27_2' : '8.4.26', available: phpDone ? '' : '8.4.27_2', update: !phpDone, locked: true, stack: true,
              role: n === 'php84' ? 'PHP' : 'PHP extension', canUpdate: true, whyNot: '', family: '^php[0-9]+(-.+)?$',
              familyReason: 'PHP and its extensions share the version number' })),
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
        case 'packages_lock':
            if (bodyText.lock && (bodyText.package === 'clamav' || bodyText.package === '')) clamavLocked = true;
            return json(route, { success: true, changed: 1, output: '  ' + bodyText.package + ': ' + (bodyText.lock ? 'locked' : 'unlocked') + '\n' });
        // The PHP family's checks, for "Update all": its own plan and signature, php-fpm to restart.
        case 'package_preflight': if (bodyText.package === 'php84') return json(route, { success: true, name: 'php84', current: '8.4.26',
            available: '8.4.27_2', signature: '1111222233334444', blocked: false, canProceed: true, services: [{ name: 'php_fpm', running: true }],
            family: ['php84', 'php84-ctype', 'php84-curl'], checks: [{ level: 'ok', label: 'Package installed', detail: 'php84 8.4.26' }],
            plan: { measured: true, unlockedPackages: ['php84', 'php84-ctype', 'php84-curl'], command: 'pkg upgrade -n -U php84 php84-ctype php84-curl',
                    changes: [{ type: 'upgrade', name: 'php84', from: '8.4.26', to: '8.4.27_2' }], blockers: [] } });
            return json(route, { success: true, name: bodyText.package, current: '1.30.4,3', available: '1.30.5_1,3',
            signature: '0123456789abcdef', blocked: false, canProceed: true, cve: ['CVE-2026-90439'],
            services: [{ name: 'nginx', running: true }],
            checks: [{ level: 'ok', label: 'Package installed', detail: 'nginx 1.30.4,3' },
                     { level: 'review', label: 'Warning', detail: 'Check the virtual hosts again after the restart.' }],
            plan: { measured: true, unlockedPackages: ['nginx'], command: 'pkg upgrade -n -U nginx', onBackup: true,
                     changes: [{ type: 'upgrade', name: 'nginx', from: '1.30.4,3', to: '1.30.5_1,3', reason: '', repo: 'FreeBSD-ports' }], blockers: [] } });
        case 'package_update':
            rounds = 0; allJob = false;
            if (bodyText.package === 'nginx') nginxDone = true;
            return json(route, { success: true, jobId: 'guid-1', async: true });
        case 'guided_update_all':
            rounds = 0; allJob = true; nginxDone = true; phpDone = true;
            return json(route, { success: true, jobId: 'guid-all-1', async: true });
        case 'job_status':
            rounds++;
            if (rounds < 2) return json(route, { success: true, job: { status: 'running', percent: 50, consoleLog: '[3/6] Upgrading...\n' } });
            if (allJob) return json(route, { success: true, job: { status: 'completed', percent: 100, elapsedSeconds: 40, errorMessage: '',
                result: 'All 2 steps done: nginx, php84.', consoleLog: '=== Step 1 of 2: nginx ===\n=== Step 2 of 2: php84 ===\n=== All 2 steps done: nginx, php84. ===\n' } });
            return json(route, { success: true, job: { status: 'completed', percent: 100, elapsedSeconds: 12, errorMessage: '',
                consoleLog: '[3/6] Upgrading...\n[6/6] Locking again...\n=== nginx 1.30.5_1,3 in service ===\n' } });
        // The plan of the other packages would remove lmdb: it does not run from here (reperto 36), and the step after
        // passes to the mail server packages.
        case 'updates_status': return json(route, { success: true, dryRun: 'Your packages are up to date.', upToDate: false, signature: 'fedcba9876543210',
            plan: { measured: true, command: 'pkg upgrade -n', changes: [{ type: 'remove', name: 'lmdb', from: '1.0.2,1', to: '' },
                { type: 'upgrade', name: 'expat', from: '2.8.1', to: '2.8.4' }], blockers: [] },
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

    console.log('\n== The Packages row: one, with the step after ==');
    await page.goto(BASE + '/updates');
    await page.waitForSelector('#uc-packages .uc-head button');
    real('one read when the page opens', readings === 1);
    real('no separate Packages card, no separate row for the mail server packages', await page.$('#packages') === null && await page.$('#uc-stack') === null);
    let row = await page.innerText('#uc-packages .uc-head');
    console.log('    ' + row.replace(/\s+/g, ' '));
    real('how many in one plan, how many of the mail server one at a time', row.includes('4 packages to update, all together in one plan')
        && row.includes('5 mail server packages have an update, in 3 steps: they are protected, and each step has its check'));
    real('  the fix available and the vulnerability the update does not fix yet', row.includes('1 security fix available')
        && row.includes('1 package has a known vulnerability that the update does not fix yet'));
    real('  the mail server ones by name, the held one with its reason, not the JDK (its own procedure)',
        row.includes('nginx: 1.30.4,3 → 1.30.5_1,3') && row.includes('dovecot-mysql: 2.3.21.1_3 → 2.4.2 (Dovecot 2.4 rewrites') && !row.includes('openjdk25'));
    real('  the PHP family is one line, not three: php84 and 2 more of its family', row.includes('php84 and 2 more of its family: 8.4.26 → 8.4.27_2')
        && !row.includes('php84-ctype') && !row.includes('php84-curl'));
    real('a mail server package without protection: said, and protecting them is the step, before the plan',
        row.includes('1 mail stack package is not locked')
        && await page.$$eval('#uc-packages .uc-head button', b => b.length === 1 && b[0].getAttribute('data-on-click') === 'updLockAll(true)'));
    if (photos) await page.locator('#uc-packages').screenshot({ path: path.join(photos, 'packages-row.png') });

    console.log('\n== The list under it, closed ==');
    real('the list is under the row and closed', await page.$eval('#uc-packages #pk-list', d => !d.open));
    await page.click('#pk-list summary');
    await page.waitForSelector('#pk-body table');
    const head = await page.textContent('#pk-body');
    real('summary: updates, vulnerable, fixable, locked', head.includes('10 updates available') && head.includes('2 vulnerable packages')
        && head.includes('1 can be fixed now') && head.includes('6 locked'));
    real('warning about the mail stack package that is not locked, with the button to lock them', head.includes('1 mail stack package is not locked')
        && await page.locator('#pk-body .alert button', { hasText: 'Lock all mail stack packages' }).count() === 1);
    const lineItems = await page.$$eval('#pk-body tbody tr:not([hidden])', tr => tr.map(r => r.cells[0].querySelector('code').textContent));
    real('one row per package: ' + lineItems.join(', '), lineItems.join(',') === 'nginx,dovecot-mysql,openjdk25,clamav,expat,php84,php84-ctype,php84-curl');
    const nginx = await page.textContent('#pk-body tbody tr:nth-child(1)');
    real('nginx: versions, "the update fixes it", locked', nginx.includes('1.30.4,3') && nginx.includes('1.30.5_1,3')
        && nginx.includes('vulnerable · the update fixes it') && nginx.includes('locked'));
    real('no update button in the list: the row above has the step (reperto 202), here only Unlock',
        await page.locator('#pk-body button', { hasText: 'Update' }).count() === 0
        && await page.locator('#pk-body button[data-pkg="nginx"]', { hasText: 'Unlock' }).count() === 1);
    real('dovecot with the "wait" advisory: "held back"', (await page.textContent('#pk-body tbody tr:nth-of-type(3)')).includes('held back'));
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
    if (photos) await page.locator('#uc-packages').screenshot({ path: path.join(photos, 'packages-list.png') });

    console.log('\n== Lock a package: the step after moves to the plan ==');
    let beforeValue = requests.length;
    await page.click('#pk-body button[data-pkg="clamav"]:has-text("Lock")');
    await page.waitForFunction(() => document.getElementById('pk-result').textContent.includes('clamav'));
    const lock = requests.slice(beforeValue).find(r => r.body && r.body.action === 'packages_lock');
    real('Lock clamav: sends name, lock=true and CSRF token', lock && lock.body.package === 'clamav' && lock.body.lock === true && lock.body.csrf_token === 'csrf-test');
    await page.waitForFunction(() => /Update the packages/.test(document.querySelector('#uc-packages .uc-head').innerText), null, { timeout: 10000 }).catch(() => {});
    real('the list read itself again', readings >= 2);
    row = await page.innerText('#uc-packages .uc-head');
    real('every mail server package protected: the step is the plan of the others, one button',
        !row.includes('is not locked') && await page.$$eval('#uc-packages .uc-head button', b => b.length === 1 && b[0].getAttribute('data-on-click') === 'ucPackages()'));

    console.log('\n== A plan that cannot run: the step passes to the mail server packages ==');
    await page.click('#uc-packages .uc-head button[data-on-click="ucPackages()"]');
    await page.waitForSelector('#upd-status li');
    real('the plan would remove a package: it does not start, and it says why', (await page.innerText('#pk-run')).includes('would remove or downgrade')
        && !requests.some(r => r.body && r.body.action === 'updates_apply'));
    await page.waitForSelector('#uc-packages .uc-head button[data-on-click="ucUpdateAll()"]', { timeout: 5000 }).catch(() => {});
    row = await page.innerText('#uc-packages .uc-head');
    real('  the step after is ONE button for the mail server steps: Update all (2 steps: nginx, the PHP family) (reperto 205)',
        row.includes('Update all (2 steps)') && await page.$$eval('#uc-packages .uc-head button', b => b.length === 1));

    console.log('\n== Vulnerabilities: the header says the verdict ==');
    const lis = await page.$$eval('#upd-status li', l => l.map(x => x.textContent));
    real('expat: "not enough" in the header, not "fixes it"', lis[0].includes('the update is not enough') && !lis[0].includes('the update fixes it'));
    real('locked nginx: "fixes it", the lock apart', lis[1].includes('the update fixes it') && lis[1].includes('locked'));

    console.log('\n== Update all: one confirmation, one job (reperto 205) ==');
    beforeValue = requests.length;
    await page.click('#uc-packages .uc-head button[data-on-click="ucUpdateAll()"]');
    await page.waitForSelector('#panelAskModal.show', { timeout: 15000 });
    const ask = await page.innerText('#panelAskModal .modal-content');
    console.log('    ' + ask.replace(/\s+/g, ' ').slice(0, 400));
    const checked = requests.slice(beforeValue).filter(r => r.body && r.body.action === 'package_preflight').map(r => r.body.package);
    real('the checks of every step first, as its window does: ' + checked.join(', '), checked.join(',') === 'nginx,php84');
    real('one confirmation with every step, its versions and the services that restart',
        ask.includes('nginx: 1.30.4,3 → 1.30.5_1,3 — restarts nginx') && ask.includes('php84 and 2 more of its family: 8.4.26 → 8.4.27_2 — restarts php_fpm'));
    real('  what happens: one after the other, it stops at the first that does not go well', ask.includes('stops at the first step that does not go well')
        && ask.includes('Update all 2 steps'));
    await page.click('#panelAskModal .modal-footer [data-bs-dismiss="modal"]');
    await page.waitForSelector('#panelAskModal', { state: 'hidden' });
    real('cancelled: nothing starts', !requests.slice(beforeValue).some(r => r.body && r.body.action === 'guided_update_all'));
    if (photos) await page.locator('#uc-packages').screenshot({ path: path.join(photos, 'packages-update-all.png') });
    await page.click('#uc-packages .uc-head button[data-on-click="ucUpdateAll()"]');
    await page.waitForSelector('#panelAskModal.show', { timeout: 15000 });
    beforeValue = requests.length;
    await page.click('#panelAskGo');
    await page.waitForFunction(() => /All 2 steps done/.test(document.getElementById('pk-run').innerText), null, { timeout: 15000 }).catch(() => {});
    const all = requests.slice(beforeValue).find(r => r.body && r.body.action === 'guided_update_all');
    real('ONE request for the job: the keyword, every step with the signature of the plan shown, the CSRF token', all && all.body.confirm === 'UPDATE'
        && JSON.stringify(all.body.steps) === JSON.stringify([{ package: 'nginx', signature: '0123456789abcdef' }, { package: 'php84', signature: '1111222233334444' }])
        && all.body.csrf_token === 'csrf-test');
    real('  no window per package', !requests.slice(beforeValue).some(r => r.body && r.body.action === 'package_update'));
    real('the outcome under the row: all the steps done', (await page.innerText('#pk-run')).includes('All 2 steps done: nginx, php84.'));

    console.log('\n== One step left: its own window ==');
    // A new page where only nginx is left (the PHP family done): one step, so its own button and window.
    nginxDone = false; phpDone = true; allJob = false;
    await page.goto(BASE + '/updates');
    await page.waitForSelector('#uc-packages .uc-head button[data-on-click="ucPackages()"]');
    await page.click('#uc-packages .uc-head button[data-on-click="ucPackages()"]');
    await page.waitForSelector('#uc-packages .uc-head button[data-pkg="nginx"]', { timeout: 5000 }).catch(() => {});
    real('one step left: no "Update all", the step by name: nginx (1 of 1)', (await page.innerText('#uc-packages .uc-head')).includes('Update nginx (1 of 1)')
        && await page.$('#uc-packages .uc-head button[data-on-click="ucUpdateAll()"]') === null);
    await page.click('#uc-packages .uc-head button[data-pkg="nginx"]');
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
    await page.waitForFunction(() => /None can be updated from here/.test(document.querySelector('#uc-packages .uc-head').innerText), null, { timeout: 10000 }).catch(() => {});
    row = await page.innerText('#uc-packages .uc-head');
    real('after nginx only dovecot is left, held with its reason, and no button for it', row.includes('None can be updated from here')
        && row.includes('Dovecot 2.4 rewrites') && await page.$('#uc-packages .uc-head button[data-pkg]') === null);
    // Only one family left: not "in 1 steps", its own sentence. The row drawn again from an overview with PHP alone.
    row = await page.evaluate(() => {
        const php = ['php84', 'php84-ctype', 'php84-curl'].map(n => ({ name: n, installed: '8.4.26', available: '8.4.27_2', update: true,
            locked: true, stack: true, canUpdate: true, whyNot: '', family: '^php[0-9]+(-.+)?$' }));
        uc.pk = { success: true, summary: { updates: 3, stackUpdates: 3, vulnerable: 0, fixable: 0, locked: 3, stackUnlocked: 0 },
            packages: php, others: [], procedures: {} };
        uc.plainBlocked = false;
        ucRender();
        return document.querySelector('#uc-packages .uc-head').innerText;
    });
    real('  a family alone: "3 mail server packages of one family ... in one step", the button for the family',
        row.includes('3 mail server packages of one family have an update: they are protected, and they go together in one step')
        && !row.includes('steps') && row.includes('Update php84 and 2 more (1 of 1)'));

    real('no error in the page' + (errorList.length ? ': ' + errorList.join(' | ') : ''), errorList.length === 0);
    await browser.close();
    console.log(failedOnes === 0 ? '\nALL GREEN' : '\n' + failedOnes + ' CHECKS FAILED');
    process.exit(failedOnes === 0 ? 0 : 1);
})();
