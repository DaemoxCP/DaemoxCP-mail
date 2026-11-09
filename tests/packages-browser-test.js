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
// nginx and the PHP family updated by "Update everything" (reperto 207); allJob: the job is that one.
let nginxDone = false, phpDone = false, allJob = false;
// The PHP family's checks stopped by a protected package with its own update (reperto 207): which one, or none.
let phpBlockedBy = '';

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
        case 'package_preflight': if (bodyText.package === 'php84' && phpBlockedBy) return json(route, { success: true, name: 'php84', canProceed: false,
            blocked: true, checks: [{ level: 'block', label: 'Protected package in the way', detail: phpBlockedBy + ' has its own update.' }],
            plan: { measured: true, changes: [], blockers: [{ name: phpBlockedBy, reason: phpBlockedBy + ' has its own update.' }] } });
            if (bodyText.package === 'php84') return json(route, { success: true, name: 'php84', current: '8.4.26',
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
        case 'update_everything':
            rounds = 0; allJob = true; nginxDone = true; phpDone = true;
            return json(route, { success: true, jobId: 'all-1', async: true });
        case 'job_status':
            rounds++;
            if (rounds < 2) return json(route, { success: true, job: { status: 'running', percent: 50, consoleLog: '[3/6] Upgrading...\n' } });
            if (allJob) return json(route, { success: true, job: { status: 'completed', percent: 100, elapsedSeconds: 40, errorMessage: '',
                result: 'All 2 steps done.', consoleLog: '=== Step 1 of 2: nginx ===\n=== Step 2 of 2: php84 ===\n=== All 2 steps done. ===\n' } });
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

    console.log('\n== The Packages row says the state; Update everything, at the top, has the one button (reperto 207) ==');
    await page.goto(BASE + '/updates');
    await page.waitForSelector('#uc-all .uc-head button');
    real('one read when the page opens', readings === 1);
    real('no separate Packages card, no separate row for the mail server packages', await page.$('#packages') === null && await page.$('#uc-stack') === null);
    let row = await page.innerText('#uc-packages .uc-head');
    console.log('    ' + row.replace(/\s+/g, ' '));
    real('how many in one plan, how many of the mail server and in how many steps', row.includes('4 packages to update, all together in one plan')
        && row.includes('5 mail server packages have an update, in 3 steps'));
    real('  the fix available and the vulnerability the update does not fix yet', row.includes('1 security fix available')
        && row.includes('1 package has a known vulnerability that the update does not fix yet'));
    real('  the held one with its reason, the ones to do not repeated here', row.includes('dovecot-mysql: 2.3.21.1_3 → 2.4.2 (Dovecot 2.4 rewrites')
        && !row.includes('nginx: 1.30.4,3') && !row.includes('openjdk25'));
    real('  and no button in this row', await page.$$eval('#uc-packages .uc-head button', b => b.length === 0));
    let top = await page.innerText('#uc-all .uc-head');
    real('a mail server package without protection: Update everything asks to protect it first, with that one button',
        top.includes('1 mail stack package is not locked') && top.includes('Protect them first')
        && await page.$$eval('#uc-all .uc-head button', b => b.length === 1 && b[0].getAttribute('data-on-click') === 'updLockAll(true)'));
    if (photos) await page.locator('#update-center').screenshot({ path: path.join(photos, 'packages-row.png') });

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
    real('no update button in the list, here only Unlock', await page.locator('#pk-body button', { hasText: 'Update' }).count() === 0
        && await page.locator('#pk-body button[data-pkg="nginx"]', { hasText: 'Unlock' }).count() === 1);
    real('dovecot with the "wait" advisory: "held back"', (await page.textContent('#pk-body tbody tr:nth-of-type(3)')).includes('held back'));
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

    console.log('\n== Protect a package: Update everything is the one button now ==');
    let beforeValue = requests.length;
    await page.click('#pk-body button[data-pkg="clamav"]:has-text("Lock")');
    await page.waitForFunction(() => document.getElementById('pk-result').textContent.includes('clamav'));
    const lock = requests.slice(beforeValue).find(r => r.body && r.body.action === 'packages_lock');
    real('Lock clamav: sends name, lock=true and CSRF token', lock && lock.body.package === 'clamav' && lock.body.lock === true && lock.body.csrf_token === 'csrf-test');
    await page.waitForSelector('#uc-all .uc-head button[data-on-click="ucEverything()"]', { timeout: 10000 }).catch(() => {});
    real('the list read itself again', readings >= 2);
    const steps = await page.$$eval('#uc-all .uc-head li', l => l.map(x => x.textContent));
    console.log('    steps: ' + steps.join(' | '));
    real('every package protected: the steps in order, the PHP family one step, one button', steps.length === 3
        && /4 packages, all together in one plan/.test(steps[0]) && /nginx: 1\.30\.4,3 → 1\.30\.5_1,3/.test(steps[1])
        && /php84 and 2 more of its family: 8\.4\.26 → 8\.4\.27_2/.test(steps[2])
        && await page.$$eval('#uc-all .uc-head button', b => b.length === 1 && /Update everything \(3 steps\)/.test(b[0].textContent)));

    console.log('\n== Update everything: a plan that cannot run is left out, cancel changes nothing, one job ==');
    beforeValue = requests.length;
    await page.click('#uc-all .uc-head button[data-on-click="ucEverything()"]');
    await page.waitForSelector('#panelAskModal.show', { timeout: 15000 });
    const ask = await page.innerText('#panelAskModal .modal-content');
    console.log('    ' + ask.replace(/\s+/g, ' ').slice(0, 500));
    const checked = requests.slice(beforeValue).filter(r => r.body && /preflight|updates_status/.test(r.body.action)).map(r => r.body.action + (r.body.package ? ':' + r.body.package : ''));
    real('the checks of every step first: ' + checked.join(', '), checked.join(',') === 'updates_status,package_preflight:nginx,package_preflight:php84');
    real('the plan that would remove a package is left out, with the reason', ask.includes('Left out, the checks stop them: 4 packages, all together in one plan: the plan would remove or downgrade packages'));
    real('  the two that go, numbered, with the services that restart', ask.includes('1. nginx: 1.30.4,3 → 1.30.5_1,3 — restarts nginx')
        && ask.includes('2. php84 and 2 more of its family: 8.4.26 → 8.4.27_2 — restarts php_fpm') && ask.includes('Update everything (2 steps)'));
    await page.click('#panelAskModal .modal-footer [data-bs-dismiss="modal"]');
    await page.waitForSelector('#panelAskModal', { state: 'hidden' });
    await page.waitForTimeout(300);
    top = await page.innerText('#uc-all .uc-head');
    real('cancelled: nothing starts, and a button to update is still there', !requests.slice(beforeValue).some(r => r.body && r.body.action === 'update_everything')
        && await page.$$eval('#uc-all .uc-head button[data-on-click="ucEverything()"]', b => b.length === 1));
    real('  the plan that cannot run is no longer counted as a step', /Update everything \(2 steps\)/.test(top) && !/4 packages, all together/.test(top));
    if (photos) await page.locator('#update-center').screenshot({ path: path.join(photos, 'packages-update-everything.png') });
    await page.click('#uc-all .uc-head button[data-on-click="ucEverything()"]');
    await page.waitForSelector('#panelAskModal.show', { timeout: 15000 });
    beforeValue = requests.length;
    await page.click('#panelAskGo');
    await page.waitForFunction(() => /All 2 steps done/.test(document.getElementById('all-run').innerText), null, { timeout: 15000 }).catch(() => {});
    const all = requests.slice(beforeValue).find(r => r.body && r.body.action === 'update_everything');
    real('ONE request: the word, the two steps with the signatures of their checks, the CSRF token', all && all.body.confirm === 'UPDATE'
        && JSON.stringify(all.body.steps) === JSON.stringify([{ kind: 'package', package: 'nginx', signature: '0123456789abcdef' },
            { kind: 'package', package: 'php84', signature: '1111222233334444' }]) && all.body.csrf_token === 'csrf-test');
    const approved = Object.fromEntries(((all && all.body.approved) || []).map(a => [a.name, a.to]));
    real('  and the changes shown, with their versions', approved.nginx === '1.30.5_1,3' && approved.php84 === '8.4.27_2');
    real('  no window per package', !requests.slice(beforeValue).some(r => r.body && r.body.action === 'package_update'));
    real('the outcome under the row: all the steps done', (await page.innerText('#all-run')).includes('All 2 steps done.'));
    await page.waitForFunction(() => /1 step/.test(document.querySelector('#uc-all .uc-head').innerText), null, { timeout: 10000 }).catch(() => {});
    top = await page.innerText('#uc-all .uc-head');
    real('after: the card reads itself again and offers what is left, the other packages, with the button (it is tried again)',
        /Update everything \(1 step\)/.test(top) && /4 packages, all together in one plan/.test(top) && !/Nothing to update/.test(top));

    // One family left: Update everything for one step, and the Packages row does not count it again (reperto 207).
    const family = unlocked => page.evaluate(u => {
        const php = ['php84', 'php84-ctype', 'php84-curl'].map(n => ({ name: n, installed: '8.4.26', available: '8.4.27_2', update: true,
            locked: true, stack: true, canUpdate: true, whyNot: '', family: '^php[0-9]+(-.+)?$' }));
        uc.pk = { success: true, summary: { updates: 3, stackUpdates: 3, vulnerable: 0, fixable: 0, locked: 3, stackUnlocked: u },
            packages: php, others: [], procedures: {} };
        uc.plainBlocked = false;
        ucRender();
        return document.querySelector('#uc-packages .uc-head').innerText + ' || ' + document.querySelector('#uc-all .uc-head').innerText;
    }, unlocked);
    row = await family(0);
    real('  a family alone: one step in Update everything; the Packages row says its updates are there, without counting them again',
        row.includes('Update everything (1 step)') && row.includes('php84 and 2 more of its family')
        && row.includes('Their updates are steps of «Update everything», above.') && !row.includes('mail server packages of one family'));
    // Not listed above (a package to protect first): then the row counts them, with the sentence of a family.
    row = await family(1);
    real('  not listed above: "3 mail server packages of one family ... in one step", never "in 1 steps"',
        row.includes('3 mail server packages of one family have an update, in one step') && !row.includes('in 1 steps')
        && !row.includes('Their updates are steps'));

    console.log('\n== A step held only by a package an earlier step updates: checked when its turn comes (reperto 207) ==');
    nginxDone = false; phpDone = false; allJob = false; phpBlockedBy = 'nginx';
    await page.goto(BASE + '/updates');
    await page.waitForSelector('#uc-all .uc-head button[data-on-click="ucEverything()"]', { timeout: 10000 });
    await page.click('#uc-all .uc-head button[data-on-click="ucEverything()"]');
    await page.waitForSelector('#panelAskModal.show', { timeout: 15000 });
    let held = await page.innerText('#panelAskModal .modal-content');
    real('PHP, held by nginx which step 1 updates, stays in: after it, "checked when its turn comes, after nginx"',
        held.includes('1. nginx: 1.30.4,3 → 1.30.5_1,3') && held.includes('2. php84 and 2 more of its family: 8.4.26 → 8.4.27_2 — checked when its turn comes, after nginx'));
    beforeValue = requests.length;
    await page.click('#panelAskGo');
    await page.waitForFunction(() => /steps done/.test(document.getElementById('all-run').innerText), null, { timeout: 15000 }).catch(() => {});
    const later = requests.slice(beforeValue).find(r => r.body && r.body.action === 'update_everything');
    const laterShown = Object.fromEntries(((later && later.body.approved) || []).map(a => [a.name, a.to]));
    real('  in the job without a signature, with the versions of the whole family shown', later
        && JSON.stringify(later.body.steps[1]) === JSON.stringify({ kind: 'package', package: 'php84', signature: '' })
        && laterShown.php84 === '8.4.27_2' && laterShown['php84-ctype'] === '8.4.27_2' && laterShown['php84-curl'] === '8.4.27_2');
    nginxDone = false; phpDone = false; allJob = false; phpBlockedBy = 'libfoo';
    await page.goto(BASE + '/updates');
    await page.waitForSelector('#uc-all .uc-head button[data-on-click="ucEverything()"]', { timeout: 10000 });
    await page.click('#uc-all .uc-head button[data-on-click="ucEverything()"]');
    await page.waitForSelector('#panelAskModal.show', { timeout: 15000 });
    held = await page.innerText('#panelAskModal .modal-content');
    real('held by a package no step updates: left out, with the reason', held.replace(/\s+/g, ' ').includes('php84 and 2 more of its family: 8.4.26 → 8.4.27_2: Protected package in the way — libfoo has its own update.')
        && !/\d\. php84/.test(held));
    await page.click('#panelAskModal .modal-footer [data-bs-dismiss="modal"]');
    await page.waitForSelector('#panelAskModal', { state: 'hidden' });

    real('no error in the page' + (errorList.length ? ': ' + errorList.join(' | ') : ''), errorList.length === 0);
    await browser.close();
    console.log(failedOnes === 0 ? '\nALL GREEN' : '\n' + failedOnes + ' CHECKS FAILED');
    process.exit(failedOnes === 0 ? 0 : 1);
})();
