// Updating from the panel (reperti 185-187), in Chromium with a simulated server and the panel's CSP.
//
//  1. The restart banner at the top of every page (Updates and Home), with the reason and the button;
//     on the Italian page the text is the one of it.json.
//  2. "Update the server" (reperto 207): at the top "Update everything", the numbered list of what it will do, in order
//     (the FreeBSD patches, the other packages in one plan, the mail server steps, Roundcube, the panel's Java last) and
//     ONE button; below, the state of FreeBSD and of the packages without update buttons, no rows for Java and
//     Roundcube, the restart with its button. The branch has its own card (reperto 205). In words, not only by color.
//  3. "Update everything": the checks of every step, one confirmation with the numbered steps (the panel's window, not
//     the browser's); cancelling starts nothing and the button stays; confirming sends ONE request with every step's
//     signature and the changes shown; the outcome under the row; the card reads itself again (the restart left).
//  4b. A new FreeBSD release, one step at a time: only when there is one; four steps, only the current one with its
//     button; check and prepare with one confirmation, the command from SSH, the install, the final check by itself.
//  4c. The checks stop the preparation: only the rows that stop it, and nothing starts.
//  9. Diagnostics, check everything (reperto 199): one button, every read-only check in turn, first what needs a look
//     (most important first), each with one button for its next step; what is fine closed below.
//  4d. Roundcube is a step of "Update everything", before Java: its checks with the others, its signature in the job;
//      when its checks stop it, it is left out with the reason and the rest still goes.
//  5. The restart window: what stops, the chosen delay, the time, cancelling; Escape closes it.
//  6. Reads queue up: two "System state" calls at once both answer.
//  7. At 375 px: no horizontal scrolling, 44 px buttons.
//  10. A restart scheduled (reperto 200): the strip says the time and that the panel only reads; a button of the page
//      does nothing and says why (once); a change the server refuses (409) makes the strip read again; cancelling
//      unlocks the page. With a job running, the restart window says which and has no restart button.
//  11. A job in progress started elsewhere (reperto 206): the card says what and since when, with its log closed below;
//      the buttons of the steps and "Check for updates" wait, saying why; when it ends the line goes, the buttons come back
//      and the card reads itself again.
//
// Usage (from the project root, with the pages of PageGenerator in $D, see csp-browser-test.js):
//   NODE_PATH=$(npm root -g) node tests/update-center-browser-test.js $D [screenshot-folder]
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const csp = require('./browser-csp');

const pages = process.argv[2];
const shots = process.argv[3];
const resources = path.join(__dirname, '..', 'src', 'main', 'resources');
const IT = JSON.parse(fs.readFileSync(path.join(resources, 'lang', 'it.json'), 'utf8'));
const fill = (text, values) => text.replace(/\{([A-Za-z0-9_]+)\}/g, (all, k) => (k in values ? String(values[k]) : all));
const BASE = 'https://panel.test';
let failed = 0;
function check(what, ok) {
    console.log((ok ? '  OK   ' : '  FAILED ') + what);
    if (!ok) failed++;
}

const PLAN = { measured: true, command: 'pkg upgrade -n', changes: [
    { type: 'upgrade', name: 'libX11', from: '1.8.12,1', to: '1.8.14,1', reason: 'CVE-2026-88806' },
    { type: 'upgrade', name: 'brotli', from: '1.1.0,1', to: '1.2.1,1' },
    // On the VM the plan of the other packages also reinstalled cyrus-sasl: not an update (reperto 207).
    { type: 'reinstall', name: 'cyrus-sasl', from: '2.1.28_6', to: '2.1.28_6' }] };
// st is the server's state for one page: what the actions so far have changed.
function replies(o, st) {
    return {
        os_status: st.patched || st.allDone
            ? { success: true, installedKernel: '15.1-RELEASE-p5', uname: '15.1-RELEASE', userland: '15.1-RELEASE-p6', arch: 'arm64 GENERIC',
                restartNeeded: true, series: '15.1', updatableWithFreebsdUpdate: true, readyExist: false }
            : { success: true, installedKernel: '15.1-RELEASE', uname: '15.1-RELEASE', userland: '15.1-RELEASE', arch: 'arm64 GENERIC',
                restartNeeded: false, endOfSupport: '2027-03-31', supportNotes: '', supportSource: 'freebsd.org', series: '15.1',
                updatableWithFreebsdUpdate: true, readyExist: !o.noPatches, readyTarget: '15.1-RELEASE-p6', readyKernel: true },
        os_upgrade_targets: { success: true, current: '15.1', versions: o.targets ? [{ version: '15.2', endOfSupport: '30/06/2027', note: '' }] : [] },
        jump_state: { success: true, inProgress: !!st.phase, phase: st.phase || '', target: st.phase ? '15.2' : '', upgradeFetched: !!st.fetched,
            steps: [], restartNeeded: false, bootEnvironment: 'before-upgrade-15.2' },
        os_upgrade_preflight: o.blocked
            ? { success: true, blocked: true, checks: [{ label: 'Restart pending', level: 'block', detail: 'Restart the server first.' },
                { label: 'Current version', level: 'ok', detail: '15.1-RELEASE' }] }
            : { success: true, blocked: false, checks: [{ label: 'Current version', level: 'ok', detail: '15.1-RELEASE' },
                { label: 'Space', level: 'ok', detail: 'Enough.' }, { label: 'Boot environments', level: 'ok', detail: 'ZFS.' }] },
        os_upgrade_prepare: { success: true, jobId: 'prep-1' },
        roundcube_preflight: o.rcBlocked
            ? { success: true, blocked: true, canProceed: false, checks: [{ label: 'Database copy', level: 'block', detail: 'No space for the copy of the database.' },
                { label: 'Version', level: 'ok', detail: '1.6.11 -> 1.7.0' }] }
            : { success: true, blocked: false, canProceed: true, signature: 'fedcba9876543210', checks: [{ label: 'Version', level: 'ok', detail: '1.6.11 -> 1.7.0' },
                { label: 'Downtime', level: 'wait', detail: 'The webmail is off for about a minute.' }],
                plan: { measured: true, command: 'pkg upgrade -n', changes: [{ type: 'upgrade', name: 'roundcube-php84', from: '1.6.11', to: '1.7.0' }] } },
        roundcube_update: { success: true, jobId: 'rc-1' },
        // Diagnostics: two to look at (a failed job, a newer standard), one step (patches ready), the rest fine.
        journal_list: { success: true, dir: '/var/db/mailpanel/jobs', journals: [
            { name: '20261109-000000-os-patch__osp-1.log', type: 'os-patch', startedUtc: '2026-11-09T00:00:00Z', status: 'error', bytes: 100 },
            { name: '20261108-230000-search__srch-1.log', type: 'search', startedUtc: '2026-11-08T23:00:00Z', status: 'completed', bytes: 90 }] },
        journal_read: { success: true, name: '20261109-000000-os-patch__osp-1.log', truncated: false, text: '=== job osp-1 (os-patch) started ===\n=== end: error ===' },
        watch: { success: true, replaced: 0, updated: 1, unread: 0, note: '1 standard has a newer version.', standard: [], source: 'rfc-editor' },
        broken_libs: { success: true, packages: [] },
        compatibility: { success: true, dovecot: { scanned: true, compatible24: true, doveconfOk: true }, postfix: { verdict: 'ALIGNED' },
            rspamd: { verdict: 'NOTHING_TO_REPORT' }, mysql: { present: true, issues: [], eol: false }, webmail: { consistent: true } },
        java_status: { success: true, present: false },
        web_diagnosis: { success: true, plainContents: false, verdict: 'nginx serves only what it should.' },
        defaults_check: { success: true, lines: [{ component: 'OpenSSL', outcome: 'consistent' }] },
        panel_env: { success: true, unreachable: false, absent: false, explanation: 'Every tool is reachable.', tools: [] },
        jump_continue: { success: true, jobId: 'jump-1' },
        jump_cancel: { success: true, note: 'Move cancelled.' },
        os_upgrade_verify: { success: true, allGood: true, checks: [{ label: 'Services', level: 'ok', detail: 'All up.' }], environments: { success: false } },
        // After "Update everything" (st.allDone, reperto 207) nothing is left; before, the other packages, dovecot and Java.
        packages_overview: st.allDone ? { success: true, procedures: { java: false, roundcube: false, roundcubePackage: 'roundcube-php84', mysql84: false, python: false },
            summary: { updates: 0, stackUpdates: 0, vulnerable: 1, fixable: 0, locked: 39 }, others: [],
            packages: [{ name: 'postfix-mysql', role: 'SMTP', installed: '3.11.7', available: '', update: false, locked: true, stack: true }] }
        : { success: true, procedures: { java: true, roundcube: !!o.roundcube && !st.rcDone, roundcubePackage: 'roundcube-php84', mysql84: false, python: false },
            summary: { updates: st.plainDone ? 2 : 4, stackUpdates: 2, vulnerable: 3, fixable: 2, locked: 39 },
            packages: [
                ...(o.roundcube ? [{ name: 'roundcube-php84', role: 'Webmail', installed: '1.6.11', available: '1.7.0', update: true, locked: true, stack: true, canUpdate: false }] : []),
                { name: 'dovecot-mysql', role: 'IMAP', installed: '2.3.21.1_3', available: '2.3.21.1_4', update: true, locked: true, stack: true, canUpdate: true },
                { name: 'openjdk25', role: 'Java', installed: '25.0.4', available: '25.0.5', update: true, locked: true, stack: true, canUpdate: false, javaFlow: true },
                { name: 'postfix-mysql', role: 'SMTP', installed: '3.11.7', available: '', update: false, locked: true, stack: true }],
            others: st.plainDone ? [] : [{ name: 'libX11', installed: '1.8.12,1', available: '1.8.14,1' }, { name: 'brotli', installed: '1.1.0,1', available: '1.2.1,1' }] },
        branch_status: { success: true, branch: 'quarterly', explanation: 'Quarterly.', changeable: true, destination: ['latest'], panelOwnedFile: false, repository: [] },
        reboot_state: Object.assign({ success: true, state: o.reboot || 'needed', installedKernel: '15.1-RELEASE-p5', runningKernel: '15.1-RELEASE',
            scheduled: !!o.scheduled && !st.cancelled }, o.rebootAt && !st.cancelled ? { at: o.rebootAt } : {}),
        reboot_preview: o.busy
            ? { success: false, busy: 'Package update (dovecot), started 2 minutes ago',
                error: 'Still running: Package update (dovecot), started 2 minutes ago. A restart now would stop it halfway.' }
            : { success: true, services: ['postfix', 'dovecot', 'mysql-server'], minutes: 1, autoStart: { active: true } },
        reboot_now: { success: true, executed: true, pid: '4242' },
        reboot_cancel: { success: true, existedBefore: true },
        updates_status: { success: true, plan: PLAN, signature: '0123456789abcdef', vulnerable: [], lockedUpdates: [] },
        updates_apply: { success: true, jobId: 'upd-1' },
        // The checks of the steps of "Update everything" (reperto 207), and the job itself.
        package_preflight: { success: true, canProceed: true, signature: '1111222233334444', services: [{ name: 'dovecot', running: true }],
            // A new library the new version needs, as lmdb0 for postfix-mysql on the real server (reperto 208).
            plan: { measured: true, changes: [{ type: 'upgrade', name: 'dovecot-mysql', from: '2.3.21.1_3', to: '2.3.21.1_4' },
                { type: 'install', name: 'libsodium', from: '', to: '1.0.21' }] } },
        java_preflight: { success: true, canProceed: true, signature: 'aaaabbbbccccdddd',
            plan: { measured: true, changes: [{ type: 'upgrade', name: 'openjdk25', from: '25.0.4', to: '25.0.5' }] } },
        update_everything: { success: true, jobId: 'all-1' },
        updates_search: { success: true, jobId: 'srch-1' },
        // The job in progress (reperto 206): with o.turn a search holds the turn for the first two reads, then ends.
        // The update of the panel's Java, outside the panel (reperto 210): the turn says it, with the script's log.
        package_turn: o.javaTurn ? { success: true, running: true, java: true, who: "the update of the panel's Java",
                log: '[1/7] Packing the current JVM as a way back...\n[2/7] Downloading the new packages, with the panel still answering...' }
            : o.turn && st.turnCalls <= 2 ? { success: true, running: true, who: 'check for updates, just started', jobId: 'srch-9' }
            : { success: true, running: false },
        os_patch_install: { success: true, jobId: 'osp-1' },
        job_status: { success: true, job: { status: 'completed', consoleLog: 'done', elapsedSeconds: 3,
            result: st.allDone ? 'All 4 steps done: the panel now stops to finish updating its Java, and starts again in a couple of minutes. Then you sign in again.'
                + ' Installed: FreeBSD 15.1-RELEASE-p6. The new kernel (15.1-RELEASE-p6) takes effect with a restart: the panel says so at the top of every page, and you can restart from there.'
                : st.rcDone ? 'Roundcube 1.7.0 is in place and answers.' : 'Lists updated.' } },
        service_users: { success: true, problems: [], pools: [], services: [
            { service: 'php-fpm', users: ['root', 'roundcube'], ok: true, processes: 4,
              rootWhy: 'Root only for the master process <b>bold</b>: it creates the webmail socket.' },
            { service: 'redis', users: ['redis'], ok: true, processes: 1 }] },
    };
}

async function open(ctx, name, lang, o = {}) {
    const page = await ctx.newPage();
    const calls = [], errors = [], dialogs = [], st = {};
    page.on('pageerror', e => errors.push(String(e)));
    page.on('dialog', d => { dialogs.push(d.type() + ': ' + d.message()); d.dismiss(); });
    csp.watch(page, errors);
    await page.route('**/*', async route => {
        const req = route.request();
        const p = new URL(req.url()).pathname;
        if (p.startsWith('/assets/')) return csp.asset(route, pages, p);
        if (p.startsWith('/i18n/')) return route.fulfill({ status: 200, contentType: 'text/javascript', body: fs.readFileSync(path.join(pages, p)) });
        if (p.startsWith('/vendor/') || p.startsWith('/fa/')) {
            const f = path.join(resources, p);
            if (!fs.existsSync(f)) return route.fulfill({ status: 404, body: '' });
            const type = p.endsWith('.css') ? 'text/css' : p.endsWith('.js') ? 'text/javascript' : p.endsWith('.woff2') ? 'font/woff2' : 'application/octet-stream';
            return route.fulfill({ status: 200, contentType: type, body: fs.readFileSync(f) });
        }
        if (p === '/api/updates') {
            const body = JSON.parse(req.postData() || '{}');
            // The database restarting (reperto 209): the server refuses before doing anything, 503 with its header.
            if (st.dbDown > 0) {
                st.dbDown--;
                st.dbRefused = (st.dbRefused || 0) + 1;
                return route.fulfill({ status: 503, contentType: 'application/json', headers: { 'X-Panel-Database': 'unavailable', 'Retry-After': '3' },
                    body: JSON.stringify({ success: false, error: 'The database is not answering (it is restarting): nothing was done. The page tries again by itself.' }) });
            }
            calls.push(body);
            if (o.slow && body.action === 'os_status') await new Promise(r => setTimeout(r, 700));
            if (body.action === 'package_turn') st.turnCalls = (st.turnCalls || 0) + 1;
            const r = replies(o, st)[body.action] || { success: false, error: 'mock' };
            if (body.action === 'os_patch_install') st.patched = true;
            if (body.action === 'os_upgrade_prepare') st.phase = 'prepared';
            if (body.action === 'jump_continue') st.phase = 'finished';
            if (body.action === 'jump_cancel') st.phase = '';
            if (body.action === 'roundcube_update') st.rcDone = true;
            if (body.action === 'updates_apply') st.plainDone = true;
            if (body.action === 'update_everything') st.allDone = true;
            if (body.action === 'reboot_cancel') st.cancelled = true;
            return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(r) });
        }
        // With a restart scheduled the server refuses a change (RestartLock): 409 and the header the pages read.
        if (p === '/api/aliases' && req.method() === 'POST' && o.scheduled && !st.cancelled)
            return route.fulfill({ status: 409, contentType: 'application/json', headers: { 'X-Panel-Restart': 'scheduled' },
                body: JSON.stringify({ success: false, restart_scheduled: true, error: 'A server restart is scheduled.' }) });
        if (p === '/api/panel_info') st.panelInfo = (st.panelInfo || 0) + 1;
        if (p.startsWith('/api/')) return route.fulfill({ status: 200, contentType: 'application/json', body: '{"success":false,"error":"mock"}' });
        const f = path.join(pages, name + (lang === 'it' ? '' : '.' + lang) + '.html');
        const html = fs.readFileSync(f, 'utf8').replace(/\{\{CSRF_TOKEN\}\}/g, 'csrf-test').replace(/\{\{THEME\}\}/g, 'light')
            .replace(/\{\{COLOR_SCHEME\}\}/g, 'light').replace(/\{\{[A-Z_]+\}\}/g, 'x');
        return route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: html, headers: csp.headers(pages) });
    });
    await page.goto(BASE + '/' + name);
    return { page, calls, errors, dialogs, st };
}

// Ready when every row has its data: the card fills in as the other cards' reads arrive.
const centerReady = page => page.waitForFunction(() => document.querySelectorAll('#ucList > li:not([hidden])').length >= 3
    && document.getElementById('ucState').textContent === '' && !document.getElementById('ucList').textContent.includes(t('uc.reading')),
    null, { timeout: 20000 });
const allErrors = [], allDialogs = [];

(async () => {
    const browser = await chromium.launch({ executablePath: process.env.CHROMIUM || '/opt/pw-browsers/chromium' }).catch(() => chromium.launch());
    const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 }, locale: 'en-GB', timezoneId: 'Europe/Rome' });

    console.log('== 1. The restart banner ==');
    let { page, calls, errors, dialogs } = await open(ctx, 'updates', 'en');
    allErrors.push(errors); allDialogs.push(dialogs);
    const shown = await page.waitForSelector('#panelRebootBanner:not([hidden])', { timeout: 10000 }).then(() => true, () => false);
    check('the banner is shown on Updates', shown);
    const banner = await page.innerText('#panelRebootBanner');
    check('on Updates: the reason, with both versions', /installed kernel \(15\.1-RELEASE-p5\)/.test(banner) && /running yet \(15\.1-RELEASE\)/.test(banner));
    check('  and the restart button', await page.$('#panelRebootBanner button[data-on-click="panelRebootOpen()"]') !== null);
    const home = await open(ctx, 'home', 'en');
    await home.page.waitForSelector('#panelRebootBanner:not([hidden])', { timeout: 10000 });
    check('on Home too', /needs a restart/.test(await home.page.innerText('#panelRebootBanner')));
    await home.page.close();
    const italian = await open(ctx, 'home', 'it');
    await italian.page.waitForSelector('#panelRebootBanner:not([hidden])', { timeout: 10000 });
    check('on the Italian page, the text of it.json', (await italian.page.innerText('#panelRebootBanner'))
        .includes(fill(IT['rb.needed'], { installed: '15.1-RELEASE-p5', running: '15.1-RELEASE' })));
    await italian.page.close();
    const none = await open(ctx, 'home', 'en', { reboot: 'none' });
    await none.page.waitForTimeout(1500);
    check('when not needed, it is not there', await none.page.$eval('#panelRebootBanner', b => b.hidden));
    await none.page.close();

    console.log('\n== 2. Update the server: one button for everything, the state below (reperto 207) ==');
    await centerReady(page);
    const rows = await page.$$eval('#ucList > li:not([hidden])', lis => lis.map(li => li.querySelector('.uc-head').innerText.replace(/\s+/g, ' ').trim()));
    console.log('    ' + rows.join('\n    '));
    check('four rows: Update everything first, FreeBSD, the packages, restart', rows.length === 4 && /^Update everything/.test(rows[0]));
    check('  no rows of their own for Java and Roundcube: they are steps of Update everything', await page.$$eval('#uc-java, #uc-roundcube', l => l.every(x => x.hidden)));
    check('  the branch in a card of its own under the card, not a row (reperto 205)', await page.$('#uc-branch') === null
        && await page.$('section#branch.card #branch-body') !== null && /quarterly/.test(await page.innerText('#branch-body')));
    check('  one row for the packages, with the list closed under it (reperto 202)', await page.$('#uc-stack') === null && await page.$('#packages') === null
        && await page.$eval('#uc-packages #pk-list', d => !d.open));
    const steps = await page.$$eval('#uc-all .uc-head li', l => l.map(x => x.textContent));
    console.log('    steps: ' + steps.join(' | '));
    check('Update everything lists what it will do, in order: the patches, the other packages, dovecot, Java last',
        steps.length === 4 && /FreeBSD patches up to 15\.1-RELEASE-p6/.test(steps[0]) && /2 packages, all together in one plan/.test(steps[1])
        && /dovecot-mysql: 2\.3\.21\.1_3 → 2\.3\.21\.1_4/.test(steps[2]) && /The panel's Java 25\.0\.4 → 25\.0\.5: last/.test(steps[3]));
    check('  with ONE button for all of it', /Update everything \(4 steps\)/.test(rows[0])
        && await page.$$eval('#uc-all .uc-head button', b => b.length === 1 && b[0].getAttribute('data-on-click') === 'ucEverything()'));
    check('the other rows say the state, with no update button: FreeBSD (patches ready), the packages (security)',
        /Now 15\.1-RELEASE; patches up to 15\.1-RELEASE-p6/.test(rows[1]) && await page.$$eval('#uc-os .uc-head button, #uc-packages .uc-head button', b => b.length === 0)
        && /2 security fixes/.test(rows[2]) && /1 package has a known vulnerability that the update does not fix yet/.test(rows[2]));
    check('  only the restart keeps its button, it is not an update', /needs a restart/.test(rows[3])
        && await page.$$eval('#ucList .uc-head button', b => b.map(x => x.getAttribute('data-on-click')).join(',')) === 'ucEverything(),panelRebootOpen()');
    check('no newer release: nothing about moving to one, no button for it (reperto 196)', !/available|Move to/.test(rows[1])
        && await page.$('[data-on-click="ucRelease()"]') === null);
    check('one read each of packages and branch when the page opens (the card reuses the cards\' reads)',
        calls.filter(c => c.action === 'packages_overview').length === 1 && calls.filter(c => c.action === 'branch_status').length === 1);
    check('the state in words too, not only by color', await page.$$eval('#ucList > li:not([hidden])', l => l.every(li =>
        /\((to do|up to date|information|error)\)/.test(li.querySelector('.uc-head .visually-hidden') ? li.querySelector('.uc-head .visually-hidden').textContent : ''))));
    if (shots) await page.locator('#update-center').screenshot({ path: path.join(shots, 'update-center.png') });

    console.log('\n== 3. Update everything: the checks, one confirmation, cancel, one job ==');
    await page.click('#uc-all .uc-head button[data-on-click="ucEverything()"]');
    await page.waitForSelector('#panelAskModal.show', { timeout: 15000 });
    const ask = await page.innerText('#panelAskModal .modal-content');
    console.log('    ' + ask.replace(/\s+/g, ' ').slice(0, 500));
    check('the checks of every step first: the plan of the other packages, dovecot\'s, Java\'s', ['updates_status', 'package_preflight', 'java_preflight']
        .every(a => calls.some(c => c.action === a)));
    check('one confirmation with every step, numbered, in order', /1\. FreeBSD patches up to 15\.1-RELEASE-p6/.test(ask) && /2\. 2 packages, all together in one plan \(and 1 reinstalled, because a package it uses changed\)/.test(ask)
        && /3\. dovecot-mysql: 2\.3\.21\.1_3 → 2\.3\.21\.1_4 — restarts dovecot — also installs libsodium 1\.0\.21/.test(ask) && /4\. The panel's Java/.test(ask));
    check('  what happens: one after the other, it stops at the first that does not go well; the page reloads after Java',
        /stops at the first step that does not go well/.test(ask) && /this page reloads by itself on the sign-in page: sign in again/.test(ask) && /Update everything \(4 steps\)/.test(ask));
    await page.waitForFunction(() => document.getElementById('panelAskModal').contains(document.activeElement), null, { timeout: 2000 }).catch(() => {});
    check('  the panel\'s window, labelled, with the focus inside', await page.$eval('#panelAskModal', m => m.getAttribute('aria-labelledby') === 'panelAskTitle'
        && m.contains(document.activeElement)));
    await page.click('#panelAskModal .modal-footer [data-bs-dismiss="modal"]');
    await page.waitForSelector('#panelAskModal', { state: 'hidden' });
    await page.waitForTimeout(300);
    check('cancelled: nothing starts, and the button is still there (it disappeared before)', !calls.some(c => c.action === 'update_everything')
        && await page.$$eval('#uc-all .uc-head button[data-on-click="ucEverything()"]', b => b.length === 1) && await page.$eval('#uc-all-detail', d => d.hidden));
    await page.click('#uc-all .uc-head button[data-on-click="ucEverything()"]');
    await page.waitForSelector('#panelAskModal.show', { timeout: 15000 });
    await page.click('#panelAskGo');
    await page.waitForFunction(() => /All 4 steps done/.test(document.getElementById('all-run').innerText), null, { timeout: 15000 });
    const all = calls.find(c => c.action === 'update_everything');
    check('ONE request: the word, the steps in order with their signatures', all && all.confirm === 'UPDATE' && JSON.stringify(all.steps) === JSON.stringify([
        { kind: 'os', package: '', signature: '' }, { kind: 'plain', package: '', signature: '0123456789abcdef' },
        { kind: 'package', package: 'dovecot-mysql', signature: '1111222233334444' }, { kind: 'java', package: '', signature: 'aaaabbbbccccdddd' }]));
    const approvedShown = Object.fromEntries((all && all.approved || []).map(a => [a.name, a.to]));
    check('  and every change the confirmation showed, with its version', approvedShown.libX11 === '1.8.14,1' && approvedShown.brotli === '1.2.1,1'
        && approvedShown['dovecot-mysql'] === '2.3.21.1_4' && approvedShown.libsodium === '1.0.21' && approvedShown.openjdk25 === '25.0.5');
    check('  no job of the old buttons', !calls.some(c => ['updates_apply', 'os_patch_install', 'package_update', 'java_update'].includes(c.action)));
    await page.waitForTimeout(800);
    check('the outcome stays under the row, with the restart the patches left, the log closed below',
        /All 4 steps done/.test(await page.innerText('#all-run')) && /takes effect with a restart/.test(await page.innerText('#all-run'))
        && await page.$eval('#all-log-box', d => !d.hidden && !d.open));
    await page.waitForFunction(() => /One step left/.test(document.querySelector('#uc-os .uc-head').innerText), null, { timeout: 10000 }).catch(() => {});
    check('the card reads itself again: the FreeBSD patches in, the restart left with its button, once',
        /One step left/.test(await page.innerText('#uc-os .uc-head'))
        && await page.$$eval('#uc-os button[data-on-click="panelRebootOpen()"]', b => b.filter(x => x.offsetParent).length) === 1);
    check('  and nothing left to update', /All 4 steps done|Nothing to update/.test(await page.innerText('#uc-all .uc-head'))
        && await page.$('#uc-all .uc-head button[data-on-click="ucEverything()"]') === null);
    if (shots) await page.locator('#update-center').screenshot({ path: path.join(shots, 'update-everything-done.png') });

    console.log('\n== 4b. A new FreeBSD release, one step at a time ==');
    const mv = await open(ctx, 'updates', 'en', { targets: true, noPatches: true, reboot: 'none' });
    allErrors.push(mv.errors); allDialogs.push(mv.dialogs);
    await centerReady(mv.page);
    const osRow = await mv.page.innerText('#uc-os .uc-head');
    check('the FreeBSD row says the new release is there, with one button', /FreeBSD 15\.2 is available/.test(osRow)
        && await mv.page.$$eval('#uc-os .uc-head button', b => b.map(x => x.textContent.trim())).then(b => b.length === 1 && /Move to FreeBSD 15\.2/.test(b[0])));
    await mv.page.click('#uc-os button[data-on-click="ucRelease()"]');
    const stepState = () => mv.page.$$eval('#os-steps > li', lis => lis.map(li => li.querySelector('.fw-semibold').innerText.replace(/\s+/g, ' ')));
    const actions = () => mv.page.$$eval('#os-release button', b => b.filter(x => x.offsetParent).map(x => x.textContent.trim()));
    let st1 = await stepState();
    console.log('    ' + st1.join(' | '));
    check('four steps, the first now and the others later', st1.length === 4 && /\(now\)/.test(st1[0]) && st1.slice(1).every(x => /\(later\)/.test(x)));
    check('  one button only: ' + (await actions()).join(', '), (await actions()).length === 1);
    check('  the patches part is not there', await mv.page.$eval('#os-patch', p => p.hidden));
    await mv.page.click('#os-release button[data-on-click="osRelPrepare()"]');
    await mv.page.waitForSelector('#panelAskModal.show');
    check('one confirmation after the checks: all 3 fine, what happens', /All 3 checks are fine/.test(await mv.page.innerText('#panelAskModal')));
    await mv.page.click('#panelAskGo');
    await mv.page.waitForFunction(() => document.querySelector('#os-steps pre'), null, { timeout: 10000 });
    const prep = mv.calls.find(c => c.action === 'os_upgrade_prepare');
    check('prepared for 15.2 with PREPARE UPGRADE', prep && prep.target === '15.2' && prep.confirm === 'PREPARE UPGRADE');
    st1 = await stepState();
    check('step 1 done, step 2 now', /\(done\)/.test(st1[0]) && /\(now\)/.test(st1[1]));
    check('  the row says step 2 of 4, without repeating the button of the open steps',
        /step 2 of 4/.test(await mv.page.innerText('#uc-os .uc-head')) && await mv.page.$('#uc-os .uc-head button') === null);
    check('  the command, ready to copy', (await mv.page.innerText('#os-cmd')) === 'freebsd-update -r 15.2-RELEASE upgrade');
    check('  copy, I have run it, and cancel: ' + (await actions()).join(', '), (await actions()).length === 3);
    if (shots) await mv.page.locator('#uc-os').screenshot({ path: path.join(shots, 'os-move-step2.png') });
    await mv.page.click('#os-release button[data-on-click="osRelFetched()"]');
    await mv.page.waitForFunction(() => /does not see the downloaded release/.test(document.getElementById('up-body').innerText), null, { timeout: 10000 });
    check('"I have run it" before the command ended: the panel says it does not see the release yet', true);
    mv.st.fetched = true;
    await mv.page.click('#os-release button[data-on-click="osRelFetched()"]');
    await mv.page.waitForSelector('#os-release button[data-on-click="osRelInstall()"]', { timeout: 10000 });
    st1 = await stepState();
    check('the panel sees the downloaded release by itself: step 3 now, one button', /\(now\)/.test(st1[2]) && (await actions()).length === 1);
    await mv.page.click('#os-release button[data-on-click="osRelInstall()"]');
    await mv.page.waitForSelector('#panelAskModal.show');
    await mv.page.click('#panelAskGo');
    await mv.page.waitForFunction(() => /\(now\)/.test((document.querySelectorAll('#os-steps > li')[3] || {}).innerText || ''), null, { timeout: 10000 });
    const cont = mv.calls.find(c => c.action === 'jump_continue');
    check('installed with CONTINUE and the target', cont && cont.confirm === 'CONTINUE' && cont.target === '15.2');
    await mv.page.waitForFunction(() => /still there|All/.test(document.getElementById('up-body').innerText), null, { timeout: 10000 }).catch(() => {});
    check('the final check runs by itself, once', mv.calls.filter(c => c.action === 'os_upgrade_verify').length === 1);
    check('  and no button left to press', (await actions()).filter(x => !/Delete/.test(x)).length === 0);
    await mv.page.close();

    console.log('\n== 4c. The checks stop the preparation ==');
    const bl = await open(ctx, 'updates', 'en', { targets: true, noPatches: true, blocked: true, reboot: 'none' });
    allErrors.push(bl.errors); allDialogs.push(bl.dialogs);
    await centerReady(bl.page);
    await bl.page.click('#uc-os button[data-on-click="ucRelease()"]');
    await bl.page.click('#os-release button[data-on-click="osRelPrepare()"]');
    await bl.page.waitForFunction(() => /not ready yet/.test(document.getElementById('up-body').innerText), null, { timeout: 10000 });
    const why = await bl.page.innerText('#up-body');
    check('only the row that stops it, with what to do', /Restart pending/.test(why) && /Restart the server first/.test(why) && !/Current version/.test(why));
    check('  nothing started', !bl.calls.some(c => c.action === 'os_upgrade_prepare') && !await bl.page.$('#panelAskModal.show'));
    await bl.page.close();

    console.log('\n== 4d. Roundcube is a step of Update everything (reperto 207) ==');
    const rc = await open(ctx, 'updates', 'en', { roundcube: true, noPatches: true, reboot: 'none' });
    allErrors.push(rc.errors); allDialogs.push(rc.dialogs);
    await centerReady(rc.page);
    const rcSteps = await rc.page.$$eval('#uc-all .uc-head li', l => l.map(x => x.textContent));
    console.log('    steps: ' + rcSteps.join(' | '));
    check('no Roundcube row of its own: the webmail is a step, before Java', await rc.page.$eval('#uc-roundcube', li => li.hidden)
        && /Webmail \(Roundcube\) 1\.6\.11 → 1\.7\.0: a copy of its database/.test(rcSteps[rcSteps.length - 2]) && /The panel's Java/.test(rcSteps[rcSteps.length - 1]));
    await rc.page.click('#uc-all .uc-head button[data-on-click="ucEverything()"]');
    await rc.page.waitForSelector('#panelAskModal.show', { timeout: 15000 });
    check('  its checks read with the others, and its step in the confirmation', rc.calls.some(c => c.action === 'roundcube_preflight')
        && /Webmail \(Roundcube\) 1\.6\.11 → 1\.7\.0/.test(await rc.page.innerText('#panelAskModal')));
    await rc.page.click('#panelAskGo');
    await rc.page.waitForFunction(() => /steps done/.test(document.getElementById('all-run').innerText), null, { timeout: 15000 });
    const rcAll = rc.calls.find(c => c.action === 'update_everything');
    check('  the job has the Roundcube step with its signature, before Java', rcAll && rcAll.steps.map(x => x.kind).join(',') === 'plain,package,roundcube,java'
        && rcAll.steps[2].signature === 'fedcba9876543210');
    await rc.page.close();
    const rcb = await open(ctx, 'updates', 'en', { roundcube: true, rcBlocked: true, noPatches: true, reboot: 'none' });
    allErrors.push(rcb.errors); allDialogs.push(rcb.dialogs);
    await centerReady(rcb.page);
    await rcb.page.click('#uc-all .uc-head button[data-on-click="ucEverything()"]');
    await rcb.page.waitForSelector('#panelAskModal.show', { timeout: 15000 });
    const stop = await rcb.page.innerText('#panelAskModal');
    check('the checks stop Roundcube: left out, with the reason, the rest still goes', /Left out, the checks stop them: Webmail \(Roundcube\).*Database copy — No space for the copy of the database/.test(stop.replace(/\s+/g, ' '))
        && !/\d\. Webmail/.test(stop));
    await rcb.page.click('#panelAskModal .modal-footer [data-bs-dismiss="modal"]');
    await rcb.page.close();

    console.log('\n== 5. The restart window ==');
    await page.click('#panelRebootBanner button');
    await page.waitForFunction(() => !document.getElementById('panelRebootGo').disabled, null, { timeout: 10000 });
    const rm = await page.innerText('#panelRebootModal .modal-content');
    check('what stops, mail that retries, the panel that comes back', /postfix, dovecot, mysql-server/.test(rm) && /retry on their own/.test(rm)
        && /comes back on its own/.test(rm));
    if (shots) await page.locator('#panelRebootModal .modal-content').screenshot({ path: path.join(shots, 'reboot-modal.png') });
    await page.check('#panelRebootIn5');
    await page.click('#panelRebootGo');
    await page.waitForFunction(() => /restarts at/.test(document.getElementById('panelRebootBody').innerText), null, { timeout: 10000 });
    const now = calls.find(c => c.action === 'reboot_now');
    check('reboot_now with the right keyword and the 5 minutes chosen', now && now.confirm === 'REBOOT THE SERVER' && now.minutes === 5);
    check('  the time, and the button to cancel', /at \d\d:\d\d/.test(await page.innerText('#panelRebootBody'))
        && await page.$('#panelRebootBody button[data-on-click="panelRebootCancel()"]') !== null);
    await page.click('#panelRebootBody button');
    await page.waitForFunction(() => /cancelled/.test(document.getElementById('panelRebootBody').innerText), null, { timeout: 10000 });
    check('cancelled: reboot_cancel', calls.some(c => c.action === 'reboot_cancel'));
    check('  the focus stays inside the window (the pressed button is gone)', await page.$eval('#panelRebootModal', m => m.contains(document.activeElement)));
    await page.keyboard.press('Escape');
    await page.waitForFunction(() => !document.getElementById('panelRebootModal').classList.contains('show'), null, { timeout: 5000 }).catch(() => {});
    check('Escape closes the window', await page.$eval('#panelRebootModal', m => !m.classList.contains('show')));
    await page.close();

    console.log('\n== 6. Reads queue up ==');
    const slow = await open(ctx, 'updates', 'en', { slow: true, reboot: 'none' });
    allErrors.push(slow.errors); allDialogs.push(slow.dialogs);
    await slow.page.waitForTimeout(500);
    const both = await slow.page.evaluate(async () => Promise.all([updApi('os_status'), updApi('os_status')]));
    check('two reads at once both answer (no "operation already running")', both.every(r => r.success));
    await slow.page.close();

    console.log('\n== 8. Why root, on the service users card (Diagnostics) ==');
    const su = await open(ctx, 'diagnostics', 'en', { reboot: 'none' });
    allErrors.push(su.errors); allDialogs.push(su.dialogs);
    await su.page.click('button[data-on-click="svcUsersLoad()"]');
    await su.page.waitForFunction(() => document.querySelectorAll('#upd-svc-users tbody tr').length >= 2, null, { timeout: 10000 });
    const suRows = await su.page.$$eval('#upd-svc-users tbody tr', trs => trs.map(tr => ({ text: tr.innerText, html: tr.innerHTML,
        hidden: [...tr.querySelectorAll('.visually-hidden')].map(x => x.textContent) })));
    check('php-fpm says why it keeps root, under its users', suRows[0].text.includes('Root only for the master process')
        && suRows[0].text.includes('it creates the webmail socket'));
    check('  as text: a tag in the reason is not markup', suRows[0].text.includes('<b>bold</b>') && !suRows[0].html.includes('<b>bold</b>'));
    check('  with the label for screen readers (' + suRows[0].hidden.join('|') + ')', suRows[0].hidden.some(x => x.trim() === 'Why root:'));
    check('redis, without root, says nothing', !suRows[1].text.includes('Root only') && suRows[1].hidden.length === 0);
    await su.page.close();

    console.log('\n== 9. Diagnostics, check everything ==');
    const dg = await open(ctx, 'diagnostics', 'en', { noPatches: false, reboot: 'none' });
    allErrors.push(dg.errors); allDialogs.push(dg.dialogs);
    check('one button to start', await dg.page.$$eval('#diag-all button', b => b.length) === 1);
    await dg.page.click('#diagAllGo');
    await dg.page.waitForFunction(() => /things to look at|checks are fine/.test(document.getElementById('diagAllState').textContent), null, { timeout: 20000 });
    const items = await dg.page.$$eval('#diagAllList > li', lis => lis.map(li => ({ key: li.dataset.diag, level: li.dataset.level,
        text: li.innerText.replace(/\s+/g, ' '), buttons: li.querySelectorAll('button, a.btn').length })));
    items.forEach(x => console.log('    ' + x.level + ' ' + x.key + ': ' + x.text.slice(0, 110)));
    check('every check ran, one after the other', ['os_status', 'journal_list', 'service_users', 'watch', 'broken_libs', 'compatibility', 'java_status',
        'web_diagnosis', 'defaults_check', 'panel_env'].every(a => dg.calls.some(c => c.action === a)));
    check('first what needs a look, the most important first: the two to look at, then the step to do',
        items.length === 3 && items[0].level === 'warn' && items[1].level === 'warn' && items[2].level === 'todo' && items[2].key === 'os');
    check('  each with its state in words and one button', items.every(x => x.buttons === 1) && /\(to look at\)/.test(items[0].text));
    check('  the patches: go to Updates', await dg.page.$('#diagAllList li[data-diag="os"] a[href="/updates"]') !== null);
    check('the state says how many', /2|3 things to look at/.test(await dg.page.textContent('#diagAllState')));
    check('what is fine is closed below, with how many', await dg.page.$eval('#diagAllOkBox', d => !d.hidden && !d.open)
        && /7 checks are fine/.test(await dg.page.textContent('#diagAllOkTitle')));
    if (shots) await dg.page.locator('#diag-all').screenshot({ path: path.join(shots, 'diagnostics-check-all.png') });
    const cmp = await dg.page.evaluate(() => [
        diagCompat({ dovecot: { scanned: true, compatible24: false, doveconfOk: true }, postfix: { verdict: 'LEVEL_BEHIND' },
            rspamd: { present: false }, mysql: { present: true, eol: true, issues: [] }, webmail: { consistent: false } }),
        diagCompat({ dovecot: { scanned: true, compatible24: true, doveconfOk: true }, postfix: { verdict: 'LEVEL_BEHIND' },
            rspamd: { present: true, verdict: 'BEHAVIOR_DIFFS' }, mysql: { present: false }, webmail: { consistent: true } }),
        diagCompat({ dovecot: { scanned: true, compatible24: true, doveconfOk: true }, postfix: { verdict: 'ALIGNED' },
            rspamd: { present: true, verdict: 'NOTHING_TO_REPORT' }, mysql: { present: true, issues: [] }, webmail: { consistent: true } })]);
    console.log('    ' + cmp.map(c => c[0] + ': ' + c[1]).join('\n    '));
    check('compatibility says what and whose: Dovecot first (red), then Postfix, MySQL, webmail (yellow)', cmp[0][0] === 'problem'
        && /^Dovecot: the configuration is not ready for 2\.4; Postfix: .+; MySQL: this version is at the end of its support; Webmail: PHP and Roundcube do not match\.$/.test(cmp[0][1]));
    check('  only Postfix behind: to look at, the card\'s verdict inside the sentence', cmp[1][0] === 'warn' && cmp[1][1] === 'Postfix: the level is behind.');
    check('  all in order: fine', cmp[2][0] === 'ok');
    await dg.page.click('#diagAllList li[data-diag="journal"] button');
    await dg.page.waitForFunction(() => /=== end: error ===/.test(document.getElementById('jr-text').textContent), null, { timeout: 10000 });
    check('the failed job: its log, from the operation logs', dg.calls.some(c => c.action === 'journal_read' && c.name === '20261109-000000-os-patch__osp-1.log'));
    await dg.page.close();

    console.log('\n== 10. A restart scheduled: the panel only reads (reperto 200) ==');
    const lk = await open(ctx, 'updates', 'en', { scheduled: true, rebootAt: Date.now() + 7 * 60000, noPatches: true });
    allErrors.push(lk.errors); allDialogs.push(lk.dialogs);
    await centerReady(lk.page);
    await lk.page.waitForFunction(() => document.body.classList.contains('panel-restart-locked'), null, { timeout: 10000 });
    const strip = await lk.page.innerText('#panelRebootBanner');
    check('the strip: the time, the panel only reads, the cancel button', /restarts at \d\d:\d\d/.test(strip) && /only reads/.test(strip)
        && await lk.page.$('#panelRebootBanner button[data-on-click="panelRebootCancel()"]') !== null);
    if (shots) await lk.page.locator('#panelRebootBanner').screenshot({ path: path.join(shots, 'restart-read-only.png') });
    const pageButton = lk.page.locator('#update-center button[data-on-click]:not([data-bs-toggle])').first();
    const before = lk.calls.length;
    await pageButton.click();
    await lk.page.waitForSelector('#panelNotices .alert-warning', { timeout: 5000 });
    check('a button of the page does nothing, and says why', lk.calls.length === before
        && /Not now: a server restart is scheduled/.test(await lk.page.innerText('#panelNotices')));
    await pageButton.click();
    check('  pressed again: still one notice', (await lk.page.$$('#panelNotices .alert-warning')).length === 1 && lk.calls.length === before);
    check('  the button looks off', await pageButton.evaluate(b => Number(getComputedStyle(b).opacity) < 0.7));
    const reads = () => lk.calls.filter(c => c.action === 'reboot_state').length;
    const r0 = reads();
    const refused = await lk.page.evaluate(() => fetch('/api/aliases', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })
        .then(r => r.status));
    await lk.page.waitForTimeout(800);
    check('a change the server refuses (409): the strip reads its state again', refused === 409 && reads() > r0);
    await lk.page.click('#panelRebootBanner button[data-on-click="panelRebootCancel()"]');
    await lk.page.waitForFunction(() => !document.body.classList.contains('panel-restart-locked'), null, { timeout: 10000 });
    check('cancelled: reboot_cancel, and the page acts again', lk.calls.some(c => c.action === 'reboot_cancel')
        && !/only reads/.test(await lk.page.innerText('#panelRebootBanner')));
    const after = lk.calls.length;
    await pageButton.click();
    await lk.page.waitForTimeout(800);
    check('  the same button works again', lk.calls.length > after);
    await lk.page.close();
    const bz = await open(ctx, 'updates', 'en', { busy: true, noPatches: true });
    allErrors.push(bz.errors); allDialogs.push(bz.dialogs);
    await bz.page.waitForSelector('#panelRebootBanner button', { timeout: 10000 });
    await bz.page.click('#panelRebootBanner button');
    await bz.page.waitForFunction(() => /Still running/.test(document.getElementById('panelRebootBody').innerText), null, { timeout: 10000 });
    check('a job running: the restart window says which, and there is no restart button',
        /Package update \(dovecot\)/.test(await bz.page.innerText('#panelRebootBody')) && await bz.page.$eval('#panelRebootGo', b => b.hidden));
    await bz.page.close();

    console.log('\n== 11. A job in progress, started elsewhere (reperto 206) ==');
    const busy = await open(ctx, 'updates', 'en', { turn: true });
    allErrors.push(busy.errors); allDialogs.push(busy.dialogs);
    await centerReady(busy.page);
    await busy.page.waitForSelector('#ucRunning:not([hidden])', { timeout: 10000 });
    check('the card says what is running and since when', /In progress: check for updates, just started/.test(await busy.page.innerText('#ucRunning')));
    check('  with what it is doing, closed below', await busy.page.$eval('#ucRunningLogBox', d => !d.hidden && !d.open)
        && /done/.test(await busy.page.textContent('#ucRunningLog')));
    check('  and the steps wait: every button of the rows and "Check for updates" off, saying why',
        await busy.page.$$eval('#ucList .uc-head button, #ucSearchButton', b => b.length > 1 && b.every(x => x.disabled && x.title === 'After the job in progress')));
    if (shots) await busy.page.locator('#update-center').screenshot({ path: path.join(shots, 'update-center-running.png') });
    const readsBefore = busy.calls.filter(c => c.action === 'packages_overview').length;
    await busy.page.waitForSelector('#ucRunning', { state: 'hidden', timeout: 15000 }).catch(() => {});
    for (let i = 0; i < 20 && busy.calls.filter(c => c.action === 'packages_overview').length <= readsBefore; i++) await busy.page.waitForTimeout(250);
    await busy.page.waitForTimeout(500);
    check('when it ends: the line goes, the buttons are back', await busy.page.$eval('#ucRunning', b => b.hidden)
        && await busy.page.$$eval('#ucList .uc-head button, #ucSearchButton', b => b.every(x => !x.disabled && !x.title)));
    check('  and the card reads itself again', busy.calls.filter(c => c.action === 'packages_overview').length > readsBefore);
    await busy.page.close();

    console.log('\n== 12. The database restarting: the page waits and tries again (reperto 209) ==');
    // On the real server MySQL restarted inside "Update everything": for 9 seconds every request got 401, the card lost
    // the job in progress and filled with errors. Now the server says 503 "database", and the page waits.
    const db = await open(ctx, 'updates', 'en');
    allErrors.push(db.errors); allDialogs.push(db.dialogs);
    await centerReady(db.page);
    const searchesBefore = db.calls.filter(c => c.action === 'updates_search').length;
    db.st.dbDown = 3;
    await db.page.click('#ucSearchButton');
    await db.page.waitForSelector('#panelDbWait', { timeout: 10000 }).catch(() => {});
    const dbStrip = await db.page.$('#panelDbWait') ? await db.page.innerText('#panelDbWait') : '';
    check('while it is down: the strip says it, and the page waits (no error under the button)', /The database is restarting: the panel waits and tries again/.test(dbStrip)
        && await db.page.$eval('#panelDbWait', n => n.getAttribute('role') === 'status') && !/not answering|mock|Unauthorized/.test(await db.page.innerText('#update-center')));
    await db.page.waitForSelector('#panelDbWait', { state: 'detached', timeout: 20000 }).catch(() => {});
    await db.page.waitForFunction(() => /Lists updated/.test(document.getElementById('ucOutcome').innerText), null, { timeout: 15000 }).catch(() => {});
    check('when it is back: the strip goes, and the search was asked again and done once (' + db.st.dbRefused + ' refused)',
        await db.page.$('#panelDbWait') === null && db.st.dbRefused === 3
        && db.calls.filter(c => c.action === 'updates_search').length === searchesBefore + 1
        && /Lists updated/.test(await db.page.innerText('#ucOutcome')));
    await db.page.close();

    console.log("\n== 13. The panel's Java being updated, the page reloaded meanwhile (reperto 210) ==");
    // On the real server the page was reloaded while the Java script worked: it said "1 step to do: the Java" and a
    // warning about a job "that did not finish", and nothing of what was happening.
    const jv = await open(ctx, 'updates', 'en', { javaTurn: true });
    allErrors.push(jv.errors); allDialogs.push(jv.dialogs);
    await centerReady(jv.page);
    await jv.page.waitForSelector('#ucRunning:not([hidden])', { timeout: 10000 }).catch(() => {});
    const running = await jv.page.innerText('#ucRunning').catch(() => '');
    check('the card says the Java is being updated, and what the script is doing', /In progress: the update of the panel's Java/.test(running)
        && /reloads on the sign-in page/.test(running) && /\[2\/7\] Downloading the new packages/.test(await jv.page.textContent('#ucRunningLog')));
    check('  where it is, without opening the log: "Now: [2/7] Downloading the new packages..."',
        (await jv.page.innerText('#ucRunningNow').catch(() => '')).trim() === 'Now: [2/7] Downloading the new packages, with the panel still answering...');
    await jv.page.waitForFunction(() => /being updated now/.test(document.querySelector('#uc-all .uc-head').innerText), null, { timeout: 10000 }).catch(() => {});
    const javaTop = await jv.page.innerText('#uc-all .uc-head');
    check('  Update everything says it too, with nothing to press, and does not offer the Java again', /The panel's Java is being updated now: nothing to press/.test(javaTop)
        && await jv.page.$('#uc-all .uc-head button[data-on-click="ucEverything()"]') === null && !/25\.0\.4 → 25\.0\.5/.test(javaTop));
    await jv.page.waitForTimeout(6000);
    check('  and the page waits for the panel to come back, to reload itself (it asks /api/panel_info)', (jv.st.panelInfo || 0) > 0);
    if (shots) await jv.page.locator('#update-center').screenshot({ path: path.join(shots, 'update-center-java-running.png') });
    await jv.page.close();

    console.log('\n== 7. At 375 px ==');
    const phone = await browser.newContext({ viewport: { width: 375, height: 812 }, isMobile: true, hasTouch: true, locale: 'en-GB' });
    const small = await open(phone, 'updates', 'en');
    allErrors.push(small.errors); allDialogs.push(small.dialogs);
    await centerReady(small.page);
    const lay = await small.page.evaluate(() => ({ scroll: document.documentElement.scrollWidth - window.innerWidth,
        tiny: [...document.querySelectorAll('#update-center button, #panelRebootBanner button')].filter(b => b.offsetParent)
            .map(b => Math.round(Math.min(b.getBoundingClientRect().height, b.getBoundingClientRect().width))).filter(h => h < 44) }));
    check('no horizontal scrolling (' + lay.scroll + ')', lay.scroll <= 0);
    check('touch buttons are 44 px' + (lay.tiny.length ? ': ' + lay.tiny.join(', ') : ''), lay.tiny.length === 0);
    if (shots) await small.page.screenshot({ path: path.join(shots, 'update-center-phone.png'), fullPage: false });

    const errs = allErrors.flat(), dlg = allDialogs.flat();
    check('no browser dialog in the whole test (prompt, confirm)' + (dlg.length ? ': ' + dlg.slice(0, 2).join(' | ') : ''), dlg.length === 0);
    check('no policy violation or page error' + (errs.length ? ': ' + errs.slice(0, 3).join(' | ') : ''), errs.length === 0);
    await browser.close();
    console.log(failed === 0 ? '\nALL GREEN' : '\n' + failed + ' CHECKS FAILED');
    process.exit(failed === 0 ? 0 : 1);
})().catch(e => { console.error(e); process.exit(1); });
