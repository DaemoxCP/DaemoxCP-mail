// Updating from the panel (reperti 185-187), in Chromium with a simulated server and the panel's CSP.
//
//  1. The restart banner at the top of every page (Updates and Home), with the reason and the button;
//     on the Italian page the text is the one of it.json.
//  2. "Update the server": one row each for FreeBSD, packages, mail server packages, the dedicated procedures
//     only when they apply (here the panel's Java), branch and restart, in words and not only by color, with the
//     buttons for what there is to do (reperto 193: every row acts in place).
//  3. No browser dialog (prompt, confirm): confirmations are the panel's own window, which shows the
//     exact plan; the job starts with the plan's signature and the right keyword.
//  4. FreeBSD patches: the confirmation, os_patch_install with INSTALL PATCHES, then the outcome with the one step left
//     (the restart, with its button) and the details closed (reperto 196).
//  4b. A new FreeBSD release, one step at a time: only when there is one; four steps, only the current one with its
//     button; check and prepare with one confirmation, the command from SSH, the install, the final check by itself.
//  4c. The checks stop the preparation: only the rows that stop it, and nothing starts.
//  5. The restart window: what stops, the chosen delay, the time, cancelling; Escape closes it.
//  6. Reads queue up: two "System state" calls at once both answer.
//  7. At 375 px: no horizontal scrolling, 44 px buttons.
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
    { type: 'upgrade', name: 'brotli', from: '1.1.0,1', to: '1.2.1,1' }] };
// st is the server's state for one page: what the actions so far have changed.
function replies(o, st) {
    return {
        os_status: st.patched
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
        jump_continue: { success: true, jobId: 'jump-1' },
        jump_cancel: { success: true, note: 'Move cancelled.' },
        os_upgrade_verify: { success: true, allGood: true, checks: [{ label: 'Services', level: 'ok', detail: 'All up.' }], environments: { success: false } },
        packages_overview: { success: true, procedures: { java: true, roundcube: false, roundcubePackage: '', mysql84: false, python: false }, summary: { updates: 4, stackUpdates: 2, vulnerable: 3, fixable: 2, locked: 39 },
            packages: [
                { name: 'dovecot-mysql', role: 'IMAP', installed: '2.3.21.1_3', available: '2.3.21.1_4', update: true, locked: true, stack: true, canUpdate: true },
                { name: 'openjdk25', role: 'Java', installed: '25.0.4', available: '25.0.5', update: true, locked: true, stack: true, canUpdate: false, javaFlow: true },
                { name: 'postfix-mysql', role: 'SMTP', installed: '3.11.7', available: '', update: false, locked: true, stack: true }],
            others: [{ name: 'libX11', installed: '1.8.12,1', available: '1.8.14,1' }, { name: 'brotli', installed: '1.1.0,1', available: '1.2.1,1' }] },
        branch_status: { success: true, branch: 'quarterly', explanation: 'Quarterly.', changeable: true, destination: ['latest'], panelOwnedFile: false, repository: [] },
        reboot_state: { success: true, state: o.reboot || 'needed', installedKernel: '15.1-RELEASE-p5', runningKernel: '15.1-RELEASE', scheduled: !!o.scheduled },
        reboot_preview: { success: true, services: ['postfix', 'dovecot', 'mysql-server'], minutes: 1, autoStart: { active: true } },
        reboot_now: { success: true, executed: true, pid: '4242' },
        reboot_cancel: { success: true, existedBefore: true },
        updates_status: { success: true, plan: PLAN, signature: '0123456789abcdef', vulnerable: [], lockedUpdates: [] },
        updates_apply: { success: true, jobId: 'upd-1' },
        updates_search: { success: true, jobId: 'srch-1' },
        os_patch_install: { success: true, jobId: 'osp-1' },
        job_status: { success: true, job: { status: 'completed', consoleLog: 'done', result: 'Lists updated.', elapsedSeconds: 3 } },
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
            calls.push(body);
            if (o.slow && body.action === 'os_status') await new Promise(r => setTimeout(r, 700));
            const r = replies(o, st)[body.action] || { success: false, error: 'mock' };
            if (body.action === 'os_patch_install') st.patched = true;
            if (body.action === 'os_upgrade_prepare') st.phase = 'prepared';
            if (body.action === 'jump_continue') st.phase = 'finished';
            if (body.action === 'jump_cancel') st.phase = '';
            return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(r) });
        }
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
const centerReady = page => page.waitForFunction(() => document.querySelectorAll('#ucList > li:not([hidden])').length >= 6
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

    console.log('\n== 2. Update the server ==');
    await centerReady(page);
    const rows = await page.$$eval('#ucList > li:not([hidden])', lis => lis.map(li => li.querySelector('.uc-head').innerText.replace(/\s+/g, ' ').trim()));
    console.log('    ' + rows.join('\n    '));
    check('six rows: FreeBSD, packages, mail server, the panel\'s Java (it has an update), branch, restart', rows.length === 6);
    check('  the procedures with nothing to do have no row (Roundcube, MySQL, Python)', await page.$$eval('#uc-roundcube, #uc-mysql, #uc-python', l => l.every(x => x.hidden)));
    check('FreeBSD: now and what is ready, with the button', /Now 15\.1-RELEASE; patches up to 15\.1-RELEASE-p6/.test(rows[0]) && /Install the FreeBSD updates/.test(rows[0]));
    check('packages: two to update, two fixes, the button', /2 packages to update/.test(rows[1]) && /2 security fixes/.test(rows[1]) && /Update the packages/.test(rows[1]));
    check('mail server: dovecot with its button, and not Java (it has its own row)', /dovecot-mysql: 2\.3\.21\.1_3 → 2\.3\.21\.1_4/.test(rows[2])
        && await page.$('#ucList button[data-pkg="dovecot-mysql"]') !== null && !/openjdk/.test(rows[2]));
    check('the panel\'s Java: its row, with the versions and Prepare', /openjdk25: 25\.0\.4/.test(rows[3]) && /Prepare/.test(rows[3]));
    check('branch and restart', /quarterly branch/.test(rows[4]) && /needs a restart/.test(rows[5]));
    check('no newer release: nothing about moving to one, no button for it (reperto 196)', !/available|Move to/.test(rows[0])
        && await page.$('[data-on-click="ucRelease()"]') === null);
    check('one read each of packages and branch when the page opens (the card reuses the cards\' reads)',
        calls.filter(c => c.action === 'packages_overview').length === 1 && calls.filter(c => c.action === 'branch_status').length === 1);
    check('the state in words too, not only by color', await page.$$eval('#ucList .visually-hidden', s => s.map(x => x.textContent).join(' '))
        .then(x => /to do/.test(x) && /information/.test(x)));
    if (shots) await page.locator('#update-center').screenshot({ path: path.join(shots, 'update-center.png') });

    console.log('\n== 3. Packages, with the panel\'s confirmation ==');
    await page.click('#ucList button[data-on-click="ucPackages()"]');
    await page.waitForSelector('#panelAskModal.show');
    const ask = await page.innerText('#panelAskModal .modal-content');
    check('the confirmation shows the exact plan', /libX11: 1\.8\.12,1 → 1\.8\.14,1/.test(ask) && /brotli/.test(ask) && /Update 2 packages/.test(ask));
    await page.waitForFunction(() => document.getElementById('panelAskModal').contains(document.activeElement), null, { timeout: 2000 }).catch(() => {});
    check('  it is labelled, with the focus inside', await page.$eval('#panelAskModal', m => m.getAttribute('aria-labelledby') === 'panelAskTitle'
        && m.contains(document.activeElement)));
    await page.click('#panelAskGo');
    await page.waitForTimeout(800);
    check('the job\'s outcome stays in the card after it reads its state again', await page.textContent('#ucOutcome') === 'Lists updated.');
    const apply = calls.find(c => c.action === 'updates_apply');
    check('the job starts with UPDATE and the signature of the plan shown', apply && apply.confirm === 'UPDATE' && apply.signature === '0123456789abcdef');

    console.log('\n== 4. FreeBSD patches ==');
    await page.click('#ucList button[data-on-click="ucOsInstall()"]');
    await page.waitForSelector('#panelAskModal.show');
    check('the confirmation says what happens (boot environment, mail stays up)', /boot environment/.test(await page.innerText('#panelAskModal'))
        && /mail stays up/.test(await page.innerText('#panelAskModal')));
    await page.click('#panelAskGo');
    await page.waitForFunction(() => /Patches installed/.test(document.getElementById('os-body').innerText), null, { timeout: 10000 });
    const inst = calls.find(c => c.action === 'os_patch_install');
    check('os_patch_install with INSTALL PATCHES', inst && inst.confirm === 'INSTALL PATCHES');
    const outcome = await page.innerText('#os-body');
    console.log('    ' + outcome.replace(/\s+/g, ' '));
    check('the outcome says what is installed and the one step left, the restart, with its button',
        /Patches installed: FreeBSD 15\.1-RELEASE-p6/.test(outcome) && /One step left: restart the server/.test(outcome)
        && await page.$('#os-body button[data-on-click="panelRebootOpen()"]') !== null);
    check('  what the server did is there, closed', await page.$eval('#os-log-box', d => !d.hidden && !d.open));
    check('  nothing about a new release under it', await page.$eval('#os-release', r => r.hidden));
    await page.waitForFunction(() => /One step left/.test(document.querySelector('#uc-os .uc-head').innerText), null, { timeout: 10000 });
    check('the FreeBSD row says it too, and the button is there once, not twice',
        await page.$$eval('#uc-os button[data-on-click="panelRebootOpen()"]', b => b.filter(x => x.offsetParent).length) === 1);
    if (shots) await page.locator('#uc-os').screenshot({ path: path.join(shots, 'os-patches-done.png') });

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
