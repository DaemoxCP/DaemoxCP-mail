// The new-version notice (ReleaseCheck) in the panel's pages, end to end on the FreeBSD test machine. Here only the
// browser runs; the panel is the test machine's own, through an ssh tunnel.
//
//   1. Updates: the "DaemoxCP Mail version" card says the running version, and the daily check is on by default.
//   2. "Check now" asks GitHub for real. Until the repository is public GitHub answers 404, and the card says so in
//      words; the button is busy meanwhile. A second "Check now" within a minute does not ask again.
//   3. The daily check switched off and on. Off asks for the recent confirmation, like every system change: cancelled,
//      the switch goes back; confirmed with a console code, it goes off. The page and a reload agree, and each change
//      is in the audit log.
//   4. A newer release (the page's API answer replaced in the browser, since the real repository has none yet): the
//      card and the Dashboard say it, with the link to the release page; a link that is not a GitHub release page is
//      not shown. Without a newer release the Dashboard says nothing.
//   5. At 375 px the card fits the screen; no script errors.
//
// ONLY on the test machine. Usage:
//   HOST=<panel name> CHROMIUM=<chrome binary> REMOTE=root@<test machine> REMOTE_KEY=<ssh key> \
//     NODE_PATH=$(npm root -g) node tests/release-notice-browser-test.js
const { chromium } = require('playwright');
const { spawn, execFileSync } = require('child_process');
const net = require('net');

const REMOTE = process.env.REMOTE, HOST = process.env.HOST;
const SSH = ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-i', process.env.REMOTE_KEY.replace(/^~/, process.env.HOME)];
const PORT = 25000 + Math.floor(Math.random() * 1000);
const BASE = 'https://' + HOST + ':' + PORT;
const AUDIT = '/var/log/daemoxcp-mail-auth.log';
let failures = 0;
function check(what, ok) { console.log((ok ? '  OK     ' : '  FAILED ') + what); if (!ok) failures++; }
function remote(cmd) { return execFileSync('ssh', SSH.concat([REMOTE, cmd]), { encoding: 'utf8' }); }
function code(out) { const m = out.match(/One-time access code for [^:]*: (\d{4} \d{4})/); return m ? m[1] : ''; }
function auditCount(action) { return Number(remote('grep -c "' + action + '" ' + AUDIT + ' || true').trim() || 0); }
function portOpen(port) {
    return new Promise(resolve => { const s = net.connect(port, '127.0.0.1', () => { s.destroy(); resolve(true); }); s.on('error', () => resolve(false)); });
}

// Newer than the panel that runs (1.0.0 is the first release): a 1.0.0 here would be the same version, not a newer one.
const NEWER = { version: '1.1.0', tag: 'v1.1.0', url: 'https://github.com/DaemoxCP/DaemoxCP-mail/releases/tag/v1.1.0',
    publishedAt: '2026-12-01T10:00:00Z', preRelease: false };

(async () => {
    const tunnel = spawn('ssh', SSH.concat(['-N', '-o', 'ExitOnForwardFailure=yes', '-L', PORT + ':127.0.0.1:2096', REMOTE]), { stdio: 'ignore' });
    let up = false;
    for (let i = 0; i < 40 && !up; i++) { await new Promise(r => setTimeout(r, 250)); up = await portOpen(PORT); }
    const browser = await chromium.launch({ executablePath: process.env.CHROMIUM, args: ['--host-resolver-rules=MAP ' + HOST + ' 127.0.0.1'] });
    const errors = [];
    try {
        const context = await browser.newContext({ ignoreHTTPSErrors: true, locale: 'en-GB' });
        const page = await context.newPage();
        page.on('pageerror', e => errors.push(e.message));
        await page.goto(BASE + '/index');
        await page.click('#linkConsole');
        await page.fill('#consoleCode', code(remote('cd /home/panel && /usr/local/openjdk25/bin/java -jar daemoxcp-mail.jar --lang en --access-code 2>/dev/null')));
        await Promise.all([page.waitForURL(u => !u.pathname.endsWith('/index'), { timeout: 30000 }), page.click('#btnConsole')]);

        console.log('== 1. The card on Updates ==');
        await page.goto(BASE + '/updates');
        await page.waitForFunction(() => !document.getElementById('relAuto').disabled, null, { timeout: 30000 });
        const running = (await page.locator('#relRunning').innerText()).trim();
        check('it says the running version (' + running + ')', /^This panel runs version \d+\.\d+\.\d+\.$/.test(running));
        check('the daily check is on by default', await page.locator('#relAuto').isChecked());
        const hint = (await page.locator('#relAutoHint').innerText()).trim();
        check('the switch says what leaves the server (' + hint.slice(0, 70) + '...)', /api\.github\.com/.test(hint) && /DaemoxCP\/mail/.test(hint));
        check('the switch has its label', await page.locator('label[for="relAuto"]').count() === 1);

        console.log('\n== 2. Check now, for real ==');
        const button = page.locator('#relCheckButton');
        const asked = page.waitForResponse(r => r.url().endsWith('/api/updates') && r.request().postData().includes('panel_release_check'), { timeout: 60000 });
        await button.click();
        const busy = await button.isDisabled() && await page.locator('#relCheckIcon.fa-spinner').count() === 1;
        check('the button is busy meanwhile', busy);
        const answer = await (await asked).json();
        await page.waitForFunction(() => !document.getElementById('relCheckButton').disabled, null, { timeout: 60000 });
        const outcome = (await page.locator('#relOutcome').innerText()).trim();
        console.log('  (the panel got: ' + JSON.stringify({ ok: answer.ok, error: answer.error, newest: answer.newest }) + ')');
        check('GitHub was asked and the answer saved (' + answer.checkedAt + ')', !!answer.checkedAt);
        if (answer.error === 'not_found')
            check('404: the card says the repository is not public yet (' + outcome + ')', /not public yet/.test(outcome) && /DaemoxCP\/mail/.test(outcome));
        else
            check('the card says the outcome in words (' + outcome + ')', outcome.length > 20 && !/undefined|\{|null/.test(outcome));
        check('no release told, there is none', await page.locator('#relOutcome .alert').count() === 0 || !!answer.newest);
        await button.click();
        await page.waitForFunction(() => !document.getElementById('relCheckButton').disabled, null, { timeout: 30000 });
        const again = (await page.locator('#relOutcome').innerText()).trim();
        check('a second "Check now" within a minute does not ask again (' + again.split('\n').pop() + ')', /less than a minute ago/.test(again));

        console.log('\n== 3. The daily check off and on ==');
        const offBefore = auditCount('RELEASE_CHECK_OFF'), onBefore = auditCount('RELEASE_CHECK_ON');
        // Off is a system change (system.manage): the panel asks for a recent confirmation first, as for every other.
        await page.locator('#relAuto').click();
        await page.waitForSelector('#panelConfirmModal.show', { timeout: 20000 });
        check('switching it off asks for the confirmation', true);
        // Escape once the window has the focus (during its fade-in it does not listen yet).
        await page.waitForFunction(() => document.getElementById('panelConfirmModal').contains(document.activeElement), null, { timeout: 10000 });
        await page.keyboard.press('Escape');
        await page.waitForSelector('#panelConfirmModal', { state: 'hidden', timeout: 10000 });
        await page.waitForFunction(() => !document.getElementById('relAuto').disabled, null, { timeout: 20000 });
        check('cancelled: the switch goes back on, and says why (' + (await page.locator('#relAutoState').innerText()).trim() + ')',
            await page.locator('#relAuto').isChecked() && (await page.locator('#relAutoState').innerText()).trim() !== '');
        check('cancelled: nothing in the audit log', auditCount('RELEASE_CHECK_OFF') === offBefore);
        await page.locator('#relAuto').click();
        await page.waitForSelector('#panelConfirmModal.show', { timeout: 20000 });
        await page.click('#panelConfirmModal [data-confirm="console"]');
        await page.waitForSelector('#panelConfirmConsoleCode', { state: 'visible' });
        const command = (await page.locator('#panelConfirmConsoleCommand').innerText()).trim();
        await page.fill('#panelConfirmConsoleCode', code(remote('cd /home/panel && /usr/local/openjdk25/bin/' + command + ' 2>/dev/null')));
        await page.click('#panelConfirmModal [data-confirm="console-verify"]');
        await page.waitForFunction(() => !document.getElementById('relAuto').disabled && /off/.test(document.getElementById('relAutoState').textContent), null, { timeout: 20000 });
        check('off: the card says so (' + (await page.locator('#relAutoState').innerText()).trim() + ')', !(await page.locator('#relAuto').isChecked()));
        await page.reload();
        await page.waitForFunction(() => !document.getElementById('relAuto').disabled, null, { timeout: 30000 });
        check('after a reload it is still off', !(await page.locator('#relAuto').isChecked()));
        check('the audit log has it (RELEASE_CHECK_OFF)', auditCount('RELEASE_CHECK_OFF') === offBefore + 1);
        // On again within the five minutes of that confirmation: no window.
        await page.locator('#relAuto').click();
        await page.waitForFunction(() => !document.getElementById('relAuto').disabled && /is on/.test(document.getElementById('relAutoState').textContent), null, { timeout: 20000 });
        await page.reload();
        await page.waitForFunction(() => !document.getElementById('relAuto').disabled, null, { timeout: 30000 });
        check('on again, after a reload too', await page.locator('#relAuto').isChecked());
        check('the audit log has it (RELEASE_CHECK_ON)', auditCount('RELEASE_CHECK_ON') === onBefore + 1);

        console.log('\n== 4. A newer release ==');
        // The page's own API answer, with a release in it: the real repository has none yet. The real answer is read
        // through the page first (route.fetch would ask from Node, which does not know the test machine's name).
        const realStatus = await page.evaluate(() => updSend('panel_release'));
        check('the real answer, read first (' + JSON.stringify({ current: realStatus.current, error: realStatus.error }) + ')', realStatus.success === true);
        const fake = (release) => async route => {
            const body = route.request().postData() || '';
            if (!body.includes('"panel_release"')) return route.continue();
            const answer = Object.assign({}, realStatus, { newest: release, ok: true, checkedAt: '2026-12-06T08:00:00Z' });
            delete answer.error;
            return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(answer) });
        };
        await page.route('**/api/updates', fake(NEWER));
        await page.reload();
        await page.waitForSelector('#relOutcome .alert', { timeout: 60000 });
        const said = (await page.locator('#relOutcome .alert').innerText()).trim();
        check('the card says it (' + said + ')', new RegExp('Version ' + NEWER.version.replace(/\./g, '\\.') + ' is out, published on (1 December 2026|December 1, 2026)\\.').test(said));
        const link = page.locator('#relOutcome .alert a');
        check('with the link to the release page (' + await link.getAttribute('href') + ')', await link.getAttribute('href') === NEWER.url);
        await page.unroute('**/api/updates');
        await page.route('**/api/updates', fake(Object.assign({}, NEWER, { url: 'https://attacker.example/releases/tag/v1.1.0' })));
        await page.reload();
        await page.waitForSelector('#relOutcome .alert', { timeout: 60000 });
        check('a link that is not a GitHub release page is not shown', await page.locator('#relOutcome .alert a').count() === 0);
        await page.unroute('**/api/updates');

        const realUptime = await page.evaluate(() => fetch('/api/panel_info?action=uptime').then(r => r.json()));
        await page.goto(BASE + '/home');
        await page.waitForFunction(() => document.getElementById('panelInfoUptime').textContent.trim() !== '–', null, { timeout: 30000 });
        check('no newer release: the server sends none (' + JSON.stringify(realUptime.release) + ')', !realUptime.release);
        check('and the Dashboard shows nothing', await page.locator('#panelReleaseNotice').isHidden());
        await page.route('**/api/panel_info?action=uptime', route => route.fulfill({ status: 200, contentType: 'application/json',
            body: JSON.stringify(Object.assign({}, realUptime, { release: Object.assign({ current: realStatus.current }, NEWER) })) }));
        await page.reload();
        await page.waitForSelector('#panelReleaseNotice:not([hidden])', { timeout: 30000 });
        const notice = (await page.locator('#panelReleaseNotice').innerText()).trim();
        check('with one, the Dashboard says it (' + notice.replace(/\s+/g, ' ') + ')',
            notice.includes('DaemoxCP Mail ' + NEWER.version + ' is out: this panel runs ' + realStatus.current + '.'));
        check('and links the release page', await page.locator('#panelReleaseLink').getAttribute('href') === NEWER.url);
        // The link and the text against the notice, in both themes: at least 4.5:1 (WCAG 1.4.3).
        for (const theme of ['light', 'dark']) {
            const ratios = await page.evaluate(theme => {
                document.documentElement.setAttribute('data-theme', theme);
                const rgb = s => (s.match(/[\d.]+/g) || []).map(Number);
                const lum = c => { const v = c.slice(0, 3).map(x => { x /= 255; return x <= 0.03928 ? x / 12.92 : Math.pow((x + 0.055) / 1.055, 2.4); });
                    return 0.2126 * v[0] + 0.7152 * v[1] + 0.0722 * v[2]; };
                // The notice's background over the card's, when it is see-through.
                const box = document.querySelector('#panelReleaseNotice .alert');
                let bg = rgb(getComputedStyle(box).backgroundColor);
                if (bg.length === 4 && bg[3] < 1) {
                    const under = rgb(getComputedStyle(box.closest('.card')).backgroundColor);
                    bg = [0, 1, 2].map(i => bg[i] * bg[3] + under[i] * (1 - bg[3]));
                }
                const ratio = el => { const a = lum(rgb(getComputedStyle(el).color)), b = lum(bg); return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05); };
                return { link: ratio(document.getElementById('panelReleaseLink')), text: ratio(document.getElementById('panelReleaseText')) };
            }, theme);
            check(theme + ' theme: link ' + ratios.link.toFixed(2) + ':1, text ' + ratios.text.toFixed(2) + ':1 (at least 4.5:1)', ratios.link >= 4.5 && ratios.text >= 4.5);
        }
        await page.unroute('**/api/panel_info?action=uptime');

        console.log('\n== 5. A phone, and errors ==');
        await page.setViewportSize({ width: 375, height: 812 });
        await page.goto(BASE + '/updates');
        await page.waitForFunction(() => !document.getElementById('relAuto').disabled, null, { timeout: 30000 });
        const fits = await page.evaluate(() => {
            const card = document.getElementById('panelRelease').getBoundingClientRect();
            return card.right <= window.innerWidth + 1 && card.left >= -1;
        });
        check('at 375 px the card fits the screen', fits);
        check('no script errors (' + errors.join(' | ').slice(0, 160) + ')', errors.length === 0);
    } catch (e) {
        check('the run went to the end (' + e.message.split('\n')[0] + ')', false);
    } finally {
        await browser.close();
        tunnel.kill();
    }
    console.log(failures ? '\n' + failures + ' CHECKS FAILED' : '\nALL OK');
    process.exit(failures ? 1 : 0);
})();
