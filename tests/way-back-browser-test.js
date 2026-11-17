// The notice of the interrupted reinstallation in the Updates page, in Chromium, with the simulated
// server (reperto 170), on the English page: the "Go back to the server before the reinstallation"
// button is there only for the reinstallation with its way back; it asks for confirmation; it sends
// action, name and confirmation; it says the outcome and the restart; a refusal from the server can
// be read; cancelling sends nothing; the name is shown as text (not as HTML). The real function is
// tested by ReinstallReturnE2ETest and RolesTest.
//
// Usage (from the project root, after mvn package):
//   D=$(mktemp -d) && javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/daemoxcp/mail/content/PageGenerator.java \
//     && java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.daemoxcp.mail.content.PageGenerator $D >/dev/null
//   NODE_PATH=$(npm root -g) node tests/way-back-browser-test.js $D [screenshot-folder]
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

const WAY_BACK = 'reinstall-before-2026-11-06-120000';
let notice = null;
let wayBackAnswer = null;
const requests = [];

function json(route, body) { return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) }); }

async function served(route) {
    const req = route.request();
    const p = new URL(req.url()).pathname;
    if (p === '/updates') {
        const html = fs.readFileSync(path.join(pageList, 'updates.en.html'), 'utf8').replace(/\{\{CSRF_TOKEN\}\}/g, 'csrf-test');
        return route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: html, headers: csp.headers(pageList) });
    }
    if (p.startsWith('/assets/')) return csp.asset(route, pageList, p);
    if (p.startsWith('/i18n/')) return route.fulfill({ status: 200, contentType: 'application/javascript', body: fs.readFileSync(path.join(pageList, p)) });
    if (p.startsWith('/vendor/') || p.startsWith('/fa/')) {
        const f = path.join(resourceList, p);
        if (!fs.existsSync(f)) return route.fulfill({ status: 404, body: '' });
        const kind = p.endsWith('.css') ? 'text/css' : p.endsWith('.js') ? 'application/javascript' : p.endsWith('.woff2') ? 'font/woff2' : 'application/octet-stream';
        return route.fulfill({ status: 200, contentType: kind, body: fs.readFileSync(f) });
    }
    const body = req.postData() ? JSON.parse(req.postData()) : null;
    requests.push({ path: p, body: body });
    if (p !== '/api/updates' || !body) return json(route, { success: true });
    switch (body.action) {
        case 'interruption_status': return json(route, { success: true, notice: notice });
        case 'reinstall_way_back': return json(route, wayBackAnswer);
        default: return json(route, { success: true });
    }
}

// The notice must appear at load time, even if other slow requests (branch_status,
// packages_overview) start first: updApi's guard turned it away without asking (reperto 176).
async function open(page) {
    await page.goto(BASE + '/updates');
    const shown = await page.waitForFunction(() => document.getElementById('upd-interrupted')
        && document.getElementById('upd-interrupted').innerHTML.length > 0, null, { timeout: 10000 }).then(() => true, () => false);
    real('the notice appears when the page loads', shown);
    if (!shown) { console.log('\n' + failedOnes + ' CHECKS FAILED'); process.exit(1); }
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

    console.log('\n== Any job interrupted: no button to go back ==');
    notice = { description: 'nginx update', text: 'A job did not reach the end.' };
    await open(page);
    real('the notice is there', (await page.textContent('#upd-interrupted')).includes('A job did not reach the end'));
    real('no button to go back', await page.locator('#upd-way-back-btn').count() === 0);

    console.log('\n== The interrupted reinstallation, with its way back ==');
    notice = { description: 'complete mail server installation', reinstall: true, wayBack: WAY_BACK,
               text: 'It was the full reinstallation of the mail server.' };
    await open(page);
    const btn = page.locator('#upd-way-back-btn');
    real('the button is there, with the name of the way back', await btn.count() === 1 && (await btn.textContent()).includes(WAY_BACK));

    console.log('\n== Cancelling the confirmation sends nothing ==');
    // The panel's window (reperto 197): what it says, then "Cancel".
    const before = requests.filter(r => r.body && r.body.action === 'reinstall_way_back').length;
    await btn.click();
    await page.waitForSelector('#panelAskModal.show');
    const asked = await page.innerText('#panelAskModal');
    await page.click('#panelAskModal .modal-footer [data-bs-dismiss="modal"]');
    await page.waitForFunction(() => !document.getElementById('panelAskModal').classList.contains('show'), null, { timeout: 5000 });
    await page.waitForTimeout(400);
    real('it asks for confirmation, with the name', asked.includes(WAY_BACK));
    real('and cancelling does not send the request', requests.filter(r => r.body && r.body.action === 'reinstall_way_back').length === before);

    console.log('\n== Confirming: the request and the outcome ==');
    wayBackAnswer = { success: true, name: WAY_BACK, merged: 3, note: 'At the next restart the server is the one from before.',
                      log: ['3 mail files that arrived later copied inside.'], reboot: { success: true } };
    await btn.click();
    await page.waitForSelector('#panelAskModal.show');
    await page.click('#panelAskGo');
    await page.waitForSelector('#upd-interrupted .alert-success');
    const sent = requests.filter(r => r.body && r.body.action === 'reinstall_way_back').pop();
    real('it sends action, name and confirmation', sent && sent.body.name === WAY_BACK && sent.body.confirm === 'GO BACK');
    const done = await page.textContent('#upd-interrupted');
    real('it says the outcome, the files added and the restart', done.includes('At the next restart the server is the one from before')
        && done.includes('3 mail files') && done.includes('restarts in one minute'));
    if (photos) await page.screenshot({ path: path.join(photos, 'way-back-done.png'), fullPage: true });

    console.log('\n== The server refuses ==');
    await open(page);
    wayBackAnswer = { success: false, error: 'The boot environment is no longer there: I did nothing.' };
    await page.locator('#upd-way-back-btn').click();
    await page.waitForSelector('#panelAskModal.show');
    await page.click('#panelAskGo');
    await page.waitForSelector('#upd-interrupted .alert-danger');
    real('the refusal can be read', (await page.textContent('#upd-interrupted .alert-danger')).includes('no longer there'));

    console.log('\n== The restart cannot be scheduled ==');
    await open(page);
    wayBackAnswer = { success: true, note: 'Ready.', log: [], reboot: { success: false } };
    await page.locator('#upd-way-back-btn').click();
    await page.waitForSelector('#panelAskModal.show');
    await page.click('#panelAskGo');
    await page.waitForSelector('#upd-interrupted .alert-success');
    real('it says to restart by hand', (await page.textContent('#upd-interrupted')).includes('shutdown -r now'));

    console.log('\n== A name with HTML in it is shown as text ==');
    notice = { reinstall: true, wayBack: WAY_BACK + '<img src=x onerror="window.injectedRan=1">', text: 'x' };
    await open(page);
    await page.waitForTimeout(300);
    real('no code run from the name', await page.evaluate(() => window.injectedRan === undefined));

    real('no error in the page' + (errorList.length ? ': ' + errorList.join(' | ') : ''), errorList.length === 0);
    await browser.close();
    console.log(failedOnes === 0 ? '\nALL GREEN' : '\n' + failedOnes + ' CHECKS FAILED');
    process.exit(failedOnes === 0 ? 0 : 1);
})();
