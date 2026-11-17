// The "Package branch" card of the Updates page in Chromium, on the English page, with the
// simulated server: the real logic (pkg -vv, the panel's file, the restores) is tested by
// PkgBranchTest. Here it is checked that the card reads itself, shows branch and repositories only
// as text, asks for the preview, wants the branch name typed by hand, sends fingerprint and CSRF
// token, follows the job to its outcome and says the errors.
//
// Usage (from the project root, after mvn package):
//   D=$(mktemp -d) && javac -cp target/daemoxcp-mail.jar -d tests tests/org/daemoxcp/mail/content/PageGenerator.java \
//     && java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.content.PageGenerator $D >/dev/null
//   NODE_PATH=$(npm root -g) node tests/pkg-branch-browser-test.js $D [screenshot-folder]
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
let branchNow = 'quarterly', changeSucceeds = true, readings = 0, rounds = 0;
function stateValue() {
    const latest = branchNow === 'latest';
    return { success: true, branch: branchNow, changeable: true, destination: [latest ? 'quarterly' : 'latest'],
        explanation: latest ? 'Rolling branch: versions arrive as soon as the port is updated and built.'
                            : 'Quarterly branch: it branches off the ports development in January, April, July and October.',
        fingerprint: latest ? 'bbbbbbbbbbbbbbbb' : 'aaaaaaaaaaaaaaaa',
        file: '/usr/local/etc/pkg/repos/zz-panel-branch.conf', panelOwnedFile: latest,
        repository: [
            { name: 'FreeBSD-ports', role: 'Packages (ports)', branch: branchNow, enabled: true, type: 'packages',
              url: 'pkg+https://pkg.FreeBSD.org/FreeBSD:15:amd64/' + branchNow },
            { name: 'FreeBSD-ports-kmods', role: 'Kernel modules', branch: branchNow, enabled: true, type: 'modules',
              url: 'pkg+https://pkg.FreeBSD.org/FreeBSD:15:amd64/kmods_' + branchNow + '_0' },
            { name: 'FreeBSD-base', role: 'Base system', branch: 'release', enabled: false, type: 'base',
              url: 'pkg+https://pkg.FreeBSD.org/FreeBSD:15:amd64/base_release_0' },
            { name: 'my<b>repo</b>', role: 'Unofficial repository', branch: '', enabled: true, type: 'external',
              url: 'file:///usr/local/<img src=x onerror="window.injectedRan=1">' },
        ] };
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
    // The script dictionary (t() and the texts), as the panel serves it.
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
        case 'branch_status': readings++; return json(route, stateValue());
        case 'branch_preview': return json(route, { success: true, possible: true, from: branchNow, destination: bodyText.destination,
            fingerprint: stateValue().fingerprint, file: '/usr/local/etc/pkg/repos/zz-panel-branch.conf',
            changes: [{ name: 'FreeBSD-ports', from: 'pkg+https://pkg.FreeBSD.org/FreeBSD:15:amd64/quarterly', to: 'pkg+https://pkg.FreeBSD.org/${ABI}/latest' }],
            warnings: ['No package is updated: it changes where pkg takes them from.', 'On latest the next update can bring new major versions.'],
            content: '# Written by DaemoxCP Mail\nFreeBSD-ports: { url: "pkg+https://pkg.FreeBSD.org/${ABI}/latest" }\n', howToReturn: '' });
        case 'branch_change':
            if (!changeSucceeds) return json(route, { success: false, error: 'A package job is already running (nginx update).' });
            rounds = 0;
            return json(route, { success: true, jobId: 'branch-1', async: true });
        case 'job_status':
            rounds++;
            if (rounds < 2) return json(route, { success: true, job: { status: 'running', consoleLog: '[12:00:00] [3/3] Downloading the catalog of the latest branch (pkg update -f)...\n' } });
            branchNow = 'latest';
            return json(route, { success: true, job: { status: 'completed', elapsedSeconds: 9, errorMessage: '',
                result: 'Packages now come from the latest branch, and its catalog is downloaded. No package was changed. 2 packages can be upgraded.',
                consoleLog: '[12:00:00] [3/3] Downloading the catalog...\n[12:00:09] All repositories are up to date.\n' } });
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
    // The branch has a card of its own under "Update the server" (reperto 205): it reads itself, nothing to open.
    await page.waitForSelector('#branch-body table');
    real('the branch is a card of its own, not a row of "Update the server"', await page.$('section#branch.card') !== null
        && await page.$('#uc-branch') === null && await page.$('#update-center #branch-body') === null);
    const textValue = await page.textContent('#branch-body');
    real('quarterly branch, with the explanation', textValue.includes('Packages come from the quarterly branch') && textValue.includes('Quarterly branch'));
    const lineItems = await page.$$eval('#branch-body tbody tr', tr => tr.map(r => r.cells[0].textContent));
    real('the four repositories, the unofficial one too: ' + lineItems.join(', '), lineItems.length === 4 && lineItems[3] === 'my<b>repo</b>');
    real('names and addresses stay text: no <b>, no <img>', await page.locator('#branch-body b, #branch-body img').count() === 0
        && await page.evaluate(() => window.injectedRan) === undefined);
    real('out of the box: "no panel file"', textValue.includes('No panel file'));
    real('the button to switch to latest', await page.locator('#branch-body button', { hasText: 'Switch to the latest branch' }).count() === 1);
    if (photos) await page.locator('#branch').screenshot({ path: path.join(photos, 'branch-card.png') });

    console.log('\n== Preview and confirmation ==');
    await page.click('#branch-body button:has-text("Switch to the latest branch")');
    await page.waitForSelector('#branch-confirm');
    const previewText = await page.textContent('#branch-preview');
    real('the preview: what changes, the warnings, the file being written', previewText.includes('Switch from the quarterly branch to the latest branch')
        && previewText.includes('pkg+https://pkg.FreeBSD.org/${ABI}/latest') && previewText.includes('No package is updated')
        && previewText.includes('zz-panel-branch.conf'));
    real('"Change branch" off until latest is typed', await page.isDisabled('#branch-go'));
    await page.fill('#branch-confirm', 'Latest');
    real('typed differently (Latest): it stays off', await page.isDisabled('#branch-go'));
    await page.fill('#branch-confirm', 'latest');
    real('typed right: it turns on', await page.isEnabled('#branch-go'));
    if (photos) await page.locator('#branch').screenshot({ path: path.join(photos, 'branch-preview-shot.png') });

    console.log('\n== The change, followed to its outcome ==');
    await page.click('#branch-go');
    const post = requests.find(r => r.body && r.body.action === 'branch_change');
    real('the request: branch, confirmation, the preview\'s fingerprint, CSRF token', post && post.body.destination === 'latest'
        && post.body.confirm === 'latest' && post.body.fingerprint === 'aaaaaaaaaaaaaaaa' && post.body.csrf_token === 'csrf-test');
    await page.waitForFunction(() => document.getElementById('branch-outcome').textContent.includes('Packages now come from'), null, { timeout: 15000 });
    real('the job log can be seen', (await page.textContent('#branch-log')).includes('All repositories are up to date'));
    real('the outcome, in green', await page.locator('#branch-outcome .alert-success').count() === 1);
    await page.waitForFunction(() => document.getElementById('branch-body').textContent.includes('the latest branch'));
    real('the card reads itself again: now latest, with the panel\'s file', readings === 2
        && (await page.textContent('#branch-body')).includes('The branch is decided by the panel\'s file'));
    if (photos) await page.locator('#branch').screenshot({ path: path.join(photos, 'branch-after.png') });

    console.log('\n== A change that does not start ==');
    changeSucceeds = false;
    await page.click('#branch-body button:has-text("Switch to the quarterly branch")');
    await page.waitForSelector('#branch-confirm');
    await page.fill('#branch-confirm', 'quarterly');
    await page.click('#branch-go');
    await page.waitForSelector('#branch-outcome .alert-danger');
    real('the server\'s error, in red: ' + await page.textContent('#branch-outcome'), (await page.textContent('#branch-outcome')).includes('package job is already running'));
    real('and it can be tried again', await page.isEnabled('#branch-go'));

    console.log('\n== Dark theme and phone ==');
    await page.evaluate(() => document.documentElement.setAttribute('data-theme', 'dark'));
    await page.waitForTimeout(600);   // the theme change has a transition
    if (photos) await page.locator('#branch').screenshot({ path: path.join(photos, 'branch-dark.png') });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.evaluate(() => document.documentElement.setAttribute('data-theme', 'light'));
    await page.waitForTimeout(300);
    const pageWidth = await page.evaluate(() => document.documentElement.scrollWidth);
    real('on the phone the page does not scroll sideways: ' + pageWidth + 'px', pageWidth <= 390);
    if (photos) await page.locator('#branch').screenshot({ path: path.join(photos, 'branch-phone.png') });

    real('no error in the page' + (errorList.length ? ': ' + errorList.join(' | ') : ''), errorList.length === 0);
    await browser.close();
    console.log('\n' + (failedOnes === 0 ? 'ALL GREEN' : failedOnes + ' CHECKS FAILED'));
    process.exit(failedOnes ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
