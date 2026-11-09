// The Home in Chromium: the Version column of "Mail services" (with MySQL and Redis), the "Other
// software" table, the "needs a restart" notes, the confirmations before stopping a service and the
// CSRF token sent to /api/service. The server is simulated: the real reads are tested by
// SoftwareVersionsTest. Here it is checked that the page shows what the server says, only as text.
// The Italian page is checked against the texts of it.json, never written here.
//
// Usage (from the project root, after mvn package):
//   D=$(mktemp -d) && javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/content/PageGenerator.java \
//     && java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.content.PageGenerator $D >/dev/null
//   NODE_PATH=$(npm root -g) node tests/software-versions-browser-test.js $D [screenshot-folder]
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const csp = require('./browser-csp');

const pageList = process.argv[2];
const photos = process.argv[3];
const resourceList = path.join(__dirname, '..', 'src', 'main', 'resources');
const IT = JSON.parse(fs.readFileSync(path.join(resourceList, 'lang', 'it.json'), 'utf8'));
const fill = (text, values) => text.replace(/\{([A-Za-z0-9_]+)\}/g, (all, k) => (k in values ? String(values[k]) : all));
const SERVICES_TABLE = 'table[aria-label="' + IT['home.servicesTable'] + '"]';
const BASE = 'http://panel.test';
let failedOnes = 0;
function real(whatItem, ok) {
    console.log((ok ? '  OK   ' : '  FAILED ') + whatItem);
    if (!ok) failedOnes++;
}

const requests = [];
const VERSIONS = {
    success: true, readAt: '2026-10-03T14:00:05+02:00', branch: 'quarterly',
    services: {
        postfix: { key: 'postfix', name: 'Postfix', role: 'SMTP server', installed: true, version: '3.10.4', source: '/usr/local/sbin/postconf -h mail_version',
            pkgName: 'postfix-mysql-3.10.4,1', restart: true,
            restartNote: 'Postfix started on 28/09/2026 08:15, before the package was installed (02/10/2026 09:00): it is running the old version. Restart it to use the installed one.' },
        dovecot: { key: 'dovecot', name: 'Dovecot', role: 'IMAP', installed: true, version: '2.3.21.1', source: '/usr/local/sbin/dovecot --version', pkgName: 'dovecot-mysql-2.3.21.1_8' },
        mysql: { key: 'mysql', name: 'MySQL', role: 'Database', installed: true, version: '8.0.42', source: "SELECT VERSION() on the panel's connection",
            running: true, pkgName: 'mysql80-server-8.0.43', restart: true, installedVersion: '8.0.43',
            restartNote: 'The running MySQL is 8.0.42, the installed one 8.0.43: restart MySQL to use the installed one.' },
        rspamd: { key: 'rspamd', name: 'Rspamd', role: 'Antispam', installed: true, version: '<img src=x onerror="window.injectedRan=1">',
            source: 'test', pkgName: 'rspamd-3.12.1' },
        redis: { key: 'redis', name: 'Redis', role: 'Data store', installed: false },
        clamav: { key: 'clamav', name: 'ClamAV', role: 'Antivirus', installed: true, version: '1.4.3', running: true, signatures: '27780',
            detail: 'signatures 27780 of 02/10/2026 08:24', pkgName: 'clamav-1.4.3,1' },
        roundcube: { key: 'roundcube', name: 'Roundcube', role: 'Webmail', installed: true, version: '1.6.11', pkgName: 'roundcube-php84-1.6.11,1' },
    },
    other: [
        { key: 'freebsd', name: 'FreeBSD', role: 'Operating system', installed: true, version: '15.0-RELEASE-p3', detail: 'running kernel 15.0-RELEASE-p2',
            restart: true, restartNote: 'The installed kernel is 15.0-RELEASE-p3, the running one 15.0-RELEASE-p2: the server needs a restart.' },
        { key: 'openssl', name: 'OpenSSL', role: 'TLS library of the base system: the official packages use it', installed: true, version: '3.5.1', detail: 'released on 01/07/2025' },
        { key: 'nginx', name: 'nginx', role: 'Web server: webmail, MTA-STS, automatic client configuration', installed: true, version: '1.28.0', pkgName: 'nginx-1.28.0_3,3' },
        { key: 'php', name: 'PHP-FPM', role: 'Runs the webmail', installed: true, version: '8.4.13', pkgName: 'php84-8.4.13' },
        { key: 'pigeonhole', name: 'Pigeonhole', role: 'Sieve filters and auto-replies', installed: false },
        { key: 'java', name: 'Java', role: 'Runs this panel', installed: true, version: '25.0.1+8-1', running: true, pkgName: 'openjdk25-25.0.1+8.1' },
        { key: 'clamav', name: 'ClamAV', role: 'Antivirus', installed: true, version: '1.4.3', warning: 'The signatures are 19 days old: freshclam is not updating them, and new viruses get through.' },
    ],
};
// The last row of "other" is fake (ClamAV does not belong there): it is there to see the warning in red.

function json(route, bodyText) { return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(bodyText) }); }

async function served(route) {
    const req = route.request();
    const url = new URL(req.url());
    const p = url.pathname;
    if (p === '/') {
        const html = fs.readFileSync(path.join(pageList, 'home.html'), 'utf8').replace(/\{\{CSRF_TOKEN\}\}/g, 'csrf-test');
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
    requests.push({ method: req.method(), path: p + url.search, body: bodyText });
    if (p === '/api/status') return json(route, { postfix: true, dovecot: true, mysql: true, rspamd: true, redis: false, clamav: true, roundcube: true,
        domains: 2, mailboxes: 5, aliases: 3, mail_hostname: '', server_ip: '' });
    if (p === '/api/versions') return json(route, VERSIONS);
    if (p === '/api/service') return json(route, { success: true });
    if (p === '/api/updates') return json(route, { success: true, active: true, reason: 'The panel restarts by itself.' });
    return json(route, { success: true });
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

    console.log('\n== Mail services: the Version column ==');
    await page.goto(BASE + '/');
    await page.waitForFunction(prefix => document.getElementById('versionsState').textContent.startsWith(prefix), IT['ver.readAt'].split(' ')[0]);
    const lineItems = await page.$$eval(SERVICES_TABLE + ' tbody tr', tr => tr.map(r => r.cells[0].textContent.trim()));
    real('seven rows, with MySQL and Redis: ' + lineItems.join(' | '), lineItems.length === 7 && lineItems[2] === 'MySQL (Database)' && lineItems[4] === 'Redis (' + IT['home.redisRole'] + ')');
    const pf = await page.textContent('#ver-postfix');
    real('Postfix: 3.10.4, the package and "needs a restart" with the note', pf.includes('3.10.4') && pf.includes(fill(IT['ver.package'], { name: 'postfix-mysql-3.10.4,1' }))
        && pf.includes(IT['ver.restartNeeded']) && pf.includes('28/09/2026 08:15'));
    real('the source in the version\'s title', await page.getAttribute('#ver-postfix strong', 'title') === fill(IT['ver.readWith'], { source: '/usr/local/sbin/postconf -h mail_version' }));
    const my = await page.textContent('#ver-mysql');
    real('MySQL: 8.0.42 (running), needs a restart because the package is 8.0.43', my.includes('8.0.42') && my.includes(IT['ver.running'])
        && my.includes(IT['ver.restartNeeded']) && my.includes('the installed one 8.0.43'));
    real('ClamAV: engine and signatures', (await page.textContent('#ver-clamav')).includes('signatures 27780 of 02/10/2026 08:24'));
    real('Redis not installed', (await page.textContent('#ver-redis')).trim() === IT['ver.notInstalled']);
    real('state of Redis: Stopped; of MySQL: Running', (await page.textContent('#redis-status')) === IT['home.stopped'] && (await page.textContent('#mysql-status')) === IT['home.running']);
    const injected = await page.evaluate(() => ({ img: document.querySelectorAll('#ver-rspamd img').length, flag: window.injectedRan }));
    real('a version with HTML in it stays text: no <img>, no script', injected.img === 0 && injected.flag === undefined
        && (await page.textContent('#ver-rspamd strong')).startsWith('<img'));
    const stateValue = await page.textContent('#versionsState');
    real('summary: time of the read and how many need a restart — ' + stateValue, stateValue.startsWith(fill(IT['ver.readAt'], { time: '14:00:05' }))
        && stateValue.includes(fill(IT['ver.toRestart.other'], { n: 3 }).split(':')[0]));
    real('and the package branch, with the link to the card to change it', stateValue.includes(IT['ver.branch'] + ' quarterly.')
        && await page.getAttribute('#versionsState a', 'href') === '/updates#branch');

    console.log('\n== Other software ==');
    const otherOne = await page.$$eval('#otherSoftware tr', tr => tr.map(r => [...r.cells].map(c => c.textContent.trim())));
    real('one row per program: ' + otherOne.map(r => r[0]).join(', '), otherOne.length === 7 && otherOne[0][0] === 'FreeBSD' && otherOne[5][0] === 'Java');
    real('FreeBSD: userland, running kernel, server restart', otherOne[0][2].includes('15.0-RELEASE-p3') && otherOne[0][2].includes('running kernel 15.0-RELEASE-p2')
        && otherOne[0][2].includes('the server needs a restart'));
    real('what it is for: nginx', otherOne[2][1].startsWith('Web server'));
    real('Pigeonhole not installed', otherOne[4][2] === IT['ver.notInstalled']);
    real('the warning is red, the restart note yellow', await page.locator('#otherSoftware .text-risk').count() === 1
        && await page.locator('#otherSoftware .text-caution').count() === 1);
    real('every cell has its label for the phone', await page.locator('#otherSoftware td:not([data-label])').count() === 0);
    if (photos) await page.screenshot({ path: path.join(photos, 'home-versions.png'), fullPage: true });

    console.log('\n== Commands: names, confirmations, CSRF ==');
    real('the buttons have a name: Start/Restart/Stop Postfix, Stop the webmail',
        await page.locator('button[aria-label="' + IT['home.start'] + ' Postfix"]').count() === 1 && await page.locator('button[aria-label="' + IT['home.restart'] + ' Postfix"]').count() === 1
        && await page.locator('button[aria-label="' + IT['home.stop'] + ' Postfix"]').count() === 1 && await page.locator('button[aria-label="' + IT['home.stop'] + ' ' + IT['home.theWebmail'] + '"]').count() === 1);
    // The panel's window and its notices (reperto 198), not the browser's dialogs.
    const ask = async accept => {
        await page.waitForSelector('#panelAskModal.show', { timeout: 5000 });
        const q = await page.innerText('#panelAskModal .modal-body');
        await page.click(accept ? '#panelAskGo' : '#panelAskModal .modal-footer [data-bs-dismiss="modal"]');
        await page.waitForFunction(() => !document.getElementById('panelAskModal').classList.contains('show'), null, { timeout: 5000 });
        return q;
    };
    const notices = () => page.$$eval('#panelNotices .alert', a => a.map(x => x.innerText.trim()));
    const clearNotices = () => page.evaluate(() => { const b = document.getElementById('panelNotices'); if (b) b.replaceChildren(); });
    const beforeValue = requests.length;
    await page.click('button[aria-label="' + IT['home.stop'] + ' Postfix"]');
    const question = await ask(false);
    real('Stop Postfix: it asks in the panel\'s window, and says what happens — ' + question.replace(/\s+/g, ' '), question.includes(IT['home.confirm.postfix.stop'].split('\n')[0]));
    real('cancelled: no request', !requests.slice(beforeValue).some(r => r.path === '/api/service'));
    await page.click('button[aria-label="' + IT['home.stop'] + ' Postfix"]');
    await ask(true);
    await page.waitForTimeout(500);
    const post = requests.find(r => r.path === '/api/service');
    real('confirmed: POST with service, action and CSRF token', post && post.body.service === 'postfix' && post.body.action === 'stop'
        && post.body.csrf_token === 'csrf-test');
    real('after the command the versions are read again at once (?fresh=1)', requests.some(r => r.path === '/api/versions?fresh=1'));
    await clearNotices();
    await page.click('button[aria-label="' + IT['home.restart'] + ' Postfix"]');
    await page.waitForTimeout(400);
    const said = await notices();
    real('Restart Postfix: no question, only the outcome, as a notice of the panel', !await page.$('#panelAskModal.show')
        && said.length === 1 && said[0].includes(IT['common.done']));
    await clearNotices();
    await page.click('button[aria-label="' + IT['home.restart'] + ' MySQL"]');
    const mysqlQuestion = await ask(true);
    await page.waitForTimeout(400);
    real('Restart MySQL: it asks first — ' + mysqlQuestion.replace(/\s+/g, ' ').slice(0, 80), mysqlQuestion.includes(IT['home.confirm.mysql.restart'].split('\n')[0])
        && (await notices()).length === 1);
    const mysql = requests.filter(r => r.path === '/api/service').pop();
    real('and it sends mysql-server', mysql.body.service === 'mysql-server' && mysql.body.action === 'restart');
    const n = requests.filter(r => r.path === '/api/versions?fresh=1').length;
    await page.click('#versionsReread');
    await page.waitForFunction(k => true, n);
    await page.waitForTimeout(300);
    real('"Read the versions again" asks for a fresh read', requests.filter(r => r.path === '/api/versions?fresh=1').length === n + 1);

    console.log('\n== Dark theme and phone ==');
    await page.evaluate(() => document.documentElement.setAttribute('data-theme', 'dark'));
    await page.waitForTimeout(600);   // the theme change has a transition
    if (photos) await page.screenshot({ path: path.join(photos, 'home-versions-dark.png'), fullPage: true });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.evaluate(() => document.documentElement.setAttribute('data-theme', 'light'));
    await page.waitForTimeout(300);
    const pageWidth = await page.evaluate(() => document.documentElement.scrollWidth);
    real('on the phone the page does not scroll sideways: ' + pageWidth + 'px', pageWidth <= 390);
    real('on the phone the tables become cards (headers hidden)',
        await page.$eval(SERVICES_TABLE + ' thead', t => getComputedStyle(t).display) === 'none');
    if (photos) {
        await page.locator(SERVICES_TABLE).scrollIntoViewIfNeeded();
        await page.screenshot({ path: path.join(photos, 'home-versions-phone.png') });
    }

    real('no error in the page' + (errorList.length ? ': ' + errorList.join(' | ') : ''), errorList.length === 0);
    await browser.close();
    console.log('\n' + (failedOnes === 0 ? 'ALL GREEN' : failedOnes + ' CHECKS FAILED'));
    process.exit(failedOnes ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
