// The mail queue page in Chromium, in Italian and in English, with a simulated server that answers
// /api/queue like the panel and records every POST.
//
// What it checks: the texts in both languages; the four counters from the fields the server really
// sends (they used to read inflight/tempfail/permfail, which the server never sent: always 0);
// whatever comes from the mail (sender, subject, deferral reason, text) shown as text and never run
// as HTML; every POST carrying the CSRF token; deleting one message after the confirmation;
// deleting the permanent failures only after typing their number, with the IDs seen; the
// X-CSRF-Token header that the script in every page head adds to each fetch; the dates in
// the page language; no sideways scrolling on a phone.
//
// Usage (from the project root, after mvn package):
//   D=$(mktemp -d) && javac -cp target/daemoxcp-mail.jar -d tests tests/org/daemoxcp/mail/content/PageGenerator.java \
//     && java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.content.PageGenerator $D >/dev/null
//   NODE_PATH=$(npm root -g) node tests/queue-browser-test.js $D [screenshot-folder]
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const csp = require('./browser-csp');

const pages = process.argv[2];
const shots = process.argv[3];
const resources = path.join(__dirname, '..', 'src', 'main', 'resources');
// The Italian page is checked against the texts of it.json, never written here.
const IT = JSON.parse(fs.readFileSync(path.join(resources, 'lang', 'it.json'), 'utf8'));
const fill = (text, values) => text.replace(/\{([A-Za-z0-9_]+)\}/g, (all, k) => (k in values ? String(values[k]) : all));
const BASE = 'http://panel.test';
let failed = 0;
function check(what, ok) {
    console.log((ok ? '  OK   ' : '  FAILED ') + what);
    if (!ok) failed++;
}

let language = 'it';
const posts = [];
const XSS = '<img src=x onerror="window.__xss=1">';
let queue = [
    { id: '3A1F2B4C5D', state: 'DEFERRED', sender: 'news@example.org', size: 2048, arrival: '2025-10-10T10:00:00Z',
      recipients: [{ address: 'gone@example.com', reason: 'host mx.example.com said: 550 5.1.1 unknown user' }],
      error: 'host mx.example.com said: 550 5.1.1 unknown user', permanent: true },
    { id: '4Nq8Zk1yQPz9Lm2', state: 'DEFERRED', sender: XSS + '@example.org', size: 512, arrival: '2025-10-10T11:00:00Z',
      recipients: [{ address: 'b@example.net', reason: XSS + ' Connection timed out' }],
      error: XSS + ' Connection timed out', permanent: false },
    { id: '5B2C3D4E6F', state: 'ACTIVE', sender: '', size: 100, arrival: '2025-10-10T12:00:00Z',
      recipients: [{ address: 'you@example.com', reason: '' }], error: '', permanent: false }
];

function stats() {
    const count = s => queue.filter(m => m.state === s).length;
    return { success: true, total: queue.length, active: count('ACTIVE'), deferred: count('DEFERRED'), hold: count('HOLD'),
             incoming: 0, permanent: queue.filter(m => m.permanent).length, total_size: 0, top_senders: [], top_destinations: [] };
}

async function serve(route) {
    const req = route.request();
    const url = new URL(req.url());
    const p = url.pathname;
    const json = body => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
    if (p === '/queue') {
        const f = path.join(pages, 'queue' + (language === 'it' ? '' : '.' + language) + '.html');
        const html = fs.readFileSync(f, 'utf8').replace(/\{\{CSRF_TOKEN\}\}/g, 'csrf-test')
            .replace(/\{\{THEME\}\}/g, 'light').replace(/\{\{COLOR_SCHEME\}\}/g, 'light');
        return route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: html, headers: csp.headers(pages) });
    }
    if (p.startsWith('/assets/')) return csp.asset(route, pages, p);
    if (p.startsWith('/i18n/')) return route.fulfill({ status: 200, contentType: 'application/javascript', body: fs.readFileSync(path.join(pages, p)) });
    if (p.startsWith('/vendor/') || p.startsWith('/fa/')) {
        const f = path.join(resources, p);
        if (!fs.existsSync(f)) return route.fulfill({ status: 404, body: '' });
        const type = p.endsWith('.css') ? 'text/css' : p.endsWith('.js') ? 'application/javascript' : p.endsWith('.woff2') ? 'font/woff2' : 'application/octet-stream';
        return route.fulfill({ status: 200, contentType: type, body: fs.readFileSync(f) });
    }
    if (p === '/api/queue' && req.method() === 'GET') {
        const action = url.searchParams.get('action');
        if (action === 'stats') return json(stats());
        if (action === 'message') {
            return json({ success: true, from: 'News ' + XSS, to: 'gone@example.com', subject: '<script>window.__xss=2</script>',
                          date: 'Fri, 10 Oct 2025 10:00:00 +0000', body_preview: 'Hello ' + XSS + '\nsecond line', body_truncated: true });
        }
        return json({ success: true, count: queue.length, messages: queue });
    }
    if (p === '/api/queue' && req.method() === 'POST') {
        const body = JSON.parse(req.postData() || '{}');
        body.header = req.headers()['x-csrf-token'];
        posts.push(body);
        if (body.csrf_token !== 'csrf-test') return route.fulfill({ status: 403, contentType: 'application/json', body: '{"success":false,"error":"csrf"}' });
        if (body.action === 'remove') {
            queue = queue.filter(m => m.id !== body.id);
            return json({ success: true, message: 'Message ' + body.id + ' removed from the queue.' });
        }
        if (body.action === 'purge_permfails' && !body.ids) {
            const perm = queue.filter(m => m.permanent);
            return json({ success: true, preview: true, count: perm.length, messages: perm, message: perm.length + ' message with a permanent rejection.' });
        }
        if (body.action === 'purge_permfails') {
            queue = queue.filter(m => !(m.permanent && body.ids.includes(m.id)));
            return json({ success: true, message: '1 message with a permanent error removed.' });
        }
        return json({ success: true, message: 'ok ' + body.action });
    }
    return route.fulfill({ status: 200, contentType: 'application/json', body: '{"success":false}' });
}

async function text(page, sel) { return (await page.textContent(sel)).replace(/\s+/g, ' ').trim(); }

(async () => {
    const browser = await chromium.launch({ executablePath: process.env.CHROMIUM || '/opt/pw-browsers/chromium' }).catch(() => chromium.launch());
    const ctx = await browser.newContext({ viewport: { width: 1366, height: 900 }, timezoneId: 'Europe/Rome' });
    await ctx.route('**/*', serve);
    const page = await ctx.newPage();
    const errors = [];
    page.on('pageerror', e => errors.push(String(e)));
    csp.watch(page, errors);
    // Confirmations are the panel's window (reperto 198): a browser dialog is a fault, counted and closed.
    const dialogs = [];
    page.on('dialog', async d => { dialogs.push(d.type() + ': ' + d.message()); await d.dismiss(); });
    const answer = async accept => {
        await page.waitForSelector('#panelAskModal.show', { timeout: 5000 });
        const asked = await page.innerText('#panelAskModal .modal-content');
        await page.click(accept ? '#panelAskGo' : '#panelAskModal .modal-footer [data-bs-dismiss="modal"]');
        await page.waitForFunction(() => !document.getElementById('panelAskModal').classList.contains('show'), null, { timeout: 5000 });
        return asked;
    };

    console.log('\n== In Italian ==');
    await page.goto(BASE + '/queue');
    await page.waitForSelector('#queueBody tr td code');
    check('title and intro in Italian', (await text(page, 'h2')) === IT['que.title'] && (await text(page, '#main p.text-muted')) === IT['que.intro']);
    check('counters from total/active/deferred/hold: 3, 1, 2, 0', await text(page, '#statTotal') === '3' && await text(page, '#statActive') === '1'
        && await text(page, '#statDeferred') === '2' && await text(page, '#statHold') === '0');
    check('the permanent failures under Deferred', (await text(page, '#statPermanent')) === fill(IT['que.permanentOf.one'], { n: 1 }));
    check('Release disabled with nothing held, the others enabled', await page.isDisabled('#releaseBtn') && !(await page.isDisabled('#holdBtn'))
        && !(await page.isDisabled('#purgeBtn')) && !(await page.isDisabled('#flushBtn')));
    const headers = await page.$$eval('#queueTable thead th', e => e.map(x => x.textContent.trim()));
    check('column headers: ' + headers.join(', '), JSON.stringify(headers) === JSON.stringify(['que.colId', 'que.colState', 'que.colFrom', 'que.colTo',
        'que.colSize', 'que.colArrival', 'que.colError', 'home.colActions'].map(k => IT[k])));
    check('states translated', (await page.$$eval('.queue-state', e => e.map(x => x.textContent))).join('|')
        === [IT['que.state.deferred'], IT['que.state.deferred'], IT['que.state.active']].join('|'));
    check('the state badge has its color class', await page.locator('.queue-state.state-deferred').count() === 2 && await page.locator('.queue-state.state-active').count() === 1);
    check('the empty sender explained', (await page.textContent('#queueBody')).includes(IT['que.nullSender']));
    check('arrival in the page language and local time (12:00 in Rome)', (await page.textContent('#queueBody')).includes('10/10/2025, 12:00:00'));
    check('the sender with HTML in it shown as text, nothing run', (await page.textContent('#queueBody')).includes('<img src=x onerror=')
        && await page.locator('#queueBody img').count() === 0 && await page.evaluate(() => window.__xss === undefined));
    check('the row buttons have a name', await page.getAttribute('[data-queue-remove="3A1F2B4C5D"]', 'aria-label') === fill(IT['que.removeOf'], { id: '3A1F2B4C5D' }));

    console.log('\n== The details ==');
    await page.click('[data-queue-view="4Nq8Zk1yQPz9Lm2"]');
    await page.waitForSelector('#messageModal.show');
    const details = await page.textContent('#messageDetails');
    check('headers, envelope, recipients and text in the window', details.includes(IT['que.headers']) && details.includes(IT['que.envelope'])
        && details.includes('b@example.net') && details.includes('second line') && details.includes(IT['que.truncated']));
    check('subject, From and body with HTML: text, nothing run', details.includes('<script>window.__xss=2</script>')
        && await page.locator('#messageDetails img, #messageDetails script').count() === 0 && await page.evaluate(() => window.__xss === undefined));
    if (shots) await page.screenshot({ path: path.join(shots, 'queue-details.png') });
    await page.click('#messageModal .btn-close');
    await page.waitForSelector('#messageModal', { state: 'hidden' });

    console.log('\n== Deleting one message ==');
    await page.click('[data-queue-remove="5B2C3D4E6F"]');
    const asked = await answer(false);
    check('cancelled: nothing sent', posts.length === 0 && asked.includes('5B2C3D4E6F'));
    await page.click('[data-queue-remove="5B2C3D4E6F"]');
    await answer(true);
    await page.waitForSelector('#queueMsg .alert-success');
    check('confirmed: remove with the ID and the CSRF token', posts.length === 1 && posts[0].action === 'remove'
        && posts[0].id === '5B2C3D4E6F' && posts[0].csrf_token === 'csrf-test');
    await page.waitForFunction(() => document.querySelectorAll('#queueBody tr').length === 2);
    check('the answer in the message area, the list read again', (await text(page, '#queueMsg')) === 'Message 5B2C3D4E6F removed from the queue.');

    console.log('\n== Deleting the permanent failures ==');
    await page.click('#purgeBtn');
    const purge = await answer(false);
    check('the panel\'s window lists the recipient and the reason, with how many go and a red button',
        purge.includes('gone@example.com') && purge.includes('550 5.1.1') && purge.includes(fill(IT['que.purgeGo.one'], { n: 1 }))
        && await page.$eval('#panelAskGo', b => b.classList.contains('btn-danger')));
    check('cancelled: only the preview was sent', posts.length === 2 && !posts[1].ids && posts[1].csrf_token === 'csrf-test');
    await page.click('#purgeBtn');
    await answer(true);
    await page.waitForFunction(() => document.querySelectorAll('#queueBody tr').length === 1);
    const last = posts[posts.length - 1];
    check('the right number: the IDs seen and the number, with the token', last.action === 'purge_permfails'
        && JSON.stringify(last.ids) === '["3A1F2B4C5D"]' && last.confirm === '1' && last.csrf_token === 'csrf-test');
    check('every POST had the token', posts.every(b => b.csrf_token === 'csrf-test'));
    check('and the X-CSRF-Token header the shared script adds to every fetch that changes something',
        posts.every(b => b.header === 'csrf-test'));

    console.log('\n== Flush, hold ==');
    await page.click('#flushBtn');
    await answer(true);
    await page.waitForFunction(() => document.getElementById('queueMsg').textContent.includes('ok flush'));
    await page.click('#holdBtn');
    await answer(true);
    await page.waitForFunction(() => document.getElementById('queueMsg').textContent.includes('ok hold'));
    check('flush and hold asked first, then sent with the token', posts.slice(-2).map(b => b.action).join(',') === 'flush,hold'
        && posts.slice(-2).every(b => b.csrf_token === 'csrf-test'));

    console.log('\n== In English ==');
    language = 'en';
    queue.push({ id: '6C3D4E5F7A', state: 'HOLD', sender: 'me@example.org', size: 300, arrival: '2025-10-10T09:00:00Z',
                 recipients: [{ address: 'x@example.com', reason: '' }], error: '', permanent: false });
    await page.goto(BASE + '/queue');
    await page.waitForSelector('#queueBody tr td code');
    check('title, buttons and headers in English', (await text(page, 'h2')) === 'Mail queue' && (await text(page, '#flushBtn')) === 'Retry all now'
        && (await text(page, '#releaseBtn')) === 'Release held' && (await text(page, '#queueTable thead th:nth-child(7)')) === 'Deferral reason');
    check('states in English, the held one enables Release', (await page.$$eval('.queue-state', e => e.map(x => x.textContent))).join('|') === 'Deferred|Held'
        && !(await page.isDisabled('#releaseBtn')) && await page.isDisabled('#purgeBtn'));
    check('the date in English', (await page.textContent('#queueBody')).includes('10/10/2025, 13:00:00') || (await page.textContent('#queueBody')).includes('10/10/2025, 1:00:00 PM'));
    if (shots) await page.screenshot({ path: path.join(shots, 'queue-english.png') });
    queue = [];
    await page.click('text=Refresh');
    await page.waitForFunction(() => document.getElementById('queueBody').textContent.includes('The queue is empty'));
    check('an empty queue says so, the buttons with nothing to do disabled', await page.isDisabled('#flushBtn') && await page.isDisabled('#holdBtn'));

    console.log('\n== On a phone ==');
    queue = [{ id: '3A1F2B4C5D', state: 'DEFERRED', sender: 'a-very-long-sender-address-for-testing@subdomain.example.org', size: 2048,
               arrival: '2025-10-10T10:00:00Z', recipients: [{ address: 'gone@example.com', reason: 'x'.repeat(200) }], error: 'x'.repeat(200), permanent: true }];
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(BASE + '/queue');
    await page.waitForSelector('#queueBody tr td code');
    const wide = await page.evaluate(() => document.documentElement.scrollWidth);
    check('no sideways scrolling: ' + wide + 'px', wide <= 390);
    if (shots) await page.screenshot({ path: path.join(shots, 'queue-phone.png'), fullPage: true });

    check('no page errors' + (errors.length ? ': ' + errors.join(' | ') : ''), errors.length === 0);
    check('no browser dialog (confirmations are the panel\'s window)' + (dialogs.length ? ': ' + dialogs.join(' | ') : ''), dialogs.length === 0);
    await browser.close();
    console.log('\n' + (failed === 0 ? 'ALL GREEN' : failed + ' CHECKS FAILED'));
    process.exit(failed ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
