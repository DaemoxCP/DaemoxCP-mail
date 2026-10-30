// The Sending limits and Statistics pages in Chromium, in Italian and in English, with a simulated
// server that answers like the panel and records every POST.
//
// Sending limits: the notice that hourly and daily limits are saved but not applied; the global
// limits read and saved with the CSRF token; a mailbox limit created with the action and fields
// the server knows (save_mailbox, mailbox_id, hourly, daily: the page used to send create/update,
// which the server did not know), edited without changing mailbox, deleted after the
// confirmation; a mailbox address with HTML in it shown as text.
// Statistics: the notice that sent/received counts are not collected; the cards from "totals" and
// the per-domain table from "domains" (the page used to read fields the server never sent); the
// Rspamd numbers read from the top level of the answer (they used to be looked for under "stats":
// always "-"); the period sent as days; numbers and dates in the page language.
//
// Usage (from the project root, after mvn package):
//   D=$(mktemp -d) && javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/content/PageGenerator.java \
//     && java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.content.PageGenerator $D >/dev/null
//   NODE_PATH=$(npm root -g) node tests/limits-statistics-browser-test.js $D [screenshot-folder]
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const pages = process.argv[2];
const shots = process.argv[3];
const resources = path.join(__dirname, '..', 'src', 'main', 'resources');
const BASE = 'http://panel.test';
let failed = 0;
function check(what, ok) {
    console.log((ok ? '  OK   ' : '  FAILED ') + what);
    if (!ok) failed++;
}

let language = 'it';
const posts = [];
const statsQueries = [];
const XSS = '<img src=x onerror="window.__xss=1">';
let limits = [{ id: 4, email: 'info@example.com', target_id: 11, hourly_limit: 20, daily_limit: 200, max_recipients: 50, enabled: true }];

async function serve(route) {
    const req = route.request();
    const url = new URL(req.url());
    const p = url.pathname;
    const json = body => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
    if (p === '/ratelimits' || p === '/statistics') {
        const f = path.join(pages, p.slice(1) + (language === 'it' ? '' : '.' + language) + '.html');
        const html = fs.readFileSync(f, 'utf8').replace(/\{\{CSRF_TOKEN\}\}/g, 'csrf-test')
            .replace(/\{\{THEME\}\}/g, 'light').replace(/\{\{COLOR_SCHEME\}\}/g, 'light');
        return route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: html });
    }
    if (p.startsWith('/i18n/')) return route.fulfill({ status: 200, contentType: 'application/javascript', body: fs.readFileSync(path.join(pages, p)) });
    if (p.startsWith('/vendor/') || p.startsWith('/fa/')) {
        const f = path.join(resources, p);
        if (!fs.existsSync(f)) return route.fulfill({ status: 404, body: '' });
        const type = p.endsWith('.css') ? 'text/css' : p.endsWith('.js') ? 'application/javascript' : p.endsWith('.woff2') ? 'font/woff2' : 'application/octet-stream';
        return route.fulfill({ status: 200, contentType: type, body: fs.readFileSync(f) });
    }
    if (p === '/api/ratelimits' && req.method() === 'GET') {
        return json({ success: true, limits, global: { hourly: 30, daily: 300, max_recipients: 50, max_size_mb: 25 } });
    }
    if (p === '/api/ratelimits' && req.method() === 'POST') {
        const body = JSON.parse(req.postData() || '{}');
        posts.push(body);
        if (body.csrf_token !== 'csrf-test') return route.fulfill({ status: 403, contentType: 'application/json', body: '{"success":false,"error":"csrf"}' });
        if (body.action === 'save_global') return json({ success: true, message: 'Limiti globali salvati: ' + body.hourly + " all'ora, " + body.daily + ' al giorno.' });
        if (body.action === 'save_mailbox') {
            const l = limits.find(x => x.target_id === body.mailbox_id);
            if (l) Object.assign(l, { hourly_limit: body.hourly, daily_limit: body.daily, enabled: body.enabled });
            else limits.push({ id: 9, email: XSS + '@example.com', target_id: body.mailbox_id, hourly_limit: body.hourly, daily_limit: body.daily, max_recipients: 50, enabled: body.enabled });
            return json({ success: true, message: 'Limite della casella salvato.' });
        }
        if (body.action === 'delete') {
            limits = limits.filter(x => x.id !== body.id);
            return json({ success: true });
        }
        return json({ success: false, error: 'Azione sconosciuta.' });
    }
    if (p === '/api/mailboxes') {
        return json({ success: true, mailboxes: [{ id: 11, email: 'info@example.com' }, { id: 12, email: XSS + '@example.com' }] });
    }
    if (p === '/api/statistics') {
        statsQueries.push(url.searchParams.get('days'));
        return json({ success: true, days: 7, totals: { sent: 1234, received: 5678, spam: 90, virus: 0, bounced: 12 },
                      daily: [{ date: '2025-10-09', sent: 600, received: 3000 }, { date: '2025-10-10', sent: 634, received: 2678 }],
                      domains: [{ domain: XSS + '.example', sent: 1234, received: 5678, spam: 90, bounced: 12 }],
                      spam_trained: 3, ham_trained: 5 });
    }
    if (p === '/api/rspamd') {
        return json({ success: true, scanned: 2000, spam_count: 150, ham_count: 1850, spam_percent: 7.5, uptime: 3600, version: '3.10' });
    }
    return route.fulfill({ status: 200, contentType: 'application/json', body: '{"success":false}' });
}

async function text(page, sel) { return (await page.textContent(sel)).replace(/\s+/g, ' ').trim(); }

(async () => {
    const browser = await chromium.launch({ executablePath: process.env.CHROMIUM || '/opt/pw-browsers/chromium' }).catch(() => chromium.launch());
    const ctx = await browser.newContext({ viewport: { width: 1366, height: 900 } });
    await ctx.route('**/*', serve);
    const page = await ctx.newPage();
    const errors = [];
    page.on('pageerror', e => errors.push(String(e)));
    const dialogs = [];
    let accept = true;
    page.on('dialog', async d => { dialogs.push(d.message()); if (accept) await d.accept(); else await d.dismiss(); });

    console.log('\n== Sending limits, in Italian ==');
    await page.goto(BASE + '/ratelimits');
    await page.waitForSelector('#limitsBody [data-limit-edit]');
    check('title and the notice that the limits are not applied', (await text(page, 'h2')) === 'Limiti di invio'
        && (await text(page, '.alert-warning')).includes('salvati ma non ancora applicati'));
    check('global limits read: 30, 300, 25 MB', await page.inputValue('#globalHourly') === '30' && await page.inputValue('#globalDaily') === '300'
        && await page.inputValue('#globalMaxSize') === '25');
    await page.fill('#globalHourly', '40');
    await page.click('text=Salva i limiti globali');
    await page.waitForSelector('#rlMsg .alert-success');
    check('save_global with the values and the CSRF token', posts.length === 1 && posts[0].action === 'save_global' && posts[0].hourly === 40
        && posts[0].daily === 300 && posts[0].max_size_mb === 25 && posts[0].csrf_token === 'csrf-test');
    check('the answer shown', (await text(page, '#rlMsg')).startsWith('Limiti globali salvati: 40'));

    await page.click('text=Nuovo limite');
    await page.waitForSelector('#addLimitModal.show');
    await page.waitForFunction(() => document.querySelectorAll('#limitMailbox option').length === 3);
    check('the mailbox list: the address with HTML is an option text, not an element', await page.locator('#limitMailbox img').count() === 0
        && (await page.$$eval('#limitMailbox option', o => o.map(x => x.textContent))).includes(XSS + '@example.com'));
    await page.click('#addLimitModal .btn-primary');
    check('no mailbox chosen: said in the window, nothing sent', (await text(page, '#limitErr')) === 'Scegli una casella.' && posts.length === 1);
    await page.selectOption('#limitMailbox', '12');
    await page.fill('#limitHourly', '5');
    await page.fill('#limitDaily', '50');
    await page.click('#addLimitModal .btn-primary');
    await page.waitForFunction(() => document.querySelectorAll('#limitsBody tr').length === 2);
    const created = posts[posts.length - 1];
    check('save_mailbox with mailbox_id, hourly, daily, enabled and the token', created.action === 'save_mailbox' && created.mailbox_id === 12
        && created.hourly === 5 && created.daily === 50 && created.enabled === true && created.csrf_token === 'csrf-test');
    check('the new row: the address shown as text, nothing run', (await page.textContent('#limitsBody')).includes('<img src=x')
        && await page.locator('#limitsBody img').count() === 0 && await page.evaluate(() => window.__xss === undefined));
    await page.waitForSelector('#addLimitModal', { state: 'hidden' });

    await page.click('[data-limit-edit="4"]');
    await page.waitForSelector('#addLimitModal.show');
    check('edit: the mailbox fixed, the values filled in', await page.isDisabled('#limitMailbox') && await page.inputValue('#limitMailbox') === '11'
        && await page.inputValue('#limitHourly') === '20');
    await page.fill('#limitDaily', '250');
    await page.click('#addLimitModal .btn-primary');
    await page.waitForSelector('#addLimitModal', { state: 'hidden' });
    check('saved for the same mailbox', posts[posts.length - 1].mailbox_id === 11 && posts[posts.length - 1].daily === 250);

    accept = false;
    await page.click('[data-limit-delete="4"]');
    await page.waitForTimeout(200);
    check('delete cancelled: nothing sent', posts[posts.length - 1].action === 'save_mailbox' && dialogs[dialogs.length - 1].includes('info@example.com'));
    accept = true;
    await page.click('[data-limit-delete="4"]');
    await page.waitForFunction(() => !document.querySelector('[data-limit-delete="4"]'));
    check('delete confirmed: id and token', posts[posts.length - 1].action === 'delete' && posts[posts.length - 1].id === 4
        && posts[posts.length - 1].csrf_token === 'csrf-test');
    check('every POST had the token', posts.every(b => b.csrf_token === 'csrf-test'));

    console.log('\n== Sending limits, in English ==');
    language = 'en';
    await page.goto(BASE + '/ratelimits');
    await page.waitForSelector('#limitsBody tr td');
    check('title, notice and headers in English', (await text(page, 'h2')) === 'Sending limits'
        && (await text(page, '.alert-warning')).includes('saved but not applied yet')
        && (await page.$$eval('thead th', e => e.map(x => x.textContent.trim()))).join('|') === 'Mailbox|Per hour|Per day|Max recipients|State|Actions');
    if (shots) await page.screenshot({ path: path.join(shots, 'ratelimits-english.png') });

    console.log('\n== Statistics, in English ==');
    await page.goto(BASE + '/statistics');
    await page.waitForFunction(() => document.getElementById('rspamdScanned').textContent !== '-' && document.getElementById('totalSent').textContent !== '-');
    check('the period sent as days (7)', statsQueries[0] === '7');
    check('the notice that sent and received counts are not collected', (await text(page, '.alert-warning')).includes('not collected yet'));
    check('cards from "totals": 1.2K, 5.7K, 90, 12', await text(page, '#totalSent') === '1.2K' && await text(page, '#totalReceived') === '5.7K'
        && await text(page, '#totalSpam') === '90' && await text(page, '#totalBounced') === '12');
    check('Rspamd from the top level: 1.9K ham, 150 spam, 2K scanned, 7.5%', await text(page, '#rspamdHam') === '1.9K'
        && await text(page, '#rspamdSpam') === '150' && await text(page, '#rspamdScanned') === '2K' && await text(page, '#rspamdShare') === '7.5%');
    check('training: 3 and 5', await text(page, '#trainedSpam') === '3' && await text(page, '#trainedHam') === '5');
    check('per-domain row, the domain with HTML shown as text', (await page.textContent('#domainStatsBody')).includes('<img src=x')
        && await page.locator('#domainStatsBody img').count() === 0 && await page.evaluate(() => window.__xss === undefined));
    check('the top senders section, which nothing filled, is gone', await page.locator('#topSendersBody').count() === 0);
    await page.selectOption('#periodSelect', '30');
    await page.waitForFunction(() => true);
    await page.waitForTimeout(200);
    check('another period: days=30', statsQueries[statsQueries.length - 1] === '30');
    if (shots) await page.screenshot({ path: path.join(shots, 'statistics-english.png'), fullPage: true });

    console.log('\n== Statistics, in Italian ==');
    language = 'it';
    await page.goto(BASE + '/statistics');
    await page.waitForFunction(() => document.getElementById('totalSent').textContent !== '-');
    const itNumber = await page.evaluate(() => (5678).toLocaleString('it', { notation: 'compact', maximumFractionDigits: 1 }));
    check('title in Italian, numbers formatted the Italian way (' + itNumber + ')',
        (await text(page, 'h2')) === 'Statistiche della posta' && (await text(page, '#totalReceived')) === itNumber
        && (await text(page, '#rspamdShare')) === '7,5%');

    console.log('\n== On a phone ==');
    await page.setViewportSize({ width: 390, height: 844 });
    for (const p of ['/ratelimits', '/statistics']) {
        await page.goto(BASE + p);
        await page.waitForTimeout(500);
        const wide = await page.evaluate(() => document.documentElement.scrollWidth);
        check(p + ': no sideways scrolling (' + wide + 'px)', wide <= 390);
    }

    check('no page errors' + (errors.length ? ': ' + errors.join(' | ') : ''), errors.length === 0);
    await browser.close();
    console.log('\n' + (failed === 0 ? 'ALL GREEN' : failed + ' CHECKS FAILED'));
    process.exit(failed ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
