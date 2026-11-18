// The frame of the mail panel pages in Chromium: the sectioned sidebar, the top bar, the panel that
// opens on a phone, the "Skip to content" link and the language switch, also on the login page.
// The server is simulated: it serves the pages as the panel completes them (PageGenerator, Italian
// or English according to the chosen language) and answers /api/language like the panel.
//
// Usage (from the project root, after mvn package):
//   D=$(mktemp -d) && javac -cp target/daemoxcp-mail.jar -d tests tests/org/daemoxcp/mail/content/PageGenerator.java \
//     && java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.content.PageGenerator $D >/dev/null
//   NODE_PATH=$(npm root -g) node tests/layout-browser-test.js $D [screenshot-folder]
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const csp = require('./browser-csp');

const pages = process.argv[2];
const shots = process.argv[3];
const resources = path.join(__dirname, '..', 'src', 'main', 'resources');
// The Italian page is checked against the texts of it.json, never written here.
const IT = JSON.parse(fs.readFileSync(path.join(resources, 'lang', 'it.json'), 'utf8'));
const BASE = 'http://panel.test';
let failed = 0;
function check(what, ok) {
    console.log((ok ? '  OK   ' : '  FAILED ') + what);
    if (!ok) failed++;
}

let language = 'it';
let theme = 'auto';
const changes = [];
const PAGES = { '/home': 'home', '/updates': 'updates', '/queue': 'queue', '/dns': 'dns', '/admins': 'admins', '/index': 'index', '/setup': 'setup' };

async function serve(route) {
    const req = route.request();
    const p = new URL(req.url()).pathname;
    if (PAGES[p]) {
        const f = path.join(pages, PAGES[p] + (language === 'it' ? '' : '.' + language) + '.html');
        const html = fs.readFileSync(f, 'utf8').replace(/\{\{CSRF_TOKEN\}\}/g, 'csrf-test')
            .replace(/\{\{THEME\}\}/g, theme).replace(/\{\{COLOR_SCHEME\}\}/g, theme === 'auto' ? 'light dark' : theme);
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
    if (p === '/api/language') {
        const body = JSON.parse(req.postData() || '{}');
        changes.push(body);
        if (body.csrf_token !== 'csrf-test' || !['it', 'en'].includes(body.language)) {
            return route.fulfill({ status: 403, contentType: 'application/json', body: '{"success":false}' });
        }
        language = body.language;
        return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ success: true, language }) });
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
    csp.watch(page, errors);

    console.log('\n== The sidebar ==');
    await page.goto(BASE + '/home');
    const sections = await page.$$eval('.sidebar-section-title', e => e.map(x => x.textContent.trim()));
    check('four sections: ' + sections.join(', '), JSON.stringify(sections) === JSON.stringify(['nav.section.mail', 'nav.section.dns', 'nav.section.security', 'nav.section.system'].map(k => IT[k])));
    const items = await page.$$eval('.sidebar-link', e => e.map(x => x.textContent.trim()));
    check(items.length + ' items, from Dashboard to Settings', items.length === 18 && items[0] === 'Dashboard' && items[items.length - 1] === IT['nav.settings']);
    check('the pages no link reached before are in the menu (queue, limits, statistics, admins, diagnostics)', await page.evaluate(() =>
        ['/queue', '/ratelimits', '/statistics', '/admins', '/diagnostics'].every(h => document.querySelector('.sidebar-link[href="' + h + '"]'))));
    check('Dashboard marked as the current page', await page.getAttribute('.sidebar-link.active', 'href') === '/home'
        && await page.getAttribute('.sidebar-link.active', 'aria-current') === 'page' && await page.locator('.sidebar-link.active').count() === 1);
    check('the sidebar is visible and fixed on the left', await page.isVisible('#sidebar')
        && await page.evaluate(() => getComputedStyle(document.getElementById('sidebar')).position) === 'fixed');
    check('the menu button is hidden on a computer', !(await page.isVisible('.topbar-toggle')));
    check('the sections are lists with their name (aria-labelledby)', await page.evaluate(() =>
        [...document.querySelectorAll('.sidebar-section ul')].every(u => document.getElementById(u.getAttribute('aria-labelledby')))));
    check('the old top menu is gone', await page.locator('nav.navbar-mail').count() === 0);
    if (shots) await page.screenshot({ path: path.join(shots, 'frame-home.png') });

    await page.goto(BASE + '/updates');
    check('Updates: active item and "System > Updates" on top', await page.getAttribute('.sidebar-link.active', 'href') === '/updates'
        && await text(page, '.topbar-title') === IT['nav.section.system'] + ' › ' + IT['nav.updates']);
    await page.goto(BASE + '/queue');
    check('Queue: "Mail > Mail queue" on top', await text(page, '.topbar-title') === IT['nav.section.mail'] + ' › ' + IT['nav.queue']);

    console.log('\n== Skip to content ==');
    await page.goto(BASE + '/dns');
    await page.keyboard.press('Tab');
    check('the first Tab reaches "Vai al contenuto"', await page.evaluate(() => document.activeElement.textContent.trim()) === 'Vai al contenuto'
        && await page.evaluate(() => document.activeElement.classList.contains('skip-link')));
    await page.keyboard.press('Enter');
    check('and Enter moves to the page content', await page.evaluate(() => document.activeElement.id) === 'main');

    console.log('\n== The language switch ==');
    check('Italian: IT pressed, EN not', await page.getAttribute('[data-set-lang="it"]', 'aria-pressed') === 'true'
        && await page.getAttribute('[data-set-lang="en"]', 'aria-pressed') === 'false'
        && await page.getAttribute('html', 'lang') === 'it');
    await Promise.all([page.waitForNavigation(), page.click('[data-set-lang="en"]')]);
    check('the request: language and CSRF token', changes.length === 1 && changes[0].language === 'en' && changes[0].csrf_token === 'csrf-test');
    check('the page comes back in English: lang, sections, top bar, logout', await page.getAttribute('html', 'lang') === 'en'
        && JSON.stringify(await page.$$eval('.sidebar-section-title', e => e.map(x => x.textContent.trim()))) === JSON.stringify(['Mail', 'DNS and certificates', 'Security', 'System'])
        && await text(page, '.topbar-title') === 'DNS and certificates › DNS' && await text(page, '#logoutButton') === 'Log out');
    check('EN pressed, the title and the footer in English', await page.getAttribute('[data-set-lang="en"]', 'aria-pressed') === 'true'
        && (await page.title()) === 'DNS - Mail Control Panel' && (await text(page, 'footer')).includes('Copyright by'));
    check('the script dictionary is the English one', await page.evaluate(() => window.I18N_LANG === 'en' && t('nav.updates') === 'Updates'));
    if (shots) await page.screenshot({ path: path.join(shots, 'frame-english.png') });
    await page.click('[data-set-lang="en"]');
    await page.waitForTimeout(300);
    check('pressing the current language again sends nothing', changes.length === 1);
    await Promise.all([page.waitForNavigation(), page.click('[data-set-lang="it"]')]);
    check('and back to Italian', await page.getAttribute('html', 'lang') === 'it' && await text(page, '.topbar-title') === 'DNS e certificati › DNS');

    console.log('\n== Before logging in ==');
    await page.goto(BASE + '/index');
    check('the login page has IT/EN and the theme button, without the frame', await page.isVisible('[data-set-lang="en"]')
        && await page.isVisible('.theme-toggle-login') && await page.locator('#sidebar').count() === 0);
    await Promise.all([page.waitForNavigation(), page.click('[data-set-lang="en"]')]);
    check('it switches with the login page token', changes.length === 3 && changes[2].csrf_token === 'csrf-test'
        && await page.getAttribute('html', 'lang') === 'en');
    await page.goto(BASE + '/setup');
    check('the setup page has the switch too', await page.isVisible('[data-set-lang="it"]')
        && await page.getAttribute('[data-set-lang="en"]', 'aria-pressed') === 'true');
    language = 'it';

    console.log('\n== On a phone ==');
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(BASE + '/admins');
    check('the sidebar is closed, the menu button is visible', !(await page.isVisible('.sidebar-link.active')) && await page.isVisible('.topbar-toggle'));
    const wide = await page.evaluate(() => document.documentElement.scrollWidth);
    check('the page does not scroll sideways: ' + wide + 'px', wide <= 390);
    check('on a phone the page name stays, without the section', await page.isVisible('.topbar-title') && !(await page.isVisible('.topbar-section')));
    await page.click('.topbar-toggle');
    await page.waitForSelector('#sidebar.show');
    await page.waitForTimeout(400);
    check('the button opens the menu, with the active item', await page.isVisible('.sidebar-link.active')
        && await page.getAttribute('.topbar-toggle', 'aria-controls') === 'sidebar');
    check('the focus goes into the open menu', await page.evaluate(() => document.getElementById('sidebar').contains(document.activeElement)));
    if (shots) await page.screenshot({ path: path.join(shots, 'frame-phone-menu.png') });
    await page.keyboard.press('Escape');
    await page.waitForFunction(() => !document.getElementById('sidebar').classList.contains('show'));
    check('Esc closes it', !(await page.isVisible('.sidebar-link.active')));
    await page.click('.topbar-toggle');
    await page.waitForSelector('#sidebar.show');
    await page.waitForTimeout(400);
    await page.click('#sidebar .btn-close');
    await page.waitForFunction(() => !document.getElementById('sidebar').classList.contains('show'));
    check('the X closes it too', !(await page.isVisible('.sidebar-link.active')));

    console.log('\n== Dark theme ==');
    await page.setViewportSize({ width: 1366, height: 900 });
    theme = 'dark';
    await page.goto(BASE + '/home');
    await page.waitForTimeout(300);
    check('the top bar takes the dark theme colors', await page.evaluate(() =>
        getComputedStyle(document.querySelector('.topbar')).backgroundColor) === 'rgb(45, 50, 56)');
    check('the theme button shows the moon', await page.getAttribute('#themeIcon', 'class') === 'fas fa-moon');
    if (shots) await page.screenshot({ path: path.join(shots, 'frame-dark.png') });

    check('no page errors' + (errors.length ? ': ' + errors.join(' | ') : ''), errors.length === 0);
    await browser.close();
    console.log('\n' + (failed === 0 ? 'ALL GREEN' : failed + ' CHECKS FAILED'));
    process.exit(failed ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
