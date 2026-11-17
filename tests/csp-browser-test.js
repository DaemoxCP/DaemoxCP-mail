// Every page of the panel in Chromium with the same Content-Security-Policy the server sends
// (SecurityHeaders, without 'unsafe-inline': reperto 178), with the simulated server. For every page:
//  - no policy violation (an inline <script> or <style>, a style="", a resource from outside: the
//    browser refuses them and says so with securitypolicyviolation);
//  - no on... attribute left (the browser refuses an inline handler only when the event arrives:
//    it is looked for in the DOM);
//  - every data-on-* (panel-actions.js) parses and calls only panel functions and allowed methods,
//    and every data-style is applied;
//  - the functions the scripts call from the HTML they build later (data-on-* inside their strings)
//    exist in the page as panel functions.
// The APIs answer {success:false}: what counts here is the policy, not the data. The scripts'
// errors for the missing data are printed but do not count, except those of panel-actions.
//
// Usage (from the project root, after mvn package):
//   D=$(mktemp -d) && javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/daemoxcp/mail/content/PageGenerator.java \
//     && java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.daemoxcp.mail.content.PageGenerator $D >/dev/null
//   NODE_PATH=$(npm root -g) node tests/csp-browser-test.js $D
// On the Mac with the installed Chrome: CHROMIUM="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const pageList = process.argv[2];
const resourceList = path.join(__dirname, '..', 'src', 'main', 'resources');
const BASE = 'http://panel.test';
const CSP = fs.readFileSync(path.join(pageList, 'csp.txt'), 'utf8').trim();
let failedOnes = 0;
function real(whatItem, ok) {
    console.log((ok ? '  OK   ' : '  FAILED ') + whatItem);
    if (!ok) failedOnes++;
}

const TYPES = { '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.woff2': 'font/woff2', '.woff': 'font/woff', '.ttf': 'font/ttf' };
function file(route, f) {
    if (!fs.existsSync(f)) return route.fulfill({ status: 404, body: '' });
    return route.fulfill({ status: 200, contentType: TYPES[path.extname(f)] || 'application/octet-stream', body: fs.readFileSync(f) });
}

// The inline handlers and styles in the HTML the scripts build later (on...= and style= inside
// their strings): they are not in the freshly opened page yet, and the browser would refuse them
// only when that piece appears. They are looked for in the scripts' text.
function builtInline(js) {
    return [...js.matchAll(/(?<![-\w.$])(on[a-z]+|style)=\\{0,2}["']/g)].map(m => js.slice(Math.max(0, m.index - 40), m.index + 30).replace(/\s+/g, ' '));
}

// The functions the scripts call from the HTML they build: data-on-*="name(" inside the strings.
function builtNames(js) {
    const names = new Set();
    for (const m of js.matchAll(/data-on-[a-z]+=\\?["']([^"'\\]*?)([A-Za-z_$][\w$]*)\s*\(/g)) {
        if (!/\.\s*$/.test(m[1])) names.add(m[2]);
    }
    names.delete('Number');
    return [...names];
}

async function served(route) {
    const req = route.request();
    const p = new URL(req.url()).pathname;
    if (p.startsWith('/assets/')) return file(route, path.join(pageList, p.slice(1)));
    if (p.startsWith('/i18n/')) return file(route, path.join(pageList, p.slice(1)));
    if (p.startsWith('/vendor/') || p.startsWith('/fa/')) return file(route, path.join(resourceList, p.slice(1)));
    if (p.startsWith('/api/')) return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ success: false, error: 'mock' }) });
    const name = p.slice(1) || 'index';
    const f = path.join(pageList, name + '.html');
    if (!/^[a-z]+$/.test(name) || !fs.existsSync(f)) return route.fulfill({ status: 404, body: '' });
    const html = fs.readFileSync(f, 'utf8').replace(/\{\{CSRF_TOKEN\}\}/g, 'csrf-test').replace(/\{\{THEME\}\}/g, 'light')
        .replace(/\{\{COLOR_SCHEME\}\}/g, 'light').replace(/\{\{MAIL_HOSTNAME\}\}/g, 'mail.example.test')
        .replace(/\{\{ROUNDCUBE_DOMAIN\}\}/g, 'webmail.example.test').replace(/\{\{[A-Z_]+\}\}/g, 'x');
    return route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: html, headers: { 'Content-Security-Policy': CSP } });
}

(async () => {
    real('the policy has no unsafe-inline, unsafe-eval or sources from outside', !/unsafe-|https?:|\*/.test(CSP) && /script-src 'self';/.test(CSP));
    const browser = await chromium.launch({ executablePath: process.env.CHROMIUM || '/opt/pw-browsers/chromium-1194/chrome-linux/chrome' }).catch(() => chromium.launch());
    const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
    await ctx.route('**/*', served);
    await ctx.addInitScript(() => {
        window.__violations = [];
        document.addEventListener('securitypolicyviolation', e => window.__violations.push(e.violatedDirective + ' ' + (e.blockedURI || '') + ' ' + (e.sample || '')));
    });
    const pages = fs.readdirSync(pageList).filter(n => /^[a-z]+\.html$/.test(n)).map(n => n.slice(0, -5)).sort();
    for (const name of pages) {
        console.log('\n== ' + name + ' ==');
        const page = await ctx.newPage();
        const actionErrors = [], pageErrors = [];
        page.on('console', m => { if (m.type() === 'error') (m.text().includes('[panel-actions]') ? actionErrors : pageErrors).push(m.text()); });
        page.on('pageerror', e => pageErrors.push(String(e)));
        await page.goto(BASE + '/' + name);
        await page.waitForTimeout(1200);
        const html = fs.readFileSync(path.join(pageList, name + '.html'), 'utf8');
        const js = [...html.matchAll(/<script src="\/assets\/([^"]+)"/g)].map(m => fs.readFileSync(path.join(pageList, 'assets', m[1]), 'utf8')).join('\n');
        const r = await page.evaluate(names => {
            // Without panel-actions (the head does not load it) the handlers do not start: it is
            // said, without stopping the test at the first call.
            const loaded = typeof window.panelActionsCheck === 'function' && typeof window.panelStyleApplied === 'function';
            const check = loaded ? window.panelActionsCheck : () => ['panel-actions is not loaded'];
            const applied = loaded ? window.panelStyleApplied : () => false;
            const inline = [];
            const actions = [];
            const styles = [];
            for (const el of document.querySelectorAll('*')) {
                for (const a of el.attributes) {
                    if (/^on/i.test(a.name)) inline.push(el.tagName + ' ' + a.name);
                    if (a.name === 'style' && !el.hasAttribute('data-style')) inline.push(el.tagName + ' style');
                    if (a.name.startsWith('data-on-')) {
                        const problems = check(a.value);
                        if (problems.length) actions.push(a.name + '="' + a.value + '": ' + problems.join('; '));
                    }
                }
                if (el.hasAttribute('data-style') && !applied(el)) styles.push(el.tagName + ' ' + el.getAttribute('data-style'));
            }
            const missing = loaded ? names.filter(n => check(n + '()').some(p => p.includes('not a function'))) : names;
            return { violations: window.__violations, inline, actions, styles, missing, checked: loaded };
        }, builtNames(js));
        real('panel-actions loaded', r.checked);
        real('no policy violation' + (r.violations.length ? ': ' + r.violations.slice(0, 3).join(' | ') : ''), r.violations.length === 0);
        real('no inline handler or style in the DOM' + (r.inline.length ? ': ' + r.inline.slice(0, 5).join(', ') : ''), r.inline.length === 0);
        real('every data-on-* calls panel functions' + (r.actions.length ? ': ' + r.actions.slice(0, 3).join(' | ') : ''), r.actions.length === 0);
        real('every data-style is applied' + (r.styles.length ? ': ' + r.styles.slice(0, 3).join(' | ') : ''), r.styles.length === 0);
        const inlineBuilt = builtInline(js);
        real('no inline handler or style in the HTML the scripts build' + (inlineBuilt.length ? ': ' + inlineBuilt.slice(0, 2).join(' | ') : ''), inlineBuilt.length === 0);
        real('the functions called from the HTML the scripts build exist' + (r.missing.length ? ': ' + r.missing.join(', ') : ''), r.missing.length === 0);
        real('no panel-actions error' + (actionErrors.length ? ': ' + actionErrors.slice(0, 3).join(' | ') : ''), actionErrors.length === 0);
        if (pageErrors.length) console.log('    (page errors with the fake data, they do not count: ' + pageErrors.length + ', the first: ' + pageErrors[0].slice(0, 140) + ')');
        await page.close();
    }
    await browser.close();
    console.log(failedOnes === 0 ? '\nALL GREEN' : '\n' + failedOnes + ' CHECKS FAILED');
    process.exit(failedOnes === 0 ? 0 : 1);
})();
