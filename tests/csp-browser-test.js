// Ogni pagina del pannello in Chromium con la stessa Content-Security-Policy che manda il server
// (SecurityHeaders, senza 'unsafe-inline': reperto 178), col server simulato. Per ogni pagina:
//  - nessuna violazione della politica (un <script> o uno <style> in linea, un style="", una
//    risorsa da fuori: il browser li rifiuta e lo dice con securitypolicyviolation);
//  - nessun attributo on... rimasto (un gestore in linea il browser lo rifiuta solo quando
//    l'evento arriva: si cerca nel DOM);
//  - ogni data-on-* (panel-actions.js) si analizza e chiama solo funzioni del pannello e metodi
//    ammessi, e ogni data-style e' applicato;
//  - le funzioni che gli script chiamano dall'HTML che costruiscono dopo (data-on-* dentro le loro
//    stringhe) esistono nella pagina come funzioni del pannello.
// Le API rispondono {success:false}: qui conta la politica, non i dati. Gli errori degli script
// per i dati mancanti si stampano ma non contano, salvo quelli di panel-actions.
//
// Uso (dalla radice del progetto, dopo mvn package):
//   D=$(mktemp -d) && javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/content/PageGenerator.java \
//     && java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.content.PageGenerator $D >/dev/null
//   NODE_PATH=$(npm root -g) node tests/csp-browser-test.js $D
// Sul Mac col Chrome installato: CHROMIUM="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const pageList = process.argv[2];
const resourceList = path.join(__dirname, '..', 'src', 'main', 'resources');
const BASE = 'http://pannello.test';
const CSP = fs.readFileSync(path.join(pageList, 'csp.txt'), 'utf8').trim();
let failedOnes = 0;
function real(whatItem, ok) {
    console.log((ok ? '  OK   ' : '  FALLITO ') + whatItem);
    if (!ok) failedOnes++;
}

const TYPES = { '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.woff2': 'font/woff2', '.woff': 'font/woff', '.ttf': 'font/ttf' };
function file(route, f) {
    if (!fs.existsSync(f)) return route.fulfill({ status: 404, body: '' });
    return route.fulfill({ status: 200, contentType: TYPES[path.extname(f)] || 'application/octet-stream', body: fs.readFileSync(f) });
}

// I gestori e gli stili in linea nell'HTML che gli script costruiscono dopo (on...= e style= dentro
// le loro stringhe): nella pagina appena aperta non ci sono ancora, e il browser li rifiuterebbe solo
// quando quel pezzo compare. Si cercano nel testo degli script.
function builtInline(js) {
    return [...js.matchAll(/(?<![-\w.$])(on[a-z]+|style)=\\{0,2}["']/g)].map(m => js.slice(Math.max(0, m.index - 40), m.index + 30).replace(/\s+/g, ' '));
}

// Le funzioni che gli script chiamano dall'HTML che costruiscono: data-on-*="nome(" dentro le stringhe.
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
    const html = fs.readFileSync(f, 'utf8').replace(/\{\{CSRF_TOKEN\}\}/g, 'csrf-prova').replace(/\{\{THEME\}\}/g, 'light')
        .replace(/\{\{COLOR_SCHEME\}\}/g, 'light').replace(/\{\{MAIL_HOSTNAME\}\}/g, 'mail.prova.test')
        .replace(/\{\{ROUNDCUBE_DOMAIN\}\}/g, 'webmail.prova.test').replace(/\{\{[A-Z_]+\}\}/g, 'x');
    return route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: html, headers: { 'Content-Security-Policy': CSP } });
}

(async () => {
    real('la politica non ha unsafe-inline, unsafe-eval ne\' sorgenti da fuori', !/unsafe-|https?:|\*/.test(CSP) && /script-src 'self';/.test(CSP));
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
            // Senza panel-actions (la testa non lo carica) i gestori non partono: lo si dice, senza
            // fermare la prova sulla prima chiamata.
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
        real('panel-actions caricato', r.checked);
        real('nessuna violazione della politica' + (r.violations.length ? ': ' + r.violations.slice(0, 3).join(' | ') : ''), r.violations.length === 0);
        real('nessun gestore o stile in linea nel DOM' + (r.inline.length ? ': ' + r.inline.slice(0, 5).join(', ') : ''), r.inline.length === 0);
        real('ogni data-on-* chiama funzioni del pannello' + (r.actions.length ? ': ' + r.actions.slice(0, 3).join(' | ') : ''), r.actions.length === 0);
        real('ogni data-style e\' applicato' + (r.styles.length ? ': ' + r.styles.slice(0, 3).join(' | ') : ''), r.styles.length === 0);
        const inlineBuilt = builtInline(js);
        real('nessun gestore o stile in linea nell\'HTML che gli script costruiscono' + (inlineBuilt.length ? ': ' + inlineBuilt.slice(0, 2).join(' | ') : ''), inlineBuilt.length === 0);
        real('le funzioni chiamate dall\'HTML costruito dagli script esistono' + (r.missing.length ? ': ' + r.missing.join(', ') : ''), r.missing.length === 0);
        real('nessun errore di panel-actions' + (actionErrors.length ? ': ' + actionErrors.slice(0, 3).join(' | ') : ''), actionErrors.length === 0);
        if (pageErrors.length) console.log('    (errori della pagina coi dati finti, non contano: ' + pageErrors.length + ', il primo: ' + pageErrors[0].slice(0, 140) + ')');
        await page.close();
    }
    await browser.close();
    console.log(failedOnes === 0 ? '\nTUTTO VERDE' : '\n' + failedOnes + ' CONTROLLI FALLITI');
    process.exit(failedOnes === 0 ? 0 : 1);
})();
