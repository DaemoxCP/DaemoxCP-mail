// The panel's Content-Security-Policy in the browser tests with the simulated server (finding 178).
// The pages' scripts and styles are files in assets/ (PageAssets), the policy is the one in csp.txt
// (PageGenerator writes it from SecurityHeaders, the same as the server's), and a violation or a
// panel-actions error ends up among the page errors, which every test wants empty.
const fs = require('fs');
const path = require('path');

// The header to send with the pages.
exports.headers = dir => ({ 'Content-Security-Policy': fs.readFileSync(path.join(dir, 'csp.txt'), 'utf8').trim() });

// A file of assets/ (/assets/<fingerprint>.js or /assets/open/<fingerprint>.css), as the panel serves it.
exports.asset = (route, dir, p) => {
    const f = path.join(dir, p.replace(/^\/+/, ''));
    if (!/^\/assets\/(open\/)?[0-9a-f]{20}\.(js|css)$/.test(p) || !fs.existsSync(f)) return route.fulfill({ status: 404, body: '' });
    return route.fulfill({ status: 200, contentType: p.endsWith('.css') ? 'text/css; charset=utf-8' : 'text/javascript; charset=utf-8', body: fs.readFileSync(f) });
};

// The policy violations (Chrome writes them in the console) and the panel-actions errors.
exports.watch = (page, errors) => page.on('console', m => {
    if (m.type() === 'error' && /Content Security Policy|\[panel-actions\]/.test(m.text())) errors.push(m.text());
});
