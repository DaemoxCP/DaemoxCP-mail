// La Content-Security-Policy del pannello nelle prove da browser col server simulato (reperto 178).
// Gli script e gli stili delle pagine sono file in assets/ (PageAssets), la politica e' quella di
// csp.txt (PageGenerator la scrive da SecurityHeaders, la stessa del server), e una violazione o un
// errore di panel-actions finisce fra gli errori della pagina, che ogni prova vuole vuoti.
const fs = require('fs');
const path = require('path');

// L'intestazione da mandare con le pagine.
exports.headers = dir => ({ 'Content-Security-Policy': fs.readFileSync(path.join(dir, 'csp.txt'), 'utf8').trim() });

// Un file di assets/ (/assets/<impronta>.js o /assets/open/<impronta>.css), come lo serve il pannello.
exports.asset = (route, dir, p) => {
    const f = path.join(dir, p.replace(/^\/+/, ''));
    if (!/^\/assets\/(open\/)?[0-9a-f]{20}\.(js|css)$/.test(p) || !fs.existsSync(f)) return route.fulfill({ status: 404, body: '' });
    return route.fulfill({ status: 200, contentType: p.endsWith('.css') ? 'text/css; charset=utf-8' : 'text/javascript; charset=utf-8', body: fs.readFileSync(f) });
};

// Le violazioni della politica (Chrome le scrive in console) e gli errori di panel-actions.
exports.watch = (page, errors) => page.on('console', m => {
    if (m.type() === 'error' && /Content Security Policy|\[panel-actions\]/.test(m.text())) errors.push(m.text());
});
