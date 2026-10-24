// La scheda "Ramo dei pacchetti" della pagina Aggiornamenti in Chromium, con il server simulato:
// la logica vera (pkg -vv, il file del pannello, i ripristini) la prova PkgBranchTest. Qui si
// controlla che la scheda si legga da sola, mostri ramo e repository solo come testo, chieda
// l'anteprima, pretenda il nome del ramo scritto a mano, mandi fingerprint e token CSRF, segua il
// lavoro fino all'esito e dica gli errori.
//
// Uso (dalla radice del progetto, dopo mvn package):
//   D=$(mktemp -d) && javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/content/PageGenerator.java \
//     && java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.content.PageGenerator $D >/dev/null
//   NODE_PATH=$(npm root -g) node tests/pkg-branch-browser-test.js $D [cartella-per-le-foto]
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const pagine = process.argv[2];
const foto = process.argv[3];
const risorse = path.join(__dirname, '..', 'src', 'main', 'resources');
const BASE = 'http://pannello.test';
let falliti = 0;
function vero(cosa, ok) {
    console.log((ok ? '  OK   ' : '  FALLITO ') + cosa);
    if (!ok) falliti++;
}

const richieste = [];
let ramoAdesso = 'quarterly', cambioRiesce = true, letture = 0, giri = 0;
function stato() {
    const latest = ramoAdesso === 'latest';
    return { success: true, branch: ramoAdesso, changeable: true, destination: [latest ? 'quarterly' : 'latest'],
        explanation: latest ? 'Ramo continuo: le versioni arrivano appena il port e\' aggiornato e compilato.'
                            : 'Ramo trimestrale: si stacca dallo sviluppo dei port a gennaio, aprile, luglio e ottobre.',
        fingerprint: latest ? 'bbbbbbbbbbbbbbbb' : 'aaaaaaaaaaaaaaaa',
        file: '/usr/local/etc/pkg/repos/zz-panel-branch.conf', panelOwnedFile: latest,
        repository: [
            { name: 'FreeBSD-ports', role: 'Pacchetti (port)', branch: ramoAdesso, enabled: true, type: 'pacchetti',
              url: 'pkg+https://pkg.FreeBSD.org/FreeBSD:15:amd64/' + ramoAdesso },
            { name: 'FreeBSD-ports-kmods', role: 'Moduli del kernel', branch: ramoAdesso, enabled: true, type: 'moduli',
              url: 'pkg+https://pkg.FreeBSD.org/FreeBSD:15:amd64/kmods_' + ramoAdesso + '_0' },
            { name: 'FreeBSD-base', role: 'Sistema base', branch: 'release', enabled: false, type: 'base',
              url: 'pkg+https://pkg.FreeBSD.org/FreeBSD:15:amd64/base_release_0' },
            { name: 'mio<b>repo</b>', role: 'Repository non ufficiale', branch: '', enabled: true, type: 'esterno',
              url: 'file:///usr/local/<img src=x onerror="window.iniettato=1">' },
        ] };
}

function json(route, corpo) { return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(corpo) }); }

async function servi(route) {
    const req = route.request();
    const url = new URL(req.url());
    const p = url.pathname;
    if (p === '/updates') {
        const html = fs.readFileSync(path.join(pagine, 'updates.html'), 'utf8').replace(/\{\{CSRF_TOKEN\}\}/g, 'csrf-prova');
        return route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: html });
    }
    // The script dictionary (t() and the texts), as the panel serves it.
    if (p.startsWith('/i18n/')) return route.fulfill({ status: 200, contentType: 'application/javascript', body: fs.readFileSync(path.join(pagine, p)) });
    if (p.startsWith('/vendor/') || p.startsWith('/fa/')) {
        const f = path.join(risorse, p);
        if (!fs.existsSync(f)) return route.fulfill({ status: 404, body: '' });
        const tipo = p.endsWith('.css') ? 'text/css' : p.endsWith('.js') ? 'application/javascript' : p.endsWith('.woff2') ? 'font/woff2' : 'application/octet-stream';
        return route.fulfill({ status: 200, contentType: tipo, body: fs.readFileSync(f) });
    }
    const corpo = req.postData() ? JSON.parse(req.postData()) : null;
    richieste.push({ metodo: req.method(), path: p, body: corpo });
    if (p !== '/api/updates' || !corpo) return json(route, { success: true });
    switch (corpo.action) {
        case 'branch_status': letture++; return json(route, stato());
        case 'branch_preview': return json(route, { success: true, possible: true, from: ramoAdesso, destination: corpo.destination,
            fingerprint: stato().fingerprint, file: '/usr/local/etc/pkg/repos/zz-panel-branch.conf',
            changes: [{ name: 'FreeBSD-ports', from: 'pkg+https://pkg.FreeBSD.org/FreeBSD:15:amd64/quarterly', to: 'pkg+https://pkg.FreeBSD.org/${ABI}/latest' }],
            warnings: ['Non si aggiorna nessun pacchetto: cambia da dove pkg li prende.', 'Su latest il prossimo aggiornamento puo\' portare versioni maggiori nuove.'],
            content: '# Scritto dal pannello\nFreeBSD-ports: { url: "pkg+https://pkg.FreeBSD.org/${ABI}/latest" }\n', howToReturn: '' });
        case 'branch_change':
            if (!cambioRiesce) return json(route, { success: false, error: 'C\'e\' gia\' un lavoro sui pacchetti in corso (aggiornamento di nginx).' });
            giri = 0;
            return json(route, { success: true, jobId: 'ramo-1', async: true });
        case 'job_status':
            giri++;
            if (giri < 2) return json(route, { success: true, job: { status: 'running', consoleLog: '[12:00:00] [3/3] Scarico il catalogo del ramo latest (pkg update -f)...\n' } });
            ramoAdesso = 'latest';
            return json(route, { success: true, job: { status: 'completed', elapsedSeconds: 9, errorMessage: '',
                result: 'Adesso i pacchetti arrivano dal ramo latest, e il suo catalogo e\' scaricato. Nessun pacchetto e\' stato cambiato. 2 pacchetti si possono aggiornare.',
                consoleLog: '[12:00:00] [3/3] Scarico il catalogo...\n[12:00:09] All repositories are up to date.\n' } });
        default: return json(route, { success: true });
    }
}

(async () => {
    const browser = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium-1194/chrome-linux/chrome' }).catch(() => chromium.launch());
    const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
    await ctx.route('**/*', servi);
    const page = await ctx.newPage();
    const errori = [];
    page.on('pageerror', e => errori.push(String(e)));
    page.on('console', m => { if (m.type() === 'error') errori.push(m.text()); });

    console.log('\n== La scheda si legge da sola ==');
    await page.goto(BASE + '/updates');
    await page.waitForSelector('#branch-body table');
    const testo = await page.textContent('#branch-body');
    vero('ramo quarterly, con la spiegazione', testo.includes('I pacchetti arrivano dal ramo quarterly') && testo.includes('Ramo trimestrale'));
    const righe = await page.$$eval('#branch-body tbody tr', tr => tr.map(r => r.cells[0].textContent));
    vero('i quattro repository, anche quello non ufficiale: ' + righe.join(', '), righe.length === 4 && righe[3] === 'mio<b>repo</b>');
    vero('nomi e indirizzi restano testo: nessun <b>, nessun <img>', await page.locator('#branch-body b, #branch-body img').count() === 0
        && await page.evaluate(() => window.iniettato) === undefined);
    vero('di serie: "nessun file del pannello"', testo.includes('Nessun file del pannello'));
    vero('il pulsante per passare a latest', await page.locator('#branch-body button', { hasText: 'Passa al ramo latest' }).count() === 1);
    if (foto) await page.locator('#branch').screenshot({ path: path.join(foto, 'ramo-scheda.png') });

    console.log('\n== Anteprima e conferma ==');
    await page.click('#branch-body button:has-text("Passa al ramo latest")');
    await page.waitForSelector('#branch-confirm');
    const ant = await page.textContent('#branch-preview');
    vero('l\'anteprima: cosa cambia, gli warnings, il file che si scrive', ant.includes('Passare dal ramo quarterly al ramo latest')
        && ant.includes('pkg+https://pkg.FreeBSD.org/${ABI}/latest') && ant.includes('Non si aggiorna nessun pacchetto')
        && ant.includes('zz-panel-branch.conf'));
    vero('"Cambia ramo" spento finche\' non si scrive latest', await page.isDisabled('#branch-go'));
    await page.fill('#branch-confirm', 'Latest');
    vero('scritto diverso (Latest): resta spento', await page.isDisabled('#branch-go'));
    await page.fill('#branch-confirm', 'latest');
    vero('scritto giusto: si accende', await page.isEnabled('#branch-go'));
    if (foto) await page.locator('#branch').screenshot({ path: path.join(foto, 'ramo-anteprima.png') });

    console.log('\n== Il cambio, seguito fino all\'esito ==');
    await page.click('#branch-go');
    const post = richieste.find(r => r.body && r.body.action === 'branch_change');
    vero('la richiesta: ramo, conferma, fingerprint dell\'anteprima, token CSRF', post && post.body.destination === 'latest'
        && post.body.confirm === 'latest' && post.body.fingerprint === 'aaaaaaaaaaaaaaaa' && post.body.csrf_token === 'csrf-prova');
    await page.waitForFunction(() => document.getElementById('branch-outcome').textContent.includes('Adesso i pacchetti arrivano'), null, { timeout: 15000 });
    vero('il registro del lavoro si vede', (await page.textContent('#branch-log')).includes('All repositories are up to date'));
    vero('l\'esito, in verde', await page.locator('#branch-outcome .alert-success').count() === 1);
    await page.waitForFunction(() => document.getElementById('branch-body').textContent.includes('dal ramo latest'));
    vero('la scheda si rilegge da sola: ora latest, con il file del pannello', letture === 2
        && (await page.textContent('#branch-body')).includes('Il ramo lo decide il file del pannello'));
    if (foto) await page.locator('#branch').screenshot({ path: path.join(foto, 'ramo-dopo.png') });

    console.log('\n== Un cambio che non parte ==');
    cambioRiesce = false;
    await page.click('#branch-body button:has-text("Passa al ramo quarterly")');
    await page.waitForSelector('#branch-confirm');
    await page.fill('#branch-confirm', 'quarterly');
    await page.click('#branch-go');
    await page.waitForSelector('#branch-outcome .alert-danger');
    vero('l\'errore del server, in rosso: ' + await page.textContent('#branch-outcome'), (await page.textContent('#branch-outcome')).includes('lavoro sui pacchetti in corso'));
    vero('e si puo\' riprovare', await page.isEnabled('#branch-go'));

    console.log('\n== Tema scuro e telefono ==');
    await page.evaluate(() => document.documentElement.setAttribute('data-theme', 'dark'));
    await page.waitForTimeout(600);   // il cambio di tema ha una transizione
    if (foto) await page.locator('#branch').screenshot({ path: path.join(foto, 'ramo-scuro.png') });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.evaluate(() => document.documentElement.setAttribute('data-theme', 'light'));
    await page.waitForTimeout(300);
    const largo = await page.evaluate(() => document.documentElement.scrollWidth);
    vero('sul telefono la pagina non scorre di lato: ' + largo + 'px', largo <= 390);
    if (foto) await page.locator('#branch').screenshot({ path: path.join(foto, 'ramo-telefono.png') });

    vero('nessun errore nella pagina' + (errori.length ? ': ' + errori.join(' | ') : ''), errori.length === 0);
    await browser.close();
    console.log('\n' + (falliti === 0 ? 'TUTTO VERDE' : falliti + ' CONTROLLI FALLITI'));
    process.exit(falliti ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
