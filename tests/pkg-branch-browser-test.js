// La scheda "Ramo dei pacchetti" della pagina Aggiornamenti in Chromium, con il server simulato:
// la logica vera (pkg -vv, il file del pannello, i ripristini) la prova PkgBranchTest. Qui si
// controlla che la scheda si legga da sola, mostri ramo e repository solo come testo, chieda
// l'anteprima, pretenda il nome del ramo scritto a mano, mandi impronta e token CSRF, segua il
// lavoro fino all'esito e dica gli errori.
//
// Uso (dalla radice del progetto, dopo mvn package):
//   D=$(mktemp -d) && javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/content/PageGenerator.java \
//     && java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.content.PageGenerator $D >/dev/null
//   NODE_PATH=$(npm root -g) node tests/pkg-branch-browser-test.js $D [cartella-per-le-foto]
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const pageList = process.argv[2];
const photos = process.argv[3];
const resourceList = path.join(__dirname, '..', 'src', 'main', 'resources');
const BASE = 'http://pannello.test';
let failedOnes = 0;
function real(whatItem, ok) {
    console.log((ok ? '  OK   ' : '  FALLITO ') + whatItem);
    if (!ok) failedOnes++;
}

const requests = [];
let branchNow = 'quarterly', changeSucceeds = true, readings = 0, rounds = 0;
function stateValue() {
    const latest = branchNow === 'latest';
    return { success: true, branch: branchNow, changeable: true, destination: [latest ? 'quarterly' : 'latest'],
        explanation: latest ? 'Ramo continuo: le versioni arrivano appena il port e\' aggiornato e compilato.'
                            : 'Ramo trimestrale: si stacca dallo sviluppo dei port a gennaio, aprile, luglio e ottobre.',
        fingerprint: latest ? 'bbbbbbbbbbbbbbbb' : 'aaaaaaaaaaaaaaaa',
        file: '/usr/local/etc/pkg/repos/zz-panel-branch.conf', panelOwnedFile: latest,
        repository: [
            { name: 'FreeBSD-ports', role: 'Pacchetti (port)', branch: branchNow, enabled: true, type: 'packages',
              url: 'pkg+https://pkg.FreeBSD.org/FreeBSD:15:amd64/' + branchNow },
            { name: 'FreeBSD-ports-kmods', role: 'Moduli del kernel', branch: branchNow, enabled: true, type: 'modules',
              url: 'pkg+https://pkg.FreeBSD.org/FreeBSD:15:amd64/kmods_' + branchNow + '_0' },
            { name: 'FreeBSD-base', role: 'Sistema base', branch: 'release', enabled: false, type: 'base',
              url: 'pkg+https://pkg.FreeBSD.org/FreeBSD:15:amd64/base_release_0' },
            { name: 'mio<b>repo</b>', role: 'Repository non ufficiale', branch: '', enabled: true, type: 'external',
              url: 'file:///usr/local/<img src=x onerror="window.injectedRan=1">' },
        ] };
}

function json(route, bodyText) { return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(bodyText) }); }

async function served(route) {
    const req = route.request();
    const url = new URL(req.url());
    const p = url.pathname;
    if (p === '/updates') {
        const html = fs.readFileSync(path.join(pageList, 'updates.html'), 'utf8').replace(/\{\{CSRF_TOKEN\}\}/g, 'csrf-prova');
        return route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: html });
    }
    // The script dictionary (t() and the texts), as the panel serves it.
    if (p.startsWith('/i18n/')) return route.fulfill({ status: 200, contentType: 'application/javascript', body: fs.readFileSync(path.join(pageList, p)) });
    if (p.startsWith('/vendor/') || p.startsWith('/fa/')) {
        const f = path.join(resourceList, p);
        if (!fs.existsSync(f)) return route.fulfill({ status: 404, body: '' });
        const kindValue = p.endsWith('.css') ? 'text/css' : p.endsWith('.js') ? 'application/javascript' : p.endsWith('.woff2') ? 'font/woff2' : 'application/octet-stream';
        return route.fulfill({ status: 200, contentType: kindValue, body: fs.readFileSync(f) });
    }
    const bodyText = req.postData() ? JSON.parse(req.postData()) : null;
    requests.push({ metodo: req.method(), path: p, body: bodyText });
    if (p !== '/api/updates' || !bodyText) return json(route, { success: true });
    switch (bodyText.action) {
        case 'branch_status': readings++; return json(route, stateValue());
        case 'branch_preview': return json(route, { success: true, possible: true, from: branchNow, destination: bodyText.destination,
            fingerprint: stateValue().fingerprint, file: '/usr/local/etc/pkg/repos/zz-panel-branch.conf',
            changes: [{ name: 'FreeBSD-ports', from: 'pkg+https://pkg.FreeBSD.org/FreeBSD:15:amd64/quarterly', to: 'pkg+https://pkg.FreeBSD.org/${ABI}/latest' }],
            warnings: ['Non si aggiorna nessun pacchetto: cambia da dove pkg li prende.', 'Su latest il prossimo aggiornamento puo\' portare versioni maggiori nuove.'],
            content: '# Written by the mail panel\nFreeBSD-ports: { url: "pkg+https://pkg.FreeBSD.org/${ABI}/latest" }\n', howToReturn: '' });
        case 'branch_change':
            if (!changeSucceeds) return json(route, { success: false, error: 'C\'e\' gia\' un lavoro sui pacchetti in corso (aggiornamento di nginx).' });
            rounds = 0;
            return json(route, { success: true, jobId: 'ramo-1', async: true });
        case 'job_status':
            rounds++;
            if (rounds < 2) return json(route, { success: true, job: { status: 'running', consoleLog: '[12:00:00] [3/3] Scarico il catalogo del ramo latest (pkg update -f)...\n' } });
            branchNow = 'latest';
            return json(route, { success: true, job: { status: 'completed', elapsedSeconds: 9, errorMessage: '',
                result: 'Adesso i pacchetti arrivano dal ramo latest, e il suo catalogo e\' scaricato. Nessun pacchetto e\' stato cambiato. 2 pacchetti si possono aggiornare.',
                consoleLog: '[12:00:00] [3/3] Scarico il catalogo...\n[12:00:09] All repositories are up to date.\n' } });
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
    page.on('console', m => { if (m.type() === 'error') errorList.push(m.text()); });

    console.log('\n== La scheda si legge da sola ==');
    await page.goto(BASE + '/updates');
    await page.waitForSelector('#branch-body table');
    const textValue = await page.textContent('#branch-body');
    real('ramo quarterly, con la spiegazione', textValue.includes('I pacchetti arrivano dal ramo quarterly') && textValue.includes('Ramo trimestrale'));
    const lineItems = await page.$$eval('#branch-body tbody tr', tr => tr.map(r => r.cells[0].textContent));
    real('i quattro repository, anche quello non ufficiale: ' + lineItems.join(', '), lineItems.length === 4 && lineItems[3] === 'mio<b>repo</b>');
    real('nomi e indirizzi restano testo: nessun <b>, nessun <img>', await page.locator('#branch-body b, #branch-body img').count() === 0
        && await page.evaluate(() => window.injectedRan) === undefined);
    real('di serie: "nessun file del pannello"', textValue.includes('Nessun file del pannello'));
    real('il pulsante per passare a latest', await page.locator('#branch-body button', { hasText: 'Passa al ramo latest' }).count() === 1);
    if (photos) await page.locator('#branch').screenshot({ path: path.join(photos, 'branch-card.png') });

    console.log('\n== Anteprima e conferma ==');
    await page.click('#branch-body button:has-text("Passa al ramo latest")');
    await page.waitForSelector('#branch-confirm');
    const previewText = await page.textContent('#branch-preview');
    real('l\'anteprima: cosa cambia, gli warnings, il file che si scrive', previewText.includes('Passare dal ramo quarterly al ramo latest')
        && previewText.includes('pkg+https://pkg.FreeBSD.org/${ABI}/latest') && previewText.includes('Non si aggiorna nessun pacchetto')
        && previewText.includes('zz-panel-branch.conf'));
    real('"Cambia ramo" spento finche\' non si scrive latest', await page.isDisabled('#branch-go'));
    await page.fill('#branch-confirm', 'Latest');
    real('scritto diverso (Latest): resta spento', await page.isDisabled('#branch-go'));
    await page.fill('#branch-confirm', 'latest');
    real('scritto giusto: si accende', await page.isEnabled('#branch-go'));
    if (photos) await page.locator('#branch').screenshot({ path: path.join(photos, 'branch-preview-shot.png') });

    console.log('\n== Il cambio, seguito fino all\'esito ==');
    await page.click('#branch-go');
    const post = requests.find(r => r.body && r.body.action === 'branch_change');
    real('la richiesta: ramo, conferma, fingerprint dell\'anteprima, token CSRF', post && post.body.destination === 'latest'
        && post.body.confirm === 'latest' && post.body.fingerprint === 'aaaaaaaaaaaaaaaa' && post.body.csrf_token === 'csrf-prova');
    await page.waitForFunction(() => document.getElementById('branch-outcome').textContent.includes('Adesso i pacchetti arrivano'), null, { timeout: 15000 });
    real('il registro del lavoro si vede', (await page.textContent('#branch-log')).includes('All repositories are up to date'));
    real('l\'esito, in verde', await page.locator('#branch-outcome .alert-success').count() === 1);
    await page.waitForFunction(() => document.getElementById('branch-body').textContent.includes('dal ramo latest'));
    real('la scheda si rilegge da sola: ora latest, con il file del pannello', readings === 2
        && (await page.textContent('#branch-body')).includes('Il ramo lo decide il file del pannello'));
    if (photos) await page.locator('#branch').screenshot({ path: path.join(photos, 'branch-after.png') });

    console.log('\n== Un cambio che non parte ==');
    changeSucceeds = false;
    await page.click('#branch-body button:has-text("Passa al ramo quarterly")');
    await page.waitForSelector('#branch-confirm');
    await page.fill('#branch-confirm', 'quarterly');
    await page.click('#branch-go');
    await page.waitForSelector('#branch-outcome .alert-danger');
    real('l\'errore del server, in rosso: ' + await page.textContent('#branch-outcome'), (await page.textContent('#branch-outcome')).includes('lavoro sui pacchetti in corso'));
    real('e si puo\' riprovare', await page.isEnabled('#branch-go'));

    console.log('\n== Tema scuro e telefono ==');
    await page.evaluate(() => document.documentElement.setAttribute('data-theme', 'dark'));
    await page.waitForTimeout(600);   // il cambio di tema ha una transizione
    if (photos) await page.locator('#branch').screenshot({ path: path.join(photos, 'branch-dark.png') });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.evaluate(() => document.documentElement.setAttribute('data-theme', 'light'));
    await page.waitForTimeout(300);
    const pageWidth = await page.evaluate(() => document.documentElement.scrollWidth);
    real('sul telefono la pagina non scorre di lato: ' + pageWidth + 'px', pageWidth <= 390);
    if (photos) await page.locator('#branch').screenshot({ path: path.join(photos, 'branch-phone.png') });

    real('nessun errore nella pagina' + (errorList.length ? ': ' + errorList.join(' | ') : ''), errorList.length === 0);
    await browser.close();
    console.log('\n' + (failedOnes === 0 ? 'TUTTO VERDE' : failedOnes + ' CONTROLLI FALLITI'));
    process.exit(failedOnes ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
