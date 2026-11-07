// L'avviso della reinstallazione interrotta nella pagina Aggiornamenti, in Chromium, col server
// simulato (reperto 170): il pulsante «Torna al server di prima della reinstallazione» c'e' solo per la
// reinstallazione con la sua via di ritorno; chiede conferma; manda azione, nome e conferma; dice
// l'esito e il riavvio; un rifiuto del server si legge; annullare non manda niente; il nome si
// mostra come testo (non come HTML). La funzione vera la provano ReinstallReturnE2ETest e RolesTest.
//
// Uso (dalla radice del progetto, dopo mvn package):
//   D=$(mktemp -d) && javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/content/PageGenerator.java \
//     && java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.content.PageGenerator $D >/dev/null
//   NODE_PATH=$(npm root -g) node tests/way-back-browser-test.js $D [cartella-per-le-foto]
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

const WAY_BACK = 'reinstall-before-2026-11-06-120000';
let notice = null;
let wayBackAnswer = null;
const requests = [];

function json(route, body) { return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) }); }

async function served(route) {
    const req = route.request();
    const p = new URL(req.url()).pathname;
    if (p === '/updates') {
        const html = fs.readFileSync(path.join(pageList, 'updates.html'), 'utf8').replace(/\{\{CSRF_TOKEN\}\}/g, 'csrf-prova');
        return route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: html });
    }
    if (p.startsWith('/i18n/')) return route.fulfill({ status: 200, contentType: 'application/javascript', body: fs.readFileSync(path.join(pageList, p)) });
    if (p.startsWith('/vendor/') || p.startsWith('/fa/')) {
        const f = path.join(resourceList, p);
        if (!fs.existsSync(f)) return route.fulfill({ status: 404, body: '' });
        const kind = p.endsWith('.css') ? 'text/css' : p.endsWith('.js') ? 'application/javascript' : p.endsWith('.woff2') ? 'font/woff2' : 'application/octet-stream';
        return route.fulfill({ status: 200, contentType: kind, body: fs.readFileSync(f) });
    }
    const body = req.postData() ? JSON.parse(req.postData()) : null;
    requests.push({ path: p, body: body });
    if (p !== '/api/updates' || !body) return json(route, { success: true });
    switch (body.action) {
        case 'interruption_status': return json(route, { success: true, notice: notice });
        case 'reinstall_way_back': return json(route, wayBackAnswer);
        default: return json(route, { success: true });
    }
}

async function open(page) {
    await page.goto(BASE + '/updates');
    await page.waitForFunction(() => document.getElementById('upd-interrupted') && document.getElementById('upd-interrupted').innerHTML.length > 0);
}

(async () => {
    const browser = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium-1194/chrome-linux/chrome' }).catch(() => chromium.launch());
    const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
    await ctx.route('**/*', served);
    const page = await ctx.newPage();
    const errorList = [];
    page.on('pageerror', e => errorList.push(String(e)));
    page.on('console', m => { if (m.type() === 'error') errorList.push(m.text()); });

    console.log('\n== Un lavoro qualunque interrotto: nessun pulsante per tornare indietro ==');
    notice = { description: 'aggiornamento di nginx', text: 'Un lavoro non è arrivato in fondo.' };
    await open(page);
    real('l\'avviso c\'e\'', (await page.textContent('#upd-interrupted')).includes('Un lavoro non è arrivato in fondo'));
    real('nessun pulsante per tornare indietro', await page.locator('#upd-way-back-btn').count() === 0);

    console.log('\n== La reinstallazione interrotta, con la sua via di ritorno ==');
    notice = { description: 'complete mail server installation', reinstall: true, wayBack: WAY_BACK,
               text: 'Era la reinstallazione completa del server di posta.' };
    await open(page);
    const btn = page.locator('#upd-way-back-btn');
    real('il pulsante c\'e\', col nome della via di ritorno', await btn.count() === 1 && (await btn.textContent()).includes(WAY_BACK));

    console.log('\n== Annullare la conferma non manda niente ==');
    let asked = '';
    page.once('dialog', d => { asked = d.message(); d.dismiss(); });
    const before = requests.filter(r => r.body && r.body.action === 'reinstall_way_back').length;
    await btn.click();
    await page.waitForTimeout(300);
    real('chiede conferma, col nome', asked.includes(WAY_BACK));
    real('e annullando non manda la richiesta', requests.filter(r => r.body && r.body.action === 'reinstall_way_back').length === before);

    console.log('\n== Confermare: la richiesta e l\'esito ==');
    wayBackAnswer = { success: true, name: WAY_BACK, merged: 3, note: 'Al prossimo riavvio il server è quello di prima.',
                      log: ['3 file di posta arrivati dopo copiati dentro.'], reboot: { success: true } };
    page.once('dialog', d => d.accept());
    await btn.click();
    await page.waitForSelector('#upd-interrupted .alert-success');
    const sent = requests.filter(r => r.body && r.body.action === 'reinstall_way_back').pop();
    real('manda azione, nome e conferma', sent && sent.body.name === WAY_BACK && sent.body.confirm === 'GO BACK');
    const done = await page.textContent('#upd-interrupted');
    real('dice l\'esito, i file aggiunti e il riavvio', done.includes('Al prossimo riavvio il server è quello di prima')
        && done.includes('3 file di posta') && done.includes('si riavvia fra un minuto'));
    if (photos) await page.screenshot({ path: path.join(photos, 'way-back-done.png'), fullPage: true });

    console.log('\n== Il server rifiuta ==');
    await open(page);
    wayBackAnswer = { success: false, error: 'Il boot environment non c\'è più: non ho fatto niente.' };
    page.once('dialog', d => d.accept());
    await page.locator('#upd-way-back-btn').click();
    await page.waitForSelector('#upd-interrupted .alert-danger');
    real('il rifiuto si legge', (await page.textContent('#upd-interrupted .alert-danger')).includes('non c\'è più'));

    console.log('\n== Il riavvio non si puo\' programmare ==');
    await open(page);
    wayBackAnswer = { success: true, note: 'Pronto.', log: [], reboot: { success: false } };
    page.once('dialog', d => d.accept());
    await page.locator('#upd-way-back-btn').click();
    await page.waitForSelector('#upd-interrupted .alert-success');
    real('dice di riavviare a mano', (await page.textContent('#upd-interrupted')).includes('shutdown -r now'));

    console.log('\n== Un nome con dell\'HTML si mostra come testo ==');
    notice = { reinstall: true, wayBack: WAY_BACK + '<img src=x onerror="window.injectedRan=1">', text: 'x' };
    await open(page);
    await page.waitForTimeout(300);
    real('nessun codice eseguito dal nome', await page.evaluate(() => window.injectedRan === undefined));

    real('nessun errore nella pagina' + (errorList.length ? ': ' + errorList.join(' | ') : ''), errorList.length === 0);
    await browser.close();
    console.log(failedOnes === 0 ? '\nTUTTO VERDE' : '\n' + failedOnes + ' CONTROLLI FALLITI');
    process.exit(failedOnes === 0 ? 0 : 1);
})();
