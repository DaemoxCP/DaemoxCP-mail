// Le finestre "Trasforma in casella" (pagina Alias) e "Trasforma in alias" (pagina Caselle) in
// Chromium, sulle pagine generate dal pannello. Il server qui e' simulato: le sue regole e le sue
// transazioni le prova AddressConversionTest, su MySQL. Qui si controlla che la pagina mostri l'anteprima,
// chieda quello che serve (password, scelta sulla posta di prima, indirizzo scritto per conferma),
// mandi al server l'impronta e il token CSRF, e che "Elimina casella" ora mandi il token.
//
// Uso (dalla radice del progetto, dopo mvn package):
//   D=$(mktemp -d) && javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/content/PageGenerator.java \
//     && java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.content.PageGenerator $D >/dev/null
//   NODE_PATH=$(npm root -g) node tests/address-conversion-browser-test.js $D [cartella-per-le-foto]
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
const ALIAS = [
    { id: 1, source: 'dmarc@domain-d.test', destination: 'owner@example.net', domain: 'domain-d.test', active: true },
    { id: 2, source: '@domain-d.test', destination: 'owner@domain-d.test', domain: 'domain-d.test', active: true },
    { id: 3, source: 'postmaster@domain-d.test', destination: 'dmarc@domain-d.test', domain: 'domain-d.test', active: true },
];
const CASELLE = [{ id: 7, email: 'info@domain-d.test', name: 'Info', domain: 'domain-d.test', quota_mb: 1024, active: true,
    receive_enabled: true, last_login: '2026-09-30 10:00:00', autoresponder_enabled: true, forwarding_count: 1, filters_count: 2 }];

// La finestra entra con una dissolvenza di Bootstrap: le foto si fanno quando e' ferma.
async function ferma(page, id) {
    await page.waitForSelector('#' + id + '.show');
    await page.waitForFunction(i => getComputedStyle(document.getElementById(i)).opacity === '1'
        && getComputedStyle(document.querySelector('#' + i + ' .modal-dialog')).transform === 'none', id);
}

function json(route, corpo) { return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(corpo) }); }

async function servi(route) {
    const req = route.request();
    const url = new URL(req.url());
    const p = url.pathname;
    if (p === '/aliases' || p === '/mailboxes') {
        const html = fs.readFileSync(path.join(pagine, p.substring(1) + '.html'), 'utf8').replace(/\{\{CSRF_TOKEN\}\}/g, 'csrf-prova');
        return route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: html });
    }
    if (p.startsWith('/vendor/') || p.startsWith('/fa/')) {
        const f = path.join(risorse, p);
        if (!fs.existsSync(f)) return route.fulfill({ status: 404, body: '' });
        const tipo = p.endsWith('.css') ? 'text/css' : p.endsWith('.js') ? 'application/javascript' : p.endsWith('.woff2') ? 'font/woff2' : 'application/octet-stream';
        return route.fulfill({ status: 200, contentType: tipo, body: fs.readFileSync(f) });
    }
    const corpo = req.postData() ? JSON.parse(req.postData()) : null;
    richieste.push({ metodo: req.method(), percorso: p + url.search, corpo });
    if (p === '/api/domains') return json(route, { success: true, domains: [{ id: 1, domain: 'domain-d.test' }] });
    if (p === '/api/aliases' && req.method() === 'GET') {
        if (url.searchParams.get('trasforma') === 'dmarc@domain-d.test') return json(route, { success: true, possibile: true,
            indirizzo: 'dmarc@domain-d.test', impronta: 'imp-alias',
            destinazioni: [{ destinazione: 'owner@example.net', attivo: true }], copia: false,
            versoQui: [{ sorgente: 'postmaster@domain-d.test', attivo: true }],
            posta: { presente: true, messaggi: 1234, almeno: false, byte: 52428800, dimensione: '50,0 MB', filtri: true, ultimo: '2025-05-12T09:30:00+02:00' } });
        if (url.searchParams.get('trasforma')) return json(route, { success: true, possibile: false, motivo: 'Non si puo\' in questa prova.' });
        return json(route, { success: true, aliases: ALIAS });
    }
    if (p === '/api/aliases' && req.method() === 'POST' && corpo.action === 'trasforma_in_casella')
        return json(route, { success: true, id: 99, message: 'dmarc@domain-d.test ora e\' una casella. La posta di prima e\' in /var/vmail/.archivio-pannello/domain-d.test/dmarc-20261003T120000Z.' });
    if (p === '/api/mailboxes' && req.method() === 'GET') {
        if (url.searchParams.get('trasforma') === '7') return json(route, { success: true, possibile: true, id: 7,
            indirizzo: 'info@domain-d.test', impronta: 'imp-casella',
            perdite: { ultimoAccesso: '2026-09-30T10:00:00+02:00', soloInvio: false, attiva: true, rispostaAutomatica: true,
                inoltri: ['owner@example.net'], filtri: 2 },
            proposte: ['owner@example.net'], giaInoltrata: [{ destinazione: 'capo@esterno.it', attivo: true }], copia: true,
            versoQui: [{ sorgente: 'vendite@domain-d.test', attivo: true }],
            posta: { presente: true, messaggi: 87, almeno: false, byte: 1048576, dimensione: '1,0 MB', filtri: true },
            cartella: '/var/vmail/domain-d.test/info' });
        return json(route, { success: true, mailboxes: CASELLE });
    }
    if (p === '/api/mailboxes' && req.method() === 'POST' && corpo.action === 'generate_password')
        return json(route, { success: true, password: 'Proposta-Dal-Generatore-42', entropy_bits: 120, strength_label: 'Molto forte' });
    if (p === '/api/mailboxes' && req.method() === 'POST' && corpo.action === 'trasforma_in_alias')
        return json(route, { success: true, message: 'info@domain-d.test ora e\' un alias verso owner@example.net.' });
    if (p === '/api/mailboxes' && req.method() === 'DELETE') return json(route, { success: true });
    return json(route, { success: true });
}

(async () => {
    const browser = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium-1194/chrome-linux/chrome' }).catch(() => chromium.launch());
    const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
    await ctx.route('**/*', servi);
    const page = await ctx.newPage();
    const errori = [];
    page.on('pageerror', e => errori.push(String(e)));
    page.on('console', m => { if (m.type() === 'error') errori.push(m.text()); });

    console.log('\n== Pagina Alias: "In casella" ==');
    await page.goto(BASE + '/aliases');
    await page.waitForSelector('#aliasesTable button');
    vero('il pulsante c\'e\' per dmarc@ e postmaster@, non per la raccolta @domain-d.test',
        await page.locator('button[aria-label="Trasforma in casella dmarc@domain-d.test"]').count() === 1
        && await page.locator('button[aria-label="Trasforma in casella @domain-d.test"]').count() === 0);
    await page.click('button[aria-label="Trasforma in casella dmarc@domain-d.test"]');
    await page.waitForSelector('#acSi:not(.d-none)');
    vero('anteprima: destinazione di adesso e chi arriva qui', (await page.textContent('#acDestinazioni')).includes('owner@example.net')
        && (await page.textContent('#acVersoQui')).includes('postmaster@domain-d.test'));
    vero('la posta di prima: 1234 messaggi, 50,0 MB, ultimo del 12/05/2025, e i filtri',
        (await page.textContent('#acPostaInfo')).includes('1234 messaggi, 50,0 MB, l\'ultimo del 12/05/2025') && await page.isVisible('#acPostaBlocco'));
    await page.waitForFunction(() => document.getElementById('acPass').value === 'Proposta-Dal-Generatore-42');
    vero('la password e\' gia\' proposta dal generatore', true);
    await page.click('#acVia');
    vero('senza scegliere cosa fare della posta di prima: si ferma e lo chiede', (await page.textContent('#acErr')).includes('Scegli cosa fare'));
    await page.check('#acArchivia');
    vero('fatta la scelta, l\'avviso sparisce', (await page.textContent('#acErr')) === '');
    await page.fill('#acNome', 'DMARC');
    await ferma(page, 'aCasellaModal');
    if (foto) await page.screenshot({ path: path.join(foto, 'trasforma-in-casella.png') });
    await page.click('#acVia');
    await page.waitForSelector('#aCasellaModal', { state: 'hidden' });
    const post = richieste.find(r => r.corpo && r.corpo.action === 'trasforma_in_casella');
    vero('la richiesta: password, scelta "archivia", impronta, CSRF, inoltri non tenuti', post && post.corpo.password === 'Proposta-Dal-Generatore-42'
        && post.corpo.posta_vecchia === 'archivia' && post.corpo.impronta === 'imp-alias' && post.corpo.csrf_token === 'csrf-prova'
        && post.corpo.tieni_inoltri === false && post.corpo.name === 'DMARC' && post.corpo.quota_mb === 1024);
    vero('e il messaggio del server', (await page.textContent('#aliasMsg')).includes('ora e\' una casella'));

    console.log('\n== Pagina Caselle: "Trasforma in alias" ==');
    await page.goto(BASE + '/mailboxes');
    await page.waitForSelector('#mailboxesTable .dropdown-toggle');
    await page.click('#mailboxesTable .dropdown-toggle');
    await page.click('text=Trasforma in alias');
    await page.waitForSelector('#aaSi:not(.d-none)');
    const perdite = await page.textContent('#aaPerdite');
    vero('cosa si perde: login (con l\'ultimo accesso), risposta automatica, 2 filtri, inoltri, la copia su se stessa',
        perdite.includes('Ultimo accesso: 30/09/2026') && perdite.includes('risposta automatica') && perdite.includes('2 filtri')
        && perdite.includes('Gli inoltri della casella') && perdite.includes('info@domain-d.test -> info@domain-d.test'));
    const resta = await page.textContent('#aaResta');
    vero('cosa resta: la posta (87 messaggi, nella sua cartella), gli alias che ha, chi porta qui',
        resta.includes('87 messaggi, 1,0 MB, in /var/vmail/domain-d.test/info') && resta.includes('capo@esterno.it') && resta.includes('vendite@domain-d.test'));
    vero('le destinazioni proposte sono gli inoltri', (await page.inputValue('#aaDest')) === 'owner@example.net');
    vero('il pulsante resta spento finche\' non si scrive l\'indirizzo', await page.isDisabled('#aaVia'));
    await page.fill('#aaConferma', 'INFO@domain-d.test ');
    vero('scritto (maiuscole e spazi non contano): si accende', await page.isEnabled('#aaVia'));
    await page.fill('#aaDest', 'owner@example.net\npostmaster@domain-c.test\n');
    await ferma(page, 'aAliasModal');
    if (foto) await page.screenshot({ path: path.join(foto, 'trasforma-in-alias.png') });
    await page.click('#aaVia');
    await page.waitForSelector('#aAliasModal', { state: 'hidden' });
    const pa = richieste.find(r => r.corpo && r.corpo.action === 'trasforma_in_alias');
    vero('la richiesta: due destinazioni, la conferma, l\'impronta, il CSRF', pa && pa.corpo.destinazioni.length === 2
        && pa.corpo.destinazioni[1] === 'postmaster@domain-c.test' && pa.corpo.conferma === 'INFO@domain-d.test'
        && pa.corpo.impronta === 'imp-casella' && pa.corpo.csrf_token === 'csrf-prova' && pa.corpo.id === 7);
    vero('e il messaggio del server sopra la tabella', (await page.textContent('#mbMsg')).includes('ora e\' un alias'));

    console.log('\n== Elimina casella: ora con il token CSRF ==');
    page.once('dialog', d => { vero('la conferma dice che la posta resta sul disco', d.message().includes('resta sul disco')); d.accept(); });
    await page.click('#mailboxesTable .dropdown-toggle');
    await page.click('#mailboxesTable .dropdown-item.text-danger');
    await page.waitForFunction(() => true);
    await page.waitForTimeout(300);
    const del = richieste.find(r => r.metodo === 'DELETE');
    vero('DELETE con il token CSRF nel corpo', del && del.corpo && del.corpo.csrf_token === 'csrf-prova');

    console.log('\n== Tema scuro e telefono ==');
    await page.evaluate(() => document.documentElement.setAttribute('data-theme', 'dark'));
    await page.click('#mailboxesTable .dropdown-toggle');
    await page.click('text=Trasforma in alias');
    await page.waitForSelector('#aaSi:not(.d-none)');
    await ferma(page, 'aAliasModal');
    await page.waitForTimeout(400);   // il cambio di tema ha una transizione
    if (foto) await page.screenshot({ path: path.join(foto, 'trasforma-in-alias-scuro.png') });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.waitForTimeout(300);
    const largo = await page.evaluate(() => document.querySelector('#aAliasModal .modal-dialog').getBoundingClientRect().right);
    vero('sul telefono la finestra sta nello schermo: ' + Math.round(largo) + 'px', largo <= 390);
    if (foto) await page.screenshot({ path: path.join(foto, 'trasforma-in-alias-telefono.png') });

    vero('nessun errore nella pagina' + (errori.length ? ': ' + errori.join(' | ') : ''), errori.length === 0);
    await browser.close();
    console.log('\n' + (falliti === 0 ? 'TUTTO VERDE' : falliti + ' CONTROLLI FALLITI'));
    process.exit(falliti ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
