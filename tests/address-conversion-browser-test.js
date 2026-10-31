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
const ALIAS = [
    { id: 1, source: 'dmarc@domain-d.test', destination: 'owner@example.net', domain: 'domain-d.test', active: true },
    { id: 2, source: '@domain-d.test', destination: 'owner@domain-d.test', domain: 'domain-d.test', active: true },
    { id: 3, source: 'postmaster@domain-d.test', destination: 'dmarc@domain-d.test', domain: 'domain-d.test', active: true },
];
const MAILBOXES = [{ id: 7, email: 'info@domain-d.test', name: 'Info', domain: 'domain-d.test', quota_mb: 1024, active: true,
    receive_enabled: true, last_login: '2026-09-30 10:00:00', autoresponder_enabled: true, forwarding_count: 1, filters_count: 2 }];

// La finestra entra con una dissolvenza di Bootstrap: le foto si fanno quando e' ferma.
async function stop(page, id) {
    await page.waitForSelector('#' + id + '.show');
    await page.waitForFunction(i => getComputedStyle(document.getElementById(i)).opacity === '1'
        && getComputedStyle(document.querySelector('#' + i + ' .modal-dialog')).transform === 'none', id);
}

function json(route, bodyText) { return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(bodyText) }); }

async function served(route) {
    const req = route.request();
    const url = new URL(req.url());
    const p = url.pathname;
    if (p === '/aliases' || p === '/mailboxes') {
        const html = fs.readFileSync(path.join(pageList, p.substring(1) + '.html'), 'utf8').replace(/\{\{CSRF_TOKEN\}\}/g, 'csrf-prova');
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
    requests.push({ metodo: req.method(), path: p + url.search, body: bodyText });
    if (p === '/api/domains') return json(route, { success: true, domains: [{ id: 1, domain: 'domain-d.test' }] });
    if (p === '/api/aliases' && req.method() === 'GET') {
        if (url.searchParams.get('transform') === 'dmarc@domain-d.test') return json(route, { success: true, possible: true,
            address: 'dmarc@domain-d.test', fingerprint: 'imp-alias',
            destinations: [{ destination: 'owner@example.net', active: true }], copy: false,
            towardsHere: [{ source: 'postmaster@domain-d.test', active: true }],
            mail: { present: true, messages: 1234, atLeast: false, bytes: 52428800, size: '50,0 MB', filters: true, last: '2025-05-12T09:30:00+02:00' } });
        if (url.searchParams.get('transform')) return json(route, { success: true, possible: false, reason: 'Non si puo\' in questa prova.' });
        return json(route, { success: true, aliases: ALIAS });
    }
    if (p === '/api/aliases' && req.method() === 'POST' && bodyText.action === 'transform_to_mailbox')
        return json(route, { success: true, id: 99, message: 'dmarc@domain-d.test ora e\' una casella. La posta di prima e\' in /var/vmail/.panel-archive/domain-d.test/dmarc-20261003T120000Z.' });
    if (p === '/api/mailboxes' && req.method() === 'GET') {
        if (url.searchParams.get('transform') === '7') return json(route, { success: true, possible: true, id: 7,
            address: 'info@domain-d.test', fingerprint: 'imp-casella',
            losses: { lastAccess: '2026-09-30T10:00:00+02:00', sendOnly: false, active: true, autoReply: true,
                forwards: ['owner@example.net'], filters: 2 },
            proposals: ['owner@example.net'], alreadyForwarded: [{ destination: 'capo@esterno.it', active: true }], copy: true,
            towardsHere: [{ source: 'vendite@domain-d.test', active: true }],
            mail: { present: true, messages: 87, atLeast: false, bytes: 1048576, size: '1,0 MB', filters: true },
            folder: '/var/vmail/domain-d.test/info' });
        return json(route, { success: true, mailboxes: MAILBOXES });
    }
    if (p === '/api/mailboxes' && req.method() === 'POST' && bodyText.action === 'generate_password')
        return json(route, { success: true, password: 'Proposta-Dal-Generatore-42', entropy_bits: 120, strength_label: 'Molto forte' });
    if (p === '/api/mailboxes' && req.method() === 'POST' && bodyText.action === 'transform_to_alias')
        return json(route, { success: true, message: 'info@domain-d.test ora e\' un alias verso owner@example.net.' });
    if (p === '/api/mailboxes' && req.method() === 'DELETE') return json(route, { success: true });
    return json(route, { success: true });
}

(async () => {
    const browser = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium-1194/chrome-linux/chrome' }).catch(() => chromium.launch());
    const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
    await ctx.route('**/*', served);
    const page = await ctx.newPage();
    const errorList = [];
    page.on('pageerror', e => errorList.push(String(e)));
    page.on('console', m => { if (m.type() === 'error') errorList.push(m.text()); });

    console.log('\n== Pagina Alias: "In casella" ==');
    await page.goto(BASE + '/aliases');
    await page.waitForSelector('#aliasesTable button');
    real('il pulsante c\'e\' per dmarc@ e postmaster@, non per la raccolta @domain-d.test',
        await page.locator('button[aria-label="Trasforma in casella dmarc@domain-d.test"]').count() === 1
        && await page.locator('button[aria-label="Trasforma in casella @domain-d.test"]').count() === 0);
    await page.click('button[aria-label="Trasforma in casella dmarc@domain-d.test"]');
    await page.waitForSelector('#acSi:not(.d-none)');
    real('anteprima: destinazione di adesso e chi arriva qui', (await page.textContent('#acDestinations')).includes('owner@example.net')
        && (await page.textContent('#acToHere')).includes('postmaster@domain-d.test'));
    real('la posta di prima: 1234 messaggi, 50,0 MB, ultimo del 12/05/2025, e i filtri',
        (await page.textContent('#acMailInfo')).includes('1234 messaggi, 50,0 MB. L\'ultimo è del 12/05/2025') && await page.isVisible('#acMailBlock'));
    await page.waitForFunction(() => document.getElementById('acPass').value === 'Proposta-Dal-Generatore-42');
    real('la password e\' gia\' proposta dal generatore', true);
    await page.click('#acVia');
    real('senza scegliere cosa fare della posta di prima: si ferma e lo chiede', (await page.textContent('#acErr')).includes('Scegli cosa fare'));
    await page.check('#acArchive');
    real('fatta la scelta, l\'avviso sparisce', (await page.textContent('#acErr')) === '');
    await page.fill('#acName', 'DMARC');
    await stop(page, 'aMailboxModal');
    if (photos) await page.screenshot({ path: path.join(photos, 'transform-to-mailbox.png') });
    await page.click('#acVia');
    await page.waitForSelector('#aMailboxModal', { state: 'hidden' });
    const post = requests.find(r => r.body && r.body.action === 'transform_to_mailbox');
    real('la richiesta: password, scelta "archivia", fingerprint, CSRF, inoltri non tenuti', post && post.body.password === 'Proposta-Dal-Generatore-42'
        && post.body.old_mail === 'archive' && post.body.fingerprint === 'imp-alias' && post.body.csrf_token === 'csrf-prova'
        && post.body.keep_forwards === false && post.body.name === 'DMARC' && post.body.quota_mb === 1024);
    real('e il messaggio del server', (await page.textContent('#aliasMsg')).includes('ora e\' una casella'));

    console.log('\n== Pagina Caselle: "Trasforma in alias" ==');
    await page.goto(BASE + '/mailboxes');
    await page.waitForSelector('#mailboxesTable .dropdown-toggle');
    await page.click('#mailboxesTable .dropdown-toggle');
    await page.click('text=Trasforma in alias');
    await page.waitForSelector('#aaSi:not(.d-none)');
    const losses = await page.textContent('#aaLosses');
    real('cosa si perde: login (con l\'ultimo accesso), risposta automatica, 2 filtri, inoltri, la copia su se stessa',
        losses.includes('Ultimo accesso: 30/09/2026') && losses.includes('risposta automatica') && losses.includes('2 filtri')
        && losses.includes('Gli inoltri della casella') && losses.includes('info@domain-d.test → info@domain-d.test'));
    const stays = await page.textContent('#aaStays');
    real('cosa resta: la posta (87 messaggi, nella sua cartella), gli alias che ha, chi porta qui',
        stays.includes('87 messaggi, 1,0 MB, in /var/vmail/domain-d.test/info') && stays.includes('capo@esterno.it') && stays.includes('vendite@domain-d.test'));
    real('le destinazioni proposte sono gli inoltri', (await page.inputValue('#aaDest')) === 'owner@example.net');
    real('il pulsante resta spento finche\' non si scrive l\'indirizzo', await page.isDisabled('#aaVia'));
    await page.fill('#aaConfirm', 'INFO@domain-d.test ');
    real('scritto (maiuscole e spazi non contano): si accende', await page.isEnabled('#aaVia'));
    await page.fill('#aaDest', 'owner@example.net\npostmaster@domain-c.test\n');
    await stop(page, 'aAliasModal');
    if (photos) await page.screenshot({ path: path.join(photos, 'transform-to-alias.png') });
    await page.click('#aaVia');
    await page.waitForSelector('#aAliasModal', { state: 'hidden' });
    const pa = requests.find(r => r.body && r.body.action === 'transform_to_alias');
    real('la richiesta: due destinazioni, la conferma, l\'fingerprint, il CSRF', pa && pa.body.destinations.length === 2
        && pa.body.destinations[1] === 'postmaster@domain-c.test' && pa.body.confirmation === 'INFO@domain-d.test'
        && pa.body.fingerprint === 'imp-casella' && pa.body.csrf_token === 'csrf-prova' && pa.body.id === 7);
    real('e il messaggio del server sopra la tabella', (await page.textContent('#mbMsg')).includes('ora e\' un alias'));

    console.log('\n== Elimina casella: ora con il token CSRF ==');
    page.once('dialog', d => { real('la conferma dice che la posta resta sul disco', d.message().includes('resta sul disco')); d.accept(); });
    await page.click('#mailboxesTable .dropdown-toggle');
    await page.click('#mailboxesTable .dropdown-item.text-danger');
    await page.waitForFunction(() => true);
    await page.waitForTimeout(300);
    const del = requests.find(r => r.metodo === 'DELETE');
    real('DELETE con il token CSRF nel corpo', del && del.body && del.body.csrf_token === 'csrf-prova');

    console.log('\n== Tema scuro e telefono ==');
    await page.evaluate(() => document.documentElement.setAttribute('data-theme', 'dark'));
    await page.click('#mailboxesTable .dropdown-toggle');
    await page.click('text=Trasforma in alias');
    await page.waitForSelector('#aaSi:not(.d-none)');
    await stop(page, 'aAliasModal');
    await page.waitForTimeout(400);   // il cambio di tema ha una transizione
    if (photos) await page.screenshot({ path: path.join(photos, 'transform-to-alias-dark.png') });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.waitForTimeout(300);
    const pageWidth = await page.evaluate(() => document.querySelector('#aAliasModal .modal-dialog').getBoundingClientRect().right);
    real('sul telefono la finestra sta nello schermo: ' + Math.round(pageWidth) + 'px', pageWidth <= 390);
    if (photos) await page.screenshot({ path: path.join(photos, 'transform-to-alias-phone.png') });

    real('nessun errore nella pagina' + (errorList.length ? ': ' + errorList.join(' | ') : ''), errorList.length === 0);
    await browser.close();
    console.log('\n' + (failedOnes === 0 ? 'TUTTO VERDE' : failedOnes + ' CONTROLLI FALLITI'));
    process.exit(failedOnes ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
