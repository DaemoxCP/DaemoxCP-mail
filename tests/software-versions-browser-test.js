// La Home in Chromium: la colonna Versione di "Servizi Mail" (con MySQL e Redis), la tabella
// "Altro software", gli warnings "da riavviare", le conferme prima di fermare un servizio e il
// token CSRF mandato a /api/service. Il server e' simulato: le letture vere le prova
// SoftwareVersionsTest. Qui si controlla che la pagina mostri cio' che il server dice, solo come testo.
//
// Uso (dalla radice del progetto, dopo mvn package):
//   D=$(mktemp -d) && javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/content/PageGenerator.java \
//     && java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.content.PageGenerator $D >/dev/null
//   NODE_PATH=$(npm root -g) node tests/software-versions-browser-test.js $D [cartella-per-le-foto]
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
const VERSIONS = {
    success: true, readAt: '2026-10-03T14:00:05+02:00', branch: 'quarterly',
    services: {
        postfix: { key: 'postfix', name: 'Postfix', role: 'Server SMTP', installed: true, version: '3.10.4', source: '/usr/local/sbin/postconf -h mail_version',
            pkgName: 'postfix-mysql-3.10.4,1', restart: true,
            restartNote: "Postfix e' partito il 28/09/2026 08:15, prima dell'installazione del pacchetto (02/10/2026 09:00): sta eseguendo la versione di prima. Riavvialo per usare quella installata." },
        dovecot: { key: 'dovecot', name: 'Dovecot', role: 'IMAP', installed: true, version: '2.3.21.1', source: '/usr/local/sbin/dovecot --version', pkgName: 'dovecot-mysql-2.3.21.1_8' },
        mysql: { key: 'mysql', name: 'MySQL', role: 'Database', installed: true, version: '8.0.42', source: 'SELECT VERSION() sulla connessione del pannello',
            running: true, pkgName: 'mysql80-server-8.0.43', restart: true, installedVersion: '8.0.43',
            restartNote: "MySQL in esecuzione e' la 8.0.42, quella installata la 8.0.43: riavvia MySQL per usare quella installata." },
        rspamd: { key: 'rspamd', name: 'Rspamd', role: 'Antispam', installed: true, version: '<img src=x onerror="window.injectedRan=1">',
            source: 'prova', pkgName: 'rspamd-3.12.1' },
        redis: { key: 'redis', name: 'Redis', role: 'Archivio', installed: false },
        clamav: { key: 'clamav', name: 'ClamAV', role: 'Antivirus', installed: true, version: '1.4.3', running: true, signatures: '27780',
            detail: 'firme 27780 del 02/10/2026 08:24', pkgName: 'clamav-1.4.3,1' },
        roundcube: { key: 'roundcube', name: 'Roundcube', role: 'Webmail', installed: true, version: '1.6.11', pkgName: 'roundcube-php84-1.6.11,1' },
    },
    other: [
        { key: 'freebsd', name: 'FreeBSD', role: 'Sistema operativo', installed: true, version: '15.0-RELEASE-p3', detail: 'kernel in esecuzione 15.0-RELEASE-p2',
            restart: true, restartNote: "Il kernel installato e' 15.0-RELEASE-p3, quello in esecuzione 15.0-RELEASE-p2: serve un riavvio del server." },
        { key: 'openssl', name: 'OpenSSL', role: 'Libreria TLS del sistema base: la usano i pacchetti ufficiali', installed: true, version: '3.5.1', detail: 'rilasciata il 01/07/2025' },
        { key: 'nginx', name: 'nginx', role: 'Web server: webmail, MTA-STS, configurazione automatica dei client', installed: true, version: '1.28.0', pkgName: 'nginx-1.28.0_3,3' },
        { key: 'php', name: 'PHP-FPM', role: 'Esegue la webmail', installed: true, version: '8.4.13', pkgName: 'php84-8.4.13' },
        { key: 'pigeonhole', name: 'Pigeonhole', role: 'Filtri Sieve e risposte automatiche', installed: false },
        { key: 'java', name: 'Java', role: 'Esegue questo pannello', installed: true, version: '25.0.1+8-1', running: true, pkgName: 'openjdk25-25.0.1+8.1' },
        { key: 'clamav', name: 'ClamAV', role: 'Antivirus', installed: true, version: '1.4.3', warning: 'Le firme hanno 19 giorni: freshclam non le sta aggiornando, e i virus nuovi passano.' },
    ],
};
// L'ultima riga di "altro" e' finta (ClamAV non sta li'): serve a vedere l'avviso in rosso.

function json(route, bodyText) { return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(bodyText) }); }

async function served(route) {
    const req = route.request();
    const url = new URL(req.url());
    const p = url.pathname;
    if (p === '/') {
        const html = fs.readFileSync(path.join(pageList, 'home.html'), 'utf8').replace(/\{\{CSRF_TOKEN\}\}/g, 'csrf-prova');
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
    if (p === '/api/status') return json(route, { postfix: true, dovecot: true, mysql: true, rspamd: true, redis: false, clamav: true, roundcube: true,
        domains: 2, mailboxes: 5, aliases: 3, mail_hostname: '', server_ip: '' });
    if (p === '/api/versions') return json(route, VERSIONS);
    if (p === '/api/service') return json(route, { success: true });
    if (p === '/api/updates') return json(route, { success: true, active: true, reason: 'Il pannello riparte da solo.' });
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

    console.log('\n== Servizi Mail: la colonna Versione ==');
    await page.goto(BASE + '/');
    await page.waitForFunction(() => document.getElementById('versioniStato').textContent.startsWith('Lette'));
    const lineItems = await page.$$eval('table[aria-label^="Servizi mail"] tbody tr', tr => tr.map(r => r.cells[0].textContent.trim()));
    real('sette righe, con MySQL e Redis: ' + lineItems.join(' | '), lineItems.length === 7 && lineItems[2] === 'MySQL (Database)' && lineItems[4] === 'Redis (dati di Rspamd)');
    const pf = await page.textContent('#ver-postfix');
    real('Postfix: 3.10.4, il pacchetto e "da riavviare" con la nota', pf.includes('3.10.4') && pf.includes('pacchetto postfix-mysql-3.10.4,1')
        && pf.includes('da riavviare') && pf.includes('28/09/2026 08:15'));
    real('la fonte nel title della versione', await page.getAttribute('#ver-postfix strong', 'title') === 'Letta con: /usr/local/sbin/postconf -h mail_version');
    const my = await page.textContent('#ver-mysql');
    real('MySQL: 8.0.42 (in esecuzione), da riavviare perche\' il pacchetto e\' la 8.0.43', my.includes('8.0.42') && my.includes('(in esecuzione)')
        && my.includes('da riavviare') && my.includes('quella installata la 8.0.43'));
    real('ClamAV: motore e firme', (await page.textContent('#ver-clamav')).includes('firme 27780 del 02/10/2026 08:24'));
    real('Redis non installato', (await page.textContent('#ver-redis')).trim() === 'non installato');
    real('stato di Redis: Fermo; di MySQL: Attivo', (await page.textContent('#redis-status')) === 'Fermo' && (await page.textContent('#mysql-status')) === 'Attivo');
    const injected = await page.evaluate(() => ({ img: document.querySelectorAll('#ver-rspamd img').length, flag: window.injectedRan }));
    real('una versione con dentro HTML resta testo: nessun <img>, nessuno script', injected.img === 0 && injected.flag === undefined
        && (await page.textContent('#ver-rspamd strong')).startsWith('<img'));
    const stateValue = await page.textContent('#versioniStato');
    real('riepilogo: ora della lettura e quanti da riavviare — ' + stateValue, stateValue.startsWith('Lette dal server alle 14:00:05.') && stateValue.includes('3 programmi vanno riavviati'));
    real('e il ramo dei pacchetti, con il collegamento alla scheda per cambiarlo', stateValue.includes('Pacchetti dal ramo quarterly.')
        && await page.getAttribute('#versioniStato a', 'href') === '/updates#branch');

    console.log('\n== Altro software ==');
    const otherOne = await page.$$eval('#altroSoftware tr', tr => tr.map(r => [...r.cells].map(c => c.textContent.trim())));
    real('una riga per programma: ' + otherOne.map(r => r[0]).join(', '), otherOne.length === 7 && otherOne[0][0] === 'FreeBSD' && otherOne[5][0] === 'Java');
    real('FreeBSD: userland, kernel in esecuzione, riavvio del server', otherOne[0][2].includes('15.0-RELEASE-p3') && otherOne[0][2].includes('kernel in esecuzione 15.0-RELEASE-p2')
        && otherOne[0][2].includes('serve un riavvio del server'));
    real('a cosa serve: nginx', otherOne[2][1].startsWith('Web server'));
    real('Pigeonhole non installato', otherOne[4][2] === 'non installato');
    real("l'avviso e' rosso, la nota sul riavvio gialla", await page.locator('#altroSoftware .testo-rischio').count() === 1
        && await page.locator('#altroSoftware .testo-avviso').count() === 1);
    real('ogni cella ha la sua etichetta per il telefono', await page.locator('#altroSoftware td:not([data-label])').count() === 0);
    if (photos) await page.screenshot({ path: path.join(photos, 'home-versioni.png'), fullPage: true });

    console.log('\n== Comandi: nomi, conferme, CSRF ==');
    real('i pulsanti hanno un nome: Avvia/Riavvia/Ferma Postfix, Ferma la webmail',
        await page.locator('button[aria-label="Avvia Postfix"]').count() === 1 && await page.locator('button[aria-label="Riavvia Postfix"]').count() === 1
        && await page.locator('button[aria-label="Ferma Postfix"]').count() === 1 && await page.locator('button[aria-label="Ferma la webmail"]').count() === 1);
    let question = '';
    page.once('dialog', d => { question = d.message(); d.dismiss(); });
    const beforeValue = requests.length;
    await page.click('button[aria-label="Ferma Postfix"]');
    await page.waitForTimeout(300);
    real('Ferma Postfix: chiede, e dice cosa succede — ' + question, question.startsWith('Fermare Postfix?') && question.includes('smette di ricevere'));
    real('annullato: nessuna richiesta', !requests.slice(beforeValue).some(r => r.path === '/api/service'));
    const dialogs2 = [];
    page.on('dialog', d => { dialogs2.push(d.message()); d.accept(); });
    await page.click('button[aria-label="Ferma Postfix"]');
    await page.waitForFunction(() => true);
    await page.waitForTimeout(500);
    const post = requests.find(r => r.path === '/api/service');
    real('confermato: POST con servizio, azione e token CSRF', post && post.body.service === 'postfix' && post.body.action === 'stop'
        && post.body.csrf_token === 'csrf-prova');
    real('dopo il comando si rileggono le versioni subito (?fresh=1)', requests.some(r => r.path === '/api/versions?fresh=1'));
    dialogs2.length = 0;
    await page.click('button[aria-label="Riavvia Postfix"]');
    await page.waitForTimeout(400);
    real('Riavvia Postfix: nessuna domanda, solo l\'esito', dialogs2.length === 1 && dialogs2[0] === 'Operazione completata');
    dialogs2.length = 0;
    await page.click('button[aria-label="Riavvia MySQL"]');
    await page.waitForTimeout(400);
    real('Riavvia MySQL: chiede prima — ' + dialogs2[0], dialogs2.length === 2 && dialogs2[0].startsWith('Riavviare MySQL?'));
    const mysql = requests.filter(r => r.path === '/api/service').pop();
    real('e manda mysql-server', mysql.body.service === 'mysql-server' && mysql.body.action === 'restart');
    const n = requests.filter(r => r.path === '/api/versions?fresh=1').length;
    await page.click('#versioniRileggi');
    await page.waitForFunction(k => true, n);
    await page.waitForTimeout(300);
    real('"Rileggi le versioni" chiede una lettura fresca', requests.filter(r => r.path === '/api/versions?fresh=1').length === n + 1);

    console.log('\n== Tema scuro e telefono ==');
    await page.evaluate(() => document.documentElement.setAttribute('data-theme', 'dark'));
    await page.waitForTimeout(600);   // il cambio di tema ha una transizione
    if (photos) await page.screenshot({ path: path.join(photos, 'home-versioni-scuro.png'), fullPage: true });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.evaluate(() => document.documentElement.setAttribute('data-theme', 'light'));
    await page.waitForTimeout(300);
    const pageWidth = await page.evaluate(() => document.documentElement.scrollWidth);
    real('sul telefono la pagina non scorre di lato: ' + pageWidth + 'px', pageWidth <= 390);
    real('sul telefono le tabelle diventano schede (intestazioni nascoste)',
        await page.$eval('table[aria-label^="Servizi mail"] thead', t => getComputedStyle(t).display) === 'none');
    if (photos) {
        await page.locator('table[aria-label^="Servizi mail"]').scrollIntoViewIfNeeded();
        await page.screenshot({ path: path.join(photos, 'home-versioni-telefono.png') });
    }

    real('nessun errore nella pagina' + (errorList.length ? ': ' + errorList.join(' | ') : ''), errorList.length === 0);
    await browser.close();
    console.log('\n' + (failedOnes === 0 ? 'TUTTO VERDE' : failedOnes + ' CONTROLLI FALLITI'));
    process.exit(failedOnes ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
