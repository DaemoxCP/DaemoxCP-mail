// La Home in Chromium: la colonna Versione di "Servizi Mail" (con MySQL e Redis), la tabella
// "Altro software", gli avvisi "da riavviare", le conferme prima di fermare un servizio e il
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
const VERSIONI = {
    success: true, letteAlle: '2026-10-03T14:00:05+02:00', ramo: 'quarterly',
    servizi: {
        postfix: { chiave: 'postfix', nome: 'Postfix', ruolo: 'Server SMTP', installato: true, versione: '3.10.4', fonte: '/usr/local/sbin/postconf -h mail_version',
            pacchetto: 'postfix-mysql-3.10.4,1', riavvio: true,
            notaRiavvio: "Postfix e' partito il 28/09/2026 08:15, prima dell'installazione del pacchetto (02/10/2026 09:00): sta eseguendo la versione di prima. Riavvialo per usare quella installata." },
        dovecot: { chiave: 'dovecot', nome: 'Dovecot', ruolo: 'IMAP', installato: true, versione: '2.3.21.1', fonte: '/usr/local/sbin/dovecot --version', pacchetto: 'dovecot-mysql-2.3.21.1_8' },
        mysql: { chiave: 'mysql', nome: 'MySQL', ruolo: 'Database', installato: true, versione: '8.0.42', fonte: 'SELECT VERSION() sulla connessione del pannello',
            inEsecuzione: true, pacchetto: 'mysql80-server-8.0.43', riavvio: true, installata: '8.0.43',
            notaRiavvio: "MySQL in esecuzione e' la 8.0.42, quella installata la 8.0.43: riavvia MySQL per usare quella installata." },
        rspamd: { chiave: 'rspamd', nome: 'Rspamd', ruolo: 'Antispam', installato: true, versione: '<img src=x onerror="window.iniettato=1">',
            fonte: 'prova', pacchetto: 'rspamd-3.12.1' },
        redis: { chiave: 'redis', nome: 'Redis', ruolo: 'Archivio', installato: false },
        clamav: { chiave: 'clamav', nome: 'ClamAV', ruolo: 'Antivirus', installato: true, versione: '1.4.3', inEsecuzione: true, firme: '27780',
            dettaglio: 'firme 27780 del 02/10/2026 08:24', pacchetto: 'clamav-1.4.3,1' },
        roundcube: { chiave: 'roundcube', nome: 'Roundcube', ruolo: 'Webmail', installato: true, versione: '1.6.11', pacchetto: 'roundcube-php84-1.6.11,1' },
    },
    altro: [
        { chiave: 'freebsd', nome: 'FreeBSD', ruolo: 'Sistema operativo', installato: true, versione: '15.0-RELEASE-p3', dettaglio: 'kernel in esecuzione 15.0-RELEASE-p2',
            riavvio: true, notaRiavvio: "Il kernel installato e' 15.0-RELEASE-p3, quello in esecuzione 15.0-RELEASE-p2: serve un riavvio del server." },
        { chiave: 'openssl', nome: 'OpenSSL', ruolo: 'Libreria TLS del sistema base: la usano i pacchetti ufficiali', installato: true, versione: '3.5.1', dettaglio: 'rilasciata il 01/07/2025' },
        { chiave: 'nginx', nome: 'nginx', ruolo: 'Web server: webmail, MTA-STS, configurazione automatica dei client', installato: true, versione: '1.28.0', pacchetto: 'nginx-1.28.0_3,3' },
        { chiave: 'php', nome: 'PHP-FPM', ruolo: 'Esegue la webmail', installato: true, versione: '8.4.13', pacchetto: 'php84-8.4.13' },
        { chiave: 'pigeonhole', nome: 'Pigeonhole', ruolo: 'Filtri Sieve e risposte automatiche', installato: false },
        { chiave: 'java', nome: 'Java', ruolo: 'Esegue questo pannello', installato: true, versione: '25.0.1+8-1', inEsecuzione: true, pacchetto: 'openjdk25-25.0.1+8.1' },
        { chiave: 'clamav', nome: 'ClamAV', ruolo: 'Antivirus', installato: true, versione: '1.4.3', avviso: 'Le firme hanno 19 giorni: freshclam non le sta aggiornando, e i virus nuovi passano.' },
    ],
};
// L'ultima riga di "altro" e' finta (ClamAV non sta li'): serve a vedere l'avviso in rosso.

function json(route, corpo) { return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(corpo) }); }

async function servi(route) {
    const req = route.request();
    const url = new URL(req.url());
    const p = url.pathname;
    if (p === '/') {
        const html = fs.readFileSync(path.join(pagine, 'home.html'), 'utf8').replace(/\{\{CSRF_TOKEN\}\}/g, 'csrf-prova');
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
    richieste.push({ metodo: req.method(), percorso: p + url.search, corpo });
    if (p === '/api/status') return json(route, { postfix: true, dovecot: true, mysql: true, rspamd: true, redis: false, clamav: true, roundcube: true,
        domains: 2, mailboxes: 5, aliases: 3, mail_hostname: '', server_ip: '' });
    if (p === '/api/versioni') return json(route, VERSIONI);
    if (p === '/api/service') return json(route, { success: true });
    if (p === '/api/updates') return json(route, { success: true, attivo: true, motivo: 'Il pannello riparte da solo.' });
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

    console.log('\n== Servizi Mail: la colonna Versione ==');
    await page.goto(BASE + '/');
    await page.waitForFunction(() => document.getElementById('versioniStato').textContent.startsWith('Lette'));
    const righe = await page.$$eval('table[aria-label^="Servizi mail"] tbody tr', tr => tr.map(r => r.cells[0].textContent.trim()));
    vero('sette righe, con MySQL e Redis: ' + righe.join(' | '), righe.length === 7 && righe[2] === 'MySQL (Database)' && righe[4] === 'Redis (dati di Rspamd)');
    const pf = await page.textContent('#ver-postfix');
    vero('Postfix: 3.10.4, il pacchetto e "da riavviare" con la nota', pf.includes('3.10.4') && pf.includes('pacchetto postfix-mysql-3.10.4,1')
        && pf.includes('da riavviare') && pf.includes('28/09/2026 08:15'));
    vero('la fonte nel title della versione', await page.getAttribute('#ver-postfix strong', 'title') === 'Letta con: /usr/local/sbin/postconf -h mail_version');
    const my = await page.textContent('#ver-mysql');
    vero('MySQL: 8.0.42 (in esecuzione), da riavviare perche\' il pacchetto e\' la 8.0.43', my.includes('8.0.42') && my.includes('(in esecuzione)')
        && my.includes('da riavviare') && my.includes('quella installata la 8.0.43'));
    vero('ClamAV: motore e firme', (await page.textContent('#ver-clamav')).includes('firme 27780 del 02/10/2026 08:24'));
    vero('Redis non installato', (await page.textContent('#ver-redis')).trim() === 'non installato');
    vero('stato di Redis: Fermo; di MySQL: Attivo', (await page.textContent('#redis-status')) === 'Fermo' && (await page.textContent('#mysql-status')) === 'Attivo');
    const iniettato = await page.evaluate(() => ({ img: document.querySelectorAll('#ver-rspamd img').length, flag: window.iniettato }));
    vero('una versione con dentro HTML resta testo: nessun <img>, nessuno script', iniettato.img === 0 && iniettato.flag === undefined
        && (await page.textContent('#ver-rspamd strong')).startsWith('<img'));
    const stato = await page.textContent('#versioniStato');
    vero('riepilogo: ora della lettura e quanti da riavviare — ' + stato, stato.startsWith('Lette dal server alle 14:00:05.') && stato.includes('3 programmi vanno riavviati'));
    vero('e il ramo dei pacchetti, con il collegamento alla scheda per cambiarlo', stato.includes('Pacchetti dal ramo quarterly.')
        && await page.getAttribute('#versioniStato a', 'href') === '/updates#ramo');

    console.log('\n== Altro software ==');
    const altro = await page.$$eval('#altroSoftware tr', tr => tr.map(r => [...r.cells].map(c => c.textContent.trim())));
    vero('una riga per programma: ' + altro.map(r => r[0]).join(', '), altro.length === 7 && altro[0][0] === 'FreeBSD' && altro[5][0] === 'Java');
    vero('FreeBSD: userland, kernel in esecuzione, riavvio del server', altro[0][2].includes('15.0-RELEASE-p3') && altro[0][2].includes('kernel in esecuzione 15.0-RELEASE-p2')
        && altro[0][2].includes('serve un riavvio del server'));
    vero('a cosa serve: nginx', altro[2][1].startsWith('Web server'));
    vero('Pigeonhole non installato', altro[4][2] === 'non installato');
    vero("l'avviso e' rosso, la nota sul riavvio gialla", await page.locator('#altroSoftware .testo-rischio').count() === 1
        && await page.locator('#altroSoftware .testo-avviso').count() === 1);
    vero('ogni cella ha la sua etichetta per il telefono', await page.locator('#altroSoftware td:not([data-label])').count() === 0);
    if (foto) await page.screenshot({ path: path.join(foto, 'home-versioni.png'), fullPage: true });

    console.log('\n== Comandi: nomi, conferme, CSRF ==');
    vero('i pulsanti hanno un nome: Avvia/Riavvia/Ferma Postfix, Ferma la webmail',
        await page.locator('button[aria-label="Avvia Postfix"]').count() === 1 && await page.locator('button[aria-label="Riavvia Postfix"]').count() === 1
        && await page.locator('button[aria-label="Ferma Postfix"]').count() === 1 && await page.locator('button[aria-label="Ferma la webmail"]').count() === 1);
    let domanda = '';
    page.once('dialog', d => { domanda = d.message(); d.dismiss(); });
    const prima = richieste.length;
    await page.click('button[aria-label="Ferma Postfix"]');
    await page.waitForTimeout(300);
    vero('Ferma Postfix: chiede, e dice cosa succede — ' + domanda, domanda.startsWith('Fermare Postfix?') && domanda.includes('smette di ricevere'));
    vero('annullato: nessuna richiesta', !richieste.slice(prima).some(r => r.percorso === '/api/service'));
    const dialoghi = [];
    page.on('dialog', d => { dialoghi.push(d.message()); d.accept(); });
    await page.click('button[aria-label="Ferma Postfix"]');
    await page.waitForFunction(() => true);
    await page.waitForTimeout(500);
    const post = richieste.find(r => r.percorso === '/api/service');
    vero('confermato: POST con servizio, azione e token CSRF', post && post.corpo.service === 'postfix' && post.corpo.action === 'stop'
        && post.corpo.csrf_token === 'csrf-prova');
    vero('dopo il comando si rileggono le versioni subito (?fresco=1)', richieste.some(r => r.percorso === '/api/versioni?fresco=1'));
    dialoghi.length = 0;
    await page.click('button[aria-label="Riavvia Postfix"]');
    await page.waitForTimeout(400);
    vero('Riavvia Postfix: nessuna domanda, solo l\'esito', dialoghi.length === 1 && dialoghi[0] === 'Operazione completata');
    dialoghi.length = 0;
    await page.click('button[aria-label="Riavvia MySQL"]');
    await page.waitForTimeout(400);
    vero('Riavvia MySQL: chiede prima — ' + dialoghi[0], dialoghi.length === 2 && dialoghi[0].startsWith('Riavviare MySQL?'));
    const mysql = richieste.filter(r => r.percorso === '/api/service').pop();
    vero('e manda mysql-server', mysql.corpo.service === 'mysql-server' && mysql.corpo.action === 'restart');
    const n = richieste.filter(r => r.percorso === '/api/versioni?fresco=1').length;
    await page.click('#versioniRileggi');
    await page.waitForFunction(k => true, n);
    await page.waitForTimeout(300);
    vero('"Rileggi le versioni" chiede una lettura fresca', richieste.filter(r => r.percorso === '/api/versioni?fresco=1').length === n + 1);

    console.log('\n== Tema scuro e telefono ==');
    await page.evaluate(() => document.documentElement.setAttribute('data-theme', 'dark'));
    await page.waitForTimeout(600);   // il cambio di tema ha una transizione
    if (foto) await page.screenshot({ path: path.join(foto, 'home-versioni-scuro.png'), fullPage: true });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.evaluate(() => document.documentElement.setAttribute('data-theme', 'light'));
    await page.waitForTimeout(300);
    const largo = await page.evaluate(() => document.documentElement.scrollWidth);
    vero('sul telefono la pagina non scorre di lato: ' + largo + 'px', largo <= 390);
    vero('sul telefono le tabelle diventano schede (intestazioni nascoste)',
        await page.$eval('table[aria-label^="Servizi mail"] thead', t => getComputedStyle(t).display) === 'none');
    if (foto) {
        await page.locator('table[aria-label^="Servizi mail"]').scrollIntoViewIfNeeded();
        await page.screenshot({ path: path.join(foto, 'home-versioni-telefono.png') });
    }

    vero('nessun errore nella pagina' + (errori.length ? ': ' + errori.join(' | ') : ''), errori.length === 0);
    await browser.close();
    console.log('\n' + (falliti === 0 ? 'TUTTO VERDE' : falliti + ' CONTROLLI FALLITI'));
    process.exit(falliti ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
