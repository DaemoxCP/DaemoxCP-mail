// La scheda "Pacchetti" della pagina Aggiornamenti in Chromium, con il server simulato: le letture
// vere (pkg version, pkg query, pkg audit) le prova PackagePlanTest. Qui si controlla che la scheda
// si legga da sola, che ogni riga dica versione, vulnerabilita' e blocco come testo, che il pulsante
// Aggiorna apra la finestra con il piano esatto e chieda il nome del pacchetto prima di partire, che
// segua il lavoro fino all'esito, che Blocca/Sblocca mandino il nome giusto, che il JDK del pannello
// rimandi alla sua procedura e che l'intestazione di una vulnerabilita' dica lo stesso verdict del
// dettaglio (era "l'aggiornamento la corregge" sopra un "l'aggiornamento non basta").
//
// Uso (dalla radice del progetto, dopo mvn package):
//   D=$(mktemp -d) && javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/content/PageGenerator.java \
//     && java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.content.PageGenerator $D >/dev/null
//   NODE_PATH=$(npm root -g) node tests/packages-browser-test.js $D [cartella-per-le-foto]
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
let giri = 0, letture = 0;

const VULN_NGINX = { verdict: 'si-risolve-aggiornando', installata: '1.30.4,3', catalogo: '1.30.5_1,3', firstFixed: '1.30.5,3',
    spiegazione: 'Si: aggiornare alla 1.30.5_1,3, che il tuo catalogo offre, corregge il problema.',
    problemi: [{ descrizione: 'nginx -- buffer overflow <img src=x onerror="window.iniettato=1">', cve: ['CVE-2026-90439'],
                 url: 'https://vuxml.FreeBSD.org/freebsd/7dc8fd4b.html' }] };
const VULN_EXPAT = { verdict: 'aggiornamento-non-basta', installata: '2.8.1', catalogo: '2.8.4', firstFixed: '2.8.5',
    spiegazione: 'Il catalogo offre 2.8.4, ma VuXML la considera ancora vulnerabile. La fix e\' dalla 2.8.5.',
    problemi: [{ descrizione: 'libexpat -- Improper Handling of Unicode Encoding', cve: ['CVE-2026-93990'], url: 'https://vuxml.FreeBSD.org/freebsd/7fed71c4.html' }] };

function quadro() {
    return { success: true,
        summary: { updates: 7, stackUpdates: 4, vulnerable: 2, fixable: 1, locked: 3, stackUnlocked: 1, panelRestart: false },
        packages: [
            { name: 'nginx', installed: '1.30.4,3', available: '1.30.5_1,3', update: true, locked: true, stack: true, role: 'Web server della webmail',
              majorJump: false, canUpdate: true, whyNot: '', vuln: VULN_NGINX },
            { name: 'dovecot-mysql', installed: '2.3.21.1_3', available: '2.4.2', update: true, locked: true, stack: true, role: 'Componente di Dovecot',
              majorJump: true, canUpdate: false, whyNot: 'Dovecot 2.4 riscrive la configurazione: aspetta la procedura dedicata.',
              advisory: { level: 'attendi', text: 'Dovecot 2.4 riscrive la configurazione: aspetta la procedura dedicata.' } },
            { name: 'openjdk25', installed: '25.0.3+9.f.1', available: '25.0.4+7.f.1_1', update: true, locked: true, stack: true, role: 'Runtime Java',
              inUse: 'il pannello gira su questo', panelRuntime: true, javaFlow: true, canUpdate: false,
              whyNot: 'Il pannello gira su questo Java: si aggiorna con la sua procedura.' },
            { name: 'clamav', installed: '1.5.4_1,1', available: '', update: false, locked: false, stack: true, role: 'Antivirus', canUpdate: false, whyNot: '' },
            { name: 'expat', installed: '2.8.1', available: '2.8.4', update: true, locked: false, stack: false, role: '', canUpdate: true, whyNot: '', vuln: VULN_EXPAT },
        ],
        others: [{ name: 'curl', installed: '8.20.0', available: '8.22.0' }, { name: 'pcre2', installed: '10.47_1', available: '10.49' }] };
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
    if (p.startsWith('/i18n/')) return route.fulfill({ status: 200, contentType: 'application/javascript', body: fs.readFileSync(path.join(pagine, p)) });
    if (p.startsWith('/vendor/') || p.startsWith('/fa/')) {
        const f = path.join(risorse, p);
        if (!fs.existsSync(f)) return route.fulfill({ status: 404, body: '' });
        const tipo = p.endsWith('.css') ? 'text/css' : p.endsWith('.js') ? 'application/javascript' : p.endsWith('.woff2') ? 'font/woff2' : 'application/octet-stream';
        return route.fulfill({ status: 200, contentType: tipo, body: fs.readFileSync(f) });
    }
    const corpo = req.postData() ? JSON.parse(req.postData()) : null;
    richieste.push({ metodo: req.method(), percorso: p, corpo });
    if (p !== '/api/updates' || !corpo) return json(route, { success: true });
    switch (corpo.action) {
        case 'packages_overview': letture++; return json(route, quadro());
        case 'packages_lock': return json(route, { success: true, changed: 1, output: '  ' + corpo.package + ': ' + (corpo.lock ? 'bloccato' : 'sbloccato') + '\n' });
        case 'package_preflight': return json(route, { success: true, name: corpo.package, current: '1.30.4,3', available: '1.30.5_1,3',
            signature: '0123456789abcdef', blocked: false, canProceed: true, cve: ['CVE-2026-90439'],
            services: [{ name: 'nginx', running: true }],
            checks: [{ level: 'ok', label: 'Pacchetto installato', detail: 'nginx 1.30.4,3' },
                     { level: 'verifica', label: 'Avvertenza', detail: 'Ricontrolla i virtual host dopo il riavvio.' }],
            piano: { measured: true, unlockedPackages: ['nginx'], comando: 'pkg upgrade -n -U nginx', onBackup: true,
                     changes: [{ tipo: 'aggiorna', nome: 'nginx', da: '1.30.4,3', a: '1.30.5_1,3', motivo: '', repo: 'FreeBSD-ports' }], blockers: [] } });
        case 'package_update':
            giri = 0;
            return json(route, { success: true, jobId: 'guid-1', async: true });
        case 'job_status':
            giri++;
            if (giri < 2) return json(route, { success: true, job: { status: 'running', percent: 50, consoleLog: '[3/6] Aggiornamento...\n' } });
            return json(route, { success: true, job: { status: 'completed', percent: 100, elapsedSeconds: 12, errorMessage: '',
                consoleLog: '[3/6] Aggiornamento...\n[6/6] Riblocco...\n=== nginx 1.30.5_1,3 in servizio ===\n' } });
        case 'updates_status': return json(route, { success: true, dryRun: 'Your packages are up to date.', upToDate: false,
            vulnerable: [
                { name: 'expat', role: '', locked: false, fixedByUpgrade: true, aggiornamentoDisponibile: true, cve: ['CVE-2026-93990'], fix: VULN_EXPAT },
                { name: 'nginx', role: 'Web server della webmail', locked: true, fixedByUpgrade: false, aggiornamentoDisponibile: true, cve: ['CVE-2026-90439'], fix: VULN_NGINX },
            ], lockedUpdates: [], coinvolti: [] });
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
    await page.waitForSelector('#pk-body table');
    vero('una lettura all\'apertura della pagina', letture === 1);
    const testa = await page.textContent('#pk-body');
    vero('riepilogo: aggiornamenti, vulnerabili, correggibili, lockedPackages', testa.includes('7 aggiornamenti disponibili') && testa.includes('2 pacchetti vulnerabili')
        && testa.includes('1 si corregge subito') && testa.includes('3 lockedPackages'));
    vero('avviso sul pacchetto dello stack non bloccato, con il pulsante per bloccarli', testa.includes('1 pacchetto dello stack di posta non è bloccato')
        && await page.locator('#pk-body .alert button', { hasText: 'Blocca tutti i pacchetti dello stack di posta' }).count() === 1);
    const righe = await page.$$eval('#pk-body tbody tr:not([hidden])', tr => tr.map(r => r.cells[0].querySelector('code').textContent));
    vero('una riga per pacchetto: ' + righe.join(', '), righe.join(',') === 'nginx,dovecot-mysql,openjdk25,clamav,expat');
    const nginx = await page.textContent('#pk-body tbody tr:nth-child(1)');
    vero('nginx: versioni, "l\'aggiornamento la corregge", bloccato', nginx.includes('1.30.4,3') && nginx.includes('1.30.5_1,3')
        && nginx.includes("vulnerabile · l'aggiornamento la corregge") && nginx.includes('bloccato'));
    vero('nginx bloccato ha comunque il pulsante Aggiorna (sblocca, aggiorna, riblocca) e Sblocca',
        await page.locator('#pk-body button[data-pkg="nginx"]', { hasText: 'Aggiorna a 1.30.5_1,3' }).count() === 1
        && await page.locator('#pk-body button[data-pkg="nginx"]', { hasText: 'Sblocca' }).count() === 1);
    vero('dovecot con l\'avvertenza "attendi": niente Aggiorna, solo "trattenuto"',
        await page.locator('#pk-body button[data-pkg="dovecot-mysql"]', { hasText: 'Aggiorna' }).count() === 0
        && (await page.textContent('#pk-body tbody tr:nth-of-type(3)')).includes('trattenuto'));
    vero('il JDK del pannello rimanda alla procedura di Java', await page.locator('#pk-body button', { hasText: 'Procedura di aggiornamento di Java' }).count() === 1);
    vero('clamav aggiornato e non bloccato: pulsante Blocca', (await page.textContent('#pk-body tbody tr:has(code:text-is("clamav"))')).includes('aggiornato')
        && await page.locator('#pk-body button[data-pkg="clamav"]', { hasText: 'Blocca' }).count() === 1);
    vero('expat: "l\'aggiornamento non basta"', (await page.textContent('#pk-body tbody tr:has(code:text-is("expat"))')).includes("l'aggiornamento non basta"));
    vero('gli altri pacchetti, in fondo e chiusi', (await page.textContent('#pk-body details summary')).includes('2 altri pacchetti hanno un aggiornamento'));
    await page.click('#pk-body tbody tr:nth-child(1) button.btn-link');
    const det = await page.textContent('#pk-det-0');
    vero('dettagli di nginx: spiegazione e CVE con il collegamento a VuXML', det.includes('corregge il problema') && det.includes('CVE-2026-90439')
        && await page.getAttribute('#pk-det-0 a', 'href') === 'https://vuxml.FreeBSD.org/freebsd/7dc8fd4b.html');
    vero('la descrizione con dentro HTML resta testo', await page.locator('#pk-body img').count() === 0 && await page.evaluate(() => window.iniettato) === undefined);
    vero('ogni cella ha la sua etichetta per il telefono', await page.locator('#pk-body tbody tr:not([id]) td:not([data-label]):not(.text-end)').count() === 0);
    if (foto) await page.locator('#pacchetti').screenshot({ path: path.join(foto, 'pacchetti-scheda.png') });

    console.log('\n== Blocca e sblocca un pacchetto ==');
    let prima = richieste.length;
    await page.click('#pk-body button[data-pkg="clamav"]:has-text("Blocca")');
    await page.waitForFunction(() => document.getElementById('pk-result').textContent.includes('clamav'));
    const lock = richieste.slice(prima).find(r => r.corpo && r.corpo.action === 'packages_lock');
    vero('Blocca clamav: manda nome, lock=true e token CSRF', lock && lock.corpo.package === 'clamav' && lock.corpo.lock === true && lock.corpo.csrf_token === 'csrf-prova');
    await page.waitForSelector('#pk-body table');
    vero('e la tabella si rilegge', letture >= 2);

    console.log('\n== Aggiornare un pacchetto: la finestra ==');
    await page.click('#pk-body button[data-pkg="nginx"]:has-text("Aggiorna")');
    await page.waitForSelector('#pkUpdConfirm:not([hidden])');
    const fin = await page.textContent('#pkUpdModal .modal-content');
    vero('titolo, versioni e CVE chiuse', fin.includes('Aggiorna nginx') && fin.includes('1.30.4,3') && fin.includes('CVE-2026-90439'));
    vero('i passi in chiaro: sblocco, aggiornamento, riavvio di nginx, riblocco', fin.includes('Sblocco nginx per la durata') && fin.includes('Riavvio nginx')
        && fin.includes('Blocco di nuovo i pacchetti'));
    vero('il piano esatto di pkg e l\'avvertenza', fin.includes('pkg upgrade -n -U nginx') && fin.includes('Ricontrolla i virtual host'));
    vero('il pulsante resta spento finche\' il nome non e\' giusto', await page.isDisabled('#pkUpdGo'));
    await page.fill('#pkUpdName', 'ngin');
    vero('con un nome sbagliato resta spento', await page.isDisabled('#pkUpdGo'));
    await page.fill('#pkUpdName', 'nginx');
    vero('con il nome giusto si accende', !(await page.isDisabled('#pkUpdGo')));
    prima = richieste.length;
    await page.click('#pkUpdGo');
    await page.waitForSelector('#pkUpdResult .alert-success', { timeout: 15000 });
    const upd = richieste.slice(prima).find(r => r.corpo && r.corpo.action === 'package_update');
    vero('package_update con pacchetto, conferma, fingerprint e CSRF', upd && upd.corpo.package === 'nginx' && upd.corpo.confirm === 'nginx'
        && upd.corpo.signature === '0123456789abcdef' && upd.corpo.csrf_token === 'csrf-prova');
    vero('il registro del lavoro e l\'esito', (await page.textContent('#pkUpdLog')).includes('in servizio')
        && (await page.textContent('#pkUpdResult')).includes('nginx è aggiornato'));
    if (foto) await page.locator('#pkUpdModal .modal-content').screenshot({ path: path.join(foto, 'pacchetti-finestra.png') });
    await page.click('#pkUpdModal .btn-close');
    await page.waitForSelector('#pkUpdModal', { state: 'hidden' });

    console.log('\n== Vulnerabilita\': l\'intestazione dice il verdict ==');
    await page.click('#aggiornamenti button:has-text("Verifica")');
    await page.waitForSelector('#upd-status li');
    const lis = await page.$$eval('#upd-status li', l => l.map(x => x.textContent));
    vero('expat: "non basta" nell\'intestazione, non "la corregge"', lis[0].includes("l'aggiornamento non basta") && !lis[0].includes("l'aggiornamento la corregge"));
    vero('nginx bloccato: "la corregge", il blocco a parte e il pulsante Aggiorna', lis[1].includes("l'aggiornamento la corregge") && lis[1].includes('bloccato')
        && await page.locator('#upd-status li button[data-pkg="nginx"]', { hasText: 'Aggiorna a 1.30.5_1,3' }).count() === 1);

    vero('nessun errore nella pagina' + (errori.length ? ': ' + errori.join(' | ') : ''), errori.length === 0);
    await browser.close();
    console.log(falliti === 0 ? '\nTUTTO VERDE' : '\n' + falliti + ' CONTROLLI FALLITI');
    process.exit(falliti === 0 ? 0 : 1);
})();
