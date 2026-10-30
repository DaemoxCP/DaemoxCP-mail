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
let rounds = 0, readings = 0;

const VULN_NGINX = { verdict: 'si-risolve-aggiornando', installedVersion: '1.30.4,3', catalog: '1.30.5_1,3', firstFixed: '1.30.5,3',
    explanation: 'Si: aggiornare alla 1.30.5_1,3, che il tuo catalogo offre, corregge il problema.',
    issues: [{ description: 'nginx -- buffer overflow <img src=x onerror="window.injectedRan=1">', cve: ['CVE-2026-90439'],
                 url: 'https://vuxml.FreeBSD.org/freebsd/7dc8fd4b.html' }] };
const VULN_EXPAT = { verdict: 'aggiornamento-non-basta', installedVersion: '2.8.1', catalog: '2.8.4', firstFixed: '2.8.5',
    explanation: 'Il catalogo offre 2.8.4, ma VuXML la considera ancora vulnerabile. La fix e\' dalla 2.8.5.',
    issues: [{ description: 'libexpat -- Improper Handling of Unicode Encoding', cve: ['CVE-2026-93990'], url: 'https://vuxml.FreeBSD.org/freebsd/7fed71c4.html' }] };

function overview() {
    return { success: true,
        summary: { updates: 7, stackUpdates: 4, vulnerable: 2, fixable: 1, locked: 3, stackUnlocked: 1, panelRestart: false },
        packages: [
            { name: 'nginx', installed: '1.30.4,3', available: '1.30.5_1,3', update: true, locked: true, stack: true, role: 'Web server della webmail',
              majorJump: false, canUpdate: true, whyNot: '', vuln: VULN_NGINX },
            { name: 'dovecot-mysql', installed: '2.3.21.1_3', available: '2.4.2', update: true, locked: true, stack: true, role: 'Componente di Dovecot',
              majorJump: true, canUpdate: false, whyNot: 'Dovecot 2.4 riscrive la configurazione: aspetta la procedura dedicata.',
              advisory: { level: 'wait', text: 'Dovecot 2.4 riscrive la configurazione: aspetta la procedura dedicata.' } },
            { name: 'openjdk25', installed: '25.0.3+9.f.1', available: '25.0.4+7.f.1_1', update: true, locked: true, stack: true, role: 'Runtime Java',
              inUse: 'il pannello gira su questo', panelRuntime: true, javaFlow: true, canUpdate: false,
              whyNot: 'Il pannello gira su questo Java: si aggiorna con la sua procedura.' },
            { name: 'clamav', installed: '1.5.4_1,1', available: '', update: false, locked: false, stack: true, role: 'Antivirus', canUpdate: false, whyNot: '' },
            { name: 'expat', installed: '2.8.1', available: '2.8.4', update: true, locked: false, stack: false, role: '', canUpdate: true, whyNot: '', vuln: VULN_EXPAT },
        ],
        others: [{ name: 'curl', installed: '8.20.0', available: '8.22.0' }, { name: 'pcre2', installed: '10.47_1', available: '10.49' }] };
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
        case 'packages_overview': readings++; return json(route, overview());
        case 'packages_lock': return json(route, { success: true, changed: 1, output: '  ' + bodyText.package + ': ' + (bodyText.lock ? 'bloccato' : 'sbloccato') + '\n' });
        case 'package_preflight': return json(route, { success: true, name: bodyText.package, current: '1.30.4,3', available: '1.30.5_1,3',
            signature: '0123456789abcdef', blocked: false, canProceed: true, cve: ['CVE-2026-90439'],
            services: [{ name: 'nginx', running: true }],
            checks: [{ level: 'ok', label: 'Pacchetto installato', detail: 'nginx 1.30.4,3' },
                     { level: 'review', label: 'Avvertenza', detail: 'Ricontrolla i virtual host dopo il riavvio.' }],
            plan: { measured: true, unlockedPackages: ['nginx'], command: 'pkg upgrade -n -U nginx', onBackup: true,
                     changes: [{ type: 'upgrade', name: 'nginx', from: '1.30.4,3', to: '1.30.5_1,3', reason: '', repo: 'FreeBSD-ports' }], blockers: [] } });
        case 'package_update':
            rounds = 0;
            return json(route, { success: true, jobId: 'guid-1', async: true });
        case 'job_status':
            rounds++;
            if (rounds < 2) return json(route, { success: true, job: { status: 'running', percent: 50, consoleLog: '[3/6] Aggiornamento...\n' } });
            return json(route, { success: true, job: { status: 'completed', percent: 100, elapsedSeconds: 12, errorMessage: '',
                consoleLog: '[3/6] Aggiornamento...\n[6/6] Riblocco...\n=== nginx 1.30.5_1,3 in servizio ===\n' } });
        case 'updates_status': return json(route, { success: true, dryRun: 'Your packages are up to date.', upToDate: false,
            vulnerable: [
                { name: 'expat', role: '', locked: false, fixedByUpgrade: true, updateAvailable: true, cve: ['CVE-2026-93990'], fix: VULN_EXPAT },
                { name: 'nginx', role: 'Web server della webmail', locked: true, fixedByUpgrade: false, updateAvailable: true, cve: ['CVE-2026-90439'], fix: VULN_NGINX },
            ], lockedUpdates: [], affectedMailPackages: [] });
        default: return json(route, { success: true });
    }
}

(async () => {
    const browser = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium-1194/chrome-linux/chrome' }).catch(() => chromium.launch());
    const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
    await ctx.route('**/*', served);
    const page = await ctx.newPage();
    const errorList = [];
    page.on('pageerror', e => errorList.push(String(e)));
    page.on('console', m => { if (m.type() === 'error') errorList.push(m.text()); });

    console.log('\n== La scheda si legge da sola ==');
    await page.goto(BASE + '/updates');
    await page.waitForSelector('#pk-body table');
    real('una lettura all\'apertura della pagina', readings === 1);
    const head = await page.textContent('#pk-body');
    real('riepilogo: aggiornamenti, vulnerabili, correggibili, bloccati', head.includes('7 aggiornamenti disponibili') && head.includes('2 pacchetti vulnerabili')
        && head.includes('1 si corregge subito') && head.includes('3 bloccati'));
    real('avviso sul pacchetto dello stack non bloccato, con il pulsante per bloccarli', head.includes('1 pacchetto dello stack di posta non è bloccato')
        && await page.locator('#pk-body .alert button', { hasText: 'Blocca tutti i pacchetti dello stack di posta' }).count() === 1);
    const lineItems = await page.$$eval('#pk-body tbody tr:not([hidden])', tr => tr.map(r => r.cells[0].querySelector('code').textContent));
    real('una riga per pacchetto: ' + lineItems.join(', '), lineItems.join(',') === 'nginx,dovecot-mysql,openjdk25,clamav,expat');
    const nginx = await page.textContent('#pk-body tbody tr:nth-child(1)');
    real('nginx: versioni, "l\'aggiornamento la corregge", bloccato', nginx.includes('1.30.4,3') && nginx.includes('1.30.5_1,3')
        && nginx.includes("vulnerabile · l'aggiornamento la corregge") && nginx.includes('bloccato'));
    real('nginx bloccato ha comunque il pulsante Aggiorna (sblocca, aggiorna, riblocca) e Sblocca',
        await page.locator('#pk-body button[data-pkg="nginx"]', { hasText: 'Aggiorna a 1.30.5_1,3' }).count() === 1
        && await page.locator('#pk-body button[data-pkg="nginx"]', { hasText: 'Sblocca' }).count() === 1);
    real('dovecot con l\'avvertenza "attendi": niente Aggiorna, solo "trattenuto"',
        await page.locator('#pk-body button[data-pkg="dovecot-mysql"]', { hasText: 'Aggiorna' }).count() === 0
        && (await page.textContent('#pk-body tbody tr:nth-of-type(3)')).includes('trattenuto'));
    real('il JDK del pannello rimanda alla procedura di Java', await page.locator('#pk-body button', { hasText: 'Procedura di aggiornamento di Java' }).count() === 1);
    real('clamav aggiornato e non bloccato: pulsante Blocca', (await page.textContent('#pk-body tbody tr:has(code:text-is("clamav"))')).includes('aggiornato')
        && await page.locator('#pk-body button[data-pkg="clamav"]', { hasText: 'Blocca' }).count() === 1);
    real('expat: "l\'aggiornamento non basta"', (await page.textContent('#pk-body tbody tr:has(code:text-is("expat"))')).includes("l'aggiornamento non basta"));
    real('gli altri pacchetti, in fondo e chiusi', (await page.textContent('#pk-body details summary')).includes('2 altri pacchetti hanno un aggiornamento'));
    await page.click('#pk-body tbody tr:nth-child(1) button.btn-link');
    const detailInfo = await page.textContent('#pk-det-0');
    real('dettagli di nginx: spiegazione e CVE con il collegamento a VuXML', detailInfo.includes('corregge il problema') && detailInfo.includes('CVE-2026-90439')
        && await page.getAttribute('#pk-det-0 a', 'href') === 'https://vuxml.FreeBSD.org/freebsd/7dc8fd4b.html');
    real('la descrizione con dentro HTML resta testo', await page.locator('#pk-body img').count() === 0 && await page.evaluate(() => window.injectedRan) === undefined);
    real('ogni cella ha la sua etichetta per il telefono', await page.locator('#pk-body tbody tr:not([id]) td:not([data-label]):not(.text-end)').count() === 0);
    if (photos) await page.locator('#pacchetti').screenshot({ path: path.join(photos, 'pacchetti-scheda.png') });

    console.log('\n== Blocca e sblocca un pacchetto ==');
    let beforeValue = requests.length;
    await page.click('#pk-body button[data-pkg="clamav"]:has-text("Blocca")');
    await page.waitForFunction(() => document.getElementById('pk-result').textContent.includes('clamav'));
    const lock = requests.slice(beforeValue).find(r => r.body && r.body.action === 'packages_lock');
    real('Blocca clamav: manda nome, lock=true e token CSRF', lock && lock.body.package === 'clamav' && lock.body.lock === true && lock.body.csrf_token === 'csrf-prova');
    await page.waitForSelector('#pk-body table');
    real('e la tabella si rilegge', readings >= 2);

    console.log('\n== Aggiornare un pacchetto: la finestra ==');
    await page.click('#pk-body button[data-pkg="nginx"]:has-text("Aggiorna")');
    await page.waitForSelector('#pkUpdConfirm:not([hidden])');
    const finalText = await page.textContent('#pkUpdModal .modal-content');
    real('titolo, versioni e CVE chiuse', finalText.includes('Aggiorna nginx') && finalText.includes('1.30.4,3') && finalText.includes('CVE-2026-90439'));
    real('i passi in chiaro: sblocco, aggiornamento, riavvio di nginx, riblocco', finalText.includes('Sblocco nginx per la durata') && finalText.includes('Riavvio nginx')
        && finalText.includes('Blocco di nuovo i pacchetti'));
    real('il piano esatto di pkg e l\'avvertenza', finalText.includes('pkg upgrade -n -U nginx') && finalText.includes('Ricontrolla i virtual host'));
    real('il pulsante resta spento finche\' il nome non e\' giusto', await page.isDisabled('#pkUpdGo'));
    await page.fill('#pkUpdName', 'ngin');
    real('con un nome sbagliato resta spento', await page.isDisabled('#pkUpdGo'));
    await page.fill('#pkUpdName', 'nginx');
    real('con il nome giusto si accende', !(await page.isDisabled('#pkUpdGo')));
    beforeValue = requests.length;
    await page.click('#pkUpdGo');
    await page.waitForSelector('#pkUpdResult .alert-success', { timeout: 15000 });
    const upd = requests.slice(beforeValue).find(r => r.body && r.body.action === 'package_update');
    real('package_update con pacchetto, conferma, fingerprint e CSRF', upd && upd.body.package === 'nginx' && upd.body.confirm === 'nginx'
        && upd.body.signature === '0123456789abcdef' && upd.body.csrf_token === 'csrf-prova');
    real('il registro del lavoro e l\'esito', (await page.textContent('#pkUpdLog')).includes('in servizio')
        && (await page.textContent('#pkUpdResult')).includes('nginx è aggiornato'));
    if (photos) await page.locator('#pkUpdModal .modal-content').screenshot({ path: path.join(photos, 'pacchetti-finestra.png') });
    await page.click('#pkUpdModal .btn-close');
    await page.waitForSelector('#pkUpdModal', { state: 'hidden' });

    console.log('\n== Vulnerabilita\': l\'intestazione dice il verdict ==');
    await page.click('#aggiornamenti button:has-text("Verifica")');
    await page.waitForSelector('#upd-status li');
    const lis = await page.$$eval('#upd-status li', l => l.map(x => x.textContent));
    real('expat: "non basta" nell\'intestazione, non "la corregge"', lis[0].includes("l'aggiornamento non basta") && !lis[0].includes("l'aggiornamento la corregge"));
    real('nginx bloccato: "la corregge", il blocco a parte e il pulsante Aggiorna', lis[1].includes("l'aggiornamento la corregge") && lis[1].includes('bloccato')
        && await page.locator('#upd-status li button[data-pkg="nginx"]', { hasText: 'Aggiorna a 1.30.5_1,3' }).count() === 1);

    real('nessun errore nella pagina' + (errorList.length ? ': ' + errorList.join(' | ') : ''), errorList.length === 0);
    await browser.close();
    console.log(failedOnes === 0 ? '\nTUTTO VERDE' : '\n' + failedOnes + ' CONTROLLI FALLITI');
    process.exit(failedOnes === 0 ? 0 : 1);
})();
