// Every translated page of the mail panel in Chromium, IN ENGLISH, with a simulated server that
// answers each API with a small, plausible reply.
//
// For each page: the page loads and its scripts run without errors, <html lang="en">, and the
// visible text (after the scripts have filled the page in) has no Italian left: a list of common
// Italian words, as whole words, in the text a person reads, and in the title, aria-label and
// placeholder attributes. The replies of the simulated server are in English, so whatever Italian
// shows up comes from the page itself. One exception on purpose: the firewall's country catalog and
// presets come in Italian, as the real server sends them, and the page must show them in English.
//
// Usage (from the project root, after mvn package):
//   D=$(mktemp -d) && javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/content/PageGenerator.java \
//     && java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.content.PageGenerator $D >/dev/null
//   NODE_PATH=$(npm root -g) node tests/english-pages-browser-test.js $D [screenshot-folder]
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const pages = process.argv[2];
const shots = process.argv[3];
const resources = path.join(__dirname, '..', 'src', 'main', 'resources');
const BASE = 'http://panel.test';
let failed = 0;
function check(what, ok) {
    console.log((ok ? '  OK   ' : '  FAILED ') + what);
    if (!ok) failed++;
}

// Whole Italian words that do not exist in English (or are rare enough not to clash).
const ITALIAN = ['il', 'lo', 'gli', 'della', 'delle', 'degli', 'dello', 'nel', 'nella', 'alla', 'dal', 'dalla',
    'non', 'sono', 'che', 'una', 'con', 'questo', 'questa', 'quello', 'ancora', 'prima', 'dopo',
    'errore', 'nessun', 'nessuna', 'caricamento', 'seleziona', 'scegli', 'salva', 'annulla', 'chiudi',
    'elimina', 'aggiungi', 'modifica', 'verifica', 'dominio', 'domini', 'casella', 'caselle', 'chiave',
    'giorni', 'oggi', 'ieri', 'tutti', 'tutto', 'anche', 'quando', 'perché', 'già', 'più', 'può', 'è',
    'configurazione', 'credenziali', 'amministratore', 'avvia', 'pacchetti', 'aggiornamento', 'riavvia', 'impostazioni'];
const IT_RE = new RegExp('(^|[^\\p{L}])(' + ITALIAN.join('|') + ')(?=$|[^\\p{L}])', 'iu');

const now = Date.now();
const API = {
    'GET /api/domains': { success: true, domains: [{ id: 1, domain: 'example.com' }] },
    'GET /api/dns': { success: true, mail_hostname: 'mail.example.com', server_ip: '192.0.2.1',
        records: [{ name: '@', type: 'MX', value: 'mail.example.com', valoreCompleto: '10 mail.example.com', required: true,
                    description: 'Where mail for the domain goes', dnsZone: 'example.com', checkType: 'MX' },
                  { name: '_dmarc', type: 'TXT', value: 'v=DMARC1; p=none', required: false, description: 'DMARC', dnsZone: 'example.com', checkType: 'DMARC' }] },
    'POST /api/dns': { success: true, domain: 'example.com', score: 50, all_passed: false,
        checks: [{ type: 'MX', name: 'example.com', passed: true, message: 'MX is right', current_value: '10 mail.example.com' },
                 { type: 'DMARC', name: '_dmarc.example.com', passed: false, message: 'record missing' }] },
    'GET /api/dkim': { success: true, configured: true, selector: 's2026', dns_record_name: 's2026._domainkey.example.com' },
    'POST /api/dkim': { success: true, presets: [{ days: 0, label: 'Off' }, { days: 90, label: 'Every 90 days' }], interval_days: 90,
        last_rotation_at_ms: now - 10 * 86400000, next_rotation_at_ms: now + 80 * 86400000, server_now_ms: now, cloudflare_configured: true,
        auto_activate_after_hours: 24, grace_period_days: 7, avvio_automatico: true, has_dkim: true, events: [], records: [], domini: [] },
    'GET /api/cloudflare': { success: true, accounts: [{ id: 3, label: 'Main', email: 'me@example.com', token_masked: 'abc…xyz' }],
        domains: [{ id: 1, domain: 'example.com', cloudflare_account_id: 3 }], mail_server: { hostname: 'mail.example.com', cloudflare_account_id: 3 } },
    'GET /api/timezone-diag': { alignment: 'OK', os_now_ms: now, jvm_now_ms: now, mysql_now_ms: now, os_offset: '+00:00', os_tz: 'UTC',
        jvm_default_zone: 'UTC', jvm_offset: '+00:00', mysql_now: '2026-10-10 10:00:00', mysql_utc_now: '2026-10-10 10:00:00',
        mysql_session_tz: 'SYSTEM', mysql_global_tz: 'SYSTEM', mysql_system_tz: 'UTC' },
    'POST /api/autodns': { success: true, cloudflare: false, nota: 'This domain has no Cloudflare account.', modo: 'testing',
        politica: 'version: STSv1\nmode: testing', recordTxt: 'v=STSv1; id=20261010', domini: [] },
    'POST /api/autoconfig': { success: true, pronto: true, conf: '/usr/local/etc/nginx/nginx.conf', hostDiPosta: 'mail.example.com',
        nomeCoperto: true, rottaPresente: true, domini: [{ nome: 'autoconfig.example.com', dns: true, certificato: true, prova: { ok: true } }] },
    'GET /api/blacklist_check': { success: true, reports: [] },
    'GET /api/ssl': { certificate_installed: true, lets_encrypt: true, common_name: 'mail.example.com', issuer: "Let's Encrypt R11",
        valid_from: 'Sep 1 2026', expires_at: 'Nov 30 2026', days_until_expiry: 51, algorithm: 'ECDSA', serial: '04AB' },
    'POST /api/ssl': { success: true, enabled: true, threshold_days: 30, last_check_human: '2 hours ago', last_result_html: 'OK',
        last_renewal_human: 'Sep 1 2026', next_check_human: 'in 22 hours' },
    // Fail2ban: the reply depends on the action, in the query (GET) or in the body (POST).
    'GET /api/fail2ban': (q) => ({
        status: { installed: true, running: true, total_banned: 2, total_banned_total: 9, active_jails: ['postfix-sasl'],
            jails: [{ name: 'postfix-sasl', enabled: true, currently_banned: 2, currently_failed: 1, total_banned: 9,
                      porta_dichiarata: true, porte: 'smtp,submission', ban_usa_la_porta: false, log: '/var/log/maillog' }],
            recent_bans: [{ action: 'ban', ip: '192.0.2.7', jail: 'postfix-sasl', timestamp: now - 600000 }] },
        banned: { success: true, banned: [{ ip: '192.0.2.7', jail: 'postfix-sasl' }] },
        live_state_all: { success: true, installed: true, running: true,
            jails: [{ name: 'postfix-sasl', currently_banned: 2, total_banned: 9, currently_failed: 1, total_failed: 30,
                      maxretry: '5', findtime: '600', bantime: '3600', logpath: '/var/log/maillog', filter: 'postfix-sasl',
                      ignoreip: '127.0.0.1/8', banned_ips_raw: '192.0.2.7 198.51.100.9', status_raw: 'Status for the jail: postfix-sasl' }] },
        permaban_list: { success: true, count: 1, permabans: [{ ip: '203.0.113.5', in_runtime: true }, { ip: '203.0.113.6', in_runtime: false }] },
    })[q.get('action')] || { success: true },
    'POST /api/fail2ban': (q, body) => ({
        get_jail_config: { success: true, max_retry: 5, find_time: 600, ban_time: 3600, filter: 'postfix-sasl', ignoreip: ['127.0.0.1/8'] },
    })[body.action] || { success: true },
    'GET /api/fail2ban_health': { success: true, all_ok: false, checks: [
        { ok: true, label: 'Fail2ban installed', status: 'version 1.1.0' },
        { ok: false, label: 'Ban action', status: 'the pf table is missing', impact: 'bans block nothing', fix_description: 'Creates the table', fix_action: 'fix_pf' }] },
    'GET /api/unbound_health': { success: true, all_ok: true, checks: [{ ok: true, label: 'unbound running', status: 'listening on 127.0.0.1' }] },
    'GET /api/clamav_health': { success: true, all_ok: false, checks: [
        { ok: true, label: 'ClamAV installed', status: 'clamav 1.4' },
        { ok: false, label: 'Rspamd uses ClamAV', status: 'antivirus.conf missing', impact: 'mail is not scanned', fix_description: 'Writes antivirus.conf', fix_action: 'configure_rspamd' }] },
    // Firewall: the catalog and the presets come from the server with Italian names, as the real one sends them.
    'GET /api/firewall': { success: true, enabled: true, mode: 'GEO_WHITELIST', apply_geo_to_port25: false,
        geo_countries: ['it', 'de'], whitelist_cidrs: ['203.0.113.10/32'], blacklist_cidrs: [],
        table_sizes: { panel_wl_cidrs: 1, panel_bl_cidrs: 0, panel_geo_wl: 9876, panel_geo_bl: 0 },
        auto_sync: { enabled: true, interval_days: 7, last_check_ms: now - 3600000, last_run_ms: now - 2 * 86400000, stale_countries_count: 1 },
        geo_detail: [{ code: 'it', cidr_count: 5000, freshness: 'FRESH', ago_seconds: 7200 },
                     { code: 'de', cidr_count: 4876, freshness: 'STALE', ago_seconds: 40 * 86400 }],
        country_catalog: [{ code: 'it', name: 'Italia', flag: '🇮🇹', common: true }, { code: 'de', name: 'Germania', flag: '🇩🇪', common: true },
                          { code: 'fr', name: 'Francia', flag: '🇫🇷', common: true }, { code: 'us', name: 'Stati Uniti', flag: '🇺🇸', common: true }],
        preset_groups: [{ id: 'italy', label: 'Solo Italia', icon: '🇮🇹', codes: ['it'], description: 'Solo IP italiani' },
                        { id: 'g7', label: 'G7', icon: '🌐', codes: ['it', 'fr', 'de', 'us'], description: 'Italia, Francia, Germania' }] },
    'GET /api/stats': { success: true, security: { spam_detected: 12 }, imap: { active_users: 3 } },
    'GET /api/logs': { logs: [{ id: 'maillog', description: 'Mail log', exists: true }],
        entries: [{ timestamp: 'Oct 10 10:00:00', process: 'postfix/smtpd', level: 'INFO', message: 'connect from mail.example.org' }] },
    'POST /api/logs': { results: [] },
    'GET /api/system_paths': { success: true, categories: [{ name: 'Postfix', entries: [
        { label: 'main.cf', path: '/usr/local/etc/postfix/main.cf', description: 'Main configuration', exists: true, is_directory: false,
          size: 2048, perms: 'rw-r--r--', modified: '2026-10-10T10:00:00' },
        { label: 'spool', path: '/var/spool/postfix', exists: false }] }] },
    'GET /api/admins': { success: true, admins: [
        { id: 1, username: 'root-admin', role: 'superadmin', email: 'root@example.com', passkeys: 2, is_current: true, created_at: '2026-01-01T10:00:00Z' },
        { id: 2, username: 'helper', role: 'operator', email: '', passkeys: 0, last_login: '2026-10-09T18:00:00Z', created_at: '2026-02-01T10:00:00Z' }] },
    'GET /api/account': { success: true, username: 'root-admin', role: 'superadmin', email: 'root@example.com', passkeysAvailable: true, reauthenticated: false,
        passkeys: [{ id: 4, name: 'Laptop key', created_at: '2026-09-01T10:00:00Z', last_used: '2026-10-09T08:00:00Z' }],
        sessions: [{ id: 7, ip: '203.0.113.5', user_agent: 'Mozilla/5.0 (X11; Linux x86_64) Chrome/140.0', created_at: '2026-10-10T09:00:00Z',
                     last_seen: '2026-10-10T09:30:00Z', current: true },
                   { id: 8, ip: '198.51.100.7', user_agent: 'Mozilla/5.0 (iPhone) Safari/605.1', created_at: '2026-10-09T09:00:00Z',
                     last_seen: '2026-10-09T09:20:00Z', current: false }] },
    'GET /api/hostname': { success: true, consistent: false, sqlite_hostname: 'mail.example.com', mysql_hostname: 'mail.example.com' },
    'GET /api/roundcube-domain': { success: true, domain: 'webmail.example.com', dns_ok: false },
    'POST /api/report': (q, body) => ({
        status: { success: true, mittente: 'panel@example.com', destinatario: 'me@example.com', frequenza: 'settimanale', ora: 7, attivo: true,
                  prossimo: 'Next report: Monday 07:00' },
        identity: { success: true, esiste: false, dominioGestito: true, creabile: true, mittente: 'panel@example.com', nota: 'The address is free.',
                    dominioDelPannelloGestito: true, dominioDelPannello: 'example.com', caselleDisponibili: ['panel@example.com'], dominiGestiti: ['example.com'] },
    })[body.action] || { success: true },
    // Updates: one endpoint, the reply depends on the action in the body.
    'POST /api/updates': (q, body) => ({
        ramo_stato: { success: true, ramo: 'quarterly', spiegazione: 'Quarterly is the default.', changeable: true, verso: ['latest'], panelOwnedFile: false,
                      repository: [{ nome: 'FreeBSD', ruolo: 'packages', ramo: 'quarterly', acceso: true, url: 'pkg+https://pkg.FreeBSD.org/...' }] },
        os_status: { success: true, kernelInstallato: '15.0-RELEASE-p3', uname: '15.0-RELEASE-p3', riavvioNecessario: false, userland: '15.0-RELEASE-p3',
                     arch: 'amd64', fineSupporto: '2026-12-31', noteSupporto: '', fonteSupporto: 'freebsd.org', aggiornabileConFreebsdUpdate: true, giaPronti: 'none' },
        plan: { success: true, daFare: 1, passi: [
            { gruppo: 'fase', lettera: 'A', titolo: 'Lock the stack', stato: 'fatto', situazione: 'Locked.', perche: 'So nothing replaces it.' },
            { gruppo: 'pacchetto', titolo: 'curl', stato: 'dafare', situazione: '8.9 to 8.10', perche: 'Fixes a CVE.', azione: { tipo: 'package_update', package: 'curl' } }],
            senzaRimedio: ['libfoo'] },
        packages_overview: { success: true, summary: { updates: 2, stackUpdates: 1, vulnerable: 1, fixable: 1, locked: 1, stackUnlocked: 1, panelRestart: true },
            packages: [{ name: 'postfix', installed: '3.9', available: '3.10', update: true, locked: true, stack: true, role: 'SMTP', canUpdate: true, whyNot: '',
                         vuln: { verdict: 'aggiornamento-non-basta', catalogo: '3.10', spiegazione: 'Not enough.', problemi: [] } },
                       { name: 'openjdk25', installed: '25.0.1', available: '25.0.2', update: true, locked: true, stack: true, role: 'Java', javaFlow: true,
                         inUse: 'the panel runs on it', panelRestart: 'Restart the panel.', canUpdate: false, whyNot: 'Own procedure.' }],
            others: [{ name: 'curl', installed: '8.9', available: '8.10' }] },
        packages_status: { success: true, lockedCount: 1, installedCount: 2, packages: [
            { name: 'postfix', role: 'SMTP', version: '3.9', locked: true }, { name: 'dovecot', role: 'IMAP', version: '2.3', locked: false }] },
        updates_status: { success: true, rebootPending: true, kernel: '15.0-p3', running: '15.0-p2', dryRun: 'Nothing to do.',
            vulnerable: [{ name: 'curl', role: 'tools', locked: false, fixedByUpgrade: true, cve: ['CVE-2026-0001'],
                           fix: { verdict: 'si-risolve-aggiornando', spiegazione: 'The repository has 8.10.' } }],
            lockedUpdates: [{ name: 'postfix', role: 'SMTP', current: '3.9', available: '3.10', majorJump: false, advisory: { level: 'verifica', text: 'Read the notes.' } }] },
        defaults_check: { success: true, fonte: 'ports', avvertenza: 'Defaults move.', ramo: { ramo: 'quarterly', spiegazione: 'Default.', dove: '/etc/pkg' },
            righe: [{ componente: 'OpenSSL', perche: 'TLS', predefinito: 'base', installato: 'base', esito: 'coerente', dipendenti: [] }] },
        panel_env: { success: true, spiegazione: 'Every tool is reachable.', pathEreditato: '/usr/bin', pathUsato: '/usr/bin:/usr/local/bin',
            strumenti: [{ comando: 'doveadm', aCosaServe: 'mailboxes', risolto: '/usr/local/bin/doveadm', stato: 'raggiungibile' }] },
    })[body.action] || { success: true },
    'GET /api/postfix-aliases-health': { success: true, overall: 'OK', summary: 'The aliases are fine.', alias_file: '/etc/mail/aliases',
        source_exists: true, alias_db_file: '/etc/mail/aliases.db', db_exists: true, root_forward: 'admin@example.com' },
};

async function serve(route) {
    const req = route.request();
    const url = new URL(req.url());
    const p = url.pathname;
    if (p.startsWith('/i18n/')) return route.fulfill({ status: 200, contentType: 'application/javascript', body: fs.readFileSync(path.join(pages, p)) });
    if (p.startsWith('/vendor/') || p.startsWith('/fa/')) {
        const f = path.join(resources, p);
        if (!fs.existsSync(f)) return route.fulfill({ status: 404, body: '' });
        const type = p.endsWith('.css') ? 'text/css' : p.endsWith('.js') ? 'application/javascript' : p.endsWith('.woff2') ? 'font/woff2' : 'application/octet-stream';
        return route.fulfill({ status: 200, contentType: type, body: fs.readFileSync(f) });
    }
    if (p.startsWith('/api/')) {
        let reply = API[req.method() + ' ' + p] || { success: true };
        if (typeof reply === 'function') {
            let body = {};
            try { body = JSON.parse(req.postData() || '{}'); } catch (e) { }
            reply = reply(url.searchParams, body);
        }
        return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(reply) });
    }
    const name = p.slice(1) || 'home';
    const f = path.join(pages, name + '.en.html');
    if (!fs.existsSync(f)) return route.fulfill({ status: 404, body: '' });
    const html = fs.readFileSync(f, 'utf8').replace(/\{\{CSRF_TOKEN\}\}/g, 'csrf-test')
        .replace(/\{\{THEME\}\}/g, 'light').replace(/\{\{COLOR_SCHEME\}\}/g, 'light');
    return route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: html });
}

// The pages to visit, with what to do on each before reading the text.
const VISITS = [
    { path: '/dns', prepare: async page => {
        await page.waitForFunction(() => document.querySelectorAll('#domainSelect option').length > 1);
        await page.selectOption('#domainSelect', 'example.com');
        await page.waitForSelector('.dns-record');
        await page.waitForFunction(() => !document.querySelector('.record-status-badge .fa-spinner'));
        await page.click('#verifyDnsBtn');
        await page.waitForSelector('#verificationResults:not(.d-none) table');
        await page.click('.card-header[onclick="toggleTzDiag()"]');
        await page.waitForSelector('#tzDiagTable table');
        await page.evaluate(() => { autoDnsCarica(); acCarica(); stsCarica(); });
        await page.waitForTimeout(800);
    } },
    { path: '/ssl', prepare: async page => {
        await page.waitForSelector('#certInfo .cert-info');
        await page.waitForFunction(() => document.getElementById('autoRenewBadge').textContent.trim() !== '-');
    } },
    { path: '/cloudflare', prepare: async page => {
        await page.waitForSelector('#cfAccountsBox table');
        await page.waitForSelector('#cfMailServerSelect');
        await page.click('#cfAccountsBox .btn-outline-primary');
    } },
    { path: '/security', prepare: async page => {
        await page.waitForSelector('#jailsContainer .jail-card');
        await page.waitForSelector('#bannedBody .ip-badge');
        await page.waitForSelector('#permabanBody .ip-badge');
        await page.waitForSelector('#fhcContainer .list-group-item');
        await page.waitForSelector('#ubContainer .alert-success');
        await page.waitForSelector('#cavContainer .btn-warning');
        await page.waitForSelector('#paliasBody table');
        await page.waitForSelector('#jailLiveBody .p-2');
        await page.waitForFunction(() => /\S/.test(document.getElementById('cfgJailStatus').textContent)
            && !document.getElementById('cfgJailStatus').textContent.includes('...'));
        await page.waitForTimeout(500);
    } },
    { path: '/firewall', prepare: async page => {
        await page.waitForSelector('#fwModeContainer .fw-mode-card');
        await page.waitForSelector('#fwCountriesGrid .fw-country-item');
        await page.waitForSelector('#fwPresetGroups button');
        await page.waitForSelector('#fwWlList .fw-cidr-item');
        await page.click('#fwToggleOnlySelected');
        await page.fill('#fwCodeEditor', 'IT, DE, XX');
        await page.waitForTimeout(1200);
    } },
    { path: '/logs', prepare: async page => {
        await page.waitForFunction(() => document.querySelector('#logSelect option[value="maillog"]'));
        await page.click('.log-preset-btn[data-preset="mail-bounce"]');
        await page.waitForSelector('#logViewer .log-entry');
        await page.fill('#searchPattern', 'reject');
        await page.click('button[onclick="searchLogs()"]');
        await page.waitForSelector('#searchResults .alert');
    } },
    { path: '/paths', prepare: async page => {
        await page.waitForSelector('#pathsContainer .path-entry.missing');
    } },
    { path: '/admins', prepare: async page => {
        await page.waitForSelector('#adminsBody .role-badge');
    } },
    { path: '/account', prepare: async page => {
        await page.waitForSelector('#passkeysList button.btn-outline-danger');
        await page.waitForSelector('#sessionsList .badge');
    } },
    { path: '/settings', prepare: async page => {
        await page.waitForSelector('#hostnameConsistency .alert');
        await page.waitForSelector('#rcDomainDns .badge');
        await page.click('.card-header button[onclick="repCarica()"]');
        await page.waitForSelector('#repFreq');
    } },
    { path: '/install' },
    { path: '/setup' },
    { path: '/updates', prepare: async page => {
        await page.waitForSelector('#ramo-body table');
        for (const [fn, sel] of [['osStato', '#os-body table'], ['planLoad', '#plan-body .border'], ['pkOverview', '#pk-body table'],
                                 ['updStatus', '#upd-status .alert-danger'], ['defCheck', '#def-body table'], ['envCheck', '#env-body table']]) {
            await page.evaluate(f => window[f](), fn);
            await page.waitForSelector(sel);
        }
        await page.click('#proc-release-tog');
    } },
];

(async () => {
    const browser = await chromium.launch({ executablePath: process.env.CHROMIUM || '/opt/pw-browsers/chromium' }).catch(() => chromium.launch());
    const ctx = await browser.newContext({ viewport: { width: 1366, height: 900 } });
    await ctx.route('**/*', serve);
    for (const v of VISITS) {
        console.log('\n== ' + v.path + ' ==');
        const page = await ctx.newPage();
        const errors = [];
        page.on('pageerror', e => errors.push(String(e)));
        page.on('dialog', d => d.dismiss());
        await page.goto(BASE + v.path);
        try {
            if (v.prepare) await v.prepare(page);
        } catch (e) {
            errors.push('prepare: ' + e.message);
        }
        check('<html lang="en">', await page.getAttribute('html', 'lang') === 'en');
        const found = await page.evaluate(src => {
            const re = new RegExp(src, 'iu');
            const out = [];
            const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
            for (let n = walker.nextNode(); n; n = walker.nextNode()) {
                const el = n.parentElement;
                if (!el || el.closest('script,style,code,pre,.visually-hidden-focusable')) continue;
                const s = n.textContent.replace(/\s+/g, ' ').trim();
                if (s && re.test(s)) out.push(s.slice(0, 120));
            }
            document.querySelectorAll('[title],[aria-label],[placeholder]').forEach(el => {
                ['title', 'aria-label', 'placeholder'].forEach(a => {
                    const s = el.getAttribute(a);
                    if (s && re.test(s)) out.push(a + '=' + s.slice(0, 100));
                });
            });
            return out;
        }, IT_RE.source);
        check('no Italian in the visible text' + (found.length ? ': ' + found.slice(0, 8).join(' | ') : ''), found.length === 0);
        check('no page errors' + (errors.length ? ': ' + errors.join(' | ') : ''), errors.length === 0);
        if (shots) await page.screenshot({ path: path.join(shots, 'en-' + v.path.slice(1) + '.png'), fullPage: true });
        await page.close();
    }
    await browser.close();
    console.log('\n' + (failed === 0 ? 'ALL GREEN' : failed + ' CHECKS FAILED'));
    process.exit(failed ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
