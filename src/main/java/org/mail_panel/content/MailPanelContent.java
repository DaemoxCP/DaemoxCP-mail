package org.mail_panel.content;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

/**
 * HTML content for FreeBSD Mail Panel
 * Same styling as Web Panel (Bootstrap 5)
 */
public class MailPanelContent {

    /**
     * Legge un pezzo di interfaccia dalle risorse del jar.
     *
     * Perche' esiste: finche' HTML, CSS e JavaScript vivono dentro literal Java, si sbatte
     * contro il limite di 65535 byte per costante del formato .class — e ci si sbatte a ogni
     * aggiunta, perche' javac fonde anche i literal adiacenti uniti da un "+". La cura non e'
     * spezzare i metodi all'infinito: e' smettere di tenere il contenuto dentro il codice.
     * Un file nel jar non ha nessun limite di dimensione, si legge con gli accenti giusti, e
     * si puo' aprire in un editor che sa cos'e' invece che come stringa Java.
     *
     * Il contenuto e' fissato al momento della compilazione, quindi nessun percorso arriva
     * mai dalla rete: qui non c'e' niente da filtrare, a differenza della rotta /fa e /vendor.
     */
    private static String resource(String path) {
        try (java.io.InputStream in = MailPanelContent.class.getResourceAsStream("/" + path)) {
            if (in == null) {
                System.err.println("[Contenuto] risorsa mancante nel jar: " + path);
                return "<!-- risorsa mancante: " + path + " -->";
            }
            return new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            System.err.println("[Contenuto] non riesco a leggere " + path + ": " + e.getMessage());
            return "<!-- risorsa illeggibile: " + path + " -->";
        }
    }

    private static String getJarDirectory() throws URISyntaxException {
        String jarPath = MailPanelContent.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath();
        return new File(jarPath).getParent();
    }

    public static void generateAllContent() {
        try {
            String jarDir = getJarDirectory();
            String adminDir = jarDir + "/admin";
            Path adminPath = Paths.get(adminDir);

            Files.createDirectories(adminPath);

            writeFile(adminDir + "/index.html", getIndexHtml());
            writeFile(adminDir + "/setup.html", getSetupHtml());
            writeFile(adminDir + "/home.html", getHomeHtml());
            writeFile(adminDir + "/domains.html", getDomainsHtml());
            writeFile(adminDir + "/mailboxes.html", getMailboxesHtml());
            writeFile(adminDir + "/aliases.html", getAliasesHtml());
            writeFile(adminDir + "/dns.html", getDnsHtml());
            writeFile(adminDir + "/ssl.html", getSslHtml());
            writeFile(adminDir + "/logs.html", getLogsHtml());
            writeFile(adminDir + "/queue.html", getQueueHtml());
            writeFile(adminDir + "/security.html", getSecurityHtml());
            writeFile(adminDir + "/firewall.html", getFirewallHtml());
            writeFile(adminDir + "/cloudflare.html", getCloudflareHtml());
            writeFile(adminDir + "/paths.html", getPathsHtml());
            writeFile(adminDir + "/install.html", getInstallHtml());
            writeFile(adminDir + "/settings.html", getSettingsHtml());
            writeFile(adminDir + "/account.html", getAccountHtml());
            writeFile(adminDir + "/statistics.html", getStatisticsHtml());
            writeFile(adminDir + "/admins.html", getAdminsHtml());
            writeFile(adminDir + "/ratelimits.html", getRateLimitsHtml());
            writeFile(adminDir + "/updates.html", getUpdatesHtml());

        } catch (IOException | URISyntaxException e) {
            // Silent fail
        }
    }

    private static void writeFile(String filePath, String content) throws IOException {
        Path path = Paths.get(filePath);
        Files.writeString(path, content, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
    }

    // ============== COMMON TEMPLATES FOR PAGES ==============

    /**
     * Common CSS styles used across all pages
     */
    private static String getCommonStyles() {
        return """
        /* ===== THEME VARIABLES ===== */
        :root {
            color-scheme: light;
            --bg-body: #f5f5f5;
            --bg-card: #ffffff;
            --bg-input: #ffffff;
            --text-primary: #212529;
            --text-secondary: #6c757d;
            --text-muted: #6c757d;
            --border-color: #dee2e6;
            --table-bg: #ffffff;
            --table-stripe: #f8f9fa;
            --table-hover: #e9ecef;
            --shadow-color: rgba(0, 0, 0, 0.1);
            --dropdown-bg: #ffffff;
            --modal-bg: #ffffff;
            --alert-bg: #f8f9fa;
        }
        [data-theme="dark"] {
            color-scheme: dark;
            --bg-body: #1a1d21;
            --bg-card: #2d3238;
            --bg-input: #3d4249;
            --text-primary: #e9ecef;
            --text-secondary: #adb5bd;
            --text-muted: #adb5bd;
            --border-color: #495057;
            --table-bg: #2d3238;
            --table-stripe: #343a40;
            --table-hover: #3d4249;
            --shadow-color: rgba(0, 0, 0, 0.3);
            --dropdown-bg: #2d3238;
            --modal-bg: #2d3238;
            --alert-bg: #343a40;
        }
        /* ===== BASE STYLES ===== */
        body { display: flex; flex-direction: column; min-height: 100vh; background-color: var(--bg-body); color: var(--text-primary); transition: background-color 0.3s, color 0.3s; }
        .content { flex: 1 0 auto; }
        .footer { flex-shrink: 0; }
        .content-container { background-color: var(--bg-card); border-radius: 10px; box-shadow: 0 0 20px var(--shadow-color); padding: 30px; margin-top: 30px; }
        .btn-mail { background-color: #e94560; border-color: #e94560; color: white; }
        .btn-mail:hover { background-color: #d63850; border-color: #d63850; color: white; }
        .btn-logout { background-color: #dc3545; border-color: #dc3545; }
        .btn-logout:hover { background-color: #c82333; border-color: #bd2130; color: white; }
        .stat-card { border-left: 4px solid #e94560; }
        /* ===== DARK THEME OVERRIDES ===== */
        [data-theme="dark"] .card { background-color: var(--bg-card); border-color: var(--border-color); }
        [data-theme="dark"] .card-header { background-color: var(--table-stripe); border-color: var(--border-color); color: var(--text-primary); }
        [data-theme="dark"] .card-body { background-color: var(--bg-card); color: var(--text-primary); }
        [data-theme="dark"] .table { --bs-table-bg: var(--table-bg); --bs-table-striped-bg: var(--table-stripe); --bs-table-hover-bg: var(--table-hover); color: var(--text-primary); }
        [data-theme="dark"] .table th, [data-theme="dark"] .table td { border-color: var(--border-color); }
        [data-theme="dark"] .form-control, [data-theme="dark"] .form-select { background-color: var(--bg-input); border-color: var(--border-color); color: var(--text-primary); }
        [data-theme="dark"] .form-control:focus, [data-theme="dark"] .form-select:focus { background-color: var(--bg-input); color: var(--text-primary); border-color: #e94560; box-shadow: 0 0 0 0.2rem rgba(233, 69, 96, 0.25); }
        [data-theme="dark"] .form-control::placeholder { color: var(--text-muted); }
        [data-theme="dark"] .modal-content { background-color: var(--modal-bg); color: var(--text-primary); }
        [data-theme="dark"] .modal-header, [data-theme="dark"] .modal-footer { border-color: var(--border-color); }
        [data-theme="dark"] .dropdown-menu { background-color: var(--dropdown-bg); border-color: var(--border-color); }
        [data-theme="dark"] .dropdown-item { color: var(--text-primary); }
        [data-theme="dark"] .dropdown-item:hover { background-color: var(--table-hover); color: var(--text-primary); }
        [data-theme="dark"] .dropdown-divider { border-color: var(--border-color); }
        [data-theme="dark"] .alert { background-color: var(--alert-bg); border-color: var(--border-color); color: var(--text-primary); }
        [data-theme="dark"] .alert-info { background-color: rgba(13, 202, 240, 0.15); border-color: rgba(13, 202, 240, 0.3); color: #6edff6; }
        [data-theme="dark"] .alert-warning { background-color: rgba(255, 193, 7, 0.15); border-color: rgba(255, 193, 7, 0.3); color: #ffda6a; }
        [data-theme="dark"] .alert-success { background-color: rgba(25, 135, 84, 0.15); border-color: rgba(25, 135, 84, 0.3); color: #75d9a3; }
        [data-theme="dark"] .alert-danger { background-color: rgba(220, 53, 69, 0.15); border-color: rgba(220, 53, 69, 0.3); color: #f1aeb5; }
        [data-theme="dark"] .list-group-item { background-color: var(--bg-card); border-color: var(--border-color); color: var(--text-primary); }
        [data-theme="dark"] .nav-tabs .nav-link { color: var(--text-secondary); }
        [data-theme="dark"] .nav-tabs .nav-link.active { background-color: var(--bg-card); border-color: var(--border-color) var(--border-color) var(--bg-card); color: var(--text-primary); }
        [data-theme="dark"] .footer { background-color: var(--bg-card) !important; }
        [data-theme="dark"] .text-muted { color: var(--text-muted) !important; }
        [data-theme="dark"] .bg-light { background-color: var(--table-stripe) !important; }
        [data-theme="dark"] h1, [data-theme="dark"] h2, [data-theme="dark"] h3, [data-theme="dark"] h4, [data-theme="dark"] h5, [data-theme="dark"] h6 { color: var(--text-primary); }
        [data-theme="dark"] .input-group-text { background-color: var(--table-stripe); border-color: var(--border-color); color: var(--text-primary); }
        [data-theme="dark"] .btn-secondary { background-color: var(--table-stripe); border-color: var(--border-color); color: var(--text-primary); }
        [data-theme="dark"] .btn-outline-secondary { border-color: var(--border-color); color: var(--text-secondary); }
        [data-theme="dark"] .btn-outline-secondary:hover { background-color: var(--table-hover); color: var(--text-primary); }
        [data-theme="dark"] pre, [data-theme="dark"] code { background-color: var(--table-stripe); color: #f8f9fa; }
        [data-theme="dark"] .table-light { --bs-table-bg: var(--table-stripe) !important; --bs-table-color: var(--text-primary) !important; }
        [data-theme="dark"] .table-light th { background-color: var(--table-stripe) !important; color: var(--text-primary) !important; border-color: var(--border-color) !important; }
        [data-theme="dark"] .table-bordered { border-color: var(--border-color); }
        [data-theme="dark"] .table-bordered td, [data-theme="dark"] .table-bordered th { border-color: var(--border-color) !important; }
        [data-theme="dark"] .table > :not(caption) > * > * { background-color: var(--table-bg); color: var(--text-primary); }
        [data-theme="dark"] .table-striped > tbody > tr:nth-of-type(odd) > * { background-color: var(--table-stripe); }
        [data-theme="dark"] .table-hover > tbody > tr:hover > * { background-color: var(--table-hover); }
        [data-theme="dark"] strong { color: var(--text-primary); }
        [data-theme="dark"] .btn-close { filter: invert(1) grayscale(100%) brightness(200%); }
        [data-theme="dark"] .form-label { color: var(--text-primary); }
        [data-theme="dark"] .form-check-label { color: var(--text-primary); }
        [data-theme="dark"] label { color: var(--text-primary); }
        [data-theme="dark"] .alert-primary { background-color: rgba(13, 110, 253, 0.15); border-color: rgba(13, 110, 253, 0.3); color: var(--text-primary); }
        [data-theme="dark"] p { color: var(--text-primary); }
        [data-theme="dark"] .bg-white { background-color: var(--bg-input) !important; color: var(--text-primary) !important; }
        [data-theme="dark"] .border { border-color: var(--border-color) !important; }
        [data-theme="dark"] .form-control.bg-light, [data-theme="dark"] .bg-light { background-color: var(--table-stripe) !important; color: var(--text-primary) !important; }
        /* ===== LA CORNICE: barra laterale a sezioni e barra in alto (Layout) =====
           Da 992px la barra laterale e' fissa a sinistra e la pagina le lascia il posto; sotto e'
           un pannello che si apre dal pulsante in alto (offcanvas-lg di Bootstrap). Le pagine di
           accesso e di installazione non hanno la cornice, e niente spazio a sinistra (body:has).
           Gli stessi colori e le stesse misure del pannello web. */
        :root { --sidebar-width: 16.5rem; }
        .sidebar { --bs-offcanvas-width: 17.5rem; background: linear-gradient(180deg, #16213e 0%, #0f3460 100%); color: #fff; }
        .sidebar .offcanvas-header { border-bottom: 1px solid rgba(255, 255, 255, .15); }
        .sidebar .offcanvas-body { padding: 0; }
        .sidebar-brand { display: flex; align-items: center; gap: .6rem; padding: 1rem 1.25rem; color: #fff; font-weight: 600; font-size: 1.05rem; text-decoration: none; white-space: nowrap; }
        .sidebar-brand:hover, .sidebar-brand:focus-visible { color: #fff; }
        .sidebar-menu, .sidebar-menu ul { list-style: none; margin: 0; padding: 0; }
        .sidebar-menu { padding-bottom: 1.5rem; }
        .sidebar-section-title { display: block; padding: .85rem 1.25rem .3rem; font-size: .72rem; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; color: rgba(255, 255, 255, .65); }
        .sidebar-link { display: flex; align-items: center; gap: .7rem; padding: .38rem 1.25rem .38rem calc(1.25rem - 3px); color: rgba(255, 255, 255, .88); text-decoration: none; border-left: 3px solid transparent; }
        .sidebar-link i { width: 1.25rem; text-align: center; flex-shrink: 0; }
        .sidebar-link:hover { background: rgba(255, 255, 255, .08); color: #fff; }
        .sidebar-link:focus-visible { outline: 2px solid #fff; outline-offset: -2px; color: #fff; }
        .sidebar-link.active { background: rgba(233, 69, 96, .22); border-left-color: #e94560; color: #fff; font-weight: 600; }
        .icona-cloudflare { color: #f6821f; }
        @media (min-width: 992px) {
            body:has(> #sidebar) { padding-left: var(--sidebar-width); }
            .sidebar { position: fixed; top: 0; bottom: 0; left: 0; width: var(--sidebar-width); overflow-y: auto; z-index: 1030; }
            .sidebar .offcanvas-body { display: block; }
        }
        .topbar { position: sticky; top: 0; z-index: 1020; display: flex; align-items: center; gap: .75rem; min-height: 3.5rem; padding: .5rem 1rem; background: var(--bg-card); color: var(--text-primary); border-bottom: 1px solid var(--border-color); box-shadow: 0 1px 4px var(--shadow-color); }
        .topbar-toggle { color: var(--text-primary); font-size: 1.2rem; padding: .25rem .6rem; }
        .topbar-title { min-width: 0; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; font-weight: 600; }
        .topbar-section { color: var(--text-secondary); font-weight: 400; }
        .topbar-sep { color: var(--text-secondary); margin: 0 .35rem; }
        .topbar-actions { margin-left: auto; display: flex; align-items: center; gap: .5rem; flex-shrink: 0; }
        .theme-toggle { cursor: pointer; padding: .25rem .6rem; border-radius: 6px; background: transparent; border: 1px solid var(--border-color); color: var(--text-primary); font-size: 1rem; line-height: 1.5; }
        .theme-toggle:hover { background: var(--table-hover); }
        .skip-link { position: absolute; top: .5rem; left: .5rem; z-index: 2000; padding: .5rem 1rem; background: #fff; color: #0f3460; border-radius: 6px; }
        #main:focus { outline: none; }
        @media (max-width: 575.98px) { .topbar-section, .topbar-sep { display: none; } }
        .table-responsive { overflow: visible; }
        .dropdown-menu { z-index: 1050; }
        #nav-placeholder, #footer-placeholder { display: contents; }
        /* Celle con "parole" lunghissime: indirizzi, domini, host, errori di consegna (classe testo-lungo).
           Vanno a capo anche a meta' parola, quando serve, invece di allargare la tabella e con lei la
           pagina: su computer le tabelle non scorrono nel loro riquadro, perche' i menu a tendina delle
           righe devono poter uscire. Solo su queste celle: una regola su tutte spezzava anche le parole
           corte nelle colonne strette ("deferre-d", le date a meta' numero). */
        .table td.testo-lungo { overflow-wrap: anywhere; }
        /* Fuori dalle tabelle (finestre, messaggi): un indirizzo lungo va a capo invece di allargare. */
        .modal .testo-lungo, .alert.testo-lungo, code.testo-lungo { overflow-wrap: anywhere; }
        /* Testo che dice com'e' andata: verde, giallo, rosso leggibili in tutti e due i temi.
           text-success, text-warning e text-danger di Bootstrap sul fondo scuro stanno sotto
           il contrasto minimo di 4.5:1 (gli stessi colori del pannello web). */
        .testo-ok { color: #146c43; }
        .testo-avviso { color: #7a4e00; }
        .testo-rischio { color: #b02a37; }
        [data-theme="dark"] .testo-ok { color: #75d9a3; }
        [data-theme="dark"] .testo-avviso { color: #ffcf5c; }
        [data-theme="dark"] .testo-rischio { color: #f1aeb5; }
        /* ===== Telefono e tablet: sotto i 992px niente deve allargare la pagina =====
           Una pagina piu' larga della finestra scorre tutta in orizzontale. Regole per i casi che si
           ripetono, invece di una pezza per pagina (agiscono solo quando il contenuto non ci sta):
           - una tabella scorre dentro il suo riquadro (.table-responsive qui sopra la lascia uscire,
             per i menu a tendina nelle righe: sul telefono restano solo nelle tabelle a schede), e in
             una tabella senza riquadro i testi lunghi vanno a capo nella cella;
           - le righe "titolo a sinistra, comandi a destra" (intestazioni di pagina e di riquadro)
             vanno a capo, compresi i gruppi di pulsanti marcati text-nowrap;
           - i testi lunghi senza spazi (chiavi, record DNS, percorsi, nomi di parametri come
             innodb_flush_log_at_trx_commit nelle etichette) vanno a capo. */
        @media (max-width: 991.98px) {
            .table-responsive { overflow-x: auto; }
            .table-responsive:has(> .tabella-schede) { overflow-x: visible; }
            /* Tabelle senza riquadro che scorre: un indirizzo o un dominio lungo va a capo nella cella. */
            table.table:not(.table-responsive table) td { overflow-wrap: anywhere; }
            .d-flex.justify-content-between { flex-wrap: wrap; gap: .5rem; }
            .d-flex.justify-content-between > .d-flex { flex-wrap: wrap; }
            .d-flex.justify-content-between > .text-nowrap { white-space: normal !important; }
            pre { white-space: pre-wrap; overflow-wrap: anywhere; }
            code, .form-label { overflow-wrap: anywhere; }
        }
        /* Tabelle che su telefono e tablet (sotto i 992px, come la barra laterale che si chiude) diventano schede:
           classe tabella-schede sulla <table> e data-label su ogni cella. Cinque colonne in 375px non
           ci stanno, e una tabella piu' larga della pagina la faceva scorrere tutta in orizzontale; il
           suo riquadro non scorre, perche' i menu a tendina nelle righe non vengano tagliati. */
        @media (max-width: 991.98px) {
            .tabella-schede thead { display: none; }
            .tabella-schede, .tabella-schede tbody, .tabella-schede tr, .tabella-schede td { display: block; width: 100%; }
            .tabella-schede tr { border: 1px solid var(--border-color); border-radius: 8px; padding: .5rem .75rem; margin-bottom: .75rem; }
            .tabella-schede td { border: 0; padding: .2rem 0; overflow-wrap: anywhere; }
            .tabella-schede td[data-label]::before { content: attr(data-label); display: block; font-size: .75rem; color: var(--text-secondary); }
            .tabella-schede td:empty { display: none; }
        }
        /* Campo password (campoPassword): su un telefono, accanto ai tre pulsanti, una password di
           20 caratteri deve vedersi tutta. */
        @media (max-width: 575.98px) { .campo-password { font-size: .875rem; padding-left: .5rem; padding-right: .5rem; } }
        /* I ruoli, con lo stesso colore ovunque: barra in alto, pagina Amministratori. */
        .role-badge { color: #fff; font-weight: 500; }
        .role-badge.superadmin { background-color: #dc3545; }
        .role-badge.admin { background-color: #0d6efd; }
        .role-badge.operator { background-color: #198754; }
        .role-badge.viewer { background-color: #6c757d; }
        """;
    }

    /**
     * L'inizio di ogni pagina con la cornice: la <head> e il segnaposto della barra laterale e della
     * barra in alto, che il server completa a ogni richiesta (Layout.expand) insieme ai testi nella
     * lingua di chi chiede (I18n.render).
     * @param titleKey la chiave del titolo nei file di lingua
     * @param pageName la pagina, per evidenziarla nel menu (e.g., "home", "domains")
     * @param extraStyles CSS della sola pagina (puo' essere vuoto)
     */
    private static String getHead(String titleKey, String pageName, String extraStyles) {
        // {{THEME}} e {{COLOR_SCHEME}} li scrive il server a ogni richiesta (handleProtectedPage):
        // la preferenza dell'admin arriva dentro la pagina, e il tema si applica qui nella <head>,
        // prima del primo disegno. Prima lo applicava lo script in fondo alla pagina, e solo dopo
        // una chiamata a /api/theme: fino ad allora il browser disegnava la pagina chiara, cioe'
        // il lampo bianco a ogni cambio di pagina. La meta color-scheme copre l'attimo prima che
        // arrivi il CSS: e' lei a dire al browser di che colore e' la pagina vuota.
        return """
<!DOCTYPE html>
<html lang="{{lang}}" data-theme-pref="{{THEME}}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="color-scheme" content="{{COLOR_SCHEME}}">
    <title>{{t:""" + titleKey + """
}} - Mail Control Panel</title>
    <script>
        (function () {
            var d = document.documentElement, pref = d.getAttribute('data-theme-pref');
            if (pref !== 'light' && pref !== 'dark') pref = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
            d.setAttribute('data-theme', pref);
        })();
        // Ogni richiesta che cambia qualcosa porta il token CSRF della pagina nell'intestazione
        // X-CSRF-Token, e il server lo controlla per tutte le rotte in un punto solo
        // (SSLMailServer.context). Prima erano le singole pagine a doverlo mettere nel corpo, e
        // venticinque rotte non lo chiedevano affatto.
        (function () {
            var send = window.fetch;
            window.fetch = function (input, init) {
                init = init || {};
                var method = String(init.method || (input && input.method) || 'GET').toUpperCase();
                var url = typeof input === 'string' ? input : (input && input.url) || String(input);
                var field = document.getElementById('csrf_token');
                if (method !== 'GET' && method !== 'HEAD' && field && new URL(url, location.href).origin === location.origin) {
                    var headers = new Headers(init.headers || (input && input.headers) || {});
                    if (!headers.has('X-CSRF-Token')) headers.set('X-CSRF-Token', field.value);
                    init = Object.assign({}, init, { headers: headers });
                }
                return send.call(this, input, init);
            };
        })();
    </script>
    <script src="/i18n/{{lang}}.js?v={{i18nVersion}}"></script>
    <link href="/vendor/bootstrap.min.css" rel="stylesheet">
    <link href="/fa/css/all.min.css" rel="stylesheet">
    <style>
""" + getCommonStyles() + "\n" + (extraStyles != null ? extraStyles : "") + """
    </style>
</head>
""" + "<body data-page=\"" + pageName + "\">\n" + Layout.placeholder(pageName) + "\n";
    }

    /**
     * Common footer section with inline footer HTML and logout script
     */
    private static String getFooterSection() {
        return """
    <footer class="footer bg-dark text-white py-3 mt-4">
        <div class="container text-center">
            <small>&copy; <span id="footer-year"></span> {{t:footer.text}}</small>
        </div>
    </footer>
    <script>document.getElementById('footer-year').textContent = new Date().getFullYear();</script>
    <input type="hidden" id="csrf_token" value="{{CSRF_TOKEN}}">
    <script src="/vendor/bootstrap.bundle.min.js"></script>
    <script>
        // ===== THEME MANAGEMENT =====
        // Il tema e' gia' applicato dalla <head>, con la preferenza che il server ha scritto nella
        // pagina (data-theme-pref). Qui resta il contorno: icona, pulsante, e "auto" che segue il sistema.
        (function() {
            let savedTheme = document.documentElement.getAttribute('data-theme-pref');
            const writtenByServer = savedTheme === 'auto' || savedTheme === 'light' || savedTheme === 'dark';
            if (!writtenByServer) savedTheme = 'auto';

            // Get browser preference
            function getBrowserTheme() {
                return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
            }

            // Apply theme to document
            function applyTheme(theme) {
                const effectiveTheme = theme === 'auto' ? getBrowserTheme() : theme;
                document.documentElement.setAttribute('data-theme', effectiveTheme);
                updateIcon(theme);
            }

            // L'icona del pulsante mostra la scelta, come nel pannello web: mezzo cerchio per
            // automatico (segue il sistema), sole per chiaro, luna per scuro.
            function updateIcon(theme) {
                const icon = document.getElementById('themeIcon');
                if (icon) {
                    icon.className = theme === 'auto' ? 'fas fa-circle-half-stroke' : theme === 'dark' ? 'fas fa-moon' : 'fas fa-sun';
                }
            }

            // Chiede la preferenza al server. Serve solo se la pagina non l'aveva scritta, o se il
            // browser la ripresenta dalla cache di indietro/avanti con il tema di allora.
            function loadTheme() {
                fetch('/api/theme').then(r => r.json()).then(data => {
                    if (data.success) {
                        savedTheme = data.theme || 'auto';
                        applyTheme(savedTheme);
                    }
                }).catch(() => {});
            }

            // Save theme to server
            function saveTheme(theme) {
                fetch('/api/theme', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ theme: theme, csrf_token: document.getElementById('csrf_token').value })
                });
            }

            // Cycle through themes: auto -> light -> dark -> auto
            function cycleTheme() {
                if (savedTheme === 'auto') savedTheme = 'light';
                else if (savedTheme === 'light') savedTheme = 'dark';
                else savedTheme = 'auto';
                applyTheme(savedTheme);
                saveTheme(savedTheme);
            }

            // Listen for browser theme changes (for auto mode)
            window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
                if (savedTheme === 'auto') applyTheme('auto');
            });

            // Initialize theme toggle
            document.addEventListener('DOMContentLoaded', function() {
                if (!writtenByServer) loadTheme();
                const toggle = document.getElementById('themeToggle');
                if (toggle) {
                    toggle.addEventListener('click', cycleTheme);
                }
            });
            window.addEventListener('pageshow', function(e) { if (e.persisted) loadTheme(); });

            // Lo stesso tema della <head>: qui serve solo a mettere l'icona giusta. Prima c'era
            // applyTheme(getBrowserTheme()), che rimetteva il tema del SISTEMA sopra quello scelto
            // fino alla risposta di /api/theme: sistema chiaro e pannello scuro davano il lampo bianco.
            applyTheme(savedTheme);
        })();

        // Logout handler
        document.getElementById('logoutButton').addEventListener('click', function(e) {
            e.preventDefault();
            fetch('/api/logout', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ csrf_token: document.getElementById('csrf_token').value })
            }).then(() => window.location.href = '/');
        });
    </script>
""";
    }

    /**
     * Script section start - includes csrfToken variable
     */
    private static String getScriptStart() {
        return """
    <script>
        let csrfToken = document.getElementById('csrf_token').value;
""";
    }

    /**
     * Script section end
     */
    private static String getScriptEnd() {
        return """
    </script>
</body>
</html>
""";
    }

    /**
     * Le opzioni WebAuthn arrivano dal server in JSON (base64url, dalla libreria Yubico): il browser
     * vuole ArrayBuffer. E la risposta dell'autenticatore torna al server in JSON. Funzioni comuni
     * alla pagina di accesso e alle Impostazioni (registrazione e conferma con la passkey).
     */
    static String getWebAuthnScript() {
        return """
        function b64uToBuf(s) {
            s = s.replace(/-/g, '+').replace(/_/g, '/');
            while (s.length % 4) s += '=';
            const bin = atob(s), out = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
            return out.buffer;
        }
        function bufToB64u(buf) {
            const bytes = new Uint8Array(buf);
            let bin = '';
            for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
            return btoa(bin).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
        }
        function webauthnGetOptions(json) {
            const pk = Object.assign({}, json.publicKey);
            pk.challenge = b64uToBuf(pk.challenge);
            if (pk.allowCredentials) pk.allowCredentials = pk.allowCredentials.map(c => Object.assign({}, c, { id: b64uToBuf(c.id) }));
            return { publicKey: pk };
        }
        function webauthnCreateOptions(json) {
            const pk = Object.assign({}, json.publicKey);
            pk.challenge = b64uToBuf(pk.challenge);
            pk.user = Object.assign({}, pk.user, { id: b64uToBuf(pk.user.id) });
            if (pk.excludeCredentials) pk.excludeCredentials = pk.excludeCredentials.map(c => Object.assign({}, c, { id: b64uToBuf(c.id) }));
            return { publicKey: pk };
        }
        function webauthnCredentialJson(cred) {
            const r = cred.response;
            const out = { type: cred.type, id: cred.id, rawId: bufToB64u(cred.rawId), clientExtensionResults: {},
                response: { clientDataJSON: bufToB64u(r.clientDataJSON) } };
            if (r.attestationObject) out.response.attestationObject = bufToB64u(r.attestationObject);
            if (r.authenticatorData) {
                out.response.authenticatorData = bufToB64u(r.authenticatorData);
                out.response.signature = bufToB64u(r.signature);
                if (r.userHandle) out.response.userHandle = bufToB64u(r.userHandle);
            }
            return out;
        }
""";
    }

    // ============== INDEX.HTML (Login Page) ==============
    public static String getIndexHtml() {
        int year = java.time.Year.now().getValue();
        return ("""
<!DOCTYPE html>
<html lang="{{lang}}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{t:login.title}} - Mail Control Panel</title>
    <script src="/i18n/{{lang}}.js?v={{i18nVersion}}"></script>
    <link href="/vendor/bootstrap.min.css" rel="stylesheet">
    <link href="/fa/css/all.min.css" rel="stylesheet">
    <style>
        /* Theme Variables */
        :root {
            --bg-body: #f8f9fa;
            --bg-card: #ffffff;
            --bg-input: #ffffff;
            --text-primary: #212529;
            --text-secondary: #6c757d;
            --border-color: #dee2e6;
            --shadow-color: rgba(0, 0, 0, 0.1);
        }
        [data-theme="dark"] {
            --bg-body: #1a1d21;
            --bg-card: #2d3238;
            --bg-input: #3d4249;
            --text-primary: #e9ecef;
            --text-secondary: #adb5bd;
            --border-color: #495057;
            --shadow-color: rgba(0, 0, 0, 0.3);
        }
        body { display: flex; flex-direction: column; min-height: 100vh; background-color: var(--bg-body); color: var(--text-primary); transition: background-color 0.3s, color 0.3s; }
        .content { flex: 1 0 auto; }
        .footer { flex-shrink: 0; }
        .login-container { max-width: 450px; margin: 50px auto; padding: 30px; background-color: var(--bg-card); border-radius: 10px; box-shadow: 0 0 20px var(--shadow-color); }
        .login-logo { text-align: center; margin-bottom: 30px; }
        .login-logo i { font-size: 64px; color: #e94560; }
        .char-hint { font-size: 0.75rem; color: var(--text-secondary); margin-top: 4px; }
        .char-hint code { background-color: var(--bg-input); padding: 1px 4px; border-radius: 3px; font-size: 0.7rem; }
        .validation-error { color: #dc3545; font-size: 0.8rem; margin-top: 4px; display: none; }
        .input-valid { border-color: #198754 !important; }
        .input-invalid { border-color: #dc3545 !important; }
        .btn-mail { background-color: #e94560; border-color: #e94560; }
        .btn-mail:hover { background-color: #d63850; border-color: #d63850; }
        /* La passkey usa il colore del pannello, non un colore suo: e' un'azione come le
           altre, e un accento estraneo la faceva sembrare un pezzo di un'altra applicazione. */
        .btn-passkey {
            background-color: #e94560; border-color: #e94560; color: #fff;
            font-weight: 600; letter-spacing: .2px;
            padding: .7rem 1rem; border-radius: 10px;
            display: inline-flex; align-items: center; justify-content: center; gap: .6rem;
            transition: background-color .15s ease, border-color .15s ease, transform .06s ease;
        }
        .btn-passkey:hover, .btn-passkey:focus { background-color: #d63850; border-color: #d63850; color: #fff; }
        .btn-passkey:active { transform: translateY(1px); }
        .btn-passkey:focus-visible { outline: 3px solid rgba(233, 69, 96, .45); outline-offset: 2px; }
        /* L'icona dentro il pulsante non deve gareggiare con la parola: nella versione
           precedente la chiave era grande quanto il testo e tirava l'occhio da sola. */
        .btn-passkey i { font-size: .95em; opacity: .9; }
        .step { display: none; }
        .step.active { display: block; }
        .code-input { letter-spacing: 8px; font-size: 1.5rem; }
        .login-links { display: flex; justify-content: space-between; gap: 1rem; margin-top: 1rem; font-size: .9rem; }
        .login-links a, .login-link { color: #e94560; }
        .passkey-prompt { text-align: center; padding: 26px 20px 22px; }
        /* L'fingerprint stava sospesa nel vuoto. Dentro un cerchio diventa un oggetto, e si
           legge come "il dispositivo sta chiedendo" invece che come una decorazione. */
        .passkey-prompt .passkey-badge {
            width: 76px; height: 76px; margin: 0 auto 18px;
            display: flex; align-items: center; justify-content: center;
            border-radius: 50%;
            background-color: rgba(233, 69, 96, .12);
            border: 1px solid rgba(233, 69, 96, .28);
        }
        .passkey-prompt .passkey-badge i { font-size: 34px; color: #e94560; margin: 0; }
        /* Sul fondo scuro un velo al 12% si perde: serve piu' contrasto, non lo stesso valore. */
        [data-theme="dark"] .passkey-prompt .passkey-badge {
            background-color: rgba(233, 69, 96, .18);
            border-color: rgba(233, 69, 96, .42);
        }
        [data-theme="dark"] .passkey-prompt .passkey-badge i { color: #ff6b83; }
        .passkey-prompt h5 { font-weight: 600; margin-bottom: .35rem; }
        .passkey-prompt p { font-size: .9rem; line-height: 1.45; max-width: 21rem; margin-left: auto; margin-right: auto; }
        .divider { display: flex; align-items: center; text-align: center; margin: 20px 0; }
        .divider::before, .divider::after { content: ''; flex: 1; border-bottom: 1px solid var(--border-color); }
        .divider span { padding: 0 10px; color: var(--text-secondary); font-size: 0.9rem; }
        /* Dark mode overrides */
        [data-theme="dark"] .form-control, [data-theme="dark"] .input-group-text { background-color: var(--bg-input); border-color: var(--border-color); color: var(--text-primary); }
        [data-theme="dark"] .form-control::placeholder { color: var(--text-secondary); }
        [data-theme="dark"] .form-control:focus { background-color: var(--bg-input); color: var(--text-primary); border-color: #e94560; box-shadow: 0 0 0 0.2rem rgba(233, 69, 96, 0.25); }
        [data-theme="dark"] .alert { background-color: #343a40; border-color: var(--border-color); }
        [data-theme="dark"] .alert-success { background-color: rgba(25, 135, 84, 0.15); border-color: rgba(25, 135, 84, 0.3); color: #75d9a3; }
        [data-theme="dark"] .alert-danger { background-color: rgba(220, 53, 69, 0.15); border-color: rgba(220, 53, 69, 0.3); color: #f1aeb5; }
        [data-theme="dark"] .text-muted { color: var(--text-secondary) !important; }
        [data-theme="dark"] h2 { color: var(--text-primary); }
        [data-theme="dark"] .footer { background-color: var(--bg-card) !important; }
        /* Theme toggle */
        /* In alto a destra: la lingua e il tema, anche prima di entrare. */
        .login-actions { position: fixed; top: 15px; right: 15px; display: flex; align-items: center; gap: .5rem; z-index: 1000; }
        .login-actions .btn-group { background: var(--bg-card); border-radius: .25rem; }
        .theme-toggle-login { cursor: pointer; padding: 10px 14px; border-radius: 50%; background: var(--bg-card); border: 1px solid var(--border-color); color: var(--text-primary); font-size: 1.2rem; box-shadow: 0 2px 10px var(--shadow-color); z-index: 1000; }
        .theme-toggle-login:hover { background: var(--bg-input); }
    </style>
    <script>
        // Theme management for login page (uses localStorage before login)
        (function() {
            function getBrowserTheme() {
                return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
            }
            function getTheme() {
                const saved = localStorage.getItem('theme');
                if (saved === 'light' || saved === 'dark') return saved;
                return getBrowserTheme(); // auto = follow browser
            }
            function applyTheme(theme) {
                document.documentElement.setAttribute('data-theme', theme);
                const icon = document.getElementById('themeIconLogin');
                if (icon) icon.className = theme === 'dark' ? 'fas fa-moon' : 'fas fa-sun';
            }
            function toggleTheme() {
                const current = document.documentElement.getAttribute('data-theme');
                const newTheme = current === 'dark' ? 'light' : 'dark';
                localStorage.setItem('theme', newTheme);
                applyTheme(newTheme);
            }
            // Apply immediately
            applyTheme(getTheme());
            // Listen for browser changes
            window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
                if (!localStorage.getItem('theme')) applyTheme(getBrowserTheme());
            });
            // Expose toggle function
            window.toggleLoginTheme = toggleTheme;
        })();
    </script>
</head>
<body>
    <div class="login-actions">
        {{LANGUAGE_SWITCH}}
        <button type="button" class="theme-toggle-login" onclick="toggleLoginTheme()" title="{{t:layout.theme}}" aria-label="{{t:layout.theme}}">
            <i class="fas fa-sun" id="themeIconLogin" aria-hidden="true"></i>
        </button>
    </div>
    <main class="content">
        <div class="container">
            <div class="login-container">
                <div class="login-logo"><i class="fas fa-envelope" aria-hidden="true"></i></div>
                <h1 class="h2 text-center mb-4">Mail Control Panel</h1>
                <div class="alert alert-success d-none" id="successAlert" role="status" aria-live="polite">{{t:login.success}}</div>
                <div class="alert alert-danger d-none" id="errorAlert" role="alert">
                    <span id="errorMessage">{{t:login.error}}</span>
                </div>
                <input type="hidden" id="csrf_token" value="{{CSRF_TOKEN}}">

                <!-- Accesso con passkey, oppure codice via email -->
                <div id="step-start" class="step active">
                    <div class="passkey-prompt">
                        <div class="passkey-badge"><i class="fas fa-fingerprint" aria-hidden="true"></i></div>
                        <h2 class="h5">{{t:login.usePasskeyTitle}}</h2>
                        <p class="text-muted mb-3">{{t:login.passkeyHint}}</p>
                        <button type="button" class="btn btn-passkey w-100" id="btnPasskey">
                            <i class="fas fa-right-to-bracket" aria-hidden="true"></i><span>{{t:login.usePasskey}}</span>
                        </button>
                    </div>
                    <div class="divider"><span>{{t:login.or}}</span></div>
                    <form id="emailForm" novalidate>
                        <label for="email" class="form-label">{{t:login.email}}</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="fas fa-envelope" aria-hidden="true"></i></span>
                            <input type="email" class="form-control" id="email" maxlength="254" autocomplete="email"
                                   inputmode="email" autocapitalize="off" autocorrect="off" spellcheck="false" aria-describedby="emailHint">
                        </div>
                        <div class="char-hint" id="emailHint">{{t:login.emailHint}}</div>
                        <div class="d-grid mt-3">
                            <button type="submit" class="btn btn-outline-secondary" id="btnSendCode">
                                <i class="fas fa-paper-plane me-2" aria-hidden="true"></i><span>{{t:login.sendCode}}</span>
                            </button>
                        </div>
                    </form>
                    <p class="text-center mt-3 mb-0"><a href="#" class="login-link small" id="linkConsole">{{t:login.consoleLink}}</a></p>
                </div>

                <!-- Il codice arrivato per email -->
                <div id="step-code" class="step">
                    <p class="text-muted">{{t:login.codeSentText}}</p>
                    <form id="codeForm" novalidate>
                        <label for="emailCode" class="form-label">{{t:login.codeLabel}}</label>
                        <input type="text" class="form-control text-center code-input" id="emailCode" maxlength="6"
                               inputmode="numeric" autocomplete="one-time-code" placeholder="000000">
                        <div class="d-grid mt-3">
                            <button type="submit" class="btn btn-mail btn-lg text-white" id="btnVerifyCode">{{t:login.verify}}</button>
                        </div>
                    </form>
                    <div class="login-links"><a href="#" data-back>{{t:login.back}}</a><a href="#" id="linkResend">{{t:login.resend}}</a></div>
                </div>

                <!-- Il codice generato sulla console del server -->
                <div id="step-console" class="step">
                    <p class="text-muted">{{t:login.consoleText.html}}</p>
                    <form id="consoleForm" novalidate>
                        <label for="consoleCode" class="form-label">{{t:login.consoleLabel}}</label>
                        <input type="text" class="form-control text-center code-input" id="consoleCode" maxlength="9"
                               inputmode="numeric" autocomplete="one-time-code" placeholder="0000 0000">
                        <div class="d-grid mt-3">
                            <button type="submit" class="btn btn-mail btn-lg text-white" id="btnConsole">{{t:login.submit}}</button>
                        </div>
                    </form>
                    <div class="login-links"><a href="#" data-back>{{t:login.back}}</a></div>
                </div>
            </div>
        </div>
    </main>
    <footer class="footer bg-light text-center text-lg-start mt-4">
        <div class="text-center p-3" style="background-color: rgba(0, 0, 0, 0.2);">&copy; {{YEAR}} {{t:footer.text}}</div>
    </footer>
    <script src="/vendor/bootstrap.bundle.min.js"></script>
    <script>
""" + getWebAuthnScript() + """
        const el = id => document.getElementById(id);
        // Solo ASCII stampabile, come lo controlla il server
        const EMAIL = /^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\\.[A-Za-z]{2,}$/;

        function showError(msg) { el('successAlert').classList.add('d-none'); el('errorMessage').textContent = msg; el('errorAlert').classList.remove('d-none'); }
        function showInfo(msg) { el('errorAlert').classList.add('d-none'); el('successAlert').textContent = msg; el('successAlert').classList.remove('d-none'); }
        function hideAlerts() { el('errorAlert').classList.add('d-none'); el('successAlert').classList.add('d-none'); }
        function go(step) {
            document.querySelectorAll('.step').forEach(s => s.classList.remove('active'));
            el('step-' + step).classList.add('active');
            hideAlerts();
            const first = { start: 'btnPasskey', code: 'emailCode', console: 'consoleCode' }[step];
            if (first) el(first).focus();
        }
        document.querySelectorAll('[data-back]').forEach(a => a.addEventListener('click', e => { e.preventDefault(); go('start'); }));
        el('linkConsole').addEventListener('click', e => { e.preventDefault(); go('console'); });

        // Tutto passa da /api/login con il token della pagina
        async function login(action, body) {
            const res = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(Object.assign({ action: action, csrf_token: el('csrf_token').value }, body)) });
            try { return await res.json(); } catch (e) { return {}; }
        }
        async function busy(btn, job) {
            btn.disabled = true;
            try { await job(); } catch (err) { showError(t('login.connectionError')); }
            btn.disabled = false;
        }
        function enter(d) {
            showInfo(t('login.success'));
            window.location.href = d.redirect || '/home';
        }

        // Passkey: nessun nome da scrivere, il dispositivo sa per quale account e' la passkey
        el('btnPasskey').addEventListener('click', function() {
            const btn = this;
            hideAlerts();
            if (!window.PublicKeyCredential || !navigator.credentials) { showError(t('login.passkeyUnsupported')); return; }
            busy(btn, async () => {
                const o = await login('passkey_options', {});
                if (!o.success) { showError(o.error || t('login.passkeyStartError')); return; }
                let cred;
                try { cred = await navigator.credentials.get(webauthnGetOptions(o.options)); }
                catch (err) { showError(err && err.name === 'NotAllowedError' ? t('login.cancelled') : t('login.passkeyError', { message: err.message })); return; }
                const r = await login('passkey_verify', { request: o.request, credential: webauthnCredentialJson(cred) });
                if (r.success) enter(r); else showError(r.error || t('login.passkeyFailed'));
            });
        });

        // Codice via email: la risposta e' la stessa per ogni indirizzo, quindi la pagina non sa se esiste
        let lastEmail = '';
        async function requestCode(btn) {
            const email = el('email').value.trim();
            if (!EMAIL.test(email) || email.length > 254) { showError(t('login.emailInvalid')); el('email').focus(); return; }
            await busy(btn, async () => {
                const r = await login('code_request', { email: email });
                if (!r.success) { showError(r.error || t('login.error')); return; }
                lastEmail = email;
                go('code');
                showInfo(r.message || t('login.codeSentText'));
            });
        }
        el('emailForm').addEventListener('submit', e => { e.preventDefault(); requestCode(el('btnSendCode')); });
        el('linkResend').addEventListener('click', e => { e.preventDefault(); el('email').value = lastEmail; requestCode(el('btnVerifyCode')); });
        el('emailCode').addEventListener('input', function() { this.value = this.value.replace(/[^0-9]/g, ''); });
        el('codeForm').addEventListener('submit', e => {
            e.preventDefault();
            const code = el('emailCode').value;
            if (!/^[0-9]{6}$/.test(code)) { showError(t('login.enterOtp')); return; }
            busy(el('btnVerifyCode'), async () => {
                const r = await login('code_verify', { email: lastEmail, code: code });
                if (r.success) enter(r); else { showError(r.error || t('login.error')); el('emailCode').select(); }
            });
        });

        // Codice dalla console del server: otto cifre, lo spazio in mezzo non conta
        el('consoleCode').addEventListener('input', function() { this.value = this.value.replace(/[^0-9 ]/g, ''); });
        el('consoleForm').addEventListener('submit', e => {
            e.preventDefault();
            const code = el('consoleCode').value.replace(/ /g, '');
            if (!/^[0-9]{8}$/.test(code)) { showError(t('login.consoleEnterValid')); return; }
            busy(el('btnConsole'), async () => {
                const r = await login('console_verify', { code: code });
                if (r.success) enter(r); else { showError(r.error || t('login.error')); el('consoleCode').select(); }
            });
        });
    </script>
</body>
</html>
""").replace("{{YEAR}}", String.valueOf(year));
    }

    // ============== SETUP.HTML ==============
    /**
     * Il pannello non ha ancora un amministratore. La pagina non lo crea: chi la raggiungesse per
     * primo diventerebbe amministratore. Mostra il comando da lanciare sul server (--create-admin),
     * che crea il primo superadmin e stampa un codice di accesso monouso.
     */
    public static String getSetupHtml() {
        return """
<!DOCTYPE html>
<html lang="{{lang}}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{t:su.pageTitle}} - FreeBSD Mail Panel</title>
    <script src="/i18n/{{lang}}.js?v={{i18nVersion}}"></script>
    <link href="/vendor/bootstrap.min.css" rel="stylesheet">
    <link href="/fa/css/all.min.css" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #16213e 0%, #0f3460 50%, #1a1a2e 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 72px 16px 24px;
        }
        /* La lingua, in alto a destra sul fondo scuro: su un riquadro chiaro, per leggerla. */
        .setup-lang { position: fixed; top: 15px; right: 15px; background: #fff; border-radius: .375rem; padding: 2px; z-index: 1000; }
        .setup-card {
            background: #fff;
            color: #212529;
            border-radius: 15px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
            padding: 32px;
            max-width: 560px;
            width: 100%;
        }
        .setup-header { text-align: center; margin-bottom: 24px; }
        .setup-header i { font-size: 3rem; color: #e94560; margin-bottom: 15px; }
        /* Il comando si legge e si copia per intero, anche sul telefono: va a capo invece di uscire. */
        .setup-cmd {
            background: #1a1a2e; color: #e6e6e6; border-radius: 8px; padding: 12px 14px;
            font-size: .95rem; white-space: pre-wrap; word-break: break-word; margin: 0 0 1rem;
        }
        .setup-cmd var { color: #ffb4c1; font-style: normal; }
        .btn-setup { background: linear-gradient(90deg, #e94560 0%, #0f3460 100%); border: none; color: #fff; padding: 12px 30px; }
        .btn-setup:hover, .btn-setup:focus { opacity: 0.9; color: #fff; }
    </style>
</head>
<body>
    <div class="setup-lang">{{LANGUAGE_SWITCH}}</div>
    <main class="setup-card">
        <div class="setup-header">
            <i class="fas fa-user-shield" aria-hidden="true"></i>
            <h1 class="h2">FreeBSD Mail Panel</h1>
            <p class="text-muted mb-0">{{t:su.pageTitle}}</p>
        </div>
        <p>{{t:su.noAdmin}}</p>
        <p class="mb-2">{{t:su.runOnServer}}</p>
        <pre class="setup-cmd" id="setupCommand"><code>java -jar freebsd-mail-panel-1.0.jar --create-admin <var>{{t:su.argName}}</var> <var>{{t:su.argEmail}}</var></code></pre>
        <p class="small text-muted">{{t:su.example.html}}</p>
        <p>{{t:su.thenCode}}</p>
        <a href="/index" class="btn btn-setup w-100" id="setupDone">
            <i class="fas fa-right-to-bracket me-2" aria-hidden="true"></i>{{t:su.goToLogin}}
        </a>
    </main>
    <input type="hidden" id="csrf_token" value="{{CSRF_TOKEN}}">
    <script src="/vendor/bootstrap.bundle.min.js"></script>
</body>
</html>
""";
    }

    // ============== HOME.HTML ==============
    public static String getHomeHtml() {
        String extraStyles = """
        .welcome-banner { background: linear-gradient(135deg, #e94560 0%, #0f3460 100%); color: #ffffff; padding: 20px; border-radius: 10px; margin-bottom: 30px; }
        .action-btn { padding: 0.25rem 0.5rem; font-size: 0.875rem; line-height: 1.5; border-radius: 0.2rem; margin-right: 5px; }
        """;
        return getHead("nav.home", "home", extraStyles) + """
    <div id="main" tabindex="-1" class="content container mt-4">
        <div class="content-container">
            <div class="welcome-banner">
                <h2><i class="fas fa-envelope-open-text me-2" aria-hidden="true"></i>Mail Server Dashboard</h2>
                <p class="mb-0">{{t:home.subtitle}}</p>
            </div>

            <!-- CRITICAL DNS SETUP WARNING -->
            <!-- Parte NASCOSTO: si apre solo se la verifica dice che il record A non va.
                 Senza display:none inline lampeggerebbe in rosso a ogni caricamento, prima
                 che il JS lo chiuda: un allarme che compare e sparisce e' comunque un allarme
                 che hai letto. -->
            <div class="alert alert-danger mt-4" id="dnsSetupWarning" style="display:none;">
                <h5><i class="fas fa-exclamation-triangle me-2" aria-hidden="true"></i>{{t:home.dnsEssential}}</h5>
                <p class="mb-2">{{t:home.dnsFirst.html}}</p>
                <div class="bg-white p-3 rounded border mb-3">
                    <table class="table table-sm mb-0">
                        <tr><td width="150"><strong>{{t:home.cfDomain}}</strong></td><td><code id="mailServerDomain">-</code></td></tr>
                        <tr><td><strong>Type:</strong></td><td>A</td></tr>
                        <tr><td><strong>Name:</strong></td><td><code id="mailServerSubdomain">mail</code></td></tr>
                        <tr><td><strong>IPv4 address:</strong></td><td><code id="serverIpDisplay">-</code></td></tr>
                        <tr><td><strong>Proxy status:</strong></td><td><span class="text-danger"><strong>{{t:home.dnsOnlyGrey}}</strong></span></td></tr>
                        <tr><td><strong>TTL:</strong></td><td>Auto</td></tr>
                    </table>
                </div>
                <div class="alert alert-warning mb-0">
                    <i class="fas fa-info-circle me-2"></i>
                    {{t:home.dnsUseless.html}}
                    {{t:home.hostnameMustPoint}} <code id="mailHostnameDisplay">-</code><br>
                    <small class="text-muted">{{t:home.cfAddA}}</small>
                </div>
            </div>

            <!-- SSL CERTIFICATE MISMATCH WARNING -->
            <div class="alert alert-danger mt-3" id="sslMismatchWarning" style="display:none;">
                <h5><i class="fas fa-shield-alt me-2" aria-hidden="true"></i>{{t:home.sslMismatch}}</h5>
                <p class="mb-1">{{t:home.sslIssuedFor}} <strong><code id="sslCnDisplay">-</code></strong></p>
                <p class="mb-1">{{t:home.sslExpected}} <strong><code id="sslExpectedDisplay">-</code></strong></p>
                <p class="mb-1">{{t:home.sslClients}}</p>
                <hr>
                <p class="mb-0">
                    <i class="fas fa-arrow-right me-2" aria-hidden="true"></i><a href="/ssl"><strong>{{t:nav.ssl}}</strong></a>: {{t:home.sslGenerate}} <code id="sslNewHostDisplay">-</code>
                </p>
            </div>

            <!-- DNS VERIFICATION STATUS -->
            <div class="card mt-3 mb-4" id="dnsVerificationCard" style="display:none;">
                <div class="card-header" id="dnsVerificationHeader">
                    <i class="fas fa-stethoscope me-2" aria-hidden="true"></i>{{t:home.dnsLive}}
                </div>
                <div class="card-body">
                    <div id="dnsVerificationLoading" class="text-center py-2">
                        <i class="fas fa-spinner fa-spin me-2" aria-hidden="true"></i>{{t:home.dnsChecking}}
                    </div>
                    <div id="dnsVerificationResults" style="display:none;">
                        <table class="table table-sm mb-2">
                            <thead><tr><th>Record</th><th>{{t:home.colName}}</th><th>{{t:home.colCurrent}}</th><th>{{t:home.colExpected}}</th><th>{{t:home.colState}}</th></tr></thead>
                            <tbody id="dnsVerificationBody"></tbody>
                        </table>
                        <div id="dnsVerificationSummary"></div>
                        <button class="btn btn-outline-primary btn-sm mt-2" onclick="runDnsVerification()">
                            <i class="fas fa-sync me-1" aria-hidden="true"></i>{{t:home.recheck}}
                        </button>
                    </div>
                </div>
            </div>

            <h3><i class="fas fa-chart-line me-2" aria-hidden="true"></i>{{t:home.overview}}</h3>
            <div class="row">
                <div class="col-md-4 mb-3">
                    <div class="card stat-card"><div class="card-body"><h5 class="card-title"><i class="fas fa-globe me-2" aria-hidden="true"></i>{{t:nav.domains}}</h5><p class="card-text" id="domainCount">{{t:home.total}} -</p></div></div>
                </div>
                <div class="col-md-4 mb-3">
                    <div class="card stat-card"><div class="card-body"><h5 class="card-title"><i class="fas fa-inbox me-2" aria-hidden="true"></i>{{t:nav.mailboxes}}</h5><p class="card-text" id="mailboxCount">{{t:home.total}} -</p></div></div>
                </div>
                <div class="col-md-4 mb-3">
                    <div class="card stat-card"><div class="card-body"><h5 class="card-title"><i class="fas fa-share me-2" aria-hidden="true"></i>{{t:nav.aliases}}</h5><p class="card-text" id="aliasCount">{{t:home.total}} -</p></div></div>
                </div>
            </div>

            <div class="d-flex justify-content-between align-items-center mt-4 mb-1">
                <h3 class="mb-0"><i class="fas fa-server me-2" aria-hidden="true"></i>{{t:home.services}}</h3>
                <button type="button" class="btn btn-outline-secondary btn-sm" id="versioniRileggi" onclick="loadVersions(true)"><i class="fas fa-sync me-1" aria-hidden="true"></i>{{t:home.rereadVersions}}</button>
            </div>
            <p class="small text-muted mb-2" id="versioniStato" role="status">{{t:home.readingVersions}}</p>
            <div class="table-responsive">
                <table class="table table-hover tabella-schede" aria-label="{{t:home.servicesTable}}">
                    <thead class="table-light"><tr><th scope="col">{{t:home.colService}}</th><th scope="col">{{t:home.colVersion}}</th><th scope="col">{{t:home.colState}}</th><th scope="col">{{t:home.colActions}}</th></tr></thead>
                    <tbody>
""" + serviceLine("postfix", "postfix", "fa-paper-plane", "Postfix (SMTP)", "Postfix")
    + serviceLine("dovecot", "dovecot", "fa-inbox", "Dovecot (IMAP/POP3)", "Dovecot")
    + serviceLine("mysql", "mysql-server", "fa-database", "MySQL (Database)", "MySQL")
    + serviceLine("rspamd", "rspamd", "fa-shield-alt", "Rspamd (Anti-Spam)", "Rspamd")
    + serviceLine("redis", "redis", "fa-memory", "Redis ({{t:home.redisRole}})", "Redis")
    + serviceLine("clamav", "clamav", "fa-bug", "ClamAV (Antivirus)", "ClamAV")
    + serviceLine("roundcube", "roundcube", "fa-envelope-open-text", "Roundcube (Webmail)", "{{t:home.theWebmail}}") + """
                    </tbody>
                </table>
            </div>

            <h3 class="mt-4"><i class="fas fa-cubes me-2" aria-hidden="true"></i>{{t:home.otherSoftware}}</h3>
            <div class="table-responsive">
                <table class="table table-hover tabella-schede" aria-label="{{t:home.otherTable}}">
                    <thead class="table-light"><tr><th scope="col">Software</th><th scope="col">{{t:home.colPurpose}}</th><th scope="col">{{t:home.colVersion}}</th></tr></thead>
                    <tbody id="altroSoftware"><tr><td colspan="3" class="text-muted small">{{t:home.readingVersions}}</td></tr></tbody>
                </table>
            </div>
""" + resource("pages/home-status-card.html") + """
        </div>
    </div>
""" + getFooterSection() + getScriptStart() + """
        // Fermare un servizio (e riavviare MySQL) tocca tutta la posta: prima si chiede, dicendo cosa succede.
        const serviceQuestions = {
            'postfix:stop': t('home.confirm.postfix.stop'),
            'dovecot:stop': t('home.confirm.dovecot.stop'),
            'mysql-server:stop': t('home.confirm.mysql.stop'),
            'mysql-server:restart': t('home.confirm.mysql.restart'),
            'rspamd:stop': t('home.confirm.rspamd.stop'),
            'redis:stop': t('home.confirm.redis.stop'),
            'clamav:stop': t('home.confirm.clamav.stop'),
            'roundcube:stop': t('home.confirm.roundcube.stop')
        };

        function serviceAction(service, action) {
            const question = serviceQuestions[service + ':' + action];
            if (question && !confirm(question)) return;
            fetch('/api/service', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ service: service, action: action, csrf_token: csrfToken })
            })
            .then(r => r.json())
            .then(data => {
                if (data.csrf_token) csrfToken = data.csrf_token;
                alert(data.success ? t('common.done') : t('common.error', { message: data.error || data.message || t('common.unknown') }));
                checkStatus();
                loadVersions(true);
            })
            .catch(() => alert(t('home.noAnswer')));
        }

        function checkStatus() {
            fetch('/api/status').then(r => r.json()).then(data => {
                ['postfix','dovecot','mysql','rspamd','redis','clamav','roundcube'].forEach(svc => {
                    const el = document.getElementById(svc + '-status');
                    if (!el) return;
                    const running = data[svc];
                    el.textContent = running ? t('home.running') : t('home.stopped');
                    el.className = 'badge ' + (running ? 'bg-success' : 'bg-danger');
                });

                // Stats
                document.getElementById('domainCount').textContent = t('home.total') + ' ' + (data.domains || 0);
                document.getElementById('mailboxCount').textContent = t('home.total') + ' ' + (data.mailboxes || 0);
                document.getElementById('aliasCount').textContent = t('home.total') + ' ' + (data.aliases || 0);

                // DNS Warning on home page - populate mail server hostname and IP
                const mailHostname = data.mail_hostname || '';
                const serverIp = data.server_ip || '';
                const dnsWarning = document.getElementById('dnsSetupWarning');

                if (mailHostname && serverIp) {
                    const dotIndex = mailHostname.indexOf('.');
                    let subdomain = 'mail';
                    let parentDomain = mailHostname;
                    if (dotIndex > 0) {
                        subdomain = mailHostname.substring(0, dotIndex);
                        parentDomain = mailHostname.substring(dotIndex + 1);
                    }

                    document.getElementById('mailServerDomain').textContent = parentDomain;
                    document.getElementById('mailServerSubdomain').textContent = subdomain;
                    document.getElementById('serverIpDisplay').textContent = serverIp;
                    document.getElementById('mailHostnameDisplay').textContent = mailHostname;
                    // I campi si riempiono, ma il riquadro NON si mostra ancora: prima si guarda
                    // com'e' il DNS davvero. Mostrarlo sempre voleva dire gridare "se non
                    // configuri questo, tutto il resto e' INUTILE" anche a chi lo aveva gia'
                    // configurato, contraddicendo la card verde due centimetri piu' sotto.
                    // Chi legge non sa piu' a quale dei due messaggi credere.
                    dnsWarning.style.display = 'none';
                } else {
                    dnsWarning.style.display = 'none';
                }

                // SSL Certificate Mismatch Warning
                const sslWarning = document.getElementById('sslMismatchWarning');
                if (data.ssl_match === false && mailHostname) {
                    const sslCn = data.ssl_cn || t('home.selfSigned');
                    document.getElementById('sslCnDisplay').textContent = sslCn;
                    document.getElementById('sslExpectedDisplay').textContent = mailHostname;
                    document.getElementById('sslNewHostDisplay').textContent = mailHostname;
                    sslWarning.style.display = 'block';
                } else {
                    sslWarning.style.display = 'none';
                }

                // Auto-run DNS verification if hostname is configured
                if (mailHostname) {
                    runDnsVerification();
                }
            });
        }

        function runDnsVerification() {
            const card = document.getElementById('dnsVerificationCard');
            const loading = document.getElementById('dnsVerificationLoading');
            const results = document.getElementById('dnsVerificationResults');
            card.style.display = 'block';
            loading.style.display = 'block';
            results.style.display = 'none';

            fetch('/api/hostname', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'check_dns', csrf_token: '{{CSRF_TOKEN}}' })
            })
            .then(r => r.json())
            .then(data => {
                loading.style.display = 'none';
                results.style.display = 'block';

                if (!data.success) {
                    // Non si e' potuto guardare: si dice questo, non "il DNS e' sbagliato".
                    // Un controllo che non ha funzionato non e' una diagnosi.
                    document.getElementById('dnsVerificationBody').innerHTML =
                        '<tr><td colspan="5" class="text-danger">'
                        + escHtml(t('home.dnsNotChecked', { error: data.error || t('common.unknownError') }))
                        + ' <a href="/dns">DNS</a></td></tr>';
                    return;
                }

                // Render results table
                const tbody = document.getElementById('dnsVerificationBody');
                tbody.innerHTML = data.checks.map(c => {
                    const icon = c.passed
                        ? '<i class="fas fa-check-circle text-success" role="img" aria-label="' + escHtml(t('home.ok')) + '"></i>'
                        : '<i class="fas fa-times-circle text-danger" role="img" aria-label="' + escHtml(t('home.wrong')) + '"></i>';
                    return '<tr>' +
                        '<td><code>' + escHtml(c.type) + '</code></td>' +
                        '<td><small>' + escHtml(c.name) + '</small></td>' +
                        '<td><small><code>' + escHtml(c.current) + '</code></small></td>' +
                        '<td><small><code>' + escHtml(c.expected) + '</code></small></td>' +
                        '<td class="text-center">' + icon + '</td></tr>';
                }).join('');

                // Summary and card header color
                const header = document.getElementById('dnsVerificationHeader');
                const summary = document.getElementById('dnsVerificationSummary');
                const hostname = data.hostname || '';
                const domain = hostname.indexOf('.') > 0 ? hostname.substring(hostname.indexOf('.') + 1) : hostname;
                const subdomain = hostname.indexOf('.') > 0 ? hostname.substring(0, hostname.indexOf('.')) : hostname;

                const noticeText = document.getElementById('dnsSetupWarning');

                if (data.all_passed) {
                    if (noticeText) noticeText.style.display = 'none';
                    header.className = 'card-header bg-success text-white';
                    header.innerHTML = '<i class="fas fa-check-circle me-2" aria-hidden="true"></i>' + escHtml(t('home.dnsOk'));
                    summary.innerHTML = '<div class="alert alert-success mb-0 py-2">' +
                        '<i class="fas fa-check-circle me-2" aria-hidden="true"></i>' + escHtml(t('home.dnsAllOk')) + '<br>' +
                        '<small class="mt-1 d-block"><i class="fas fa-arrow-right me-1" aria-hidden="true"></i>' + escHtml(t('home.dnsFullRecords')) + ' ' +
                        '<a href="/dns" class="fw-bold">DNS</a></small></div>';
                } else {
                    header.className = 'card-header bg-danger text-white';
                    header.innerHTML = '<i class="fas fa-exclamation-triangle me-2" aria-hidden="true"></i>' + escHtml(t('home.dnsToFix'));
                    const failed = data.checks.filter(c => !c.passed);
                    // Le istruzioni per il record A si mostrano quando e' il record A a
                    // mancare, non ogni volta che un qualsiasi record opzionale non c'e'.
                    if (noticeText) noticeText.style.display = failed.some(c => c.type === 'A') ? 'block' : 'none';
                    let advice = '';

                    failed.forEach(c => {
                        if (c.type === 'A') {
                            advice += '<div class="card border-danger mb-2"><div class="card-body py-2 px-3">' +
                                '<h6 class="text-danger mb-2"><i class="fas fa-times-circle me-1" aria-hidden="true"></i>' + escHtml(t('home.aMissing')) + '</h6>' +
                                '<p class="mb-1">' + t('home.aWhat.html') + '</p>' +
                                '<table class="table table-sm table-bordered mb-2" style="max-width:500px">' +
                                '<tr><td width="100"><strong>Type</strong></td><td><code>A</code></td></tr>' +
                                '<tr><td><strong>Name</strong></td><td><code>' + escHtml(subdomain) + '</code></td></tr>' +
                                '<tr><td><strong>IPv4</strong></td><td><code>' + escHtml(c.expected) + '</code></td></tr>' +
                                '<tr><td><strong>Proxy</strong></td><td><span class="text-danger fw-bold">' + escHtml(t('home.dnsOnlyGrey')) + '</span></td></tr>' +
                                '<tr><td><strong>TTL</strong></td><td>Auto</td></tr>' +
                                '</table>' +
                                '<small class="text-muted"><i class="fas fa-info-circle me-1" aria-hidden="true"></i>' + t('home.cfPathRecord.html', { domain: escHtml(domain) }) + '</small>' +
                                '</div></div>';
                        } else if (c.type === 'MX') {
                            advice += '<div class="card border-danger mb-2"><div class="card-body py-2 px-3">' +
                                '<h6 class="text-danger mb-2"><i class="fas fa-times-circle me-1" aria-hidden="true"></i>' + escHtml(t('home.mxMissing')) + '</h6>' +
                                '<p class="mb-1">' + t('home.mxWhat.html') + '</p>' +
                                '<table class="table table-sm table-bordered mb-2" style="max-width:500px">' +
                                '<tr><td width="100"><strong>Type</strong></td><td><code>MX</code></td></tr>' +
                                '<tr><td><strong>Name</strong></td><td>' + t('home.mxName.html', { name: escHtml(c.name) }) + '</td></tr>' +
                                '<tr><td><strong>Server</strong></td><td><code>' + escHtml(hostname) + '</code></td></tr>' +
                                '<tr><td><strong>' + escHtml(t('home.priority')) + '</strong></td><td><code>10</code></td></tr>' +
                                '<tr><td><strong>TTL</strong></td><td>Auto</td></tr>' +
                                '</table>' +
                                '<small class="text-muted"><i class="fas fa-info-circle me-1" aria-hidden="true"></i>' + t('home.cfPathMx.html', { domain: escHtml(c.name) }) + '</small>' +
                                '</div></div>';
                        } else if (c.type === 'PTR') {
                            advice += '<div class="card border-warning mb-2"><div class="card-body py-2 px-3">' +
                                '<h6 class="text-warning mb-2"><i class="fas fa-exclamation-triangle me-1" aria-hidden="true"></i>' + escHtml(t('home.ptrMissing')) + '</h6>' +
                                '<p class="mb-1">' + t('home.ptrWhat.html') + '</p>' +
                                '<table class="table table-sm table-bordered mb-2" style="max-width:500px">' +
                                '<tr><td width="100"><strong>IP</strong></td><td><code>' + escHtml(c.name) + '</code></td></tr>' +
                                '<tr><td><strong>PTR</strong></td><td><code>' + escHtml(hostname) + '</code></td></tr>' +
                                '</table>' +
                                '<p class="mb-0"><strong>' + escHtml(t('home.ptrHow')) + '</strong></p>' +
                                '<ul class="mb-0 small">' +
                                '<li><strong>Hetzner:</strong> Cloud Console &rarr; Server &rarr; Networking &rarr; Reverse DNS &rarr; Edit</li>' +
                                '<li><strong>OVH:</strong> Manager &rarr; Server &rarr; IP &rarr; ' + escHtml(t('home.ptrOvh')) + '</li>' +
                                '<li><strong>DigitalOcean:</strong> ' + t('home.ptrDo.html', { host: escHtml(hostname) }) + '</li>' +
                                '<li><strong>Vultr:</strong> Products &rarr; Server &rarr; Settings &rarr; IPv4 &rarr; Reverse DNS</li>' +
                                '<li><strong>Contabo:</strong> Customer Control Panel &rarr; Reverse DNS Management</li>' +
                                '</ul>' +
                                '</div></div>';
                        }
                    });

                    advice += '<div class="mt-2">' +
                        '<a href="/dns" class="btn btn-primary btn-sm"><i class="fas fa-list me-1" aria-hidden="true"></i>' + escHtml(t('home.allRecords')) + '</a>' +
                        '</div>';

                    summary.innerHTML = advice;
                }

                // Also check Roundcube domain DNS
                checkRoundcubeDomainDns();
            })
            .catch(() => {
                loading.style.display = 'none';
                results.style.display = 'block';
                document.getElementById('dnsVerificationBody').innerHTML =
                    '<tr><td colspan="5" class="text-muted">' + escHtml(t('home.dnsUnavailable')) + ' <a href="/dns">DNS</a></td></tr>';
            });
        }

        function checkRoundcubeDomainDns() {
            fetch('/api/roundcube-domain')
                .then(r => r.json())
                .then(data => {
                    if (!data.success || !data.domain || data.domain === t('server.notConfigured') || data.domain === '') return;
                    const tbody = document.getElementById('dnsVerificationBody');
                    let icon, expectedCol;
                    if (data.dns_ok && data.dns_proxied) {
                        icon = '<i class="fas fa-cloud text-info" role="img" title="Proxy/CDN" aria-label="Proxy/CDN"></i>';
                        expectedCol = escapeHtml(data.server_ip || t('home.serverIp')) + ' <small class="text-muted">(proxy OK)</small>';
                    } else if (data.dns_ok) {
                        icon = '<i class="fas fa-check-circle text-success" role="img" aria-label="' + escHtml(t('home.ok')) + '"></i>';
                        expectedCol = escapeHtml(data.server_ip || t('home.serverIp'));
                    } else {
                        icon = '<i class="fas fa-times-circle text-danger" role="img" aria-label="' + escHtml(t('home.wrong')) + '"></i>';
                        expectedCol = escapeHtml(data.server_ip || t('home.serverIp'));
                    }
                    tbody.innerHTML += '<tr>' +
                        '<td><code>A</code> <small class="text-muted">(Webmail)</small></td>' +
                        '<td><small>' + escapeHtml(data.domain) + '</small></td>' +
                        '<td><small><code>' + escapeHtml(data.dns_result || t('home.notFound')) + '</code></small></td>' +
                        '<td><small><code>' + expectedCol + '</code></small></td>' +
                        '<td class="text-center">' + icon + '</td></tr>';

                    if (!data.dns_ok) {
                        const summary = document.getElementById('dnsVerificationSummary');
                        const rcSub = data.domain.indexOf('.') > 0 ? data.domain.substring(0, data.domain.indexOf('.')) : data.domain;
                        const rcBaseDomain = data.domain.indexOf('.') > 0 ? data.domain.substring(data.domain.indexOf('.') + 1) : data.domain;
                        summary.innerHTML += '<div class="card border-danger mb-2 mt-2"><div class="card-body py-2 px-3">' +
                            '<h6 class="text-danger mb-2"><i class="fas fa-envelope-open-text me-1" aria-hidden="true"></i>' + escHtml(t('home.rcMissing')) + '</h6>' +
                            '<p class="mb-1">' + t('home.rcWhat.html') + '</p>' +
                            '<table class="table table-sm table-bordered mb-2" style="max-width:500px">' +
                            '<tr><td width="100"><strong>Type</strong></td><td><code>A</code></td></tr>' +
                            '<tr><td><strong>Name</strong></td><td><code>' + escHtml(rcSub) + '</code></td></tr>' +
                            '<tr><td><strong>IPv4</strong></td><td><code>' + escapeHtml(data.server_ip || 'IP_SERVER') + '</code></td></tr>' +
                            '<tr><td><strong>Proxy</strong></td><td>' + escHtml(t('home.rcProxy')) + '</td></tr>' +
                            '<tr><td><strong>TTL</strong></td><td>Auto</td></tr>' +
                            '</table>' +
                            '<small class="text-muted"><i class="fas fa-info-circle me-1" aria-hidden="true"></i>' + t('home.cfPathRecord.html', { domain: escHtml(rcBaseDomain) }) + '</small>' +
                            '</div></div>';

                        // Update header to danger if not already
                        const header = document.getElementById('dnsVerificationHeader');
                        if (!header.className.includes('bg-danger')) {
                            header.className = 'card-header bg-danger text-white';
                            header.innerHTML = '<i class="fas fa-exclamation-triangle me-2" aria-hidden="true"></i>' + escHtml(t('home.dnsToFix'));
                        }
                    }
                })
                .catch(() => {});
        }

        checkStatus();
""" + getVersionsJs() + resource("pages/home-status.js") + getScriptEnd();
    }

    /**
     * Una riga di "Servizi Mail" nella Home: il nome, la versione (la scrive caricaVersioni), lo
     * stato (checkStatus) e i tre comandi, con il loro nome per chi usa un lettore di schermo.
     * Una definizione sola per tutte le righe.
     */
    private static String serviceLine(String key, String service, String icon, String name, String chi) {
        return """
                        <tr>
                            <td data-label="{{t:home.colService}}" class="text-nowrap"><i class="fas %s me-2" aria-hidden="true"></i>%s</td>
                            <td data-label="{{t:home.colVersion}}" id="ver-%s"><span class="small text-muted">{{t:home.reading}}</span></td>
                            <td data-label="{{t:home.colState}}"><span class="badge bg-secondary" id="%s-status">-</span></td>
                            <td data-label="{{t:home.colActions}}" class="text-nowrap">
                                <button type="button" class="btn btn-success action-btn" onclick="serviceAction('%s','start')" aria-label="{{t:home.start}} %s" title="{{t:home.start}}"><i class="fas fa-play" aria-hidden="true"></i></button>
                                <button type="button" class="btn btn-warning action-btn" onclick="serviceAction('%s','restart')" aria-label="{{t:home.restart}} %s" title="{{t:home.restart}}"><i class="fas fa-redo" aria-hidden="true"></i></button>
                                <button type="button" class="btn btn-danger action-btn" onclick="serviceAction('%s','stop')" aria-label="{{t:home.stop}} %s" title="{{t:home.stop}}"><i class="fas fa-stop" aria-hidden="true"></i></button>
                            </td>
                        </tr>
""".formatted(icon, name, key, key, service, chi, service, chi, service, chi);
    }

    /**
     * Le versioni nella Home (SoftwareVersions sul server): la colonna Versione di "Servizi Mail"
     * e la tabella "Altro software". Tutto con textContent: le versioni arrivano da programmi e
     * file del server, e non devono poter diventare HTML.
     */
    private static String getVersionsJs() {
        return """
        // ===== Versioni del software (SoftwareVersions sul server) =====
        function verCell(cell, v) {
            cell.textContent = '';
            if (!v || !v.installed) {
                const n = document.createElement('span');
                n.className = 'text-muted';
                n.textContent = t('ver.notInstalled');
                cell.appendChild(n);
                return;
            }
            const lineItem = document.createElement('div');
            const num = document.createElement('strong');
            num.textContent = v.version || t('ver.notRead');
            if (v.source) num.title = t('ver.readWith', { source: v.source });
            lineItem.appendChild(num);
            if (v.running) {
                const e = document.createElement('span');
                e.className = 'small text-muted ms-1';
                e.textContent = t('ver.running');
                lineItem.appendChild(e);
            }
            if (v.restart) {
                const b = document.createElement('span');
                b.className = 'badge bg-warning text-dark ms-1';
                b.textContent = t('ver.restartNeeded');
                lineItem.appendChild(b);
            }
            cell.appendChild(lineItem);
            [[v.detail, 'small text-muted'], [v.pkgName ? t('ver.package', { name: v.pkgName }) : '', 'small text-muted'],
             [v.restartNote, 'small testo-avviso'], [v.warning, 'small testo-rischio']].forEach(([textValue, cssClass]) => {
                if (!textValue) return;
                const d = document.createElement('div');
                d.className = cssClass;
                d.textContent = textValue;
                cell.appendChild(d);
            });
        }

        function loadVersions(freshRead) {
            const stateValue = document.getElementById('versioniStato');
            const btn = document.getElementById('versioniRileggi');
            btn.disabled = true;
            stateValue.textContent = t('home.readingVersions');
            fetch('/api/versioni' + (freshRead ? '?fresco=1' : '')).then(r => r.json()).then(d => {
                btn.disabled = false;
                if (!d.success) {
                    stateValue.textContent = t('ver.readFailed', { error: d.error || t('common.unknownError') });
                    return;
                }
                Object.keys(d.services).forEach(k => {
                    const cell = document.getElementById('ver-' + k);
                    if (cell) verCell(cell, d.services[k]);
                });
                const bodyText = document.getElementById('altroSoftware');
                bodyText.textContent = '';
                d.other.forEach(v => {
                    const tr = document.createElement('tr');
                    const entryName = document.createElement('td');
                    entryName.setAttribute('data-label', 'Software');
                    const strongEl = document.createElement('strong');
                    strongEl.textContent = v.name;
                    entryName.appendChild(strongEl);
                    const roleName = document.createElement('td');
                    roleName.setAttribute('data-label', t('home.colPurpose'));
                    roleName.textContent = v.role;
                    const ver = document.createElement('td');
                    ver.setAttribute('data-label', t('home.colVersion'));
                    verCell(ver, v);
                    tr.append(entryName, roleName, ver);
                    bodyText.appendChild(tr);
                });
                const toRestart = Object.values(d.services).concat(d.other).filter(v => v.restart).length;
                stateValue.textContent = t('ver.readAt', { time: d.readAt.substring(11, 19) })
                    + (toRestart > 0 ? ' ' + tn('ver.toRestart', toRestart) : '');
                if (d.branch) {
                    // Da quale ramo arrivano i pacchetti: lo si cambia in Aggiornamenti.
                    stateValue.appendChild(document.createTextNode(' ' + t('ver.branch') + ' '));
                    const a = document.createElement('a');
                    a.href = '/updates#ramo';
                    a.textContent = d.branch === 'mixed' ? t('ver.branchMixed') : d.branch === 'none' ? t('ver.branchNone') : d.branch;
                    stateValue.appendChild(a);
                    stateValue.appendChild(document.createTextNode('.'));
                }
            }).catch(() => {
                btn.disabled = false;
                stateValue.textContent = t('ver.noAnswer');
            });
        }
        loadVersions(false);
""";
    }

    // ============== DOMAINS.HTML ==============
    public static String getDomainsHtml() {
        return getHead("nav.domains", "domains", "") + """
    <div id="main" tabindex="-1" class="content container mt-4">
        <div class="content-container">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h2><i class="fas fa-globe me-2" aria-hidden="true"></i>{{t:dom.title}}</h2>
                <button class="btn btn-mail" data-bs-toggle="modal" data-bs-target="#addDomainModal"><i class="fas fa-plus me-1" aria-hidden="true"></i>{{t:dom.add}}</button>
            </div>

            <div class="table-responsive">
                <table class="table table-hover tabella-schede">
                    <thead class="table-light">
                        <tr><th>{{t:dom.colDomain}}</th><th>{{t:dom.colDesc}}</th><th>{{t:nav.mailboxes}}</th><th>{{t:nav.aliases}}</th><th>DKIM</th><th>{{t:home.colActions}}</th></tr>
                    </thead>
                    <tbody id="domainsTable">
                        <tr><td colspan="6" class="text-center">{{t:common.loading}}</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Add Domain Modal -->
    <div class="modal fade" id="addDomainModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header"><h5 class="modal-title">{{t:dom.add}}</h5><button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="{{t:common.close}}"></button></div>
                <div class="modal-body">
                    <form id="addDomainForm">
                        <div class="mb-3">
                            <label class="form-label" for="domainName">{{t:dom.name}}</label>
                            <input type="text" class="form-control" id="domainName" placeholder="example.com" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label" for="domainDesc">{{t:dom.descOptional}}</label>
                            <input type="text" class="form-control" id="domainDesc" placeholder="{{t:dom.descPh}}">
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">{{t:common.cancel}}</button>
                    <button type="button" class="btn btn-mail" onclick="addDomain()">{{t:common.add}}</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Edit Description Modal -->
    <div class="modal fade" id="editDescModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header"><h5 class="modal-title"><i class="fas fa-edit me-2" aria-hidden="true"></i>{{t:dom.editDesc}}</h5><button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="{{t:common.close}}"></button></div>
                <div class="modal-body">
                    <input type="hidden" id="editDomainId">
                    <div class="mb-3">
                        <label class="form-label" for="editDomainName">{{t:dom.colDomain}}</label>
                        <input type="text" class="form-control" id="editDomainName" readonly disabled>
                    </div>
                    <div class="mb-3">
                        <label class="form-label" for="editDomainDesc">{{t:dom.colDesc}}</label>
                        <input type="text" class="form-control" id="editDomainDesc" placeholder="{{t:dom.descPh}}">
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">{{t:common.cancel}}</button>
                    <button type="button" class="btn btn-mail" onclick="saveDomainDesc()">{{t:common.save}}</button>
                </div>
            </div>
        </div>
    </div>

""" + getFooterSection() + """
    <script>
        let csrfToken = document.getElementById('csrf_token').value;

        function loadDomains() {
            fetch('/api/domains').then(r => r.json()).then(data => {
                const tbody = document.getElementById('domainsTable');
                if (!data.domains || data.domains.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" class="text-center">' + escDom(t('dom.none')) + '</td></tr>';
                    return;
                }
                // L'elenco si conserva: cosi' i pulsanti passano un id e vanno a prendersi il
                // record, invece di ricevere il testo infilato dentro un attributo HTML.
                currentDomains = data.domains;
                tbody.innerHTML = data.domains.map(d => `
                    <tr>
                        <td data-label="${escDom(t('dom.colDomain'))}" class="testo-lungo"><strong>${escDom(d.domain)}</strong></td>
                        <td data-label="${escDom(t('dom.colDesc'))}">${escDom(d.description || '-')}</td>
                        <td data-label="${escDom(t('nav.mailboxes'))}"><span class="badge bg-info">${d.mailbox_count || 0}</span></td>
                        <td data-label="${escDom(t('nav.aliases'))}"><span class="badge bg-info">${d.alias_count || 0}</span></td>
                        <td data-label="DKIM">${d.has_dkim ? '<span class="badge bg-success">' + escDom(t('dom.dkimOn')) + '</span>' : '<span class="badge bg-warning text-dark">' + escDom(t('dom.dkimOff')) + '</span>'}</td>
                        <td data-label="${escDom(t('home.colActions'))}">
                            <button class="btn btn-sm btn-secondary" onclick="editDomain(${d.id})" title="${escDom(t('dom.editDesc'))}" aria-label="${escDom(t('dom.editDescOf', { domain: d.domain }))}"><i class="fas fa-edit" aria-hidden="true"></i></button>
                            <button class="btn btn-sm btn-primary" onclick="viewDnsById(${d.id})"><i class="fas fa-server" aria-hidden="true"></i> DNS</button>
                            <button class="btn btn-sm btn-danger" onclick="deleteDomain(${d.id})" title="${escDom(t('common.delete'))}" aria-label="${escDom(t('dom.deleteOf', { domain: d.domain }))}"><i class="fas fa-trash" aria-hidden="true"></i></button>
                        </td>
                    </tr>
                `).join('');
            });
        }

        function addDomain() {
            const domain = document.getElementById('domainName').value;
            const desc = document.getElementById('domainDesc').value;
            fetch('/api/domains', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain: domain, description: desc, csrf_token: csrfToken })
            }).then(r => r.json()).then(data => {
                if (data.success) {
                    bootstrap.Modal.getInstance(document.getElementById('addDomainModal')).hide();
                    loadDomains();
                } else {
                    alert(t('common.error', { message: data.error || t('common.unknown') }));
                }
            });
        }

        function deleteDomain(id) {
            if (!confirm(t('dom.confirmDelete'))) return;
            fetch('/api/domains?id=' + id, { method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ csrf_token: csrfToken }) })
                .then(() => loadDomains());
        }

        function viewDns(domain) {
            window.location.href = '/dns?domain=' + domain;
        }

        // La descrizione finiva dentro un attributo onclick racchiuso fra virgolette doppie,
        // protetta soltanto dall'apice: bastava una virgoletta doppia nella descrizione per
        // uscire dall'attributo e far eseguire codice nella sessione di un altro
        // amministratore. Ora il pulsante passa un id e il testo non attraversa piu' l'HTML.
        let currentDomains = [];

        function escDom(v) {
            const d = document.createElement('div');
            d.textContent = v === null || v === undefined ? '' : String(v);
            return d.innerHTML;
        }

        function findDomain(id) {
            return (currentDomains || []).find(x => x.id === id) || null;
        }

        function editDomain(id) {
            const d = findDomain(id);
            if (!d) return;
            document.getElementById('editDomainId').value = d.id;
            document.getElementById('editDomainName').value = d.domain;
            document.getElementById('editDomainDesc').value = d.description || '';
            new bootstrap.Modal(document.getElementById('editDescModal')).show();
        }

        function viewDnsById(id) {
            const d = findDomain(id);
            if (d) viewDns(d.domain);
        }

        function saveDomainDesc() {
            const id = document.getElementById('editDomainId').value;
            const desc = document.getElementById('editDomainDesc').value;
            fetch('/api/domains', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ id: parseInt(id), description: desc, csrf_token: csrfToken })
            }).then(r => r.json()).then(data => {
                if (data.success) {
                    bootstrap.Modal.getInstance(document.getElementById('editDescModal')).hide();
                    loadDomains();
                } else {
                    alert(t('common.error', { message: data.error || t('common.unknown') }));
                }
            });
        }

""" + """
        loadDomains();
    </script>
</body>
</html>
""";
    }

    // ============== MAILBOXES.HTML ==============
    /**
     * Modal "Configurazione Client Email" — credenziali + server IMAP/SMTP/POP3,
     * con bottoni copia per ogni campo e reveal della password se nel vault.
     */
    private static String getMailConfigModal() {
        return """
    <!-- Mail Client Config Modal -->
    <div class="modal fade" id="mailConfigModal" tabindex="-1">
        <div class="modal-dialog modal-lg modal-dialog-scrollable">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-mobile-alt me-2" aria-hidden="true"></i>{{t:cfg.title}}</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="{{t:common.close}}"></button>
                </div>
                <div class="modal-body">

                    <!-- Box credenziali con copia-incolla ovunque -->
                    <div class="card mb-3 border-primary">
                        <div class="card-header bg-primary text-white"><i class="fas fa-key me-2" aria-hidden="true"></i>{{t:cfg.credentials}}</div>
                        <div class="card-body">
                            <div class="mb-2">
                                <label class="form-label small fw-bold mb-1">{{t:cfg.username}}</label>
                                <div class="input-group input-group-sm">
                                    <input type="text" class="form-control font-monospace" id="cfgEmailField" readonly>
                                    <button class="btn btn-outline-secondary" type="button" onclick="copyInputValue('cfgEmailField')" title="{{t:common.copy}}"><i class="fas fa-copy" aria-hidden="true"></i></button>
                                </div>
                            </div>
                            <div class="mb-2">
                                <label class="form-label small fw-bold mb-1">Password</label>
                                <div class="input-group input-group-sm">
                                    <input type="password" class="form-control font-monospace" id="cfgPasswordField" value="" placeholder="{{t:cfg.passNone}}" readonly>
                                    <button class="btn btn-outline-secondary" type="button" id="cfgPasswordToggleBtn" onclick="toggleCfgPasswordVisibility()" title="{{t:cfg.showHide}}" disabled><i class="fas fa-eye" aria-hidden="true"></i></button>
                                    <button class="btn btn-outline-secondary" type="button" id="cfgPasswordCopyBtn" onclick="copyInputValue('cfgPasswordField')" title="{{t:common.copy}}" disabled><i class="fas fa-copy" aria-hidden="true"></i></button>
                                    <button class="btn btn-warning" type="button" id="cfgPasswordRevealBtn" onclick="revealCfgPassword()" title="{{t:cfg.fromVault}}"><i class="fas fa-unlock me-1" aria-hidden="true"></i>{{t:mbx.reveal}}</button>
                                </div>
                                <small class="text-muted" id="cfgPasswordHint">{{t:mbx.revealHint}}</small>
                            </div>
                        </div>
                    </div>

                    <ul class="nav nav-tabs mb-3" id="configTabs" role="tablist">
                        <li class="nav-item" role="presentation">
                            <button class="nav-link active" data-bs-toggle="tab" data-bs-target="#configGeneral">{{t:cfg.general}}</button>
                        </li>
                        <li class="nav-item" role="presentation">
                            <button class="nav-link" data-bs-toggle="tab" data-bs-target="#configOutlook">Outlook</button>
                        </li>
                        <li class="nav-item" role="presentation">
                            <button class="nav-link" data-bs-toggle="tab" data-bs-target="#configApple">iPhone/Mac</button>
                        </li>
                        <li class="nav-item" role="presentation">
                            <button class="nav-link" data-bs-toggle="tab" data-bs-target="#configAndroid">Android</button>
                        </li>
                    </ul>

                    <div class="tab-content">
                        <!-- ===== Tab GENERALE ===== -->
                        <div class="tab-pane fade show active" id="configGeneral">
                            <h6 class="mb-2 text-success"><i class="fas fa-inbox me-1" aria-hidden="true"></i>{{t:cfg.inImap}}</h6>
                            <div class="row g-2 mb-3">
                                <div class="col-md-8"><label class="form-label small mb-1">Server</label>
                                    <div class="input-group input-group-sm"><input type="text" class="form-control font-monospace" id="cfgImapServer" readonly><button class="btn btn-outline-secondary" onclick="copyInputValue('cfgImapServer')"><i class="fas fa-copy" aria-hidden="true"></i></button></div>
                                </div>
                                <div class="col-md-2"><label class="form-label small mb-1">{{t:cfg.port}}</label>
                                    <div class="input-group input-group-sm"><input type="text" class="form-control" value="993" id="cfgImapPort" readonly><button class="btn btn-outline-secondary" onclick="copyInputValue('cfgImapPort')"><i class="fas fa-copy" aria-hidden="true"></i></button></div>
                                </div>
                                <div class="col-md-2"><label class="form-label small mb-1">{{t:cfg.security}}</label>
                                    <input type="text" class="form-control form-control-sm" value="SSL/TLS" readonly>
                                </div>
                            </div>

                            <h6 class="mb-2 text-secondary"><i class="fas fa-inbox me-1" aria-hidden="true"></i>{{t:cfg.inPop}}</h6>
                            <div class="row g-2 mb-3">
                                <div class="col-md-8"><label class="form-label small mb-1">Server</label>
                                    <div class="input-group input-group-sm"><input type="text" class="form-control font-monospace" id="cfgPop3Server" readonly><button class="btn btn-outline-secondary" onclick="copyInputValue('cfgPop3Server')"><i class="fas fa-copy" aria-hidden="true"></i></button></div>
                                </div>
                                <div class="col-md-2"><label class="form-label small mb-1">{{t:cfg.port}}</label>
                                    <div class="input-group input-group-sm"><input type="text" class="form-control" value="995" id="cfgPop3Port" readonly><button class="btn btn-outline-secondary" onclick="copyInputValue('cfgPop3Port')"><i class="fas fa-copy" aria-hidden="true"></i></button></div>
                                </div>
                                <div class="col-md-2"><label class="form-label small mb-1">{{t:cfg.security}}</label>
                                    <input type="text" class="form-control form-control-sm" value="SSL/TLS" readonly>
                                </div>
                            </div>

                            <h6 class="mb-2 text-primary"><i class="fas fa-paper-plane me-1" aria-hidden="true"></i>{{t:cfg.outSmtp}}</h6>
                            <div class="row g-2 mb-2">
                                <div class="col-md-8"><label class="form-label small mb-1">Server</label>
                                    <div class="input-group input-group-sm"><input type="text" class="form-control font-monospace" id="cfgSmtpServer" readonly><button class="btn btn-outline-secondary" onclick="copyInputValue('cfgSmtpServer')"><i class="fas fa-copy" aria-hidden="true"></i></button></div>
                                </div>
                                <div class="col-md-2"><label class="form-label small mb-1">{{t:cfg.port}}</label>
                                    <div class="input-group input-group-sm"><input type="text" class="form-control" value="587" id="cfgSmtpPort" readonly><button class="btn btn-outline-secondary" onclick="copyInputValue('cfgSmtpPort')"><i class="fas fa-copy" aria-hidden="true"></i></button></div>
                                </div>
                                <div class="col-md-2"><label class="form-label small mb-1">{{t:cfg.security}}</label>
                                    <input type="text" class="form-control form-control-sm" value="STARTTLS" readonly>
                                </div>
                            </div>
                            <small class="text-muted"><i class="fas fa-info-circle me-1" aria-hidden="true"></i>{{t:cfg.auth.html}}</small>
                        </div>

                        <!-- ===== Tab OUTLOOK ===== -->
                        <div class="tab-pane fade" id="configOutlook">
                            <h6><i class="fab fa-microsoft me-2" aria-hidden="true"></i>Microsoft Outlook</h6>
                            <ol class="mt-3 small">
                                <li class="mb-2">{{t:cfg.ol1.html}}</li>
                                <li class="mb-3">{{t:cfg.ol2}}
                                    <table class="table table-sm table-bordered mt-2 mb-0">
                                        <tr><td class="fw-bold" style="width:30%">{{t:cfg.imapServer}}</td><td><div class="input-group input-group-sm"><input type="text" class="form-control font-monospace" id="cfgOutlookImap" readonly><button class="btn btn-outline-secondary" onclick="copyInputValue('cfgOutlookImap')"><i class="fas fa-copy" aria-hidden="true"></i></button></div></td></tr>
                                        <tr><td class="fw-bold">{{t:cfg.imapPortSec}}</td><td><code>993 / SSL-TLS</code></td></tr>
                                        <tr><td class="fw-bold">{{t:cfg.smtpServer}}</td><td><div class="input-group input-group-sm"><input type="text" class="form-control font-monospace" id="cfgOutlookSmtp" readonly><button class="btn btn-outline-secondary" onclick="copyInputValue('cfgOutlookSmtp')"><i class="fas fa-copy" aria-hidden="true"></i></button></div></td></tr>
                                        <tr><td class="fw-bold">{{t:cfg.smtpPortSec}}</td><td><code>587 / STARTTLS</code></td></tr>
                                        <tr><td class="fw-bold">Username</td><td><div class="input-group input-group-sm"><input type="text" class="form-control font-monospace cfg-shared-email" readonly><button class="btn btn-outline-secondary" onclick="copySharedField(this)"><i class="fas fa-copy" aria-hidden="true"></i></button></div></td></tr>
                                        <tr><td class="fw-bold">Password</td><td><small class="text-muted">{{t:cfg.seeCredentials}}</small></td></tr>
                                    </table>
                                </li>
                                <li>{{t:cfg.ol3}}</li>
                            </ol>
                        </div>

                        <!-- ===== Tab APPLE ===== -->
                        <div class="tab-pane fade" id="configApple">
                            <h6><i class="fab fa-apple me-2" aria-hidden="true"></i>iPhone / iPad / Mac</h6>
                            <ol class="mt-3 small">
                                <li class="mb-2">{{t:cfg.ap1.html}}</li>
                                <li class="mb-2">{{t:cfg.ap2.html}}</li>
                                <li class="mb-3">{{t:cfg.setValues}}
                                    <table class="table table-sm table-bordered mt-2 mb-0">
                                        <tr><td class="fw-bold" style="width:35%">{{t:cfg.inServerImap}}</td><td><div class="input-group input-group-sm"><input type="text" class="form-control font-monospace" id="cfgAppleImap" readonly><button class="btn btn-outline-secondary" onclick="copyInputValue('cfgAppleImap')"><i class="fas fa-copy" aria-hidden="true"></i></button></div></td></tr>
                                        <tr><td class="fw-bold">{{t:cfg.outServerSmtp}}</td><td><div class="input-group input-group-sm"><input type="text" class="form-control font-monospace" id="cfgAppleSmtp" readonly><button class="btn btn-outline-secondary" onclick="copyInputValue('cfgAppleSmtp')"><i class="fas fa-copy" aria-hidden="true"></i></button></div></td></tr>
                                        <tr><td class="fw-bold">Username</td><td><div class="input-group input-group-sm"><input type="text" class="form-control font-monospace cfg-shared-email" readonly><button class="btn btn-outline-secondary" onclick="copySharedField(this)"><i class="fas fa-copy" aria-hidden="true"></i></button></div></td></tr>
                                        <tr><td class="fw-bold">Password</td><td><small class="text-muted">{{t:cfg.seeCredentials}}</small></td></tr>
                                    </table>
                                </li>
                                <li>{{t:cfg.ap4}}</li>
                            </ol>
                        </div>

                        <!-- ===== Tab ANDROID ===== -->
                        <div class="tab-pane fade" id="configAndroid">
                            <h6><i class="fab fa-android me-2" aria-hidden="true"></i>Android ({{t:cfg.gmailApp}})</h6>
                            <ol class="mt-3 small">
                                <li class="mb-2">{{t:cfg.an1.html}}</li>
                                <li class="mb-2">{{t:cfg.an2.html}}</li>
                                <li class="mb-3">{{t:cfg.setValues}}
                                    <table class="table table-sm table-bordered mt-2 mb-0">
                                        <tr><td class="fw-bold" style="width:35%">{{t:cfg.inServer}}</td><td><div class="input-group input-group-sm"><input type="text" class="form-control font-monospace" id="cfgAndroidImap" readonly><button class="btn btn-outline-secondary" onclick="copyInputValue('cfgAndroidImap')"><i class="fas fa-copy" aria-hidden="true"></i></button></div></td></tr>
                                        <tr><td class="fw-bold">{{t:cfg.inPortSec}}</td><td><code>993 / SSL</code></td></tr>
                                        <tr><td class="fw-bold">{{t:cfg.outServer}}</td><td><div class="input-group input-group-sm"><input type="text" class="form-control font-monospace" id="cfgAndroidSmtp" readonly><button class="btn btn-outline-secondary" onclick="copyInputValue('cfgAndroidSmtp')"><i class="fas fa-copy" aria-hidden="true"></i></button></div></td></tr>
                                        <tr><td class="fw-bold">{{t:cfg.outPortSec}}</td><td><code>587 / STARTTLS</code></td></tr>
                                        <tr><td class="fw-bold">Username</td><td><div class="input-group input-group-sm"><input type="text" class="form-control font-monospace cfg-shared-email" readonly><button class="btn btn-outline-secondary" onclick="copySharedField(this)"><i class="fas fa-copy" aria-hidden="true"></i></button></div></td></tr>
                                        <tr><td class="fw-bold">Password</td><td><small class="text-muted">{{t:cfg.seeCredentials}}</small></td></tr>
                                    </table>
                                </li>
                                <li>{{t:cfg.an4}}</li>
                            </ol>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">{{t:common.close}}</button>
                </div>
            </div>
        </div>
    </div>
""";
    }

    /**
     * Modal "Generatore Password" — UI riusabile per generare password con opzioni dettagliate.
     * Quando l'utente clicca "Usa questa password", invoca il callback registrato in
     * window.__pwGenCallback (impostato da chi apre il modal).
     */
    private static String getPasswordGeneratorModal() {
        return """
    <div class="modal fade" id="passwordGeneratorModal" tabindex="-1">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-magic me-2" aria-hidden="true"></i>{{t:pw.genTitle}}</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="{{t:common.close}}"></button>
                </div>
                <div class="modal-body">
                    <!-- Tipo -->
                    <div class="mb-3">
                        <label class="form-label small fw-bold">{{t:pw.type}}</label>
                        <div class="border rounded p-2">
                            <div class="form-check">
                                <input class="form-check-input pwgen-type" type="radio" name="pwgenType" id="pwgenTypeSay" value="easy_to_say">
                                <label class="form-check-label" for="pwgenTypeSay">
                                    <strong>{{t:pw.typeSay}}</strong> <small class="text-muted">{{t:pw.typeSayHint}}</small>
                                </label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input pwgen-type" type="radio" name="pwgenType" id="pwgenTypeRead" value="easy_to_read" checked>
                                <label class="form-check-label" for="pwgenTypeRead">
                                    <strong>{{t:pw.typeRead}}</strong> <small class="text-muted">{{t:pw.typeReadHint}}</small>
                                </label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input pwgen-type" type="radio" name="pwgenType" id="pwgenTypeAll" value="all_chars">
                                <label class="form-check-label" for="pwgenTypeAll">
                                    <strong>{{t:pw.typeAll}}</strong> <small class="text-muted">{{t:pw.typeAllHint}}</small>
                                </label>
                            </div>
                        </div>
                    </div>

                    <!-- Lunghezza -->
                    <div class="row g-3 mb-3 align-items-center">
                        <div class="col-md-6">
                            <label class="form-label small fw-bold mb-1">{{t:pw.length}}</label>
                            <div class="input-group">
                                <button class="btn btn-outline-secondary" type="button" onclick="pwgenLengthDelta(-1)"><i class="fas fa-minus" aria-hidden="true"></i></button>
                                <input type="number" class="form-control text-center" id="pwgenLength" value="20" min="{{PW_MIN}}" max="128">
                                <button class="btn btn-outline-secondary" type="button" onclick="pwgenLengthDelta(1)"><i class="fas fa-plus" aria-hidden="true"></i></button>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <input type="range" class="form-range mt-3" id="pwgenLengthRange" min="{{PW_MIN}}" max="64" value="20" oninput="document.getElementById('pwgenLength').value = this.value">
                        </div>
                    </div>

                    <!-- Include -->
                    <div class="mb-3">
                        <label class="form-label small fw-bold">{{t:pw.include}}</label>
                        <div class="border rounded p-2 d-flex flex-wrap gap-3">
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="pwgenIncludeLower" checked>
                                <label class="form-check-label" for="pwgenIncludeLower">{{t:pw.lower}}</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="pwgenIncludeUpper" checked>
                                <label class="form-check-label" for="pwgenIncludeUpper">{{t:pw.upper}}</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="pwgenIncludeNumbers" checked>
                                <label class="form-check-label" for="pwgenIncludeNumbers">{{t:pw.numbers}}</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="pwgenIncludeSymbols" checked>
                                <label class="form-check-label" for="pwgenIncludeSymbols">{{t:pw.symbols}}</label>
                            </div>
                        </div>
                        <small class="text-muted" id="pwgenIncludeNote"></small>
                    </div>

                    <!-- Preview -->
                    <div class="mb-2">
                        <label class="form-label small fw-bold">{{t:pw.generated}}</label>
                        <div class="input-group">
                            <input type="text" class="form-control font-monospace fs-5" id="pwgenPreview" readonly placeholder="{{t:pw.previewPh}}">
                            <button class="btn btn-outline-secondary" type="button" onclick="pwgenCopy()" title="{{t:common.copy}}"><i class="fas fa-copy" aria-hidden="true"></i></button>
                        </div>
                        <div class="mt-2 small">
                            <span id="pwgenStrengthBadge" class="badge bg-secondary">—</span>
                            <span class="text-muted ms-2" id="pwgenEntropyText">{{t:pw.entropyNone}}</span>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">{{t:common.cancel}}</button>
                    <button type="button" class="btn btn-info" onclick="pwgenGenerate()"><i class="fas fa-sync-alt me-1" aria-hidden="true"></i>{{t:pw.generate}}</button>
                    <button type="button" class="btn btn-success" id="pwgenUseBtn" onclick="pwgenUse()" disabled><i class="fas fa-check me-1" aria-hidden="true"></i>{{t:pw.use}}</button>
                </div>
            </div>
        </div>
    </div>
""".replace("{{PW_MIN}}", String.valueOf(org.mail_panel.webserver.SecurityUtils.MAILBOX_PASSWORD_MIN));
    }

    /**
     * Campo password di una casella, con i suoi strumenti: mostra/nascondi, Genera (apre il
     * Generatore Password), Copia, e l'avviso se un carattere non e' ammesso.
     *
     * Lo stesso componente per "Aggiungi Casella" e "Modifica Casella". Prima la seconda aveva gli
     * strumenti e la prima no: la password di una casella nuova si digitava alla cieca, senza poterla
     * generare ne' copiare per chi l'avrebbe usata. Il codice del componente e' getPasswordFieldJs().
     */
    private static String passwordField(String id, String placeholder) {
        return """
                        <div class="input-group has-validation">
                            <input type="password" class="form-control font-monospace campo-password" id="%1$s" placeholder="%2$s" maxlength="128"
                                   autocomplete="new-password" autocapitalize="off" spellcheck="false" oninput="pwCheck('%1$s')" aria-describedby="%1$sErr">
                            <button class="btn btn-outline-secondary" type="button" id="%1$sMostra" onclick="pwShow('%1$s')" title="{{t:pw.showHide}}" aria-label="{{t:pw.show}}"><i class="fas fa-eye" aria-hidden="true"></i></button>
                            <button class="btn btn-outline-primary" type="button" onclick="pwGenerate('%1$s')" title="{{t:pw.generateSafe}}" aria-label="{{t:pw.generateSafe}}"><i class="fas fa-magic" aria-hidden="true"></i><span class="d-none d-sm-inline ms-1">{{t:pw.generate}}</span></button>
                            <button class="btn btn-outline-secondary" type="button" id="%1$sCopia" onclick="pwDoCopy('%1$s')" title="{{t:pw.copyClipboard}}" aria-label="{{t:pw.copy}}"><i class="fas fa-copy" aria-hidden="true"></i></button>
                            <div class="invalid-feedback" id="%1$sErr" role="alert"></div>
                        </div>
""".formatted(id, placeholder);
    }

    /**
     * Il codice del campo password (passwordField). La regola dei caratteri arriva da SecurityUtils
     * quando si genera la pagina: e' la stessa che applica il server, che resta l'unico a decidere.
     */
    private static String getPasswordFieldJs() {
        // Righe normali, non text block: un text block comincia sempre a capo, e la regex si spezzerebbe.
        String rule = "        const PW_CHARACTER = /^" + org.mail_panel.webserver.SecurityUtils.PASSWORD_CHARACTERS + "$/;\n"
                + "        const PW_MIN = " + org.mail_panel.webserver.SecurityUtils.MAILBOX_PASSWORD_MIN
                + ", PW_MAX = " + org.mail_panel.webserver.SecurityUtils.PASSWORD_MAX + ";\n"
                + "        const PW_SYMBOLS = '" + org.mail_panel.webserver.SecurityUtils.PASSWORD_SYMBOLS
                        .replace("\\", "\\\\").replace("'", "\\'") + "';\n";
        return """
        // ===== Campo password (componente condiviso, vedi campoPassword) =====
""" + rule + """

        function pwShow(id, showIt) {
            const input = document.getElementById(id);
            const btn = document.getElementById(id + 'Mostra');
            const isVisible = showIt === undefined ? input.type === 'password' : showIt;
            input.type = isVisible ? 'text' : 'password';
            btn.innerHTML = isVisible ? '<i class="fas fa-eye-slash" aria-hidden="true"></i>' : '<i class="fas fa-eye" aria-hidden="true"></i>';
            btn.setAttribute('aria-label', isVisible ? t('pw.hide') : t('pw.show'));
        }

        // Vuoto va bene (in Modifica vuol dire "non cambiare"): l'obbligo lo controlla chi salva.
        function pwCheck(id) {
            const input = document.getElementById(id);
            const v = input.value;
            let msg = '';
            if (v) {
                const forbidden = [...new Set([...v].filter(c => !PW_CHARACTER.test(c)))];
                if (forbidden.length) {
                    msg = t('pw.badChar', { chars: forbidden.map(c => c === ' ' ? t('pw.space') : c.trim() === '' ? t('pw.specialSpace') : c).join(' '),
                                            symbols: PW_SYMBOLS.split('').join(' ') });
                } else if (v.length < PW_MIN) {
                    msg = t('pw.min', { n: PW_MIN });
                } else if (v.length > PW_MAX) {
                    msg = t('pw.max', { n: PW_MAX });
                }
            }
            document.getElementById(id + 'Err').textContent = msg;
            input.classList.toggle('is-invalid', !!msg);
            return !msg;
        }

        function pwPutPassword(id, pw) {
            const input = document.getElementById(id);
            input.value = pw;
            pwShow(id, true);
            pwCheck(id);
        }

        // Il generatore completo, con le sue opzioni: la scelta torna nel campo da cui e' partito.
        function pwGenerate(id) {
            window.__pwGenCallback = function (pw) {
                pwPutPassword(id, pw);
                const input = document.getElementById(id);
                input.focus();
                input.select();
            };
            openPasswordGeneratorModal();
        }

        // Una password proposta subito, con le impostazioni di default del generatore (sul server).
        // Se nel frattempo nel campo e' stato scritto o incollato qualcosa, la proposta si scarta.
        function pwPropose(id) {
            fetch('/api/mailboxes', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'generate_password', csrf_token: csrfToken })
            }).then(r => r.json()).then(data => {
                if (data.success && data.password && !document.getElementById(id).value) pwPutPassword(id, data.password);
            }).catch(() => {});
        }

        function pwDoCopy(id) {
            const input = document.getElementById(id);
            if (!input.value) { document.getElementById(id + 'Err').textContent = t('pw.empty'); input.classList.add('is-invalid'); return; }
            const done = () => {
                const btn = document.getElementById(id + 'Copia');
                btn.innerHTML = '<i class="fas fa-check" aria-hidden="true"></i>';
                btn.setAttribute('aria-label', t('pw.copied'));
                setTimeout(() => { btn.innerHTML = '<i class="fas fa-copy" aria-hidden="true"></i>'; btn.setAttribute('aria-label', t('pw.copy')); }, 1500);
            };
            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(input.value).then(done).catch(() => { if (pwCopyOldWay(input)) done(); });
            } else if (pwCopyOldWay(input)) {
                done();
            }
        }

        // execCommand('copy') non copia da un campo password: lo si rende leggibile per l'istante della copia.
        function pwCopyOldWay(input) {
            const kindValue = input.type;
            input.type = 'text';
            input.select();
            let ok = false;
            try { ok = document.execCommand('copy'); } catch (e) { }
            input.type = kindValue;
            return ok;
        }
""";
    }

    /** Finestra "Trasforma in casella" della pagina Alias (AddressTransform sul server). */
    private static String getAliasToMailboxModal() {
        return """
    <div class="modal fade" id="aCasellaModal" tabindex="-1" aria-labelledby="aCasellaTitolo" aria-hidden="true">
        <div class="modal-dialog modal-lg modal-dialog-scrollable">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title testo-lungo" id="aCasellaTitolo">{{t:ac.title}}</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="{{t:common.close}}"></button>
                </div>
                <div class="modal-body">
                    <p id="acCaricamento" class="mb-0" role="status">{{t:conv.checking}}</p>
                    <div id="acNo" class="alert alert-warning d-none mb-0 testo-lungo" role="alert"></div>
                    <div id="acSi" class="d-none">
                        <p><strong id="acIndirizzo" class="testo-lungo"></strong></p>
                        <p>{{t:ac.intro}}</p>
                        <p id="acDestinazioni" class="mb-2 testo-lungo"></p>
                        <div class="form-check mb-3">
                            <input class="form-check-input" type="checkbox" id="acTieni">
                            <label class="form-check-label" for="acTieni">{{t:ac.keep}}</label>
                        </div>
                        <p id="acVersoQui" class="small text-muted testo-lungo"></p>
                        <fieldset id="acPostaBlocco" class="border rounded p-2 mb-3 d-none">
                            <legend class="fs-6 float-none w-auto px-1 mb-0">{{t:ac.oldMail}}</legend>
                            <p class="small mb-2" id="acPostaInfo"></p>
                            <div class="form-check">
                                <input class="form-check-input" type="radio" name="acPosta" id="acRitrova" value="recover">
                                <label class="form-check-label" for="acRitrova">{{t:ac.recover}}</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="radio" name="acPosta" id="acArchivia" value="archive">
                                <label class="form-check-label" for="acArchivia">{{t:ac.archive}}</label>
                            </div>
                        </fieldset>
                        <div class="mb-3">
                            <label class="form-label" for="acPass">{{t:ac.pass}}</label>
""" + passwordField("acPass", "") + """
                            <small class="d-block text-muted mt-1">{{t:ac.passHint}}</small>
                        </div>
                        <div class="row g-2">
                            <div class="col-sm-8">
                                <label class="form-label" for="acNome">{{t:mbx.colName}} <span class="text-muted small">{{t:ac.nameHint}}</span></label>
                                <input type="text" class="form-control" id="acNome" maxlength="100" autocomplete="off">
                            </div>
                            <div class="col-sm-4">
                                <label class="form-label" for="acQuota">{{t:ac.quota}}</label>
                                <input type="number" class="form-control" id="acQuota" min="0" max="1048576" value="1024" aria-describedby="acQuotaAiuto">
                                <small class="text-muted" id="acQuotaAiuto">{{t:ac.quotaHint}}</small>
                            </div>
                        </div>
                        <div id="acErr" class="text-danger small mt-2 testo-lungo" role="alert"></div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">{{t:common.cancel}}</button>
                    <button type="button" class="btn btn-mail" id="acVia" onclick="transformToMailbox()" disabled><i class="fas fa-inbox me-1" aria-hidden="true"></i>{{t:ac.title}}</button>
                </div>
            </div>
        </div>
    </div>
""";
    }

    /** Lo script di "Trasforma in casella": anteprima dal server, poi la richiesta con la sua fingerprint. */
    private static String getAliasToMailboxJs() {
        return """
        // ===== Trasforma in casella (decide il server: AddressTransform) =====
        let acInfo = null;
        function acShow(id, si) { document.getElementById(id).classList.toggle('d-none', !si); }
        function acData(iso) { return iso ? iso.substring(8, 10) + '/' + iso.substring(5, 7) + '/' + iso.substring(0, 4) : ''; }

        function openToMailbox(id) {
            const a = currentAliases.find(x => parseInt(x.id) === id);
            if (!a) return;
            acInfo = { address: a.source, fingerprint: '', mail: false };
            document.getElementById('aCasellaTitolo').textContent = t('ac.titleFor', { address: a.source });
            document.getElementById('acErr').textContent = '';
            acShow('acCaricamento', true);
            acShow('acNo', false);
            acShow('acSi', false);
            document.getElementById('acVia').disabled = true;
            document.getElementById('acTieni').checked = false;
            document.getElementById('acRitrova').checked = false;
            document.getElementById('acArchivia').checked = false;
            document.getElementById('acPass').value = '';
            pwShow('acPass', false);
            pwCheck('acPass');
            document.getElementById('acNome').value = '';
            document.getElementById('acQuota').value = '1024';
            bootstrap.Modal.getOrCreateInstance(document.getElementById('aCasellaModal')).show();
            fetch('/api/aliases?trasforma=' + encodeURIComponent(a.source)).then(r => r.json()).then(d => {
                acShow('acCaricamento', false);
                if (!d.success || !d.possible) {
                    document.getElementById('acNo').textContent = d.reason || d.error || t('conv.notPossible');
                    acShow('acNo', true);
                    return;
                }
                acInfo.fingerprint = d.fingerprint;
                acInfo.mail = !!(d.mail && d.mail.present);
                document.getElementById('acIndirizzo').textContent = d.address;
                const box = document.getElementById('acDestinazioni');
                box.textContent = '';
                if (d.destinations.length) {
                    box.appendChild(document.createTextNode(t('ac.nowGoesTo') + ' '));
                    d.destinations.forEach((x, k) => {
                        if (k) box.appendChild(document.createTextNode(', '));
                        const c = document.createElement('code');
                        c.textContent = x.destination;
                        box.appendChild(c);
                        if (!x.active) box.appendChild(document.createTextNode(' ' + t('ac.inactive')));
                    });
                    box.appendChild(document.createTextNode('. ' + t('ac.withoutTick')));
                }
                const vq = (d.towardsHere || []).filter(x => x.active).map(x => x.source);
                document.getElementById('acVersoQui').textContent = vq.length
                    ? t('ac.alsoFrom', { list: vq.join(', ') }) : '';
                if (acInfo.mail) {
                    const p = d.mail;
                    document.getElementById('acPostaInfo').textContent = t('ac.oldMailInfo', {
                            messages: (p.atLeast ? t('ac.atLeast') + ' ' : '') + tn('conv.messages', p.messages), size: p.size })
                        + (p.last ? ' ' + t('ac.lastOne', { date: acData(p.last) }) : '')
                        + (p.filters ? ' ' + t('ac.oldFilters') : '');
                }
                acShow('acPostaBlocco', acInfo.mail);
                acShow('acSi', true);
                document.getElementById('acVia').disabled = false;
                pwPropose('acPass');
            }).catch(() => {
                acShow('acCaricamento', false);
                document.getElementById('acNo').textContent = t('common.noAnswer');
                acShow('acNo', true);
            });
        }

        function transformToMailbox() {
            const err = document.getElementById('acErr');
            err.textContent = '';
            const pass = document.getElementById('acPass');
            if (!pass.value) {
                document.getElementById('acPassErr').textContent = t('mbx.needPass');
                pass.classList.add('is-invalid');
                return;
            }
            if (!pwCheck('acPass')) return;
            let mail = '';
            if (acInfo.mail) {
                const choice = document.querySelector('input[name="acPosta"]:checked');
                if (!choice) { err.textContent = t('ac.chooseMail'); return; }
                mail = choice.value;
            }
            const quota = parseInt(document.getElementById('acQuota').value);
            const btn = document.getElementById('acVia');
            btn.disabled = true;
            fetch('/api/aliases', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action: 'trasforma_in_casella', source: acInfo.address, password: pass.value,
                    name: document.getElementById('acNome').value.trim(), quota_mb: isNaN(quota) ? 1024 : quota,
                    keep_forwards: document.getElementById('acTieni').checked, old_mail: mail,
                    fingerprint: acInfo.fingerprint, csrf_token: csrfToken
                })
            }).then(r => r.json()).then(d => {
                btn.disabled = false;
                if (d.success) {
                    bootstrap.Modal.getInstance(document.getElementById('aCasellaModal')).hide();
                    aliasMsg(d.message, 'success');
                    loadAliases();
                } else {
                    err.textContent = d.error || t('conv.failed');
                }
            }).catch(() => {
                btn.disabled = false;
                err.textContent = t('conv.noAnswer');
            });
        }
        // Fatta la scelta sulla posta di prima, l'avviso che la chiedeva non serve piu'.
        document.querySelectorAll('input[name="acPosta"]').forEach(x => x.addEventListener('change', () => {
            document.getElementById('acErr').textContent = '';
        }));
""";
    }

    /** Finestra "Trasforma in alias" della pagina Caselle (AddressTransform sul server). */
    private static String getMailboxToAliasModal() {
        return """
    <div class="modal fade" id="aAliasModal" tabindex="-1" aria-labelledby="aAliasTitolo" aria-hidden="true">
        <div class="modal-dialog modal-lg modal-dialog-scrollable">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title testo-lungo" id="aAliasTitolo">{{t:mbx.toAlias}}</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="{{t:common.close}}"></button>
                </div>
                <div class="modal-body">
                    <p id="aaCaricamento" class="mb-0" role="status">{{t:conv.checking}}</p>
                    <div id="aaNo" class="alert alert-warning d-none mb-0 testo-lungo" role="alert"></div>
                    <div id="aaSi" class="d-none">
                        <p><strong id="aaIndirizzo" class="testo-lungo"></strong></p>
                        <p>{{t:aa.intro}}</p>
                        <h6 class="testo-rischio"><i class="fas fa-minus-circle me-1" aria-hidden="true"></i>{{t:conv.lost}}</h6>
                        <ul id="aaPerdite" class="small testo-lungo"></ul>
                        <h6 class="testo-ok"><i class="fas fa-check-circle me-1" aria-hidden="true"></i>{{t:conv.kept}}</h6>
                        <ul id="aaResta" class="small testo-lungo"></ul>
                        <div class="mb-3">
                            <label class="form-label" for="aaDest">{{t:aa.dest}}</label>
                            <textarea class="form-control font-monospace" id="aaDest" rows="3" autocomplete="off" autocapitalize="off" spellcheck="false" aria-describedby="aaDestAiuto"></textarea>
                            <small class="text-muted" id="aaDestAiuto">{{t:aa.destHint}}</small>
                        </div>
                        <div class="mb-1">
                            <label class="form-label" for="aaConferma">{{t:conv.typeAddress}} <code id="aaIndirizzoConferma" class="testo-lungo"></code></label>
                            <input type="text" class="form-control" id="aaConferma" autocomplete="off" autocapitalize="off" spellcheck="false">
                        </div>
                        <div id="aaErr" class="text-danger small mt-2 testo-lungo" role="alert"></div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">{{t:common.cancel}}</button>
                    <button type="button" class="btn btn-danger" id="aaVia" onclick="transformToAlias()" disabled><i class="fas fa-share me-1" aria-hidden="true"></i>{{t:mbx.toAlias}}</button>
                </div>
            </div>
        </div>
    </div>
""";
    }

    /** Lo script di "Trasforma in alias": anteprima di cosa si perde e cosa resta, conferma scritta. */
    private static String getMailboxToAliasJs() {
        return """
        // ===== Trasforma in alias (decide il server: AddressTransform) =====
        let aaInfo = null;
        function aaShow(id, si) { document.getElementById(id).classList.toggle('d-none', !si); }
        function aaEntry(itemList, textValue) {
            const li = document.createElement('li');
            li.textContent = textValue;
            document.getElementById(itemList).appendChild(li);
        }
        function aaData(iso) { return iso ? iso.substring(8, 10) + '/' + iso.substring(5, 7) + '/' + iso.substring(0, 4) : ''; }
        function mbMsg(textValue, kindValue) {
            const box = document.getElementById('mbMsg');
            box.textContent = '';
            if (!textValue) return;
            const div = document.createElement('div');
            div.className = 'alert alert-' + kindValue + ' py-2 small testo-lungo';
            div.textContent = textValue;
            box.appendChild(div);
        }

        function openToAlias(id) {
            aaInfo = { id: id, address: '', fingerprint: '' };
            document.getElementById('aaErr').textContent = '';
            document.getElementById('aaDest').value = '';
            document.getElementById('aaConferma').value = '';
            document.getElementById('aaPerdite').textContent = '';
            document.getElementById('aaResta').textContent = '';
            aaShow('aaCaricamento', true);
            aaShow('aaNo', false);
            aaShow('aaSi', false);
            document.getElementById('aaVia').disabled = true;
            bootstrap.Modal.getOrCreateInstance(document.getElementById('aAliasModal')).show();
            fetch('/api/mailboxes?trasforma=' + id).then(r => r.json()).then(d => {
                aaShow('aaCaricamento', false);
                if (!d.success || !d.possible) {
                    document.getElementById('aaNo').textContent = d.reason || d.error || t('conv.notPossible');
                    aaShow('aaNo', true);
                    return;
                }
                aaInfo.address = d.address;
                aaInfo.fingerprint = d.fingerprint;
                document.getElementById('aAliasTitolo').textContent = t('aa.titleFor', { address: d.address });
                document.getElementById('aaIndirizzo').textContent = d.address;
                document.getElementById('aaIndirizzoConferma').textContent = d.address;
                const p = d.losses;
                aaEntry('aaPerdite', t('aa.lostLogin') + ' '
                    + (p.lastAccess ? t('aa.lastLogin', { date: aaData(p.lastAccess) }) : t('aa.neverUsed')));
                if (p.sendOnly) aaEntry('aaPerdite', t('aa.lostSendOnly'));
                if (p.autoReply) aaEntry('aaPerdite', t('aa.lostAutoReply'));
                if (p.filters) aaEntry('aaPerdite', tn('aa.lostFilters', p.filters));
                if (p.forwards.length) aaEntry('aaPerdite', t('aa.lostForwards', { list: p.forwards.join(', ') }));
                if (d.copy) aaEntry('aaPerdite', t('aa.lostSelfAlias', { address: d.address }));
                const mail = d.mail;
                aaEntry('aaResta', mail.present
                    ? (mail.atLeast ? t('aa.keptMailAtLeast', { messages: tn('conv.messages', mail.messages), size: mail.size, folder: d.folder }) : t('aa.keptMail', { messages: tn('conv.messages', mail.messages), size: mail.size, folder: d.folder }))
                    : t('aa.noMail'));
                const already = (d.alreadyForwarded || []).filter(x => x.active).map(x => x.destination);
                if (already.length) aaEntry('aaResta', t('aa.keptAliases', { list: already.join(', ') }));
                const vq = (d.towardsHere || []).filter(x => x.active).map(x => x.source);
                if (vq.length) aaEntry('aaResta', t('aa.keptIncoming', { list: vq.join(', ') }));
                document.getElementById('aaDest').value = (d.proposals || []).join(String.fromCharCode(10));
                aaShow('aaSi', true);
                aaCheck();
            }).catch(() => {
                aaShow('aaCaricamento', false);
                document.getElementById('aaNo').textContent = t('common.noAnswer');
                aaShow('aaNo', true);
            });
        }

        function aaCheck() {
            document.getElementById('aaVia').disabled = !aaInfo || !aaInfo.fingerprint
                || document.getElementById('aaConferma').value.trim().toLowerCase() !== aaInfo.address;
        }

        function transformToAlias() {
            const err = document.getElementById('aaErr');
            err.textContent = '';
            const dest = document.getElementById('aaDest').value.split(String.fromCharCode(10)).map(x => x.trim()).filter(x => x);
            if (!dest.length) { err.textContent = t('aa.needDest'); return; }
            const btn = document.getElementById('aaVia');
            btn.disabled = true;
            fetch('/api/mailboxes', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action: 'trasforma_in_alias', id: aaInfo.id, destinations: dest,
                    confirmation: document.getElementById('aaConferma').value.trim(), fingerprint: aaInfo.fingerprint, csrf_token: csrfToken
                })
            }).then(r => r.json()).then(d => {
                if (d.success) {
                    bootstrap.Modal.getInstance(document.getElementById('aAliasModal')).hide();
                    mbMsg(d.message, 'success');
                    loadMailboxes();
                } else {
                    err.textContent = d.error || t('conv.failed');
                    aaCheck();
                }
            }).catch(() => {
                err.textContent = t('conv.noAnswer');
                aaCheck();
            });
        }
        document.getElementById('aaConferma').addEventListener('input', aaCheck);
""";
    }

    /**
     * Il codice del Generatore Password (getPasswordGeneratorModal): con passwordField e
     * getPasswordFieldJs e' il componente condiviso delle password delle caselle, in "Aggiungi
     * casella", "Modifica casella" e "Trasforma in casella" (pagina Alias).
     */
    private static String getPasswordGeneratorJs() {
        return """
        // ===== Password Generator (modal riusabile) =====
        function openPasswordGeneratorModal() {
            // Reset preview
            document.getElementById('pwgenPreview').value = '';
            document.getElementById('pwgenStrengthBadge').textContent = '—';
            document.getElementById('pwgenStrengthBadge').className = 'badge bg-secondary';
            document.getElementById('pwgenEntropyText').textContent = 'Entropia: — bit';
            document.getElementById('pwgenUseBtn').disabled = true;
            // Aggiorna nota Include in base al type selezionato
            pwgenUpdateIncludeNote();
            new bootstrap.Modal(document.getElementById('passwordGeneratorModal')).show();
            // Genera subito una password con i default così l'utente vede un esempio
            setTimeout(pwgenGenerate, 100);
        }

        function pwgenLengthDelta(delta) {
            const input = document.getElementById('pwgenLength');
            let v = parseInt(input.value) + delta;
            if (v < PW_MIN) v = PW_MIN;
            if (v > PW_MAX) v = PW_MAX;
            input.value = v;
            const range = document.getElementById('pwgenLengthRange');
            if (v <= 64) range.value = v;
        }

        function pwgenUpdateIncludeNote() {
            const type = document.querySelector('input.pwgen-type:checked').value;
            const numbersChk = document.getElementById('pwgenIncludeNumbers');
            const symbolsChk = document.getElementById('pwgenIncludeSymbols');
            const note = document.getElementById('pwgenIncludeNote');
            if (type === 'easy_to_say') {
                numbersChk.disabled = true; symbolsChk.disabled = true;
                numbersChk.checked = false; symbolsChk.checked = false;
                note.textContent = t('pw.sayNote');
            } else {
                numbersChk.disabled = false; symbolsChk.disabled = false;
                note.textContent = '';
            }
        }

        // Listener per radio type
        document.addEventListener('change', function(e) {
            if (e.target && e.target.classList && e.target.classList.contains('pwgen-type')) {
                pwgenUpdateIncludeNote();
            }
        });

        function pwgenGenerate() {
            // Dentro i limiti delle caselle anche se nel campo si scrive altro (il server li applica comunque).
            const length = Math.min(PW_MAX, Math.max(PW_MIN, parseInt(document.getElementById('pwgenLength').value) || 20));
            document.getElementById('pwgenLength').value = length;
            const type = document.querySelector('input.pwgen-type:checked').value;
            const lo = document.getElementById('pwgenIncludeLower').checked;
            const up = document.getElementById('pwgenIncludeUpper').checked;
            const nu = document.getElementById('pwgenIncludeNumbers').checked;
            const sy = document.getElementById('pwgenIncludeSymbols').checked;

            if (!lo && !up && !nu && !sy) {
                alert(t('pw.pickCategory'));
                return;
            }

            fetch('/api/mailboxes', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action: 'generate_password',
                    length: length,
                    type: type,
                    include_lowercase: lo,
                    include_uppercase: up,
                    include_numbers: nu,
                    include_symbols: sy,
                    csrf_token: csrfToken
                })
            })
            .then(r => r.json())
            .then(data => {
                if (!data.success) {
                    alert(t('common.error', { message: data.error || '' }));
                    return;
                }
                document.getElementById('pwgenPreview').value = data.password;
                const ent = data.entropy_bits || 0;
                const levelValue = data.strength || '';
                document.getElementById('pwgenEntropyText').textContent = t('pw.entropy', { bits: ent });
                const badge = document.getElementById('pwgenStrengthBadge');
                badge.textContent = ({ weak: t('pw.strength.weak'), fair: t('pw.strength.fair'), strong: t('pw.strength.strong'), very_strong: t('pw.strength.very_strong') })[levelValue] || '—';
                if (levelValue === 'very_strong' || levelValue === 'strong') badge.className = 'badge bg-success';
                else if (levelValue === 'fair')      badge.className = 'badge bg-warning text-dark';
                else                              badge.className = 'badge bg-danger';
                document.getElementById('pwgenUseBtn').disabled = false;
            })
            .catch(e => alert(t('common.networkError', { message: e.message })));
        }

        function pwgenCopy() {
            const v = document.getElementById('pwgenPreview').value;
            if (!v) return;
            navigator.clipboard.writeText(v).catch(() => {});
        }

        function pwgenUse() {
            const v = document.getElementById('pwgenPreview').value;
            if (!v) return;
            const cb = window.__pwGenCallback;
            // Chiudi il modal e invoca la callback
            const modalEl = document.getElementById('passwordGeneratorModal');
            const modal = bootstrap.Modal.getInstance(modalEl);
            if (modal) modal.hide();
            if (typeof cb === 'function') cb(v);
            window.__pwGenCallback = null;
        }

""";
    }

    /**
     * Modal "Cambia password massivo" della pagina /mailboxes.
     * Estratto come metodo per non gonfiare il text block constante della pagina.
     */
    private static String getBulkRotateMailboxesModal() {
        return """
    <!-- Bulk rotate passwords modal -->
    <div class="modal fade" id="bulkRotateModal" tabindex="-1">
        <div class="modal-dialog modal-xl modal-dialog-scrollable">
            <div class="modal-content">
                <div class="modal-header bg-warning">
                    <h5 class="modal-title"><i class="fas fa-sync-alt me-2" aria-hidden="true"></i>{{t:bulk.title}}</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="{{t:common.close}}"></button>
                </div>
                <div class="modal-body">
                    <div class="alert alert-info small mb-3">
                        <i class="fas fa-info-circle me-1" aria-hidden="true"></i>
                        {{t:bulk.intro.html}}
                    </div>

                    <div id="bulkRotateStep1" class="">
                        <!-- Opzioni generatore -->
                        <div class="border rounded p-2 mb-3" style="background:rgba(13,110,253,0.04)">
                            <div class="row g-2">
                                <div class="col-md-6">
                                    <label class="form-label small fw-bold mb-1" for="bulkRotateType">{{t:bulk.type}}</label>
                                    <select class="form-select form-select-sm" id="bulkRotateType" onchange="bulkRotateOnTypeChange()">
                                        <option value="easy_to_say">{{t:bulk.typeSay}}</option>
                                        <option value="easy_to_read" selected>{{t:bulk.typeRead}}</option>
                                        <option value="all_chars">{{t:bulk.typeAll}}</option>
                                    </select>
                                </div>
                                <div class="col-md-3">
                                    <label class="form-label small fw-bold mb-1" for="bulkRotateLength">{{t:pw.length}}</label>
                                    <input type="number" min="{{PW_MIN}}" max="128" class="form-control form-control-sm" id="bulkRotateLength" value="20">
                                </div>
                                <div class="col-md-3 d-flex align-items-end">
                                    <span class="text-muted small" id="bulkRotateSelectedCount">{{t:bulk.zeroSelected}}</span>
                                </div>
                            </div>
                            <div class="mt-2 d-flex flex-wrap gap-3 align-items-center">
                                <span class="small fw-bold text-muted">{{t:bulk.include}}</span>
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="bulkRotateInclLower" checked>
                                    <label class="form-check-label small" for="bulkRotateInclLower">{{t:pw.lower}}</label>
                                </div>
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="bulkRotateInclUpper" checked>
                                    <label class="form-check-label small" for="bulkRotateInclUpper">{{t:pw.upper}}</label>
                                </div>
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="bulkRotateInclNumbers" checked>
                                    <label class="form-check-label small" for="bulkRotateInclNumbers">{{t:pw.numbers}}</label>
                                </div>
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="bulkRotateInclSymbols" checked>
                                    <label class="form-check-label small" for="bulkRotateInclSymbols">{{t:pw.symbols}}</label>
                                </div>
                                <button class="btn btn-outline-secondary btn-sm ms-auto" type="button" onclick="bulkRotatePreviewSample()" title="{{t:bulk.sampleHint}}">
                                    <i class="fas fa-eye me-1" aria-hidden="true"></i>{{t:bulk.preview}}
                                </button>
                            </div>
                            <div class="mt-2 small text-muted" id="bulkRotatePreviewBox"></div>
                        </div>

                        <div class="d-flex gap-2 mb-2 flex-wrap">
                            <button class="btn btn-outline-secondary btn-sm" onclick="bulkRotateSelectAll()"><i class="fas fa-check-square me-1" aria-hidden="true"></i>{{t:bulk.selectAll}}</button>
                            <button class="btn btn-outline-secondary btn-sm" onclick="bulkRotateSelectNone()"><i class="fas fa-square me-1" aria-hidden="true"></i>{{t:bulk.selectNone}}</button>
                        </div>
                        <div class="table-responsive" style="max-height:50vh">
                            <table class="table table-sm table-hover align-middle mb-0">
                                <thead class="table-light sticky-top">
                                    <tr>
                                        <th style="width:40px"><input type="checkbox" class="form-check-input" id="bulkRotateChkAll" onchange="bulkRotateToggleAll(this)" aria-label="{{t:bulk.selectAll}}"></th>
                                        <th>Email</th>
                                        <th>{{t:mbx.colName}}</th>
                                        <th>{{t:bulk.vaultState}}</th>
                                    </tr>
                                </thead>
                                <tbody id="bulkRotateMboxList">
                                    <tr><td colspan="4" class="text-center text-muted"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>{{t:common.loading}}</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <div id="bulkRotateStep2" class="d-none">
                        <div class="alert alert-success" id="bulkRotateSummary"></div>
                        <div class="d-flex gap-2 mb-2">
                            <button class="btn btn-sm btn-outline-primary" onclick="bulkRotateCopyAll()"><i class="fas fa-copy me-1" aria-hidden="true"></i>{{t:bulk.copyAll}}</button>
                            <button class="btn btn-sm btn-outline-secondary" onclick="bulkRotateShowHide()" id="bulkRotateToggleVis"><i class="fas fa-eye me-1" aria-hidden="true"></i>{{t:bulk.showHide}}</button>
                        </div>
                        <div class="table-responsive" style="max-height:60vh">
                            <table class="table table-sm align-middle mb-0">
                                <thead class="table-light sticky-top"><tr><th>Email</th><th>{{t:mbx.newPass}}</th><th>{{t:home.colState}}</th></tr></thead>
                                <tbody id="bulkRotateResultsList"></tbody>
                            </table>
                        </div>
                        <div class="alert alert-warning small mt-3 mb-0">
                            <i class="fas fa-exclamation-triangle me-1" aria-hidden="true"></i>
                            {{t:bulk.important.html}}
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">{{t:common.close}}</button>
                    <button type="button" class="btn btn-warning" id="bulkRotateRunBtn" onclick="bulkRotateRun()"><i class="fas fa-bolt me-1" aria-hidden="true"></i>{{t:bulk.run}}</button>
                </div>
            </div>
        </div>
    </div>
""".replace("{{PW_MIN}}", String.valueOf(org.mail_panel.webserver.SecurityUtils.MAILBOX_PASSWORD_MIN));
    }

    /**
     * Funzioni JS per il "Cambio password massivo" delle caselle.
     * Estratte come metodo separato per ridurre la dimensione del text block constante.
     */
    private static String getBulkRotateMailboxesJs() {
        return """
        // ===== Bulk rotate passwords =====
        // Helper locale di escaping HTML (non possiamo dipendere da escapeHtmlBl
        // che è definito solo nella pagina /dns).
        if (typeof escapeHtmlBl === 'undefined') {
            window.escapeHtmlBl = function(s) {
                const d = document.createElement('div');
                d.textContent = s == null ? '' : String(s);
                return d.innerHTML;
            };
        }

        let bulkRotateResults = [];
        let bulkRotatePasswordsVisible = false;

        function openBulkRotateModal() {
            // Reset stato
            document.getElementById('bulkRotateStep1').classList.remove('d-none');
            document.getElementById('bulkRotateStep2').classList.add('d-none');
            document.getElementById('bulkRotateRunBtn').classList.remove('d-none');
            document.getElementById('bulkRotateChkAll').checked = false;
            updateBulkRotateCount();
            // Carica lista caselle
            const tbody = document.getElementById('bulkRotateMboxList');
            tbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escapeHtmlBl(t('common.loading')) + '</td></tr>';
            fetch('/api/mailboxes').then(r => r.json()).then(data => {
                const list = (data.mailboxes || []).sort((a, b) => a.email.localeCompare(b.email));
                if (list.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">' + escapeHtmlBl(t('bulk.none')) + '</td></tr>';
                    return;
                }
                let html = '';
                list.forEach(m => {
                    html += '<tr>';
                    html += '<td><input type="checkbox" class="form-check-input bulk-rotate-chk" value="' + m.id + '" onchange="updateBulkRotateCount()" aria-label="' + escapeHtmlBl(m.email) + '"></td>';
                    html += '<td><code>' + escapeHtmlBl(m.email) + '</code></td>';
                    html += '<td>' + escapeHtmlBl(m.name || '') + '</td>';
                    // Stato vault: NON disponibile su /api/mailboxes lista, mostriamo placeholder
                    html += '<td><small class="text-muted">—</small></td>';
                    html += '</tr>';
                });
                tbody.innerHTML = html;
            }).catch(e => {
                tbody.innerHTML = '<tr><td colspan="4" class="text-danger">' + escapeHtmlBl(t('bulk.loadError', { message: e.message })) + '</td></tr>';
            });
            new bootstrap.Modal(document.getElementById('bulkRotateModal')).show();
        }

        function bulkRotateToggleAll(chk) {
            document.querySelectorAll('.bulk-rotate-chk').forEach(c => c.checked = chk.checked);
            updateBulkRotateCount();
        }
        function bulkRotateSelectAll() {
            document.querySelectorAll('.bulk-rotate-chk').forEach(c => c.checked = true);
            document.getElementById('bulkRotateChkAll').checked = true;
            updateBulkRotateCount();
        }
        function bulkRotateSelectNone() {
            document.querySelectorAll('.bulk-rotate-chk').forEach(c => c.checked = false);
            document.getElementById('bulkRotateChkAll').checked = false;
            updateBulkRotateCount();
        }
        function updateBulkRotateCount() {
            const n = document.querySelectorAll('.bulk-rotate-chk:checked').length;
            document.getElementById('bulkRotateSelectedCount').textContent = tn('bulk.selected', n);
            document.getElementById('bulkRotateRunBtn').disabled = (n === 0);
        }

        function bulkRotateGetGeneratorOpts() {
            return {
                length: parseInt(document.getElementById('bulkRotateLength').value) || 20,
                type: document.getElementById('bulkRotateType').value,
                include_lowercase: document.getElementById('bulkRotateInclLower').checked,
                include_uppercase: document.getElementById('bulkRotateInclUpper').checked,
                include_numbers:   document.getElementById('bulkRotateInclNumbers').checked,
                include_symbols:   document.getElementById('bulkRotateInclSymbols').checked
            };
        }

        function bulkRotateOnTypeChange() {
            // Easy to say → disabilita numeri/simboli (per definizione)
            const type = document.getElementById('bulkRotateType').value;
            const nums = document.getElementById('bulkRotateInclNumbers');
            const syms = document.getElementById('bulkRotateInclSymbols');
            if (type === 'easy_to_say') {
                nums.disabled = true; nums.checked = false;
                syms.disabled = true; syms.checked = false;
            } else {
                nums.disabled = false;
                syms.disabled = false;
            }
        }

        function bulkRotatePreviewSample() {
            const opts = bulkRotateGetGeneratorOpts();
            if (!opts.include_lowercase && !opts.include_uppercase && !opts.include_numbers && !opts.include_symbols) {
                alert(t('bulk.pickCategory'));
                return;
            }
            const box = document.getElementById('bulkRotatePreviewBox');
            box.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escapeHtmlBl(t('bulk.generatingPreview'));
            fetch('/api/mailboxes', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(Object.assign({ action: 'generate_password', csrf_token: csrfToken }, opts))
            })
            .then(r => r.json())
            .then(data => {
                if (!data.success) {
                    box.innerHTML = '<span class="text-danger">' + escapeHtmlBl(t('common.error', { message: data.error || '' })) + '</span>';
                    return;
                }
                const ent = data.entropy_bits || 0;
                const levelValue = data.strength || '';
                const label = ({ weak: t('pw.strength.weak'), fair: t('pw.strength.fair'), strong: t('pw.strength.strong'), very_strong: t('pw.strength.very_strong') })[levelValue] || '—';
                let badgeClass = 'bg-secondary';
                if (levelValue === 'very_strong' || levelValue === 'strong') badgeClass = 'bg-success';
                else if (levelValue === 'fair') badgeClass = 'bg-warning text-dark';
                else if (levelValue === 'weak') badgeClass = 'bg-danger';
                box.innerHTML = '<strong>' + escapeHtmlBl(t('bulk.example')) + '</strong> <code class="font-monospace">' + escapeHtmlBl(data.password) +
                    '</code>  <span class="badge ' + badgeClass + ' ms-1">' + escapeHtmlBl(label) + '</span>' +
                    ' <span class="text-muted">' + escapeHtmlBl(t('bulk.bits', { bits: ent })) + '</span>';
            })
            .catch(e => { box.innerHTML = '<span class="text-danger">' + escapeHtmlBl(t('common.networkError', { message: e.message })) + '</span>'; });
        }

        function bulkRotateRun() {
            const ids = Array.from(document.querySelectorAll('.bulk-rotate-chk:checked')).map(c => parseInt(c.value));
            if (ids.length === 0) { alert(t('bulk.pickMailbox')); return; }
            const opts = bulkRotateGetGeneratorOpts();
            if (!opts.include_lowercase && !opts.include_uppercase && !opts.include_numbers && !opts.include_symbols) {
                alert(t('bulk.pickCategory'));
                return;
            }
            if (!confirm(t('bulk.confirm', { n: ids.length, type: opts.type, length: opts.length }))) return;

            const btn = document.getElementById('bulkRotateRunBtn');
            const origBtn = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1" aria-hidden="true"></span>' + escapeHtmlBl(t('bulk.generating'));

            fetch('/api/mailboxes', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(Object.assign({
                    action: 'bulk_rotate_passwords',
                    mailbox_ids: ids,
                    csrf_token: csrfToken
                }, opts))
            })
            .then(r => r.json())
            .then(data => {
                btn.disabled = false;
                btn.innerHTML = origBtn;
                if (!data.success) {
                    alert(t('common.error', { message: data.error || t('common.unknown') }));
                    return;
                }
                bulkRotateResults = data.results || [];
                bulkRotatePasswordsVisible = true;

                // Vista risultati
                document.getElementById('bulkRotateStep1').classList.add('d-none');
                document.getElementById('bulkRotateStep2').classList.remove('d-none');
                document.getElementById('bulkRotateRunBtn').classList.add('d-none');

                const summary = data.summary || {};
                document.getElementById('bulkRotateSummary').innerHTML =
                    t('bulk.done.html', { ok: escapeHtmlBl(summary.succeeded || 0), failed: escapeHtmlBl(summary.failed || 0), total: escapeHtmlBl(summary.total || 0) });

                bulkRotateRenderResults();
            })
            .catch(e => {
                btn.disabled = false;
                btn.innerHTML = origBtn;
                alert(t('common.networkError', { message: e.message }));
            });
        }

        function bulkRotateRenderResults() {
            const tbody = document.getElementById('bulkRotateResultsList');
            let html = '';
            bulkRotateResults.forEach(r => {
                html += '<tr>';
                html += '<td><code>' + escapeHtmlBl(r.email || ('id ' + r.id)) + '</code></td>';
                if (r.success && r.password) {
                    const display = bulkRotatePasswordsVisible ? r.password : ('•').repeat(r.password.length);
                    html += '<td><div class="input-group input-group-sm">';
                    html += '<input type="text" class="form-control font-monospace" value="' + escapeHtmlBl(display) + '" readonly>';
                    html += '<button class="btn btn-outline-secondary" type="button" onclick="bulkRotateCopyOne(\\'' + escapeHtmlBl((r.password || '').replace(/\\\\/g, "\\\\\\\\").replace(/'/g, "\\\\'")) + '\\')" title="' + escapeHtmlBl(t('common.copy')) + '" aria-label="' + escapeHtmlBl(t('common.copy')) + '"><i class="fas fa-copy" aria-hidden="true"></i></button>';
                    html += '</div></td>';
                    html += '<td><span class="badge bg-success">OK</span></td>';
                } else {
                    html += '<td><span class="text-danger">—</span></td>';
                    html += '<td><span class="badge bg-danger" title="' + escapeHtmlBl(r.error || '') + '">' + escapeHtmlBl(t('common.errorShort')) + '</span></td>';
                }
                html += '</tr>';
            });
            tbody.innerHTML = html;
        }

        function bulkRotateShowHide() {
            bulkRotatePasswordsVisible = !bulkRotatePasswordsVisible;
            bulkRotateRenderResults();
            document.getElementById('bulkRotateToggleVis').innerHTML = bulkRotatePasswordsVisible
                ? '<i class="fas fa-eye-slash me-1" aria-hidden="true"></i>' + escapeHtmlBl(t('bulk.hidePasswords'))
                : '<i class="fas fa-eye me-1" aria-hidden="true"></i>' + escapeHtmlBl(t('bulk.showPasswords'));
        }

        function bulkRotateCopyOne(pw) {
            navigator.clipboard.writeText(pw).catch(() => {});
        }

        function bulkRotateCopyAll() {
            // Output CSV semplice: email,password
            const lines = ['email,password'];
            bulkRotateResults.forEach(r => {
                if (r.success && r.password) {
                    // Quote-escape per CSV
                    const email = '"' + (r.email || '').replace(/"/g, '""') + '"';
                    const pw = '"' + r.password.replace(/"/g, '""') + '"';
                    lines.push(email + ',' + pw);
                }
            });
            const csv = lines.join('\\n');
            navigator.clipboard.writeText(csv).then(() => {
                alert(tn('bulk.copiedCsv', lines.length - 1));
            }).catch(() => {
                // Fallback: prompt
                window.prompt(t('bulk.copyCsvPrompt'), csv);
            });
        }

""";
    }

    public static String getMailboxesHtml() {
        String extraStyles = """
        .btn-webmail { background-color: #3498db; border-color: #3498db; }
        .feature-badge { font-size: 0.7rem; padding: 2px 6px; margin-left: 4px; }
        .action-dropdown .dropdown-menu { min-width: 200px; }
        .filter-rule { background: #f8f9fa; padding: 10px; margin-bottom: 10px; border-radius: 5px; border-left: 3px solid #0d6efd; }
        [data-theme="dark"] .filter-rule { background: #343a40; }
        .condition-row, .action-row { background: #fff; padding: 8px; margin: 5px 0; border-radius: 4px; border: 1px solid #dee2e6; }
        [data-theme="dark"] .condition-row, [data-theme="dark"] .action-row { background: #3d4249; border-color: #495057; }
        """;
        return getHead("nav.mailboxes", "mailboxes", extraStyles) + """
    <div id="main" tabindex="-1" class="content container mt-4">
        <div class="content-container">
            <div class="d-flex justify-content-between align-items-center mb-4 flex-wrap gap-2">
                <h2><i class="fas fa-inbox me-2" aria-hidden="true"></i>{{t:mbx.title}}</h2>
                <div class="d-flex gap-2 flex-wrap">
                    <button class="btn btn-outline-warning" onclick="openBulkRotateModal()" title="{{t:mbx.bulkHint}}">
                        <i class="fas fa-sync-alt me-1" aria-hidden="true"></i>{{t:mbx.bulk}}
                    </button>
                    <button class="btn btn-mail" data-bs-toggle="modal" data-bs-target="#addMailboxModal"><i class="fas fa-plus me-1" aria-hidden="true"></i>{{t:mbx.add}}</button>
                </div>
            </div>

            <div id="mbMsg" role="status" aria-live="polite"></div>
            <div class="table-responsive">
                <table class="table table-hover tabella-schede">
                    <thead class="table-light">
                        <tr><th>Email</th><th>{{t:mbx.colName}}</th><th>Quota</th><th>{{t:mbx.colFeatures}}</th><th>{{t:home.colActions}}</th></tr>
                    </thead>
                    <tbody id="mailboxesTable">
                        <tr><td colspan="5" class="text-center">{{t:common.loading}}</td></tr>
                    </tbody>
                </table>
            </div>
""" + resource("pages/apple-profile-card.html") + """
        </div>
    </div>

    <!-- Add Mailbox Modal -->
    <div class="modal fade" id="addMailboxModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header"><h5 class="modal-title">{{t:mbx.add}}</h5><button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="{{t:common.close}}"></button></div>
                <div class="modal-body">
                    <form id="addMailboxForm">
                        <div class="mb-3">
                            <label class="form-label" for="mbDomain">{{t:dom.colDomain}}</label>
                            <select class="form-select" id="mbDomain" required></select>
                        </div>
                        <div class="mb-3">
                            <label class="form-label" for="mbUser">Username</label>
                            <input type="text" class="form-control" id="mbUser" placeholder="mario" autocomplete="off" autocapitalize="off" spellcheck="false" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label" for="mbPass">Password</label>
""" + passwordField("mbPass", "") + """
                            <small class="d-block text-muted mt-1">{{t:mbx.passHint}}</small>
                        </div>
                        <div class="mb-3">
                            <label class="form-label" for="mbName">{{t:mbx.fullName}}</label>
                            <input type="text" class="form-control" id="mbName" placeholder="Mario Rossi">
                        </div>
                        <div class="mb-3">
                            <label class="form-label" for="mbQuota">Quota</label>
                            <select class="form-select" id="mbQuota">
                                <option value="1024" selected>1 GB</option>
                                <option value="256">256 MB</option>
                                <option value="512">512 MB</option>
                                <option value="2048">2 GB</option>
                                <option value="5120">5 GB</option>
                                <option value="10240">10 GB</option>
                                <option value="0">{{t:mbx.unlimited}}</option>
                            </select>
                        </div>
                        <div class="form-check form-switch mb-3">
                            <input class="form-check-input" type="checkbox" id="mbReceive" checked>
                            <label class="form-check-label" for="mbReceive">{{t:mbx.receive}}</label>
                            <small class="d-block text-muted">{{t:mbx.receiveHint}}</small>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">{{t:common.cancel}}</button>
                    <button type="button" class="btn btn-mail" onclick="addMailbox()">{{t:mbx.create}}</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Edit Mailbox Modal -->
    <div class="modal fade" id="editMailboxModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-edit me-2" aria-hidden="true"></i>{{t:mbx.edit}}</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="{{t:common.close}}"></button>
                </div>
                <div class="modal-body">
                    <input type="hidden" id="editMbId">
                    <div class="mb-3">
                        <label class="form-label" for="editMbEmail">Email</label>
                        <input type="text" class="form-control" id="editMbEmail" readonly disabled>
                    </div>
                    <div class="mb-3">
                        <label class="form-label" for="editMbName">{{t:mbx.fullName}}</label>
                        <input type="text" class="form-control" id="editMbName" placeholder="Mario Rossi">
                    </div>
                    <div class="mb-3">
                        <label class="form-label" for="editMbPass">{{t:mbx.newPass}} <small class="text-muted">{{t:mbx.newPassHint}}</small></label>
""" + passwordField("editMbPass", "{{t:mbx.newPassPh}}") + """
                        <small class="text-muted">{{t:mbx.vaultHint}}</small>

                        <!-- Riquadro per password archiviata: rivelabile con click -->
                        <div class="mt-2" id="editMbVaultBox" style="display:none">
                            <div class="border rounded p-2 small" style="background:rgba(13,110,253,0.05)">
                                <i class="fas fa-shield-alt text-primary me-1" aria-hidden="true"></i>
                                <strong>{{t:mbx.stored}}</strong> {{t:mbx.storedHint}}
                                <button type="button" class="btn btn-sm btn-link p-0 ms-2" onclick="revealMailboxStoredPassword()">
                                    <i class="fas fa-eye me-1" aria-hidden="true"></i>{{t:mbx.reveal}}
                                </button>
                                <div class="mt-1 d-none" id="editMbRevealedBox">
                                    <div class="input-group input-group-sm">
                                        <input type="text" class="form-control font-monospace" id="editMbRevealedValue" readonly>
                                        <button class="btn btn-outline-secondary" type="button" onclick="copyRevealedPassword()" title="{{t:common.copy}}"><i class="fas fa-copy" aria-hidden="true"></i></button>
                                        <button class="btn btn-outline-danger" type="button" onclick="hideRevealedPassword()" title="{{t:mbx.hide}}"><i class="fas fa-eye-slash" aria-hidden="true"></i></button>
                                    </div>
                                    <div class="small text-muted mt-1"><i class="fas fa-exclamation-triangle me-1" aria-hidden="true"></i>{{t:mbx.auditLogged}}</div>
                                </div>
                            </div>
                        </div>
                        <div class="mt-2 border rounded p-2 small text-muted" id="editMbNoCopyBox" style="display:none">
                            <i class="fas fa-info-circle me-1" aria-hidden="true"></i>{{t:mbx.noCopy}}
                        </div>
                    </div>
                    <div class="mb-3">
                        <label class="form-label" for="editMbQuota">Quota</label>
                        <select class="form-select" id="editMbQuota">
                            <option value="0">{{t:mbx.unlimited}}</option>
                            <option value="256">256 MB</option>
                            <option value="512">512 MB</option>
                            <option value="1024">1 GB</option>
                            <option value="2048">2 GB</option>
                            <option value="5120">5 GB</option>
                            <option value="10240">10 GB</option>
                            <option value="51200">50 GB</option>
                            <option value="102400">100 GB</option>
                        </select>
                    </div>
                    <div class="row">
                        <div class="col-md-6">
                            <div class="form-check form-switch mb-3">
                                <input class="form-check-input" type="checkbox" id="editMbActive" checked>
                                <label class="form-check-label" for="editMbActive">{{t:mbx.active}}</label>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="form-check form-switch mb-3">
                                <input class="form-check-input" type="checkbox" id="editMbReceive" checked>
                                <label class="form-check-label" for="editMbReceive">{{t:mbx.receive}}</label>
                            </div>
                        </div>
                    </div>
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle me-2" aria-hidden="true"></i>
                        {{t:mbx.noReply.html}}
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">{{t:common.cancel}}</button>
                    <button type="button" class="btn btn-mail" onclick="saveMailbox()">{{t:common.saveChanges}}</button>
                </div>
            </div>
        </div>
    </div>

""" + getBulkRotateMailboxesModal() + getPasswordGeneratorModal() + getMailboxToAliasModal() + """
    <!-- Mail Client Config Modal -->
""" + getMailConfigModal() + """

    <!-- Auto-Responder Modal -->
    <div class="modal fade" id="autoResponderModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-reply-all me-2" aria-hidden="true"></i>{{t:mbx.arTitle}}</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="{{t:common.close}}"></button>
                </div>
                <div class="modal-body">
                    <input type="hidden" id="arMailboxId">
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle me-2" aria-hidden="true"></i>{{t:mbx.arHint}}
                    </div>
                    <div class="form-check form-switch mb-3">
                        <input class="form-check-input" type="checkbox" id="arEnabled">
                        <label class="form-check-label" for="arEnabled">{{t:mbx.arEnable}}</label>
                    </div>
                    <div class="mb-3">
                        <label class="form-label" for="arSubject">{{t:mbx.subject}}</label>
                        <input type="text" class="form-control" id="arSubject" placeholder="{{t:mbx.arSubjectPh}}">
                    </div>
                    <div class="mb-3">
                        <label class="form-label" for="arBody">{{t:mbx.message}}</label>
                        <textarea class="form-control" id="arBody" rows="5" placeholder="{{t:mbx.arBodyPh}}"></textarea>
                    </div>
                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <label class="form-label" for="arStartDate">{{t:mbx.arStart}}</label>
                            <input type="date" class="form-control" id="arStartDate">
                        </div>
                        <div class="col-md-6 mb-3">
                            <label class="form-label" for="arEndDate">{{t:mbx.arEnd}}</label>
                            <input type="date" class="form-control" id="arEndDate">
                        </div>
                    </div>
                    <div class="mb-3">
                        <label class="form-label" for="arInterval">{{t:mbx.arInterval}}</label>
                        <input type="number" class="form-control" id="arInterval" value="24" min="1" max="168">
                        <small class="text-muted">{{t:mbx.arIntervalHint}}</small>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-outline-warning" onclick="resetVacationTracking()" title="{{t:mbx.resetHint}}">
                        <i class="fas fa-redo me-1" aria-hidden="true"></i>{{t:mbx.resetTracking}}
                    </button>
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">{{t:common.cancel}}</button>
                    <button type="button" class="btn btn-primary" onclick="saveAutoResponder()">{{t:common.save}}</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Forwarding Modal -->
    <div class="modal fade" id="forwardingModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-share me-2" aria-hidden="true"></i>{{t:mbx.fwTitle}}</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="{{t:common.close}}"></button>
                </div>
                <div class="modal-body">
                    <input type="hidden" id="fwMailboxId">
                    <div id="forwardingRules"></div>
                    <hr>
                    <h6>{{t:mbx.fwAdd}}</h6>
                    <div class="mb-3">
                        <label class="form-label" for="fwDestination">{{t:mbx.fwDest}}</label>
                        <input type="email" class="form-control" id="fwDestination" placeholder="{{t:mbx.fwDestPh}}">
                    </div>
                    <div class="form-check mb-3">
                        <input class="form-check-input" type="checkbox" id="fwKeepCopy" checked>
                        <label class="form-check-label" for="fwKeepCopy">{{t:mbx.fwKeep}}</label>
                    </div>
                    <button class="btn btn-success" onclick="addForwarding()">
                        <i class="fas fa-plus me-1" aria-hidden="true"></i>{{t:mbx.fwAdd}}
                    </button>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">{{t:common.close}}</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Sieve Filters Modal -->
    <div class="modal fade" id="sieveModal" tabindex="-1">
        <div class="modal-dialog modal-xl">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-filter me-2" aria-hidden="true"></i>{{t:mbx.svTitle}}</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="{{t:common.close}}"></button>
                </div>
                <div class="modal-body">
                    <input type="hidden" id="svMailboxId">
                    <div class="row">
                        <div class="col-md-4">
                            <h6>{{t:mbx.svActive}}</h6>
                            <div id="sieveFiltersList" class="mb-3"></div>
                            <button class="btn btn-primary btn-sm" onclick="newSieveFilter()">
                                <i class="fas fa-plus me-1" aria-hidden="true"></i>{{t:mbx.svNew}}
                            </button>
                        </div>
                        <div class="col-md-8">
                            <div id="sieveEditor" style="display:none;">
                                <input type="hidden" id="svFilterId">
                                <div class="mb-3">
                                    <label class="form-label" for="svName">{{t:mbx.svName}}</label>
                                    <input type="text" class="form-control" id="svName" placeholder="{{t:mbx.svNamePh}}">
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">{{t:mbx.svConditions}}</label>
                                    <div id="svConditions"></div>
                                    <button class="btn btn-outline-secondary btn-sm mt-2" onclick="addSieveCondition()">
                                        <i class="fas fa-plus" aria-hidden="true"></i> {{t:mbx.svAddCondition}}
                                    </button>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">{{t:home.colActions}}</label>
                                    <div id="svActions"></div>
                                    <button class="btn btn-outline-secondary btn-sm mt-2" onclick="addSieveAction()">
                                        <i class="fas fa-plus" aria-hidden="true"></i> {{t:mbx.svAddAction}}
                                    </button>
                                </div>
                                <div class="form-check mb-3">
                                    <input class="form-check-input" type="checkbox" id="svEnabled" checked>
                                    <label class="form-check-label" for="svEnabled">{{t:mbx.svEnabled}}</label>
                                </div>
                                <button class="btn btn-success" onclick="saveSieveFilter()">
                                    <i class="fas fa-save me-1" aria-hidden="true"></i>{{t:mbx.svSave}}
                                </button>
                            </div>
                            <div id="sieveHelp">
                                <div class="alert alert-secondary">
                                    <h6>{{t:mbx.svHowTitle}}</h6>
                                    <p>{{t:mbx.svHow}}</p>
                                    <ul>
                                        <li>{{t:mbx.svHowCond.html}}</li>
                                        <li>{{t:mbx.svHowAct.html}}</li>
                                    </ul>
                                    <p>{{t:mbx.svHowPick}}</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">{{t:common.close}}</button>
                </div>
            </div>
        </div>
    </div>

""" + getFooterSection() + """
    <script>
        let csrfToken = document.getElementById('csrf_token').value;
        let domains = [];
        let currentMailboxes = [];

        // Il nome della casella e' testo libero e NON e' validato in ingresso: una whitelist
        // stretta boccerebbe nomi veri come "D'Amico Real Estate". La difesa giusta e'
        // all'uscita, neutralizzando il testo quando entra nella pagina.
        function escMbx(v) {
            const d = document.createElement('div');
            d.textContent = v === null || v === undefined ? '' : String(v);
            return d.innerHTML;
        }

        function loadDomains() {
            fetch('/api/domains').then(r => r.json()).then(data => {
                domains = data.domains || [];
                const select = document.getElementById('mbDomain');
                select.innerHTML = domains.map(d => `<option value="${d.id}" data-domain="${d.domain}">${d.domain}</option>`).join('');
            });
        }

        function loadMailboxes() {
            fetch('/api/mailboxes').then(r => r.json()).then(data => {
                const tbody = document.getElementById('mailboxesTable');
                currentMailboxes = data.mailboxes || [];
                if (currentMailboxes.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="5" class="text-center">' + escMbx(t('mbx.none')) + '</td></tr>';
                    return;
                }
                tbody.innerHTML = currentMailboxes.map(m => `
                    <tr>
                        <td data-label="Email" class="testo-lungo">
                            <strong>${escMbx(m.email)}</strong>
                            ${!m.receive_enabled ? '<span class="badge bg-secondary ms-1" title="' + escMbx(t('mbx.sendOnly')) + '"><i class="fas fa-ban" aria-hidden="true"></i> No-Reply</span>' : ''}
                            ${!m.active ? '<span class="badge bg-danger ms-1">' + escMbx(t('mbx.inactive')) + '</span>' : ''}
                        </td>
                        <td data-label="${escMbx(t('mbx.colName'))}">${escMbx(m.name || '-')}</td>
                        <td data-label="Quota">${m.quota_mb === 0 ? '<span class="text-success"><i class="fas fa-infinity" aria-hidden="true"></i> ' + escMbx(t('mbx.unlimited')) + '</span>' : m.quota_mb + ' MB'}</td>
                        <td data-label="${escMbx(t('mbx.colFeatures'))}">${[
                            m.autoresponder_enabled ? '<span class="badge bg-info feature-badge" title="' + escMbx(t('mbx.arOn')) + '"><i class="fas fa-reply-all" aria-hidden="true"></i></span>' : '',
                            m.forwarding_count > 0 ? '<span class="badge bg-warning feature-badge" title="' + escMbx(t('mbx.fwOn')) + '"><i class="fas fa-share" aria-hidden="true"></i> ' + m.forwarding_count + '</span>' : '',
                            m.filters_count > 0 ? '<span class="badge bg-primary feature-badge" title="' + escMbx(t('mbx.svActive')) + '"><i class="fas fa-filter" aria-hidden="true"></i> ' + m.filters_count + '</span>' : ''
                        ].join(' ').trim()}</td>
                        <td data-label="${escMbx(t('home.colActions'))}">
                            <div class="btn-group">
                                <button class="btn btn-sm btn-webmail text-white" onclick="openWebmail('${m.email}')" title="${escMbx(t('mbx.openWebmail'))}" aria-label="${escMbx(t('mbx.openWebmail'))}">
                                    <i class="fas fa-envelope-open" aria-hidden="true"></i>
                                </button>
                                <button class="btn btn-sm btn-primary" onclick="editMailbox(${m.id})" title="${escMbx(t('common.edit'))}" aria-label="${escMbx(t('common.edit'))}">
                                    <i class="fas fa-edit" aria-hidden="true"></i>
                                </button>
                                <button class="btn btn-sm btn-info" onclick="showMailConfig('${m.email}', ${m.id})" title="${escMbx(t('mbx.clientConfig'))}" aria-label="${escMbx(t('mbx.clientConfig'))}">
                                    <i class="fas fa-mobile-alt" aria-hidden="true"></i>
                                </button>
                                <button class="btn btn-sm btn-secondary dropdown-toggle" data-bs-toggle="dropdown" aria-label="${escMbx(t('mbx.more'))}">
                                    <i class="fas fa-cog" aria-hidden="true"></i>
                                </button>
                                <ul class="dropdown-menu">
                                    <li><a class="dropdown-item" href="#" onclick="openAutoResponder(${m.id}, '${m.email}')">
                                        <i class="fas fa-reply-all me-2" aria-hidden="true"></i>Auto-Responder
                                    </a></li>
                                    <li><a class="dropdown-item" href="#" onclick="openForwarding(${m.id}, '${m.email}')">
                                        <i class="fas fa-share me-2" aria-hidden="true"></i>${escMbx(t('mbx.forwarding'))}
                                    </a></li>
                                    <li><a class="dropdown-item" href="#" onclick="openSieveFilters(${m.id}, '${m.email}')">
                                        <i class="fas fa-filter me-2" aria-hidden="true"></i>${escMbx(t('mbx.filters'))}
                                    </a></li>
                                    <li><a class="dropdown-item" href="#" onclick="openToAlias(${m.id}); return false;">
                                        <i class="fas fa-share me-2" aria-hidden="true"></i>${escMbx(t('mbx.toAlias'))}
                                    </a></li>
                                    <li><hr class="dropdown-divider"></li>
                                    <li><a class="dropdown-item text-danger" href="#" onclick="deleteMailbox(${m.id})">
                                        <i class="fas fa-trash me-2" aria-hidden="true"></i>${escMbx(t('common.delete'))}
                                    </a></li>
                                </ul>
                            </div>
                        </td>
                    </tr>
                `).join('');
            });
        }

        function addMailbox() {
            const passInput = document.getElementById('mbPass');
            if (!passInput.value) {
                document.getElementById('mbPassErr').textContent = t('mbx.needPass');
                passInput.classList.add('is-invalid');
                return;
            }
            if (!pwCheck('mbPass')) return;
            const domainId = document.getElementById('mbDomain').value;
            const domainName = document.getElementById('mbDomain').selectedOptions[0].dataset.domain;
            const user = document.getElementById('mbUser').value;
            fetch('/api/mailboxes', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    domain_id: parseInt(domainId),
                    email: user + '@' + domainName,
                    password: document.getElementById('mbPass').value,
                    name: document.getElementById('mbName').value,
                    quota_mb: parseInt(document.getElementById('mbQuota').value),
                    receive_enabled: document.getElementById('mbReceive').checked,
                    csrf_token: csrfToken
                })
            }).then(r => r.json()).then(data => {
                if (data.success) {
                    bootstrap.Modal.getInstance(document.getElementById('addMailboxModal')).hide();
                    loadMailboxes();
                    // Reset form
                    document.getElementById('mbUser').value = '';
                    document.getElementById('mbPass').value = '';
                    pwCheck('mbPass');
                    document.getElementById('mbName').value = '';
                    document.getElementById('mbQuota').value = '1024';
                    document.getElementById('mbReceive').checked = true;
                } else {
                    alert(t('common.error', { message: data.error || t('common.unknown') }));
                }
            });
        }

        function deleteMailbox(id) {
            const m = currentMailboxes.find(x => x.id === id);
            // La posta non e' nel database: eliminare la casella la lascia sul disco del server (prima diceva "e tutte le email").
            if (!confirm(t('mbx.confirmDelete', { email: m ? m.email : '' }))) return;
            fetch('/api/mailboxes?id=' + id, {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ csrf_token: csrfToken })
            }).then(r => r.json()).then(d => {
                if (!d.success) mbMsg(d.error || t('mbx.deleteFailed'), 'danger');
                loadMailboxes();
            }).catch(() => mbMsg(t('common.noAnswer'), 'danger'));
        }

        function editMailbox(id) {
            fetch('/api/mailboxes?id=' + id).then(r => r.json()).then(data => {
                if (data.success && data.mailbox) {
                    const m = data.mailbox;
                    document.getElementById('editMbId').value = m.id;
                    document.getElementById('editMbEmail').value = m.email;
                    document.getElementById('editMbName').value = m.name || '';
                    document.getElementById('editMbPass').value = '';
                    document.getElementById('editMbQuota').value = m.quota_mb;
                    document.getElementById('editMbActive').checked = m.active;
                    document.getElementById('editMbReceive').checked = m.receive_enabled;
                    // Reset stato del campo password (sempre nascosto all'apertura)
                    pwShow('editMbPass', false);
                    pwCheck('editMbPass');
                    // Reset stato del riquadro vault
                    const vaultBox = document.getElementById('editMbVaultBox');
                    const revealedBox = document.getElementById('editMbRevealedBox');
                    revealedBox.classList.add('d-none');
                    document.getElementById('editMbRevealedValue').value = '';
                    // Mostra il riquadro "Password archiviata" SOLO se ce n'è una nel vault
                    vaultBox.style.display = m.has_encrypted_password ? '' : 'none';
                    document.getElementById('editMbNoCopyBox').style.display = m.has_encrypted_password ? 'none' : '';
                    new bootstrap.Modal(document.getElementById('editMailboxModal')).show();
                } else {
                    alert(t('mbx.loadFailed'));
                }
            });
        }

""" + getPasswordFieldJs() + """
        // Una casella nuova parte con una password gia' proposta, in chiaro (vedi pwProponi).
        document.getElementById('addMailboxModal').addEventListener('show.bs.modal', function () {
            if (!document.getElementById('mbPass').value) pwPropose('mbPass');
        });

""" + getPasswordGeneratorJs() + getMailboxToAliasJs() + """
        function revealMailboxStoredPassword() {
            const id = parseInt(document.getElementById('editMbId').value);
            if (!id) return;
            if (!confirm(t('mbx.confirmReveal'))) return;
            fetch('/api/mailboxes', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'reveal_password', id: id, csrf_token: csrfToken })
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    const revealedBox = document.getElementById('editMbRevealedBox');
                    revealedBox.classList.remove('d-none');
                    document.getElementById('editMbRevealedValue').value = data.password || '';
                } else {
                    alert(data.error || t('mbx.revealFailed'));
                }
            })
            .catch(e => alert(t('common.networkError', { message: e.message })));
        }

        function copyRevealedPassword() {
            const input = document.getElementById('editMbRevealedValue');
            if (!input.value) return;
            navigator.clipboard.writeText(input.value).catch(() => {
                input.select(); document.execCommand('copy');
            });
        }

        function hideRevealedPassword() {
            const revealedBox = document.getElementById('editMbRevealedBox');
            revealedBox.classList.add('d-none');
            document.getElementById('editMbRevealedValue').value = '';
        }

""" + getBulkRotateMailboxesJs() + """
        function saveMailbox() {
            if (!pwCheck('editMbPass')) return;
            const id = parseInt(document.getElementById('editMbId').value);
            const data = {
                id: id,
                name: document.getElementById('editMbName').value,
                password: document.getElementById('editMbPass').value,
                quota_mb: parseInt(document.getElementById('editMbQuota').value),
                active: document.getElementById('editMbActive').checked,
                receive_enabled: document.getElementById('editMbReceive').checked,
                csrf_token: csrfToken
            };

            fetch('/api/mailboxes', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            }).then(r => r.json()).then(result => {
                if (result.success) {
                    bootstrap.Modal.getInstance(document.getElementById('editMailboxModal')).hide();
                    loadMailboxes();
                    if (result.warning) {
                        alert(result.warning);
                    }
                } else {
                    alert(t('common.error', { message: result.error || t('common.unknown') }));
                }
            });
        }

        // Stato corrente del modal mailConfig (email + id casella selezionata)
        let __cfgCurrentEmail = '';
        let __cfgCurrentMailboxId = 0;

        function showMailConfig(email, mailboxId) {
            __cfgCurrentEmail = email || '';
            __cfgCurrentMailboxId = mailboxId || 0;

            // Email completa nel campo Credenziali principale
            const emailField = document.getElementById('cfgEmailField');
            if (emailField) emailField.value = email;
            // Email replicata in tutti i tab (Outlook/Apple/Android)
            document.querySelectorAll('.cfg-shared-email').forEach(el => { el.value = email; });

            // Reset campo password
            const pwField = document.getElementById('cfgPasswordField');
            const pwToggle = document.getElementById('cfgPasswordToggleBtn');
            const pwCopy = document.getElementById('cfgPasswordCopyBtn');
            const pwReveal = document.getElementById('cfgPasswordRevealBtn');
            const pwHint = document.getElementById('cfgPasswordHint');
            if (pwField) {
                pwField.value = '';
                pwField.type = 'password';
            }
            if (pwToggle) { pwToggle.innerHTML = '<i class="fas fa-eye" aria-hidden="true"></i>'; pwToggle.disabled = true; }
            if (pwCopy) pwCopy.disabled = true;
            if (pwReveal) {
                pwReveal.disabled = false;
                pwReveal.innerHTML = '<i class="fas fa-unlock me-1" aria-hidden="true"></i>' + escMbx(t('mbx.reveal'));
            }
            if (pwHint) pwHint.textContent = t('mbx.revealHint');

            // Carica server config
            fetch('/api/mailconfig').then(r => r.json()).then(data => {
                if (data.success) {
                    const server = data.server;
                    // Generale
                    setValIfExists('cfgImapServer', server);
                    setValIfExists('cfgPop3Server', server);
                    setValIfExists('cfgSmtpServer', server);
                    // Outlook
                    setValIfExists('cfgOutlookImap', server);
                    setValIfExists('cfgOutlookSmtp', server);
                    // Apple
                    setValIfExists('cfgAppleImap', server);
                    setValIfExists('cfgAppleSmtp', server);
                    // Android
                    setValIfExists('cfgAndroidImap', server);
                    setValIfExists('cfgAndroidSmtp', server);
                }
                new bootstrap.Modal(document.getElementById('mailConfigModal')).show();
            });
        }

        function setValIfExists(id, val) {
            const el = document.getElementById(id);
            if (el) el.value = val;
        }

        // Helper generico: copia il value di un input negli appunti
        function copyInputValue(id) {
            const el = document.getElementById(id);
            if (!el || !el.value) return;
            const wasPassword = (el.type === 'password');
            // Se è password (mascherato), abbiamo bisogno di rivelarlo brevemente per copiare
            if (wasPassword) el.type = 'text';
            navigator.clipboard.writeText(el.value).catch(() => {
                try { el.select(); document.execCommand('copy'); } catch (e) {}
            });
            if (wasPassword) el.type = 'password';
        }

        // Helper per i campi "cfg-shared-email" replicati nei tab (Outlook/Apple/Android)
        function copySharedField(btn) {
            const input = btn.parentElement.querySelector('input');
            if (!input || !input.value) return;
            navigator.clipboard.writeText(input.value).catch(() => {
                try { input.select(); document.execCommand('copy'); } catch (e) {}
            });
        }

        function toggleCfgPasswordVisibility() {
            const input = document.getElementById('cfgPasswordField');
            const btn = document.getElementById('cfgPasswordToggleBtn');
            if (!input || !btn) return;
            if (input.type === 'password') {
                input.type = 'text';
                btn.innerHTML = '<i class="fas fa-eye-slash" aria-hidden="true"></i>';
            } else {
                input.type = 'password';
                btn.innerHTML = '<i class="fas fa-eye" aria-hidden="true"></i>';
            }
        }

        function revealCfgPassword() {
            if (!__cfgCurrentMailboxId) {
                alert(t('mbx.unknownBox'));
                return;
            }
            const btn = document.getElementById('cfgPasswordRevealBtn');
            const pwField = document.getElementById('cfgPasswordField');
            const pwToggle = document.getElementById('cfgPasswordToggleBtn');
            const pwCopy = document.getElementById('cfgPasswordCopyBtn');
            const pwHint = document.getElementById('cfgPasswordHint');
            if (!confirm(t('mbx.confirmRevealOf', { email: __cfgCurrentEmail }))) return;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>...';
            fetch('/api/mailboxes', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'reveal_password', id: __cfgCurrentMailboxId, csrf_token: csrfToken })
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    pwField.value = data.password || '';
                    pwField.type = 'text';
                    if (pwToggle) {
                        pwToggle.disabled = false;
                        pwToggle.innerHTML = '<i class="fas fa-eye-slash" aria-hidden="true"></i>';
                    }
                    if (pwCopy) pwCopy.disabled = false;
                    btn.innerHTML = '<i class="fas fa-check me-1" aria-hidden="true"></i>' + escMbx(t('mbx.revealed'));
                    if (pwHint) pwHint.innerHTML = '<span class="text-success">' + escMbx(t('mbx.recovered')) + '</span>';
                } else {
                    btn.disabled = false;
                    btn.innerHTML = '<i class="fas fa-unlock me-1" aria-hidden="true"></i>' + escMbx(t('mbx.reveal'));
                    if (pwHint) pwHint.innerHTML = '<span class="text-danger">' + escMbx(data.error || t('common.errorShort')) + '</span>';
                }
            })
            .catch(e => {
                btn.disabled = false;
                btn.innerHTML = '<i class="fas fa-unlock me-1" aria-hidden="true"></i>' + escMbx(t('mbx.reveal'));
                if (pwHint) pwHint.innerHTML = '<span class="text-danger">' + escMbx(t('common.networkError', { message: e.message })) + '</span>';
            });
        }

        function openWebmail(email) {
            // SSO with master user - no password needed
            fetch('/api/webmail/open', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: email })
            }).then(r => r.json()).then(data => {
                if (data.success && data.redirect_url) {
                    window.open(data.redirect_url, '_blank');
                } else {
                    alert(t('mbx.ssoError', { message: data.error || t('mbx.ssoFailed') }));
                }
            });
        }

        // ========== AUTO-RESPONDER ==========
        function openAutoResponder(mailboxId, email) {
            document.getElementById('arMailboxId').value = mailboxId;
            document.querySelector('#autoResponderModal .modal-title').innerHTML =
                '<i class="fas fa-reply-all me-2" aria-hidden="true"></i>' + escMbx(t('mbx.arFor', { email: email }));

            fetch('/api/autoresponder?mailbox_id=' + mailboxId)
                .then(r => r.json())
                .then(data => {
                    if (data.success) {
                        document.getElementById('arEnabled').checked = data.enabled || false;
                        document.getElementById('arSubject').value = data.subject || '';
                        document.getElementById('arBody').value = data.body || '';
                        document.getElementById('arStartDate').value = data.start_date || '';
                        document.getElementById('arEndDate').value = data.end_date || '';
                        document.getElementById('arInterval').value = data.interval_hours || 24;
                    }
                    new bootstrap.Modal(document.getElementById('autoResponderModal')).show();
                });
        }

        function saveAutoResponder() {
            fetch('/api/autoresponder', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    mailbox_id: parseInt(document.getElementById('arMailboxId').value),
                    enabled: document.getElementById('arEnabled').checked,
                    subject: document.getElementById('arSubject').value,
                    body: document.getElementById('arBody').value,
                    start_date: document.getElementById('arStartDate').value || null,
                    end_date: document.getElementById('arEndDate').value || null,
                    interval_hours: parseInt(document.getElementById('arInterval').value)
                })
            }).then(r => r.json()).then(data => {
                if (data.success) {
                    bootstrap.Modal.getInstance(document.getElementById('autoResponderModal')).hide();
                    loadMailboxes();
                } else {
                    alert(data.error || t('common.errorShort'));
                }
            });
        }

        function resetVacationTracking() {
            if (!confirm(t('mbx.confirmReset'))) {
                return;
            }
            fetch('/api/autoresponder', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action: 'reset_tracking',
                    mailbox_id: parseInt(document.getElementById('arMailboxId').value)
                })
            }).then(r => r.json()).then(data => {
                if (data.success) {
                    alert(t('mbx.resetDone'));
                } else {
                    alert(data.error || t('common.errorShort'));
                }
            });
        }

        // ========== FORWARDING ==========
        function openForwarding(mailboxId, email) {
            document.getElementById('fwMailboxId').value = mailboxId;
            document.querySelector('#forwardingModal .modal-title').innerHTML =
                '<i class="fas fa-share me-2" aria-hidden="true"></i>' + escMbx(t('mbx.fwFor', { email: email }));
            document.getElementById('fwDestination').value = '';
            document.getElementById('fwKeepCopy').checked = true;

            loadForwardingRules(mailboxId);
            new bootstrap.Modal(document.getElementById('forwardingModal')).show();
        }

        function loadForwardingRules(mailboxId) {
            fetch('/api/forwarding?mailbox_id=' + mailboxId)
                .then(r => r.json())
                .then(data => {
                    const container = document.getElementById('forwardingRules');
                    const rules = data.rules || [];
                    if (rules.length === 0) {
                        container.innerHTML = '<p class="text-muted">' + escMbx(t('mbx.fwNone')) + '</p>';
                        return;
                    }
                    container.innerHTML = rules.map(r => `
                        <div class="d-flex justify-content-between align-items-center mb-2 p-2 bg-light rounded">
                            <div>
                                <i class="fas fa-arrow-right me-2" aria-hidden="true"></i>${escMbx(r.destination)}
                                ${r.keep_copy ? '<span class="badge bg-secondary ms-2">' + escMbx(t('mbx.localCopy')) + '</span>' : ''}
                                ${!r.enabled ? '<span class="badge bg-warning text-dark ms-2">' + escMbx(t('mbx.disabled')) + '</span>' : ''}
                            </div>
                            <button class="btn btn-sm btn-outline-danger" onclick="deleteForwarding(${r.id})" aria-label="${escMbx(t('common.delete'))}">
                                <i class="fas fa-trash" aria-hidden="true"></i>
                            </button>
                        </div>
                    `).join('');
                });
        }

        function addForwarding() {
            const dest = document.getElementById('fwDestination').value.trim();
            if (!dest) { alert(t('mbx.enterEmail')); return; }

            fetch('/api/forwarding', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action: 'create',
                    mailbox_id: parseInt(document.getElementById('fwMailboxId').value),
                    destination: dest,
                    keep_copy: document.getElementById('fwKeepCopy').checked
                })
            }).then(r => r.json()).then(data => {
                if (data.success) {
                    document.getElementById('fwDestination').value = '';
                    loadForwardingRules(document.getElementById('fwMailboxId').value);
                    loadMailboxes();
                } else {
                    alert(data.error || t('common.errorShort'));
                }
            });
        }

        function deleteForwarding(id) {
            if (!confirm(t('mbx.confirmFwDelete'))) return;
            fetch('/api/forwarding', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'delete', id: id })
            }).then(r => r.json()).then(data => {
                if (data.success) {
                    loadForwardingRules(document.getElementById('fwMailboxId').value);
                    loadMailboxes();
                }
            });
        }

        // ========== SIEVE FILTERS ==========
        let sieveConditions = [];
        let sieveActions = [];

        // Il nome del filtro lo sceglie chi lo crea: testo libero, quindi neutralizzato
        // quando entra nella pagina.
        function escSieve(v) {
            const d = document.createElement('div');
            d.textContent = v === null || v === undefined ? '' : String(v);
            return d.innerHTML;
        }

        function openSieveFilters(mailboxId, email) {
            document.getElementById('svMailboxId').value = mailboxId;
            document.querySelector('#sieveModal .modal-title').innerHTML =
                '<i class="fas fa-filter me-2" aria-hidden="true"></i>' + escMbx(t('mbx.svFor', { email: email }));

            document.getElementById('sieveEditor').style.display = 'none';
            document.getElementById('sieveHelp').style.display = 'block';
            loadSieveFilters(mailboxId);
            new bootstrap.Modal(document.getElementById('sieveModal')).show();
        }

        function loadSieveFilters(mailboxId) {
            fetch('/api/sieve?mailbox_id=' + mailboxId)
                .then(r => r.json())
                .then(data => {
                    const container = document.getElementById('sieveFiltersList');
                    const filters = data.filters || [];
                    if (filters.length === 0) {
                        container.innerHTML = '<p class="text-muted">' + escMbx(t('mbx.svNone')) + '</p>';
                        return;
                    }
                    container.innerHTML = filters.map(f => `
                        <div class="filter-rule ${!f.enabled ? 'opacity-50' : ''}" onclick="editSieveFilter(${f.id})">
                            <div class="d-flex justify-content-between">
                                <strong>${escSieve(f.name)}</strong>
                                ${f.enabled ? '<span class="badge bg-success">' + escMbx(t('mbx.on')) + '</span>' : '<span class="badge bg-secondary">' + escMbx(t('mbx.off')) + '</span>'}
                            </div>
                        </div>
                    `).join('');
                });
        }

        function newSieveFilter() {
            document.getElementById('svFilterId').value = '';
            document.getElementById('svName').value = '';
            document.getElementById('svEnabled').checked = true;
            sieveConditions = [];
            sieveActions = [];
            renderSieveConditions();
            renderSieveActions();
            document.getElementById('sieveEditor').style.display = 'block';
            document.getElementById('sieveHelp').style.display = 'none';
        }

        function editSieveFilter(id) {
            fetch('/api/sieve?id=' + id)
                .then(r => r.json())
                .then(data => {
                    const f = data.filter;
                    document.getElementById('svFilterId').value = f.id;
                    document.getElementById('svName').value = f.name;
                    document.getElementById('svEnabled').checked = f.enabled;
                    sieveConditions = JSON.parse(f.conditions || '[]');
                    sieveActions = JSON.parse(f.actions || '[]');
                    renderSieveConditions();
                    renderSieveActions();
                    document.getElementById('sieveEditor').style.display = 'block';
                    document.getElementById('sieveHelp').style.display = 'none';
                });
        }

        function addSieveCondition() {
            sieveConditions.push({ field: 'from', operator: 'contains', value: '' });
            renderSieveConditions();
        }

        function addSieveAction() {
            sieveActions.push({ type: 'move', value: 'INBOX.Filtered' });
            renderSieveActions();
        }

        function renderSieveConditions() {
            document.getElementById('svConditions').innerHTML = sieveConditions.map((c, i) => `
                <div class="condition-row d-flex gap-2 align-items-center">
                    <select class="form-select form-select-sm" style="width:120px" onchange="sieveConditions[${i}].field=this.value">
                        <option value="from" ${c.field==='from'?'selected':''}>${escHtml(t('mbx.svFrom'))}</option>
                        <option value="to" ${c.field==='to'?'selected':''}>${escHtml(t('mbx.svTo'))}</option>
                        <option value="subject" ${c.field==='subject'?'selected':''}>${escHtml(t('mbx.subject'))}</option>
                        <option value="body" ${c.field==='body'?'selected':''}>${escHtml(t('mbx.svBody'))}</option>
                    </select>
                    <select class="form-select form-select-sm" style="width:130px" onchange="sieveConditions[${i}].operator=this.value">
                        <option value="contains" ${c.operator==='contains'?'selected':''}>${escHtml(t('mbx.svContains'))}</option>
                        <option value="is" ${c.operator==='is'?'selected':''}>${escHtml(t('mbx.svIs'))}</option>
                        <option value="matches" ${c.operator==='matches'?'selected':''}>${escHtml(t('mbx.svMatches'))}</option>
                        <option value="not_contains" ${c.operator==='not_contains'?'selected':''}>${escHtml(t('mbx.svNotContains'))}</option>
                    </select>
                    <input type="text" class="form-control form-control-sm" value="${escMbx(c.value)}" aria-label="${escMbx(t('mbx.svValue'))}" onchange="sieveConditions[${i}].value=this.value">
                    <button class="btn btn-sm btn-outline-danger" onclick="sieveConditions.splice(${i},1);renderSieveConditions()">
                        <i class="fas fa-times" aria-hidden="true"></i>
                    </button>
                </div>
            `).join('') || '<p class="text-muted">' + escMbx(t('mbx.svNoCond')) + '</p>';
        }

        function renderSieveActions() {
            document.getElementById('svActions').innerHTML = sieveActions.map((a, i) => `
                <div class="action-row d-flex gap-2 align-items-center">
                    <select class="form-select form-select-sm" style="width:150px" onchange="sieveActions[${i}].type=this.value;renderSieveActions()">
                        <option value="move" ${a.type==='move'?'selected':''}>${escHtml(t('mbx.svMove'))}</option>
                        <option value="copy" ${a.type==='copy'?'selected':''}>${escHtml(t('mbx.svCopy'))}</option>
                        <option value="delete" ${a.type==='delete'?'selected':''}>${escHtml(t('common.delete'))}</option>
                        <option value="mark_read" ${a.type==='mark_read'?'selected':''}>${escHtml(t('mbx.svMarkRead'))}</option>
                        <option value="forward" ${a.type==='forward'?'selected':''}>${escHtml(t('mbx.svForward'))}</option>
                        <option value="reject" ${a.type==='reject'?'selected':''}>${escHtml(t('mbx.svReject'))}</option>
                    </select>
                    ${['move','copy','forward','reject'].includes(a.type) ?
                        `<input type="text" class="form-control form-control-sm" value="${escMbx(a.value||'')}" placeholder="${a.type==='forward'?'email@...':escMbx(t('mbx.svFolder'))}" onchange="sieveActions[${i}].value=this.value">` : ''}
                    <button class="btn btn-sm btn-outline-danger" onclick="sieveActions.splice(${i},1);renderSieveActions()">
                        <i class="fas fa-times" aria-hidden="true"></i>
                    </button>
                </div>
            `).join('') || '<p class="text-muted">' + escMbx(t('mbx.svNoAct')) + '</p>';
        }

        function saveSieveFilter() {
            const name = document.getElementById('svName').value.trim();
            if (!name) { alert(t('mbx.svNeedName')); return; }
            if (sieveConditions.length === 0) { alert(t('mbx.svNeedCond')); return; }
            if (sieveActions.length === 0) { alert(t('mbx.svNeedAct')); return; }

            const filterId = document.getElementById('svFilterId').value;
            fetch('/api/sieve', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action: filterId ? 'update' : 'create',
                    id: filterId ? parseInt(filterId) : undefined,
                    mailbox_id: parseInt(document.getElementById('svMailboxId').value),
                    name: name,
                    conditions: JSON.stringify(sieveConditions),
                    actions: JSON.stringify(sieveActions),
                    enabled: document.getElementById('svEnabled').checked
                })
            }).then(r => r.json()).then(data => {
                if (data.success) {
                    loadSieveFilters(document.getElementById('svMailboxId').value);
                    loadMailboxes();
                    document.getElementById('sieveEditor').style.display = 'none';
                    document.getElementById('sieveHelp').style.display = 'block';
                } else {
                    alert(data.error || t('common.errorShort'));
                }
            });
        }

""" + resource("pages/apple-profile.js") + """
        loadDomains();
        loadMailboxes();
        paLoad();
    </script>
</body>
</html>
""";
    }

    // ============== ALIASES.HTML ==============
    // La pagina mostrava solo l'elenco: non c'era modo di creare un alias, e "Elimina" non era
    // collegato a niente, mentre /api/aliases sapeva gia' fare entrambe le cose.
    public static String getAliasesHtml() {
        return getHead("nav.aliases", "aliases", "") + """
    <div id="main" tabindex="-1" class="content container mt-4">
        <div class="content-container">
            <div class="d-flex justify-content-between align-items-center mb-2 flex-wrap gap-2">
                <h2><i class="fas fa-share me-2" aria-hidden="true"></i>{{t:al.title}}</h2>
                <button class="btn btn-mail" data-bs-toggle="modal" data-bs-target="#addAliasModal"><i class="fas fa-plus me-1" aria-hidden="true"></i>{{t:al.add}}</button>
            </div>
            <p>{{t:al.intro}}</p>
            <div id="aliasMsg" role="status" aria-live="polite"></div>
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead><tr><th>{{t:al.source}}</th><th>{{t:mbx.fwDest}}</th><th>{{t:home.colActions}}</th></tr></thead>
                    <tbody id="aliasesTable"><tr><td colspan="3">{{t:common.loading}}</td></tr></tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Add Alias Modal -->
    <div class="modal fade" id="addAliasModal" tabindex="-1" aria-labelledby="addAliasTitle">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header"><h5 class="modal-title" id="addAliasTitle">{{t:al.add}}</h5><button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="{{t:common.close}}"></button></div>
                <div class="modal-body">
                    <form id="addAliasForm" onsubmit="addAlias(); return false;">
                        <label class="form-label" for="alLocal">{{t:al.source}}</label>
                        <div class="input-group mb-1">
                            <input type="text" class="form-control" id="alLocal" placeholder="info" maxlength="64" autocomplete="off" required>
                            <span class="input-group-text">@</span>
                            <select class="form-select" id="alDomain" aria-label="{{t:al.sourceDomain}}" required></select>
                        </div>
                        <small class="d-block text-muted mb-3">{{t:al.sourceHint}}</small>
                        <label class="form-label" for="alDest">{{t:mbx.fwDest}}</label>
                        <input type="email" class="form-control mb-1" id="alDest" placeholder="{{t:al.destPh}}" maxlength="254" autocomplete="off" required>
                        <small class="d-block text-muted mb-3">{{t:al.destHint}}</small>
                        <div class="alert alert-info py-2 small mb-0">
                            {{t:al.addHint.html}}
                        </div>
                        <div id="alErr" class="text-danger small mt-2" role="alert"></div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">{{t:common.cancel}}</button>
                    <button type="button" class="btn btn-mail" onclick="addAlias()">{{t:al.create}}</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Edit Alias Modal -->
    <div class="modal fade" id="editAliasModal" tabindex="-1" aria-labelledby="editAliasTitle">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header"><h5 class="modal-title" id="editAliasTitle">{{t:al.edit}}</h5><button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="{{t:common.close}}"></button></div>
                <div class="modal-body">
                    <form id="editAliasForm" onsubmit="saveAlias(); return false;">
                        <input type="hidden" id="edAliasId">
                        <label class="form-label" for="edSource">{{t:al.source}}</label>
                        <input type="text" class="form-control mb-1" id="edSource" readonly>
                        <small class="d-block text-muted mb-3">{{t:al.sourceFixed}}</small>
                        <label class="form-label" for="edDest">{{t:mbx.fwDest}}</label>
                        <input type="email" class="form-control mb-1" id="edDest" maxlength="254" autocomplete="off" required>
                        <small class="d-block text-muted">{{t:al.editHint}}</small>
                        <div id="edErr" class="text-danger small mt-2" role="alert"></div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">{{t:common.cancel}}</button>
                    <button type="button" class="btn btn-mail" onclick="saveAlias()">{{t:common.save}}</button>
                </div>
            </div>
        </div>
    </div>
""" + getAliasToMailboxModal() + getPasswordGeneratorModal() + getFooterSection() + """
    <script>
        let csrfToken = document.getElementById('csrf_token').value;

        function escAl(v) {
            const d = document.createElement('div');
            d.textContent = v === null || v === undefined ? '' : String(v);
            return d.innerHTML;
        }

        function aliasMsg(textValue, kindValue) {
            document.getElementById('aliasMsg').innerHTML = textValue
                ? '<div class="alert alert-' + kindValue + ' py-2 small">' + escAl(textValue) + '</div>' : '';
        }

        function loadAliasDomains() {
            fetch('/api/domains').then(r => r.json()).then(data => {
                const domainList = data.domains || [];
                const select = document.getElementById('alDomain');
                select.innerHTML = domainList.map(d => '<option value="' + escAl(d.domain) + '">' + escAl(d.domain) + '</option>').join('');
                if (domainList.length === 0) {
                    select.innerHTML = '<option value="">' + escAl(t('al.noDomain')) + '</option>';
                    document.getElementById('alErr').textContent = t('al.addDomainFirst');
                }
            });
        }

        let currentAliases = [];

        function loadAliases() {
            fetch('/api/aliases').then(r => r.json()).then(data => {
                const tbody = document.getElementById('aliasesTable');
                if (!data.success) {
                    tbody.innerHTML = '<tr><td colspan="3" class="text-danger">' + escAl(data.error || t('al.loadError')) + '</td></tr>';
                    return;
                }
                currentAliases = data.aliases || [];
                if (currentAliases.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="3">' + escAl(t('al.none')) + '</td></tr>';
                    return;
                }
                tbody.innerHTML = currentAliases.map(a => {
                    const id = parseInt(a.id);
                    const whoText = escAl(t('al.who', { source: a.source, dest: a.destination }));
                    return '<tr' + (a.active ? '' : ' class="text-muted"') + '><td class="testo-lungo">' + escAl(a.source) + '</td><td class="testo-lungo">' + escAl(a.destination)
                        + (a.active ? '' : ' <span class="badge bg-secondary ms-1">' + escAl(t('mbx.inactive')) + '</span>') + '</td>'
                        + '<td class="text-nowrap">'
                        + '<button type="button" class="btn btn-sm btn-outline-primary me-1" onclick="openEditAlias(' + id + ')" aria-label="' + escAl(t('al.editOf')) + ' ' + whoText + '">' + escAl(t('common.edit')) + '</button>'
                        + (a.source.startsWith('@') ? '' : '<button type="button" class="btn btn-sm btn-outline-success me-1" onclick="openToMailbox(' + id + ')"'
                            + ' title="' + escAl(t('al.toMailboxHint')) + '" aria-label="' + escAl(t('al.toMailboxOf', { source: a.source })) + '">' + escAl(t('al.toMailboxShort')) + '</button>')
                        + '<button type="button" class="btn btn-sm btn-outline-secondary me-1" onclick="toggleAlias(' + id + ', ' + (a.active ? 'false' : 'true') + ')"'
                        + ' aria-label="' + escAl(a.active ? t('al.disableOf') : t('al.enableOf')) + ' ' + whoText + '">' + escAl(a.active ? t('al.disable') : t('al.enable')) + '</button>'
                        + '<button type="button" class="btn btn-sm btn-danger" onclick="deleteAlias(' + id + ')" aria-label="' + escAl(t('al.deleteOf')) + ' ' + whoText + '">' + escAl(t('common.delete')) + '</button>'
                        + '</td></tr>';
                }).join('');
            });
        }

        function openEditAlias(id) {
            const a = currentAliases.find(x => parseInt(x.id) === id);
            if (!a) return;
            document.getElementById('edAliasId').value = id;
            document.getElementById('edSource').value = a.source;
            document.getElementById('edDest').value = a.destination;
            document.getElementById('edErr').textContent = '';
            bootstrap.Modal.getOrCreateInstance(document.getElementById('editAliasModal')).show();
        }

        function saveAlias() {
            const err = document.getElementById('edErr');
            err.textContent = '';
            const id = parseInt(document.getElementById('edAliasId').value);
            const source = document.getElementById('edSource').value;
            const dest = document.getElementById('edDest').value.trim().toLowerCase();
            if (!dest) { err.textContent = t('al.needDest'); return; }
            fetch('/api/aliases', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ id: id, destination: dest, csrf_token: csrfToken })
            }).then(r => r.json()).then(data => {
                if (data.success) {
                    bootstrap.Modal.getInstance(document.getElementById('editAliasModal')).hide();
                    aliasMsg(data.note || t('al.updated', { source: source, dest: dest }), data.note ? 'warning' : 'success');
                    loadAliases();
                } else {
                    err.textContent = data.error || t('common.unknownErrorCap');
                }
            }).catch(() => { err.textContent = t('common.noAnswer'); });
        }

        function toggleAlias(id, isOn) {
            const a = currentAliases.find(x => parseInt(x.id) === id);
            if (!a) return;
            if (!isOn && !confirm(t('al.confirmDisable', { source: a.source, dest: a.destination }))) return;
            fetch('/api/aliases', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ id: id, active: isOn, csrf_token: csrfToken })
            }).then(r => r.json()).then(data => {
                if (data.success) aliasMsg(data.note || (isOn ? t('al.enabled', { source: a.source, dest: a.destination }) : t('al.disabled', { source: a.source, dest: a.destination })), data.note ? 'warning' : 'success');
                else aliasMsg(data.error || t('common.failed'), 'danger');
                loadAliases();
            }).catch(() => aliasMsg(t('common.noAnswer'), 'danger'));
        }

        function addAlias() {
            const err = document.getElementById('alErr');
            err.textContent = '';
            const local = document.getElementById('alLocal').value.trim().toLowerCase();
            const domain = document.getElementById('alDomain').value;
            const dest = document.getElementById('alDest').value.trim().toLowerCase();
            if (!local || !domain || !dest) { err.textContent = t('al.fillBoth'); return; }
            // Sorgente = destinazione e' ammessa solo su una casella (serve a tenerne una copia):
            // lo decide il server, che sa quali indirizzi sono caselle.
            const source = local + '@' + domain;
            fetch('/api/aliases', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ source: source, destination: dest, csrf_token: csrfToken })
            }).then(r => r.json()).then(data => {
                if (data.success) {
                    bootstrap.Modal.getInstance(document.getElementById('addAliasModal')).hide();
                    document.getElementById('alLocal').value = '';
                    document.getElementById('alDest').value = '';
                    aliasMsg(data.note || t('al.created', { source: source, dest: dest }), data.note ? 'warning' : 'success');
                    loadAliases();
                } else {
                    err.textContent = data.error || t('common.unknownErrorCap');
                }
            }).catch(() => { err.textContent = t('common.noAnswer'); });
        }

        function deleteAlias(id) {
            if (!confirm(t('al.confirmDelete'))) return;
            fetch('/api/aliases?id=' + id, {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ csrf_token: csrfToken })
            }).then(r => r.json()).then(data => {
                if (data.success) aliasMsg(data.note || t('al.deleted'), data.note ? 'warning' : 'success');
                else aliasMsg(data.error || t('mbx.deleteFailed'), 'danger');
                loadAliases();
            }).catch(() => aliasMsg(t('common.noAnswer'), 'danger'));
        }

""" + getPasswordFieldJs() + getPasswordGeneratorJs() + getAliasToMailboxJs() + """
        loadAliasDomains();
        loadAliases();
""" + """
    </script>
</body>
</html>
""";
    }

    // ============== DNS.HTML - Full DNS Records Page ==============
    /**
     * Seconda metà del blocco JS della pagina /dns,
     * estratta per stare sotto il limite di 65535 byte del constant pool Java.
     */
    private static String getDnsJsPart2() {
        return """
        // ===== DKIM rotation =====
        function loadDkimRotationStatus(domainId) {
            fetch('/api/dkim', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'rotate_status', domain_id: parseInt(domainId) })
            }).then(r => r.json()).then(data => {
                const panel = document.getElementById('dkimRotationPanel');
                const stepper = document.getElementById('dkimRotationStepper');
                const body = document.getElementById('dkimRotationBody');
                const badge = document.getElementById('dkimRotationBadge');
                const rotateBtn = document.getElementById('rotateDkimBtn');
                const cfInfo = document.getElementById('dkimDomainCfInfo');
                const state = data.rotation_state || '';

                // Aggiorna il flag e l'info CF visibile sopra ai bottoni
                cloudflareConfigured = !!data.cloudflare_configured;
                if (cfInfo) {
                    if (data.cloudflare_configured) {
                        const lbl = data.cloudflare_account_label || '?';
                        const em = data.cloudflare_account_email ? ' (' + escapeHtmlBl(data.cloudflare_account_email) + ')' : '';
                        cfInfo.innerHTML = '<div class="alert alert-info py-2 mb-0 small"><i class="fas fa-cloud me-1" aria-hidden="true"></i><strong>' + escHtml(t('dns.autoViaCf')) + '</strong> ' + escHtml(t('dns.autoViaCfHint', { account: lbl + (data.cloudflare_account_email ? ' (' + data.cloudflare_account_email + ')' : '') })) + '</div>';
                    } else if (data.has_dkim) {
                        cfInfo.innerHTML = '<div class="alert alert-secondary py-2 mb-0 small"><i class="fas fa-edit me-1" aria-hidden="true"></i><strong>' + escHtml(t('dns.manualRotation')) + '</strong> ' + escHtml(t('dns.manualRotationHint')) + ' <a href="/cloudflare" class="alert-link">' + escHtml(t('dns.assignCf')) + '</a>.</div>';
                    } else {
                        cfInfo.innerHTML = '';
                    }
                }

                if (!data.success || !state) {
                    panel.classList.add('d-none');
                    badge.innerHTML = '';
                    if (rotateBtn && data.has_dkim) rotateBtn.disabled = false;
                    return;
                }

                // Rotazione in corso: nascondi il bottone "Avvia rotazione"
                if (rotateBtn) rotateBtn.disabled = true;
                panel.classList.remove('d-none');

                // Badge sull'header
                if (state === 'pending_dns')      badge.innerHTML = '<span class="badge bg-warning text-dark">' + escHtml(t('dns.badgePending')) + '</span>';
                else if (state === 'propagated')  badge.innerHTML = '<span class="badge bg-info text-dark">' + escHtml(t('dns.badgePropagated')) + '</span>';
                else if (state === 'active_grace') badge.innerHTML = '<span class="badge bg-success">' + escHtml(t('dns.badgeGrace')) + '</span>';

                // Stepper
                const stepDef = [
                    { key: 'pending_dns',   label: t('dns.step1') },
                    { key: 'propagated',    label: t('dns.step2') },
                    { key: 'active_grace',  label: t('dns.step3') },
                    { key: 'completed',     label: t('dns.step4') }
                ];
                let stepperHtml = '<div class="d-flex justify-content-between flex-wrap gap-2">';
                let activeIdx = 0;
                if (state === 'pending_dns')      activeIdx = 0;
                else if (state === 'propagated')  activeIdx = 1;
                else if (state === 'active_grace') activeIdx = 2;
                stepDef.forEach((s, i) => {
                    let cls = 'badge bg-secondary';
                    if (i < activeIdx) cls = 'badge bg-success';
                    else if (i === activeIdx) cls = 'badge bg-primary';
                    stepperHtml += '<span class="' + cls + '" style="padding:8px 12px;font-size:0.85rem"' + (i === activeIdx ? ' aria-current="step"' : '') + '>' + escHtml(s.label) + '</span>';
                });
                stepperHtml += '</div>';
                stepper.innerHTML = stepperHtml;

                // Body per ogni stato
                let html = '';

                if (state === 'pending_dns' || state === 'propagated') {
                    // Con un account Cloudflare il record lo pubblica il pannello: chiedere di
                    // aggiungerlo a mano, per giunta in un riquadro giallo, e' un compito
                    // inventato — e due righe piu' sotto la stessa scheda scriveva "il record
                    // DNS e' stato pubblicato correttamente". I valori restano a schermo, ma
                    // come riferimento, non come istruzione.
                    html += '<div class="alert alert-' + (cloudflareConfigured ? 'info' : 'warning') + '">';
                    html += cloudflareConfigured
                        ? '<strong><i class="fas fa-cloud me-1" aria-hidden="true"></i>' + escHtml(t('dns.recPublishedByPanel')) + '</strong>'
                        : '<strong><i class="fas fa-edit me-1" aria-hidden="true"></i>' + escHtml(t('dns.recAddYourself')) + '</strong>';
                    html += '<div class="mt-2"><strong>' + escHtml(t('dns.recName')) + '</strong> <code>' + escapeHtmlBl(data.pending_dns_name || '') + '</code></div>';
                    html += '<div class="mt-1"><strong>' + escHtml(t('dns.recType')) + '</strong> <code>TXT</code></div>';
                    html += '<div class="mt-1"><strong>' + escHtml(t('dns.recValueShort')) + '</strong> <code style="word-break:break-all">' + escapeHtmlBl(data.pending_dns_value || '') + '</code> ';
                    html += '<button class="btn btn-sm btn-outline-secondary ms-2" onclick="copyDkimRotateValue(this)" data-val="' + escapeHtmlBl(data.pending_dns_value || '') + '" aria-label="' + escHtml(t('common.copy')) + '" title="' + escHtml(t('common.copy')) + '"><i class="fas fa-copy" aria-hidden="true"></i></button></div>';
                    // "Finché non attivi" da' per scontato che l'attivazione la faccia tu.
                    // Con un account Cloudflare non e' cosi': lo scheduler chiama activatePending
                    // da solo trascorse le ore di propagazione, e piu' avanti completeRotation
                    // da solo a grazia finita. Dire a qualcuno che deve fare una cosa che
                    // avviene da se' lo tiene in attesa di un compito inesistente.
                    const autoHours = data.auto_activate_after_hours || 24;
                    html += '<div class="mt-2 small text-muted">' + escHtml(t('dns.newSelectorIs')) + ' <code>' + escapeHtmlBl(data.pending_selector || '') + '</code>. '
                        + escHtml(t('dns.oldKeyIs')) + ' <code>' + escapeHtmlBl(data.current_selector || '') + '</code> '
                        + escHtml(cloudflareConfigured ? t('dns.oldSignsUntilAuto', { hours: autoHours }) : t('dns.oldSignsUntilYou')) + '</div>';
                    html += '</div>';

                    if (state === 'pending_dns') {
                        html += '<div class="d-flex gap-2 flex-wrap">';
                        html += '<button class="btn btn-primary" onclick="rotateDkimCheck()"><i class="fas fa-search me-1" aria-hidden="true"></i>' + escHtml(t('dns.checkPropagation')) + '</button>';
                        html += '<button class="btn btn-outline-danger" onclick="rotateDkimCancel()"><i class="fas fa-times me-1" aria-hidden="true"></i>' + escHtml(t('dns.cancelRotation')) + '</button>';
                        html += '</div>';
                        html += '<div class="small text-muted mt-2">' + escHtml(cloudflareConfigured
                            ? t('dns.propagationCf')
                            : t('dns.propagationManual')) + '</div>';
                    } else {
                        // propagated
                        html += '<div class="alert alert-info"><i class="fas fa-check-circle me-1" aria-hidden="true"></i>' + escHtml(t('dns.recPublishedOk')) + ' ' + (cloudflareConfigured
                            ? escHtml(t('dns.activationAuto', { hours: data.auto_activate_after_hours || 24, days: data.grace_period_days || 7 })) + ' ' + autoStartSentence(data)
                            : escHtml(t('dns.activationYou'))) + '</div>';
                        html += '<div class="d-flex gap-2 flex-wrap">';
                        html += '<button class="btn btn-success" onclick="rotateDkimActivate(false)"><i class="fas fa-bolt me-1" aria-hidden="true"></i>' + escHtml(t('dns.activateNew')) + '</button>';
                        html += '<button class="btn btn-outline-primary" onclick="rotateDkimCheck()"><i class="fas fa-sync me-1" aria-hidden="true"></i>' + escHtml(t('dns.recheckDns')) + '</button>';
                        html += '<button class="btn btn-outline-danger" onclick="rotateDkimCancel()"><i class="fas fa-times me-1" aria-hidden="true"></i>' + escHtml(t('dns.cancelRotation')) + '</button>';
                        html += '</div>';
                    }
                } else if (state === 'active_grace') {
                    const graceDays = data.grace_period_days || 7;
                    const isOver = !!data.grace_period_over;
                    html += '<div class="alert ' + (isOver ? 'alert-success' : 'alert-info') + '">';
                    html += '<strong><i class="fas fa-check-circle me-1" aria-hidden="true"></i>' + escHtml(t('dns.newKeyActive')) + '</strong> ' + escHtml(t('dns.nowSignedWith')) + ' <code>' + escapeHtmlBl(data.current_selector || '') + '</code>.';
                    if (data.previous_selector) {
                        if (data.previous_in_dns === false) {
                            // Il periodo di grazia serve a proteggere un record che esiste. Se
                            // quel record non c'e', non c'e' niente da proteggere — e la cosa
                            // da dire e' un'altra: quella chiave non era pubblicata, quindi le
                            // firme fatte con lei non erano verificabili da nessuno.
                            html += '<div class="mt-2 small">' + escHtml(t('dns.oldKey')) + ' <code>' + escapeHtmlBl(data.previous_selector) + '</code> ' + escHtml(t('dns.oldNotInDns')) + '</div>';
                        } else {
                            html += '<div class="mt-2 small">' + escHtml(t('dns.oldKey')) + ' <code>' + escapeHtmlBl(data.previous_selector) + '</code> ' + escHtml(tn('dns.oldStays', graceDays)) + (data.previous_in_dns === true ? ' <span class="text-muted">' + escHtml(t('dns.oldVerified')) + '</span>' : '') + '</div>';
                        }
                    }
                    if (data.activated_at) {
                        html += '<div class="mt-1 small text-muted">' + escHtml(t('dns.activatedAt', { date: pickTs(data, 'activated_at') ? formatPanelDate(pickTs(data, 'activated_at')) : data.activated_at })) + '</div>';
                    }
                    html += '</div>';

                    // Calcola la data prevista di completamento (activated_at + grace_days)
                    let expectedCompletionStr = '';
                    const actMs = (typeof pickTs === 'function')
                        ? (pickTs(data, 'activated_at') ? pickTs(data, 'activated_at').getTime() : null)
                        : null;
                    if (actMs) {
                        const completionDate = new Date(actMs + graceDays * 24 * 60 * 60 * 1000);
                        expectedCompletionStr = (typeof formatPanelDate === 'function')
                            ? formatPanelDate(completionDate)
                            : completionDate.toLocaleString(window.I18N_LANG);
                    }

                    if (isOver) {
                        if (data.cloudflare_configured) {
                            html += '<div class="alert alert-success"><i class="fas fa-robot me-1" aria-hidden="true"></i><strong>' + escHtml(t('dns.graceOver')) + '</strong> ' + escHtml(t('dns.graceOverCf')) + '</div>';
                        } else {
                            html += '<div class="alert alert-warning"><i class="fas fa-clock me-1" aria-hidden="true"></i><strong>' + escHtml(t('dns.graceOver')) + '</strong> ' + escHtml(t('dns.graceOverManual')) + ' <a href="/cloudflare" class="alert-link">' + escHtml(t('dns.setUpCf')) + '</a>.</div>';
                        }
                        html += '<button class="btn btn-success" onclick="rotateDkimComplete()"><i class="fas fa-flag-checkered me-1" aria-hidden="true"></i>' + escHtml(t('dns.completeRotation')) + '</button>';
                    } else {
                        // PRIMA del grace period: il bottone "Completa" è SEMPRE disabilitato.
                        // Nessuna possibilità di forzare: il server side rifiuterebbe comunque la chiamata
                        // (vedi DkimManager.completeRotation), quindi non offriamo nemmeno il bottone.
                        if (data.cloudflare_configured) {
                            html += '<div class="alert alert-info"><i class="fas fa-robot me-1" aria-hidden="true"></i><strong>' + escHtml(t('dns.autoCompleteAt')) + '</strong> ' + escHtml(expectedCompletionStr || tn('dns.daysAfterActivation', graceDays)) + '.<br>' + escHtml(t('dns.autoCompleteHow')) + '</div>';
                        } else {
                            html += '<div class="alert alert-light"><i class="fas fa-hourglass-half me-1" aria-hidden="true"></i>' + escHtml(expectedCompletionStr ? t('dns.waitGraceUntil', { date: expectedCompletionStr }) : tn('dns.waitGrace', graceDays)) + '<br><small class="text-muted">' + escHtml(t('dns.waitGraceManual')) + '</small></div>';
                        }
                        html += '<button class="btn btn-success" disabled title="' + escHtml(t('dns.completeLockedHint')) + '">';
                        html += '<i class="fas fa-lock me-1" aria-hidden="true"></i>' + escHtml(expectedCompletionStr ? t('dns.completeLockedUntil', { date: expectedCompletionStr }) : t('dns.completeLocked'));
                        html += '</button>';
                    }
                }

                body.innerHTML = html;
            }).catch(e => {
                console.error('rotate_status error', e);
            });
        }

        function copyDkimRotateValue(btn) {
            const v = btn.getAttribute('data-val') || '';
            navigator.clipboard.writeText(v).then(() => {
                const old = btn.innerHTML;
                btn.innerHTML = '<i class="fas fa-check" aria-hidden="true"></i> ' + escHtml(t('dns.copied'));
                setTimeout(() => btn.innerHTML = old, 1500);
            });
        }

        // Esegue la POST /api/dkim rotate_start con il flag auto scelto dall'utente.
        function rotateDkimStartExec(useAuto) {
            fetch('/api/dkim', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'rotate_start', domain_id: parseInt(currentDomainId), auto: useAuto })
            }).then(r => r.json()).then(data => {
                if (!data.success) { alert(t('common.error', { message: data.error || t('common.unknownError') })); return; }
                if (data.warning) {
                    alert('⚠ ' + data.warning);
                } else if (data.message && useAuto) {
                    alert('✓ ' + data.message);
                }
                loadDkimRotationStatus(currentDomainId);
            }).catch(e => alert(t('common.networkError', { message: e.message })));
        }

        function rotateDkimStart() {
            if (!currentDomainId) { alert(t('dns.chooseDomainFirst')); return; }
            // Identifica l'account CF collegato (se c'è)
            const domInfo = cfDomainsCf.find(d => d.id === parseInt(currentDomainId));
            const linkedAccount = domInfo && domInfo.cloudflare_account_id
                ? cfAccounts.find(a => a.id === domInfo.cloudflare_account_id)
                : null;
            const acctLabel = linkedAccount
                ? linkedAccount.label + (linkedAccount.email ? ' (' + linkedAccount.email + ')' : '')
                : '';

            // Se NON c'è CF assegnato → solo manuale
            if (!cloudflareConfigured) {
                if (!confirm(t('dns.confirmManualStart'))) return;
                rotateDkimStartExec(false);
                return;
            }

            // CF disponibile → mostra modal di scelta tra Cloudflare e DNS manuale
            const modalEl = document.getElementById('rotateModeChooserModal');
            document.getElementById('rotateModeAccountLabel').textContent = acctLabel || t('dns.noneParen');
            // Bootstrap modal (Bootstrap 5)
            const modal = new bootstrap.Modal(modalEl);
            modal.show();
        }

        // Callback invocato dai bottoni dentro al modal di scelta
        function rotateDkimStartChooseCloudflare() {
            const modalEl = document.getElementById('rotateModeChooserModal');
            const modal = bootstrap.Modal.getInstance(modalEl);
            if (modal) modal.hide();
            rotateDkimStartExec(true);
        }

        function rotateDkimStartChooseManual() {
            const modalEl = document.getElementById('rotateModeChooserModal');
            const modal = bootstrap.Modal.getInstance(modalEl);
            if (modal) modal.hide();
            if (!confirm(t('dns.confirmManual'))) return;
            rotateDkimStartExec(false);
        }

        function rotateDkimCheck() {
            if (!currentDomainId) return;
            fetch('/api/dkim', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'rotate_check', domain_id: parseInt(currentDomainId) })
            }).then(r => r.json()).then(data => {
                if (!data.success) { alert(t('common.error', { message: data.message || t('common.unknownError') })); return; }
                if (data.propagated) {
                    alert('✓ ' + t('dns.propagatedNow'));
                } else {
                    alert('⚠ ' + (data.message || t('dns.notPropagatedYet')));
                }
                loadDkimRotationStatus(currentDomainId);
            }).catch(e => alert(t('common.networkError', { message: e.message })));
        }

        function rotateDkimActivate(force) {
            if (!currentDomainId) return;
            const msg = force
                ? t('dns.confirmForce')
                : t('dns.confirmActivate');
            if (!confirm(msg)) return;
            fetch('/api/dkim', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'rotate_activate', domain_id: parseInt(currentDomainId), force: !!force })
            }).then(r => r.json()).then(data => {
                alert((data.success ? '✓ ' : '✗ ') + (data.message || ''));
                if (data.success) {
                    loadDkimStatus(currentDomainId);
                    loadDnsRecords();
                }
            }).catch(e => alert(t('common.networkError', { message: e.message })));
        }

        function rotateDkimComplete() {
            if (!currentDomainId) return;
            if (!confirm(t('dns.confirmComplete'))) return;
            fetch('/api/dkim', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'rotate_complete', domain_id: parseInt(currentDomainId) })
            }).then(r => r.json()).then(data => {
                alert((data.success ? '✓ ' : '✗ ') + (data.message || ''));
                if (data.success) {
                    loadDkimStatus(currentDomainId);
                    loadDnsRecords();
                }
            }).catch(e => alert(t('common.networkError', { message: e.message })));
        }

        function rotateDkimCancel() {
            if (!currentDomainId) return;
            if (!confirm(t('dns.confirmCancel'))) return;
            fetch('/api/dkim', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'rotate_cancel', domain_id: parseInt(currentDomainId) })
            }).then(r => r.json()).then(data => {
                alert((data.success ? '✓ ' : '✗ ') + (data.message || ''));
                loadDkimRotationStatus(currentDomainId);
            }).catch(e => alert(t('common.networkError', { message: e.message })));
        }

        // ===== Blacklist Check =====
        function runBlacklistCheck() {
            const btn = document.getElementById('btnBlCheck');
            const container = document.getElementById('blContainer');
            const overall = document.getElementById('blOverallStatus');
            const originalHtml = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1" aria-hidden="true"></span>' + escHtml(t('dns.blChecking'));
            container.innerHTML = '<p class="text-muted"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('dns.blAsking')) + '</p>';
            fetch('/api/blacklist_check').then(r => r.json()).then(data => {
                btn.disabled = false;
                btn.innerHTML = originalHtml;
                if (!data.success) {
                    container.innerHTML = '<div class="alert alert-danger mb-0">' + escHtml(t('common.error', { message: data.error || t('common.unknownError') })) + '</div>';
                    return;
                }
                let totalListed = 0;
                let totalChecks = 0;
                let html = '';
                (data.reports || []).forEach(report => {
                    totalListed += report.listed_count;
                    totalChecks += (report.listed_count + report.clean_count + report.error_count + (report.web_only_count || 0));

                    const labelType = report.type === 'IP' ? t('dns.blIp') : t('st.colDomain');
                    let headerClass, badge;
                    if (report.listed_count > 0) {
                        headerClass = 'bg-danger text-white';
                        badge = '<span class="badge bg-light text-danger ms-2">⚠ ' + escHtml(tn('dns.blListedN', report.listed_count)) + '</span>';
                    } else if (report.error_count > report.clean_count / 2) {
                        headerClass = 'bg-warning text-dark';
                        badge = '<span class="badge bg-secondary ms-2">' + escHtml(tn('dns.blErrors', report.error_count)) + '</span>';
                    } else {
                        headerClass = 'bg-success text-white';
                        let txt = '✓ ' + tn('dns.blClean', report.clean_count);
                        if (report.web_only_count) txt += ' + ' + tn('dns.blWeb', report.web_only_count);
                        badge = '<span class="badge bg-light text-success ms-2">' + escHtml(txt) + '</span>';
                    }

                    html += '<div class="card mb-3">';
                    html += '<div class="card-header ' + headerClass + ' d-flex justify-content-between align-items-center">';
                    html += '<div><strong>' + escHtml(labelType) + ':</strong> <code class="ms-1" style="background:rgba(255,255,255,0.2);padding:2px 6px;border-radius:3px;color:inherit">' + escapeHtmlBl(report.target) + '</code>' + badge + '</div>';
                    html += '<small class="opacity-75">' + escHtml(report.elapsed_ms) + ' ms</small>';
                    html += '</div>';
                    html += '<div class="card-body p-2"><div class="table-responsive"><table class="table table-sm mb-0">';
                    html += '<thead><tr><th scope="col">Blacklist</th><th scope="col">' + escHtml(t('que.colState')) + '</th><th scope="col">' + escHtml(t('dns.blDetails')) + '</th><th scope="col">' + escHtml(t('dns.blLookup')) + '</th></tr></thead><tbody>';
                    (report.results || []).forEach(res => {
                        let stateBadge;
                        if (res.listed) {
                            stateBadge = '<span class="badge bg-danger"><i class="fas fa-ban me-1" aria-hidden="true"></i>' + escHtml(t('dns.blListed')) + '</span>';
                        } else if (res.web_only) {
                            stateBadge = '<span class="badge bg-info text-dark"><i class="fas fa-external-link-alt me-1" aria-hidden="true"></i>' + escHtml(t('dns.blWebCheck')) + '</span>';
                        } else if (res.error) {
                            stateBadge = '<span class="badge bg-secondary"><i class="fas fa-question-circle me-1" aria-hidden="true"></i>' + escHtml(t('common.errorShort')) + '</span>';
                        } else {
                            stateBadge = '<span class="badge bg-success"><i class="fas fa-check me-1" aria-hidden="true"></i>' + escHtml(t('dns.blCleanOne')) + '</span>';
                        }
                        html += '<tr>';
                        html += '<td><strong>' + escapeHtmlBl(res.blacklist) + '</strong><br><small class="text-muted">' + escapeHtmlBl(res.zone) + '</small></td>';
                        html += '<td>' + stateBadge + '</td>';
                        html += '<td><small>' + escapeHtmlBl(res.message || '') + '</small></td>';
                        html += '<td>' + (res.lookup_url ? '<a href="' + escapeHtmlBl(res.lookup_url) + '" target="_blank" rel="noopener" class="btn btn-sm btn-outline-primary" title="' + escHtml(t('dns.blOpenLookup')) + '" aria-label="' + escHtml(t('dns.blOpenLookup')) + ' ' + escapeHtmlBl(res.blacklist) + '"><i class="fas fa-external-link-alt" aria-hidden="true"></i></a>' : '') + '</td>';
                        html += '</tr>';
                    });
                    html += '</tbody></table></div></div>';
                    html += '</div>';
                });

                // Overall status badge
                if (totalListed === 0) {
                    overall.innerHTML = '<span class="badge bg-success">' + escHtml(tn('dns.blAllClean', totalChecks)) + '</span>';
                } else {
                    overall.innerHTML = '<span class="badge bg-danger">' + escHtml(tn('dns.blYouAreListed', totalListed)) + '</span>';
                }

                if (html === '') {
                    html = '<p class="text-muted">' + escHtml(t('dns.blNoReport')) + '</p>';
                }
                container.innerHTML = html;
            }).catch(e => {
                btn.disabled = false;
                btn.innerHTML = originalHtml;
                container.innerHTML = '<div class="alert alert-danger mb-0">' + escHtml(t('common.networkError', { message: e.message })) + '</div>';
            });
        }

        function escapeHtmlBl(s) {
            const d = document.createElement('div');
            d.textContent = s == null ? '' : String(s);
            return d.innerHTML;
        }

        function generateDkim() {
            if (!currentDomainId) return;
            if (!confirm(t('dns.confirmGenerate'))) return;

            fetch('/api/dkim', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'generate', domain_id: parseInt(currentDomainId), selector: 'mail' })
            }).then(r => r.json()).then(data => {
                if (data.success) {
                    alert(t('dns.generated'));
                    loadDnsRecords();
                } else {
                    alert(t('common.error', { message: data.error }));
                }
            });
        }

        function verifyDns() {
            const domain = document.getElementById('domainSelect').value;
            if (!domain) { alert(t('dns.chooseDomainFirst')); return; }

            fetch('/api/dns', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'verify', domain: domain })
            }).then(r => r.json()).then(data => {
                const container = document.getElementById('verificationResults');
                const body = document.getElementById('verificationBody');
                container.classList.remove('d-none');

                let html = '<div class="d-flex justify-content-between align-items-center mb-3">';
                html += '<h5>' + escHtml(t('dns.domainIs', { domain: data.domain })) + '</h5>';
                html += '<span class="score-badge badge ' + (data.all_passed ? 'bg-success' : 'bg-warning') + '">' + escHtml(data.score) + '%</span>';
                html += '</div>';

                html += '<table class="table table-sm table-bordered"><thead><tr><th scope="col" width="80">Record</th><th scope="col" width="50">' + escHtml(t('que.colState')) + '</th><th scope="col">' + escHtml(t('dns.colCheck')) + '</th></tr></thead><tbody>';
                data.checks.forEach(c => {
                    const icon = c.passed ? '<i class="fas fa-check-circle text-success" title="' + escHtml(t('dns.succeeded')) + '"></i><span class="visually-hidden">' + escHtml(t('dns.succeeded')) + '</span>' : '<i class="fas fa-times-circle text-danger" title="' + escHtml(t('dns.failed')) + '"></i><span class="visually-hidden">' + escHtml(t('dns.failed')) + '</span>';
                    const rowClass = c.passed ? '' : 'table-danger';
                    html += '<tr class="' + rowClass + '">';
                    html += '<td><strong>' + escHtml(c.type) + '</strong></td>';
                    html += '<td class="text-center">' + icon + '</td>';
                    html += '<td>';
                    html += '<div><strong>' + escHtml(c.message) + '</strong></div>';
                    if (c.current_value) {
                        const shortVal = c.current_value.length > 80 ? c.current_value.substring(0, 80) + '...' : c.current_value;
                        html += '<div class="mt-1"><small class="text-muted">' + escHtml(t('dns.found')) + ' </small><code class="small">' + escHtml(shortVal) + '</code></div>';
                    }
                    html += '</td>';
                    html += '</tr>';
                });
                html += '</tbody></table>';

                if (data.all_passed) {
                    html += '<div class="alert alert-success mb-0"><i class="fas fa-check-circle me-2" aria-hidden="true"></i>' + escHtml(t('dns.allRight')) + '</div>';
                } else {
                    html += '<div class="alert alert-warning mb-0"><i class="fas fa-exclamation-triangle me-2" aria-hidden="true"></i>' + escHtml(t('dns.someNeedAttention')) + '</div>';
                }

                body.innerHTML = html;
            });
        }

        function copyToClipboard(el) {
            const name = el.querySelector('.record-name').textContent;
            const value = el.querySelector('.record-value').textContent;
            navigator.clipboard.writeText(value).then(() => {
                alert(t('dns.copiedClipboard'));
            });
        }

        let csrfToken = document.getElementById('csrf_token').value;
""";
    }

    /**
     * Terzo blocco JS della pagina /dns (verifica DKIM in DNS + storico rotazioni + schedule helpers),
     * estratto per stare sotto il limite del constant pool Java.
     */
    private static String getDnsJsPart3() {
        return """
        // ===== Verifica chiave attiva in DNS =====
        function verifyActiveDkim() {
            if (!currentDomainId) return;
            const out = document.getElementById('dkimVerifyResult');
            out.innerHTML = '<div class="alert alert-info py-2 mb-0"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('dns.askingPublic')) + '</div>';
            fetch('/api/dkim', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'verify_active_dns', domain_id: parseInt(currentDomainId) })
            }).then(r => r.json()).then(data => {
                if (!data.success) {
                    out.innerHTML = '<div class="alert alert-danger py-2 mb-0"><i class="fas fa-times-circle me-1"></i>' + escapeHtmlBl(data.message || data.error || t('common.errorShort')) + '</div>';
                    return;
                }
                let html = '';
                if (data.match) {
                        html += '<div class="alert alert-success py-2 mb-2">'
                             + '<i class="fas fa-check-circle me-1" aria-hidden="true"></i><strong>' + escHtml(t('dns.verifiable')) + '</strong> '
                             + escHtml(t('dns.verifiableHint'))
                             + '<div class="small mt-1">' + escapeHtmlBl(data.message || '') + '</div></div>';
                } else {
                        html += '<div class="alert alert-danger py-2 mb-2">'
                             + '<i class="fas fa-exclamation-triangle me-1" aria-hidden="true"></i><strong>' + escHtml(t('dns.notVerifiable')) + '</strong> '
                             + escHtml(t('dns.notVerifiableHint'))
                             + '<div class="small mt-1">' + escapeHtmlBl(data.message || '') + '</div>'
                             + '<div class="small mt-1">' + escHtml(t('dns.notVerifiableFix')) + '</div></div>';
                }
                html += '<table class="table table-sm mb-0 small"><tbody>';
                html += '<tr><th style="width:180px">' + escHtml(t('dns.queriedRecord')) + '</th><td><code>' + escapeHtmlBl(data.dns_record_name || '') + '</code></td></tr>';
                html += '<tr><th>' + escHtml(t('dns.activeSelector')) + '</th><td><code>' + escapeHtmlBl(data.selector || '') + '</code></td></tr>';
                if (data.expected_public_key) {
                    const exp = data.expected_public_key;
                    const trunc = exp.length > 60 ? exp.substring(0, 60) + '…' : exp;
                    html += '<tr><th>' + escHtml(t('dns.expectedKey')) + '</th><td><code style="word-break:break-all">' + escapeHtmlBl(trunc) + '</code> <small class="text-muted">' + escHtml(t('dns.chars', { n: exp.length })) + '</small></td></tr>';
                }
                if (data.actual_public_key) {
                    const act = data.actual_public_key;
                    const trunc = act.length > 60 ? act.substring(0, 60) + '…' : act;
                    html += '<tr><th>' + escHtml(t('dns.foundKey')) + '</th><td><code style="word-break:break-all">' + escapeHtmlBl(trunc) + '</code> <small class="text-muted">' + escHtml(t('dns.chars', { n: act.length })) + '</small></td></tr>';
                }
                html += '</tbody></table>';
                if (data.raw_output) {
                    html += '<details class="mt-2"><summary class="small text-muted">' + escHtml(t('dns.digOutput')) + '</summary><pre class="small mt-2" style="white-space:pre-wrap;word-break:break-all">' + escapeHtmlBl(data.raw_output) + '</pre></details>';
                }
                out.innerHTML = html;
                // Lo storico ora include un evento "key_verified": ricaricalo
                loadDkimHistory(currentDomainId);
            }).catch(e => {
                out.innerHTML = '<div class="alert alert-danger py-2 mb-0">' + escHtml(t('common.networkError', { message: e.message })) + '</div>';
            });
        }

        // ===== Cleanup record DKIM orfani =====
        function scanDkimOrphans() {
            if (!currentDomainId) { alert(t('dns.chooseDomainFirst')); return; }
            const btn = document.getElementById('scanDkimOrphansBtn');
            const out = document.getElementById('dkimOrphansResult');
            const originalBtn = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1" aria-hidden="true"></span>' + escHtml(t('dns.scanning'));
            out.innerHTML = '';
            fetch('/api/dkim', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'orphans_scan', domain_id: parseInt(currentDomainId) })
            }).then(r => r.json()).then(data => {
                btn.disabled = false;
                btn.innerHTML = originalBtn;
                if (!data.success) {
                    out.innerHTML = '<div class="alert alert-danger py-2 mb-0"><i class="fas fa-times-circle me-1"></i>' + escapeHtmlBl(data.error || t('common.unknownError')) + '</div>';
                    return;
                }
                const records = data.records || [];
                if (records.length === 0) {
                    out.innerHTML = '<div class="alert alert-info py-2 mb-0"><i class="fas fa-info-circle me-1" aria-hidden="true"></i>' + escHtml(t('dns.orphNone', { name: '*._domainkey.' + data.domain, account: data.cloudflare_account_label || '?' })) + '</div>';
                    return;
                }
                const orphanCount      = records.filter(r => r.is_orphan).length;
                const removableCount   = records.filter(r => r.is_orphan && !r.in_grace_period).length;
                const graceProtCount   = records.filter(r => r.is_orphan && r.in_grace_period).length;
                const activeCount = records.length - orphanCount;
                const graceDays = data.grace_period_days || 7;
                // La scansione guarda UNA zona, quella del dominio selezionato: scanDkimRecords
                // riceve un domainId, ne trova la zona e tiene solo i record che finiscono con
                // quel dominio esatto. Le altre zone dello stesso account non le apre mai.
                //
                // Diceva pero' "record DKIM totali nell'account". Con cinque domini sullo stesso
                // account, leggere "trovati 1 record DKIM totali nell'account Pietro" porta a
                // concludere che gli altri quattro non hanno DKIM — mentre ce l'hanno. Un
                // conteggio giusto sotto un'etichetta che promette un perimetro piu' largo di
                // quello measured e' un numero falso.
                let html = '<div class="alert ' + (removableCount > 0 ? 'alert-warning' : 'alert-success') + ' py-2 mb-2"><i class="fas fa-info-circle me-1" aria-hidden="true"></i>'
                    + escHtml(t('dns.orphSummary', { zone: data.domain || '?', total: records.length, active: activeCount, grace: graceProtCount, removable: removableCount, account: data.cloudflare_account_label || '?' }))
                    + ' <span class="text-muted">' + escHtml(t('dns.orphOneZone')) + '</span></div>';
                html += '<div class="table-responsive"><table class="table table-sm align-middle mb-0">';
                html += '<thead><tr><th scope="col">' + escHtml(t('dns.colSelector')) + '</th><th scope="col">' + escHtml(t('que.colState')) + '</th><th scope="col">' + escHtml(t('dns.colPreview')) + '</th><th scope="col" class="text-end">' + escHtml(t('home.colActions')) + '</th></tr></thead><tbody>';
                records.forEach(r => {
                    html += '<tr>';
                    html += '<td><code>' + escapeHtmlBl(r.selector || '') + '</code><br><small class="text-muted">' + escapeHtmlBl(r.name || '') + '</small></td>';
                    let badge;
                    let stateExtra = '';
                    if (r.is_current)       badge = '<span class="badge bg-success">' + escHtml(t('rl.active')) + '</span>';
                    else if (r.is_pending)  badge = '<span class="badge bg-warning text-dark">' + escHtml(t('dns.pending')) + '</span>';
                    else if (r.is_previous) badge = '<span class="badge bg-info text-dark">' + escHtml(t('dns.grace')) + '</span>';
                    else if (r.in_grace_period) {
                        badge = '<span class="badge bg-info text-dark">' + escHtml(tn('dns.graceDays', graceDays)) + '</span>';
                        // Mostra data fine grace period
                        const endsTs = (typeof pickTs === 'function') ? pickTs(r, 'grace_period_ends_at') : null;
                        if (endsTs) {
                            const endsStr = (typeof formatPanelDate === 'function') ? formatPanelDate(endsTs) : endsTs.toLocaleString(window.I18N_LANG);
                            stateExtra = '<br><small class="text-muted">' + escHtml(t('dns.removableFrom', { date: endsStr })) + '</small>';
                        }
                    } else {
                        badge = '<span class="badge bg-danger">' + escHtml(t('dns.orphan')) + '</span>';
                    }
                    html += '<td>' + badge + stateExtra + '</td>';
                    html += '<td><code class="small" style="word-break:break-all">' + escapeHtmlBl(r.content_preview || '') + '</code></td>';
                    if (r.is_orphan && !r.in_grace_period) {
                        // ORFANO rimovibile (grace period scaduto o mai stato attivo)
                        html += '<td class="text-end"><button class="btn btn-sm btn-outline-danger" onclick="deleteDkimOrphan(\\'' + escapeHtmlBl(r.record_id).replace(/'/g, "\\\\'") + '\\', \\'' + escapeHtmlBl(r.selector).replace(/'/g, "\\\\'") + '\\')"><i class="fas fa-trash me-1" aria-hidden="true"></i>' + escHtml(t('common.delete')) + '</button></td>';
                    } else if (r.is_orphan && r.in_grace_period) {
                        // ORFANO ma in grace period esteso: NON rimovibile
                        html += '<td class="text-end"><span class="text-muted small" title="' + escHtml(t('dns.graceProtectedHint')) + '"><i class="fas fa-shield-alt me-1" aria-hidden="true"></i>' + escHtml(t('dns.graceProtected')) + '</span></td>';
                    } else {
                        // Attivo / Pending / Previous: protetto
                        html += '<td class="text-end"><span class="text-muted small"><i class="fas fa-lock me-1" aria-hidden="true"></i>' + escHtml(t('dns.protected')) + '</span></td>';
                    }
                    html += '</tr>';
                });
                html += '</tbody></table></div>';
                out.innerHTML = html;
            }).catch(e => {
                btn.disabled = false;
                btn.innerHTML = originalBtn;
                out.innerHTML = '<div class="alert alert-danger py-2 mb-0">' + escHtml(t('common.networkError', { message: e.message })) + '</div>';
            });
        }

        function deleteDkimOrphan(recordId, selector) {
            if (!currentDomainId) return;
            if (!confirm(t('dns.confirmOrphanDelete', { selector: selector }))) return;
            fetch('/api/dkim', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'orphans_delete', domain_id: parseInt(currentDomainId), record_id: recordId })
            }).then(r => r.json()).then(data => {
                alert((data.success ? '✓ ' : '✗ ') + (data.message || data.error || ''));
                if (data.success) {
                    // Re-scansiona per aggiornare la lista
                    scanDkimOrphans();
                    // Aggiorna anche lo storico (è stato loggato un evento orphan_record_deleted)
                    if (typeof loadDkimHistory === 'function') loadDkimHistory(currentDomainId);
                }
            }).catch(e => alert(t('common.networkError', { message: e.message })));
        }

        // ===== Storico rotazioni DKIM =====
        function loadDkimHistory(domainId) {
            const body = document.getElementById('dkimHistoryBody');
            body.innerHTML = '<p class="text-muted small mb-0"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('common.loading')) + '</p>';
            fetch('/api/dkim', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'rotate_history', domain_id: parseInt(domainId), limit: 100 })
            }).then(r => r.json()).then(data => {
                if (!data.success) {
                    body.innerHTML = '<div class="text-muted small">' + escHtml(t('dns.historyUnavailable', { message: data.error || '' })) + '</div>';
                    return;
                }
                const events = data.events || [];
                if (events.length === 0) {
                    body.innerHTML = '<div class="text-muted small">' + escHtml(t('dns.noRotation')) + '</div>';
                    return;
                }
                // Label leggibili e colori per evento
                const labels = {
                    rotation_started:   { txt: t('dns.evStarted'),     badge: 'bg-primary' },
                    dns_published:      { txt: t('dns.evPublished'),   badge: 'bg-info text-dark' },
                    dns_propagated:     { txt: t('dns.evPropagated'),  badge: 'bg-info text-dark' },
                    key_activated:      { txt: t('dns.evActivated'),   badge: 'bg-success' },
                    rotation_completed: { txt: t('dns.evCompleted'),   badge: 'bg-success' },
                    rotation_cancelled: { txt: t('dns.evCancelled'),   badge: 'bg-secondary' },
                    key_verified:       { txt: t('dns.evVerified'),    badge: 'bg-secondary' },
                    orphan_record_deleted: { txt: t('dns.evOrphan'),   badge: 'bg-warning text-dark' },
                    schedule_changed:   { txt: t('dns.evSchedule'),    badge: 'bg-secondary' }
                };
                // Etichette + colori per la "Modalità DNS" (come viene gestito il record in DNS)
                const modeLabels = {
                    automatic: { txt: 'Cloudflare',             badge: 'bg-info text-dark',         title: t('dns.modeCfHint') },
                    manual:    { txt: t('dns.modeManual'),      badge: 'bg-light text-dark border', title: t('dns.modeManualHint') },
                    forced:    { txt: t('dns.modeForced'),      badge: 'bg-warning text-dark',      title: t('dns.modeForcedHint') }
                };
                // Etichette per "Origine" (chi ha avviato l'operazione)
                const triggerLabels = {
                    user:      { txt: t('dns.trigUser'),      icon: 'user',  badge: 'bg-primary', title: t('dns.trigUserHint') },
                    scheduler: { txt: t('dns.trigScheduler'), icon: 'robot', badge: 'bg-dark',    title: t('dns.trigSchedulerHint') }
                };
                let html = '<div class="table-responsive"><table class="table table-sm align-middle mb-0">';
                html += '<thead><tr>';
                html += '<th scope="col">' + escHtml(t('dns.colWhen')) + '</th>';
                html += '<th scope="col">' + escHtml(t('dns.colEvent')) + '</th>';
                html += '<th scope="col">' + escHtml(t('dns.colSelector')) + '</th>';
                html += '<th scope="col" title="' + escHtml(t('dns.colOriginHint')) + '" style="cursor:help">' + escHtml(t('dns.colOrigin')) + ' <i class="fas fa-info-circle text-muted small" aria-hidden="true"></i></th>';
                html += '<th scope="col" title="' + escHtml(t('dns.colModeHint')) + '" style="cursor:help">' + escHtml(t('dns.colMode')) + ' <i class="fas fa-info-circle text-muted small" aria-hidden="true"></i></th>';
                html += '<th scope="col">' + escHtml(t('dns.colCfAccount')) + '</th>';
                html += '<th scope="col">' + escHtml(t('dns.colOutcome')) + '</th>';
                html += '<th scope="col">' + escHtml(t('dns.colNotes')) + '</th>';
                html += '</tr></thead><tbody>';
                events.forEach(ev => {
                    const lbl = labels[ev.event_type] || { txt: ev.event_type, badge: 'bg-secondary' };
                    const mode = ev.mode ? modeLabels[ev.mode] : null;
                    const trig = ev.triggered_by ? triggerLabels[ev.triggered_by] : null;
                    html += '<tr>';
                    // Timestamp formattato in locale (preferisce occurred_at_ms se presente)
                    const tsDate = (typeof pickTs === 'function') ? pickTs(ev, 'occurred_at')
                        : (typeof parseTs === 'function' ? parseTs(ev.occurred_at) : null);
                    const tsDisplay = tsDate
                        ? (typeof formatPanelDate === 'function' ? formatPanelDate(tsDate) : tsDate.toLocaleString(window.I18N_LANG))
                        : (ev.occurred_at || '');
                    html += '<td><small class="text-nowrap">' + escapeHtmlBl(tsDisplay) + '</small></td>';
                    html += '<td><span class="badge ' + lbl.badge + '">' + escapeHtmlBl(lbl.txt) + '</span></td>';
                    html += '<td>' + (ev.selector ? '<code>' + escapeHtmlBl(ev.selector) + '</code>' : '<span class="text-muted">—</span>') + '</td>';
                    // Colonna Origine
                    if (trig) {
                        html += '<td><span class="badge ' + trig.badge + '" title="' + escapeHtmlBl(trig.title) + '" style="cursor:help"><i class="fas fa-' + trig.icon + ' me-1" aria-hidden="true"></i>' + escapeHtmlBl(trig.txt) + '</span></td>';
                    } else if (ev.triggered_by) {
                        html += '<td><span class="badge bg-secondary">' + escapeHtmlBl(ev.triggered_by) + '</span></td>';
                    } else {
                        html += '<td><span class="text-muted" title="' + escHtml(t('dns.noOriginHint')) + '" style="cursor:help">—</span></td>';
                    }
                    // Colonna Modalità DNS
                    if (mode) {
                        html += '<td><span class="badge ' + mode.badge + '" title="' + escapeHtmlBl(mode.title) + '" style="cursor:help">' + escapeHtmlBl(mode.txt) + '</span></td>';
                    } else if (ev.mode) {
                        html += '<td><span class="badge bg-light text-dark border">' + escapeHtmlBl(ev.mode) + '</span></td>';
                    } else {
                        html += '<td><span class="text-muted" title="' + escHtml(t('dns.notApplicable')) + '" style="cursor:help">—</span></td>';
                    }
                    html += '<td>' + (ev.cloudflare_account_label ? escapeHtmlBl(ev.cloudflare_account_label) : '<span class="text-muted">—</span>') + '</td>';
                    html += '<td>' + (ev.success
                        ? '<span class="badge bg-success" title="' + escHtml(t('dns.succeeded')) + '"><i class="fas fa-check" aria-hidden="true"></i><span class="visually-hidden">' + escHtml(t('dns.succeeded')) + '</span></span>'
                        : '<span class="badge bg-danger" title="' + escHtml(t('dns.failed')) + '"><i class="fas fa-times" aria-hidden="true"></i><span class="visually-hidden">' + escHtml(t('dns.failed')) + '</span></span>') + '</td>';
                    html += '<td><small>' + escapeHtmlBl(ev.message || '') + '</small></td>';
                    html += '</tr>';
                });
                html += '</tbody></table></div>';

                // Legenda compatta sotto la tabella
                html += '<div class="small text-muted mt-2">';
                html += '<div class="mb-1"><i class="fas fa-info-circle me-1" aria-hidden="true"></i><strong>' + escHtml(t('dns.colOrigin')) + ':</strong> ';
                html += '<span class="badge bg-primary"><i class="fas fa-user me-1" aria-hidden="true"></i>' + escHtml(t('dns.trigUser')) + '</span> = ' + escHtml(t('dns.legUser')) + ' · ';
                html += '<span class="badge bg-dark"><i class="fas fa-robot me-1" aria-hidden="true"></i>' + escHtml(t('dns.trigScheduler')) + '</span> = ' + escHtml(t('dns.legScheduler')) + ' · ';
                html += '<span class="text-muted">—</span> = ' + escHtml(t('dns.legNoOrigin')) + '';
                html += '</div>';
                html += '<div><i class="fas fa-info-circle me-1" aria-hidden="true"></i><strong>' + escHtml(t('dns.colMode')) + ':</strong> ';
                html += '<span class="badge bg-info text-dark">Cloudflare</span> = ' + escHtml(t('dns.legCf')) + ' · ';
                html += '<span class="badge bg-light text-dark border">' + escHtml(t('dns.modeManual')) + '</span> = ' + escHtml(t('dns.legManual')) + ' · ';
                html += '<span class="badge bg-warning text-dark">' + escHtml(t('dns.modeForced')) + '</span> = ' + escHtml(t('dns.legForced')) + ' · ';
                html += '<span class="text-muted">—</span> = ' + escHtml(t('dns.legNa')) + '';
                html += '</div></div>';

                body.innerHTML = html;
            }).catch(e => {
                body.innerHTML = '<div class="text-danger small">' + escHtml(t('common.networkError', { message: e.message })) + '</div>';
            });
        }

""";
    }

    /**
     * Blocco JS della diagnostica timezone DKIM (estratto per ridurre la dimensione
     * del text block constante).
     */
    private static String getDnsJsTzDiag() {
        return """
        // ===== Diagnostica timezone =====
        function toggleTzDiag() {
            const body = document.getElementById('tzDiagBody');
            const isOpen = !body.classList.contains('d-none');
            if (isOpen) {
                body.classList.add('d-none');
            } else {
                body.classList.remove('d-none');
                loadTzDiag();
            }
        }

        function loadTzDiag() {
            const badge = document.getElementById('tzDiagStatusBadge');
            const table = document.getElementById('tzDiagTable');
            const logEl = document.getElementById('tzDiagLog');
            if (logEl) logEl.innerHTML = '';
            badge.innerHTML = '<span class="badge bg-light text-dark"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('dns.checking')) + '</span>';
            table.innerHTML = '<div class="text-muted small"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('common.loading')) + '</div>';

            fetch('/api/timezone-diag').then(r => r.json()).then(data => {
                renderTzDiag(data);
            }).catch(e => {
                badge.innerHTML = '<span class="badge bg-danger">' + escHtml(t('common.errorShort')) + '</span>';
                table.innerHTML = '<div class="alert alert-danger small mb-0">' + escHtml(t('common.error', { message: e.message })) + '</div>';
            });
        }

        function renderTzDiag(data) {
            const badge = document.getElementById('tzDiagStatusBadge');
            const table = document.getElementById('tzDiagTable');

            // Badge nell'header
            const alignment = data.alignment || 'UNKNOWN';
            if (alignment === 'OK') {
                badge.innerHTML = '<span class="badge bg-success"><i class="fas fa-check-circle me-1" aria-hidden="true"></i>' + escHtml(t('dns.tzAligned')) + '</span>';
            } else if (alignment === 'MISMATCH') {
                const skewMin = Math.round((data.skew_mysql_vs_jvm_ms || 0) / 60000);
                badge.innerHTML = '<span class="badge bg-danger"><i class="fas fa-exclamation-triangle me-1" aria-hidden="true"></i>' + escHtml(t('dns.tzMisaligned', { min: skewMin })) + '</span>';
            } else {
                badge.innerHTML = '<span class="badge bg-secondary">?</span>';
            }

            // Tabella
            let html = '<table class="table table-sm align-middle mb-0">';
            html += '<thead><tr><th scope="col">' + escHtml(t('dns.tzSource')) + '</th><th scope="col">' + escHtml(t('dns.tzTimestamp')) + '</th><th scope="col">' + escHtml(t('dns.tzZone')) + '</th></tr></thead><tbody>';

            // OS
            const osMs = data.os_now_ms;
            const osDate = osMs ? new Date(osMs) : null;
            html += '<tr><td><strong>' + escHtml(t('dns.tzOs')) + '</strong><br><small class="text-muted">' + escHtml(t('dns.tzOsHow')) + ' <code>date</code></small></td>';
            html += '<td>' + (osDate ? '<code>' + osDate.toISOString() + '</code><br><small>' + escHtml(t('dns.tzLocal', { time: osDate.toLocaleString(window.I18N_LANG) })) + '</small>' : '<em>' + escHtml(t('dns.tzUnavailable')) + '</em>') + '</td>';
            html += '<td>' + (data.os_offset ? '<code>' + escapeHtmlCf(data.os_offset) + '</code>' : '') + ' ' + (data.os_tz ? '<small class="text-muted">' + escapeHtmlCf(data.os_tz) + '</small>' : '') + '</td>';
            html += '</tr>';

            // JVM
            const jvmMs = data.jvm_now_ms;
            const jvmDate = jvmMs ? new Date(jvmMs) : null;
            html += '<tr><td><strong>Java (JVM)</strong><br><small class="text-muted">Instant.now()</small></td>';
            html += '<td>' + (jvmDate ? '<code>' + jvmDate.toISOString() + '</code>' : '') + '</td>';
            html += '<td><code>' + escapeHtmlCf(data.jvm_default_zone || '?') + '</code> <small class="text-muted">(' + escapeHtmlCf(data.jvm_offset || '?') + ')</small></td>';
            html += '</tr>';

            // MySQL
            const mysqlMs = data.mysql_now_ms;
            const mysqlDate = mysqlMs ? new Date(mysqlMs) : null;
            html += '<tr><td><strong>MySQL</strong><br><small class="text-muted">NOW() via UNIX_TIMESTAMP</small></td>';
            html += '<td>' + (mysqlDate ? '<code>' + mysqlDate.toISOString() + '</code><br><small>NOW(): ' + escapeHtmlCf(data.mysql_now || '') + '</small><br><small>UTC: ' + escapeHtmlCf(data.mysql_utc_now || '') + '</small>' : '<em class="text-danger">' + escapeHtmlCf(data.mysql_error || t('dns.tzUnavailable')) + '</em>') + '</td>';
            html += '<td>session: <code>' + escapeHtmlCf(data.mysql_session_tz || '?') + '</code><br>global: <code>' + escapeHtmlCf(data.mysql_global_tz || '?') + '</code><br>system: <code>' + escapeHtmlCf(data.mysql_system_tz || '?') + '</code></td>';
            html += '</tr>';

            // Browser (cliente)
            const browserNow = new Date();
            html += '<tr><td><strong>' + escHtml(t('dns.tzBrowser')) + '</strong><br><small class="text-muted">Date.now()</small></td>';
            html += '<td><code>' + browserNow.toISOString() + '</code><br><small>' + escHtml(t('dns.tzLocal', { time: browserNow.toLocaleString(window.I18N_LANG) })) + '</small></td>';
            html += '<td>' + escapeHtmlCf(Intl.DateTimeFormat().resolvedOptions().timeZone || '?') + '</td>';
            html += '</tr>';

            html += '</tbody></table>';

            // Verdetto
            if (alignment === 'MISMATCH') {
                const skewMs = data.skew_mysql_vs_jvm_ms || 0;
                const skewMin = Math.round(skewMs / 60000);
                const verdict = skewMs > 0 ? t('dns.tzAhead', { min: Math.abs(skewMin) }) : t('dns.tzBehind', { min: Math.abs(skewMin) });
                html += '<div class="alert alert-warning mt-3 mb-0"><i class="fas fa-exclamation-triangle me-2" aria-hidden="true"></i><strong>' + escHtml(verdict) + '</strong> ' + escHtml(t('dns.tzFixHint')) + '</div>';
            } else if (alignment === 'OK') {
                html += '<div class="alert alert-success mt-3 mb-0"><i class="fas fa-check-circle me-2" aria-hidden="true"></i>' + escHtml(t('dns.tzAllAligned')) + '</div>';
            }

            table.innerHTML = html;
        }

        function tzSyncToSystem() {
            if (!confirm(t('dns.tzConfirmSync'))) return;
            tzPerformAction({ action: 'sync_to_system' });
        }

        function tzSetManual() {
            const v = document.getElementById('tzManualValue').value.trim();
            if (!v) { alert(t('dns.tzNeedValue')); return; }
            tzPerformAction({ action: 'set', value: v });
        }

        function tzPerformAction(payload) {
            const logEl = document.getElementById('tzDiagLog');
            logEl.innerHTML = '<div class="text-muted"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('dns.running')) + '</div>';
            fetch('/api/timezone-diag', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            }).then(r => r.json()).then(data => {
                let html = '';
                if (data.log) {
                    html += '<pre class="bg-light p-2 rounded small mb-2" style="white-space:pre-wrap">' + escapeHtmlCf(data.log) + '</pre>';
                }
                if (data.success) {
                    html = '<div class="alert alert-success py-2 mb-2"><i class="fas fa-check-circle me-1" aria-hidden="true"></i>' + escHtml(t('dns.tzDone')) + ' <code>' + escapeHtmlCf(data.desired_value || '') + '</code></div>' + html;
                } else {
                    html = '<div class="alert alert-danger py-2 mb-2"><i class="fas fa-times-circle me-1" aria-hidden="true"></i>' + escHtml(t('common.error', { message: data.error || t('common.unknownError') })) + '</div>' + html;
                }
                logEl.innerHTML = html;
                // Aggiorna i dati visualizzati
                renderTzDiag(data);
            }).catch(e => {
                logEl.innerHTML = '<div class="alert alert-danger py-2 mb-0">' + escHtml(t('common.networkError', { message: e.message })) + '</div>';
            });
        }

        // Carica subito lo stato della diagnostica (anche se il body è collassato,
        // il badge nell'header deve mostrare OK/Disallineato)
        loadTzDiag();

""";
    }

    /**
     * Markup HTML del modal di scelta della modalità di rotazione DKIM (Cloudflare vs Manuale).
     * Estratto come metodo per ridurre la dimensione del text block constante.
     */
    private static String getDnsRotateModeChooserModal() {
        return """
            <!-- Modal di scelta modalità rotazione (Cloudflare API vs DNS manuale) -->
            <div class="modal fade" id="rotateModeChooserModal" tabindex="-1" aria-labelledby="rotateModeChooserModalLabel" aria-hidden="true">
                <div class="modal-dialog modal-dialog-centered">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title" id="rotateModeChooserModalLabel"><i class="fas fa-sync-alt me-2" aria-hidden="true"></i>{{t:dns.rotModeTitle}}</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="{{t:common.close}}"></button>
                        </div>
                        <div class="modal-body">
                            <p class="mb-3">{{t:dns.rotModeQuestion}}</p>

                            <div class="d-grid gap-2">
                                <button type="button" class="btn btn-success text-start" onclick="rotateDkimStartChooseCloudflare()">
                                    <div class="d-flex align-items-start">
                                        <i class="fas fa-cloud fa-2x me-3 mt-1" aria-hidden="true"></i>
                                        <div>
                                            <strong>{{t:dns.rotModeCf}}</strong><br>
                                            <small>{{t:dns.rotModeCfHint}} <strong id="rotateModeAccountLabel">—</strong>.</small>
                                            <div class="small mt-1 text-muted">{{t:dns.rotModeCfWhen}}</div>
                                        </div>
                                    </div>
                                </button>

                                <button type="button" class="btn btn-outline-secondary text-start" onclick="rotateDkimStartChooseManual()">
                                    <div class="d-flex align-items-start">
                                        <i class="fas fa-edit fa-2x me-3 mt-1" aria-hidden="true"></i>
                                        <div>
                                            <strong>{{t:dns.rotModeManual}}</strong><br>
                                            <small>{{t:dns.rotModeManualHint}}</small>
                                            <div class="small mt-1 text-muted">{{t:dns.rotModeManualWhen}}</div>
                                        </div>
                                    </div>
                                </button>
                            </div>

                            <div class="alert alert-light mt-3 small mb-0">
                                <i class="fas fa-info-circle me-1" aria-hidden="true"></i>{{t:dns.rotModeBoth}}
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-link" data-bs-dismiss="modal">{{t:common.cancel}}</button>
                        </div>
                    </div>
                </div>
            </div>

""";
    }

    /**
     * Markup HTML della card "Cambia Username" (estratta per ridurre la dimensione del
     * text block constante della pagina admin settings).
     */
    /**
     * Le schede dell'accesso nelle Impostazioni: l'email a cui arrivano i codici, le passkey e le
     * sessioni aperte. Nessuna password: non esiste piu'.
     */
    private static String getAccountCards() {
        return """
                    <div class="alert alert-warning d-none" id="passkeySetupNotice" role="status">
                        <i class="fas fa-fingerprint me-2" aria-hidden="true"></i>{{t:acc.setupNotice}}
                    </div>

                    <!-- Email di accesso -->
                    <div class="card mb-4" id="accountCard">
                        <div class="card-header"><i class="fas fa-envelope me-2" aria-hidden="true"></i>{{t:acc.emailTitle}}</div>
                        <div class="card-body">
                            <p class="text-muted small">{{t:acc.intro}}</p>
                            <p class="mb-2">{{t:acc.emailCurrent}} <strong id="accEmailCurrent" class="testo-lungo">…</strong></p>
                            <label class="form-label" for="accEmailNew">{{t:acc.emailNew}}</label>
                            <div class="input-group mb-2">
                                <input type="email" class="form-control" id="accEmailNew" maxlength="254" autocomplete="email"
                                       inputmode="email" autocapitalize="off" spellcheck="false">
                                <button class="btn btn-outline-primary" type="button" id="accEmailSend" onclick="accEmailRequest()">{{t:login.sendCode}}</button>
                            </div>
                            <div id="accEmailCodeBox" class="d-none">
                                <label class="form-label" for="accEmailCode">{{t:acc.emailCode}}</label>
                                <div class="input-group">
                                    <input type="text" class="form-control" id="accEmailCode" maxlength="6" inputmode="numeric"
                                           autocomplete="one-time-code" placeholder="000000">
                                    <button class="btn btn-primary" type="button" onclick="accEmailConfirm()">{{t:acc.confirm}}</button>
                                </div>
                            </div>
                            <div id="accEmailMsg" class="small mt-2" role="status" aria-live="polite"></div>
                            <p class="small text-muted mt-3 mb-0">{{t:acc.emailNote.html}}</p>
                        </div>
                    </div>

                    <!-- Passkey -->
                    <div class="card mb-4" id="passkeysCard">
                        <div class="card-header"><i class="fas fa-fingerprint me-2" aria-hidden="true"></i>{{t:set.passkeys}}</div>
                        <div class="card-body">
                            <p class="text-muted">{{t:acc.passkeysIntro}}</p>
                            <div id="passkeysList" class="mb-3" aria-live="polite">
                                <div class="text-center text-muted py-3"><i class="fas fa-spinner fa-spin" aria-hidden="true"></i> {{t:common.loading}}</div>
                            </div>
                            <p id="passkeyDomainNote" class="small text-warning d-none">{{t:acc.needsDomain}}</p>
                            <button class="btn btn-success" onclick="addPasskey()" id="addPasskeyBtn">
                                <i class="fas fa-plus me-1" aria-hidden="true"></i>{{t:set.addPasskey}}
                            </button>
                        </div>
                    </div>

                    <!-- Sessioni -->
                    <div class="card mb-4">
                        <div class="card-header"><i class="fas fa-laptop me-2" aria-hidden="true"></i>{{t:acc.sessionsTitle}}</div>
                        <div class="card-body">
                            <p class="text-muted small">{{t:acc.sessionsIntro}}</p>
                            <div id="sessionsList" class="mb-3" aria-live="polite"></div>
                            <button class="btn btn-outline-danger btn-sm" type="button" id="btnRevokeOthers" onclick="revokeOthers()">
                                <i class="fas fa-right-from-bracket me-1" aria-hidden="true"></i>{{t:acc.revokeOthers}}
                            </button>
                        </div>
                    </div>

""";
    }

    /** Le finestre dell'accesso: nome della passkey, nuovo nome, conferma di un'operazione delicata. */
    private static String getAccountModals() {
        return """
    <!-- Nome della passkey nuova -->
    <div class="modal fade" id="passkeyNameModal" tabindex="-1" aria-labelledby="passkeyNameTitle" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="passkeyNameTitle"><i class="fas fa-fingerprint me-2" aria-hidden="true"></i>{{t:set.passkeyName}}</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="{{t:common.close}}"></button>
                </div>
                <div class="modal-body">
                    <label class="form-label" for="passkeyName">{{t:set.namePasskey}}</label>
                    <input type="text" class="form-control" id="passkeyName" maxlength="40" placeholder="{{t:set.passkeyNamePlaceholder}}" aria-describedby="passkeyNameHint">
                    <small class="text-muted" id="passkeyNameHint">{{t:acc.passkeyNameHint}}</small>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">{{t:common.cancel}}</button>
                    <button type="button" class="btn btn-primary" onclick="confirmPasskeyName()">{{t:common.save}}</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Nuovo nome di una passkey -->
    <div class="modal fade" id="renamePasskeyModal" tabindex="-1" aria-labelledby="renamePasskeyTitle" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="renamePasskeyTitle"><i class="fas fa-edit me-2" aria-hidden="true"></i>{{t:set.renamePasskey}}</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="{{t:common.close}}"></button>
                </div>
                <div class="modal-body">
                    <input type="hidden" id="renamePasskeyId">
                    <label class="form-label" for="renamePasskeyName">{{t:set.newName}}</label>
                    <input type="text" class="form-control" id="renamePasskeyName" maxlength="40" aria-describedby="renamePasskeyHint">
                    <small class="text-muted" id="renamePasskeyHint">{{t:acc.passkeyNameHint}}</small>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">{{t:common.cancel}}</button>
                    <button type="button" class="btn btn-primary" onclick="confirmRenamePasskey()">{{t:common.save}}</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Conferma che sei tu -->
    <div class="modal fade" id="stepUpModal" tabindex="-1" aria-labelledby="stepUpTitle" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="stepUpTitle"><i class="fas fa-user-shield me-2" aria-hidden="true"></i>{{t:acc.stepUpTitle}}</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="{{t:common.close}}"></button>
                </div>
                <div class="modal-body">
                    <p class="text-muted">{{t:acc.stepUpIntro}}</p>
                    <div class="d-grid gap-2">
                        <button type="button" class="btn btn-primary" id="stepUpPasskeyBtn" onclick="stepUpPasskey()">
                            <i class="fas fa-fingerprint me-2" aria-hidden="true"></i>{{t:acc.stepUpPasskey}}
                        </button>
                        <button type="button" class="btn btn-outline-secondary" id="stepUpEmailBtn" onclick="stepUpEmail()">
                            <i class="fas fa-paper-plane me-2" aria-hidden="true"></i>{{t:acc.stepUpEmail}}
                        </button>
                    </div>
                    <div id="stepUpCodeBox" class="d-none mt-3">
                        <label class="form-label" for="stepUpCode">{{t:login.codeLabel}}</label>
                        <div class="input-group">
                            <input type="text" class="form-control" id="stepUpCode" maxlength="6" inputmode="numeric" autocomplete="one-time-code" placeholder="000000">
                            <button type="button" class="btn btn-primary" onclick="stepUpVerify()">{{t:login.verify}}</button>
                        </div>
                    </div>
                    <div id="stepUpMsg" class="small mt-2" role="status" aria-live="polite"></div>
                </div>
            </div>
        </div>
    </div>
""";
    }

    private static String getChangeUsernameCard() {
        return """
                    <!-- Change Username -->
                    <div class="card mb-4">
                        <div class="card-header"><i class="fas fa-user-edit me-2" aria-hidden="true"></i>{{t:set.changeUsername}}</div>
                        <div class="card-body">
                            <div class="alert alert-info py-2 mb-3 small">
                                <i class="fas fa-info-circle me-1" aria-hidden="true"></i>
                                {{t:set.usernameInfo}}
                            </div>
                            <div class="mb-3">
                                <label class="form-label" for="newUsername">{{t:set.newUsername}}</label>
                                <input type="text" class="form-control" id="newUsername" maxlength="50" placeholder="{{t:set.usernamePlaceholder}}" autocomplete="off" autocapitalize="off" spellcheck="false" aria-describedby="newUsernameHint">
                                <small class="text-muted" id="newUsernameHint">{{t:set.usernameHint}}</small>
                            </div>
                            <button class="btn btn-primary" onclick="changeUsername()">
                                <i class="fas fa-save me-1" aria-hidden="true"></i>{{t:set.changeUsername}}
                            </button>
                        </div>
                    </div>

""";
    }

    /**
     * Markup HTML della card "Master key del vault" (gestione backup + rotazione).
     */
    private static String getClamavHealthCard() {
        return """
            <!-- ClamAV Health Check -->
            <div class="card mb-4 border-success">
                <div class="card-header bg-success text-white d-flex justify-content-between align-items-center flex-wrap gap-2">
                    <span><i class="fas fa-virus-slash me-2" aria-hidden="true"></i><strong>{{t:sec.clamav}}</strong> <small class="ms-2" id="cavOverallStatus"></small></span>
                    <div class="d-flex gap-2">
                        <button class="btn btn-sm btn-info text-white" id="btnCavTestEicar" onclick="runCavTestEicar()" title="{{t:sec.eicarHint}}">
                            <i class="fas fa-flask me-1" aria-hidden="true"></i>{{t:sec.eicar}}
                        </button>
                        <button class="btn btn-sm btn-warning d-none" id="btnCavFixAll" onclick="runCavFixAll()">
                            <i class="fas fa-magic me-1" aria-hidden="true"></i>{{t:sec.fixAll}}
                        </button>
                        <button class="btn btn-sm btn-light" onclick="loadClamavHealth()">
                            <i class="fas fa-sync me-1" aria-hidden="true"></i>{{t:dns.tzRecheck}}
                        </button>
                    </div>
                </div>
                <div class="card-body" id="cavContainer">
                    <p class="text-muted mb-0"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>{{t:sec.diagnosing}}</p>
                </div>
                <div class="card-body border-top d-none" id="cavEicarResult">
                    <h6 class="mb-2"><i class="fas fa-flask me-1" aria-hidden="true"></i>{{t:sec.eicarResult}}</h6>
                    <div id="cavEicarBody"></div>
                </div>
                <div class="card-body border-top d-none" id="cavFixAllReport">
                    <h6 class="mb-2"><i class="fas fa-list-check me-1" aria-hidden="true"></i>{{t:sec.fixReport}}</h6>
                    <div id="cavFixAllSteps"></div>
                </div>
            </div>
""";
    }

    private static String getJailConfigurationJs() {
        return """
        // ===== Jail Configuration =====
        // Helper per i pulsanti preset: setta il valore dell'input
        function setCfg(id, value) {
            const el = document.getElementById(id);
            if (el) { el.value = value; el.dispatchEvent(new Event('input')); }
        }

        // Popola la select con tutte le jail attualmente attive (chiamato all'avvio)
        function populateJailSelect(onDone) {
            const sel = document.getElementById('cfgJailSelect');
            const prev = sel.value;
            fetch('/api/fail2ban?action=live_state_all').then(r => r.json()).then(data => {
                if (!data || !Array.isArray(data.jails)) { if (onDone) onDone(); return; }
                const names = data.jails.map(j => j.name).filter(Boolean);
                if (names.length === 0) { if (onDone) onDone(); return; }
                // Conserva la selezione precedente se ancora valida
                sel.innerHTML = names.map(n => '<option value="' + escHtml(n) + '">' + escHtml(n) + '</option>').join('');
                if (names.indexOf(prev) >= 0) sel.value = prev;
                if (onDone) onDone();
            }).catch(() => { if (onDone) onDone(); });
        }

        // Opzioni filtro disponibili, raggruppate per "famiglia" di jail.
        // Per ogni jail mostriamo SOLO le opzioni della sua famiglia (es. dovecot
        // non vede i preset postfix). Una opzione "custom" e' sempre disponibile.
        const FILTER_PRESETS = {
            postfix: [
                { value: 'postfix-sasl', label: t('jc.fSafe'), badge: t('jc.bNoScanner'), catches: t('jc.pfSaslCatches'), misses: t('jc.pfSaslMisses') },
                { value: 'postfix[mode=more]', label: t('jc.fMedium'), badge: '', catches: t('jc.pfMoreCatches'), misses: t('jc.pfMoreMisses') },
                { value: 'postfix[mode=aggressive]', label: t('jc.fAggressive'), badge: t('jc.bAntiBot'), catches: t('jc.pfAggCatches'), misses: t('jc.pfAggMisses') },
                { value: 'postfix[mode=ddos]', label: 'DDoS', badge: t('jc.bVolume'), catches: t('jc.pfDdosCatches'), misses: t('jc.pfDdosMisses') }
            ],
            dovecot: [
                { value: 'dovecot', label: t('jc.fSafe'), badge: t('jc.bNoScanner'), catches: t('jc.dvCatches'), misses: t('jc.dvMisses') },
                { value: 'dovecot[mode=aggressive]', label: t('jc.fAggressive'), badge: t('jc.bAntiBot'), catches: t('jc.dvAggCatches'), misses: t('jc.dvAggMisses') }
            ],
            rspamd: [
                { value: 'rspamd', label: t('jc.fStandard'), badge: '', catches: t('jc.rsCatches'), misses: t('jc.rsMisses') }
            ],
            other: [
                { value: '__custom__', label: t('jc.fCustom'), badge: '', catches: t('jc.customCatches'), misses: '' }
            ]
        };

        // Determina la famiglia di una jail dal suo nome.
        function jailFamily(jailName) {
            const n = (jailName || '').toLowerCase();
            if (n.includes('postfix')) return 'postfix';
            if (n.includes('dovecot')) return 'dovecot';
            if (n.includes('rspamd')) return 'rspamd';
            return 'other';
        }

        function renderFilterOptions(jail, currentFilter) {
            const family = jailFamily(jail);
            const container = document.getElementById('cfgFilterOptions');
            const customWrap = document.getElementById('cfgFilterCustom');
            const customInput = document.getElementById('cfgFilter');
            const currentEl = document.getElementById('cfgFilterCurrent');
            if (!container) return;

            const esc = (s) => { const d = document.createElement('div'); d.textContent = s == null ? '' : String(s); return d.innerHTML; };
            currentEl.textContent = currentFilter || t('jc.notSet');

            // Jail senza preset (mail-panel-auth, roundcube-auth, ...):
            // niente card, solo un input semplice prefillato col valore corrente.
            if (family === 'other') {
                container.innerHTML =
                    '<div class="alert alert-info py-2 px-3 mb-0 small">'
                    + '<i class="fas fa-info-circle me-1" aria-hidden="true"></i>'
                    + escHtml(t('jc.customJail', { jail: jail }))
                    + '</div>';
                customWrap.classList.remove('d-none');
                if (customInput) customInput.value = currentFilter || '';
                window.__cfgSelectedFilter = '__custom__';
                return;
            }

            // Per famiglie note (postfix/dovecot/rspamd): card cliccabili + "Personalizzato"
            const presets = (FILTER_PRESETS[family] || []).concat(FILTER_PRESETS.other);

            // Capisci quale preset corrisponde al filtro corrente; se nessuno, e' custom
            let activeValue = currentFilter;
            const knownValues = presets.map(p => p.value);
            if (currentFilter && !knownValues.includes(currentFilter)) {
                activeValue = '__custom__';
                customWrap.classList.remove('d-none');
                if (customInput) customInput.value = currentFilter;
            } else {
                customWrap.classList.add('d-none');
                if (customInput) customInput.value = '';
            }

            container.innerHTML = presets.map(p => {
                const isActive = (p.value === activeValue);
                const badgeHtml = p.badge
                    ? '<span class="badge bg-success ms-2" style="font-size:.65rem">' + esc(p.badge) + '</span>'
                    : '';
                const inUseBadge = isActive
                    ? '<span class="badge bg-primary ms-2" style="font-size:.65rem"><i class="fas fa-check me-1" aria-hidden="true"></i>' + escHtml(t('jc.inUse')) + '</span>'
                    : '';
                // Colori che funzionano su tema chiaro E scuro:
                //  - bordo: blu solido se attivo, grigio semi-trasparente se inattivo
                //  - sfondo: tinta blu trasparente se attivo, niente sfondo se inattivo
                //    (cosi' il colore del container parent rimane visibile)
                const borderColor = isActive ? '#0d6efd' : 'rgba(128,128,128,0.35)';
                const bg = isActive ? 'rgba(13,110,253,0.15)' : 'transparent';
                return '<div class="filter-option" data-value="' + esc(p.value) + '" '
                     + 'style="cursor:pointer; padding:10px; border:2px solid ' + borderColor + '; border-radius:6px; background:' + bg + '" '
                     + 'onclick="selectFilterOption(\\'' + esc(p.value) + '\\')">'
                     + '<div class="d-flex justify-content-between align-items-center mb-1 flex-wrap gap-1">'
                     + '  <div><strong>' + esc(p.label) + '</strong> <code class="small text-muted ms-2">' + esc(p.value === '__custom__' ? t('jc.otherFilter') : p.value) + '</code>' + badgeHtml + inUseBadge + '</div>'
                     + '</div>'
                     + (p.catches ? '<div class="small text-success mb-0"><i class="fas fa-check-circle me-1" aria-hidden="true"></i><strong>' + escHtml(t('jc.catches')) + '</strong> ' + esc(p.catches) + '</div>' : '')
                     + (p.misses ? '<div class="small text-muted mb-0"><i class="fas fa-times-circle me-1" aria-hidden="true"></i><strong>' + escHtml(t('jc.misses')) + '</strong> ' + esc(p.misses) + '</div>' : '')
                     + '</div>';
            }).join('');
        }

        // Click su una card → seleziona quel filtro
        function selectFilterOption(value) {
            const customWrap = document.getElementById('cfgFilterCustom');
            const customInput = document.getElementById('cfgFilter');
            if (value === '__custom__') {
                customWrap.classList.remove('d-none');
                if (customInput) customInput.focus();
            } else {
                customWrap.classList.add('d-none');
                if (customInput) customInput.value = value;
            }
            // Riapplica gli stili attivi senza ricaricare dal server
            const cards = document.querySelectorAll('.filter-option');
            cards.forEach(c => {
                const active = c.getAttribute('data-value') === value;
                c.style.borderColor = active ? '#0d6efd' : 'rgba(128,128,128,0.35)';
                c.style.background = active ? 'rgba(13,110,253,0.15)' : 'transparent';
            });
            // Memorizza la selezione (per il save successivo)
            window.__cfgSelectedFilter = value;
        }

        function loadJailConfig() {
            const jail = document.getElementById('cfgJailSelect').value;
            const status = document.getElementById('cfgJailStatus');
            status.textContent = t('common.loading');
            status.className = 'ms-2 small text-muted';
            fetch('/api/fail2ban', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'get_jail_config', jail: jail })
            }).then(r => r.json()).then(data => {
                if (data.success) {
                    document.getElementById('cfgMaxRetry').value = data.max_retry;
                    document.getElementById('cfgFindTime').value = data.find_time;
                    document.getElementById('cfgBanTime').value = data.ban_time;
                    // Filtro + ignoreip
                    renderFilterOptions(jail, data.filter || '');
                    window.__cfgSelectedFilter = data.filter || '';
                    renderIgnoreIpList(jail, data.ignoreip || []);
                    status.textContent = t('jc.readFrom');
                    status.className = 'ms-2 small text-success';
                } else {
                    status.textContent = t('common.error', { message: data.message || t('common.unknownError') });
                    status.className = 'ms-2 small text-danger';
                    renderIgnoreIpList(jail, []);
                    renderFilterOptions(jail, '');
                }
            }).catch(e => {
                status.textContent = t('common.error', { message: e.message });
                status.className = 'ms-2 small text-danger';
            });
        }

        function renderIgnoreIpList(jail, ips) {
            const el = document.getElementById('cfgIgnoreIpList');
            if (!el) return;
            const esc = (s) => { const d = document.createElement('div'); d.textContent = s == null ? '' : String(s); return d.innerHTML; };
            if (!ips || ips.length === 0) {
                el.innerHTML = '<span class="text-muted small"><i class="fas fa-info-circle me-1" aria-hidden="true"></i>' + escHtml(t('jc.noIgnore', { jail: jail })) + '</span>';
                return;
            }
            el.innerHTML = ips.map(ip =>
                '<span class="badge bg-light text-dark border me-1 mb-1" style="font-size:.8rem">' +
                '<code>' + esc(ip) + '</code>' +
                ' <button class="btn btn-link btn-sm p-0 ms-1" style="font-size:.75rem;color:#dc3545" onclick="removeIgnoreIp(\\'' + esc(ip) + '\\')" title="' + escHtml(t('jc.removeIgnore')) + '" aria-label="' + escHtml(t('jc.removeIgnore')) + ' ' + esc(ip) + '"><i class="fas fa-times" aria-hidden="true"></i></button>' +
                '</span>'
            ).join('');
        }

        function saveJailFilter() {
            const jail = document.getElementById('cfgJailSelect').value;
            const status = document.getElementById('cfgJailStatus');
            // Il filtro selezionato e' sia il preset cliccato che il testo custom.
            // Se l'utente ha cliccato "Personalizzato", prende il valore dell'input.
            let filter = window.__cfgSelectedFilter || '';
            const customInput = document.getElementById('cfgFilter');
            if (filter === '__custom__') {
                filter = customInput ? customInput.value.trim() : '';
            }
            if (!filter || filter === '__custom__') {
                status.textContent = t('jc.chooseFilter');
                status.className = 'ms-2 small text-danger';
                return;
            }
            if (!confirm(t('jc.confirmFilter', { jail: jail, filter: filter }))) return;
            status.textContent = t('jc.savingFilter');
            status.className = 'ms-2 small text-muted';
            fetch('/api/fail2ban', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'set_jail_filter', jail: jail, filter: filter })
            }).then(r => r.json()).then(data => {
                status.textContent = data.success ? t('jc.ok', { message: data.message || '' }) : t('common.error', { message: data.message || '' });
                status.className = 'ms-2 small ' + (data.success ? 'text-success' : 'text-danger');
                if (data.success) {
                    setTimeout(() => loadJailConfig(), 500);
                    if (typeof loadJailLiveState === 'function') setTimeout(loadJailLiveState, 1000);
                }
            }).catch(e => {
                status.textContent = t('common.networkError', { message: e.message });
                status.className = 'ms-2 small text-danger';
            });
        }

        function addIgnoreIp() {
            const jail = document.getElementById('cfgJailSelect').value;
            const ip = document.getElementById('cfgIgnoreIpInput').value.trim();
            const status = document.getElementById('cfgJailStatus');
            if (!ip) { status.textContent = t('jc.needIp'); status.className = 'ms-2 small text-danger'; return; }
            fetch('/api/fail2ban', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'add_jail_ignoreip', jail: jail, ip: ip })
            }).then(r => r.json()).then(data => {
                status.textContent = data.success ? t('jc.ok', { message: data.message || '' }) : t('common.error', { message: data.message || '' });
                status.className = 'ms-2 small ' + (data.success ? 'text-success' : 'text-danger');
                if (data.success) {
                    document.getElementById('cfgIgnoreIpInput').value = '';
                    loadJailConfig();
                }
            }).catch(e => {
                status.textContent = t('common.networkError', { message: e.message });
                status.className = 'ms-2 small text-danger';
            });
        }

        function removeIgnoreIp(ip) {
            const jail = document.getElementById('cfgJailSelect').value;
            const status = document.getElementById('cfgJailStatus');
            if (!confirm(t('jc.confirmRemoveIgnore', { ip: ip, jail: jail }))) return;
            fetch('/api/fail2ban', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'remove_jail_ignoreip', jail: jail, ip: ip })
            }).then(r => r.json()).then(data => {
                status.textContent = data.success ? t('jc.ok', { message: data.message || '' }) : t('common.error', { message: data.message || '' });
                status.className = 'ms-2 small ' + (data.success ? 'text-success' : 'text-danger');
                if (data.success) loadJailConfig();
            }).catch(e => {
                status.textContent = t('common.networkError', { message: e.message });
                status.className = 'ms-2 small text-danger';
            });
        }

        function saveJailConfig() {
            const jail = document.getElementById('cfgJailSelect').value;
            const maxRetry = parseInt(document.getElementById('cfgMaxRetry').value, 10);
            const findTime = parseInt(document.getElementById('cfgFindTime').value, 10);
            const banTime = parseInt(document.getElementById('cfgBanTime').value, 10);
            const status = document.getElementById('cfgJailStatus');
            if (!Number.isFinite(maxRetry) || !Number.isFinite(findTime) || !Number.isFinite(banTime)) {
                status.textContent = t('jc.needNumbers');
                status.className = 'ms-2 small text-danger';
                return;
            }
            status.textContent = t('jc.saving');
            status.className = 'ms-2 small text-muted';
            fetch('/api/fail2ban', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action: 'update_jail_config',
                    jail: jail,
                    max_retry: maxRetry,
                    find_time: findTime,
                    ban_time: banTime
                })
            }).then(r => r.json()).then(data => {
                if (data.success) {
                    status.textContent = data.message || t('ssl.savedShort');
                    status.className = 'ms-2 small text-success';
                    loadStatus();
                } else {
                    status.textContent = t('common.error', { message: data.message || data.error || t('common.unknownError') });
                    status.className = 'ms-2 small text-danger';
                }
            }).catch(e => {
                status.textContent = t('common.error', { message: e.message });
                status.className = 'ms-2 small text-danger';
            });
        }

        function saveJailConfigAllJails() {
            const maxRetry = parseInt(document.getElementById('cfgMaxRetry').value, 10);
            const findTime = parseInt(document.getElementById('cfgFindTime').value, 10);
            const banTime = parseInt(document.getElementById('cfgBanTime').value, 10);
            const status = document.getElementById('cfgJailStatus');
            if (!Number.isFinite(maxRetry) || !Number.isFinite(findTime) || !Number.isFinite(banTime)) {
                status.textContent = t('jc.needNumbers');
                status.className = 'ms-2 small text-danger';
                return;
            }
            if (!confirm(t('jc.confirmAll', { maxretry: maxRetry, findtime: findTime, bantime: banTime }))) return;
            status.textContent = t('jc.applying');
            status.className = 'ms-2 small text-muted';
            fetch('/api/fail2ban', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action: 'update_all_jails_config',
                    max_retry: maxRetry,
                    find_time: findTime,
                    ban_time: banTime
                })
            }).then(r => r.json()).then(data => {
                if (data.success) {
                    status.textContent = tn('jc.appliedTo', data.success_count || 0);
                    status.className = 'ms-2 small text-success';
                } else {
                    let msg = data.message || data.error || t('common.errorShort');
                    if (Array.isArray(data.results)) {
                        const failed = data.results.filter(r => !r.success).map(r => r.jail + ': ' + r.message).join('\\n');
                        if (failed) msg += '\\n' + failed;
                    }
                    status.textContent = t('common.error', { message: msg });
                    status.className = 'ms-2 small text-danger';
                }
                loadStatus();
                if (typeof loadJailLiveState === 'function') loadJailLiveState();
            }).catch(e => {
                status.textContent = t('common.error', { message: e.message });
                status.className = 'ms-2 small text-danger';
            });
        }
""";
    }

    private static String getJailConfigurationCard() {
        return """
                    <!-- Jail Configuration -->
                    <div class="card mb-4">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <span><i class="fas fa-cog me-2" aria-hidden="true"></i>{{t:jc.title}}</span>
                            <select class="form-select form-select-sm w-auto" id="cfgJailSelect" aria-label="Jail" onchange="loadJailConfig()">
                                <option value="mail-panel-auth">mail-panel-auth</option>
                            </select>
                        </div>
                        <div class="card-body">
                            <div class="row g-2 align-items-start">
                                <div class="col-md-4">
                                    <label class="form-label small mb-1" for="cfgMaxRetry">{{t:jc.maxRetry}}</label>
                                    <input type="number" class="form-control form-control-sm" id="cfgMaxRetry" min="1" max="100" value="5">
                                    <div class="mt-1 d-flex gap-1 flex-wrap">
                                        <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2" style="font-size:.7rem" onclick="setCfg('cfgMaxRetry',2)">2 <span class="text-success">★</span></button>
                                        <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2" style="font-size:.7rem" onclick="setCfg('cfgMaxRetry',3)">3</button>
                                        <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2" style="font-size:.7rem" onclick="setCfg('cfgMaxRetry',5)">5</button>
                                        <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2" style="font-size:.7rem" onclick="setCfg('cfgMaxRetry',10)">10</button>
                                    </div>
                                    <div class="form-text small mt-1">{{t:jc.maxRetryHint.html}}</div>
                                </div>
                                <div class="col-md-4">
                                    <label class="form-label small mb-1" for="cfgFindTime">{{t:jc.findTime}}</label>
                                    <input type="number" class="form-control form-control-sm" id="cfgFindTime" min="30" max="86400" value="600">
                                    <div class="mt-1 d-flex gap-1 flex-wrap">
                                        <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2" style="font-size:.7rem" onclick="setCfg('cfgFindTime',300)">5 min</button>
                                        <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2" style="font-size:.7rem" onclick="setCfg('cfgFindTime',1200)">20 min</button>
                                        <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2" style="font-size:.7rem" onclick="setCfg('cfgFindTime',1800)">30 min</button>
                                        <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2" style="font-size:.7rem" onclick="setCfg('cfgFindTime',3600)">1 h <span class="text-success">★</span></button>
                                        <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2" style="font-size:.7rem" onclick="setCfg('cfgFindTime',10800)">3 h</button>
                                        <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2" style="font-size:.7rem" onclick="setCfg('cfgFindTime',21600)">6 h</button>
                                        <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2" style="font-size:.7rem" onclick="setCfg('cfgFindTime',86400)">24 h</button>
                                    </div>
                                    <div class="form-text small mt-1">{{t:jc.findTimeHint.html}}</div>
                                </div>
                                <div class="col-md-4">
                                    <label class="form-label small mb-1" for="cfgBanTime">{{t:jc.banTime}}</label>
                                    <input type="number" class="form-control form-control-sm" id="cfgBanTime" min="60" max="31536000" value="3600">
                                    <div class="mt-1 d-flex gap-1 flex-wrap">
                                        <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2" style="font-size:.7rem" onclick="setCfg('cfgBanTime',600)">10 min</button>
                                        <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2" style="font-size:.7rem" onclick="setCfg('cfgBanTime',3600)">1 h</button>
                                        <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2" style="font-size:.7rem" onclick="setCfg('cfgBanTime',21600)">6 h</button>
                                        <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2" style="font-size:.7rem" onclick="setCfg('cfgBanTime',86400)">24 h <span class="text-success">★</span></button>
                                        <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2" style="font-size:.7rem" onclick="setCfg('cfgBanTime',604800)">{{t:jc.week}}</button>
                                        <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2" style="font-size:.7rem" onclick="setCfg('cfgBanTime',2592000)">{{t:jc.days30}}</button>
                                        <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2" style="font-size:.7rem" onclick="setCfg('cfgBanTime',-1)">{{t:jc.permanent}}</button>
                                    </div>
                                    <div class="form-text small mt-1">{{t:jc.banTimeHint.html}}</div>
                                </div>
                            </div>
                            <div class="alert alert-success py-2 px-2 mt-2 mb-0 small">
                                <i class="fas fa-shield-alt me-1" aria-hidden="true"></i>
                                {{t:jc.presetTitle.html}}
                                <button type="button" class="btn btn-success btn-sm py-0 px-2 ms-2" style="font-size:.75rem" onclick="setCfg('cfgMaxRetry',2);setCfg('cfgFindTime',3600);setCfg('cfgBanTime',86400)">
                                    <i class="fas fa-magic me-1" aria-hidden="true"></i>{{t:jc.aggressive}}
                                </button>
                                <button type="button" class="btn btn-outline-success btn-sm py-0 px-2 ms-1" style="font-size:.75rem" onclick="setCfg('cfgMaxRetry',3);setCfg('cfgFindTime',1800);setCfg('cfgBanTime',21600)">
                                    {{t:jc.balanced}}
                                </button>
                                <button type="button" class="btn btn-outline-success btn-sm py-0 px-2 ms-1" style="font-size:.75rem" onclick="setCfg('cfgMaxRetry',5);setCfg('cfgFindTime',600);setCfg('cfgBanTime',3600)">
                                    {{t:jc.permissive}}
                                </button>
                                <div class="text-muted mt-1" style="font-size:.75rem">{{t:jc.presetHint}}</div>
                            </div>
                            <div class="d-flex gap-2 mt-3 flex-wrap">
                                <button class="btn btn-primary btn-sm" onclick="saveJailConfig()">
                                    <i class="fas fa-save me-1" aria-hidden="true"></i>{{t:jc.saveOne}}
                                </button>
                                <button class="btn btn-warning btn-sm" onclick="saveJailConfigAllJails()">
                                    <i class="fas fa-clone me-1" aria-hidden="true"></i>{{t:jc.applyAll}}
                                </button>
                                <button class="btn btn-outline-secondary btn-sm" onclick="loadJailConfig()">
                                    <i class="fas fa-sync me-1" aria-hidden="true"></i>{{t:jc.reloadFile}}
                                </button>
                                <span id="cfgJailStatus" class="ms-2 small"></span>
                            </div>
                            <div class="alert alert-warning py-2 px-2 mt-3 mb-0 small">
                                <i class="fas fa-exclamation-triangle me-1" aria-hidden="true"></i>
{{t:jc.eachJail.html}}
                            </div>
                            <div class="alert alert-info py-1 px-2 mt-2 mb-0 small">
                                <i class="fas fa-info-circle me-1" aria-hidden="true"></i>
{{t:jc.whereWritten.html}}
                            </div>

                            <!-- ============ FILTRO ============ -->
                            <hr class="my-3">
                            <h6 class="mb-2"><i class="fas fa-filter me-2" aria-hidden="true"></i>{{t:jc.filterTitle}}</h6>
                            <p class="small text-muted mb-2">
{{t:jc.filterIntro.html}}
                            </p>

                            <div class="small mb-2">
                                <span class="text-muted">{{t:jc.filterNow}}</span>
                                <code id="cfgFilterCurrent" class="ms-1">—</code>
                            </div>

                            <div id="cfgFilterOptions" class="d-grid gap-2 mb-2">
                                <!-- Le opzioni vengono renderizzate da JS in base alla jail selezionata -->
                            </div>

                            <div id="cfgFilterCustom" class="d-none mb-2 mt-2">
                                <label class="form-label small mb-1" for="cfgFilter">{{t:jc.filterName}}</label>
                                <input type="text" class="form-control form-control-sm" id="cfgFilter" placeholder="{{t:jc.filterPh}}">
                                <div class="form-text small">{{t:jc.filterFormat.html}}</div>
                            </div>

                            <div class="d-flex gap-2">
                                <button class="btn btn-primary btn-sm" onclick="saveJailFilter()">
                                    <i class="fas fa-save me-1" aria-hidden="true"></i>{{t:jc.saveFilter}}
                                </button>
                            </div>

                            <!-- ============ IGNOREIP (WHITELIST) ============ -->
                            <hr class="my-3">
                            <h6 class="mb-2"><i class="fas fa-shield-alt me-2" aria-hidden="true"></i>{{t:jc.ignoreTitle}}</h6>
                            <p class="small text-muted mb-2">
{{t:jc.ignoreIntro.html}}
                            </p>
                            <div id="cfgIgnoreIpList" class="mb-2"><span class="text-muted small">{{t:common.loading}}</span></div>
                            <div class="row g-2 align-items-end">
                                <div class="col-md-9">
                                    <input type="text" class="form-control form-control-sm" id="cfgIgnoreIpInput" aria-label="{{t:jc.ignoreTitle}}" placeholder="{{t:jc.ignorePh}}">
                                </div>
                                <div class="col-md-3">
                                    <button class="btn btn-success btn-sm w-100" onclick="addIgnoreIp()">
                                        <i class="fas fa-plus me-1" aria-hidden="true"></i>{{t:jc.addIgnore}}
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
""";
    }

    private static String getVaultManagementCard() {
        return """
                    <!-- Master key vault management -->
                    <div class="card mb-4 border-warning">
                        <div class="card-header bg-warning text-dark"><i class="fas fa-shield-alt me-2" aria-hidden="true"></i>{{t:set.vaultTitle}}</div>
                        <div class="card-body">
                            <div class="alert alert-info py-2 mb-3 small">
                                <i class="fas fa-info-circle me-1" aria-hidden="true"></i>
                                {{t:set.vaultInfo.html}}
                            </div>
                            <p class="small text-muted">{{t:set.vaultReauth}}</p>

                            <h6 class="mt-3"><i class="fas fa-download me-1" aria-hidden="true"></i>{{t:set.vaultBackup}}</h6>
                            <p class="small text-muted mb-2">{{t:set.vaultBackupIntro}}</p>
                            <button class="btn btn-outline-primary btn-sm mb-2" onclick="vaultBackupKey()">
                                <i class="fas fa-download me-1" aria-hidden="true"></i>{{t:set.vaultExport}}
                            </button>
                            <div id="vaultBackupResult" class="mt-2"></div>

                            <hr class="my-4">

                            <h6 class="mt-3 text-warning"><i class="fas fa-sync-alt me-1" aria-hidden="true"></i>{{t:set.vaultRotation}}</h6>
                            <div class="alert alert-warning py-2 small mb-2">
                                <i class="fas fa-exclamation-triangle me-1" aria-hidden="true"></i>
                                {{t:set.vaultRotationInfo.html}}
                            </div>
                            <button class="btn btn-warning btn-sm mb-2" onclick="vaultRotateKey()">
                                <i class="fas fa-sync-alt me-1" aria-hidden="true"></i>{{t:set.vaultRotate}}
                            </button>
                            <div id="vaultRotateResult" class="mt-2"></div>
                        </div>
                    </div>

""";
    }

    /**
     * Gli script dell'accesso nelle Impostazioni: email di accesso, passkey, sessioni, nome utente,
     * conferma d'identita' e chiave del vault. Tutto passa da /api/account (e /api/admins per il
     * vault); il token CSRF lo aggiunge a ogni fetch lo script della <head>.
     */
    private static String getSettingsAuthJs() {
        return """
        // ===== Account =====
        const acc = { passkeysAvailable: true, hasEmail: false, hasPasskeys: false };
        const ACC_EMAIL = /^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\\.[A-Za-z]{2,}$/;
        const ACC_PASSKEY_NAME = /^[A-Za-z0-9 ._()-]{1,40}$/;
        let pendingPasskey = null;

        // Le date arrivano in UTC (ISO con la Z): si mostrano nel fuso del browser.
        function accDate(iso) {
            if (!iso) return '-';
            const d = new Date(iso);
            return isNaN(d) ? iso : d.toLocaleString(window.I18N_LANG || undefined);
        }
        async function accPost(action, body) {
            const r = await fetch('/api/account', { method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(Object.assign({ action: action }, body || {})) });
            try { return await r.json(); } catch (e) { return {}; }
        }
        function accMsg(id, kind, text) {
            const box = document.getElementById(id);
            box.className = 'small mt-2' + (kind ? ' text-' + kind : '');
            box.textContent = text || '';
        }
        function accButton(cls, icon, label, onClick) {
            const b = document.createElement('button');
            b.type = 'button';
            b.className = 'btn btn-sm ' + cls;
            b.title = label;
            b.setAttribute('aria-label', label);
            const i = document.createElement('i');
            i.className = 'fas ' + icon;
            i.setAttribute('aria-hidden', 'true');
            b.append(i);
            b.addEventListener('click', onClick);
            return b;
        }
        function accRow(title, meta, actions, badge) {
            const row = document.createElement('div');
            row.className = 'd-flex justify-content-between align-items-center gap-2 p-2 bg-light rounded mb-2';
            const info = document.createElement('div');
            info.className = 'testo-lungo';
            const strong = document.createElement('strong');
            strong.textContent = title;
            info.append(strong);
            if (badge) {
                const b = document.createElement('span');
                b.className = 'badge bg-info ms-2';
                b.textContent = badge;
                info.append(b);
            }
            const small = document.createElement('small');
            small.className = 'd-block text-muted';
            small.textContent = meta;
            info.append(small);
            const box = document.createElement('div');
            box.className = 'd-flex gap-1 flex-shrink-0';
            actions.forEach(a => box.append(a));
            row.append(info, box);
            return row;
        }
        function accEmpty(box, text) {
            const p = document.createElement('p');
            p.className = 'text-muted text-center py-2 mb-0';
            p.textContent = text;
            box.replaceChildren(p);
        }

        async function loadAccount() {
            let d = {};
            try { d = await (await fetch('/api/account')).json(); } catch (e) { d = {}; }
            if (!d.success) { accEmpty(document.getElementById('passkeysList'), t('set.loadFailed')); return; }
            acc.passkeysAvailable = !!d.passkeysAvailable;
            acc.hasEmail = !!d.email;
            acc.hasPasskeys = d.passkeys.length > 0;
            document.getElementById('accEmailCurrent').textContent = d.email || t('acc.noEmail');
            renderPasskeys(d.passkeys);
            renderSessions(d.sessions);
            document.getElementById('addPasskeyBtn').disabled = !acc.passkeysAvailable;
            document.getElementById('passkeyDomainNote').classList.toggle('d-none', acc.passkeysAvailable);
            const notice = document.getElementById('passkeySetupNotice');
            notice.classList.toggle('d-none', acc.hasPasskeys || new URLSearchParams(location.search).get('setup') !== 'passkey');
        }

        function renderPasskeys(list) {
            const box = document.getElementById('passkeysList');
            if (!list.length) { accEmpty(box, t('set.noPasskeys')); return; }
            box.replaceChildren(...list.map(pk => accRow(pk.name,
                t('set.passkeyMeta', { created: accDate(pk.created_at), used: pk.last_used ? accDate(pk.last_used) : t('adm.never') }),
                [accButton('btn-outline-secondary', 'fa-edit', t('set.renameOne', { name: pk.name }), () => renamePasskey(pk.id, pk.name)),
                 accButton('btn-outline-danger', 'fa-trash', t('adm.deleteOne', { name: pk.name }), () => deletePasskey(pk.id, pk.name))])));
        }

        // Il browser e il sistema, non tutta la stringa User-Agent
        function accBrowser(ua) {
            if (!ua) return t('acc.unknownBrowser');
            const b = /Edg\\//.test(ua) ? 'Edge' : /Firefox\\//.test(ua) ? 'Firefox' : /Chrome\\//.test(ua) ? 'Chrome' : /Safari\\//.test(ua) ? 'Safari' : '';
            const o = /iPhone|iPad/.test(ua) ? 'iOS' : /Android/.test(ua) ? 'Android' : /Mac OS X/.test(ua) ? 'macOS'
                : /Windows/.test(ua) ? 'Windows' : /FreeBSD/.test(ua) ? 'FreeBSD' : /Linux/.test(ua) ? 'Linux' : '';
            return b || o ? [b, o].filter(Boolean).join(' · ') : ua.slice(0, 60);
        }
        function renderSessions(list) {
            const box = document.getElementById('sessionsList');
            if (!list.length) { accEmpty(box, t('acc.noSessions')); }
            else box.replaceChildren(...list.map(s => accRow(accBrowser(s.user_agent),
                t('acc.sessionMeta', { ip: s.ip || '-', seen: accDate(s.last_seen), created: accDate(s.created_at) }),
                [accButton('btn-outline-danger', 'fa-right-from-bracket', s.current ? t('acc.revokeCurrent') : t('acc.revokeOne'), () => revokeSession(s.id, s.current))],
                s.current ? t('acc.thisSession') : '')));
            document.getElementById('btnRevokeOthers').disabled = !list.some(s => !s.current);
        }
        async function revokeSession(id, current) {
            if (!confirm(current ? t('acc.confirmRevokeCurrent') : t('acc.confirmRevoke'))) return;
            const r = await accPost('revoke_session', { id: id });
            if (!r.success) { alert(r.error || t('common.failed')); return; }
            if (r.current) window.location.href = '/'; else loadAccount();
        }
        async function revokeOthers() {
            if (!confirm(t('acc.confirmRevokeOthers'))) return;
            const r = await accPost('revoke_other_sessions');
            if (!r.success) { alert(r.error || t('common.failed')); return; }
            loadAccount();
        }

        // ----- email di accesso: cambia solo quando torna il codice mandato al nuovo indirizzo -----
        async function accEmailRequest() {
            const email = document.getElementById('accEmailNew').value.trim();
            if (!ACC_EMAIL.test(email) || email.length > 254) { accMsg('accEmailMsg', 'danger', t('login.emailInvalid')); return; }
            const r = await accPost('email_request', { email: email });
            if (!r.success) { accMsg('accEmailMsg', 'danger', r.error || t('common.failed')); return; }
            document.getElementById('accEmailCodeBox').classList.remove('d-none');
            accMsg('accEmailMsg', 'success', r.message);
            document.getElementById('accEmailCode').focus();
        }
        async function accEmailConfirm() {
            const code = document.getElementById('accEmailCode').value.trim();
            if (!/^[0-9]{6}$/.test(code)) { accMsg('accEmailMsg', 'danger', t('login.enterOtp')); return; }
            const r = await accPost('email_confirm', { code: code });
            if (!r.success) { accMsg('accEmailMsg', 'danger', r.error || t('common.failed')); return; }
            document.getElementById('accEmailCodeBox').classList.add('d-none');
            document.getElementById('accEmailNew').value = '';
            document.getElementById('accEmailCode').value = '';
            accMsg('accEmailMsg', 'success', t('acc.emailChanged'));
            loadAccount();
        }

        // ----- passkey -----
        async function addPasskey() {
            if (!window.PublicKeyCredential || !navigator.credentials) { alert(t('login.passkeyUnsupported')); return; }
            const btn = document.getElementById('addPasskeyBtn');
            btn.disabled = true;
            try {
                const o = await accPost('passkey_register_options');
                if (!o.success) { alert(o.error || t('common.failed')); return; }
                let cred;
                try { cred = await navigator.credentials.create(webauthnCreateOptions(o.options)); }
                catch (err) { alert(err && err.name === 'NotAllowedError' ? t('set.regCancelled') : t('common.error', { message: err.message })); return; }
                pendingPasskey = { request: o.request, credential: webauthnCredentialJson(cred) };
                document.getElementById('passkeyName').value = '';
                bootstrap.Modal.getOrCreateInstance(document.getElementById('passkeyNameModal')).show();
            } catch (e) {
                alert(t('common.networkError', { message: e.message }));
            } finally {
                btn.disabled = !acc.passkeysAvailable;
            }
        }
        async function confirmPasskeyName() {
            if (!pendingPasskey) return;
            const name = document.getElementById('passkeyName').value.trim() || 'Passkey';
            if (!ACC_PASSKEY_NAME.test(name)) { alert(t('acc.passkeyNameHint')); return; }
            const r = await accPost('passkey_register', Object.assign({ name: name }, pendingPasskey));
            pendingPasskey = null;
            bootstrap.Modal.getOrCreateInstance(document.getElementById('passkeyNameModal')).hide();
            if (r.success) {
                alert(t('set.passkeyAdded'));
                history.replaceState(null, '', location.pathname);
            } else {
                alert(r.error || t('common.failed'));
            }
            loadAccount();
        }
        function renamePasskey(id, currentName) {
            document.getElementById('renamePasskeyId').value = id;
            document.getElementById('renamePasskeyName').value = currentName;
            bootstrap.Modal.getOrCreateInstance(document.getElementById('renamePasskeyModal')).show();
        }
        async function confirmRenamePasskey() {
            const id = Number(document.getElementById('renamePasskeyId').value);
            const name = document.getElementById('renamePasskeyName').value.trim();
            if (!ACC_PASSKEY_NAME.test(name)) { alert(t('acc.passkeyNameHint')); return; }
            const r = await accPost('passkey_rename', { id: id, name: name });
            if (!r.success) { alert(r.error || t('common.failed')); return; }
            bootstrap.Modal.getOrCreateInstance(document.getElementById('renamePasskeyModal')).hide();
            loadAccount();
        }
        async function deletePasskey(id, name) {
            if (!confirm(t('set.confirmDeletePasskey', { name: name }))) return;
            const r = await accPost('passkey_delete', { id: id });
            if (!r.success) { alert(r.error || t('common.failed')); return; }
            loadAccount();
        }

        // ----- nome utente (con il nome non si entra: serve a riconoscersi nell'elenco) -----
        async function changeUsername() {
            const newUsername = document.getElementById('newUsername').value.trim();
            if (!/^[A-Za-z0-9_-]{3,50}$/.test(newUsername)) { alert(t('set.usernameInvalid')); return; }
            if (!confirm(t('set.confirmUsername', { name: newUsername }))) return;
            const r = await accPost('change_username', { username: newUsername });
            if (!r.success) { alert(r.error || t('common.failed')); return; }
            alert(t('set.usernameChanged'));
            document.getElementById('newUsername').value = '';
        }

        // ----- conferma d'identita' per le operazioni delicate: passkey o codice via email -----
        let stepUpResolve = null;
        // Passkey ed email dell'account, per sapere quali conferme offrire: la finestra si apre
        // anche da pagine che non mostrano l'account (Impostazioni, per il vault).
        async function accState() {
            try {
                const d = await (await fetch('/api/account')).json();
                if (d.success) {
                    acc.passkeysAvailable = !!d.passkeysAvailable;
                    acc.hasEmail = !!d.email;
                    acc.hasPasskeys = (d.passkeys || []).length > 0;
                }
            } catch (e) { /* restano i valori di prima: al peggio i pulsanti sono spenti */ }
        }
        async function confirmIdentity() {
            await accState();
            return new Promise(resolve => {
                stepUpResolve = resolve;
                document.getElementById('stepUpCodeBox').classList.add('d-none');
                document.getElementById('stepUpCode').value = '';
                accMsg('stepUpMsg', '', '');
                document.getElementById('stepUpPasskeyBtn').disabled = !acc.passkeysAvailable || !acc.hasPasskeys;
                document.getElementById('stepUpEmailBtn').disabled = !acc.hasEmail;
                const modal = document.getElementById('stepUpModal');
                modal.addEventListener('hidden.bs.modal', () => { if (stepUpResolve) { stepUpResolve(false); stepUpResolve = null; } }, { once: true });
                bootstrap.Modal.getOrCreateInstance(modal).show();
            });
        }
        function stepUpDone() {
            const resolve = stepUpResolve;
            stepUpResolve = null;
            bootstrap.Modal.getOrCreateInstance(document.getElementById('stepUpModal')).hide();
            if (resolve) resolve(true);
        }
        async function stepUpPasskey() {
            const o = await accPost('stepup_options');
            if (!o.success) { accMsg('stepUpMsg', 'danger', o.error || t('common.failed')); return; }
            let cred;
            try { cred = await navigator.credentials.get(webauthnGetOptions(o.options)); }
            catch (err) { accMsg('stepUpMsg', 'danger', err && err.name === 'NotAllowedError' ? t('login.cancelled') : t('login.passkeyError', { message: err.message })); return; }
            const r = await accPost('stepup_verify', { request: o.request, credential: webauthnCredentialJson(cred) });
            if (r.success) stepUpDone(); else accMsg('stepUpMsg', 'danger', r.error || t('login.passkeyFailed'));
        }
        async function stepUpEmail() {
            const r = await accPost('stepup_code_request');
            if (!r.success) { accMsg('stepUpMsg', 'danger', r.error || t('common.failed')); return; }
            document.getElementById('stepUpCodeBox').classList.remove('d-none');
            accMsg('stepUpMsg', 'success', r.message);
            document.getElementById('stepUpCode').focus();
        }
        async function stepUpVerify() {
            const code = document.getElementById('stepUpCode').value.trim();
            if (!/^[0-9]{6}$/.test(code)) { accMsg('stepUpMsg', 'danger', t('login.enterOtp')); return; }
            const r = await accPost('stepup_code_verify', { code: code });
            if (r.success) stepUpDone(); else accMsg('stepUpMsg', 'danger', r.error || t('common.failed'));
        }
        // Una richiesta a /api/admins: se il server chiede la conferma, la si chiede e si riprova una volta.
        async function withIdentity(body) {
            const call = async () => (await fetch('/api/admins', { method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body) })).json();
            let d = await call();
            if (d && d.needs_reauth) {
                if (!(await confirmIdentity())) return null;
                d = await call();
            }
            return d;
        }

        // ===== Vault management =====
        function vaultAlert(kind, icon, text) {
            return '<div class="alert alert-' + kind + ' py-2 small mb-0"><i class="fas ' + icon + ' me-1" aria-hidden="true"></i>' + escHtml(text) + '</div>';
        }
        async function vaultBackupKey() {
            const out = document.getElementById('vaultBackupResult');
            out.innerHTML = '<div class="text-muted small"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('set.exporting')) + '</div>';
            let data;
            try { data = await withIdentity({ action: 'vault_backup_key' }); }
            catch (e) { out.innerHTML = vaultAlert('danger', 'fa-times-circle', t('common.networkError', { message: e.message })); return; }
            if (data === null) { out.innerHTML = ''; return; }
            if (!data.success) { out.innerHTML = vaultAlert('danger', 'fa-times-circle', data.error || t('common.unknownError')); return; }
            let html = '<div class="alert alert-success py-2 mb-2 small">';
            html += '<i class="fas fa-check-circle me-1" aria-hidden="true"></i><strong>' + escHtml(t('set.exported')) + '</strong> ' + escHtml(t('set.exportedHint'));
            html += '</div>';
            html += '<div class="input-group input-group-sm mb-2">';
            html += '<span class="input-group-text" id="vaultKeyLabel">' + escHtml(t('set.keyBase64')) + '</span>';
            html += '<input type="text" class="form-control font-monospace" id="vaultBackupKeyValue" value="" readonly aria-labelledby="vaultKeyLabel">';
            html += '<button class="btn btn-outline-secondary" type="button" onclick="vaultCopyBackupKey()"><i class="fas fa-copy me-1" aria-hidden="true"></i>' + escHtml(t('common.copy')) + '</button>';
            html += '<button class="btn btn-outline-primary" type="button" onclick="vaultDownloadBackupKey()"><i class="fas fa-download me-1" aria-hidden="true"></i>' + escHtml(t('set.downloadTxt')) + '</button>';
            html += '</div>';
            html += '<div class="small text-muted">' + escHtml(t('set.fileOnServer')) + ' <code>' + escHtml(data.key_file_path || '') + '</code></div>';
            out.innerHTML = html;
            // Il valore entra come proprieta', non dentro l'HTML
            document.getElementById('vaultBackupKeyValue').value = data.key_base64 || '';
        }
        function vaultCopyBackupKey() {
            const v = document.getElementById('vaultBackupKeyValue').value;
            if (!v) return;
            navigator.clipboard.writeText(v).then(() => alert(t('set.keyCopied'))).catch(() => {});
        }
        function vaultDownloadBackupKey() {
            const field = document.getElementById('vaultBackupKeyValue');
            const v = field ? field.value : '';
            if (!v) return;
            const url = URL.createObjectURL(new Blob([v + '\\n'], { type: 'text/plain' }));
            const a = document.createElement('a');
            a.href = url;
            a.download = 'mail-panel-master-key-' + new Date().toISOString().replace(/[:.]/g, '-') + '.txt';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }
        async function vaultRotateKey() {
            if (!confirm(t('set.confirmRotate'))) return;
            const out = document.getElementById('vaultRotateResult');
            out.innerHTML = '<div class="text-muted small"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('set.rotating')) + '</div>';
            let data;
            try { data = await withIdentity({ action: 'vault_rotate_key' }); }
            catch (e) { out.innerHTML = vaultAlert('danger', 'fa-times-circle', t('common.networkError', { message: e.message })); return; }
            if (data === null) { out.innerHTML = ''; return; }
            if (!data.success) { out.innerHTML = vaultAlert('danger', 'fa-times-circle', data.error || t('common.unknownError')); return; }
            const s = data.summary || {};
            let html = '<div class="alert ' + ((s.failed || 0) > 0 ? 'alert-warning' : 'alert-success') + ' py-2 mb-0 small">';
            html += '<i class="fas fa-check-circle me-1" aria-hidden="true"></i><strong>' + escHtml(t('set.rotated')) + '</strong><br>';
            html += escHtml(t('set.reencrypted', { n: s.reencrypted || 0, total: s.total || 0 }));
            if ((s.failed || 0) > 0) html += ' ' + escHtml(tn('set.rotateFailed', s.failed));
            html += '<br><small class="text-muted">' + escHtml(data.message || '') + '</small>';
            html += '</div>';
            out.innerHTML = html;
        }

""";
    }

    public static String getDnsHtml() {
        String extraStyles = """
        .dns-record { background: #f8f9fa; border-radius: 8px; padding: 15px; margin-bottom: 15px; border-left: 4px solid #e94560; }
        .dns-record.required { border-left-color: #dc3545; }
        .dns-record.optional { border-left-color: #6c757d; }
        .record-type { font-weight: bold; font-size: 0.9rem; color: #e94560; }
        .record-name { font-family: monospace; background: #e9ecef; padding: 2px 6px; border-radius: 3px; }
        .record-value { font-family: monospace; font-size: 0.85rem; word-break: break-all; background: #fff; padding: 8px; border: 1px solid #dee2e6; border-radius: 4px; margin-top: 8px; }
        .copy-btn { cursor: pointer; }
        .copy-btn:hover { color: #e94560; }
        .score-badge { font-size: 1.5rem; }
        .check-passed { color: #198754; }
        .check-failed { color: #dc3545; }
        /* Dark mode overrides */
        [data-theme="dark"] .dns-record { background: var(--table-stripe); color: var(--text-primary); }
        [data-theme="dark"] .record-name { background: var(--bg-input); color: var(--text-primary); }
        [data-theme="dark"] .record-value { background: var(--bg-input); border-color: var(--border-color); color: var(--text-primary); }
        [data-theme="dark"] .card-header.bg-dark { background-color: #1a1d21 !important; }
        [data-theme="dark"] .bg-white { background-color: var(--bg-input) !important; color: var(--text-primary) !important; }
        [data-theme="dark"] .border { border-color: var(--border-color) !important; }
        /* ===== Explanation panels (details > div.bg-white) ===== */
        [data-theme="dark"] details .bg-white,
        [data-theme="dark"] details > div { background-color: var(--bg-input) !important; color: var(--text-primary) !important; border-color: var(--border-color) !important; }
        [data-theme="dark"] details strong { color: var(--text-primary); }
        [data-theme="dark"] details .table,
        [data-theme="dark"] details .table > :not(caption) > * > * { background-color: transparent !important; color: var(--text-primary) !important; border-color: var(--border-color) !important; }
        [data-theme="dark"] details .table-sm td, [data-theme="dark"] details .table-sm th { color: var(--text-primary) !important; }
        [data-theme="dark"] details code { background-color: var(--table-stripe) !important; color: #f8f9fa !important; padding: 1px 4px; border-radius: 3px; }
        [data-theme="dark"] details summary { color: var(--text-primary); }
        /* Globale: tabelle dentro alert/info che non riceverebbero override */
        [data-theme="dark"] .alert .table, [data-theme="dark"] .alert .table > :not(caption) > * > * { background-color: transparent !important; color: var(--text-primary) !important; }
        """;
        return getHead("nav.dns", "dns", extraStyles) + """
    <div id="main" tabindex="-1" class="content container mt-4">
        <div class="content-container">
            <h2 class="mb-3"><i class="fas fa-server me-2" aria-hidden="true"></i>{{t:dns.title}}</h2>

            <!-- BANNER: dominio corrente sempre visibile, con switcher -->
            <div class="card text-white mb-3" style="background:linear-gradient(135deg,#e94560 0%,#a52a45 100%)">
                <div class="card-body py-3">
                    <div class="row align-items-center g-3">
                        <div class="col-md-7">
                            <div class="small text-uppercase opacity-75 mb-1" style="letter-spacing:1px">{{t:dns.managing}}</div>
                            <h3 class="mb-0">
                                <i class="fas fa-globe me-2" aria-hidden="true"></i>
                                <span id="currentDomainBanner" style="font-family:monospace">{{t:dns.noDomain}}</span>
                            </h3>
                        </div>
                        <div class="col-md-5">
                            <label class="small opacity-75 mb-1" for="domainSelect"><i class="fas fa-exchange-alt me-1" aria-hidden="true"></i>{{t:dns.changeDomain}}</label>
                            <select class="form-select" id="domainSelect">
                                <option value="">{{t:dns.chooseDomain}}</option>
                            </select>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Azioni globali (visibili sempre, ma operano solo se un dominio è selezionato) -->
            <div class="mb-3 d-flex gap-2 flex-wrap">
                <button class="btn btn-outline-primary" id="reloadDnsBtn" onclick="loadDnsRecords()" disabled>
                    <i class="fas fa-sync me-1" aria-hidden="true"></i>{{t:dns.reload}}
                </button>
                <button class="btn btn-success" id="verifyDnsBtn" onclick="verifyDns()" disabled>
                    <i class="fas fa-check me-1" aria-hidden="true"></i>{{t:dns.verify}}
                </button>
            </div>

            <div class="alert alert-info">
                <i class="fas fa-info-circle me-2" aria-hidden="true"></i>
                {{t:dns.howItWorks.html}}
            </div>

            <!-- Verification Results -->
            <div id="verificationResults" class="d-none mb-4">
                <div class="card">
                    <div class="card-header">
                        <i class="fas fa-clipboard-check me-2" aria-hidden="true"></i><strong>{{t:dns.results}}</strong>
                    </div>
                    <div class="card-body" id="verificationBody">
                    </div>
                </div>

""" + resource("pages/autodns-card.html") + resource("pages/autoconfig-card.html") + resource("pages/mtasts-card.html") + """
            </div>

            <!-- DNS Records -->
            <div id="dnsRecordsContainer">
                <p class="text-muted">{{t:dns.pickToSee}}</p>
            </div>

            <!-- Cloudflare integration Section -->
            <div class="card mt-4">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-cloud me-2" aria-hidden="true"></i>{{t:dns.cfAccounts}}</span>
                    <small id="cfAccountsCountBadge"></small>
                </div>
                <div class="card-body">
                    <p class="mb-2">{{t:dns.cfIntro}}</p>

                    <details class="mb-3">
                        <summary>{{t:dns.cfHowTo}}</summary>
                        <div class="mt-2 p-3 bg-white border rounded small">
                            <ol class="mb-2">
                                <li>{{t:dns.cfStep1a}} <a href="https://dash.cloudflare.com/profile/api-tokens" target="_blank" rel="noopener">My Profile → API Tokens</a>{{t:dns.cfStep1b.html}}</li>
                                <li>{{t:dns.cfStep2.html}}</li>
                                <li>{{t:dns.cfStep3.html}}</li>
                                <li>{{t:dns.cfStep4.html}}</li>
                                <li>{{t:dns.cfStep5}}</li>
                            </ol>
                            <div class="text-muted">{{t:dns.cfTokenNote}}</div>
                        </div>
                    </details>

                    <!-- LISTA ACCOUNT -->
                    <h6 class="mt-3 mb-2"><i class="fas fa-users me-1" aria-hidden="true"></i>{{t:dns.cfConfigured}}</h6>
                    <div id="cfAccountsList" class="mb-3">
                        <div class="text-muted small"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>{{t:common.loading}}</div>
                    </div>

                    <!-- AGGIUNGI ACCOUNT -->
                    <h6 class="mt-4 mb-2"><i class="fas fa-plus-circle me-1" aria-hidden="true"></i>{{t:dns.cfAdd}}</h6>
                    <div class="row g-2 mb-2">
                        <div class="col-md-4">
                            <label class="form-label small mb-1" for="cfNewLabel">{{t:dns.cfLabel}} <span class="text-danger" aria-hidden="true">*</span></label>
                            <input type="text" class="form-control" id="cfNewLabel" required placeholder="{{t:dns.cfLabelPh}}">
                        </div>
                        <div class="col-md-4">
                            <label class="form-label small mb-1" for="cfNewEmail">{{t:dns.cfEmail}} <small class="text-muted">{{t:dns.cfEmailHint}}</small></label>
                            <input type="email" class="form-control" id="cfNewEmail" placeholder="{{t:dns.cfEmailPh}}">
                        </div>
                        <div class="col-md-4">
                            <label class="form-label small mb-1" for="cfNewToken">{{t:dns.cfToken}} <span class="text-danger" aria-hidden="true">*</span></label>
                            <input type="password" class="form-control" id="cfNewToken" required placeholder="{{t:dns.cfTokenPh}}" autocomplete="off">
                        </div>
                    </div>
                    <div class="d-flex gap-2">
                        <button class="btn btn-outline-secondary btn-sm" type="button" onclick="cfTestNewToken()"><i class="fas fa-vial me-1" aria-hidden="true"></i>{{t:dns.cfTest}}</button>
                        <button class="btn btn-primary btn-sm" type="button" onclick="cfAddAccount()"><i class="fas fa-save me-1" aria-hidden="true"></i>{{t:dns.cfSave}}</button>
                    </div>

                    <!-- ASSEGNAZIONE PER-DOMINIO -->
                    <h6 class="mt-4 mb-2"><i class="fas fa-link me-1" aria-hidden="true"></i>{{t:dns.cfAssign}}</h6>
                    <div id="cfDomainAssignments" class="mb-2">
                        <div class="text-muted small"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>{{t:common.loading}}</div>
                    </div>
                </div>
            </div>

""" + resource("pages/dkim-summary-card.html") + """
            <!-- DKIM Section -->
            <div class="card mt-4">
                <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-key me-2" aria-hidden="true"></i>{{t:dns.dkimTitle}}</span>
                    <small id="dkimRotationBadge"></small>
                </div>
                <div class="card-body">
                    <p>{{t:dns.dkimIntro}}</p>
                    <div id="dkimStatus">{{t:dns.dkimPick}}</div>

                    <!-- Info account CF per dominio selezionato -->
                    <div id="dkimDomainCfInfo" class="mt-2"></div>

                    <!-- Last/Next rotation: sempre visibile quando DKIM è configurato -->
                    <div id="dkimRotationTimeline" class="mt-2 d-none">
                        <div class="row g-2">
                            <div class="col-md-6">
                                <div class="border rounded p-2 h-100" style="background:rgba(25,135,84,0.08)">
                                    <div class="small text-muted mb-1"><i class="fas fa-history me-1" aria-hidden="true"></i>{{t:dns.lastRotation}}</div>
                                    <div id="dkimLastRotationText"><span class="text-muted">—</span></div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="border rounded p-2 h-100" style="background:rgba(13,110,253,0.08)">
                                    <div class="small text-muted mb-1"><i class="fas fa-calendar-day me-1" aria-hidden="true"></i>{{t:dns.nextRotation}}</div>
                                    <div id="dkimNextRotationText"><span class="text-muted">—</span></div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Rotazione programmata -->
                    <div id="dkimSchedulePanel" class="mt-3 d-none">
                        <div class="border rounded p-3" style="background:rgba(13,110,253,0.05)">
                            <h6 class="mb-2"><i class="fas fa-calendar-alt me-1" aria-hidden="true"></i>{{t:dns.scheduled}}</h6>
                            <div class="row g-2 align-items-end">
                                <div class="col-md-5">
                                    <label class="form-label small mb-1" for="dkimSchedulePreset">{{t:dns.frequency}}</label>
                                    <select class="form-select form-select-sm" id="dkimSchedulePreset" onchange="onSchedulePresetChange()">
                                        <!-- popolato dinamicamente dai preset del server -->
                                    </select>
                                </div>
                                <div class="col-md-3" id="dkimScheduleCustomWrap" style="display:none">
                                    <label class="form-label small mb-1" for="dkimScheduleCustomDays">{{t:dns.customDays}}</label>
                                    <input type="number" min="1" max="3650" class="form-control form-control-sm" id="dkimScheduleCustomDays" placeholder="{{t:dns.customDaysPh}}">
                                </div>
                                <div class="col-md-4 text-md-end">
                                    <button class="btn btn-sm btn-primary" onclick="saveDkimSchedule()"><i class="fas fa-save me-1" aria-hidden="true"></i>{{t:dns.saveSchedule}}</button>
                                </div>
                            </div>
                            <div class="mt-2 small" id="dkimScheduleInfo"></div>
                        </div>
                    </div>

                    <div class="mt-3 d-flex gap-2 flex-wrap">
                        <button class="btn btn-warning" id="generateDkimBtn" onclick="generateDkim()" disabled>
                            <i class="fas fa-key me-1" aria-hidden="true"></i>{{t:dns.generateDkim}}
                        </button>
                        <button class="btn btn-outline-primary" id="rotateDkimBtn" onclick="rotateDkimStart()" disabled>
                            <i class="fas fa-sync-alt me-1" aria-hidden="true"></i>{{t:dns.startRotation}}
                        </button>
                        <button class="btn btn-outline-success" id="verifyActiveDkimBtn" onclick="verifyActiveDkim()" disabled>
                            <i class="fas fa-search me-1" aria-hidden="true"></i>{{t:dns.verifyActive}}
                        </button>
                    </div>

                    <!-- Risultato verifica chiave attiva -->
                    <div id="dkimVerifyResult" class="mt-3"></div>

                    <!-- Pannello rotazione: visibile solo se in corso -->
                    <div id="dkimRotationPanel" class="mt-4 d-none">
                        <hr>
                        <h5><i class="fas fa-route me-2" aria-hidden="true"></i>{{t:dns.rotationRunning}}</h5>
                        <div id="dkimRotationStepper" class="my-3"></div>
                        <div id="dkimRotationBody"></div>
                    </div>

                    <!-- Vecchi record DKIM (orphan cleanup)

                         Si rilegge a ogni apertura. Un pannello a scomparsa carica una volta
                         sola e poi mostra la fotografia di quel momento: riaperto piu' tardi
                         racconta un passato che sembra il presente. E' successo due volte in
                         due giorni — la cassetta dei rapporti dichiarata mancante venti secondi
                         dopo che il pannello l'aveva creata, e lo storico DKIM senza la
                         rotazione appena avviata. Chi apre un elenco si aspetta di vedere
                         adesso, non l'ultima volta che ci ha guardato. -->
                    <details class="mt-4"
                             ontoggle="if (this.open &amp;&amp; typeof scanDkimOrphans === 'function' &amp;&amp; currentDomainId) scanDkimOrphans();">
                        <summary class="text-primary" style="cursor:pointer"><i class="fas fa-broom me-1" aria-hidden="true"></i>{{t:dns.orphansSummary}}</summary>
                        <div class="mt-3">
                            <p class="small text-muted mb-2">{{t:dns.orphansIntro.html}}</p>
                            <button class="btn btn-sm btn-outline-primary" onclick="scanDkimOrphans()" id="scanDkimOrphansBtn"><i class="fas fa-search me-1" aria-hidden="true"></i>{{t:dns.scanOrphans}}</button>
                            <div id="dkimOrphansResult" class="mt-3"></div>
                        </div>
                    </details>

                    <!-- Storico rotazioni: riletto a ogni apertura, stessa ragione. -->
                    <details class="mt-4" id="dkimHistoryDetails"
                             ontoggle="if (this.open &amp;&amp; typeof loadDkimHistory === 'function' &amp;&amp; currentDomainId) loadDkimHistory(currentDomainId);">
                        <summary class="text-primary" style="cursor:pointer"><i class="fas fa-history me-1" aria-hidden="true"></i>{{t:dns.historySummary}}</summary>
                        <div id="dkimHistoryBody" class="mt-3">
                            <p class="text-muted small mb-0">{{t:dns.historyPick}}</p>
                        </div>
                    </details>
                </div>
            </div>

""" + getDnsRotateModeChooserModal() + """
            <!-- Blacklist Check -->
            <div class="card mt-4">
                <div class="card-header d-flex justify-content-between align-items-center flex-wrap gap-2">
                    <span><i class="fas fa-ban me-2" aria-hidden="true"></i><strong>{{t:dns.blTitle}}</strong> <small class="ms-2" id="blOverallStatus"></small></span>
                    <button class="btn btn-sm btn-outline-secondary" id="btnBlCheck" onclick="runBlacklistCheck()">
                        <i class="fas fa-search me-1" aria-hidden="true"></i>{{t:dns.blCheck}}
                    </button>
                </div>

                <div class="card-body" id="blContainer">
                    <p class="text-muted mb-0">
                        <i class="fas fa-info-circle me-1" aria-hidden="true"></i>
                        {{t:dns.blIntro}}
                    </p>
                    <p class="text-muted small mb-0">{{t:dns.blHint}}</p>
                </div>
            </div>
            <!-- Diagnostica orario server (timezone) -->
            <div class="card mt-4">
                <div class="card-header d-flex justify-content-between align-items-center" style="cursor:pointer" onclick="toggleTzDiag()">
                    <span><i class="fas fa-clock me-2" aria-hidden="true"></i>{{t:dns.tzTitle}}</span>
                    <span id="tzDiagStatusBadge"><span class="badge bg-secondary"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>{{t:dns.checking}}</span></span>
                </div>
                <div class="card-body d-none" id="tzDiagBody">
                    <p class="small text-muted mb-2">{{t:dns.tzIntro}}</p>
                    <div id="tzDiagTable">
                        <div class="text-muted small"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>{{t:common.loading}}</div>
                    </div>
                    <div class="mt-3 d-flex gap-2 flex-wrap">
                        <button class="btn btn-success btn-sm" onclick="tzSyncToSystem()"><i class="fas fa-magic me-1" aria-hidden="true"></i>{{t:dns.tzSync}}</button>
                        <div class="input-group input-group-sm" style="width:auto">
                            <input type="text" class="form-control form-control-sm" id="tzManualValue" placeholder="{{t:dns.tzManualPh}}" aria-label="{{t:dns.tzManual}}" style="width:200px">
                            <button class="btn btn-outline-secondary btn-sm" onclick="tzSetManual()"><i class="fas fa-cog me-1" aria-hidden="true"></i>{{t:dns.tzManual}}</button>
                        </div>
                        <button class="btn btn-outline-secondary btn-sm" onclick="loadTzDiag()"><i class="fas fa-sync me-1" aria-hidden="true"></i>{{t:dns.tzRecheck}}</button>
                    </div>
                    <div id="tzDiagLog" class="mt-2 small"></div>
                </div>
            </div>
        </div>
    </div>
""" + getFooterSection() + """
    <script>
        let currentDomainId = null;
        let cloudflareConfigured = false;

        // Load domains
        fetch('/api/domains').then(r => r.json()).then(data => {
            const select = document.getElementById('domainSelect');
            (data.domains || []).forEach(d => {
                const opt = document.createElement('option');
                opt.value = d.domain;
                opt.dataset.id = d.id;
                opt.textContent = d.domain;
                select.appendChild(opt);
            });
            // Pre-seleziona se presente ?domain=... nel querystring (es. link da /domains)
            try {
                const params = new URLSearchParams(window.location.search);
                const preselect = params.get('domain');
                if (preselect) {
                    // Trova l'option con quel value (case-insensitive)
                    const target = Array.from(select.options).find(o => o.value.toLowerCase() === preselect.toLowerCase());
                    if (target) {
                        select.value = target.value;
                        // Triggera l'evento change come se l'utente avesse cliccato
                        select.dispatchEvent(new Event('change', { bubbles: true }));
                    }
                }
            } catch (e) {
                console.warn('Domain preselection failed:', e);
            }
        });

        // Helper: aggiorna il banner del dominio corrente
        function setCurrentDomainBanner(name) {
            const el = document.getElementById('currentDomainBanner');
            if (!el) return;
            if (name) {
                el.textContent = name;
                el.style.opacity = '1';
            } else {
                el.textContent = t('dns.noDomain');
                el.style.opacity = '0.6';
            }
        }

        // Cambio dominio: carica TUTTO automaticamente (DNS records + DKIM + storico + schedule),
        // così non serve cliccare "Ricarica" per cambiare contesto.
        document.getElementById('domainSelect').addEventListener('change', function() {
            const opt = this.selectedOptions[0];
            const reloadBtn = document.getElementById('reloadDnsBtn');
            const verifyBtn = document.getElementById('verifyDnsBtn');

            if (!opt || !opt.dataset || !opt.dataset.id) {
                // Deselezionato: pulisci tutto
                currentDomainId = null;
                setCurrentDomainBanner(null);
                if (reloadBtn) reloadBtn.disabled = true;
                if (verifyBtn) verifyBtn.disabled = true;
                const tl = document.getElementById('dkimRotationTimeline'); if (tl) tl.classList.add('d-none');
                const st = document.getElementById('dkimStatus');           if (st) st.textContent = t('dns.dkimPick');
                const sp = document.getElementById('dkimSchedulePanel');    if (sp) sp.classList.add('d-none');
                const rp = document.getElementById('dkimRotationPanel');    if (rp) rp.classList.add('d-none');
                const ci = document.getElementById('dkimDomainCfInfo');     if (ci) ci.innerHTML = '';
                const hb = document.getElementById('dkimHistoryBody');      if (hb) hb.innerHTML = '<p class="text-muted small mb-0">' + escHtml(t('dns.historyPick')) + '</p>';
                const rc = document.getElementById('dnsRecordsContainer');  if (rc) rc.innerHTML = '<p class="text-muted">' + escHtml(t('dns.pickToSee')) + '</p>';
                const vr = document.getElementById('verificationResults');  if (vr) vr.classList.add('d-none');
                document.getElementById('generateDkimBtn').disabled = true;
                document.getElementById('rotateDkimBtn').disabled = true;
                document.getElementById('verifyActiveDkimBtn').disabled = true;
                return;
            }

            currentDomainId = opt.dataset.id;
            setCurrentDomainBanner(opt.value);
            if (reloadBtn) reloadBtn.disabled = false;
            if (verifyBtn) verifyBtn.disabled = false;
            document.getElementById('generateDkimBtn').disabled = false;

            // Carica AUTOMATICAMENTE tutto: record DNS + stato DKIM (status, timeline, history, schedule)
            loadDnsRecords();
        });

""" + getDnsJsTzDiag() + resource("pages/dns.js") + getDnsJsPart3() + getDnsJsPart2() + resource("pages/autodns.js") + resource("pages/autoconfig.js") + resource("pages/mtasts.js") + """
    </script>
</body>
</html>
""";
    }

    // ============== SSL.HTML - SSL Certificate Management ==============
    public static String getSslHtml() {
        String extraStyles = """
        .cert-info { background: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 15px; }
        .cert-valid { border-left: 4px solid #198754; }
        .cert-expiring { border-left: 4px solid #ffc107; }
        .cert-expired { border-left: 4px solid #dc3545; }
        .option-card { transition: all 0.3s; cursor: pointer; }
        .option-card:hover { transform: translateY(-5px); box-shadow: 0 5px 15px rgba(0,0,0,0.1); }
        .option-card.selected { border: 2px solid #0d6efd; }
        .step-number { width: 30px; height: 30px; background: #0d6efd; color: white; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; margin-right: 10px; }
        .dns-record { font-family: monospace; background: #f1f1f1; padding: 10px; border-radius: 5px; word-break: break-all; }
        .copy-btn { cursor: pointer; }
        .copy-btn:hover { color: #0d6efd; }
        .cert-self-signed { border-left: 4px solid #dc3545; }
        /* Dark mode overrides */
        [data-theme="dark"] .cert-info { background: var(--table-stripe); color: var(--text-primary); }
        [data-theme="dark"] .dns-record { background: var(--table-stripe); color: var(--text-primary); }
        [data-theme="dark"] .option-card { background: var(--bg-card); }
        [data-theme="dark"] .option-card:hover { box-shadow: 0 5px 15px rgba(0,0,0,0.3); }
        [data-theme="dark"] .form-control.bg-light, [data-theme="dark"] .bg-light { background-color: var(--table-stripe) !important; color: var(--text-primary) !important; }
        [data-theme="dark"] .card-body { color: var(--text-primary); }
        [data-theme="dark"] .text-muted { color: var(--text-muted) !important; }
        [data-theme="dark"] .card-header.bg-success { background-color: #198754 !important; }
        [data-theme="dark"] .card-header.bg-primary { background-color: #0d6efd !important; }
        [data-theme="dark"] .card-header.bg-warning { background-color: #ffc107 !important; color: #000 !important; }
        """;
        return getHead("nav.ssl", "ssl", extraStyles) + """
    <div id="main" tabindex="-1" class="content container mt-4">
        <div class="content-container">
            <h2><i class="fas fa-lock me-2" aria-hidden="true"></i>{{t:ssl.title}}</h2>
            <p class="text-muted">{{t:ssl.subtitle}} (<strong>{{MAIL_HOSTNAME}}</strong>)</p>

            <!-- Guida Let's Encrypt -->
            <div class="card mb-4">
                <div class="card-header bg-secondary text-white" style="cursor:pointer;" data-bs-toggle="collapse" data-bs-target="#leGuide" aria-expanded="false">
                    <i class="fas fa-book me-2" aria-hidden="true"></i><strong>{{t:ssl.guide}}</strong>
                    <small class="ms-2 text-white-50">{{t:ssl.clickToggle}}</small>
                    <i class="fas fa-chevron-down float-end mt-1" aria-hidden="true"></i>
                </div>
                <div id="leGuide" class="collapse">
                    <div class="card-body">
                        <h5><i class="fas fa-clock me-2" aria-hidden="true"></i>{{t:ssl.validity}}</h5>
                        <ul>
                            <li>{{t:ssl.g1.html}}</li>
                            <li>{{t:ssl.g2.html}}</li>
                            <li>{{t:ssl.g3.html}}</li>
                        </ul>

                        <h5 class="mt-3"><i class="fas fa-tachometer-alt me-2" aria-hidden="true"></i>{{t:ssl.rateLimits}}</h5>
                        <ul>
                            <li>{{t:ssl.rl1.html}}</li>
                            <li>{{t:ssl.rl2.html}}</li>
                            <li>{{t:ssl.rl3.html}}</li>
                            <li>{{t:ssl.rl4.html}}</li>
                        </ul>
                        <p class="text-muted small">{{t:ssl.rlBlocked}}</p>

                        <h5 class="mt-3"><i class="fas fa-sliders-h me-2" aria-hidden="true"></i>{{t:ssl.whichThreshold}}</h5>
                        <div class="table-responsive">
                            <table class="table table-sm table-bordered align-middle mb-2">
                                <thead class="table-light">
                                    <tr><th style="width:120px">{{t:ssl.days}}</th><th>{{t:ssl.whenToUse}}</th><th>{{t:dns.colNotes}}</th></tr>
                                </thead>
                                <tbody>
                                    <tr class="table-success"><td><strong>30</strong> ✅</td><td><strong>{{t:ssl.defaultRecommended}}</strong></td><td>{{t:ssl.recommendedBy}}</td></tr>
                                    <tr><td>14–29</td><td>{{t:ssl.aggressive}}</td><td>{{t:ssl.aggressiveNote}}</td></tr>
                                    <tr class="table-danger"><td>&lt; 14</td><td>{{t:ssl.risky}}</td><td>{{t:ssl.riskyNote}}</td></tr>
                                    <tr><td>31–60</td><td>{{t:ssl.conservative}}</td><td>{{t:ssl.conservativeNote}}</td></tr>
                                    <tr class="table-danger"><td>&gt; 60</td><td>{{t:ssl.notRecommended}}</td><td>{{t:ssl.notRecommendedNote}}</td></tr>
                                </tbody>
                            </table>
                        </div>
                        <p class="mb-0">{{t:ssl.range.html}}</p>

                        <h5 class="mt-3"><i class="fas fa-route me-2" aria-hidden="true"></i>HTTP-01 vs DNS-01</h5>
                        <ul>
                            <li>{{t:ssl.h1.html}}</li>
                            <li>{{t:ssl.h2.html}}</li>
                            <li>{{t:ssl.h3.html}}</li>
                        </ul>

                        <h5 class="mt-3"><i class="fas fa-redo me-2" aria-hidden="true"></i>{{t:ssl.autoRenewal}}</h5>
                        <ul>
                            <li>{{t:ssl.ar1}}</li>
                            <li>{{t:ssl.ar2.html}}</li>
                            <li>{{t:ssl.ar3}}</li>
                            <li>{{t:ssl.ar4}}</li>
                        </ul>

                        <h5 class="mt-3"><i class="fas fa-bug me-2" aria-hidden="true"></i>{{t:ssl.existsWhat}}</h5>
                        <p class="mb-1">{{t:ssl.existsWhy.html}}</p>
                        <p class="mb-0">{{t:ssl.twoOptions}}</p>
                        <ul>
                            <li><strong>{{t:ssl.deployExisting}}</strong> {{t:ssl.opt1}}</li>
                            <li>{{t:ssl.opt2.html}}</li>
                        </ul>

                        <h5 class="mt-3"><i class="fas fa-link me-2" aria-hidden="true"></i>{{t:ssl.references}}</h5>
                        <ul class="mb-0">
                            <li><a href="https://letsencrypt.org/docs/rate-limits/" target="_blank" rel="noopener">{{t:ssl.officialRl}}</a></li>
                            <li><a href="https://github.com/acmesh-official/acme.sh/wiki" target="_blank" rel="noopener">Wiki acme.sh</a></li>
                        </ul>
                    </div>
                </div>
            </div>

            <!-- SSL Hostname Mismatch Warning -->
            <div id="sslHostnameMismatch" class="alert alert-danger d-none">
                <h5><i class="fas fa-exclamation-triangle me-2" aria-hidden="true"></i>{{t:ssl.mismatchTitle}}</h5>
                <p class="mb-1">{{t:ssl.mismatchIssued}} <strong><code id="sslMismatchCn">-</code></strong>,
                    {{t:ssl.mismatchButHost}} <strong><code id="sslMismatchExpected">-</code></strong>.</p>
                <p class="mb-0"><i class="fas fa-arrow-down me-1" aria-hidden="true"></i>{{t:ssl.mismatchGen}} <strong id="sslMismatchTarget">-</strong> {{t:ssl.mismatchGenHow}}</p>
            </div>

            <!-- Self-Signed Warning -->
            <div id="selfSignedWarning" class="alert alert-danger d-none">
                <h5><i class="fas fa-exclamation-triangle me-2" aria-hidden="true"></i>{{t:ssl.selfSignedTitle}}</h5>
                <p class="mb-0">{{t:ssl.selfSigned.html}}</p>
                <p class="mb-0">{{t:ssl.selfSignedFix}}</p>
            </div>

            <!-- Current Certificate Status -->
            <div class="card mb-4">
                <div class="card-header"><i class="fas fa-certificate me-2" aria-hidden="true"></i>{{t:ssl.current}}</div>
                <div class="card-body" id="certInfo">
                    <div class="text-center py-3">
                        <div class="spinner-border text-primary" role="status"></div>
                        <p class="mt-2">{{t:ssl.loadingCert}}</p>
                    </div>
                </div>
            </div>

            <!-- Auto-Renewal Card -->
            <div class="card mb-4">
                <div class="card-header bg-info text-white d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-sync-alt me-2" aria-hidden="true"></i>{{t:ssl.autoRenewalCard}}</span>
                    <span id="autoRenewBadge" class="badge bg-secondary">-</span>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-6">
                            <div class="form-check form-switch mb-3">
                                <input class="form-check-input" type="checkbox" id="autoRenewEnabled" onchange="saveAutoRenewSettings()">
                                <label class="form-check-label" for="autoRenewEnabled">
                                    <strong>{{t:ssl.enableAuto}}</strong>
                                </label>
                                <div class="text-muted small">{{t:ssl.enableAutoHint}}</div>
                            </div>
                            <div class="mb-3">
                                <label class="form-label" for="autoRenewThreshold">{{t:ssl.threshold}}</label>
                                <input type="number" class="form-control" id="autoRenewThreshold" value="30" min="1" max="89" onchange="saveAutoRenewSettings()">
                                <div class="text-muted small">{{t:ssl.thresholdDefault}}</div>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <table class="table table-sm">
                                <tbody>
                                    <tr><td><strong>{{t:ssl.lastCheck}}</strong></td><td id="autoRenewLastCheck" class="text-muted">{{t:ssl.never}}</td></tr>
                                    <tr><td><strong>{{t:ssl.result}}</strong></td><td id="autoRenewLastResult" class="text-muted">-</td></tr>
                                    <tr><td><strong>{{t:ssl.lastRenewal}}</strong></td><td id="autoRenewLastRenewal" class="text-muted">{{t:ssl.never}}</td></tr>
                                    <tr><td><strong>{{t:ssl.nextCheck}}</strong></td><td id="autoRenewNextCheck" class="text-muted">-</td></tr>
                                </tbody>
                            </table>
                            <button class="btn btn-outline-info btn-sm" onclick="triggerManualCheck()">
                                <i class="fas fa-play me-1" aria-hidden="true"></i>{{t:ssl.checkNow}}
                            </button>
                            <div class="card mt-3 border-0" style="background: rgba(246,130,31,0.08)">
                                <div class="card-body py-3">
                                    <h6 class="mb-2"><i class="fas fa-cloud me-1" style="color:#f6821f"></i>{{t:ssl.autoViaCf}}</h6>
                                    <p class="small text-muted mb-2">
                                        {{t:ssl.cfLinkA}}
                                        (<strong id="autoRenewMailHost">{{MAIL_HOSTNAME}}</strong>){{t:ssl.cfLinkB}}
                                    </p>
                                    <label class="form-label small mb-1" for="autoRenewCfAccount">{{t:ssl.cfAccount}}</label>
                                    <div class="d-flex gap-2 align-items-center flex-wrap">
                                        <select class="form-select form-select-sm" style="max-width:280px" id="autoRenewCfAccount" onchange="saveCfMailServerAccount(this.value)">
                                            <option value="0">{{t:common.loading}}</option>
                                        </select>
                                        <button class="btn btn-outline-info btn-sm" type="button" onclick="testCfMailServer()">
                                            <i class="fas fa-plug me-1" aria-hidden="true"></i>{{t:ssl.testLink}}
                                        </button>
                                        <a href="/cloudflare" class="btn btn-outline-secondary btn-sm">
                                            <i class="fas fa-gear me-1" aria-hidden="true"></i>{{t:ssl.manageAccounts}}
                                        </a>
                                    </div>
                                    <div id="autoRenewCfTest" class="mt-2 small"></div>
                                    <div class="small text-muted mt-1" id="autoRenewCfHint" style="display:none">
                                        <i class="fas fa-exclamation-triangle text-warning me-1" aria-hidden="true"></i>
                                        {{t:ssl.noCfAccount}}
                                        <a href="/cloudflare" class="alert-link">{{t:ssl.addOneHere}}</a>.
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- SSL Configuration Options -->
            <h4 class="mb-1"><i class="fas fa-cogs me-2" aria-hidden="true"></i>{{t:ssl.configure}} <small class="text-muted fs-6">{{t:ssl.manualOps}}</small></h4>
            <div class="alert alert-secondary py-2 small">
                <i class="fas fa-hand me-1" aria-hidden="true"></i>
                {{t:ssl.manualSection.html}}
            </div>

            <div class="row mb-4">
                <!-- Option 1: Let's Encrypt HTTP-01 -->
                <div class="col-md-4 mb-3">
                    <div class="card option-card h-100" onclick="selectOption(1)">
                        <div class="card-body text-center">
                            <i class="fas fa-bolt fa-3x text-warning mb-3" aria-hidden="true"></i>
                            <h5>Let's Encrypt (HTTP-01)</h5>
                            <p class="text-muted small">{{t:ssl.http01Hint}}</p>
                            <span class="badge bg-danger">{{t:ssl.notAdvised}}</span>
                        </div>
                    </div>
                </div>

                <!-- Option 2: Let's Encrypt DNS-01 -->
                <div class="col-md-4 mb-3">
                    <div class="card option-card h-100" onclick="selectOption(2)">
                        <div class="card-body text-center">
                            <i class="fas fa-globe fa-3x text-success mb-3" aria-hidden="true"></i>
                            <h5>Let's Encrypt (DNS-01)</h5>
                            <p class="text-muted small">{{t:ssl.dns01Hint}}</p>
                            <span class="badge bg-success">{{t:ssl.advised}}</span>
                        </div>
                    </div>
                </div>

                <!-- Option 3: Manual Certificate -->
                <div class="col-md-4 mb-3">
                    <div class="card option-card h-100" onclick="selectOption(3)">
                        <div class="card-body text-center">
                            <i class="fas fa-upload fa-3x text-warning mb-3" aria-hidden="true"></i>
                            <h5>{{t:ssl.manualCert}}</h5>
                            <p class="text-muted small">{{t:ssl.manualHint}}</p>
                            <span class="badge bg-warning text-dark">{{t:ssl.advanced}}</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Option 1: HTTP-01 Form -->
            <div id="option1Form" class="card mb-4 d-none">
                <div class="card-header bg-success text-white">
                    <i class="fas fa-bolt me-2" aria-hidden="true"></i>{{t:ssl.http01Title}}
                </div>
                <div class="card-body">
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle me-2" aria-hidden="true"></i>
                        {{t:ssl.http01Req.html}}
                    </div>
                    <form id="http01Form">
                        <div class="mb-3">
                            <label class="form-label">{{t:ssl.mailHostname}}</label>
                            <div class="form-control bg-light">
                                <strong>{{MAIL_HOSTNAME}}</strong>
                            </div>
                            <input type="hidden" id="http01Hostname" value="{{MAIL_HOSTNAME}}">
                        </div>
                        <button type="submit" class="btn btn-success">
                            <i class="fas fa-certificate me-1" aria-hidden="true"></i>{{t:ssl.generateCert}}
                        </button>
                    </form>
                    <div id="http01Output" class="mt-3 d-none">
                        <pre class="bg-dark text-light p-3" style="max-height:300px;overflow-y:auto"></pre>
                    </div>
                </div>
            </div>

            <!-- Option 2: DNS-01 Form -->
            <div id="option2Form" class="card mb-4 d-none">
                <div class="card-header bg-primary text-white">
                    <i class="fas fa-globe me-2" aria-hidden="true"></i>{{t:ssl.dns01Title}}
                </div>
                <div class="card-body">
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle me-2" aria-hidden="true"></i>
                        {{t:ssl.dns01Intro}}
                    </div>

                    <!-- Step 1: Hostname display -->
                    <div id="dns01Step1">
                        <h5><span class="step-number">1</span>{{t:ssl.step1}}</h5>
                        <div class="mb-3">
                            <div class="form-control bg-light">
                                <strong>{{MAIL_HOSTNAME}}</strong>
                            </div>
                            <input type="hidden" id="dns01Hostname" value="{{MAIL_HOSTNAME}}">
                        </div>
                        <button class="btn btn-primary" onclick="generateDnsChallenge()">
                            <i class="fas fa-key me-1" aria-hidden="true"></i>{{t:ssl.generateChallenge}}
                        </button>
                    </div>

                    <!-- Certificate exists - show options -->
                    <div id="dns01CertExists" class="d-none">
                        <div class="alert alert-info">
                            <i class="fas fa-certificate me-2" aria-hidden="true"></i>
                            <strong>{{t:ssl.exists}}</strong><br>
                            {{t:ssl.existsHint}}
                        </div>
                        <div class="d-flex gap-2 flex-wrap">
                            <button class="btn btn-success" onclick="deployExistingCert()">
                                <i class="fas fa-download me-1" aria-hidden="true"></i>{{t:ssl.deployExisting}}
                            </button>
                            <button class="btn btn-warning" onclick="forceRegenerateChallenge()">
                                <i class="fas fa-sync me-1" aria-hidden="true"></i>{{t:ssl.regenChallenge}}
                            </button>
                            <button class="btn btn-outline-secondary" onclick="resetDnsChallenge()">
                                <i class="fas fa-times me-1" aria-hidden="true"></i>{{t:common.cancel}}
                            </button>
                        </div>
                    </div>

                    <!-- Step 2: Add DNS record -->
                    <div id="dns01Step2" class="d-none">
                        <h5><span class="step-number">2</span>{{t:dns.recAddYourself}}</h5>
                        <div class="mb-3">
                            <label class="form-label">{{t:ssl.recordName}}</label>
                            <div class="dns-record">
                                <span id="dnsRecordName">_acme-challenge.mail.example.com</span>
                                <button type="button" class="btn btn-link p-0 copy-btn float-end" onclick="copyToClipboard('dnsRecordName')" aria-label="{{t:common.copy}}" title="{{t:common.copy}}"><i class="fas fa-copy" aria-hidden="true"></i></button>
                            </div>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">{{t:ssl.recordValue}}</label>
                            <div class="dns-record">
                                <span id="dnsRecordValue">xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</span>
                                <button type="button" class="btn btn-link p-0 copy-btn float-end" onclick="copyToClipboard('dnsRecordValue')" aria-label="{{t:common.copy}}" title="{{t:common.copy}}"><i class="fas fa-copy" aria-hidden="true"></i></button>
                            </div>
                        </div>
                        <div class="alert alert-warning">
                            <i class="fas fa-clock me-2" aria-hidden="true"></i>
                            {{t:ssl.waitPropagation}}
                        </div>
                    </div>

                    <!-- Step 3: Verify and generate -->
                    <div id="dns01Step3" class="d-none">
                        <h5><span class="step-number">3</span>{{t:ssl.step3}}</h5>
                        <p>{{t:ssl.step3Hint}}</p>
                        <button class="btn btn-success" onclick="verifyDnsAndGenerate()">
                            <i class="fas fa-check-circle me-1" aria-hidden="true"></i>{{t:ssl.verifyGenerate}}
                        </button>
                        <button class="btn btn-outline-secondary ms-2" onclick="resetDnsChallenge()">
                            <i class="fas fa-redo me-1" aria-hidden="true"></i>{{t:ssl.restart}}
                        </button>
                    </div>

                    <div id="dns01Output" class="mt-3 d-none">
                        <pre class="bg-dark text-light p-3" style="max-height:300px;overflow-y:auto"></pre>
                    </div>
                </div>
            </div>

            <!-- Option 3: Manual Upload Form -->
            <div id="option3Form" class="card mb-4 d-none">
                <div class="card-header bg-warning text-dark">
                    <i class="fas fa-upload me-2" aria-hidden="true"></i>{{t:ssl.uploadManual}}
                </div>
                <div class="card-body">

                    <!-- Guida certificato manuale -->
                    <div class="card mb-4 border-info">
                        <div class="card-header bg-info text-white" style="cursor:pointer;" data-bs-toggle="collapse" data-bs-target="#manualGuide" aria-expanded="true">
                            <i class="fas fa-book me-2" aria-hidden="true"></i><strong>{{t:ssl.mgTitle}}</strong>
                            <i class="fas fa-chevron-down float-end mt-1" aria-hidden="true"></i>
                        </div>
                        <div id="manualGuide" class="collapse show">
                            <div class="card-body">

                                <h5><i class="fas fa-question-circle me-2" aria-hidden="true"></i>{{t:ssl.mgWhyFull}}</h5>
                                <p>
                                    {{t:ssl.mgWhyFullText.html}}
                                </p>

                                <h5 class="mt-3"><i class="fas fa-folder-open me-2" aria-hidden="true"></i>{{t:ssl.mgWhatCa}}</h5>
                                <p>{{t:ssl.mgThree.html}}</p>
                                <div class="table-responsive">
                                    <table class="table table-sm table-bordered align-middle">
                                        <thead class="table-light">
                                            <tr><th>{{t:ssl.mgFile}}</th><th>{{t:ssl.mgWhat}}</th><th>{{t:ssl.mgExample}}</th></tr>
                                        </thead>
                                        <tbody>
                                            <tr><td><strong>{{t:ssl.mgServerCert}}</strong></td><td>{{t:ssl.mgLeaf}}</td><td><code>tuodominio.crt</code>, <code>cert.pem</code></td></tr>
                                            <tr><td><strong>{{t:ssl.mgBundle}}</strong></td><td>{{t:ssl.mgBundleWhat}}</td><td><code>ca-bundle.crt</code>, <code>intermediate.crt</code>, <code>chain.pem</code></td></tr>
                                            <tr><td><strong>{{t:ssl.mgKey}}</strong></td><td>{{t:ssl.mgKeyWhat}}</td><td><code>tuodominio.key</code>, <code>privkey.pem</code></td></tr>
                                        </tbody>
                                    </table>
                                </div>

                                <h5 class="mt-3"><i class="fas fa-tools me-2" aria-hidden="true"></i>{{t:ssl.mgBuild}}</h5>

                                <p class="mb-2"><strong>{{t:ssl.mgM1}}</strong></p>
                                <pre class="bg-dark text-light p-3 mb-3" style="font-size:0.85rem;">cat tuodominio.crt ca-bundle.crt > fullchain.pem</pre>
                                <p class="text-muted small mb-3">{{t:ssl.mgOrder.html}}</p>

                                <p class="mb-2"><strong>{{t:ssl.mgM2}}</strong></p>
                                <ol>
                                    <li>{{t:ssl.mgM2s1.html}}</li>
                                    <li>{{t:ssl.mgM2s2.html}}</li>
                                    <li>{{t:ssl.mgM2s3}}</li>
                                    <li>{{t:ssl.mgM2s4}}</li>
                                    <li>{{t:ssl.mgM2s5.html}}</li>
                                    <li>{{t:ssl.mgM2s6.html}}</li>
                                    <li>{{t:ssl.mgM2s7.html}}</li>
                                </ol>

                                <h5 class="mt-3"><i class="fas fa-eye me-2" aria-hidden="true"></i>{{t:ssl.mgLooks}}</h5>
<pre class="bg-dark text-light p-3" style="font-size:0.85rem;">-----BEGIN CERTIFICATE-----
MIIE...   ← (1) {{t:ssl.mgYours}}
... base64 ...
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIE...   ← (2) intermediate CA
... base64 ...
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIE...   ← (3) {{t:ssl.mgRoot}}
... base64 ...
-----END CERTIFICATE-----</pre>
                                <p class="small">{{t:ssl.mgTwoBlocks.html}}</p>

                                <h5 class="mt-3"><i class="fas fa-clipboard me-2" aria-hidden="true"></i>{{t:ssl.mgFields}}</h5>
                                <div class="table-responsive">
                                    <table class="table table-sm table-bordered align-middle mb-2">
                                        <thead class="table-light"><tr><th style="width:35%">{{t:ssl.mgField}}</th><th>{{t:ssl.mgContent}}</th></tr></thead>
                                        <tbody>
                                            <tr><td><strong>{{t:ssl.certField}}</strong></td><td>{{t:ssl.mgCertContent.html}}</td></tr>
                                            <tr><td><strong>{{t:ssl.keyField}}</strong></td><td>{{t:ssl.mgKeyContent.html}}</td></tr>
                                        </tbody>
                                    </table>
                                </div>

                                <h5 class="mt-3"><i class="fas fa-check-double me-2" aria-hidden="true"></i>{{t:ssl.mgQuick}}</h5>
                                <ul class="mb-0">
                                    <li>{{t:ssl.q1.html}}</li>
                                    <li>{{t:ssl.q2.html}}</li>
                                    <li>{{t:ssl.q3.html}}</li>
                                    <li>{{t:ssl.q4.html}}</li>
                                </ul>

                                <h5 class="mt-3"><i class="fas fa-exclamation-triangle text-warning me-2" aria-hidden="true"></i>{{t:ssl.mgErrors}}</h5>
                                <ul class="mb-0">
                                    <li>{{t:ssl.e1.html}}</li>
                                    <li>{{t:ssl.e2.html}}</li>
                                    <li>{{t:ssl.e3.html}}
                                        <code>openssl rsa -in privkey-encrypted.key -out privkey.pem</code></li>
                                    <li>{{t:ssl.e4.html}}
                                        <code>openssl pkcs12 -in cert.pfx -nocerts -nodes -out privkey.pem</code><br>
                                        <code>openssl pkcs12 -in cert.pfx -nokeys -clcerts -out cert.crt</code><br>
                                        <code>openssl pkcs12 -in cert.pfx -nokeys -cacerts -out ca-bundle.crt</code></li>
                                </ul>

                                <h5 class="mt-3"><i class="fas fa-balance-scale me-2" aria-hidden="true"></i>{{t:ssl.mgPay}}</h5>
                                <p class="mb-0">
                                    {{t:ssl.mgPayText.html}}
                                </p>
                            </div>
                        </div>
                    </div>

                    <form id="manualCertForm">
                        <div class="mb-3">
                            <label class="form-label" for="manualCert">{{t:ssl.certField}}</label>
                            <textarea class="form-control font-monospace" id="manualCert" rows="8" placeholder="-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----" required></textarea>
                            <div class="form-text">{{t:ssl.certFieldHint}}</div>
                        </div>
                        <div class="mb-3">
                            <label class="form-label" for="manualKey">{{t:ssl.keyField}}</label>
                            <textarea class="form-control font-monospace" id="manualKey" rows="8" placeholder="-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----" required></textarea>
                        </div>
                        <button type="submit" class="btn btn-warning">
                            <i class="fas fa-save me-1" aria-hidden="true"></i>{{t:ssl.saveCert}}
                        </button>
                    </form>
                    <div id="manualOutput" class="mt-3 d-none">
                        <pre class="bg-dark text-light p-3"></pre>
                    </div>
                </div>
            </div>
        </div>
    </div>
""" + getFooterSection() + """
    <script>
        let currentDnsChallenge = null;

        function loadSslStatus() {
            fetch('/api/ssl').then(r => r.json()).then(data => {
                const certDiv = document.getElementById('certInfo');
                const warningDiv = document.getElementById('selfSignedWarning');

                if (data.self_signed) {
                    warningDiv.classList.remove('d-none');
                    certDiv.innerHTML = `
                        <div class="cert-info cert-self-signed">
                            <div class="row">
                                <div class="col-md-8">
                                    <h5><i class="fas fa-exclamation-triangle text-danger me-2" aria-hidden="true"></i>${escHtml(t('ssl.selfSignedTemp'))}</h5>
                                    <table class="table table-sm table-borderless mb-0">
                                        <tr><td style="width:150px"><strong>${escHtml(t('ssl.cDomain'))}</strong></td><td>${escHtml(data.common_name || data.hostname || 'N/A')}</td></tr>
                                        <tr><td><strong>${escHtml(t('ssl.cIssuer'))}</strong></td><td>${escHtml(data.issuer || 'Self-Signed')}</td></tr>
                                        <tr><td><strong>${escHtml(t('ssl.cExpires'))}</strong></td><td>${escHtml(data.expires_at || 'N/A')} ${data.days_until_expiry ? escHtml(tn('dns.daysParen', data.days_until_expiry)) : ''}</td></tr>
                                        <tr><td><strong>${escHtml(t('ssl.cAlgorithm'))}</strong></td><td>${escHtml(data.algorithm || 'RSA')}</td></tr>
                                    </table>
                                </div>
                                <div class="col-md-4 text-center">
                                    <span class="badge bg-danger fs-6 p-2"><i class="fas fa-times-circle me-1" aria-hidden="true"></i>${escHtml(t('ssl.notValid'))}</span>
                                    <p class="text-danger mt-2 small"><strong>${escHtml(t('ssl.clientsWarn'))}</strong></p>
                                </div>
                            </div>
                        </div>`;
                } else if (data.certificate_installed) {
                    warningDiv.classList.add('d-none');
                    let statusClass = 'cert-valid';
                    let statusBadge = '<span class="badge bg-success fs-6 p-2"><i class="fas fa-check-circle me-1" aria-hidden="true"></i>' + escHtml(t('ssl.valid')) + '</span>';
                    let statusText = '';

                    if (data.expired) {
                        statusClass = 'cert-self-signed';
                        statusBadge = '<span class="badge bg-danger fs-6 p-2"><i class="fas fa-times-circle me-1" aria-hidden="true"></i>' + escHtml(t('ssl.expired')) + '</span>';
                        statusText = '<p class="text-danger mt-2 small"><strong>' + escHtml(t('ssl.expiredText')) + '</strong></p>';
                    } else if (data.expiring_soon) {
                        statusClass = 'cert-expiring';
                        statusBadge = '<span class="badge bg-warning fs-6 p-2"><i class="fas fa-exclamation-triangle me-1" aria-hidden="true"></i>' + escHtml(t('ssl.expiring')) + '</span>';
                        statusText = '<p class="text-warning mt-2 small"><strong>' + escHtml(t('ssl.renewSoon')) + '</strong></p>';
                    }

                    let certType = data.lets_encrypt ? '<span class="badge bg-info">Let\\'s Encrypt</span>' :
                                   (data.self_signed ? '<span class="badge bg-secondary">' + escHtml(t('ssl.selfSignedShort')) + '</span>' : '<span class="badge bg-primary">' + escHtml(t('ssl.custom')) + '</span>');

                    certDiv.innerHTML = `
                        <div class="cert-info ${statusClass}">
                            <div class="row">
                                <div class="col-md-8">
                                    <h5><i class="fas fa-shield-alt text-success me-2" aria-hidden="true"></i>${escHtml(data.common_name || t('ssl.sslCert'))}</h5>
                                    <table class="table table-sm table-borderless mb-0">
                                        <tr><td style="width:150px"><strong>${escHtml(t('ssl.cDomain'))}</strong></td><td>${escHtml(data.common_name || 'N/A')}</td></tr>
                                        <tr><td><strong>${escHtml(t('ssl.cIssuer'))}</strong></td><td>${escHtml(data.issuer || 'N/A')} ${certType}</td></tr>
                                        <tr><td><strong>${escHtml(t('ssl.cFrom'))}</strong></td><td>${escHtml(data.valid_from || 'N/A')}</td></tr>
                                        <tr><td><strong>${escHtml(t('ssl.cExpires'))}</strong></td><td>${escHtml(data.expires_at || 'N/A')} <strong>${data.days_until_expiry ? escHtml(tn('dns.daysParen', data.days_until_expiry)) : ''}</strong></td></tr>
                                        <tr><td><strong>${escHtml(t('ssl.cAlgorithm'))}</strong></td><td>${escHtml(data.algorithm || 'N/A')}</td></tr>
                                        ${data.serial ? '<tr><td><strong>' + escHtml(t('ssl.cSerial')) + '</strong></td><td><code>' + escHtml(data.serial) + '</code></td></tr>' : ''}
                                    </table>
                                </div>
                                <div class="col-md-4 text-center">
                                    ${statusBadge}
                                    ${statusText}
                                </div>
                            </div>
                        </div>`;
                } else {
                    warningDiv.classList.add('d-none');
                    certDiv.innerHTML = `
                        <div class="alert alert-secondary">
                            <i class="fas fa-info-circle me-2" aria-hidden="true"></i>${escHtml(t('ssl.noCert'))}
                        </div>`;
                }
                // Check hostname mismatch
                const mismatchDiv = document.getElementById('sslHostnameMismatch');
                const currentMailHostname = '{{MAIL_HOSTNAME}}';
                const certCn = data.common_name || '';
                if (currentMailHostname && certCn && currentMailHostname !== t('server.notConfigured')) {
                    // Check CN and SANs
                    let matches = certCn.toLowerCase() === currentMailHostname.toLowerCase();
                    if (!matches && data.san) {
                        matches = data.san.some(s => s.toLowerCase() === currentMailHostname.toLowerCase());
                    }
                    if (!matches) {
                        document.getElementById('sslMismatchCn').textContent = certCn || 'self-signed';
                        document.getElementById('sslMismatchExpected').textContent = currentMailHostname;
                        document.getElementById('sslMismatchTarget').textContent = currentMailHostname;
                        mismatchDiv.classList.remove('d-none');
                    } else {
                        mismatchDiv.classList.add('d-none');
                    }
                } else {
                    mismatchDiv.classList.add('d-none');
                }
            }).catch(err => {
                document.getElementById('certInfo').innerHTML =
                    '<div class="alert alert-warning"><i class="fas fa-exclamation-triangle me-2" aria-hidden="true"></i>' + escHtml(t('ssl.stateError')) + '</div>';
            });
        }

        function selectOption(num) {
            // Hide all forms
            document.getElementById('option1Form').classList.add('d-none');
            document.getElementById('option2Form').classList.add('d-none');
            document.getElementById('option3Form').classList.add('d-none');

            // Remove selected class from all cards
            document.querySelectorAll('.option-card').forEach(c => c.classList.remove('selected'));

            // Show selected form and highlight card
            document.getElementById('option' + num + 'Form').classList.remove('d-none');
            document.querySelectorAll('.option-card')[num-1].classList.add('selected');
        }

        function copyToClipboard(elementId) {
            const text = document.getElementById(elementId).textContent;
            navigator.clipboard.writeText(text).then(() => {
                alert(t('dns.copiedClipboard'));
            });
        }

        // HTTP-01 form
        document.getElementById('http01Form').addEventListener('submit', function(e) {
            e.preventDefault();
            const hostname = document.getElementById('http01Hostname').value;
            const output = document.getElementById('http01Output');
            output.classList.remove('d-none');
            output.querySelector('pre').textContent = t('ssl.generating');

            fetch('/api/ssl', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action: 'issue_http01',
                    hostname: hostname,
                    csrf_token: document.getElementById('csrf_token').value
                })
            }).then(r => r.json()).then(data => {
                output.querySelector('pre').textContent = data.output || data.message;
                if (data.success) {
                    loadSslStatus();
                    alert(t('ssl.generated'));
                }
            });
        });

        // DNS-01 challenge generation
        function generateDnsChallenge() {
            const hostname = document.getElementById('dns01Hostname').value;
            if (!hostname) {
                alert(t('ssl.needHostname'));
                return;
            }

            fetch('/api/ssl', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action: 'generate_dns_challenge',
                    hostname: hostname,
                    csrf_token: document.getElementById('csrf_token').value
                })
            }).then(r => r.json()).then(data => {
                if (data.success) {
                    currentDnsChallenge = data;
                    currentDnsChallenge.hostname = hostname;
                    document.getElementById('dnsRecordName').textContent = data.txt_domain;
                    document.getElementById('dnsRecordValue').textContent = data.txt_value;

                    document.getElementById('dns01Step1').classList.add('d-none');
                    document.getElementById('dns01CertExists').classList.add('d-none');
                    document.getElementById('dns01Step2').classList.remove('d-none');
                    document.getElementById('dns01Step3').classList.remove('d-none');
                } else if (data.message === 'CERT_EXISTS') {
                    // Certificate exists - show options
                    document.getElementById('dns01Step1').classList.add('d-none');
                    document.getElementById('dns01CertExists').classList.remove('d-none');
                } else {
                    alert(t('common.error', { message: data.message }));
                }
            });
        }

        function deployExistingCert() {
            const hostname = document.getElementById('dns01Hostname').value;
            fetch('/api/ssl', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action: 'deploy_existing_cert',
                    hostname: hostname,
                    csrf_token: document.getElementById('csrf_token').value
                })
            }).then(r => r.json()).then(data => {
                if (data.success) {
                    alert(t('ssl.deployed'));
                    loadSslStatus();
                    resetDnsChallenge();
                } else {
                    alert(t('common.error', { message: data.message }));
                }
            });
        }

        function forceRegenerateChallenge() {
            const hostname = document.getElementById('dns01Hostname').value;
            fetch('/api/ssl', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action: 'generate_dns_challenge',
                    hostname: hostname,
                    force: true,
                    csrf_token: document.getElementById('csrf_token').value
                })
            }).then(r => r.json()).then(data => {
                if (data.success) {
                    currentDnsChallenge = data;
                    currentDnsChallenge.hostname = hostname;
                    document.getElementById('dnsRecordName').textContent = data.txt_domain;
                    document.getElementById('dnsRecordValue').textContent = data.txt_value;

                    document.getElementById('dns01CertExists').classList.add('d-none');
                    document.getElementById('dns01Step2').classList.remove('d-none');
                    document.getElementById('dns01Step3').classList.remove('d-none');
                } else {
                    alert(t('common.error', { message: data.message }));
                }
            });
        }

        function verifyDnsAndGenerate() {
            if (!currentDnsChallenge) {
                alert(t('ssl.challengeFirst'));
                return;
            }

            const output = document.getElementById('dns01Output');
            output.classList.remove('d-none');
            output.querySelector('pre').textContent = t('ssl.verifying');

            fetch('/api/ssl', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action: 'verify_dns_and_issue',
                    hostname: currentDnsChallenge.hostname,
                    challenge_token: currentDnsChallenge.challenge_token,
                    csrf_token: document.getElementById('csrf_token').value
                })
            }).then(r => r.json()).then(data => {
                output.querySelector('pre').textContent = data.output || data.message;
                if (data.success) {
                    loadSslStatus();
                    alert(t('ssl.generated'));
                    resetDnsChallenge();
                }
            });
        }

        function resetDnsChallenge() {
            currentDnsChallenge = null;
            document.getElementById('dns01Step1').classList.remove('d-none');
            document.getElementById('dns01CertExists').classList.add('d-none');
            document.getElementById('dns01Step2').classList.add('d-none');
            document.getElementById('dns01Step3').classList.add('d-none');
            document.getElementById('dns01Output').classList.add('d-none');
        }

        // Manual certificate form
        document.getElementById('manualCertForm').addEventListener('submit', function(e) {
            e.preventDefault();
            const cert = document.getElementById('manualCert').value;
            const key = document.getElementById('manualKey').value;
            const output = document.getElementById('manualOutput');
            output.classList.remove('d-none');
            output.querySelector('pre').textContent = t('ssl.saving');

            fetch('/api/ssl', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action: 'upload_manual',
                    certificate: cert,
                    private_key: key,
                    csrf_token: document.getElementById('csrf_token').value
                })
            }).then(r => r.json()).then(data => {
                output.querySelector('pre').textContent = data.message;
                if (data.success) {
                    loadSslStatus();
                    alert(t('ssl.saved'));
                }
            });
        });

        loadSslStatus();
        loadAutoRenewSettings();
        loadCfMailServerAccount();

        // ===== Cloudflare account per il certificato del server mail =====
        function escSslCf(s) {
            return String(s == null ? '' : s)
                .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
        }

        function loadCfMailServerAccount() {
            fetch('/api/cloudflare').then(r => r.json()).then(data => {
                const sel = document.getElementById('autoRenewCfAccount');
                const hint = document.getElementById('autoRenewCfHint');
                if (!sel) return;
                const accounts = data.accounts || [];
                const ms = data.mail_server || {};
                const cur = ms.cloudflare_account_id || 0;
                if (ms.hostname) {
                    const hostEl = document.getElementById('autoRenewMailHost');
                    if (hostEl) hostEl.textContent = ms.hostname;
                }
                let opts = '<option value="0"' + (cur === 0 ? ' selected' : '') + '>' + escHtml(t('ssl.manualNoAccount')) + '</option>';
                accounts.forEach(a => {
                    opts += '<option value="' + a.id + '"' + (cur === a.id ? ' selected' : '') + '>'
                        + escSslCf(a.label || ('account #' + a.id)) + '</option>';
                });
                sel.innerHTML = opts;
                if (hint) hint.style.display = accounts.length ? 'none' : '';
            }).catch(e => console.error('loadCfMailServerAccount error:', e));
        }

        function saveCfMailServerAccount(accountId) {
            fetch('/api/cloudflare', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'assign_mailserver', account_id: parseInt(accountId, 10) || 0,
                    csrf_token: document.getElementById('csrf_token').value })
            }).then(r => r.json()).then(data => {
                const out = document.getElementById('autoRenewCfTest');
                if (data.success) {
                    out.innerHTML = '<span class="text-success"><i class="fas fa-check-circle me-1" aria-hidden="true"></i>'
                        + escSslCf(data.message || t('ssl.savedShort')) + '</span>';
                } else {
                    out.innerHTML = '<span class="text-danger"><i class="fas fa-times-circle me-1" aria-hidden="true"></i>'
                        + escSslCf(data.message || data.error || t('common.errorShort')) + '</span>';
                }
            }).catch(e => alert(t('common.error', { message: e.message })));
        }

        function testCfMailServer() {
            const sel = document.getElementById('autoRenewCfAccount');
            const out = document.getElementById('autoRenewCfTest');
            const accountId = sel ? (parseInt(sel.value, 10) || 0) : 0;
            if (accountId <= 0) {
                out.innerHTML = '<span class="text-warning"><i class="fas fa-exclamation-triangle me-1" aria-hidden="true"></i>' + escHtml(t('ssl.chooseCfFirst')) + '</span>';
                return;
            }
            out.innerHTML = '<span class="text-muted"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('ssl.testingCf')) + '</span>';
            fetch('/api/cloudflare', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'test_mailserver', account_id: accountId,
                    csrf_token: document.getElementById('csrf_token').value })
            }).then(r => r.json()).then(data => {
                if (data.success) {
                    out.innerHTML = '<div class="alert alert-success py-2 mb-0"><i class="fas fa-check-circle me-1" aria-hidden="true"></i>'
                        + escSslCf(data.message || t('ssl.linkOk')) + '</div>';
                } else {
                    out.innerHTML = '<div class="alert alert-danger py-2 mb-0"><i class="fas fa-times-circle me-1" aria-hidden="true"></i>'
                        + escSslCf(data.error || data.message || t('dns.checkFailed')) + '</div>';
                }
            }).catch(e => alert(t('common.error', { message: e.message })));
        }

        // ===== Auto-Renewal =====
        function loadAutoRenewSettings() {
            fetch('/api/ssl', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'get_auto_renewal_settings', csrf_token: document.getElementById('csrf_token').value })
            }).then(r => r.json()).then(data => {
                if (!data.success) return;
                const enabled = !!data.enabled;
                document.getElementById('autoRenewEnabled').checked = enabled;
                document.getElementById('autoRenewThreshold').value = data.threshold_days || 30;
                const badge = document.getElementById('autoRenewBadge');
                if (enabled) {
                    badge.className = 'badge bg-success';
                    badge.innerHTML = '<i class="fas fa-check me-1" aria-hidden="true"></i>' + escHtml(t('rl.active'));
                } else {
                    badge.className = 'badge bg-secondary';
                    badge.innerHTML = '<i class="fas fa-pause me-1" aria-hidden="true"></i>' + escHtml(t('ssl.off'));
                }
                document.getElementById('autoRenewLastCheck').textContent = data.last_check_human || t('ssl.never');
                document.getElementById('autoRenewLastResult').innerHTML = data.last_result_html || '-';
                document.getElementById('autoRenewLastRenewal').textContent = data.last_renewal_human || t('ssl.never');
                document.getElementById('autoRenewNextCheck').textContent = data.next_check_human || '-';
            }).catch(e => console.error('loadAutoRenewSettings error:', e));
        }

        function saveAutoRenewSettings() {
            const enabled = document.getElementById('autoRenewEnabled').checked;
            const threshold = parseInt(document.getElementById('autoRenewThreshold').value, 10) || 30;
            fetch('/api/ssl', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action: 'set_auto_renewal_settings',
                    enabled: enabled,
                    threshold_days: threshold,
                    csrf_token: document.getElementById('csrf_token').value
                })
            }).then(r => r.json()).then(data => {
                if (data.success) loadAutoRenewSettings();
                else alert(t('common.error', { message: data.message || data.error || t('common.unknownError') }));
            });
        }

        function triggerManualCheck() {
            const btn = event.currentTarget;
            const originalHtml = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1" aria-hidden="true"></span>' + escHtml(t('dns.checkingRecord'));
            fetch('/api/ssl', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'trigger_manual_check', csrf_token: document.getElementById('csrf_token').value })
            }).then(r => r.json()).then(data => {
                btn.disabled = false;
                btn.innerHTML = originalHtml;
                if (data.success) {
                    alert(data.message || t('ssl.checkDone'));
                    loadAutoRenewSettings();
                    loadSslStatus();
                } else {
                    alert(t('common.error', { message: data.message || data.error || t('common.unknownError') }));
                }
            }).catch(e => {
                btn.disabled = false;
                btn.innerHTML = originalHtml;
                alert(t('common.error', { message: e.message }));
            });
        }

        let csrfToken = document.getElementById('csrf_token').value;
""" + """
    </script>
</body>
</html>
""";
    }

    // ============== LOGS.HTML - Logs & Monitoring Page ==============
    public static String getLogsHtml() {
        String extraStyles = """
        .log-container { background: #1e1e1e; color: #d4d4d4; font-family: 'Courier New', monospace; font-size: 12px; padding: 15px; border-radius: 8px; max-height: 500px; overflow-y: auto; }
        .log-line { margin: 0; padding: 2px 0; }
        .log-error { color: #f14c4c; }
        .log-warning { color: #cca700; }
        .log-info { color: #3794ff; }
        .log-viewer { background: #1e1e1e; color: #d4d4d4; font-family: 'Consolas', monospace; font-size: 0.85rem; padding: 15px; border-radius: 8px; max-height: 500px; overflow-y: auto; }
        /* Force-reset di line-through ovunque venga (Bootstrap, html del log, etc) */
        .log-entry, .log-entry *, .log-viewer, .log-viewer * {
            text-decoration: none !important;
            text-decoration-line: none !important;
            text-decoration-style: none !important;
        }
        /* Padding verticale + separatore tenue per evitare overlap visivo con il testo */
        .log-entry {
            padding: 6px 4px;
            border-bottom: 1px solid rgba(255,255,255,0.06);
            word-break: break-word;
            white-space: pre-wrap;
            line-height: 1.4;
        }
        .log-entry:last-child { border-bottom: none; }
        .log-entry:hover { background: #2d2d2d; }
        .log-ERROR { color: #f44336; }
        .log-WARNING { color: #ff9800; }
        .log-INFO { color: #4caf50; }
        .log-DEBUG { color: #9e9e9e; }
        .stat-number { font-size: 2rem; font-weight: bold; color: #e94560; }
        .log-preset-btn { font-size: 0.78rem; padding: 2px 8px; }
        .log-preset-btn.active { font-weight: 600; box-shadow: 0 0 0 2px rgba(0,123,255,.35); }
        .log-preset-group { display:flex; flex-wrap:wrap; gap:.35rem; align-items:center; }
        .log-preset-cat { font-size:.7rem; font-weight:600; text-transform:uppercase; color:#6c757d; min-width:90px; }
        #filterActiveDesc { font-size: 0.8rem; padding: 6px 10px; border-radius: 6px; background: #eef5ff; border-left: 3px solid #0d6efd; }
        [data-theme="dark"] #filterActiveDesc { background: rgba(13, 110, 253, .16); }
        """;
        return getHead("nav.logs", "logs", extraStyles) + """
    <div id="main" tabindex="-1" class="content container mt-4">
        <!-- Statistiche -->
        <div class="row mb-4">
            <div class="col-md-6">
                <div class="card stat-card"><div class="card-body text-center">
                    <div class="stat-number" id="statSpam">-</div>
                    <div>{{t:lg.spamBlocked}}</div>
                </div></div>
            </div>
            <div class="col-md-6">
                <div class="card stat-card"><div class="card-body text-center">
                    <div class="stat-number" id="statUsers">-</div>
                    <div>{{t:lg.activeUsers}}</div>
                </div></div>
            </div>
        </div>

        <div class="content-container">
            <div class="d-flex justify-content-between align-items-center mb-3 flex-wrap gap-2">
                <h2 class="mb-0"><i class="fas fa-file-alt me-2" aria-hidden="true"></i>{{t:lg.title}}</h2>
                <div class="d-flex gap-2 align-items-center flex-wrap">
                    <select class="form-select form-select-sm w-auto" id="logSelect" aria-label="{{t:lg.whichLog}}" onchange="loadLogs()">
                        <option value="">{{t:common.loading}}</option>
                    </select>
                    <input type="text" class="form-control form-control-sm w-auto" id="logFilter" maxlength="200" placeholder="{{t:lg.filterPlaceholder}}" aria-label="{{t:lg.filter}}" onkeyup="if(event.key==='Enter')loadLogs()">
                    <button class="btn btn-sm btn-mail" onclick="loadLogs()" title="{{t:lg.reload}}" aria-label="{{t:lg.reload}}"><i class="fas fa-sync" aria-hidden="true"></i></button>
                </div>
            </div>

            <!-- Filtri rapidi -->
            <div class="card mb-3 border-info">
                <div class="card-header bg-info text-white py-2 d-flex justify-content-between align-items-center flex-wrap gap-2">
                    <span><i class="fas fa-filter me-2" aria-hidden="true"></i><strong>{{t:lg.quickFilters}}</strong> <small class="text-white-50 ms-2">{{t:lg.quickFiltersHint}}</small></span>
                    <button class="btn btn-sm btn-light" onclick="applyPreset('all', this)" title="{{t:lg.allDesc}}"><i class="fas fa-eye me-1" aria-hidden="true"></i>{{t:lg.showAll}}</button>
                </div>
                <div class="card-body py-2">
                    <div class="log-preset-group mb-2" role="group" aria-labelledby="lgCat0">
                        <span class="log-preset-cat text-danger" id="lgCat0"><i class="fas fa-shield-alt me-1" aria-hidden="true"></i>{{t:lg.catSecurity}}</span>
                        <button type="button" class="btn btn-outline-danger log-preset-btn" data-preset="brute-smtp" aria-pressed="false" onclick="applyPreset('brute-smtp', this)">
                            <i class="fas fa-user-secret me-1" aria-hidden="true"></i>{{t:lg.bruteSmtp}}
                        </button>
                        <button type="button" class="btn btn-outline-danger log-preset-btn" data-preset="brute-imap" aria-pressed="false" onclick="applyPreset('brute-imap', this)">
                            <i class="fas fa-inbox me-1" aria-hidden="true"></i>{{t:lg.bruteImap}}
                        </button>
                        <button type="button" class="btn btn-outline-danger log-preset-btn" data-preset="brute-panel" aria-pressed="false" onclick="applyPreset('brute-panel', this)">
                            <i class="fas fa-lock me-1" aria-hidden="true"></i>{{t:lg.brutePanel}}
                        </button>
                        <button type="button" class="btn btn-outline-danger log-preset-btn" data-preset="banned" aria-pressed="false" onclick="applyPreset('banned', this)">
                            <i class="fas fa-gavel me-1" aria-hidden="true"></i>{{t:lg.banned}}
                        </button>
                    </div>
                    <div class="log-preset-group mb-2" role="group" aria-labelledby="lgCat1">
                        <span class="log-preset-cat text-warning" id="lgCat1"><i class="fas fa-broom me-1" aria-hidden="true"></i>{{t:lg.catNoise}}</span>
                        <button type="button" class="btn btn-outline-warning log-preset-btn" data-preset="scanners" aria-pressed="false" onclick="applyPreset('scanners', this)">
                            <i class="fas fa-satellite-dish me-1" aria-hidden="true"></i>{{t:lg.scanners}}
                        </button>
                        <button type="button" class="btn btn-outline-warning log-preset-btn" data-preset="known-scanners" aria-pressed="false" onclick="applyPreset('known-scanners', this)">
                            <i class="fas fa-robot me-1" aria-hidden="true"></i>{{t:lg.knownScanners}}
                        </button>
                        <button type="button" class="btn btn-outline-warning log-preset-btn" data-preset="anvil" aria-pressed="false" onclick="applyPreset('anvil', this)">
                            <i class="fas fa-chart-line me-1" aria-hidden="true"></i>{{t:lg.anvil}}
                        </button>
                    </div>
                    <div class="log-preset-group mb-2" role="group" aria-labelledby="lgCat2">
                        <span class="log-preset-cat text-success" id="lgCat2"><i class="fas fa-envelope me-1" aria-hidden="true"></i>{{t:lg.catMail}}</span>
                        <button type="button" class="btn btn-outline-success log-preset-btn" data-preset="mail-sent" aria-pressed="false" onclick="applyPreset('mail-sent', this)">
                            <i class="fas fa-paper-plane me-1" aria-hidden="true"></i>{{t:lg.mailSent}}
                        </button>
                        <button type="button" class="btn btn-outline-success log-preset-btn" data-preset="mail-bounce" aria-pressed="false" onclick="applyPreset('mail-bounce', this)">
                            <i class="fas fa-undo me-1" aria-hidden="true"></i>{{t:lg.mailBounce}}
                        </button>
                        <button type="button" class="btn btn-outline-success log-preset-btn" data-preset="spam" aria-pressed="false" onclick="applyPreset('spam', this)">
                            <i class="fas fa-bug me-1" aria-hidden="true"></i>{{t:lg.spam}}
                        </button>
                    </div>
                    <div class="log-preset-group" role="group" aria-labelledby="lgCat3">
                        <span class="log-preset-cat text-primary" id="lgCat3"><i class="fas fa-exclamation-circle me-1" aria-hidden="true"></i>{{t:lg.catDiag}}</span>
                        <button type="button" class="btn btn-outline-primary log-preset-btn" data-preset="errors" aria-pressed="false" onclick="applyPreset('errors', this)">
                            <i class="fas fa-exclamation-triangle me-1" aria-hidden="true"></i>{{t:lg.errors}}
                        </button>
                        <button type="button" class="btn btn-outline-primary log-preset-btn" data-preset="connections" aria-pressed="false" onclick="applyPreset('connections', this)">
                            <i class="fas fa-plug me-1" aria-hidden="true"></i>{{t:lg.connections}}
                        </button>
                        <button type="button" class="btn btn-outline-primary log-preset-btn" data-preset="tls" aria-pressed="false" onclick="applyPreset('tls', this)">
                            <i class="fas fa-lock me-1" aria-hidden="true"></i>{{t:lg.tls}}
                        </button>
                    </div>
                    <div id="filterActiveDesc" class="mt-2 d-none" aria-live="polite"></div>
                </div>
            </div>

            <div class="log-viewer" id="logViewer" tabindex="0" aria-label="{{t:lg.viewer}}">
                <div class="text-muted">{{t:lg.pickLog}}</div>
            </div>

            <!-- Ricerca -->
            <div class="card mt-4">
                <div class="card-header"><i class="fas fa-search me-2" aria-hidden="true"></i>{{t:lg.searchTitle}}</div>
                <div class="card-body">
                    <div class="input-group">
                        <input type="text" class="form-control" id="searchPattern" maxlength="200" placeholder="{{t:lg.searchPlaceholder}}" aria-label="{{t:lg.searchTitle}}" onkeyup="if(event.key==='Enter')searchLogs()">
                        <button class="btn btn-primary" onclick="searchLogs()">{{t:lg.search}}</button>
                    </div>
                    <div id="searchResults" class="mt-3" aria-live="polite"></div>
                </div>
            </div>
        </div>
    </div>
""" + getFooterSection() + """
    <script>
        // Load stats
        fetch('/api/stats').then(r => r.json()).then(data => {
            if (data.success) {
                document.getElementById('statSpam').textContent = data.security.spam_detected;
                document.getElementById('statUsers').textContent = data.imap.active_users;
            }
        });

        // Load available logs — mostra SOLO quelli effettivamente presenti
        fetch('/api/logs').then(r => r.json()).then(data => {
            const select = document.getElementById('logSelect');
            select.innerHTML = '';
            const available = (data.logs || []).filter(log => log.exists);
            if (available.length === 0) {
                const opt = document.createElement('option');
                opt.value = '';
                opt.textContent = t('lg.noLogs');
                opt.disabled = true;
                select.appendChild(opt);
                return;
            }
            available.forEach(log => {
                const opt = document.createElement('option');
                opt.value = log.id;
                opt.textContent = log.description;
                select.appendChild(opt);
            });
        });

        // ===== Filtri preset =====
        // catches: il suggerimento sul pulsante; desc: la spiegazione sotto i filtri.
        const LOG_PRESETS = {
            'all':           { regex: '', catches: t('lg.allDesc'), desc: '' },
            'brute-smtp':    { regex: 'SASL.*authentication failed', catches: t('lg.bruteSmtpCatch'), desc: t('lg.bruteSmtpDesc.html') },
            'brute-imap':    { regex: 'dovecot.*(auth failed|Disconnected.*auth)', catches: t('lg.bruteImapCatch'), desc: t('lg.bruteImapDesc.html') },
            'brute-panel':   { regex: 'mail-panel-auth|AUTH_FAILED', catches: t('lg.brutePanelCatch'), desc: t('lg.brutePanelDesc.html') },
            'banned':        { regex: 'fail2ban.*(Ban |Found )', catches: t('lg.bannedCatch'), desc: t('lg.bannedDesc.html') },
            'scanners':      { regex: 'SSL_accept error|TLS library problem|lost connection after (STARTTLS|EHLO)|http request', catches: t('lg.scannersCatch'), desc: t('lg.scannersDesc.html') },
            'known-scanners':{ regex: 'censys-scanner|shodan|driftnet|internet-?measurement|securitytrails|binaryedge|shadowserver|stretchoid', catches: t('lg.knownScannersCatch'), desc: t('lg.knownScannersDesc.html') },
            'anvil':         { regex: 'postfix/anvil|max connection', catches: t('lg.anvilCatch'), desc: t('lg.anvilDesc.html') },
            'mail-sent':     { regex: 'status=sent|relay=', catches: t('lg.mailSentCatch'), desc: t('lg.mailSentDesc.html') },
            'mail-bounce':   { regex: 'status=(bounced|deferred|rejected)|NOQUEUE.*reject', catches: t('lg.mailBounceCatch'), desc: t('lg.mailBounceDesc.html') },
            'spam':          { regex: 'rspamd|spam|virus|clamav', catches: t('lg.spamCatch'), desc: t('lg.spamDesc.html') },
            'errors':        { regex: 'error|fatal|warning', catches: t('lg.errorsCatch'), desc: t('lg.errorsDesc.html') },
            'connections':   { regex: 'connect from|disconnect from', catches: t('lg.connectionsCatch'), desc: t('lg.connectionsDesc.html') },
            'tls':           { regex: 'TLS|SSL|STARTTLS|cipher', catches: t('lg.tlsCatch'), desc: t('lg.tlsDesc.html') }
        };

        // Il suggerimento di ogni pulsante: l'espressione e cosa trova.
        document.querySelectorAll('.log-preset-btn').forEach(b => {
            const preset = LOG_PRESETS[b.dataset.preset];
            if (preset) b.title = 'REGEX: ' + preset.regex + '\\n' + preset.catches;
        });

        function applyPreset(presetId, btn) {
            const preset = LOG_PRESETS[presetId];
            if (!preset) return;
            document.getElementById('logFilter').value = preset.regex;
            // Evidenzia il pulsante attivo
            document.querySelectorAll('.log-preset-btn').forEach(b => { b.classList.remove('active'); b.setAttribute('aria-pressed', 'false'); });
            if (btn && presetId !== 'all') { btn.classList.add('active'); btn.setAttribute('aria-pressed', 'true'); }
            // Mostra descrizione del filtro
            const descEl = document.getElementById('filterActiveDesc');
            if (presetId === 'all') {
                descEl.classList.add('d-none');
                descEl.innerHTML = '';
            } else {
                descEl.classList.remove('d-none');
                descEl.innerHTML = '<i class="fas fa-info-circle me-1" aria-hidden="true"></i>' + preset.desc +
                    ' &nbsp;<code class="ms-1" style="font-size:.7rem">' + escHtml(preset.regex) + '</code>';
            }
            loadLogs();
        }

        function loadLogs() {
            const logId = document.getElementById('logSelect').value;
            const filter = document.getElementById('logFilter').value;
            if (!logId) return;

            let url = '/api/logs?log=' + encodeURIComponent(logId) + '&lines=200';
            if (filter) url += '&filter=' + encodeURIComponent(filter);

            fetch(url).then(r => r.json()).then(data => {
                const viewer = document.getElementById('logViewer');
                if (!data.entries || data.entries.length === 0) {
                    viewer.innerHTML = '<div class="text-muted">' + escHtml(t('lg.empty')) + '</div>';
                    return;
                }

                // ESCAPE HTML — i log mail contengono spesso "<user@example.com>" che il
                // browser interpreta come tag HTML sconosciuto. Senza escape, tag come <s>
                // o <del> nei log produrrebbero text-decoration line-through indesiderato.
                const escLog = (s) => {
                    if (s == null) return '';
                    const d = document.createElement('div');
                    d.textContent = String(s);
                    return d.innerHTML;
                };
                viewer.innerHTML = data.entries.map(e => {
                    const levelClass = 'log-' + (e.level || 'INFO');
                    const ts = escLog(e.timestamp || '');
                    const proc = e.process ? '[' + escLog(e.process) + '] ' : '';
                    return '<div class="log-entry ' + levelClass + '">' + ts + ' ' + proc + escLog(e.message) + '</div>';
                }).join('');

                viewer.scrollTop = viewer.scrollHeight;
            });
        }

        function searchLogs() {
            const pattern = document.getElementById('searchPattern').value;
            const logId = document.getElementById('logSelect').value || 'maillog';

            fetch('/api/logs', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'search', log_id: logId, pattern: pattern, max_results: 50 })
            }).then(r => r.json()).then(data => {
                const results = document.getElementById('searchResults');
                if (!data.results || data.results.length === 0) {
                    results.innerHTML = '<div class="alert alert-info">' + escHtml(t('lg.noResults')) + '</div>';
                    return;
                }

                // Escape HTML anche qui (i log contengono spesso "<user@example.com>")
                const escSearch = (s) => {
                    if (s == null) return '';
                    const d = document.createElement('div');
                    d.textContent = String(s);
                    return d.innerHTML;
                };
                results.innerHTML = '<div class="log-viewer" style="max-height:200px">' +
                    data.results.map(r => '<div class="log-entry">' + escSearch(r.raw) + '</div>').join('') +
                    '</div>';
            });
        }

        // Auto-refresh every 30 seconds
        setInterval(loadLogs, 30000);

        let csrfToken = document.getElementById('csrf_token').value;
""" + """
    </script>
</body>
</html>
""";
    }

    // ============== INSTALL.HTML ==============
    public static String getInstallHtml() {
        String extraStyles = """
        .install-progress { max-height: 400px; overflow-y: auto; background: #1e1e1e; color: #d4d4d4; padding: 15px; border-radius: 8px; font-family: monospace; font-size: 0.85rem; }
        .component-card { border: 2px solid #dee2e6; border-radius: 8px; padding: 20px; margin-bottom: 15px; transition: all 0.2s; }
        .component-card:hover { border-color: #e94560; }
        .component-card.installed { background: #d4edda; border-color: #198754; }
        [data-theme="dark"] .component-card.installed { background: rgba(25, 135, 84, .18); }
        """;
        return getHead("nav.install", "install", extraStyles) + """
    <div id="main" tabindex="-1" class="content container mt-4">
        <div class="content-container">
            <h2><i class="fas fa-download me-2" aria-hidden="true"></i>{{t:ins.title}}</h2>
            <p class="text-muted">{{t:ins.intro}}</p>

            <div class="alert alert-warning">
                <i class="fas fa-exclamation-triangle me-2" aria-hidden="true"></i>
                {{t:ins.warning.html}}
            </div>

            <div class="row" id="componentsGrid">
                <div class="col-md-6"><div class="component-card" data-component="timezone">
                    <h5><i class="fas fa-clock me-2" aria-hidden="true"></i>{{t:ins.tzDns}}</h5>
                    <p class="text-muted small">{{t:ins.tzDnsDesc}}</p>
                    <button class="btn btn-sm btn-outline-primary" onclick="installComponent('timezone')">{{t:ins.configure}}</button>
                </div></div>
                <div class="col-md-6"><div class="component-card" data-component="postfix">
                    <h5><i class="fas fa-paper-plane me-2" aria-hidden="true"></i>Postfix</h5>
                    <p class="text-muted small">{{t:ins.postfixDesc}}</p>
                    <button class="btn btn-sm btn-outline-primary" onclick="installComponent('postfix')">{{t:ins.install}}</button>
                </div></div>
                <div class="col-md-6"><div class="component-card" data-component="dovecot">
                    <h5><i class="fas fa-inbox me-2" aria-hidden="true"></i>Dovecot</h5>
                    <p class="text-muted small">{{t:ins.dovecotDesc}}</p>
                    <button class="btn btn-sm btn-outline-primary" onclick="installComponent('dovecot')">{{t:ins.install}}</button>
                </div></div>
                <div class="col-md-6"><div class="component-card" data-component="rspamd">
                    <h5><i class="fas fa-shield-alt me-2" aria-hidden="true"></i>Rspamd</h5>
                    <p class="text-muted small">{{t:ins.rspamdDesc}}</p>
                    <button class="btn btn-sm btn-outline-primary" onclick="installComponent('rspamd')">{{t:ins.install}}</button>
                </div></div>
                <div class="col-md-6"><div class="component-card" data-component="clamav">
                    <h5><i class="fas fa-bug me-2" aria-hidden="true"></i>ClamAV</h5>
                    <p class="text-muted small">{{t:ins.clamavDesc}}</p>
                    <button class="btn btn-sm btn-outline-primary" onclick="installComponent('clamav')">{{t:ins.install}}</button>
                </div></div>
                <div class="col-md-6"><div class="component-card" data-component="roundcube">
                    <h5><i class="fas fa-envelope-open-text me-2" aria-hidden="true"></i>Roundcube</h5>
                    <p class="text-muted small">{{t:ins.roundcubeDesc}}</p>
                    <button class="btn btn-sm btn-outline-primary" onclick="installComponent('roundcube')">{{t:ins.install}}</button>
                </div></div>
            </div>

            <hr>
            <div class="text-center">
                <button class="btn btn-lg btn-danger" onclick="installComponent('all')">
                    <i class="fas fa-magic me-2" aria-hidden="true"></i>{{t:ins.all}}
                </button>
            </div>

            <div id="installOutput" class="mt-4 d-none">
                <h5>{{t:ins.output}}</h5>
                <pre class="bg-dark text-light p-3" style="max-height:400px;overflow-y:auto" id="outputText"></pre>
            </div>
        </div>
    </div>
""" + getFooterSection() + """
    <script>
        let csrfToken = document.getElementById('csrf_token').value;

        function installComponent(component) {
            if (!confirm(t('ins.confirm', { component: component }))) return;

            document.getElementById('installOutput').classList.remove('d-none');
            document.getElementById('outputText').textContent = t('ins.running');

            fetch('/api/install', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ component: component, csrf_token: csrfToken })
            }).then(r => r.json()).then(data => {
                document.getElementById('outputText').textContent = data.output || data.error || t('common.done');
                if (data.success) {
                    alert(t('ins.done'));
                }
            });
        }
""" + """
    </script>
</body>
</html>
""";
    }

    // ============== SETTINGS.HTML ==============
    /**
     * Il JavaScript della scheda "Rapporto periodico". Sta in un metodo suo per due
     * ragioni: la pagina Impostazioni superava i 65535 byte di un singolo letterale
     * (limite del formato .class), e una chiamata a metodo interrompe la fusione che
     * javac fa dei letterali adiacenti, che e' il motivo per cui spezzare il testo
     * in due pezzi affiancati non basterebbe.
     */

    public static String getSettingsHtml() {
        return getHead("nav.settings", "settings", "") + """
    <div id="main" tabindex="-1" class="content container mt-4">
        <div class="content-container">
            <h2><i class="fas fa-cog me-2" aria-hidden="true"></i>{{t:nav.settings}}</h2>
            <p class="text-muted">{{t:set.intro}}</p>

            <div class="card mb-4 mb-4 border-success">
""" + resource("pages/report-card.html") + """
                <div class="card-body">
                    <p class="small text-muted mb-2">{{t:set.reportIntro.html}}</p>
                    <div id="rep-body" aria-live="polite"><span class="text-muted">{{t:set.reportPress}}</span></div>
                </div>
            </div>
            <div class="row">
                <div class="col-md-6">
""" + getVaultManagementCard() + """
                </div>

                <div class="col-md-6">
                    <!-- Mail Hostname -->
                    <div class="card mb-4">
                        <div class="card-header"><i class="fas fa-server me-2" aria-hidden="true"></i>{{t:set.mailHostname}}</div>
                        <div class="card-body">
                            <div class="d-flex align-items-center mb-2">
                                <div class="form-control bg-light flex-grow-1" id="mailHostnameDisplay">
                                    {{MAIL_HOSTNAME}}
                                </div>
                                <button class="btn btn-outline-primary btn-sm ms-2" onclick="openChangeHostname()" title="{{t:set.changeHostnameShort}}" aria-label="{{t:set.changeHostnameShort}}">
                                    <i class="fas fa-edit" aria-hidden="true"></i>
                                </button>
                            </div>
                            <div id="hostnameConsistency" class="mb-2" style="display:none;"></div>
                            <small class="text-muted"><i class="fas fa-info-circle me-1" aria-hidden="true"></i>{{t:set.mailHostnameHint}}</small>
                        </div>
                    </div>

                    <!-- Roundcube Domain -->
                    <div class="card mb-4">
                        <div class="card-header"><i class="fas fa-envelope-open-text me-2" aria-hidden="true"></i>{{t:set.rcDomain}}</div>
                        <div class="card-body">
                            <div class="d-flex align-items-center mb-2">
                                <div class="form-control bg-light flex-grow-1" id="rcDomainDisplay">
                                    {{ROUNDCUBE_DOMAIN}}
                                </div>
                                <button class="btn btn-outline-primary btn-sm ms-2" onclick="openChangeRcDomain()" title="{{t:set.changeRcShort}}" aria-label="{{t:set.changeRcShort}}">
                                    <i class="fas fa-edit" aria-hidden="true"></i>
                                </button>
                            </div>
                            <div id="rcDomainDns" class="mb-2" style="display:none;"></div>
                            <small class="text-muted"><i class="fas fa-info-circle me-1" aria-hidden="true"></i>{{t:set.rcDomainHint}}</small>
                        </div>
                    </div>

                    <!-- System Info -->
                    <div class="card">
                        <div class="card-header"><i class="fas fa-info-circle me-2" aria-hidden="true"></i>{{t:set.sysInfo}}</div>
                        <div class="card-body">
                            <table class="table table-sm mb-0">
                                <tr><td><strong>{{t:set.version}}</strong></td><td>1.0</td></tr>
                                <tr><td><strong>{{t:set.database}}</strong></td><td>{{DATABASE}}</td></tr>
                                <tr><td><strong>{{t:set.platform}}</strong></td><td>{{PLATFORM}}</td></tr>
                                <tr><td><strong>Java:</strong></td><td id="javaVersion">{{JAVA_VERSION}}</td></tr>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Change Hostname Modal -->
    <div class="modal fade" id="changeHostnameModal" tabindex="-1">
        <div class="modal-dialog modal-lg modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-exchange-alt me-2" aria-hidden="true"></i>{{t:set.changeHostnameTitle}}</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="{{t:common.close}}"></button>
                </div>
                <div class="modal-body">
                    <!-- Step 1: Input -->
                    <div id="hostnameStep1">
                        <div class="alert alert-warning">
                            <i class="fas fa-exclamation-triangle me-2" aria-hidden="true"></i>
                            {{t:set.hostnameWarning.html}}
                        </div>

                        <div id="hostnameCurrentState" class="mb-3">
                            <h6><i class="fas fa-info-circle me-2" aria-hidden="true"></i>{{t:set.currentState}}</h6>
                            <table class="table table-sm table-bordered">
                                <tr><td><strong>SQLite</strong></td><td id="hsCurSqlite">-</td><td id="hsCurSqliteIcon"></td></tr>
                                <tr><td><strong>MySQL</strong></td><td id="hsCurMysql">-</td><td id="hsCurMysqlIcon"></td></tr>
                                <tr><td><strong>Postfix (main.cf)</strong></td><td id="hsCurPostfix">-</td><td id="hsCurPostfixIcon"></td></tr>
                                <tr><td><strong>{{t:set.sslCert}}</strong></td><td id="hsCurSsl">-</td><td id="hsCurSslIcon"></td></tr>
                            </table>
                        </div>

                        <div class="mb-3">
                            <label class="form-label" for="newHostnameInput"><strong>{{t:set.newHostname}}</strong></label>
                            <input type="text" class="form-control" id="newHostnameInput" placeholder="mail.example.com">
                            <small class="text-muted">{{t:set.newHostnameHint}}</small>
                        </div>

                        <button class="btn btn-primary w-100" onclick="executeHostnameChange()">
                            <i class="fas fa-play me-1" aria-hidden="true"></i>{{t:set.changeHostnameShort}}
                        </button>
                    </div>

                    <!-- Step 2: Progress -->
                    <div id="hostnameStep2" style="display:none;">
                        <div class="text-center mb-3">
                            <div class="spinner-border text-primary" role="status"></div>
                            <p class="mt-2">{{t:set.hostnameChanging}}</p>
                        </div>
                    </div>

                    <!-- Step 3: Results -->
                    <div id="hostnameStep3" style="display:none;">
                        <h6><i class="fas fa-clipboard-check me-2" aria-hidden="true"></i>{{t:set.autoDone}}</h6>
                        <div id="hostnameAutoSteps" class="mb-3"></div>

                        <hr>
                        <h6><i class="fas fa-hand-point-right me-2" aria-hidden="true"></i>{{t:set.manualNeeded}}</h6>
                        <p class="text-muted">{{t:set.manualIntro}}</p>
                        <div id="hostnameManualActions" class="mb-3"></div>

                        <hr>
                        <h6><i class="fas fa-stethoscope me-2" aria-hidden="true"></i>{{t:set.dnsCheck}}</h6>
                        <p class="text-muted">{{t:set.dnsCheckIntro}}</p>
                        <button class="btn btn-info w-100 mb-2" onclick="checkHostnameDns()">
                            <i class="fas fa-search me-1" aria-hidden="true"></i>{{t:set.checkDnsRecords}}
                        </button>
                        <div id="hostnameDnsChecks" style="display:none;"></div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">{{t:common.close}}</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Change Roundcube Domain Modal -->
    <div class="modal fade" id="changeRcDomainModal" tabindex="-1">
        <div class="modal-dialog modal-lg modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-envelope-open-text me-2" aria-hidden="true"></i>{{t:set.changeRcTitle}}</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="{{t:common.close}}"></button>
                </div>
                <div class="modal-body">
                    <!-- Step 1: Input -->
                    <div id="rcDomainStep1">
                        <div class="alert alert-info">
                            <i class="fas fa-info-circle me-2" aria-hidden="true"></i>
                            {{t:set.rcInfo.html}}
                        </div>

                        <div class="mb-3">
                            <label class="form-label"><strong>{{t:set.currentDomain}}</strong></label>
                            <div class="form-control bg-light" id="rcDomainCurrent">-</div>
                        </div>
                        <div class="mb-3" id="rcDomainDnsStatus" style="display:none;"></div>

                        <div class="mb-3">
                            <label class="form-label" for="newRcDomainInput"><strong>{{t:set.newDomain}}</strong></label>
                            <input type="text" class="form-control" id="newRcDomainInput" placeholder="webmail.example.com">
                            <small class="text-muted">{{t:set.newDomainHint}}</small>
                        </div>

                        <button class="btn btn-primary w-100 mb-3" onclick="executeRcDomainChange()">
                            <i class="fas fa-play me-1" aria-hidden="true"></i>{{t:set.changeRcTitle}}
                        </button>

                        <hr>
                        <h6><i class="fas fa-lock me-2" aria-hidden="true"></i>{{t:set.rcSsl}}</h6>
                        <p class="text-muted small">{{t:set.rcSslIntro}}</p>
                        <small class="text-muted mb-2 d-block" id="rcSslPathInfo"></small>
                        <div class="mb-2">
                            <label class="form-label small" for="rcSslCertInput"><strong>{{t:set.certFullchain}}</strong></label>
                            <textarea class="form-control form-control-sm font-monospace" id="rcSslCertInput" rows="4" placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"></textarea>
                        </div>
                        <div class="mb-2">
                            <label class="form-label small" for="rcSslKeyInput"><strong>{{t:set.privKey}}</strong></label>
                            <textarea class="form-control form-control-sm font-monospace" id="rcSslKeyInput" rows="4" placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----"></textarea>
                        </div>
                        <div class="mb-3">
                            <label class="form-label small" for="rcSslChainInput"><strong>{{t:set.caChain}}</strong></label>
                            <textarea class="form-control form-control-sm font-monospace" id="rcSslChainInput" rows="3" placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"></textarea>
                        </div>
                        <button class="btn btn-warning w-100" onclick="executeRcSslChange()">
                            <i class="fas fa-lock me-1" aria-hidden="true"></i>{{t:set.saveSsl}}
                        </button>
                    </div>

                    <!-- Step 2: Progress -->
                    <div id="rcDomainStep2" style="display:none;">
                        <div class="text-center mb-3">
                            <div class="spinner-border text-primary" role="status"></div>
                            <p class="mt-2">{{t:set.updating}}</p>
                        </div>
                    </div>

                    <!-- Step 3: Results -->
                    <div id="rcDomainStep3" style="display:none;">
                        <h6><i class="fas fa-clipboard-check me-2" aria-hidden="true"></i>{{t:set.autoDone}}</h6>
                        <div id="rcDomainAutoSteps" class="mb-3"></div>

                        <hr>
                        <h6><i class="fas fa-hand-point-right me-2" aria-hidden="true"></i>{{t:set.manualNeeded}}</h6>
                        <div id="rcDomainManualActions" class="mb-3"></div>

                        <hr>
                        <h6><i class="fas fa-stethoscope me-2" aria-hidden="true"></i>{{t:set.dnsCheck}}</h6>
                        <p class="text-muted">{{t:set.dnsCheckIntro2}}</p>
                        <button class="btn btn-info w-100 mb-2" onclick="checkRcDomainDns()">
                            <i class="fas fa-search me-1" aria-hidden="true"></i>{{t:set.checkRcDns}}
                        </button>
                        <div id="rcDomainDnsChecks" style="display:none;"></div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">{{t:common.close}}</button>
                </div>
            </div>
        </div>
    </div>

""" + getAccountModals() + getFooterSection() + """
    <script>
""" + getWebAuthnScript() + getSettingsAuthJs() + """
""" + getSettingsHostnameJs() + """
        // Load on page load
""" + resource("pages/report.js") + """
        checkHostnameConsistency();
        checkRcDomainDnsStatus();
        repLoad();

        let csrfToken = document.getElementById('csrf_token').value;
""" + """
    </script>
</body>
</html>
""";
    }

    // ============== QUEUE.HTML ==============
    /**
     * JS della pagina Impostazioni per il cambio di hostname e del dominio di Roundcube.
     * Metodo a parte: col resto della pagina il text block sforava il constant pool.
     */
    private static String getSettingsHostnameJs() {
        return """
        // ========== HOSTNAME CHANGE FUNCTIONS ==========

        let hostnameChangeData = null;

        function checkHostnameConsistency() {
            fetch('/api/hostname')
                .then(r => r.json())
                .then(data => {
                    if (!data.success) return;
                    const div = document.getElementById('hostnameConsistency');
                    if (!data.consistent && data.sqlite_hostname) {
                        div.style.display = 'block';
                        div.innerHTML = '<div class="alert alert-warning alert-sm py-1 px-2 mb-0">' +
                            '<i class="fas fa-exclamation-triangle me-1" aria-hidden="true"></i>' +
                            '<small>' + escHtml(t('set.hostnameMismatch')) + '</small></div>';
                    } else {
                        div.style.display = 'none';
                    }
                })
                .catch(() => {});
        }

        // Un'icona di stato con il suo significato per chi non la vede.
        function setMark(icon, text) {
            return '<i class="fas fa-' + icon + '" aria-hidden="true"></i><span class="visually-hidden">' + escHtml(text) + '</span>';
        }

        function openChangeHostname() {
            // Reset to step 1
            document.getElementById('hostnameStep1').style.display = 'block';
            document.getElementById('hostnameStep2').style.display = 'none';
            document.getElementById('hostnameStep3').style.display = 'none';

            // Load current state
            fetch('/api/hostname')
                .then(r => r.json())
                .then(data => {
                    if (!data.success) return;

                    const setCell = (id, val) => {
                        const el = document.getElementById(id);
                        el.textContent = val || t('server.notConfigured');
                    };
                    const setIcon = (id, val, ref) => {
                        const el = document.getElementById(id);
                        if (!val || !ref) {
                            el.innerHTML = setMark('minus text-muted', t('set.na'));
                        } else if (val === ref) {
                            el.innerHTML = setMark('check-circle text-success', t('set.aligned'));
                        } else {
                            el.innerHTML = setMark('times-circle text-danger', t('set.notAligned'));
                        }
                    };

                    const ref = data.sqlite_hostname || data.mysql_hostname || '';
                    setCell('hsCurSqlite', data.sqlite_hostname);
                    setCell('hsCurMysql', data.mysql_hostname);
                    setCell('hsCurPostfix', data.postfix_hostname);
                    setCell('hsCurSsl', data.ssl_cn || data.ssl_hostname || t('set.na'));

                    setIcon('hsCurSqliteIcon', data.sqlite_hostname, ref);
                    setIcon('hsCurMysqlIcon', data.mysql_hostname, ref);
                    setIcon('hsCurPostfixIcon', data.postfix_hostname, ref || data.postfix_hostname);
                    // SSL: compare with ref
                    const sslVal = data.ssl_cn || data.ssl_hostname || '';
                    if (sslVal && ref && sslVal === ref) {
                        document.getElementById('hsCurSslIcon').innerHTML = setMark('check-circle text-success', t('set.aligned'));
                    } else if (sslVal) {
                        document.getElementById('hsCurSslIcon').innerHTML = setMark('exclamation-circle text-warning', t('set.sslDiffers'));
                    } else {
                        document.getElementById('hsCurSslIcon').innerHTML = setMark('minus text-muted', t('set.na'));
                    }

                    // Pre-fill with current hostname
                    document.getElementById('newHostnameInput').value = ref;
                });

            new bootstrap.Modal(document.getElementById('changeHostnameModal')).show();
        }

        function executeHostnameChange() {
            const newHostname = document.getElementById('newHostnameInput').value.trim().toLowerCase();
            if (!newHostname || !newHostname.includes('.')) {
                alert(t('set.needHostname'));
                return;
            }

            const currentHostname = document.getElementById('mailHostnameDisplay').textContent.trim();
            if (newHostname === currentHostname) {
                if (!confirm(t('set.confirmRealignHost'))) return;
            } else {
                if (!confirm(t('set.confirmChangeHost', { from: currentHostname, to: newHostname }))) return;
            }

            // Show progress
            document.getElementById('hostnameStep1').style.display = 'none';
            document.getElementById('hostnameStep2').style.display = 'block';
            document.getElementById('hostnameStep3').style.display = 'none';

            fetch('/api/hostname', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action: 'change',
                    hostname: newHostname,
                    csrf_token: csrfToken
                })
            })
            .then(r => r.json())
            .then(data => {
                hostnameChangeData = data;

                // Show results
                document.getElementById('hostnameStep2').style.display = 'none';
                document.getElementById('hostnameStep3').style.display = 'block';

                // Render auto steps
                const stepsDiv = document.getElementById('hostnameAutoSteps');
                if (data.steps) {
                    stepsDiv.innerHTML = data.steps.map(s => {
                        const icon = s.success
                            ? setMark('check-circle text-success me-2', t('dns.succeeded'))
                            : setMark('times-circle text-danger me-2', t('dns.failed'));
                        return '<div class="d-flex align-items-start mb-2">' + icon +
                            '<div><strong>' + escapeHtml(s.step) + '</strong><br><small class="text-muted">' +
                            escapeHtml(s.detail) + '</small></div></div>';
                    }).join('');
                }

                // Render manual actions
                const actionsDiv = document.getElementById('hostnameManualActions');
                if (data.manual_actions) {
                    actionsDiv.innerHTML = data.manual_actions.map((a, i) => {
                        let icon = '<i class="fas fa-globe text-primary me-2" aria-hidden="true"></i>';
                        if (a.type === 'ssl') icon = '<i class="fas fa-lock text-warning me-2" aria-hidden="true"></i>';
                        if (a.type === 'verify') icon = '<i class="fas fa-check-double text-info me-2" aria-hidden="true"></i>';
                        if (a.type === 'roundcube') icon = '<i class="fas fa-envelope-open-text text-info me-2" aria-hidden="true"></i>';
                        return '<div class="d-flex align-items-start mb-2 p-2 bg-light rounded">' +
                            '<div class="me-2"><strong>' + (i + 1) + '.</strong></div>' + icon +
                            '<div><strong>' + escapeHtml(a.action) + '</strong><br><small>' +
                            escapeHtml(a.detail) + '</small></div></div>';
                    }).join('');
                }

                // Update display on the settings page
                if (data.success && data.new_hostname) {
                    document.getElementById('mailHostnameDisplay').textContent = data.new_hostname;
                }
            })
            .catch(err => {
                document.getElementById('hostnameStep2').style.display = 'none';
                document.getElementById('hostnameStep1').style.display = 'block';
                alert(t('common.error', { message: err.message }));
            });
        }

        function checkHostnameDns() {
            const hostname = hostnameChangeData ? hostnameChangeData.new_hostname : document.getElementById('mailHostnameDisplay').textContent.trim();
            const checksDiv = document.getElementById('hostnameDnsChecks');
            checksDiv.style.display = 'block';
            checksDiv.innerHTML = '<div class="text-center"><i class="fas fa-spinner fa-spin" aria-hidden="true"></i> ' + escHtml(t('set.checking')) + '</div>';

            fetch('/api/hostname', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action: 'check_dns',
                    hostname: hostname,
                    csrf_token: csrfToken
                })
            })
            .then(r => r.json())
            .then(data => {
                if (!data.success) {
                    checksDiv.innerHTML = '<div class="alert alert-danger">' + escHtml(data.error || t('common.errorShort')) + '</div>';
                    return;
                }

                let html = '<table class="table table-sm table-bordered mt-2">';
                html += '<thead><tr><th scope="col">' + escHtml(t('set.colType')) + '</th><th scope="col">' + escHtml(t('set.colName')) + '</th><th scope="col">' + escHtml(t('set.colCurrent')) + '</th>'
                    + '<th scope="col">' + escHtml(t('set.colExpected')) + '</th><th scope="col">' + escHtml(t('set.colState')) + '</th></tr></thead><tbody>';
                data.checks.forEach(c => {
                    const icon = c.passed
                        ? setMark('check-circle text-success', t('dns.succeeded'))
                        : setMark('times-circle text-danger', t('dns.failed'));
                    html += '<tr><td><code>' + escHtml(c.type) + '</code></td><td>' + escapeHtml(c.name) +
                        '</td><td><small>' + escapeHtml(c.current) + '</small></td><td><small>' +
                        escapeHtml(c.expected) + '</small></td><td class="text-center">' + icon + '</td></tr>';
                });
                html += '</tbody></table>';

                if (data.all_passed) {
                    html += '<div class="alert alert-success mt-2"><i class="fas fa-check-circle me-2" aria-hidden="true"></i>' + escHtml(t('set.dnsAllOk')) + '</div>';
                } else {
                    html += '<div class="alert alert-warning mt-2"><i class="fas fa-exclamation-triangle me-2" aria-hidden="true"></i>' + escHtml(t('set.dnsSomeMissing')) + '</div>';
                }

                checksDiv.innerHTML = html;
            })
            .catch(err => {
                checksDiv.innerHTML = '<div class="alert alert-danger">' + escHtml(t('common.error', { message: err.message })) + '</div>';
            });
        }

        // ===== Roundcube Domain Functions =====
        let rcDomainChangeData = null;

        function checkRcDomainDnsStatus() {
            fetch('/api/roundcube-domain')
                .then(r => r.json())
                .then(data => {
                    if (!data.success) return;
                    const el = document.getElementById('rcDomainDns');
                    if (data.domain && data.domain !== t('server.notConfigured')) {
                        el.style.display = 'block';
                        if (data.dns_ok && data.dns_proxied) {
                            el.innerHTML = '<span class="badge bg-info"><i class="fas fa-cloud me-1" aria-hidden="true"></i>DNS OK (Proxy/CDN) - ' + escapeHtml(data.domain) + ' -> ' + escapeHtml(data.dns_result) + '</span>';
                        } else if (data.dns_ok) {
                            el.innerHTML = '<span class="badge bg-success"><i class="fas fa-check-circle me-1" aria-hidden="true"></i>DNS OK - ' + escapeHtml(data.domain) + ' -> ' + escapeHtml(data.dns_result) + '</span>';
                        } else {
                            el.innerHTML = '<span class="badge bg-danger"><i class="fas fa-times-circle me-1" aria-hidden="true"></i>' + escHtml(t('set.dnsNotSetFor', { domain: data.domain })) + '</span>';
                        }
                    }
                });
        }

        function openChangeRcDomain() {
            // Reset modal state
            document.getElementById('rcDomainStep1').style.display = 'block';
            document.getElementById('rcDomainStep2').style.display = 'none';
            document.getElementById('rcDomainStep3').style.display = 'none';
            rcDomainChangeData = null;

            // Load current state
            fetch('/api/roundcube-domain')
                .then(r => r.json())
                .then(data => {
                    if (!data.success) return;
                    document.getElementById('rcDomainCurrent').textContent = data.domain || t('server.notConfigured');
                    document.getElementById('newRcDomainInput').value = data.domain || '';

                    const dnsEl = document.getElementById('rcDomainDnsStatus');
                    if (data.domain) {
                        dnsEl.style.display = 'block';
                        if (data.dns_ok && data.dns_proxied) {
                            dnsEl.innerHTML = '<div class="alert alert-info py-2 mb-0"><i class="fas fa-cloud me-1" aria-hidden="true"></i>DNS OK (Proxy/CDN): <code>' + escapeHtml(data.domain) + '</code> -> <code>' + escapeHtml(data.dns_result) + '</code></div>';
                        } else if (data.dns_ok) {
                            dnsEl.innerHTML = '<div class="alert alert-success py-2 mb-0"><i class="fas fa-check-circle me-1" aria-hidden="true"></i>DNS OK: <code>' + escapeHtml(data.domain) + '</code> -> <code>' + escapeHtml(data.dns_result) + '</code></div>';
                        } else {
                            dnsEl.innerHTML = '<div class="alert alert-danger py-2 mb-0"><i class="fas fa-times-circle me-1" aria-hidden="true"></i>' + escHtml(t('set.dnsNotSetFor', { domain: data.domain })) + '</div>';
                        }
                    }

                    // Populate SSL fields with file contents
                    document.getElementById('rcSslCertInput').value = data.ssl_cert_content || '';
                    document.getElementById('rcSslKeyInput').value = data.ssl_key_content || '';
                    document.getElementById('rcSslChainInput').value = data.ssl_chain_content || '';
                    const sslPath = data.nginx_ssl_cert || '';
                    document.getElementById('rcSslPathInfo').textContent = sslPath ? t('set.currentFiles', { files: sslPath + ', ' + (data.nginx_ssl_key || '') }) : '';
                });

            new bootstrap.Modal(document.getElementById('changeRcDomainModal')).show();
        }

        function executeRcDomainChange() {
            const newDomain = document.getElementById('newRcDomainInput').value.trim().toLowerCase();
            if (!newDomain || !newDomain.includes('.')) {
                alert(t('set.needDomain'));
                return;
            }

            const currentDomain = document.getElementById('rcDomainCurrent').textContent.trim();
            if (newDomain === currentDomain) {
                if (!confirm(t('set.confirmRealignRc'))) return;
            } else {
                if (!confirm(t('set.confirmChangeRc', { from: currentDomain, to: newDomain }))) return;
            }

            // Show progress
            document.getElementById('rcDomainStep1').style.display = 'none';
            document.getElementById('rcDomainStep2').style.display = 'block';
            document.getElementById('rcDomainStep3').style.display = 'none';

            fetch('/api/roundcube-domain', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action: 'change',
                    domain: newDomain,
                    csrf_token: csrfToken
                })
            })
            .then(r => r.json())
            .then(data => {
                rcDomainChangeData = data;

                document.getElementById('rcDomainStep2').style.display = 'none';
                document.getElementById('rcDomainStep3').style.display = 'block';

                // Render auto steps
                const stepsDiv = document.getElementById('rcDomainAutoSteps');
                if (data.steps) {
                    stepsDiv.innerHTML = data.steps.map(s => {
                        const icon = s.success
                            ? setMark('check-circle text-success me-2', t('dns.succeeded'))
                            : setMark('times-circle text-danger me-2', t('dns.failed'));
                        return '<div class="d-flex align-items-start mb-2">' + icon +
                            '<div><strong>' + escapeHtml(s.step) + '</strong><br><small class="text-muted">' +
                            escapeHtml(s.detail) + '</small></div></div>';
                    }).join('');
                }

                // Render manual actions
                const actionsDiv = document.getElementById('rcDomainManualActions');
                if (data.manual_actions) {
                    actionsDiv.innerHTML = data.manual_actions.map((a, i) => {
                        let icon = '<i class="fas fa-globe text-primary me-2" aria-hidden="true"></i>';
                        if (a.type === 'ssl') icon = '<i class="fas fa-lock text-warning me-2" aria-hidden="true"></i>';
                        return '<div class="d-flex align-items-start mb-2 p-2 bg-light rounded">' +
                            '<div class="me-2"><strong>' + (i + 1) + '.</strong></div>' + icon +
                            '<div><strong>' + escapeHtml(a.action) + '</strong><br><small>' +
                            escapeHtml(a.detail) + '</small></div></div>';
                    }).join('');
                }

                // Update display
                if (data.success && data.new_domain) {
                    document.getElementById('rcDomainDisplay').textContent = data.new_domain;
                    checkRcDomainDnsStatus();
                }
            })
            .catch(err => {
                document.getElementById('rcDomainStep2').style.display = 'none';
                document.getElementById('rcDomainStep1').style.display = 'block';
                alert(t('common.error', { message: err.message }));
            });
        }

        function checkRcDomainDns() {
            const domain = rcDomainChangeData ? rcDomainChangeData.new_domain : document.getElementById('rcDomainDisplay').textContent.trim();
            const checksDiv = document.getElementById('rcDomainDnsChecks');
            checksDiv.style.display = 'block';
            checksDiv.innerHTML = '<div class="text-center"><i class="fas fa-spinner fa-spin" aria-hidden="true"></i> ' + escHtml(t('set.checking')) + '</div>';

            fetch('/api/roundcube-domain', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action: 'check_dns',
                    domain: domain,
                    csrf_token: csrfToken
                })
            })
            .then(r => r.json())
            .then(data => {
                if (!data.success) {
                    checksDiv.innerHTML = '<div class="alert alert-danger">' + escHtml(data.error || t('common.errorShort')) + '</div>';
                    return;
                }

                let html = '';
                if (data.a_ok && data.a_proxied) {
                    html += '<div class="alert alert-info"><i class="fas fa-cloud me-2" aria-hidden="true"></i>' + escHtml(t('set.rcAProxied', { domain: data.domain })) + '</div>';
                } else if (data.a_ok) {
                    html += '<div class="alert alert-success"><i class="fas fa-check-circle me-2" aria-hidden="true"></i>' + escHtml(t('set.rcAOk', { domain: data.domain, ip: data.server_ip })) + '</div>';
                } else {
                    html += '<div class="alert alert-danger"><i class="fas fa-times-circle me-2" aria-hidden="true"></i>' + escHtml(t('set.rcANone', { domain: data.domain })) + '<br>';
                    html += '<small class="text-muted">' + escHtml(t('set.rcAHint', { name: String(data.domain || '').split('.')[0], ip: data.server_ip || t('set.serverIp') })) + '</small></div>';
                }
                checksDiv.innerHTML = html;
            })
            .catch(err => {
                checksDiv.innerHTML = '<div class="alert alert-danger">' + escHtml(t('common.error', { message: err.message })) + '</div>';
            });
        }

        function executeRcSslChange() {
            const sslCert = document.getElementById('rcSslCertInput').value.trim();
            const sslKey = document.getElementById('rcSslKeyInput').value.trim();
            const sslChain = document.getElementById('rcSslChainInput').value.trim();

            if (!sslCert && !sslKey) {
                if (!confirm(t('set.confirmEmptySsl'))) return;
            }
            if ((sslCert && !sslKey) || (!sslCert && sslKey)) {
                alert(t('set.needBoth'));
                return;
            }
            if (sslCert && !sslCert.includes('BEGIN')) {
                alert(t('set.certPem'));
                return;
            }
            if (sslKey && !sslKey.includes('BEGIN')) {
                alert(t('set.keyPem'));
                return;
            }

            // Show progress
            document.getElementById('rcDomainStep1').style.display = 'none';
            document.getElementById('rcDomainStep2').style.display = 'block';
            document.getElementById('rcDomainStep3').style.display = 'none';

            fetch('/api/roundcube-domain', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action: 'update_ssl',
                    ssl_cert: sslCert,
                    ssl_key: sslKey,
                    ssl_chain: sslChain,
                    csrf_token: csrfToken
                })
            })
            .then(r => r.json())
            .then(data => {
                document.getElementById('rcDomainStep2').style.display = 'none';
                document.getElementById('rcDomainStep3').style.display = 'block';

                const stepsDiv = document.getElementById('rcDomainAutoSteps');
                if (data.steps) {
                    stepsDiv.innerHTML = data.steps.map(s => {
                        const icon = s.success
                            ? setMark('check-circle text-success me-2', t('dns.succeeded'))
                            : setMark('times-circle text-danger me-2', t('dns.failed'));
                        return '<div class="d-flex align-items-start mb-2">' + icon +
                            '<div><strong>' + escapeHtml(s.step) + '</strong><br><small class="text-muted">' +
                            escapeHtml(s.detail) + '</small></div></div>';
                    }).join('');
                }

                document.getElementById('rcDomainManualActions').innerHTML =
                    data.success
                        ? '<div class="alert alert-success py-2"><i class="fas fa-check-circle me-1" aria-hidden="true"></i>' + escHtml(t('set.sslUpdated')) + '</div>'
                        : '<div class="alert alert-danger py-2"><i class="fas fa-times-circle me-1" aria-hidden="true"></i>' + escHtml(t('common.error', { message: data.error || t('set.checkLogs') })) + '</div>';
            })
            .catch(err => {
                document.getElementById('rcDomainStep2').style.display = 'none';
                document.getElementById('rcDomainStep1').style.display = 'block';
                alert(t('common.error', { message: err.message }));
            });
        }

""";
    }

    public static String getQueueHtml() {
        String extraStyles = """
        .stat-card { border-left: 4px solid transparent; }
        .stat-total { border-left-color: #6c757d; }
        .stat-active { border-left-color: #0dcaf0; }
        .stat-deferred { border-left-color: #fd7e14; }
        .stat-hold { border-left-color: #0d6efd; }
        .queue-state { font-size: 0.75rem; padding: 2px 8px; border-radius: 3px; white-space: nowrap; }
        .state-active { background: #d1ecf1; color: #0c5460; }
        .state-deferred { background: #ffe5d0; color: #8a4600; }
        .state-hold { background: #cce5ff; color: #004085; }
        .state-incoming { background: #fff3cd; color: #856404; }
        .state-corrupt { background: #f8d7da; color: #721c24; }
        .state-unknown { background: #e2e3e5; color: #383d41; }
        .queue-preview { max-height: 240px; overflow: auto; }
        .queue-recipients { list-style: none; padding-left: 0; margin-bottom: 0; }
        """;
        return getHead("nav.queue", "queue", extraStyles) + """
    <div id="main" tabindex="-1" class="content container mt-4">
        <div class="content-container">
            <div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-2">
                <h2 class="mb-0"><i class="fas fa-list-ol me-2" aria-hidden="true"></i>{{t:que.title}}</h2>
                <div class="d-flex flex-wrap gap-2">
                    <button type="button" class="btn btn-success btn-sm" id="flushBtn" onclick="flushQueue()">
                        <i class="fas fa-play" aria-hidden="true"></i> {{t:que.flush}}
                    </button>
                    <button type="button" class="btn btn-warning btn-sm" id="holdBtn" onclick="holdAll()">
                        <i class="fas fa-pause" aria-hidden="true"></i> {{t:que.hold}}
                    </button>
                    <button type="button" class="btn btn-primary btn-sm" id="releaseBtn" onclick="releaseAll()">
                        <i class="fas fa-play" aria-hidden="true"></i> {{t:que.release}}
                    </button>
                    <button type="button" class="btn btn-danger btn-sm" id="purgeBtn" onclick="purgePermfails()">
                        <i class="fas fa-trash" aria-hidden="true"></i> {{t:que.purge}}
                    </button>
                </div>
            </div>
            <p class="text-muted small mb-3">{{t:que.intro}}</p>
            <div id="queueMsg" role="status" aria-live="polite"></div>

            <div class="row g-3 mb-4" id="statsRow">
                <div class="col-6 col-md-3">
                    <div class="card stat-card stat-total h-100">
                        <div class="card-body text-center">
                            <p class="h3 mb-0" id="statTotal">-</p>
                            <small class="text-muted">{{t:que.statTotal}}</small>
                        </div>
                    </div>
                </div>
                <div class="col-6 col-md-3">
                    <div class="card stat-card stat-active h-100">
                        <div class="card-body text-center">
                            <p class="h3 mb-0" id="statActive">-</p>
                            <small class="text-muted">{{t:que.statActive}}</small>
                        </div>
                    </div>
                </div>
                <div class="col-6 col-md-3">
                    <div class="card stat-card stat-deferred h-100">
                        <div class="card-body text-center">
                            <p class="h3 mb-0" id="statDeferred">-</p>
                            <small class="text-muted">{{t:que.statDeferred}}</small>
                            <small class="d-block text-danger" id="statPermanent"></small>
                        </div>
                    </div>
                </div>
                <div class="col-6 col-md-3">
                    <div class="card stat-card stat-hold h-100">
                        <div class="card-body text-center">
                            <p class="h3 mb-0" id="statHold">-</p>
                            <small class="text-muted">{{t:que.statHold}}</small>
                        </div>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span id="queueTableTitle">{{t:que.messages}}</span>
                    <button type="button" class="btn btn-sm btn-outline-secondary" onclick="refreshQueue()">
                        <i class="fas fa-sync" aria-hidden="true"></i> {{t:common.refresh}}
                    </button>
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-hover tabella-schede" id="queueTable" aria-labelledby="queueTableTitle">
                            <thead>
                                <tr>
                                    <th scope="col">{{t:que.colId}}</th>
                                    <th scope="col">{{t:que.colState}}</th>
                                    <th scope="col">{{t:que.colFrom}}</th>
                                    <th scope="col">{{t:que.colTo}}</th>
                                    <th scope="col">{{t:que.colSize}}</th>
                                    <th scope="col">{{t:que.colArrival}}</th>
                                    <th scope="col">{{t:que.colError}}</th>
                                    <th scope="col">{{t:home.colActions}}</th>
                                </tr>
                            </thead>
                            <tbody id="queueBody">
                                <tr><td colspan="8" class="text-center">{{t:common.loading}}</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="modal fade" id="messageModal" tabindex="-1" aria-labelledby="messageModalTitle" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="messageModalTitle">{{t:que.details}}</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="{{t:common.close}}"></button>
                </div>
                <div class="modal-body">
                    <div id="messageDetails"></div>
                </div>
            </div>
        </div>
    </div>
""" + getFooterSection() + """
    <script>
        const csrfToken = document.getElementById('csrf_token').value;
        // I nomi degli stati di Postfix (QueueState sul server)
        const QUEUE_STATES = {
            ACTIVE: t('que.state.active'), DEFERRED: t('que.state.deferred'), HOLD: t('que.state.hold'),
            INCOMING: t('que.state.incoming'), CORRUPT: t('que.state.corrupt'), UNKNOWN: t('que.state.unknown')
        };
        // L'elenco dell'ultima lettura, per i dettagli della busta senza un'altra richiesta
        let queueMessages = {};

        // Tutto quello che arriva dalla coda (mittente, oggetto, motivo del rinvio, testo) lo
        // scrive chi manda la posta: entra nella pagina solo passando per escHtml.
        function queueMsg(text, kind) {
            document.getElementById('queueMsg').innerHTML = text
                ? '<div class="alert alert-' + kind + ' py-2 small">' + escHtml(text) + '</div>' : '';
        }

        function formatDate(iso) {
            if (!iso) return '-';
            const d = new Date(iso);
            return isNaN(d) ? '-' : d.toLocaleString(window.I18N_LANG);
        }

        function formatSize(bytes) {
            if (!bytes) return '-';
            if (bytes < 1024) return bytes + ' B';
            if (bytes < 1024 * 1024) return (bytes / 1024).toLocaleString(window.I18N_LANG, { maximumFractionDigits: 1 }) + ' KB';
            return (bytes / (1024 * 1024)).toLocaleString(window.I18N_LANG, { maximumFractionDigits: 1 }) + ' MB';
        }

        function loadStats() {
            fetch('/api/queue?action=stats')
                .then(r => r.json())
                .then(data => {
                    if (!data.success) return;
                    document.getElementById('statTotal').textContent = data.total || 0;
                    document.getElementById('statActive').textContent = data.active || 0;
                    document.getElementById('statDeferred').textContent = data.deferred || 0;
                    document.getElementById('statHold').textContent = data.hold || 0;
                    document.getElementById('statPermanent').textContent =
                        data.permanent ? tn('que.permanentOf', data.permanent) : '';
                    // Si trattiene solo quello che non e' gia' trattenuto, si rilascia solo se c'e' qualcosa
                    document.getElementById('holdBtn').disabled = (data.total || 0) - (data.hold || 0) === 0;
                    document.getElementById('releaseBtn').disabled = !data.hold;
                    document.getElementById('flushBtn').disabled = !data.total;
                    document.getElementById('purgeBtn').disabled = !data.permanent;
                })
                .catch(() => {});
        }

        function loadQueue() {
            fetch('/api/queue')
                .then(r => r.json())
                .then(data => {
                    const tbody = document.getElementById('queueBody');
                    queueMessages = {};
                    if (!data.success) {
                        tbody.innerHTML = '<tr><td colspan="8" class="text-center text-danger">'
                            + escHtml(data.error || t('common.unknownErrorCap')) + '</td></tr>';
                        return;
                    }
                    if (!data.messages || data.messages.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">' + escHtml(t('que.empty')) + '</td></tr>';
                        return;
                    }
                    tbody.innerHTML = data.messages.map(msg => {
                        queueMessages[msg.id] = msg;
                        const state = QUEUE_STATES[msg.state] ? msg.state : 'UNKNOWN';
                        const to = (msg.recipients || []).map(r => r.address).join(', ');
                        const id = escHtml(msg.id);
                        return `<tr>
                            <td data-label="${escHtml(t('que.colId'))}"><code>${id}</code></td>
                            <td data-label="${escHtml(t('que.colState'))}"><span class="queue-state state-${state.toLowerCase()}">${escHtml(QUEUE_STATES[state])}</span></td>
                            <td data-label="${escHtml(t('que.colFrom'))}" class="testo-lungo">${escHtml(msg.sender || t('que.nullSender'))}</td>
                            <td data-label="${escHtml(t('que.colTo'))}" class="testo-lungo">${escHtml(to || '-')}</td>
                            <td data-label="${escHtml(t('que.colSize'))}">${escHtml(formatSize(msg.size))}</td>
                            <td data-label="${escHtml(t('que.colArrival'))}">${escHtml(formatDate(msg.arrival))}</td>
                            <td data-label="${escHtml(t('que.colError'))}" class="text-danger testo-lungo">${escHtml(msg.error || '')}</td>
                            <td data-label="${escHtml(t('home.colActions'))}" class="text-nowrap">
                                <button type="button" class="btn btn-sm btn-outline-info" data-queue-view="${id}" title="${escHtml(t('que.viewOf', { id: msg.id }))}" aria-label="${escHtml(t('que.viewOf', { id: msg.id }))}">
                                    <i class="fas fa-eye" aria-hidden="true"></i>
                                </button>
                                <button type="button" class="btn btn-sm btn-outline-success" data-queue-retry="${id}" title="${escHtml(t('que.retryOf', { id: msg.id }))}" aria-label="${escHtml(t('que.retryOf', { id: msg.id }))}">
                                    <i class="fas fa-redo" aria-hidden="true"></i>
                                </button>
                                <button type="button" class="btn btn-sm btn-outline-danger" data-queue-remove="${id}" title="${escHtml(t('que.removeOf', { id: msg.id }))}" aria-label="${escHtml(t('que.removeOf', { id: msg.id }))}">
                                    <i class="fas fa-trash" aria-hidden="true"></i>
                                </button>
                            </td>
                        </tr>`;
                    }).join('');
                })
                .catch(() => {
                    document.getElementById('queueBody').innerHTML = '<tr><td colspan="8" class="text-center text-danger">'
                        + escHtml(t('common.noAnswer')) + '</td></tr>';
                });
        }

        function refreshQueue() {
            loadStats();
            loadQueue();
        }

        // I pulsanti delle righe: l'identificativo sta in un attributo, non in un onclick scritto a mano
        document.getElementById('queueBody').addEventListener('click', e => {
            const b = e.target.closest('button');
            if (!b) return;
            if (b.dataset.queueView) viewMessage(b.dataset.queueView);
            else if (b.dataset.queueRetry) queueAction({ action: 'schedule', id: b.dataset.queueRetry });
            else if (b.dataset.queueRemove && confirm(t('que.confirmRemove', { id: b.dataset.queueRemove }))) {
                queueAction({ action: 'remove', id: b.dataset.queueRemove });
            }
        });

        function viewMessage(id) {
            const env = queueMessages[id] || {};
            fetch('/api/queue?action=message&id=' + encodeURIComponent(id))
                .then(r => r.json())
                .then(msg => {
                    const row = (label, value) => '<dt class="col-sm-4">' + escHtml(label) + '</dt><dd class="col-sm-8 text-break">' + escHtml(value || '-') + '</dd>';
                    let html = '<div class="row"><div class="col-md-6">';
                    html += '<h6>' + escHtml(t('que.headers')) + '</h6>';
                    if (msg.success) {
                        html += '<dl class="row small">' + row(t('que.hFrom'), msg.from) + row(t('que.hTo'), msg.to)
                            + row(t('que.hSubject'), msg.subject) + row(t('que.hDate'), msg.date) + '</dl>';
                    } else {
                        html += '<p class="small text-danger">' + escHtml(msg.error || t('common.unknownErrorCap')) + '</p>';
                    }
                    html += '</div><div class="col-md-6">';
                    html += '<h6>' + escHtml(t('que.envelope')) + '</h6>';
                    html += '<dl class="row small">' + row(t('que.colId'), env.id || id)
                        + row(t('que.colState'), QUEUE_STATES[env.state] || '')
                        + row(t('que.colFrom'), env.sender || t('que.nullSender'))
                        + row(t('que.colArrival'), formatDate(env.arrival))
                        + row(t('que.colSize'), formatSize(env.size)) + '</dl>';
                    html += '</div></div>';
                    const recipients = env.recipients || [];
                    if (recipients.length) {
                        html += '<h6>' + escHtml(t('que.recipients')) + '</h6><ul class="queue-recipients small mb-3">';
                        html += recipients.map(r => '<li class="mb-1"><code>' + escHtml(r.address) + '</code>'
                            + (r.reason ? '<br><span class="text-danger">' + escHtml(r.reason) + '</span>' : '') + '</li>').join('');
                        html += '</ul>';
                    }
                    if (msg.success && msg.body_preview) {
                        html += '<h6>' + escHtml(t('que.bodyPreview')) + (msg.body_truncated ? ' <small class="text-muted">' + escHtml(t('que.truncated')) + '</small>' : '') + '</h6>';
                        html += '<pre class="bg-light p-2 border rounded small queue-preview">' + escHtml(msg.body_preview) + '</pre>';
                    }
                    document.getElementById('messageDetails').innerHTML = html;
                    bootstrap.Modal.getOrCreateInstance(document.getElementById('messageModal')).show();
                })
                .catch(() => queueMsg(t('common.noAnswer'), 'danger'));
        }

        function queuePost(body) {
            body.csrf_token = csrfToken;
            return fetch('/api/queue', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            }).then(r => r.json());
        }

        function queueAction(body) {
            queueMsg('', '');
            return queuePost(body).then(data => {
                queueMsg(data.message || data.error || t('common.unknownErrorCap'), data.success ? 'success' : 'danger');
                refreshQueue();
            }).catch(() => queueMsg(t('common.noAnswer'), 'danger'));
        }

        function flushQueue() {
            if (confirm(t('que.confirmFlush'))) queueAction({ action: 'flush' });
        }

        function holdAll() {
            if (confirm(t('que.confirmHold'))) queueAction({ action: 'hold' });
        }

        function releaseAll() {
            queueAction({ action: 'release' });
        }

        function purgePermfails() {
            // Prima si guarda, poi si cancella: la conferma porta gli identificativi visti e il
            // loro numero, scritto a mano. Un messaggio arrivato nel frattempo non si tocca.
            queueMsg('', '');
            queuePost({ action: 'purge_permfails' }).then(data => {
                if (!data.success) { queueMsg(data.error || data.message || t('common.unknownErrorCap'), 'danger'); return; }
                if (!data.count) { queueMsg(data.message, 'info'); return; }
                const list = data.messages || [];
                const lines = list.slice(0, 15)
                    .map(m => '• ' + (m.recipients || []).map(r => r.address).join(', ') + '  —  ' + (m.error || '')).join('\\n');
                const extra = list.length > 15 ? '\\n' + tn('que.andMore', list.length - 15) : '';
                const typed = prompt(data.message + '\\n\\n' + lines + extra + '\\n\\n' + tn('que.typeCount', list.length));
                if (typed === null) return;
                if (typed.trim() !== String(list.length)) { queueMsg(t('que.confirmWrong'), 'warning'); return; }
                queueAction({ action: 'purge_permfails', ids: list.map(m => m.id), confirm: String(list.length) });
            }).catch(() => queueMsg(t('common.noAnswer'), 'danger'));
        }

        refreshQueue();
        // La coda cambia da sola: si rilegge ogni 30 secondi
        setInterval(refreshQueue, 30000);
    </script>
</body>
</html>
""";
    }

    // ============== SECURITY.HTML (FAIL2BAN) ==============
    public static String getSecurityHtml() {
        String extraStyles = """
        .jail-card { border-left: 4px solid #dc3545; }
        .jail-card.enabled { border-color: #198754; }
        .ban-event { font-size: 0.85rem; padding: 8px; border-left: 3px solid; margin-bottom: 5px; }
        .ban-event.ban { border-color: #dc3545; background: #fff5f5; }
        [data-theme="dark"] .ban-event.ban { background: rgba(220, 53, 69, .14); }
        .ban-event.unban { border-color: #198754; background: #f5fff5; }
        [data-theme="dark"] .ban-event.unban { background: rgba(25, 135, 84, .14); }
        .ip-badge { font-family: monospace; background: #f8f9fa; color: #212529; padding: 2px 6px; border-radius: 3px; }
        [data-theme="dark"] .ip-badge { background: var(--table-stripe); color: var(--text-primary); border: 1px solid var(--border-color); }
        /* Form helper text — leggibile sia in light che dark */
        .form-text, .form-text.small { color: #6c757d; }
        [data-theme="dark"] .form-text, [data-theme="dark"] .form-text.small { color: #adb5bd !important; }
        [data-theme="dark"] small.text-muted, [data-theme="dark"] .text-muted small, [data-theme="dark"] .small.text-muted { color: #adb5bd !important; }
        """;
        // NOTA: Java fa constant folding sui text block adiacenti — questo crea
        // un UNICO string literal nel constant pool. Limite: 65535 byte UTF-8.
        // Spezziamo in variabili locali per non superare il limite:
        String htmlPart1 = """
    <input type="hidden" id="csrf_token" value="{{CSRF_TOKEN}}">
    <div id="main" tabindex="-1" class="content container mt-4">
        <div class="content-container">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h2><i class="fas fa-shield-alt me-2" aria-hidden="true"></i>{{t:sec.title}}</h2>
                <div>
                    <span class="badge bg-secondary me-2" id="statusBadge">{{t:sec.checkingBadge}}</span>
                    <button class="btn btn-outline-primary btn-sm" onclick="loadStatus()">
                        <i class="fas fa-sync" aria-hidden="true"></i> {{t:common.refresh}}
                    </button>
                </div>
            </div>

            <!-- Setup Wizard / Health Check -->
            <div class="card mb-4 border-primary">
                <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-stethoscope me-2" aria-hidden="true"></i><strong>{{t:sec.f2bState}}</strong> <small class="ms-2" id="fhcOverallStatus"></small></span>
                    <div class="d-flex gap-2 flex-wrap">
                        <button class="btn btn-sm btn-warning d-none" id="btnFixAll" onclick="runFhcFixAll()">
                            <i class="fas fa-magic me-1" aria-hidden="true"></i>{{t:sec.fixAll}}
                        </button>
                        <button class="btn btn-sm btn-outline-light" onclick="reloadFail2banFromPanel()" title="{{t:sec.reloadHint}}">
                            <i class="fas fa-sync-alt me-1" aria-hidden="true"></i>{{t:sec.reloadConfig}}
                        </button>
                        <button class="btn btn-sm btn-danger" onclick="restartFail2banFromPanel()" title="{{t:sec.restartHint}}">
                            <i class="fas fa-power-off me-1" aria-hidden="true"></i>{{t:sec.restartF2b}}
                        </button>
                        <button class="btn btn-sm btn-light" onclick="loadFail2banHealth()">
                            <i class="fas fa-sync me-1" aria-hidden="true"></i>{{t:dns.tzRecheck}}
                        </button>
                    </div>
                </div>
                <div class="card-body" id="fhcContainer">
                    <p class="text-muted mb-0"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>{{t:sec.diagnosing}}</p>
                </div>
                <div class="card-body border-top d-none" id="fhcFixAllReport">
                    <h6 class="mb-2"><i class="fas fa-list-check me-1" aria-hidden="true"></i>{{t:sec.fixReport}}</h6>
                    <div id="fhcFixAllSteps"></div>
                </div>
            </div>

            <!-- Stato Live Jail Fail2ban (output di fail2ban-client get/status) -->
            <div class="card mb-4 border-secondary">
                <div class="card-header bg-secondary text-white d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-microscope me-2" aria-hidden="true"></i><strong>{{t:sec.liveTitle}}</strong> <small class="ms-2 text-white-50">{{t:sec.liveHint}}</small></span>
                    <button class="btn btn-sm btn-light" onclick="loadJailLiveState()">
                        <i class="fas fa-sync me-1" aria-hidden="true"></i>{{t:common.refresh}}
                    </button>
                </div>
                <div class="card-body p-2" id="jailLiveBody">
                    <p class="text-muted small mb-0 p-2"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>{{t:common.loading}}</p>
                </div>
            </div>

            <!-- Postfix Aliases Health / Auto-fix -->
            <div class="card mb-4 border-info">
                <div class="card-header bg-info text-white d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-at me-2" aria-hidden="true"></i><strong>{{t:sec.paliasTitle}}</strong> <small class="ms-2" id="paliasOverallBadge"></small></span>
                    <div class="d-flex gap-2">
                        <button class="btn btn-sm btn-warning d-none" id="paliasFixBtn" onclick="paliasFix()">
                            <i class="fas fa-magic me-1" aria-hidden="true"></i>{{t:sec.fix}}
                        </button>
                        <button class="btn btn-sm btn-light" onclick="paliasLoad()">
                            <i class="fas fa-sync me-1" aria-hidden="true"></i>{{t:dns.tzRecheck}}
                        </button>
                    </div>
                </div>
                <div class="card-body" id="paliasBody">
                    <p class="text-muted mb-0"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>{{t:common.loading}}</p>
                </div>
                <div class="card-body border-top">
                    <h6 class="mb-2"><i class="fas fa-share me-1" aria-hidden="true"></i>{{t:sec.rootFwd}}</h6>
                    <p class="small text-muted mb-2">{{t:sec.rootFwdHint.html}}</p>
                    <div class="input-group input-group-sm">
                        <span class="input-group-text">root →</span>
                        <input type="text" class="form-control" id="paliasRootForward" aria-label="{{t:sec.rootFwd}}" placeholder="{{t:sec.rootFwdPh}}">
                        <button class="btn btn-info" type="button" onclick="paliasSetRootForward()"><i class="fas fa-save me-1" aria-hidden="true"></i>{{t:sec.saveFwd}}</button>
                    </div>
                    <div id="paliasLog" class="mt-2 small"></div>
                </div>
            </div>

            <!-- Unbound (resolver DNS locale) Health Check -->
            <div class="card mb-4 border-info">
                <div class="card-header bg-info text-white d-flex justify-content-between align-items-center flex-wrap gap-2">
                    <span><i class="fas fa-network-wired me-2" aria-hidden="true"></i><strong>{{t:sec.unbound}}</strong> <small class="ms-2" id="ubOverallStatus"></small></span>
                    <div class="d-flex gap-2">
                        <button class="btn btn-sm btn-light" id="btnUbTestQuery" onclick="runUbTestQuery()" title="{{t:sec.testQueryHint}}">
                            <i class="fas fa-vial me-1" aria-hidden="true"></i>{{t:sec.testQuery}}
                        </button>
                        <button class="btn btn-sm btn-warning d-none" id="btnUbFixAll" onclick="runUbFixAll()">
                            <i class="fas fa-magic me-1" aria-hidden="true"></i>{{t:sec.fixAll}}
                        </button>
                        <button class="btn btn-sm btn-light" onclick="loadUnboundHealth()">
                            <i class="fas fa-sync me-1" aria-hidden="true"></i>{{t:dns.tzRecheck}}
                        </button>
                    </div>
                </div>
                <div class="card-body" id="ubContainer">
                    <p class="text-muted mb-0"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>{{t:sec.diagnosing}}</p>
                </div>
                <div class="card-body border-top d-none" id="ubTestResult">
                    <h6 class="mb-2"><i class="fas fa-vial me-1" aria-hidden="true"></i>{{t:sec.testQueryResult}}</h6>
                    <pre id="ubTestBody" class="small mb-0" style="white-space:pre-wrap"></pre>
                </div>
                <div class="card-body border-top d-none" id="ubFixAllReport">
                    <h6 class="mb-2"><i class="fas fa-list-check me-1" aria-hidden="true"></i>{{t:sec.fixReport}}</h6>
                    <div id="ubFixAllSteps"></div>
                </div>
            </div>

""";
        String htmlPart2 = """
""" + getClamavHealthCard() + """

            <!-- Status Cards -->
            <div class="row mb-4">
                <div class="col-md-4">
                    <div class="card text-center">
                        <div class="card-body">
                            <h3 class="text-danger" id="totalBanned">-</h3>
                            <small class="text-muted">{{t:sec.bannedNow}}</small>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card text-center">
                        <div class="card-body">
                            <h3 class="text-info" id="totalJails">-</h3>
                            <small class="text-muted">{{t:sec.activeJails}}</small>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card text-center">
                        <div class="card-body">
                            <h3 class="text-warning" id="totalBannedAll">-</h3>
                            <small class="text-muted">{{t:sec.totalBans}}</small>
                        </div>
                    </div>
                </div>
            </div>

            <div class="row">
                <!-- Jails -->
                <div class="col-md-6">
                    <div class="card mb-4">
                        <div class="card-header d-flex justify-content-between align-items-center flex-wrap gap-2">
                            <span><i class="fas fa-lock me-2" aria-hidden="true"></i>{{t:sec.activeJails}} <span class="badge bg-secondary ms-1" id="jailsCount">-</span></span>
                            <div class="d-flex align-items-center gap-2">
                                <small class="text-muted d-none d-md-inline"><i class="fas fa-info-circle me-1" aria-hidden="true"></i>{{t:sec.jailsWhere}}</small>
                                <button class="btn btn-outline-primary btn-sm" id="btnRefreshJails" onclick="refreshJails(true)" title="{{t:sec.refreshJails}}">
                                    <i class="fas fa-sync" id="iconRefreshJails"></i>
                                </button>
                            </div>
                        </div>
                        <div class="card-body" id="jailsContainer">
                            <p class="text-muted">{{t:common.loading}}</p>
                        </div>
                    </div>

                    <!-- Manual Ban -->
                    <div class="card mb-4">
                        <div class="card-header"><i class="fas fa-ban me-2" aria-hidden="true"></i>{{t:sec.manualBan}}</div>
                        <div class="card-body">
                            <div class="row g-2">
                                <div class="col-5">
                                    <input type="text" class="form-control" id="banIp" placeholder="{{t:sec.ipAddress}}" aria-label="{{t:sec.ipAddress}}">
                                </div>
                                <div class="col-4">
                                    <select class="form-select" id="banJail" aria-label="Jail"></select>
                                </div>
                                <div class="col-3">
                                    <button class="btn btn-danger w-100" onclick="banIp()">{{t:sec.ban}}</button>
                                </div>
                            </div>
                        </div>
                    </div>

""" + getJailConfigurationCard() + """
                </div>

                <!-- Recent Bans & Banned IPs -->
                <div class="col-md-6">
                    <div class="card mb-4">
                        <div class="card-header"><i class="fas fa-history me-2" aria-hidden="true"></i>{{t:sec.recent}}</div>
                        <div class="card-body" style="max-height: 300px; overflow-y: auto;" id="recentBans">
                            <p class="text-muted">{{t:common.loading}}</p>
                        </div>
                    </div>

                    <div class="card mb-4">
                        <div class="card-header"><i class="fas fa-list me-2" aria-hidden="true"></i>{{t:sec.bannedIps}}</div>
                        <div class="card-body">
                            <div class="table-responsive" style="max-height: 300px; overflow-y: auto;">
                                <table class="table table-sm" id="bannedTable">
                                    <thead>
                                        <tr>
                                            <th>IP</th>
                                            <th>Jail</th>
                                            <th>{{t:home.colActions}}</th>
                                        </tr>
                                    </thead>
                                    <tbody id="bannedBody">
                                        <tr><td colspan="3" class="text-muted">{{t:common.loading}}</td></tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>

""" + resource("pages/pf-comparison-card.html") + """

                    <!-- Permaban list (via pf, independent from Fail2ban) -->
                    <div class="card">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <span><i class="fas fa-ban me-2 text-danger" aria-hidden="true"></i>Permaban (pf)</span>
                            <span class="badge bg-danger" id="permabanCount">0</span>
                        </div>
                        <div class="card-body">
                            <p class="small text-muted mb-2">
                                <i class="fas fa-info-circle me-1" aria-hidden="true"></i>
{{t:sec.permabanHint.html}}
                            </p>
                            <div class="row g-2 mb-3">
                                <div class="col-8">
                                    <input type="text" id="permabanIpInput" class="form-control form-control-sm" placeholder="{{t:sec.ipPh}}" aria-label="{{t:sec.ipAddress}}">
                                </div>
                                <div class="col-4">
                                    <button class="btn btn-danger btn-sm w-100" onclick="permabanAddManual()">
                                        <i class="fas fa-plus me-1" aria-hidden="true"></i>{{t:common.add}}
                                    </button>
                                </div>
                            </div>
                            <div class="table-responsive" style="max-height: 250px; overflow-y: auto;">
                                <table class="table table-sm mb-0">
                                    <thead>
                                        <tr>
                                            <th>IP</th>
                                            <th>{{t:sec.runtime}}</th>
                                            <th>{{t:home.colActions}}</th>
                                        </tr>
                                    </thead>
                                    <tbody id="permabanBody">
                                        <tr><td colspan="3" class="text-muted">{{t:common.loading}}</td></tr>
                                    </tbody>
                                </table>
                            </div>
                            <div class="mt-2">
                                <button class="btn btn-outline-secondary btn-sm" onclick="permabanReload()" title="{{t:sec.pfReloadHint}}">
                                    <i class="fas fa-sync me-1" aria-hidden="true"></i>{{t:sec.pfReload}}
                                </button>
                                <button class="btn btn-outline-secondary btn-sm" onclick="permabanList()" title="{{t:sec.refreshList}}">
                                    <i class="fas fa-redo me-1" aria-hidden="true"></i>{{t:common.refresh}}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Service Controls -->
            <div class="card mt-4">
                <div class="card-header"><i class="fas fa-cogs me-2" aria-hidden="true"></i>{{t:sec.service}}</div>
                <div class="card-body">
                    <button class="btn btn-success me-2" onclick="serviceAction('start')">
                        <i class="fas fa-play" aria-hidden="true"></i> {{t:sec.start}}
                    </button>
                    <button class="btn btn-danger me-2" onclick="serviceAction('stop')">
                        <i class="fas fa-stop" aria-hidden="true"></i> {{t:sec.stop}}
                    </button>
                    <button class="btn btn-warning" onclick="serviceAction('reload')">
                        <i class="fas fa-sync" aria-hidden="true"></i> {{t:sec.reloadCfg}}
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- IP Info Modal -->
    <div class="modal fade" id="ipModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">{{t:sec.ipInfo}}</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="{{t:common.close}}"></button>
                </div>
                <div class="modal-body" id="ipInfo"></div>
            </div>
        </div>
    </div>
""" + getFooterSection() + """
    <script>
        let csrfToken = document.getElementById('csrf_token').value;

        function loadStatus() {
            fetch('/api/fail2ban?action=status')
                .then(r => r.json())
                .then(data => {
                    // Update status badge
                    const badge = document.getElementById('statusBadge');
                    if (!data.installed) {
                        badge.className = 'badge bg-danger me-2';
                        badge.textContent = t('sec.notInstalled');
                        return;
                    }
                    badge.className = data.running ? 'badge bg-success me-2' : 'badge bg-warning me-2';
                    badge.textContent = data.running ? t('rl.active') : t('sec.stopped');

                    // Update stats
                    const jailCount = data.jails?.length || data.active_jails?.length || 0;
                    document.getElementById('totalBanned').textContent = data.total_banned || 0;
                    document.getElementById('totalJails').textContent = jailCount;
                    document.getElementById('totalBannedAll').textContent = data.total_banned_total || 0;

                    // Counter sulla card "Jail Attive"
                    const cnt = document.getElementById('jailsCount');
                    if (cnt) {
                        cnt.textContent = jailCount;
                        cnt.className = 'badge ms-1 ' + (jailCount > 0 ? 'bg-success' : 'bg-warning text-dark');
                    }

                    // Update jails
                    const jailsHtml = (data.jails || []).map(jail => `
                        <div class="jail-card card mb-2 ${jail.enabled ? 'enabled' : ''}">
                            <div class="card-body py-2">
                                <div class="d-flex justify-content-between align-items-center">
                                    <strong>${escapeHtml(jail.name)}</strong>
                                    <span class="badge bg-danger">${escHtml(tn('sec.bannedN', jail.currently_banned))}</span>
                                </div>
                                <small class="text-muted">
                                    ${escHtml(t('sec.jailCounts', { failed: jail.currently_failed, total: jail.total_banned }))}
                                </small>
                                <div class="mt-1">
                                    <button class="btn btn-sm btn-outline-secondary py-0" data-jail="${escHtml(jail.name)}" onclick="checkJailFilter(this.dataset.jail)" title="${escHtml(t('sec.seesHint'))}">
                                        <i class="fas fa-magnifying-glass me-1" aria-hidden="true"></i>${escHtml(t('sec.sees'))}</button>
                                    <div id="filtro-${escapeHtml(jail.name)}" class="small mt-1"></div>
                                </div>
                                <div class="small text-muted">
                                    ${escHtml(t('sec.port'))} ${jail.declared_port
                                        ? '<code>' + escapeHtml(jail.ports) + '</code>' + (jail.ban_uses_port
                                            ? ' <span class="badge bg-warning text-dark" title="' + escHtml(t('sec.portBanHint')) + '">' + escHtml(t('sec.portBan')) + '</span>'
                                            : ' <span class="text-muted" title="' + escHtml(t('sec.portIndicativeHint')) + '">' + escHtml(t('sec.portIndicative')) + '</span>')
                                        : '<span title="' + escHtml(t('sec.portNoneHint')) + '">' + escHtml(t('sec.portNone')) + '</span>'}
                                    ${jail.log ? ' &middot; Log: <code>' + escapeHtml(jail.log) + '</code>' : ''}
                                </div>
                            </div>
                        </div>
                    `).join('') || '<p class="text-muted mb-0">' + escHtml(t('sec.noJails')) + '</p>';
                    document.getElementById('jailsContainer').innerHTML = jailsHtml;

                    // Populate jail select
                    const select = document.getElementById('banJail');
                    select.innerHTML = (data.active_jails || []).map(j => `<option value="${escapeHtml(j)}">${escapeHtml(j)}</option>`).join('');

                    // Recent bans
                    const recentHtml = (data.recent_bans || []).map(event => `
                        <div class="ban-event ${event.action}">
                            <i class="fas fa-${event.action === 'ban' ? 'ban text-danger' : 'unlock text-success'}" aria-hidden="true"></i>
                            <span class="ip-badge">${escapeHtml(event.ip)}</span>
                            <span class="text-muted ms-2">${escapeHtml(event.jail)}</span>
                            <small class="float-end text-muted">${event.timestamp ? new Date(event.timestamp).toLocaleString(window.I18N_LANG) : ''}</small>
                        </div>
                    `).join('') || '<p class="text-muted">' + escHtml(t('sec.noRecent')) + '</p>';
                    document.getElementById('recentBans').innerHTML = recentHtml;

                    // Load banned IPs
                    loadBannedIps();
                });
        }

        function loadBannedIps() {
            fetch('/api/fail2ban?action=banned')
                .then(r => r.json())
                .then(data => {
                    const tbody = document.getElementById('bannedBody');
                    if (!data.banned || data.banned.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="3" class="text-muted text-center">' + escHtml(t('sec.noBanned')) + '</td></tr>';
                        return;
                    }

                    tbody.innerHTML = data.banned.map(ban => `
                        <tr>
                            <td>
                                <span class="ip-badge">${escapeHtml(ban.ip)}</span>
                                <button class="btn btn-link btn-sm p-0 ms-1" data-ip="${escHtml(ban.ip)}" onclick="showIpInfo(this.dataset.ip)" title="${escHtml(t('sec.ipInfo'))}" aria-label="${escHtml(t('sec.ipInfo'))} ${escapeHtml(ban.ip)}">
                                    <i class="fas fa-info-circle" aria-hidden="true"></i>
                                </button>
                            </td>
                            <td><small>${escapeHtml(ban.jail)}</small></td>
                            <td class="d-flex gap-1">
                                <button class="btn btn-sm btn-outline-success" data-ip="${escHtml(ban.ip)}" data-jail="${escHtml(ban.jail)}" onclick="unbanIp(this.dataset.ip, this.dataset.jail)" title="${escHtml(t('sec.unban'))}" aria-label="${escHtml(t('sec.unban'))} ${escapeHtml(ban.ip)}">
                                    <i class="fas fa-unlock" aria-hidden="true"></i>
                                </button>
                                <button class="btn btn-sm btn-outline-danger" data-ip="${escHtml(ban.ip)}" onclick="permabanAdd(this.dataset.ip)" title="${escHtml(t('sec.permaban'))}" aria-label="${escHtml(t('sec.permaban'))} ${escapeHtml(ban.ip)}">
                                    <i class="fas fa-ban" aria-hidden="true"></i>
                                </button>
                            </td>
                        </tr>
                    `).join('');
                });
        }

        function banIp() {
            const ip = document.getElementById('banIp').value.trim();
            const jail = document.getElementById('banJail').value;

            if (!ip) { alert(t('sec.needIp')); return; }
            if (!jail) { alert(t('sec.needJail')); return; }

            fetch('/api/fail2ban', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'ban', ip: ip, jail: jail })
            }).then(r => r.json()).then(data => {
                alert(data.message);
                if (data.success) {
                    document.getElementById('banIp').value = '';
                    loadStatus();
                }
            });
        }

        function unbanIp(ip, jail) {
            if (!confirm(t('sec.confirmUnban', { ip: ip }))) return;

            fetch('/api/fail2ban', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'unban', ip: ip, jail: jail })
            }).then(r => r.json()).then(data => {
                alert(data.message);
                loadStatus();
            });
        }

        function showIpInfo(ip) {
            document.getElementById('ipInfo').innerHTML = '<p><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('common.loading')) + '</p>';
            new bootstrap.Modal(document.getElementById('ipModal')).show();

            fetch('/api/fail2ban?action=ip_info&ip=' + encodeURIComponent(ip))
                .then(r => r.json())
                .then(data => {
                    let html = '<table class="table table-sm mb-2"><tbody>';
                    html += `<tr><td style="width:35%"><strong>IP</strong></td><td><code>${escapeHtml(data.ip || ip)}</code></td></tr>`;

                    // Posizione geografica (GeoIP)
                    let country = '';
                    if (data.country_name && data.country) country = `${escapeHtml(data.country_name)} (${escapeHtml(data.country)})`;
                    else if (data.country) country = escapeHtml(data.country);
                    if (country) html += `<tr><td><strong>${escHtml(t('sec.country'))}</strong></td><td>${country}</td></tr>`;
                    if (data.region) html += `<tr><td><strong>${escHtml(t('sec.region'))}</strong></td><td>${escapeHtml(data.region)}</td></tr>`;
                    if (data.city) html += `<tr><td><strong>${escHtml(t('sec.city'))}</strong></td><td>${escapeHtml(data.city)}</td></tr>`;

                    // Rete / Provider
                    if (data.isp) html += `<tr><td><strong>ISP</strong></td><td>${escapeHtml(data.isp)}</td></tr>`;
                    if (data.asn) html += `<tr><td><strong>ASN</strong></td><td><code>${escapeHtml(data.asn)}</code></td></tr>`;
                    if (data.organization) html += `<tr><td><strong>${escHtml(t('sec.org'))}</strong></td><td>${escapeHtml(data.organization)}</td></tr>`;
                    if (data.net_range) html += `<tr><td><strong>${escHtml(t('sec.netRange'))}</strong></td><td><code>${escapeHtml(data.net_range)}</code></td></tr>`;

                    html += '</tbody></table>';

                    // Mappa (se abbiamo coordinate)
                    if (data.latitude != null && data.longitude != null) {
                        const lat = data.latitude;
                        const lon = data.longitude;
                        const mapsUrl = `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=8/${lat}/${lon}`;
                        html += `<div class="mb-2"><small class="text-muted">${escHtml(t('sec.coords'))} <code>${escapeHtml(lat)}, ${escapeHtml(lon)}</code></small> `;
                        html += `<a href="${escapeHtml(mapsUrl)}" target="_blank" rel="noopener" class="btn btn-outline-primary btn-sm ms-2"><i class="fas fa-map-marker-alt me-1" aria-hidden="true"></i>${escHtml(t('sec.openMap'))}</a></div>`;
                    }

                    if (data.geo_source) {
                        html += `<div class="text-muted small"><i class="fas fa-info-circle me-1" aria-hidden="true"></i>${escHtml(t('sec.source', { source: data.geo_source }))}</div>`;
                    }
                    if (!data.success) {
                        html += `<div class="alert alert-warning mt-2 mb-0 py-2"><i class="fas fa-exclamation-triangle me-1" aria-hidden="true"></i>${escHtml(t('sec.noWhois'))}</div>`;
                    }

                    document.getElementById('ipInfo').innerHTML = html;
                })
                .catch(e => {
                    document.getElementById('ipInfo').innerHTML = '<div class="alert alert-danger">' + escHtml(t('common.error', { message: e.message })) + '</div>';
                });
        }

        function escapeHtml(s) {
            const d = document.createElement('div');
            d.textContent = s == null ? '' : String(s);
            return d.innerHTML;
        }

        function serviceAction(action) {
            fetch('/api/fail2ban', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: action })
            }).then(r => r.json()).then(data => {
                alert(data.message);
                loadStatus();
            });
        }

        function installMailJails() {
            if (!confirm(t('sec.confirmMailJails'))) return;

            fetch('/api/fail2ban', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'install_mail_jails' })
            }).then(r => r.json()).then(data => {
                alert(data.message || data.error);
                loadStatus();
            });
        }

""" + getJailConfigurationJs() + """
""" + resource("pages/security-jail.js") + resource("pages/pf-comparison.js") + """
""";
        String jsPart2 = """
""" + resource("pages/security-health.js") + """
""" + """
    </script>
</body>
</html>
""";
        return getHead("nav.security", "security", extraStyles) + htmlPart1 + htmlPart2 + jsPart2;
    }

    // ============== STATISTICS.HTML ==============
    public static String getStatisticsHtml() {
        String extraStyles = """
        .stat-card { border-left: 4px solid; }
        .stat-card.sent { border-color: #198754; }
        .stat-card.received { border-color: #0dcaf0; }
        .stat-card.spam { border-color: #dc3545; }
        .stat-card.bounced { border-color: #ffc107; }
        .chart-container { position: relative; height: 300px; }
        """;
        return getHead("nav.statistics", "statistics", extraStyles) + """
    <div id="main" tabindex="-1" class="content container mt-4">
        <div class="content-container">
            <div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-3">
                <h2 class="mb-0"><i class="fas fa-chart-line me-2" aria-hidden="true"></i>{{t:st.title}}</h2>
                <div class="d-flex gap-2 align-items-center">
                    <label class="visually-hidden" for="periodSelect">{{t:st.period}}</label>
                    <select class="form-select form-select-sm w-auto" id="periodSelect" onchange="loadStats()">
                        <option value="1">{{t:st.today}}</option>
                        <option value="7" selected>{{t:st.week}}</option>
                        <option value="30">{{t:st.month}}</option>
                        <option value="365">{{t:st.year}}</option>
                    </select>
                    <button type="button" class="btn btn-outline-primary btn-sm" onclick="loadStats()" title="{{t:common.refresh}}" aria-label="{{t:common.refresh}}">
                        <i class="fas fa-sync" aria-hidden="true"></i>
                    </button>
                </div>
            </div>

            <!-- Nessun componente del pannello scrive email_statistics (incrementEmailStat non e'
                 chiamato da nessuno): i conteggi di invio e ricezione restano a zero. Si dice,
                 invece di mostrare zeri come se fossero misure. Rspamd invece e' letto davvero. -->
            <div class="alert alert-warning small" role="note">
                <i class="fas fa-triangle-exclamation me-1" aria-hidden="true"></i>{{t:st.notCollected.html}}
            </div>
            <div id="statsMsg" role="status" aria-live="polite"></div>

            <div class="row g-3 mb-4">
                <div class="col-6 col-md-3">
                    <div class="card stat-card sent h-100">
                        <div class="card-body text-center">
                            <p class="h3 mb-0" id="totalSent">-</p>
                            <small class="text-muted"><i class="fas fa-paper-plane me-1" aria-hidden="true"></i>{{t:st.sent}}</small>
                        </div>
                    </div>
                </div>
                <div class="col-6 col-md-3">
                    <div class="card stat-card received h-100">
                        <div class="card-body text-center">
                            <p class="h3 mb-0" id="totalReceived">-</p>
                            <small class="text-muted"><i class="fas fa-inbox me-1" aria-hidden="true"></i>{{t:st.received}}</small>
                        </div>
                    </div>
                </div>
                <div class="col-6 col-md-3">
                    <div class="card stat-card spam h-100">
                        <div class="card-body text-center">
                            <p class="h3 mb-0" id="totalSpam">-</p>
                            <small class="text-muted"><i class="fas fa-exclamation-triangle me-1" aria-hidden="true"></i>{{t:st.spam}}</small>
                        </div>
                    </div>
                </div>
                <div class="col-6 col-md-3">
                    <div class="card stat-card bounced h-100">
                        <div class="card-body text-center">
                            <p class="h3 mb-0" id="totalBounced">-</p>
                            <small class="text-muted"><i class="fas fa-reply me-1" aria-hidden="true"></i>{{t:st.bounced}}</small>
                        </div>
                    </div>
                </div>
            </div>

            <div class="row">
                <div class="col-lg-8">
                    <div class="card mb-4">
                        <div class="card-header"><i class="fas fa-chart-line me-2" aria-hidden="true"></i>{{t:st.traffic}}</div>
                        <div class="card-body">
                            <div class="chart-container">
                                <canvas id="trafficChart" role="img" aria-label="{{t:st.traffic}}"></canvas>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-lg-4">
                    <div class="card mb-4">
                        <div class="card-header"><i class="fas fa-chart-pie me-2" aria-hidden="true"></i>{{t:st.distribution}}</div>
                        <div class="card-body">
                            <div class="chart-container">
                                <canvas id="distributionChart" role="img" aria-label="{{t:st.distribution}}"></canvas>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="row">
                <div class="col-md-6">
                    <div class="card mb-4">
                        <div class="card-header"><i class="fas fa-shield-alt me-2" aria-hidden="true"></i>{{t:st.rspamd}}</div>
                        <div class="card-body">
                            <div class="row text-center">
                                <div class="col-4">
                                    <p class="h4 text-success mb-0" id="rspamdHam">-</p>
                                    <small class="text-muted">{{t:st.ham}}</small>
                                </div>
                                <div class="col-4">
                                    <p class="h4 text-danger mb-0" id="rspamdSpam">-</p>
                                    <small class="text-muted">{{t:st.spamShort}}</small>
                                </div>
                                <div class="col-4">
                                    <p class="h4 text-info mb-0" id="rspamdScanned">-</p>
                                    <small class="text-muted">{{t:st.scanned}}</small>
                                </div>
                            </div>
                            <hr>
                            <div class="d-flex justify-content-between">
                                <small class="text-muted">{{t:st.spamShare}}</small>
                                <span id="rspamdShare">-</span>
                            </div>
                            <div class="d-flex justify-content-between">
                                <small class="text-muted">{{t:st.rspamdSince}}</small>
                                <span id="rspamdUptime">-</span>
                            </div>
                            <p class="small text-muted mb-0 mt-2" id="rspamdNote">{{t:st.rspamdHint}}</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="card mb-4">
                        <div class="card-header"><i class="fas fa-graduation-cap me-2" aria-hidden="true"></i>{{t:st.training}}</div>
                        <div class="card-body">
                            <div class="row text-center">
                                <div class="col-6">
                                    <p class="h4 text-danger mb-0" id="trainedSpam">-</p>
                                    <small class="text-muted">{{t:st.trainedSpam}}</small>
                                </div>
                                <div class="col-6">
                                    <p class="h4 text-success mb-0" id="trainedHam">-</p>
                                    <small class="text-muted">{{t:st.trainedHam}}</small>
                                </div>
                            </div>
                            <p class="small text-muted mb-0 mt-3">{{t:st.trainingHint}}</p>
                        </div>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-header" id="domainStatsTitle"><i class="fas fa-globe me-2" aria-hidden="true"></i>{{t:st.perDomain}}</div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-hover tabella-schede" aria-labelledby="domainStatsTitle">
                            <thead>
                                <tr>
                                    <th scope="col">{{t:st.colDomain}}</th>
                                    <th scope="col" class="text-end">{{t:st.sent}}</th>
                                    <th scope="col" class="text-end">{{t:st.received}}</th>
                                    <th scope="col" class="text-end">{{t:st.spam}}</th>
                                    <th scope="col" class="text-end">{{t:st.bounced}}</th>
                                    <th scope="col" class="text-end">{{t:st.total}}</th>
                                </tr>
                            </thead>
                            <tbody id="domainStatsBody">
                                <tr><td colspan="6" class="text-center text-muted">{{t:common.loading}}</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>
""" + getFooterSection() + """
    <script src="/vendor/chart.umd.js"></script>
    <script>
        let trafficChart, distributionChart;

        function formatNumber(n) {
            return Number(n || 0).toLocaleString(window.I18N_LANG, { notation: 'compact', maximumFractionDigits: 1 });
        }

        function statsMsg(text, kind) {
            document.getElementById('statsMsg').innerHTML = text
                ? '<div class="alert alert-' + kind + ' py-2 small">' + escHtml(text) + '</div>' : '';
        }

        function loadStats() {
            const days = document.getElementById('periodSelect').value;
            statsMsg('', '');
            fetch('/api/statistics?days=' + encodeURIComponent(days))
                .then(r => r.json())
                .then(data => {
                    if (!data.success) { statsMsg(data.error || t('common.unknownErrorCap'), 'danger'); return; }
                    const tot = data.totals || {};
                    document.getElementById('totalSent').textContent = formatNumber(tot.sent);
                    document.getElementById('totalReceived').textContent = formatNumber(tot.received);
                    document.getElementById('totalSpam').textContent = formatNumber(tot.spam);
                    document.getElementById('totalBounced').textContent = formatNumber(tot.bounced);
                    document.getElementById('trainedSpam').textContent = formatNumber(data.spam_trained);
                    document.getElementById('trainedHam').textContent = formatNumber(data.ham_trained);
                    updateTrafficChart(data.daily || []);
                    updateDistributionChart(tot);
                    updateDomainStats(data.domains || []);
                })
                .catch(() => statsMsg(t('common.noAnswer'), 'danger'));

            // Rspamd: i numeri vengono da Rspamd stesso (dal suo ultimo avvio), non dal periodo scelto
            fetch('/api/rspamd?action=stats')
                .then(r => r.json())
                .then(data => {
                    if (!data.success) {
                        document.getElementById('rspamdNote').textContent = data.error || t('common.unknownErrorCap');
                        return;
                    }
                    document.getElementById('rspamdHam').textContent = formatNumber(data.ham_count);
                    document.getElementById('rspamdSpam').textContent = formatNumber(data.spam_count);
                    document.getElementById('rspamdScanned').textContent = formatNumber(data.scanned);
                    document.getElementById('rspamdShare').textContent = data.scanned > 0
                        ? (data.spam_count / data.scanned).toLocaleString(window.I18N_LANG, { style: 'percent', maximumFractionDigits: 1 }) : '-';
                    document.getElementById('rspamdUptime').textContent = data.uptime > 0
                        ? new Date(Date.now() - data.uptime * 1000).toLocaleString(window.I18N_LANG) : '-';
                })
                .catch(() => { document.getElementById('rspamdNote').textContent = t('common.noAnswer'); });
        }

        function updateTrafficChart(daily) {
            if (trafficChart) trafficChart.destroy();
            if (typeof Chart === 'undefined') return;
            trafficChart = new Chart(document.getElementById('trafficChart').getContext('2d'), {
                type: 'line',
                data: {
                    labels: daily.map(d => new Date(d.date + 'T00:00:00').toLocaleDateString(window.I18N_LANG)),
                    datasets: [
                        { label: t('st.sent'), data: daily.map(d => d.sent), borderColor: '#198754', backgroundColor: 'rgba(25, 135, 84, 0.1)', fill: true, tension: 0.4 },
                        { label: t('st.received'), data: daily.map(d => d.received), borderColor: '#0dcaf0', backgroundColor: 'rgba(13, 202, 240, 0.1)', fill: true, tension: 0.4 }
                    ]
                },
                options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'top' } }, scales: { y: { beginAtZero: true } } }
            });
        }

        function updateDistributionChart(tot) {
            if (distributionChart) distributionChart.destroy();
            if (typeof Chart === 'undefined') return;
            const delivered = Math.max(0, (tot.sent || 0) + (tot.received || 0) - (tot.spam || 0) - (tot.bounced || 0));
            distributionChart = new Chart(document.getElementById('distributionChart').getContext('2d'), {
                type: 'doughnut',
                data: {
                    labels: [t('st.delivered'), t('st.spam'), t('st.bounced')],
                    datasets: [{ data: [delivered, tot.spam || 0, tot.bounced || 0], backgroundColor: ['#198754', '#dc3545', '#ffc107'] }]
                },
                options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom' } } }
            });
        }

        function updateDomainStats(domains) {
            const tbody = document.getElementById('domainStatsBody');
            if (!domains.length) {
                tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">' + escHtml(t('st.noData')) + '</td></tr>';
                return;
            }
            tbody.innerHTML = domains.map(d => `
                <tr>
                    <td data-label="${escHtml(t('st.colDomain'))}" class="testo-lungo"><i class="fas fa-globe me-1" aria-hidden="true"></i>${escHtml(d.domain)}</td>
                    <td data-label="${escHtml(t('st.sent'))}" class="text-end">${escHtml(formatNumber(d.sent))}</td>
                    <td data-label="${escHtml(t('st.received'))}" class="text-end">${escHtml(formatNumber(d.received))}</td>
                    <td data-label="${escHtml(t('st.spam'))}" class="text-end text-danger">${escHtml(formatNumber(d.spam))}</td>
                    <td data-label="${escHtml(t('st.bounced'))}" class="text-end">${escHtml(formatNumber(d.bounced))}</td>
                    <td data-label="${escHtml(t('st.total'))}" class="text-end"><strong>${escHtml(formatNumber((d.sent || 0) + (d.received || 0)))}</strong></td>
                </tr>`).join('');
        }

        loadStats();
    </script>
</body>
</html>
""";
    }

    // ============== RUOLI: CHI PUO' FARE COSA ==============
    /**
     * Le aree del pannello nella tabella dei ruoli: la chiave del nome, il permesso per vedere e
     * quello per cambiare ("" se nell'area non c'e' niente da cambiare).
     */
    private static final String[][] ROLE_AREAS = {
        {"adm.area.home", "home.view", ""},
        {"adm.area.mailboxes", "mail.view", "mailboxes.manage"},
        {"adm.area.domains", "mail.view", "domains.manage"},
        {"adm.area.queue", "queue.view", "queue.manage"},
        {"adm.area.dns", "dns.view", "dns.manage"},
        {"adm.area.security", "security.view", "security.manage"},
        {"adm.area.system", "system.view", "system.manage"},
        {"adm.area.settings", "settings.manage", "settings.manage"},
        {"adm.area.admins", "admins.manage", "admins.manage"},
    };

    /** Il nome di un ruolo nei file di lingua (adm.rSuperadmin, adm.rAdmin...). */
    private static String roleKey(String role) {
        return "adm.r" + Character.toUpperCase(role.charAt(0)) + role.substring(1);
    }

    /**
     * La tabella "chi puo' fare cosa", costruita dai permessi veri (AuthStore): non puo' dire una
     * cosa diversa da quella che il server applica.
     */
    static String roleMatrix() {
        StringBuilder head = new StringBuilder();
        for (String role : org.mail_panel.security.AuthStore.ROLES)
            head.append("<th scope=\"col\" class=\"text-center\"><span class=\"badge role-badge ").append(role)
                .append("\">{{t:").append(roleKey(role)).append("}}</span></th>");
        StringBuilder rows = new StringBuilder();
        for (String[] area : ROLE_AREAS) {
            rows.append("<tr><th scope=\"row\">{{t:").append(area[0]).append("}}</th>");
            for (String role : org.mail_panel.security.AuthStore.ROLES) {
                java.util.Set<String> p = org.mail_panel.security.AuthStore.permissionsOf(role);
                String cell = !area[2].isEmpty() && p.contains(area[2])
                        ? "<i class=\"fas fa-pen text-success\" aria-hidden=\"true\"></i><span class=\"ms-1 matrix-label\">{{t:adm.can.manage}}</span>"
                        : p.contains(area[1])
                        ? "<i class=\"fas fa-eye text-primary\" aria-hidden=\"true\"></i><span class=\"ms-1 matrix-label\">{{t:adm.can.view}}</span>"
                        : "<i class=\"fas fa-minus text-muted\" aria-hidden=\"true\"></i><span class=\"ms-1 text-muted matrix-label\">{{t:adm.can.none}}</span>";
                rows.append("<td class=\"text-center\" data-role=\"").append(role).append("\">").append(cell).append("</td>");
            }
            rows.append("</tr>\n");
        }
        return "<div class=\"table-responsive\"><table class=\"table table-sm align-middle mb-0\" id=\"roleMatrix\">"
             + "<thead><tr><th scope=\"col\">{{t:adm.area}}</th>" + head + "</tr></thead><tbody>" + rows + "</tbody></table></div>"
             + "<p class=\"small text-muted mt-2 mb-0 d-sm-none\" aria-hidden=\"true\">"
             + "<i class=\"fas fa-pen text-success\"></i> {{t:adm.can.manage}} &middot; "
             + "<i class=\"fas fa-eye text-primary\"></i> {{t:adm.can.view}} &middot; "
             + "<i class=\"fas fa-minus\"></i> {{t:adm.can.none}}</p>";
    }

    // ============== ACCOUNT.HTML ==============
    /**
     * Il proprio account: email di accesso, passkey, sessioni e nome utente. Ogni ruolo ci arriva
     * dal pulsante col proprio nome in alto. Prima stava dentro Impostazioni, che ora e' solo del
     * superadmin.
     */
    public static String getAccountHtml() {
        return getHead("nav.account", "account", "") + """
    <div id="main" tabindex="-1" class="content container mt-4">
        <div class="content-container">
            <h2><i class="fas fa-user-gear me-2" aria-hidden="true"></i>{{t:nav.account}}</h2>
            <p class="text-muted">{{t:acc.pageIntro}}</p>
            <div class="row">
                <div class="col-lg-6">
""" + getAccountCards() + """
                </div>
                <div class="col-lg-6">
""" + getChangeUsernameCard() + """
                </div>
            </div>
        </div>
    </div>
""" + getAccountModals() + getFooterSection() + """
    <script>
""" + getWebAuthnScript() + getSettingsAuthJs() + """
        loadAccount();
        let csrfToken = document.getElementById('csrf_token').value;
    </script>
</body>
</html>
""";
    }

    // ============== ACCESSO NEGATO ==============
    /** La pagina che risponde, con 403, a chi apre una pagina che il suo ruolo non puo' vedere. */
    public static String getForbiddenHtml() {
        return getHead("access.title", "forbidden", "") + """
    <div id="main" tabindex="-1" class="content container mt-4">
        <div class="content-container">
            <div class="text-center py-5">
                <i class="fas fa-ban fa-3x text-danger mb-3" aria-hidden="true"></i>
                <h2>{{t:access.title}}</h2>
                <p class="text-muted mx-auto" style="max-width: 36rem">{{t:access.text}}</p>
                <a class="btn btn-primary mt-2" href="/home"><i class="fas fa-gauge-high me-1" aria-hidden="true"></i>{{t:access.home}}</a>
            </div>
        </div>
    </div>
""" + getFooterSection() + """
</body>
</html>
""";
    }

    // ============== ADMINS.HTML ==============
    public static String getAdminsHtml() {
        // Sul telefono cinque colonne di parole non ci stanno: nella tabella dei ruoli restano le
        // icone (il testo lo leggono gli screen reader, sotto c'e' la legenda) e i nomi dei ruoli
        // in testa alle colonne vanno in verticale.
        String extraStyles = """
        @media (max-width: 575.98px) {
            #roleMatrix td { position: relative; }
            #roleMatrix .matrix-label { position: absolute; left: 0; top: 0; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
            #roleMatrix thead .role-badge { writing-mode: vertical-rl; transform: rotate(180deg); padding: .45em .3em; }
            #roleMatrix th[scope="row"] { font-weight: 500; font-size: .85rem; }
        }
        """;
        return getHead("nav.admins", "admins", extraStyles) + """
    <div id="main" tabindex="-1" class="content container mt-4">
        <div class="content-container">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h2><i class="fas fa-users-cog me-2" aria-hidden="true"></i>{{t:adm.title}}</h2>
                <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addAdminModal">
                    <i class="fas fa-plus me-1" aria-hidden="true"></i>{{t:adm.new}}
                </button>
            </div>

            <!-- Roles Info -->
            <div class="alert alert-info mb-4">
                <h6><i class="fas fa-info-circle me-2" aria-hidden="true"></i>{{t:adm.roles}}</h6>
                <div class="row mt-2">
                    <div class="col-md-3">
                        <span class="badge role-badge superadmin">{{t:adm.rSuperadmin}}</span>
                        <small class="d-block text-muted">{{t:adm.rSuperadminDesc}}</small>
                    </div>
                    <div class="col-md-3">
                        <span class="badge role-badge admin">{{t:adm.rAdmin}}</span>
                        <small class="d-block text-muted">{{t:adm.rAdminDesc}}</small>
                    </div>
                    <div class="col-md-3">
                        <span class="badge role-badge operator">{{t:adm.rOperator}}</span>
                        <small class="d-block text-muted">{{t:adm.rOperatorDesc}}</small>
                    </div>
                    <div class="col-md-3">
                        <span class="badge role-badge viewer">{{t:adm.rViewer}}</span>
                        <small class="d-block text-muted">{{t:adm.rViewerDesc}}</small>
                    </div>
                </div>
            </div>


            <!-- Admins Table -->
            <div class="card">
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-hover tabella-schede">
                            <thead class="table-light">
                                <tr>
                                    <th scope="col">{{t:adm.username}}</th>
                                    <th scope="col">{{t:adm.role}}</th>
                                    <th scope="col">{{t:adm.email}}</th>
                                    <th scope="col">{{t:set.passkeys}}</th>
                                    <th scope="col">{{t:adm.lastLogin}}</th>
                                    <th scope="col">{{t:adm.created}}</th>
                                    <th scope="col">{{t:home.colActions}}</th>
                                </tr>
                            </thead>
                            <tbody id="adminsBody">
                                <tr><td colspan="7" class="text-center text-muted">{{t:common.loading}}</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            <div class="card mb-4">
                <div class="card-header"><i class="fas fa-user-shield me-2" aria-hidden="true"></i>{{t:adm.matrixTitle}}</div>
                <div class="card-body">
""" + roleMatrix() + """
                    <p class="small text-muted mt-3 mb-0">{{t:adm.matrixNote}}</p>
                </div>
            </div>
        </div>
    </div>

    <!-- Add Admin Modal -->
    <div class="modal fade" id="addAdminModal" tabindex="-1">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-user-plus me-2" aria-hidden="true"></i>{{t:adm.newTitle}}</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="{{t:common.close}}"></button>
                </div>
                <div class="modal-body">
                    <form id="addAdminForm">
                        <div class="mb-3">
                            <label class="form-label" for="newUsername">{{t:adm.username}}</label>
                            <input type="text" class="form-control" id="newUsername" required
                                   pattern="^[a-zA-Z0-9_\\-]{3,50}$" minlength="3" maxlength="50" autocomplete="off" autocapitalize="off" spellcheck="false">
                            <small class="text-muted">{{t:adm.usernameHint}}</small>
                        </div>
                        <div class="mb-3">
                            <label class="form-label" for="newEmail">{{t:adm.email}}</label>
                            <input type="email" class="form-control" id="newEmail" required maxlength="254" autocomplete="off"
                                   inputmode="email" autocapitalize="off" spellcheck="false" aria-describedby="newEmailHint">
                            <small class="text-muted" id="newEmailHint">{{t:adm.emailHint}}</small>
                        </div>
                        <div class="mb-3">
                            <label class="form-label" for="newRole">{{t:adm.role}}</label>
                            <select class="form-select" id="newRole">
                                <option value="viewer">{{t:adm.rViewer}}</option>
                                <option value="operator">{{t:adm.rOperator}}</option>
                                <option value="admin">{{t:adm.rAdmin}}</option>
                                <option value="superadmin">{{t:adm.rSuperadmin}}</option>
                            </select>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">{{t:common.cancel}}</button>
                    <button type="button" class="btn btn-primary" onclick="createAdmin()">{{t:adm.create}}</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Edit Admin Modal -->
    <div class="modal fade" id="editAdminModal" tabindex="-1">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-user-edit me-2" aria-hidden="true"></i>{{t:adm.editTitle}}</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="{{t:common.close}}"></button>
                </div>
                <div class="modal-body">
                    <input type="hidden" id="editAdminId">
                    <div class="mb-3">
                        <label class="form-label" for="editUsername">{{t:adm.username}}</label>
                        <input type="text" class="form-control" id="editUsername" readonly>
                    </div>
                    <div class="mb-3">
                        <label class="form-label" for="editEmail">{{t:adm.email}}</label>
                        <input type="email" class="form-control" id="editEmail" maxlength="254" autocomplete="off"
                               inputmode="email" autocapitalize="off" spellcheck="false">
                    </div>
                    <div class="mb-3">
                        <label class="form-label" for="editRole">{{t:adm.role}}</label>
                        <select class="form-select" id="editRole">
                            <option value="viewer">{{t:adm.rViewer}}</option>
                            <option value="operator">{{t:adm.rOperator}}</option>
                            <option value="admin">{{t:adm.rAdmin}}</option>
                            <option value="superadmin">{{t:adm.rSuperadmin}}</option>
                        </select>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">{{t:common.cancel}}</button>
                    <button type="button" class="btn btn-primary" onclick="updateAdmin()">{{t:common.save}}</button>
                </div>
            </div>
        </div>
    </div>
""" + getFooterSection() + """
    <script>
        let csrfToken = document.getElementById('csrf_token').value;

        // Il nome del ruolo nella lingua della pagina; il codice resta quello del server.
        function admRoleLabel(role) {
            return ({ superadmin: t('adm.rSuperadmin'), admin: t('adm.rAdmin'), operator: t('adm.rOperator'), viewer: t('adm.rViewer') })[role] || role;
        }

        const ADM_EMAIL = /^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\\.[A-Za-z]{2,}$/;
        // Le date arrivano in UTC (ISO con la Z): si mostrano nel fuso del browser.
        function admDate(iso) {
            if (!iso) return '';
            const d = new Date(iso);
            return isNaN(d) ? iso : d.toLocaleString(window.I18N_LANG || undefined);
        }
        let admList = [];
        function loadAdmins() {
            fetch('/api/admins?action=list')
                .then(r => r.json())
                .then(data => {
                    const tbody = document.getElementById('adminsBody');
                    if (!data.success) {
                        tbody.innerHTML = '<tr><td colspan="7" class="text-center text-danger">' + escHtml(data.error || t('common.failed')) + '</td></tr>';
                        return;
                    }
                    admList = data.admins || [];
                    if (!admList.length) {
                        tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">' + escHtml(t('adm.none')) + '</td></tr>';
                        return;
                    }
                    // Nomi ed email arrivano dal database, ma ci sono arrivati da una richiesta: tutto
                    // passa da escHtml, e i pulsanti portano solo l'id (data-id), mai il testo.
                    tbody.innerHTML = admList.map(admin => `
                        <tr>
                            <td data-label="${escHtml(t('adm.username'))}" class="testo-lungo">
                                <i class="fas fa-user me-1" aria-hidden="true"></i>${escHtml(admin.username)}
                                ${admin.is_current ? '<span class="badge bg-info ms-1">' + escHtml(t('adm.you')) + '</span>' : ''}
                            </td>
                            <td data-label="${escHtml(t('adm.role'))}"><span class="badge role-badge ${escHtml(admin.role)}">${escHtml(admRoleLabel(admin.role))}</span></td>
                            <td data-label="${escHtml(t('adm.email'))}" class="testo-lungo"><small>${admin.email ? escHtml(admin.email) : '<span class="text-warning">' + escHtml(t('acc.noEmail')) + '</span>'}</small></td>
                            <td data-label="${escHtml(t('set.passkeys'))}"><small>${Number(admin.passkeys) || 0}</small></td>
                            <td data-label="${escHtml(t('adm.lastLogin'))}"><small>${escHtml(admDate(admin.last_login) || t('adm.never'))}</small></td>
                            <td data-label="${escHtml(t('adm.created'))}"><small>${escHtml(admDate(admin.created_at))}</small></td>
                            <td data-label="${escHtml(t('home.colActions'))}">
                                <button class="btn btn-sm btn-outline-primary" data-id="${Number(admin.id)}" onclick="editAdmin(Number(this.dataset.id))"
                                        title="${escHtml(t('common.edit'))}" aria-label="${escHtml(t('adm.editOne', { name: admin.username }))}" ${admin.is_current ? 'disabled' : ''}>
                                    <i class="fas fa-edit" aria-hidden="true"></i>
                                </button>
                                <button class="btn btn-sm btn-outline-danger" data-id="${Number(admin.id)}" onclick="deleteAdmin(Number(this.dataset.id))"
                                        title="${escHtml(t('common.delete'))}" aria-label="${escHtml(t('adm.deleteOne', { name: admin.username }))}" ${admin.is_current ? 'disabled' : ''}>
                                    <i class="fas fa-trash" aria-hidden="true"></i>
                                </button>
                            </td>
                        </tr>
                    `).join('');
                });
        }
        function admPost(body) {
            return fetch('/api/admins', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
                .then(r => r.json());
        }
        function createAdmin() {
            const username = document.getElementById('newUsername').value.trim();
            const email = document.getElementById('newEmail').value.trim();
            const role = document.getElementById('newRole').value;
            if (!/^[A-Za-z0-9_-]{3,50}$/.test(username)) { alert(t('set.usernameInvalid')); return; }
            if (!ADM_EMAIL.test(email) || email.length > 254) { alert(t('login.emailInvalid')); return; }
            admPost({ action: 'create', username: username, email: email, role: role }).then(data => {
                if (data.success) {
                    bootstrap.Modal.getOrCreateInstance(document.getElementById('addAdminModal')).hide();
                    document.getElementById('addAdminForm').reset();
                    loadAdmins();
                } else {
                    alert(data.error || t('common.failed'));
                }
            }).catch(e => alert(t('common.networkError', { message: e.message })));
        }
        function editAdmin(id) {
            const admin = admList.find(a => a.id === id);
            if (!admin) return;
            document.getElementById('editAdminId').value = id;
            document.getElementById('editUsername').value = admin.username;
            document.getElementById('editEmail').value = admin.email || '';
            document.getElementById('editRole').value = admin.role;
            bootstrap.Modal.getOrCreateInstance(document.getElementById('editAdminModal')).show();
        }
        function updateAdmin() {
            const id = Number(document.getElementById('editAdminId').value);
            const role = document.getElementById('editRole').value;
            const email = document.getElementById('editEmail').value.trim();
            if (email && (!ADM_EMAIL.test(email) || email.length > 254)) { alert(t('login.emailInvalid')); return; }
            admPost({ action: 'update', id: id, role: role, email: email }).then(data => {
                if (data.success) {
                    bootstrap.Modal.getOrCreateInstance(document.getElementById('editAdminModal')).hide();
                    loadAdmins();
                } else {
                    alert(data.error || t('common.failed'));
                }
            }).catch(e => alert(t('common.networkError', { message: e.message })));
        }
        function deleteAdmin(id) {
            const admin = admList.find(a => a.id === id);
            if (!admin || !confirm(t('adm.confirmDelete', { name: admin.username }))) return;
            admPost({ action: 'delete', id: id }).then(data => {
                if (data.success) loadAdmins(); else alert(data.error || t('common.failed'));
            }).catch(e => alert(t('common.networkError', { message: e.message })));
        }
        // Load on page load
        loadAdmins();
""" + """
    </script>
</body>
</html>
""";
    }

    // ============== RATELIMITS.HTML ==============
    public static String getRateLimitsHtml() {
        String extraStyles = """
        .limit-disabled td { opacity: 0.6; }
        """;
        return getHead("nav.rateLimits", "ratelimits", extraStyles) + """
    <div id="main" tabindex="-1" class="content container mt-4">
        <div class="content-container">
            <div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-3">
                <h2 class="mb-0"><i class="fas fa-stopwatch me-2" aria-hidden="true"></i>{{t:rl.title}}</h2>
                <div class="d-flex flex-wrap gap-2">
                    <button type="button" class="btn btn-outline-primary btn-sm" onclick="loadRateLimits()">
                        <i class="fas fa-sync" aria-hidden="true"></i> {{t:common.refresh}}
                    </button>
                    <button type="button" class="btn btn-primary btn-sm" onclick="newLimit()">
                        <i class="fas fa-plus" aria-hidden="true"></i> {{t:rl.new}}
                    </button>
                </div>
            </div>

            <!-- I limiti orari e giornalieri stanno nel database ma niente li applica: ne' Postfix
                 ne' Rspamd leggono la tabella rate_limits. Si dice, invece di lasciar credere che
                 ci sia una protezione. La dimensione massima invece e' un parametro di Postfix. -->
            <div class="alert alert-warning small" role="note">
                <i class="fas fa-triangle-exclamation me-1" aria-hidden="true"></i>{{t:rl.notEnforced.html}}
            </div>
            <div id="rlMsg" role="status" aria-live="polite"></div>

            <div class="card mb-4">
                <div class="card-header">
                    <i class="fas fa-globe me-2" aria-hidden="true"></i>{{t:rl.global}}
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-4">
                            <div class="mb-3">
                                <label class="form-label" for="globalHourly">{{t:rl.hourlyPerMailbox}}</label>
                                <input type="number" class="form-control" id="globalHourly" min="1" max="1000000" value="50">
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="mb-3">
                                <label class="form-label" for="globalDaily">{{t:rl.dailyPerMailbox}}</label>
                                <input type="number" class="form-control" id="globalDaily" min="1" max="10000000" value="500">
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="mb-3">
                                <label class="form-label" for="globalMaxSize">{{t:rl.maxSize}}</label>
                                <input type="number" class="form-control" id="globalMaxSize" min="1" max="1024" value="25" aria-describedby="globalMaxSizeHint">
                                <div class="form-text" id="globalMaxSizeHint">{{t:rl.maxSizeHint}}</div>
                            </div>
                        </div>
                    </div>
                    <button type="button" class="btn btn-primary" onclick="saveGlobalLimits()">
                        <i class="fas fa-save me-1" aria-hidden="true"></i>{{t:rl.saveGlobal}}
                    </button>
                </div>
            </div>

            <div class="card">
                <div class="card-header d-flex flex-wrap justify-content-between align-items-center gap-1">
                    <span id="limitsTitle"><i class="fas fa-envelope me-2" aria-hidden="true"></i>{{t:rl.perMailbox}}</span>
                    <small class="text-muted">{{t:rl.perMailboxHint}}</small>
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-hover tabella-schede" aria-labelledby="limitsTitle">
                            <thead>
                                <tr>
                                    <th scope="col">{{t:rl.colMailbox}}</th>
                                    <th scope="col" class="text-center">{{t:rl.colHourly}}</th>
                                    <th scope="col" class="text-center">{{t:rl.colDaily}}</th>
                                    <th scope="col" class="text-center">{{t:rl.colRecipients}}</th>
                                    <th scope="col" class="text-center">{{t:que.colState}}</th>
                                    <th scope="col">{{t:home.colActions}}</th>
                                </tr>
                            </thead>
                            <tbody id="limitsBody">
                                <tr><td colspan="6" class="text-center text-muted">{{t:common.loading}}</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- La sezione "Mittenti lockedPackages" e' stata TOLTA.
                 Non esisteva nessun meccanismo di blocco: ne' una tabella nel database, ne'
                 una regola in Postfix. Era una tabella che scriveva "Nessun blocco attivo"
                 qualunque cosa succedesse, con un pulsante "Sblocca" che rispondeva "azione
                 sconosciuta". Una schermata che dichiara di sorvegliare qualcosa che non
                 sorveglia e' peggio della sua assenza: fa credere di avere una protezione. -->
        </div>
    </div>

    <div class="modal fade" id="addLimitModal" tabindex="-1" aria-labelledby="addLimitTitle" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="addLimitTitle"><i class="fas fa-stopwatch me-2" aria-hidden="true"></i>{{t:rl.modalTitle}}</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="{{t:common.close}}"></button>
                </div>
                <div class="modal-body">
                    <div class="mb-3">
                        <label class="form-label" for="limitMailbox">{{t:rl.colMailbox}}</label>
                        <select class="form-select" id="limitMailbox">
                            <option value="">{{t:rl.chooseMailbox}}</option>
                        </select>
                    </div>
                    <div class="mb-3">
                        <label class="form-label" for="limitHourly">{{t:rl.hourly}}</label>
                        <input type="number" class="form-control" id="limitHourly" min="1" max="1000000" value="50">
                    </div>
                    <div class="mb-3">
                        <label class="form-label" for="limitDaily">{{t:rl.daily}}</label>
                        <input type="number" class="form-control" id="limitDaily" min="1" max="10000000" value="500">
                    </div>
                    <div class="form-check mb-3">
                        <input type="checkbox" class="form-check-input" id="limitEnabled" checked>
                        <label class="form-check-label" for="limitEnabled">{{t:rl.enabled}}</label>
                    </div>
                    <div id="limitErr" class="text-danger small" role="alert"></div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">{{t:common.cancel}}</button>
                    <button type="button" class="btn btn-primary" onclick="saveLimit()">{{t:common.save}}</button>
                </div>
            </div>
        </div>
    </div>
""" + getFooterSection() + """
    <script>
        const csrfToken = document.getElementById('csrf_token').value;
        let currentLimits = [];

        function rlMsg(text, kind) {
            document.getElementById('rlMsg').innerHTML = text
                ? '<div class="alert alert-' + kind + ' py-2 small">' + escHtml(text) + '</div>' : '';
        }

        function rlPost(body) {
            body.csrf_token = csrfToken;
            return fetch('/api/ratelimits', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            }).then(r => r.json());
        }

        function loadRateLimits() {
            // Una sola richiesta: i limiti globali stanno in "globale", le caselle in "limits".
            fetch('/api/ratelimits')
                .then(r => r.json())
                .then(data => {
                    const tbody = document.getElementById('limitsBody');
                    if (!data.success) {
                        tbody.innerHTML = '<tr><td colspan="6" class="text-center text-danger">' + escHtml(data.error || t('common.unknownErrorCap')) + '</td></tr>';
                        return;
                    }
                    const g = data.global || {};
                    document.getElementById('globalHourly').value = g.hourly || 50;
                    document.getElementById('globalDaily').value = g.daily || 500;
                    if (g.max_size_mb !== null && g.max_size_mb !== undefined) document.getElementById('globalMaxSize').value = g.max_size_mb;
                    if (g.max_size_note) rlMsg(g.max_size_note, 'warning');
                    currentLimits = data.limits || [];
                    if (!currentLimits.length) {
                        tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">' + escHtml(t('rl.none')) + '</td></tr>';
                        return;
                    }
                    // La colonna "Uso Oggi" mostrava un conteggio che nessuno calcola: il pannello
                    // non tiene traccia degli invii per casella. Al suo posto c'e' un dato che
                    // esiste davvero, il numero massimo di destinatari.
                    tbody.innerHTML = currentLimits.map(limit => {
                        const who = escHtml(limit.email);
                        return `<tr class="${limit.enabled ? '' : 'limit-disabled'}">
                            <td data-label="${escHtml(t('rl.colMailbox'))}" class="testo-lungo"><i class="fas fa-envelope me-1" aria-hidden="true"></i>${who}</td>
                            <td data-label="${escHtml(t('rl.colHourly'))}" class="text-center">${escHtml(limit.hourly_limit)}</td>
                            <td data-label="${escHtml(t('rl.colDaily'))}" class="text-center">${escHtml(limit.daily_limit)}</td>
                            <td data-label="${escHtml(t('rl.colRecipients'))}" class="text-center">${escHtml(limit.max_recipients)}</td>
                            <td data-label="${escHtml(t('que.colState'))}" class="text-center">${limit.enabled
                                ? '<span class="badge bg-success">' + escHtml(t('rl.active')) + '</span>'
                                : '<span class="badge bg-secondary">' + escHtml(t('mbx.inactive')) + '</span>'}</td>
                            <td data-label="${escHtml(t('home.colActions'))}" class="text-nowrap">
                                <button type="button" class="btn btn-sm btn-outline-primary" data-limit-edit="${escHtml(limit.id)}" aria-label="${escHtml(t('rl.editOf', { mailbox: limit.email }))}" title="${escHtml(t('common.edit'))}">
                                    <i class="fas fa-edit" aria-hidden="true"></i>
                                </button>
                                <button type="button" class="btn btn-sm btn-outline-danger" data-limit-delete="${escHtml(limit.id)}" aria-label="${escHtml(t('rl.deleteOf', { mailbox: limit.email }))}" title="${escHtml(t('common.delete'))}">
                                    <i class="fas fa-trash" aria-hidden="true"></i>
                                </button>
                            </td>
                        </tr>`;
                    }).join('');
                })
                .catch(() => rlMsg(t('common.noAnswer'), 'danger'));
            loadMailboxes();
        }

        function loadMailboxes() {
            fetch('/api/mailboxes')
                .then(r => r.json())
                .then(data => {
                    const select = document.getElementById('limitMailbox');
                    const keep = select.value;
                    select.innerHTML = '<option value="">' + escHtml(t('rl.chooseMailbox')) + '</option>'
                        + (data.mailboxes || []).map(m => '<option value="' + escHtml(m.id) + '">' + escHtml(m.email) + '</option>').join('');
                    select.value = keep;
                })
                .catch(() => {});
        }

        function saveGlobalLimits() {
            rlMsg('', '');
            rlPost({
                action: 'save_global',
                hourly: parseInt(document.getElementById('globalHourly').value, 10) || 0,
                daily: parseInt(document.getElementById('globalDaily').value, 10) || 0,
                max_size_mb: parseInt(document.getElementById('globalMaxSize').value, 10) || 0
            }).then(data => {
                rlMsg(data.success ? (data.message || t('common.done')) : (data.error || t('common.unknownErrorCap')), data.success ? 'success' : 'danger');
            }).catch(() => rlMsg(t('common.noAnswer'), 'danger'));
        }

        function openLimitModal(limit) {
            const select = document.getElementById('limitMailbox');
            select.value = limit ? String(limit.target_id) : '';
            // Il limite e' legato alla casella: per un'altra casella se ne crea uno nuovo
            select.disabled = !!limit;
            document.getElementById('limitHourly').value = limit ? limit.hourly_limit : 50;
            document.getElementById('limitDaily').value = limit ? limit.daily_limit : 500;
            document.getElementById('limitEnabled').checked = limit ? !!limit.enabled : true;
            document.getElementById('limitErr').textContent = '';
            bootstrap.Modal.getOrCreateInstance(document.getElementById('addLimitModal')).show();
        }

        function newLimit() {
            openLimitModal(null);
        }

        document.getElementById('limitsBody').addEventListener('click', e => {
            const b = e.target.closest('button');
            if (!b) return;
            const id = parseInt(b.dataset.limitEdit || b.dataset.limitDelete, 10);
            const limit = currentLimits.find(x => x.id === id);
            if (!limit) return;
            if (b.dataset.limitEdit) openLimitModal(limit);
            else deleteLimit(limit);
        });

        function saveLimit() {
            const mailboxId = parseInt(document.getElementById('limitMailbox').value, 10);
            const err = document.getElementById('limitErr');
            if (!mailboxId) {
                err.textContent = t('rl.chooseMailboxFirst');
                return;
            }
            rlPost({
                action: 'save_mailbox',
                mailbox_id: mailboxId,
                hourly: parseInt(document.getElementById('limitHourly').value, 10) || 0,
                daily: parseInt(document.getElementById('limitDaily').value, 10) || 0,
                enabled: document.getElementById('limitEnabled').checked
            }).then(data => {
                if (data.success) {
                    bootstrap.Modal.getInstance(document.getElementById('addLimitModal')).hide();
                    rlMsg(data.message || t('common.done'), 'success');
                    loadRateLimits();
                } else {
                    err.textContent = data.error || t('common.unknownErrorCap');
                }
            }).catch(() => { err.textContent = t('common.noAnswer'); });
        }

        function deleteLimit(limit) {
            if (!confirm(t('rl.confirmDelete', { mailbox: limit.email }))) return;
            rlPost({ action: 'delete', id: limit.id }).then(data => {
                rlMsg(data.success ? t('rl.deleted', { mailbox: limit.email }) : (data.error || t('common.unknownErrorCap')), data.success ? 'success' : 'danger');
                if (data.success) loadRateLimits();
            }).catch(() => rlMsg(t('common.noAnswer'), 'danger'));
        }

        loadRateLimits();
    </script>
</body>
</html>
""";
    }

    // ============== FIREWALL.HTML — Geo-firewall pf con whitelist paesi + CIDR ==============
    public static String getFirewallHtml() {
        String extraStyles = """
        .fw-mode-card {
            cursor: pointer; padding: 12px; border: 2px solid rgba(128,128,128,0.35);
            border-radius: 8px; transition: all .15s;
            background: transparent; color: inherit; width: 100%; text-align: left; height: 100%;
        }
        .fw-mode-card:hover { border-color: rgba(13,110,253,0.6); }
        .fw-mode-card.active {
            border-color: #0d6efd;
            background: rgba(13,110,253,0.15);
        }
        .fw-country-grid {
            display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
            gap: 6px; max-height: 360px; overflow-y: auto;
            padding: 8px; border: 1px solid rgba(128,128,128,0.3); border-radius: 6px;
        }
        .fw-country-item {
            padding: 6px 10px; border-radius: 4px; cursor: pointer; user-select: none;
            display: flex; align-items: center; gap: 6px; font-size: .9rem;
            transition: background .1s, border-color .1s;
            border: 1px solid transparent;
        }
        .fw-country-item:hover { background: rgba(128,128,128,0.12); }
        .fw-country-item.selected {
            background: rgba(13,110,253,0.15);
            border-color: rgba(13,110,253,0.5);
        }
        .fw-country-item.selected .flag { filter: none; }
        .fw-country-item.selected strong { color: var(--bs-primary, #0d6efd); }
        .fw-country-item input[type=checkbox] { margin: 0; flex-shrink: 0; }
        .fw-country-item .flag { font-size: 1.1rem; }
        .fw-country-item .badge-cidr {
            margin-left: auto; font-size: .7rem;
            color: var(--bs-secondary-color, #6c757d);
        }
        /* Divider tra "comuni" e "alfabetico" dentro l'unico grid */
        .fw-country-separator {
            grid-column: 1 / -1;
            padding: 4px 0 2px 0;
            font-size: .75rem;
            font-weight: 600;
            color: var(--bs-secondary-color, #6c757d);
            text-transform: uppercase;
            letter-spacing: .03em;
            border-top: 1px solid rgba(128,128,128,0.25);
            margin-top: 4px;
        }
        .fw-country-separator:first-child {
            border-top: none;
            margin-top: 0;
        }
        .fw-cidr-item {
            display: inline-flex; align-items: center; gap: 6px;
            padding: 4px 10px; margin: 0 4px 4px 0;
            border: 1px solid rgba(128,128,128,0.4); border-radius: 999px;
            font-family: monospace; font-size: .85rem;
        }
        .fw-cidr-item .btn-remove {
            border: none; background: transparent; color: #dc3545; padding: 0;
            cursor: pointer; line-height: 1;
        }
        .fw-warning-banner {
            background: rgba(255,193,7,0.15); border-left: 4px solid #ffc107;
            padding: 10px 12px; border-radius: 4px;
        }
        """;
        return getHead("nav.firewall", "firewall", extraStyles) + """
    <div id="main" tabindex="-1" class="content container-fluid mt-4" style="max-width: 1200px">

        <div class="d-flex justify-content-between align-items-center mb-3 flex-wrap gap-2">
            <h2 class="mb-0"><i class="fas fa-fire me-2" aria-hidden="true"></i>{{t:fw.title}}</h2>
            <div class="d-flex gap-2">
                <button class="btn btn-outline-secondary btn-sm" onclick="loadFirewall()" title="{{t:fw.reload}}" aria-label="{{t:fw.reload}}">
                    <i class="fas fa-sync" aria-hidden="true"></i>
                </button>
                <button class="btn btn-success" onclick="fwApply()" title="{{t:fw.applyHint}}">
                    <i class="fas fa-check-circle me-1" aria-hidden="true"></i>{{t:fw.apply}}
                </button>
            </div>
        </div>

        <!-- Stato -->
        <div class="card mb-3 border-primary">
            <div class="card-header bg-primary text-white py-2">
                <i class="fas fa-info-circle me-2" aria-hidden="true"></i>{{t:fw.statusTitle}}
            </div>
            <div class="card-body py-2" id="fwStatusBody" aria-live="polite">
                <p class="text-muted mb-0"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>{{t:common.loading}}</p>
            </div>
        </div>

        <!-- Modalita' -->
        <div class="card mb-3">
            <div class="card-header py-2"><i class="fas fa-cog me-2" aria-hidden="true"></i>{{t:fw.mode}}</div>
            <div class="card-body">
                <p class="small text-muted mb-3">{{t:fw.modeIntro.html}}</p>
                <div class="row g-2" id="fwModeContainer"></div>

                <div class="mt-3" id="fwPort25Row" style="display:none">
                    <div class="form-check">
                        <input type="checkbox" class="form-check-input" id="fwPort25Geo" onchange="fwSetPort25Geo(this.checked)">
                        <label class="form-check-label small" for="fwPort25Geo">
                            {{t:fw.port25Label.html}}
                            <i class="fas fa-exclamation-triangle text-warning ms-1" aria-hidden="true"></i>
                        </label>
                    </div>
                    <div class="alert alert-warning py-2 px-2 mt-2 mb-0 small">
                        <p class="mb-2"><i class="fas fa-info-circle me-1" aria-hidden="true"></i>{{t:fw.port25What.html}}</p>
                        <p class="mb-2">{{t:fw.port25If.html}}</p>
                        <p class="mb-2"><i class="fas fa-exclamation-triangle me-1" aria-hidden="true"></i>{{t:fw.port25When.html}}</p>
                        <p class="mb-0"><i class="fas fa-lightbulb me-1" aria-hidden="true"></i>{{t:fw.port25Advice.html}}</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Aggiornamento automatico GeoIP -->
        <div class="card mb-3 border-info">
            <div class="card-header py-2 d-flex justify-content-between align-items-center flex-wrap gap-2 bg-info bg-opacity-10">
                <span><i class="fas fa-cloud-download-alt me-2" aria-hidden="true"></i>{{t:fw.autoSyncTitle}} <span id="fwAutoSyncStatus"></span></span>
                <div>
                    <button class="btn btn-warning btn-sm me-1" onclick="fwSyncAll()" title="{{t:fw.syncNowHint}}">
                        <i class="fas fa-sync me-1" aria-hidden="true"></i>{{t:fw.syncNow}}
                    </button>
                </div>
            </div>
            <div class="card-body">
                <div id="fwAutoSyncSummary" class="small mb-2 text-muted">{{t:common.loading}}</div>
                <div class="row g-2 align-items-end">
                    <div class="col-md-4">
                        <div class="form-check form-switch">
                            <input type="checkbox" class="form-check-input" id="fwAutoSyncEnabled">
                            <label class="form-check-label small" for="fwAutoSyncEnabled">
                                <strong>{{t:fw.autoSyncOn}}</strong>
                                <span class="d-block text-muted" style="font-size:.75rem">{{t:fw.autoSyncOnHint}}</span>
                            </label>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <label class="form-label small mb-1" for="fwAutoSyncInterval">{{t:fw.interval}}</label>
                        <select class="form-select form-select-sm" id="fwAutoSyncInterval">
                            <option value="1">{{t:fw.every1}}</option>
                            <option value="3">{{t:fw.every3}}</option>
                            <option value="7" selected>{{t:fw.every7}}</option>
                            <option value="14">{{t:fw.every14}}</option>
                            <option value="30">{{t:fw.every30}}</option>
                        </select>
                    </div>
                    <div class="col-md-4">
                        <button class="btn btn-primary btn-sm w-100" onclick="fwSaveAutoSync()">
                            <i class="fas fa-save me-1" aria-hidden="true"></i>{{t:fw.saveAutoSync}}
                        </button>
                    </div>
                </div>
                <div class="alert alert-info py-2 px-2 mt-2 mb-0 small">
                    <i class="fas fa-info-circle me-1" aria-hidden="true"></i>{{t:fw.autoSyncHow.html}}
                </div>
            </div>
        </div>

        <!-- Paesi -->
        <div class="card mb-3" id="fwCountriesCard">
            <div class="card-header py-2 d-flex justify-content-between align-items-center flex-wrap gap-2">
                <span><i class="fas fa-globe me-2" aria-hidden="true"></i>{{t:fw.countries}} <span class="badge bg-secondary ms-1" id="fwCountriesCount">0</span></span>
                <button class="btn btn-warning btn-sm" onclick="fwSyncAll()" title="{{t:fw.syncGeoHint}}">
                    <i class="fas fa-cloud-download-alt me-1" aria-hidden="true"></i>{{t:fw.syncGeo}}
                </button>
            </div>
            <div class="card-body">
                <p class="small text-muted mb-2">{{t:fw.countriesIntro.html}}</p>

                <!-- Preset (UE, G7, NATO...) -->
                <div class="mb-2">
                    <div class="d-flex justify-content-between align-items-center mb-1 flex-wrap gap-1">
                        <strong class="small" id="fwPresetsLabel">{{t:fw.presets}}</strong>
                        <div class="btn-group btn-group-sm" role="group" aria-label="{{t:fw.presetMode}}">
                            <input type="radio" class="btn-check" name="fwPresetMode" id="fwPresetModeReplace" value="replace" checked>
                            <label class="btn btn-outline-primary" for="fwPresetModeReplace" title="{{t:fw.replaceHint}}">
                                <i class="fas fa-exchange-alt me-1" aria-hidden="true"></i>{{t:fw.replace}}
                            </label>
                            <input type="radio" class="btn-check" name="fwPresetMode" id="fwPresetModeAdd" value="add">
                            <label class="btn btn-outline-success" for="fwPresetModeAdd" title="{{t:fw.addHint}}">
                                <i class="fas fa-plus me-1" aria-hidden="true"></i>{{t:common.add}}
                            </label>
                        </div>
                    </div>
                    <div class="d-flex flex-wrap gap-1" id="fwPresetGroups" role="group" aria-labelledby="fwPresetsLabel"></div>
                </div>

                <!-- Selezione in blocco -->
                <div class="d-flex flex-wrap gap-1 mb-2">
                    <button id="fwToggleOnlySelected" class="btn btn-outline-info btn-sm" onclick="fwToggleOnlySelected()" title="{{t:fw.onlySelectedHint}}" aria-pressed="false">
                        <i class="fas fa-filter me-1" aria-hidden="true"></i>{{t:fw.onlySelected}}
                    </button>
                    <button class="btn btn-outline-primary btn-sm" onclick="fwSelectAllVisible()" title="{{t:fw.selectVisibleHint}}">
                        <i class="fas fa-check-double me-1" aria-hidden="true"></i>{{t:fw.selectVisible}}
                    </button>
                    <button class="btn btn-outline-secondary btn-sm" onclick="fwDeselectAllVisible()" title="{{t:fw.deselectVisibleHint}}">
                        <i class="fas fa-times me-1" aria-hidden="true"></i>{{t:fw.deselectVisible}}
                    </button>
                    <button class="btn btn-outline-danger btn-sm" onclick="fwClearAllCountries()" title="{{t:fw.clearHint}}">
                        <i class="fas fa-trash me-1" aria-hidden="true"></i>{{t:fw.clear}}
                    </button>
                </div>

                <input type="text" class="form-control form-control-sm mb-2" id="fwCountrySearch" maxlength="60"
                       placeholder="{{t:fw.searchPlaceholder}}" aria-label="{{t:fw.search}}" oninput="fwFilterCountries()">
                <div class="small mb-2"><strong id="fwGridLabel">{{t:fw.available}}</strong></div>
                <div class="fw-country-grid" id="fwCountriesGrid" style="max-height: 500px" role="group" aria-labelledby="fwGridLabel"></div>
                <div class="alert alert-info py-2 px-2 mt-2 mb-0 small">
                    <i class="fas fa-info-circle me-1" aria-hidden="true"></i>{{t:fw.blueHint}}
                </div>

                <!-- Editor dei codici, nei due sensi -->
                <div class="mt-3 pt-3" style="border-top: 1px solid rgba(128,128,128,0.25)">
                    <div class="d-flex justify-content-between align-items-center mb-2 flex-wrap gap-2">
                        <strong class="small" id="fwCodeEditorLabel"><i class="fas fa-code me-1" aria-hidden="true"></i>{{t:fw.codeEditor}}</strong>
                        <div class="d-flex gap-1 align-items-center flex-wrap">
                            <label class="small mb-0" for="fwCodeFormat">{{t:fw.format}}</label>
                            <select class="form-select form-select-sm" id="fwCodeFormat" style="width:auto;max-width:100%" onchange="renderFwCodeEditor()">
                                <option value="cf_ne">{{t:fw.fmtCfNe}}</option>
                                <option value="cf_eq">{{t:fw.fmtCfEq}}</option>
                                <option value="csv" selected>{{t:fw.fmtCsv}}</option>
                                <option value="json">{{t:fw.fmtJson}}</option>
                                <option value="lines">{{t:fw.fmtLines}}</option>
                            </select>
                            <button class="btn btn-sm btn-outline-secondary" onclick="fwCopyCodeEditor()" title="{{t:fw.copyClipboard}}" aria-label="{{t:fw.copyClipboard}}">
                                <i class="fas fa-copy" aria-hidden="true"></i>
                            </button>
                        </div>
                    </div>
                    <textarea id="fwCodeEditor" class="form-control" rows="4" maxlength="20000"
                              style="font-family: monospace; font-size: .85rem"
                              placeholder="{{t:fw.editorPlaceholder}}" aria-labelledby="fwCodeEditorLabel"
                              oninput="fwScheduleCodeApply()"></textarea>
                    <div class="d-flex justify-content-between align-items-center mt-1 flex-wrap gap-1">
                        <div id="fwCodeEditorStatus" class="small" role="status">{{t:fw.ready}}</div>
                        <button class="btn btn-primary btn-sm" onclick="fwApplyCodeEditorNow()">
                            <i class="fas fa-check me-1" aria-hidden="true"></i>{{t:fw.applyNow}}
                        </button>
                    </div>
                    <div class="alert alert-info py-2 px-2 mt-2 mb-0 small">
                        <i class="fas fa-info-circle me-1" aria-hidden="true"></i>{{t:fw.editorHint.html}}
                    </div>
                </div>
            </div>
        </div>

        <!-- Whitelist CIDR -->
        <div class="card mb-3">
            <div class="card-header py-2 d-flex justify-content-between align-items-center">
                <span><i class="fas fa-check-circle text-success me-2" aria-hidden="true"></i>{{t:fw.wlTitle}}</span>
                <span class="badge bg-success" id="fwWlCount">0</span>
            </div>
            <div class="card-body">
                <p class="small text-muted mb-2">{{t:fw.wlIntro.html}}</p>
                <div id="fwWlList" class="mb-2"><span class="text-muted small">{{t:fw.noWl}}</span></div>
                <div class="row g-2">
                    <div class="col-md-9"><input type="text" class="form-control form-control-sm" id="fwWlInput" maxlength="43" placeholder="{{t:fw.wlPlaceholder}}" aria-label="{{t:fw.wlInput}}"></div>
                    <div class="col-md-3"><button class="btn btn-success btn-sm w-100" onclick="fwAddCidr('wl')"><i class="fas fa-plus me-1" aria-hidden="true"></i>{{t:common.add}}</button></div>
                </div>
            </div>
        </div>

        <!-- Blacklist CIDR -->
        <div class="card mb-3">
            <div class="card-header py-2 d-flex justify-content-between align-items-center">
                <span><i class="fas fa-ban text-danger me-2" aria-hidden="true"></i>{{t:fw.blTitle}}</span>
                <span class="badge bg-danger" id="fwBlCount">0</span>
            </div>
            <div class="card-body">
                <p class="small text-muted mb-2">{{t:fw.blIntro.html}}</p>
                <div id="fwBlList" class="mb-2"><span class="text-muted small">{{t:fw.noBl}}</span></div>
                <div class="row g-2">
                    <div class="col-md-9"><input type="text" class="form-control form-control-sm" id="fwBlInput" maxlength="43" placeholder="{{t:fw.blPlaceholder}}" aria-label="{{t:fw.blInput}}"></div>
                    <div class="col-md-3"><button class="btn btn-danger btn-sm w-100" onclick="fwAddCidr('bl')"><i class="fas fa-plus me-1" aria-hidden="true"></i>{{t:common.add}}</button></div>
                </div>
            </div>
        </div>

        <!-- Avvertenze prima di applicare -->
        <div class="fw-warning-banner mb-3">
            <strong><i class="fas fa-exclamation-triangle me-1" aria-hidden="true"></i>{{t:fw.beforeApply}}</strong>
            <ul class="small mb-0 mt-1 ps-3">
                <li>{{t:fw.before1.html}}</li>
                <li>{{t:fw.before2.html}}</li>
                <li>{{t:fw.before3.html}}</li>
                <li>{{t:fw.before4.html}}</li>
            </ul>
        </div>
    </div>
""" + getFooterSection() + """
    <script>
""" + getFirewallJs() + """
""" + """
    </script>
</body>
</html>
""";
    }

    /** JS della pagina /firewall (estratto per non sforare il constant pool). */
    private static String getFirewallJs() {
        return """
        let __fwCsrf = '';
        let __fwState = null;     // ultimo stato ricevuto dal server
        let __fwCatalog = [];     // lista paesi del catalogo

        // CSRF token: riusa quello globale dell'app se presente
        try {
            const el = document.getElementById('csrf_token');
            if (el && el.value) __fwCsrf = el.value;
        } catch (e) {}

        // Modalita' disponibili (nome + descrizione, nella lingua della pagina)
        const FW_MODES = [
            { value: 'CIDR_ONLY',     label: t('fw.mCidr'),  desc: t('fw.mCidrDesc') },
            { value: 'GEO_WHITELIST', label: t('fw.mGeoWl'), desc: t('fw.mGeoWlDesc'), recommended: true },
            { value: 'GEO_BLACKLIST', label: t('fw.mGeoBl'), desc: t('fw.mGeoBlDesc') },
            { value: 'DISABLED',      label: t('fw.mOff'),   desc: t('fw.mOffDesc') }
        ];

        // I preset arrivano dal server con nome e descrizione in italiano: qui quelli della pagina.
        const FW_GROUP_TEXT = {
            italy:    { label: t('fw.gItaly'),   desc: t('fw.gItalyDesc') },
            eu27:     { label: t('fw.gEu27'),    desc: t('fw.gEu27Desc') },
            eu_efta:  { label: t('fw.gEuEfta'),  desc: t('fw.gEuEftaDesc') },
            g7:       { desc: t('fw.gG7Desc') },
            nato:     { desc: t('fw.gNatoDesc') },
            usa:      { label: t('fw.gUsa'),     desc: t('fw.gUsaDesc') },
            north_am: { label: t('fw.gNorthAm'), desc: t('fw.gNorthAmDesc') }
        };
        function fwGroupLabel(g) { return (FW_GROUP_TEXT[g.id] && FW_GROUP_TEXT[g.id].label) || g.label || g.id; }
        function fwGroupDesc(g) { return (FW_GROUP_TEXT[g.id] && FW_GROUP_TEXT[g.id].desc) || g.description || ''; }

        // Il nome del paese nella lingua della pagina (Intl), con quello del catalogo come riserva.
        let __fwRegionNames = null;
        try { __fwRegionNames = new Intl.DisplayNames([window.I18N_LANG], { type: 'region' }); } catch (e) {}
        function fwCountryName(c) {
            try {
                const n = __fwRegionNames && __fwRegionNames.of(String(c.code).toUpperCase());
                if (n && n.toUpperCase() !== String(c.code).toUpperCase()) return n;
            } catch (e) {}
            return c.name;
        }

        // ===== Status JSON loader =====
        function loadFirewall() {
            fetch('/api/firewall').then(r => r.json()).then(data => {
                if (!data.success) {
                    document.getElementById('fwStatusBody').innerHTML =
                        '<div class="text-danger">' + escHtml(t('common.error', { message: data.error || t('common.unknownError') })) + '</div>';
                    return;
                }
                __fwState = data;
                __fwCatalog = data.country_catalog || [];
                renderFwStatus();
                renderFwModes();
                renderFwAutoSync();
                renderFwPresetGroups();
                renderFwCountries();
                renderFwCodeEditor();
                renderFwCidrList('wl', data.whitelist_cidrs || []);
                renderFwCidrList('bl', data.blacklist_cidrs || []);
                // port25 toggle visibility
                const showPort25 = (data.mode === 'GEO_WHITELIST');
                document.getElementById('fwPort25Row').style.display = showPort25 ? '' : 'none';
                document.getElementById('fwPort25Geo').checked = !!data.apply_geo_to_port25;
            }).catch(e => {
                document.getElementById('fwStatusBody').innerHTML =
                    '<div class="text-danger">' + escHtml(t('common.networkError', { message: e.message })) + '</div>';
            });
        }

        function escapeHtml(s) {
            const d = document.createElement('div');
            d.textContent = s == null ? '' : String(s);
            return d.innerHTML;
        }

        function renderFwStatus() {
            const s = __fwState;
            const ts = s.table_sizes || {};
            const enabledBadge = s.enabled
                ? '<span class="badge bg-success">' + escHtml(t('fw.on')) + '</span>'
                : '<span class="badge bg-secondary">' + escHtml(t('fw.off')) + '</span>';
            const mode = FW_MODES.find(m => m.value === s.mode);
            const modeBadge = '<span class="badge bg-primary">' + escHtml(mode ? mode.label : s.mode) + '</span>';
            const item = (label, value) => '<div><strong>' + escHtml(label) + '</strong> ' + value + '</div>';
            document.getElementById('fwStatusBody').innerHTML =
                '<div class="d-flex flex-wrap gap-3 align-items-center">' +
                item(t('fw.state'), enabledBadge) +
                item(t('fw.modeLabel'), modeBadge) +
                item(t('fw.wlShort'), escHtml(tn('fw.rules', ts.panel_wl_cidrs || 0))) +
                item(t('fw.blShort'), escHtml(tn('fw.rules', ts.panel_bl_cidrs || 0))) +
                item(t('fw.geoWlShort'), escHtml(tn('fw.ips', ts.panel_geo_wl || 0))) +
                item(t('fw.geoBlShort'), escHtml(tn('fw.ips', ts.panel_geo_bl || 0))) +
                '</div>';
        }

        function renderFwModes() {
            const container = document.getElementById('fwModeContainer');
            container.innerHTML = FW_MODES.map(m => {
                const active = (m.value === __fwState.mode);
                const recommended = m.recommended
                    ? '<span class="badge bg-success ms-1" style="font-size:.65rem"><span aria-hidden="true">★ </span>' + escHtml(t('fw.recommended')) + '</span>' : '';
                return '<div class="col-md-6">' +
                    '<button type="button" class="fw-mode-card' + (active ? ' active' : '') + '" aria-pressed="' + active + '"'
                    + ' data-mode="' + escHtml(m.value) + '" onclick="fwSetMode(this.dataset.mode)">' +
                    '<span class="d-block"><strong>' + escHtml(m.label) + '</strong>' + recommended + '</span>' +
                    '<span class="d-block small text-muted mt-1">' + escHtml(m.desc) + '</span>' +
                    '</button></div>';
            }).join('');
        }

        function fwSetMode(mode) {
            fwPost({ action: 'set_mode', mode: mode }, (data) => loadFirewall());
        }

        function fwSetPort25Geo(value) {
            fwPost({ action: 'set_port25_geo', value: value }, () => loadFirewall());
        }

        // ============================================================
        // EDITOR CODICI PAESI — sincronizzazione bidirezionale con la
        // selezione visiva. L'utente scrive/cancella codici nel textarea
        // → dopo 800ms di pausa parsiamo i codici, calcoliamo diff con
        // la selezione corrente, e applichiamo via bulk_add / bulk_remove.
        // Viceversa, quando l'utente clicca un paese nella griglia, lo
        // state si aggiorna e renderFwCodeEditor() rigenera il testo.
        // ============================================================
        let __fwCodeApplyTimer = null;
        let __fwCodeEditorSelfUpdate = false; // flag per evitare loop

        function fwExtractCodesFromText(text) {
            if (!text) return [];
            // Pattern: 2 lettere consecutive isolate (con word-boundary).
            // Matcha codici paese da qualsiasi formato (CSV, JSON array, Cloudflare expression, una per riga).
            // NB: \\b nel regex deve essere scritto \\\\b nel text block Java per arrivare come \\b al JS.
            const re = /\\b([A-Za-z]{2})\\b/g;
            const seen = new Set();
            const out = [];
            let m;
            while ((m = re.exec(text)) !== null) {
                const cc = m[1].toLowerCase();
                if (!seen.has(cc)) { seen.add(cc); out.push(cc); }
            }
            return out;
        }

        function renderFwCodeEditor() {
            const ta = document.getElementById('fwCodeEditor');
            if (!ta) return;
            const selected = (__fwState && __fwState.geo_countries) ? __fwState.geo_countries.slice() : [];
            // Ordina alfabeticamente per output stabile
            selected.sort();
            const upper = selected.map(c => c.toUpperCase());
            const fmtEl = document.getElementById('fwCodeFormat');
            const fmt = fmtEl ? fmtEl.value : 'csv';
            let text;
            if (upper.length === 0) {
                text = '';
            } else if (fmt === 'cf_ne') {
                text = '(' + upper.map(c => 'ip.geoip.country ne "' + c + '"').join(' and ') + ')';
            } else if (fmt === 'cf_eq') {
                text = '(' + upper.map(c => 'ip.geoip.country eq "' + c + '"').join(' or ') + ')';
            } else if (fmt === 'json') {
                text = JSON.stringify(upper);
            } else if (fmt === 'lines') {
                text = upper.join('\\n');
            } else { // csv
                text = upper.join(', ');
            }
            // Aggiorna il textarea SENZA triggerare l'apply (siamo noi a scrivere, non l'utente)
            __fwCodeEditorSelfUpdate = true;
            ta.value = text;
            __fwCodeEditorSelfUpdate = false;
            // Status: mostra quanti codici sono nel testo
            const statusEl = document.getElementById('fwCodeEditorStatus');
            if (statusEl) {
                statusEl.textContent = upper.length === 0
                    ? t('fw.noneSelected')
                    : tn('fw.inText', upper.length);
                statusEl.className = 'small mt-1 text-muted';
            }
        }

        function fwScheduleCodeApply() {
            if (__fwCodeEditorSelfUpdate) return; // siamo noi a scrivere, ignora
            const statusEl = document.getElementById('fwCodeEditorStatus');
            if (statusEl) {
                statusEl.textContent = t('fw.waitingPause');
                statusEl.className = 'small mt-1 text-warning';
            }
            if (__fwCodeApplyTimer) clearTimeout(__fwCodeApplyTimer);
            __fwCodeApplyTimer = setTimeout(fwApplyCodeEditor, 800);
        }

        /** Bypass del debounce: applica IMMEDIATAMENTE quello che c'e' nel textarea. */
        function fwApplyCodeEditorNow() {
            if (__fwCodeApplyTimer) { clearTimeout(__fwCodeApplyTimer); __fwCodeApplyTimer = null; }
            fwApplyCodeEditor();
        }

        function fwApplyCodeEditor() {
            const ta = document.getElementById('fwCodeEditor');
            const statusEl = document.getElementById('fwCodeEditorStatus');
            if (!ta) return;
            const setStatus = (msg, cls) => {
                if (statusEl) {
                    statusEl.textContent = msg;
                    statusEl.className = 'small ' + (cls || 'text-muted');
                }
            };
            try {
                const text = ta.value || '';
                const codes = fwExtractCodesFromText(text);

                if (!__fwCatalog || __fwCatalog.length === 0) {
                    setStatus(t('fw.noCatalog'), 'text-warning');
                    return;
                }

                const catalogSet = new Set(__fwCatalog.map(c => c.code));
                const validCodes = codes.filter(c => catalogSet.has(c));
                const invalidCodes = codes.filter(c => !catalogSet.has(c));

                const current = new Set(__fwState && __fwState.geo_countries ? __fwState.geo_countries : []);
                const target = new Set(validCodes);

                const toAdd = validCodes.filter(c => !current.has(c));
                const toRemove = [...current].filter(c => !target.has(c));

                if (toAdd.length === 0 && toRemove.length === 0) {
                    setStatus(invalidCodes.length > 0
                        ? t('fw.noChangeInvalid', { codes: invalidCodes.map(c => c.toUpperCase()).join(', ') })
                        : t('fw.noChange'),
                        invalidCodes.length > 0 ? 'text-warning' : 'text-success');
                    return;
                }

                setStatus(t('fw.applying', { add: toAdd.length, remove: toRemove.length }), 'text-info');

                // POST helper con error handling esplicito
                const post = (action, countries) => {
                    if (!countries || countries.length === 0) return Promise.resolve({ success: true, skipped: true });
                    return fetch('/api/firewall', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ action: action, countries: countries, csrf_token: __fwCsrf })
                    }).then(r => {
                        if (!r.ok) throw new Error('HTTP ' + r.status + ' (' + r.statusText + ')');
                        return r.json();
                    }).then(data => {
                        if (data && data.success === false) {
                            throw new Error(data.error || data.message || t('fw.serverFailed'));
                        }
                        return data;
                    });
                };

                // Sequenziale: prima add, poi remove
                post('bulk_add_countries', toAdd)
                    .then(() => post('bulk_remove_countries', toRemove))
                    .then(() => {
                        setStatus(t('fw.applied', { add: toAdd.length, remove: toRemove.length })
                            + (invalidCodes.length > 0 ? '. ' + t('fw.ignored', { codes: invalidCodes.map(c => c.toUpperCase()).join(', ') }) : ''),
                            'text-success');
                        loadFirewall();
                    })
                    .catch(e => {
                        setStatus(t('fw.applyFailed', { message: e && e.message ? e.message : t('common.unknownError') }), 'text-danger');
                    });
            } catch (e) {
                setStatus(t('common.error', { message: e && e.message ? e.message : t('common.unknownError') }), 'text-danger');
            }
        }

        function fwCopyCodeEditor() {
            const ta = document.getElementById('fwCodeEditor');
            if (!ta) return;
            ta.select();
            try {
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(ta.value);
                } else {
                    document.execCommand('copy');
                }
                const statusEl = document.getElementById('fwCodeEditorStatus');
                if (statusEl) {
                    statusEl.textContent = t('fw.copied');
                    statusEl.className = 'small mt-1 text-success';
                }
            } catch (e) {}
        }

        // ===== Helper: freschezza GeoIP =====
        function fmtAgo(seconds) {
            if (!seconds || seconds < 0) return t('fw.never');
            const rtf = new Intl.RelativeTimeFormat(window.I18N_LANG, { numeric: 'auto', style: 'short' });
            if (seconds < 60) return rtf.format(-Math.floor(seconds), 'second');
            if (seconds < 3600) return rtf.format(-Math.floor(seconds / 60), 'minute');
            if (seconds < 86400) return rtf.format(-Math.floor(seconds / 3600), 'hour');
            return rtf.format(-Math.floor(seconds / 86400), 'day');
        }

        function renderFreshnessBadge(freshness, cidrCount, agoSec) {
            if (!freshness || freshness === 'NEVER') {
                return '<span class="text-danger">⚠ ' + escHtml(t('fw.neverSynced')) + '</span>';
            }
            const ago = escHtml(fmtAgo(agoSec));
            if (freshness === 'FRESH') {
                return '<span class="text-success">✓ ' + cidrCount + ' CIDR · ' + ago + '</span>';
            }
            if (freshness === 'AGING') {
                return '<span class="text-warning">⏰ ' + cidrCount + ' CIDR · ' + ago + '</span>';
            }
            if (freshness === 'STALE') {
                return '<span class="text-warning">⚠ ' + escHtml(t('fw.old')) + ' · ' + ago + '</span>';
            }
            return '<span class="text-danger">⚠⚠ ' + escHtml(t('fw.obsolete')) + ' · ' + ago + '</span>';
        }

        // ===== Auto-sync GeoIP =====
        function renderFwAutoSync() {
            const a = (__fwState && __fwState.auto_sync) || {};
            const statusEl = document.getElementById('fwAutoSyncStatus');
            const summaryEl = document.getElementById('fwAutoSyncSummary');
            const enabledEl = document.getElementById('fwAutoSyncEnabled');
            const intervalEl = document.getElementById('fwAutoSyncInterval');

            if (enabledEl) enabledEl.checked = !!a.enabled;
            if (intervalEl) intervalEl.value = String(a.interval_days || 7);

            // Status badge in header
            if (statusEl) {
                statusEl.innerHTML = a.enabled
                    ? '<span class="badge bg-success ms-2">' + escHtml(tn('fw.autoEvery', a.interval_days || 7)) + '</span>'
                    : '<span class="badge bg-secondary ms-2">' + escHtml(t('fw.off')) + '</span>';
            }

            // Summary
            if (summaryEl) {
                const lines = [];
                if (a.last_check_ms) {
                    const checkAgo = fmtAgo((Date.now() - a.last_check_ms) / 1000);
                    lines.push('<i class="fas fa-clock me-1 text-muted" aria-hidden="true"></i>' + escHtml(t('fw.lastCheck')) + ' <strong>' + escHtml(checkAgo) + '</strong>');
                }
                if (a.last_run_ms) {
                    const runAgo = fmtAgo((Date.now() - a.last_run_ms) / 1000);
                    lines.push('<i class="fas fa-cloud-download-alt me-1 text-muted" aria-hidden="true"></i>' + escHtml(t('fw.lastRun')) + ' <strong>' + escHtml(runAgo) + '</strong>');
                } else {
                    lines.push('<i class="fas fa-cloud-download-alt me-1 text-muted" aria-hidden="true"></i>' + escHtml(t('fw.noRunYet')));
                }
                if (a.stale_countries_count > 0) {
                    lines.push('<i class="fas fa-exclamation-triangle me-1 text-warning" aria-hidden="true"></i><span class="text-warning">' + escHtml(tn('fw.staleCount', a.stale_countries_count)) + '</span>');
                } else if (__fwState.geo_countries && __fwState.geo_countries.length > 0) {
                    lines.push('<i class="fas fa-check-circle me-1 text-success" aria-hidden="true"></i><span class="text-success">' + escHtml(t('fw.allFresh')) + '</span>');
                }
                summaryEl.innerHTML = lines.join(' &nbsp;·&nbsp; ');
            }
        }

        function fwSaveAutoSync() {
            const enabled = document.getElementById('fwAutoSyncEnabled').checked;
            const interval = parseInt(document.getElementById('fwAutoSyncInterval').value, 10) || 7;
            fwPost({ action: 'set_auto_sync', enabled: enabled, interval_days: interval }, (data) => {
                alert(data.message || t('fw.saved'));
                loadFirewall();
            });
        }

        // ===== Preset groups (UE, G7, NATO...) =====
        function renderFwPresetGroups() {
            const container = document.getElementById('fwPresetGroups');
            if (!container) return;
            const groups = __fwState.preset_groups || [];
            const selected = new Set(__fwState.geo_countries || []);
            container.innerHTML = groups.map(g => {
                const codes = g.codes || [];
                // Quanti paesi del gruppo sono attualmente selezionati
                let matchCount = 0;
                for (const c of codes) if (selected.has(c)) matchCount++;
                // "fully contained" = tutti i paesi del preset sono presenti nella selezione
                // (anche se ce ne sono altri extra)
                const isFullyContained = (matchCount === codes.length && codes.length > 0);
                // "exact match" = la selezione COINCIDE col preset (modalita' replace giusta)
                const isExactMatch = isFullyContained && selected.size === codes.length;

                let cls = 'btn-outline-primary';
                let badge;
                if (isExactMatch) {
                    // Selezione = esattamente il preset
                    cls = 'btn-primary';
                    badge = '<i class="fas fa-check ms-1" aria-hidden="true"></i><span class="visually-hidden"> ' + escHtml(t('fw.exactMatch')) + '</span>';
                } else if (isFullyContained) {
                    // Tutto il preset e' nella selezione + altri extra
                    cls = 'btn-success';
                    badge = '<i class="fas fa-check-double ms-1" aria-hidden="true"></i><span class="visually-hidden"> ' + escHtml(t('fw.contained')) + '</span>';
                } else if (matchCount > 0) {
                    // Solo alcuni paesi del preset selezionati
                    badge = '<span class="badge bg-light text-dark ms-1" style="font-size:.65rem" title="' + escHtml(t('fw.partial', { n: matchCount, total: codes.length })) + '">' + matchCount + '/' + codes.length + '</span>';
                } else {
                    // Nessun paese del preset selezionato
                    badge = '<span class="badge bg-light text-dark ms-1" style="font-size:.65rem">' + codes.length + '</span>';
                }
                return '<button type="button" class="btn btn-sm ' + cls + '" '
                     + 'data-group="' + escHtml(g.id) + '" onclick="fwApplyPresetGroup(this.dataset.group)" '
                     + 'title="' + escHtml(fwGroupDesc(g)) + '">'
                     + '<span aria-hidden="true">' + escHtml(g.icon || '') + '</span> ' + escHtml(fwGroupLabel(g)) + badge
                     + '</button>';
            }).join('');
        }

        // Helper: rende leggibile una lista di codici paese (es. "🇮🇹 Italia (IT), 🇺🇸 Stati Uniti (US)")
        function fwFormatCountryList(codes, maxShow) {
            if (!codes || codes.length === 0) return t('fw.none');
            const catalogMap = new Map();
            (__fwCatalog || []).forEach(c => catalogMap.set(c.code, c));
            const formatted = codes.map(code => {
                const meta = catalogMap.get(code);
                if (meta) return meta.flag + ' ' + fwCountryName(meta) + ' (' + code.toUpperCase() + ')';
                return code.toUpperCase();
            });
            if (maxShow && formatted.length > maxShow) {
                const shown = formatted.slice(0, maxShow).join(', ');
                return shown + ', ' + t('fw.andMore', { n: formatted.length - maxShow });
            }
            return formatted.join(', ');
        }

        function fwApplyPresetGroup(groupId) {
            const grp = (__fwState.preset_groups || []).find(g => g.id === groupId);
            if (!grp) return;
            const modeEl = document.querySelector('input[name="fwPresetMode"]:checked');
            const mode = modeEl ? modeEl.value : 'replace';

            if (mode === 'add') {
                // Modalita' AGGIUNGI
                const existing = new Set(__fwState.geo_countries || []);
                const toAdd = grp.codes.filter(c => !existing.has(c));
                if (toAdd.length === 0) {
                    alert(t('fw.presetAllSelected', { preset: fwGroupLabel(grp) }));
                    return;
                }
                const msg = tn('fw.confirmPresetAdd', toAdd.length, { preset: fwGroupLabel(grp), list: fwFormatCountryList(toAdd, 20),
                                                                       current: existing.size, total: existing.size + toAdd.length });
                if (!confirm(msg)) return;
                fwPost({ action: 'bulk_add_countries', countries: toAdd }, () => loadFirewall());
            } else {
                // Modalita' SOSTITUISCI: dettagliamo chi viene aggiunto e chi rimosso
                const existing = new Set(__fwState.geo_countries || []);
                const targetSet = new Set(grp.codes);
                const toAdd = grp.codes.filter(c => !existing.has(c));
                const toRemove = [...existing].filter(c => !targetSet.has(c));

                let msg = tn('fw.confirmPresetReplace', grp.codes.length, { preset: fwGroupLabel(grp) }) + '\\n\\n';
                if (toRemove.length > 0) {
                    msg += tn('fw.willRemove', toRemove.length, { list: fwFormatCountryList(toRemove, 15) }) + '\\n\\n';
                }
                if (toAdd.length > 0) {
                    msg += tn('fw.willAdd', toAdd.length, { list: fwFormatCountryList(toAdd, 15) }) + '\\n\\n';
                }
                if (toAdd.length === 0 && toRemove.length === 0) {
                    msg += t('fw.noChangePreset');
                }
                if (!confirm(msg)) return;
                fwPost({ action: 'apply_preset_group', group_id: groupId }, () => loadFirewall());
            }
        }

        // ===== Bulk select/deselect dei paesi VISIBILI (rispetta filtro) =====
        function fwGetVisibleCountryCodes() {
            const codes = [];
            document.querySelectorAll('.fw-country-item').forEach(el => {
                if (el.style.display !== 'none') {
                    const cc = el.getAttribute('data-cc');
                    if (cc) codes.push(cc);
                }
            });
            return codes;
        }

        function fwSelectAllVisible() {
            const codes = fwGetVisibleCountryCodes();
            if (codes.length === 0) { alert(t('fw.noVisible')); return; }
            const alreadySelected = new Set(__fwState.geo_countries || []);
            const toAdd = codes.filter(c => !alreadySelected.has(c));
            if (toAdd.length === 0) { alert(t('fw.allVisibleSelected')); return; }
            if (!confirm(tn('fw.confirmAddN', toAdd.length))) return;
            fwPost({ action: 'bulk_add_countries', countries: toAdd }, () => loadFirewall());
        }

        function fwDeselectAllVisible() {
            const codes = fwGetVisibleCountryCodes();
            const selected = new Set(__fwState.geo_countries || []);
            const toRemove = codes.filter(c => selected.has(c));
            if (toRemove.length === 0) { alert(t('fw.noVisibleSelected')); return; }
            if (!confirm(tn('fw.confirmDeselectN', toRemove.length))) return;
            fwPost({ action: 'bulk_remove_countries', countries: toRemove }, () => loadFirewall());
        }

        function fwClearAllCountries() {
            const n = (__fwState.geo_countries || []).length;
            if (n === 0) { alert(t('fw.noneSelected')); return; }
            if (!confirm(tn('fw.confirmClear', n))) return;
            fwPost({ action: 'clear_countries' }, () => loadFirewall());
        }

        // ===== Countries: SINGOLA GRIGLIA =====
        function renderFwCountries() {
            const selected = new Set(__fwState.geo_countries || []);
            const detailMap = {};
            (__fwState.geo_detail || []).forEach(d => { detailMap[d.code] = d; });

            const renderItem = (c) => {
                const detail = detailMap[c.code];
                const cidrCount = detail ? detail.cidr_count : 0;
                const freshness = detail ? detail.freshness : null;
                const agoSec = detail ? detail.ago_seconds : 0;
                const isSelected = selected.has(c.code);
                const cidrBadge = isSelected
                    ? '<span class="badge-cidr">' + renderFreshnessBadge(freshness, cidrCount, agoSec) + '</span>'
                    : '';
                const isChecked = isSelected ? ' checked' : '';
                const selClass = isSelected ? ' selected' : '';
                const name = fwCountryName(c);
                const nameHtml = isSelected
                    ? '<strong>' + escHtml(name) + '</strong>'
                    : escHtml(name);
                // La ricerca trova il paese col nome della pagina e con quello del catalogo.
                const searchable = (name + ' ' + c.name).toLowerCase();
                return '<label class="fw-country-item' + selClass + '" data-cc="' + escHtml(c.code) + '" data-name="' + escHtml(searchable) + '" data-common="' + (c.common ? '1' : '0') + '">' +
                       '<input type="checkbox" onchange="fwToggleCountry(this.closest(\\'label\\').dataset.cc, this.checked)"' + isChecked + '>' +
                       '<span class="flag" aria-hidden="true">' + escHtml(c.flag) + '</span>' +
                       '<span>' + nameHtml + '</span>' +
                       '<span class="text-muted small">(' + escHtml(c.code) + ')</span>' +
                       cidrBadge +
                       '</label>';
            };

            // Lista UNICA in ordine alfabetico, nella lingua della pagina
            const all = __fwCatalog.slice().sort((a, b) => fwCountryName(a).localeCompare(fwCountryName(b), window.I18N_LANG));
            const grid = document.getElementById('fwCountriesGrid');
            grid.innerHTML = all.map(renderItem).join('');

            // Aggiorna il counter selezionati nella header
            document.getElementById('fwCountriesCount').textContent = selected.size;
            fwFilterCountries();
        }

        // Stato del toggle "solo selezionati"
        let __fwOnlySelected = false;

        function fwToggleOnlySelected() {
            __fwOnlySelected = !__fwOnlySelected;
            const btn = document.getElementById('fwToggleOnlySelected');
            if (__fwOnlySelected) {
                btn.classList.remove('btn-outline-info');
                btn.classList.add('btn-info');
                btn.innerHTML = '<i class="fas fa-filter me-1" aria-hidden="true"></i>' + escHtml(t('fw.showAll'));
            } else {
                btn.classList.add('btn-outline-info');
                btn.classList.remove('btn-info');
                btn.innerHTML = '<i class="fas fa-filter me-1" aria-hidden="true"></i>' + escHtml(t('fw.onlySelected'));
            }
            btn.setAttribute('aria-pressed', String(__fwOnlySelected));
            fwFilterCountries();
        }

        function fwFilterCountries() {
            const q = (document.getElementById('fwCountrySearch').value || '').toLowerCase().trim();
            const selectedSet = new Set(__fwState && __fwState.geo_countries ? __fwState.geo_countries : []);

            let visible = 0;
            let total = 0;
            document.querySelectorAll('.fw-country-item').forEach(el => {
                const cc = el.getAttribute('data-cc') || '';
                const name = el.getAttribute('data-name') || '';
                let show = true;
                if (q && !cc.includes(q) && !name.includes(q)) show = false;
                if (show && __fwOnlySelected && !selectedSet.has(cc)) show = false;
                el.style.display = show ? '' : 'none';
                total++;
                if (show) visible++;
            });

            // Counter selezionati nella header card
            document.getElementById('fwCountriesCount').textContent = selectedSet.size;

            // Label sopra la griglia: mostra "X paesi (Y visibili)" se filtro attivo
            const labelEl = document.getElementById('fwGridLabel');
            const filterActive = q.length > 0 || __fwOnlySelected;
            if (labelEl && total > 0) {
                labelEl.textContent = filterActive
                    ? t('fw.availableVisible', { visible: visible, total: total })
                    : t('fw.availableTotal', { total: total });
            }
        }

        function fwToggleCountry(cc, checked) {
            fwPost({ action: checked ? 'add_country' : 'remove_country', country: cc }, () => loadFirewall());
        }

        function fwSyncAll() {
            const selectedCount = (__fwState && __fwState.geo_countries) ? __fwState.geo_countries.length : 0;
            if (selectedCount === 0) {
                alert(t('fw.syncNoCountries'));
                return;
            }
            if (!confirm(tn('fw.confirmSync', selectedCount, { seconds: Math.max(2, selectedCount * 2) }))) return;
            fwPost({ action: 'sync_geo_all' }, (data) => {
                let msg = data.message || '';
                if (Array.isArray(data.results)) {
                    msg += '\\n\\n' + data.results.map(r => (r.success ? '✓' : '✗') + ' ' + r.country + ': ' + (r.message || '')).join('\\n');
                }
                alert(msg);
                loadFirewall();
            });
        }

        // ===== CIDR (whitelist/blacklist) =====
        function renderFwCidrList(kind, cidrs) {
            const list = document.getElementById(kind === 'wl' ? 'fwWlList' : 'fwBlList');
            const count = document.getElementById(kind === 'wl' ? 'fwWlCount' : 'fwBlCount');
            count.textContent = cidrs.length;
            if (cidrs.length === 0) {
                list.innerHTML = '<span class="text-muted small">' + escHtml(kind === 'wl' ? t('fw.noWl') : t('fw.noBl')) + '</span>';
                return;
            }
            list.innerHTML = cidrs.map(c =>
                '<span class="fw-cidr-item"><code>' + escHtml(c) + '</code>' +
                '<button type="button" class="btn-remove" data-kind="' + escHtml(kind) + '" data-cidr="' + escHtml(c) + '" onclick="fwRemoveCidr(this.dataset.kind, this.dataset.cidr)"'
                + ' title="' + escHtml(t('fw.removeCidr', { cidr: c })) + '" aria-label="' + escHtml(t('fw.removeCidr', { cidr: c })) + '"><i class="fas fa-times" aria-hidden="true"></i></button>' +
                '</span>'
            ).join('');
        }

        function fwAddCidr(kind) {
            const input = document.getElementById(kind === 'wl' ? 'fwWlInput' : 'fwBlInput');
            const cidr = (input.value || '').trim();
            if (!cidr) { alert(t('jc.needIp')); return; }
            fwPost({ action: kind === 'wl' ? 'add_cidr_wl' : 'add_cidr_bl', cidr: cidr }, (data) => {
                if (data.success) input.value = '';
                else alert(data.message || t('common.errorShort'));
                loadFirewall();
            });
        }

        function fwRemoveCidr(kind, cidr) {
            if (!confirm(kind === 'wl' ? t('fw.confirmRemoveWl', { cidr: cidr }) : t('fw.confirmRemoveBl', { cidr: cidr }))) return;
            fwPost({ action: kind === 'wl' ? 'remove_cidr_wl' : 'remove_cidr_bl', cidr: cidr }, () => loadFirewall());
        }

        // ===== Apply =====
        function fwApply() {
            if (!confirm(t('fw.confirmApply'))) return;
            fwPost({ action: 'apply' }, (data) => {
                let msg = data.message || '';
                if (data.backup_path) msg += '\\n\\n' + t('fw.backup', { path: data.backup_path });
                alert((data.success ? '✓ ' : '✗ ') + msg);
                loadFirewall();
            });
        }

        // ===== HTTP helper =====
        function fwPost(body, onSuccess) {
            const payload = Object.assign({ csrf_token: __fwCsrf }, body);
            fetch('/api/firewall', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            }).then(r => r.json()).then(data => {
                if (onSuccess) onSuccess(data);
            }).catch(e => alert(t('common.networkError', { message: e.message })));
        }

        // Init
        loadFirewall();
""";
    }

    // ============== CLOUDFLARE.HTML — Gestione account/API token Cloudflare ==============
    public static String getCloudflareHtml() {
        String extraStyles = """
        .cf-token-cell { font-family: monospace; font-size: .85rem; color: var(--text-secondary); }
        .cf-help code { background: rgba(128,128,128,0.15); padding: 1px 5px; border-radius: 4px; }
        .cf-account-card { border-left: 4px solid #f6821f; }
        .cf-form-card { border-left: 4px solid #0d6efd; }
        """;
        return getHead("nav.cloudflare", "cloudflare", extraStyles) + """
    <div id="main" tabindex="-1" class="content container mt-4" style="max-width: 1100px">

        <div class="d-flex justify-content-between align-items-center mb-3 flex-wrap gap-2">
            <h2 class="mb-0"><i class="fas fa-cloud me-2" style="color:#f6821f" aria-hidden="true"></i>Cloudflare <small class="text-muted fs-6">— {{t:cf.subtitle}} (<code>{{MAIL_HOSTNAME}}</code>)</small></h2>
            <button class="btn btn-outline-secondary btn-sm" onclick="cfLoad()" title="{{t:cf.reload}}">
                <i class="fas fa-sync" aria-hidden="true"></i> {{t:cf.reload}}
            </button>
        </div>

        <p class="text-muted">
{{t:cf.intro.html}}
        </p>

        <!-- ===== Form: aggiungi / modifica account ===== -->
        <div class="card mb-4 cf-form-card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <span><i class="fas fa-plus-circle me-2" aria-hidden="true"></i><span id="cfFormTitle">{{t:cf.addTitle}}</span></span>
                <button class="btn btn-sm btn-outline-secondary" id="cfCancelEditBtn" style="display:none" onclick="cfResetForm()">
                    <i class="fas fa-times me-1" aria-hidden="true"></i>{{t:cf.cancelEdit}}
                </button>
            </div>
            <div class="card-body">
                <input type="hidden" id="cfEditingId" value="0">
                <div class="row g-3">
                    <div class="col-md-6">
                        <label class="form-label" for="cfLabel">{{t:cf.label}} <span class="text-danger" aria-hidden="true">*</span></label>
                        <input type="text" class="form-control" id="cfLabel" maxlength="100"
                               placeholder="{{t:cf.labelPh}}" required>
                        <small class="text-muted">{{t:cf.labelHint}}</small>
                    </div>
                    <div class="col-md-6">
                        <label class="form-label" for="cfEmail">{{t:cf.email}}</label>
                        <input type="email" class="form-control" id="cfEmail" maxlength="200"
                               placeholder="{{t:cf.emailPh}}">
                        <small class="text-muted">{{t:cf.emailHint}}</small>
                    </div>
                    <div class="col-12">
                        <label class="form-label" for="cfToken">{{t:dns.cfToken}} <span class="text-danger" aria-hidden="true">*</span></label>
                        <div class="input-group">
                            <input type="password" class="form-control" id="cfToken" autocomplete="off"
                                   placeholder="{{t:cf.tokenPh}}">
                            <button class="btn btn-outline-secondary" type="button" onclick="cfToggleToken()" title="{{t:cf.showHide}}" aria-label="{{t:cf.showHide}}">
                                <i class="fas fa-eye" id="cfTokenEye"></i>
                            </button>
                            <button class="btn btn-outline-info" type="button" onclick="cfTest()">
                                <i class="fas fa-vial me-1" aria-hidden="true"></i>{{t:dns.cfTest}}
                            </button>
                        </div>
                        <small class="text-muted" id="cfTokenHint">
                            {{t:cf.keepToken.html}}
                        </small>
                        <div id="cfTestResult" class="mt-2"></div>
                    </div>
                </div>
                <div class="mt-3">
                    <button class="btn btn-primary" onclick="cfSave()">
                        <i class="fas fa-save me-1" aria-hidden="true"></i><span id="cfSaveLabel">{{t:cf.verifySave}}</span>
                    </button>
                </div>
            </div>
        </div>

        <!-- ===== Lista account ===== -->
        <div class="card mb-4 cf-account-card">
            <div class="card-header"><i class="fas fa-key me-2" aria-hidden="true"></i>{{t:dns.cfConfigured}}</div>
            <div class="card-body">
                <div id="cfAccountsBox">
                    <p class="text-muted mb-0"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>{{t:common.loading}}</p>
                </div>
            </div>
        </div>

        <!-- ===== Certificato del server mail (Mail Hostname) ===== -->
        <div class="card mb-4" style="border-left:4px solid #198754">
            <div class="card-header"><i class="fas fa-server me-2" aria-hidden="true"></i>{{t:cf.mailCert}}</div>
            <div class="card-body">
                <p class="small text-muted mb-2">
{{t:cf.mailCertIntro.html}}
                </p>
                <div id="cfMailServerBox">
                    <p class="text-muted mb-0"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>{{t:common.loading}}</p>
                </div>
            </div>
        </div>


        <!-- ===== Aiuto: come creare il token ===== -->
        <div class="card mb-4 cf-help">
            <div class="card-header"><i class="fas fa-circle-question me-2" aria-hidden="true"></i>{{t:cf.howToken}}</div>
            <div class="card-body small">
                <ol class="mb-2">
                    <li>{{t:cf.step1.html}}</li>
                    <li>{{t:cf.step2.html}}</li>
                    <li>{{t:cf.step3.html}}</li>
                    <li>{{t:cf.step4.html}}</li>
                    <li>{{t:cf.step5}}</li>
                </ol>
                <div class="alert alert-warning py-2 mb-0">
                    <i class="fas fa-shield-halved me-1" aria-hidden="true"></i>
{{t:cf.tokenWarn}}
                </div>
            </div>
        </div>

    </div>

""" + getFooterSection() + """
    <script>
        let __cfCsrf = '';
        try { const el = document.getElementById('csrf_token'); if (el && el.value) __cfCsrf = el.value; } catch (e) {}

        // Mail Hostname pre-compilato lato server (stesso meccanismo di /settings e /ssl)
        const __cfMailHostname = '{{MAIL_HOSTNAME}}';

        let cfState = { accounts: [], mailServer: null };

        function escCf(s) {
            return String(s == null ? '' : s)
                .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
        }

        function cfPost(body, onDone) {
            const payload = Object.assign({ csrf_token: __cfCsrf }, body);
            return fetch('/api/cloudflare', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            }).then(r => r.json()).then(data => { if (onDone) onDone(data); })
              .catch(e => alert(t('common.networkError', { message: e.message })));
        }

        function cfLoad() {
            fetch('/api/cloudflare').then(r => r.json()).then(data => {
                cfState.accounts = data.accounts || [];
                cfState.mailServer = data.mail_server || null;
                cfRenderAccounts();
                cfRenderMailServer();
            }).catch(e => {
                document.getElementById('cfAccountsBox').innerHTML =
                    '<div class="alert alert-danger mb-0">' + escHtml(t('common.error', { message: e.message })) + '</div>';
            });
        }

        function cfRenderAccounts() {
            const box = document.getElementById('cfAccountsBox');
            if (!cfState.accounts.length) {
                box.innerHTML = '<p class="text-muted mb-0">' + escHtml(t('cf.none')) + '</p>';
                return;
            }
            let html = '<div class="table-responsive"><table class="table table-striped align-middle mb-0">'
                + '<thead><tr><th scope="col">' + escHtml(t('cf.label')) + '</th><th scope="col">Email</th><th scope="col">Token</th><th scope="col">' + escHtml(t('cf.verified')) + '</th><th scope="col" class="text-end">' + escHtml(t('home.colActions')) + '</th></tr></thead><tbody>';
            cfState.accounts.forEach(a => {
                const verified = a.verified_at ? ('<span class="text-success"><i class="fas fa-check-circle me-1" aria-hidden="true"></i>'
                    + escCf((a.verified_at || '').replace('T', ' ').substring(0, 16)) + '</span>')
                    : '<span class="text-muted">—</span>';
                html += '<tr>'
                    + '<td><strong>' + escCf(a.label || t('cf.noName')) + '</strong></td>'
                    + '<td>' + (a.email ? escCf(a.email) : '<span class="text-muted">—</span>') + '</td>'
                    + '<td class="cf-token-cell">' + escCf(a.token_masked || '••••') + '</td>'
                    + '<td>' + verified + '</td>'
                    + '<td class="text-end">'
                    + '<button class="btn btn-sm btn-outline-primary me-1" onclick="cfEdit(' + a.id + ')" title="' + escHtml(t('common.edit')) + '" aria-label="' + escHtml(t('common.edit')) + ' ' + escCf(a.label || '') + '"><i class="fas fa-pen" aria-hidden="true"></i></button>'
                    + '<button class="btn btn-sm btn-outline-danger" onclick="cfDelete(' + a.id + ')" title="' + escHtml(t('common.delete')) + '" aria-label="' + escHtml(t('common.delete')) + ' ' + escCf(a.label || '') + '"><i class="fas fa-trash" aria-hidden="true"></i></button>'
                    + '</td></tr>';
            });
            html += '</tbody></table></div>';
            box.innerHTML = html;
        }

        function cfRenderMailServer() {
            const box = document.getElementById('cfMailServerBox');
            const ms = cfState.mailServer || {};
            // Hostname: usa il valore pre-compilato lato server; fallback all'API
            let host = __cfMailHostname;
            if (!host || host === t('server.notConfigured') || host.indexOf('{{') === 0) host = ms.hostname || '';
            if (!host) {
                box.innerHTML = '<div class="alert alert-warning py-2 mb-0">' + escHtml(t('cf.noHostname')) + '</div>';
                return;
            }
            const cur = ms.cloudflare_account_id || 0;
            let opts = '<option value="0"' + (cur === 0 ? ' selected' : '') + '>' + escHtml(t('ssl.manualNoAccount')) + '</option>';
            cfState.accounts.forEach(a => {
                opts += '<option value="' + a.id + '"' + (cur === a.id ? ' selected' : '') + '>'
                    + escCf(a.label || ('account #' + a.id)) + '</option>';
            });
            let status = cur > 0
                ? '<span class="badge bg-success"><i class="fas fa-check me-1" aria-hidden="true"></i>' + escHtml(t('cf.autoOn')) + '</span>'
                : '<span class="badge bg-secondary"><i class="fas fa-hand me-1" aria-hidden="true"></i>' + escHtml(t('cf.manual')) + '</span>';
            box.innerHTML = '<div class="table-responsive"><table class="table align-middle mb-2">'
                + '<thead><tr><th scope="col">' + escHtml(t('cf.colHost')) + '</th><th scope="col" style="width:340px">' + escHtml(t('cf.colAccount')) + '</th></tr></thead><tbody>'
                + '<tr>'
                + '<td><i class="fas fa-server me-1 text-success" aria-hidden="true"></i><strong>' + escCf(host) + '</strong> ' + status + '</td>'
                + '<td><select class="form-select form-select-sm" id="cfMailServerSelect" aria-label="' + escHtml(t('cf.colAccount')) + '" onchange="cfAssignMailServer(this.value)">' + opts + '</select></td>'
                + '</tr></tbody></table></div>'
                + '<button class="btn btn-outline-info btn-sm" onclick="cfTestMailServer()">'
                + '<i class="fas fa-plug me-1" aria-hidden="true"></i>' + escHtml(t('ssl.testLink')) + '</button>'
                + '<div id="cfMailServerTest" class="mt-2"></div>'
                + '<div class="small text-muted mt-2"><i class="fas fa-info-circle me-1" aria-hidden="true"></i>' + escHtml(t('cf.tokenNeeds', { host: host })) + '</div>';
        }

        function cfTestMailServer() {
            const sel = document.getElementById('cfMailServerSelect');
            const accountId = sel ? (parseInt(sel.value, 10) || 0) : 0;
            const out = document.getElementById('cfMailServerTest');
            if (accountId <= 0) {
                out.innerHTML = '<div class="alert alert-warning py-2 mb-0">' + escHtml(t('ssl.chooseCfFirst')) + '</div>';
                return;
            }
            out.innerHTML = '<span class="text-muted"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('ssl.testingCf')) + '</span>';
            cfPost({ action: 'test_mailserver', account_id: accountId }, data => {
                if (data.success) {
                    out.innerHTML = '<div class="alert alert-success py-2 mb-0"><i class="fas fa-check-circle me-1" aria-hidden="true"></i>'
                        + escCf(data.message || t('ssl.linkOk')) + '</div>';
                } else {
                    out.innerHTML = '<div class="alert alert-danger py-2 mb-0"><i class="fas fa-times-circle me-1" aria-hidden="true"></i>'
                        + escCf(data.error || data.message || t('dns.checkFailed')) + '</div>';
                }
            });
        }

        function cfAssignMailServer(accountId) {
            cfPost({ action: 'assign_mailserver', account_id: parseInt(accountId, 10) || 0 }, data => {
                if (!data.success) { alert('✗ ' + (data.message || data.error || t('cf.assignFailed'))); }
                else if (data.message) { /* feedback silenzioso, lo stato si aggiorna sotto */ }
                cfLoad();
            });
        }

        function cfToggleToken() {
            const inp = document.getElementById('cfToken');
            const eye = document.getElementById('cfTokenEye');
            if (inp.type === 'password') { inp.type = 'text'; eye.className = 'fas fa-eye-slash'; }
            else { inp.type = 'password'; eye.className = 'fas fa-eye'; }
        }

        function cfTest() {
            const token = document.getElementById('cfToken').value.trim();
            const out = document.getElementById('cfTestResult');
            if (!token) { out.innerHTML = '<div class="alert alert-warning py-2 mb-0">' + escHtml(t('cf.needToken')) + '</div>'; return; }
            out.innerHTML = '<span class="text-muted"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('dns.checkingRecord')) + '</span>';
            cfPost({ action: 'test', token: token }, data => {
                if (data.success) {
                    out.innerHTML = '<div class="alert alert-success py-2 mb-0"><i class="fas fa-check-circle me-1" aria-hidden="true"></i>'
                        + escCf(data.message || t('cf.tokenOk')) + '</div>';
                } else {
                    out.innerHTML = '<div class="alert alert-danger py-2 mb-0"><i class="fas fa-times-circle me-1" aria-hidden="true"></i>'
                        + escCf(data.message || data.error || t('cf.tokenBad')) + '</div>';
                }
            });
        }

        function cfEdit(id) {
            const a = cfState.accounts.find(x => x.id === id);
            if (!a) return;
            document.getElementById('cfEditingId').value = id;
            document.getElementById('cfLabel').value = a.label || '';
            document.getElementById('cfEmail').value = a.email || '';
            document.getElementById('cfToken').value = '';
            document.getElementById('cfFormTitle').textContent = t('cf.editTitle', { name: a.label || ('#' + id) });
            document.getElementById('cfSaveLabel').textContent = t('common.saveChanges');
            document.getElementById('cfCancelEditBtn').style.display = '';
            document.getElementById('cfTokenHint').style.display = '';
            document.getElementById('cfTestResult').innerHTML = '';
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }

        function cfResetForm() {
            document.getElementById('cfEditingId').value = '0';
            document.getElementById('cfLabel').value = '';
            document.getElementById('cfEmail').value = '';
            document.getElementById('cfToken').value = '';
            document.getElementById('cfFormTitle').textContent = t('cf.addTitle');
            document.getElementById('cfSaveLabel').textContent = t('cf.verifySave');
            document.getElementById('cfCancelEditBtn').style.display = 'none';
            document.getElementById('cfTestResult').innerHTML = '';
        }

        function cfSave() {
            const id = parseInt(document.getElementById('cfEditingId').value, 10) || 0;
            const label = document.getElementById('cfLabel').value.trim();
            const email = document.getElementById('cfEmail').value.trim();
            const token = document.getElementById('cfToken').value.trim();

            if (!label) { alert(t('cf.needLabel')); return; }
            if (id === 0 && !token) { alert(t('cf.needApiToken')); return; }

            const body = id > 0
                ? { action: 'update', account_id: id, label: label, email: email }
                : { action: 'add', label: label, email: email, token: token };
            if (token) body.token = token;

            cfPost(body, data => {
                if (data.success) {
                    cfResetForm();
                    cfLoad();
                    alert('✓ ' + (data.message || t('ssl.savedShort')));
                } else {
                    alert('✗ ' + (data.message || data.error || t('common.failed')));
                }
            });
        }

        function cfDelete(id) {
            const a = cfState.accounts.find(x => x.id === id);
            const name = a ? (a.label || ('#' + id)) : ('#' + id);
            if (!confirm(t('dns.cfConfirmDelete', { label: name }))) return;
            cfPost({ action: 'delete', account_id: id }, data => {
                alert((data.success ? '✓ ' : '✗ ') + (data.message || data.error || ''));
                cfLoad();
            });
        }

        // Init
        cfLoad();
""" + """
    </script>
</body>
</html>
""";
    }

    // ============== PATHS.HTML — Diagnostic page con tutti i path usati dal pannello ==============
    public static String getPathsHtml() {
        String extraStyles = """
        .path-entry { display: flex; flex-direction: column; padding: 12px; border-left: 4px solid #6c757d; background: #f8f9fa; border-radius: 4px; margin-bottom: 8px; }
        .path-entry.exists { border-color: #198754; }
        .path-entry.missing { border-color: #dc3545; }
        .path-entry.directory { border-color: #0dcaf0; }
        .path-label { font-weight: 600; }
        .path-code { font-family: monospace; word-break: break-all; padding: 4px 8px; background: rgba(0,0,0,0.05); border-radius: 3px; user-select: all; }
        .path-meta { font-size: 0.8rem; color: #6c757d; }
        .path-desc { font-size: 0.85rem; }
        [data-theme="dark"] .path-entry { background: var(--table-stripe); color: var(--text-primary); }
        [data-theme="dark"] .path-code { background: rgba(255,255,255,0.05); color: var(--text-primary); }
        [data-theme="dark"] .path-meta { color: var(--text-muted); }
        .copy-btn { cursor: pointer; padding: 2px 8px; font-size: 0.75rem; border: 1px solid #ced4da; background: white; border-radius: 3px; }
        .copy-btn:hover { background: #e9ecef; }
        [data-theme="dark"] .copy-btn { background: var(--bg-input); color: var(--text-primary); border-color: var(--border-color); }
        [data-theme="dark"] .copy-btn:hover { background: var(--table-hover); }
        .copy-btn.copied { background: #198754; color: white; border-color: #198754; }
        """;
        return getHead("nav.paths", "paths", extraStyles) + """
    <div id="main" tabindex="-1" class="content container mt-4">
        <div class="content-container">
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h2><i class="fas fa-folder-tree me-2" aria-hidden="true"></i>{{t:pt.title}}</h2>
                <button class="btn btn-outline-primary btn-sm" onclick="loadPaths()">
                    <i class="fas fa-sync me-1" aria-hidden="true"></i>{{t:common.refresh}}
                </button>
            </div>
            <p class="text-muted mb-3">{{t:pt.intro}}</p>

            <div class="d-flex gap-3 mb-3 align-items-center flex-wrap">
                <input type="text" id="pathSearch" class="form-control form-control-sm" style="max-width:300px" maxlength="100" placeholder="{{t:pt.filterPlaceholder}}" aria-label="{{t:pt.filter}}" oninput="filterPaths()">
                <span class="small text-muted" id="pathStats" aria-live="polite">-</span>
            </div>

            <div id="pathsContainer">
                <p class="text-muted"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>{{t:common.loading}}</p>
            </div>
        </div>
    </div>
""" + getFooterSection() + """
    <script>
        let allCategories = [];

        function loadPaths() {
            const c = document.getElementById('pathsContainer');
            c.innerHTML = '<p class="text-muted"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('common.loading')) + '</p>';
            fetch('/api/system_paths')
                .then(r => r.json())
                .then(data => {
                    if (!data.success) {
                        c.innerHTML = '<div class="alert alert-danger">' + escHtml(t('common.error', { message: data.error || t('common.unknownError') })) + '</div>';
                        return;
                    }
                    allCategories = data.categories || [];
                    renderPaths(allCategories);
                })
                .catch(e => {
                    c.innerHTML = '<div class="alert alert-danger">' + escHtml(t('common.networkError', { message: e.message })) + '</div>';
                });
        }

        function renderPaths(categories) {
            const c = document.getElementById('pathsContainer');
            let totalEntries = 0, totalExists = 0;
            let html = '';
            categories.forEach(cat => {
                if (!cat.entries || cat.entries.length === 0) return;
                html += '<div class="card mb-3">';
                html += '<div class="card-header bg-dark text-white"><strong>' + escapePathHtml(cat.name) + '</strong> <span class="badge bg-secondary ms-2">' + cat.entries.length + '</span></div>';
                html += '<div class="card-body">';
                cat.entries.forEach(entry => {
                    totalEntries++;
                    let cls = 'path-entry';
                    if (entry.exists) {
                        totalExists++;
                        cls += entry.is_directory ? ' directory' : ' exists';
                    } else cls += ' missing';
                    html += '<div class="' + cls + '" data-search="' + escapePathHtml((entry.label + ' ' + entry.path + ' ' + (entry.description || '')).toLowerCase()) + '">';
                    html += '<div class="d-flex justify-content-between align-items-start gap-2 flex-wrap">';
                    html += '<div class="flex-grow-1">';
                    html += '<div class="path-label">';
                    if (entry.exists) html += '<i class="fas fa-' + (entry.is_directory ? 'folder' : 'file') + ' text-' + (entry.is_directory ? 'info' : 'success') + ' me-1" aria-hidden="true"></i>'
                        + '<span class="visually-hidden">' + escHtml(entry.is_directory ? t('pt.directory') : t('pt.file')) + ': </span>';
                    else html += '<i class="fas fa-times-circle text-danger me-1" aria-hidden="true"></i><span class="visually-hidden">' + escHtml(t('pt.missing')) + ': </span>';
                    html += escapePathHtml(entry.label) + '</div>';
                    if (entry.description) html += '<div class="path-desc text-muted">' + escapePathHtml(entry.description) + '</div>';
                    html += '<div class="mt-1"><code class="path-code">' + escapePathHtml(entry.path) + '</code></div>';
                    // Meta
                    let meta = [];
                    if (entry.exists) {
                        if (entry.size !== undefined) meta.push(formatSize(entry.size));
                        if (entry.perms) meta.push(escHtml(t('pt.perms', { perms: entry.perms })));
                        if (entry.modified) meta.push(escHtml(t('pt.modified', { date: entry.modified.substring(0, 19).replace('T', ' ') })));
                        if (entry.readable === false) meta.push('<span class="text-warning">' + escHtml(t('pt.unreadable')) + '</span>');
                    } else {
                        meta.push('<span class="text-danger">' + escHtml(t('pt.notExists')) + '</span>');
                    }
                    if (meta.length > 0) html += '<div class="path-meta mt-1">' + meta.join(' • ') + '</div>';
                    html += '</div>';
                    html += '<button type="button" class="copy-btn" data-path="' + escHtml(entry.path) + '" onclick="copyPath(this, this.dataset.path)"><i class="fas fa-copy" aria-hidden="true"></i> ' + escHtml(t('common.copy')) + '</button>';
                    html += '</div>';
                    html += '</div>';
                });
                html += '</div></div>';
            });
            c.innerHTML = html;
            document.getElementById('pathStats').textContent =
                t('pt.stats', { n: totalExists, total: totalEntries });
        }

        function filterPaths() {
            const q = document.getElementById('pathSearch').value.toLowerCase().trim();
            document.querySelectorAll('.path-entry').forEach(el => {
                const text = el.dataset.search || '';
                el.style.display = (q === '' || text.indexOf(q) >= 0) ? '' : 'none';
            });
        }

        function copyPath(btn, path) {
            navigator.clipboard.writeText(path).then(() => {
                const oldHtml = btn.innerHTML;
                btn.classList.add('copied');
                btn.innerHTML = '<i class="fas fa-check" aria-hidden="true"></i> ' + escHtml(t('pt.copied')) + '';
                setTimeout(() => { btn.classList.remove('copied'); btn.innerHTML = oldHtml; }, 1500);
            });
        }

        function formatSize(bytes) {
            if (bytes < 1024) return bytes + ' B';
            if (bytes < 1024*1024) return (bytes/1024).toFixed(1) + ' KB';
            if (bytes < 1024*1024*1024) return (bytes/1024/1024).toFixed(1) + ' MB';
            return (bytes/1024/1024/1024).toFixed(1) + ' GB';
        }

        function escapePathHtml(s) {
            const d = document.createElement('div');
            d.textContent = s == null ? '' : String(s);
            return d.innerHTML;
        }

        function escapeForJs(s) {
            return String(s).replace(/\\\\/g, '\\\\\\\\').replace(/'/g, "\\\\'");
        }

        loadPaths();
""" + """
    </script>
</body>
</html>
""";
    }

    // ============== AGGIORNAMENTI E PROTEZIONE PACCHETTI ==============
    /**
     * Pagina /updates. Il JavaScript sta in un metodo a parte: un blocco di testo Java non
     * puo' superare i 65535 byte nel constant pool, e una chiamata a metodo interrompe la
     * concatenazione costante che porterebbe a sforarlo.
     */
    public static String getUpdatesHtml() {
        String extraStyles = """
        .upd-badge-ok    { background:#198754; }
        .upd-badge-warn  { background:#ffc107; color:#000; }
        .upd-badge-stop  { background:#dc3545; }
        .upd-log { background:#1a1d21; color:#e9ecef; padding:10px; border-radius:6px;
                   max-height:420px; overflow:auto; white-space:pre-wrap; font-size:0.78rem; }
        .upd-cell { font-size:0.85rem; }
        """;
        return getHead("nav.updates", "updates", extraStyles) + """
    <div id="main" tabindex="-1" class="content container mt-4">
        <div class="content-container">
            <h2><i class="fas fa-arrow-up-right-dots me-2" aria-hidden="true"></i>{{t:up.title}}</h2>
            <p class="text-muted">{{t:up.intro.html}}</p>

            <div class="card mb-4">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span><i class="fab fa-freebsd me-2" aria-hidden="true"></i><strong>{{t:up.os}}</strong>
                        <span class="small text-muted ms-2">{{t:up.osSub}}</span></span>
                    <span>
                        <button class="btn btn-sm btn-outline-danger me-1" onclick="rebPrev()"><i class="fas fa-rotate-right me-1" aria-hidden="true"></i>{{t:up.reboot}}</button>
                        <button class="btn btn-sm btn-outline-secondary me-1" onclick="rcPrev()"><i class="fas fa-power-off me-1" aria-hidden="true"></i>{{t:up.autostart}}</button>
                        <button class="btn btn-sm btn-outline-primary" onclick="osState()"><i class="fas fa-magnifying-glass me-1" aria-hidden="true"></i>{{t:up.sysState}}</button>
                    </span>
                </div>
                <div class="card-body">
                    <div id="os-body"><span class="text-muted">{{t:up.phSysState}}</span></div>
                    <pre id="os-log" class="upd-log mt-2" style="display:none"></pre>
                </div>
            </div>

            <div class="card mb-4" id="pacchetti">
                <div class="card-header d-flex flex-wrap justify-content-between align-items-center gap-2">
                    <span><i class="fas fa-cubes me-2" aria-hidden="true"></i><strong>{{t:pkgs.title}}</strong></span>
                    <button type="button" class="btn btn-sm btn-outline-primary" onclick="pkOverview()"><i class="fas fa-rotate me-1" aria-hidden="true"></i>{{t:common.refresh}}</button>
                </div>
                <div class="card-body">
                    <p class="small text-muted mb-2">{{t:pkgs.intro.html}}</p>
                    <div id="pk-body" role="status" aria-live="polite"><span class="text-muted">{{t:pkgs.loading}}</span></div>
                    <div id="pk-result" class="mt-2"></div>
                </div>
                <div class="card-footer">
                    <div class="small text-muted mb-2">{{t:pkgs.bulk.intro.html}}</div>
                    <div class="d-flex flex-wrap gap-1">
                        <button type="button" class="btn btn-sm btn-outline-success" onclick="updLockAll(true)"><i class="fas fa-lock me-1" aria-hidden="true"></i>{{t:pkgs.bulk.lockAll}}</button>
                        <button type="button" class="btn btn-sm btn-outline-secondary" onclick="updLockAll(false)"><i class="fas fa-lock-open me-1" aria-hidden="true"></i>{{t:pkgs.bulk.unlockAll}}</button>
                        <a class="btn btn-sm btn-outline-primary" href="#aggiornamenti"><i class="fas fa-arrow-down me-1" aria-hidden="true"></i>{{t:pkgs.bulk.goUpdates}}</a>
                    </div>
                </div>
            </div>

            <div class="modal fade" id="pkUpdModal" tabindex="-1" aria-labelledby="pkUpdTitle" aria-hidden="true">
                <div class="modal-dialog modal-lg modal-dialog-scrollable">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title" id="pkUpdTitle"></h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="{{t:common.close}}"></button>
                        </div>
                        <div class="modal-body">
                            <div id="pkUpdBody"></div>
                            <div id="pkUpdConfirm" class="mt-3" hidden>
                                <label for="pkUpdName" class="form-label small" id="pkUpdNameLabel"></label>
                                <input type="text" id="pkUpdName" class="form-control" autocomplete="off" autocapitalize="off" spellcheck="false" maxlength="64">
                            </div>
                            <div class="progress mt-3" id="pkUpdProgress" hidden role="progressbar" aria-label="{{t:pkgs.m.progress}}" aria-valuemin="0" aria-valuemax="100">
                                <div class="progress-bar progress-bar-striped progress-bar-animated" style="width:0%"></div>
                            </div>
                            <div id="pkUpdResult" class="mt-2" role="status" aria-live="polite"></div>
                            <pre id="pkUpdLog" class="upd-log mt-2 mb-0" hidden></pre>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">{{t:common.close}}</button>
                            <button type="button" class="btn btn-danger" id="pkUpdGo" disabled hidden onclick="pkUpdRun()"><i class="fas fa-play me-1" aria-hidden="true"></i>{{t:pkgs.m.go}}</button>
                        </div>
                    </div>
                </div>
            </div>

""" + resource("pages/branch-card.html") + """
            <div class="card mb-4 border-danger">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-arrow-up-right-dots me-2" aria-hidden="true"></i><strong>{{t:up.release}}</strong>
                        <span class="small text-muted ms-2">{{t:up.releaseSub}}</span></span>
                    <span>
                        <select id="os-target" class="form-select form-select-sm d-inline-block me-1" style="width:auto" aria-label="{{t:up.targetVersionLabel}}">
                            <option value="">{{t:up.targetVersion}}</option>
                        </select>
                        <button class="btn btn-sm btn-warning me-1" onclick="jumpState()"><i class="fas fa-forward me-1" aria-hidden="true"></i>{{t:up.continueJump}}</button>
                        <button class="btn btn-sm btn-outline-secondary me-1" onclick="upCheck()"><i class="fas fa-clipboard-check me-1" aria-hidden="true"></i>{{t:up.checkAfter}}</button>
                        <button class="btn btn-sm btn-outline-danger" onclick="upPre()"><i class="fas fa-clipboard-check me-1" aria-hidden="true"></i>{{t:up.checkPre}}</button>
                        <button class="btn btn-sm btn-outline-secondary ms-1" id="proc-release-tog" onclick="procOpen('proc-release')" title="{{t:up.toggleProc}}" aria-label="{{t:up.toggleProc}}" aria-expanded="false"><i class="fas fa-chevron-down" aria-hidden="true"></i></button>
                    </span>
                </div>
                <div class="card-body" id="proc-release" style="display:none">
                    <p class="small text-muted mb-2">{{t:up.releaseIntro.html}}</p>
                    <div id="up-body"><span class="text-muted">{{t:up.phRelease}}</span></div>
                    <pre id="up-log" class="upd-log mt-2" style="display:none"></pre>
                </div>
            </div>

            <div class="card mb-4 border-info">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-clipboard-list me-2" aria-hidden="true"></i><strong>{{t:up.report}}</strong>
                        <span class="small text-muted ms-2">{{t:up.reportSub}}</span></span>
                    <span>
                        <button class="btn btn-sm btn-outline-secondary me-1" id="rep-copy" onclick="repCopy()" style="display:none"><i class="fas fa-copy me-1" aria-hidden="true"></i>{{t:common.copy}}</button>
                        <button class="btn btn-sm btn-outline-info" onclick="repGen()"><i class="fas fa-file-lines me-1" aria-hidden="true"></i>{{t:up.genReport}}</button>
                    </span>
                </div>
                <div class="card-body">
                    <p class="small text-muted mb-2">{{t:up.reportIntro.html}}</p>
                    <div id="rep-stato"><span class="text-muted">{{t:up.phReport}}</span></div>
                    <pre id="rep-testo" class="upd-log mt-2" style="display:none"></pre>
                </div>
            </div>

            <div class="card mb-4">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-scale-balanced me-2" aria-hidden="true"></i><strong>{{t:up.defaults}}</strong>
                        <span class="small text-muted ms-2">{{t:up.defaultsSub}}</span></span>
                    <button class="btn btn-sm btn-outline-primary" onclick="defCheck()"><i class="fas fa-magnifying-glass me-1" aria-hidden="true"></i>{{t:up.compare}}</button>
                </div>
                <div class="card-body">
                    <p class="small text-muted mb-2">{{t:up.defaultsIntro.html}}</p>
                    <div id="def-body"><span class="text-muted">{{t:up.phCompare}}</span></div>
                </div>
            </div>

            <div class="card mb-4 border-info">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-terminal me-2" aria-hidden="true"></i><strong>{{t:up.env}}</strong>
                        <span class="small text-muted ms-2">{{t:up.envSub}}</span></span>
                    <div class="text-nowrap">
                        <button class="btn btn-sm btn-outline-info" onclick="envCheck()"><i class="fas fa-magnifying-glass me-1" aria-hidden="true"></i>{{t:up.check}}</button>
                    </div>
                </div>
                <div class="card-body">
                    <p class="small text-muted mb-2">{{t:up.envIntro.html}}</p>
                    <div id="env-body"><span class="text-muted">{{t:up.phCheck}}</span></div>
                </div>
            </div>
            <div class="card mb-4 border-warning">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-hand me-2" aria-hidden="true"></i><strong>{{t:up.remove}}</strong>
                        <span class="small text-muted ms-2">{{t:up.removeSub}}</span></span>
                    <div class="text-nowrap">
                        <button class="btn btn-sm btn-outline-warning" onclick="rmCandidates()"><i class="fas fa-list me-1" aria-hidden="true"></i>{{t:up.listCandidates}}</button>
                    </div>
                </div>
                <div class="card-body">
                    <p class="small text-muted mb-2">{{t:up.removeIntro.html}}</p>
                    <div id="rim-body"><span class="text-muted">{{t:up.phCandidates}}</span></div>
                </div>
            </div>
            <div class="card mb-4 border-danger">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-link-slash me-2" aria-hidden="true"></i><strong>{{t:up.libs}}</strong>
                        <span class="small text-muted ms-2">{{t:up.libsSub}}</span></span>
<div class="text-nowrap">
                        <button class="btn btn-sm btn-outline-danger me-1" onclick="libsCheck()"><i class="fas fa-magnifying-glass me-1" aria-hidden="true"></i>{{t:up.check}}</button>
                        <button class="btn btn-sm btn-outline-secondary" onclick="libsDiag()"><i class="fas fa-stethoscope me-1" aria-hidden="true"></i>{{t:up.mysqlClientDiag}}</button>
                    </div>
                </div>
                <div class="card-body">
                    <p class="small text-muted mb-2">{{t:up.libsIntro.html}}</p>
                    <div id="libs-body"><span class="text-muted">{{t:up.phCheck}}</span></div>
                    <pre id="libs-log" class="upd-log mt-2" style="display:none"></pre>
                </div>
            </div>

            <div class="card mb-4 border-primary">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-list-check me-2" aria-hidden="true"></i><strong>{{t:up.plan}}</strong>
                        <span class="small text-muted ms-2">{{t:up.planSub}}</span></span>
                    <button class="btn btn-sm btn-primary" onclick="planLoad()"><i class="fas fa-rotate me-1" aria-hidden="true"></i>{{t:up.computePlan}}</button>
                </div>
                <div class="card-body">
                    <p class="small text-muted mb-2">{{t:up.planIntro.html}}</p>
                    <div id="plan-body"><span class="text-muted">{{t:up.phPlan}}</span></div>
                    <pre id="plan-log" class="upd-log mt-2" style="display:none"></pre>
                </div>
            </div>

            <div class="card mb-4">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-vial me-2" aria-hidden="true"></i><strong>{{t:up.compat}}</strong>
                        <span class="small text-muted ms-2">{{t:up.compatSub}}</span></span>
                    <div class="text-nowrap">
                        <button class="btn btn-sm btn-outline-primary me-1" onclick="updCompat()"><i class="fas fa-magnifying-glass me-1" aria-hidden="true"></i>{{t:set.verify}}</button>
                        <button class="btn btn-sm btn-outline-secondary me-1" onclick="updDumpDovecot()" title="{{t:up.showDovecotHint}}"><i class="fas fa-file-code me-1" aria-hidden="true"></i>{{t:up.showDovecot}}</button>
                        <button class="btn btn-sm btn-outline-warning" onclick="updRegenDovecot()" title="{{t:up.regenDovecotHint}}"><i class="fas fa-wand-magic-sparkles me-1" aria-hidden="true"></i>{{t:up.regenDovecot}}</button>
                    </div>
                </div>
                <div class="card-body">
                    <div id="upd-compat"><span class="text-muted">{{t:up.phCompat}}</span></div>
                    <div id="upd-dovecot-dump" class="mt-3"></div>
                </div>
            </div>

            <div class="card mb-4 border-success">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-wand-magic-sparkles me-2" aria-hidden="true"></i><strong>{{t:up.ams}}</strong>
                        <span class="small text-muted ms-2">{{t:up.amsSub}}</span></span>
                    <button class="btn btn-sm btn-outline-primary" onclick="amsPlan()"><i class="fas fa-list-check me-1" aria-hidden="true"></i>{{t:up.state}}</button>
                </div>
                <div class="card-body">
                    <p class="small text-muted mb-2">{{t:up.amsIntro1.html}}</p>
                    <p class="small text-muted mb-2">{{t:up.amsIntro2.html}}</p>
                    <div id="upd-ams"><span class="text-muted">{{t:up.phState}}</span></div>
                </div>
            </div>
""" + resource("pages/cf-ranges-card.html") + """

            <div class="card mb-4">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-shield-halved me-2" aria-hidden="true"></i><strong>{{t:up.w443}}</strong>
                        <span class="small text-muted ms-2">{{t:up.w443Sub}}</span></span>
                    <button class="btn btn-sm btn-outline-primary" onclick="w443Load()"><i class="fas fa-magnifying-glass me-1" aria-hidden="true"></i>{{t:up.state}}</button>
                </div>
                <div class="card-body">
                    <p class="small text-muted mb-2">{{t:up.w443Intro1.html}}</p>
                    <p class="small text-muted mb-2">{{t:up.w443Intro2.html}}</p>
                    <div id="upd-443"><span class="text-muted">{{t:up.phState}}</span></div>
                </div>
            </div>

            <div class="card mb-4">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-globe me-2" aria-hidden="true"></i><strong>{{t:up.web}}</strong>
                        <span class="small text-muted ms-2">{{t:up.webSub}}</span></span>
                    <button class="btn btn-sm btn-outline-primary" onclick="webDiag()"><i class="fas fa-magnifying-glass me-1" aria-hidden="true"></i>{{t:up.diagnose}}</button>
                </div>
                <div class="card-body">
                    <p class="small text-muted mb-2">{{t:up.webIntro1.html}}</p>
                    <p class="small text-muted mb-2">{{t:up.webIntro2.html}}</p>
                    <div id="upd-web"><span class="text-muted">{{t:up.phDiagnose}}</span></div>
                </div>
            </div>

            <div class="card mb-4">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-binoculars me-2" aria-hidden="true"></i><strong>{{t:up.watch}}</strong>
                        <span class="small text-muted ms-2">{{t:up.watchSub}}</span></span>
                    <button class="btn btn-sm btn-outline-primary" onclick="watchLoad()"><i class="fas fa-magnifying-glass me-1" aria-hidden="true"></i>{{t:up.check}}</button>
                </div>
                <div class="card-body">
                    <p class="small text-muted mb-2">{{t:up.watchIntro1.html}}</p>
                    <p class="small text-muted mb-2">{{t:up.watchIntro2.html}}</p>
                    <div id="upd-sorv"><span class="text-muted">{{t:up.phCheck}}</span></div>
                </div>
            </div>

            <div class="card mb-4">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-lock me-2" aria-hidden="true"></i><strong>{{t:up.p465}}</strong>
                        <span class="small text-muted ms-2">{{t:up.p465Sub}}</span></span>
                    <button class="btn btn-sm btn-outline-primary" onclick="upd465()"><i class="fas fa-magnifying-glass me-1" aria-hidden="true"></i>{{t:set.verify}}</button>
                </div>
                <div class="card-body">
                    <p class="small text-muted mb-2">{{t:up.p465Intro1.html}}</p>
                    <p class="small text-muted mb-2">{{t:up.p465Intro2.html}}</p>
                    <div id="upd-465"><span class="text-muted">{{t:up.ph465}}</span></div>
                </div>
            </div>


            <div class="card mb-4" id="aggiornamenti">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-download me-2" aria-hidden="true"></i><strong>{{t:up.updates}}</strong>
                        <span class="small text-muted ms-2">{{t:up.updatesSub}}</span></span>
                    <div class="text-nowrap">
                        <button class="btn btn-sm btn-outline-primary me-1" onclick="updStatus()"><i class="fas fa-magnifying-glass me-1" aria-hidden="true"></i>{{t:set.verify}}</button>
                        <button class="btn btn-sm btn-outline-warning me-1" onclick="updApply()" title="{{t:up.upgradeUnlockedHint}}"><i class="fas fa-download me-1" aria-hidden="true"></i>{{t:up.upgradeUnlocked}}</button>
                        <button class="btn btn-sm btn-outline-danger" onclick="updMaintPreview()" title="{{t:up.fullMaintHint}}"><i class="fas fa-screwdriver-wrench me-1" aria-hidden="true"></i>{{t:up.fullMaint}}</button>
                    </div>
                </div>
                <div class="card-body">
                    <div id="upd-status"><span class="text-muted">{{t:up.phUpdates}}</span></div>
                    <pre id="upd-log" class="upd-log mt-2" style="display:none"></pre>
                </div>
            </div>

            <div class="card mb-4">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span><i class="fab fa-python me-2" aria-hidden="true"></i><strong>{{t:up.py}}</strong>
                        <span class="small text-muted ms-2">{{t:up.pySub}}</span></span>
                    <span>
                        <button class="btn btn-sm btn-outline-secondary me-1" onclick="pyLeftovers()"><i class="fas fa-broom me-1" aria-hidden="true"></i>{{t:up.leftovers}}</button>
                        <button class="btn btn-sm btn-outline-primary" onclick="pyPre()"><i class="fas fa-clipboard-check me-1" aria-hidden="true"></i>{{t:up.checkPre}}</button>
                        <button class="btn btn-sm btn-outline-secondary ms-1" id="proc-python-tog" onclick="procOpen('proc-python')" title="{{t:up.toggleProc}}" aria-label="{{t:up.toggleProc}}" aria-expanded="false"><i class="fas fa-chevron-down" aria-hidden="true"></i></button>
                    </span>
                </div>
                <div class="card-body" id="proc-python" style="display:none">
                    <p class="small text-muted mb-2">{{t:up.pyIntro.html}}</p>
                    <div id="py-pre"><span class="text-muted">{{t:up.phPre}}</span></div>
                    <pre id="py-log" class="upd-log mt-2" style="display:none"></pre>
                </div>
            </div>

            <div class="card mb-4 border-danger">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span><i class="fab fa-java me-2" aria-hidden="true"></i><strong>{{t:up.jvm}}</strong>
                        <span class="small text-muted ms-2">{{t:up.jvmSub}}</span></span>
                    <span>
                        <button class="btn btn-sm btn-outline-secondary me-1" onclick="jvState()"><i class="fas fa-file-alt me-1" aria-hidden="true"></i>{{t:up.lastReport}}</button>
                        <button class="btn btn-sm btn-outline-danger" onclick="jvPre()"><i class="fas fa-clipboard-check me-1" aria-hidden="true"></i>{{t:up.checkPre}}</button>
                        <button class="btn btn-sm btn-outline-secondary ms-1" id="proc-jvm-tog" onclick="procOpen('proc-jvm')" title="{{t:up.toggleProc}}" aria-label="{{t:up.toggleProc}}" aria-expanded="false"><i class="fas fa-chevron-down" aria-hidden="true"></i></button>
                    </span>
                </div>
                <div class="card-body" id="proc-jvm" style="display:none">
                    <p class="small text-muted mb-2">{{t:up.jvmIntro.html}}</p>
                    <div id="jv-pre"><span class="text-muted">{{t:up.phPre}}</span></div>
                    <pre id="jv-log" class="upd-log mt-2" style="display:none"></pre>
                </div>
            </div>

            <div class="card mb-4 border-warning">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-envelope-open-text me-2" aria-hidden="true"></i><strong>{{t:up.rc}}</strong>
                        <span class="small text-muted ms-2">{{t:up.rcSub}}</span></span>
                    <span>
                        <button class="btn btn-sm btn-outline-secondary me-1" onclick="rcDiag()"><i class="fas fa-stethoscope me-1" aria-hidden="true"></i>{{t:up.whyNoAnswer}}</button>
                        <button class="btn btn-sm btn-outline-info me-1" onclick="rcNginx()"><i class="fas fa-wrench me-1" aria-hidden="true"></i>{{t:up.assetsNoStyle}}</button>
                        <button class="btn btn-sm btn-outline-warning" onclick="rcPre()"><i class="fas fa-clipboard-check me-1" aria-hidden="true"></i>{{t:up.checkPre}}</button>
                        <button class="btn btn-sm btn-outline-secondary ms-1" id="proc-roundcube-tog" onclick="procOpen('proc-roundcube')" title="{{t:up.toggleProc}}" aria-label="{{t:up.toggleProc}}" aria-expanded="false"><i class="fas fa-chevron-down" aria-hidden="true"></i></button>
                    </span>
                </div>
                <div class="card-body" id="proc-roundcube" style="display:none">
                    <p class="small text-muted mb-2">{{t:up.rcIntro.html}}</p>
                    <div id="rc-pre"><span class="text-muted">{{t:up.phPre}}</span></div>
                    <pre id="rc-log" class="upd-log mt-2" style="display:none"></pre>
                </div>
            </div>

            <div class="card mb-4 border-warning">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-database me-2" aria-hidden="true"></i><strong>{{t:up.my84}}</strong>
                        <span class="small text-muted ms-2">{{t:up.my84Sub}}</span></span>
                    <button class="btn btn-sm btn-outline-warning" onclick="my84Pre()"><i class="fas fa-clipboard-check me-1" aria-hidden="true"></i>{{t:up.checkPre}}</button>
                    <button class="btn btn-sm btn-outline-secondary ms-1" id="proc-mysql-tog" onclick="procOpen('proc-mysql')" title="{{t:up.toggleProc}}" aria-label="{{t:up.toggleProc}}" aria-expanded="false"><i class="fas fa-chevron-down" aria-hidden="true"></i></button>
                </div>
                <div class="card-body" id="proc-mysql" style="display:none">
                    <p class="small text-muted mb-2">{{t:up.my84Intro.html}}</p>
                    <div id="my84-pre"><span class="text-muted">{{t:up.phPre2}}</span></div>
                    <pre id="my84-log" class="upd-log mt-2" style="display:none"></pre>
                </div>
            </div>

        </div>
    </div>
""" + getFooterSection() + """
    <script>
""" + getUpdatesScript() + """
    </script>
</body>
</html>
""";
    }

    private static String getUpdatesScript() {
        // Spezzato in parti perche' un letterale di testo non puo' superare 65535 byte
        // (limite del formato .class). Concatenare due letterali NON basta: javac li fonde
        // in una sola costante e il limite torna. Una chiamata a metodo non e' una costante,
        // quindi interrompe la fusione — ed e' per questo che le parti sono metodi.
        return getUpdatesScript1() + getUpdatesScript2() + getUpdatesScriptPackages() + resource("pages/branch.js");
    }

    /** La tabella dei pacchetti e la finestra di aggiornamento di un pacchetto. */
    private static String getUpdatesScriptPackages() {
        return """
        // ================= il quadro dei pacchetti =================
        // Una tabella sola: versione installata e del catalogo, vulnerabilita' con il verdict
        // sulla fix, blocco, e su ogni riga i pulsanti per agire. Si carica da sola.

        /* Il verdict sulla vulnerabilita', in una parola e un colore. */
        function pkVulnBadge(v) {
            if (!v) return '<span class="text-muted small">' + escHtml(t('pkgs.noVuln')) + '</span>';
            const m = { 'si-risolve-aggiornando': ['bg-warning text-dark', 'pkgs.v.fixable'],
                        'aggiornamento-non-basta': ['bg-danger', 'pkgs.v.notEnough'],
                        'fix-fuori-dal-ramo': ['bg-danger', 'pkgs.v.outOfBranch'],
                        'fix-non-indicata': ['bg-danger', 'pkgs.v.noFix'],
                        'nessuna-fix': ['bg-danger', 'pkgs.v.noFix'] }[v.verdict] || ['bg-secondary', 'pkgs.v.unknown'];
            return '<span class="badge ' + m[0] + '"><i class="fas fa-bug me-1" aria-hidden="true"></i>' + escHtml(t(m[1])) + '</span>';
        }

        /* Il dettaglio di una riga: il perche' della vulnerabilita', le CVE, l'avvertenza. */
        function pkDetails(p) {
            let h = '';
            if (p.vuln) {
                h += '<div class="small mb-1">' + escHtml(p.vuln.explanation || '') + '</div>';
                (p.vuln.issues || []).forEach(x => {
                    const url = String(x.url || '');
                    const cves = (x.cve || []).join(', ') || 'VuXML';
                    h += '<div class="small">' + (url.indexOf('https://') === 0
                            ? '<a href="' + escHtml(url) + '" target="_blank" rel="noopener noreferrer">' + escHtml(cves) + '</a>'
                            : '<code>' + escHtml(cves) + '</code>') + ' &mdash; ' + escHtml(x.description || '') + '</div>';
                });
            }
            if (p.advisory && p.advisory.text) h += '<div class="small mt-1"><i class="fas fa-circle-info me-1" aria-hidden="true"></i>' + escHtml(p.advisory.text) + '</div>';
            if (p.whyNot) h += '<div class="small mt-1 text-danger"><i class="fas fa-hand me-1" aria-hidden="true"></i>' + escHtml(p.whyNot) + '</div>';
            if (p.panelRestart) h += '<div class="small mt-1 text-warning"><i class="fas fa-rotate me-1" aria-hidden="true"></i>' + escHtml(p.panelRestart) + '</div>';
            return h;
        }

        async function pkOverview() {
            const el = document.getElementById('pk-body');
            if (!el) return;
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('pkgs.loading'));
            let r;
            try { r = await updApi('packages_overview'); }
            catch (e) { r = { success: false, error: t('common.networkError', { message: e.message }) }; }
            // Un'altra lettura della pagina e' in corso: si riprova fra poco invece di mostrare un errore.
            if (!r.success && r.error === t('up.busy')) { setTimeout(pkOverview, 1500); return; }
            if (!r.success) { el.innerHTML = '<div class="alert alert-danger py-2 small mb-0">' + escHtml(r.error || t('common.unknownError')) + '</div>'; return; }
            const s = r.summary || {};
            let h = '<div class="d-flex flex-wrap gap-1 mb-2">'
                  + '<span class="badge ' + (s.updates ? 'bg-primary' : 'bg-success') + '">' + escHtml(tn('pkgs.sum.updates', s.updates || 0)) + '</span>'
                  + '<span class="badge ' + (s.vulnerable ? 'bg-danger' : 'bg-success') + '">' + escHtml(tn('pkgs.sum.vulnerable', s.vulnerable || 0)) + '</span>'
                  + (s.fixable ? '<span class="badge bg-warning text-dark">' + escHtml(tn('pkgs.sum.fixable', s.fixable)) + '</span>' : '')
                  + '<span class="badge bg-secondary">' + escHtml(tn('pkgs.sum.locked', s.locked || 0)) + '</span></div>';
            if (s.panelRestart) h += '<div class="alert alert-warning py-2 small"><i class="fas fa-rotate me-1" aria-hidden="true"></i>' + escHtml(t('pkgs.panelRestart')) + '</div>';
            if (r.catalogError) h += '<div class="alert alert-danger py-2 small">' + escHtml(t('pkgs.catalogError', { error: r.catalogError })) + '</div>';
            if (r.vulnError) h += '<div class="alert alert-secondary py-2 small">' + escHtml(t('pkgs.vulnError', { error: r.vulnError })) + '</div>';
            if (s.stackUnlocked > 0) {
                h += '<div class="alert alert-warning py-2 small d-flex flex-wrap align-items-center gap-2"><span><i class="fas fa-lock-open me-1" aria-hidden="true"></i>'
                   + escHtml(tn('pkgs.stackUnlocked', s.stackUnlocked)) + '</span>'
                   + '<button type="button" class="btn btn-sm btn-success" onclick="updLockAll(true)"><i class="fas fa-lock me-1" aria-hidden="true"></i>' + escHtml(t('pkgs.bulk.lockAll')) + '</button></div>';
            }
            h += '<div class="table-responsive"><table class="table tabella-schede table-sm align-middle mb-2"><thead><tr>'
               + '<th scope="col">' + escHtml(t('pkgs.colPackage')) + '</th><th scope="col">' + escHtml(t('pkgs.colInstalled')) + '</th><th scope="col">' + escHtml(t('pkgs.colAvailable')) + '</th>'
               + '<th scope="col">' + escHtml(t('pkgs.colSecurity')) + '</th><th scope="col">' + escHtml(t('pkgs.colLock')) + '</th><th scope="col"><span class="visually-hidden">' + escHtml(t('up.colAction')) + '</span></th></tr></thead><tbody>';
            (r.packages || []).forEach((p, i) => {
                const detailInfo = pkDetails(p);
                let actionItems = '';
                if (p.update) {
                    if (p.canUpdate) {
                        actionItems += '<button type="button" class="btn btn-sm ' + (p.vuln ? 'btn-warning' : 'btn-outline-primary') + ' me-1 mb-1 text-nowrap" data-pkg="' + escHtml(p.name) + '" onclick="pkUpdOpen(this.dataset.pkg)">'
                                + '<i class="fas fa-arrow-up me-1" aria-hidden="true"></i>' + escHtml(t('pkgs.update', { v: p.available })) + '</button>';
                    } else if (p.javaFlow) {
                        actionItems += '<button type="button" class="btn btn-sm btn-outline-primary me-1 mb-1 text-nowrap" onclick="pkGoJava()">'
                                + '<i class="fab fa-java me-1" aria-hidden="true"></i>' + escHtml(t('pkgs.javaFlow')) + '</button>';
                    } else {
                        actionItems += '<span class="badge bg-secondary me-1 mb-1">' + escHtml(t('pkgs.heldBack')) + '</span>';
                    }
                }
                actionItems += '<button type="button" class="btn btn-sm btn-outline-secondary mb-1 text-nowrap" data-pkg="' + escHtml(p.name) + '" data-lock="' + (p.locked ? '0' : '1') + '" onclick="pkLock(this.dataset.pkg, this.dataset.lock === \\'1\\')">'
                        + '<i class="fas ' + (p.locked ? 'fa-lock-open' : 'fa-lock') + ' me-1" aria-hidden="true"></i>' + escHtml(p.locked ? t('pkgs.unlock') : t('pkgs.lock')) + '</button>';
                h += '<tr class="upd-cell' + (p.vuln ? ' table-danger' : '') + '">'
                   + '<td data-label="' + escHtml(t('pkgs.colPackage')) + '"><code>' + escHtml(p.name) + '</code>'
                   + (p.role ? '<div class="small text-muted">' + escHtml(p.role) + '</div>' : '')
                   + (p.inUse ? '<span class="badge bg-info text-dark">' + escHtml(p.inUse) + '</span>' : '') + '</td>'
                   + '<td data-label="' + escHtml(t('pkgs.colInstalled')) + '" class="small">' + escHtml(p.installed) + '</td>'
                   + '<td data-label="' + escHtml(t('pkgs.colAvailable')) + '" class="small">' + (p.update ? '<strong>' + escHtml(p.available) + '</strong>'
                        + (p.majorJump ? ' <span class="badge bg-danger">' + escHtml(t('pkgs.majorJump')) + '</span>' : '')
                        : '<span class="text-muted">' + escHtml(t('pkgs.upToDate')) + '</span>') + '</td>'
                   + '<td data-label="' + escHtml(t('pkgs.colSecurity')) + '">' + pkVulnBadge(p.vuln)
                   + (detailInfo ? ' <button type="button" class="btn btn-link btn-sm p-0 ms-1 align-baseline" aria-expanded="false" aria-controls="pk-det-' + i + '" onclick="pkDetail(this, ' + i + ')">' + escHtml(t('pkgs.details')) + '</button>' : '') + '</td>'
                   + '<td data-label="' + escHtml(t('pkgs.colLock')) + '"><span class="badge ' + (p.locked ? 'bg-success' : 'bg-warning text-dark') + '"><i class="fas '
                   + (p.locked ? 'fa-lock' : 'fa-lock-open') + ' me-1" aria-hidden="true"></i>' + escHtml(p.locked ? t('pkgs.locked') : t('pkgs.unlocked')) + '</span></td>'
                   + '<td class="text-end">' + actionItems + '</td></tr>';
                if (detailInfo) h += '<tr id="pk-det-' + i + '" hidden><td colspan="6" class="small">' + detailInfo + '</td></tr>';
            });
            h += '</tbody></table></div>';
            if ((r.others || []).length) {
                h += '<details class="small"><summary>' + escHtml(tn('pkgs.others', r.others.length)) + '</summary>'
                   + '<p class="text-muted mt-2 mb-1">' + escHtml(t('pkgs.othersHint')) + '</p><ul class="mb-0">'
                   + r.others.map(o => '<li><code>' + escHtml(o.name) + '</code> ' + escHtml(o.installed) + ' &rarr; ' + escHtml(o.available) + '</li>').join('')
                   + '</ul></details>';
            }
            el.innerHTML = h;
        }

        function pkDetail(btn, i) {
            const row = document.getElementById('pk-det-' + i);
            if (!row) return;
            row.hidden = !row.hidden;
            btn.setAttribute('aria-expanded', String(!row.hidden));
        }

        /* Il JDK del pannello ha la sua procedura: si apre la sua scheda. */
        function pkGoJava() {
            procOpen('proc-jvm', true);
            const c = document.getElementById('proc-jvm');
            if (c) c.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }

        async function pkLock(name, lock) {
            const el = document.getElementById('pk-result');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(lock ? t('up.locking') : t('up.unlocking'));
            const r = await updApi('packages_lock', { lock: lock, package: name });
            el.innerHTML = r.success
                ? '<div class="small text-success">' + escHtml((r.output || '').trim()) + '</div>'
                : '<div class="small text-danger">' + escHtml(r.error || t('common.unknownError')) + '</div>';
            pkOverview();
        }

        // ---------- l'aggiornamento di un pacchetto, in una finestra ----------
        let pkUpd = { name: '', signature: '', job: '' };

        function pkUpdModal() { return bootstrap.Modal.getOrCreateInstance(document.getElementById('pkUpdModal')); }

        async function pkUpdOpen(name) {
            pkUpd = { name: name, signature: '', job: '' };
            document.getElementById('pkUpdTitle').textContent = t('pkgs.m.title', { name: name });
            const body = document.getElementById('pkUpdBody');
            body.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('pkgs.m.planning'));
            ['pkUpdConfirm', 'pkUpdProgress', 'pkUpdLog'].forEach(id => document.getElementById(id).hidden = true);
            document.getElementById('pkUpdResult').innerHTML = '';
            const go = document.getElementById('pkUpdGo');
            go.hidden = true; go.disabled = true;
            pkUpdModal().show();
            const r = await updApi('package_preflight', { package: name });
            if (!r.success) { body.innerHTML = '<div class="alert alert-danger py-2 small mb-0">' + escHtml(r.error || t('common.unknownError')) + '</div>'; return; }
            pkUpd.signature = r.signature || '';
            const blocks = (r.checks || []).filter(c => c.level === 'block');
            const warnings = (r.checks || []).filter(c => c.level === 'review' || c.level === 'warn' || c.level === 'wait');
            const services = (r.services || []).map(x => typeof x === 'string' ? x : x.name);
            let h = '<p class="mb-2"><code>' + escHtml(r.name) + '</code> ' + escHtml(r.current) + ' &rarr; <strong>' + escHtml(r.available || '?') + '</strong></p>';
            if ((r.cve || []).length) h += '<div class="small mb-2"><strong>' + escHtml(t('up.closes')) + '</strong> ' + r.cve.map(c => '<span class="badge bg-dark me-1">' + escHtml(c) + '</span>').join('') + '</div>';
            if (blocks.length) {
                h += '<div class="alert alert-danger py-2 small"><strong>' + escHtml(t('pkgs.m.blocked')) + '</strong><ul class="mb-0">'
                   + blocks.map(c => '<li><strong>' + escHtml(c.label) + ':</strong> ' + escHtml(c.detail) + '</li>').join('') + '</ul></div>';
            }
            const unlockedList = (r.plan && r.plan.unlockedPackages) || [];
            h += '<h6 class="mt-3">' + escHtml(t('pkgs.m.steps')) + '</h6><ol class="small">'
               + '<li>' + escHtml(unlockedList.length ? t('pkgs.m.stepUnlock', { list: unlockedList.join(', ') }) : t('pkgs.m.stepNoUnlock')) + '</li>'
               + '<li>' + escHtml(t('pkgs.m.stepUpgrade')) + '</li>'
               + '<li>' + escHtml(services.length ? t('pkgs.m.stepRestart', { list: services.join(', ') }) : t('pkgs.m.stepNoRestart')) + '</li>'
               + '<li>' + escHtml(unlockedList.length ? t('pkgs.m.stepRelock') : t('pkgs.m.stepCheck')) + '</li></ol>'
               + updPlanHtml(r.plan, r.signature);
            if (warnings.length) {
                h += '<h6 class="mt-3">' + escHtml(t('pkgs.m.warnings')) + '</h6><ul class="small">'
                   + warnings.map(c => '<li><strong>' + escHtml(c.label) + ':</strong> ' + escHtml(c.detail) + '</li>').join('') + '</ul>';
            }
            body.innerHTML = h;
            if (!blocks.length && !r.blocked) {
                const inp = document.getElementById('pkUpdName');
                document.getElementById('pkUpdNameLabel').textContent = t('pkgs.m.confirm', { name: name });
                inp.value = '';
                inp.oninput = () => { go.disabled = inp.value !== name; };
                document.getElementById('pkUpdConfirm').hidden = false; go.hidden = false; go.disabled = true;
                inp.focus();
            }
        }

        async function pkUpdRun() {
            const go = document.getElementById('pkUpdGo');
            go.disabled = true;
            const res = document.getElementById('pkUpdResult');
            const r = await updApi('package_update', { package: pkUpd.name, confirm: document.getElementById('pkUpdName').value, signature: pkUpd.signature });
            if (!r.success) { res.innerHTML = '<div class="alert alert-danger py-2 small mb-0">' + escHtml(r.error || t('common.unknownError')) + '</div>'; go.disabled = false; return; }
            pkUpd.job = r.jobId;
            go.hidden = true;
            document.getElementById('pkUpdConfirm').hidden = true;
            document.getElementById('pkUpdProgress').hidden = false;
            document.getElementById('pkUpdLog').hidden = false;
            res.innerHTML = '<span class="text-info"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('pkgs.m.running')) + '</span>';
            pkUpdPoll(r.jobId);
        }

        async function pkUpdPoll(id) {
            if (pkUpd.job !== id) return;
            const s = await updApi('job_status', { jobId: id });
            const res = document.getElementById('pkUpdResult');
            if (s.success && s.job) {
                const log = document.getElementById('pkUpdLog');
                log.textContent = s.job.consoleLog || '';
                log.scrollTop = log.scrollHeight;
                const bar = document.querySelector('#pkUpdProgress .progress-bar');
                const pct = s.job.percent || 0;
                bar.style.width = pct + '%';
                document.getElementById('pkUpdProgress').setAttribute('aria-valuenow', String(pct));
                if (s.job.status === 'completed') {
                    bar.classList.remove('progress-bar-animated'); bar.classList.add('bg-success'); bar.style.width = '100%';
                    res.innerHTML = '<div class="alert alert-success py-2 small mb-0"><i class="fas fa-check me-1" aria-hidden="true"></i>' + escHtml(t('pkgs.m.done', { name: pkUpd.name })) + '</div>';
                    pkOverview();
                    return;
                }
                if (s.job.status === 'error') {
                    bar.classList.remove('progress-bar-animated'); bar.classList.add('bg-danger');
                    res.innerHTML = '<div class="alert alert-danger py-2 small mb-0"><i class="fas fa-times me-1" aria-hidden="true"></i>' + escHtml(t('pkgs.m.failed', { error: s.job.errorMessage || '' })) + '</div>';
                    pkOverview();
                    return;
                }
            }
            setTimeout(() => pkUpdPoll(id), 3000);
        }

        document.addEventListener('DOMContentLoaded', () => { if (document.getElementById('pk-body')) pkOverview(); });
        """;
    }

    private static String getUpdatesScript1() {
        return """
        let updBusy = false;

        // Le operazioni su pkg toccano la rete e durano decine di secondi, tenendo occupato
        // un thread HTTP del pannello: due click o due schede bastano a saturarlo. La guardia
        // sta qui, in un punto solo, invece che dentro ogni funzione.
        async function updApi(action, extra) {
            if (updBusy) return { success: false, error: t('up.busy') };
            const slow = action !== 'job_status';
            if (slow) updBusy = true;
            try {
                const body = Object.assign({
                    action: action,
                    csrf_token: document.getElementById('csrf_token').value
                }, extra || {});
                const res = await fetch('/api/updates', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body)
                });
                return await res.json();
            } catch (e) {
                return { success: false, error: t('common.networkError', { message: e.message }) };
            } finally {
                if (slow) updBusy = false;
            }
        }

        // Conferma scritta: la parola si mostra nella lingua della pagina; al server va il suo codice.
        function updConfirm(textValue, keyword) {
            const typed = prompt((textValue ? textValue + '\\n\\n' : '') + t('ad.typeToConfirm', { word: keyword }));
            return typed !== null && typed.trim().toUpperCase() === keyword.toUpperCase();
        }

        function updEsc(v) {
            const d = document.createElement('div');
            d.textContent = v === null || v === undefined ? '' : String(v);
            return d.innerHTML;
        }

        // I verdetti arrivano come codici: il server e la pagina li confrontano cosi' come sono,
        // e il testo da leggere si sceglie qui, nella lingua della pagina.
        function updVerdict(v) {
            return ({
                "IL LIVELLO E' INDIETRO": t('up.vLevelBehind'),
                'ALLINEATO': t('up.vAligned'),
                'LOG NON LEGGIBILE': t('up.vLogUnreadable'),
                'CI SONO ANALISI INTERROTTE': t('up.vScansInterrupted'),
                'NESSUNA ANALISI INTERROTTA': t('up.vNoScanInterrupted'),
                "NESSUNA TRACCIA, MA IL LOG E' CORTO": t('up.vNoTraceShortLog'),
                "C'E' UN COSTRUTTO NON PIU' VALIDO": t('up.vInvalidConstruct'),
                'DIFFERENZE DI COMPORTAMENTO NELLA TUA CONFIGURAZIONE': t('up.vBehaviorDiffs'),
                'NIENTE DA SEGNALARE': t('up.vNothingToReport'),
                'CI SONO RIFERIMENTI CHE SI ROMPEREBBERO': t('up.vRefsWouldBreak'),
                'NESSUN RIFERIMENTO CHE SI ROMPA': t('up.vNoRefBreaks'),
                'NON DETERMINABILE': t('up.vUndetermined'),
                "NON NE USA I COMANDI, MA E' UNA LIBRERIA": t('up.vLibraryOnly'),
                'IL PANNELLO NON LO USA': t('up.vPanelDoesNotUse'),
                'LI NOMINA, MA NON SONO I SUOI': t('up.vNamesNotTheirs'),
                "LO USA, E NON C'E' RICAMBIO": t('up.vUsesNoSpare'),
                'LO USA': t('up.vUses'),
                'IN USO ADESSO': t('up.vInUseNow'),
                'RICHIESTO': t('up.vRequired'),
                "IL COMANDO E' SUO": t('up.vCommandIsIts'),
                'NESSUNO LO USA': t('up.vNobodyUses')
            })[v] || v;
        }

        function updBadge(level) {
            if (level === 'ok') return '<span class="badge upd-badge-ok">OK</span>';
            // "NOTA" e' diverso da "VERIFICA": VERIFICA chiede qualcosa a chi legge, NOTA
            // racconta soltanto cosa fara' la procedura. Messe sotto la stessa etichetta
            // gialla, una riga puramente descrittiva sembra una cosa rimasta da fare.
            if (level === 'note') return '<span class="badge upd-badge-info">' + escHtml(t('up.bNote')) + '</span>';
            if (level === 'review') return '<span class="badge upd-badge-warn">' + escHtml(t('up.bCheck')) + '</span>';
            return '<span class="badge upd-badge-stop">' + escHtml(t('up.bWait')) + '</span>';
        }

""" + resource("pages/port465.js") + resource("pages/standards-watch.js") + resource("pages/web-diagnostics.js") + resource("pages/web443.js") + resource("pages/enable-mtasts.js") + resource("pages/cf-ranges.js") + """
        // ---------- compatibilita' ----------
        async function updCompat() {
            const el = document.getElementById('upd-compat');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.readingConfig')) + '';
            const r = await updApi('compatibility');
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            let h = '';

            const d = r.dovecot || {};
            h += '<h6 class="mb-1"><i class="fas fa-inbox me-1"></i>Dovecot</h6>';
            h += '<div class="small text-muted mb-2">' + escHtml(t('up.dvLine', { installed: d.installed || '?', available: d.available || '?', n: d.configFilesScanned || 0 })) + '</div>';

            if ((d.repoPackages || []).length) {
                h += '<div class="small mb-2"><strong>' + escHtml(t('up.dvRepoPkgs')) + '</strong> '
                   + d.repoPackages.map(p => updEsc(p.name) + ' ' + updEsc(p.version)).join(' &middot; ')
                   + '</div>';
            }

            if (d.doveconfAvailable === false) {
                h += '<div class="small text-muted mb-2">' + escHtml(t('up.noDoveconf')) + '</div>';
            } else if (d.doveconfOk) {
                h += '<div class="small text-success mb-2"><i class="fas fa-check me-1" aria-hidden="true"></i>'
                   + t('up.doveconfOk.html') + '</div>';
            } else {
                h += '<div class="alert alert-warning py-2 small mb-2"><strong>' + escHtml(t('up.doveconfWarn')) + '</strong>'
                   + '<pre class="upd-log mt-1 mb-0">' + updEsc(d.doveconfOutput || '') + '</pre></div>';
            }
            if (!d.scanned) {
                h += '<div class="alert alert-secondary py-2 small">' + updEsc(d.note || t('up.configNotFound')) + '</div>';
            } else if (d.compatible24) {
                h += '<div class="alert alert-success py-2 small"><i class="fas fa-check me-1" aria-hidden="true"></i>'
                   + escHtml(t('up.dvCompatOk')) + '</div>';
            } else {
                h += '<div class="alert alert-danger py-2 small mb-2">' + t('up.dvBreak.html') + ' '
                   + escHtml(d.breakingUpgradeAvailable ? t('up.dvBreakNow') : t('up.dvBreakLater'))
                   + '</div>';
                h += '<div class="table-responsive"><table class="table table-sm"><thead><tr>'
                   + '<th scope="col" style="width:30%">' + escHtml(t('up.colConstruct')) + '</th><th scope="col">' + escHtml(t('up.colWants24')) + '</th><th scope="col" style="width:30%">' + escHtml(t('up.colWhere')) + '</th></tr></thead><tbody>';
                (d.issues || []).forEach(i => {
                    h += '<tr class="upd-cell"><td><code>' + updEsc(i.construct) + '</code></td>'
                       + '<td>' + updEsc(i.replacement) + '</td>'
                       + '<td class="small text-muted">' + (i.files || []).map(f => updEsc(f)).join('<br>') + '</td></tr>';
                });
                h += '</tbody></table></div>';
                h += '<p class="small text-muted">' + t('up.dvBlock.html') + '</p>';
                if (d.source) {
                    h += '<p class="small text-muted"><strong>' + escHtml(t('up.source')) + '</strong> ' + updEsc(d.source) + '</p>';
                }
                h += '<button class="btn btn-sm btn-outline-primary" onclick="where24()">'
                   + '<i class="fas fa-file-lines me-1" aria-hidden="true"></i>' + escHtml(t('up.see24')) + '</button>'
                   + '<div id="dove24-body" class="mt-2"></div>';
            }

            // ---------- Postfix: non una rottura annunciata, ma la rete di sicurezza ----------
            const pf = r.postfix || {};
            h += '<hr><h6 class="mb-1"><i class="fas fa-paper-plane me-1"></i>Postfix</h6>';
            if (!pf.present) {
                h += '<div class="small text-muted">' + updEsc(pf.note || t('up.notInstalled')) + '</div>';
            } else if (!pf.readable) {
                h += '<div class="alert alert-warning py-2 small mb-2">' + updEsc(pf.note) + '</div>';
            } else {
                h += '<div class="small text-muted mb-1">' + escHtml(t('up.pfLine', { pkg: pf.package, version: pf.version, repo: pf.repoVersion || '?', level: pf.level || '?' }))
                   + ' ' + escHtml(pf.explicitLevel ? t('up.inMainCf') : t('up.defaultValue')) + '</div>'
                   + '<div class="alert alert-' + (pf.verdict === 'ALLINEATO' ? 'success' : 'warning')
                   + ' py-2 small mb-2"><strong>' + updEsc(updVerdict(pf.verdict)) + '</strong> &mdash; '
                   + updEsc(pf.explanation) + '</div>';
                const cb = pf.changes || [];
                if (cb.length) {
                    h += '<div class="table-responsive"><table class="table table-sm mb-2"><thead><tr>'
                       + '<th scope="col">' + escHtml(t('up.colLevel')) + '</th><th scope="col">' + escHtml(t('up.colWouldChange')) + '</th></tr></thead><tbody>';
                    cb.forEach(x => {
                        h += '<tr class="upd-cell"><td><code>' + updEsc(x.level) + '</code></td>'
                           + '<td class="small">' + updEsc(x.change)
                           + '<div class="mt-1">' + (x.parameters || []).map(pp =>
                                pp.alreadyDecided
                                  ? '<span class="badge upd-badge-ok me-1">' + updEsc(pp.name)
                                    + ' = ' + updEsc(pp.value) + ' (' + escHtml(t('up.decidedByYou')) + ')</span>'
                                  : (!pp.relevant
                                     ? '<span class="badge upd-badge-info me-1">' + updEsc(pp.name)
                                       + ' (' + escHtml(t('up.irrelevant', { gate: pp.gate, value: pp.gateValue || 'no' })) + ')</span>'
                                     : '<span class="badge upd-badge-warn me-1">' + updEsc(pp.name)
                                       + ' (' + escHtml(t('up.defaultDecides')) + ')</span>')).join(' ')
                           + '</div></td></tr>';
                    });
                    h += '</tbody></table></div>';
                    if (pf.effectHere) {
                        h += '<div class="alert alert-' + (pf.openHere ? 'warning' : 'success')
                           + ' py-2 small mb-2"><strong>' + escHtml(t('up.onThisServer')) + '</strong> ' + updEsc(pf.effectHere) + '</div>';
                    }
                }
                if (pf.back && pf.recommended) {
                    h += '<button class="btn btn-sm btn-outline-warning mb-1" data-level="' + escHtml(pf.recommended) + '" data-open="' + Number(pf.openHere || 0) + '"'
                       + ' onclick="pfRaise(this.dataset.level, Number(this.dataset.open))">'
                       + '<i class="fas fa-arrow-up me-1" aria-hidden="true"></i>' + escHtml(t('up.raiseLevel', { level: pf.recommended }))
                       + '</button><div id="pf-outcome" class="mt-1"></div>'
                       + '<div class="small text-muted mb-2">' + t('up.raiseNote.html') + '</div>';
                }
                const ap = pf.supports || [];
                if (ap.length) {
                    h += '<div class="small mb-1">' + escHtml(t('up.pfLegacy')) + '</div>'
                       + '<div class="table-responsive"><table class="table table-sm mb-2"><tbody>';
                    ap.forEach(x => { h += '<tr class="upd-cell"><td><code class="small">' + updEsc(x) + '</code></td></tr>'; });
                    h += '</tbody></table></div>';
                }
                // Doppia condizione di proposito: il campo puo' mancare (e' gia' successo),
                // ma il contenuto vuoto e' un fatto che si vede sempre.
                if (!pf.cleanCheck && pf.check) {
                    h += '<div class="small mb-1"><strong>postfix check:</strong></div>'
                       + '<pre class="upd-log mb-2">' + updEsc(pf.check) + '</pre>';
                } else {
                    h += '<div class="small text-muted mb-2">' + t('up.pfCheckClean.html') + '</div>';
                }
                h += '<div class="small text-muted mb-2"><strong>' + escHtml(t('up.source')) + '</strong> ' + updEsc(pf.source) + '</div>';
            }

            // ---------- Rspamd: cambia il comportamento, non la sintassi ----------
            const rs = r.rspamd || {};
            h += '<hr><h6 class="mb-1"><i class="fas fa-shield-halved me-1"></i>Rspamd</h6>';
            if (!rs.present) {
                h += '<div class="small text-muted">' + updEsc(rs.note || t('up.notInstalled')) + '</div>';
            } else {
                const cls = rs.verdict === 'NIENTE DA SEGNALARE' ? 'success'
                          : (rs.verdict === 'DIFFERENZE DI COMPORTAMENTO NELLA TUA CONFIGURAZIONE' ? 'info' : 'danger');
                h += '<div class="small text-muted mb-1">' + escHtml(t('up.rsLine', { version: rs.version, repo: rs.repoVersion || '?', n: rs.filesRead })) + '</div>'
                   + '<div class="alert alert-' + cls + ' py-2 small mb-2"><strong>' + updEsc(updVerdict(rs.verdict))
                   + '</strong> &mdash; ' + updEsc(rs.explanation) + '</div>';
                const is = rs.issues || [];
                if (is.length) {
                    h += '<div class="table-responsive"><table class="table table-sm mb-2"><thead><tr>'
                       + '<th scope="col">' + escHtml(t('up.colConstruct')) + '</th><th scope="col">' + escHtml(t('up.colChanges')) + '</th><th scope="col">' + escHtml(t('up.colWhere')) + '</th></tr></thead><tbody>';
                    is.forEach(x => {
                        h += '<tr class="upd-cell"><td><code class="small">' + updEsc(x.construct) + '</code><br>'
                           + '<span class="badge ' + (x.type === 'broken' ? 'upd-badge-stop'
                                : (x.type === 'default' ? 'upd-badge-info' : 'upd-badge-warn'))
                           + '">' + escHtml(x.type === 'broken' ? t('up.noLongerValid')
                                : (x.type === 'default' ? t('up.pkgDefaultOnly') : t('up.behaviour')))
                           + '</span></td>'
                           + '<td class="small">' + updEsc(x.whatChanges) + '</td>'
                           + '<td class="small">'
                           + ((x.files || []).length
                              ? '<strong>' + escHtml(t('up.inYourFiles')) + '</strong><br>' + x.files.map(f => updEsc(f)).join('<br>')
                              : '<span class="text-muted">' + escHtml(t('up.inNoFile')) + '</span>')
                           + ((x.packageFiles || []).length
                              ? '<br><span class="text-muted">' + escHtml(t('up.pkgFilesOnly')) + '<br>' + x.packageFiles.map(f => updEsc(f)).join('<br>')
                                + '</span>'
                              : '')
                           + '</td></tr>';
                    });
                    h += '</tbody></table></div>';
                }
                h += '<button class="btn btn-sm btn-outline-primary mb-2" onclick="rsTimeout()">'
                   + '<i class="fas fa-stopwatch me-1" aria-hidden="true"></i>' + escHtml(t('up.everTimedOut')) + '</button>'
                   + '<div id="rs-timeout" class="mb-2"></div>';
                h += '<div class="small mb-1"><strong>rspamadm configtest:</strong> '
                   + (rs.configtestOk
                      ? '<span class="badge upd-badge-ok">' + escHtml(t('up.configValid')) + '</span>'
                      : '<span class="badge upd-badge-warn">' + escHtml(t('up.toLookAt')) + '</span>')
                   + '</div><pre class="upd-log mb-2">' + updEsc(rs.configtest) + '</pre>'
                   + '<div class="small text-muted mb-1"><strong>' + escHtml(t('up.bayes')) + '</strong> ' + updEsc(rs.bayes) + '</div>'
                   + '<div class="small text-muted mb-2"><strong>' + escHtml(t('up.source')) + '</strong> ' + updEsc(rs.source) + '</div>';
            }

            const m = r.mysql || {};
            h += '<hr><h6 class="mb-1"><i class="fas fa-database me-1"></i>MySQL</h6>';
            if (!m.present) {
                h += '<div class="small text-muted">' + updEsc(m.note || t('up.notInstalled')) + '</div>';
            } else {
                h += '<div class="small text-muted mb-2">' + updEsc(m.package) + ' ' + updEsc(m.version) + '</div>';
                if (m.eol) {
                    h += '<div class="alert alert-warning py-2 small">' + t('up.my80Eol.html') + '</div>';
                }
                if ((m.issues || []).length) {
                    h += '<div class="alert alert-danger py-2 small"><strong>' + escHtml(tn('up.mycnfRemoved', m.issues.length)) + '</strong> '
                       + escHtml(t('up.mycnfOneEnough')) + '<ul class="mb-0 mt-1">';
                    m.issues.forEach(i => { h += '<li><code>' + updEsc(i.option) + '</code> &rarr; ' + updEsc(i.replacement) + '</li>'; });
                    h += '</ul></div>';
                } else if (m.mycnfPresent) {
                    h += '<div class="small text-success"><i class="fas fa-check me-1" aria-hidden="true"></i>' + escHtml(t('up.mycnfClean')) + '</div>';
                }
            }

            const w = r.webmail || {};
            h += '<hr><h6 class="mb-1"><i class="fas fa-globe me-1" aria-hidden="true"></i>' + escHtml(t('up.webmailPhp')) + '</h6>';
            h += '<div class="small text-muted mb-2">' + updEsc(w.php || t('up.phpMissing')) + ' ' + updEsc(w.phpVersion || '')
               + ' &middot; ' + updEsc(w.roundcube || t('up.rcMissing')) + ' ' + updEsc(w.roundcubeVersion || '') + '</div>';
            if (w.consistent) {
                h += '<div class="small text-success"><i class="fas fa-check me-1" aria-hidden="true"></i>' + escHtml(t('up.phpConsistent')) + '</div>';
            } else {
                h += '<div class="alert alert-warning py-2 small"><ul class="mb-0">'
                   + (w.notes || []).map(n => '<li>' + updEsc(n) + '</li>').join('') + '</ul></div>';
            }
            el.innerHTML = h;
        }

        async function updDumpDovecot() {
            const el = document.getElementById('upd-dovecot-dump');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.readingFiles')) + '';
            const r = await updApi('dovecot_config_dump');
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            let h = '<hr><div class="small text-muted mb-2">' + escHtml(t('up.filesRead', { n: r.count })) + '</div>';
            (r.files || []).forEach(f => {
                h += '<details class="mb-1"><summary class="small"><code>' + updEsc(f.path) + '</code> '
                   + '<span class="text-muted">(' + escHtml(tn('sj.lines', f.lines)) + ')</span></summary>'
                   + '<pre class="upd-log mt-1">' + updEsc(f.content) + '</pre></details>';
            });
            el.innerHTML = h;
        }

        async function updRegenDovecot() {
            if (!updConfirm(t('up.confirmRegenDovecot'), t('up.wRegen'))) return;
            const el = document.getElementById('upd-status');
            const pre = document.getElementById('upd-log');
            const r = await updApi('dovecot_config_regen', { confirm: 'RIGENERA' });
            if (!r.success) { alert(r.error || t('common.failed')); return; }
            el.innerHTML = '<span class="text-info"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.regenRunning')) + '</span>';
            pre.style.display = 'block';
            updPoll(r.jobId, el, pre);
        }

        async function cleanClient(foreign, correct) {
            if (!updConfirm('', t('up.wRemove'))) return;
            const el = document.getElementById('libs-body');
            const pre = document.getElementById('libs-log');
            const r = await updApi('clean_client', { confirm: 'REMOVE', foreign: foreign, correct: correct });
            if (!r.success) { alert(r.error || t('common.failed')); return; }
            el.innerHTML = '<span class="text-info"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.cleaning')) + '</span>';
            pre.style.display = 'block';
            planPoll(r.jobId, el, pre);
        }

        // ---------- coerenza con i predefiniti ----------
        // ---------- riavvio del server ----------
        async function rebPrev() {
            const el = document.getElementById('os-body');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.checkingImpact')) + '';
            const r = await updApi('reboot_preview');
            if (!r.success) {
                el.innerHTML = '<div class="alert alert-danger py-2 mb-0">' + updEsc(r.error) + '</div>';
                return;
            }
            let h = '<div class="table-responsive"><table class="table table-sm mb-2"><tbody>'
                  + '<tr class="upd-cell"><td style="width:14rem"><strong>' + escHtml(t('up.kernelInstalled')) + '</strong></td><td><code>'
                  + updEsc(r.installedKernel) + '</code></td></tr>'
                  + '<tr class="upd-cell"><td><strong>' + escHtml(t('up.kernelRunning')) + '</strong></td><td><code>'
                  + updEsc(r.runningKernel) + '</code>'
                  + (r.restartNeeded
                     ? ' <span class="badge upd-badge-warn ms-2">' + escHtml(t('up.kernelMismatchReboot')) + '</span>'
                     : ' <span class="badge upd-badge-ok ms-2">' + escHtml(t('up.kernelMatchNoReboot')) + '</span>') + '</td></tr>'
                  + '<tr class="upd-cell"><td><strong>' + escHtml(t('up.servicesStopping')) + '</strong></td><td>'
                  + (r.services || []).map(updEsc).join(', ') + '</td></tr>'
                  + '<tr class="upd-cell"><td><strong>' + escHtml(t('up.commandRun')) + '</strong></td><td><code>'
                  + updEsc(r.daemonPath) + ' -f -o /var/db/mailpanel/reboot.log '
                  + updEsc(r.shutdownPath) + ' -r +1</code></td></tr>' 
                  + '</tbody></table></div>'
                  + '<div class="alert alert-warning py-2">' + updEsc(r.effect) + '</div>';
            if (r.noshutdown) {
                h += '<div class="alert alert-danger py-2"><strong>' + updEsc(r.noshutdownWarning) + '</strong></div>';
            }
            if (r.gaScheduled) {
                h += '<div class="alert alert-danger py-2">' + escHtml(t('up.rebootScheduled')) + ' <code>'
                   + updEsc(r.gaScheduled) + '</code> '
                   + '<button class="btn btn-sm btn-light ms-2" onclick="rebCancel()">' + escHtml(t('up.cancelReboot')) + '</button></div>';
            }
            h += '<div class="alert alert-secondary py-2 small">' + t('up.rebootInfo.html') + '</div>'
               + '<button class="btn btn-danger" onclick="rebGo()"><i class="fas fa-rotate-right me-1" aria-hidden="true"></i>' + escHtml(t('up.scheduleReboot')) + '</button>';
            el.innerHTML = h;
        }

        async function rebGo() {
            if (!updConfirm('', t('up.wReboot'))) return;
            const el = document.getElementById('os-body');
            const r = await updApi('reboot_now', { confirm: 'RIAVVIA IL SERVER', minutes: 1 });
            if (!r.success) {
                el.innerHTML = '<div class="alert alert-danger py-2 mb-0"><strong>' + escHtml(t('up.rebootNotScheduled')) + '</strong><br>'
                    + updEsc(r.error) + (r.output ? '<br><code>' + updEsc(r.output) + '</code>' : '') + '</div>';
                return;
            }
            el.innerHTML = '<div class="alert alert-danger py-2 mb-0"><strong>' + updEsc(r.note) + '</strong>'
                + ' (' + escHtml(t('up.process', { pid: r.pid })) + ')'
                + '<br>' + escHtml(t('up.pageWillStop'))
                + '<br><button class="btn btn-light mt-2" onclick="rebCancel()">'
                + '<i class="fas fa-ban me-1" aria-hidden="true"></i>' + escHtml(t('up.cancelReboot')) + '</button></div>';
        }

        // Su FreeBSD non esiste un'opzione per annullare: il manuale di shutdown(8) dice di
        // terminare il processo. Attenzione, "shutdown -c" NON annulla: e' power cycle.
        async function rebCancel() {
            const el = document.getElementById('os-body');
            const r = await updApi('reboot_cancel');
            el.innerHTML = '<div class="alert alert-' + (r.success ? (r.existedBefore ? 'success' : 'secondary') : 'danger')
                + ' py-2 mb-0">' + updEsc(r.note || r.error) + '</div>';
        }

        // ---------- avvio automatico del pannello (rc.d) ----------
        async function rcPrev() {
            const el = document.getElementById('os-body'), pre = document.getElementById('os-log');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.preparingScript')) + '';
            const r = await updApi('rc_preview');
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            pre.style.display = 'block';
            pre.textContent = r.text;
            let h = '<p class="small text-muted mb-2">' + t('up.rcdIntro.html', { path: updEsc(r.path) }) + '</p>'
                  + '<div class="table-responsive"><table class="table table-sm mb-2"><tbody>'
                  + '<tr class="upd-cell"><td style="width:12rem"><strong>' + escHtml(t('up.workDir')) + '</strong></td><td><code>' + updEsc(r.dir) + '</code></td></tr>'
                  + '<tr class="upd-cell"><td><strong>Java</strong></td><td><code>' + updEsc(r.java) + '</code></td></tr>'
                  + '<tr class="upd-cell"><td><strong>Jar</strong></td><td><code>' + updEsc(r.jar) + '</code></td></tr>'
                  + '<tr class="upd-cell"><td><strong>' + escHtml(t('up.alreadyInstalled')) + '</strong></td><td>' + escHtml(r.exists ? t('dns.yes') : t('acf.no'))
                  + (r.enabled ? '  &mdash; mailpanel_enable=' + updEsc(r.enabled) : '') + '</td></tr>'
                  + '</tbody></table></div>'
                  + '<div class="alert alert-info py-2">' + t('up.rcNotStarted.html') + '</div>'
                  + '<button class="btn btn-warning" onclick="rcGo()"><i class="fas fa-power-off me-1" aria-hidden="true"></i>' + escHtml(t('up.installEnable')) + '</button>'
                  // La via d'uscita si mostra solo quando c'e' qualcosa da togliere: un
                  // pulsante che, premuto, risponde "non c'e' niente da fare" e' un pulsante
                  // che non andava mostrato.
                  + ((r.exists || r.enabled)
                     ? ' <button class="btn btn-outline-danger ms-2" onclick="rcRemovePrev()"><i class="fas fa-trash me-1" aria-hidden="true"></i>' + escHtml(t('up.removeAutostart')) + '</button>'
                     : '');
            el.innerHTML = h;
        }

        // ---------- togliere l'avvio automatico ----------
        // Esiste perche' un pulsante che si puo' solo premere in un verso non e' una scelta:
        // e' una porta a senso unico. Il pannello web ha la rimozione da stamattina, qui
        // mancava.
        async function rcRemovePrev() {
            const el = document.getElementById('os-body'), pre = document.getElementById('os-log');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.lookingRemove')) + '';
            const r = await updApi('rc_remove_preview');
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            pre.style.display = 'none';
            if (r.nothingToDo) {
                el.innerHTML = '<div class="alert alert-info py-2 mb-0">' + updEsc(r.note) + '</div>'
                             + '<button class="btn btn-sm btn-outline-secondary mt-2" onclick="rcPrev()">' + escHtml(t('up.back')) + '</button>';
                return;
            }
            el.innerHTML = '<div class="alert alert-warning py-2 mb-2"><strong>' + escHtml(t('up.whatHappens')) + '</strong> '
                + updEsc(r.note) + '</div>'
                + '<div class="table-responsive"><table class="table table-sm mb-2"><tbody>'
                + '<tr class="upd-cell"><td style="width:14rem"><strong>' + escHtml(t('up.rcScript')) + '</strong></td><td>'
                + (r.installed ? '<code>' + updEsc(r.path) + '</code> &mdash; ' + escHtml(t('up.willBeDeleted'))
                                : '<span class="text-muted">' + escHtml(t('up.notPresent')) + '</span>') + '</td></tr>'
                + '<tr class="upd-cell"><td><strong>mailpanel_enable</strong></td><td>'
                + (r.variableExists ? '<code>' + updEsc((r.before && r.before.sysrcValue) || '') + '</code> &mdash; ' + escHtml(t('up.willLeaveRcConf'))
                                     : '<span class="text-muted">' + escHtml(t('up.notSetUntouched')) + '</span>') + '</td></tr>'
                + '<tr class="upd-cell"><td><strong>' + escHtml(t('up.backupCopy')) + '</strong></td><td><code>' + updEsc(r.copy) + '</code>'
                + '<div class="small text-muted">' + escHtml(t('up.noCopyNoDelete')) + '</div></td></tr>'
                + '</tbody></table></div>'
                + '<div class="alert alert-info py-2 mb-2"><i class="fas fa-circle-info me-1" aria-hidden="true"></i>'
                + t('up.rcRemoveInfo.html') + '</div>'
                + '<button class="btn btn-danger" onclick="rcRemoveGo()"><i class="fas fa-trash me-1" aria-hidden="true"></i>' + escHtml(t('up.removeAutostart')) + '</button>'
                + ' <button class="btn btn-outline-secondary ms-2" onclick="rcPrev()">' + escHtml(t('common.cancel')) + '</button>';
        }

        async function rcRemoveGo() {
            if (!updConfirm(t('up.confirmRemoveRc'), t('up.wRemoveRc'))) return;
            const el = document.getElementById('os-body');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.removingAutostart')) + '';
            const r = await updApi('rc_remove', { confirm: 'RIMUOVI RC' });
            el.innerHTML = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 mb-0">'
                + updEsc(r.note || r.error) + '</div>'
                + '<button class="btn btn-sm btn-outline-secondary mt-2" onclick="rcPrev()">'
                + '<i class="fas fa-rotate me-1" aria-hidden="true"></i>' + escHtml(t('up.rereadState')) + '</button>';
        }

        async function rcGo() {
            if (!updConfirm('', t('up.wInstallRc'))) return;
            const el = document.getElementById('os-body'), pre = document.getElementById('os-log');
            const r = await updApi('rc_install', { confirm: 'INSTALLA RC' });
            if (!r.success) { el.innerHTML = '<div class="alert alert-danger py-2 mb-0">' + updEsc(r.error) + '</div>'; return; }
            pre.style.display = 'block';
            pre.textContent = 'service mailpanel rcvar:\\n' + (r.rcvar || '');
            el.innerHTML = '<div class="alert alert-' + (r.loaded ? 'success' : 'warning') + ' py-2 mb-0">'
                + (r.loaded
                   ? '<strong>' + escHtml(t('up.installed')) + '</strong> ' + escHtml(t('up.rcLoaded', { value: r.enabledNow })) + ' '
                   : '<strong>' + escHtml(t('up.installedNotRecognized')) + '</strong> ' + escHtml(t('up.lookBelow')) + ' ')
                + updEsc(r.note) + '</div>';
        }

        // ---------- sistema operativo ----------
        async function osState() {
            const el = document.getElementById('os-body');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.readingOs')) + '';
            const r = await updApi('os_status');
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            let h = '<div class="table-responsive"><table class="table table-sm align-middle mb-2"><tbody>'
                  + '<tr class="upd-cell"><td style="width:16rem"><strong>' + escHtml(t('up.kernelInstalled')) + '</strong></td><td><code>'
                  + updEsc(r.installedKernel) + '</code></td></tr>'
                  + '<tr class="upd-cell"><td><strong>' + escHtml(t('up.kernelRunning')) + '</strong></td><td><code>'
                  + updEsc(r.uname) + '</code>' + (r.restartNeeded
                      ? ' <span class="badge upd-badge-warn ms-2">' + escHtml(t('up.kernelMismatch')) + '</span>'
                      : ' <span class="badge upd-badge-ok ms-2">' + escHtml(t('up.kernelMatch')) + '</span>') + '</td></tr>'
                  + '<tr class="upd-cell"><td><strong>Userland</strong></td><td><code>' + updEsc(r.userland) + '</code></td></tr>'
                  + '<tr class="upd-cell"><td><strong>' + escHtml(t('up.arch')) + '</strong></td><td><code>' + updEsc(r.arch) + '</code></td></tr>'
                  + '<tr class="upd-cell"><td><strong>' + escHtml(t('up.eos')) + '</strong></td><td>'
                  + (r.endOfSupport
                     ? '<strong>' + updEsc(r.endOfSupport) + '</strong> <span class="small text-muted">' + updEsc(r.supportNotes) + '</span>'
                     : '<span class="text-warning">' + escHtml(t('up.seriesUnknown', { series: r.series })) + '</span>')
                  + '</td></tr></tbody></table></div>'
                  + '<p class="small text-muted">' + escHtml(t('up.sourceIs', { source: r.supportSource })) + '</p>';
            if (r.updatableWithFreebsdUpdate) {
                h += '<div class="alert alert-' + (r.readyExist ? 'warning' : 'secondary') + ' py-2">'
                   + '<strong>' + escHtml(t('up.baseFetched')) + '</strong> ' + updEsc(r.alreadyReady) + '</div>'
                   + '<button class="btn btn-outline-primary" onclick="osSearch()"><i class="fas fa-download me-1" aria-hidden="true"></i>' + escHtml(t('up.fetchOs')) + '</button>'
                   + '<span class="small text-muted ms-2">' + t('up.fetchOsNote.html') + '</span>';
            } else {
                h += '<div class="alert alert-info py-2 mb-0">' + updEsc(r.updatesNote) + '</div>';
            }
            el.innerHTML = h;
        }

        async function osSearch() {
            if (!updConfirm(t('up.fetchNote'), t('up.wFetch'))) return;
            const pre = document.getElementById('os-log');
            pre.style.display = 'block';
            pre.textContent = t('up.fetchRunning');
            const r = await updApi('os_fetch', { confirm: 'CERCA AGGIORNAMENTI' });
            if (!r.success) { pre.textContent = r.error || t('common.errorShort'); return; }
            // Segue il lavoro con il polling: su un sistema indietro di mesi il download dura
            // minuti, e una richiesta HTTP tenuta aperta cosi' a lungo la chiude il browser.
            planPoll(r.jobId, document.getElementById('os-body'), pre);
        }

        // ---------- eliminazione di un ambiente di avvio ----------
        async function beDelete(entryName) {
            if (!updConfirm(t('up.confirmBeDelete', { name: entryName }), t('up.wDelete'))) return;
            const el = document.getElementById('up-body');
            const r = await updApi('be_destroy', { confirm: 'DELETE', name: entryName });
            const box = document.createElement('div');
            box.className = 'alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 mt-2';
            box.textContent = r.note || r.error || t('shu.unknownResult');
            el.appendChild(box);
            if (r.success) upCheck();
        }

        // ---------- proseguimento del salto, che sopravvive ai riavvii ----------
        async function jumpState() {
            const el = document.getElementById('up-body'), pre = document.getElementById('up-log');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.readingWhere')) + '';
            const r = await updApi('jump_state');
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            let h = '<div class="table-responsive"><table class="table table-sm mb-2"><tbody>'
                  + '<tr class="upd-cell"><td style="width:14rem"><strong>' + escHtml(t('up.kernelInstalled')) + '</strong></td><td><code>'
                  + updEsc(r.installedKernel) + '</code></td></tr>'
                  + '<tr class="upd-cell"><td><strong>' + escHtml(t('up.kernelRunning')) + '</strong></td><td><code>'
                  + updEsc(r.runningKernel) + '</code>'
                  + (r.restartNeeded ? ' <span class="badge upd-badge-warn ms-2">' + escHtml(t('up.needReboot')) + '</span>'
                                         : ' <span class="badge upd-badge-ok ms-2">' + escHtml(t('up.kernelMatch')) + '</span>') + '</td></tr>'
                  + '<tr class="upd-cell"><td><strong>Userland</strong></td><td><code>' + updEsc(r.userland) + '</code></td></tr>'
                  + '</tbody></table></div>';
            if ((r.steps || []).length) {
                h += '<h6 class="mt-2 mb-1">' + escHtml(t('up.alreadyDone')) + '</h6>'
                   + '<div class="table-responsive"><table class="table table-sm mb-2"><thead><tr>'
                   + '<th scope="col">' + escHtml(t('up.colRound')) + '</th><th scope="col">' + escHtml(t('up.colResult')) + '</th><th scope="col">' + escHtml(t('up.colAsked')) + '</th><th scope="col">' + escHtml(t('up.colUserlandAfter')) + '</th>'
                   + '</tr></thead><tbody>';
                (r.steps || []).forEach(p => {
                    h += '<tr class="upd-cell"><td>' + updEsc(p.round) + '</td><td>'
                       + (p.code === 0 ? 'ok' : escHtml(t('up.code', { code: p.code }))) + '</td><td>'
                       + updEsc(p.asks) + '</td><td><code>' + updEsc(p.userland) + '</code></td></tr>';
                });
                h += '</tbody></table></div>';
            }
            if (r.restartNeeded) {
                h += '<div class="alert alert-warning py-2">' + t('up.rebootFirst.html') + '</div>'
                   + '<button class="btn btn-danger" onclick="rebPrev()"><i class="fas fa-rotate-right me-1" aria-hidden="true"></i>' + escHtml(t('up.goReboot')) + '</button>';
            } else if (r.phase === 'finished') {
                h += '<div class="alert alert-success py-2 mb-0">' + escHtml(t('up.jumpDone')) + '</div>';
            } else {
                h += '<div class="alert alert-info py-2">' + t('up.jumpInfo.html') + '</div>'
                   + '<button class="btn btn-warning" onclick="jumpGo()"><i class="fas fa-forward me-1" aria-hidden="true"></i>' + escHtml(t('up.continue')) + '</button>';
            }
            el.innerHTML = h;
            pre.style.display = 'none';
        }

        async function jumpGo() {
            if (!updConfirm('', t('up.wContinue'))) return;
            const el = document.getElementById('up-body'), pre = document.getElementById('up-log');
            const r = await updApi('jump_continue', { confirm: 'PROSEGUI', target: upTarget() });
            if (!r.success) { alert(r.error || t('common.failed')); return; }
            el.innerHTML = '<span class="text-info"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.runningKeepOpen')) + '</span>';
            pre.style.display = 'block';
            planPoll(r.jobId, el, pre);
        }

        // ---------- passaggio di release ----------
        function upTarget() { return (document.getElementById('os-target').value || '').trim(); }

        // L'elenco lo decide il pannello, non la tastiera: un campo libero lasciava scrivere
        // 16.0 (salto maggiore), 15.9 (inesistente) o 14.4 (indietro).
        async function upTargets() {
            const sel = document.getElementById('os-target');
            if (sel.options.length > 1) return true;
            const r = await updApi('os_upgrade_targets');
            if (!r.success) {
                document.getElementById('up-body').innerHTML =
                    '<span class="text-danger">' + updEsc(r.error) + '</span>';
                return false;
            }
            sel.innerHTML = '';
            (r.versions || []).forEach(v => {
                const o = document.createElement('option');
                o.value = v.version;
                o.textContent = t('up.supportedUntil', { version: v.version, date: v.endOfSupport });
                sel.appendChild(o);
            });
            if (!(r.versions || []).length) {
                const o = document.createElement('option');
                o.value = ''; o.textContent = t('up.noneAvailable');
                sel.appendChild(o);
                document.getElementById('up-body').innerHTML =
                    '<div class="alert alert-info py-2 mb-0">' + updEsc(r.note) + '</div>';
                return false;
            }
            document.getElementById('up-body').innerHTML =
                '<div class="alert alert-secondary py-2 small mb-0">' + escHtml(t('up.youAreOn', { version: r.current })) + ' '
              + updEsc(r.note) + '<br>' + escHtml(t('up.sourceIs', { source: r.source })) + '</div>';
            return true;
        }

        async function upPre() {
            const el = document.getElementById('up-body');
            if (!await upTargets()) return;
            if (!upTarget()) { el.innerHTML = '<span class="text-warning">' + escHtml(t('up.pickTarget')) + '</span>'; return; }
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.preflightRunning')) + '';
            const r = await updApi('os_upgrade_preflight', { target: upTarget() });
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            let h = '<div class="table-responsive"><table class="table table-sm align-middle mb-2"><thead><tr>'
                  + '<th scope="col" style="width:8rem">' + escHtml(t('up.colResult')) + '</th><th scope="col" style="width:16rem">' + escHtml(t('up.colCheck')) + '</th><th scope="col">' + escHtml(t('up.colDetail')) + '</th></tr></thead><tbody>';
            (r.checks || []).forEach(c => {
                h += '<tr class="upd-cell"><td>' + updBadge(c.level === 'block' ? 'wait' : c.level) + '</td>'
                   + '<td><strong>' + updEsc(c.label) + '</strong></td><td>' + updEsc(c.detail) + '</td></tr>';
            });
            h += '</tbody></table></div>';
            if (r.blocked) {
                h += '<div class="alert alert-danger py-2 mb-0"><strong>' + escHtml(t('up.cannotStart')) + '</strong> ' + escHtml(t('up.fixRedRows')) + '</div>';
            } else {
                h += '<div class="alert alert-warning py-2">' + t('up.prepInfo.html') + '</div>'
                   + '<button class="btn btn-warning me-2" onclick="upPrep()"><i class="fas fa-shield-halved me-1" aria-hidden="true"></i>' + escHtml(t('up.prepare')) + '</button>'
                   + '<button class="btn btn-outline-secondary" onclick="upInstr()"><i class="fas fa-list-ol me-1" aria-hidden="true"></i>' + escHtml(t('up.showCommands')) + '</button>';
            }
            el.innerHTML = h;
        }

        async function upPrep() {
            if (!updConfirm('', t('up.wPrepare'))) return;
            const el = document.getElementById('up-body'), pre = document.getElementById('up-log');
            const r = await updApi('os_upgrade_prepare', { confirm: 'PREPARA AGGIORNAMENTO', target: upTarget() });
            if (!r.success) { alert(r.error || t('common.failed')); return; }
            el.innerHTML = '<span class="text-info"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.preparingKeepOpen')) + '</span>';
            pre.style.display = 'block';
            planPoll(r.jobId, el, pre);
        }

        async function upInstr() {
            const pre = document.getElementById('up-log');
            pre.style.display = 'block';
            pre.textContent = t('up.genCommands');
            const r = await updApi('os_upgrade_instructions', { target: upTarget() });
            if (!r.success) { pre.textContent = r.error || t('common.errorShort'); return; }
            let textValue = t('up.jumpTitle', { version: r.target }) + '\\n'
                  + t('up.sourceIs', { source: r.source }) + '\\n\\n';
            (r.steps || []).forEach(p => {
                textValue += p.n + '. ' + p.title + '\\n     ' + p.cmd + '\\n     ' + p.note + '\\n\\n';
            });
            textValue += t('up.wayBack') + '\\n     ' + r.returnInfo + '\\n';
            pre.textContent = textValue;
        }

        async function upCheck() {
            const el = document.getElementById('up-body');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.comparingInventory')) + '';
            const r = await updApi('os_upgrade_verify');
            if (!r.success) { el.innerHTML = '<div class="alert alert-warning py-2 mb-0">' + updEsc(r.error) + '</div>'; return; }
            let h = '<div class="table-responsive"><table class="table table-sm align-middle mb-2"><thead><tr>'
                  + '<th scope="col" style="width:8rem">' + escHtml(t('up.colResult')) + '</th><th scope="col" style="width:16rem">' + escHtml(t('up.colCheck')) + '</th><th scope="col">' + escHtml(t('up.colDetail')) + '</th></tr></thead><tbody>';
            (r.checks || []).forEach(c => {
                h += '<tr class="upd-cell"><td>' + updBadge(c.level === 'block' ? 'wait' : c.level) + '</td>'
                   + '<td><strong>' + updEsc(c.label) + '</strong></td><td>' + updEsc(c.detail) + '</td></tr>';
            });
            h += '</tbody></table></div>'
               + (r.allGood
                  ? '<div class="alert alert-success py-2 mb-0">' + escHtml(t('up.allStillThere')) + '</div>'
                  : '<div class="alert alert-danger py-2 mb-0">' + escHtml(t('up.somethingOff')) + '</div>');

            // Gli ambienti di avvio meritano una tabella loro: "bectl list" e' illeggibile
            // per chi non sa gia' cosa sta guardando.
            const be = r.environments;
            if (be && be.success) {
                h += '<h6 class="mt-4 mb-1">' + escHtml(t('up.yourWaysBack')) + '</h6>'
                   + '<p class="small text-muted mb-2">' + updEsc(be.whatTheyAre) + '</p>'
                   + '<div class="table-responsive"><table class="table table-sm align-middle mb-2"><thead><tr>'
                   + '<th scope="col">' + escHtml(t('up.colEnv')) + '</th><th scope="col">' + escHtml(t('up.colWhatIs')) + '</th><th scope="col">' + escHtml(t('set.colState')) + '</th>'
                   + '<th scope="col" class="text-end">' + escHtml(t('up.colSpace')) + '</th><th scope="col">' + escHtml(t('adm.created')) + '</th></tr></thead><tbody>';
                (be.environments || []).forEach(x => {
                    const badge = x.inUse
                        ? '<span class="badge upd-badge-ok">' + escHtml(t('up.inUseNow')) + '</span>'
                        : (x.atRestart
                           ? '<span class="badge upd-badge-warn">' + escHtml(t('up.atReboot')) + '</span>'
                           : '<span class="badge upd-badge-info">' + escHtml(t('up.spare')) + '</span>');
                    h += '<tr class="upd-cell"><td><code>' + updEsc(x.name) + '</code><br>'
                       + '<span class="small text-muted">' + updEsc(x.origin) + '</span></td>'
                       + '<td class="small">' + updEsc(x.explanation) + '</td>'
                       + '<td>' + badge + '<br><span class="small text-muted">' + updEsc(x.why) + '</span></td>'
                       + '<td class="text-end">' + updEsc(x.space) + '</td>'
                       + '<td class="small">' + updEsc(x.created)
                       + (x.deletable
                          ? '<br><button class="btn btn-sm btn-outline-danger mt-1" data-name="' + escHtml(x.name) + '" onclick="beDelete(this.dataset.name)">'
                            + '<i class="fas fa-trash me-1" aria-hidden="true"></i>' + escHtml(t('common.delete')) + '</button>'
                          : '')
                       + '</td></tr>';
                });
                h += '</tbody></table></div>'
                   + '<div class="alert alert-secondary py-2 small mb-0"><strong>' + escHtml(t('up.toGoBack')) + '</strong> '
                   + updEsc(be.howToGoBack) + '<br><strong>' + escHtml(t('up.whenDelete')) + '</strong> ' + updEsc(be.whenToDelete)
                   + '</div>';
            }
            el.innerHTML = h;
        }
        """
        + """

        // ---------- rapporto del sistema ----------
        async function repGen() {
            const st = document.getElementById('rep-stato'), pre = document.getElementById('rep-testo');
            st.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.collecting')) + '';
            const r = await updApi('system_report');
            if (!r.success && !r.partial) { st.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            pre.style.display = 'block';
            pre.textContent = r.text || r.partial;
            document.getElementById('rep-copy').style.display = '';
            st.innerHTML = r.success
                ? '<span class="text-success"><i class="fas fa-check me-1" aria-hidden="true"></i>' + escHtml(t('up.reportReady', { n: (r.text || '').length })) + '</span>'
                : '<span class="text-warning">' + escHtml(t('up.reportCut', { error: r.error })) + '</span>';
        }

        async function repCopy() {
            const textValue = document.getElementById('rep-testo').textContent;
            try {
                await navigator.clipboard.writeText(textValue);
                document.getElementById('rep-stato').innerHTML = '<span class="text-success"><i class="fas fa-check me-1" aria-hidden="true"></i>' + escHtml(t('fw.copied')) + '</span>';
            } catch (e) {
                // Senza HTTPS o senza permesso la clipboard non c&#39;e&#39;: si seleziona a mano.
                const el = document.getElementById('rep-testo');
                const sel = window.getSelection(); const rg = document.createRange();
                rg.selectNodeContents(el); sel.removeAllRanges(); sel.addRange(rg);
                document.getElementById('rep-stato').innerHTML = '<span class="text-warning">' + escHtml(t('up.clipboardBlocked')) + '</span>';
            }
        }
        """ + getUpdatesScript1b();
    }

    private static String getUpdatesScript1b() {
        return """
        // L'esito arriva come codice del server; qui il nome nella lingua della pagina.
        function updOutcome(v) {
            return ({ coerente: t('up.eConsistent'), DIVERGE: t('up.eDiverges'), MISTO: t('up.eMixed'), assente: t('up.eMissing'),
                      'port installato accanto al sistema base': t('up.ePortBeside') })[v] || v;
        }

        async function defCheck() {
            const el = document.getElementById('def-body');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.comparing')) + '';
            const r = await updApi('defaults_check');
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            const rm = r.branch || {};
            let h = '';
            if (rm.branch) {
                h += '<div class="alert alert-' + (rm.branch === 'quarterly' ? 'warning' : rm.branch === 'latest' ? 'info' : 'secondary')
                   + ' py-2"><strong>' + escHtml(t('up.branchIs', { branch: rm.branch })) + '</strong>'
                   + (rm.url ? ' &mdash; <code>' + updEsc(rm.url) + '</code>' : '')
                   + '<br><span class="small">' + updEsc(rm.explanation) + '</span>'
                   + '<br><span class="small text-muted">' + updEsc(rm.where) + '</span></div>';
            }
            h += '<div class="table-responsive"><table class="table table-sm align-middle mb-2"><thead><tr>'
                  + '<th scope="col">' + escHtml(t('up.colComponent')) + '</th><th scope="col">' + escHtml(t('up.colFbsdDefault')) + '</th><th scope="col">' + escHtml(t('up.colInstalled')) + '</th><th scope="col">' + escHtml(t('up.colResult')) + '</th></tr></thead><tbody>';
            (r.lines || []).forEach(x => {
                const cls = x.outcome === 'consistent' ? 'upd-badge-ok'
                          : (x.outcome === 'DIVERGE' ? 'upd-badge-stop' : 'upd-badge-warn');
                const outside = x.outsideDefault
                    ? '<br><span class="small text-danger">' + escHtml(t('up.outsideDefault')) + ' <code>'
                      + updEsc(x.outsideDefault) + '</code></span>' : '';
                let dependentsHtml = '';
                (x.dependents || []).forEach(d => {
                    const q = d.requiredBy || [];
                    // "si puo' togliere" era una conclusione, non una misura: %rn dice solo chi lo
                    // DICHIARA. Qui si dice esattamente questo, e per il port openssl si offre la
                    // misura vera, che guarda cosa i processi vivi hanno davvero aperto.
                    dependentsHtml += '<br><span class="small ' + (q.length ? 'text-muted' : 'text-muted') + '">'
                         + '<code>' + updEsc(d.pkgName) + '</code> '
                         + (q.length
                            ? escHtml(t('up.declaredBy', { list: q.join(', ') }))
                            : escHtml(t('up.declaredByNone')))
                         + '</span>';
                    if (d.pkgName === 'openssl') {
                        dependentsHtml += '<br><button class="btn btn-sm btn-outline-primary mt-1" onclick="sslUsage()">'
                             + '<i class="fas fa-magnifying-glass me-1" aria-hidden="true"></i>' + escHtml(t('up.whoUses')) + '</button>';
                    }
                });
                h += '<tr class="upd-cell"><td><strong>' + updEsc(x.component) + '</strong><br>'
                   + '<span class="small text-muted">' + updEsc(x.why) + '</span></td>'
                   + '<td><code>' + updEsc(x.defaultValue) + '</code></td>'
                   + '<td><code>' + updEsc(x.installed || '-') + '</code></td>'
                   + '<td><span class="badge ' + cls + '">' + escHtml(updOutcome(x.outcome)) + '</span>' + outside + dependentsHtml + '</td></tr>';
            });
            h += '</tbody></table></div>'
               + '<div id="ssl-uso" class="mb-2"></div>'
               + '<div class="small text-muted"><strong>' + escHtml(t('up.source')) + '</strong> ' + updEsc(r.source) + '<br>'
               + '<i class="fas fa-triangle-exclamation me-1" aria-hidden="true"></i>' + updEsc(r.caveat) + '</div>';
            el.innerHTML = h;
        }

        // ---------- chi usa davvero il port openssl ----------
        async function sslUsage() {
            const el = document.getElementById('ssl-uso');
            el.innerHTML = '<div class="alert alert-secondary py-2 mb-0"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>'
                         + escHtml(t('up.lookingProcs')) + '</div>';
            const r = await updApi('ssl_usage');
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            const cls = r.verdict === 'NESSUNO LO USA' ? 'success'
                      : (r.verdict === 'IN USO ADESSO' || r.verdict === 'RICHIESTO') ? 'danger' : 'warning';
            // "IL COMANDO E' SUO" e "NON DETERMINABILE" restano gialli: non sono un divieto,
            // ma nemmeno un via libera.
            let h = '<div class="alert alert-' + cls + ' py-2 mb-2">'
                  + '<strong>' + updEsc(updVerdict(r.verdict)) + '</strong> &mdash; ' + updEsc(r.explanation) + '</div>'
                  + '<div class="alert alert-info py-2 small mb-2">' + updEsc(r.note) + '</div>'
                  + (r.whyItIsHere
                     ? '<div class="alert alert-secondary py-2 small mb-2"><strong>' + escHtml(t('up.whyHere')) + '</strong> '
                       + updEsc(r.whyItIsHere) + '</div>' : '');
            // Le librerie sono meta' della domanda. L'altra meta' e' il comando: un "openssl x509"
            // dura millisecondi e procstat non lo coglie mai, ma gira lo stesso.
            const bn = r.binaries || [];
            if (bn.length || r.commandInPath) {
                h += '<h6 class="mt-2 mb-1">' + t('up.opensslCommand.html') + '</h6>'
                   + '<div class="table-responsive"><table class="table table-sm mb-2"><thead><tr>'
                   + '<th scope="col">' + escHtml(t('up.colExecutable')) + '</th><th scope="col">' + escHtml(t('up.colVersion')) + '</th><th scope="col">' + escHtml(t('up.colPackage')) + '</th><th scope="col">' + escHtml(t('up.colResult')) + '</th></tr></thead><tbody>';
                bn.forEach(b => {
                    const wins = b.path === r.commandInPath;
                    h += '<tr class="upd-cell"><td><code>' + updEsc(b.path) + '</code></td>'
                       + '<td class="small">' + updEsc(b.version) + '</td>'
                       + '<td class="small">' + updEsc(b.pkgName || t('up.baseSystem')) + '</td>'
                       + '<td>' + (wins
                          ? '<span class="badge ' + (b.delPort ? 'upd-badge-warn' : 'upd-badge-ok') + '">'
                            + escHtml(t('up.winsPath')) + '</span>'
                          : '<span class="badge upd-badge-info">' + escHtml(t('up.presentNotChosen')) + '</span>') + '</td></tr>';
                });
                h += '</tbody></table></div>'
                   + '<div class="small text-muted mb-3">' + updEsc(r.whoInvokesIt) + '</div>';
            }
            if (r.installed) {
                h += '<div class="table-responsive"><table class="table table-sm mb-2"><tbody>'
                   + '<tr><td class="small">' + escHtml(t('up.portVersion')) + '</td><td><code>'
                   + updEsc(r.version) + '</code></td></tr>'
                   + '<tr><td class="small">' + escHtml(t('up.portLibs')) + '</td><td><code>'
                   + updEsc((r.portSoname || []).join(' ') || '-') + '</code></td></tr>'
                   + '<tr><td class="small">' + escHtml(t('up.baseLibs')) + '</td><td><code>'
                   + updEsc((r.baseSoname || []).join(' ') || '-') + '</code></td></tr>'
                   + '<tr><td class="small">' + escHtml(t('up.sameNames')) + '</td><td>'
                   + (r.ambiguous
                      ? '<span class="badge upd-badge-warn">' + escHtml(t('up.yesList', { list: (r.sharedSoname || []).join(' ') })) + '</span>'
                        + '<br><span class="small text-muted">' + escHtml(t('up.ambiguous')) + '</span>'
                      : '<span class="badge upd-badge-ok">' + escHtml(t('acf.no')) + '</span>') + '</td></tr>'
                   + '<tr><td class="small">' + escHtml(t('up.procsTls')) + '</td><td>'
                   + '<strong>' + updEsc(r.processesWithTls) + '</strong>'
                   + '<br><span class="small text-muted">' + updEsc(r.howMeasured) + '</span></td></tr>'
                   + '</tbody></table></div>';
                const pr = r.processes || [];
                if (pr.length) {
                    h += '<div class="table-responsive"><table class="table table-sm mb-2"><thead><tr>'
                       + '<th scope="col">PID</th><th scope="col">' + escHtml(t('up.colProcess')) + '</th><th scope="col">' + escHtml(t('up.colWhichOpenssl')) + '</th></tr></thead><tbody>';
                    pr.forEach(x => {
                        h += '<tr class="upd-cell"><td><code>' + updEsc(x.pid) + '</code></td>'
                           + '<td>' + updEsc(x.command) + '</td><td class="small">'
                           + (x.libraries || []).map(l => '<code>' + updEsc(l) + '</code>').join('<br>')
                           + (x.usesThePort
                              ? '<br><span class="badge upd-badge-stop">' + escHtml(t('up.usesPort')) + '</span>'
                              : '<br><span class="badge upd-badge-ok">' + escHtml(t('up.baseSystem')) + '</span>')
                           + '</td></tr>';
                    });
                    h += '</tbody></table></div>';
                }
            }
            if (r.panel && r.panel.success) {
                h += '<h6 class="mt-2 mb-1">' + escHtml(t('up.panelUses')) + '</h6>'
                   + rmBox(r.panel);
            }
            h += '<div class="alert alert-secondary py-2 small mb-0 mt-2"><strong>' + escHtml(t('up.ifRemoved')) + '</strong> '
               + updEsc(r.howToRemove) + '</div>';
            el.innerHTML = h;
        }

        // ---------- schede di procedura: chiuse finche' non servono ----------
        // Le schede di DIAGNOSTICA restano sempre aperte: si leggono a colpo d'occhio.
        // Le PROCEDURE no: hanno finito il loro lavoro e tornano utili solo quando ci sara'
        // una nuova release, una nuova Roundcube, una nuova JVM. Tenerle spalancate significa
        // scorrere ogni volta attraverso cose gia' fatte per arrivare a quelle da leggere.
        const PROCEDURE = ['proc-release', 'proc-python', 'proc-jvm',
                           'proc-roundcube', 'proc-mysql', 'proc-protetto'];

        function procOpen(id, forced) {
            const c = document.getElementById(id), tog = document.getElementById(id + '-tog');
            if (!c) return;
            const closed = c.style.display === 'none';
            const open = forced === undefined ? closed : forced;
            c.style.display = open ? '' : 'none';
            if (tog) { tog.innerHTML = '<i class="fas fa-chevron-' + (open ? 'up' : 'down') + '" aria-hidden="true"></i>'; tog.setAttribute('aria-expanded', String(open)); }
            try { localStorage.setItem('mp-' + id, open ? 'open' : 'closed'); } catch (e) { }
        }

        function procInit() {
            PROCEDURE.forEach(id => {
                const c = document.getElementById(id);
                if (!c) return;
                let wanted = null;
                try { wanted = localStorage.getItem('mp-' + id); } catch (e) { }
                // Chiuse per impostazione predefinita: si aprono se le hai aperte tu.
                // 'aperta' e' come lo salvava la pagina fino al 24/10/2026: chi aveva lasciato una
                // scheda aperta la ritrova aperta.
                procOpen(id, wanted === 'open' || wanted === 'aperta');
                // E si aprono DA SOLE quando hanno qualcosa da dire: premere un pulsante
                // dell'intestazione scrive nel corpo, e un corpo nascosto non si vedrebbe.
                try {
                    new MutationObserver(() => {
                        if (c.style.display === 'none') procOpen(id, true);
                    }).observe(c, { childList: true, subtree: true, characterData: true });
                } catch (e) { }
            });
        }

        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', procInit);
        } else {
            procInit();
        }

        // ---------- il tempo massimo di analisi: e' mai stato raggiunto? ----------
        async function rsTimeout() {
            const el = document.getElementById('rs-timeout');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.readingRspamdLog')) + '';
            const r = await updApi('rspamd_timeout');
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            const cls = r.verdict === 'NESSUNA ANALISI INTERROTTA' ? 'success'
                      : (r.verdict === 'CI SONO ANALISI INTERROTTE' ? 'danger'
                      : (r.verdict === "NESSUNA TRACCIA, MA IL LOG E' CORTO" ? 'info' : 'secondary'));
            let h = '<div class="alert alert-' + cls + ' py-2 small mb-2"><strong>' + updEsc(updVerdict(r.verdict))
                  + '</strong> &mdash; ' + updEsc(r.explanation) + '</div>';
            if (r.warns) {
                h += '<div class="small text-muted mb-1">task_timeout <code>' + updEsc(r.taskTimeout)
                   + '</code> &middot; ' + escHtml(t('up.cacheMax')) + ' <code>' + updEsc(r.theoreticalMax) + '</code></div>';
            }
            if (r.logLines2 !== undefined) {
                h += '<div class="small text-muted mb-1">' + escHtml(t('up.sample', { n: r.logLines2 }))
                   + (r.since ? ' ' + escHtml(t('up.fromTo', { from: r.since, to: r.until })) : '')
                   + ' &middot; ' + escHtml(t('up.olderRotations', { n: r.rotations || 0 }))
                   + ((r.compressedRotations || 0) > 0
                      ? ' (' + escHtml(t('up.compressedRead', { n: r.compressedRotations })) + ')' : '') + '</div>';
            }
            const sy = r.symbols || [];
            if (sy.length) {
                h += '<div class="small mb-1">' + escHtml(t('up.symbolLimits')) + '</div>'
                   + '<div class="mb-2">' + sy.map(x => '<span class="badge upd-badge-info me-1">'
                     + updEsc(x.name) + ' ' + updEsc(x.seconds) + 's</span>').join(' ') + '</div>';
            }
            const g = r.inLog || [];
            if (g.length) {
                h += '<div class="table-responsive"><table class="table table-sm mb-2"><thead><tr>'
                   + '<th scope="col" class="text-end">' + escHtml(t('up.colTimes')) + '</th><th scope="col">' + escHtml(t('up.colLogMessage')) + '</th></tr></thead><tbody>';
                g.forEach(x => {
                    h += '<tr class="upd-cell"><td class="text-end">' + updEsc(x.times) + '</td>'
                       + '<td class="small">'
                       + '<span class="badge ' + (x.isWarning ? 'upd-badge-info' : 'upd-badge-stop') + ' me-1">'
                       + escHtml(x.isWarning ? t('up.theWarning') : t('up.scanCut')) + '</span><br>'
                       + '<code>' + updEsc(x.messageText) + '</code></td></tr>';
                });
                h += '</tbody></table></div>';
            }
            h += '<div class="alert alert-secondary py-2 small mb-1">' + updEsc(r.ifNeeded) + '</div>'
               + '<div class="small text-muted">' + updEsc(r.source) + '</div>';
            el.innerHTML = h;
        }

        // ---------- alzare il livello di compatibilita' di Postfix ----------
        async function pfRaise(levelValue, opened) {
            const noticeText = opened > 0 ? tn('up.paramsChange', opened) : t('up.paramsSame');
            if (!updConfirm(t('up.confirmLevel', { level: levelValue, note: noticeText }), t('up.wRaise'))) return;
            const el = document.getElementById('pf-outcome');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.raising')) + '';
            const r = await updApi('postfix_level', { confirm: 'ALZA', level: levelValue });
            let h = '<div class="alert alert-' + (r.success ? (r.warningVia === false ? 'warning' : 'success') : 'danger')
                  + ' py-2 small mb-1">' + updEsc(r.error || r.note || t('shu.unknownResult')) + '</div>';
            if (r.before !== undefined) {
                h += '<div class="small text-muted">compatibility_level: <code>' + updEsc(r.before)
                   + '</code> &rarr; <code>' + updEsc(r.after) + '</code>'
                   + (r.active !== undefined
                      ? ' &middot; Postfix ' + (r.active ? escHtml(t('up.running')) : '<span class="text-danger">' + escHtml(t('up.notRunning')) + '</span>')
                      : '') + '</div>';
            }
            if (r.log) h += '<pre class="upd-log mt-1">' + updEsc(r.log) + '</pre>';
            el.innerHTML = h;
            // La scheda sopra mostra ancora lo stato di PRIMA: lasciarla li' significa
            // far leggere "il livello e' indietro, 3.6" sotto un esito che dice 3.11.
            // Si rilegge tutto, e l'esito appena mostrato si riattacca in fondo.
            if (r.success) {
                const outcomeValue = h;
                await updCompat();
                const newOne = document.getElementById('pf-outcome');
                if (newOne) newOne.innerHTML = outcomeValue;
            }
        }

        // ---------- anteprima della configurazione Dovecot 2.4 ----------
        async function where24() {
            const el = document.getElementById('dove24-body');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.buildingPreview')) + '';
            const r = await updApi('dovecot24_preview');
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            let h = '<div class="alert alert-info py-2 small">' + updEsc(r.caveat) + '</div>';

            const v = r.checks || [];
            const conf = v.filter(x => x.state === 'confirmed');
            const doubtful = v.filter(x => x.state !== 'confirmed');
            h += '<h6 class="mb-1">' + escHtml(t('up.verifiedDocs')) + '</h6>'
               + '<div class="table-responsive"><table class="table table-sm mb-2"><tbody>';
            conf.forEach(x => {
                h += '<tr class="upd-cell"><td style="width:12rem"><span class="badge upd-badge-ok">' + escHtml(t('up.sConfirmed')) + '</span></td>'
                   + '<td><code class="small">' + updEsc(x.setting) + '</code><br>'
                   + '<span class="small text-muted">' + updEsc(x.note) + '</span></td></tr>';
            });
            doubtful.forEach(x => {
                h += '<tr class="upd-cell"><td><span class="badge ' + (x.state === 'criterion' ? 'upd-badge-info' : 'upd-badge-warn')
                   + '">' + escHtml(({ criterio: t('up.sCriterion'), 'da verificare': t('up.sToCheck') })[x.state] || x.state) + '</span></td>'
                   + '<td><code class="small">' + updEsc(x.setting) + '</code><br>'
                   + '<span class="small text-muted">' + updEsc(x.note) + '</span></td></tr>';
            });
            h += '</tbody></table></div>';

            h += '<h6 class="mb-1">' + escHtml(t('up.filesAsWritten')) + '</h6>';
            (r.file || []).forEach(f => {
                h += '<div class="small text-muted mt-2"><code>' + updEsc(f.path) + '</code></div>'
                   + '<pre class="upd-log mb-0">' + updEsc(f.content) + '</pre>';
            });
            el.innerHTML = h;
        }

        // ---------- ambiente del pannello ----------
        async function envCheck() {
            const el = document.getElementById('env-body');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.checkingPath')) + '';
            const r = await updApi('panel_env');
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            const cls = r.unreachable ? 'danger' : (r.absent ? 'warning' : 'success');
            let h = '<div class="alert alert-' + cls + ' py-2 small mb-2">' + updEsc(r.explanation) + '</div>'
                  + '<div class="table-responsive"><table class="table table-sm mb-2"><tbody>'
                  + '<tr><td class="small">' + escHtml(t('up.pathInherited')) + '</td>'
                  + '<td><code class="small">' + updEsc(r.inheritedPath || t('up.empty')) + '</code></td></tr>'
                  + '<tr><td class="small">' + escHtml(t('up.pathUsed')) + '</td>'
                  + '<td><code class="small">' + updEsc(r.pathUsed) + '</code>'
                  + (r.inheritedPath !== r.pathUsed
                     ? '<br><span class="small text-muted">' + escHtml(t('up.pathCompleted')) + '</span>' : '') + '</td></tr>'
                  + '</tbody></table></div>'
                  + '<div class="table-responsive"><table class="table table-sm mb-0"><thead><tr>'
                  + '<th scope="col">' + escHtml(t('up.colCommand')) + '</th><th scope="col">' + escHtml(t('up.colWhatFor')) + '</th><th scope="col">' + escHtml(t('up.colResolves')) + '</th><th scope="col">' + escHtml(t('up.colResult')) + '</th>'
                  + '</tr></thead><tbody>';
            (r.tools || []).forEach(x => {
                const b = x.state === 'reachable' ? 'upd-badge-ok'
                        : (x.state === 'non installato' ? 'upd-badge-warn' : 'upd-badge-stop');
                h += '<tr class="upd-cell"><td><code>' + updEsc(x.command) + '</code></td>'
                   + '<td class="small text-muted">' + updEsc(x.purpose) + '</td>'
                   + '<td class="small"><code>' + updEsc(x.resolved || '-') + '</code>'
                   + (!x.resolved && x.onDisk
                      ? '<br><span class="small text-danger">' + escHtml(t('up.existsIn', { dir: x.expectedIn })) + '</span>' : '')
                   + '</td>'
                   + '<td><span class="badge ' + b + '">' + escHtml(({ raggiungibile: t('up.sReachable'), 'non installato': t('up.notInstalled'),
                                                                        "C'E' MA IL PATH NON LO RAGGIUNGE": t('up.sUnreachable') })[x.state] || x.state) + '</span></td></tr>';
            });
            h += '</tbody></table></div>';
            el.innerHTML = h;
        }

        // ---------- prima di togliere un pacchetto ----------
        async function rmCandidates() {
            const el = document.getElementById('rim-body');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.lookingUndeclared')) + '';
            const r = await updApi('removal_candidates');
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            const c = r.candidates || [];
            let h = '<p class="small text-muted">' + updEsc(r.explanation) + '</p>';
            if (!c.length) {
                h += '<div class="alert alert-info py-2 mb-0">' + escHtml(t('up.noCandidates')) + '</div>';
                el.innerHTML = h; return;
            }
            if (r.caution) {
                h += '<div class="alert alert-warning py-2 small"><i class="fas fa-triangle-exclamation me-1" aria-hidden="true"></i>'
                   + updEsc(r.caution) + '</div>';
            }
            h += '<div class="table-responsive"><table class="table table-sm align-middle mb-0"><thead><tr>'
               + '<th scope="col">' + escHtml(t('up.colPackage')) + '</th><th scope="col">' + escHtml(t('up.colVersion')) + '</th><th scope="col">' + escHtml(t('up.colRole')) + '</th><th scope="col">' + escHtml(t('up.colLocked')) + '</th>'
               + '<th scope="col">' + escHtml(t('up.colPanelUses')) + '</th></tr></thead><tbody>';
            c.forEach((x, i) => {
                h += '<tr class="upd-cell"><td><code>' + updEsc(x.name) + '</code></td>'
                   + '<td class="small">' + updEsc(x.version) + '</td>'
                   + '<td class="small">' + (x.essential
                      ? '<span class="badge upd-badge-stop">' + escHtml(t('up.doNotTouch')) + '</span><br>' + updEsc(x.warning)
                      : (x.role
                         ? '<span class="badge upd-badge-warn">' + updEsc(x.role) + '</span>'
                         : '<span class="text-muted">' + escHtml(t('up.noneKnown')) + '</span>')) + '</td>'
                   + '<td>' + (x.isProtected
                      ? '<span class="badge upd-badge-ok">' + escHtml(t('dns.yes')) + '</span>'
                      : '<span class="badge upd-badge-warn">' + escHtml(t('acf.no')) + '</span>') + '</td>'
                   + '<td><button class="btn btn-sm btn-outline-primary" data-name="' + escHtml(x.name) + '" data-i="' + i + '" onclick="rmUse(this.dataset.name, Number(this.dataset.i))">'
                   + '<i class="fas fa-magnifying-glass me-1" aria-hidden="true"></i>' + escHtml(t('up.check')) + '</button>'
                   + '<div id="rim-outcome-' + i + '" class="mt-1"></div></td></tr>';
            });
            h += '</tbody></table></div>';
            el.innerHTML = h;
        }

        // Il riquadro che spiega l'esito, riusato sia qui sia dentro la scheda di openssl.
        function rmBox(r) {
            const cls = r.verdict === 'IL PANNELLO NON LO USA' ? 'success'
                      : r.verdict === "LO USA, E NON C'E' RICAMBIO" ? 'danger'
                      : r.verdict === 'LO USA' ? 'warning'
                      : r.verdict === "NON NE USA I COMANDI, MA E' UNA LIBRERIA" ? 'info'
                      : r.verdict === 'LI NOMINA, MA NON SONO I SUOI' ? 'success' : 'secondary';
            let h = '<div class="alert alert-' + cls + ' py-2 mb-1 small"><strong>' + updEsc(updVerdict(r.verdict))
                  + '</strong> &mdash; ' + updEsc(r.explanation) + '</div>';
            const lb = r.providesLibraries || [];
            if (lb.length) {
                h += '<div class="small text-muted mb-1">' + escHtml(t('up.sharedLibs')) + ' '
                   + lb.map(x => '<code>' + updEsc(x) + '</code>').join(' ') + '</div>';
            }
            const u = r.commandsUsed || [];
            if (u.length) {
                h += '<div class="table-responsive"><table class="table table-sm mb-1"><thead><tr>'
                   + '<th scope="col">' + escHtml(t('up.colCommand')) + '</th><th scope="col">' + escHtml(t('up.colNamed')) + '</th><th scope="col">' + escHtml(t('up.colIfRemoved')) + '</th></tr></thead><tbody>';
                u.forEach(x => {
                    h += '<tr class="upd-cell"><td><code>' + updEsc(x.path) + '</code></td>'
                       + '<td class="small">' + escHtml(t('up.timesWord', { n: x.occurrences }))
                       + (x.withArguments ? '<br>' + escHtml(t('up.withArgs', { n: x.withArguments })) : '')
                       + '</td>'
                       + '<td class="small">'
                       + (!x.isItsOwn
                          ? '<span class="badge upd-badge-ok">' + escHtml(t('up.noEffect')) + '</span>'
                          : (x.wouldStay ? '<span class="badge upd-badge-warn">' + escHtml(t('up.changesBinary')) + '</span>'
                                          : '<span class="badge upd-badge-stop">' + escHtml(t('up.disappears')) + '</span>'))
                       + '<br>' + updEsc(x.effect || '')
                       + (x.inUseNow ? '<br>' + escHtml(t('up.inUseNowColon')) + ' <code>' + updEsc(x.inUseNow) + '</code>' : '')
                       + '</td></tr>';
                });
                h += '</tbody></table></div>';
            }
            // Il pulsante compare SOLO dove la misura dice che si puo': non si offre un'azione
            // che il controllo appena fatto rifiuterebbe.
            if (r.pkgName && (r.verdict === 'IL PANNELLO NON LO USA'
                             || r.verdict === 'LI NOMINA, MA NON SONO I SUOI')) {
                // L'analisi approfondita viene PRIMA del pulsante che toglie, ed e' l'unica che
                // guarda gli script su disco: quelli girano dopo, e il jar non li contiene.
                h += '<button class="btn btn-sm btn-outline-primary mb-1 me-1" data-pkg="' + escHtml(r.pkgName) + '" onclick="rmDeep(this.dataset.pkg)">'
                   + '<i class="fas fa-microscope me-1" aria-hidden="true"></i>' + escHtml(t('up.deepScan')) + '</button>'
                   + '<button class="btn btn-sm btn-outline-danger mb-1" data-pkg="' + escHtml(r.pkgName) + '" onclick="rmRemove(this.dataset.pkg)">'
                   + '<i class="fas fa-trash me-1" aria-hidden="true"></i>' + escHtml(t('up.removePkg', { pkg: r.pkgName })) + '</button>'
                   + '<div id="rim-prof-' + updEsc(r.pkgName) + '" class="mt-1"></div>'
                   + '<div id="rim-esec-' + updEsc(r.pkgName) + '" class="mt-1"></div>';
            }
            h += '<div class="small text-muted">' + t('up.scanStats.html', { bytes: updEsc(r.bytesRead), jar: updEsc(r.jar || '?'), n: updEsc(r.runnablesFound), how: updEsc(r.asListed) }) + '</div>';
            return h;
        }

        async function rmUse(entryName, i) {
            const el = document.getElementById('rim-outcome-' + i);
            el.innerHTML = '<i class="fas fa-spinner fa-spin" aria-hidden="true"></i><span class="visually-hidden">' + escHtml(t('sj.inProgress')) + '</span>';
            const r = await updApi('panel_uses', { name: entryName });
            el.innerHTML = r.success ? rmBox(r)
                                     : '<span class="text-danger small">' + updEsc(r.error) + '</span>';
        }

        // ---------- analisi approfondita: dove si nominano davvero i suoi file ----------
        async function rmDeep(entryName) {
            const el = document.getElementById('rim-prof-' + entryName);
            el.innerHTML = '<div class="alert alert-secondary py-2 small mb-0">'
                         + '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.deepScanning')) + '</div>';
            const r = await updApi('deep_scan', { name: entryName });
            if (!r.success) { el.innerHTML = '<span class="text-danger small">' + updEsc(r.error) + '</span>'; return; }
            let h = '<div class="alert alert-' + (r.blocking ? 'danger' : 'success') + ' py-2 small mb-1">'
                  + '<strong>' + updEsc(updVerdict(r.verdict)) + '</strong> &mdash; ' + updEsc(r.explanation) + '</div>'
                  + '<div class="small text-muted mb-1">' + escHtml(t('up.searchedRefs')) + ' '
                  + (r.searched || []).map(x => '<code>' + updEsc(x) + '</code>').join(' ') + '</div>';

            const ds = r.declareSoname || [];
            h += '<div class="small mb-1"><strong>' + escHtml(t('up.pkgsDeclaringLibs')) + '</strong> '
               + (ds.length
                  ? '<span class="text-danger">' + ds.map(x => updEsc(x.pkgName) + ' (' + updEsc(x.library) + ')').join(', ') + '</span>'
                  : '<span class="text-success">' + escHtml(t('up.none')) + '</span>') + '</div>';
            h += '<div class="small mb-1"><strong>' + escHtml(t('up.inRunningJar')) + '</strong> '
               + (!r.jarRead
                  ? '<span class="text-warning">' + escHtml(t('up.notRead')) + '</span>'
                  : ((r.inJar || []).length
                     ? r.inJar.map(x => (x.selfReference
                          ? '<span class="text-muted"><code>' + updEsc(x.className)
                            + '</code> (' + escHtml(t('up.selfRef')) + ')</span>'
                          : '<span class="text-danger"><code>' + updEsc(x.className) + '</code></span>')).join(', ')
                     : '<span class="text-success">' + escHtml(t('up.noAbsRef')) + '</span>')
                    + ' <span class="text-muted">(' + escHtml(t('up.classBytes', { n: r.jarBytes })) + ')</span>') + '</div>';

            h += '<div class="table-responsive"><table class="table table-sm mb-1"><thead><tr>'
               + '<th scope="col">' + escHtml(t('up.colWhere')) + '</th><th scope="col" class="text-end">' + escHtml(t('up.colTextFiles')) + '</th>'
               + '<th scope="col" class="text-end">' + escHtml(t('up.colWouldBreak')) + '</th><th scope="col" class="text-end">' + escHtml(t('up.colHold')) + '</th></tr></thead><tbody>';
            (r.places || []).forEach(x => {
                h += '<tr class="upd-cell"><td><code>' + updEsc(x.where) + '</code><br>'
                   + '<span class="small text-muted">' + updEsc(x.whatItContains) + '</span></td>'
                   + '<td class="text-end">' + updEsc(x.filesReviewed) + '</td>'
                   + '<td class="text-end">' + ((x.breakOnes || []).length
                      ? '<span class="badge upd-badge-stop">' + updEsc(x.breakOnes.length) + '</span>'
                      : '<span class="badge upd-badge-ok">0</span>') + '</td>'
                   + '<td class="text-end small text-muted">' + updEsc(x.hold) + '</td></tr>';
                (x.breakOnes || []).forEach(lineItem => {
                    h += '<tr class="upd-cell"><td colspan="4" class="small text-danger">'
                       + '<code>' + updEsc(lineItem) + '</code></td></tr>';
                });
            });
            h += '</tbody></table></div>'
               + '<div class="small text-muted">' + t('up.holdNote.html') + '<br>'
               + '<i class="fas fa-triangle-exclamation me-1" aria-hidden="true"></i>' + updEsc(r.caveat) + '</div>';
            el.innerHTML = h;
        }

        // ---------- togliere un pacchetto, dal pannello ----------
        async function rmRemove(entryName) {
            if (!updConfirm(t('up.confirmRemovePkg', { pkg: entryName }), t('up.wRemove'))) return;
            const el = document.getElementById('rim-esec-' + entryName);
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.removingChecking')) + '';
            const r = await updApi('pkg_remove', { confirm: 'REMOVE', name: entryName });
            let h = '<div class="alert alert-' + (!r.success ? 'danger' : (r.fault ? 'danger' : 'success'))
                  + ' py-2 small mb-1">' + updEsc(r.error || r.note || t('shu.unknownResult')) + '</div>';
            if (r.before !== undefined) {
                h += '<div class="small text-muted">' + escHtml(t('up.pkgCount', { before: r.before, after: r.after })) + '</div>';
            }
            const sv = r.services || [];
            if (sv.length) {
                const down = sv.filter(x => !x.active);
                h += '<div class="small ' + (down.length ? 'text-danger' : 'text-success') + '">'
                   + (down.length
                      ? escHtml(t('up.servicesDown', { list: down.map(x => x.name).join(', ') }))
                      : escHtml(tn('up.servicesUp', sv.length)))
                   + '</div>';
            }
            if (r.log) h += '<pre class="upd-log mt-1">' + updEsc(r.log) + '</pre>';
            el.innerHTML = h;
        }

        // ---------- librerie mancanti ----------
        async function libsCheck() {
            const el = document.getElementById('libs-body');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.checkingLibs')) + '';
            const r = await updApi('broken_libs');
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            const pk = r.packages || [];
            if (!pk.length) {
                el.innerHTML = '<div class="alert alert-success py-2 mb-0"><i class="fas fa-check me-1" aria-hidden="true"></i>'
                             + escHtml(t('up.libsOk')) + '</div>';
                return;
            }
            let h = '<div class="alert alert-danger py-2"><strong>' + escHtml(tn('up.libsMissing', pk.length)) + '</strong> '
                  + escHtml(t('up.libsMissingNote')) + '</div>'
                  + '<ul class="small">';
            pk.forEach(p => { h += '<li>' + t('up.requires.html', { pkg: updEsc(p.name), lib: updEsc(p.lib) }) + '</li>'; });
            h += '</ul><button class="btn btn-danger" onclick="libsRelink()">'
               + '<i class="fas fa-link me-1" aria-hidden="true"></i>' + escHtml(t('up.relink')) + '</button>';
            el.innerHTML = h;
        }

        async function libsRelink() {
            if (!updConfirm('', t('up.wRelink'))) return;
            const el = document.getElementById('libs-body');
            const pre = document.getElementById('libs-log');
            const r = await updApi('relink', { confirm: 'RICOLLEGA' });
            if (!r.success) { alert(r.error || t('common.failed')); return; }
            el.innerHTML = '<span class="text-info"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.relinking')) + '</span>';
            pre.style.display = 'block';
            planPoll(r.jobId, el, pre);
        }

        async function libsDiag() {
            const el = document.getElementById('libs-body');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.collectingDecl')) + '';
            const r = await updApi('mysql_client_diag');
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            let h = '<h6 class="small">' + escHtml(t('up.mysqlPkgs')) + '</h6><ul class="small">';
            (r.mysqlPackages || []).forEach(p => { h += '<li><code>' + updEsc(p.name) + '</code> ' + updEsc(p.version) + '</li>'; });
            h += '</ul>';
            h += '<h6 class="small mt-2">' + escHtml(t('up.clientUsers')) + '</h6>';
            (r.dependents || []).forEach(d => {
                h += '<div class="small mb-2"><code>' + updEsc(d.name) + '</code> ' + updEsc(d.version) + '<br>'
                   + '<span class="text-muted">' + escHtml(t('up.depsInstalled')) + '</span> ' + updEsc(d.installedDependencies) + '<br>'
                   + '<span class="text-muted">' + escHtml(t('up.depsRepo')) + '</span> ' + updEsc(d.repositoryDependencies) + '<br>'
                   + '<span class="text-muted">' + escHtml(t('up.libsRequired')) + '</span> ' + updEsc(d.requiredLibraries) + '</div>';
            });
            h += '<h6 class="small mt-2">' + escHtml(t('up.contestedLib')) + '</h6><div class="small">'
               + '<span class="text-muted">' + escHtml(t('up.belongsTo')) + '</span> ' + updEsc(r.provideLib || t('fw.none')) + '<br>'
               + '<span class="text-muted">' + escHtml(t('up.fileColon')) + '</span> <code>' + updEsc(r.fileLib || t('up.absent')) + '</code></div>';
            if (r.hasConflicts) {
                h += '<h6 class="small mt-2">' + escHtml(t('up.fileIntegrity')) + '</h6>'
                   + '<pre class="upd-log mt-1">' + updEsc(r.hasConflicts) + '</pre>';
            }
            // Se ci sono due client e uno non serve a nessuno, si puo' ripulire.
            const cl = (r.mysqlPackages || []).filter(p => /-client$/.test(p.name)).map(p => p.name);
            if (cl.length > 1) {
                const correct = cl.find(n => (r.dependents || []).some(d =>
                    (d.repositoryDependencies || '').indexOf(n) >= 0));
                const foreign = cl.find(n => n !== correct);
                if (correct && foreign) {
                    h += '<div class="alert alert-warning py-2 mt-2 small">'
                       + t('up.twoClients.html', { good: updEsc(correct), bad: updEsc(foreign) }) + '</div>'
                       + '<button class="btn btn-warning" data-bad="' + escHtml(foreign) + '" data-good="' + escHtml(correct) + '" onclick="cleanClient(this.dataset.bad, this.dataset.good)">'
                       + '<i class="fas fa-broom me-1" aria-hidden="true"></i>' + escHtml(t('up.cleanClient', { bad: foreign, good: correct })) + '</button>';
                }
            }
            el.innerHTML = h;
        }

        // ---------- piano di manutenzione ----------
        function planBadge(stateValue) {
            if (stateValue === 'done')   return '<span class="badge upd-badge-ok"><i class="fas fa-check me-1" aria-hidden="true"></i>' + escHtml(t('up.pDone')) + '</span>';
            if (stateValue === 'manual') return '<span class="badge upd-badge-warn">' + escHtml(t('up.pManual')) + '</span>';
            return '<span class="badge upd-badge-stop">' + escHtml(t('up.pTodo')) + '</span>';
        }

        let planActions = [];

        async function planLoad() {
            planActions = [];
            const el = document.getElementById('plan-body');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.readingSystem')) + '';
            const r = await updApi('plan');
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }

            let firstToDo = true;

            function lineItem(p, labelText) {
                const activeNow = p.state === 'todo' && firstToDo;
                if (p.state === 'todo') firstToDo = false;
                let h = '<div class="border rounded p-2 mb-2' + (activeNow ? ' border-primary' : '') + '">'
                      + '<div class="d-flex justify-content-between align-items-center">'
                      + '<span><strong>' + labelText + updEsc(p.title) + '</strong> ' + planBadge(p.state) + '</span>';
                if (activeNow && p.action) {
                    const idx = planActions.push(p.action) - 1;
                    h += '<button class="btn btn-sm btn-primary" onclick="planRun(' + idx + ')">'
                       + '<i class="fas fa-play me-1" aria-hidden="true"></i>' + escHtml(t('up.runStep')) + '</button>';
                } else if (p.redoAction) {
                    // Passo gia' fatto ma ripetibile: pulsante secondario, sempre disponibile,
                    // fuori dalla regola del "solo il primo" perche' non e' un passo da fare.
                    const idx = planActions.push(p.redoAction) - 1;
                    h += '<button class="btn btn-sm btn-outline-secondary" onclick="planRun(' + idx + ')" '
                       + 'title="' + escHtml(t('up.redoHint')) + '">'
                       + '<i class="fas fa-rotate me-1" aria-hidden="true"></i>' + escHtml(t('up.redo')) + '</button>';
                }
                h += '</div>'
                   + '<div class="small mt-1">' + updEsc(p.situation) + '</div>'
                   + '<div class="small text-muted mt-1">' + updEsc(p.why) + '</div>'
                   + '</div>';
                return h;
            }

            const steps = r.steps || [];
            let h = '<div class="mb-2 small">' + (r.daFare === 0
                ? '<span class="text-success"><i class="fas fa-circle-check me-1" aria-hidden="true"></i><strong>' + escHtml(t('up.nothingToDo')) + '</strong></span>'
                : '<strong>' + escHtml(tn('up.stepsToDo', r.daFare)) + '</strong> ' + escHtml(t('up.onlyFirst')))
                + '</div>';

            // I passi si presentano nell'ordine di esecuzione, ma con identita' stabili:
            // le fasi hanno una lettera fissa, i pacchetti si chiamano col proprio nome.
            // Cosi' nessuna etichetta cambia significato quando un passo viene completato.
            // Nessuna intestazione di gruppo: fasi e pacchetti si alternano nell'ordine di
            // esecuzione, e ripetere "Fasi" e "Pacchetti" a ogni cambio faceva sembrare sezioni
            // separate cio' che e' una sequenza sola. Ogni riga si presenta gia' da se': le fasi
            // con la loro lettera, i pacchetti col loro nome.
            steps.forEach(p => {
                // La lettera arriva dal backend, legata alla chiave del passo: non si ricava
                // dalla posizione, altrimenti una fase che compare farebbe scorrere le altre.
                const labelText = p.group === 'phase' ? escHtml(t('up.phase', { letter: p.letter })) + ' &mdash; ' : '';
                h += lineItem(p, labelText);
            });

            if ((r.withoutRemedy || []).length) {
                h += '<div class="alert alert-secondary py-2 small mb-0"><strong>' + escHtml(t('up.noFix')) + '</strong> '
                   + r.withoutRemedy.map(x => updEsc(x)).join(', ')
                   + '. ' + escHtml(t('up.noFixNote')) + '</div>';
            }
            el.innerHTML = h;
        }

        async function planRun(idx) {
            const actionItem = planActions[idx];
            if (!actionItem) { alert(t('up.stepStale')); return; }
            const el = document.getElementById('plan-body');
            const pre = document.getElementById('plan-log');
            let r;
            if (actionItem.type === 'packages_lock_all') {
                r = await updApi('packages_lock', { lock: true, package: '' });
                if (!r.success) { alert(r.error || t('common.failed')); return; }
                planLoad();
                return;
            }
            if (actionItem.type === 'updates_apply') {
                /* Non si parte da qui: questo aggiornamento ha un piano e una firma, e si
                   approva nella scheda che li mostra. Come per il JDK del pannello, si va
                   dove la decisione si puo' prendere guardandola. */
                const c = document.getElementById('upd-status');
                if (c) {
                    updStatus();
                    c.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
                alert(t('up.applyFromCard'));
                return;
            } else if (actionItem.type === 'package_update') {
                // L'aggiornamento di un pacchetto passa sempre dalla sua finestra: piano esatto,
                // conferma con il nome, avanzamento.
                pkUpdOpen(actionItem.package);
                return;
            } else if (actionItem.type === 'rspamd_clean_cache') {
                if (!updConfirm('', t('up.wDeleteCache'))) return;
                r = await updApi('rspamd_clean_cache', { confirm: 'ELIMINA CACHE' });
            } else if (actionItem.type === 'dovecot_config_regen') {
                if (!updConfirm('', t('up.wRegen'))) return;
                r = await updApi('dovecot_config_regen', { confirm: 'RIGENERA' });
            } else {
                alert(t('up.noAutoAction'));
                return;
            }
            if (!r.success) { alert(r.error || t('common.failed')); return; }
            el.innerHTML = '<span class="text-info"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.stepRunning')) + '</span>';
            pre.style.display = 'block';
            planPoll(r.jobId, el, pre);
        }

        async function planPoll(id, el, pre) {
            const s = await updApi('job_status', { jobId: id });
            if (s.success && s.job) {
                pre.textContent = s.job.consoleLog || '';
                pre.scrollTop = pre.scrollHeight;
                if (s.job.status === 'completed') {
                    el.innerHTML = '<span class="text-success"><i class="fas fa-check me-1" aria-hidden="true"></i>'
                                 + escHtml(t('up.stepDone', { s: s.job.elapsedSeconds })) + '</span>';
                    setTimeout(planLoad, 1500);
                    return;
                }
                if (s.job.status === 'error') {
                    el.innerHTML = '<div class="alert alert-danger py-2"><strong>' + escHtml(t('up.stepFailed')) + '</strong> '
                                 + updEsc(s.job.errorMessage) + '<br>' + escHtml(t('up.readLogFirst')) + '</div>'
                                 + '<button class="btn btn-sm btn-outline-primary" onclick="planLoad()">' + escHtml(t('up.recomputePlan')) + '</button>';
                    return;
                }
            }
            setTimeout(() => planPoll(id, el, pre), 3000);
        }
        """ + getUpdatesScript1bb();
    }

    private static String getUpdatesScript1bb() {
        return """

        // ---------- passaggio Python ----------
        // ---------- resti della vecchia famiglia Python ----------
        async function pyLeftovers() {
            const el = document.getElementById('py-pre');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.lookingLeftovers')) + '';
            const r = await updApi('python_leftovers');
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            if (r.nothing) { el.innerHTML = '<div class="alert alert-success py-2 mb-0">' + updEsc(r.note) + '</div>'; return; }
            let h = '<p class="small text-muted mb-2">' + t('up.pyLeftIntro.html') + '</p>'
                  + '<div class="table-responsive"><table class="table table-sm align-middle mb-2"><thead><tr>'
                  + '<th scope="col">' + escHtml(t('up.colPackage')) + '</th><th scope="col">' + escHtml(t('up.colVersion')) + '</th><th scope="col" class="text-end">KB</th><th scope="col">' + escHtml(t('set.colState')) + '</th></tr></thead><tbody>';
            let free = 0;
            (r.detail || []).forEach(d => {
                if (d.free) free++;
                h += '<tr class="upd-cell"><td><code>' + updEsc(d.name) + '</code></td><td>' + updEsc(d.version) + '</td>'
                   + '<td class="text-end">' + updEsc(d.kb) + '</td><td>'
                   + (d.free ? '<span class="badge upd-badge-ok">' + escHtml(t('up.canRemove')) + '</span>'
                               : '<span class="badge upd-badge-warn">' + escHtml(t('up.requiredBy', { list: (d.heldBackBy || []).join(', ') })) + '</span>')
                   + '</td></tr>';
            });
            h += '</tbody></table></div>';
            // Chi nomina il vecchio interprete fra cio' che RESTA: e' cio' che pkg non sa.
            const refEl = r.references || {};
            const prob = refEl.issues || [];
            h += '<h6 class="mt-3 mb-1">' + escHtml(t('up.whoRefsOld')) + '</h6>'
               + '<p class="small text-muted mb-2">' + t('up.refsExamined.html', { n: updEsc(refEl.reviewed || 0), gone: updEsc((refEl.harmless || []).length) }) + '</p>';
            const quoteList = refEl.quotes || [];
            if (quoteList.length) {
                h += '<div class="alert alert-secondary py-2 small mb-2">' + t('up.citations.html', { n: quoteList.length }) + ' '
                   + quoteList.map(x => '<code>' + updEsc(x.file) + '</code>').join(' ') + '</div>';
            }
            if (prob.length === 0) {
                h += '<div class="alert alert-success py-2">' + t('up.noOldRefs.html') + '</div>';
            } else {
                h += '<div class="alert alert-danger py-2"><strong>' + escHtml(tn('up.oldRefs', prob.length)) + '</strong> '
                   + escHtml(t('up.oldRefsBlock')) + '</div>'
                   + '<div class="table-responsive"><table class="table table-sm mb-2"><thead><tr>'
                   + '<th scope="col">' + escHtml(t('up.colFileLine')) + '</th><th scope="col">' + escHtml(t('up.colBelongs')) + '</th></tr></thead><tbody>';
                prob.forEach(x => { h += '<tr class="upd-cell"><td><code>' + updEsc(x.file) + '</code>'
                   + (x.line ? '<br><span class="small text-muted">' + updEsc(x.line) + '</span>' : '')
                   + '</td><td>' + updEsc(x.owner) + '</td></tr>'; });
                h += '</tbody></table></div>';
            }
            h += (free > 0 && prob.length === 0)
               ? '<button class="btn btn-warning" onclick="pyLeftoversGo()"><i class="fas fa-broom me-1" aria-hidden="true"></i>' + escHtml(tn('up.removeFree', free)) + '</button>'
               : (free === 0
                  ? '<div class="alert alert-info py-2 mb-0">' + escHtml(t('up.noneFree')) + '</div>'
                  : '');
            el.innerHTML = h;
        }
        """;
    }

    private static String getUpdatesScript2() {
        return """

        async function pyLeftoversGo() {
            if (!updConfirm('', t('up.wCleanPython'))) return;
            const el = document.getElementById('py-pre'), pre = document.getElementById('py-log');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.removing')) + '';
            const r = await updApi('python_leftovers_clean', { confirm: 'PULISCI PYTHON' });
            if (!r.success) { el.innerHTML = '<div class="alert alert-danger py-2 mb-0">' + updEsc(r.error) + '</div>'; return; }
            pre.style.display = 'block';
            pre.textContent = t('up.removedList', { list: (r.removed || []).join(', ') || t('fw.none') })
                + '\\n' + t('up.failedList', { list: (r.failed || []).join(', ') || t('fw.none') })
                + '\\n' + t('up.stillPresent', { n: r.stillPresent });
            el.innerHTML = '<div class="alert alert-' + ((r.failed || []).length ? 'warning' : 'success')
                + ' py-2 mb-0">' + escHtml(tn('up.removedN', (r.removed || []).length)) + ' ' + escHtml(t('up.pressLeftoversAgain')) + '</div>';
        }

        async function pyPre() {
            const el = document.getElementById('py-pre');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.pyChecks')) + '';
            const r = await updApi('python_preflight');
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            let h = '<div class="table-responsive"><table class="table table-sm align-middle mb-2"><thead><tr>'
                  + '<th scope="col" style="width:8rem">' + escHtml(t('up.colResult')) + '</th><th scope="col" style="width:16rem">' + escHtml(t('up.colCheck')) + '</th><th scope="col">' + escHtml(t('up.colDetail')) + '</th></tr></thead><tbody>';
            (r.checks || []).forEach(c => {
                h += '<tr class="upd-cell"><td>' + updBadge(c.level === 'block' ? 'wait' : c.level) + '</td>'
                   + '<td><strong>' + updEsc(c.label) + '</strong></td><td>' + updEsc(c.detail) + '</td></tr>';
            });
            h += '</tbody></table></div>';
            if (r.already) h += '<div class="alert alert-success py-2 mb-0">' + escHtml(t('up.nothingToMove')) + '</div>';
            else if (r.blocked) h += '<div class="alert alert-danger py-2 mb-0"><strong>' + escHtml(t('up.cannotStart')) + '</strong> ' + escHtml(t('up.fixRedRows')) + '</div>';
            else h += '<button class="btn btn-danger" onclick="pyRun()"><i class="fas fa-play me-1" aria-hidden="true"></i>' + escHtml(t('up.moveTo', { to: 'py' + r.newVersion })) + '</button>';
            el.innerHTML = h;
        }

        async function pyRun() {
            if (!updConfirm('', t('up.wMovePython'))) return;
            const el = document.getElementById('py-pre'), pre = document.getElementById('py-log');
            const r = await updApi('python_move', { confirm: 'SPOSTA PYTHON' });
            if (!r.success) { alert(r.error || t('common.failed')); return; }
            el.innerHTML = '<span class="text-info"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.runningKeepOpen')) + '</span>';
            pre.style.display = 'block';
            planPoll(r.jobId, el, pre);
        }

        // ---------- aggiornamento della JVM ----------
        async function jvPre() {
            const el = document.getElementById('jv-pre');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.jvmChecks')) + '';
            const r = await updApi('java_preflight');
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            let h = '<div class="table-responsive"><table class="table table-sm align-middle mb-2"><thead><tr>'
                  + '<th scope="col" style="width:8rem">' + escHtml(t('up.colResult')) + '</th><th scope="col" style="width:16rem">' + escHtml(t('up.colCheck')) + '</th><th scope="col">' + escHtml(t('up.colDetail')) + '</th></tr></thead><tbody>';
            (r.checks || []).forEach(c => {
                h += '<tr class="upd-cell"><td>' + updBadge(c.level === 'block' ? 'wait' : c.level) + '</td>'
                   + '<td><strong>' + updEsc(c.label) + '</strong></td><td>' + updEsc(c.detail) + '</td></tr>';
            });
            h += '</tbody></table></div>';
            if (r.already) h += '<div class="alert alert-success py-2 mb-0">' + escHtml(t('up.latestAlready')) + '</div>';
            else if (r.blocked) h += '<div class="alert alert-danger py-2 mb-0"><strong>' + escHtml(t('up.cannotStart')) + '</strong> ' + escHtml(t('up.fixRedRows')) + '</div>';
            else h += '<div class="alert alert-danger py-2"><strong>' + escHtml(t('up.pageWillStopShort')) + '</strong> ' + escHtml(t('up.jvmStopNote')) + '</div>'
                   + '<button class="btn btn-danger" onclick="jvRun()"><i class="fas fa-power-off me-1" aria-hidden="true"></i>' + escHtml(t('up.jvmRun')) + '</button>';
            el.innerHTML = h;
        }

        async function jvRun() {
            if (!updConfirm(t('up.javaStops'), t('up.wUpgradeJava'))) return;
            const el = document.getElementById('jv-pre');
            const r = await updApi('java_update', { confirm: 'AGGIORNA JAVA' });
            if (!r.success) { alert(r.error || t('common.failed')); return; }
            el.innerHTML = '<div class="alert alert-warning mb-0"><strong>' + escHtml(t('up.started')) + '</strong> ' + escHtml(t('up.panelStopping')) + ' '
                + updEsc(r.note || '') + '<br>' + t('up.reportWrittenIn.html', { path: updEsc(r.log || '') }) + '</div>';
        }

        async function jvState() {
            const pre = document.getElementById('jv-log');
            pre.style.display = 'block';
            pre.textContent = t('up.reading');
            const r = await updApi('java_status');
            if (!r.success) { pre.textContent = r.error || t('common.errorShort'); return; }
            if (!r.present) { pre.textContent = t('up.noJvmRun'); return; }
            pre.textContent = r.text + (r.finished ? '' : '\\n\\n' + t('up.stillRunning'));
        }

        // ---------- aggiornamento Roundcube ----------
        // ---------- nginx: gli asset della 1.7 passano da static.php ----------
        async function rcNginx() {
            const pre = document.getElementById('rc-log');
            const el = document.getElementById('rc-pre');
            pre.style.display = 'block';
            pre.textContent = t('up.readingNginx');
            const r = await updApi('roundcube_nginx_preview');
            if (!r.success) { pre.textContent = r.error || t('common.errorShort'); return; }
            if (r.alreadyOk) { pre.textContent = r.note; return; }
            pre.textContent =
                t('up.fileLines', { file: r.file, from: r.from, to: r.to }) + '\\n'
              + 'use_secure_urls in Roundcube: ' + (r.safeUrls ? t('up.running') : t('adm.notActive')) + '\\n\\n'
              + '=== ' + t('up.nowIs') + ' ===\\n' + r.current + '\\n\\n'
              + '=== ' + t('up.wouldBe') + ' ===\\n' + r.proposed;
            el.innerHTML = '<div class="alert alert-info py-2">' + t('up.nginxChange.html') + '</div>'
              + '<button class="btn btn-warning" onclick="rcNginxGo()"><i class="fas fa-wrench me-1" aria-hidden="true"></i>' + escHtml(t('up.apply')) + '</button>';
        }

        async function rcNginxGo() {
            if (!updConfirm('', t('up.wFixNginx'))) return;
            const pre = document.getElementById('rc-log');
            const el = document.getElementById('rc-pre');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('sj.inProgress')) + '';
            const r = await updApi('roundcube_nginx_fix', { confirm: 'RIPARA NGINX' });
            if (!r.success) {
                el.innerHTML = '<div class="alert alert-danger py-2 mb-0">' + updEsc(r.error) + '</div>';
                return;
            }
            const css = r.css || {};
            el.innerHTML = css.ok
              ? '<div class="alert alert-success py-2 mb-0"><strong>' + escHtml(t('up.doneShort')) + '</strong> ' + escHtml(t('up.cssOk')) + ' '
                + updEsc(css.answer) + '<br>' + escHtml(t('up.prevConfigCopy')) + ' <code>' + updEsc(r.backup) + '</code>'
                + '<br>' + escHtml(t('up.reloadWebmail')) + '</div>'
              : '<div class="alert alert-warning py-2 mb-0">' + updEsc(r.caution || t('up.cssNotOk'))
                + '</div>';
        }

        async function rcDiag() {
            const pre = document.getElementById('rc-log');
            pre.style.display = 'block';
            pre.textContent = t('up.rcDiagRunning');
            const r = await updApi('roundcube_diag');
            if (!r.success) { pre.textContent = r.error || t('common.errorShort'); return; }
            pre.textContent = (r.entries || []).map(v => '=== ' + v.title + ' ===\\n' + v.text).join('\\n\\n');
        }

        async function rcPre() {
            const el = document.getElementById('rc-pre');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.rcChecks')) + '';
            const r = await updApi('roundcube_preflight');
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            let h = '<div class="table-responsive"><table class="table table-sm align-middle mb-2"><thead><tr>'
                  + '<th scope="col" style="width:8rem">' + escHtml(t('up.colResult')) + '</th><th scope="col" style="width:16rem">' + escHtml(t('up.colCheck')) + '</th><th scope="col">' + escHtml(t('up.colDetail')) + '</th></tr></thead><tbody>';
            (r.checks || []).forEach(c => {
                h += '<tr class="upd-cell"><td>' + updBadge(c.level === 'block' ? 'wait' : c.level) + '</td>'
                   + '<td><strong>' + updEsc(c.label) + '</strong></td><td>' + updEsc(c.detail) + '</td></tr>';
            });
            h += '</tbody></table></div>';
            if (r.already) {
                h += '<div class="alert alert-success py-2 mb-0"><strong>' + escHtml(t('up.nothingToDoTitle')) + '</strong> ' + escHtml(t('up.rcLatest')) + '</div>';
            } else if (r.unknown) {
                h += '<div class="alert alert-warning py-2 mb-0">' + escHtml(t('up.repoUnknown')) + '</div>';
            } else if (r.blocked) {
                h += '<div class="alert alert-danger py-2 mb-0"><strong>' + escHtml(t('up.cannotStart')) + '</strong> ' + escHtml(t('up.fixRedRows')) + '</div>';
            } else {
                h += '<div class="alert alert-warning py-2">' + escHtml(t('up.rcDowntime')) + '</div>'
                   + '<button class="btn btn-danger" onclick="rcRun()"><i class="fas fa-play me-1" aria-hidden="true"></i>' + escHtml(t('up.rcRun')) + '</button>';
            }
            el.innerHTML = h;
        }

        async function rcRun() {
            if (!updConfirm('', t('up.wUpgradeRc'))) return;
            const el = document.getElementById('rc-pre');
            const pre = document.getElementById('rc-log');
            const r = await updApi('roundcube_update', { confirm: 'AGGIORNA ROUNDCUBE' });
            if (!r.success) { alert(r.error || t('common.failed')); return; }
            el.innerHTML = '<span class="text-info"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.upgradingKeepOpen')) + '</span>';
            pre.style.display = 'block';
            planPoll(r.jobId, el, pre);
        }

        // ---------- migrazione MySQL 8.4: solo verifica ----------
        async function my84Pre() {
            const el = document.getElementById('my84-pre');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.my84Checks')) + '';
            const r = await updApi('mysql84_preflight');
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            let h = '<div class="table-responsive"><table class="table table-sm align-middle mb-2"><thead><tr>'
                  + '<th scope="col" style="width:8rem">' + escHtml(t('up.colResult')) + '</th><th scope="col" style="width:16rem">' + escHtml(t('up.colCheck')) + '</th><th scope="col">' + escHtml(t('up.colDetail')) + '</th></tr></thead><tbody>';
            (r.checks || []).forEach(c => {
                h += '<tr class="upd-cell"><td>' + updBadge(c.level === 'block' ? 'wait' : c.level) + '</td>'
                   + '<td><strong>' + updEsc(c.label) + '</strong></td><td>' + updEsc(c.detail) + '</td></tr>';
            });
            h += '</tbody></table></div>';
            if ((r.dependents || []).length) {
                h += '<div class="small mb-2"><strong>' + escHtml(t('up.linkedPkgs')) + '</strong><ul class="mb-0">';
                r.dependents.forEach(d => {
                    h += '<li>' + t('up.requires.html', { pkg: updEsc(d.name), lib: updEsc(d.requires) }) + ' '
                       + (d.compatible ? '<span class="text-success">' + escHtml(t('up.compatible')) + '</span>'
                                        : '<span class="text-danger">' + escHtml(t('up.notCompatible84')) + '</span>') + '</li>';
                });
                h += '</ul></div>';
            }
            if (r.alreadyDone) {
                h += '<div class="alert alert-success py-2 mb-0">' + escHtml(t('up.already84')) + '</div>';
            } else if (r.blocked) {
                h += '<div class="alert alert-danger py-2 mb-0"><strong>' + escHtml(t('up.migrationCannotStart')) + '</strong> ' + escHtml(t('up.migrationRedRows')) + '</div>';
            } else {
                h += '<div class="alert alert-warning py-2"><strong>' + escHtml(t('up.prereqPassed')) + '</strong> ' + escHtml(t('up.migrationNote')) + '</div>'
                   + '<button class="btn btn-danger" onclick="my84Run()"><i class="fas fa-play me-1" aria-hidden="true"></i>' + escHtml(t('up.migrate84')) + '</button>';
            }
            el.innerHTML = h;
        }

        async function my84Run() {
            if (!updConfirm('', t('up.wMigrate84'))) return;
            const el = document.getElementById('my84-pre');
            // Il log va nel riquadro DI QUESTA scheda: prima finiva in quello del piano, in
            // un'altra parte della pagina, e chi guardava sotto il messaggio di errore non
            // trovava niente. Un log che esiste ma non e' dove lo cerchi e' un log perduto.
            const pre = document.getElementById('my84-log');
            const r = await updApi('mysql84_migrate', { confirm: 'MIGRA A 8.4' });
            if (!r.success) { alert(r.error || t('common.failed')); return; }
            el.innerHTML = '<span class="text-info"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.migrating')) + '</span>';
            pre.style.display = 'block';
            planPoll(r.jobId, el, pre);
        }

        // ---------- aggiornamento guidato ----------
        let updMaintenanceSignature = '';

        /* Il piano esatto di pkg: ogni pacchetto che cambia, da quale versione a quale. */
        function updPlanHtml(pn, signature) {
            if (!pn) return '';
            if (!pn.measured) {
                return '<div class="alert alert-danger py-2 small mb-2">' + escHtml(t('up.planUnavailable')) + ' '
                     + updEsc(pn.error || pn.error || '?') + '</div>';
            }
            const kindName = { aggiorna: t('up.tUpgrade'), installa: t('up.tInstall'), reinstalla: t('up.tReinstall'),
                               rimuove: t('up.tRemove'), retrocede: t('up.tDowngrade') };
            const kindCls = { aggiorna: 'bg-primary', installa: 'bg-info text-dark', reinstalla: 'bg-secondary',
                              rimuove: 'bg-danger', retrocede: 'bg-danger' };
            let h = '';
            if ((pn.changes || []).length) {
                h += '<div class="small fw-bold mb-1">' + escHtml(tn('up.exactPlanN', pn.changes.length)) + '</div>'
                   + '<div class="table-responsive" style="max-height:24rem;overflow:auto"><table class="table table-sm align-middle mb-1"><thead><tr>'
                   + '<th scope="col" style="width:8rem"><span class="visually-hidden">' + escHtml(t('up.colAction')) + '</span></th><th scope="col">' + escHtml(t('up.colPackage')) + '</th><th scope="col">' + escHtml(t('up.colFrom')) + '</th><th scope="col">' + escHtml(t('up.colTo')) + '</th><th scope="col">' + escHtml(t('up.colNote')) + '</th></tr></thead><tbody>';
                pn.changes.forEach(c => {
                    h += '<tr class="upd-cell"><td><span class="badge ' + (kindCls[c.type] || 'bg-secondary') + '">'
                       + updEsc(kindName[c.type] || c.type) + '</span></td>'
                       + '<td><code>' + updEsc(c.name) + '</code></td>'
                       + '<td class="small">' + updEsc(c.from || '-') + '</td>'
                       + '<td class="small">' + updEsc(c.to || '-') + '</td>'
                       + '<td class="small">' + updEsc(c.reason || '')
                       + (c.stillVulnerable ? ' <span class="badge bg-danger">' + escHtml(t('up.stillVulnerable')) + '</span>' : '')
                       + (c.repo ? ' <span class="text-muted">[' + updEsc(c.repo) + ']</span>' : '') + '</td></tr>';
                });
                h += '</tbody></table></div>';
            } else {
                h += '<div class="small text-muted mb-1">' + escHtml(t('up.planNoChange')) + '</div>';
            }
            (pn.blockers || []).forEach(x => {
                h += '<div class="small text-warning-emphasis"><i class="fas fa-lock me-1" aria-hidden="true"></i><code>' + updEsc(x.name)
                   + '</code>: ' + updEsc(x.reason) + '</div>';
            });
            h += '<div class="small text-muted mb-2">' + t('up.computedWith.html', { cmd: updEsc(pn.command || '') })
               + (pn.onBackup ? ' ' + escHtml(t('up.onCopy', { list: (pn.unlockedPackages || []).join(', ') })) : '.')
               + (signature ? ' ' + t('up.fingerprint.html', { sig: updEsc(signature) }) : '') + '</div>';
            return h;
        }

        // ---------- protezione pacchetti ----------
        // La tabella dei pacchetti e' una sola, nella scheda Pacchetti: chi chiedeva di rileggere
        // le protezioni rilegge quella.
        function updPackages() { pkOverview(); }

        async function updLockOne(entryName, doLock) {
            const r = await updApi('packages_lock', { lock: doLock, package: entryName });
            if (!r.success) { alert(r.error || t('common.failed')); return; }
            updPackages();
        }

        async function updLockAll(doLock) {
            if (!doLock && !confirm(t('up.confirmUnlockAll'))) return;
            const el = document.getElementById('upd-packages');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(doLock ? t('up.locking') : t('up.unlocking'));
            const r = await updApi('packages_lock', { lock: doLock, package: '' });
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            updPackages();
        }

        // ---------- aggiornamenti e vulnerabilita' ----------
        /* La firma del piano letto nella scheda: si manda al via, e il server esegue quello
           o niente. Senza, l'aggiornamento dei non protetti era l'unico che partiva alla
           cieca. Vuota finche' la scheda non e' stata letta: il pulsante lo dice. */
        let updUnprotectedSignature = '';
        async function updStatus() {
            const el = document.getElementById('upd-status');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.simulating')) + '';
            const r = await updApi('updates_status');
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            updUnprotectedSignature = r.signature || '';
            let h = '';

            if (r.rebootPending) {
                h += '<div class="alert alert-warning py-2 small"><strong>' + escHtml(t('up.rebootMissing')) + '</strong> '
                   + escHtml(t('up.kernelDiffers', { kernel: r.kernel, running: r.running })) + '</div>';
            }

            const vuln = r.vulnerable || [];
            if (vuln.length) {
                h += '<div class="alert alert-danger py-2 small"><strong>' + escHtml(tn('up.vulnPkgs', vuln.length)) + '</strong><ul class="mb-0 mt-1">';
                vuln.forEach(v => {
                    // L'intestazione dice lo stesso verdict del dettaglio: quando c'e' il confronto
                    // con VuXML, sa se l'aggiornamento basta o no. Il blocco e' un'informazione a
                    // parte, non un verdict: il pulsante aggiorna anche un pacchetto bloccato.
                    const vc0 = v.fix;
                    const updatable = vc0 && (vc0.verdict === 'si-risolve-aggiornando' || vc0.verdict === 'aggiornamento-non-basta');
                    h += '<li class="mb-2"><div class="d-flex flex-wrap align-items-center gap-1"><code>' + updEsc(v.name) + '</code>'
                       + (v.role ? ' <span class="text-muted">(' + updEsc(v.role) + ')</span>' : '')
                       + (vc0 && vc0.verdict
                            ? ' ' + pkVulnBadge(vc0)
                            : (v.locked
                                ? (v.updateAvailable
                                    ? ' &mdash; ' + t('up.lockedHasUpdate.html')
                                    : ' &mdash; ' + t('up.lockedNoUpdate.html'))
                                : ' &mdash; ' + escHtml(v.fixedByUpgrade ? t('up.fixedByUpgrade') : t('up.noUpdateInCatalog'))))
                       + (v.locked && vc0 && vc0.verdict ? ' <span class="badge bg-secondary"><i class="fas fa-lock me-1" aria-hidden="true"></i>' + escHtml(t('pkgs.locked')) + '</span>' : '')
                       + (updatable ? '<button type="button" class="btn btn-sm btn-warning ms-auto" data-pkg="' + escHtml(v.name) + '" onclick="pkUpdOpen(this.dataset.pkg)">'
                            + '<i class="fas fa-arrow-up me-1" aria-hidden="true"></i>' + escHtml(t('pkgs.update', { v: vc0.catalog || '' })) + '</button>' : '')
                       + '</div>';
                    if ((v.cve || []).length) {
                        h += '<br><span class="badge bg-dark me-1">'
                           + v.cve.map(c => updEsc(c)).join('</span><span class="badge bg-dark me-1">')
                           + '</span>';
                    }
                    if (v.description) {
                        h += '<br><span class="text-muted">' + updEsc(v.description) + '</span>';
                    }
                    // La domanda vera: la fix c'e'? La dicono gli ranges di VuXML
                    // messi accanto alla versione che il catalogo offre.
                    if (v.fix) h += '<br><span>' + updEsc(v.fix.explanation || '') + '</span>';
                    (v.references || []).forEach(u => {
                        h += '<br><a href="' + updEsc(u) + '" target="_blank" rel="noopener noreferrer" class="small">'
                           + updEsc(u) + '</a>';
                    });
                    h += '</li>';
                });
                h += '</ul>';
                if (r.fixesError) {
                    h += '<div class="small text-muted">' + escHtml(t('up.fixUnknown')) + ' '
                       + updEsc(r.fixesError) + '</div>';
                }
                if (r.restartNote) {
                    h += '<div class="mt-2 pt-2 border-top small"><i class="fas fa-triangle-exclamation me-1" aria-hidden="true"></i>'
                       + '<strong>' + updEsc(r.restartNote) + '</strong></div>';
                }
                h += '</div>';
            } else {
                h += '<div class="alert alert-success py-2 small"><i class="fas fa-check me-1" aria-hidden="true"></i>' + escHtml(t('up.noVulns')) + '</div>';
            }

            const locked = r.lockedUpdates || [];
            if (locked.length) {
                h += '<h6 class="mt-3">' + escHtml(t('up.lockedUpdates')) + '</h6>'
                   + '<div class="small text-muted mb-2">' + escHtml(t('up.lockedUpdatesNote')) + '</div>'
                   + '<div class="table-responsive"><table class="table table-sm"><thead><tr>'
                   + '<th scope="col">' + escHtml(t('up.colPackage')) + '</th><th scope="col">' + escHtml(t('up.colFrom')) + '</th><th scope="col">' + escHtml(t('up.colTo')) + '</th><th scope="col">' + escHtml(t('up.colResult')) + '</th><th scope="col">' + escHtml(t('up.colWhy')) + '</th></tr></thead><tbody>';
                locked.forEach(p => {
                    const a = p.advisory;
                    h += '<tr class="upd-cell"><td><code>' + updEsc(p.name) + '</code><br><span class="small text-muted">'
                       + updEsc(p.role) + '</span></td>'
                       + '<td class="small">' + updEsc(p.current) + '</td>'
                       + '<td class="small">' + updEsc(p.available)
                       + (p.majorJump ? ' <span class="badge bg-secondary">' + escHtml(t('up.major')) + '</span>' : '') + '</td>'
                       + '<td>' + (a ? updBadge(a.level) : '<span class="badge bg-secondary">-</span>') + '</td>'
                       + '<td class="small">' + (a ? updEsc(a.text) : '') + '</td></tr>';
                });
                h += '</tbody></table></div>';
            }

            const aff = r.affectedMailPackages || [];
            if (aff.length) {
                h += '<div class="small mb-2"><strong>' + escHtml(t('up.affected')) + '</strong> '
                   + aff.map(p => updEsc(p.name) + (p.locked ? ' (' + escHtml(t('up.locked')) + ')' : '')).join(', ') + '</div>';
            }

            /* Il piano esatto con la sua firma, come nelle altre due schede. L'uscita grezza
               di pkg resta sotto, ripiegata: e' il dettaglio, non la decisione. */
            if (r.plan) h += updPlanHtml(r.plan, r.signature);
            h += '<details class="mt-2"><summary class="small text-muted">' + escHtml(t('up.fullSim')) + '</summary>'
               + '<pre class="upd-log mt-2">' + updEsc(r.dryRun) + '</pre></details>';
            if (r.audit) {
                h += '<details class="mt-1"><summary class="small text-muted">' + escHtml(t('up.fullAudit')) + '</summary>'
                   + '<pre class="upd-log mt-2">' + updEsc(r.audit) + '</pre></details>';
            }
            el.innerHTML = h;
        }

        async function updApply() {
            /* Senza la firma non si parte: vuol dire che la scheda non e' stata letta, cioe'
               che nessuno ha visto il piano che si sta per eseguire. */
            if (!updUnprotectedSignature) { alert(t('up.readFirst')); return; }
            if (!confirm(t('up.confirmApply'))) return;
            if (!updConfirm('', t('up.wUpgrade'))) return;
            const el = document.getElementById('upd-status');
            const pre = document.getElementById('upd-log');
            const r = await updApi('updates_apply', { confirm: 'UPDATE', signature: updUnprotectedSignature });
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            el.innerHTML = '<span class="text-info"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.upgradingKeepOpen')) + '</span>';
            pre.style.display = 'block';
            updPoll(r.jobId, el, pre);
        }

        async function updMaintPreview() {
            const el = document.getElementById('upd-status');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.computingChange')) + '';
            const r = await updApi('maintenance_preview');
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            let h = '<div class="alert alert-secondary py-2 small">' + updEsc(r.generalNote) + '</div>';
            /* Se il piano rimuove o retrocede pacchetti il pannello non lo esegue: si dice
               QUI, prima del pulsante, non dopo aver scritto MANUTENZIONE. */
            if (r.blockedReason) {
                h += '<div class="alert alert-danger py-2 small"><strong>'
                   + escHtml(t('up.notRunnable')) + '</strong> ' + updEsc(r.blockedReason) + '</div>';
            }
            const pk = r.packages || [];
            if (!pk.length) {
                h += '<div class="small text-muted">' + escHtml(t('up.noLockedUpd')) + '</div>';
                el.innerHTML = h;
                return;
            }
            h += '<div class="table-responsive"><table class="table table-sm"><thead><tr>'
               + '<th scope="col">' + escHtml(t('up.colPackage')) + '</th><th scope="col">' + escHtml(t('up.colFrom')) + '</th><th scope="col">' + escHtml(t('up.colTo')) + '</th><th scope="col">' + escHtml(t('up.colResult')) + '</th></tr></thead><tbody>';
            pk.forEach(p => {
                const a = p.advisory;
                h += '<tr class="upd-cell"><td><code>' + updEsc(p.name) + '</code></td>'
                   + '<td class="small">' + updEsc(p.current) + '</td>'
                   + '<td class="small">' + updEsc(p.available) + '</td>'
                   + '<td>' + (a ? updBadge(a.level) : '<span class="badge bg-secondary">-</span>') + '</td></tr>';
            });
            h += '</tbody></table></div>';
            if (r.waitCount > 0) {
                h += '<div class="alert alert-warning py-2 small"><strong>' + escHtml(tn('up.staysLocked', r.waitCount)) + '</strong> '
                   + escHtml(t('up.staysLockedNote')) + '</div>';
            }
            h += updPlanHtml(r.plan, r.signature);
            updMaintenanceSignature = r.signature || '';
            if (r.plan && r.plan.runnable) {
                h += '<button class="btn btn-sm btn-danger" onclick="updMaintRun()"><i class="fas fa-play me-1" aria-hidden="true"></i>' + escHtml(t('up.runMaint')) + '</button>';
            } else {
                h += '<div class="alert alert-secondary py-2 small mb-0">' + escHtml(t('up.nothingToRun')) + '</div>';
            }
            el.innerHTML = h;
        }

        async function updMaintRun() {
            if (!updConfirm(t('up.confirmMaint'), t('up.wMaint'))) return;
            const el = document.getElementById('upd-status');
            const pre = document.getElementById('upd-log');
            const r = await updApi('maintenance_run', { confirm: 'MANUTENZIONE', signature: updMaintenanceSignature });
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            el.innerHTML = '<span class="text-info"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.maintRunning')) + '</span>';
            pre.style.display = 'block';
            updPoll(r.jobId, el, pre);
        }

        async function updPoll(id, el, pre) {
            const s = await updApi('job_status', { jobId: id });
            if (s.success && s.job) {
                pre.textContent = s.job.consoleLog || '';
                pre.scrollTop = pre.scrollHeight;
                if (s.job.status === 'completed') {
                    el.innerHTML = '<span class="text-success"><i class="fas fa-check me-1" aria-hidden="true"></i>'
                                 + escHtml(t('up.opDone', { s: s.job.elapsedSeconds })) + '</span>';
                    updPackages();
                    return;
                }
                if (s.job.status === 'error') {
                    el.innerHTML = '<div class="alert alert-danger py-2 mb-0"><strong>' + escHtml(t('up.opFailed')) + '</strong> '
                                 + updEsc(s.job.errorMessage) + '<br>' + escHtml(t('up.readLogWhere')) + '</div>';
                    updPackages();
                    return;
                }
            }
            setTimeout(() => updPoll(id, el, pre), 3000);
        }
        """;
    }


}
