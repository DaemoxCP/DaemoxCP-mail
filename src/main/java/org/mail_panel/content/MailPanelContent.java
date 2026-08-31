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

            // Centralized header and footer
            writeFile(adminDir + "/header.html", getHeaderHtml());
            writeFile(adminDir + "/footer.html", getFooterHtml());

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

    // ============== CENTRALIZED HEADER.HTML ==============
    /**
     * Generates header.html - the centralized navbar loaded by all pages
     */
    private static String getHeaderHtml() {
        return """
<nav class="navbar navbar-expand-lg navbar-dark navbar-mail">
    <div class="container-fluid">
        <a class="navbar-brand" href="/home"><i class="fas fa-envelope me-2"></i>Mail Control Panel</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav"><span class="navbar-toggler-icon"></span></button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav me-auto">
                <li class="nav-item"><a class="nav-link" href="/home" data-page="home"><i class="fas fa-home me-1"></i>Dashboard</a></li>
                <li class="nav-item"><a class="nav-link" href="/domains" data-page="domains"><i class="fas fa-globe me-1"></i>Domini</a></li>
                <li class="nav-item"><a class="nav-link" href="/mailboxes" data-page="mailboxes"><i class="fas fa-inbox me-1"></i>Caselle</a></li>
                <li class="nav-item"><a class="nav-link" href="/aliases" data-page="aliases"><i class="fas fa-share me-1"></i>Alias</a></li>
                <li class="nav-item"><a class="nav-link" href="/dns" data-page="dns"><i class="fas fa-server me-1"></i>DNS</a></li>
                <li class="nav-item"><a class="nav-link" href="/ssl" data-page="ssl"><i class="fas fa-lock me-1"></i>SSL</a></li>
                <li class="nav-item"><a class="nav-link" href="/security" data-page="security"><i class="fas fa-shield-alt me-1"></i>Sicurezza</a></li>
                <li class="nav-item"><a class="nav-link" href="/firewall" data-page="firewall"><i class="fas fa-fire me-1"></i>Firewall</a></li>
                <li class="nav-item"><a class="nav-link" href="/cloudflare" data-page="cloudflare"><i class="fas fa-cloud me-1"></i>Cloudflare</a></li>
                <li class="nav-item"><a class="nav-link" href="/paths" data-page="paths"><i class="fas fa-folder-tree me-1"></i>Path</a></li>
                <li class="nav-item"><a class="nav-link" href="/updates" data-page="updates"><i class="fas fa-arrow-up-right-dots me-1"></i>Aggiornamenti</a></li>
                <li class="nav-item"><a class="nav-link" href="/logs" data-page="logs"><i class="fas fa-file-alt me-1"></i>Logs</a></li>
                <li class="nav-item"><a class="nav-link" href="/settings" data-page="settings"><i class="fas fa-cog me-1"></i>Impostazioni</a></li>
            </ul>
            <ul class="navbar-nav align-items-center">
                <li class="nav-item me-2">
                    <button class="theme-toggle" id="themeToggle" title="Cambia tema">
                        <i class="fas fa-sun" id="themeIcon"></i>
                    </button>
                </li>
                <li class="nav-item"><a class="nav-link btn btn-logout text-white" href="#" id="logoutButton"><i class="fas fa-sign-out-alt me-1"></i>Logout</a></li>
            </ul>
        </div>
    </div>
</nav>
""";
    }

    // ============== CENTRALIZED FOOTER.HTML ==============
    /**
     * Generates footer.html - the centralized footer loaded by all pages
     */
    private static String getFooterHtml() {
        int year = java.time.Year.now().getValue();
        return """
<footer class="footer bg-light text-center mt-4">
    <div class="text-center p-3" style="background-color: rgba(0, 0, 0, 0.2);">&copy; {{YEAR}} FreeBSD 15 - Mail Control Panel - Copyright by Pietro Giuseppe D'Amico</div>
</footer>
""".replace("{{YEAR}}", String.valueOf(year));
    }

    // ============== COMMON TEMPLATES FOR PAGES ==============

    /**
     * Common CSS styles used across all pages
     */
    private static String getCommonStyles() {
        return """
        /* ===== THEME VARIABLES ===== */
        :root {
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
        .navbar-mail { background: linear-gradient(90deg, #16213e 0%, #0f3460 100%); }
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
        /* Theme toggle button */
        .theme-toggle { cursor: pointer; padding: 8px 12px; border-radius: 6px; background: transparent; border: none; color: white; font-size: 1.1rem; }
        .theme-toggle:hover { background: rgba(255,255,255,0.1); }
        .table-responsive { overflow: visible; }
        .dropdown-menu { z-index: 1050; }
        #nav-placeholder, #footer-placeholder { display: contents; }
        """;
    }

    /**
     * Common HTML head section - pages load header.html and footer.html dynamically
     * @param title Page title
     * @param pageName The page name for active nav highlighting (e.g., "home", "domains")
     * @param extraStyles Additional page-specific CSS (can be empty)
     */
    private static String getHead(String title, String pageName, String extraStyles) {
        return String.format("""
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s - Mail Control Panel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css" rel="stylesheet">
    <style>
        %s
        %s
    </style>
</head>
<body data-page="%s">
%s
""", title, getCommonStyles(), extraStyles != null ? extraStyles : "", pageName, getNavbarHtml(pageName));
    }

    /**
     * Generates the navbar HTML with the active page highlighted
     */
    private static String getNavbarHtml(String activePage) {
        return """
<nav class="navbar navbar-expand-lg navbar-dark navbar-mail">
    <div class="container-fluid">
        <a class="navbar-brand" href="/home"><i class="fas fa-envelope me-2"></i>Mail Control Panel</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav"><span class="navbar-toggler-icon"></span></button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav me-auto">
                <li class="nav-item"><a class="nav-link""" + (activePage.equals("home") ? " active" : "") + """
" href="/home"><i class="fas fa-home me-1"></i>Dashboard</a></li>
                <li class="nav-item"><a class="nav-link""" + (activePage.equals("domains") ? " active" : "") + """
" href="/domains"><i class="fas fa-globe me-1"></i>Domini</a></li>
                <li class="nav-item"><a class="nav-link""" + (activePage.equals("mailboxes") ? " active" : "") + """
" href="/mailboxes"><i class="fas fa-inbox me-1"></i>Caselle</a></li>
                <li class="nav-item"><a class="nav-link""" + (activePage.equals("aliases") ? " active" : "") + """
" href="/aliases"><i class="fas fa-share me-1"></i>Alias</a></li>
                <li class="nav-item"><a class="nav-link""" + (activePage.equals("dns") ? " active" : "") + """
" href="/dns"><i class="fas fa-server me-1"></i>DNS</a></li>
                <li class="nav-item"><a class="nav-link""" + (activePage.equals("ssl") ? " active" : "") + """
" href="/ssl"><i class="fas fa-lock me-1"></i>SSL</a></li>
                <li class="nav-item"><a class="nav-link""" + (activePage.equals("security") ? " active" : "") + """
" href="/security"><i class="fas fa-shield-alt me-1"></i>Sicurezza</a></li>
                <li class="nav-item"><a class="nav-link""" + (activePage.equals("firewall") ? " active" : "") + """
" href="/firewall"><i class="fas fa-fire me-1"></i>Firewall</a></li>
                <li class="nav-item"><a class="nav-link""" + (activePage.equals("cloudflare") ? " active" : "") + """
" href="/cloudflare"><i class="fas fa-cloud me-1"></i>Cloudflare</a></li>
                <li class="nav-item"><a class="nav-link""" + (activePage.equals("paths") ? " active" : "") + """
" href="/paths"><i class="fas fa-folder-tree me-1"></i>Path</a></li>
                <li class="nav-item"><a class="nav-link""" + (activePage.equals("updates") ? " active" : "") + """
" href="/updates"><i class="fas fa-arrow-up-right-dots me-1"></i>Aggiornamenti</a></li>
                <li class="nav-item"><a class="nav-link""" + (activePage.equals("logs") ? " active" : "") + """
" href="/logs"><i class="fas fa-file-alt me-1"></i>Logs</a></li>
                <li class="nav-item"><a class="nav-link""" + (activePage.equals("settings") ? " active" : "") + """
" href="/settings"><i class="fas fa-cog me-1"></i>Impostazioni</a></li>
            </ul>
            <ul class="navbar-nav">
                <li class="nav-item"><a class="nav-link btn btn-logout text-white" href="#" id="logoutButton"><i class="fas fa-sign-out-alt me-1"></i>Logout</a></li>
            </ul>
        </div>
    </div>
</nav>
""";
    }

    /**
     * Common footer section with inline footer HTML and logout script
     */
    private static String getFooterSection() {
        int year = java.time.Year.now().getValue();
        return ("""
    <footer class="footer bg-dark text-white py-3 mt-4">
        <div class="container text-center">
            <small>&copy; {{YEAR}} FreeBSD 15 - Mail Control Panel - Copyright by Pietro Giuseppe D'Amico</small>
        </div>
    </footer>""").replace("{{YEAR}}", String.valueOf(year)) + """
    <input type="hidden" id="csrf_token" value="{{CSRF_TOKEN}}">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // ===== THEME MANAGEMENT =====
        (function() {
            let savedTheme = 'auto';

            // Get browser preference
            function getBrowserTheme() {
                return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
            }

            // Apply theme to document
            function applyTheme(theme) {
                const effectiveTheme = theme === 'auto' ? getBrowserTheme() : theme;
                document.documentElement.setAttribute('data-theme', effectiveTheme);
                updateIcon(effectiveTheme);
            }

            // Update toggle icon
            function updateIcon(effectiveTheme) {
                const icon = document.getElementById('themeIcon');
                if (icon) {
                    icon.className = effectiveTheme === 'dark' ? 'fas fa-moon' : 'fas fa-sun';
                }
            }

            // Load theme from server
            function loadTheme() {
                fetch('/api/theme').then(r => r.json()).then(data => {
                    if (data.success) {
                        savedTheme = data.theme || 'auto';
                        applyTheme(savedTheme);
                    }
                }).catch(() => applyTheme('auto'));
            }

            // Save theme to server
            function saveTheme(theme) {
                fetch('/api/theme', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ theme: theme })
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
                loadTheme();
                const toggle = document.getElementById('themeToggle');
                if (toggle) {
                    toggle.addEventListener('click', cycleTheme);
                }
            });

            // Apply immediately (before DOM ready) to prevent flash
            applyTheme(getBrowserTheme());
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

    // ============== BACKWARD COMPATIBILITY (temporary) ==============
    // These methods will be removed after all pages are updated

    /**
     * @deprecated Use getHead(title, pageName, extraStyles) instead
     */
    private static String getHead(String title, String extraStyles) {
        // Infer pageName from title for backward compatibility
        String pageName = switch (title.toLowerCase()) {
            case "dashboard" -> "home";
            case "domini" -> "domains";
            case "caselle email" -> "mailboxes";
            case "alias" -> "aliases";
            case "dns" -> "dns";
            case "ssl" -> "ssl";
            case "logs" -> "logs";
            case "impostazioni" -> "settings";
            case "coda email" -> "queue";
            case "sicurezza" -> "security";
            case "installazione" -> "install";
            case "statistiche" -> "statistics";
            case "gestione admin" -> "admins";
            case "rate limits" -> "ratelimits";
            case "cloudflare" -> "cloudflare";
            default -> "";
        };
        return getHead(title, pageName, extraStyles);
    }

    /**
     * @deprecated Navbar is now loaded from header.html
     */
    private static String getNavbar(String activePage) {
        return ""; // Navbar now loaded dynamically
    }

    /**
     * @deprecated Use getFooterSection() instead
     */
    private static String getFooter() {
        return getFooterSection();
    }

    /**
     * @deprecated Logout is now handled in header.html loading
     */
    private static String getLogoutScript() {
        return ""; // Logout now handled in getFooterSection
    }

    // ============== INDEX.HTML (Login Page) ==============
    public static String getIndexHtml() {
        int year = java.time.Year.now().getValue();
        return """
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Mail Control Panel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css" rel="stylesheet">
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
        .btn-passkey { background-color: #6f42c1; border-color: #6f42c1; }
        .btn-passkey:hover { background-color: #5a32a3; border-color: #5a32a3; }
        .step { display: none; }
        .step.active { display: block; }
        .user-info { background: var(--bg-input); padding: 10px 15px; border-radius: 8px; margin-bottom: 20px; display: flex; align-items: center; justify-content: space-between; }
        .user-info .username { font-weight: 600; }
        .user-info .change-user { color: #e94560; cursor: pointer; font-size: 0.9rem; }
        .passkey-prompt { text-align: center; padding: 30px 20px; }
        .passkey-prompt i { font-size: 48px; color: #6f42c1; margin-bottom: 15px; }
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
        .theme-toggle-login { position: fixed; top: 15px; right: 15px; cursor: pointer; padding: 10px 14px; border-radius: 50%; background: var(--bg-card); border: 1px solid var(--border-color); color: var(--text-primary); font-size: 1.2rem; box-shadow: 0 2px 10px var(--shadow-color); z-index: 1000; }
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
    <button class="theme-toggle-login" onclick="toggleLoginTheme()" title="Cambia tema">
        <i class="fas fa-sun" id="themeIconLogin"></i>
    </button>
    <div class="content">
        <div class="container">
            <div class="login-container">
                <div class="login-logo"><i class="fas fa-envelope"></i></div>
                <h2 class="text-center mb-4">Mail Control Panel</h2>
                <div class="alert alert-success d-none" id="successAlert" role="alert">Login effettuato con successo!</div>
                <div class="alert alert-danger d-none" id="errorAlert" role="alert">
                    <span id="errorMessage">Errore di login.</span>
                </div>
                <input type="hidden" id="csrf_token" value="{{CSRF_TOKEN}}">

                <!-- STEP 1: Username -->
                <div id="step-username" class="step active">
                    <div class="mb-3">
                        <label for="username" class="form-label">Username</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="fas fa-user"></i></span>
                            <input type="text" class="form-control" id="username" placeholder="Inserisci il tuo username"
                                   pattern="^[a-zA-Z0-9_\\-]{3,50}$" minlength="3" maxlength="50" autocomplete="username">
                        </div>
                        <div class="validation-error" id="usernameError">Username non valido.</div>
                    </div>
                    <div class="d-grid">
                        <button type="button" class="btn btn-mail btn-lg text-white" id="btnContinue">
                            <span id="continueText">Continua</span>
                            <span id="continueSpinner" class="spinner-border spinner-border-sm d-none" role="status"></span>
                        </button>
                    </div>
                </div>

                <!-- STEP 2: Passkey -->
                <div id="step-passkey" class="step">
                    <div class="user-info">
                        <span><i class="fas fa-user me-2"></i><span class="username" id="displayUsername"></span></span>
                        <span class="change-user" onclick="goToStep('username')"><i class="fas fa-edit me-1"></i>Cambia</span>
                    </div>
                    <div class="passkey-prompt">
                        <i class="fas fa-fingerprint"></i>
                        <h5>Usa la tua Passkey</h5>
                        <p class="text-muted mb-3">Tocca il sensore biometrico o inserisci il PIN del dispositivo</p>
                        <button type="button" class="btn btn-passkey btn-lg text-white w-100" id="btnPasskey">
                            <i class="fas fa-key me-2"></i>Usa Passkey
                        </button>
                    </div>
                    <div class="divider"><span>oppure</span></div>
                    <div class="d-grid">
                        <button type="button" class="btn btn-outline-secondary" id="btnUsePassword">
                            <i class="fas fa-lock me-2"></i>Usa Password
                        </button>
                    </div>
                </div>

                <!-- STEP 3: Password -->
                <div id="step-password" class="step">
                    <div class="user-info">
                        <span><i class="fas fa-user me-2"></i><span class="username" id="displayUsername2"></span></span>
                        <span class="change-user" onclick="goToStep('username')"><i class="fas fa-edit me-1"></i>Cambia</span>
                    </div>
                    <div class="mb-3">
                        <label for="password" class="form-label">Password</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="fas fa-lock"></i></span>
                            <input type="password" class="form-control" id="password" placeholder="Inserisci la tua password"
                                   minlength="8" maxlength="128" autocomplete="current-password">
                        </div>
                        <div class="validation-error" id="passwordError">Password non valida.</div>
                    </div>
                    <div class="d-grid">
                        <button type="button" class="btn btn-mail btn-lg text-white" id="btnLogin">
                            <span id="loginText">Accedi</span>
                            <span id="loginSpinner" class="spinner-border spinner-border-sm d-none" role="status"></span>
                        </button>
                    </div>
                </div>

                <!-- STEP 4: 2FA/OTP -->
                <div id="step-2fa" class="step">
                    <div class="user-info">
                        <span><i class="fas fa-user me-2"></i><span class="username" id="displayUsername3"></span></span>
                        <span class="change-user" onclick="goToStep('username')"><i class="fas fa-edit me-1"></i>Cambia</span>
                    </div>
                    <div class="mb-3">
                        <label for="otpCode" class="form-label">Codice di Verifica</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="fas fa-shield-alt"></i></span>
                            <input type="text" class="form-control text-center" id="otpCode" placeholder="000000"
                                   maxlength="6" pattern="[0-9]{6}" autocomplete="one-time-code" style="letter-spacing: 8px; font-size: 1.5rem;">
                        </div>
                        <div class="char-hint"><i class="fas fa-info-circle"></i> Inserisci il codice a 6 cifre dalla tua app di autenticazione</div>
                    </div>
                    <div class="d-grid">
                        <button type="button" class="btn btn-mail btn-lg text-white" id="btnVerify2FA">
                            <span id="verifyText">Verifica</span>
                            <span id="verifySpinner" class="spinner-border spinner-border-sm d-none" role="status"></span>
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <footer class="footer bg-light text-center text-lg-start mt-4">
        <div class="text-center p-3" style="background-color: rgba(0, 0, 0, 0.2);">&copy; {{YEAR}} FreeBSD 15 - Mail Control Panel - Copyright by Pietro Giuseppe D'Amico</div>
    </footer>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // State
        let currentUsername = '';
        let authMethods = {};
        let tempPassword = '';

        // Elements
        const usernameInput = document.getElementById('username');
        const passwordInput = document.getElementById('password');
        const otpInput = document.getElementById('otpCode');

        // Utility functions
        function showError(msg) {
            document.getElementById('errorMessage').textContent = msg;
            document.getElementById('errorAlert').classList.remove('d-none');
        }
        function hideError() { document.getElementById('errorAlert').classList.add('d-none'); }
        function showSuccess(msg) {
            document.getElementById('successAlert').textContent = msg || 'Login effettuato con successo!';
            document.getElementById('successAlert').classList.remove('d-none');
        }

        function goToStep(step) {
            document.querySelectorAll('.step').forEach(s => s.classList.remove('active'));
            document.getElementById('step-' + step).classList.add('active');
            hideError();
            if (step === 'username') {
                currentUsername = '';
                authMethods = {};
                tempPassword = '';
                usernameInput.value = '';
                passwordInput.value = '';
                otpInput.value = '';
                usernameInput.focus();
            } else if (step === 'password') {
                document.getElementById('displayUsername2').textContent = currentUsername;
                passwordInput.focus();
            } else if (step === 'passkey') {
                document.getElementById('displayUsername').textContent = currentUsername;
            } else if (step === '2fa') {
                document.getElementById('displayUsername3').textContent = currentUsername;
                otpInput.focus();
            }
        }

        // Step 1: Check username
        document.getElementById('btnContinue').addEventListener('click', async function() {
            const username = usernameInput.value.trim();
            if (!username || username.length < 3) {
                showError('Inserisci un username valido');
                return;
            }

            const btn = this;
            btn.disabled = true;
            document.getElementById('continueSpinner').classList.remove('d-none');
            document.getElementById('continueText').textContent = 'Verifica...';
            hideError();

            try {
                const res = await fetch('/api/auth/check', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: username })
                });
                const data = await res.json();

                if (!data.exists) {
                    showError('Utente non trovato');
                    btn.disabled = false;
                    document.getElementById('continueSpinner').classList.add('d-none');
                    document.getElementById('continueText').textContent = 'Continua';
                    return;
                }

                currentUsername = username;
                authMethods = data;

                // If user has passkey, show passkey step
                if (data.hasPasskey) {
                    goToStep('passkey');
                } else {
                    // No passkey, go to password
                    goToStep('password');
                }
            } catch (err) {
                showError('Errore di connessione');
            }

            btn.disabled = false;
            document.getElementById('continueSpinner').classList.add('d-none');
            document.getElementById('continueText').textContent = 'Continua';
        });

        // Enter key on username
        usernameInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') document.getElementById('btnContinue').click();
        });

        // Step 2: Passkey authentication
        document.getElementById('btnPasskey').addEventListener('click', async function() {
            hideError();
            const btn = this;
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Attendere...';

            try {
                // Start passkey authentication
                const startRes = await fetch('/api/passkey/login/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: currentUsername })
                });
                const startData = await startRes.json();

                if (!startData.success || startData.error) {
                    showError(startData.error || 'Errore nell avvio passkey');
                    btn.disabled = false;
                    btn.innerHTML = '<i class="fas fa-key me-2"></i>Usa Passkey';
                    return;
                }

                // Parse the options from JSON string
                const options = JSON.parse(startData.options);

                // Convert base64url to ArrayBuffer for WebAuthn API
                options.publicKey.challenge = base64ToArrayBuffer(options.publicKey.challenge);
                if (options.publicKey.allowCredentials) {
                    options.publicKey.allowCredentials = options.publicKey.allowCredentials.map(c => ({
                        ...c,
                        id: base64ToArrayBuffer(c.id)
                    }));
                }

                btn.innerHTML = '<i class="fas fa-fingerprint fa-spin me-2"></i>Conferma...';

                // Call WebAuthn API
                const credential = await navigator.credentials.get(options);

                // Build credential object for server
                const credentialObj = {
                    id: credential.id,
                    rawId: arrayBufferToBase64(credential.rawId),
                    type: credential.type,
                    response: {
                        clientDataJSON: arrayBufferToBase64(credential.response.clientDataJSON),
                        authenticatorData: arrayBufferToBase64(credential.response.authenticatorData),
                        signature: arrayBufferToBase64(credential.response.signature),
                        userHandle: credential.response.userHandle ? arrayBufferToBase64(credential.response.userHandle) : null
                    },
                    clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {}
                };

                // Send to server
                const finishRes = await fetch('/api/passkey/login/finish', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        challengeId: startData.challengeId,
                        credential: JSON.stringify(credentialObj)
                    })
                });
                const finishData = await finishRes.json();

                if (finishData.success) {
                    showSuccess();
                    setTimeout(() => { window.location.href = './home'; }, 1000);
                } else {
                    showError(finishData.error || 'Autenticazione passkey fallita');
                }
            } catch (err) {
                if (err.name === 'NotAllowedError') {
                    showError('Autenticazione annullata');
                } else {
                    console.error('Passkey error:', err);
                    showError('Errore passkey: ' + err.message);
                }
            }

            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-key me-2"></i>Usa Passkey';
        });

        // Use password instead of passkey
        document.getElementById('btnUsePassword').addEventListener('click', function() {
            goToStep('password');
        });

        // Step 3: Password login
        document.getElementById('btnLogin').addEventListener('click', async function() {
            const password = passwordInput.value;
            if (!password || password.length < 8) {
                showError('Password non valida (minimo 8 caratteri)');
                return;
            }

            const btn = this;
            btn.disabled = true;
            document.getElementById('loginSpinner').classList.remove('d-none');
            document.getElementById('loginText').textContent = 'Verifica...';
            hideError();

            try {
                const res = await fetch('/login_check', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        username: currentUsername,
                        password: password,
                        csrf_token: document.getElementById('csrf_token').value
                    })
                });
                const data = await res.json();

                if (data.success) {
                    showSuccess();
                    setTimeout(() => { window.location.href = './home'; }, 1000);
                } else if (data.requires_2fa) {
                    tempPassword = password;
                    goToStep('2fa');
                } else {
                    showError(data.Message || 'Password errata');
                }
            } catch (err) {
                showError('Errore di connessione');
            }

            btn.disabled = false;
            document.getElementById('loginSpinner').classList.add('d-none');
            document.getElementById('loginText').textContent = 'Accedi';
        });

        // Enter key on password
        passwordInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') document.getElementById('btnLogin').click();
        });

        // Step 4: 2FA verification
        document.getElementById('btnVerify2FA').addEventListener('click', async function() {
            const code = otpInput.value.trim();
            if (!code || code.length !== 6) {
                showError('Inserisci un codice a 6 cifre');
                return;
            }

            const btn = this;
            btn.disabled = true;
            document.getElementById('verifySpinner').classList.remove('d-none');
            document.getElementById('verifyText').textContent = 'Verifica...';
            hideError();

            try {
                const res = await fetch('/login_check', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        username: currentUsername,
                        password: tempPassword,
                        totp_code: code,
                        csrf_token: document.getElementById('csrf_token').value
                    })
                });
                const data = await res.json();

                if (data.success) {
                    showSuccess();
                    setTimeout(() => { window.location.href = './home'; }, 1000);
                } else {
                    showError(data.Message || 'Codice non valido');
                }
            } catch (err) {
                showError('Errore di connessione');
            }

            btn.disabled = false;
            document.getElementById('verifySpinner').classList.add('d-none');
            document.getElementById('verifyText').textContent = 'Verifica';
        });

        // Enter key on OTP
        otpInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') document.getElementById('btnVerify2FA').click();
        });

        // Only allow digits in OTP
        otpInput.addEventListener('input', function() {
            this.value = this.value.replace(/[^0-9]/g, '');
        });

        // WebAuthn helper functions
        function base64ToArrayBuffer(base64) {
            const binary = atob(base64.replace(/-/g, '+').replace(/_/g, '/'));
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
            return bytes.buffer;
        }

        function arrayBufferToBase64(buffer) {
            const bytes = new Uint8Array(buffer);
            let binary = '';
            for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
            return btoa(binary).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=/g, '');
        }

        // Focus username on load
        usernameInput.focus();
    </script>
</body>
</html>
""".replace("{{YEAR}}", String.valueOf(year));
    }

    // ============== SETUP.HTML ==============
    public static String getSetupHtml() {
        return """
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Setup Iniziale - FreeBSD Mail Panel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #16213e 0%, #0f3460 50%, #1a1a2e 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .setup-card {
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
            padding: 40px;
            max-width: 500px;
            width: 100%;
        }
        .setup-header {
            text-align: center;
            margin-bottom: 30px;
        }
        .setup-header i {
            font-size: 3rem;
            color: #e94560;
            margin-bottom: 15px;
        }
        .btn-setup {
            background: linear-gradient(90deg, #e94560 0%, #0f3460 100%);
            border: none;
            color: white;
            padding: 12px 30px;
            font-size: 1.1rem;
        }
        .btn-setup:hover {
            opacity: 0.9;
            color: white;
        }
        .info-box {
            background: #f8f9fa;
            border-left: 4px solid #17a2b8;
            padding: 15px;
            margin-bottom: 20px;
            font-size: 0.9rem;
        }
        .auto-badge {
            background: #198754;
            color: white;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
        }
    </style>
</head>
<body>
    <div class="setup-card">
        <div class="setup-header">
            <i class="fas fa-envelope"></i>
            <h2>FreeBSD Mail Panel</h2>
            <p class="text-muted">Configurazione Iniziale</p>
        </div>

        <!-- Main Form -->
        <div id="setupForm">
            <div class="info-box">
                <i class="fas fa-magic me-1"></i>
                <strong>Setup Automatico</strong><br>
                Il pannello configurerà automaticamente:
                <ul class="mb-0 mt-2">
                    <li>Database MySQL <span class="auto-badge">AUTO</span></li>
                    <li>Tabelle e utenti DB <span class="auto-badge">AUTO</span></li>
                    <li>Configurazioni servizi <span class="auto-badge">AUTO</span></li>
                </ul>
            </div>

            <h5 class="mt-4"><i class="fas fa-user-shield me-2"></i>Credenziali Amministratore</h5>
            <div class="mb-3">
                <label class="form-label">Username</label>
                <input type="text" class="form-control" id="adminUser" placeholder="admin" value="admin">
            </div>
            <div class="mb-3">
                <label class="form-label">Password</label>
                <input type="password" class="form-control" id="adminPass" placeholder="Password sicura (min 8 caratteri)">
            </div>
            <div class="mb-3">
                <label class="form-label">Conferma Password</label>
                <input type="password" class="form-control" id="adminPassConfirm" placeholder="Ripeti password">
            </div>

            <h5 class="mt-4"><i class="fas fa-server me-2"></i>Hostname Mail Server</h5>
            <div class="mb-3">
                <div class="form-control bg-light">
                    <strong id="mailHostnameDisplay">{{MAIL_HOSTNAME}}</strong>
                </div>
                <small class="text-muted">Configurato durante l'installazione dal terminale</small>
            </div>

            <button class="btn btn-setup w-100 mt-3" onclick="completeSetup()">
                <i class="fas fa-rocket me-2"></i>Avvia Configurazione
            </button>
        </div>

        <!-- Progress -->
        <div id="progressPanel" class="d-none text-center">
            <div class="spinner-border text-primary mb-3" role="status"></div>
            <p id="progressText">Configurazione automatica in corso...</p>
            <div class="progress mt-3" style="height: 6px;">
                <div class="progress-bar progress-bar-striped progress-bar-animated" id="progressBar" style="width: 0%"></div>
            </div>
            <small class="text-muted mt-2" id="progressStep">Inizializzazione...</small>
        </div>

        <!-- Error -->
        <div id="errorAlert" class="alert alert-danger d-none mt-3"></div>
    </div>

    <input type="hidden" id="csrf_token" value="{{CSRF_TOKEN}}">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function completeSetup() {
            const adminUser = document.getElementById('adminUser').value.trim();
            const adminPass = document.getElementById('adminPass').value;
            const adminPassConfirm = document.getElementById('adminPassConfirm').value;

            // Validazioni
            if (!adminUser) {
                showError('Inserisci un username');
                return;
            }
            if (!adminPass || adminPass.length < 8) {
                showError('La password deve essere di almeno 8 caratteri');
                return;
            }
            if (adminPass !== adminPassConfirm) {
                showError('Le password non corrispondono');
                return;
            }

            // Mostra progress
            document.getElementById('setupForm').classList.add('d-none');
            document.getElementById('progressPanel').classList.remove('d-none');
            hideError();

            // Simula progressi
            let progress = 0;
            const steps = [
                'Configurazione MySQL...',
                'Creazione database...',
                'Creazione tabelle...',
                'Configurazione amministratore...',
                'Finalizzazione...'
            ];

            const interval = setInterval(() => {
                progress += 20;
                document.getElementById('progressBar').style.width = progress + '%';
                document.getElementById('progressStep').textContent = steps[Math.floor(progress/25)] || 'Completamento...';
            }, 500);

            fetch('/api/setup', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action: 'auto_setup',
                    admin_username: adminUser,
                    admin_password: adminPass,
                    csrf_token: document.getElementById('csrf_token').value
                })
            })
            .then(r => r.json())
            .then(data => {
                clearInterval(interval);
                if (data.success) {
                    document.getElementById('progressBar').style.width = '100%';
                    document.getElementById('progressText').innerHTML =
                        '<i class="fas fa-check-circle text-success fa-3x mb-3"></i><br>' +
                        '<strong>Setup Completato!</strong>';
                    document.getElementById('progressStep').textContent = 'Reindirizzamento al login...';
                    setTimeout(() => window.location.href = '/index', 2000);
                } else {
                    document.getElementById('progressPanel').classList.add('d-none');
                    document.getElementById('setupForm').classList.remove('d-none');
                    showError(data.error || 'Errore durante la configurazione');
                }
            })
            .catch(err => {
                clearInterval(interval);
                document.getElementById('progressPanel').classList.add('d-none');
                document.getElementById('setupForm').classList.remove('d-none');
                showError('Errore di connessione: ' + err.message);
            });
        }

        function showError(msg) {
            const alert = document.getElementById('errorAlert');
            alert.textContent = msg;
            alert.classList.remove('d-none');
        }

        function hideError() {
            document.getElementById('errorAlert').classList.add('d-none');
        }
    </script>
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
        return getHead("Dashboard", "home", extraStyles) + """
    <div class="content container mt-4">
        <div class="content-container">
            <div class="welcome-banner">
                <h2><i class="fas fa-envelope-open-text me-2"></i>Mail Server Dashboard</h2>
                <p class="mb-0">FreeBSD 15 - Gestione completa del server mail</p>
            </div>

            <!-- CRITICAL DNS SETUP WARNING -->
            <div class="alert alert-danger mt-4" id="dnsSetupWarning">
                <h5><i class="fas fa-exclamation-triangle me-2"></i>CONFIGURAZIONE DNS ESSENZIALE</h5>
                <p class="mb-2"><strong>Prima di tutto, devi configurare questo record A sul dominio del mail server:</strong></p>
                <div class="bg-white p-3 rounded border mb-3">
                    <table class="table table-sm mb-0">
                        <tr><td width="150"><strong>Dominio Cloudflare:</strong></td><td><code id="mailServerDomain">-</code></td></tr>
                        <tr><td><strong>Type:</strong></td><td>A</td></tr>
                        <tr><td><strong>Name:</strong></td><td><code id="mailServerSubdomain">mail</code></td></tr>
                        <tr><td><strong>IPv4 address:</strong></td><td><code id="serverIpDisplay">-</code></td></tr>
                        <tr><td><strong>Proxy status:</strong></td><td><span class="text-danger"><strong>DNS only (nuvola GRIGIA!)</strong></span></td></tr>
                        <tr><td><strong>TTL:</strong></td><td>Auto</td></tr>
                    </table>
                </div>
                <div class="alert alert-warning mb-0">
                    <i class="fas fa-info-circle me-2"></i>
                    <strong>Se non configuri questo record A, tutto il resto è INUTILE!</strong><br>
                    Il mail server hostname <code id="mailHostnameDisplay">-</code> deve puntare all'IP del server.<br>
                    <small class="text-muted">Vai su Cloudflare → Dominio indicato sopra → DNS → Aggiungi record A</small>
                </div>
            </div>

            <!-- SSL CERTIFICATE MISMATCH WARNING -->
            <div class="alert alert-danger mt-3" id="sslMismatchWarning" style="display:none;">
                <h5><i class="fas fa-shield-alt me-2"></i>Certificato SSL Non Allineato</h5>
                <p class="mb-1">
                    Il certificato SSL attuale e' emesso per <strong><code id="sslCnDisplay">-</code></strong>,
                    ma l'hostname del mail server e' <strong><code id="sslExpectedDisplay">-</code></strong>.
                </p>
                <p class="mb-1">I client email (Thunderbird, Outlook, ecc.) mostreranno errori di sicurezza finche' il certificato non viene aggiornato.</p>
                <hr>
                <p class="mb-0">
                    <i class="fas fa-arrow-right me-2"></i>Vai nella sezione <a href="/ssl"><strong>SSL</strong></a> e genera un nuovo certificato per <code id="sslNewHostDisplay">-</code>.
                </p>
            </div>

            <!-- DNS VERIFICATION STATUS -->
            <div class="card mt-3 mb-4" id="dnsVerificationCard" style="display:none;">
                <div class="card-header" id="dnsVerificationHeader">
                    <i class="fas fa-stethoscope me-2"></i>Verifica DNS in Tempo Reale
                </div>
                <div class="card-body">
                    <div id="dnsVerificationLoading" class="text-center py-2">
                        <i class="fas fa-spinner fa-spin me-2"></i>Verifica record DNS in corso...
                    </div>
                    <div id="dnsVerificationResults" style="display:none;">
                        <table class="table table-sm mb-2">
                            <thead><tr><th>Record</th><th>Nome</th><th>Valore Attuale</th><th>Valore Atteso</th><th>Stato</th></tr></thead>
                            <tbody id="dnsVerificationBody"></tbody>
                        </table>
                        <div id="dnsVerificationSummary"></div>
                        <button class="btn btn-outline-primary btn-sm mt-2" onclick="runDnsVerification()">
                            <i class="fas fa-sync me-1"></i>Ricontrolla
                        </button>
                    </div>
                </div>
            </div>

            <h3><i class="fas fa-chart-line me-2"></i>Panoramica</h3>
            <div class="row">
                <div class="col-md-4 mb-3">
                    <div class="card stat-card"><div class="card-body"><h5 class="card-title"><i class="fas fa-globe me-2"></i>Domini</h5><p class="card-text" id="domainCount">Totale: -</p></div></div>
                </div>
                <div class="col-md-4 mb-3">
                    <div class="card stat-card"><div class="card-body"><h5 class="card-title"><i class="fas fa-inbox me-2"></i>Caselle</h5><p class="card-text" id="mailboxCount">Totale: -</p></div></div>
                </div>
                <div class="col-md-4 mb-3">
                    <div class="card stat-card"><div class="card-body"><h5 class="card-title"><i class="fas fa-share me-2"></i>Alias</h5><p class="card-text" id="aliasCount">Totale: -</p></div></div>
                </div>
            </div>

            <h3 class="mt-4"><i class="fas fa-server me-2"></i>Servizi Mail</h3>
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead class="table-light"><tr><th>Servizio</th><th>Stato</th><th>Azioni</th></tr></thead>
                    <tbody>
                        <tr>
                            <td><i class="fas fa-paper-plane me-2"></i>Postfix (SMTP)</td>
                            <td><span class="badge bg-secondary" id="postfix-status">-</span></td>
                            <td>
                                <button class="btn btn-success action-btn" onclick="serviceAction('postfix','start')"><i class="fas fa-play"></i></button>
                                <button class="btn btn-warning action-btn" onclick="serviceAction('postfix','restart')"><i class="fas fa-redo"></i></button>
                                <button class="btn btn-danger action-btn" onclick="serviceAction('postfix','stop')"><i class="fas fa-stop"></i></button>
                            </td>
                        </tr>
                        <tr>
                            <td><i class="fas fa-inbox me-2"></i>Dovecot (IMAP/POP3)</td>
                            <td><span class="badge bg-secondary" id="dovecot-status">-</span></td>
                            <td>
                                <button class="btn btn-success action-btn" onclick="serviceAction('dovecot','start')"><i class="fas fa-play"></i></button>
                                <button class="btn btn-warning action-btn" onclick="serviceAction('dovecot','restart')"><i class="fas fa-redo"></i></button>
                                <button class="btn btn-danger action-btn" onclick="serviceAction('dovecot','stop')"><i class="fas fa-stop"></i></button>
                            </td>
                        </tr>
                        <tr>
                            <td><i class="fas fa-shield-alt me-2"></i>Rspamd (Anti-Spam)</td>
                            <td><span class="badge bg-secondary" id="rspamd-status">-</span></td>
                            <td>
                                <button class="btn btn-success action-btn" onclick="serviceAction('rspamd','start')"><i class="fas fa-play"></i></button>
                                <button class="btn btn-warning action-btn" onclick="serviceAction('rspamd','restart')"><i class="fas fa-redo"></i></button>
                                <button class="btn btn-danger action-btn" onclick="serviceAction('rspamd','stop')"><i class="fas fa-stop"></i></button>
                            </td>
                        </tr>
                        <tr>
                            <td><i class="fas fa-bug me-2"></i>ClamAV (Antivirus)</td>
                            <td><span class="badge bg-secondary" id="clamav-status">-</span></td>
                            <td>
                                <button class="btn btn-success action-btn" onclick="serviceAction('clamav','start')"><i class="fas fa-play"></i></button>
                                <button class="btn btn-warning action-btn" onclick="serviceAction('clamav','restart')"><i class="fas fa-redo"></i></button>
                                <button class="btn btn-danger action-btn" onclick="serviceAction('clamav','stop')"><i class="fas fa-stop"></i></button>
                            </td>
                        </tr>
                        <tr>
                            <td><i class="fas fa-envelope-open-text me-2"></i>Roundcube (Webmail)</td>
                            <td><span class="badge bg-secondary" id="roundcube-status">-</span></td>
                            <td>
                                <button class="btn btn-success action-btn" onclick="serviceAction('roundcube','start')"><i class="fas fa-play"></i></button>
                                <button class="btn btn-warning action-btn" onclick="serviceAction('roundcube','restart')"><i class="fas fa-redo"></i></button>
                                <button class="btn btn-danger action-btn" onclick="serviceAction('roundcube','stop')"><i class="fas fa-stop"></i></button>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <h3 class="mt-4"><i class="fas fa-check-circle me-2"></i>Componenti Installati</h3>
            <div class="row" id="installedComponents">
                <div class="col-md-3 mb-2"><span class="badge bg-secondary w-100 p-2" id="comp-postfix">Postfix: -</span></div>
                <div class="col-md-3 mb-2"><span class="badge bg-secondary w-100 p-2" id="comp-dovecot">Dovecot: -</span></div>
                <div class="col-md-3 mb-2"><span class="badge bg-secondary w-100 p-2" id="comp-rspamd">Rspamd: -</span></div>
                <div class="col-md-3 mb-2"><span class="badge bg-secondary w-100 p-2" id="comp-roundcube">Roundcube: -</span></div>
            </div>
        </div>
    </div>
""" + getFooterSection() + getScriptStart() + """
        function serviceAction(service, action) {
            fetch('/api/service', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ service: service, action: action, csrf_token: csrfToken })
            })
            .then(r => r.json())
            .then(data => {
                if (data.csrf_token) csrfToken = data.csrf_token;
                alert(data.success ? 'Operazione completata' : 'Errore: ' + (data.message || 'sconosciuto'));
                checkStatus();
            });
        }

        function checkStatus() {
            fetch('/api/status').then(r => r.json()).then(data => {
                ['postfix','dovecot','rspamd','clamav','roundcube'].forEach(svc => {
                    const el = document.getElementById(svc + '-status');
                    if (!el) return;
                    const running = data[svc];
                    el.textContent = running ? 'Attivo' : 'Fermo';
                    el.className = 'badge ' + (running ? 'bg-success' : 'bg-danger');
                });

                // Components
                ['postfix','dovecot','rspamd','roundcube'].forEach(comp => {
                    const el = document.getElementById('comp-' + comp);
                    const installed = data['installed_' + comp];
                    el.textContent = comp.charAt(0).toUpperCase() + comp.slice(1) + ': ' + (installed ? 'Installato' : 'Non installato');
                    el.className = 'badge w-100 p-2 ' + (installed ? 'bg-success' : 'bg-warning');
                });

                // Stats
                document.getElementById('domainCount').textContent = 'Totale: ' + (data.domains || 0);
                document.getElementById('mailboxCount').textContent = 'Totale: ' + (data.mailboxes || 0);
                document.getElementById('aliasCount').textContent = 'Totale: ' + (data.aliases || 0);

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
                    dnsWarning.style.display = 'block';
                } else {
                    dnsWarning.style.display = 'none';
                }

                // SSL Certificate Mismatch Warning
                const sslWarning = document.getElementById('sslMismatchWarning');
                if (data.ssl_match === false && mailHostname) {
                    const sslCn = data.ssl_cn || 'self-signed/sconosciuto';
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
                    document.getElementById('dnsVerificationBody').innerHTML =
                        '<tr><td colspan="5" class="text-danger">Errore: ' + (data.error || 'sconosciuto') + '</td></tr>';
                    return;
                }

                // Render results table
                const tbody = document.getElementById('dnsVerificationBody');
                tbody.innerHTML = data.checks.map(c => {
                    const icon = c.passed
                        ? '<i class="fas fa-check-circle text-success"></i>'
                        : '<i class="fas fa-times-circle text-danger"></i>';
                    return '<tr>' +
                        '<td><code>' + c.type + '</code></td>' +
                        '<td><small>' + c.name + '</small></td>' +
                        '<td><small><code>' + c.current + '</code></small></td>' +
                        '<td><small><code>' + c.expected + '</code></small></td>' +
                        '<td class="text-center">' + icon + '</td></tr>';
                }).join('');

                // Summary and card header color
                const header = document.getElementById('dnsVerificationHeader');
                const summary = document.getElementById('dnsVerificationSummary');
                const hostname = data.hostname || '';
                const domain = hostname.indexOf('.') > 0 ? hostname.substring(hostname.indexOf('.') + 1) : hostname;
                const subdomain = hostname.indexOf('.') > 0 ? hostname.substring(0, hostname.indexOf('.')) : hostname;

                if (data.all_passed) {
                    header.className = 'card-header bg-success text-white';
                    header.innerHTML = '<i class="fas fa-check-circle me-2"></i>DNS Configurato Correttamente';
                    summary.innerHTML = '<div class="alert alert-success mb-0 py-2">' +
                        '<i class="fas fa-check-circle me-2"></i>Tutti i record DNS essenziali sono configurati correttamente.<br>' +
                        '<small class="mt-1 d-block"><i class="fas fa-arrow-right me-1"></i>Per i record completi (SPF, DKIM, DMARC, autoconfig, SRV, MTA-STS) vai nella sezione ' +
                        '<a href="/dns" class="fw-bold">DNS</a>.</small></div>';
                } else {
                    header.className = 'card-header bg-danger text-white';
                    header.innerHTML = '<i class="fas fa-exclamation-triangle me-2"></i>DNS Da Configurare';
                    const failed = data.checks.filter(c => !c.passed);
                    let advice = '';

                    failed.forEach(c => {
                        if (c.type === 'A') {
                            advice += '<div class="card border-danger mb-2"><div class="card-body py-2 px-3">' +
                                '<h6 class="text-danger mb-2"><i class="fas fa-times-circle me-1"></i>Record A mancante o errato</h6>' +
                                '<p class="mb-1"><strong>Cosa fare:</strong> Vai nel pannello del tuo provider DNS (es. Cloudflare) e crea/modifica un record A:</p>' +
                                '<table class="table table-sm table-bordered mb-2" style="max-width:500px">' +
                                '<tr><td width="100"><strong>Type</strong></td><td><code>A</code></td></tr>' +
                                '<tr><td><strong>Name</strong></td><td><code>' + subdomain + '</code></td></tr>' +
                                '<tr><td><strong>IPv4</strong></td><td><code>' + c.expected + '</code></td></tr>' +
                                '<tr><td><strong>Proxy</strong></td><td><span class="text-danger fw-bold">DNS only (nuvola GRIGIA)</span></td></tr>' +
                                '<tr><td><strong>TTL</strong></td><td>Auto</td></tr>' +
                                '</table>' +
                                '<small class="text-muted"><i class="fas fa-info-circle me-1"></i>Cloudflare: Dashboard &rarr; <code>' + domain + '</code> &rarr; DNS &rarr; Aggiungi record</small>' +
                                '</div></div>';
                        } else if (c.type === 'MX') {
                            advice += '<div class="card border-danger mb-2"><div class="card-body py-2 px-3">' +
                                '<h6 class="text-danger mb-2"><i class="fas fa-times-circle me-1"></i>Record MX mancante o errato</h6>' +
                                '<p class="mb-1"><strong>Cosa fare:</strong> Crea/modifica un record MX sul dominio:</p>' +
                                '<table class="table table-sm table-bordered mb-2" style="max-width:500px">' +
                                '<tr><td width="100"><strong>Type</strong></td><td><code>MX</code></td></tr>' +
                                '<tr><td><strong>Name</strong></td><td><code>@</code> (oppure <code>' + c.name + '</code>)</td></tr>' +
                                '<tr><td><strong>Server</strong></td><td><code>' + hostname + '</code></td></tr>' +
                                '<tr><td><strong>Priorita</strong></td><td><code>10</code></td></tr>' +
                                '<tr><td><strong>TTL</strong></td><td>Auto</td></tr>' +
                                '</table>' +
                                '<small class="text-muted"><i class="fas fa-info-circle me-1"></i>Cloudflare: Dashboard &rarr; <code>' + c.name + '</code> &rarr; DNS &rarr; Aggiungi record MX</small>' +
                                '</div></div>';
                        } else if (c.type === 'PTR') {
                            advice += '<div class="card border-warning mb-2"><div class="card-body py-2 px-3">' +
                                '<h6 class="text-warning mb-2"><i class="fas fa-exclamation-triangle me-1"></i>Record PTR (Reverse DNS) non configurato</h6>' +
                                '<p class="mb-1"><strong>Cosa fare:</strong> Il PTR si configura dal <strong>pannello del provider hosting</strong>, NON da Cloudflare.</p>' +
                                '<table class="table table-sm table-bordered mb-2" style="max-width:500px">' +
                                '<tr><td width="100"><strong>IP</strong></td><td><code>' + c.name + '</code></td></tr>' +
                                '<tr><td><strong>PTR</strong></td><td><code>' + hostname + '</code></td></tr>' +
                                '</table>' +
                                '<p class="mb-0"><strong>Come fare in base al provider:</strong></p>' +
                                '<ul class="mb-0 small">' +
                                '<li><strong>Hetzner:</strong> Cloud Console &rarr; Server &rarr; Networking &rarr; Reverse DNS &rarr; Modifica</li>' +
                                '<li><strong>OVH:</strong> Manager &rarr; Server &rarr; IP &rarr; Icona ingranaggio &rarr; Modifica reverse</li>' +
                                '<li><strong>DigitalOcean:</strong> Rinomina il Droplet con il FQDN (<code>' + hostname + '</code>)</li>' +
                                '<li><strong>Vultr:</strong> Products &rarr; Server &rarr; Settings &rarr; IPv4 &rarr; Reverse DNS</li>' +
                                '<li><strong>Contabo:</strong> Customer Control Panel &rarr; Reverse DNS Management</li>' +
                                '</ul>' +
                                '</div></div>';
                        }
                    });

                    advice += '<div class="mt-2">' +
                        '<a href="/dns" class="btn btn-primary btn-sm"><i class="fas fa-list me-1"></i>Vedi tutti i record DNS da configurare (SPF, DKIM, DMARC, ...)</a>' +
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
                    '<tr><td colspan="5" class="text-muted">Verifica non disponibile</td></tr>';
            });
        }

        function checkRoundcubeDomainDns() {
            fetch('/api/roundcube-domain')
                .then(r => r.json())
                .then(data => {
                    if (!data.success || !data.domain || data.domain === 'Non configurato' || data.domain === '') return;
                    const tbody = document.getElementById('dnsVerificationBody');
                    let icon, expectedCol;
                    if (data.dns_ok && data.dns_proxied) {
                        icon = '<i class="fas fa-cloud text-info" title="Proxy/CDN"></i>';
                        expectedCol = escapeHtml(data.server_ip || 'IP server') + ' <small class="text-muted">(proxy OK)</small>';
                    } else if (data.dns_ok) {
                        icon = '<i class="fas fa-check-circle text-success"></i>';
                        expectedCol = escapeHtml(data.server_ip || 'IP server');
                    } else {
                        icon = '<i class="fas fa-times-circle text-danger"></i>';
                        expectedCol = escapeHtml(data.server_ip || 'IP server');
                    }
                    tbody.innerHTML += '<tr>' +
                        '<td><code>A</code> <small class="text-muted">(Webmail)</small></td>' +
                        '<td><small>' + escapeHtml(data.domain) + '</small></td>' +
                        '<td><small><code>' + escapeHtml(data.dns_result || 'Non trovato') + '</code></small></td>' +
                        '<td><small><code>' + expectedCol + '</code></small></td>' +
                        '<td class="text-center">' + icon + '</td></tr>';

                    if (!data.dns_ok) {
                        const summary = document.getElementById('dnsVerificationSummary');
                        const rcSub = data.domain.indexOf('.') > 0 ? data.domain.substring(0, data.domain.indexOf('.')) : data.domain;
                        const rcBaseDomain = data.domain.indexOf('.') > 0 ? data.domain.substring(data.domain.indexOf('.') + 1) : data.domain;
                        summary.innerHTML += '<div class="card border-danger mb-2 mt-2"><div class="card-body py-2 px-3">' +
                            '<h6 class="text-danger mb-2"><i class="fas fa-envelope-open-text me-1"></i>Record A per Roundcube (Webmail) mancante</h6>' +
                            '<p class="mb-1"><strong>Cosa fare:</strong> Crea un record A per il dominio della webmail:</p>' +
                            '<table class="table table-sm table-bordered mb-2" style="max-width:500px">' +
                            '<tr><td width="100"><strong>Type</strong></td><td><code>A</code></td></tr>' +
                            '<tr><td><strong>Name</strong></td><td><code>' + rcSub + '</code></td></tr>' +
                            '<tr><td><strong>IPv4</strong></td><td><code>' + escapeHtml(data.server_ip || 'IP_SERVER') + '</code></td></tr>' +
                            '<tr><td><strong>Proxy</strong></td><td>Nuvola arancione o grigia (entrambe OK per webmail)</td></tr>' +
                            '<tr><td><strong>TTL</strong></td><td>Auto</td></tr>' +
                            '</table>' +
                            '<small class="text-muted"><i class="fas fa-info-circle me-1"></i>Cloudflare: Dashboard &rarr; <code>' + rcBaseDomain + '</code> &rarr; DNS &rarr; Aggiungi record</small>' +
                            '</div></div>';

                        // Update header to danger if not already
                        const header = document.getElementById('dnsVerificationHeader');
                        if (!header.className.includes('bg-danger')) {
                            header.className = 'card-header bg-danger text-white';
                            header.innerHTML = '<i class="fas fa-exclamation-triangle me-2"></i>DNS Da Configurare';
                        }
                    }
                })
                .catch(() => {});
        }

        checkStatus();
""" + getScriptEnd();
    }

    // ============== DOMAINS.HTML ==============
    public static String getDomainsHtml() {
        return getHead("Domini", "") + getNavbar("domains") + """
    <div class="content container mt-4">
        <div class="content-container">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h2><i class="fas fa-globe me-2"></i>Domini Mail</h2>
                <button class="btn btn-mail" data-bs-toggle="modal" data-bs-target="#addDomainModal"><i class="fas fa-plus me-1"></i>Aggiungi Dominio</button>
            </div>

            <div class="table-responsive">
                <table class="table table-hover">
                    <thead class="table-light">
                        <tr><th>Dominio</th><th>Descrizione</th><th>Caselle</th><th>Alias</th><th>DKIM</th><th>Azioni</th></tr>
                    </thead>
                    <tbody id="domainsTable">
                        <tr><td colspan="6" class="text-center">Caricamento...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Add Domain Modal -->
    <div class="modal fade" id="addDomainModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header"><h5 class="modal-title">Aggiungi Dominio</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
                <div class="modal-body">
                    <form id="addDomainForm">
                        <div class="mb-3">
                            <label class="form-label">Nome Dominio</label>
                            <input type="text" class="form-control" id="domainName" placeholder="example.com" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Descrizione (opzionale)</label>
                            <input type="text" class="form-control" id="domainDesc" placeholder="Mail aziendale">
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Annulla</button>
                    <button type="button" class="btn btn-mail" onclick="addDomain()">Aggiungi</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Edit Description Modal -->
    <div class="modal fade" id="editDescModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header"><h5 class="modal-title"><i class="fas fa-edit me-2"></i>Modifica Descrizione</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
                <div class="modal-body">
                    <input type="hidden" id="editDomainId">
                    <div class="mb-3">
                        <label class="form-label">Dominio</label>
                        <input type="text" class="form-control" id="editDomainName" readonly disabled>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Descrizione</label>
                        <input type="text" class="form-control" id="editDomainDesc" placeholder="Mail aziendale">
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Annulla</button>
                    <button type="button" class="btn btn-mail" onclick="saveDomainDesc()">Salva</button>
                </div>
            </div>
        </div>
    </div>

""" + getFooter() + """
    <script>
        let csrfToken = document.getElementById('csrf_token').value;

        function loadDomains() {
            fetch('/api/domains').then(r => r.json()).then(data => {
                const tbody = document.getElementById('domainsTable');
                if (!data.domains || data.domains.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" class="text-center">Nessun dominio. Clicca "Aggiungi Dominio" per crearne uno.</td></tr>';
                    return;
                }
                tbody.innerHTML = data.domains.map(d => `
                    <tr>
                        <td><strong>${d.domain}</strong></td>
                        <td>${d.description || '-'}</td>
                        <td><span class="badge bg-info">${d.mailbox_count || 0}</span></td>
                        <td><span class="badge bg-info">${d.alias_count || 0}</span></td>
                        <td>${d.has_dkim ? '<span class="badge bg-success">Attivo</span>' : '<span class="badge bg-warning">Non configurato</span>'}</td>
                        <td>
                            <button class="btn btn-sm btn-secondary" onclick="editDomain(${d.id}, '${d.domain}', '${(d.description || '').replace(/'/g, "\\'")}')"><i class="fas fa-edit"></i></button>
                            <button class="btn btn-sm btn-primary" onclick="viewDns('${d.domain}')"><i class="fas fa-server"></i> DNS</button>
                            <button class="btn btn-sm btn-danger" onclick="deleteDomain(${d.id})"><i class="fas fa-trash"></i></button>
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
                    alert('Errore: ' + (data.error || 'sconosciuto'));
                }
            });
        }

        function deleteDomain(id) {
            if (!confirm('Eliminare questo dominio e tutte le sue caselle?')) return;
            fetch('/api/domains?id=' + id, { method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ csrf_token: csrfToken }) })
                .then(() => loadDomains());
        }

        function viewDns(domain) {
            window.location.href = '/dns?domain=' + domain;
        }

        function editDomain(id, domain, desc) {
            document.getElementById('editDomainId').value = id;
            document.getElementById('editDomainName').value = domain;
            document.getElementById('editDomainDesc').value = desc;
            new bootstrap.Modal(document.getElementById('editDescModal')).show();
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
                    alert('Errore: ' + (data.error || 'sconosciuto'));
                }
            });
        }

""" + getLogoutScript() + """
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
                    <h5 class="modal-title"><i class="fas fa-mobile-alt me-2"></i>Configurazione Client Email</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">

                    <!-- Box credenziali con copia-incolla ovunque -->
                    <div class="card mb-3 border-primary">
                        <div class="card-header bg-primary text-white"><i class="fas fa-key me-2"></i>Credenziali</div>
                        <div class="card-body">
                            <div class="mb-2">
                                <label class="form-label small fw-bold mb-1">Username (email completa)</label>
                                <div class="input-group input-group-sm">
                                    <input type="text" class="form-control font-monospace" id="cfgEmailField" readonly>
                                    <button class="btn btn-outline-secondary" type="button" onclick="copyInputValue('cfgEmailField')" title="Copia"><i class="fas fa-copy"></i></button>
                                </div>
                            </div>
                            <div class="mb-2">
                                <label class="form-label small fw-bold mb-1">Password</label>
                                <div class="input-group input-group-sm">
                                    <input type="password" class="form-control font-monospace" id="cfgPasswordField" value="" placeholder="Non disponibile (vault vuoto per questa casella)" readonly>
                                    <button class="btn btn-outline-secondary" type="button" id="cfgPasswordToggleBtn" onclick="toggleCfgPasswordVisibility()" title="Mostra/nascondi" disabled><i class="fas fa-eye"></i></button>
                                    <button class="btn btn-outline-secondary" type="button" id="cfgPasswordCopyBtn" onclick="copyInputValue('cfgPasswordField')" title="Copia" disabled><i class="fas fa-copy"></i></button>
                                    <button class="btn btn-warning" type="button" id="cfgPasswordRevealBtn" onclick="revealCfgPassword()" title="Recupera dal vault"><i class="fas fa-unlock me-1"></i>Rivela</button>
                                </div>
                                <small class="text-muted" id="cfgPasswordHint">Clicca "Rivela" per recuperare la password dal vault del pannello. L'operazione viene registrata nell'audit log.</small>
                            </div>
                        </div>
                    </div>

                    <ul class="nav nav-tabs mb-3" id="configTabs" role="tablist">
                        <li class="nav-item" role="presentation">
                            <button class="nav-link active" data-bs-toggle="tab" data-bs-target="#configGeneral">Generale</button>
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
                            <h6 class="mb-2 text-success"><i class="fas fa-inbox me-1"></i>Posta in Arrivo — IMAP (consigliato)</h6>
                            <div class="row g-2 mb-3">
                                <div class="col-md-8"><label class="form-label small mb-1">Server</label>
                                    <div class="input-group input-group-sm"><input type="text" class="form-control font-monospace" id="cfgImapServer" readonly><button class="btn btn-outline-secondary" onclick="copyInputValue('cfgImapServer')"><i class="fas fa-copy"></i></button></div>
                                </div>
                                <div class="col-md-2"><label class="form-label small mb-1">Porta</label>
                                    <div class="input-group input-group-sm"><input type="text" class="form-control" value="993" id="cfgImapPort" readonly><button class="btn btn-outline-secondary" onclick="copyInputValue('cfgImapPort')"><i class="fas fa-copy"></i></button></div>
                                </div>
                                <div class="col-md-2"><label class="form-label small mb-1">Sicurezza</label>
                                    <input type="text" class="form-control form-control-sm" value="SSL/TLS" readonly>
                                </div>
                            </div>

                            <h6 class="mb-2 text-secondary"><i class="fas fa-inbox me-1"></i>Posta in Arrivo — POP3 (alternativa)</h6>
                            <div class="row g-2 mb-3">
                                <div class="col-md-8"><label class="form-label small mb-1">Server</label>
                                    <div class="input-group input-group-sm"><input type="text" class="form-control font-monospace" id="cfgPop3Server" readonly><button class="btn btn-outline-secondary" onclick="copyInputValue('cfgPop3Server')"><i class="fas fa-copy"></i></button></div>
                                </div>
                                <div class="col-md-2"><label class="form-label small mb-1">Porta</label>
                                    <div class="input-group input-group-sm"><input type="text" class="form-control" value="995" id="cfgPop3Port" readonly><button class="btn btn-outline-secondary" onclick="copyInputValue('cfgPop3Port')"><i class="fas fa-copy"></i></button></div>
                                </div>
                                <div class="col-md-2"><label class="form-label small mb-1">Sicurezza</label>
                                    <input type="text" class="form-control form-control-sm" value="SSL/TLS" readonly>
                                </div>
                            </div>

                            <h6 class="mb-2 text-primary"><i class="fas fa-paper-plane me-1"></i>Posta in Uscita — SMTP</h6>
                            <div class="row g-2 mb-2">
                                <div class="col-md-8"><label class="form-label small mb-1">Server</label>
                                    <div class="input-group input-group-sm"><input type="text" class="form-control font-monospace" id="cfgSmtpServer" readonly><button class="btn btn-outline-secondary" onclick="copyInputValue('cfgSmtpServer')"><i class="fas fa-copy"></i></button></div>
                                </div>
                                <div class="col-md-2"><label class="form-label small mb-1">Porta</label>
                                    <div class="input-group input-group-sm"><input type="text" class="form-control" value="587" id="cfgSmtpPort" readonly><button class="btn btn-outline-secondary" onclick="copyInputValue('cfgSmtpPort')"><i class="fas fa-copy"></i></button></div>
                                </div>
                                <div class="col-md-2"><label class="form-label small mb-1">Sicurezza</label>
                                    <input type="text" class="form-control form-control-sm" value="STARTTLS" readonly>
                                </div>
                            </div>
                            <small class="text-muted"><i class="fas fa-info-circle me-1"></i>Autenticazione: <strong>Password normale</strong>.</small>
                        </div>

                        <!-- ===== Tab OUTLOOK ===== -->
                        <div class="tab-pane fade" id="configOutlook">
                            <h6><i class="fab fa-microsoft me-2"></i>Microsoft Outlook</h6>
                            <ol class="mt-3 small">
                                <li class="mb-2">Apri Outlook → <strong>File → Aggiungi Account</strong>, inserisci l'email e seleziona <strong>IMAP</strong></li>
                                <li class="mb-3">Inserisci questi dati (clicca 📋 per copiare):
                                    <table class="table table-sm table-bordered mt-2 mb-0">
                                        <tr><td class="fw-bold" style="width:30%">Server IMAP</td><td><div class="input-group input-group-sm"><input type="text" class="form-control font-monospace" id="cfgOutlookImap" readonly><button class="btn btn-outline-secondary" onclick="copyInputValue('cfgOutlookImap')"><i class="fas fa-copy"></i></button></div></td></tr>
                                        <tr><td class="fw-bold">Porta IMAP / Sicurezza</td><td><code>993 / SSL-TLS</code></td></tr>
                                        <tr><td class="fw-bold">Server SMTP</td><td><div class="input-group input-group-sm"><input type="text" class="form-control font-monospace" id="cfgOutlookSmtp" readonly><button class="btn btn-outline-secondary" onclick="copyInputValue('cfgOutlookSmtp')"><i class="fas fa-copy"></i></button></div></td></tr>
                                        <tr><td class="fw-bold">Porta SMTP / Sicurezza</td><td><code>587 / STARTTLS</code></td></tr>
                                        <tr><td class="fw-bold">Username</td><td><div class="input-group input-group-sm"><input type="text" class="form-control font-monospace cfg-shared-email" readonly><button class="btn btn-outline-secondary" onclick="copySharedField(this)"><i class="fas fa-copy"></i></button></div></td></tr>
                                        <tr><td class="fw-bold">Password</td><td><small class="text-muted">vedi sezione Credenziali in alto</small></td></tr>
                                    </table>
                                </li>
                                <li>Conferma e attendi la verifica della connessione</li>
                            </ol>
                        </div>

                        <!-- ===== Tab APPLE ===== -->
                        <div class="tab-pane fade" id="configApple">
                            <h6><i class="fab fa-apple me-2"></i>iPhone / iPad / Mac</h6>
                            <ol class="mt-3 small">
                                <li class="mb-2"><strong>Impostazioni → Mail → Account → Aggiungi Account → Altro → Aggiungi account Mail</strong></li>
                                <li class="mb-2">Inserisci Nome, Email e Password, poi seleziona <strong>IMAP</strong></li>
                                <li class="mb-3">Imposta i seguenti dati (clicca 📋 per copiare):
                                    <table class="table table-sm table-bordered mt-2 mb-0">
                                        <tr><td class="fw-bold" style="width:35%">Server posta in arrivo (IMAP)</td><td><div class="input-group input-group-sm"><input type="text" class="form-control font-monospace" id="cfgAppleImap" readonly><button class="btn btn-outline-secondary" onclick="copyInputValue('cfgAppleImap')"><i class="fas fa-copy"></i></button></div></td></tr>
                                        <tr><td class="fw-bold">Server posta in uscita (SMTP)</td><td><div class="input-group input-group-sm"><input type="text" class="form-control font-monospace" id="cfgAppleSmtp" readonly><button class="btn btn-outline-secondary" onclick="copyInputValue('cfgAppleSmtp')"><i class="fas fa-copy"></i></button></div></td></tr>
                                        <tr><td class="fw-bold">Username</td><td><div class="input-group input-group-sm"><input type="text" class="form-control font-monospace cfg-shared-email" readonly><button class="btn btn-outline-secondary" onclick="copySharedField(this)"><i class="fas fa-copy"></i></button></div></td></tr>
                                        <tr><td class="fw-bold">Password</td><td><small class="text-muted">vedi sezione Credenziali in alto</small></td></tr>
                                    </table>
                                </li>
                                <li>Salva e attendi la verifica dell'account</li>
                            </ol>
                        </div>

                        <!-- ===== Tab ANDROID ===== -->
                        <div class="tab-pane fade" id="configAndroid">
                            <h6><i class="fab fa-android me-2"></i>Android (Gmail App)</h6>
                            <ol class="mt-3 small">
                                <li class="mb-2">Apri Gmail → <strong>Impostazioni → Aggiungi account → Altro</strong></li>
                                <li class="mb-2">Inserisci l'email e seleziona <strong>Personale (IMAP)</strong></li>
                                <li class="mb-3">Imposta i seguenti dati (clicca 📋 per copiare):
                                    <table class="table table-sm table-bordered mt-2 mb-0">
                                        <tr><td class="fw-bold" style="width:35%">Server in arrivo</td><td><div class="input-group input-group-sm"><input type="text" class="form-control font-monospace" id="cfgAndroidImap" readonly><button class="btn btn-outline-secondary" onclick="copyInputValue('cfgAndroidImap')"><i class="fas fa-copy"></i></button></div></td></tr>
                                        <tr><td class="fw-bold">Porta in arrivo / Sicurezza</td><td><code>993 / SSL</code></td></tr>
                                        <tr><td class="fw-bold">Server in uscita</td><td><div class="input-group input-group-sm"><input type="text" class="form-control font-monospace" id="cfgAndroidSmtp" readonly><button class="btn btn-outline-secondary" onclick="copyInputValue('cfgAndroidSmtp')"><i class="fas fa-copy"></i></button></div></td></tr>
                                        <tr><td class="fw-bold">Porta in uscita / Sicurezza</td><td><code>587 / STARTTLS</code></td></tr>
                                        <tr><td class="fw-bold">Username</td><td><div class="input-group input-group-sm"><input type="text" class="form-control font-monospace cfg-shared-email" readonly><button class="btn btn-outline-secondary" onclick="copySharedField(this)"><i class="fas fa-copy"></i></button></div></td></tr>
                                        <tr><td class="fw-bold">Password</td><td><small class="text-muted">vedi sezione Credenziali in alto</small></td></tr>
                                    </table>
                                </li>
                                <li>Completa la configurazione</li>
                            </ol>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Chiudi</button>
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
                    <h5 class="modal-title"><i class="fas fa-magic me-2"></i>Generatore Password</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <!-- Tipo -->
                    <div class="mb-3">
                        <label class="form-label small fw-bold">Tipo</label>
                        <div class="border rounded p-2">
                            <div class="form-check">
                                <input class="form-check-input pwgen-type" type="radio" name="pwgenType" id="pwgenTypeSay" value="easy_to_say">
                                <label class="form-check-label" for="pwgenTypeSay">
                                    <strong>Facile da dettare</strong> <small class="text-muted">— solo lettere (no numeri/simboli)</small>
                                </label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input pwgen-type" type="radio" name="pwgenType" id="pwgenTypeRead" value="easy_to_read" checked>
                                <label class="form-check-label" for="pwgenTypeRead">
                                    <strong>Facile da leggere/copiare</strong> <small class="text-muted">— niente caratteri ambigui (0/O, 1/l/I) né simboli problematici</small>
                                </label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input pwgen-type" type="radio" name="pwgenType" id="pwgenTypeAll" value="all_chars">
                                <label class="form-check-label" for="pwgenTypeAll">
                                    <strong>Tutti i caratteri</strong> <small class="text-muted">— massima entropia (anche simboli come ?/=/&)</small>
                                </label>
                            </div>
                        </div>
                    </div>

                    <!-- Lunghezza -->
                    <div class="row g-3 mb-3 align-items-center">
                        <div class="col-md-6">
                            <label class="form-label small fw-bold mb-1">Lunghezza</label>
                            <div class="input-group">
                                <button class="btn btn-outline-secondary" type="button" onclick="pwgenLengthDelta(-1)"><i class="fas fa-minus"></i></button>
                                <input type="number" class="form-control text-center" id="pwgenLength" value="20" min="8" max="128">
                                <button class="btn btn-outline-secondary" type="button" onclick="pwgenLengthDelta(1)"><i class="fas fa-plus"></i></button>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <input type="range" class="form-range mt-3" id="pwgenLengthRange" min="8" max="64" value="20" oninput="document.getElementById('pwgenLength').value = this.value">
                        </div>
                    </div>

                    <!-- Include -->
                    <div class="mb-3">
                        <label class="form-label small fw-bold">Includi</label>
                        <div class="border rounded p-2 d-flex flex-wrap gap-3">
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="pwgenIncludeLower" checked>
                                <label class="form-check-label" for="pwgenIncludeLower">Minuscole</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="pwgenIncludeUpper" checked>
                                <label class="form-check-label" for="pwgenIncludeUpper">Maiuscole</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="pwgenIncludeNumbers" checked>
                                <label class="form-check-label" for="pwgenIncludeNumbers">Numeri</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="pwgenIncludeSymbols" checked>
                                <label class="form-check-label" for="pwgenIncludeSymbols">Simboli</label>
                            </div>
                        </div>
                        <small class="text-muted" id="pwgenIncludeNote"></small>
                    </div>

                    <!-- Preview -->
                    <div class="mb-2">
                        <label class="form-label small fw-bold">Password generata</label>
                        <div class="input-group">
                            <input type="text" class="form-control font-monospace fs-5" id="pwgenPreview" readonly placeholder="Clicca Genera per ottenere una password">
                            <button class="btn btn-outline-secondary" type="button" onclick="pwgenCopy()" title="Copia"><i class="fas fa-copy"></i></button>
                        </div>
                        <div class="mt-2 small">
                            <span id="pwgenStrengthBadge" class="badge bg-secondary">—</span>
                            <span class="text-muted ms-2" id="pwgenEntropyText">Entropia: — bit</span>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Annulla</button>
                    <button type="button" class="btn btn-info" onclick="pwgenGenerate()"><i class="fas fa-sync-alt me-1"></i>Genera</button>
                    <button type="button" class="btn btn-success" id="pwgenUseBtn" onclick="pwgenUse()" disabled><i class="fas fa-check me-1"></i>Usa questa password</button>
                </div>
            </div>
        </div>
    </div>
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
                    <h5 class="modal-title"><i class="fas fa-sync-alt me-2"></i>Cambio password massivo</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="alert alert-info small mb-3">
                        <i class="fas fa-info-circle me-1"></i>
                        Genera nuove password sicure per le caselle selezionate. Le password in chiaro vengono mostrate <strong>una sola volta</strong> — copiale subito e inoltrale agli utenti. Verranno comunque archiviate nel vault del pannello (cifrate AES-256-GCM) e potrai rivederle dal "Modifica Casella".
                    </div>

                    <div id="bulkRotateStep1" class="">
                        <!-- Opzioni generatore -->
                        <div class="border rounded p-2 mb-3" style="background:rgba(13,110,253,0.04)">
                            <div class="row g-2">
                                <div class="col-md-6">
                                    <label class="form-label small fw-bold mb-1">Tipo password</label>
                                    <select class="form-select form-select-sm" id="bulkRotateType" onchange="bulkRotateOnTypeChange()">
                                        <option value="easy_to_say">Facile da dettare (solo lettere)</option>
                                        <option value="easy_to_read" selected>Facile da leggere/copiare (no ambigui, simboli safe)</option>
                                        <option value="all_chars">Tutti i caratteri (max entropia, anche ?/=/&amp;)</option>
                                    </select>
                                </div>
                                <div class="col-md-3">
                                    <label class="form-label small fw-bold mb-1">Lunghezza</label>
                                    <input type="number" min="8" max="128" class="form-control form-control-sm" id="bulkRotateLength" value="20">
                                </div>
                                <div class="col-md-3 d-flex align-items-end">
                                    <span class="text-muted small" id="bulkRotateSelectedCount">0 selezionate</span>
                                </div>
                            </div>
                            <div class="mt-2 d-flex flex-wrap gap-3 align-items-center">
                                <span class="small fw-bold text-muted">Includi:</span>
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="bulkRotateInclLower" checked>
                                    <label class="form-check-label small" for="bulkRotateInclLower">Minuscole</label>
                                </div>
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="bulkRotateInclUpper" checked>
                                    <label class="form-check-label small" for="bulkRotateInclUpper">Maiuscole</label>
                                </div>
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="bulkRotateInclNumbers" checked>
                                    <label class="form-check-label small" for="bulkRotateInclNumbers">Numeri</label>
                                </div>
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="bulkRotateInclSymbols" checked>
                                    <label class="form-check-label small" for="bulkRotateInclSymbols">Simboli</label>
                                </div>
                                <button class="btn btn-outline-secondary btn-sm ms-auto" type="button" onclick="bulkRotatePreviewSample()" title="Genera un esempio (NON applica)">
                                    <i class="fas fa-eye me-1"></i>Anteprima
                                </button>
                            </div>
                            <div class="mt-2 small text-muted" id="bulkRotatePreviewBox"></div>
                        </div>

                        <div class="d-flex gap-2 mb-2 flex-wrap">
                            <button class="btn btn-outline-secondary btn-sm" onclick="bulkRotateSelectAll()"><i class="fas fa-check-square me-1"></i>Seleziona tutte</button>
                            <button class="btn btn-outline-secondary btn-sm" onclick="bulkRotateSelectNone()"><i class="fas fa-square me-1"></i>Deseleziona tutte</button>
                        </div>
                        <div class="table-responsive" style="max-height:50vh">
                            <table class="table table-sm table-hover align-middle mb-0">
                                <thead class="table-light sticky-top">
                                    <tr>
                                        <th style="width:40px"><input type="checkbox" class="form-check-input" id="bulkRotateChkAll" onchange="bulkRotateToggleAll(this)"></th>
                                        <th>Email</th>
                                        <th>Nome</th>
                                        <th>Stato vault</th>
                                    </tr>
                                </thead>
                                <tbody id="bulkRotateMboxList">
                                    <tr><td colspan="4" class="text-center text-muted"><i class="fas fa-spinner fa-spin me-1"></i>Caricamento...</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <div id="bulkRotateStep2" class="d-none">
                        <div class="alert alert-success" id="bulkRotateSummary"></div>
                        <div class="d-flex gap-2 mb-2">
                            <button class="btn btn-sm btn-outline-primary" onclick="bulkRotateCopyAll()"><i class="fas fa-copy me-1"></i>Copia tutto (CSV)</button>
                            <button class="btn btn-sm btn-outline-secondary" onclick="bulkRotateShowHide()" id="bulkRotateToggleVis"><i class="fas fa-eye me-1"></i>Mostra/nascondi password</button>
                        </div>
                        <div class="table-responsive" style="max-height:60vh">
                            <table class="table table-sm align-middle mb-0">
                                <thead class="table-light sticky-top"><tr><th>Email</th><th>Nuova password</th><th>Stato</th></tr></thead>
                                <tbody id="bulkRotateResultsList"></tbody>
                            </table>
                        </div>
                        <div class="alert alert-warning small mt-3 mb-0">
                            <i class="fas fa-exclamation-triangle me-1"></i>
                            <strong>Importante:</strong> chiudi questo modal SOLO dopo aver copiato/salvato le password. Anche se restano nel vault, è la singola occasione in cui le vedi assieme così.
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Chiudi</button>
                    <button type="button" class="btn btn-warning" id="bulkRotateRunBtn" onclick="bulkRotateRun()"><i class="fas fa-bolt me-1"></i>Genera e applica nuove password</button>
                </div>
            </div>
        </div>
    </div>
""";
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
            tbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted"><i class="fas fa-spinner fa-spin me-1"></i>Caricamento...</td></tr>';
            fetch('/api/mailboxes').then(r => r.json()).then(data => {
                const list = (data.mailboxes || []).sort((a, b) => a.email.localeCompare(b.email));
                if (list.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">Nessuna casella configurata.</td></tr>';
                    return;
                }
                let html = '';
                list.forEach(m => {
                    html += '<tr>';
                    html += '<td><input type="checkbox" class="form-check-input bulk-rotate-chk" value="' + m.id + '" onchange="updateBulkRotateCount()"></td>';
                    html += '<td><code>' + escapeHtmlBl(m.email) + '</code></td>';
                    html += '<td>' + escapeHtmlBl(m.name || '') + '</td>';
                    // Stato vault: NON disponibile su /api/mailboxes lista, mostriamo placeholder
                    html += '<td><small class="text-muted">—</small></td>';
                    html += '</tr>';
                });
                tbody.innerHTML = html;
            }).catch(e => {
                tbody.innerHTML = '<tr><td colspan="4" class="text-danger">Errore caricamento: ' + e.message + '</td></tr>';
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
            document.getElementById('bulkRotateSelectedCount').textContent = n + ' selezionate';
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
                alert('Seleziona almeno una categoria di caratteri (Minuscole/Maiuscole/Numeri/Simboli).');
                return;
            }
            const box = document.getElementById('bulkRotatePreviewBox');
            box.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Generazione anteprima...';
            fetch('/api/mailboxes', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(Object.assign({ action: 'generate_password', csrf_token: csrfToken }, opts))
            })
            .then(r => r.json())
            .then(data => {
                if (!data.success) {
                    box.innerHTML = '<span class="text-danger">Errore: ' + (data.error || '') + '</span>';
                    return;
                }
                const ent = data.entropy_bits || 0;
                const label = data.strength_label || '—';
                let badgeClass = 'bg-secondary';
                if (label === 'Molto forte' || label === 'Forte') badgeClass = 'bg-success';
                else if (label === 'Discreta') badgeClass = 'bg-warning text-dark';
                else if (label === 'Debole') badgeClass = 'bg-danger';
                box.innerHTML = '<strong>Esempio:</strong> <code class="font-monospace">' + escapeHtmlBl(data.password) +
                    '</code>  <span class="badge ' + badgeClass + ' ms-1">' + escapeHtmlBl(label) + '</span>' +
                    ' <span class="text-muted">(' + ent + ' bit)</span>';
            })
            .catch(e => { box.innerHTML = '<span class="text-danger">Errore rete: ' + e.message + '</span>'; });
        }

        function bulkRotateRun() {
            const ids = Array.from(document.querySelectorAll('.bulk-rotate-chk:checked')).map(c => parseInt(c.value));
            if (ids.length === 0) { alert('Seleziona almeno una casella.'); return; }
            const opts = bulkRotateGetGeneratorOpts();
            if (!opts.include_lowercase && !opts.include_uppercase && !opts.include_numbers && !opts.include_symbols) {
                alert('Seleziona almeno una categoria di caratteri (Minuscole/Maiuscole/Numeri/Simboli).');
                return;
            }
            if (!confirm('Generare ' + ids.length + ' nuove password (tipo: ' + opts.type + ', lunghezza ' + opts.length + ') e applicarle?\\n\\nLe password attuali smetteranno di funzionare immediatamente.\\nLe nuove verranno mostrate UNA SOLA volta in questa schermata.\\n\\nProcedere?')) return;

            const btn = document.getElementById('bulkRotateRunBtn');
            const origBtn = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Generazione in corso...';

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
                    alert('Errore: ' + (data.error || 'sconosciuto'));
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
                    '<strong>Completato:</strong> ' + (summary.succeeded || 0) + ' caselle aggiornate, ' +
                    (summary.failed || 0) + ' fallite su ' + (summary.total || 0) + ' totali.';

                bulkRotateRenderResults();
            })
            .catch(e => {
                btn.disabled = false;
                btn.innerHTML = origBtn;
                alert('Errore rete: ' + e.message);
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
                    html += '<button class="btn btn-outline-secondary" type="button" onclick="bulkRotateCopyOne(\\'' + escapeHtmlBl((r.password || '').replace(/\\\\/g, "\\\\\\\\").replace(/'/g, "\\\\'")) + '\\')" title="Copia"><i class="fas fa-copy"></i></button>';
                    html += '</div></td>';
                    html += '<td><span class="badge bg-success">OK</span></td>';
                } else {
                    html += '<td><span class="text-danger">—</span></td>';
                    html += '<td><span class="badge bg-danger" title="' + escapeHtmlBl(r.error || '') + '">Errore</span></td>';
                }
                html += '</tr>';
            });
            tbody.innerHTML = html;
        }

        function bulkRotateShowHide() {
            bulkRotatePasswordsVisible = !bulkRotatePasswordsVisible;
            bulkRotateRenderResults();
            document.getElementById('bulkRotateToggleVis').innerHTML = bulkRotatePasswordsVisible
                ? '<i class="fas fa-eye-slash me-1"></i>Nascondi password'
                : '<i class="fas fa-eye me-1"></i>Mostra password';
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
                alert('Copiato ' + (lines.length - 1) + ' coppie email,password negli appunti (formato CSV).');
            }).catch(() => {
                // Fallback: prompt
                window.prompt('Copia il testo CSV qui sotto:', csv);
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
        .condition-row, .action-row { background: #fff; padding: 8px; margin: 5px 0; border-radius: 4px; border: 1px solid #dee2e6; }
        """;
        return getHead("Caselle Email", extraStyles) + getNavbar("mailboxes") + """
    <div class="content container mt-4">
        <div class="content-container">
            <div class="d-flex justify-content-between align-items-center mb-4 flex-wrap gap-2">
                <h2><i class="fas fa-inbox me-2"></i>Caselle Email</h2>
                <div class="d-flex gap-2 flex-wrap">
                    <button class="btn btn-outline-warning" onclick="openBulkRotateModal()" title="Genera nuove password sicure per caselle selezionate (o tutte) — utile per rotazione periodica o recovery dopo perdita master.key">
                        <i class="fas fa-sync-alt me-1"></i>Cambia password massivo
                    </button>
                    <button class="btn btn-mail" data-bs-toggle="modal" data-bs-target="#addMailboxModal"><i class="fas fa-plus me-1"></i>Aggiungi Casella</button>
                </div>
            </div>

            <div class="table-responsive">
                <table class="table table-hover">
                    <thead class="table-light">
                        <tr><th>Email</th><th>Nome</th><th>Quota</th><th>Funzionalita</th><th>Azioni</th></tr>
                    </thead>
                    <tbody id="mailboxesTable">
                        <tr><td colspan="5" class="text-center">Caricamento...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Add Mailbox Modal -->
    <div class="modal fade" id="addMailboxModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header"><h5 class="modal-title">Aggiungi Casella</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
                <div class="modal-body">
                    <form id="addMailboxForm">
                        <div class="mb-3">
                            <label class="form-label">Dominio</label>
                            <select class="form-select" id="mbDomain" required></select>
                        </div>
                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <label class="form-label">Username</label>
                                <input type="text" class="form-control" id="mbUser" placeholder="mario" required>
                            </div>
                            <div class="col-md-6 mb-3">
                                <label class="form-label">Password</label>
                                <input type="password" class="form-control" id="mbPass" required>
                            </div>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Nome Completo</label>
                            <input type="text" class="form-control" id="mbName" placeholder="Mario Rossi">
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Quota</label>
                            <select class="form-select" id="mbQuota">
                                <option value="1024" selected>1 GB</option>
                                <option value="256">256 MB</option>
                                <option value="512">512 MB</option>
                                <option value="2048">2 GB</option>
                                <option value="5120">5 GB</option>
                                <option value="10240">10 GB</option>
                                <option value="0">Illimitato</option>
                            </select>
                        </div>
                        <div class="form-check form-switch mb-3">
                            <input class="form-check-input" type="checkbox" id="mbReceive" checked>
                            <label class="form-check-label" for="mbReceive">Ricevi Email</label>
                            <small class="d-block text-muted">Disattiva per creare un account no-reply (solo invio)</small>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Annulla</button>
                    <button type="button" class="btn btn-mail" onclick="addMailbox()">Crea Casella</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Edit Mailbox Modal -->
    <div class="modal fade" id="editMailboxModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-edit me-2"></i>Modifica Casella</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <input type="hidden" id="editMbId">
                    <div class="mb-3">
                        <label class="form-label">Email</label>
                        <input type="text" class="form-control" id="editMbEmail" readonly disabled>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Nome Completo</label>
                        <input type="text" class="form-control" id="editMbName" placeholder="Mario Rossi">
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Nuova Password <small class="text-muted">(lascia vuoto per non cambiare)</small></label>
                        <div class="input-group">
                            <input type="password" class="form-control" id="editMbPass" placeholder="Nuova password..." autocomplete="new-password">
                            <button class="btn btn-outline-secondary" type="button" id="editMbPassToggleBtn" onclick="toggleEditMbPassVisibility()" title="Mostra/nascondi password nel campo"><i class="fas fa-eye"></i></button>
                            <button class="btn btn-outline-primary" type="button" onclick="generateEditMbPass()" title="Genera nuova password sicura"><i class="fas fa-magic me-1"></i>Genera</button>
                            <button class="btn btn-outline-secondary" type="button" onclick="copyEditMbPass()" title="Copia password negli appunti"><i class="fas fa-copy"></i></button>
                        </div>
                        <small class="text-muted">Quando salvi, la password viene cifrata (AES-256-GCM) nel vault del pannello — potrai rivederla in seguito.</small>

                        <!-- Riquadro per password archiviata: rivelabile con click -->
                        <div class="mt-2" id="editMbVaultBox" style="display:none">
                            <div class="border rounded p-2 small" style="background:rgba(13,110,253,0.05)">
                                <i class="fas fa-shield-alt text-primary me-1"></i>
                                <strong>Password archiviata disponibile</strong> (cifrata nel vault).
                                <button type="button" class="btn btn-sm btn-link p-0 ms-2" onclick="revealMailboxStoredPassword()">
                                    <i class="fas fa-eye me-1"></i>Rivela
                                </button>
                                <div class="mt-1 d-none" id="editMbRevealedBox">
                                    <div class="input-group input-group-sm">
                                        <input type="text" class="form-control font-monospace" id="editMbRevealedValue" readonly>
                                        <button class="btn btn-outline-secondary" type="button" onclick="copyRevealedPassword()" title="Copia"><i class="fas fa-copy"></i></button>
                                        <button class="btn btn-outline-danger" type="button" onclick="hideRevealedPassword()" title="Nascondi"><i class="fas fa-eye-slash"></i></button>
                                    </div>
                                    <div class="small text-muted mt-1"><i class="fas fa-exclamation-triangle me-1"></i>Operazione registrata nell'audit log per sicurezza.</div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Quota</label>
                        <select class="form-select" id="editMbQuota">
                            <option value="0">Illimitato</option>
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
                                <label class="form-check-label" for="editMbActive">Account Attivo</label>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="form-check form-switch mb-3">
                                <input class="form-check-input" type="checkbox" id="editMbReceive" checked>
                                <label class="form-check-label" for="editMbReceive">Ricevi Email</label>
                            </div>
                        </div>
                    </div>
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle me-2"></i>
                        <strong>No-Reply:</strong> Disattiva "Ricevi Email" per creare un account che può solo inviare, non ricevere.
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Annulla</button>
                    <button type="button" class="btn btn-mail" onclick="saveMailbox()">Salva Modifiche</button>
                </div>
            </div>
        </div>
    </div>

""" + getBulkRotateMailboxesModal() + getPasswordGeneratorModal() + """
    <!-- Mail Client Config Modal -->
""" + getMailConfigModal() + """

    <!-- Auto-Responder Modal -->
    <div class="modal fade" id="autoResponderModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-reply-all me-2"></i>Auto-Responder (Vacation)</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <input type="hidden" id="arMailboxId">
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle me-2"></i>Rispondi automaticamente alle email ricevute quando sei assente.
                    </div>
                    <div class="form-check form-switch mb-3">
                        <input class="form-check-input" type="checkbox" id="arEnabled">
                        <label class="form-check-label" for="arEnabled">Attiva Auto-Responder</label>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Oggetto</label>
                        <input type="text" class="form-control" id="arSubject" placeholder="Sono assente dall'ufficio">
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Messaggio</label>
                        <textarea class="form-control" id="arBody" rows="5" placeholder="Grazie per la tua email. Sono attualmente fuori ufficio..."></textarea>
                    </div>
                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <label class="form-label">Data Inizio (opzionale)</label>
                            <input type="date" class="form-control" id="arStartDate">
                        </div>
                        <div class="col-md-6 mb-3">
                            <label class="form-label">Data Fine (opzionale)</label>
                            <input type="date" class="form-control" id="arEndDate">
                        </div>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Intervallo minimo tra risposte (ore)</label>
                        <input type="number" class="form-control" id="arInterval" value="24" min="1" max="168">
                        <small class="text-muted">Evita di inviare risposte multiple allo stesso mittente</small>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-outline-warning" onclick="resetVacationTracking()" title="Permette di inviare nuovamente la risposta automatica agli stessi mittenti">
                        <i class="fas fa-redo me-1"></i>Reset Tracking
                    </button>
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Annulla</button>
                    <button type="button" class="btn btn-primary" onclick="saveAutoResponder()">Salva</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Forwarding Modal -->
    <div class="modal fade" id="forwardingModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-share me-2"></i>Inoltro Email</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <input type="hidden" id="fwMailboxId">
                    <div id="forwardingRules"></div>
                    <hr>
                    <h6>Aggiungi Inoltro</h6>
                    <div class="mb-3">
                        <label class="form-label">Destinazione</label>
                        <input type="email" class="form-control" id="fwDestination" placeholder="altro@example.com">
                    </div>
                    <div class="form-check mb-3">
                        <input class="form-check-input" type="checkbox" id="fwKeepCopy" checked>
                        <label class="form-check-label" for="fwKeepCopy">Mantieni una copia locale</label>
                    </div>
                    <button class="btn btn-success" onclick="addForwarding()">
                        <i class="fas fa-plus me-1"></i>Aggiungi Inoltro
                    </button>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Chiudi</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Sieve Filters Modal -->
    <div class="modal fade" id="sieveModal" tabindex="-1">
        <div class="modal-dialog modal-xl">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-filter me-2"></i>Filtri Email (Sieve)</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <input type="hidden" id="svMailboxId">
                    <div class="row">
                        <div class="col-md-4">
                            <h6>Filtri Attivi</h6>
                            <div id="sieveFiltersList" class="mb-3"></div>
                            <button class="btn btn-primary btn-sm" onclick="newSieveFilter()">
                                <i class="fas fa-plus me-1"></i>Nuovo Filtro
                            </button>
                        </div>
                        <div class="col-md-8">
                            <div id="sieveEditor" style="display:none;">
                                <input type="hidden" id="svFilterId">
                                <div class="mb-3">
                                    <label class="form-label">Nome Filtro</label>
                                    <input type="text" class="form-control" id="svName" placeholder="Sposta newsletter in cartella">
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Condizioni</label>
                                    <div id="svConditions"></div>
                                    <button class="btn btn-outline-secondary btn-sm mt-2" onclick="addSieveCondition()">
                                        <i class="fas fa-plus"></i> Aggiungi Condizione
                                    </button>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Azioni</label>
                                    <div id="svActions"></div>
                                    <button class="btn btn-outline-secondary btn-sm mt-2" onclick="addSieveAction()">
                                        <i class="fas fa-plus"></i> Aggiungi Azione
                                    </button>
                                </div>
                                <div class="form-check mb-3">
                                    <input class="form-check-input" type="checkbox" id="svEnabled" checked>
                                    <label class="form-check-label" for="svEnabled">Filtro Attivo</label>
                                </div>
                                <button class="btn btn-success" onclick="saveSieveFilter()">
                                    <i class="fas fa-save me-1"></i>Salva Filtro
                                </button>
                            </div>
                            <div id="sieveHelp">
                                <div class="alert alert-secondary">
                                    <h6>Come funzionano i filtri</h6>
                                    <p>I filtri Sieve permettono di organizzare automaticamente le email in arrivo:</p>
                                    <ul>
                                        <li><strong>Condizioni:</strong> Criteri per selezionare le email (mittente, oggetto, ecc.)</li>
                                        <li><strong>Azioni:</strong> Cosa fare con le email che corrispondono (sposta, elimina, ecc.)</li>
                                    </ul>
                                    <p>Seleziona un filtro esistente o creane uno nuovo.</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Chiudi</button>
                </div>
            </div>
        </div>
    </div>

""" + getFooter() + """
    <script>
        let csrfToken = document.getElementById('csrf_token').value;
        let domains = [];
        let currentMailboxes = [];

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
                    tbody.innerHTML = '<tr><td colspan="5" class="text-center">Nessuna casella. Aggiungi prima un dominio, poi crea le caselle.</td></tr>';
                    return;
                }
                tbody.innerHTML = currentMailboxes.map(m => `
                    <tr>
                        <td>
                            <strong>${m.email}</strong>
                            ${!m.receive_enabled ? '<span class="badge bg-secondary ms-1" title="Solo invio (No-Reply)"><i class="fas fa-ban"></i> No-Reply</span>' : ''}
                            ${!m.active ? '<span class="badge bg-danger ms-1">Disattivo</span>' : ''}
                        </td>
                        <td>${m.name || '-'}</td>
                        <td>${m.quota_mb === 0 ? '<span class="text-success"><i class="fas fa-infinity"></i> Illimitato</span>' : m.quota_mb + ' MB'}</td>
                        <td>
                            ${m.autoresponder_enabled ? '<span class="badge bg-info feature-badge" title="Auto-Responder Attivo"><i class="fas fa-reply-all"></i></span>' : ''}
                            ${m.forwarding_count > 0 ? '<span class="badge bg-warning feature-badge" title="Inoltro Attivo"><i class="fas fa-share"></i> ' + m.forwarding_count + '</span>' : ''}
                            ${m.filters_count > 0 ? '<span class="badge bg-primary feature-badge" title="Filtri Attivi"><i class="fas fa-filter"></i> ' + m.filters_count + '</span>' : ''}
                        </td>
                        <td>
                            <div class="btn-group">
                                <button class="btn btn-sm btn-webmail text-white" onclick="openWebmail('${m.email}')" title="Apri Webmail">
                                    <i class="fas fa-envelope-open"></i>
                                </button>
                                <button class="btn btn-sm btn-primary" onclick="editMailbox(${m.id})" title="Modifica">
                                    <i class="fas fa-edit"></i>
                                </button>
                                <button class="btn btn-sm btn-info" onclick="showMailConfig('${m.email}', ${m.id})" title="Configurazione Client">
                                    <i class="fas fa-mobile-alt"></i>
                                </button>
                                <button class="btn btn-sm btn-secondary dropdown-toggle" data-bs-toggle="dropdown">
                                    <i class="fas fa-cog"></i>
                                </button>
                                <ul class="dropdown-menu">
                                    <li><a class="dropdown-item" href="#" onclick="openAutoResponder(${m.id}, '${m.email}')">
                                        <i class="fas fa-reply-all me-2"></i>Auto-Responder
                                    </a></li>
                                    <li><a class="dropdown-item" href="#" onclick="openForwarding(${m.id}, '${m.email}')">
                                        <i class="fas fa-share me-2"></i>Inoltro
                                    </a></li>
                                    <li><a class="dropdown-item" href="#" onclick="openSieveFilters(${m.id}, '${m.email}')">
                                        <i class="fas fa-filter me-2"></i>Filtri
                                    </a></li>
                                    <li><hr class="dropdown-divider"></li>
                                    <li><a class="dropdown-item text-danger" href="#" onclick="deleteMailbox(${m.id})">
                                        <i class="fas fa-trash me-2"></i>Elimina
                                    </a></li>
                                </ul>
                            </div>
                        </td>
                    </tr>
                `).join('');
            });
        }

        function addMailbox() {
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
                    document.getElementById('mbName').value = '';
                    document.getElementById('mbQuota').value = '1024';
                    document.getElementById('mbReceive').checked = true;
                } else {
                    alert('Errore: ' + (data.error || 'sconosciuto'));
                }
            });
        }

        function deleteMailbox(id) {
            if (!confirm('Eliminare questa casella e tutte le email?')) return;
            fetch('/api/mailboxes?id=' + id, { method: 'DELETE' }).then(() => loadMailboxes());
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
                    document.getElementById('editMbPass').type = 'password';
                    document.getElementById('editMbPassToggleBtn').innerHTML = '<i class="fas fa-eye"></i>';
                    // Reset stato del riquadro vault
                    const vaultBox = document.getElementById('editMbVaultBox');
                    const revealedBox = document.getElementById('editMbRevealedBox');
                    revealedBox.classList.add('d-none');
                    document.getElementById('editMbRevealedValue').value = '';
                    // Mostra il riquadro "Password archiviata" SOLO se ce n'è una nel vault
                    if (m.has_encrypted_password) {
                        vaultBox.style.display = '';
                    } else {
                        vaultBox.style.display = 'none';
                    }
                    new bootstrap.Modal(document.getElementById('editMailboxModal')).show();
                } else {
                    alert('Errore: impossibile caricare i dati della mailbox');
                }
            });
        }

        // ===== Password vault helpers =====
        function toggleEditMbPassVisibility() {
            const input = document.getElementById('editMbPass');
            const btn = document.getElementById('editMbPassToggleBtn');
            if (input.type === 'password') {
                input.type = 'text';
                btn.innerHTML = '<i class="fas fa-eye-slash"></i>';
            } else {
                input.type = 'password';
                btn.innerHTML = '<i class="fas fa-eye"></i>';
            }
        }

        function generateEditMbPass() {
            // Apri il modal Generatore Password e registra un callback che riempie il campo della casella
            window.__pwGenCallback = function(pw) {
                const input = document.getElementById('editMbPass');
                input.value = pw;
                input.type = 'text';
                document.getElementById('editMbPassToggleBtn').innerHTML = '<i class="fas fa-eye-slash"></i>';
                input.focus();
                input.select();
            };
            openPasswordGeneratorModal();
        }

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
            if (v < 8) v = 8;
            if (v > 128) v = 128;
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
                note.textContent = 'Tipo "facile da dettare": numeri e simboli sono disattivati per definizione.';
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
            const length = parseInt(document.getElementById('pwgenLength').value) || 20;
            const type = document.querySelector('input.pwgen-type:checked').value;
            const lo = document.getElementById('pwgenIncludeLower').checked;
            const up = document.getElementById('pwgenIncludeUpper').checked;
            const nu = document.getElementById('pwgenIncludeNumbers').checked;
            const sy = document.getElementById('pwgenIncludeSymbols').checked;

            if (!lo && !up && !nu && !sy) {
                alert('Seleziona almeno una categoria di caratteri.');
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
                    alert('Errore: ' + (data.error || ''));
                    return;
                }
                document.getElementById('pwgenPreview').value = data.password;
                const ent = data.entropy_bits || 0;
                const label = data.strength_label || '—';
                document.getElementById('pwgenEntropyText').textContent = 'Entropia: ' + ent + ' bit';
                const badge = document.getElementById('pwgenStrengthBadge');
                badge.textContent = label;
                if (label === 'Molto forte')      badge.className = 'badge bg-success';
                else if (label === 'Forte')       badge.className = 'badge bg-success';
                else if (label === 'Discreta')    badge.className = 'badge bg-warning text-dark';
                else                              badge.className = 'badge bg-danger';
                document.getElementById('pwgenUseBtn').disabled = false;
            })
            .catch(e => alert('Errore rete: ' + e.message));
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

        function copyEditMbPass() {
            const input = document.getElementById('editMbPass');
            if (!input.value) { alert('Il campo è vuoto. Genera o digita una password prima.'); return; }
            navigator.clipboard.writeText(input.value).then(() => {
                // Feedback breve sull'icona
                // (non uso alert per non interrompere il flusso)
            }).catch(() => {
                input.select(); document.execCommand('copy');
            });
        }

        function revealMailboxStoredPassword() {
            const id = parseInt(document.getElementById('editMbId').value);
            if (!id) return;
            if (!confirm('Rivelare la password archiviata di questa casella?\\n\\nL\\'operazione viene registrata nell\\'audit log con il tuo username, IP e timestamp.')) return;
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
                    alert(data.error || 'Errore rivelazione password');
                }
            })
            .catch(e => alert('Errore rete: ' + e.message));
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
                    alert('Errore: ' + (result.error || 'sconosciuto'));
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
            if (pwToggle) { pwToggle.innerHTML = '<i class="fas fa-eye"></i>'; pwToggle.disabled = true; }
            if (pwCopy) pwCopy.disabled = true;
            if (pwReveal) {
                pwReveal.disabled = false;
                pwReveal.innerHTML = '<i class="fas fa-unlock me-1"></i>Rivela';
            }
            if (pwHint) pwHint.innerHTML = 'Clicca "Rivela" per recuperare la password dal vault del pannello. L\\'operazione viene registrata nell\\'audit log.';

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
                btn.innerHTML = '<i class="fas fa-eye-slash"></i>';
            } else {
                input.type = 'password';
                btn.innerHTML = '<i class="fas fa-eye"></i>';
            }
        }

        function revealCfgPassword() {
            if (!__cfgCurrentMailboxId) {
                alert('Casella non identificata — chiudi e riapri la finestra.');
                return;
            }
            const btn = document.getElementById('cfgPasswordRevealBtn');
            const pwField = document.getElementById('cfgPasswordField');
            const pwToggle = document.getElementById('cfgPasswordToggleBtn');
            const pwCopy = document.getElementById('cfgPasswordCopyBtn');
            const pwHint = document.getElementById('cfgPasswordHint');
            if (!confirm('Rivelare la password della casella ' + __cfgCurrentEmail + '?\\n\\nL\\'operazione viene registrata nell\\'audit log.')) return;
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
                        pwToggle.innerHTML = '<i class="fas fa-eye-slash"></i>';
                    }
                    if (pwCopy) pwCopy.disabled = false;
                    btn.innerHTML = '<i class="fas fa-check me-1"></i>Rivelata';
                    if (pwHint) pwHint.innerHTML = '<span class="text-success">✓ Password recuperata dal vault. Clicca 📋 per copiarla o 👁 per nasconderla.</span>';
                } else {
                    btn.disabled = false;
                    btn.innerHTML = '<i class="fas fa-unlock me-1"></i>Rivela';
                    if (pwHint) pwHint.innerHTML = '<span class="text-danger">' + (data.error || 'Errore') + '</span>';
                }
            })
            .catch(e => {
                btn.disabled = false;
                btn.innerHTML = '<i class="fas fa-unlock me-1"></i>Rivela';
                if (pwHint) pwHint.innerHTML = '<span class="text-danger">Errore rete: ' + e.message + '</span>';
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
                    alert('Errore SSO: ' + (data.error || 'Impossibile aprire webmail'));
                }
            });
        }

        // ========== AUTO-RESPONDER ==========
        function openAutoResponder(mailboxId, email) {
            document.getElementById('arMailboxId').value = mailboxId;
            document.querySelector('#autoResponderModal .modal-title').innerHTML =
                '<i class="fas fa-reply-all me-2"></i>Auto-Responder - ' + email;

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
                    alert(data.error || 'Errore');
                }
            });
        }

        function resetVacationTracking() {
            if (!confirm('Vuoi resettare il tracking delle risposte automatiche?\\n\\nQuesto permetterà di inviare nuovamente la risposta ai mittenti che l\\'hanno già ricevuta.')) {
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
                    alert('Tracking resettato! Ora puoi testare di nuovo la risposta automatica.');
                } else {
                    alert(data.error || 'Errore');
                }
            });
        }

        // ========== FORWARDING ==========
        function openForwarding(mailboxId, email) {
            document.getElementById('fwMailboxId').value = mailboxId;
            document.querySelector('#forwardingModal .modal-title').innerHTML =
                '<i class="fas fa-share me-2"></i>Inoltro - ' + email;
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
                        container.innerHTML = '<p class="text-muted">Nessun inoltro configurato</p>';
                        return;
                    }
                    container.innerHTML = rules.map(r => `
                        <div class="d-flex justify-content-between align-items-center mb-2 p-2 bg-light rounded">
                            <div>
                                <i class="fas fa-arrow-right me-2"></i>${r.destination}
                                ${r.keep_copy ? '<span class="badge bg-secondary ms-2">Copia locale</span>' : ''}
                                ${!r.enabled ? '<span class="badge bg-warning ms-2">Disattivato</span>' : ''}
                            </div>
                            <button class="btn btn-sm btn-outline-danger" onclick="deleteForwarding(${r.id})">
                                <i class="fas fa-trash"></i>
                            </button>
                        </div>
                    `).join('');
                });
        }

        function addForwarding() {
            const dest = document.getElementById('fwDestination').value.trim();
            if (!dest) { alert('Inserisci un indirizzo email'); return; }

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
                    alert(data.error || 'Errore');
                }
            });
        }

        function deleteForwarding(id) {
            if (!confirm('Eliminare questo inoltro?')) return;
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

        function openSieveFilters(mailboxId, email) {
            document.getElementById('svMailboxId').value = mailboxId;
            document.querySelector('#sieveModal .modal-title').innerHTML =
                '<i class="fas fa-filter me-2"></i>Filtri - ' + email;

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
                        container.innerHTML = '<p class="text-muted">Nessun filtro</p>';
                        return;
                    }
                    container.innerHTML = filters.map(f => `
                        <div class="filter-rule ${!f.enabled ? 'opacity-50' : ''}" onclick="editSieveFilter(${f.id})">
                            <div class="d-flex justify-content-between">
                                <strong>${f.name}</strong>
                                ${f.enabled ? '<span class="badge bg-success">Attivo</span>' : '<span class="badge bg-secondary">Off</span>'}
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
                        <option value="from" ${c.field==='from'?'selected':''}>Da</option>
                        <option value="to" ${c.field==='to'?'selected':''}>A</option>
                        <option value="subject" ${c.field==='subject'?'selected':''}>Oggetto</option>
                        <option value="body" ${c.field==='body'?'selected':''}>Corpo</option>
                    </select>
                    <select class="form-select form-select-sm" style="width:130px" onchange="sieveConditions[${i}].operator=this.value">
                        <option value="contains" ${c.operator==='contains'?'selected':''}>Contiene</option>
                        <option value="is" ${c.operator==='is'?'selected':''}>E' uguale a</option>
                        <option value="matches" ${c.operator==='matches'?'selected':''}>Corrisponde</option>
                        <option value="not_contains" ${c.operator==='not_contains'?'selected':''}>Non contiene</option>
                    </select>
                    <input type="text" class="form-control form-control-sm" value="${c.value}" onchange="sieveConditions[${i}].value=this.value">
                    <button class="btn btn-sm btn-outline-danger" onclick="sieveConditions.splice(${i},1);renderSieveConditions()">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            `).join('') || '<p class="text-muted">Nessuna condizione</p>';
        }

        function renderSieveActions() {
            document.getElementById('svActions').innerHTML = sieveActions.map((a, i) => `
                <div class="action-row d-flex gap-2 align-items-center">
                    <select class="form-select form-select-sm" style="width:150px" onchange="sieveActions[${i}].type=this.value;renderSieveActions()">
                        <option value="move" ${a.type==='move'?'selected':''}>Sposta in</option>
                        <option value="copy" ${a.type==='copy'?'selected':''}>Copia in</option>
                        <option value="delete" ${a.type==='delete'?'selected':''}>Elimina</option>
                        <option value="mark_read" ${a.type==='mark_read'?'selected':''}>Segna come letto</option>
                        <option value="forward" ${a.type==='forward'?'selected':''}>Inoltra a</option>
                        <option value="reject" ${a.type==='reject'?'selected':''}>Rifiuta</option>
                    </select>
                    ${['move','copy','forward','reject'].includes(a.type) ?
                        `<input type="text" class="form-control form-control-sm" value="${a.value||''}" placeholder="${a.type==='forward'?'email@...':'Cartella'}" onchange="sieveActions[${i}].value=this.value">` : ''}
                    <button class="btn btn-sm btn-outline-danger" onclick="sieveActions.splice(${i},1);renderSieveActions()">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            `).join('') || '<p class="text-muted">Nessuna azione</p>';
        }

        function saveSieveFilter() {
            const name = document.getElementById('svName').value.trim();
            if (!name) { alert('Inserisci un nome per il filtro'); return; }
            if (sieveConditions.length === 0) { alert('Aggiungi almeno una condizione'); return; }
            if (sieveActions.length === 0) { alert('Aggiungi almeno un\\'azione'); return; }

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
                    alert(data.error || 'Errore');
                }
            });
        }

""" + getLogoutScript() + """
        loadDomains();
        loadMailboxes();
    </script>
</body>
</html>
""";
    }

    // ============== ALIASES.HTML ==============
    public static String getAliasesHtml() {
        return getHead("Alias", "") + getNavbar("aliases") + """
    <div class="content container mt-4">
        <div class="content-container">
            <h2><i class="fas fa-share me-2"></i>Alias Email</h2>
            <p>Gestione alias e forward email.</p>
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead><tr><th>Sorgente</th><th>Destinazione</th><th>Azioni</th></tr></thead>
                    <tbody id="aliasesTable"><tr><td colspan="3">Caricamento...</td></tr></tbody>
                </table>
            </div>
        </div>
    </div>
""" + getFooter() + """
    <script>
        let csrfToken = document.getElementById('csrf_token').value;
        fetch('/api/aliases').then(r => r.json()).then(data => {
            const tbody = document.getElementById('aliasesTable');
            if (!data.aliases || data.aliases.length === 0) {
                tbody.innerHTML = '<tr><td colspan="3">Nessun alias configurato.</td></tr>';
                return;
            }
            tbody.innerHTML = data.aliases.map(a => '<tr><td>' + a.source + '</td><td>' + a.destination + '</td><td><button class="btn btn-sm btn-danger">Elimina</button></td></tr>').join('');
        });
""" + getLogoutScript() + """
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
                        cfInfo.innerHTML = '<div class="alert alert-info py-2 mb-0 small"><i class="fas fa-cloud me-1"></i><strong>Rotazione automatica via Cloudflare</strong> — account collegato: <strong>' + escapeHtmlBl(lbl) + '</strong>' + em + '. Il record DNS verrà creato e cancellato dal pannello.</div>';
                    } else if (data.has_dkim) {
                        cfInfo.innerHTML = '<div class="alert alert-secondary py-2 mb-0 small"><i class="fas fa-edit me-1"></i><strong>Rotazione manuale</strong> — questo dominio non è legato a nessun account Cloudflare. Per renderla automatica, <a href="/cloudflare" class="alert-link">configura e assegna un account Cloudflare</a>.</div>';
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
                if (state === 'pending_dns')      badge.innerHTML = '<span class="badge bg-warning text-dark">In attesa DNS</span>';
                else if (state === 'propagated')  badge.innerHTML = '<span class="badge bg-info text-dark">DNS propagato — pronto da attivare</span>';
                else if (state === 'active_grace') badge.innerHTML = '<span class="badge bg-success">Nuova chiave attiva — grace period</span>';

                // Stepper
                const stepDef = [
                    { key: 'pending_dns',   label: '1. Pubblica DNS' },
                    { key: 'propagated',    label: '2. Verifica propagazione' },
                    { key: 'active_grace',  label: '3. Attiva firma' },
                    { key: 'completed',     label: '4. Rimuovi vecchia chiave' }
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
                    stepperHtml += '<span class="' + cls + '" style="padding:8px 12px;font-size:0.85rem">' + s.label + '</span>';
                });
                stepperHtml += '</div>';
                stepper.innerHTML = stepperHtml;

                // Body per ogni stato
                let html = '';

                if (state === 'pending_dns' || state === 'propagated') {
                    html += '<div class="alert alert-warning">';
                    html += '<strong><i class="fas fa-edit me-1"></i>Aggiungi questo record TXT al tuo DNS:</strong>';
                    html += '<div class="mt-2"><strong>Nome:</strong> <code>' + escapeHtmlBl(data.pending_dns_name || '') + '</code></div>';
                    html += '<div class="mt-1"><strong>Tipo:</strong> <code>TXT</code></div>';
                    html += '<div class="mt-1"><strong>Valore:</strong> <code style="word-break:break-all">' + escapeHtmlBl(data.pending_dns_value || '') + '</code> ';
                    html += '<button class="btn btn-sm btn-outline-secondary ms-2" onclick="copyDkimRotateValue(this)" data-val="' + escapeHtmlBl(data.pending_dns_value || '') + '"><i class="fas fa-copy"></i></button></div>';
                    html += '<div class="mt-2 small text-muted">Il selector della NUOVA chiave è <code>' + escapeHtmlBl(data.pending_selector || '') + '</code>. La vecchia chiave (<code>' + escapeHtmlBl(data.current_selector || '') + '</code>) continua a firmare finché non attivi.</div>';
                    html += '</div>';

                    if (state === 'pending_dns') {
                        html += '<div class="d-flex gap-2 flex-wrap">';
                        html += '<button class="btn btn-primary" onclick="rotateDkimCheck()"><i class="fas fa-search me-1"></i>Verifica propagazione DNS</button>';
                        html += '<button class="btn btn-outline-danger" onclick="rotateDkimCancel()"><i class="fas fa-times me-1"></i>Annulla rotazione</button>';
                        html += '</div>';
                        html += '<div class="small text-muted mt-2">Tip: dopo aver aggiunto il record TXT al DNS, attendi 1-5 minuti e poi premi "Verifica". Lo stato passerà automaticamente al passo successivo.</div>';
                    } else {
                        // propagated
                        html += '<div class="alert alert-info"><i class="fas fa-check-circle me-1"></i>Il record DNS è stato pubblicato correttamente. Ora puoi attivare la nuova chiave: da quel momento le mail in uscita verranno firmate con il nuovo selector.</div>';
                        html += '<div class="d-flex gap-2 flex-wrap">';
                        html += '<button class="btn btn-success" onclick="rotateDkimActivate(false)"><i class="fas fa-bolt me-1"></i>Attiva nuova chiave</button>';
                        html += '<button class="btn btn-outline-primary" onclick="rotateDkimCheck()"><i class="fas fa-sync me-1"></i>Ricontrolla DNS</button>';
                        html += '<button class="btn btn-outline-danger" onclick="rotateDkimCancel()"><i class="fas fa-times me-1"></i>Annulla rotazione</button>';
                        html += '</div>';
                    }
                } else if (state === 'active_grace') {
                    const graceDays = data.grace_period_days || 7;
                    const isOver = !!data.grace_period_over;
                    html += '<div class="alert ' + (isOver ? 'alert-success' : 'alert-info') + '">';
                    html += '<strong><i class="fas fa-check-circle me-1"></i>Nuova chiave attiva.</strong> Le email vengono ora firmate con il selector <code>' + escapeHtmlBl(data.current_selector || '') + '</code>.';
                    if (data.previous_selector) {
                        html += '<div class="mt-2 small">La vecchia chiave <code>' + escapeHtmlBl(data.previous_selector) + '</code> deve restare nel DNS per ' + graceDays + ' giorni, così le mail già spedite continuano a validarsi presso i destinatari.</div>';
                    }
                    if (data.activated_at) {
                        html += '<div class="mt-1 small text-muted">Attivata: ' + escapeHtmlBl(data.activated_at) + '</div>';
                    }
                    html += '</div>';

                    // Calcola la data prevista di completamento (activated_at + grace_days)
                    let expectedCompletionStr = '';
                    const actMs = (typeof pickTs === 'function')
                        ? (pickTs(data, 'activated_at') ? pickTs(data, 'activated_at').getTime() : null)
                        : null;
                    if (actMs) {
                        const completionDate = new Date(actMs + graceDays * 24 * 60 * 60 * 1000);
                        expectedCompletionStr = (typeof formatItalianDate === 'function')
                            ? formatItalianDate(completionDate)
                            : completionDate.toLocaleString('it-IT');
                    }

                    if (isOver) {
                        if (data.cloudflare_configured) {
                            html += '<div class="alert alert-success"><i class="fas fa-robot me-1"></i><strong>Grace period terminato.</strong> Lo scheduler completerà automaticamente la rotazione al prossimo tick (entro 1 ora) — rimuoverà la vecchia chiave dal DB e cancellerà il record TXT via Cloudflare. Puoi anche cliccare qui sotto per farlo subito.</div>';
                        } else {
                            html += '<div class="alert alert-warning"><i class="fas fa-clock me-1"></i><strong>Grace period terminato.</strong> Clicca "Completa rotazione" — poi dovrai rimuovere manualmente il record TXT dal tuo DNS provider (questo dominio non ha un account Cloudflare assegnato per l\\'auto-cancellazione). <a href="/cloudflare" class="alert-link">Configura Cloudflare</a> per automatizzarlo.</div>';
                        }
                        html += '<button class="btn btn-success" onclick="rotateDkimComplete()"><i class="fas fa-flag-checkered me-1"></i>Completa rotazione</button>';
                    } else {
                        // PRIMA del grace period: il bottone "Completa" è SEMPRE disabilitato.
                        // Nessuna possibilità di forzare: il server side rifiuterebbe comunque la chiamata
                        // (vedi DkimManager.completeRotation), quindi non offriamo nemmeno il bottone.
                        if (data.cloudflare_configured) {
                            html += '<div class="alert alert-info"><i class="fas fa-robot me-1"></i><strong>Completamento automatico previsto:</strong> ' + (expectedCompletionStr ? '<strong>' + expectedCompletionStr + '</strong>' : 'tra ' + graceDays + ' giorni dall\\'attivazione') + '.<br>Finché il pannello resta acceso, lo scheduler attiverà il completamento entro 1 ora dal termine del grace period: rimuoverà la vecchia chiave dal DB e cancellerà il record TXT in Cloudflare automaticamente.</div>';
                        } else {
                            html += '<div class="alert alert-light"><i class="fas fa-hourglass-half me-1"></i>Attendi la fine del grace period (' + graceDays + ' giorni' + (expectedCompletionStr ? ', circa il <strong>' + expectedCompletionStr + '</strong>' : '') + ') prima di rimuovere la vecchia chiave dal DNS.<br><small class="text-muted">Questo dominio è in modalità manuale (nessun account Cloudflare). Lo scheduler non potrà auto-completare: al termine del grace period dovrai cliccare "Completa" e poi cancellare il vecchio record TXT dal tuo DNS provider.</small></div>';
                        }
                        html += '<button class="btn btn-success" disabled title="Non puoi completare la rotazione prima del grace period — rimuovere la vecchia chiave troppo presto causerebbe DKIM-fail su mail in transito. Il pulsante si abiliterà automaticamente.">';
                        html += '<i class="fas fa-lock me-1"></i>Completa rotazione (bloccato fino al ' + (expectedCompletionStr || 'termine grace') + ')';
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
                btn.innerHTML = '<i class="fas fa-check"></i> copiato';
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
                if (!data.success) { alert('Errore: ' + (data.error || 'sconosciuto')); return; }
                if (data.warning) {
                    alert('⚠ ' + data.warning);
                } else if (data.message && useAuto) {
                    alert('✓ ' + data.message);
                }
                loadDkimRotationStatus(currentDomainId);
            }).catch(e => alert('Errore rete: ' + e.message));
        }

        function rotateDkimStart() {
            if (!currentDomainId) { alert('Seleziona un dominio'); return; }
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
                if (!confirm('Avviare la rotazione DKIM (modalità manuale)?\\n\\nQuesto dominio non è legato a nessun account Cloudflare, quindi dovrai aggiungere TU il record TXT al DNS.\\n\\n• Verrà generata una nuova chiave.\\n• La vecchia chiave continuerà a firmare finché non attivi quella nuova.\\n• Dopo l\\'attivazione, la vecchia chiave resta nel DNS per 7 giorni (grace period).')) return;
                rotateDkimStartExec(false);
                return;
            }

            // CF disponibile → mostra modal di scelta tra Cloudflare e DNS manuale
            const modalEl = document.getElementById('rotateModeChooserModal');
            document.getElementById('rotateModeAccountLabel').textContent = acctLabel || '(nessuno)';
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
            if (!confirm('Confermi la modalità MANUALE?\\n\\nIl pannello genera la chiave ma NON tocca il DNS via Cloudflare. Dovrai copiare il record TXT dalla schermata che apparirà e aggiungerlo TU al DNS provider.')) return;
            rotateDkimStartExec(false);
        }

        function rotateDkimCheck() {
            if (!currentDomainId) return;
            fetch('/api/dkim', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'rotate_check', domain_id: parseInt(currentDomainId) })
            }).then(r => r.json()).then(data => {
                if (!data.success) { alert('Errore: ' + (data.message || 'sconosciuto')); return; }
                if (data.propagated) {
                    alert('✓ Record DNS propagato. Ora puoi attivare la nuova chiave.');
                } else {
                    alert('⚠ ' + (data.message || 'Non ancora propagato — riprova tra qualche minuto.'));
                }
                loadDkimRotationStatus(currentDomainId);
            }).catch(e => alert('Errore rete: ' + e.message));
        }

        function rotateDkimActivate(force) {
            if (!currentDomainId) return;
            const msg = force
                ? 'Forzare l\\'attivazione anche se il DNS non sembra propagato?\\n\\nATTENZIONE: se il record non è ancora visibile ai destinatari, le mail firmate con la nuova chiave falliranno DKIM finché non si propaga.'
                : 'Attivare la nuova chiave DKIM?\\n\\n• Le nuove email saranno firmate con il nuovo selector.\\n• La vecchia chiave resterà nel DNS per il grace period (7 giorni).\\n• Verrà ricaricato Rspamd.';
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
            }).catch(e => alert('Errore rete: ' + e.message));
        }

        function rotateDkimComplete() {
            if (!currentDomainId) return;
            if (!confirm('Completare la rotazione e rimuovere la vecchia chiave dal pannello?\\n\\nDopo questa operazione potrai rimuovere il vecchio record TXT dal tuo DNS.')) return;
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
            }).catch(e => alert('Errore rete: ' + e.message));
        }

        function rotateDkimCancel() {
            if (!currentDomainId) return;
            if (!confirm('Annullare la rotazione in corso?\\n\\nLa chiave pending verrà eliminata. Potrai rimuovere il record TXT dal DNS.')) return;
            fetch('/api/dkim', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'rotate_cancel', domain_id: parseInt(currentDomainId) })
            }).then(r => r.json()).then(data => {
                alert((data.success ? '✓ ' : '✗ ') + (data.message || ''));
                loadDkimRotationStatus(currentDomainId);
            }).catch(e => alert('Errore rete: ' + e.message));
        }

        // ===== Blacklist Check =====
        function runBlacklistCheck() {
            const btn = document.getElementById('btnBlCheck');
            const container = document.getElementById('blContainer');
            const overall = document.getElementById('blOverallStatus');
            const originalHtml = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Verifica in corso (5-10s)...';
            container.innerHTML = '<p class="text-muted"><i class="fas fa-spinner fa-spin me-1"></i>Sto interrogando 15+ blacklist DNS-based, attendi...</p>';
            fetch('/api/blacklist_check').then(r => r.json()).then(data => {
                btn.disabled = false;
                btn.innerHTML = originalHtml;
                if (!data.success) {
                    container.innerHTML = '<div class="alert alert-danger mb-0">Errore: ' + (data.error || 'sconosciuto') + '</div>';
                    return;
                }
                let totalListed = 0;
                let totalChecks = 0;
                let html = '';
                (data.reports || []).forEach(report => {
                    totalListed += report.listed_count;
                    totalChecks += (report.listed_count + report.clean_count + report.error_count + (report.web_only_count || 0));

                    const labelType = report.type === 'IP' ? 'IP server' : 'Dominio';
                    let headerClass, badge;
                    if (report.listed_count > 0) {
                        headerClass = 'bg-danger text-white';
                        badge = '<span class="badge bg-light text-danger ms-2">⚠ ' + report.listed_count + ' listed</span>';
                    } else if (report.error_count > report.clean_count / 2) {
                        headerClass = 'bg-warning text-dark';
                        badge = '<span class="badge bg-secondary ms-2">' + report.error_count + ' err</span>';
                    } else {
                        headerClass = 'bg-success text-white';
                        let txt = '✓ ' + report.clean_count + ' clean';
                        if (report.web_only_count) txt += ' + ' + report.web_only_count + ' web';
                        badge = '<span class="badge bg-light text-success ms-2">' + txt + '</span>';
                    }

                    html += '<div class="card mb-3">';
                    html += '<div class="card-header ' + headerClass + ' d-flex justify-content-between align-items-center">';
                    html += '<div><strong>' + labelType + ':</strong> <code class="ms-1" style="background:rgba(255,255,255,0.2);padding:2px 6px;border-radius:3px;color:inherit">' + escapeHtmlBl(report.target) + '</code>' + badge + '</div>';
                    html += '<small class="opacity-75">' + report.elapsed_ms + 'ms</small>';
                    html += '</div>';
                    html += '<div class="card-body p-2"><div class="table-responsive"><table class="table table-sm mb-0">';
                    html += '<thead><tr><th>Blacklist</th><th>Stato</th><th>Dettagli</th><th>Lookup</th></tr></thead><tbody>';
                    (report.results || []).forEach(res => {
                        let stateBadge;
                        if (res.listed) {
                            stateBadge = '<span class="badge bg-danger"><i class="fas fa-ban me-1"></i>LISTED</span>';
                        } else if (res.web_only) {
                            stateBadge = '<span class="badge bg-info text-dark"><i class="fas fa-external-link-alt me-1"></i>Verifica web</span>';
                        } else if (res.error) {
                            stateBadge = '<span class="badge bg-secondary"><i class="fas fa-question-circle me-1"></i>Errore</span>';
                        } else {
                            stateBadge = '<span class="badge bg-success"><i class="fas fa-check me-1"></i>Pulito</span>';
                        }
                        html += '<tr>';
                        html += '<td><strong>' + escapeHtmlBl(res.blacklist) + '</strong><br><small class="text-muted">' + escapeHtmlBl(res.zone) + '</small></td>';
                        html += '<td>' + stateBadge + '</td>';
                        html += '<td><small>' + escapeHtmlBl(res.message || '') + '</small></td>';
                        html += '<td>' + (res.lookup_url ? '<a href="' + res.lookup_url + '" target="_blank" rel="noopener" class="btn btn-sm btn-outline-primary" title="Apri pagina lookup/delisting"><i class="fas fa-external-link-alt"></i></a>' : '') + '</td>';
                        html += '</tr>';
                    });
                    html += '</tbody></table></div></div>';
                    html += '</div>';
                });

                // Overall status badge
                if (totalListed === 0) {
                    overall.innerHTML = '<span class="badge bg-success">Tutto pulito (' + totalChecks + ' check)</span>';
                } else {
                    overall.innerHTML = '<span class="badge bg-danger">' + totalListed + ' blacklist(s) ti hanno listato</span>';
                }

                if (html === '') {
                    html = '<p class="text-muted">Nessun report disponibile.</p>';
                }
                container.innerHTML = html;
            }).catch(e => {
                btn.disabled = false;
                btn.innerHTML = originalHtml;
                container.innerHTML = '<div class="alert alert-danger mb-0">Errore rete: ' + e.message + '</div>';
            });
        }

        function escapeHtmlBl(s) {
            const d = document.createElement('div');
            d.textContent = s == null ? '' : String(s);
            return d.innerHTML;
        }

        function generateDkim() {
            if (!currentDomainId) return;
            if (!confirm('Generare nuove chiavi DKIM? Le chiavi esistenti saranno sostituite.')) return;

            fetch('/api/dkim', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'generate', domain_id: parseInt(currentDomainId), selector: 'mail' })
            }).then(r => r.json()).then(data => {
                if (data.success) {
                    alert('Chiavi DKIM generate! Aggiungi il record DNS mostrato.');
                    loadDnsRecords();
                } else {
                    alert('Errore: ' + data.error);
                }
            });
        }

        function verifyDns() {
            const domain = document.getElementById('domainSelect').value;
            if (!domain) { alert('Seleziona un dominio'); return; }

            fetch('/api/dns', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'verify', domain: domain })
            }).then(r => r.json()).then(data => {
                const container = document.getElementById('verificationResults');
                const body = document.getElementById('verificationBody');
                container.classList.remove('d-none');

                let html = '<div class="d-flex justify-content-between align-items-center mb-3">';
                html += '<h5>Dominio: ' + data.domain + '</h5>';
                html += '<span class="score-badge badge ' + (data.all_passed ? 'bg-success' : 'bg-warning') + '">' + data.score + '%</span>';
                html += '</div>';

                html += '<table class="table table-sm table-bordered"><thead class="table-light"><tr><th width="80">Record</th><th width="50">Stato</th><th>Verifica</th></tr></thead><tbody>';
                data.checks.forEach(c => {
                    const icon = c.passed ? '<i class="fas fa-check-circle text-success"></i>' : '<i class="fas fa-times-circle text-danger"></i>';
                    const rowClass = c.passed ? '' : 'table-danger';
                    html += '<tr class="' + rowClass + '">';
                    html += '<td><strong>' + c.type + '</strong></td>';
                    html += '<td class="text-center">' + icon + '</td>';
                    html += '<td>';
                    html += '<div><strong>' + c.message + '</strong></div>';
                    if (c.current_value) {
                        const shortVal = c.current_value.length > 80 ? c.current_value.substring(0, 80) + '...' : c.current_value;
                        html += '<div class="mt-1"><small class="text-muted">Trovato: </small><code class="small">' + shortVal + '</code></div>';
                    }
                    html += '</td>';
                    html += '</tr>';
                });
                html += '</tbody></table>';

                if (data.all_passed) {
                    html += '<div class="alert alert-success mb-0"><i class="fas fa-check-circle me-2"></i>Tutti i record DNS sono configurati correttamente!</div>';
                } else {
                    html += '<div class="alert alert-warning mb-0"><i class="fas fa-exclamation-triangle me-2"></i>Alcuni record DNS richiedono attenzione.</div>';
                }

                body.innerHTML = html;
            });
        }

        function copyToClipboard(el) {
            const name = el.querySelector('.record-name').textContent;
            const value = el.querySelector('.record-value').textContent;
            navigator.clipboard.writeText(value).then(() => {
                alert('Copiato negli appunti!');
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
            out.innerHTML = '<div class="alert alert-info py-2 mb-0"><i class="fas fa-spinner fa-spin me-1"></i>Interrogazione DNS pubblici in corso (1.1.1.1, 8.8.8.8)...</div>';
            fetch('/api/dkim', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'verify_active_dns', domain_id: parseInt(currentDomainId) })
            }).then(r => r.json()).then(data => {
                if (!data.success) {
                    out.innerHTML = '<div class="alert alert-danger py-2 mb-0"><i class="fas fa-times-circle me-1"></i>' + escapeHtmlBl(data.message || data.error || 'errore') + '</div>';
                    return;
                }
                let html = '';
                if (data.match) {
                    html += '<div class="alert alert-success py-2 mb-2"><i class="fas fa-check-circle me-1"></i><strong>OK</strong> — ' + escapeHtmlBl(data.message || '') + '</div>';
                } else {
                    html += '<div class="alert alert-danger py-2 mb-2"><i class="fas fa-exclamation-triangle me-1"></i><strong>NON CORRISPONDE</strong> — ' + escapeHtmlBl(data.message || '') + '</div>';
                }
                html += '<table class="table table-sm mb-0 small"><tbody>';
                html += '<tr><th style="width:180px">Record interrogato</th><td><code>' + escapeHtmlBl(data.dns_record_name || '') + '</code></td></tr>';
                html += '<tr><th>Selector attivo</th><td><code>' + escapeHtmlBl(data.selector || '') + '</code></td></tr>';
                if (data.expected_public_key) {
                    const exp = data.expected_public_key;
                    const trunc = exp.length > 60 ? exp.substring(0, 60) + '…' : exp;
                    html += '<tr><th>Chiave attesa (DB)</th><td><code style="word-break:break-all">' + escapeHtmlBl(trunc) + '</code> <small class="text-muted">(' + exp.length + ' char)</small></td></tr>';
                }
                if (data.actual_public_key) {
                    const act = data.actual_public_key;
                    const trunc = act.length > 60 ? act.substring(0, 60) + '…' : act;
                    html += '<tr><th>Chiave trovata (DNS)</th><td><code style="word-break:break-all">' + escapeHtmlBl(trunc) + '</code> <small class="text-muted">(' + act.length + ' char)</small></td></tr>';
                }
                html += '</tbody></table>';
                if (data.raw_output) {
                    html += '<details class="mt-2"><summary class="small text-muted">Output dig completo</summary><pre class="small mt-2" style="white-space:pre-wrap;word-break:break-all">' + escapeHtmlBl(data.raw_output) + '</pre></details>';
                }
                out.innerHTML = html;
                // Lo storico ora include un evento "key_verified": ricaricalo
                loadDkimHistory(currentDomainId);
            }).catch(e => {
                out.innerHTML = '<div class="alert alert-danger py-2 mb-0">Errore rete: ' + e.message + '</div>';
            });
        }

        // ===== Cleanup record DKIM orfani =====
        function scanDkimOrphans() {
            if (!currentDomainId) { alert('Seleziona un dominio'); return; }
            const btn = document.getElementById('scanDkimOrphansBtn');
            const out = document.getElementById('dkimOrphansResult');
            const originalBtn = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Scansione in corso...';
            out.innerHTML = '';
            fetch('/api/dkim', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'orphans_scan', domain_id: parseInt(currentDomainId) })
            }).then(r => r.json()).then(data => {
                btn.disabled = false;
                btn.innerHTML = originalBtn;
                if (!data.success) {
                    out.innerHTML = '<div class="alert alert-danger py-2 mb-0"><i class="fas fa-times-circle me-1"></i>' + escapeHtmlBl(data.error || 'errore sconosciuto') + '</div>';
                    return;
                }
                const records = data.records || [];
                if (records.length === 0) {
                    out.innerHTML = '<div class="alert alert-info py-2 mb-0"><i class="fas fa-info-circle me-1"></i>Nessun record TXT <code>*._domainkey.' + escapeHtmlBl(data.domain) + '</code> trovato in Cloudflare (account: ' + escapeHtmlBl(data.cloudflare_account_label || '?') + ').</div>';
                    return;
                }
                const orphanCount      = records.filter(r => r.is_orphan).length;
                const removableCount   = records.filter(r => r.is_orphan && !r.in_grace_period).length;
                const graceProtCount   = records.filter(r => r.is_orphan && r.in_grace_period).length;
                const activeCount = records.length - orphanCount;
                const graceDays = data.grace_period_days || 7;
                let html = '<div class="alert ' + (removableCount > 0 ? 'alert-warning' : 'alert-success') + ' py-2 mb-2"><i class="fas fa-info-circle me-1"></i>Trovati <strong>' + records.length + '</strong> record DKIM totali (' + activeCount + ' attivi, ' + graceProtCount + ' in grace, <strong>' + removableCount + ' rimovibili</strong>) nell\\'account <strong>' + escapeHtmlBl(data.cloudflare_account_label || '?') + '</strong>.</div>';
                html += '<div class="table-responsive"><table class="table table-sm align-middle mb-0">';
                html += '<thead class="table-light"><tr><th>Selector</th><th>Stato</th><th>Contenuto (anteprima)</th><th class="text-end">Azione</th></tr></thead><tbody>';
                records.forEach(r => {
                    html += '<tr>';
                    html += '<td><code>' + escapeHtmlBl(r.selector || '') + '</code><br><small class="text-muted">' + escapeHtmlBl(r.name || '') + '</small></td>';
                    let badge;
                    let stateExtra = '';
                    if (r.is_current)       badge = '<span class="badge bg-success">Attivo</span>';
                    else if (r.is_pending)  badge = '<span class="badge bg-warning text-dark">Pending</span>';
                    else if (r.is_previous) badge = '<span class="badge bg-info text-dark">Grace period</span>';
                    else if (r.in_grace_period) {
                        badge = '<span class="badge bg-info text-dark">In grace ' + graceDays + 'gg</span>';
                        // Mostra data fine grace period
                        const endsTs = (typeof pickTs === 'function') ? pickTs(r, 'grace_period_ends_at') : null;
                        if (endsTs) {
                            const endsStr = (typeof formatItalianDate === 'function') ? formatItalianDate(endsTs) : endsTs.toLocaleString('it-IT');
                            stateExtra = '<br><small class="text-muted">rimovibile dal ' + escapeHtmlBl(endsStr) + '</small>';
                        }
                    } else {
                        badge = '<span class="badge bg-danger">Orfano</span>';
                    }
                    html += '<td>' + badge + stateExtra + '</td>';
                    html += '<td><code class="small" style="word-break:break-all">' + escapeHtmlBl(r.content_preview || '') + '</code></td>';
                    if (r.is_orphan && !r.in_grace_period) {
                        // ORFANO rimovibile (grace period scaduto o mai stato attivo)
                        html += '<td class="text-end"><button class="btn btn-sm btn-outline-danger" onclick="deleteDkimOrphan(\\'' + escapeHtmlBl(r.record_id).replace(/'/g, "\\\\'") + '\\', \\'' + escapeHtmlBl(r.selector).replace(/'/g, "\\\\'") + '\\')"><i class="fas fa-trash me-1"></i>Cancella</button></td>';
                    } else if (r.is_orphan && r.in_grace_period) {
                        // ORFANO ma in grace period esteso: NON rimovibile
                        html += '<td class="text-end"><span class="text-muted small" title="Selector disattivato di recente — bloccato dalla cancellazione fino al termine del grace period per evitare DKIM-fail su mail in transito"><i class="fas fa-shield-alt me-1"></i>protetto da grace period</span></td>';
                    } else {
                        // Attivo / Pending / Previous: protetto
                        html += '<td class="text-end"><span class="text-muted small"><i class="fas fa-lock me-1"></i>protetto</span></td>';
                    }
                    html += '</tr>';
                });
                html += '</tbody></table></div>';
                out.innerHTML = html;
            }).catch(e => {
                btn.disabled = false;
                btn.innerHTML = originalBtn;
                out.innerHTML = '<div class="alert alert-danger py-2 mb-0">Errore rete: ' + e.message + '</div>';
            });
        }

        function deleteDkimOrphan(recordId, selector) {
            if (!currentDomainId) return;
            if (!confirm('Cancellare il record DKIM orfano con selector "' + selector + '"?\\n\\nIl record sarà rimosso da Cloudflare. Operazione irreversibile.')) return;
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
            }).catch(e => alert('Errore rete: ' + e.message));
        }

        // ===== Storico rotazioni DKIM =====
        function loadDkimHistory(domainId) {
            const body = document.getElementById('dkimHistoryBody');
            body.innerHTML = '<p class="text-muted small mb-0"><i class="fas fa-spinner fa-spin me-1"></i>Caricamento storico...</p>';
            fetch('/api/dkim', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'rotate_history', domain_id: parseInt(domainId), limit: 100 })
            }).then(r => r.json()).then(data => {
                if (!data.success) {
                    body.innerHTML = '<div class="text-muted small">Storico non disponibile: ' + escapeHtmlBl(data.error || '') + '</div>';
                    return;
                }
                const events = data.events || [];
                if (events.length === 0) {
                    body.innerHTML = '<div class="text-muted small">Nessuna rotazione registrata per questo dominio.</div>';
                    return;
                }
                // Label leggibili e colori per evento
                const labels = {
                    rotation_started:   { txt: 'Rotazione avviata',          badge: 'bg-primary' },
                    dns_published:      { txt: 'Record DNS creato (auto)',   badge: 'bg-info text-dark' },
                    dns_propagated:     { txt: 'DNS propagato e verificato', badge: 'bg-info text-dark' },
                    key_activated:      { txt: 'Chiave attivata',            badge: 'bg-success' },
                    rotation_completed: { txt: 'Rotazione completata',       badge: 'bg-success' },
                    rotation_cancelled: { txt: 'Rotazione annullata',        badge: 'bg-secondary' },
                    key_verified:       { txt: 'Verifica chiave in DNS',     badge: 'bg-secondary' },
                    orphan_record_deleted: { txt: 'Record orfano rimosso',   badge: 'bg-warning text-dark' },
                    schedule_changed:   { txt: 'Schedule modificato',        badge: 'bg-secondary' }
                };
                // Etichette + colori per la "Modalità DNS" (come viene gestito il record in DNS)
                const modeLabels = {
                    automatic: { txt: 'Cloudflare',  badge: 'bg-info text-dark',         title: 'Il record DNS è gestito automaticamente via API Cloudflare.' },
                    manual:    { txt: 'DNS manuale', badge: 'bg-light text-dark border', title: 'Il record DNS deve essere aggiunto/rimosso manualmente dall\\'utente nel proprio provider DNS.' },
                    forced:    { txt: 'Forzata',     badge: 'bg-warning text-dark',      title: 'Attivazione forzata: la chiave è stata attivata senza attendere la conferma di propagazione DNS.' }
                };
                // Etichette per "Origine" (chi ha avviato l'operazione)
                const triggerLabels = {
                    user:      { txt: 'Utente',     icon: 'user',  badge: 'bg-primary',   title: 'Operazione avviata cliccando un bottone nel pannello.' },
                    scheduler: { txt: 'Scheduler',  icon: 'robot', badge: 'bg-dark',      title: 'Operazione avviata automaticamente dal timer di rotazione programmata.' }
                };
                let html = '<div class="table-responsive"><table class="table table-sm align-middle mb-0">';
                html += '<thead class="table-light"><tr>';
                html += '<th>Data/ora</th>';
                html += '<th>Evento</th>';
                html += '<th>Selector</th>';
                html += '<th title="Chi ha avviato questa operazione: Utente (clic in UI) o Scheduler (timer automatico). Vuoto per eventi conseguenza (es. propagazione DNS rilevata)." style="cursor:help">Origine <i class="fas fa-info-circle text-muted small"></i></th>';
                html += '<th title="Come è gestito il record DNS per questa rotazione: Cloudflare (via API), DNS manuale (utente lo modifica), Forzata (attivata senza propagazione). Vuoto per eventi non-rotazione." style="cursor:help">Modalità DNS <i class="fas fa-info-circle text-muted small"></i></th>';
                html += '<th>Account CF</th>';
                html += '<th>Esito</th>';
                html += '<th>Note</th>';
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
                        ? (typeof formatItalianDate === 'function' ? formatItalianDate(tsDate) : tsDate.toLocaleString('it-IT'))
                        : (ev.occurred_at || '');
                    html += '<td><small class="text-nowrap">' + escapeHtmlBl(tsDisplay) + '</small></td>';
                    html += '<td><span class="badge ' + lbl.badge + '">' + escapeHtmlBl(lbl.txt) + '</span></td>';
                    html += '<td>' + (ev.selector ? '<code>' + escapeHtmlBl(ev.selector) + '</code>' : '<span class="text-muted">—</span>') + '</td>';
                    // Colonna Origine
                    if (trig) {
                        html += '<td><span class="badge ' + trig.badge + '" title="' + escapeHtmlBl(trig.title) + '" style="cursor:help"><i class="fas fa-' + trig.icon + ' me-1"></i>' + escapeHtmlBl(trig.txt) + '</span></td>';
                    } else if (ev.triggered_by) {
                        html += '<td><span class="badge bg-secondary">' + escapeHtmlBl(ev.triggered_by) + '</span></td>';
                    } else {
                        html += '<td><span class="text-muted" title="Evento conseguenza (es. propagazione DNS rilevata), oppure evento registrato prima dell\\'introduzione del tracciamento Origine." style="cursor:help">—</span></td>';
                    }
                    // Colonna Modalità DNS
                    if (mode) {
                        html += '<td><span class="badge ' + mode.badge + '" title="' + escapeHtmlBl(mode.title) + '" style="cursor:help">' + escapeHtmlBl(mode.txt) + '</span></td>';
                    } else if (ev.mode) {
                        html += '<td><span class="badge bg-light text-dark border">' + escapeHtmlBl(ev.mode) + '</span></td>';
                    } else {
                        html += '<td><span class="text-muted" title="Non applicabile a questo tipo di evento" style="cursor:help">—</span></td>';
                    }
                    html += '<td>' + (ev.cloudflare_account_label ? escapeHtmlBl(ev.cloudflare_account_label) : '<span class="text-muted">—</span>') + '</td>';
                    html += '<td>' + (ev.success
                        ? '<span class="badge bg-success"><i class="fas fa-check"></i></span>'
                        : '<span class="badge bg-danger"><i class="fas fa-times"></i></span>') + '</td>';
                    html += '<td><small>' + escapeHtmlBl(ev.message || '') + '</small></td>';
                    html += '</tr>';
                });
                html += '</tbody></table></div>';

                // Legenda compatta sotto la tabella
                html += '<div class="small text-muted mt-2">';
                html += '<div class="mb-1"><i class="fas fa-info-circle me-1"></i><strong>Origine:</strong> ';
                html += '<span class="badge bg-primary"><i class="fas fa-user me-1"></i>Utente</span> = avviato cliccando un bottone · ';
                html += '<span class="badge bg-dark"><i class="fas fa-robot me-1"></i>Scheduler</span> = avviato automaticamente dal timer · ';
                html += '<span class="text-muted">—</span> = evento conseguenza, o registrato prima del tracciamento Origine';
                html += '</div>';
                html += '<div><i class="fas fa-info-circle me-1"></i><strong>Modalità DNS:</strong> ';
                html += '<span class="badge bg-info text-dark">Cloudflare</span> = via API · ';
                html += '<span class="badge bg-light text-dark border">DNS manuale</span> = utente gestisce il DNS · ';
                html += '<span class="badge bg-warning text-dark">Forzata</span> = attivata senza attendere propagazione · ';
                html += '<span class="text-muted">—</span> = non applicabile';
                html += '</div></div>';

                body.innerHTML = html;
            }).catch(e => {
                body.innerHTML = '<div class="text-danger small">Errore rete: ' + e.message + '</div>';
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
            badge.innerHTML = '<span class="badge bg-light text-dark"><i class="fas fa-spinner fa-spin me-1"></i>controllo...</span>';
            table.innerHTML = '<div class="text-muted small"><i class="fas fa-spinner fa-spin me-1"></i>Caricamento...</div>';

            fetch('/api/timezone-diag').then(r => r.json()).then(data => {
                renderTzDiag(data);
            }).catch(e => {
                badge.innerHTML = '<span class="badge bg-danger">Errore</span>';
                table.innerHTML = '<div class="alert alert-danger small mb-0">Errore: ' + e.message + '</div>';
            });
        }

        function renderTzDiag(data) {
            const badge = document.getElementById('tzDiagStatusBadge');
            const table = document.getElementById('tzDiagTable');

            // Badge nell'header
            const alignment = data.alignment || 'UNKNOWN';
            if (alignment === 'OK') {
                badge.innerHTML = '<span class="badge bg-success"><i class="fas fa-check-circle me-1"></i>Allineato</span>';
            } else if (alignment === 'MISMATCH') {
                const skewMin = Math.round((data.skew_mysql_vs_jvm_ms || 0) / 60000);
                badge.innerHTML = '<span class="badge bg-danger"><i class="fas fa-exclamation-triangle me-1"></i>Disallineato (' + skewMin + ' min)</span>';
            } else {
                badge.innerHTML = '<span class="badge bg-secondary">?</span>';
            }

            // Tabella
            let html = '<table class="table table-sm align-middle mb-0">';
            html += '<thead class="table-light"><tr><th>Sorgente</th><th>Timestamp</th><th>Fuso/Offset</th></tr></thead><tbody>';

            // OS
            const osMs = data.os_now_ms;
            const osDate = osMs ? new Date(osMs) : null;
            html += '<tr><td><strong>OS del server</strong><br><small class="text-muted">comando <code>date</code></small></td>';
            html += '<td>' + (osDate ? '<code>' + osDate.toISOString() + '</code><br><small>locale: ' + osDate.toLocaleString('it-IT') + '</small>' : '<em>non disponibile</em>') + '</td>';
            html += '<td>' + (data.os_offset ? '<code>' + escapeHtmlCf(data.os_offset) + '</code>' : '') + ' ' + (data.os_tz ? '<small class="text-muted">' + escapeHtmlCf(data.os_tz) + '</small>' : '') + '</td>';
            html += '</tr>';

            // JVM
            const jvmMs = data.jvm_now_ms;
            const jvmDate = jvmMs ? new Date(jvmMs) : null;
            html += '<tr><td><strong>JVM Java</strong><br><small class="text-muted">Instant.now()</small></td>';
            html += '<td>' + (jvmDate ? '<code>' + jvmDate.toISOString() + '</code>' : '') + '</td>';
            html += '<td><code>' + escapeHtmlCf(data.jvm_default_zone || '?') + '</code> <small class="text-muted">(' + escapeHtmlCf(data.jvm_offset || '?') + ')</small></td>';
            html += '</tr>';

            // MySQL
            const mysqlMs = data.mysql_now_ms;
            const mysqlDate = mysqlMs ? new Date(mysqlMs) : null;
            html += '<tr><td><strong>MySQL</strong><br><small class="text-muted">NOW() via UNIX_TIMESTAMP</small></td>';
            html += '<td>' + (mysqlDate ? '<code>' + mysqlDate.toISOString() + '</code><br><small>NOW(): ' + escapeHtmlCf(data.mysql_now || '') + '</small><br><small>UTC: ' + escapeHtmlCf(data.mysql_utc_now || '') + '</small>' : '<em class="text-danger">' + escapeHtmlCf(data.mysql_error || 'non disponibile') + '</em>') + '</td>';
            html += '<td>session: <code>' + escapeHtmlCf(data.mysql_session_tz || '?') + '</code><br>global: <code>' + escapeHtmlCf(data.mysql_global_tz || '?') + '</code><br>system: <code>' + escapeHtmlCf(data.mysql_system_tz || '?') + '</code></td>';
            html += '</tr>';

            // Browser (cliente)
            const browserNow = new Date();
            html += '<tr><td><strong>Browser (tu)</strong><br><small class="text-muted">Date.now()</small></td>';
            html += '<td><code>' + browserNow.toISOString() + '</code><br><small>locale: ' + browserNow.toLocaleString('it-IT') + '</small></td>';
            html += '<td>' + escapeHtmlCf(Intl.DateTimeFormat().resolvedOptions().timeZone || '?') + '</td>';
            html += '</tr>';

            html += '</tbody></table>';

            // Verdetto
            if (alignment === 'MISMATCH') {
                const skewMs = data.skew_mysql_vs_jvm_ms || 0;
                const skewMin = Math.round(skewMs / 60000);
                const sign = skewMs > 0 ? 'avanti' : 'indietro';
                html += '<div class="alert alert-warning mt-3 mb-0"><i class="fas fa-exclamation-triangle me-2"></i><strong>MySQL è ' + Math.abs(skewMin) + ' minuti ' + sign + ' rispetto al JVM</strong> — questo causa timestamp DKIM sbagliati. Clicca "Sincronizza MySQL al fuso del sistema" per correggere.</div>';
            } else if (alignment === 'OK') {
                html += '<div class="alert alert-success mt-3 mb-0"><i class="fas fa-check-circle me-2"></i><strong>Tutti allineati</strong> — i timestamp DKIM saranno corretti.</div>';
            }

            table.innerHTML = html;
        }

        function tzSyncToSystem() {
            if (!confirm('Sincronizzare MySQL al fuso orario del sistema (JVM)?\\n\\nQuesto esegue:\\n  SET GLOBAL time_zone = "<offset>"\\n  SET SESSION time_zone = "<offset>"\\n\\nServe il privilegio SUPER su MySQL. Se manca, verrà aggiornata solo la session corrente.')) return;
            tzPerformAction({ action: 'sync_to_system' });
        }

        function tzSetManual() {
            const v = document.getElementById('tzManualValue').value.trim();
            if (!v) { alert('Inserisci un valore (es. "+02:00", "SYSTEM", "Europe/Rome")'); return; }
            tzPerformAction({ action: 'set', value: v });
        }

        function tzPerformAction(payload) {
            const logEl = document.getElementById('tzDiagLog');
            logEl.innerHTML = '<div class="text-muted"><i class="fas fa-spinner fa-spin me-1"></i>Esecuzione in corso...</div>';
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
                    html = '<div class="alert alert-success py-2 mb-2"><i class="fas fa-check-circle me-1"></i>Operazione eseguita. Valore impostato: <code>' + escapeHtmlCf(data.desired_value || '') + '</code></div>' + html;
                } else {
                    html = '<div class="alert alert-danger py-2 mb-2"><i class="fas fa-times-circle me-1"></i>Errore: ' + escapeHtmlCf(data.error || 'sconosciuto') + '</div>' + html;
                }
                logEl.innerHTML = html;
                // Aggiorna i dati visualizzati
                renderTzDiag(data);
            }).catch(e => {
                logEl.innerHTML = '<div class="alert alert-danger py-2 mb-0">Errore rete: ' + e.message + '</div>';
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
                            <h5 class="modal-title" id="rotateModeChooserModalLabel"><i class="fas fa-sync-alt me-2"></i>Avvia rotazione DKIM</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Chiudi"></button>
                        </div>
                        <div class="modal-body">
                            <p class="mb-3">Come vuoi gestire il record DNS della nuova chiave?</p>

                            <div class="d-grid gap-2">
                                <button type="button" class="btn btn-success text-start" onclick="rotateDkimStartChooseCloudflare()">
                                    <div class="d-flex align-items-start">
                                        <i class="fas fa-cloud fa-2x me-3 mt-1"></i>
                                        <div>
                                            <strong>Automatica via Cloudflare</strong><br>
                                            <small>Il pannello crea e cancellerà il record TXT chiamando le API Cloudflare dell'account collegato: <strong id="rotateModeAccountLabel">—</strong>.</small>
                                            <div class="small mt-1 text-muted">→ Nessun intervento manuale richiesto. Schedule + auto-complete attivi.</div>
                                        </div>
                                    </div>
                                </button>

                                <button type="button" class="btn btn-outline-secondary text-start" onclick="rotateDkimStartChooseManual()">
                                    <div class="d-flex align-items-start">
                                        <i class="fas fa-edit fa-2x me-3 mt-1"></i>
                                        <div>
                                            <strong>Manuale (modifico il DNS io)</strong><br>
                                            <small>Il pannello genera la chiave ma NON usa l'API Cloudflare. Dovrai copiare il record TXT mostrato e aggiungerlo tu nel pannello DNS del tuo provider.</small>
                                            <div class="small mt-1 text-muted">→ Utile per test, audit, o se non vuoi che il pannello tocchi DNS automaticamente in questa specifica rotazione.</div>
                                        </div>
                                    </div>
                                </button>
                            </div>

                            <div class="alert alert-light mt-3 small mb-0">
                                <i class="fas fa-info-circle me-1"></i>In entrambi i casi: nuova chiave (selector unico) generata, vecchia chiave continua a firmare finché non attivi, dopo attivazione la vecchia resta nel DNS per 7 giorni (grace period).
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-link" data-bs-dismiss="modal">Annulla</button>
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
    private static String getChangeUsernameCard() {
        return """
                    <!-- Change Username -->
                    <div class="card mb-4">
                        <div class="card-header"><i class="fas fa-user-edit me-2"></i>Cambia Username</div>
                        <div class="card-body">
                            <div class="alert alert-info py-2 mb-3 small">
                                <i class="fas fa-info-circle me-1"></i>
                                Cambiando lo username, da subito il login va fatto col nuovo nome. Tutte le passkey, sessioni attive (compresa questa) e 2FA continuano a funzionare — non serve rifare login. Lo storico audit log mantiene il vecchio username sugli eventi passati per tracciabilità.
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Nuovo Username</label>
                                <input type="text" class="form-control" id="newUsername" placeholder="es. pietro.damico" autocomplete="off">
                                <small class="text-muted">3-50 caratteri, solo lettere/numeri/underscore/trattino/punto</small>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Password Attuale <small class="text-muted">(per conferma identità)</small></label>
                                <input type="password" class="form-control" id="currentPasswordForUsername" autocomplete="current-password">
                            </div>
                            <button class="btn btn-primary" onclick="changeUsername()">
                                <i class="fas fa-save me-1"></i>Cambia Username
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
                    <span><i class="fas fa-virus-slash me-2"></i><strong>Stato ClamAV (antivirus)</strong> <small class="ms-2" id="cavOverallStatus"></small></span>
                    <div class="d-flex gap-2">
                        <button class="btn btn-sm btn-info text-white" id="btnCavTestEicar" onclick="runCavTestEicar()" title="Test end-to-end: il pannello scrive un file EICAR temporaneo e verifica che clamdscan lo rilevi">
                            <i class="fas fa-flask me-1"></i>Test EICAR
                        </button>
                        <button class="btn btn-sm btn-warning d-none" id="btnCavFixAll" onclick="runCavFixAll()">
                            <i class="fas fa-magic me-1"></i>Risolvi tutto
                        </button>
                        <button class="btn btn-sm btn-light" onclick="loadClamavHealth()">
                            <i class="fas fa-sync me-1"></i>Ricontrolla
                        </button>
                    </div>
                </div>
                <div class="card-body" id="cavContainer">
                    <p class="text-muted mb-0"><i class="fas fa-spinner fa-spin me-1"></i>Diagnosi in corso...</p>
                </div>
                <div class="card-body border-top d-none" id="cavEicarResult">
                    <h6 class="mb-2"><i class="fas fa-flask me-1"></i>Risultato Test EICAR</h6>
                    <div id="cavEicarBody"></div>
                </div>
                <div class="card-body border-top d-none" id="cavFixAllReport">
                    <h6 class="mb-2"><i class="fas fa-list-check me-1"></i>Report risoluzione</h6>
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
                sel.innerHTML = names.map(n => '<option value="' + n + '">' + n + '</option>').join('');
                if (names.indexOf(prev) >= 0) sel.value = prev;
                if (onDone) onDone();
            }).catch(() => { if (onDone) onDone(); });
        }

        // Opzioni filtro disponibili, raggruppate per "famiglia" di jail.
        // Per ogni jail mostriamo SOLO le opzioni della sua famiglia (es. dovecot
        // non vede i preset postfix). Una opzione "custom" e' sempre disponibile.
        const FILTER_PRESETS = {
            postfix: [
                { value: 'postfix-sasl',
                  label: 'Sicuro (default)',
                  badge: 'CONSIGLIATO SE NON HAI SCANNER',
                  catches: 'Solo SASL authentication failed (i veri tentativi di login con password sbagliata).',
                  misses: 'Scanner SMTP e bot che provano AUTH e disconnettono senza errore SASL esplicito.' },
                { value: 'postfix[mode=more]',
                  label: 'Intermedio',
                  badge: '',
                  catches: 'SASL fail + improper command pipelining + reject base.',
                  misses: 'Probe che fanno solo connect/disconnect con auth=0/N.' },
                { value: 'postfix[mode=aggressive]',
                  label: 'Aggressivo',
                  badge: '★ CONSIGLIATO ANTI-BOT',
                  catches: 'Tutto sopra + disconnect con auth=0/N + scanner SMTP che probano e disconnettono. Cattura i bot tipo "low-and-slow".',
                  misses: 'Quasi nulla. Rischio falsi positivi: minimo (i tuoi client legittimi fanno Login OK, non disconnect-without-auth).' },
                { value: 'postfix[mode=ddos]',
                  label: 'DDoS',
                  badge: 'PER ATTACCHI VOLUMINOSI',
                  catches: 'Connessioni massive da stesso IP in pochi secondi.',
                  misses: 'Attacchi distribuiti da molti IP diversi.' }
            ],
            dovecot: [
                { value: 'dovecot',
                  label: 'Sicuro (default)',
                  badge: 'CONSIGLIATO SE NON HAI SCANNER',
                  catches: 'Solo i login IMAP/POP3 falliti con password sbagliata.',
                  misses: 'Scanner che probano TLS senza fare login.' },
                { value: 'dovecot[mode=aggressive]',
                  label: 'Aggressivo',
                  badge: '★ CONSIGLIATO ANTI-BOT',
                  catches: 'Login falliti + TLS handshake fail + cipher errors + scanner.',
                  misses: 'Quasi nulla. Rischio falsi positivi: minimo.' }
            ],
            rspamd: [
                { value: 'rspamd',
                  label: 'Standard',
                  badge: '',
                  catches: 'Email con score Rspamd elevato (>10).',
                  misses: 'Email borderline (score 5-10).' }
            ],
            other: [
                { value: '__custom__',
                  label: 'Personalizzato',
                  badge: '',
                  catches: 'Usa un filtro con nome custom (es. mail-panel-auth, roundcube-auth).',
                  misses: '' }
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
            currentEl.textContent = currentFilter || '(non impostato)';

            // Jail senza preset (mail-panel-auth, roundcube-auth, ...):
            // niente card, solo un input semplice prefillato col valore corrente.
            if (family === 'other') {
                container.innerHTML =
                    '<div class="alert alert-info py-2 px-3 mb-0 small">'
                    + '<i class="fas fa-info-circle me-1"></i>'
                    + 'La jail <code>' + esc(jail) + '</code> usa un filtro custom dedicato. '
                    + 'Modifica il nome qui sotto solo se sai cosa stai facendo (es. switch a un filtro alternativo).'
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
                    ? '<span class="badge bg-primary ms-2" style="font-size:.65rem"><i class="fas fa-check me-1"></i>in uso adesso</span>'
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
                     + '  <div><strong>' + esc(p.label) + '</strong> <code class="small text-muted ms-2">' + esc(p.value === '__custom__' ? 'altro filtro...' : p.value) + '</code>' + badgeHtml + inUseBadge + '</div>'
                     + '</div>'
                     + (p.catches ? '<div class="small text-success mb-0"><i class="fas fa-check-circle me-1"></i><b>Cattura:</b> ' + esc(p.catches) + '</div>' : '')
                     + (p.misses ? '<div class="small text-muted mb-0"><i class="fas fa-times-circle me-1"></i><b>Si perde:</b> ' + esc(p.misses) + '</div>' : '')
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
            status.textContent = 'Caricamento...';
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
                    status.textContent = 'Letto da jail.local';
                    status.className = 'ms-2 small text-success';
                } else {
                    status.textContent = 'Errore: ' + (data.message || 'sconosciuto');
                    status.className = 'ms-2 small text-danger';
                    renderIgnoreIpList(jail, []);
                    renderFilterOptions(jail, '');
                }
            }).catch(e => {
                status.textContent = 'Errore: ' + e.message;
                status.className = 'ms-2 small text-danger';
            });
        }

        function renderIgnoreIpList(jail, ips) {
            const el = document.getElementById('cfgIgnoreIpList');
            if (!el) return;
            const esc = (s) => { const d = document.createElement('div'); d.textContent = s == null ? '' : String(s); return d.innerHTML; };
            if (!ips || ips.length === 0) {
                el.innerHTML = '<span class="text-muted small"><i class="fas fa-info-circle me-1"></i>Nessun IP in whitelist per <code>' + esc(jail) + '</code>.</span>';
                return;
            }
            el.innerHTML = ips.map(ip =>
                '<span class="badge bg-light text-dark border me-1 mb-1" style="font-size:.8rem">' +
                '<code>' + esc(ip) + '</code>' +
                ' <button class="btn btn-link btn-sm p-0 ms-1" style="font-size:.75rem;color:#dc3545" onclick="removeIgnoreIp(\\'' + esc(ip) + '\\')" title="Rimuovi dalla whitelist"><i class="fas fa-times"></i></button>' +
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
                status.textContent = 'Seleziona un filtro dalla lista (o scrivi un filtro personalizzato)';
                status.className = 'ms-2 small text-danger';
                return;
            }
            if (!confirm('Cambiare il filtro di "' + jail + '" in:\\n\\n  ' + filter + '\\n\\nViene creato un backup del file di config prima della modifica, e fail2ban viene ricaricato.')) return;
            status.textContent = 'Salvataggio filtro...';
            status.className = 'ms-2 small text-muted';
            fetch('/api/fail2ban', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'set_jail_filter', jail: jail, filter: filter })
            }).then(r => r.json()).then(data => {
                status.textContent = (data.success ? 'OK: ' : 'Errore: ') + (data.message || '');
                status.className = 'ms-2 small ' + (data.success ? 'text-success' : 'text-danger');
                if (data.success) {
                    setTimeout(() => loadJailConfig(), 500);
                    if (typeof loadJailLiveState === 'function') setTimeout(loadJailLiveState, 1000);
                }
            }).catch(e => {
                status.textContent = 'Errore rete: ' + e.message;
                status.className = 'ms-2 small text-danger';
            });
        }

        function addIgnoreIp() {
            const jail = document.getElementById('cfgJailSelect').value;
            const ip = document.getElementById('cfgIgnoreIpInput').value.trim();
            const status = document.getElementById('cfgJailStatus');
            if (!ip) { status.textContent = 'Inserisci un IP/CIDR'; status.className = 'ms-2 small text-danger'; return; }
            fetch('/api/fail2ban', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'add_jail_ignoreip', jail: jail, ip: ip })
            }).then(r => r.json()).then(data => {
                status.textContent = (data.success ? 'OK: ' : 'Errore: ') + (data.message || '');
                status.className = 'ms-2 small ' + (data.success ? 'text-success' : 'text-danger');
                if (data.success) {
                    document.getElementById('cfgIgnoreIpInput').value = '';
                    loadJailConfig();
                }
            }).catch(e => {
                status.textContent = 'Errore rete: ' + e.message;
                status.className = 'ms-2 small text-danger';
            });
        }

        function removeIgnoreIp(ip) {
            const jail = document.getElementById('cfgJailSelect').value;
            const status = document.getElementById('cfgJailStatus');
            if (!confirm('Rimuovere ' + ip + ' dalla whitelist di "' + jail + '"?')) return;
            fetch('/api/fail2ban', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'remove_jail_ignoreip', jail: jail, ip: ip })
            }).then(r => r.json()).then(data => {
                status.textContent = (data.success ? 'OK: ' : 'Errore: ') + (data.message || '');
                status.className = 'ms-2 small ' + (data.success ? 'text-success' : 'text-danger');
                if (data.success) loadJailConfig();
            }).catch(e => {
                status.textContent = 'Errore rete: ' + e.message;
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
                status.textContent = 'Inserisci valori numerici';
                status.className = 'ms-2 small text-danger';
                return;
            }
            status.textContent = 'Salvataggio...';
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
                    status.textContent = data.message || 'Salvato';
                    status.className = 'ms-2 small text-success';
                    loadStatus();
                } else {
                    status.textContent = 'Errore: ' + (data.message || data.error || 'sconosciuto');
                    status.className = 'ms-2 small text-danger';
                }
            }).catch(e => {
                status.textContent = 'Errore: ' + e.message;
                status.className = 'ms-2 small text-danger';
            });
        }

        function saveJailConfigAllJails() {
            const maxRetry = parseInt(document.getElementById('cfgMaxRetry').value, 10);
            const findTime = parseInt(document.getElementById('cfgFindTime').value, 10);
            const banTime = parseInt(document.getElementById('cfgBanTime').value, 10);
            const status = document.getElementById('cfgJailStatus');
            if (!Number.isFinite(maxRetry) || !Number.isFinite(findTime) || !Number.isFinite(banTime)) {
                status.textContent = 'Inserisci valori numerici';
                status.className = 'ms-2 small text-danger';
                return;
            }
            if (!confirm('Applicare maxretry=' + maxRetry + ', findtime=' + findTime + 's, bantime=' + banTime + 's a TUTTE le jail attive (dovecot, postfix-auth, mail-panel-auth, ecc.)?\\n\\nQuesta operazione sovrascrive i valori esistenti in ciascuna jail.')) return;
            status.textContent = 'Applicazione in corso a tutte le jail...';
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
                    status.textContent = 'OK: applicato a ' + (data.success_count || 0) + ' jail';
                    status.className = 'ms-2 small text-success';
                } else {
                    let msg = data.message || data.error || 'errore';
                    if (Array.isArray(data.results)) {
                        const failed = data.results.filter(r => !r.success).map(r => r.jail + ': ' + r.message).join('\\n');
                        if (failed) msg += '\\n' + failed;
                    }
                    status.textContent = 'Errore: ' + msg;
                    status.className = 'ms-2 small text-danger';
                }
                loadStatus();
                if (typeof loadJailLiveState === 'function') loadJailLiveState();
            }).catch(e => {
                status.textContent = 'Errore: ' + e.message;
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
                            <span><i class="fas fa-cog me-2"></i>Configurazione Jail</span>
                            <select class="form-select form-select-sm w-auto" id="cfgJailSelect" onchange="loadJailConfig()">
                                <option value="mail-panel-auth">mail-panel-auth</option>
                            </select>
                        </div>
                        <div class="card-body">
                            <div class="row g-2 align-items-end">
                                <div class="col-md-4">
                                    <label class="form-label small mb-1">Max tentativi</label>
                                    <input type="number" class="form-control form-control-sm" id="cfgMaxRetry" min="1" max="100" value="5">
                                    <div class="mt-1 d-flex gap-1 flex-wrap">
                                        <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2" style="font-size:.7rem" onclick="setCfg('cfgMaxRetry',2)">2 <span class="text-success">★</span></button>
                                        <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2" style="font-size:.7rem" onclick="setCfg('cfgMaxRetry',3)">3</button>
                                        <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2" style="font-size:.7rem" onclick="setCfg('cfgMaxRetry',5)">5</button>
                                        <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2" style="font-size:.7rem" onclick="setCfg('cfgMaxRetry',10)">10</button>
                                    </div>
                                    <div class="form-text small mt-1">Falliti consecutivi prima del ban. <b>Consigliato: 2</b> (anti brute-force aggressivo).</div>
                                </div>
                                <div class="col-md-4">
                                    <label class="form-label small mb-1">Finestra (secondi)</label>
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
                                    <div class="form-text small mt-1">Finestra in cui contare i tentativi. <b>Consigliato: 1 h</b> (copre low-and-slow).</div>
                                </div>
                                <div class="col-md-4">
                                    <label class="form-label small mb-1">Durata ban (secondi)</label>
                                    <input type="number" class="form-control form-control-sm" id="cfgBanTime" min="60" max="31536000" value="3600">
                                    <div class="mt-1 d-flex gap-1 flex-wrap">
                                        <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2" style="font-size:.7rem" onclick="setCfg('cfgBanTime',600)">10 min</button>
                                        <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2" style="font-size:.7rem" onclick="setCfg('cfgBanTime',3600)">1 h</button>
                                        <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2" style="font-size:.7rem" onclick="setCfg('cfgBanTime',21600)">6 h</button>
                                        <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2" style="font-size:.7rem" onclick="setCfg('cfgBanTime',86400)">24 h <span class="text-success">★</span></button>
                                        <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2" style="font-size:.7rem" onclick="setCfg('cfgBanTime',604800)">1 sett.</button>
                                        <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2" style="font-size:.7rem" onclick="setCfg('cfgBanTime',2592000)">30 giorni</button>
                                        <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2" style="font-size:.7rem" onclick="setCfg('cfgBanTime',-1)">permanente</button>
                                    </div>
                                    <div class="form-text small mt-1">Durata del ban. <b>Consigliato: 24 h</b> (gli IP "puliti" si autosbloccano, i recidivi rientrano e si fanno ribannare → la jail <code>recidive</code> li banna piu' a lungo).</div>
                                </div>
                            </div>
                            <div class="alert alert-success py-2 px-2 mt-2 mb-0 small">
                                <i class="fas fa-shield-alt me-1"></i>
                                <b>Preset consigliato anti brute-force mail (con <code>recidive</code> attivo):</b>
                                <button type="button" class="btn btn-success btn-sm py-0 px-2 ms-2" style="font-size:.75rem" onclick="setCfg('cfgMaxRetry',2);setCfg('cfgFindTime',3600);setCfg('cfgBanTime',86400)">
                                    <i class="fas fa-magic me-1"></i>Aggressivo (2 / 1h / 24h)
                                </button>
                                <button type="button" class="btn btn-outline-success btn-sm py-0 px-2 ms-1" style="font-size:.75rem" onclick="setCfg('cfgMaxRetry',3);setCfg('cfgFindTime',1800);setCfg('cfgBanTime',21600)">
                                    Bilanciato (3 / 30m / 6h)
                                </button>
                                <button type="button" class="btn btn-outline-success btn-sm py-0 px-2 ms-1" style="font-size:.75rem" onclick="setCfg('cfgMaxRetry',5);setCfg('cfgFindTime',600);setCfg('cfgBanTime',3600)">
                                    Permissivo / Default (5 / 10m / 1h)
                                </button>
                                <div class="text-muted mt-1" style="font-size:.75rem">I preset compilano i 3 campi ma NON salvano: poi clicca "Salva" o "Applica a TUTTE le jail attive".</div>
                            </div>
                            <div class="d-flex gap-2 mt-3 flex-wrap">
                                <button class="btn btn-primary btn-sm" onclick="saveJailConfig()">
                                    <i class="fas fa-save me-1"></i>Salva (solo questa jail)
                                </button>
                                <button class="btn btn-warning btn-sm" onclick="saveJailConfigAllJails()">
                                    <i class="fas fa-clone me-1"></i>Applica a TUTTE le jail attive
                                </button>
                                <button class="btn btn-outline-secondary btn-sm" onclick="loadJailConfig()">
                                    <i class="fas fa-sync me-1"></i>Ricarica da file
                                </button>
                                <span id="cfgJailStatus" class="ms-2 small"></span>
                            </div>
                            <div class="alert alert-warning py-2 px-2 mt-3 mb-0 small">
                                <i class="fas fa-exclamation-triangle me-1"></i>
                                <b>Attenzione:</b> ogni jail (dovecot, postfix-auth, mail-panel-auth, rspamd, ...) ha la <b>propria</b>
                                <code>maxretry</code>/<code>findtime</code>/<code>bantime</code>. Salvando "solo questa jail" modifichi
                                <b>esclusivamente</b> quella selezionata in alto. Per propagare gli stessi valori a tutte le jail
                                attive usa <b>"Applica a TUTTE le jail attive"</b>.
                            </div>
                            <div class="alert alert-info py-1 px-2 mt-2 mb-0 small">
                                <i class="fas fa-info-circle me-1"></i>
                                Le modifiche vengono scritte in <code>/usr/local/etc/fail2ban/jail.local</code> e applicate subito con <code>fail2ban-client reload</code>.
                                Sopravvivono ai restart di fail2ban e del pannello.
                            </div>

                            <!-- ============ FILTRO ============ -->
                            <hr class="my-3">
                            <h6 class="mb-2"><i class="fas fa-filter me-2"></i>Che cosa Fail2ban riconosce come "attacco"</h6>
                            <p class="small text-muted mb-2">
                                Il filtro decide <b>quali righe del log mail vengono contate come tentativo fallito</b>.
                                Filtri diversi catturano pattern diversi: il filtro <i>sicuro</i> riconosce solo i login falliti classici,
                                il filtro <i>aggressivo</i> riconosce anche scanner e probe di bot. Cambiare filtro fa
                                <b>backup automatico</b> della configurazione.
                            </p>

                            <div class="small mb-2">
                                <span class="text-muted">Filtro attivo adesso:</span>
                                <code id="cfgFilterCurrent" class="ms-1">—</code>
                            </div>

                            <div id="cfgFilterOptions" class="d-grid gap-2 mb-2">
                                <!-- Le opzioni vengono renderizzate da JS in base alla jail selezionata -->
                            </div>

                            <div id="cfgFilterCustom" class="d-none mb-2 mt-2">
                                <label class="form-label small mb-1">Nome del filtro</label>
                                <input type="text" class="form-control form-control-sm" id="cfgFilter" placeholder="es: postfix[mode=aggressive]">
                                <div class="form-text small">Formato: <code>nome-filtro</code> oppure <code>nome-filtro[opzione=valore]</code>. Il file deve esistere in <code>/usr/local/etc/fail2ban/filter.d/</code>.</div>
                            </div>

                            <div class="d-flex gap-2">
                                <button class="btn btn-primary btn-sm" onclick="saveJailFilter()">
                                    <i class="fas fa-save me-1"></i>Salva filtro selezionato
                                </button>
                            </div>

                            <!-- ============ IGNOREIP (WHITELIST) ============ -->
                            <hr class="my-3">
                            <h6 class="mb-2"><i class="fas fa-shield-alt me-2"></i>IP in whitelist (ignoreip) di questa jail</h6>
                            <p class="small text-muted mb-2">
                                Questi IP/CIDR <strong>non verranno MAI bannati</strong> da questa jail, anche se fanno tentativi falliti.
                                Usalo per il tuo IP fisso (ufficio/VPN) per evitare di auto-bannarti.
                            </p>
                            <div id="cfgIgnoreIpList" class="mb-2"><span class="text-muted small">Caricamento...</span></div>
                            <div class="row g-2 align-items-end">
                                <div class="col-md-9">
                                    <input type="text" class="form-control form-control-sm" id="cfgIgnoreIpInput" placeholder="es: 192.168.1.10 oppure 192.168.0.0/24">
                                </div>
                                <div class="col-md-3">
                                    <button class="btn btn-success btn-sm w-100" onclick="addIgnoreIp()">
                                        <i class="fas fa-plus me-1"></i>Aggiungi a whitelist
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
                        <div class="card-header bg-warning text-dark"><i class="fas fa-shield-alt me-2"></i>Vault password caselle — Master key</div>
                        <div class="card-body">
                            <div class="alert alert-info py-2 mb-3 small">
                                <i class="fas fa-info-circle me-1"></i>
                                Le password delle caselle email vengono cifrate (AES-256-GCM) con una chiave master tenuta in <code>/usr/local/etc/mail-panel/master.key</code> (perms 600 root-only).
                                Da qui puoi <strong>fare un backup</strong> della chiave (consigliato: salvala nel tuo password manager) e <strong>ruotarla periodicamente</strong> per maggior sicurezza.
                            </div>

                            <h6 class="mt-3"><i class="fas fa-download me-1"></i>Backup master key</h6>
                            <p class="small text-muted mb-2">Esporta la chiave master in formato base64. Con questo file puoi recuperare il vault anche dopo una reinstallazione completa del server.</p>
                            <div class="row g-2 align-items-end mb-2">
                                <div class="col-md-6">
                                    <label class="form-label small mb-1">Password admin attuale (conferma identità)</label>
                                    <input type="password" class="form-control form-control-sm" id="vaultBackupPassword" autocomplete="current-password">
                                </div>
                                <div class="col-md-6">
                                    <button class="btn btn-outline-primary btn-sm" onclick="vaultBackupKey()">
                                        <i class="fas fa-download me-1"></i>Esporta master key
                                    </button>
                                </div>
                            </div>
                            <div id="vaultBackupResult" class="mt-2"></div>

                            <hr class="my-4">

                            <h6 class="mt-3 text-warning"><i class="fas fa-sync-alt me-1"></i>Rotazione master key</h6>
                            <div class="alert alert-warning py-2 small mb-2">
                                <i class="fas fa-exclamation-triangle me-1"></i>
                                <strong>Operazione critica.</strong> Genera una nuova chiave master, ri-cifra tutti i blob esistenti delle password mailbox, salva la nuova chiave su disco (con backup automatico della vecchia in <code>master.key.bak.&lt;timestamp&gt;</code>). Le password mail in chiaro restano invariate (i client mail continuano a funzionare). Esegui dopo: cambio admin, sospetto compromissione, audit periodico (raccomandato ogni 6-12 mesi).
                            </div>
                            <div class="row g-2 align-items-end mb-2">
                                <div class="col-md-6">
                                    <label class="form-label small mb-1">Password admin attuale</label>
                                    <input type="password" class="form-control form-control-sm" id="vaultRotatePassword" autocomplete="current-password">
                                </div>
                                <div class="col-md-6">
                                    <button class="btn btn-warning btn-sm" onclick="vaultRotateKey()">
                                        <i class="fas fa-sync-alt me-1"></i>Ruota master key
                                    </button>
                                </div>
                            </div>
                            <div id="vaultRotateResult" class="mt-2"></div>
                        </div>
                    </div>

""";
    }

    /**
     * Funzioni JS per cambio password e cambio username (settings page).
     * Estratte come metodo separato per ridurre la dimensione del text block.
     */
    private static String getSettingsAuthJs() {
        return """
        function changePassword() {
            const current = document.getElementById('currentPassword').value;
            const newPass = document.getElementById('newPassword').value;
            const confirm = document.getElementById('confirmNewPassword').value;

            if (!current || !newPass) {
                alert('Compila tutti i campi');
                return;
            }
            if (newPass.length < 8) {
                alert('La nuova password deve essere di almeno 8 caratteri');
                return;
            }
            if (newPass !== confirm) {
                alert('Le password non corrispondono');
                return;
            }

            fetch('/api/admins', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'change_password', current_password: current, new_password: newPass })
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    alert('Password cambiata con successo');
                    document.getElementById('currentPassword').value = '';
                    document.getElementById('newPassword').value = '';
                    document.getElementById('confirmNewPassword').value = '';
                } else {
                    alert(data.error || 'Errore nel cambio password');
                }
            });
        }

        function changeUsername() {
            const newUsername = document.getElementById('newUsername').value.trim();
            const current = document.getElementById('currentPasswordForUsername').value;

            if (!newUsername || !current) {
                alert('Compila entrambi i campi (nuovo username e password attuale).');
                return;
            }
            // Pre-check formato lato client (il server riverificherà)
            if (!/^[a-zA-Z0-9._-]{3,50}$/.test(newUsername)) {
                alert('Username non valido: 3-50 caratteri, solo lettere/numeri/underscore/trattino/punto.');
                return;
            }
            if (!confirm('Cambiare il tuo username in "' + newUsername + '"?\\n\\nDa subito dovrai usare questo username per fare login. La sessione corrente resta valida (non sarai sloggato). Le passkey, 2FA e password restano invariate.')) {
                return;
            }

            fetch('/api/admins', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'change_username', new_username: newUsername, current_password: current })
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    alert((data.message || 'Username cambiato con successo'));
                    document.getElementById('newUsername').value = '';
                    document.getElementById('currentPasswordForUsername').value = '';
                } else {
                    alert(data.error || 'Errore nel cambio username');
                }
            })
            .catch(e => alert('Errore rete: ' + e.message));
        }

        // ===== Vault management =====
        function vaultBackupKey() {
            const pw = document.getElementById('vaultBackupPassword').value;
            const out = document.getElementById('vaultBackupResult');
            if (!pw) { alert('Password admin richiesta.'); return; }
            out.innerHTML = '<div class="text-muted small"><i class="fas fa-spinner fa-spin me-1"></i>Verifica password ed esportazione in corso...</div>';
            fetch('/api/admins', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'vault_backup_key', current_password: pw })
            })
            .then(r => r.json())
            .then(data => {
                document.getElementById('vaultBackupPassword').value = '';
                if (!data.success) {
                    out.innerHTML = '<div class="alert alert-danger py-2 small mb-0"><i class="fas fa-times-circle me-1"></i>' + (data.error || 'errore') + '</div>';
                    return;
                }
                const keyB64 = data.key_base64 || '';
                const keyPath = data.key_file_path || '';
                let html = '<div class="alert alert-success py-2 mb-2 small">';
                html += '<i class="fas fa-check-circle me-1"></i><strong>Master key esportata.</strong> Salvala in un posto sicuro (password manager).';
                html += '</div>';
                html += '<div class="input-group input-group-sm mb-2">';
                html += '<span class="input-group-text">key (base64)</span>';
                html += '<input type="text" class="form-control font-monospace" id="vaultBackupKeyValue" value="" readonly>';
                html += '<button class="btn btn-outline-secondary" type="button" onclick="vaultCopyBackupKey()"><i class="fas fa-copy me-1"></i>Copia</button>';
                html += '<button class="btn btn-outline-primary" type="button" onclick="vaultDownloadBackupKey()"><i class="fas fa-download me-1"></i>Scarica .txt</button>';
                html += '</div>';
                html += '<div class="small text-muted">File sul server: <code>' + keyPath + '</code></div>';
                out.innerHTML = html;
                // Inietta il valore tramite property (non innerHTML) per evitare XSS / encoding glitch
                document.getElementById('vaultBackupKeyValue').value = keyB64;
                document.getElementById('vaultBackupKeyValue').dataset.raw = keyB64;
            })
            .catch(e => {
                out.innerHTML = '<div class="alert alert-danger py-2 small mb-0">Errore rete: ' + e.message + '</div>';
            });
        }

        function vaultCopyBackupKey() {
            const v = document.getElementById('vaultBackupKeyValue').value;
            if (!v) return;
            navigator.clipboard.writeText(v).then(() => {
                alert('Master key copiata negli appunti. Incollala SUBITO nel tuo password manager.');
            }).catch(() => {});
        }

        function vaultDownloadBackupKey() {
            const el = document.getElementById('vaultBackupKeyValue');
            const v = el ? (el.dataset.raw || el.value) : '';
            if (!v) return;
            const blob = new Blob([v + '\\n'], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'mail-panel-master-key-' + new Date().toISOString().replace(/[:.]/g, '-') + '.txt';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }

        function vaultRotateKey() {
            const pw = document.getElementById('vaultRotatePassword').value;
            const out = document.getElementById('vaultRotateResult');
            if (!pw) { alert('Password admin richiesta.'); return; }
            if (!confirm('Ruotare la master key del vault?\\n\\n• Genera una nuova chiave AES-256.\\n• Ri-cifra TUTTI i blob password mailbox esistenti.\\n• Salva la nuova chiave (la vecchia resta come backup file .bak.<timestamp>).\\n• Le password mail in chiaro NON cambiano (i client mail continuano a funzionare).\\n\\nProcedere?')) return;

            out.innerHTML = '<div class="text-muted small"><i class="fas fa-spinner fa-spin me-1"></i>Rotazione in corso (può richiedere alcuni secondi se hai molte caselle)...</div>';
            fetch('/api/admins', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'vault_rotate_key', current_password: pw })
            })
            .then(r => r.json())
            .then(data => {
                document.getElementById('vaultRotatePassword').value = '';
                if (!data.success) {
                    out.innerHTML = '<div class="alert alert-danger py-2 small mb-0"><i class="fas fa-times-circle me-1"></i>' + (data.error || 'errore') + '</div>';
                    return;
                }
                const s = data.summary || {};
                let html = '<div class="alert ' + ((s.failed || 0) > 0 ? 'alert-warning' : 'alert-success') + ' py-2 mb-0 small">';
                html += '<i class="fas fa-check-circle me-1"></i><strong>Rotazione completata.</strong><br>';
                html += 'Re-cifrati <strong>' + (s.reencrypted || 0) + '/' + (s.total || 0) + '</strong> blob password mailbox';
                if ((s.failed || 0) > 0) {
                    html += ', <strong>' + s.failed + ' falliti</strong> (usa "Cambia password massivo" nella pagina Caselle per quelli).';
                } else {
                    html += '.';
                }
                html += '<br><small class="text-muted">' + (data.message || '') + '</small>';
                html += '</div>';
                out.innerHTML = html;
            })
            .catch(e => {
                out.innerHTML = '<div class="alert alert-danger py-2 small mb-0">Errore rete: ' + e.message + '</div>';
            });
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
        return getHead("DNS", extraStyles) + getNavbar("dns") + """
    <div class="content container mt-4">
        <div class="content-container">
            <h2 class="mb-3"><i class="fas fa-server me-2"></i>Configurazione DNS</h2>

            <!-- BANNER: dominio corrente sempre visibile, con switcher -->
            <div class="card text-white mb-3" style="background:linear-gradient(135deg,#0d6efd 0%,#6610f2 100%)">
                <div class="card-body py-3">
                    <div class="row align-items-center g-3">
                        <div class="col-md-7">
                            <div class="small text-uppercase opacity-75 mb-1" style="letter-spacing:1px">Stai gestendo</div>
                            <h3 class="mb-0">
                                <i class="fas fa-globe me-2"></i>
                                <span id="currentDomainBanner" style="font-family:monospace">Nessun dominio selezionato</span>
                            </h3>
                        </div>
                        <div class="col-md-5">
                            <label class="small opacity-75 mb-1" for="domainSelect"><i class="fas fa-exchange-alt me-1"></i>Cambia dominio</label>
                            <select class="form-select" id="domainSelect">
                                <option value="">Seleziona dominio...</option>
                            </select>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Azioni globali (visibili sempre, ma operano solo se un dominio è selezionato) -->
            <div class="mb-3 d-flex gap-2 flex-wrap">
                <button class="btn btn-outline-primary" id="reloadDnsBtn" onclick="loadDnsRecords()" disabled>
                    <i class="fas fa-sync me-1"></i>Ricarica record DNS
                </button>
                <button class="btn btn-success" id="verifyDnsBtn" onclick="verifyDns()" disabled>
                    <i class="fas fa-check me-1"></i>Verifica configurazione DNS
                </button>
            </div>

            <div class="alert alert-info">
                <i class="fas fa-info-circle me-2"></i>
                <strong>Come funziona:</strong> seleziona un dominio nel banner sopra. Record DNS, DKIM, schedule e storico vengono caricati automaticamente. Copia i record nel tuo provider DNS (Cloudflare, Route53, etc.) e clicca "Verifica" per controllare che siano configurati correttamente.
            </div>

            <!-- Verification Results -->
            <div id="verificationResults" class="d-none mb-4">
                <div class="card">
                    <div class="card-header bg-dark text-white">
                        <i class="fas fa-clipboard-check me-2"></i>Risultati Verifica DNS
                    </div>
                    <div class="card-body" id="verificationBody">
                    </div>
                </div>
            </div>

            <!-- DNS Records -->
            <div id="dnsRecordsContainer">
                <p class="text-muted">Seleziona un dominio per visualizzare i record DNS necessari.</p>
            </div>

            <!-- Diagnostica orario server (timezone) -->
            <div class="card mt-4 border-info">
                <div class="card-header bg-info text-white d-flex justify-content-between align-items-center" style="cursor:pointer" onclick="toggleTzDiag()">
                    <span><i class="fas fa-clock me-2"></i>Diagnostica orario server (timezone)</span>
                    <span id="tzDiagStatusBadge"><span class="badge bg-light text-dark"><i class="fas fa-spinner fa-spin me-1"></i>controllo...</span></span>
                </div>
                <div class="card-body d-none" id="tzDiagBody">
                    <p class="small text-muted mb-2">Se i timestamp delle rotazioni risultano sbagliati, il problema è quasi sempre il fuso orario di MySQL non allineato col sistema operativo. Da qui puoi vedere lo stato e correggerlo.</p>
                    <div id="tzDiagTable">
                        <div class="text-muted small"><i class="fas fa-spinner fa-spin me-1"></i>Caricamento...</div>
                    </div>
                    <div class="mt-3 d-flex gap-2 flex-wrap">
                        <button class="btn btn-success btn-sm" onclick="tzSyncToSystem()"><i class="fas fa-magic me-1"></i>Sincronizza MySQL al fuso del sistema</button>
                        <div class="input-group input-group-sm" style="width:auto">
                            <input type="text" class="form-control form-control-sm" id="tzManualValue" placeholder='es. "+02:00" o "Europe/Rome"' style="width:200px">
                            <button class="btn btn-outline-secondary btn-sm" onclick="tzSetManual()"><i class="fas fa-cog me-1"></i>Imposta manualmente</button>
                        </div>
                        <button class="btn btn-outline-secondary btn-sm" onclick="loadTzDiag()"><i class="fas fa-sync me-1"></i>Ricontrolla</button>
                    </div>
                    <div id="tzDiagLog" class="mt-2 small"></div>
                </div>
            </div>

            <!-- Cloudflare integration Section -->
            <div class="card mt-4">
                <div class="card-header bg-warning text-dark d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-cloud me-2"></i>Account Cloudflare (per la rotazione DKIM automatica)</span>
                    <small id="cfAccountsCountBadge"></small>
                </div>
                <div class="card-body">
                    <p class="mb-2">Aggiungi qui i tuoi account Cloudflare. Ogni dominio può essere legato a un account diverso (utile se hai domini su Cloudflare differenti). I record DKIM verranno gestiti automaticamente con il token corretto.</p>

                    <details class="mb-3">
                        <summary>Come creare il token Cloudflare (clicca per i dettagli)</summary>
                        <div class="mt-2 p-3 bg-white border rounded small">
                            <ol class="mb-2">
                                <li>Accedi all'account Cloudflare desiderato e apri <a href="https://dash.cloudflare.com/profile/api-tokens" target="_blank" rel="noopener">My Profile → API Tokens</a>, clicca <strong>Create Token</strong>.</li>
                                <li>Usa il template <strong>"Edit zone DNS"</strong>.</li>
                                <li>Permessi minimi: <code>Zone:Read</code> + <code>DNS:Edit</code>.</li>
                                <li>Zone Resources: <strong>Include → Specific zone → &lt;tuo dominio&gt;</strong> (più sicuro che "All zones").</li>
                                <li>Crea il token, copialo (lo vedrai una sola volta) e incollalo qui sotto.</li>
                            </ol>
                            <div class="text-muted">I token sono salvati in DB locale e possono essere revocati in qualsiasi momento dal pannello Cloudflare.</div>
                        </div>
                    </details>

                    <!-- LISTA ACCOUNT -->
                    <h6 class="mt-3 mb-2"><i class="fas fa-users me-1"></i>Account configurati</h6>
                    <div id="cfAccountsList" class="mb-3">
                        <div class="text-muted small"><i class="fas fa-spinner fa-spin me-1"></i>Caricamento...</div>
                    </div>

                    <!-- AGGIUNGI ACCOUNT -->
                    <h6 class="mt-4 mb-2"><i class="fas fa-plus-circle me-1"></i>Aggiungi un nuovo account</h6>
                    <div class="row g-2 mb-2">
                        <div class="col-md-4">
                            <label class="form-label small mb-1">Etichetta <span class="text-danger">*</span></label>
                            <input type="text" class="form-control" id="cfNewLabel" placeholder="es. Account personale">
                        </div>
                        <div class="col-md-4">
                            <label class="form-label small mb-1">Email account <small class="text-muted">(per riconoscerlo)</small></label>
                            <input type="email" class="form-control" id="cfNewEmail" placeholder="tu@example.com">
                        </div>
                        <div class="col-md-4">
                            <label class="form-label small mb-1">Token API <span class="text-danger">*</span></label>
                            <input type="password" class="form-control" id="cfNewToken" placeholder="Incolla il token Cloudflare" autocomplete="off">
                        </div>
                    </div>
                    <div class="d-flex gap-2">
                        <button class="btn btn-outline-secondary btn-sm" type="button" onclick="cfTestNewToken()"><i class="fas fa-vial me-1"></i>Verifica token</button>
                        <button class="btn btn-primary btn-sm" type="button" onclick="cfAddAccount()"><i class="fas fa-save me-1"></i>Salva account</button>
                    </div>

                    <!-- ASSEGNAZIONE PER-DOMINIO -->
                    <h6 class="mt-4 mb-2"><i class="fas fa-link me-1"></i>Assegnazione domini → account</h6>
                    <div id="cfDomainAssignments" class="mb-2">
                        <div class="text-muted small"><i class="fas fa-spinner fa-spin me-1"></i>Caricamento...</div>
                    </div>
                </div>
            </div>

            <!-- DKIM Section -->
            <div class="card mt-4">
                <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-key me-2"></i>DKIM - Firma Digitale Email</span>
                    <small id="dkimRotationBadge"></small>
                </div>
                <div class="card-body">
                    <p>DKIM firma digitalmente le email in uscita, permettendo ai destinatari di verificare l'autenticita'.</p>
                    <div id="dkimStatus">Seleziona un dominio per vedere lo stato DKIM.</div>

                    <!-- Info account CF per dominio selezionato -->
                    <div id="dkimDomainCfInfo" class="mt-2"></div>

                    <!-- Last/Next rotation: sempre visibile quando DKIM è configurato -->
                    <div id="dkimRotationTimeline" class="mt-2 d-none">
                        <div class="row g-2">
                            <div class="col-md-6">
                                <div class="border rounded p-2 h-100" style="background:rgba(25,135,84,0.08)">
                                    <div class="small text-muted mb-1"><i class="fas fa-history me-1"></i>Ultima rotazione</div>
                                    <div id="dkimLastRotationText"><span class="text-muted">—</span></div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="border rounded p-2 h-100" style="background:rgba(13,110,253,0.08)">
                                    <div class="small text-muted mb-1"><i class="fas fa-calendar-day me-1"></i>Prossima rotazione</div>
                                    <div id="dkimNextRotationText"><span class="text-muted">—</span></div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Rotazione programmata -->
                    <div id="dkimSchedulePanel" class="mt-3 d-none">
                        <div class="border rounded p-3" style="background:rgba(13,110,253,0.05)">
                            <h6 class="mb-2"><i class="fas fa-calendar-alt me-1"></i>Rotazione programmata</h6>
                            <div class="row g-2 align-items-end">
                                <div class="col-md-5">
                                    <label class="form-label small mb-1">Frequenza</label>
                                    <select class="form-select form-select-sm" id="dkimSchedulePreset" onchange="onSchedulePresetChange()">
                                        <!-- popolato dinamicamente dai preset del server -->
                                    </select>
                                </div>
                                <div class="col-md-3" id="dkimScheduleCustomWrap" style="display:none">
                                    <label class="form-label small mb-1">Giorni custom</label>
                                    <input type="number" min="1" max="3650" class="form-control form-control-sm" id="dkimScheduleCustomDays" placeholder="es. 45">
                                </div>
                                <div class="col-md-4 text-md-end">
                                    <button class="btn btn-sm btn-primary" onclick="saveDkimSchedule()"><i class="fas fa-save me-1"></i>Salva schedule</button>
                                </div>
                            </div>
                            <div class="mt-2 small" id="dkimScheduleInfo"></div>
                        </div>
                    </div>

                    <div class="mt-3 d-flex gap-2 flex-wrap">
                        <button class="btn btn-warning" id="generateDkimBtn" onclick="generateDkim()" disabled>
                            <i class="fas fa-key me-1"></i>Genera Chiavi DKIM
                        </button>
                        <button class="btn btn-outline-primary" id="rotateDkimBtn" onclick="rotateDkimStart()" disabled>
                            <i class="fas fa-sync-alt me-1"></i>Avvia rotazione chiave
                        </button>
                        <button class="btn btn-outline-success" id="verifyActiveDkimBtn" onclick="verifyActiveDkim()" disabled>
                            <i class="fas fa-search me-1"></i>Verifica chiave attiva in DNS
                        </button>
                    </div>

                    <!-- Risultato verifica chiave attiva -->
                    <div id="dkimVerifyResult" class="mt-3"></div>

                    <!-- Pannello rotazione: visibile solo se in corso -->
                    <div id="dkimRotationPanel" class="mt-4 d-none">
                        <hr>
                        <h5><i class="fas fa-route me-2"></i>Rotazione chiave DKIM in corso</h5>
                        <div id="dkimRotationStepper" class="my-3"></div>
                        <div id="dkimRotationBody"></div>
                    </div>

                    <!-- Vecchi record DKIM (orphan cleanup) -->
                    <details class="mt-4">
                        <summary class="text-primary" style="cursor:pointer"><i class="fas fa-broom me-1"></i>Vecchi record DKIM in DNS (clicca per scansionare Cloudflare)</summary>
                        <div class="mt-3">
                            <p class="small text-muted mb-2">Trova tutti i record TXT <code>*._domainkey.&lt;dominio&gt;</code> presenti in Cloudflare e ti permette di rimuovere quelli orfani (rotazioni vecchie non pulite). I record attivi (current/pending/previous) sono protetti.</p>
                            <button class="btn btn-sm btn-outline-primary" onclick="scanDkimOrphans()" id="scanDkimOrphansBtn"><i class="fas fa-search me-1"></i>Scansiona record DKIM in Cloudflare</button>
                            <div id="dkimOrphansResult" class="mt-3"></div>
                        </div>
                    </details>

                    <!-- Storico rotazioni -->
                    <details class="mt-4" id="dkimHistoryDetails">
                        <summary class="text-primary" style="cursor:pointer"><i class="fas fa-history me-1"></i>Storico rotazioni DKIM (clicca per espandere)</summary>
                        <div id="dkimHistoryBody" class="mt-3">
                            <p class="text-muted small mb-0">Seleziona un dominio per vedere lo storico.</p>
                        </div>
                    </details>
                </div>
            </div>

""" + getDnsRotateModeChooserModal() + """
            <!-- Blacklist Check -->
            <div class="card mt-4 border-danger">
                <div class="card-header bg-danger text-white d-flex justify-content-between align-items-center flex-wrap gap-2">
                    <span><i class="fas fa-ban me-2"></i><strong>Check Blacklist (DNSBL/RHSBL)</strong> <small class="ms-2" id="blOverallStatus"></small></span>
                    <button class="btn btn-sm btn-light" id="btnBlCheck" onclick="runBlacklistCheck()">
                        <i class="fas fa-search me-1"></i>Verifica IP + domini
                    </button>
                </div>
                <div class="card-body" id="blContainer">
                    <p class="text-muted mb-0">
                        <i class="fas fa-info-circle me-1"></i>
                        Verifica se l'IP del server e i tuoi domini sono in blacklist pubbliche (Spamhaus, SpamCop, Barracuda, ecc.).
                        Se ci finisci, le mail rimbalzano o vanno in spam ovunque.
                    </p>
                    <p class="text-muted small mb-0">Click su "Verifica" — esegue 15+ check in parallelo (~3-5 secondi).</p>
                </div>
            </div>
        </div>
    </div>
""" + getFooter() + """
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
                console.warn('Auto-select dominio fallito:', e);
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
                el.textContent = 'Nessun dominio selezionato';
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
                const st = document.getElementById('dkimStatus');           if (st) st.innerHTML = 'Seleziona un dominio per vedere lo stato DKIM.';
                const sp = document.getElementById('dkimSchedulePanel');    if (sp) sp.classList.add('d-none');
                const rp = document.getElementById('dkimRotationPanel');    if (rp) rp.classList.add('d-none');
                const ci = document.getElementById('dkimDomainCfInfo');     if (ci) ci.innerHTML = '';
                const hb = document.getElementById('dkimHistoryBody');      if (hb) hb.innerHTML = '<p class="text-muted small mb-0">Seleziona un dominio per vedere lo storico.</p>';
                const rc = document.getElementById('dnsRecordsContainer');  if (rc) rc.innerHTML = '<p class="text-muted">Seleziona un dominio per visualizzare i record DNS necessari.</p>';
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

""" + getDnsJsTzDiag() + """
        // ===== Cloudflare multi-account integration =====
        // Cache locale per usare i dati in giro (rotateDkim, dkim card info)
        let cfAccounts = [];     // [{id,label,email,token_masked,...}]
        let cfDomainsCf = [];    // [{id,domain,cloudflare_account_id}]

        function escapeHtmlCf(s) {
            const d = document.createElement('div');
            d.textContent = s == null ? '' : String(s);
            return d.innerHTML;
        }

        function refreshCloudflare() {
            const badge = document.getElementById('cfAccountsCountBadge');
            const list = document.getElementById('cfAccountsList');
            const assign = document.getElementById('cfDomainAssignments');
            badge.innerHTML = '<span class="badge bg-light text-dark"><i class="fas fa-spinner fa-spin me-1"></i>caricamento</span>';

            fetch('/api/cloudflare').then(r => {
                if (!r.ok) throw new Error('HTTP ' + r.status);
                return r.json();
            }).then(data => {
                cfAccounts = data.accounts || [];
                cfDomainsCf = data.domains || [];

                badge.innerHTML = cfAccounts.length === 0
                    ? '<span class="badge bg-secondary">0 account</span>'
                    : '<span class="badge bg-success">' + cfAccounts.length + ' account configurat' + (cfAccounts.length === 1 ? 'o' : 'i') + '</span>';

                // Lista account
                if (cfAccounts.length === 0) {
                    list.innerHTML = '<div class="alert alert-secondary py-2 mb-0 small"><i class="fas fa-info-circle me-1"></i>Nessun account configurato. Aggiungine uno qui sotto per abilitare la rotazione DKIM automatica.</div>';
                } else {
                    let html = '<div class="table-responsive"><table class="table table-sm align-middle mb-0">';
                    html += '<thead class="table-light"><tr><th>Etichetta</th><th>Email account</th><th>Token</th><th>Domini collegati</th><th class="text-end">Azioni</th></tr></thead><tbody>';
                    cfAccounts.forEach(a => {
                        const linkedDomains = cfDomainsCf.filter(d => d.cloudflare_account_id === a.id).map(d => d.domain);
                        const safeLabel = escapeHtmlCf(a.label).replace(/'/g, "\\\\'");
                        // Riga di visualizzazione
                        html += '<tr id="cfRowView-' + a.id + '">';
                        html += '<td><strong>' + escapeHtmlCf(a.label) + '</strong></td>';
                        html += '<td>' + (a.email ? escapeHtmlCf(a.email) : '<span class="text-muted">—</span>') + '</td>';
                        html += '<td><code>' + escapeHtmlCf(a.token_masked) + '</code></td>';
                        html += '<td>' + (linkedDomains.length === 0
                            ? '<span class="text-muted small">nessuno</span>'
                            : linkedDomains.map(d => '<span class="badge bg-info text-dark me-1">' + escapeHtmlCf(d) + '</span>').join('')) + '</td>';
                        html += '<td class="text-end text-nowrap">';
                        html += '<button class="btn btn-sm btn-outline-primary me-1" title="Modifica" onclick="cfEditOpen(' + a.id + ')"><i class="fas fa-pen"></i></button>';
                        html += '<button class="btn btn-sm btn-outline-danger" title="Rimuovi" onclick="cfDeleteAccount(' + a.id + ', \\'' + safeLabel + '\\')"><i class="fas fa-trash"></i></button>';
                        html += '</td>';
                        html += '</tr>';
                        // Riga di edit (nascosta finché non clicchi la matita)
                        html += '<tr id="cfRowEdit-' + a.id + '" class="d-none table-warning"><td colspan="5">';
                        html += '<div class="row g-2 align-items-end">';
                        html += '  <div class="col-md-3"><label class="form-label small mb-1">Etichetta</label><input type="text" class="form-control form-control-sm" id="cfEditLabel-' + a.id + '" value="' + escapeHtmlCf(a.label) + '"></div>';
                        html += '  <div class="col-md-3"><label class="form-label small mb-1">Email account</label><input type="email" class="form-control form-control-sm" id="cfEditEmail-' + a.id + '" value="' + escapeHtmlCf(a.email || '') + '" placeholder="opzionale"></div>';
                        html += '  <div class="col-md-4"><label class="form-label small mb-1">Nuovo token <small class="text-muted">(lascia vuoto per non cambiarlo)</small></label><input type="password" class="form-control form-control-sm" id="cfEditToken-' + a.id + '" placeholder="Incolla un nuovo token solo se vuoi sostituirlo" autocomplete="off"></div>';
                        html += '  <div class="col-md-2 text-end">';
                        html += '    <button class="btn btn-sm btn-primary me-1" onclick="cfEditSave(' + a.id + ')"><i class="fas fa-save"></i> Salva</button>';
                        html += '    <button class="btn btn-sm btn-secondary" onclick="cfEditClose(' + a.id + ')"><i class="fas fa-times"></i></button>';
                        html += '  </div>';
                        html += '</div>';
                        html += '</td></tr>';
                    });
                    html += '</tbody></table></div>';
                    list.innerHTML = html;
                }

                // Tabella assegnazione domini -> account
                if (cfDomainsCf.length === 0) {
                    assign.innerHTML = '<div class="text-muted small">Aggiungi prima un dominio nella sezione Domini per gestirne l\\'assegnazione qui.</div>';
                } else {
                    let html = '<div class="table-responsive"><table class="table table-sm align-middle mb-0">';
                    html += '<thead class="table-light"><tr><th>Dominio</th><th>Modalità rotazione DKIM</th></tr></thead><tbody>';
                    cfDomainsCf.forEach(d => {
                        html += '<tr>';
                        html += '<td><code>' + escapeHtmlCf(d.domain) + '</code></td>';
                        html += '<td><select class="form-select form-select-sm" onchange="cfAssignDomain(' + d.id + ', this.value)">';
                        const cur = d.cloudflare_account_id || 0;
                        html += '<option value="0"' + (cur === 0 ? ' selected' : '') + '>Manuale (devo aggiungere il record TXT a mano)</option>';
                        cfAccounts.forEach(a => {
                            const lbl = a.label + (a.email ? ' — ' + a.email : '');
                            html += '<option value="' + a.id + '"' + (cur === a.id ? ' selected' : '') + '>Cloudflare: ' + escapeHtmlCf(lbl) + '</option>';
                        });
                        html += '</select></td>';
                        html += '</tr>';
                    });
                    html += '</tbody></table></div>';
                    assign.innerHTML = html;
                }

                // Aggiorna eventuale stato visibile della rotazione (se l'utente ha già selezionato un dominio)
                if (currentDomainId) loadDkimRotationStatus(currentDomainId);
            }).catch(e => {
                console.error('cf', e);
                badge.innerHTML = '<span class="badge bg-danger">Errore</span>';
                list.innerHTML = '<div class="alert alert-danger py-2 mb-0"><i class="fas fa-exclamation-triangle me-1"></i>Impossibile leggere gli account (' + e.message + '). Ricarica la pagina.</div>';
                assign.innerHTML = '';
            });
        }
        refreshCloudflare();

        function cfTestNewToken() {
            const tok = document.getElementById('cfNewToken').value.trim();
            if (!tok) { alert('Incolla prima il token'); return; }
            fetch('/api/cloudflare', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'test', token: tok })
            }).then(r => r.json()).then(data => {
                alert((data.success ? '✓ ' : '✗ ') + (data.message || data.error || ''));
            }).catch(e => alert('Errore rete: ' + e.message));
        }

        function cfAddAccount() {
            const label = document.getElementById('cfNewLabel').value.trim();
            const email = document.getElementById('cfNewEmail').value.trim();
            const token = document.getElementById('cfNewToken').value.trim();
            if (!label) { alert('Etichetta obbligatoria'); return; }
            if (!token) { alert('Token obbligatorio'); return; }
            fetch('/api/cloudflare', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'add', label: label, email: email, token: token })
            }).then(r => r.json()).then(data => {
                alert((data.success ? '✓ ' : '✗ ') + (data.message || data.error || ''));
                if (data.success) {
                    document.getElementById('cfNewLabel').value = '';
                    document.getElementById('cfNewEmail').value = '';
                    document.getElementById('cfNewToken').value = '';
                    refreshCloudflare();
                }
            }).catch(e => alert('Errore rete: ' + e.message));
        }

        function cfEditOpen(id) {
            // Chiudi eventuali altre righe di edit aperte
            cfAccounts.forEach(a => {
                if (a.id !== id) cfEditClose(a.id);
            });
            const view = document.getElementById('cfRowView-' + id);
            const edit = document.getElementById('cfRowEdit-' + id);
            if (view) view.classList.add('d-none');
            if (edit) edit.classList.remove('d-none');
        }

        function cfEditClose(id) {
            const view = document.getElementById('cfRowView-' + id);
            const edit = document.getElementById('cfRowEdit-' + id);
            if (view) view.classList.remove('d-none');
            if (edit) edit.classList.add('d-none');
            // Pulisci il campo token così non resta in memoria nel DOM
            const tok = document.getElementById('cfEditToken-' + id);
            if (tok) tok.value = '';
        }

        function cfEditSave(id) {
            const label = document.getElementById('cfEditLabel-' + id).value.trim();
            const email = document.getElementById('cfEditEmail-' + id).value.trim();
            const token = document.getElementById('cfEditToken-' + id).value.trim();
            if (!label) { alert('Etichetta obbligatoria'); return; }
            const payload = { action: 'update', account_id: id, label: label, email: email };
            // Includi il token SOLO se l'utente l'ha effettivamente compilato
            if (token) payload.token = token;
            fetch('/api/cloudflare', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            }).then(r => r.json()).then(data => {
                alert((data.success ? '✓ ' : '✗ ') + (data.message || data.error || ''));
                if (data.success) {
                    cfEditClose(id);
                    refreshCloudflare();
                }
            }).catch(e => alert('Errore rete: ' + e.message));
        }

        function cfDeleteAccount(id, label) {
            if (!confirm('Rimuovere l\\'account "' + label + '"?\\n\\nI domini collegati torneranno in modalità manuale.')) return;
            fetch('/api/cloudflare', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'delete', account_id: id })
            }).then(r => r.json()).then(data => {
                alert((data.success ? '✓ ' : '✗ ') + (data.message || data.error || ''));
                if (data.success) refreshCloudflare();
            }).catch(e => alert('Errore rete: ' + e.message));
        }

        function cfAssignDomain(domainId, accountId) {
            fetch('/api/cloudflare', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'assign', domain_id: domainId, account_id: parseInt(accountId) })
            }).then(r => r.json()).then(data => {
                if (!data.success) alert('✗ ' + (data.message || data.error || ''));
                refreshCloudflare();
            }).catch(e => alert('Errore rete: ' + e.message));
        }

        function loadDnsRecords() {
            const domain = document.getElementById('domainSelect').value;
            if (!domain) { alert('Seleziona un dominio'); return; }

            currentDomainId = document.getElementById('domainSelect').selectedOptions[0].dataset.id;
            document.getElementById('generateDkimBtn').disabled = false;

            fetch('/api/dns?domain=' + domain).then(r => r.json()).then(data => {
                if (!data.success) { alert('Errore: ' + data.error); return; }

                // Extract mail hostname parent domain
                const mailHostname = data.mail_hostname;
                const mailHostnameParts = mailHostname.split('.');
                const mailServerParentDomain = mailHostnameParts.slice(1).join('.');

                let html = '<div class="alert alert-info mb-4">';
                html += '<h5><i class="fas fa-info-circle me-2"></i>Riepilogo Zone DNS</h5>';
                html += '<p class="mb-2">Dovrai configurare record in <strong>2 zone DNS diverse</strong>:</p>';
                html += '<ul class="mb-0">';
                html += '<li><strong>' + mailServerParentDomain + '</strong> → per il record A del server mail</li>';
                html += '<li><strong>' + domain + '</strong> → per MX, SPF, DKIM, DMARC e altri record</li>';
                html += '</ul>';
                html += '</div>';

                html += '<div class="mb-3"><strong>Server IP:</strong> <code>' + data.server_ip + '</code> | <strong>Mail Hostname:</strong> <code>' + data.mail_hostname + '</code></div>';

                // Group records by zone
                let currentZone = '';
                data.records.forEach(r => {
                    // Add zone header if changed
                    if (r.dnsZone && r.dnsZone !== currentZone) {
                        currentZone = r.dnsZone;
                        html += '<div class="mt-4 mb-3 p-2 bg-primary text-white rounded"><strong><i class="fas fa-globe me-2"></i>Zona DNS: ' + currentZone + '</strong></div>';
                    }

                    const reqClass = r.required ? 'required' : 'optional';
                    const badge = r.required ? '<span class="badge bg-danger">Richiesto</span>' : '<span class="badge bg-secondary">Opzionale</span>';
                    // ID univoco basato su name+type per il matching con la verifica
                    const recordKey = (r.name + '|' + r.type).replace(/[^a-zA-Z0-9_|.\\-]/g, '_');
                    html += '<div class="dns-record ' + reqClass + '" data-record-key="' + recordKey + '" data-record-name="' + r.name + '" data-record-type="' + r.type + '" data-record-zone="' + (r.dnsZone || '') + '">';
                    html += '<div class="d-flex justify-content-between align-items-start">';
                    html += '<div><span class="record-type">' + r.type + '</span> ' + badge;
                    // Status badge — placeholder finché non parte la verifica automatica
                    html += ' <span class="record-status-badge" data-status-key="' + recordKey + '"><span class="badge bg-light text-dark border"><i class="fas fa-spinner fa-spin me-1"></i>Verifica in corso...</span></span>';
                    if (r.dnsZone) {
                        html += ' <small class="text-muted">su ' + r.dnsZone + '</small>';
                    }
                    html += '</div>';
                    html += '<i class="fas fa-copy copy-btn" onclick="copyToClipboard(this.parentElement.parentElement)" title="Copia"></i>';
                    html += '</div>';
                    html += '<div class="mt-2"><strong>Nome:</strong> <code>' + r.name + '</code></div>';
                    html += '<div class="mt-1"><strong>Valore:</strong> <code style="word-break:break-all">' + r.value + '</code></div>';
                    html += '<small class="text-muted">' + r.description + '</small>';
                    // Area dettagli verifica (popolata dopo verifyDnsAuto)
                    html += '<div class="record-verify-detail mt-2" data-detail-key="' + recordKey + '"></div>';
                    if (r.explanation) {
                        html += '<details class="mt-2"><summary><i class="fas fa-cog me-1"></i>Istruzioni dettagliate Cloudflare</summary><div class="mt-2 p-3 bg-white border rounded" style="font-size:0.9rem">' + r.explanation + '</div></details>';
                    }
                    html += '</div>';
                });

                document.getElementById('dnsRecordsContainer').innerHTML = html;

                // Load DKIM status (parallelo alla verifica DNS)
                loadDkimStatus(currentDomainId);
                // Verifica automatica e silenziosa di tutti i record DNS
                verifyDnsAuto();
            });
        }

        /**
         * Verifica DNS in background: per ogni record, mostra un badge inline
         * "Configurato ✓" / "Da configurare ⚠" / "Verifica web" etc., così l'utente
         * sa al volo cosa serve fare senza dover scendere al pannello "Verifica" in fondo.
         */
        /**
         * Calcola l'FQDN di un record dato il suo nome relativo (può essere "@", una
         * sottoparte, o già un FQDN) e la zona DNS di appartenenza.
         * Necessario perché i record generati usano nomi relativi ("@", "mail._domainkey"),
         * mentre i check del verifier usano FQDN ("domain-a.test", "mail._domainkey.domain-a.test").
         */
        function recordFqdn(name, zone) {
            if (!name || name === '@' || name === '') return zone || '';
            // Se è già FQDN (contiene la zona alla fine) lasciamo invariato
            if (zone && name.toLowerCase().endsWith('.' + zone.toLowerCase())) return name;
            if (zone && name.toLowerCase() === zone.toLowerCase()) return name;
            // Altrimenti concatena con la zona
            return zone ? (name + '.' + zone) : name;
        }

        function verifyDnsAuto() {
            const domain = document.getElementById('domainSelect').value;
            if (!domain) return;
            fetch('/api/dns', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'verify', domain: domain })
            }).then(r => r.json()).then(data => {
                if (!data.success) {
                    document.querySelectorAll('.record-status-badge').forEach(el => {
                        el.innerHTML = '<span class="badge bg-secondary"><i class="fas fa-question-circle me-1"></i>Verifica non disponibile</span>';
                    });
                    return;
                }
                // Mappa fqdn → check (i check del verifier usano sempre FQDN come name)
                const checkByFqdn = new Map();
                (data.checks || []).forEach(c => {
                    if (c.name) checkByFqdn.set(c.name.toLowerCase(), c);
                });

                let okCount = 0, koCount = 0, unkCount = 0;
                document.querySelectorAll('.dns-record').forEach(card => {
                    const rname = card.getAttribute('data-record-name');
                    const rtype = card.getAttribute('data-record-type');
                    const rzone = card.getAttribute('data-record-zone') || '';
                    const key = card.getAttribute('data-record-key');
                    const badgeWrap = card.querySelector('[data-status-key="' + key + '"]');
                    const detailWrap = card.querySelector('[data-detail-key="' + key + '"]');
                    if (!badgeWrap) return;

                    // Costruisci l'FQDN corrispondente al record per matchare il check
                    const fqdn = recordFqdn(rname, rzone).toLowerCase();
                    let check = checkByFqdn.get(fqdn);
                    // Fallback: prova anche col rname diretto (per i record che hanno già FQDN)
                    if (!check && rname) check = checkByFqdn.get(rname.toLowerCase());
                    if (!check) {
                        // Nessun check per questo record (es. SRV autodiscover, MTA-STS policy, alcuni TXT secondari)
                        badgeWrap.innerHTML = '<span class="badge bg-light text-dark border"><i class="fas fa-minus-circle me-1"></i>Non verificato</span>';
                        if (detailWrap) detailWrap.innerHTML = '';
                        unkCount++;
                        return;
                    }

                    if (check.passed) {
                        badgeWrap.innerHTML = '<span class="badge bg-success"><i class="fas fa-check-circle me-1"></i>Configurato correttamente</span>';
                        if (detailWrap) {
                            detailWrap.innerHTML = '<div class="alert alert-success py-1 px-2 mb-0 small mt-2"><i class="fas fa-check me-1"></i><strong>Nessuna azione richiesta</strong> — il record DNS risulta già configurato correttamente. ' + (check.message ? escapeHtmlBl(check.message) : '') + '</div>';
                        }
                        // Stile leggero: bordo verde
                        card.style.borderLeft = '4px solid #198754';
                        okCount++;
                    } else {
                        badgeWrap.innerHTML = '<span class="badge bg-warning text-dark"><i class="fas fa-exclamation-triangle me-1"></i>Da configurare</span>';
                        if (detailWrap) {
                            let html = '<div class="alert alert-warning py-2 px-2 mb-0 small mt-2"><i class="fas fa-exclamation-triangle me-1"></i><strong>Azione richiesta:</strong> ' + escapeHtmlBl(check.message || 'record mancante o errato') + '.';
                            if (check.current_value) {
                                const shortCur = check.current_value.length > 100 ? check.current_value.substring(0, 100) + '…' : check.current_value;
                                html += '<div class="mt-1"><span class="text-muted">Trovato in DNS:</span> <code class="small">' + escapeHtmlBl(shortCur) + '</code></div>';
                            }
                            html += '</div>';
                            detailWrap.innerHTML = html;
                        }
                        card.style.borderLeft = '4px solid #ffc107';
                        koCount++;
                    }
                });

                // Banner riassuntivo in cima al contenitore
                const container = document.getElementById('dnsRecordsContainer');
                if (container && (okCount + koCount + unkCount) > 0) {
                    const summary = document.createElement('div');
                    let cls, icon, msg;
                    if (koCount === 0 && okCount > 0) {
                        cls = 'alert-success'; icon = 'check-circle';
                        msg = '<strong>Tutto a posto!</strong> ' + okCount + ' record DNS verificati e configurati correttamente.';
                    } else if (koCount > 0) {
                        cls = 'alert-warning'; icon = 'exclamation-triangle';
                        msg = '<strong>' + koCount + ' record DNS da configurare</strong> e ' + okCount + ' già a posto. Controlla i badge gialli qui sotto.';
                    } else {
                        cls = 'alert-info'; icon = 'info-circle';
                        msg = 'Verifica completata. ' + unkCount + ' record non sono soggetti a verifica automatica.';
                    }
                    summary.className = 'alert ' + cls + ' mb-3';
                    summary.innerHTML = '<i class="fas fa-' + icon + ' me-2"></i>' + msg + ' <span class="ms-2 small text-muted">(' + okCount + ' OK · ' + koCount + ' da fare · ' + unkCount + ' non verificati)</span>';
                    // Inserisci prima del primo .dns-record (o all'inizio se non c'è)
                    const firstRecord = container.querySelector('.dns-record');
                    if (firstRecord) container.insertBefore(summary, firstRecord);
                    else container.insertBefore(summary, container.firstChild);
                }
            }).catch(e => {
                console.error('verifyDnsAuto error', e);
                document.querySelectorAll('.record-status-badge').forEach(el => {
                    el.innerHTML = '<span class="badge bg-secondary"><i class="fas fa-times me-1"></i>Verifica fallita</span>';
                });
            });
        }

        function loadDkimStatus(domainId) {
            fetch('/api/dkim?id=' + domainId).then(r => r.json()).then(data => {
                const status = document.getElementById('dkimStatus');
                const rotateBtn = document.getElementById('rotateDkimBtn');
                const verifyBtn = document.getElementById('verifyActiveDkimBtn');
                const generateBtn = document.getElementById('generateDkimBtn');
                if (data.configured) {
                    status.innerHTML = '<div class="alert alert-success"><i class="fas fa-check-circle me-2"></i><strong>DKIM Configurato!</strong><br>' +
                        'Selector: <code>' + data.selector + '</code><br>' +
                        'Record DNS: <code>' + data.dns_record_name + '</code></div>';
                    if (rotateBtn) rotateBtn.disabled = false;
                    if (verifyBtn) verifyBtn.disabled = false;
                    // DKIM già configurato: il bottone "Genera Chiavi DKIM" deve essere NASCOSTO/disabilitato
                    // perché sovrascriverebbe la chiave attiva senza il workflow di rotazione (no grace period).
                    // Per cambiare chiave su un dominio già configurato, USARE "Avvia rotazione chiave".
                    if (generateBtn) {
                        generateBtn.style.display = 'none';
                        generateBtn.disabled = true;
                    }
                } else {
                    status.innerHTML = '<div class="alert alert-warning"><i class="fas fa-exclamation-triangle me-2"></i>DKIM non configurato per questo dominio.<br><small class="text-muted">Clicca "Genera Chiavi DKIM" per il setup iniziale.</small></div>';
                    if (rotateBtn) rotateBtn.disabled = true;
                    if (verifyBtn) verifyBtn.disabled = true;
                    // DKIM mai configurato: SOLO ora il "Genera Chiavi DKIM" ha senso (setup iniziale)
                    if (generateBtn) {
                        generateBtn.style.display = '';
                        generateBtn.disabled = false;
                    }
                    // Nascondi anche i box timeline se non c'è DKIM
                    const tl = document.getElementById('dkimRotationTimeline');
                    if (tl) tl.classList.add('d-none');
                }
                const vr = document.getElementById('dkimVerifyResult'); if (vr) vr.innerHTML = '';
                loadDkimRotationStatus(domainId);
                loadDkimHistory(domainId);
                loadDkimSchedule(domainId);
            });
        }

        // ===== Rotazione programmata =====
        let dkimSchedulePresets = [];

        // Parsing tollerante per timestamp del server.
        // Numero (epoch ms) → unambiguo, preferito quando disponibile.
        // ISO 8601 con Z o offset → parsato come UTC.
        // Fallback legacy "yyyy-MM-dd HH:mm:ss" senza TZ → assunto ora locale.
        function parseTs(s) {
            if (s == null || s === '') return null;
            // Numero o stringa numerica = epoch milliseconds
            if (typeof s === 'number') {
                const d = new Date(s);
                return isNaN(d.getTime()) ? null : d;
            }
            const v = String(s);
            if (/^\\d{10,}$/.test(v)) {
                const d = new Date(parseInt(v));
                return isNaN(d.getTime()) ? null : d;
            }
            if (/T.*([Zz]|[+\\-]\\d{2}:?\\d{2})$/.test(v)) {
                const d = new Date(v);
                return isNaN(d.getTime()) ? null : d;
            }
            const norm = v.replace(' ', 'T').replace(/\\.\\d+$/, '');
            const d = new Date(norm);
            return isNaN(d.getTime()) ? null : d;
        }

        // Wrapper: preferisce data._ms (epoch) se presente, altrimenti data[key].
        // Uso: pickTs(data, 'last_rotation_at') → cerca data.last_rotation_at_ms, poi data.last_rotation_at.
        function pickTs(obj, key) {
            if (!obj) return null;
            const ms = obj[key + '_ms'];
            if (ms != null && ms !== '') return parseTs(ms);
            return parseTs(obj[key]);
        }

        // Formatta tempo relativo: "3 ore fa", "tra 27 giorni", ecc.
        function formatRelativeTime(date) {
            if (!date) return '';
            const ms = date.getTime() - Date.now();
            const past = ms < 0;
            const abs = Math.abs(ms);
            const sec = Math.floor(abs / 1000);
            const min = Math.floor(sec / 60);
            const hr  = Math.floor(min / 60);
            const day = Math.floor(hr / 24);
            const mon = Math.floor(day / 30);
            const yr  = Math.floor(day / 365);
            let val, unit;
            if (yr > 0)        { val = yr;  unit = (yr === 1 ? 'anno' : 'anni'); }
            else if (mon > 0)  { val = mon; unit = (mon === 1 ? 'mese' : 'mesi'); }
            else if (day > 0)  { val = day; unit = (day === 1 ? 'giorno' : 'giorni'); }
            else if (hr  > 0)  { val = hr;  unit = (hr === 1 ? 'ora' : 'ore'); }
            else if (min > 0)  { val = min; unit = (min === 1 ? 'minuto' : 'minuti'); }
            else               { val = sec; unit = (sec === 1 ? 'secondo' : 'secondi'); }
            if (sec < 5 && !past) return 'tra pochi secondi';
            if (sec < 5 && past)  return 'pochi secondi fa';
            return past ? (val + ' ' + unit + ' fa') : ('tra ' + val + ' ' + unit);
        }

        // Formatta data assoluta in italiano: "15 mag 2026 16:08"
        function formatItalianDate(date) {
            if (!date) return '';
            const months = ['gen','feb','mar','apr','mag','giu','lug','ago','set','ott','nov','dic'];
            const dd = String(date.getDate()).padStart(2, '0');
            const mm = months[date.getMonth()];
            const yyyy = date.getFullYear();
            const hh = String(date.getHours()).padStart(2, '0');
            const mi = String(date.getMinutes()).padStart(2, '0');
            return dd + ' ' + mm + ' ' + yyyy + ' ' + hh + ':' + mi;
        }

        // Aggiorna i due box prominenti "Ultima/Prossima rotazione"
        function renderRotationTimeline(data, hasDkim) {
            const wrap = document.getElementById('dkimRotationTimeline');
            const lastEl = document.getElementById('dkimLastRotationText');
            const nextEl = document.getElementById('dkimNextRotationText');
            if (!hasDkim) {
                wrap.classList.add('d-none');
                return;
            }
            wrap.classList.remove('d-none');

            // DIAGNOSTICA: confronta clock server vs browser. Skew > 5 min = problema reale.
            if (data.server_now_ms) {
                const skewMs = data.server_now_ms - Date.now();
                if (Math.abs(skewMs) > 5 * 60 * 1000) {
                    const skewMin = Math.round(skewMs / 60000);
                    const sign = skewMin > 0 ? 'avanti' : 'indietro';
                    console.warn('[DKIM] Server clock skew: ' + skewMin + ' min ' + sign + ' rispetto al browser');
                }
            }

            // Ultima rotazione: il "now" di riferimento è il SERVER (server_now_ms se disponibile),
            // non il browser. Questo evita che skew di clock tra server e browser facciano
            // sembrare la rotazione "nel futuro".
            const referenceNowMs = data.server_now_ms || Date.now();
            const lastTs = pickTs(data, 'last_rotation_at');
            if (lastTs) {
                const deltaMs = lastTs.getTime() - referenceNowMs;
                let relText;
                let showFixButtons = false;
                if (deltaMs > 0 && deltaMs < 60 * 1000) {
                    relText = 'appena adesso';
                } else if (deltaMs > 0) {
                    const minAhead = Math.round(deltaMs / 60000);
                    relText = '<span class="text-warning" title="Il timestamp risulta ' + minAhead + ' minuti nel futuro rispetto al clock del server. È un valore fossile salvato prima del fix timezone — usa i bottoni per correggerlo.">incongruenza dati ⚠ (+' + minAhead + ' min)</span>';
                    showFixButtons = true;
                } else {
                    const fakeDate = new Date(lastTs.getTime() - (Date.now() - referenceNowMs));
                    relText = formatRelativeTime(fakeDate);
                }
                let html = '<strong>' + formatItalianDate(lastTs) + '</strong>' +
                    '<div class="small text-muted">' + relText + '</div>';
                if (showFixButtons) {
                    html += '<div class="mt-2 d-flex gap-1 flex-wrap">';
                    html += '<button class="btn btn-sm btn-outline-warning" onclick="resetLastRotationTimestamp()" title="Imposta il timestamp \\'ultima rotazione\\' a ora"><i class="fas fa-sync-alt me-1"></i>Reset a ora</button>';
                    html += '<button class="btn btn-sm btn-outline-secondary" onclick="clearLastRotationTimestamp()" title="Cancella il timestamp (mostra \\'Mai effettuata\\')"><i class="fas fa-eraser me-1"></i>Cancella</button>';
                    html += '</div>';
                }
                lastEl.innerHTML = html;
            } else {
                lastEl.innerHTML = '<span class="text-warning"><i class="fas fa-exclamation-triangle me-1"></i>Mai effettuata</span>' +
                    '<div class="small text-muted">Nessuna rotazione registrata per questo dominio</div>';
            }

            // Prossima rotazione (calcolata se schedule attivo)
            const nextTs = pickTs(data, 'next_rotation_at');
            const interval = data.interval_days || 0;
            if (interval === 0) {
                nextEl.innerHTML = '<span class="text-muted"><i class="fas fa-pause-circle me-1"></i>Non programmata</span>' +
                    '<div class="small text-muted">La rotazione automatica è disattivata. Avviala manualmente quando vuoi.</div>';
            } else if (nextTs) {
                const isOverdue = nextTs.getTime() <= Date.now();
                const badge = isOverdue
                    ? '<span class="badge bg-danger ms-1">in ritardo</span>'
                    : '';
                nextEl.innerHTML = '<strong>' + formatItalianDate(nextTs) + '</strong> ' + badge +
                    '<div class="small text-muted">' + formatRelativeTime(nextTs) + ' (ogni ' + interval + ' giorni)</div>';
            } else {
                nextEl.innerHTML = '<strong>Al prossimo check</strong> <span class="badge bg-warning text-dark ms-1">subito</span>' +
                    '<div class="small text-muted">Schedule attivo ogni ' + interval + ' giorni, ma nessuna rotazione ancora registrata.</div>';
            }
        }

        function loadDkimSchedule(domainId) {
            const panel = document.getElementById('dkimSchedulePanel');
            const info = document.getElementById('dkimScheduleInfo');
            panel.classList.remove('d-none');
            info.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Caricamento...';
            fetch('/api/dkim', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'schedule_get', domain_id: parseInt(domainId) })
            }).then(r => r.json()).then(data => {
                if (!data.success) {
                    info.innerHTML = '<span class="text-danger">' + escapeHtmlBl(data.error || 'errore') + '</span>';
                    return;
                }
                // Aggiorna i due box prominenti
                renderRotationTimeline(data, true);
                dkimSchedulePresets = data.presets || [];
                const cur = data.interval_days || 0;
                // Popola la dropdown con i preset + l'opzione "Custom"
                const sel = document.getElementById('dkimSchedulePreset');
                let optionsHtml = '';
                let matched = false;
                dkimSchedulePresets.forEach(p => {
                    const isSel = (p.days === cur);
                    if (isSel) matched = true;
                    optionsHtml += '<option value="' + p.days + '"' + (isSel ? ' selected' : '') + '>' + escapeHtmlBl(p.label) + (p.days > 0 ? ' (' + p.days + ' giorni)' : '') + '</option>';
                });
                // Custom: se cur > 0 ma non corrisponde a nessun preset, selezioniamo custom
                optionsHtml += '<option value="custom"' + (!matched && cur > 0 ? ' selected' : '') + '>Custom (giorni specifici)</option>';
                sel.innerHTML = optionsHtml;
                // Mostra/nascondi campo custom
                if (!matched && cur > 0) {
                    document.getElementById('dkimScheduleCustomWrap').style.display = '';
                    document.getElementById('dkimScheduleCustomDays').value = cur;
                } else {
                    document.getElementById('dkimScheduleCustomWrap').style.display = 'none';
                    document.getElementById('dkimScheduleCustomDays').value = '';
                }
                // Riepilogo testuale
                let html = '';
                if (cur === 0) {
                    html = '<span class="text-muted"><i class="fas fa-info-circle me-1"></i>Rotazione automatica programmata: <strong>disattivata</strong>. Devi avviare la rotazione manualmente quando vuoi.</span>';
                } else {
                    html = '<i class="fas fa-clock text-primary me-1"></i>Rotazione automatica ogni <strong>' + cur + ' giorni</strong>. ';
                    if (data.last_rotation_at) {
                        html += 'Ultima rotazione: <strong>' + escapeHtmlBl(data.last_rotation_at) + '</strong>. ';
                    } else {
                        html += '<span class="text-warning">Nessuna rotazione ancora effettuata.</span> ';
                    }
                    if (data.next_rotation_at) {
                        html += 'Prossima rotazione prevista: <strong>' + escapeHtmlBl(data.next_rotation_at) + '</strong>.';
                    }
                    if (!cloudflareConfigured) {
                        html += '<br><span class="text-warning"><i class="fas fa-exclamation-triangle me-1"></i><strong>Attenzione:</strong> per attivare lo schedule in automatico è necessario un account Cloudflare assegnato a questo dominio. Senza CF, lo schedule resta inattivo.</span>';
                    } else {
                        html += '<br><small class="text-muted">Lo scheduler creerà la nuova chiave, pubblicherà il record TXT, attenderà ' + (data.auto_activate_after_hours || 24) + 'h di propagazione, attiverà la firma, poi dopo ' + (data.grace_period_days || 7) + ' giorni di grace period rimuoverà la vecchia chiave. Tutto automatico.</small>';
                    }
                }
                info.innerHTML = html;
            }).catch(e => {
                info.innerHTML = '<span class="text-danger">Errore rete: ' + e.message + '</span>';
            });
        }

        function onSchedulePresetChange() {
            const sel = document.getElementById('dkimSchedulePreset');
            const wrap = document.getElementById('dkimScheduleCustomWrap');
            if (sel.value === 'custom') {
                wrap.style.display = '';
            } else {
                wrap.style.display = 'none';
            }
        }

        function resetLastRotationTimestamp() {
            if (!currentDomainId) return;
            if (!confirm('Resettare il timestamp \\'ultima rotazione\\' a ora?\\n\\nUsa questa funzione se il valore mostrato è un fossile dovuto a timezone MySQL sbagliata (prima del fix). Il nuovo timestamp userà il clock corrente del JVM Java.')) return;
            fetch('/api/dkim', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'last_rotation_reset', domain_id: parseInt(currentDomainId) })
            }).then(r => r.json()).then(data => {
                alert((data.success ? '✓ ' : '✗ ') + (data.message || data.error || ''));
                if (data.success) loadDkimSchedule(currentDomainId);
            }).catch(e => alert('Errore rete: ' + e.message));
        }

        function clearLastRotationTimestamp() {
            if (!currentDomainId) return;
            if (!confirm('Cancellare il timestamp \\'ultima rotazione\\'?\\n\\nIl campo verrà impostato a NULL e l\\'UI mostrerà \\'Mai effettuata\\'. La prossima rotazione lo ripopolerà con il valore corretto.')) return;
            fetch('/api/dkim', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'last_rotation_clear', domain_id: parseInt(currentDomainId) })
            }).then(r => r.json()).then(data => {
                alert((data.success ? '✓ ' : '✗ ') + (data.message || data.error || ''));
                if (data.success) loadDkimSchedule(currentDomainId);
            }).catch(e => alert('Errore rete: ' + e.message));
        }

        function saveDkimSchedule() {
            if (!currentDomainId) { alert('Seleziona un dominio'); return; }
            const sel = document.getElementById('dkimSchedulePreset');
            let days;
            if (sel.value === 'custom') {
                const v = parseInt(document.getElementById('dkimScheduleCustomDays').value);
                if (isNaN(v) || v < 1 || v > 3650) {
                    alert('Inserisci un numero di giorni tra 1 e 3650');
                    return;
                }
                days = v;
            } else {
                days = parseInt(sel.value);
            }
            fetch('/api/dkim', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'schedule_set', domain_id: parseInt(currentDomainId), interval_days: days })
            }).then(r => r.json()).then(data => {
                alert((data.success ? '✓ ' : '✗ ') + (data.message || data.error || ''));
                if (data.success) {
                    loadDkimSchedule(currentDomainId);
                    loadDkimHistory(currentDomainId);
                }
            }).catch(e => alert('Errore rete: ' + e.message));
        }

""" + getDnsJsPart3() + getDnsJsPart2() + getLogoutScript() + """
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
        return getHead("SSL", extraStyles) + getNavbar("ssl") + """
    <div class="content container mt-4">
        <div class="content-container">
            <h2><i class="fas fa-lock me-2"></i>Certificati SSL/TLS Mail Server</h2>
            <p class="text-muted">Gestisci il certificato SSL per Postfix e Dovecot (<strong>{{MAIL_HOSTNAME}}</strong>)</p>

            <!-- Guida Let's Encrypt -->
            <div class="card mb-4">
                <div class="card-header bg-secondary text-white" style="cursor:pointer;" data-bs-toggle="collapse" data-bs-target="#leGuide" aria-expanded="false">
                    <i class="fas fa-book me-2"></i><strong>Guida Let's Encrypt</strong>
                    <small class="ms-2 text-white-50">— clicca per espandere/comprimere</small>
                    <i class="fas fa-chevron-down float-end mt-1"></i>
                </div>
                <div id="leGuide" class="collapse">
                    <div class="card-body">
                        <h5><i class="fas fa-clock me-2"></i>Validità e rinnovo</h5>
                        <ul>
                            <li>I certificati Let's Encrypt durano <strong>90 giorni</strong>.</li>
                            <li>Il rinnovo è <strong>tecnicamente possibile in qualsiasi momento</strong>, ma esistono dei <em>rate limit</em>.</li>
                            <li>La <strong>soglia ufficiale raccomandata</strong> da Let's Encrypt e da <code>acme.sh</code> è di <strong>30 giorni prima della scadenza</strong>.</li>
                        </ul>

                        <h5 class="mt-3"><i class="fas fa-tachometer-alt me-2"></i>Rate limit principali</h5>
                        <ul>
                            <li><strong>5 certificati duplicati</strong> a settimana per lo stesso set di hostname.</li>
                            <li><strong>50 certificati</strong> a settimana per dominio registrato.</li>
                            <li><strong>5 validazioni fallite</strong> all'ora per account/hostname.</li>
                            <li><strong>300 nuovi ordini</strong> ogni 3 ore per account.</li>
                        </ul>
                        <p class="text-muted small">Se rinnovi troppo spesso o sbagli ripetutamente la verifica, vieni temporaneamente bloccato.</p>

                        <h5 class="mt-3"><i class="fas fa-sliders-h me-2"></i>Quale soglia mettere nel campo "Soglia rinnovo"?</h5>
                        <div class="table-responsive">
                            <table class="table table-sm table-bordered align-middle mb-2">
                                <thead class="table-light">
                                    <tr><th style="width:120px">Giorni</th><th>Quando usarla</th><th>Note</th></tr>
                                </thead>
                                <tbody>
                                    <tr class="table-success"><td><strong>30</strong> ✅</td><td><strong>Default consigliato</strong></td><td>Raccomandato da Let's Encrypt e da acme.sh</td></tr>
                                    <tr><td>14–29</td><td>Aggressivo</td><td>OK ma meno margine se il rinnovo fallisce alla prima</td></tr>
                                    <tr class="table-danger"><td>&lt; 14</td><td>Rischioso</td><td>Se DNS non si propaga o c'è un outage, rimani senza certificato</td></tr>
                                    <tr><td>31–60</td><td>Conservativo</td><td>Funziona ma sprechi giorni di validità del cert precedente</td></tr>
                                    <tr class="table-danger"><td>&gt; 60</td><td>Sconsigliato</td><td>Rischio di sbattere contro il rate limit (5/settimana)</td></tr>
                                </tbody>
                            </table>
                        </div>
                        <p class="mb-0"><strong>Range pratico utile: 14–60 giorni. Sweet spot: 30.</strong></p>

                        <h5 class="mt-3"><i class="fas fa-route me-2"></i>HTTP-01 vs DNS-01</h5>
                        <ul>
                            <li><strong>HTTP-01</strong>: il più semplice. Richiede che la <strong>porta 80</strong> sia raggiungibile da internet sul mail server.</li>
                            <li><strong>DNS-01</strong>: funziona anche dietro firewall. Richiede di aggiungere un record TXT al DNS (tipo Cloudflare).</li>
                            <li>Per il <strong>mail server</strong>, DNS-01 è spesso più affidabile perché i mail server raramente espongono la porta 80.</li>
                        </ul>

                        <h5 class="mt-3"><i class="fas fa-redo me-2"></i>Rinnovo automatico</h5>
                        <ul>
                            <li>Il pannello fa un check ogni 24 ore, mentre è in esecuzione.</li>
                            <li>Quando i giorni residui scendono sotto la soglia, lancia automaticamente <code>acme.sh --renew</code> e ridepoia il certificato su Postfix, Dovecot e Nginx.</li>
                            <li>Se il pannello è spento per giorni, il check non avviene — assicurati che il servizio sia avviato.</li>
                            <li>Il risultato dell'ultimo controllo è visibile nella card "Rinnovo Automatico" qui sopra.</li>
                        </ul>

                        <h5 class="mt-3"><i class="fas fa-bug me-2"></i>"Certificato già esistente" — cosa significa?</h5>
                        <p class="mb-1">Quando provi a generare un nuovo certificato e <code>acme.sh</code> trova già un cert valido per quell'hostname, blocca l'operazione per evitare di sprecare un rinnovo.</p>
                        <p class="mb-0">Hai due opzioni:</p>
                        <ul>
                            <li><strong>Deploy Certificato Esistente</strong> → riusa quello attuale (consigliato).</li>
                            <li><strong>Rigenera Challenge</strong> → forza un nuovo cert (usa solo se quello esistente è corrotto).</li>
                        </ul>

                        <h5 class="mt-3"><i class="fas fa-link me-2"></i>Riferimenti</h5>
                        <ul class="mb-0">
                            <li><a href="https://letsencrypt.org/docs/rate-limits/" target="_blank" rel="noopener">Rate limits ufficiali Let's Encrypt</a></li>
                            <li><a href="https://github.com/acmesh-official/acme.sh/wiki" target="_blank" rel="noopener">Wiki acme.sh</a></li>
                        </ul>
                    </div>
                </div>
            </div>

            <!-- SSL Hostname Mismatch Warning -->
            <div id="sslHostnameMismatch" class="alert alert-danger d-none">
                <h5><i class="fas fa-exclamation-triangle me-2"></i>Certificato Non Valido per l'Hostname Attuale</h5>
                <p class="mb-1">Il certificato e' emesso per <strong><code id="sslMismatchCn">-</code></strong>,
                    ma l'hostname del mail server e' <strong><code id="sslMismatchExpected">-</code></strong>.</p>
                <p class="mb-0"><i class="fas fa-arrow-down me-1"></i>Genera un nuovo certificato per <strong id="sslMismatchTarget">-</strong> usando una delle opzioni sotto.</p>
            </div>

            <!-- Self-Signed Warning -->
            <div id="selfSignedWarning" class="alert alert-danger d-none">
                <h5><i class="fas fa-exclamation-triangle me-2"></i>Attenzione: Certificato Self-Signed</h5>
                <p class="mb-0">Stai usando un certificato <strong>self-signed temporaneo</strong>. I client email mostreranno avvisi di sicurezza.</p>
                <p class="mb-0">Configura un certificato valido usando una delle opzioni sotto.</p>
            </div>

            <!-- Current Certificate Status -->
            <div class="card mb-4">
                <div class="card-header"><i class="fas fa-certificate me-2"></i>Certificato Corrente</div>
                <div class="card-body" id="certInfo">
                    <div class="text-center py-3">
                        <div class="spinner-border text-primary" role="status"></div>
                        <p class="mt-2">Caricamento informazioni certificato...</p>
                    </div>
                </div>
            </div>

            <!-- Auto-Renewal Card -->
            <div class="card mb-4">
                <div class="card-header bg-info text-white d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-sync-alt me-2"></i>Rinnovo Automatico</span>
                    <span id="autoRenewBadge" class="badge bg-secondary">-</span>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-6">
                            <div class="form-check form-switch mb-3">
                                <input class="form-check-input" type="checkbox" id="autoRenewEnabled" onchange="saveAutoRenewSettings()">
                                <label class="form-check-label" for="autoRenewEnabled">
                                    <strong>Abilita rinnovo automatico</strong>
                                </label>
                                <div class="text-muted small">Il pannello controlla ogni 24h e rinnova prima della scadenza</div>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Soglia rinnovo (giorni prima della scadenza)</label>
                                <input type="number" class="form-control" id="autoRenewThreshold" value="30" min="1" max="89" onchange="saveAutoRenewSettings()">
                                <div class="text-muted small">Default: 30 giorni</div>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <table class="table table-sm">
                                <tbody>
                                    <tr><td><strong>Ultimo controllo:</strong></td><td id="autoRenewLastCheck" class="text-muted">Mai</td></tr>
                                    <tr><td><strong>Esito:</strong></td><td id="autoRenewLastResult" class="text-muted">-</td></tr>
                                    <tr><td><strong>Ultimo rinnovo:</strong></td><td id="autoRenewLastRenewal" class="text-muted">Mai</td></tr>
                                    <tr><td><strong>Prossimo controllo:</strong></td><td id="autoRenewNextCheck" class="text-muted">-</td></tr>
                                </tbody>
                            </table>
                            <button class="btn btn-outline-info btn-sm" onclick="triggerManualCheck()">
                                <i class="fas fa-play me-1"></i>Verifica e rinnova ora
                            </button>
                            <div class="card mt-3 border-0" style="background: rgba(246,130,31,0.08)">
                                <div class="card-body py-3">
                                    <h6 class="mb-2"><i class="fas fa-cloud me-1" style="color:#f6821f"></i>Rinnovo automatico via Cloudflare</h6>
                                    <p class="small text-muted mb-2">
                                        Collega l'account Cloudflare che gestisce il DNS dell'hostname del server mail
                                        (<strong id="autoRenewMailHost">{{MAIL_HOSTNAME}}</strong>): il pannello pubblicherà
                                        da solo i record DNS di validazione e rinnoverà il certificato.
                                    </p>
                                    <label class="form-label small mb-1">Account Cloudflare per questo certificato</label>
                                    <div class="d-flex gap-2 align-items-center flex-wrap">
                                        <select class="form-select form-select-sm" style="max-width:280px" id="autoRenewCfAccount" onchange="saveCfMailServerAccount(this.value)">
                                            <option value="0">Caricamento...</option>
                                        </select>
                                        <button class="btn btn-outline-info btn-sm" type="button" onclick="testCfMailServer()">
                                            <i class="fas fa-plug me-1"></i>Verifica collegamento
                                        </button>
                                        <a href="/cloudflare" class="btn btn-outline-secondary btn-sm">
                                            <i class="fas fa-gear me-1"></i>Gestisci account
                                        </a>
                                    </div>
                                    <div id="autoRenewCfTest" class="mt-2 small"></div>
                                    <div class="small text-muted mt-1" id="autoRenewCfHint" style="display:none">
                                        <i class="fas fa-exclamation-triangle text-warning me-1"></i>
                                        Nessun account Cloudflare configurato.
                                        <a href="/cloudflare" class="alert-link">Aggiungine uno qui</a>.
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- SSL Configuration Options -->
            <h4 class="mb-1"><i class="fas fa-cogs me-2"></i>Configura Certificato SSL <small class="text-muted fs-6">(operazioni manuali)</small></h4>
            <div class="alert alert-secondary py-2 small">
                <i class="fas fa-hand me-1"></i>
                Questa sezione è per la <strong>configurazione e il rinnovo manuali</strong> del certificato:
                emissione/rinnovo on-demand (HTTP-01, DNS-01) oppure installazione di un
                <strong>certificato tuo</strong> (es. acquistato o con validità pluriennale, per cui non serve alcun rinnovo).
                Per il <strong>rinnovo automatico</strong> usa invece la sezione <em>“Rinnovo automatico”</em> qui sopra.
            </div>

            <div class="row mb-4">
                <!-- Option 1: Let's Encrypt HTTP-01 -->
                <div class="col-md-4 mb-3">
                    <div class="card option-card h-100" onclick="selectOption(1)">
                        <div class="card-body text-center">
                            <i class="fas fa-bolt fa-3x text-warning mb-3"></i>
                            <h5>Let's Encrypt (HTTP-01)</h5>
                            <p class="text-muted small">Automatico - richiede porta 80 accessibile da internet</p>
                            <span class="badge bg-danger">Non consigliato</span>
                        </div>
                    </div>
                </div>

                <!-- Option 2: Let's Encrypt DNS-01 -->
                <div class="col-md-4 mb-3">
                    <div class="card option-card h-100" onclick="selectOption(2)">
                        <div class="card-body text-center">
                            <i class="fas fa-globe fa-3x text-success mb-3"></i>
                            <h5>Let's Encrypt (DNS-01)</h5>
                            <p class="text-muted small">Via record DNS TXT - funziona anche dietro firewall</p>
                            <span class="badge bg-success">Consigliato</span>
                        </div>
                    </div>
                </div>

                <!-- Option 3: Manual Certificate -->
                <div class="col-md-4 mb-3">
                    <div class="card option-card h-100" onclick="selectOption(3)">
                        <div class="card-body text-center">
                            <i class="fas fa-upload fa-3x text-warning mb-3"></i>
                            <h5>Certificato Manuale</h5>
                            <p class="text-muted small">Carica certificato e chiave privata</p>
                            <span class="badge bg-warning text-dark">Avanzato</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Option 1: HTTP-01 Form -->
            <div id="option1Form" class="card mb-4 d-none">
                <div class="card-header bg-success text-white">
                    <i class="fas fa-bolt me-2"></i>Let's Encrypt - Verifica HTTP-01
                </div>
                <div class="card-body">
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle me-2"></i>
                        <strong>Requisiti:</strong> La porta 80 deve essere accessibile da internet e il dominio deve puntare a questo server.
                    </div>
                    <form id="http01Form">
                        <div class="mb-3">
                            <label class="form-label">Hostname Mail Server</label>
                            <div class="form-control bg-light">
                                <strong>{{MAIL_HOSTNAME}}</strong>
                            </div>
                            <input type="hidden" id="http01Hostname" value="{{MAIL_HOSTNAME}}">
                        </div>
                        <button type="submit" class="btn btn-success">
                            <i class="fas fa-certificate me-1"></i>Genera Certificato
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
                    <i class="fas fa-globe me-2"></i>Let's Encrypt - Verifica DNS-01
                </div>
                <div class="card-body">
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle me-2"></i>
                        Questo metodo richiede di aggiungere un record TXT al tuo DNS. Funziona anche se la porta 80 non è accessibile.
                    </div>

                    <!-- Step 1: Hostname display -->
                    <div id="dns01Step1">
                        <h5><span class="step-number">1</span>Hostname del mail server</h5>
                        <div class="mb-3">
                            <div class="form-control bg-light">
                                <strong>{{MAIL_HOSTNAME}}</strong>
                            </div>
                            <input type="hidden" id="dns01Hostname" value="{{MAIL_HOSTNAME}}">
                        </div>
                        <button class="btn btn-primary" onclick="generateDnsChallenge()">
                            <i class="fas fa-key me-1"></i>Genera Challenge
                        </button>
                    </div>

                    <!-- Certificate exists - show options -->
                    <div id="dns01CertExists" class="d-none">
                        <div class="alert alert-info">
                            <i class="fas fa-certificate me-2"></i>
                            <strong>Certificato già esistente!</strong><br>
                            Esiste già un certificato Let's Encrypt per questo hostname.
                        </div>
                        <div class="d-flex gap-2 flex-wrap">
                            <button class="btn btn-success" onclick="deployExistingCert()">
                                <i class="fas fa-download me-1"></i>Deploy Certificato Esistente
                            </button>
                            <button class="btn btn-warning" onclick="forceRegenerateChallenge()">
                                <i class="fas fa-sync me-1"></i>Rigenera Challenge (nuovo codice)
                            </button>
                            <button class="btn btn-outline-secondary" onclick="resetDnsChallenge()">
                                <i class="fas fa-times me-1"></i>Annulla
                            </button>
                        </div>
                    </div>

                    <!-- Step 2: Add DNS record -->
                    <div id="dns01Step2" class="d-none">
                        <h5><span class="step-number">2</span>Aggiungi questo record TXT al tuo DNS</h5>
                        <div class="mb-3">
                            <label class="form-label">Nome Record:</label>
                            <div class="dns-record">
                                <span id="dnsRecordName">_acme-challenge.mail.example.com</span>
                                <i class="fas fa-copy copy-btn float-end" onclick="copyToClipboard('dnsRecordName')"></i>
                            </div>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Valore Record TXT:</label>
                            <div class="dns-record">
                                <span id="dnsRecordValue">xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</span>
                                <i class="fas fa-copy copy-btn float-end" onclick="copyToClipboard('dnsRecordValue')"></i>
                            </div>
                        </div>
                        <div class="alert alert-warning">
                            <i class="fas fa-clock me-2"></i>
                            Attendi 1-5 minuti per la propagazione DNS prima di procedere.
                        </div>
                    </div>

                    <!-- Step 3: Verify and generate -->
                    <div id="dns01Step3" class="d-none">
                        <h5><span class="step-number">3</span>Verifica e genera il certificato</h5>
                        <p>Dopo aver aggiunto il record TXT e atteso la propagazione, clicca per verificare e generare il certificato.</p>
                        <button class="btn btn-success" onclick="verifyDnsAndGenerate()">
                            <i class="fas fa-check-circle me-1"></i>Verifica e Genera Certificato
                        </button>
                        <button class="btn btn-outline-secondary ms-2" onclick="resetDnsChallenge()">
                            <i class="fas fa-redo me-1"></i>Ricomincia
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
                    <i class="fas fa-upload me-2"></i>Carica Certificato Manuale
                </div>
                <div class="card-body">

                    <!-- Guida certificato manuale -->
                    <div class="card mb-4 border-info">
                        <div class="card-header bg-info text-white" style="cursor:pointer;" data-bs-toggle="collapse" data-bs-target="#manualGuide" aria-expanded="true">
                            <i class="fas fa-book me-2"></i><strong>Guida: come usare un certificato comprato da una CA</strong>
                            <i class="fas fa-chevron-down float-end mt-1"></i>
                        </div>
                        <div id="manualGuide" class="collapse show">
                            <div class="card-body">

                                <h5><i class="fas fa-question-circle me-2"></i>Perché serve il "fullchain"?</h5>
                                <p>
                                    Il pannello chiede di incollare un <strong>fullchain</strong>, cioè il <strong>tuo certificato server seguito dai certificati intermedi della CA</strong>.<br>
                                    Se metti solo il tuo certificato (file <code>.crt</code> da solo), i client di posta (Outlook, Thunderbird, smartphone) potrebbero mostrare l'avviso <em>"catena di certificati incompleta"</em> o rifiutare la connessione, perché non riescono a verificare la firma risalendo fino alla root CA.
                                </p>

                                <h5 class="mt-3"><i class="fas fa-folder-open me-2"></i>Cosa ti dà la CA quando compri un certificato</h5>
                                <p>Quando acquisti un cert (Sectigo, DigiCert, GoDaddy, GlobalSign, ecc.) di solito ricevi <strong>3 file separati</strong>:</p>
                                <div class="table-responsive">
                                    <table class="table table-sm table-bordered align-middle">
                                        <thead class="table-light">
                                            <tr><th>File tipico</th><th>Cos'è</th><th>Esempio nome</th></tr>
                                        </thead>
                                        <tbody>
                                            <tr><td><strong>Certificato server</strong></td><td>Il tuo certificato (leaf cert)</td><td><code>tuodominio.crt</code>, <code>cert.pem</code></td></tr>
                                            <tr><td><strong>Bundle intermediati</strong></td><td>I certificati delle CA intermedie</td><td><code>ca-bundle.crt</code>, <code>intermediate.crt</code>, <code>chain.pem</code></td></tr>
                                            <tr><td><strong>Chiave privata</strong></td><td>Quella che hai generato con la CSR (NON inviarla mai a nessuno)</td><td><code>tuodominio.key</code>, <code>privkey.pem</code></td></tr>
                                        </tbody>
                                    </table>
                                </div>

                                <h5 class="mt-3"><i class="fas fa-tools me-2"></i>Come costruire il fullchain — passo passo</h5>

                                <p class="mb-2"><strong>Metodo 1: da terminale (Linux / Mac)</strong></p>
                                <pre class="bg-dark text-light p-3 mb-3" style="font-size:0.85rem;">cat tuodominio.crt ca-bundle.crt > fullchain.pem</pre>
                                <p class="text-muted small mb-3">L'ordine conta: <strong>prima</strong> il tuo cert, <strong>poi</strong> gli intermediati. Mai il contrario.</p>

                                <p class="mb-2"><strong>Metodo 2: a mano con un editor di testo</strong></p>
                                <ol>
                                    <li>Apri il file del tuo certificato (<code>.crt</code>) con un editor di testo (Notepad, TextEdit, VSCode).</li>
                                    <li>Seleziona e copia <strong>tutto</strong> il contenuto, incluse le righe <code>-----BEGIN CERTIFICATE-----</code> e <code>-----END CERTIFICATE-----</code>.</li>
                                    <li>Apri un nuovo documento vuoto.</li>
                                    <li>Incolla il contenuto del tuo cert.</li>
                                    <li>Vai a capo (riga vuota dopo <code>-----END CERTIFICATE-----</code> non è obbligatoria ma non rovina nulla).</li>
                                    <li>Apri il <strong>ca-bundle</strong> (intermediati), copia tutto e incolla <strong>sotto</strong> il primo blocco.</li>
                                    <li>Salva il documento come <code>fullchain.pem</code>.</li>
                                </ol>

                                <h5 class="mt-3"><i class="fas fa-eye me-2"></i>Come deve apparire il fullchain finito</h5>
<pre class="bg-dark text-light p-3" style="font-size:0.85rem;">-----BEGIN CERTIFICATE-----
MIIE...   ← (1) il TUO certificato (leaf)
... base64 ...
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIE...   ← (2) intermediate CA
... base64 ...
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIE...   ← (3) opzionale: root CA (di solito non serve)
... base64 ...
-----END CERTIFICATE-----</pre>
                                <p class="small">Devi avere <strong>almeno 2 blocchi</strong> <code>BEGIN CERTIFICATE...END CERTIFICATE</code> uno dopo l'altro. Se ne hai uno solo, ti manca la catena.</p>

                                <h5 class="mt-3"><i class="fas fa-clipboard me-2"></i>Cosa incollare nei due campi qui sotto</h5>
                                <div class="table-responsive">
                                    <table class="table table-sm table-bordered align-middle mb-2">
                                        <thead class="table-light"><tr><th style="width:35%">Campo</th><th>Contenuto</th></tr></thead>
                                        <tbody>
                                            <tr><td><strong>Certificato (fullchain.pem)</strong></td><td>Tutto il contenuto di <code>fullchain.pem</code>: TUO cert + intermediati concatenati</td></tr>
                                            <tr><td><strong>Chiave Privata (privkey.pem)</strong></td><td>Tutto il contenuto del file <code>.key</code> ricevuto dalla CA (o quello che hai generato con la CSR)</td></tr>
                                        </tbody>
                                    </table>
                                </div>

                                <h5 class="mt-3"><i class="fas fa-check-double me-2"></i>Verifica veloce prima di salvare</h5>
                                <ul class="mb-0">
                                    <li>Il fullchain deve <strong>iniziare</strong> con <code>-----BEGIN CERTIFICATE-----</code> (il tuo cert).</li>
                                    <li>Deve <strong>finire</strong> con <code>-----END CERTIFICATE-----</code> (l'ultimo intermediato).</li>
                                    <li>La chiave deve iniziare con <code>-----BEGIN PRIVATE KEY-----</code> (o <code>RSA PRIVATE KEY</code> / <code>EC PRIVATE KEY</code>).</li>
                                    <li>Cert e chiave devono essere <strong>una coppia matematica</strong>: se rigeneri la chiave, devi rifare anche il cert con una nuova CSR.</li>
                                </ul>

                                <h5 class="mt-3"><i class="fas fa-exclamation-triangle text-warning me-2"></i>Errori comuni</h5>
                                <ul class="mb-0">
                                    <li><strong>"Chain incomplete" sui client</strong> → hai incollato solo il tuo <code>.crt</code> senza concatenare gli intermediati.</li>
                                    <li><strong>"Certificate doesn't match private key"</strong> → la chiave non corrisponde al cert (forse hai mescolato file di certificati diversi).</li>
                                    <li><strong>"Unable to load private key"</strong> → la chiave è criptata con password. Decriptala prima:<br>
                                        <code>openssl rsa -in privkey-encrypted.key -out privkey.pem</code></li>
                                    <li><strong>Cert formato Windows (.pfx / .p12)</strong> → vanno convertiti prima:<br>
                                        <code>openssl pkcs12 -in cert.pfx -nocerts -nodes -out privkey.pem</code><br>
                                        <code>openssl pkcs12 -in cert.pfx -nokeys -clcerts -out cert.crt</code><br>
                                        <code>openssl pkcs12 -in cert.pfx -nokeys -cacerts -out ca-bundle.crt</code></li>
                                </ul>

                                <h5 class="mt-3"><i class="fas fa-balance-scale me-2"></i>Vale la pena pagare un certificato?</h5>
                                <p class="mb-0">
                                    Per un mail server, <strong>Let's Encrypt</strong> (gratis, automatico, rinnovo automatico dal pannello) è praticamente sempre la scelta migliore. I certificati a pagamento hanno senso solo se hai requisiti specifici (EV, garanzie assicurative, validità multi-anno, supporto telefonico CA). Tecnicamente la sicurezza è la stessa.
                                </p>
                            </div>
                        </div>
                    </div>

                    <form id="manualCertForm">
                        <div class="mb-3">
                            <label class="form-label">Certificato (fullchain.pem)</label>
                            <textarea class="form-control font-monospace" id="manualCert" rows="8" placeholder="-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----" required></textarea>
                            <div class="form-text">Include tutti i certificati della catena</div>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Chiave Privata (privkey.pem)</label>
                            <textarea class="form-control font-monospace" id="manualKey" rows="8" placeholder="-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----" required></textarea>
                        </div>
                        <button type="submit" class="btn btn-warning">
                            <i class="fas fa-save me-1"></i>Salva Certificato
                        </button>
                    </form>
                    <div id="manualOutput" class="mt-3 d-none">
                        <pre class="bg-dark text-light p-3"></pre>
                    </div>
                </div>
            </div>
        </div>
    </div>
""" + getFooter() + """
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
                                    <h5><i class="fas fa-exclamation-triangle text-danger me-2"></i>Certificato Self-Signed (Temporaneo)</h5>
                                    <table class="table table-sm table-borderless mb-0">
                                        <tr><td style="width:150px"><strong>Dominio:</strong></td><td>${data.common_name || data.hostname || 'N/A'}</td></tr>
                                        <tr><td><strong>Emittente:</strong></td><td>${data.issuer || 'Self-Signed'}</td></tr>
                                        <tr><td><strong>Scadenza:</strong></td><td>${data.expires_at || 'N/A'} ${data.days_until_expiry ? '(' + data.days_until_expiry + ' giorni)' : ''}</td></tr>
                                        <tr><td><strong>Algoritmo:</strong></td><td>${data.algorithm || 'RSA'}</td></tr>
                                    </table>
                                </div>
                                <div class="col-md-4 text-center">
                                    <span class="badge bg-danger fs-6 p-2"><i class="fas fa-times-circle me-1"></i>Non Valido</span>
                                    <p class="text-danger mt-2 small"><strong>I client email mostreranno avvisi!</strong></p>
                                </div>
                            </div>
                        </div>`;
                } else if (data.certificate_installed) {
                    warningDiv.classList.add('d-none');
                    let statusClass = 'cert-valid';
                    let statusBadge = '<span class="badge bg-success fs-6 p-2"><i class="fas fa-check-circle me-1"></i>Valido</span>';
                    let statusText = '';

                    if (data.expired) {
                        statusClass = 'cert-self-signed';
                        statusBadge = '<span class="badge bg-danger fs-6 p-2"><i class="fas fa-times-circle me-1"></i>Scaduto!</span>';
                        statusText = '<p class="text-danger mt-2 small"><strong>Il certificato è scaduto!</strong></p>';
                    } else if (data.expiring_soon) {
                        statusClass = 'cert-expiring';
                        statusBadge = '<span class="badge bg-warning fs-6 p-2"><i class="fas fa-exclamation-triangle me-1"></i>In Scadenza</span>';
                        statusText = '<p class="text-warning mt-2 small"><strong>Rinnova presto!</strong></p>';
                    }

                    let certType = data.lets_encrypt ? '<span class="badge bg-info">Let\\'s Encrypt</span>' :
                                   (data.self_signed ? '<span class="badge bg-secondary">Self-Signed</span>' : '<span class="badge bg-primary">Custom</span>');

                    certDiv.innerHTML = `
                        <div class="cert-info ${statusClass}">
                            <div class="row">
                                <div class="col-md-8">
                                    <h5><i class="fas fa-shield-alt text-success me-2"></i>${data.common_name || 'Certificato SSL'}</h5>
                                    <table class="table table-sm table-borderless mb-0">
                                        <tr><td style="width:150px"><strong>Dominio:</strong></td><td>${data.common_name || 'N/A'}</td></tr>
                                        <tr><td><strong>Emittente:</strong></td><td>${data.issuer || 'N/A'} ${certType}</td></tr>
                                        <tr><td><strong>Valido dal:</strong></td><td>${data.valid_from || 'N/A'}</td></tr>
                                        <tr><td><strong>Scadenza:</strong></td><td>${data.expires_at || 'N/A'} <strong>(${data.days_until_expiry || '?'} giorni)</strong></td></tr>
                                        <tr><td><strong>Algoritmo:</strong></td><td>${data.algorithm || 'N/A'}</td></tr>
                                        ${data.serial ? '<tr><td><strong>Seriale:</strong></td><td><code>' + data.serial + '</code></td></tr>' : ''}
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
                            <i class="fas fa-info-circle me-2"></i>Nessun certificato configurato. Seleziona un'opzione sotto.
                        </div>`;
                }
                // Check hostname mismatch
                const mismatchDiv = document.getElementById('sslHostnameMismatch');
                const currentMailHostname = '{{MAIL_HOSTNAME}}';
                const certCn = data.common_name || '';
                if (currentMailHostname && certCn && currentMailHostname !== 'Non configurato') {
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
                    '<div class="alert alert-warning"><i class="fas fa-exclamation-triangle me-2"></i>Impossibile caricare lo stato del certificato.</div>';
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
                alert('Copiato negli appunti!');
            });
        }

        // HTTP-01 form
        document.getElementById('http01Form').addEventListener('submit', function(e) {
            e.preventDefault();
            const hostname = document.getElementById('http01Hostname').value;
            const output = document.getElementById('http01Output');
            output.classList.remove('d-none');
            output.querySelector('pre').textContent = 'Generazione certificato in corso...';

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
                    alert('Certificato generato con successo!');
                }
            });
        });

        // DNS-01 challenge generation
        function generateDnsChallenge() {
            const hostname = document.getElementById('dns01Hostname').value;
            if (!hostname) {
                alert('Inserisci l\\'hostname');
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
                    alert('Errore: ' + data.message);
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
                    alert('Certificato deployato con successo!');
                    loadSslStatus();
                    resetDnsChallenge();
                } else {
                    alert('Errore: ' + data.message);
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
                    alert('Errore: ' + data.message);
                }
            });
        }

        function verifyDnsAndGenerate() {
            if (!currentDnsChallenge) {
                alert('Prima genera il challenge');
                return;
            }

            const output = document.getElementById('dns01Output');
            output.classList.remove('d-none');
            output.querySelector('pre').textContent = 'Verifica DNS e generazione certificato in corso...';

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
                    alert('Certificato generato con successo!');
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
            output.querySelector('pre').textContent = 'Salvataggio certificato...';

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
                    alert('Certificato salvato con successo! Riavvia i servizi per applicare.');
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
                let opts = '<option value="0"' + (cur === 0 ? ' selected' : '') + '>Manuale (nessun account)</option>';
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
                    out.innerHTML = '<span class="text-success"><i class="fas fa-check-circle me-1"></i>'
                        + escSslCf(data.message || 'Salvato') + '</span>';
                } else {
                    out.innerHTML = '<span class="text-danger"><i class="fas fa-times-circle me-1"></i>'
                        + escSslCf(data.message || data.error || 'Errore') + '</span>';
                }
            }).catch(e => alert('Errore: ' + e.message));
        }

        function testCfMailServer() {
            const sel = document.getElementById('autoRenewCfAccount');
            const out = document.getElementById('autoRenewCfTest');
            const accountId = sel ? (parseInt(sel.value, 10) || 0) : 0;
            if (accountId <= 0) {
                out.innerHTML = '<span class="text-warning"><i class="fas fa-exclamation-triangle me-1"></i>Seleziona prima un account Cloudflare.</span>';
                return;
            }
            out.innerHTML = '<span class="text-muted"><i class="fas fa-spinner fa-spin me-1"></i>Verifica token e zona DNS...</span>';
            fetch('/api/cloudflare', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'test_mailserver', account_id: accountId,
                    csrf_token: document.getElementById('csrf_token').value })
            }).then(r => r.json()).then(data => {
                if (data.success) {
                    out.innerHTML = '<div class="alert alert-success py-2 mb-0"><i class="fas fa-check-circle me-1"></i>'
                        + escSslCf(data.message || 'Collegamento OK') + '</div>';
                } else {
                    out.innerHTML = '<div class="alert alert-danger py-2 mb-0"><i class="fas fa-times-circle me-1"></i>'
                        + escSslCf(data.error || data.message || 'Verifica fallita') + '</div>';
                }
            }).catch(e => alert('Errore: ' + e.message));
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
                    badge.innerHTML = '<i class="fas fa-check me-1"></i>Attivo';
                } else {
                    badge.className = 'badge bg-secondary';
                    badge.innerHTML = '<i class="fas fa-pause me-1"></i>Disattivato';
                }
                document.getElementById('autoRenewLastCheck').textContent = data.last_check_human || 'Mai';
                document.getElementById('autoRenewLastResult').innerHTML = data.last_result_html || '-';
                document.getElementById('autoRenewLastRenewal').textContent = data.last_renewal_human || 'Mai';
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
                else alert('Errore: ' + (data.message || data.error || 'Errore sconosciuto'));
            });
        }

        function triggerManualCheck() {
            const btn = event.currentTarget;
            const originalHtml = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Verifica in corso...';
            fetch('/api/ssl', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'trigger_manual_check', csrf_token: document.getElementById('csrf_token').value })
            }).then(r => r.json()).then(data => {
                btn.disabled = false;
                btn.innerHTML = originalHtml;
                if (data.success) {
                    alert(data.message || 'Verifica completata');
                    loadAutoRenewSettings();
                    loadSslStatus();
                } else {
                    alert('Errore: ' + (data.message || data.error || 'Errore'));
                }
            }).catch(e => {
                btn.disabled = false;
                btn.innerHTML = originalHtml;
                alert('Errore: ' + e.message);
            });
        }

        let csrfToken = document.getElementById('csrf_token').value;
""" + getLogoutScript() + """
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
        """;
        return getHead("Logs", extraStyles) + getNavbar("logs") + """
    <div class="content container mt-4">
        <!-- Statistics -->
        <div class="row mb-4">
            <div class="col-md-6">
                <div class="card stat-card"><div class="card-body text-center">
                    <div class="stat-number" id="statSpam">-</div>
                    <div>Spam Bloccato</div>
                </div></div>
            </div>
            <div class="col-md-6">
                <div class="card stat-card"><div class="card-body text-center">
                    <div class="stat-number" id="statUsers">-</div>
                    <div>Utenti Attivi</div>
                </div></div>
            </div>
        </div>

        <div class="content-container">
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h2 class="mb-0"><i class="fas fa-file-alt me-2"></i>Log Server</h2>
                <div class="d-flex gap-2 align-items-center">
                    <select class="form-select form-select-sm w-auto" id="logSelect">
                        <option value="">Caricamento...</option>
                    </select>
                    <input type="text" class="form-control form-control-sm w-auto" id="logFilter" placeholder="Filtra (regex)..." onkeyup="if(event.key==='Enter')loadLogs()">
                    <button class="btn btn-sm btn-mail" onclick="loadLogs()" title="Ricarica con il filtro corrente"><i class="fas fa-sync"></i></button>
                </div>
            </div>

            <!-- Filtri preset -->
            <div class="card mb-3 border-info">
                <div class="card-header bg-info text-white py-2 d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-filter me-2"></i><strong>Filtri rapidi</strong> <small class="text-white-50 ms-2">click per applicare — passaci sopra per vedere la regex</small></span>
                    <button class="btn btn-sm btn-light" onclick="applyPreset('all', this)" title="Mostra TUTTE le righe del log senza filtro"><i class="fas fa-eye me-1"></i>Mostra tutto</button>
                </div>
                <div class="card-body py-2">
                    <div class="log-preset-group mb-2">
                        <span class="log-preset-cat text-danger"><i class="fas fa-shield-alt me-1"></i>Sicurezza</span>
                        <button class="btn btn-outline-danger log-preset-btn" data-preset="brute-smtp" onclick="applyPreset('brute-smtp', this)"
                            title="REGEX: SASL.*authentication failed&#10;Cattura: tentativi di login SMTP falliti (Postfix SASL). Sono i veri brute-force di posta in uscita.">
                            <i class="fas fa-user-secret me-1"></i>Brute-force SMTP (SASL)
                        </button>
                        <button class="btn btn-outline-danger log-preset-btn" data-preset="brute-imap" onclick="applyPreset('brute-imap', this)"
                            title="REGEX: dovecot.*(auth failed|Disconnected.*auth)&#10;Cattura: tentativi di login IMAP/POP falliti (Dovecot). Sono i veri brute-force di posta in entrata/webmail.">
                            <i class="fas fa-inbox me-1"></i>Brute-force IMAP/POP
                        </button>
                        <button class="btn btn-outline-danger log-preset-btn" data-preset="brute-panel" onclick="applyPreset('brute-panel', this)"
                            title="REGEX: mail-panel-auth|AUTH_FAILED&#10;Cattura: tentativi di login falliti al pannello stesso.">
                            <i class="fas fa-lock me-1"></i>Brute-force pannello
                        </button>
                        <button class="btn btn-outline-danger log-preset-btn" data-preset="banned" onclick="applyPreset('banned', this)"
                            title="REGEX: fail2ban.*(Ban |Found )&#10;Cattura: eventi di Fail2ban (rilevamento e ban di IP).">
                            <i class="fas fa-gavel me-1"></i>Ban Fail2ban
                        </button>
                    </div>
                    <div class="log-preset-group mb-2">
                        <span class="log-preset-cat text-warning"><i class="fas fa-broom me-1"></i>Rumore</span>
                        <button class="btn btn-outline-warning log-preset-btn" data-preset="scanners" onclick="applyPreset('scanners', this)"
                            title="REGEX: SSL_accept error|TLS library problem|lost connection after (STARTTLS|EHLO)|http request&#10;Cattura: scanner internet (Censys, Shodan, BinaryEdge, ecc.) che probano le porte mail con richieste mal formate. NON sono attacchi — sono noise di internet.">
                            <i class="fas fa-satellite-dish me-1"></i>Scanner internet
                        </button>
                        <button class="btn btn-outline-warning log-preset-btn" data-preset="known-scanners" onclick="applyPreset('known-scanners', this)"
                            title="REGEX: censys-scanner|shodan|driftnet|internet-?measurement|securitytrails|binaryedge|shadowserver|stretchoid&#10;Cattura: hostname/DNS di scanner notoriamente innocui. Usalo per riconoscere il rumore.">
                            <i class="fas fa-robot me-1"></i>Bot/scanner noti
                        </button>
                        <button class="btn btn-outline-warning log-preset-btn" data-preset="anvil" onclick="applyPreset('anvil', this)"
                            title="REGEX: postfix/anvil|max connection&#10;Cattura: statistiche periodiche di anvil (rate limiter postfix). Puramente informative.">
                            <i class="fas fa-chart-line me-1"></i>Statistiche anvil
                        </button>
                    </div>
                    <div class="log-preset-group mb-2">
                        <span class="log-preset-cat text-success"><i class="fas fa-envelope me-1"></i>Posta</span>
                        <button class="btn btn-outline-success log-preset-btn" data-preset="mail-sent" onclick="applyPreset('mail-sent', this)"
                            title="REGEX: status=sent|relay=&#10;Cattura: email consegnate con successo (sent/relayed).">
                            <i class="fas fa-paper-plane me-1"></i>Email consegnate
                        </button>
                        <button class="btn btn-outline-success log-preset-btn" data-preset="mail-bounce" onclick="applyPreset('mail-bounce', this)"
                            title="REGEX: status=(bounced|deferred|rejected)|NOQUEUE.*reject&#10;Cattura: email rifiutate, bounce, deferred. Da controllare se un utente lamenta che non arrivano mail.">
                            <i class="fas fa-undo me-1"></i>Bounce / rifiutate
                        </button>
                        <button class="btn btn-outline-success log-preset-btn" data-preset="spam" onclick="applyPreset('spam', this)"
                            title="REGEX: rspamd|spam|virus|clamav&#10;Cattura: eventi anti-spam (Rspamd) e antivirus (ClamAV).">
                            <i class="fas fa-bug me-1"></i>Spam / virus
                        </button>
                    </div>
                    <div class="log-preset-group">
                        <span class="log-preset-cat text-primary"><i class="fas fa-exclamation-circle me-1"></i>Diagnostica</span>
                        <button class="btn btn-outline-primary log-preset-btn" data-preset="errors" onclick="applyPreset('errors', this)"
                            title="REGEX: error|fatal|warning&#10;Cattura: TUTTI gli errori e warning di QUALSIASI servizio. Buon punto di partenza se qualcosa non va.">
                            <i class="fas fa-exclamation-triangle me-1"></i>Solo errori/warning
                        </button>
                        <button class="btn btn-outline-primary log-preset-btn" data-preset="connections" onclick="applyPreset('connections', this)"
                            title="REGEX: connect from|disconnect from&#10;Cattura: tutte le connessioni in entrata (utili per vedere chi ti contatta).">
                            <i class="fas fa-plug me-1"></i>Connessioni
                        </button>
                        <button class="btn btn-outline-primary log-preset-btn" data-preset="tls" onclick="applyPreset('tls', this)"
                            title="REGEX: TLS|SSL|STARTTLS|cipher&#10;Cattura: tutto il negoziato TLS/SSL. Utile per debug certificati/handshake.">
                            <i class="fas fa-lock me-1"></i>TLS/SSL
                        </button>
                    </div>
                    <div id="filterActiveDesc" class="mt-2 d-none"></div>
                </div>
            </div>

            <div class="log-viewer" id="logViewer">
                <div class="text-muted">Seleziona un log per visualizzarlo...</div>
            </div>

            <!-- Search -->
            <div class="card mt-4">
                <div class="card-header"><i class="fas fa-search me-2"></i>Ricerca nei Log</div>
                <div class="card-body">
                    <div class="input-group">
                        <input type="text" class="form-control" id="searchPattern" placeholder="Pattern regex (es: error|failed|reject)">
                        <button class="btn btn-primary" onclick="searchLogs()">Cerca</button>
                    </div>
                    <div id="searchResults" class="mt-3"></div>
                </div>
            </div>
        </div>
    </div>
""" + getFooter() + """
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
                opt.textContent = 'Nessun log disponibile';
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
        const LOG_PRESETS = {
            'all':           { regex: '',
                               desc: 'Mostra TUTTE le righe del log senza filtro.' },
            'brute-smtp':    { regex: 'SASL.*authentication failed',
                               desc: '<b>Brute-force SMTP (SASL):</b> tentativi di login SMTP falliti su Postfix. Sono veri attacchi alla posta in uscita — se ne vedi parecchi dallo stesso IP, Fail2ban dovrebbe bannarlo (jail <code>postfix-auth</code>).' },
            'brute-imap':    { regex: 'dovecot.*(auth failed|Disconnected.*auth)',
                               desc: '<b>Brute-force IMAP/POP:</b> tentativi di login Dovecot falliti. Sono veri attacchi alla posta in entrata / webmail (jail <code>dovecot</code>).' },
            'brute-panel':   { regex: 'mail-panel-auth|AUTH_FAILED',
                               desc: '<b>Brute-force pannello:</b> tentativi di login falliti al pannello di amministrazione (jail <code>mail-panel-auth</code>).' },
            'banned':        { regex: 'fail2ban.*(Ban |Found )',
                               desc: '<b>Eventi Fail2ban:</b> rilevamenti (<code>Found</code>) e ban veri e propri (<code>Ban</code>). Utile per vedere chi è stato bannato e perchè.' },
            'scanners':      { regex: 'SSL_accept error|TLS library problem|lost connection after (STARTTLS|EHLO)|http request',
                               desc: '<b>Scanner internet:</b> probe di scanner pubblici (Censys, Shodan, BinaryEdge, …) che bussano alle porte mail con richieste mal formate. <b>NON sono attacchi</b>, è rumore di internet. Postfix risponde correttamente "no, parlo TLS" e amen.' },
            'known-scanners':{ regex: 'censys-scanner|shodan|driftnet|internet-?measurement|securitytrails|binaryedge|shadowserver|stretchoid',
                               desc: '<b>Bot/scanner noti:</b> filtra solo gli host con DNS riconoscibili come scanner di sicurezza pubblici. Innocui, utili da riconoscere per non confonderli con attacchi.' },
            'anvil':         { regex: 'postfix/anvil|max connection',
                               desc: '<b>Statistiche anvil:</b> report periodici del rate-limiter Postfix. Puramente informative, non azione richiesta.' },
            'mail-sent':     { regex: 'status=sent|relay=',
                               desc: '<b>Email consegnate:</b> mail recapitate con successo. Se cerchi una specifica email consegnata, combinala col filtro libero indicando il mittente/destinatario.' },
            'mail-bounce':   { regex: 'status=(bounced|deferred|rejected)|NOQUEUE.*reject',
                               desc: '<b>Bounce/rifiutate:</b> email che NON sono state consegnate (bounce permanenti, deferred, reject). <b>Primo posto dove guardare</b> se un utente lamenta che la sua mail non e\\' arrivata.' },
            'spam':          { regex: 'rspamd|spam|virus|clamav',
                               desc: '<b>Spam/virus:</b> eventi del motore anti-spam (Rspamd) e antivirus (ClamAV). Includono messaggi marcati come spam, score, virus rilevati.' },
            'errors':        { regex: 'error|fatal|warning',
                               desc: '<b>Errori/warning di tutti i servizi:</b> primo filtro da provare se qualcosa non funziona ma non sai dove guardare.' },
            'connections':   { regex: 'connect from|disconnect from',
                               desc: '<b>Connessioni:</b> tutte le aperture/chiusure di connessioni TCP verso il server mail. Utile per vedere chi ti contatta in tempo reale.' },
            'tls':           { regex: 'TLS|SSL|STARTTLS|cipher',
                               desc: '<b>TLS/SSL:</b> handshake e negoziato della cifratura. Buon punto per debug di certificati, ciphers, o problemi di compatibilita\\' con vecchi client.' }
        };

        function applyPreset(presetId, btn) {
            const preset = LOG_PRESETS[presetId];
            if (!preset) return;
            document.getElementById('logFilter').value = preset.regex;
            // Evidenzia il pulsante attivo
            document.querySelectorAll('.log-preset-btn').forEach(b => b.classList.remove('active'));
            if (btn && presetId !== 'all') btn.classList.add('active');
            // Mostra descrizione del filtro
            const descEl = document.getElementById('filterActiveDesc');
            if (presetId === 'all') {
                descEl.classList.add('d-none');
                descEl.innerHTML = '';
            } else {
                descEl.classList.remove('d-none');
                descEl.innerHTML = '<i class="fas fa-info-circle me-1"></i>' + preset.desc +
                    ' &nbsp;<code class="ms-1" style="font-size:.7rem">' + preset.regex + '</code>';
            }
            loadLogs();
        }

        function loadLogs() {
            const logId = document.getElementById('logSelect').value;
            const filter = document.getElementById('logFilter').value;
            if (!logId) return;

            let url = '/api/logs?log=' + logId + '&lines=200';
            if (filter) url += '&filter=' + encodeURIComponent(filter);

            fetch(url).then(r => r.json()).then(data => {
                const viewer = document.getElementById('logViewer');
                if (!data.entries || data.entries.length === 0) {
                    viewer.innerHTML = '<div class="text-muted">Nessuna voce nel log.</div>';
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
                    results.innerHTML = '<div class="alert alert-info">Nessun risultato trovato.</div>';
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
""" + getLogoutScript() + """
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
        .component-card.installed { background: #d4edda; border-color: #28a745; }
        """;
        return getHead("Installazione", extraStyles) + getNavbar("") + """
    <div class="content container mt-4">
        <div class="content-container">
            <h2><i class="fas fa-download me-2"></i>Installazione Componenti</h2>
            <p class="text-muted">Seleziona i componenti da installare o reinstallare.</p>

            <div class="alert alert-warning">
                <i class="fas fa-exclamation-triangle me-2"></i>
                <strong>Attenzione:</strong> La reinstallazione rimuove completamente i dati esistenti!
            </div>

            <div class="row" id="componentsGrid">
                <div class="col-md-6"><div class="component-card" data-component="timezone">
                    <h5><i class="fas fa-clock me-2"></i>Timezone & DNS</h5>
                    <p class="text-muted small">Configura timezone Europe/Rome e DNS Cloudflare</p>
                    <button class="btn btn-sm btn-outline-primary" onclick="installComponent('timezone')">Configura</button>
                </div></div>
                <div class="col-md-6"><div class="component-card" data-component="postfix">
                    <h5><i class="fas fa-paper-plane me-2"></i>Postfix</h5>
                    <p class="text-muted small">Server SMTP per invio/ricezione email</p>
                    <button class="btn btn-sm btn-outline-primary" onclick="installComponent('postfix')">Installa</button>
                </div></div>
                <div class="col-md-6"><div class="component-card" data-component="dovecot">
                    <h5><i class="fas fa-inbox me-2"></i>Dovecot</h5>
                    <p class="text-muted small">Server IMAP/POP3</p>
                    <button class="btn btn-sm btn-outline-primary" onclick="installComponent('dovecot')">Installa</button>
                </div></div>
                <div class="col-md-6"><div class="component-card" data-component="rspamd">
                    <h5><i class="fas fa-shield-alt me-2"></i>Rspamd</h5>
                    <p class="text-muted small">Anti-spam avanzato</p>
                    <button class="btn btn-sm btn-outline-primary" onclick="installComponent('rspamd')">Installa</button>
                </div></div>
                <div class="col-md-6"><div class="component-card" data-component="clamav">
                    <h5><i class="fas fa-bug me-2"></i>ClamAV</h5>
                    <p class="text-muted small">Antivirus per email</p>
                    <button class="btn btn-sm btn-outline-primary" onclick="installComponent('clamav')">Installa</button>
                </div></div>
                <div class="col-md-6"><div class="component-card" data-component="roundcube">
                    <h5><i class="fas fa-envelope-open-text me-2"></i>Roundcube</h5>
                    <p class="text-muted small">Webmail con SSO</p>
                    <button class="btn btn-sm btn-outline-primary" onclick="installComponent('roundcube')">Installa</button>
                </div></div>
            </div>

            <hr>
            <div class="text-center">
                <button class="btn btn-lg btn-danger" onclick="installComponent('all')">
                    <i class="fas fa-magic me-2"></i>Installa Tutto (Stack Completo)
                </button>
            </div>

            <div id="installOutput" class="mt-4 d-none">
                <h5>Output Installazione:</h5>
                <pre class="bg-dark text-light p-3" style="max-height:400px;overflow-y:auto" id="outputText"></pre>
            </div>
        </div>
    </div>
""" + getFooter() + """
    <script>
        let csrfToken = document.getElementById('csrf_token').value;

        function installComponent(component) {
            if (!confirm('Vuoi installare/reinstallare ' + component + '? Questo rimuovera i dati esistenti.')) return;

            document.getElementById('installOutput').classList.remove('d-none');
            document.getElementById('outputText').textContent = 'Installazione in corso...';

            fetch('/api/install', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ component: component, csrf_token: csrfToken })
            }).then(r => r.json()).then(data => {
                document.getElementById('outputText').textContent = data.output || data.error || 'Completato';
                if (data.success) {
                    alert('Installazione completata!');
                }
            });
        }
""" + getLogoutScript() + """
    </script>
</body>
</html>
""";
    }

    // ============== SETTINGS.HTML ==============
    public static String getSettingsHtml() {
        String extraStyles = """
        .totp-enabled { color: #198754; }
        .totp-disabled { color: #dc3545; }
        .backup-code { font-family: monospace; background: #f8f9fa; padding: 4px 8px; margin: 2px; display: inline-block; border-radius: 4px; }
        .qr-container { text-align: center; padding: 20px; }
        .qr-container img { max-width: 200px; border: 1px solid #dee2e6; border-radius: 8px; padding: 10px; background: white; }
        """;
        return getHead("Impostazioni", extraStyles) + getNavbar("settings") + """
    <div class="content container mt-4">
        <div class="content-container">
            <h2><i class="fas fa-cog me-2"></i>Impostazioni</h2>
            <p class="text-muted">Configurazione del Mail Panel e del tuo account.</p>

            <div class="row">
                <div class="col-md-6">
                    <!-- 2FA Section -->
                    <div class="card mb-4">
                        <div class="card-header">
                            <i class="fas fa-shield-alt me-2"></i>Autenticazione a Due Fattori (2FA)
                        </div>
                        <div class="card-body">
                            <div id="2faStatus">
                                <p>Stato: <span id="2faStatusBadge" class="badge">Caricamento...</span></p>
                            </div>

                            <div id="2faDisabled" style="display:none;">
                                <p class="text-muted">La 2FA aggiunge un ulteriore livello di sicurezza al tuo account.</p>
                                <button class="btn btn-success" onclick="setup2FA()">
                                    <i class="fas fa-lock me-1"></i>Attiva 2FA
                                </button>
                            </div>

                            <div id="2faEnabled" style="display:none;">
                                <p class="text-success"><i class="fas fa-check-circle me-1"></i>La 2FA e' attiva sul tuo account.</p>
                                <button class="btn btn-outline-warning me-2" onclick="showBackupCodes()">
                                    <i class="fas fa-key me-1"></i>Codici di Backup
                                </button>
                                <button class="btn btn-outline-danger" onclick="disable2FA()">
                                    <i class="fas fa-unlock me-1"></i>Disattiva 2FA
                                </button>
                            </div>
                        </div>
                    </div>

                    <!-- Change Password -->
                    <div class="card mb-4">
                        <div class="card-header"><i class="fas fa-key me-2"></i>Cambia Password</div>
                        <div class="card-body">
                            <div class="mb-3">
                                <label class="form-label">Password Attuale</label>
                                <input type="password" class="form-control" id="currentPassword">
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Nuova Password</label>
                                <input type="password" class="form-control" id="newPassword" minlength="8">
                                <small class="text-muted">Minimo 8 caratteri</small>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Conferma Nuova Password</label>
                                <input type="password" class="form-control" id="confirmNewPassword">
                            </div>
                            <button class="btn btn-primary" onclick="changePassword()">
                                <i class="fas fa-save me-1"></i>Cambia Password
                            </button>
                        </div>
                    </div>

""" + getChangeUsernameCard() + getVaultManagementCard() + """
                    <!-- Passkeys Section -->
                    <div class="card mb-4">
                        <div class="card-header">
                            <i class="fas fa-fingerprint me-2"></i>Passkey (Autenticazione Senza Password)
                        </div>
                        <div class="card-body">
                            <p class="text-muted">Le passkey ti permettono di accedere senza password usando biometria o chiavi di sicurezza.</p>

                            <div id="passkeysList" class="mb-3">
                                <div class="text-center text-muted py-3">
                                    <i class="fas fa-spinner fa-spin"></i> Caricamento...
                                </div>
                            </div>

                            <button class="btn btn-success" onclick="addPasskey()" id="addPasskeyBtn">
                                <i class="fas fa-plus me-1"></i>Aggiungi Passkey
                            </button>
                        </div>
                    </div>
                </div>

                <div class="col-md-6">
                    <!-- Mail Hostname -->
                    <div class="card mb-4">
                        <div class="card-header"><i class="fas fa-server me-2"></i>Mail Hostname</div>
                        <div class="card-body">
                            <div class="d-flex align-items-center mb-2">
                                <div class="form-control bg-light flex-grow-1" id="mailHostnameDisplay">
                                    {{MAIL_HOSTNAME}}
                                </div>
                                <button class="btn btn-outline-primary btn-sm ms-2" onclick="openChangeHostname()" title="Cambia hostname">
                                    <i class="fas fa-edit"></i>
                                </button>
                            </div>
                            <div id="hostnameConsistency" class="mb-2" style="display:none;"></div>
                            <small class="text-muted"><i class="fas fa-info-circle me-1"></i>Hostname del mail server (SMTP/IMAP/POP3)</small>
                        </div>
                    </div>

                    <!-- Roundcube Domain -->
                    <div class="card mb-4">
                        <div class="card-header"><i class="fas fa-envelope-open-text me-2"></i>Dominio Roundcube (Webmail)</div>
                        <div class="card-body">
                            <div class="d-flex align-items-center mb-2">
                                <div class="form-control bg-light flex-grow-1" id="rcDomainDisplay">
                                    {{ROUNDCUBE_DOMAIN}}
                                </div>
                                <button class="btn btn-outline-primary btn-sm ms-2" onclick="openChangeRcDomain()" title="Cambia dominio Roundcube">
                                    <i class="fas fa-edit"></i>
                                </button>
                            </div>
                            <div id="rcDomainDns" class="mb-2" style="display:none;"></div>
                            <small class="text-muted"><i class="fas fa-info-circle me-1"></i>Dominio usato per accedere alla webmail Roundcube (es: webmail.esempio.it)</small>
                        </div>
                    </div>

                    <!-- System Info -->
                    <div class="card">
                        <div class="card-header"><i class="fas fa-info-circle me-2"></i>Informazioni Sistema</div>
                        <div class="card-body">
                            <table class="table table-sm mb-0">
                                <tr><td><strong>Versione:</strong></td><td>1.0</td></tr>
                                <tr><td><strong>Database:</strong></td><td>{{DATABASE}}</td></tr>
                                <tr><td><strong>Piattaforma:</strong></td><td>{{PLATFORM}}</td></tr>
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
                    <h5 class="modal-title"><i class="fas fa-exchange-alt me-2"></i>Cambia Mail Hostname</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <!-- Step 1: Input -->
                    <div id="hostnameStep1">
                        <div class="alert alert-warning">
                            <i class="fas fa-exclamation-triangle me-2"></i>
                            <strong>Attenzione:</strong> Cambiare l'hostname del mail server influisce su SMTP, IMAP, POP3, certificati SSL e record DNS.
                            Il pannello aggiornera' automaticamente tutto cio' che puo', e ti guidera' per le azioni manuali.
                        </div>

                        <div id="hostnameCurrentState" class="mb-3">
                            <h6><i class="fas fa-info-circle me-2"></i>Stato Attuale</h6>
                            <table class="table table-sm table-bordered">
                                <tr><td><strong>SQLite</strong></td><td id="hsCurSqlite">-</td><td id="hsCurSqliteIcon"></td></tr>
                                <tr><td><strong>MySQL</strong></td><td id="hsCurMysql">-</td><td id="hsCurMysqlIcon"></td></tr>
                                <tr><td><strong>Postfix (main.cf)</strong></td><td id="hsCurPostfix">-</td><td id="hsCurPostfixIcon"></td></tr>
                                <tr><td><strong>Certificato SSL</strong></td><td id="hsCurSsl">-</td><td id="hsCurSslIcon"></td></tr>
                            </table>
                        </div>

                        <div class="mb-3">
                            <label class="form-label"><strong>Nuovo Hostname</strong></label>
                            <input type="text" class="form-control" id="newHostnameInput" placeholder="mail.esempio.it">
                            <small class="text-muted">FQDN del server mail (es: mail.miodominio.com)</small>
                        </div>

                        <button class="btn btn-primary w-100" onclick="executeHostnameChange()">
                            <i class="fas fa-play me-1"></i>Esegui Cambio Hostname
                        </button>
                    </div>

                    <!-- Step 2: Progress -->
                    <div id="hostnameStep2" style="display:none;">
                        <div class="text-center mb-3">
                            <div class="spinner-border text-primary" role="status"></div>
                            <p class="mt-2">Cambio hostname in corso...</p>
                        </div>
                    </div>

                    <!-- Step 3: Results -->
                    <div id="hostnameStep3" style="display:none;">
                        <h6><i class="fas fa-clipboard-check me-2"></i>Operazioni Automatiche Completate</h6>
                        <div id="hostnameAutoSteps" class="mb-3"></div>

                        <hr>
                        <h6><i class="fas fa-hand-point-right me-2"></i>Azioni Manuali Necessarie</h6>
                        <p class="text-muted">Completa queste azioni per finalizzare il cambio:</p>
                        <div id="hostnameManualActions" class="mb-3"></div>

                        <hr>
                        <h6><i class="fas fa-stethoscope me-2"></i>Verifica DNS</h6>
                        <p class="text-muted">Dopo aver aggiornato i DNS, clicca per verificare la propagazione:</p>
                        <button class="btn btn-info w-100 mb-2" onclick="checkHostnameDns()">
                            <i class="fas fa-search me-1"></i>Verifica Record DNS
                        </button>
                        <div id="hostnameDnsChecks" style="display:none;"></div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Chiudi</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Change Roundcube Domain Modal -->
    <div class="modal fade" id="changeRcDomainModal" tabindex="-1">
        <div class="modal-dialog modal-lg modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-envelope-open-text me-2"></i>Cambia Dominio Roundcube</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <!-- Step 1: Input -->
                    <div id="rcDomainStep1">
                        <div class="alert alert-info">
                            <i class="fas fa-info-circle me-2"></i>
                            Il dominio Roundcube e' l'indirizzo web con cui gli utenti accedono alla webmail
                            (es: <code>webmail.esempio.it</code>). E' separato dall'hostname del mail server (SMTP/IMAP).
                        </div>

                        <div class="mb-3">
                            <label class="form-label"><strong>Dominio Attuale</strong></label>
                            <div class="form-control bg-light" id="rcDomainCurrent">-</div>
                        </div>
                        <div class="mb-3" id="rcDomainDnsStatus" style="display:none;"></div>

                        <div class="mb-3">
                            <label class="form-label"><strong>Nuovo Dominio</strong></label>
                            <input type="text" class="form-control" id="newRcDomainInput" placeholder="webmail.esempio.it">
                            <small class="text-muted">FQDN per la webmail (es: webmail.miodominio.com, mail.miodominio.com)</small>
                        </div>

                        <button class="btn btn-primary w-100 mb-3" onclick="executeRcDomainChange()">
                            <i class="fas fa-play me-1"></i>Cambia Dominio Roundcube
                        </button>

                        <hr>
                        <h6><i class="fas fa-lock me-2"></i>Certificato SSL Roundcube</h6>
                        <p class="text-muted small">Incolla il contenuto dei certificati PEM. Lascia vuoto per usare i certificati del mail server.</p>
                        <small class="text-muted mb-2 d-block" id="rcSslPathInfo"></small>
                        <div class="mb-2">
                            <label class="form-label small"><strong>Certificato (fullchain.pem)</strong></label>
                            <textarea class="form-control form-control-sm font-monospace" id="rcSslCertInput" rows="4" placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"></textarea>
                        </div>
                        <div class="mb-2">
                            <label class="form-label small"><strong>Chiave Privata (privkey.pem)</strong></label>
                            <textarea class="form-control form-control-sm font-monospace" id="rcSslKeyInput" rows="4" placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----"></textarea>
                        </div>
                        <div class="mb-3">
                            <label class="form-label small"><strong>CA Chain (opzionale)</strong></label>
                            <textarea class="form-control form-control-sm font-monospace" id="rcSslChainInput" rows="3" placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"></textarea>
                        </div>
                        <button class="btn btn-warning w-100" onclick="executeRcSslChange()">
                            <i class="fas fa-lock me-1"></i>Salva Certificato SSL
                        </button>
                    </div>

                    <!-- Step 2: Progress -->
                    <div id="rcDomainStep2" style="display:none;">
                        <div class="text-center mb-3">
                            <div class="spinner-border text-primary" role="status"></div>
                            <p class="mt-2">Aggiornamento in corso...</p>
                        </div>
                    </div>

                    <!-- Step 3: Results -->
                    <div id="rcDomainStep3" style="display:none;">
                        <h6><i class="fas fa-clipboard-check me-2"></i>Operazioni Automatiche Completate</h6>
                        <div id="rcDomainAutoSteps" class="mb-3"></div>

                        <hr>
                        <h6><i class="fas fa-hand-point-right me-2"></i>Azioni Manuali Necessarie</h6>
                        <div id="rcDomainManualActions" class="mb-3"></div>

                        <hr>
                        <h6><i class="fas fa-stethoscope me-2"></i>Verifica DNS</h6>
                        <p class="text-muted">Dopo aver configurato il DNS, verifica la propagazione:</p>
                        <button class="btn btn-info w-100 mb-2" onclick="checkRcDomainDns()">
                            <i class="fas fa-search me-1"></i>Verifica DNS Roundcube
                        </button>
                        <div id="rcDomainDnsChecks" style="display:none;"></div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Chiudi</button>
                </div>
            </div>
        </div>
    </div>

    <!-- 2FA Setup Modal -->
    <div class="modal fade" id="setup2FAModal" tabindex="-1">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-shield-alt me-2"></i>Configura 2FA</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div id="setup2FAStep1">
                        <p>Scansiona il QR code con la tua app di autenticazione (Google Authenticator, Authy, ecc.):</p>
                        <div class="qr-container">
                            <img id="qrCodeImage" src="" alt="QR Code">
                        </div>
                        <p class="mt-3">Oppure inserisci manualmente questo codice:</p>
                        <div class="input-group mb-3">
                            <input type="text" class="form-control font-monospace" id="secretKey" readonly>
                            <button class="btn btn-outline-secondary" onclick="copySecret()">
                                <i class="fas fa-copy"></i>
                            </button>
                        </div>
                        <hr>
                        <p>Inserisci il codice a 6 cifre dalla tua app per verificare:</p>
                        <div class="input-group">
                            <input type="text" class="form-control" id="verifyCode" maxlength="6" pattern="[0-9]{6}" placeholder="000000">
                            <button class="btn btn-success" onclick="verify2FA()">Verifica</button>
                        </div>
                    </div>
                    <div id="setup2FAStep2" style="display:none;">
                        <div class="alert alert-success">
                            <i class="fas fa-check-circle me-2"></i>2FA attivata con successo!
                        </div>
                        <p><strong>Codici di Backup</strong></p>
                        <p class="text-muted">Salva questi codici in un posto sicuro. Puoi usarli per accedere se perdi il telefono.</p>
                        <div id="backupCodesContainer" class="mb-3"></div>
                        <button class="btn btn-primary" onclick="downloadBackupCodes()">
                            <i class="fas fa-download me-1"></i>Scarica Codici
                        </button>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Chiudi</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Backup Codes Modal -->
    <div class="modal fade" id="backupCodesModal" tabindex="-1">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-key me-2"></i>Codici di Backup</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="alert alert-warning">
                        <i class="fas fa-exclamation-triangle me-2"></i>Ogni codice puo' essere usato una sola volta.
                    </div>
                    <div id="existingBackupCodes"></div>
                    <hr>
                    <button class="btn btn-warning" onclick="regenerateBackupCodes()">
                        <i class="fas fa-sync me-1"></i>Rigenera Codici
                    </button>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Chiudi</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Passkey Name Modal -->
    <div class="modal fade" id="passkeyNameModal" tabindex="-1">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-fingerprint me-2"></i>Nome Passkey</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="mb-3">
                        <label class="form-label">Dai un nome a questa passkey</label>
                        <input type="text" class="form-control" id="passkeyName" placeholder="Es: MacBook Touch ID, iPhone, YubiKey">
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Annulla</button>
                    <button type="button" class="btn btn-primary" onclick="confirmPasskeyName()">Salva</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Rename Passkey Modal -->
    <div class="modal fade" id="renamePasskeyModal" tabindex="-1">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-edit me-2"></i>Rinomina Passkey</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <input type="hidden" id="renamePasskeyId">
                    <div class="mb-3">
                        <label class="form-label">Nuovo nome</label>
                        <input type="text" class="form-control" id="renamePasskeyName">
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Annulla</button>
                    <button type="button" class="btn btn-primary" onclick="confirmRenamePasskey()">Salva</button>
                </div>
            </div>
        </div>
    </div>
""" + getFooter() + """
    <script>
        let currentSecret = '';
        let backupCodes = [];
        let pendingPasskeyChallenge = null;

        function load2FAStatus() {
            fetch('/api/2fa?action=status')
                .then(r => r.json())
                .then(data => {
                    const badge = document.getElementById('2faStatusBadge');
                    if (data.enabled) {
                        badge.className = 'badge bg-success';
                        badge.textContent = 'Attivo';
                        document.getElementById('2faEnabled').style.display = 'block';
                        document.getElementById('2faDisabled').style.display = 'none';
                    } else {
                        badge.className = 'badge bg-secondary';
                        badge.textContent = 'Non Attivo';
                        document.getElementById('2faEnabled').style.display = 'none';
                        document.getElementById('2faDisabled').style.display = 'block';
                    }
                });
        }

        function setup2FA() {
            fetch('/api/2fa', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'setup' })
            })
            .then(r => r.json())
            .then(data => {
                if (data.secret) {
                    currentSecret = data.secret;
                    document.getElementById('qrCodeImage').src = data.qr_url;
                    document.getElementById('secretKey').value = data.secret;
                    document.getElementById('setup2FAStep1').style.display = 'block';
                    document.getElementById('setup2FAStep2').style.display = 'none';
                    document.getElementById('verifyCode').value = '';
                    new bootstrap.Modal(document.getElementById('setup2FAModal')).show();
                } else {
                    alert(data.error || 'Errore nella configurazione');
                }
            });
        }

        function verify2FA() {
            const code = document.getElementById('verifyCode').value.trim();
            if (!code || code.length !== 6) {
                alert('Inserisci un codice a 6 cifre');
                return;
            }

            fetch('/api/2fa', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'enable', code: code, secret: currentSecret })
            })
            .then(r => r.json())
            .then(data => {
                console.log('2FA verify response:', data);
                if (data.success) {
                    backupCodes = data.backup_codes || [];
                    document.getElementById('setup2FAStep1').style.display = 'none';
                    document.getElementById('setup2FAStep2').style.display = 'block';
                    document.getElementById('backupCodesContainer').innerHTML =
                        backupCodes.map(c => `<span class="backup-code">${c}</span>`).join(' ');
                    load2FAStatus();
                } else {
                    alert(data.error || 'Codice non valido');
                }
            })
            .catch(err => {
                console.error('2FA verify error:', err);
                alert('Errore: ' + err.message);
            });
        }

        function disable2FA() {
            if (!confirm('Sei sicuro di voler disattivare la 2FA? Il tuo account sara meno sicuro.')) return;

            const code = prompt('Inserisci il codice dalla tua app di autenticazione:');
            if (!code) return;

            fetch('/api/2fa', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'disable', code: code })
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    alert('2FA disattivata');
                    load2FAStatus();
                } else {
                    alert(data.error || 'Codice non valido');
                }
            });
        }

        function showBackupCodes() {
            fetch('/api/2fa?action=backup_codes')
                .then(r => r.json())
                .then(data => {
                    if (data.success) {
                        if (data.codes && data.codes.length > 0) {
                            document.getElementById('existingBackupCodes').innerHTML =
                                data.codes.map(c => `<span class="backup-code">${c}</span>`).join(' ');
                        } else {
                            document.getElementById('existingBackupCodes').innerHTML =
                                '<p class="text-warning"><i class="fas fa-exclamation-triangle me-2"></i>' +
                                'I codici di backup sono stati generati durante l\\'attivazione della 2FA.<br>' +
                                'Se li hai persi, usa il pulsante "Rigenera Codici" per crearne di nuovi.</p>';
                        }
                        new bootstrap.Modal(document.getElementById('backupCodesModal')).show();
                    } else {
                        alert(data.error || 'Errore nel recupero dei codici');
                    }
                })
                .catch(err => alert('Errore: ' + err.message));
        }

        function regenerateBackupCodes() {
            if (!confirm('I vecchi codici non saranno piu validi. Continuare?')) return;

            fetch('/api/2fa', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'regenerate_backup' })
            })
            .then(r => r.json())
            .then(data => {
                if (data.codes) {
                    document.getElementById('existingBackupCodes').innerHTML =
                        data.codes.map(c => `<span class="backup-code">${c}</span>`).join(' ');
                    alert('Nuovi codici generati');
                }
            });
        }

        function copySecret() {
            navigator.clipboard.writeText(document.getElementById('secretKey').value);
            alert('Codice copiato');
        }

        function downloadBackupCodes() {
            const text = 'Codici di Backup 2FA - Mail Panel\\n\\n' + backupCodes.join('\\n');
            const blob = new Blob([text], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'backup-codes-mailpanel.txt';
            a.click();
        }

""" + getSettingsAuthJs() + """
        // ========== PASSKEY FUNCTIONS ==========

        function loadPasskeys() {
            fetch('/api/passkeys')
                .then(r => r.json())
                .then(data => {
                    const container = document.getElementById('passkeysList');
                    if (data.success && data.passkeys.length > 0) {
                        container.innerHTML = data.passkeys.map(pk => `
                            <div class="d-flex justify-content-between align-items-center p-2 bg-light rounded mb-2">
                                <div>
                                    <i class="fas fa-key me-2 text-primary"></i>
                                    <strong>${escapeHtml(pk.name)}</strong>
                                    <br>
                                    <small class="text-muted">
                                        Creata: ${pk.createdAt} | Ultimo uso: ${pk.lastUsed}
                                    </small>
                                </div>
                                <div>
                                    <button class="btn btn-sm btn-outline-secondary me-1" onclick="renamePasskey(${pk.id}, '${escapeHtml(pk.name)}')">
                                        <i class="fas fa-edit"></i>
                                    </button>
                                    <button class="btn btn-sm btn-outline-danger" onclick="deletePasskey(${pk.id}, '${escapeHtml(pk.name)}')">
                                        <i class="fas fa-trash"></i>
                                    </button>
                                </div>
                            </div>
                        `).join('');
                    } else {
                        container.innerHTML = '<p class="text-muted text-center py-2">Nessuna passkey registrata</p>';
                    }
                })
                .catch(err => {
                    document.getElementById('passkeysList').innerHTML =
                        '<p class="text-danger text-center py-2">Errore nel caricamento</p>';
                });
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        async function addPasskey() {
            const btn = document.getElementById('addPasskeyBtn');
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Avvio...';

            try {
                // Start registration
                const startRes = await fetch('/api/passkey/register/start', { method: 'POST' });
                const startData = await startRes.json();

                if (!startData.success) {
                    alert(startData.error || 'Errore nell avvio della registrazione');
                    btn.disabled = false;
                    btn.innerHTML = '<i class="fas fa-plus me-1"></i>Aggiungi Passkey';
                    return;
                }

                // Parse WebAuthn options
                const options = JSON.parse(startData.options);

                // Convert base64url to ArrayBuffer for WebAuthn API
                options.publicKey.challenge = base64urlToBuffer(options.publicKey.challenge);
                options.publicKey.user.id = base64urlToBuffer(options.publicKey.user.id);
                if (options.publicKey.excludeCredentials) {
                    options.publicKey.excludeCredentials = options.publicKey.excludeCredentials.map(c => ({
                        ...c,
                        id: base64urlToBuffer(c.id)
                    }));
                }

                btn.innerHTML = '<i class="fas fa-fingerprint fa-spin me-1"></i>Conferma sul dispositivo...';

                // Call WebAuthn API
                const credential = await navigator.credentials.create(options);

                // Store challenge ID and show name modal
                pendingPasskeyChallenge = {
                    challengeId: startData.challengeId,
                    credential: {
                        id: credential.id,
                        rawId: bufferToBase64url(credential.rawId),
                        type: credential.type,
                        response: {
                            clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
                            attestationObject: bufferToBase64url(credential.response.attestationObject)
                        },
                        clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {}
                    }
                };

                document.getElementById('passkeyName').value = '';
                new bootstrap.Modal(document.getElementById('passkeyNameModal')).show();

            } catch (err) {
                console.error('Passkey registration error:', err);
                if (err.name === 'NotAllowedError') {
                    alert('Registrazione annullata o timeout');
                } else {
                    alert('Errore: ' + err.message);
                }
            }

            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-plus me-1"></i>Aggiungi Passkey';
        }

        async function confirmPasskeyName() {
            if (!pendingPasskeyChallenge) return;

            const name = document.getElementById('passkeyName').value.trim() || 'Passkey';

            try {
                const res = await fetch('/api/passkey/register/finish', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        challengeId: pendingPasskeyChallenge.challengeId,
                        credential: JSON.stringify(pendingPasskeyChallenge.credential),
                        name: name
                    })
                });
                const data = await res.json();

                if (data.success) {
                    bootstrap.Modal.getInstance(document.getElementById('passkeyNameModal')).hide();
                    alert('Passkey registrata con successo!');
                    loadPasskeys();
                } else {
                    alert(data.error || 'Errore nella registrazione');
                }
            } catch (err) {
                alert('Errore: ' + err.message);
            }

            pendingPasskeyChallenge = null;
        }

        function renamePasskey(id, currentName) {
            document.getElementById('renamePasskeyId').value = id;
            document.getElementById('renamePasskeyName').value = currentName;
            new bootstrap.Modal(document.getElementById('renamePasskeyModal')).show();
        }

        async function confirmRenamePasskey() {
            const id = document.getElementById('renamePasskeyId').value;
            const name = document.getElementById('renamePasskeyName').value.trim();

            if (!name) {
                alert('Inserisci un nome');
                return;
            }

            try {
                const res = await fetch('/api/passkeys', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ id: parseInt(id), name: name })
                });
                const data = await res.json();

                if (data.success) {
                    bootstrap.Modal.getInstance(document.getElementById('renamePasskeyModal')).hide();
                    loadPasskeys();
                } else {
                    alert(data.error || 'Errore nella rinomina');
                }
            } catch (err) {
                alert('Errore: ' + err.message);
            }
        }

        async function deletePasskey(id, name) {
            if (!confirm(`Eliminare la passkey "${name}"? Non potrai piu usarla per accedere.`)) return;

            try {
                const res = await fetch('/api/passkeys', {
                    method: 'DELETE',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ id: id })
                });
                const data = await res.json();

                if (data.success) {
                    loadPasskeys();
                } else {
                    alert(data.error || 'Errore nell eliminazione');
                }
            } catch (err) {
                alert('Errore: ' + err.message);
            }
        }

        // Base64url helpers for WebAuthn
        function base64urlToBuffer(base64url) {
            const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
            const padding = '='.repeat((4 - base64.length % 4) % 4);
            const binary = atob(base64 + padding);
            const buffer = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                buffer[i] = binary.charCodeAt(i);
            }
            return buffer.buffer;
        }

        function bufferToBase64url(buffer) {
            const bytes = new Uint8Array(buffer);
            let binary = '';
            for (let i = 0; i < bytes.length; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return btoa(binary).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=/g, '');
        }

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
                            '<i class="fas fa-exclamation-triangle me-1"></i>' +
                            '<small>Hostname non allineato tra i componenti. Clicca <i class="fas fa-edit"></i> per risolvere.</small></div>';
                    } else {
                        div.style.display = 'none';
                    }
                })
                .catch(() => {});
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
                        el.textContent = val || 'Non configurato';
                    };
                    const setIcon = (id, val, ref) => {
                        const el = document.getElementById(id);
                        if (!val || !ref) {
                            el.innerHTML = '<i class="fas fa-minus text-muted"></i>';
                        } else if (val === ref) {
                            el.innerHTML = '<i class="fas fa-check-circle text-success"></i>';
                        } else {
                            el.innerHTML = '<i class="fas fa-times-circle text-danger"></i>';
                        }
                    };

                    const ref = data.sqlite_hostname || data.mysql_hostname || '';
                    setCell('hsCurSqlite', data.sqlite_hostname);
                    setCell('hsCurMysql', data.mysql_hostname);
                    setCell('hsCurPostfix', data.postfix_hostname);
                    setCell('hsCurSsl', data.ssl_cn || data.ssl_hostname || 'N/D');

                    setIcon('hsCurSqliteIcon', data.sqlite_hostname, ref);
                    setIcon('hsCurMysqlIcon', data.mysql_hostname, ref);
                    setIcon('hsCurPostfixIcon', data.postfix_hostname, ref || data.postfix_hostname);
                    // SSL: compare with ref
                    const sslVal = data.ssl_cn || data.ssl_hostname || '';
                    if (sslVal && ref && sslVal === ref) {
                        document.getElementById('hsCurSslIcon').innerHTML = '<i class="fas fa-check-circle text-success"></i>';
                    } else if (sslVal) {
                        document.getElementById('hsCurSslIcon').innerHTML = '<i class="fas fa-exclamation-circle text-warning"></i>';
                    } else {
                        document.getElementById('hsCurSslIcon').innerHTML = '<i class="fas fa-minus text-muted"></i>';
                    }

                    // Pre-fill with current hostname
                    document.getElementById('newHostnameInput').value = ref;
                });

            new bootstrap.Modal(document.getElementById('changeHostnameModal')).show();
        }

        function executeHostnameChange() {
            const newHostname = document.getElementById('newHostnameInput').value.trim().toLowerCase();
            if (!newHostname || !newHostname.includes('.')) {
                alert('Inserisci un hostname valido (es: mail.esempio.it)');
                return;
            }

            const currentHostname = document.getElementById('mailHostnameDisplay').textContent.trim();
            if (newHostname === currentHostname) {
                if (!confirm('L\\'hostname e\\' lo stesso. Vuoi comunque riallineare tutti i componenti?')) return;
            } else {
                if (!confirm('Cambiare l\\'hostname da "' + currentHostname + '" a "' + newHostname + '"?\\n\\nQuesta operazione aggiornera\\' SQLite, MySQL, Postfix e ricarichera\\' i servizi.')) return;
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
                            ? '<i class="fas fa-check-circle text-success me-2"></i>'
                            : '<i class="fas fa-times-circle text-danger me-2"></i>';
                        return '<div class="d-flex align-items-start mb-2">' + icon +
                            '<div><strong>' + escapeHtml(s.step) + '</strong><br><small class="text-muted">' +
                            escapeHtml(s.detail) + '</small></div></div>';
                    }).join('');
                }

                // Render manual actions
                const actionsDiv = document.getElementById('hostnameManualActions');
                if (data.manual_actions) {
                    actionsDiv.innerHTML = data.manual_actions.map((a, i) => {
                        let icon = '<i class="fas fa-globe text-primary me-2"></i>';
                        if (a.type === 'ssl') icon = '<i class="fas fa-lock text-warning me-2"></i>';
                        if (a.type === 'verify') icon = '<i class="fas fa-check-double text-info me-2"></i>';
                        if (a.type === 'roundcube') icon = '<i class="fas fa-envelope-open-text text-info me-2"></i>';
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
                alert('Errore: ' + err.message);
            });
        }

        function checkHostnameDns() {
            const hostname = hostnameChangeData ? hostnameChangeData.new_hostname : document.getElementById('mailHostnameDisplay').textContent.trim();
            const checksDiv = document.getElementById('hostnameDnsChecks');
            checksDiv.style.display = 'block';
            checksDiv.innerHTML = '<div class="text-center"><i class="fas fa-spinner fa-spin"></i> Verifica in corso...</div>';

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
                    checksDiv.innerHTML = '<div class="alert alert-danger">' + (data.error || 'Errore') + '</div>';
                    return;
                }

                let html = '<table class="table table-sm table-bordered mt-2">';
                html += '<thead><tr><th>Tipo</th><th>Nome</th><th>Attuale</th><th>Atteso</th><th>Stato</th></tr></thead><tbody>';
                data.checks.forEach(c => {
                    const icon = c.passed
                        ? '<i class="fas fa-check-circle text-success"></i>'
                        : '<i class="fas fa-times-circle text-danger"></i>';
                    html += '<tr><td><code>' + c.type + '</code></td><td>' + escapeHtml(c.name) +
                        '</td><td><small>' + escapeHtml(c.current) + '</small></td><td><small>' +
                        escapeHtml(c.expected) + '</small></td><td class="text-center">' + icon + '</td></tr>';
                });
                html += '</tbody></table>';

                if (data.all_passed) {
                    html += '<div class="alert alert-success mt-2"><i class="fas fa-check-circle me-2"></i>Tutti i record DNS sono correttamente configurati!</div>';
                } else {
                    html += '<div class="alert alert-warning mt-2"><i class="fas fa-exclamation-triangle me-2"></i>Alcuni record DNS devono ancora essere aggiornati. Riprova dopo aver fatto le modifiche.</div>';
                }

                checksDiv.innerHTML = html;
            })
            .catch(err => {
                checksDiv.innerHTML = '<div class="alert alert-danger">Errore: ' + err.message + '</div>';
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
                    if (data.domain && data.domain !== 'Non configurato') {
                        el.style.display = 'block';
                        if (data.dns_ok && data.dns_proxied) {
                            el.innerHTML = '<span class="badge bg-info"><i class="fas fa-cloud me-1"></i>DNS OK (Proxy/CDN) - ' + escapeHtml(data.domain) + ' -> ' + escapeHtml(data.dns_result) + '</span>';
                        } else if (data.dns_ok) {
                            el.innerHTML = '<span class="badge bg-success"><i class="fas fa-check-circle me-1"></i>DNS OK - ' + escapeHtml(data.domain) + ' -> ' + escapeHtml(data.dns_result) + '</span>';
                        } else {
                            el.innerHTML = '<span class="badge bg-danger"><i class="fas fa-times-circle me-1"></i>DNS NON configurato per ' + escapeHtml(data.domain) + '</span>';
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
                    document.getElementById('rcDomainCurrent').textContent = data.domain || 'Non configurato';
                    document.getElementById('newRcDomainInput').value = data.domain || '';

                    const dnsEl = document.getElementById('rcDomainDnsStatus');
                    if (data.domain) {
                        dnsEl.style.display = 'block';
                        if (data.dns_ok && data.dns_proxied) {
                            dnsEl.innerHTML = '<div class="alert alert-info py-2 mb-0"><i class="fas fa-cloud me-1"></i>DNS OK (Proxy/CDN): <code>' + escapeHtml(data.domain) + '</code> -> <code>' + escapeHtml(data.dns_result) + '</code></div>';
                        } else if (data.dns_ok) {
                            dnsEl.innerHTML = '<div class="alert alert-success py-2 mb-0"><i class="fas fa-check-circle me-1"></i>DNS OK: <code>' + escapeHtml(data.domain) + '</code> -> <code>' + escapeHtml(data.dns_result) + '</code></div>';
                        } else {
                            dnsEl.innerHTML = '<div class="alert alert-danger py-2 mb-0"><i class="fas fa-times-circle me-1"></i>DNS non configurato per <code>' + escapeHtml(data.domain) + '</code></div>';
                        }
                    }

                    // Populate SSL fields with file contents
                    document.getElementById('rcSslCertInput').value = data.ssl_cert_content || '';
                    document.getElementById('rcSslKeyInput').value = data.ssl_key_content || '';
                    document.getElementById('rcSslChainInput').value = data.ssl_chain_content || '';
                    const sslPath = data.nginx_ssl_cert || '';
                    document.getElementById('rcSslPathInfo').textContent = sslPath ? 'File attuali: ' + sslPath + ', ' + (data.nginx_ssl_key || '') : '';
                });

            new bootstrap.Modal(document.getElementById('changeRcDomainModal')).show();
        }

        function executeRcDomainChange() {
            const newDomain = document.getElementById('newRcDomainInput').value.trim().toLowerCase();
            if (!newDomain || !newDomain.includes('.')) {
                alert('Inserisci un dominio valido (es: webmail.esempio.it)');
                return;
            }

            const currentDomain = document.getElementById('rcDomainCurrent').textContent.trim();
            if (newDomain === currentDomain) {
                if (!confirm('Il dominio e\\' lo stesso. Vuoi comunque riallineare la configurazione?')) return;
            } else {
                if (!confirm('Cambiare il dominio Roundcube da "' + currentDomain + '" a "' + newDomain + '"?\\n\\nVerra\\' aggiornato SQLite, Nginx e l\\'SSO manager.')) return;
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
                            ? '<i class="fas fa-check-circle text-success me-2"></i>'
                            : '<i class="fas fa-times-circle text-danger me-2"></i>';
                        return '<div class="d-flex align-items-start mb-2">' + icon +
                            '<div><strong>' + escapeHtml(s.step) + '</strong><br><small class="text-muted">' +
                            escapeHtml(s.detail) + '</small></div></div>';
                    }).join('');
                }

                // Render manual actions
                const actionsDiv = document.getElementById('rcDomainManualActions');
                if (data.manual_actions) {
                    actionsDiv.innerHTML = data.manual_actions.map((a, i) => {
                        let icon = '<i class="fas fa-globe text-primary me-2"></i>';
                        if (a.type === 'ssl') icon = '<i class="fas fa-lock text-warning me-2"></i>';
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
                alert('Errore: ' + err.message);
            });
        }

        function checkRcDomainDns() {
            const domain = rcDomainChangeData ? rcDomainChangeData.new_domain : document.getElementById('rcDomainDisplay').textContent.trim();
            const checksDiv = document.getElementById('rcDomainDnsChecks');
            checksDiv.style.display = 'block';
            checksDiv.innerHTML = '<div class="text-center"><i class="fas fa-spinner fa-spin"></i> Verifica in corso...</div>';

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
                    checksDiv.innerHTML = '<div class="alert alert-danger">' + (data.error || 'Errore') + '</div>';
                    return;
                }

                let html = '';
                if (data.a_ok && data.a_proxied) {
                    html += '<div class="alert alert-info"><i class="fas fa-cloud me-2"></i>Record A per <code>' + escapeHtml(data.domain) + '</code> configurato tramite proxy/CDN (Cloudflare). Questo e\\' normale per la webmail.</div>';
                } else if (data.a_ok) {
                    html += '<div class="alert alert-success"><i class="fas fa-check-circle me-2"></i>Record A per <code>' + escapeHtml(data.domain) + '</code> punta correttamente a <code>' + escapeHtml(data.server_ip) + '</code></div>';
                } else {
                    html += '<div class="alert alert-danger"><i class="fas fa-times-circle me-2"></i>Record A per <code>' + escapeHtml(data.domain) + '</code> non risolve a nessun IP.<br>';
                    html += '<small class="text-muted">Configura un record A nel tuo pannello DNS (es. Cloudflare): <strong>Tipo</strong> A, <strong>Nome</strong> ' + escapeHtml(data.domain.split('.')[0]) + ', <strong>IPv4</strong> ' + escapeHtml(data.server_ip || 'IP_SERVER') + '</small></div>';
                }
                checksDiv.innerHTML = html;
            })
            .catch(err => {
                checksDiv.innerHTML = '<div class="alert alert-danger">Errore: ' + err.message + '</div>';
            });
        }

        function executeRcSslChange() {
            const sslCert = document.getElementById('rcSslCertInput').value.trim();
            const sslKey = document.getElementById('rcSslKeyInput').value.trim();
            const sslChain = document.getElementById('rcSslChainInput').value.trim();

            if (!sslCert && !sslKey) {
                if (!confirm('Certificato e chiave vuoti: verranno usati i certificati del mail server. Continuare?')) return;
            }
            if ((sslCert && !sslKey) || (!sslCert && sslKey)) {
                alert('Devi specificare sia il certificato che la chiave, oppure lasciare entrambi vuoti.');
                return;
            }
            if (sslCert && !sslCert.includes('BEGIN')) {
                alert('Il certificato deve essere in formato PEM (inizia con -----BEGIN CERTIFICATE-----)');
                return;
            }
            if (sslKey && !sslKey.includes('BEGIN')) {
                alert('La chiave deve essere in formato PEM (inizia con -----BEGIN PRIVATE KEY----- o -----BEGIN RSA PRIVATE KEY-----)');
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
                            ? '<i class="fas fa-check-circle text-success me-2"></i>'
                            : '<i class="fas fa-times-circle text-danger me-2"></i>';
                        return '<div class="d-flex align-items-start mb-2">' + icon +
                            '<div><strong>' + escapeHtml(s.step) + '</strong><br><small class="text-muted">' +
                            escapeHtml(s.detail) + '</small></div></div>';
                    }).join('');
                }

                document.getElementById('rcDomainManualActions').innerHTML =
                    data.success
                        ? '<div class="alert alert-success py-2"><i class="fas fa-check-circle me-1"></i>Certificato SSL aggiornato. Verifica che Roundcube funzioni correttamente.</div>'
                        : '<div class="alert alert-danger py-2"><i class="fas fa-times-circle me-1"></i>Errore: ' + escapeHtml(data.error || 'Controlla i log') + '</div>';
            })
            .catch(err => {
                document.getElementById('rcDomainStep2').style.display = 'none';
                document.getElementById('rcDomainStep1').style.display = 'block';
                alert('Errore: ' + err.message);
            });
        }

        // Load on page load
        load2FAStatus();
        loadPasskeys();
        checkHostnameConsistency();
        checkRcDomainDnsStatus();

        let csrfToken = document.getElementById('csrf_token').value;
""" + getLogoutScript() + """
    </script>
</body>
</html>
""";
    }

    // ============== QUEUE.HTML ==============
    public static String getQueueHtml() {
        String extraStyles = """
        .queue-item { background: #f8f9fa; padding: 15px; margin-bottom: 10px; border-radius: 8px; border-left: 4px solid #e94560; }
        .queue-item:hover { background: #e9ecef; }
        .stat-pending { border-color: #ffc107; }
        .stat-inflight { border-color: #17a2b8; }
        .stat-tempfail { border-color: #fd7e14; }
        .stat-permfail { border-color: #dc3545; }
        .queue-state { font-size: 0.75rem; padding: 2px 8px; border-radius: 3px; }
        .state-pending { background: #fff3cd; color: #856404; }
        .state-scheduled { background: #cce5ff; color: #004085; }
        .state-inflight { background: #d1ecf1; color: #0c5460; }
        .state-tempfail { background: #ffe5d0; color: #8a4600; }
        .state-permfail { background: #f8d7da; color: #721c24; }
        """;
        return getHead("Coda Email", extraStyles) + getNavbar("") + """
    <div class="content container mt-4">
        <div class="content-container">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h2><i class="fas fa-inbox me-2"></i>Coda Email</h2>
                <div>
                    <button class="btn btn-success btn-sm me-2" onclick="flushQueue()">
                        <i class="fas fa-play"></i> Invia Tutti
                    </button>
                    <button class="btn btn-warning btn-sm me-2" onclick="pauseQueue()" id="pauseBtn">
                        <i class="fas fa-pause"></i> Pausa
                    </button>
                    <button class="btn btn-danger btn-sm" onclick="purgePermfails()">
                        <i class="fas fa-trash"></i> Elimina Falliti
                    </button>
                </div>
            </div>

            <!-- Statistics -->
            <div class="row mb-4" id="statsRow">
                <div class="col-md-3">
                    <div class="card stat-card stat-pending">
                        <div class="card-body text-center">
                            <h3 id="statTotal">-</h3>
                            <small class="text-muted">Totale in Coda</small>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card stat-card stat-inflight">
                        <div class="card-body text-center">
                            <h3 id="statInflight">-</h3>
                            <small class="text-muted">In Consegna</small>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card stat-card stat-tempfail">
                        <div class="card-body text-center">
                            <h3 id="statTempfail">-</h3>
                            <small class="text-muted">Errori Temp.</small>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card stat-card stat-permfail">
                        <div class="card-body text-center">
                            <h3 id="statPermfail">-</h3>
                            <small class="text-muted">Errori Perm.</small>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Queue Table -->
            <div class="card">
                <div class="card-header d-flex justify-content-between">
                    <span>Messaggi in Coda</span>
                    <button class="btn btn-sm btn-outline-secondary" onclick="loadQueue()">
                        <i class="fas fa-sync"></i> Aggiorna
                    </button>
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-hover" id="queueTable">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Stato</th>
                                    <th>Da</th>
                                    <th>A</th>
                                    <th>Dimensione</th>
                                    <th>Data</th>
                                    <th>Errore</th>
                                    <th>Azioni</th>
                                </tr>
                            </thead>
                            <tbody id="queueBody">
                                <tr><td colspan="8" class="text-center">Caricamento...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Message Detail Modal -->
    <div class="modal fade" id="messageModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Dettagli Messaggio</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div id="messageDetails"></div>
                </div>
            </div>
        </div>
    </div>
""" + getFooter() + """
    <script>
        let csrfToken = document.getElementById('csrf_token').value;
        let paused = false;

        function loadStats() {
            fetch('/api/queue?action=stats')
                .then(r => r.json())
                .then(data => {
                    if (data.success) {
                        document.getElementById('statTotal').textContent = data.total || 0;
                        document.getElementById('statInflight').textContent = data.inflight || 0;
                        document.getElementById('statTempfail').textContent = data.tempfail || 0;
                        document.getElementById('statPermfail').textContent = data.permfail || 0;
                        paused = data.paused;
                        updatePauseButton();
                    }
                });
        }

        function loadQueue() {
            fetch('/api/queue')
                .then(r => r.json())
                .then(data => {
                    const tbody = document.getElementById('queueBody');
                    if (!data.success || !data.messages || data.messages.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">Coda vuota</td></tr>';
                        return;
                    }

                    tbody.innerHTML = data.messages.map(msg => {
                        const stateClass = 'state-' + msg.state.toLowerCase();
                        return `<tr>
                            <td><code>${msg.envelope_id || msg.message_id || '-'}</code></td>
                            <td><span class="queue-state ${stateClass}">${msg.state}</span></td>
                            <td>${msg.sender || '-'}</td>
                            <td>${msg.recipient || '-'}</td>
                            <td>${formatSize(msg.size)}</td>
                            <td>${msg.created ? new Date(msg.created).toLocaleString('it-IT') : '-'}</td>
                            <td class="text-danger">${msg.error_reason || ''}</td>
                            <td>
                                <button class="btn btn-sm btn-outline-info" onclick="viewMessage('${msg.message_id}', '${msg.envelope_id}')">
                                    <i class="fas fa-eye"></i>
                                </button>
                                <button class="btn btn-sm btn-outline-success" onclick="scheduleMessage('${msg.envelope_id}')">
                                    <i class="fas fa-redo"></i>
                                </button>
                                <button class="btn btn-sm btn-outline-danger" onclick="removeMessage('${msg.envelope_id}')">
                                    <i class="fas fa-trash"></i>
                                </button>
                            </td>
                        </tr>`;
                    }).join('');
                });
        }

        function formatSize(bytes) {
            if (!bytes) return '-';
            if (bytes < 1024) return bytes + ' B';
            if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
            return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
        }

        function viewMessage(messageId, envelopeId) {
            Promise.all([
                fetch('/api/queue?action=message&id=' + messageId).then(r => r.json()),
                fetch('/api/queue?action=envelope&id=' + envelopeId).then(r => r.json())
            ]).then(([msg, env]) => {
                let html = '<div class="row"><div class="col-md-6">';
                html += '<h6>Headers</h6>';
                html += '<p><strong>From:</strong> ' + (msg.from || '-') + '</p>';
                html += '<p><strong>To:</strong> ' + (msg.to || '-') + '</p>';
                html += '<p><strong>Subject:</strong> ' + (msg.subject || '-') + '</p>';
                html += '<p><strong>Date:</strong> ' + (msg.date || '-') + '</p>';
                html += '</div><div class="col-md-6">';
                html += '<h6>Envelope</h6>';
                html += '<p><strong>Sender:</strong> ' + (env.sender || '-') + '</p>';
                html += '<p><strong>Recipient:</strong> ' + (env.recipient || '-') + '</p>';
                html += '<p><strong>Status:</strong> ' + (env.status || '-') + '</p>';
                html += '<p><strong>Retries:</strong> ' + (env.retry_count || 0) + '</p>';
                if (env.error_line) {
                    html += '<p class="text-danger"><strong>Error:</strong> ' + env.error_line + '</p>';
                }
                html += '</div></div>';

                if (msg.body_preview) {
                    html += '<hr><h6>Body Preview</h6><pre class="bg-light p-2" style="max-height:200px;overflow:auto;">' + msg.body_preview + '</pre>';
                }

                document.getElementById('messageDetails').innerHTML = html;
                new bootstrap.Modal(document.getElementById('messageModal')).show();
            });
        }

        function scheduleMessage(envelopeId) {
            fetch('/api/queue', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'schedule', envelope_id: envelopeId })
            }).then(r => r.json()).then(data => {
                alert(data.message);
                loadQueue();
                loadStats();
            });
        }

        function removeMessage(envelopeId) {
            if (!confirm('Eliminare questo messaggio dalla coda?')) return;
            fetch('/api/queue', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'remove', envelope_id: envelopeId })
            }).then(r => r.json()).then(data => {
                alert(data.message);
                loadQueue();
                loadStats();
            });
        }

        function flushQueue() {
            if (!confirm('Inviare immediatamente tutti i messaggi in coda?')) return;
            fetch('/api/queue', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'flush' })
            }).then(r => r.json()).then(data => {
                alert(data.message);
                loadQueue();
                loadStats();
            });
        }

        function pauseQueue() {
            const action = paused ? 'resume' : 'pause';
            fetch('/api/queue', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: action })
            }).then(r => r.json()).then(data => {
                alert(data.message);
                paused = !paused;
                updatePauseButton();
            });
        }

        function updatePauseButton() {
            const btn = document.getElementById('pauseBtn');
            if (paused) {
                btn.innerHTML = '<i class="fas fa-play"></i> Riprendi';
                btn.className = 'btn btn-success btn-sm me-2';
            } else {
                btn.innerHTML = '<i class="fas fa-pause"></i> Pausa';
                btn.className = 'btn btn-warning btn-sm me-2';
            }
        }

        function purgePermfails() {
            if (!confirm('Eliminare tutti i messaggi con errori permanenti?')) return;
            fetch('/api/queue', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'purge_permfails' })
            }).then(r => r.json()).then(data => {
                alert(data.message);
                loadQueue();
                loadStats();
            });
        }

        // Load on page load
        loadStats();
        loadQueue();
        // Auto-refresh every 30 seconds
        setInterval(() => { loadStats(); loadQueue(); }, 30000);
""" + getLogoutScript() + """
    </script>
</body>
</html>
""";
    }

    // ============== SECURITY.HTML (FAIL2BAN) ==============
    public static String getSecurityHtml() {
        String extraStyles = """
        .jail-card { border-left: 4px solid #dc3545; }
        .jail-card.enabled { border-color: #28a745; }
        .ban-event { font-size: 0.85rem; padding: 8px; border-left: 3px solid; margin-bottom: 5px; }
        .ban-event.ban { border-color: #dc3545; background: #fff5f5; }
        .ban-event.unban { border-color: #28a745; background: #f5fff5; }
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
    <div class="content container mt-4">
        <div class="content-container">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h2><i class="fas fa-shield-alt me-2"></i>Sicurezza - Fail2ban</h2>
                <div>
                    <span class="badge bg-secondary me-2" id="statusBadge">Checking...</span>
                    <button class="btn btn-outline-primary btn-sm" onclick="loadStatus()">
                        <i class="fas fa-sync"></i> Aggiorna
                    </button>
                </div>
            </div>

            <!-- Setup Wizard / Health Check -->
            <div class="card mb-4 border-primary">
                <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-stethoscope me-2"></i><strong>Stato Fail2ban</strong> <small class="ms-2" id="fhcOverallStatus"></small></span>
                    <div class="d-flex gap-2 flex-wrap">
                        <button class="btn btn-sm btn-warning d-none" id="btnFixAll" onclick="runFhcFixAll()">
                            <i class="fas fa-magic me-1"></i>Risolvi tutto
                        </button>
                        <button class="btn btn-sm btn-outline-light" onclick="reloadFail2banFromPanel()" title="Esegue fail2ban-client reload: rilegge i file di config senza killare il daemon. Conserva i contatori.">
                            <i class="fas fa-sync-alt me-1"></i>Reload config
                        </button>
                        <button class="btn btn-sm btn-danger" onclick="restartFail2banFromPanel()" title="Esegue service fail2ban restart: killa il daemon e lo riavvia da zero. Usa questo se fail2ban e' in uno stato bislacco. Azzera i contatori e gli IP bannati attivi.">
                            <i class="fas fa-power-off me-1"></i>Restart fail2ban
                        </button>
                        <button class="btn btn-sm btn-light" onclick="loadFail2banHealth()">
                            <i class="fas fa-sync me-1"></i>Ricontrolla
                        </button>
                    </div>
                </div>
                <div class="card-body" id="fhcContainer">
                    <p class="text-muted mb-0"><i class="fas fa-spinner fa-spin me-1"></i>Diagnosi in corso...</p>
                </div>
                <div class="card-body border-top d-none" id="fhcFixAllReport">
                    <h6 class="mb-2"><i class="fas fa-list-check me-1"></i>Report risoluzione</h6>
                    <div id="fhcFixAllSteps"></div>
                </div>
            </div>

            <!-- Stato Live Jail Fail2ban (output di fail2ban-client get/status) -->
            <div class="card mb-4 border-secondary">
                <div class="card-header bg-secondary text-white d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-microscope me-2"></i><strong>Stato live jail (fail2ban-client get/status)</strong> <small class="ms-2 text-white-50">verifica che la config sia REALMENTE applicata</small></span>
                    <button class="btn btn-sm btn-light" onclick="loadJailLiveState()">
                        <i class="fas fa-sync me-1"></i>Aggiorna
                    </button>
                </div>
                <div class="card-body p-2" id="jailLiveBody">
                    <p class="text-muted small mb-0 p-2"><i class="fas fa-spinner fa-spin me-1"></i>Caricamento...</p>
                </div>
            </div>

            <!-- Postfix Aliases Health / Auto-fix -->
            <div class="card mb-4 border-info">
                <div class="card-header bg-info text-white d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-at me-2"></i><strong>Alias di sistema Postfix</strong> <small class="ms-2" id="paliasOverallBadge"></small></span>
                    <div class="d-flex gap-2">
                        <button class="btn btn-sm btn-warning d-none" id="paliasFixBtn" onclick="paliasFix()">
                            <i class="fas fa-magic me-1"></i>Risolvi
                        </button>
                        <button class="btn btn-sm btn-light" onclick="paliasLoad()">
                            <i class="fas fa-sync me-1"></i>Ricontrolla
                        </button>
                    </div>
                </div>
                <div class="card-body" id="paliasBody">
                    <p class="text-muted mb-0"><i class="fas fa-spinner fa-spin me-1"></i>Caricamento...</p>
                </div>
                <div class="card-body border-top">
                    <h6 class="mb-2"><i class="fas fa-share me-1"></i>Forward delle mail di sistema (root)</h6>
                    <p class="small text-muted mb-2">Le mail dirette a <code>root</code>, <code>postmaster</code>, <code>mailer-daemon</code> ecc. vengono inoltrate qui. Imposta una mail vera così ricevi alert di sistema (cron, security, ecc.). Lascia <code>root</code> per non inoltrare a nessuno.</p>
                    <div class="input-group input-group-sm">
                        <span class="input-group-text">root →</span>
                        <input type="text" class="form-control" id="paliasRootForward" placeholder="es. owner@domain-a.test oppure root">
                        <button class="btn btn-info" type="button" onclick="paliasSetRootForward()"><i class="fas fa-save me-1"></i>Salva forward</button>
                    </div>
                    <div id="paliasLog" class="mt-2 small"></div>
                </div>
            </div>

            <!-- Unbound (resolver DNS locale) Health Check -->
            <div class="card mb-4 border-info">
                <div class="card-header bg-info text-white d-flex justify-content-between align-items-center flex-wrap gap-2">
                    <span><i class="fas fa-network-wired me-2"></i><strong>Resolver DNS locale (unbound)</strong> <small class="ms-2" id="ubOverallStatus"></small></span>
                    <div class="d-flex gap-2">
                        <button class="btn btn-sm btn-light" id="btnUbTestQuery" onclick="runUbTestQuery()" title="Esegue dig di test verso unbound + verifica Spamhaus">
                            <i class="fas fa-vial me-1"></i>Test query
                        </button>
                        <button class="btn btn-sm btn-warning d-none" id="btnUbFixAll" onclick="runUbFixAll()">
                            <i class="fas fa-magic me-1"></i>Risolvi tutto
                        </button>
                        <button class="btn btn-sm btn-light" onclick="loadUnboundHealth()">
                            <i class="fas fa-sync me-1"></i>Ricontrolla
                        </button>
                    </div>
                </div>
                <div class="card-body" id="ubContainer">
                    <p class="text-muted mb-0"><i class="fas fa-spinner fa-spin me-1"></i>Diagnosi in corso...</p>
                </div>
                <div class="card-body border-top d-none" id="ubTestResult">
                    <h6 class="mb-2"><i class="fas fa-vial me-1"></i>Risultato Test Query</h6>
                    <pre id="ubTestBody" class="small mb-0" style="white-space:pre-wrap"></pre>
                </div>
                <div class="card-body border-top d-none" id="ubFixAllReport">
                    <h6 class="mb-2"><i class="fas fa-list-check me-1"></i>Report risoluzione</h6>
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
                            <small class="text-muted">IP Bannati Ora</small>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card text-center">
                        <div class="card-body">
                            <h3 class="text-info" id="totalJails">-</h3>
                            <small class="text-muted">Jail Attive</small>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card text-center">
                        <div class="card-body">
                            <h3 class="text-warning" id="totalBannedAll">-</h3>
                            <small class="text-muted">Totale Ban Storici</small>
                        </div>
                    </div>
                </div>
            </div>

            <div class="row">
                <!-- Jails -->
                <div class="col-md-6">
                    <div class="card mb-4">
                        <div class="card-header d-flex justify-content-between align-items-center flex-wrap gap-2">
                            <span><i class="fas fa-lock me-2"></i>Jail Attive <span class="badge bg-secondary ms-1" id="jailsCount">-</span></span>
                            <div class="d-flex align-items-center gap-2">
                                <small class="text-muted d-none d-md-inline"><i class="fas fa-info-circle me-1"></i>Per aggiungere usa "Risolvi tutto"</small>
                                <button class="btn btn-outline-primary btn-sm" id="btnRefreshJails" onclick="refreshJails(true)" title="Aggiorna lista jail">
                                    <i class="fas fa-sync" id="iconRefreshJails"></i>
                                </button>
                            </div>
                        </div>
                        <div class="card-body" id="jailsContainer">
                            <p class="text-muted">Caricamento...</p>
                        </div>
                    </div>

                    <!-- Manual Ban -->
                    <div class="card mb-4">
                        <div class="card-header"><i class="fas fa-ban me-2"></i>Ban Manuale</div>
                        <div class="card-body">
                            <div class="row g-2">
                                <div class="col-5">
                                    <input type="text" class="form-control" id="banIp" placeholder="IP Address">
                                </div>
                                <div class="col-4">
                                    <select class="form-select" id="banJail"></select>
                                </div>
                                <div class="col-3">
                                    <button class="btn btn-danger w-100" onclick="banIp()">Ban</button>
                                </div>
                            </div>
                        </div>
                    </div>

""" + getJailConfigurationCard() + """
                </div>

                <!-- Recent Bans & Banned IPs -->
                <div class="col-md-6">
                    <div class="card mb-4">
                        <div class="card-header"><i class="fas fa-history me-2"></i>Attività Recente</div>
                        <div class="card-body" style="max-height: 300px; overflow-y: auto;" id="recentBans">
                            <p class="text-muted">Caricamento...</p>
                        </div>
                    </div>

                    <div class="card mb-4">
                        <div class="card-header"><i class="fas fa-list me-2"></i>IP Bannati</div>
                        <div class="card-body">
                            <div class="table-responsive" style="max-height: 300px; overflow-y: auto;">
                                <table class="table table-sm" id="bannedTable">
                                    <thead>
                                        <tr>
                                            <th>IP</th>
                                            <th>Jail</th>
                                            <th>Azioni</th>
                                        </tr>
                                    </thead>
                                    <tbody id="bannedBody">
                                        <tr><td colspan="3" class="text-muted">Caricamento...</td></tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>

                    <!-- Permaban list (via pf, independent from Fail2ban) -->
                    <div class="card">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <span><i class="fas fa-ban me-2 text-danger"></i>Permaban (pf)</span>
                            <span class="badge bg-danger" id="permabanCount">0</span>
                        </div>
                        <div class="card-body">
                            <p class="small text-muted mb-2">
                                <i class="fas fa-info-circle me-1"></i>
                                Ban permanenti via pf, sopravvivono al riavvio di Fail2ban, pannello e server.
                                <br>File: <code>/var/db/mail-panel/permaban.list</code>
                            </p>
                            <div class="row g-2 mb-3">
                                <div class="col-8">
                                    <input type="text" id="permabanIpInput" class="form-control form-control-sm" placeholder="IP (es. 1.2.3.4)">
                                </div>
                                <div class="col-4">
                                    <button class="btn btn-danger btn-sm w-100" onclick="permabanAddManual()">
                                        <i class="fas fa-plus me-1"></i>Aggiungi
                                    </button>
                                </div>
                            </div>
                            <div class="table-responsive" style="max-height: 250px; overflow-y: auto;">
                                <table class="table table-sm mb-0">
                                    <thead>
                                        <tr>
                                            <th>IP</th>
                                            <th>Runtime</th>
                                            <th>Azioni</th>
                                        </tr>
                                    </thead>
                                    <tbody id="permabanBody">
                                        <tr><td colspan="3" class="text-muted">Caricamento...</td></tr>
                                    </tbody>
                                </table>
                            </div>
                            <div class="mt-2">
                                <button class="btn btn-outline-secondary btn-sm" onclick="permabanReload()" title="Ricarica la tabella pf dal file (utile se i due sono divergenti)">
                                    <i class="fas fa-sync me-1"></i>Ricarica pf da file
                                </button>
                                <button class="btn btn-outline-secondary btn-sm" onclick="permabanList()" title="Aggiorna lista">
                                    <i class="fas fa-redo me-1"></i>Aggiorna
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Service Controls -->
            <div class="card mt-4">
                <div class="card-header"><i class="fas fa-cogs me-2"></i>Controllo Servizio</div>
                <div class="card-body">
                    <button class="btn btn-success me-2" onclick="serviceAction('start')">
                        <i class="fas fa-play"></i> Avvia
                    </button>
                    <button class="btn btn-danger me-2" onclick="serviceAction('stop')">
                        <i class="fas fa-stop"></i> Ferma
                    </button>
                    <button class="btn btn-warning" onclick="serviceAction('reload')">
                        <i class="fas fa-sync"></i> Ricarica Config
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
                    <h5 class="modal-title">Informazioni IP</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body" id="ipInfo"></div>
            </div>
        </div>
    </div>
""" + getFooter() + """
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
                        badge.textContent = 'Non Installato';
                        return;
                    }
                    badge.className = data.running ? 'badge bg-success me-2' : 'badge bg-warning me-2';
                    badge.textContent = data.running ? 'Attivo' : 'Fermato';

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
                                    <strong>${jail.name}</strong>
                                    <span class="badge bg-danger">${jail.currently_banned} bannati</span>
                                </div>
                                <small class="text-muted">
                                    Falliti: ${jail.currently_failed} | Totale ban: ${jail.total_banned}
                                </small>
                            </div>
                        </div>
                    `).join('') || '<p class="text-muted mb-0">Nessuna jail attiva</p>';
                    document.getElementById('jailsContainer').innerHTML = jailsHtml;

                    // Populate jail select
                    const select = document.getElementById('banJail');
                    select.innerHTML = (data.active_jails || []).map(j => `<option value="${j}">${j}</option>`).join('');

                    // Recent bans
                    const recentHtml = (data.recent_bans || []).map(event => `
                        <div class="ban-event ${event.action}">
                            <i class="fas fa-${event.action === 'ban' ? 'ban text-danger' : 'unlock text-success'}"></i>
                            <span class="ip-badge">${event.ip}</span>
                            <span class="text-muted ms-2">${event.jail}</span>
                            <small class="float-end text-muted">${event.timestamp ? new Date(event.timestamp).toLocaleString('it-IT') : ''}</small>
                        </div>
                    `).join('') || '<p class="text-muted">Nessuna attività recente</p>';
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
                        tbody.innerHTML = '<tr><td colspan="3" class="text-muted text-center">Nessun IP bannato</td></tr>';
                        return;
                    }

                    tbody.innerHTML = data.banned.map(ban => `
                        <tr>
                            <td>
                                <span class="ip-badge">${ban.ip}</span>
                                <button class="btn btn-link btn-sm p-0 ms-1" onclick="showIpInfo('${ban.ip}')" title="Info IP">
                                    <i class="fas fa-info-circle"></i>
                                </button>
                            </td>
                            <td><small>${ban.jail}</small></td>
                            <td class="d-flex gap-1">
                                <button class="btn btn-sm btn-outline-success" onclick="unbanIp('${ban.ip}', '${ban.jail}')" title="Sbanna">
                                    <i class="fas fa-unlock"></i>
                                </button>
                                <button class="btn btn-sm btn-outline-danger" onclick="permabanAdd('${ban.ip}')" title="Ban permanente (via pf, sopravvive a tutto)">
                                    <i class="fas fa-ban"></i>
                                </button>
                            </td>
                        </tr>
                    `).join('');
                });
        }

        function banIp() {
            const ip = document.getElementById('banIp').value.trim();
            const jail = document.getElementById('banJail').value;

            if (!ip) { alert('Inserisci un indirizzo IP'); return; }
            if (!jail) { alert('Seleziona una jail'); return; }

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
            if (!confirm('Sbloccare IP ' + ip + '?')) return;

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
            document.getElementById('ipInfo').innerHTML = '<p><i class="fas fa-spinner fa-spin me-1"></i>Caricamento...</p>';
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
                    if (country) html += `<tr><td><strong>Paese</strong></td><td>${country}</td></tr>`;
                    if (data.region) html += `<tr><td><strong>Regione</strong></td><td>${escapeHtml(data.region)}</td></tr>`;
                    if (data.city) html += `<tr><td><strong>Città</strong></td><td>${escapeHtml(data.city)}</td></tr>`;

                    // Rete / Provider
                    if (data.isp) html += `<tr><td><strong>ISP</strong></td><td>${escapeHtml(data.isp)}</td></tr>`;
                    if (data.asn) html += `<tr><td><strong>ASN</strong></td><td><code>${escapeHtml(data.asn)}</code></td></tr>`;
                    if (data.organization) html += `<tr><td><strong>Organizzazione</strong></td><td>${escapeHtml(data.organization)}</td></tr>`;
                    if (data.net_range) html += `<tr><td><strong>Network range</strong></td><td><code>${escapeHtml(data.net_range)}</code></td></tr>`;

                    html += '</tbody></table>';

                    // Mappa (se abbiamo coordinate)
                    if (data.latitude != null && data.longitude != null) {
                        const lat = data.latitude;
                        const lon = data.longitude;
                        const mapsUrl = `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=8/${lat}/${lon}`;
                        html += `<div class="mb-2"><small class="text-muted">Coord: <code>${lat}, ${lon}</code></small> `;
                        html += `<a href="${mapsUrl}" target="_blank" rel="noopener" class="btn btn-outline-primary btn-sm ms-2"><i class="fas fa-map-marker-alt me-1"></i>Apri su mappa</a></div>`;
                    }

                    if (data.geo_source) {
                        html += `<div class="text-muted small"><i class="fas fa-info-circle me-1"></i>Fonte: ${escapeHtml(data.geo_source)}</div>`;
                    }
                    if (!data.success) {
                        html += `<div class="alert alert-warning mt-2 mb-0 py-2"><i class="fas fa-exclamation-triangle me-1"></i>Whois non disponibile per questo IP — i dati provengono solo da GeoIP (se presenti).</div>`;
                    }

                    document.getElementById('ipInfo').innerHTML = html;
                })
                .catch(e => {
                    document.getElementById('ipInfo').innerHTML = '<div class="alert alert-danger">Errore: ' + e.message + '</div>';
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
            if (!confirm('Installare le jail per i servizi mail (Dovecot, Postfix, Roundcube, Rspamd)?')) return;

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

        // ===== Fail2ban Health Check / Setup Wizard =====
        let fhcCsrfToken = null;

        function ensureFhcCsrfToken() {
            // riusa csrf token globale se esiste, altrimenti chiama un endpoint dedicato
            // (qui assumiamo esista document.getElementById('csrf_token'))
            try {
                const el = document.getElementById('csrf_token');
                if (el && el.value) return el.value;
            } catch (e) {}
            return fhcCsrfToken || '';
        }

        // ===== Postfix Aliases =====
        function paliasEscape(s) {
            const d = document.createElement('div');
            d.textContent = s == null ? '' : String(s);
            return d.innerHTML;
        }

        // ===== Stato live jail Fail2ban =====
        // Stampa per ogni jail attiva l'output di:
        //   fail2ban-client get <jail> maxretry/findtime/bantime/logpath/filter/ignoreip
        //   fail2ban-client status <jail>
        // così l'utente vede SUBITO se la config è quella che ha impostato.
        function loadJailLiveState() {
            const body = document.getElementById('jailLiveBody');
            body.innerHTML = '<p class="text-muted small mb-0 p-2"><i class="fas fa-spinner fa-spin me-1"></i>Esecuzione di fail2ban-client su tutte le jail attive...</p>';
            fetch('/api/fail2ban?action=live_state_all').then(r => r.json()).then(data => {
                if (!data.success) {
                    body.innerHTML = '<div class="alert alert-danger m-2 mb-0">Errore: ' + paliasEscape(data.error || 'sconosciuto') + '</div>';
                    return;
                }
                if (!data.installed) {
                    body.innerHTML = '<div class="alert alert-warning m-2 mb-0">Fail2ban non risulta installato sul sistema.</div>';
                    return;
                }
                if (!data.running) {
                    body.innerHTML = '<div class="alert alert-warning m-2 mb-0">Fail2ban è installato ma NON in esecuzione. Avvialo con <code>service fail2ban start</code>.</div>';
                    return;
                }
                const jails = data.jails || [];
                if (jails.length === 0) {
                    body.innerHTML = '<div class="alert alert-info m-2 mb-0">Nessuna jail attiva.</div>';
                    return;
                }
                let html = '<div class="p-2">';
                jails.forEach(j => {
                    html += renderJailLiveCard(j);
                });
                html += '</div>';
                body.innerHTML = html;
            }).catch(e => {
                body.innerHTML = '<div class="alert alert-danger m-2 mb-0">Errore rete: ' + paliasEscape(e.message) + '</div>';
            });
        }

        function renderJailLiveCard(j) {
            const name = j.name || '?';
            // Tag colorato per "currently banned": 0 = grigio, >0 = giallo
            const cbBadge = j.currently_banned > 0
                ? '<span class="badge bg-warning text-dark ms-1">' + j.currently_banned + ' bannati ora</span>'
                : '<span class="badge bg-light text-dark ms-1">0 bannati ora</span>';
            const tbBadge = j.total_banned > 0
                ? '<span class="badge bg-secondary ms-1">' + j.total_banned + ' tot</span>'
                : '';

            let html = '<div class="card mb-3"><div class="card-header py-1 px-2 d-flex justify-content-between align-items-center bg-light">';
            html += '<div><strong><code>' + paliasEscape(name) + '</code></strong>' + cbBadge + tbBadge + '</div>';
            html += '<button class="btn btn-sm btn-link p-0" onclick="this.parentElement.parentElement.parentElement.querySelector(\\'.jail-raw-' + paliasEscape(name) + '\\').classList.toggle(\\'d-none\\')"><i class="fas fa-terminal me-1"></i>raw</button>';
            html += '</div>';
            html += '<div class="card-body p-2 small">';
            html += '<table class="table table-sm table-borderless mb-2"><tbody>';
            html += renderJailGetRow('maxretry',  j.maxretry,  'numero di fallimenti che fa scattare il ban');
            html += renderJailGetRow('findtime',  j.findtime,  'finestra (in secondi) dentro cui si contano i fallimenti', true);
            html += renderJailGetRow('bantime',   j.bantime,   'durata del ban (in secondi, -1 = permanente)', true);
            html += renderJailGetRow('logpath',   j.logpath,   'file di log monitorati');
            html += renderJailGetRow('filter',    j.filter,    'filtro Fail2ban usato per matchare le righe');
            html += renderJailGetRow('ignoreip',  j.ignoreip,  'IP/range mai bannati (whitelist)');
            html += '</tbody></table>';

            // Status counters parsati
            html += '<div class="row g-2 mb-2">';
            html += '<div class="col-md-3"><div class="border rounded p-1 text-center"><div class="text-muted small">Currently failed</div><strong class="fs-5">' + j.currently_failed + '</strong></div></div>';
            html += '<div class="col-md-3"><div class="border rounded p-1 text-center"><div class="text-muted small">Total failed</div><strong class="fs-5">' + j.total_failed + '</strong></div></div>';
            html += '<div class="col-md-3"><div class="border rounded p-1 text-center"><div class="text-muted small">Currently banned</div><strong class="fs-5">' + j.currently_banned + '</strong></div></div>';
            html += '<div class="col-md-3"><div class="border rounded p-1 text-center"><div class="text-muted small">Total banned</div><strong class="fs-5">' + j.total_banned + '</strong></div></div>';
            html += '</div>';

            if (j.banned_ips_raw) {
                html += '<div class="mb-2"><strong class="small">Banned IP list:</strong> <code class="small" style="word-break:break-all">' + paliasEscape(j.banned_ips_raw) + '</code></div>';
            }

            // Output RAW del comando "fail2ban-client status <jail>" — chiuso di default
            html += '<div class="jail-raw-' + paliasEscape(name) + ' d-none">';
            html += '<div class="small text-muted mb-1"><i class="fas fa-terminal me-1"></i>Output di <code>fail2ban-client status ' + paliasEscape(name) + '</code></div>';
            html += '<pre class="bg-dark text-light p-2 small rounded mb-0" style="font-size:0.75rem;white-space:pre-wrap">' + paliasEscape(j.status_raw || '') + '</pre>';
            html += '</div>';

            html += '</div></div>';
            return html;
        }

        function renderJailGetRow(key, value, descr, isSeconds) {
            let display = paliasEscape(value || '');
            // Se è in secondi, mostra anche la conversione umana
            if (isSeconds && /^-?\\d+$/.test((value || '').trim())) {
                const n = parseInt(value, 10);
                if (n === -1) {
                    display += ' <span class="text-muted">(permanente)</span>';
                } else if (n > 0) {
                    let human;
                    if (n >= 86400) human = (n / 86400).toFixed(1).replace(/\\.0$/, '') + ' giorni';
                    else if (n >= 3600) human = (n / 3600).toFixed(1).replace(/\\.0$/, '') + ' ore';
                    else if (n >= 60) human = (n / 60).toFixed(1).replace(/\\.0$/, '') + ' min';
                    else human = n + ' s';
                    display += ' <span class="text-muted">(' + human + ')</span>';
                }
            }
            return '<tr>' +
                '<td style="width:130px;vertical-align:top"><code class="text-primary">' + key + '</code></td>' +
                '<td><strong>' + display + '</strong>' + (descr ? '<br><small class="text-muted">' + descr + '</small>' : '') + '</td>' +
                '</tr>';
        }

        function paliasLoad() {
            const body = document.getElementById('paliasBody');
            const badge = document.getElementById('paliasOverallBadge');
            const fixBtn = document.getElementById('paliasFixBtn');
            body.innerHTML = '<p class="text-muted mb-0"><i class="fas fa-spinner fa-spin me-1"></i>Caricamento...</p>';
            badge.innerHTML = '';
            fixBtn.classList.add('d-none');

            fetch('/api/postfix-aliases-health').then(r => r.json()).then(data => {
                if (!data.success) {
                    body.innerHTML = '<div class="alert alert-danger mb-0">Errore: ' + paliasEscape(data.error || 'sconosciuto') + '</div>';
                    badge.innerHTML = '<span class="badge bg-danger">Errore</span>';
                    return;
                }
                paliasRender(data);
            }).catch(e => {
                body.innerHTML = '<div class="alert alert-danger mb-0">Errore rete: ' + paliasEscape(e.message) + '</div>';
            });
        }

        function paliasRender(data) {
            const body = document.getElementById('paliasBody');
            const badge = document.getElementById('paliasOverallBadge');
            const fixBtn = document.getElementById('paliasFixBtn');
            const overall = data.overall || 'UNKNOWN';

            // Badge nell'header
            if (overall === 'OK') {
                badge.innerHTML = '<span class="badge bg-success"><i class="fas fa-check-circle me-1"></i>OK</span>';
                fixBtn.classList.add('d-none');
            } else if (overall === 'MISSING_SOURCE') {
                badge.innerHTML = '<span class="badge bg-danger"><i class="fas fa-times-circle me-1"></i>File aliases mancante</span>';
                fixBtn.classList.remove('d-none');
            } else if (overall === 'MISSING_DB') {
                badge.innerHTML = '<span class="badge bg-warning text-dark"><i class="fas fa-exclamation-triangle me-1"></i>aliases.db mancante</span>';
                fixBtn.classList.remove('d-none');
            } else if (overall === 'STALE_DB') {
                badge.innerHTML = '<span class="badge bg-warning text-dark"><i class="fas fa-clock me-1"></i>aliases.db obsoleto</span>';
                fixBtn.classList.remove('d-none');
            } else {
                badge.innerHTML = '<span class="badge bg-secondary">?</span>';
            }

            // Tabella stato
            let html = '';
            if (overall !== 'OK') {
                html += '<div class="alert alert-warning small"><i class="fas fa-exclamation-triangle me-1"></i>' + paliasEscape(data.summary || '') + ' Clicca <strong>Risolvi</strong> per riparare automaticamente.</div>';
            } else {
                html += '<div class="alert alert-success small mb-2"><i class="fas fa-check-circle me-1"></i>' + paliasEscape(data.summary || 'OK') + '</div>';
            }
            html += '<table class="table table-sm align-middle mb-0">';
            html += '<tr><td class="fw-bold" style="width:30%">File sorgente</td><td><code>' + paliasEscape(data.alias_file || '?') + '</code> ' + (data.source_exists ? '<span class="badge bg-success">esiste</span>' : '<span class="badge bg-danger">mancante</span>') + '</td></tr>';
            html += '<tr><td class="fw-bold">File compilato (.db)</td><td><code>' + paliasEscape(data.alias_db_file || '?') + '</code> ' + (data.db_exists ? '<span class="badge bg-success">esiste</span>' : '<span class="badge bg-danger">mancante</span>') + (data.db_stale_vs_source ? ' <span class="badge bg-warning text-dark">obsoleto</span>' : '') + '</td></tr>';
            if (data.alias_database_raw) {
                html += '<tr><td class="fw-bold">alias_database (postconf)</td><td><code>' + paliasEscape(data.alias_database_raw) + '</code></td></tr>';
            }
            if (data.alias_maps_raw) {
                html += '<tr><td class="fw-bold">alias_maps (postconf)</td><td><code>' + paliasEscape(data.alias_maps_raw) + '</code></td></tr>';
            }
            if (data.root_forward) {
                html += '<tr><td class="fw-bold">root inoltrato a</td><td><code>' + paliasEscape(data.root_forward) + '</code></td></tr>';
            }
            html += '</table>';
            body.innerHTML = html;

            // Pre-compila il campo "root forward" se disponibile
            const fwInput = document.getElementById('paliasRootForward');
            if (fwInput && data.root_forward) fwInput.value = data.root_forward;
        }

        function paliasFix() {
            if (!confirm('Procedere con la riparazione automatica?\\n\\n• Se manca il file sorgente, viene creato con default sicuri.\\n• Il file .db viene ricompilato con postalias.\\n• Postfix viene ricaricato.\\n\\nOperazione non distruttiva (rispetta contenuto esistente).')) return;
            const fixBtn = document.getElementById('paliasFixBtn');
            const origBtn = fixBtn.innerHTML;
            fixBtn.disabled = true;
            fixBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Risoluzione...';
            const logEl = document.getElementById('paliasLog');
            logEl.innerHTML = '';
            fetch('/api/postfix-aliases-health', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'fix', csrf_token: csrfToken })
            })
            .then(r => r.json())
            .then(data => {
                fixBtn.disabled = false;
                fixBtn.innerHTML = origBtn;
                let html = '<div class="alert alert-' + (data.success ? 'success' : 'danger') + ' py-2 mb-2"><i class="fas fa-' + (data.success ? 'check' : 'times') + '-circle me-1"></i>' + paliasEscape(data.message || '') + '</div>';
                if (data.log) {
                    html += '<pre class="bg-light p-2 rounded small mb-0" style="white-space:pre-wrap">' + paliasEscape(data.log) + '</pre>';
                }
                logEl.innerHTML = html;
                paliasRender(data);
            })
            .catch(e => {
                fixBtn.disabled = false;
                fixBtn.innerHTML = origBtn;
                logEl.innerHTML = '<div class="alert alert-danger py-2 mb-0">Errore rete: ' + paliasEscape(e.message) + '</div>';
            });
        }

        function paliasSetRootForward() {
            const v = document.getElementById('paliasRootForward').value.trim();
            if (!v) { alert('Inserisci un indirizzo email o "root".'); return; }
            if (!confirm('Impostare il forward delle mail di root su:\\n\\n  ' + v + '\\n\\nDopo il salvataggio, root, postmaster, mailer-daemon e gli alias di sistema invieranno qui le notifiche.')) return;
            const logEl = document.getElementById('paliasLog');
            logEl.innerHTML = '<div class="text-muted small"><i class="fas fa-spinner fa-spin me-1"></i>Salvataggio...</div>';
            fetch('/api/postfix-aliases-health', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'set_root_forward', forward_to: v, csrf_token: csrfToken })
            })
            .then(r => r.json())
            .then(data => {
                let html = '<div class="alert alert-' + (data.success ? 'success' : 'danger') + ' py-2 mb-2"><i class="fas fa-' + (data.success ? 'check' : 'times') + '-circle me-1"></i>' + paliasEscape(data.message || '') + '</div>';
                if (data.log) {
                    html += '<pre class="bg-light p-2 rounded small mb-0" style="white-space:pre-wrap">' + paliasEscape(data.log) + '</pre>';
                }
                logEl.innerHTML = html;
                paliasRender(data);
            })
            .catch(e => {
                logEl.innerHTML = '<div class="alert alert-danger py-2 mb-0">Errore rete: ' + paliasEscape(e.message) + '</div>';
            });
        }

        function loadFail2banHealth() {
            const c = document.getElementById('fhcContainer');
            const overall = document.getElementById('fhcOverallStatus');
            const btnFixAll = document.getElementById('btnFixAll');
            c.innerHTML = '<p class="text-muted mb-0"><i class="fas fa-spinner fa-spin me-1"></i>Diagnosi in corso...</p>';
            fetch('/api/fail2ban_health', { method: 'GET' })
                .then(r => r.json())
                .then(data => {
                    if (!data.success) {
                        c.innerHTML = '<div class="alert alert-danger mb-0">Errore: ' + (data.error || 'sconosciuto') + '</div>';
                        return;
                    }
                    if (data.all_ok) {
                        overall.innerHTML = '<span class="badge bg-success">Tutto OK</span>';
                        if (btnFixAll) btnFixAll.classList.add('d-none');
                    } else {
                        overall.innerHTML = '<span class="badge bg-warning text-dark">Azione richiesta</span>';
                        if (btnFixAll) btnFixAll.classList.remove('d-none');
                    }
                    let html = '<div class="list-group list-group-flush">';
                    (data.checks || []).forEach((chk, idx) => {
                        const icon = chk.ok
                            ? '<i class="fas fa-check-circle text-success"></i>'
                            : '<i class="fas fa-times-circle text-danger"></i>';
                        html += '<div class="list-group-item">';
                        html += '<div class="d-flex justify-content-between align-items-start gap-3 flex-wrap">';
                        html += '<div class="flex-grow-1">';
                        html += '<div><strong>' + icon + ' ' + escapeHtml(chk.label) + '</strong></div>';
                        html += '<div class="small text-muted">' + escapeHtml(chk.status || '') + '</div>';
                        if (!chk.ok && chk.impact) {
                            html += '<div class="small text-danger mt-1"><i class="fas fa-exclamation-triangle me-1"></i>Se non lo risolvi: ' + escapeHtml(chk.impact) + '</div>';
                        }
                        if (!chk.ok && chk.fix_description) {
                            html += '<div class="small text-info mt-1"><i class="fas fa-magic me-1"></i>' + escapeHtml(chk.fix_description) + '</div>';
                        }
                        html += '</div>';
                        if (!chk.ok && chk.fix_action) {
                            html += '<button class="btn btn-warning btn-sm" onclick="runFhcFix(\\'' + chk.fix_action + '\\', this)">';
                            html += '<i class="fas fa-wrench me-1"></i>Risolvi';
                            html += '</button>';
                        }
                        html += '</div>';
                        html += '</div>';
                    });
                    html += '</div>';
                    if (data.all_ok) {
                        html += '<div class="alert alert-success mb-0 mt-3 py-2"><i class="fas fa-shield-alt me-2"></i>Configurazione completa e operativa. Nessuna azione necessaria.</div>';
                    }
                    c.innerHTML = html;
                })
                .catch(e => {
                    c.innerHTML = '<div class="alert alert-danger mb-0">Errore rete: ' + e.message + '</div>';
                });
        }

        function runFhcFixAll() {
            const confirmMsg = '🪄 RISOLVI TUTTO — esegue in ordine corretto:\\n\\n' +
                '1. Installa Fail2ban (se manca)\\n' +
                '2. Abilita Fail2ban al boot\\n' +
                '3. Configura jail mail-panel-auth\\n' +
                '4. Configura jail Postfix/Dovecot/Roundcube/Rspamd\\n' +
                '5. Crea /etc/pf.conf minimo (se manca)\\n' +
                '6. Aggiunge anchor f2b a pf.conf\\n' +
                '7. Abilita pf al boot\\n' +
                '8. Avvia pf (con syntax check pre-flight)\\n' +
                '9. Avvia Fail2ban\\n\\n' +
                '⚠️ Tocca anche pf (firewall): se hai una pf.conf custom strana c\\'è rischio teorico di lockout, ma il pannello fa backup automatico e syntax check prima di applicare.\\n\\n' +
                'Avere accesso fisico/console al server è raccomandato.\\n\\n' +
                'Procedo?';
            if (!confirm(confirmMsg)) return;

            const btn = document.getElementById('btnFixAll');
            const original = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>In corso...';

            fetch('/api/fail2ban_health', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'fix_all', csrf_token: ensureFhcCsrfToken() })
            }).then(r => r.json()).then(data => {
                btn.disabled = false;
                btn.innerHTML = original;

                // Render report passo-passo
                const report = document.getElementById('fhcFixAllReport');
                const stepsEl = document.getElementById('fhcFixAllSteps');
                let html = '';
                (data.steps || []).forEach(s => {
                    let icon, badge;
                    if (s.status === 'skipped') {
                        icon = '<i class="fas fa-forward text-secondary"></i>';
                        badge = '<span class="badge bg-secondary">SKIP</span>';
                    } else if (s.success) {
                        icon = '<i class="fas fa-check-circle text-success"></i>';
                        badge = '<span class="badge bg-success">OK</span>';
                    } else {
                        icon = '<i class="fas fa-times-circle text-danger"></i>';
                        badge = '<span class="badge bg-danger">FAIL</span>';
                    }
                    html += '<div class="d-flex align-items-start gap-2 mb-2">' + icon +
                        '<div class="flex-grow-1"><div>' + badge + ' <strong>' + escapeHtml(s.label) + '</strong></div>';
                    if (s.message) html += '<div class="small text-muted">' + escapeHtml(s.message) + '</div>';
                    if (s.output && s.output.length > 0) html += '<details class="small mt-1"><summary>Output</summary><pre class="mb-0 mt-1" style="font-size:0.75rem;max-height:200px;overflow:auto">' + escapeHtml(s.output) + '</pre></details>';
                    html += '</div></div>';
                });
                stepsEl.innerHTML = html;
                report.classList.remove('d-none');

                // Riricarica lo stato
                loadFail2banHealth();
                loadStatus();
            }).catch(e => {
                btn.disabled = false;
                btn.innerHTML = original;
                alert('Errore rete: ' + e.message);
            });
        }

        function runFhcFix(action, btn) {
            // Warning rafforzato per le azioni pf (rischio lockout SSH)
            const pfActions = { 'start_pf': true, 'enable_pf_at_boot': true, 'add_pf_anchor': true };
            let confirmMsg = 'Applicare la correzione automatica?\\n\\nIl pannello eseguirà le operazioni necessarie sul sistema.';
            if (pfActions[action]) {
                confirmMsg = 'ATTENZIONE — operazione su pf (firewall di sistema)\\n\\n' +
                    'Stai per modificare/avviare il firewall del server.\\n\\n' +
                    'RISCHIO: una configurazione pf errata può chiudere completamente l\\'accesso al server, INCLUSO SSH e questo pannello.\\n\\n' +
                    'Il pannello fa controlli di sintassi e backup automatico, ma il rischio NON è zero.\\n\\n' +
                    'Prima di confermare, verifica di avere accesso fisico/console al server (KVM, IPMI, console seriale) per recuperare in caso di problemi.\\n\\n' +
                    'Vuoi procedere?';
            }
            if (!confirm(confirmMsg)) return;
            const original = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>In corso...';
            fetch('/api/fail2ban_health', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action: action,
                    csrf_token: ensureFhcCsrfToken()
                })
            }).then(r => r.json()).then(data => {
                btn.disabled = false;
                btn.innerHTML = original;
                if (data.success) {
                    // ricarica la diagnosi
                    loadFail2banHealth();
                    loadStatus();
                } else {
                    alert('Errore: ' + (data.message || data.error || 'sconosciuto') +
                        (data.output ? '\\n\\nOutput:\\n' + data.output : ''));
                    loadFail2banHealth();
                }
            }).catch(e => {
                btn.disabled = false;
                btn.innerHTML = original;
                alert('Errore rete: ' + e.message);
            });
        }

        // Helper escapeHtml (se non già definita altrove nella pagina)
        if (typeof escapeHtml !== 'function') {
            window.escapeHtml = function(text) {
                const div = document.createElement('div');
                div.textContent = text == null ? '' : String(text);
                return div.innerHTML;
            };
        }

        // Reload morbido (fail2ban-client reload): rilegge i file senza killare il daemon
        function reloadFail2banFromPanel() {
            if (!confirm('Eseguire RELOAD di fail2ban?\\n\\nRilegge i file di configurazione senza killare il daemon. Conserva i contatori e gli IP bannati attivi.')) return;
            fetch('/api/fail2ban_health', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'reload_fail2ban', csrf_token: ensureFhcCsrfToken() })
            }).then(r => r.json()).then(data => {
                alert((data.success ? '✅ ' : '❌ ') + (data.message || 'fatto') +
                    (data.output ? '\\n\\nOutput:\\n' + data.output : ''));
                loadFail2banHealth();
                if (typeof loadJailLiveState === 'function') loadJailLiveState();
            }).catch(e => alert('Errore rete: ' + e.message));
        }

        // Restart pulito (service fail2ban restart): killa il daemon e lo riavvia
        function restartFail2banFromPanel() {
            if (!confirm('⚠️ RESTART di fail2ban (service fail2ban restart)\\n\\n' +
                'Killa il daemon e lo riavvia da zero. Utile per uscire da stati confusi (es. dopo molti reload).\\n\\n' +
                'COSA SUCCEDE:\\n' +
                '• I contatori "Currently failed" e "Total failed" si AZZERANO\\n' +
                '• Gli IP attualmente bannati a runtime si PERDONO (ma i permaban su pf restano!)\\n' +
                '• La config in jail.local viene RILETTA da zero\\n' +
                '• Pochi secondi di interruzione del monitoring\\n\\n' +
                'Procedere?')) return;
            fetch('/api/fail2ban_health', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'restart_service', csrf_token: ensureFhcCsrfToken() })
            }).then(r => r.json()).then(data => {
                alert((data.success ? '✅ ' : '❌ ') + (data.message || 'fatto') +
                    (data.output ? '\\n\\nOutput:\\n' + data.output : ''));
                loadFail2banHealth();
                if (typeof loadJailLiveState === 'function') loadJailLiveState();
            }).catch(e => alert('Errore rete: ' + e.message));
        }

        // ===== End Health Check =====
""";
        String jsPart2 = """

        // ===== Unbound (Resolver DNS locale) Health Check =====
        function loadUnboundHealth() {
            const c = document.getElementById('ubContainer');
            const overall = document.getElementById('ubOverallStatus');
            const btnFixAll = document.getElementById('btnUbFixAll');
            c.innerHTML = '<p class="text-muted mb-0"><i class="fas fa-spinner fa-spin me-1"></i>Diagnosi in corso...</p>';
            fetch('/api/unbound_health', { method: 'GET' }).then(r => r.json()).then(data => {
                if (!data.success) {
                    c.innerHTML = '<div class="alert alert-danger mb-0">Errore: ' + (data.error || 'sconosciuto') + '</div>';
                    return;
                }
                if (data.all_ok) {
                    overall.innerHTML = '<span class="badge bg-success">Tutto OK</span>';
                    if (btnFixAll) btnFixAll.classList.add('d-none');
                } else {
                    overall.innerHTML = '<span class="badge bg-warning text-dark">Azione richiesta</span>';
                    if (btnFixAll) btnFixAll.classList.remove('d-none');
                }
                let html = '<div class="list-group list-group-flush">';
                (data.checks || []).forEach(chk => {
                    const icon = chk.ok ? '<i class="fas fa-check-circle text-success"></i>' : '<i class="fas fa-times-circle text-danger"></i>';
                    html += '<div class="list-group-item">';
                    html += '<div class="d-flex justify-content-between align-items-start gap-3 flex-wrap">';
                    html += '<div class="flex-grow-1">';
                    html += '<div><strong>' + icon + ' ' + escapeHtmlUb(chk.label) + '</strong></div>';
                    html += '<div class="small text-muted">' + escapeHtmlUb(chk.status || '') + '</div>';
                    if (!chk.ok && chk.impact) html += '<div class="small text-danger mt-1"><i class="fas fa-exclamation-triangle me-1"></i>Se non lo risolvi: ' + escapeHtmlUb(chk.impact) + '</div>';
                    if (!chk.ok && chk.fix_description) html += '<div class="small text-info mt-1"><i class="fas fa-magic me-1"></i>' + escapeHtmlUb(chk.fix_description) + '</div>';
                    html += '</div>';
                    if (!chk.ok && chk.fix_action) {
                        html += '<button class="btn btn-warning btn-sm" onclick="runUbFix(\\'' + chk.fix_action + '\\', this)">';
                        html += '<i class="fas fa-wrench me-1"></i>Risolvi';
                        html += '</button>';
                    }
                    html += '</div></div>';
                });
                html += '</div>';
                if (data.all_ok) html += '<div class="alert alert-success mb-0 mt-3 py-2"><i class="fas fa-shield-alt me-2"></i>Resolver locale operativo. Le query DNSBL (Spamhaus, ecc.) ora vengono risolte correttamente.</div>';
                c.innerHTML = html;
            }).catch(e => {
                c.innerHTML = '<div class="alert alert-danger mb-0">Errore rete: ' + e.message + '</div>';
            });
        }

        function runUbFix(action, btn) {
            const warning = (action === 'switch_resolv_conf')
                ? '\\n\\n⚠️ Questo passo modifica /etc/resolv.conf. Il pannello fa pre-flight test e rollback automatico se qualcosa va storto, ma è raccomandato avere accesso console al server come backup.'
                : '';
            if (!confirm('Applicare la correzione?' + warning)) return;
            const original = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>In corso...';
            fetch('/api/unbound_health', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: action, csrf_token: document.getElementById('csrf_token').value })
            }).then(r => r.json()).then(data => {
                btn.disabled = false;
                btn.innerHTML = original;
                if (data.success) loadUnboundHealth();
                else alert('Errore: ' + (data.message || data.error || 'sconosciuto') + (data.output ? '\\n\\n' + data.output : ''));
                loadUnboundHealth();
            }).catch(e => {
                btn.disabled = false;
                btn.innerHTML = original;
                alert('Errore rete: ' + e.message);
            });
        }

        function runUbFixAll() {
            const msg = '🪄 Risolvi tutto unbound — esegue in ordine:\\n' +
                '1. Installa unbound (se manca)\\n' +
                '2. Scrive config sicura (solo loopback)\\n' +
                '3. Abilita al boot\\n' +
                '4. Avvia il servizio\\n' +
                '5. Switcha /etc/resolv.conf su 127.0.0.1\\n\\n' +
                'Step 5 ha PRE-FLIGHT test + AUTO-ROLLBACK in caso di problemi.\\n' +
                'Però è sempre raccomandato avere accesso console al server.\\n\\n' +
                'Procedo?';
            if (!confirm(msg)) return;

            const btn = document.getElementById('btnUbFixAll');
            const original = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>In corso (può richiedere 1-2 min)...';

            fetch('/api/unbound_health', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'fix_all', csrf_token: document.getElementById('csrf_token').value })
            }).then(r => r.json()).then(data => {
                btn.disabled = false;
                btn.innerHTML = original;
                const report = document.getElementById('ubFixAllReport');
                const stepsEl = document.getElementById('ubFixAllSteps');
                let html = '';
                (data.steps || []).forEach(s => {
                    let icon, badge;
                    if (s.status === 'skipped') { icon = '<i class="fas fa-forward text-secondary"></i>'; badge = '<span class="badge bg-secondary">SKIP</span>'; }
                    else if (s.success) { icon = '<i class="fas fa-check-circle text-success"></i>'; badge = '<span class="badge bg-success">OK</span>'; }
                    else { icon = '<i class="fas fa-times-circle text-danger"></i>'; badge = '<span class="badge bg-danger">FAIL</span>'; }
                    html += '<div class="d-flex align-items-start gap-2 mb-2">' + icon +
                        '<div class="flex-grow-1"><div>' + badge + ' <strong>' + escapeHtmlUb(s.label) + '</strong></div>';
                    if (s.message) html += '<div class="small text-muted">' + escapeHtmlUb(s.message) + '</div>';
                    if (s.output && s.output.length > 0) html += '<details class="small mt-1"><summary>Output</summary><pre class="mb-0 mt-1" style="font-size:0.75rem;max-height:200px;overflow:auto">' + escapeHtmlUb(s.output) + '</pre></details>';
                    html += '</div></div>';
                });
                stepsEl.innerHTML = html;
                report.classList.remove('d-none');
                loadUnboundHealth();
            }).catch(e => {
                btn.disabled = false;
                btn.innerHTML = original;
                alert('Errore rete: ' + e.message);
            });
        }

        function runUbTestQuery() {
            const btn = document.getElementById('btnUbTestQuery');
            const original = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Test...';
            fetch('/api/unbound_health', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'test_query', csrf_token: document.getElementById('csrf_token').value })
            }).then(r => r.json()).then(data => {
                btn.disabled = false;
                btn.innerHTML = original;
                const resultEl = document.getElementById('ubTestResult');
                const bodyEl = document.getElementById('ubTestBody');
                bodyEl.textContent = data.message || JSON.stringify(data);
                bodyEl.className = 'small mb-0' + (data.success ? ' text-success' : ' text-warning');
                resultEl.classList.remove('d-none');
            }).catch(e => {
                btn.disabled = false;
                btn.innerHTML = original;
                alert('Errore rete: ' + e.message);
            });
        }

        function escapeHtmlUb(s) {
            const d = document.createElement('div');
            d.textContent = s == null ? '' : String(s);
            return d.innerHTML;
        }

        // ===== ClamAV Health Check =====
        function loadClamavHealth() {
            const c = document.getElementById('cavContainer');
            const overall = document.getElementById('cavOverallStatus');
            const btnFixAll = document.getElementById('btnCavFixAll');
            c.innerHTML = '<p class="text-muted mb-0"><i class="fas fa-spinner fa-spin me-1"></i>Diagnosi in corso...</p>';
            fetch('/api/clamav_health', { method: 'GET' })
                .then(r => r.json())
                .then(data => {
                    if (!data.success) {
                        c.innerHTML = '<div class="alert alert-danger mb-0">Errore: ' + (data.error || 'sconosciuto') + '</div>';
                        return;
                    }
                    if (data.all_ok) {
                        overall.innerHTML = '<span class="badge bg-success">Tutto OK</span>';
                        if (btnFixAll) btnFixAll.classList.add('d-none');
                    } else {
                        overall.innerHTML = '<span class="badge bg-warning text-dark">Azione richiesta</span>';
                        if (btnFixAll) btnFixAll.classList.remove('d-none');
                    }
                    let html = '<div class="list-group list-group-flush">';
                    (data.checks || []).forEach(chk => {
                        const icon = chk.ok ? '<i class="fas fa-check-circle text-success"></i>' : '<i class="fas fa-times-circle text-danger"></i>';
                        html += '<div class="list-group-item">';
                        html += '<div class="d-flex justify-content-between align-items-start gap-3 flex-wrap">';
                        html += '<div class="flex-grow-1">';
                        html += '<div><strong>' + icon + ' ' + escapeHtmlCav(chk.label) + '</strong></div>';
                        html += '<div class="small text-muted">' + escapeHtmlCav(chk.status || '') + '</div>';
                        if (!chk.ok && chk.impact) html += '<div class="small text-danger mt-1"><i class="fas fa-exclamation-triangle me-1"></i>Se non lo risolvi: ' + escapeHtmlCav(chk.impact) + '</div>';
                        if (!chk.ok && chk.fix_description) html += '<div class="small text-info mt-1"><i class="fas fa-magic me-1"></i>' + escapeHtmlCav(chk.fix_description) + '</div>';
                        html += '</div>';
                        if (!chk.ok && chk.fix_action) {
                            html += '<button class="btn btn-warning btn-sm" onclick="runCavFix(\\'' + chk.fix_action + '\\', this)">';
                            html += '<i class="fas fa-wrench me-1"></i>Risolvi';
                            html += '</button>';
                        }
                        html += '</div></div>';
                    });
                    html += '</div>';
                    if (data.all_ok) html += '<div class="alert alert-success mb-0 mt-3 py-2"><i class="fas fa-virus-slash me-2"></i>ClamAV operativo, Rspamd lo chiama, tutte le mail vengono scansionate.</div>';
                    c.innerHTML = html;
                })
                .catch(e => {
                    c.innerHTML = '<div class="alert alert-danger mb-0">Errore rete: ' + e.message + '</div>';
                });
        }

        function runCavFix(action, btn) {
            if (!confirm('Applicare la correzione automatica?')) return;
            const original = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>In corso (alcune operazioni richiedono minuti)...';
            fetch('/api/clamav_health', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: action, csrf_token: document.getElementById('csrf_token').value })
            }).then(r => r.json()).then(data => {
                btn.disabled = false;
                btn.innerHTML = original;
                if (data.success) loadClamavHealth();
                else alert('Errore: ' + (data.message || data.error || 'sconosciuto') + (data.output ? '\\n\\n' + data.output : ''));
                loadClamavHealth();
            }).catch(e => {
                btn.disabled = false;
                btn.innerHTML = original;
                alert('Errore rete: ' + e.message);
            });
        }

        function runCavFixAll() {
            if (!confirm('Risolvi tutto ClamAV — esegue in ordine:\\n' +
                '1. Installa ClamAV (se manca)\\n' +
                '2. Abilita freshclam e clamd al boot\\n' +
                '3. Scarica database virus (può richiedere 2-5 min)\\n' +
                '4. Avvia freshclam e clamd\\n' +
                '5. Configura Rspamd per usare ClamAV\\n\\n' +
                'Procedo?')) return;

            const btn = document.getElementById('btnCavFixAll');
            const original = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>In corso (può richiedere fino a 10 min)...';

            fetch('/api/clamav_health', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'fix_all', csrf_token: document.getElementById('csrf_token').value })
            }).then(r => r.json()).then(data => {
                btn.disabled = false;
                btn.innerHTML = original;
                const report = document.getElementById('cavFixAllReport');
                const stepsEl = document.getElementById('cavFixAllSteps');
                let html = '';
                (data.steps || []).forEach(s => {
                    let icon, badge;
                    if (s.status === 'skipped') { icon = '<i class="fas fa-forward text-secondary"></i>'; badge = '<span class="badge bg-secondary">SKIP</span>'; }
                    else if (s.success) { icon = '<i class="fas fa-check-circle text-success"></i>'; badge = '<span class="badge bg-success">OK</span>'; }
                    else { icon = '<i class="fas fa-times-circle text-danger"></i>'; badge = '<span class="badge bg-danger">FAIL</span>'; }
                    html += '<div class="d-flex align-items-start gap-2 mb-2">' + icon +
                        '<div class="flex-grow-1"><div>' + badge + ' <strong>' + escapeHtmlCav(s.label) + '</strong></div>';
                    if (s.message) html += '<div class="small text-muted">' + escapeHtmlCav(s.message) + '</div>';
                    if (s.output && s.output.length > 0) html += '<details class="small mt-1"><summary>Output</summary><pre class="mb-0 mt-1" style="font-size:0.75rem;max-height:200px;overflow:auto">' + escapeHtmlCav(s.output) + '</pre></details>';
                    html += '</div></div>';
                });
                stepsEl.innerHTML = html;
                report.classList.remove('d-none');
                loadClamavHealth();
            }).catch(e => {
                btn.disabled = false;
                btn.innerHTML = original;
                alert('Errore rete: ' + e.message);
            });
        }

        function runCavTestEicar() {
            const btn = document.getElementById('btnCavTestEicar');
            const original = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Test in corso...';
            fetch('/api/clamav_health', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'test_eicar', csrf_token: document.getElementById('csrf_token').value })
            }).then(r => r.json()).then(data => {
                btn.disabled = false;
                btn.innerHTML = original;
                const resultEl = document.getElementById('cavEicarResult');
                const bodyEl = document.getElementById('cavEicarBody');
                let alertClass, icon;
                if (data.success && data.detected) {
                    alertClass = 'alert-success';
                    icon = '<i class="fas fa-shield-virus me-2"></i>';
                } else if (data.detected === false) {
                    alertClass = 'alert-warning';
                    icon = '<i class="fas fa-exclamation-triangle me-2"></i>';
                } else {
                    alertClass = 'alert-danger';
                    icon = '<i class="fas fa-times-circle me-2"></i>';
                }
                let html = '<div class="alert ' + alertClass + ' mb-2">' + icon + escapeHtmlCav(data.message || 'Risultato sconosciuto') + '</div>';
                if (data.scan_output) {
                    html += '<details class="small"><summary>Output clamdscan</summary>';
                    html += '<pre class="mb-0 mt-1" style="font-size:0.8rem;max-height:200px;overflow:auto">' + escapeHtmlCav(data.scan_output) + '</pre>';
                    html += '</details>';
                }
                html += '<div class="small text-muted mt-2"><i class="fas fa-info-circle me-1"></i>EICAR è un file di test standard riconosciuto da tutti gli antivirus, completamente innocuo. Se ClamAV NON lo rileva, c\\'è un problema con scan/database.</div>';
                bodyEl.innerHTML = html;
                resultEl.classList.remove('d-none');
            }).catch(e => {
                btn.disabled = false;
                btn.innerHTML = original;
                alert('Errore rete: ' + e.message);
            });
        }

        function escapeHtmlCav(s) {
            const d = document.createElement('div');
            d.textContent = s == null ? '' : String(s);
            return d.innerHTML;
        }

        // ===== Refresh Jail Attive (spinner visivo + feedback) =====
        function refreshJails(userTriggered) {
            const icon = document.getElementById('iconRefreshJails');
            const btn = document.getElementById('btnRefreshJails');
            if (icon) icon.classList.add('fa-spin');
            if (btn) btn.disabled = true;
            // Mostra "Aggiornamento..." nel container
            const container = document.getElementById('jailsContainer');
            if (container && userTriggered) {
                container.innerHTML = '<p class="text-muted mb-0"><i class="fas fa-spinner fa-spin me-1"></i>Aggiornamento in corso...</p>';
            }
            // Carica + delay artificiale per feedback visivo
            const promise = fetch('/api/fail2ban?action=status').then(r => r.json());
            const minDelay = new Promise(r => setTimeout(r, 400));
            Promise.all([promise, minDelay]).then(([data]) => {
                // Riusa la logica di loadStatus chiamandola
                loadStatus();
            }).catch(e => {
                if (container) container.innerHTML = '<p class="text-danger mb-0">Errore: ' + e.message + '</p>';
            }).finally(() => {
                if (icon) icon.classList.remove('fa-spin');
                if (btn) btn.disabled = false;
            });
        }

        // ===== Permaban =====
        function permabanAdd(ip) {
            if (!confirm('Aggiungere ' + ip + ' al ban PERMANENTE?\\n\\n' +
                'L\\'IP verrà bloccato da pf indipendentemente da Fail2ban e\\n' +
                'sopravviverà a tutti i riavvii. Per sbannare dovrai rimuoverlo dalla lista permaban.')) return;
            fetch('/api/fail2ban', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'permaban_add', ip: ip })
            }).then(r => r.json()).then(data => {
                if (data.success) {
                    permabanList();
                    loadStatus();
                } else {
                    alert('Errore: ' + (data.message || 'sconosciuto'));
                }
            }).catch(e => alert('Errore rete: ' + e.message));
        }

        function permabanAddManual() {
            const input = document.getElementById('permabanIpInput');
            const ip = input.value.trim();
            if (!ip) { alert('Inserisci un IP'); return; }
            if (!confirm('Aggiungere ' + ip + ' al ban PERMANENTE via pf?')) return;
            fetch('/api/fail2ban', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'permaban_add', ip: ip })
            }).then(r => r.json()).then(data => {
                if (data.success) {
                    input.value = '';
                    permabanList();
                } else {
                    alert('Errore: ' + (data.message || 'sconosciuto'));
                }
            }).catch(e => alert('Errore rete: ' + e.message));
        }

        function permabanRemove(ip) {
            if (!confirm('Rimuovere ' + ip + ' dal permaban?\\n\\nL\\'IP NON sarà più bloccato da pf.')) return;
            fetch('/api/fail2ban', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'permaban_remove', ip: ip })
            }).then(r => r.json()).then(data => {
                if (data.success) permabanList();
                else alert('Errore: ' + (data.message || 'sconosciuto'));
            }).catch(e => alert('Errore rete: ' + e.message));
        }

        function permabanReload() {
            fetch('/api/fail2ban', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'permaban_reload' })
            }).then(r => r.json()).then(data => {
                alert(data.message || (data.success ? 'OK' : 'Errore'));
                permabanList();
            }).catch(e => alert('Errore rete: ' + e.message));
        }

        function permabanList() {
            fetch('/api/fail2ban?action=permaban_list')
                .then(r => r.json())
                .then(data => {
                    const tbody = document.getElementById('permabanBody');
                    const counter = document.getElementById('permabanCount');
                    if (!data.success) {
                        tbody.innerHTML = '<tr><td colspan="3" class="text-muted">Errore: ' + (data.error || 'sconosciuto') + '</td></tr>';
                        return;
                    }
                    counter.textContent = data.count || 0;
                    const list = data.permabans || [];
                    if (list.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="3" class="text-muted">Nessun IP in permaban</td></tr>';
                        return;
                    }
                    tbody.innerHTML = list.map(item => `
                        <tr>
                            <td><span class="ip-badge">${escapeHtmlPermaban(item.ip)}</span></td>
                            <td>${item.in_runtime ? '<span class="badge bg-success">attivo</span>' : '<span class="badge bg-warning text-dark">non runtime</span>'}</td>
                            <td>
                                <button class="btn btn-sm btn-outline-success" onclick="permabanRemove('${item.ip}')" title="Rimuovi dal permaban">
                                    <i class="fas fa-unlock"></i>
                                </button>
                                <button class="btn btn-link btn-sm p-0 ms-1" onclick="showIpInfo('${item.ip}')" title="Info IP">
                                    <i class="fas fa-info-circle"></i>
                                </button>
                            </td>
                        </tr>
                    `).join('');
                })
                .catch(e => {
                    document.getElementById('permabanBody').innerHTML =
                        '<tr><td colspan="3" class="text-danger">Errore rete: ' + e.message + '</td></tr>';
                });
        }

        // Helper per permaban (escapeHtml potrebbe non essere definita prima)
        function escapeHtmlPermaban(s) {
            const d = document.createElement('div');
            d.textContent = s == null ? '' : String(s);
            return d.innerHTML;
        }

        // Load on page load
        loadStatus();
        // Popola prima il selettore con tutte le jail attive, poi carica la config
        populateJailSelect(() => loadJailConfig());
        loadFail2banHealth();
        loadJailLiveState();
        paliasLoad();
        loadClamavHealth();
        loadUnboundHealth();
        permabanList();
        // Auto-refresh every minute
        setInterval(loadStatus, 60000);
        setInterval(permabanList, 60000);
""" + getLogoutScript() + """
    </script>
</body>
</html>
""";
        return getHead("Sicurezza", extraStyles) + getNavbar("") + htmlPart1 + htmlPart2 + jsPart2;
    }

    // ============== STATISTICS.HTML ==============
    public static String getStatisticsHtml() {
        String extraStyles = """
        .stat-card { border-left: 4px solid; transition: transform 0.2s; }
        .stat-card:hover { transform: translateY(-2px); }
        .stat-card.sent { border-color: #28a745; }
        .stat-card.received { border-color: #17a2b8; }
        .stat-card.spam { border-color: #dc3545; }
        .stat-card.rejected { border-color: #ffc107; }
        .chart-container { position: relative; height: 300px; }
        """;
        return getHead("Statistiche", extraStyles) + getNavbar("") + """
    <div class="content container mt-4">
        <div class="content-container">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h2><i class="fas fa-chart-bar me-2"></i>Statistiche Email</h2>
                <div>
                    <select class="form-select form-select-sm d-inline-block" style="width: auto;" id="periodSelect" onchange="loadStats()">
                        <option value="today">Oggi</option>
                        <option value="week" selected>Ultima Settimana</option>
                        <option value="month">Ultimo Mese</option>
                        <option value="year">Ultimo Anno</option>
                    </select>
                    <button class="btn btn-outline-primary btn-sm ms-2" onclick="loadStats()">
                        <i class="fas fa-sync"></i>
                    </button>
                </div>
            </div>

            <!-- Summary Cards -->
            <div class="row mb-4">
                <div class="col-md-3">
                    <div class="card stat-card sent">
                        <div class="card-body text-center">
                            <h3 id="totalSent">-</h3>
                            <small class="text-muted"><i class="fas fa-paper-plane me-1"></i>Email Inviate</small>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card stat-card received">
                        <div class="card-body text-center">
                            <h3 id="totalReceived">-</h3>
                            <small class="text-muted"><i class="fas fa-inbox me-1"></i>Email Ricevute</small>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card stat-card spam">
                        <div class="card-body text-center">
                            <h3 id="totalSpam">-</h3>
                            <small class="text-muted"><i class="fas fa-exclamation-triangle me-1"></i>Spam Rilevato</small>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card stat-card rejected">
                        <div class="card-body text-center">
                            <h3 id="totalRejected">-</h3>
                            <small class="text-muted"><i class="fas fa-ban me-1"></i>Rifiutate</small>
                        </div>
                    </div>
                </div>
            </div>

            <div class="row">
                <!-- Traffic Chart -->
                <div class="col-md-8">
                    <div class="card mb-4">
                        <div class="card-header"><i class="fas fa-chart-line me-2"></i>Traffico Email</div>
                        <div class="card-body">
                            <div class="chart-container">
                                <canvas id="trafficChart"></canvas>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Distribution Chart -->
                <div class="col-md-4">
                    <div class="card mb-4">
                        <div class="card-header"><i class="fas fa-chart-pie me-2"></i>Distribuzione</div>
                        <div class="card-body">
                            <div class="chart-container">
                                <canvas id="distributionChart"></canvas>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Rspamd Stats -->
            <div class="row">
                <div class="col-md-6">
                    <div class="card mb-4">
                        <div class="card-header"><i class="fas fa-shield-alt me-2"></i>Rspamd - Statistiche Antispam</div>
                        <div class="card-body">
                            <div class="row text-center">
                                <div class="col-4">
                                    <h4 class="text-success" id="rspamdHam">-</h4>
                                    <small class="text-muted">Ham</small>
                                </div>
                                <div class="col-4">
                                    <h4 class="text-danger" id="rspamdSpam">-</h4>
                                    <small class="text-muted">Spam</small>
                                </div>
                                <div class="col-4">
                                    <h4 class="text-info" id="rspamdScanned">-</h4>
                                    <small class="text-muted">Scansionate</small>
                                </div>
                            </div>
                            <hr>
                            <div class="d-flex justify-content-between">
                                <small class="text-muted">Accuratezza:</small>
                                <span id="rspamdAccuracy">-</span>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="col-md-6">
                    <div class="card mb-4">
                        <div class="card-header"><i class="fas fa-users me-2"></i>Top Mittenti/Destinatari</div>
                        <div class="card-body">
                            <ul class="nav nav-tabs" id="topTabs">
                                <li class="nav-item">
                                    <a class="nav-link active" data-bs-toggle="tab" href="#topSenders">Mittenti</a>
                                </li>
                                <li class="nav-item">
                                    <a class="nav-link" data-bs-toggle="tab" href="#topRecipients">Destinatari</a>
                                </li>
                            </ul>
                            <div class="tab-content mt-2">
                                <div class="tab-pane fade show active" id="topSenders">
                                    <table class="table table-sm">
                                        <tbody id="topSendersBody"></tbody>
                                    </table>
                                </div>
                                <div class="tab-pane fade" id="topRecipients">
                                    <table class="table table-sm">
                                        <tbody id="topRecipientsBody"></tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Per-Domain Stats -->
            <div class="card">
                <div class="card-header"><i class="fas fa-globe me-2"></i>Statistiche per Dominio</div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead class="table-light">
                                <tr>
                                    <th>Dominio</th>
                                    <th class="text-end">Inviate</th>
                                    <th class="text-end">Ricevute</th>
                                    <th class="text-end">Spam</th>
                                    <th class="text-end">Rifiutate</th>
                                    <th class="text-end">Totale</th>
                                </tr>
                            </thead>
                            <tbody id="domainStatsBody">
                                <tr><td colspan="6" class="text-center text-muted">Caricamento...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>
""" + getFooter() + """
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        let csrfToken = document.getElementById('csrf_token').value;
        let trafficChart, distributionChart;

        function loadStats() {
            const period = document.getElementById('periodSelect').value;

            fetch('/api/statistics?period=' + period)
                .then(r => r.json())
                .then(data => {
                    // Update summary cards
                    document.getElementById('totalSent').textContent = formatNumber(data.total_sent || 0);
                    document.getElementById('totalReceived').textContent = formatNumber(data.total_received || 0);
                    document.getElementById('totalSpam').textContent = formatNumber(data.total_spam || 0);
                    document.getElementById('totalRejected').textContent = formatNumber(data.total_rejected || 0);

                    // Update traffic chart
                    updateTrafficChart(data.daily_stats || []);

                    // Update distribution chart
                    updateDistributionChart(data);

                    // Update domain stats
                    updateDomainStats(data.domain_stats || []);

                    // Update top senders/recipients
                    updateTopLists(data.top_senders || [], data.top_recipients || []);
                });

            // Load Rspamd stats
            fetch('/api/rspamd?action=stats')
                .then(r => r.json())
                .then(data => {
                    if (data.stats) {
                        document.getElementById('rspamdHam').textContent = formatNumber(data.stats.ham_count || 0);
                        document.getElementById('rspamdSpam').textContent = formatNumber(data.stats.spam_count || 0);
                        document.getElementById('rspamdScanned').textContent = formatNumber(data.stats.scanned || 0);
                        const accuracy = data.stats.scanned > 0 ?
                            ((1 - (data.stats.spam_count / data.stats.scanned)) * 100).toFixed(1) + '%' : '-';
                        document.getElementById('rspamdAccuracy').textContent = accuracy;
                    }
                });
        }

        function formatNumber(n) {
            if (n >= 1000000) return (n/1000000).toFixed(1) + 'M';
            if (n >= 1000) return (n/1000).toFixed(1) + 'K';
            return n.toString();
        }

        function updateTrafficChart(dailyStats) {
            const ctx = document.getElementById('trafficChart').getContext('2d');

            if (trafficChart) trafficChart.destroy();

            trafficChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: dailyStats.map(d => d.date),
                    datasets: [
                        {
                            label: 'Inviate',
                            data: dailyStats.map(d => d.sent),
                            borderColor: '#28a745',
                            backgroundColor: 'rgba(40, 167, 69, 0.1)',
                            fill: true,
                            tension: 0.4
                        },
                        {
                            label: 'Ricevute',
                            data: dailyStats.map(d => d.received),
                            borderColor: '#17a2b8',
                            backgroundColor: 'rgba(23, 162, 184, 0.1)',
                            fill: true,
                            tension: 0.4
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { position: 'top' } },
                    scales: { y: { beginAtZero: true } }
                }
            });
        }

        function updateDistributionChart(data) {
            const ctx = document.getElementById('distributionChart').getContext('2d');

            if (distributionChart) distributionChart.destroy();

            distributionChart = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: ['Consegnate', 'Spam', 'Rifiutate'],
                    datasets: [{
                        data: [
                            (data.total_sent || 0) + (data.total_received || 0) - (data.total_spam || 0) - (data.total_rejected || 0),
                            data.total_spam || 0,
                            data.total_rejected || 0
                        ],
                        backgroundColor: ['#28a745', '#dc3545', '#ffc107']
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { position: 'bottom' } }
                }
            });
        }

        function updateDomainStats(domains) {
            const tbody = document.getElementById('domainStatsBody');
            if (!domains.length) {
                tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">Nessun dato disponibile</td></tr>';
                return;
            }

            tbody.innerHTML = domains.map(d => `
                <tr>
                    <td><i class="fas fa-globe me-1"></i>${d.domain}</td>
                    <td class="text-end">${formatNumber(d.sent)}</td>
                    <td class="text-end">${formatNumber(d.received)}</td>
                    <td class="text-end text-danger">${formatNumber(d.spam)}</td>
                    <td class="text-end text-warning">${formatNumber(d.rejected)}</td>
                    <td class="text-end"><strong>${formatNumber(d.total)}</strong></td>
                </tr>
            `).join('');
        }

        function updateTopLists(senders, recipients) {
            const sendersBody = document.getElementById('topSendersBody');
            const recipientsBody = document.getElementById('topRecipientsBody');

            sendersBody.innerHTML = senders.length ? senders.map((s, i) => `
                <tr>
                    <td><span class="badge bg-secondary">${i+1}</span></td>
                    <td>${s.email}</td>
                    <td class="text-end">${formatNumber(s.count)}</td>
                </tr>
            `).join('') : '<tr><td colspan="3" class="text-muted">Nessun dato</td></tr>';

            recipientsBody.innerHTML = recipients.length ? recipients.map((r, i) => `
                <tr>
                    <td><span class="badge bg-secondary">${i+1}</span></td>
                    <td>${r.email}</td>
                    <td class="text-end">${formatNumber(r.count)}</td>
                </tr>
            `).join('') : '<tr><td colspan="3" class="text-muted">Nessun dato</td></tr>';
        }

        // Load on page load
        loadStats();
""" + getLogoutScript() + """
    </script>
</body>
</html>
""";
    }

    // ============== ADMINS.HTML ==============
    public static String getAdminsHtml() {
        String extraStyles = """
        .role-badge.superadmin { background-color: #dc3545; }
        .role-badge.admin { background-color: #0d6efd; }
        .role-badge.operator { background-color: #198754; }
        .role-badge.viewer { background-color: #6c757d; }
        .totp-enabled { color: #198754; }
        .totp-disabled { color: #dc3545; }
        """;
        return getHead("Gestione Admin", extraStyles) + getNavbar("") + """
    <div class="content container mt-4">
        <div class="content-container">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h2><i class="fas fa-users-cog me-2"></i>Gestione Amministratori</h2>
                <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addAdminModal">
                    <i class="fas fa-plus me-1"></i>Nuovo Admin
                </button>
            </div>

            <!-- Roles Info -->
            <div class="alert alert-info mb-4">
                <h6><i class="fas fa-info-circle me-2"></i>Ruoli Disponibili:</h6>
                <div class="row mt-2">
                    <div class="col-md-3">
                        <span class="badge role-badge superadmin">Superadmin</span>
                        <small class="d-block text-muted">Accesso completo + gestione admin</small>
                    </div>
                    <div class="col-md-3">
                        <span class="badge role-badge admin">Admin</span>
                        <small class="d-block text-muted">Gestione domini, mailbox, alias</small>
                    </div>
                    <div class="col-md-3">
                        <span class="badge role-badge operator">Operatore</span>
                        <small class="d-block text-muted">Gestione mailbox e code</small>
                    </div>
                    <div class="col-md-3">
                        <span class="badge role-badge viewer">Viewer</span>
                        <small class="d-block text-muted">Solo visualizzazione</small>
                    </div>
                </div>
            </div>

            <!-- Admins Table -->
            <div class="card">
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead class="table-light">
                                <tr>
                                    <th>Username</th>
                                    <th>Ruolo</th>
                                    <th>2FA</th>
                                    <th>Ultimo Accesso</th>
                                    <th>Creato</th>
                                    <th>Azioni</th>
                                </tr>
                            </thead>
                            <tbody id="adminsBody">
                                <tr><td colspan="6" class="text-center text-muted">Caricamento...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Add Admin Modal -->
    <div class="modal fade" id="addAdminModal" tabindex="-1">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-user-plus me-2"></i>Nuovo Amministratore</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <form id="addAdminForm">
                        <div class="mb-3">
                            <label class="form-label">Username</label>
                            <input type="text" class="form-control" id="newUsername" required
                                   pattern="^[a-zA-Z0-9_\\-]{3,50}$" minlength="3" maxlength="50">
                            <small class="text-muted">3-50 caratteri, solo lettere, numeri, _ e -</small>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Password</label>
                            <input type="password" class="form-control" id="newPassword" required minlength="8">
                            <small class="text-muted">Minimo 8 caratteri</small>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Conferma Password</label>
                            <input type="password" class="form-control" id="confirmPassword" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Ruolo</label>
                            <select class="form-select" id="newRole">
                                <option value="viewer">Viewer</option>
                                <option value="operator">Operatore</option>
                                <option value="admin">Admin</option>
                                <option value="superadmin">Superadmin</option>
                            </select>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Annulla</button>
                    <button type="button" class="btn btn-primary" onclick="createAdmin()">Crea Admin</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Edit Admin Modal -->
    <div class="modal fade" id="editAdminModal" tabindex="-1">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-user-edit me-2"></i>Modifica Amministratore</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <input type="hidden" id="editAdminId">
                    <div class="mb-3">
                        <label class="form-label">Username</label>
                        <input type="text" class="form-control" id="editUsername" readonly>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Nuova Password (lascia vuoto per non cambiare)</label>
                        <input type="password" class="form-control" id="editPassword">
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Ruolo</label>
                        <select class="form-select" id="editRole">
                            <option value="viewer">Viewer</option>
                            <option value="operator">Operatore</option>
                            <option value="admin">Admin</option>
                            <option value="superadmin">Superadmin</option>
                        </select>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Annulla</button>
                    <button type="button" class="btn btn-primary" onclick="updateAdmin()">Salva</button>
                </div>
            </div>
        </div>
    </div>
""" + getFooter() + """
    <script>
        let csrfToken = document.getElementById('csrf_token').value;

        function loadAdmins() {
            fetch('/api/admins?action=list')
                .then(r => r.json())
                .then(data => {
                    const tbody = document.getElementById('adminsBody');
                    if (!data.admins || !data.admins.length) {
                        tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">Nessun admin trovato</td></tr>';
                        return;
                    }

                    tbody.innerHTML = data.admins.map(admin => `
                        <tr>
                            <td>
                                <i class="fas fa-user me-1"></i>${admin.username}
                                ${admin.is_current ? '<span class="badge bg-info ms-1">Tu</span>' : ''}
                            </td>
                            <td><span class="badge role-badge ${admin.role}">${admin.role}</span></td>
                            <td>
                                ${admin.totp_enabled
                                    ? '<i class="fas fa-shield-alt totp-enabled" title="2FA Attivo"></i>'
                                    : '<i class="fas fa-shield-alt totp-disabled" title="2FA Non Attivo"></i>'}
                            </td>
                            <td><small>${admin.last_login || 'Mai'}</small></td>
                            <td><small>${admin.created_at}</small></td>
                            <td>
                                <button class="btn btn-sm btn-outline-primary" onclick="editAdmin(${admin.id}, '${admin.username}', '${admin.role}')"
                                        ${admin.is_current ? 'disabled' : ''}>
                                    <i class="fas fa-edit"></i>
                                </button>
                                <button class="btn btn-sm btn-outline-danger" onclick="deleteAdmin(${admin.id}, '${admin.username}')"
                                        ${admin.is_current || admin.role === 'superadmin' ? 'disabled' : ''}>
                                    <i class="fas fa-trash"></i>
                                </button>
                            </td>
                        </tr>
                    `).join('');
                });
        }

        function createAdmin() {
            const username = document.getElementById('newUsername').value.trim();
            const password = document.getElementById('newPassword').value;
            const confirm = document.getElementById('confirmPassword').value;
            const role = document.getElementById('newRole').value;

            if (!username || !password) {
                alert('Compila tutti i campi obbligatori');
                return;
            }

            if (password !== confirm) {
                alert('Le password non corrispondono');
                return;
            }

            fetch('/api/admins', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'create', username, password, role })
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    bootstrap.Modal.getInstance(document.getElementById('addAdminModal')).hide();
                    document.getElementById('addAdminForm').reset();
                    loadAdmins();
                } else {
                    alert(data.error || 'Errore nella creazione');
                }
            });
        }

        function editAdmin(id, username, role) {
            document.getElementById('editAdminId').value = id;
            document.getElementById('editUsername').value = username;
            document.getElementById('editRole').value = role;
            document.getElementById('editPassword').value = '';
            new bootstrap.Modal(document.getElementById('editAdminModal')).show();
        }

        function updateAdmin() {
            const id = document.getElementById('editAdminId').value;
            const role = document.getElementById('editRole').value;
            const password = document.getElementById('editPassword').value;

            const payload = { action: 'update', id: parseInt(id), role };
            if (password) payload.password = password;

            fetch('/api/admins', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    bootstrap.Modal.getInstance(document.getElementById('editAdminModal')).hide();
                    loadAdmins();
                } else {
                    alert(data.error || 'Errore nell\\'aggiornamento');
                }
            });
        }

        function deleteAdmin(id, username) {
            if (!confirm('Eliminare l\\'admin "' + username + '"?')) return;

            fetch('/api/admins', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'delete', id })
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    loadAdmins();
                } else {
                    alert(data.error || 'Errore nell\\'eliminazione');
                }
            });
        }

        // Load on page load
        loadAdmins();
""" + getLogoutScript() + """
    </script>
</body>
</html>
""";
    }

    // ============== RATELIMITS.HTML ==============
    public static String getRateLimitsHtml() {
        String extraStyles = """
        .limit-card { border-left: 4px solid #0d6efd; }
        .limit-enabled { border-color: #198754; }
        .limit-disabled { border-color: #dc3545; }
        .usage-bar { height: 6px; border-radius: 3px; }
        """;
        return getHead("Rate Limits", extraStyles) + getNavbar("") + """
    <div class="content container mt-4">
        <div class="content-container">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h2><i class="fas fa-tachometer-alt me-2"></i>Rate Limits</h2>
                <div>
                    <button class="btn btn-outline-primary btn-sm" onclick="loadRateLimits()">
                        <i class="fas fa-sync"></i> Aggiorna
                    </button>
                    <button class="btn btn-primary btn-sm ms-2" data-bs-toggle="modal" data-bs-target="#addLimitModal">
                        <i class="fas fa-plus"></i> Nuovo Limite
                    </button>
                </div>
            </div>

            <!-- Global Limits -->
            <div class="card mb-4">
                <div class="card-header">
                    <i class="fas fa-globe me-2"></i>Limiti Globali
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-4">
                            <div class="mb-3">
                                <label class="form-label">Max Email/Ora (per mailbox)</label>
                                <input type="number" class="form-control" id="globalHourly" value="50">
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="mb-3">
                                <label class="form-label">Max Email/Giorno (per mailbox)</label>
                                <input type="number" class="form-control" id="globalDaily" value="500">
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="mb-3">
                                <label class="form-label">Max Dimensione Messaggio (MB)</label>
                                <input type="number" class="form-control" id="globalMaxSize" value="25">
                            </div>
                        </div>
                    </div>
                    <button class="btn btn-primary" onclick="saveGlobalLimits()">
                        <i class="fas fa-save me-1"></i>Salva Limiti Globali
                    </button>
                </div>
            </div>

            <!-- Per-Mailbox Limits -->
            <div class="card">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-envelope me-2"></i>Limiti per Mailbox</span>
                    <small class="text-muted">I limiti personalizzati sovrascrivono quelli globali</small>
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead class="table-light">
                                <tr>
                                    <th>Mailbox</th>
                                    <th class="text-center">Max/Ora</th>
                                    <th class="text-center">Max/Giorno</th>
                                    <th class="text-center">Uso Oggi</th>
                                    <th class="text-center">Stato</th>
                                    <th>Azioni</th>
                                </tr>
                            </thead>
                            <tbody id="limitsBody">
                                <tr><td colspan="6" class="text-center text-muted">Caricamento...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- Blocked Senders -->
            <div class="card mt-4">
                <div class="card-header">
                    <i class="fas fa-ban me-2"></i>Mittenti Bloccati per Rate Limit
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-sm">
                            <thead class="table-light">
                                <tr>
                                    <th>Mailbox</th>
                                    <th>Bloccato Alle</th>
                                    <th>Scadenza Blocco</th>
                                    <th>Motivo</th>
                                    <th>Azioni</th>
                                </tr>
                            </thead>
                            <tbody id="blockedBody">
                                <tr><td colspan="5" class="text-center text-muted">Nessun blocco attivo</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Add/Edit Limit Modal -->
    <div class="modal fade" id="addLimitModal" tabindex="-1">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-tachometer-alt me-2"></i>Limite Personalizzato</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <input type="hidden" id="limitId">
                    <div class="mb-3">
                        <label class="form-label">Mailbox</label>
                        <select class="form-select" id="limitMailbox">
                            <option value="">Seleziona mailbox...</option>
                        </select>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Max Email/Ora</label>
                        <input type="number" class="form-control" id="limitHourly" min="1" value="50">
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Max Email/Giorno</label>
                        <input type="number" class="form-control" id="limitDaily" min="1" value="500">
                    </div>
                    <div class="form-check mb-3">
                        <input type="checkbox" class="form-check-input" id="limitEnabled" checked>
                        <label class="form-check-label" for="limitEnabled">Limite Attivo</label>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Annulla</button>
                    <button type="button" class="btn btn-primary" onclick="saveLimit()">Salva</button>
                </div>
            </div>
        </div>
    </div>
""" + getFooter() + """
    <script>
        let csrfToken = document.getElementById('csrf_token').value;

        function loadRateLimits() {
            // Load global limits
            fetch('/api/ratelimits?action=global')
                .then(r => r.json())
                .then(data => {
                    if (data.limits) {
                        document.getElementById('globalHourly').value = data.limits.hourly || 50;
                        document.getElementById('globalDaily').value = data.limits.daily || 500;
                        document.getElementById('globalMaxSize').value = data.limits.max_size_mb || 25;
                    }
                });

            // Load per-mailbox limits
            fetch('/api/ratelimits?action=list')
                .then(r => r.json())
                .then(data => {
                    const tbody = document.getElementById('limitsBody');
                    if (!data.limits || !data.limits.length) {
                        tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">Nessun limite personalizzato configurato</td></tr>';
                        return;
                    }

                    tbody.innerHTML = data.limits.map(limit => {
                        const usagePercent = limit.daily_limit > 0 ? Math.min(100, (limit.usage_today / limit.daily_limit) * 100) : 0;
                        const usageClass = usagePercent > 90 ? 'bg-danger' : usagePercent > 70 ? 'bg-warning' : 'bg-success';

                        return `
                        <tr class="${!limit.enabled ? 'table-secondary' : ''}">
                            <td><i class="fas fa-envelope me-1"></i>${limit.email}</td>
                            <td class="text-center">${limit.hourly_limit}</td>
                            <td class="text-center">${limit.daily_limit}</td>
                            <td class="text-center">
                                <div class="d-flex align-items-center">
                                    <span class="me-2">${limit.usage_today || 0}</span>
                                    <div class="progress flex-grow-1 usage-bar">
                                        <div class="progress-bar ${usageClass}" style="width: ${usagePercent}%"></div>
                                    </div>
                                </div>
                            </td>
                            <td class="text-center">
                                ${limit.enabled
                                    ? '<span class="badge bg-success">Attivo</span>'
                                    : '<span class="badge bg-secondary">Disattivo</span>'}
                            </td>
                            <td>
                                <button class="btn btn-sm btn-outline-primary" onclick="editLimit(${JSON.stringify(limit).replace(/"/g, '&quot;')})">
                                    <i class="fas fa-edit"></i>
                                </button>
                                <button class="btn btn-sm btn-outline-danger" onclick="deleteLimit(${limit.id})">
                                    <i class="fas fa-trash"></i>
                                </button>
                            </td>
                        </tr>
                    `}).join('');
                });

            // Load blocked senders
            fetch('/api/ratelimits?action=blocked')
                .then(r => r.json())
                .then(data => {
                    const tbody = document.getElementById('blockedBody');
                    if (!data.blocked || !data.blocked.length) {
                        tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">Nessun blocco attivo</td></tr>';
                        return;
                    }

                    tbody.innerHTML = data.blocked.map(block => `
                        <tr>
                            <td>${block.email}</td>
                            <td><small>${block.blocked_at}</small></td>
                            <td><small>${block.expires_at}</small></td>
                            <td><small class="text-muted">${block.reason}</small></td>
                            <td>
                                <button class="btn btn-sm btn-outline-success" onclick="unblockSender(${block.id})">
                                    <i class="fas fa-unlock"></i> Sblocca
                                </button>
                            </td>
                        </tr>
                    `).join('');
                });

            // Load mailboxes for dropdown
            loadMailboxes();
        }

        function loadMailboxes() {
            fetch('/api/mailboxes')
                .then(r => r.json())
                .then(data => {
                    const select = document.getElementById('limitMailbox');
                    select.innerHTML = '<option value="">Seleziona mailbox...</option>' +
                        (data.mailboxes || []).map(m => `<option value="${m.id}">${m.email}</option>`).join('');
                });
        }

        function saveGlobalLimits() {
            const hourly = parseInt(document.getElementById('globalHourly').value);
            const daily = parseInt(document.getElementById('globalDaily').value);
            const maxSize = parseInt(document.getElementById('globalMaxSize').value);

            fetch('/api/ratelimits', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'save_global', hourly, daily, max_size_mb: maxSize })
            })
            .then(r => r.json())
            .then(data => {
                alert(data.success ? 'Limiti globali salvati' : (data.error || 'Errore'));
            });
        }

        function editLimit(limit) {
            document.getElementById('limitId').value = limit.id;
            document.getElementById('limitMailbox').value = limit.mailbox_id;
            document.getElementById('limitHourly').value = limit.hourly_limit;
            document.getElementById('limitDaily').value = limit.daily_limit;
            document.getElementById('limitEnabled').checked = limit.enabled;
            new bootstrap.Modal(document.getElementById('addLimitModal')).show();
        }

        function saveLimit() {
            const id = document.getElementById('limitId').value;
            const mailboxId = document.getElementById('limitMailbox').value;
            const hourly = parseInt(document.getElementById('limitHourly').value);
            const daily = parseInt(document.getElementById('limitDaily').value);
            const enabled = document.getElementById('limitEnabled').checked;

            if (!mailboxId) {
                alert('Seleziona una mailbox');
                return;
            }

            fetch('/api/ratelimits', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action: id ? 'update' : 'create',
                    id: id ? parseInt(id) : undefined,
                    mailbox_id: parseInt(mailboxId),
                    hourly_limit: hourly,
                    daily_limit: daily,
                    enabled
                })
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    bootstrap.Modal.getInstance(document.getElementById('addLimitModal')).hide();
                    loadRateLimits();
                } else {
                    alert(data.error || 'Errore nel salvataggio');
                }
            });
        }

        function deleteLimit(id) {
            if (!confirm('Eliminare questo limite?')) return;

            fetch('/api/ratelimits', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'delete', id })
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) loadRateLimits();
                else alert(data.error || 'Errore');
            });
        }

        function unblockSender(id) {
            if (!confirm('Sbloccare questo mittente?')) return;

            fetch('/api/ratelimits', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'unblock', id })
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) loadRateLimits();
                else alert(data.error || 'Errore');
            });
        }

        // Load on page load
        loadRateLimits();
""" + getLogoutScript() + """
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
            background: transparent;
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
        return getHead("Firewall", extraStyles) + getNavbar("firewall") + """
    <div class="content container-fluid mt-4" style="max-width: 1200px">

        <div class="d-flex justify-content-between align-items-center mb-3 flex-wrap gap-2">
            <h2 class="mb-0"><i class="fas fa-fire me-2"></i>Firewall geo-localizzato (pf)</h2>
            <div class="d-flex gap-2">
                <button class="btn btn-outline-secondary btn-sm" onclick="loadFirewall()" title="Ricarica stato">
                    <i class="fas fa-sync"></i>
                </button>
                <button class="btn btn-success" onclick="fwApply()" title="Rigenera anchor pf con backup + syntax check + carica nel kernel">
                    <i class="fas fa-check-circle me-1"></i>Applica configurazione
                </button>
            </div>
        </div>

        <!-- Status -->
        <div class="card mb-3 border-primary">
            <div class="card-header bg-primary text-white py-2">
                <i class="fas fa-info-circle me-2"></i>Stato attuale del firewall
            </div>
            <div class="card-body py-2" id="fwStatusBody">
                <p class="text-muted mb-0"><i class="fas fa-spinner fa-spin me-1"></i>Caricamento...</p>
            </div>
        </div>

        <!-- Mode selector -->
        <div class="card mb-3">
            <div class="card-header py-2"><i class="fas fa-cog me-2"></i>Modalità</div>
            <div class="card-body">
                <p class="small text-muted mb-3">Scegli COME il firewall deve filtrare le connessioni alle porte mail.
                Le modifiche NON sono applicate fino a quando non clicchi <strong>"Applica configurazione"</strong> in alto.</p>
                <div class="row g-2" id="fwModeContainer"></div>

                <div class="mt-3" id="fwPort25Row" style="display:none">
                    <div class="form-check">
                        <input type="checkbox" class="form-check-input" id="fwPort25Geo" onchange="fwSetPort25Geo(this.checked)">
                        <label class="form-check-label small" for="fwPort25Geo">
                            Applica la geo-whitelist anche a <strong>porta 25 (SMTP delivery)</strong>
                            <i class="fas fa-exclamation-triangle text-warning ms-1"></i>
                        </label>
                    </div>
                    <div class="alert alert-warning py-2 px-2 mt-2 mb-0 small">
                        <i class="fas fa-info-circle me-1"></i>
                        <strong>Cosa fa</strong>: di default la geo-whitelist protegge solo le porte di <strong>login</strong>
                        (587, 465, 143, 993, 110, 995) — dove utenti malintenzionati provano a fare brute-force con password.
                        La <strong>porta 25</strong> rimane invece aperta al mondo: è la porta che i mail server esteri
                        (Gmail, Microsoft, server di amici/clienti) usano per <strong>consegnarti le email in entrata</strong>.<br><br>

                        <strong>Se attivi questa opzione</strong>, la geo-whitelist viene estesa anche alla porta 25:
                        i server mail dai paesi NON whitelistati non potranno più consegnarti email.<br><br>

                        <strong>⚠ Quando attivarla</strong>: <span class="text-success">solo</span> se sei sicuro al 100% che nessuno
                        ti scriverà mai da mail server in paesi fuori dalla tua whitelist (es. Cina, India, Vietnam,
                        Brasile, ecc.). Anche un piccolo provider regionale estero potrebbe inviarti fatture o notifiche
                        legittime.<br><br>

                        <strong>🟢 Consiglio</strong>: <strong>lasciala spenta</strong>. I bot che attaccano la porta 25
                        provano in genere ad usarti come open-relay, ma <strong>Postfix li respinge già correttamente</strong>
                        con <code>Relay access denied</code>. Quel rumore nei log è innocuo. Attivando questa opzione
                        guadagni quasi zero in sicurezza, ma rischi di perdere mail legittime in entrata.
                    </div>
                </div>
            </div>
        </div>

        <!-- Auto-sync GeoIP -->
        <div class="card mb-3 border-info">
            <div class="card-header py-2 d-flex justify-content-between align-items-center flex-wrap gap-2 bg-info bg-opacity-10">
                <span><i class="fas fa-cloud-download-alt me-2"></i>Aggiornamento automatico GeoIP <span id="fwAutoSyncStatus"></span></span>
                <div>
                    <button class="btn btn-warning btn-sm me-1" onclick="fwSyncAll()" title="Forza ora il download/aggiornamento per TUTTI i paesi selezionati">
                        <i class="fas fa-sync me-1"></i>Sincronizza ora
                    </button>
                </div>
            </div>
            <div class="card-body">
                <div id="fwAutoSyncSummary" class="small mb-2 text-muted">Caricamento...</div>
                <div class="row g-2 align-items-end">
                    <div class="col-md-4">
                        <div class="form-check form-switch">
                            <input type="checkbox" class="form-check-input" id="fwAutoSyncEnabled">
                            <label class="form-check-label small" for="fwAutoSyncEnabled">
                                <strong>Auto-sync attivo</strong>
                                <div class="text-muted" style="font-size:.75rem">Scarica in automatico le liste in background</div>
                            </label>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <label class="form-label small mb-1">Intervallo (giorni)</label>
                        <select class="form-select form-select-sm" id="fwAutoSyncInterval">
                            <option value="1">Ogni giorno</option>
                            <option value="3">Ogni 3 giorni</option>
                            <option value="7" selected>Ogni 7 giorni (consigliato)</option>
                            <option value="14">Ogni 14 giorni</option>
                            <option value="30">Ogni 30 giorni</option>
                        </select>
                    </div>
                    <div class="col-md-4">
                        <button class="btn btn-primary btn-sm w-100" onclick="fwSaveAutoSync()">
                            <i class="fas fa-save me-1"></i>Salva impostazioni auto-sync
                        </button>
                    </div>
                </div>
                <div class="alert alert-info py-2 px-2 mt-2 mb-0 small">
                    <i class="fas fa-info-circle me-1"></i>
                    <b>Come funziona:</b> il pannello controlla ogni ora se ci sono paesi più vecchi dell'intervallo configurato e li ri-scarica
                    da <code>ipdeny.com</code>. <b>Massimo 5 paesi per controllo</b> per non saturare la banda. Il file viene aggiornato solo se serve.
                    Per forzare adesso, usa <b>"Sincronizza ora"</b> in alto.
                </div>
            </div>
        </div>

        <!-- Countries (geo whitelist/blacklist) -->
        <div class="card mb-3" id="fwCountriesCard">
            <div class="card-header py-2 d-flex justify-content-between align-items-center flex-wrap gap-2">
                <span><i class="fas fa-globe me-2"></i>Paesi <span class="badge bg-secondary ms-1" id="fwCountriesCount">0</span></span>
                <button class="btn btn-warning btn-sm" onclick="fwSyncAll()" title="Scarica/aggiorna i range IP da ipdeny.com per tutti i paesi selezionati">
                    <i class="fas fa-cloud-download-alt me-1"></i>Sincronizza GeoIP
                </button>
            </div>
            <div class="card-body">
                <p class="small text-muted mb-2">
                    Seleziona i paesi. I range IP vengono scaricati gratuitamente da <code>ipdeny.com</code>.
                    Per ogni paese vedrai quanti CIDR sono attualmente scaricati.
                </p>

                <!-- Preset groups (UE, G7, NATO, ecc.) -->
                <div class="mb-2">
                    <div class="d-flex justify-content-between align-items-center mb-1 flex-wrap gap-1">
                        <strong class="small">Preset rapidi</strong>
                        <div class="btn-group btn-group-sm" role="group" aria-label="Modalità preset">
                            <input type="radio" class="btn-check" name="fwPresetMode" id="fwPresetModeReplace" value="replace" checked>
                            <label class="btn btn-outline-primary" for="fwPresetModeReplace" title="Cliccando un preset, la selezione attuale viene CANCELLATA e sostituita con quella del preset">
                                <i class="fas fa-exchange-alt me-1"></i>Sostituisci
                            </label>
                            <input type="radio" class="btn-check" name="fwPresetMode" id="fwPresetModeAdd" value="add">
                            <label class="btn btn-outline-success" for="fwPresetModeAdd" title="Cliccando un preset, i suoi paesi vengono AGGIUNTI alla selezione attuale (senza rimuovere niente)">
                                <i class="fas fa-plus me-1"></i>Aggiungi
                            </label>
                        </div>
                    </div>
                    <div class="d-flex flex-wrap gap-1" id="fwPresetGroups"></div>
                </div>

                <!-- Bulk select / deselect -->
                <div class="d-flex flex-wrap gap-1 mb-2">
                    <button id="fwToggleOnlySelected" class="btn btn-outline-info btn-sm" onclick="fwToggleOnlySelected()" title="Mostra solo i paesi attualmente selezionati (utile per rifinire un preset, es. togliere Turchia dopo aver applicato NATO)">
                        <i class="fas fa-filter me-1"></i>Mostra solo selezionati
                    </button>
                    <button class="btn btn-outline-primary btn-sm" onclick="fwSelectAllVisible()" title="Seleziona tutti i paesi attualmente visibili (rispetta filtro di ricerca)">
                        <i class="fas fa-check-double me-1"></i>Seleziona visibili
                    </button>
                    <button class="btn btn-outline-secondary btn-sm" onclick="fwDeselectAllVisible()" title="Deseleziona tutti i paesi attualmente visibili">
                        <i class="fas fa-times me-1"></i>Deseleziona visibili
                    </button>
                    <button class="btn btn-outline-danger btn-sm" onclick="fwClearAllCountries()" title="Rimuovi TUTTI i paesi selezionati">
                        <i class="fas fa-trash me-1"></i>Svuota tutto
                    </button>
                </div>

                <input type="text" class="form-control form-control-sm mb-2" id="fwCountrySearch"
                       placeholder="Cerca paese (es. ita, ger, italy, oppure 'tr' per Turchia)..." oninput="fwFilterCountries()">
                <div class="small mb-2"><strong id="fwGridLabel">Paesi disponibili</strong></div>
                <div class="fw-country-grid" id="fwCountriesGrid" style="max-height: 500px"></div>
                <div class="alert alert-info py-2 px-2 mt-2 mb-0 small">
                    <i class="fas fa-info-circle me-1"></i>
                    I paesi in <span class="badge text-bg-primary" style="font-size:.7rem">blu</span> sono selezionati.
                    Usa la ricerca per trovare un paese specifico, o i preset rapidi sopra per selezionare gruppi.
                </div>

                <!-- Editor testuale bidirezionale -->
                <div class="mt-3 pt-3" style="border-top: 1px solid rgba(128,128,128,0.25)">
                    <div class="d-flex justify-content-between align-items-center mb-2 flex-wrap gap-2">
                        <strong class="small"><i class="fas fa-code me-1"></i>Editor codici paesi</strong>
                        <div class="d-flex gap-1 align-items-center flex-wrap">
                            <label class="small mb-0">Formato:</label>
                            <select class="form-select form-select-sm" id="fwCodeFormat" style="width:auto" onchange="renderFwCodeEditor()">
                                <option value="cf_ne">Cloudflare (ne — blacklist)</option>
                                <option value="cf_eq">Cloudflare (eq — whitelist)</option>
                                <option value="csv" selected>Lista codici (separati da virgola)</option>
                                <option value="json">JSON array</option>
                                <option value="lines">Uno per riga</option>
                            </select>
                            <button class="btn btn-sm btn-outline-secondary" onclick="fwCopyCodeEditor()" title="Copia negli appunti">
                                <i class="fas fa-copy"></i>
                            </button>
                        </div>
                    </div>
                    <textarea id="fwCodeEditor" class="form-control" rows="4"
                              style="font-family: monospace; font-size: .85rem"
                              placeholder="Scrivi qui i codici paese (es: IT, FR, DE) — la selezione si aggiorna automaticamente"
                              oninput="fwScheduleCodeApply()"></textarea>
                    <div class="d-flex justify-content-between align-items-center mt-1 flex-wrap gap-1">
                        <div id="fwCodeEditorStatus" class="small">Pronto</div>
                        <button class="btn btn-primary btn-sm" onclick="fwApplyCodeEditorNow()">
                            <i class="fas fa-check me-1"></i>Applica adesso
                        </button>
                    </div>
                    <div class="alert alert-info py-2 px-2 mt-2 mb-0 small">
                        <i class="fas fa-info-circle me-1"></i>
                        Aggiungi/rimuovi codici e la lista paesi si sincronizza automaticamente (dopo 800ms di pausa).
                        Codici validi: 2 lettere maiuscole tipo <code>IT</code>, <code>FR</code>, <code>DE</code>.
                    </div>
                </div>
            </div>
        </div>

        <!-- CIDR Whitelist -->
        <div class="card mb-3">
            <div class="card-header py-2 d-flex justify-content-between align-items-center">
                <span><i class="fas fa-check-circle text-success me-2"></i>Whitelist CIDR (sempre permesso)</span>
                <span class="badge bg-success" id="fwWlCount">0</span>
            </div>
            <div class="card-body">
                <p class="small text-muted mb-2">
                    IP/range nella whitelist passano <strong>sempre</strong>, indipendentemente dalla geo.
                    Usalo per il tuo IP fisso, ufficio, VPN.
                </p>
                <div id="fwWlList" class="mb-2"><span class="text-muted small">Nessun IP in whitelist</span></div>
                <div class="row g-2">
                    <div class="col-md-9"><input type="text" class="form-control form-control-sm" id="fwWlInput" placeholder="es: 198.51.100.25 o 192.168.0.0/24"></div>
                    <div class="col-md-3"><button class="btn btn-success btn-sm w-100" onclick="fwAddCidr('wl')"><i class="fas fa-plus me-1"></i>Aggiungi</button></div>
                </div>
            </div>
        </div>

        <!-- CIDR Blacklist -->
        <div class="card mb-3">
            <div class="card-header py-2 d-flex justify-content-between align-items-center">
                <span><i class="fas fa-ban text-danger me-2"></i>Blacklist CIDR (sempre bloccato)</span>
                <span class="badge bg-danger" id="fwBlCount">0</span>
            </div>
            <div class="card-body">
                <p class="small text-muted mb-2">
                    IP/range nella blacklist vengono <strong>sempre droppati</strong> dal firewall, prima ancora che
                    Postfix/Dovecot vedano il pacchetto. Usalo per botnet/abuser noti come <code>109.105.211.0/24</code>.
                </p>
                <div id="fwBlList" class="mb-2"><span class="text-muted small">Nessun IP in blacklist</span></div>
                <div class="row g-2">
                    <div class="col-md-9"><input type="text" class="form-control form-control-sm" id="fwBlInput" placeholder="es: 109.105.211.0/24"></div>
                    <div class="col-md-3"><button class="btn btn-danger btn-sm w-100" onclick="fwAddCidr('bl')"><i class="fas fa-plus me-1"></i>Aggiungi</button></div>
                </div>
            </div>
        </div>

        <!-- Warning before apply -->
        <div class="fw-warning-banner mb-3">
            <strong><i class="fas fa-exclamation-triangle me-1"></i>Importante prima di applicare</strong><br>
            <span class="small">
                - <b>Aggiungi sempre il tuo IP fisso alla Whitelist CIDR</b> prima di attivare la geo-whitelist, per evitare di bloccarti da solo.<br>
                - Il pannello fa backup automatico di <code>/etc/pf.conf</code> e dell'anchor prima di scrivere.<br>
                - Lo step "Applica" fa <code>pfctl -nf</code> (syntax check) prima di caricare nel kernel. Se sintassi errata, lo stato precedente resta.<br>
                - Per la geo-whitelist, <b>scarica prima i range</b> con "Sincronizza GeoIP" — senza i range, le tabelle pf sono vuote.
            </span>
        </div>

""" + getFooter() + """
    <script>
""" + getFirewallJs() + """
""" + getLogoutScript() + """
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

        // Modalita' disponibili (label + descrizione)
        const FW_MODES = [
            { value: 'CIDR_ONLY',      label: 'Solo CIDR',
              desc: 'Solo whitelist/blacklist CIDR manuali. Niente filtro per paese.' },
            { value: 'GEO_WHITELIST',  label: 'Geo Whitelist (consigliato)',
              recommended: true,
              desc: 'Solo i paesi selezionati possono accedere alle porte AUTH (587/465/IMAP/POP). Tutto il resto bloccato.' },
            { value: 'GEO_BLACKLIST',  label: 'Geo Blacklist',
              desc: 'I paesi selezionati vengono bloccati su tutte le porte mail. Resto del mondo permesso.' },
            { value: 'DISABLED',       label: 'Disabilitato',
              desc: 'Firewall pannello disattivo. Nessuna regola caricata nell\\'anchor panel-fw.' }
        ];

        // ===== Status JSON loader =====
        function loadFirewall() {
            fetch('/api/firewall').then(r => r.json()).then(data => {
                if (!data.success) {
                    document.getElementById('fwStatusBody').innerHTML =
                        '<div class="text-danger">Errore: ' + escapeHtml(data.error || 'sconosciuto') + '</div>';
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
                    '<div class="text-danger">Errore rete: ' + escapeHtml(e.message) + '</div>';
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
                ? '<span class="badge bg-success">ATTIVO</span>'
                : '<span class="badge bg-secondary">NON ATTIVO</span>';
            const modeBadge = '<span class="badge bg-primary">' + escapeHtml(s.mode) + '</span>';
            document.getElementById('fwStatusBody').innerHTML =
                '<div class="d-flex flex-wrap gap-3 align-items-center">' +
                '<div><strong>Stato:</strong> ' + enabledBadge + '</div>' +
                '<div><strong>Modalità:</strong> ' + modeBadge + '</div>' +
                '<div><strong>WL CIDR:</strong> ' + (ts.panel_wl_cidrs || 0) + ' regole runtime</div>' +
                '<div><strong>BL CIDR:</strong> ' + (ts.panel_bl_cidrs || 0) + ' regole runtime</div>' +
                '<div><strong>Geo WL:</strong> ' + (ts.panel_geo_wl || 0) + ' IP</div>' +
                '<div><strong>Geo BL:</strong> ' + (ts.panel_geo_bl || 0) + ' IP</div>' +
                '</div>';
        }

        function renderFwModes() {
            const container = document.getElementById('fwModeContainer');
            container.innerHTML = FW_MODES.map(m => {
                const active = (m.value === __fwState.mode);
                const recommended = m.recommended
                    ? '<span class="badge bg-success ms-1" style="font-size:.65rem">★ CONSIGLIATO</span>' : '';
                return '<div class="col-md-6">' +
                    '<div class="fw-mode-card' + (active ? ' active' : '') + '" onclick="fwSetMode(\\'' + m.value + '\\')">' +
                    '<div><strong>' + escapeHtml(m.label) + '</strong>' + recommended + '</div>' +
                    '<div class="small text-muted mt-1">' + escapeHtml(m.desc) + '</div>' +
                    '</div></div>';
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
                    ? 'Nessun paese selezionato'
                    : (upper.length + ' paesi nel buffer');
                statusEl.className = 'small mt-1 text-muted';
            }
        }

        function fwScheduleCodeApply() {
            if (__fwCodeEditorSelfUpdate) return; // siamo noi a scrivere, ignora
            const statusEl = document.getElementById('fwCodeEditorStatus');
            if (statusEl) {
                statusEl.textContent = '⏳ Attendo la pausa di digitazione...';
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
                    setStatus('⚠ Catalogo paesi non caricato — ricarica la pagina', 'text-warning');
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
                        ? '✓ Sincronizzato (nessuna modifica). ⚠ Ignorati codici non validi: ' + invalidCodes.map(c => c.toUpperCase()).join(', ')
                        : '✓ Sincronizzato — nessuna modifica',
                        invalidCodes.length > 0 ? 'text-warning' : 'text-success');
                    return;
                }

                setStatus('⏳ Applico: +' + toAdd.length + ' aggiunte, -' + toRemove.length + ' rimozioni...', 'text-info');

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
                            throw new Error(data.error || data.message || 'risposta server fallita');
                        }
                        return data;
                    });
                };

                // Sequenziale: prima add, poi remove
                post('bulk_add_countries', toAdd)
                    .then(() => post('bulk_remove_countries', toRemove))
                    .then(() => {
                        setStatus('✓ Applicato (+' + toAdd.length + ' / -' + toRemove.length + ')'
                            + (invalidCodes.length > 0 ? ' — ignorati: ' + invalidCodes.map(c => c.toUpperCase()).join(', ') : ''),
                            'text-success');
                        loadFirewall();
                    })
                    .catch(e => {
                        setStatus('❌ Errore: ' + (e && e.message ? e.message : 'sconosciuto') + ' — riprova con "Applica adesso"', 'text-danger');
                    });
            } catch (e) {
                setStatus('❌ Errore JS: ' + (e && e.message ? e.message : 'sconosciuto'), 'text-danger');
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
                    statusEl.textContent = '✓ Copiato negli appunti';
                    statusEl.className = 'small mt-1 text-success';
                }
            } catch (e) {}
        }

        // ===== Helper: freschezza GeoIP =====
        function fmtAgo(seconds) {
            if (!seconds || seconds < 0) return 'mai';
            if (seconds < 60) return Math.floor(seconds) + 's fa';
            if (seconds < 3600) return Math.floor(seconds/60) + ' min fa';
            if (seconds < 86400) return Math.floor(seconds/3600) + ' h fa';
            const d = Math.floor(seconds/86400);
            return d + ' giorn' + (d === 1 ? 'o' : 'i') + ' fa';
        }

        function renderFreshnessBadge(freshness, cidrCount, agoSec) {
            if (!freshness || freshness === 'NEVER') {
                return '<span class="text-danger">⚠ mai sync</span>';
            }
            const ago = fmtAgo(agoSec);
            if (freshness === 'FRESH') {
                return '<span class="text-success">✓ ' + cidrCount + ' CIDR · ' + ago + '</span>';
            }
            if (freshness === 'AGING') {
                return '<span class="text-warning">⏰ ' + cidrCount + ' CIDR · ' + ago + '</span>';
            }
            if (freshness === 'STALE') {
                return '<span class="text-warning">⚠ vecchio · ' + ago + '</span>';
            }
            return '<span class="text-danger">⚠⚠ obsoleto · ' + ago + '</span>';
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
                    ? '<span class="badge bg-success ms-2">ATTIVO ogni ' + (a.interval_days || 7) + ' giorni</span>'
                    : '<span class="badge bg-secondary ms-2">INATTIVO</span>';
            }

            // Summary
            if (summaryEl) {
                const lines = [];
                if (a.last_check_ms) {
                    const checkAgo = fmtAgo((Date.now() - a.last_check_ms) / 1000);
                    lines.push('<i class="fas fa-clock me-1 text-muted"></i>Ultimo controllo: <strong>' + checkAgo + '</strong>');
                }
                if (a.last_run_ms) {
                    const runAgo = fmtAgo((Date.now() - a.last_run_ms) / 1000);
                    lines.push('<i class="fas fa-cloud-download-alt me-1 text-muted"></i>Ultimo download eseguito: <strong>' + runAgo + '</strong>');
                } else {
                    lines.push('<i class="fas fa-cloud-download-alt me-1 text-muted"></i>Nessun download automatico ancora eseguito');
                }
                if (a.stale_countries_count > 0) {
                    lines.push('<i class="fas fa-exclamation-triangle me-1 text-warning"></i><span class="text-warning"><strong>' + a.stale_countries_count + ' paesi</strong> da aggiornare</span>');
                } else if (__fwState.geo_countries && __fwState.geo_countries.length > 0) {
                    lines.push('<i class="fas fa-check-circle me-1 text-success"></i><span class="text-success">Tutti i paesi sono aggiornati</span>');
                }
                summaryEl.innerHTML = lines.join(' &nbsp;·&nbsp; ');
            }
        }

        function fwSaveAutoSync() {
            const enabled = document.getElementById('fwAutoSyncEnabled').checked;
            const interval = parseInt(document.getElementById('fwAutoSyncInterval').value, 10) || 7;
            fwPost({ action: 'set_auto_sync', enabled: enabled, interval_days: interval }, (data) => {
                alert(data.message || 'Salvato');
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
                    badge = '<i class="fas fa-check ms-1" title="Selezione esattamente uguale al preset"></i>';
                } else if (isFullyContained) {
                    // Tutto il preset e' nella selezione + altri extra
                    cls = 'btn-success';
                    badge = '<i class="fas fa-check-double ms-1" title="Tutti i paesi del preset sono già selezionati (con extra)"></i>';
                } else if (matchCount > 0) {
                    // Solo alcuni paesi del preset selezionati
                    badge = '<span class="badge bg-light text-dark ms-1" style="font-size:.65rem">' + matchCount + '/' + codes.length + '</span>';
                } else {
                    // Nessun paese del preset selezionato
                    badge = '<span class="badge bg-light text-dark ms-1" style="font-size:.65rem">' + codes.length + '</span>';
                }
                return '<button type="button" class="btn btn-sm ' + cls + '" '
                     + 'onclick="fwApplyPresetGroup(\\'' + escapeHtml(g.id) + '\\')" '
                     + 'title="' + escapeHtml(g.description || '') + '">'
                     + (g.icon || '') + ' ' + escapeHtml(g.label) + badge
                     + '</button>';
            }).join('');
        }

        // Helper: rende leggibile una lista di codici paese (es. "🇮🇹 Italia (IT), 🇺🇸 Stati Uniti (US)")
        function fwFormatCountryList(codes, maxShow) {
            if (!codes || codes.length === 0) return '(nessuno)';
            const catalogMap = new Map();
            (__fwCatalog || []).forEach(c => catalogMap.set(c.code, c));
            const formatted = codes.map(code => {
                const meta = catalogMap.get(code);
                if (meta) return meta.flag + ' ' + meta.name + ' (' + code.toUpperCase() + ')';
                return code.toUpperCase();
            });
            if (maxShow && formatted.length > maxShow) {
                const shown = formatted.slice(0, maxShow).join(', ');
                return shown + ', ... e altri ' + (formatted.length - maxShow);
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
                    alert('Tutti i paesi del preset "' + grp.label + '" sono già selezionati.');
                    return;
                }
                const msg = 'Aggiungere ' + toAdd.length + ' nuov' + (toAdd.length === 1 ? 'o paese' : 'i paesi') + ' dal preset "' + grp.label + '"?\\n\\n' +
                    'Paese da aggiungere:\\n' + fwFormatCountryList(toAdd, 20) + '\\n\\n' +
                    'La selezione corrente di ' + existing.size + ' paesi viene MANTENUTA e ampliata a ' + (existing.size + toAdd.length) + ' paesi totali.';
                if (!confirm(msg)) return;
                fwPost({ action: 'bulk_add_countries', countries: toAdd }, () => loadFirewall());
            } else {
                // Modalita' SOSTITUISCI: dettagliamo chi viene aggiunto e chi rimosso
                const existing = new Set(__fwState.geo_countries || []);
                const targetSet = new Set(grp.codes);
                const toAdd = grp.codes.filter(c => !existing.has(c));
                const toRemove = [...existing].filter(c => !targetSet.has(c));

                let msg = 'Sostituire la selezione corrente con il preset "' + grp.label + '"?\\n\\n';
                msg += 'Nuova selezione: ' + grp.codes.length + ' paesi (preset "' + grp.label + '")\\n\\n';
                if (toRemove.length > 0) {
                    msg += '❌ Verranno RIMOSSI ' + toRemove.length + ' paesi:\\n' + fwFormatCountryList(toRemove, 15) + '\\n\\n';
                }
                if (toAdd.length > 0) {
                    msg += '✅ Verranno AGGIUNTI ' + toAdd.length + ' paesi:\\n' + fwFormatCountryList(toAdd, 15) + '\\n\\n';
                }
                if (toAdd.length === 0 && toRemove.length === 0) {
                    msg += '(Nessuna modifica — la selezione corrisponde già al preset)';
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
            if (codes.length === 0) { alert('Nessun paese visibile'); return; }
            const alreadySelected = new Set(__fwState.geo_countries || []);
            const toAdd = codes.filter(c => !alreadySelected.has(c));
            if (toAdd.length === 0) { alert('Tutti i paesi visibili sono gia\\' selezionati'); return; }
            if (!confirm('Aggiungere ' + toAdd.length + ' paesi alla selezione?')) return;
            fwPost({ action: 'bulk_add_countries', countries: toAdd }, () => loadFirewall());
        }

        function fwDeselectAllVisible() {
            const codes = fwGetVisibleCountryCodes();
            const selected = new Set(__fwState.geo_countries || []);
            const toRemove = codes.filter(c => selected.has(c));
            if (toRemove.length === 0) { alert('Nessun paese visibile e\\' selezionato'); return; }
            if (!confirm('Deselezionare ' + toRemove.length + ' paesi visibili?')) return;
            fwPost({ action: 'bulk_remove_countries', countries: toRemove }, () => loadFirewall());
        }

        function fwClearAllCountries() {
            const n = (__fwState.geo_countries || []).length;
            if (n === 0) { alert('Nessun paese selezionato'); return; }
            if (!confirm('Rimuovere TUTTI i ' + n + ' paesi attualmente selezionati?')) return;
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
                const nameHtml = isSelected
                    ? '<strong>' + escapeHtml(c.name) + '</strong>'
                    : escapeHtml(c.name);
                return '<label class="fw-country-item' + selClass + '" data-cc="' + c.code + '" data-name="' + escapeHtml(c.name.toLowerCase()) + '" data-common="' + (c.common ? '1' : '0') + '">' +
                       '<input type="checkbox" onchange="fwToggleCountry(\\'' + c.code + '\\', this.checked)"' + isChecked + '>' +
                       '<span class="flag">' + c.flag + '</span>' +
                       '<span>' + nameHtml + '</span>' +
                       '<span class="text-muted small">(' + c.code + ')</span>' +
                       cidrBadge +
                       '</label>';
            };

            // Lista UNICA in ordine alfabetico italiano
            const all = __fwCatalog.slice().sort((a, b) => a.name.localeCompare(b.name, 'it'));
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
                btn.innerHTML = '<i class="fas fa-filter me-1"></i>Mostra tutti';
            } else {
                btn.classList.add('btn-outline-info');
                btn.classList.remove('btn-info');
                btn.innerHTML = '<i class="fas fa-filter me-1"></i>Mostra solo selezionati';
            }
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
                    ? 'Paesi disponibili (' + visible + ' visibili su ' + total + ')'
                    : 'Paesi disponibili (' + total + ')';
            }
        }

        function fwToggleCountry(cc, checked) {
            fwPost({ action: checked ? 'add_country' : 'remove_country', country: cc }, () => loadFirewall());
        }

        function fwSyncAll() {
            const selectedCount = (__fwState && __fwState.geo_countries) ? __fwState.geo_countries.length : 0;
            if (selectedCount === 0) {
                alert('⚠ Nessun paese selezionato.\\n\\n' +
                    'Il sync scarica i range IP SOLO dei paesi che hai selezionato qui sotto (per non occupare banda con dati inutili).\\n\\n' +
                    'Procedi cosi\\':\\n' +
                    '1. Seleziona uno o piu\\' paesi (clicca su un preset come "EU + EFTA" o spunta singoli paesi)\\n' +
                    '2. Torna qui e clicca "Sincronizza ora"');
                return;
            }
            if (!confirm('Scaricare i range IP per ' + selectedCount + ' paese' + (selectedCount === 1 ? '' : 'i') + ' selezionato' + (selectedCount === 1 ? '' : 'i') + ' da ipdeny.com?\\n\\nTempo stimato: ~' + Math.max(2, selectedCount * 2) + ' secondi.')) return;
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
                list.innerHTML = '<span class="text-muted small">Nessun IP in ' + (kind === 'wl' ? 'whitelist' : 'blacklist') + '</span>';
                return;
            }
            list.innerHTML = cidrs.map(c =>
                '<span class="fw-cidr-item"><code>' + escapeHtml(c) + '</code>' +
                '<button class="btn-remove" onclick="fwRemoveCidr(\\'' + kind + '\\', \\'' + escapeHtml(c) + '\\')" title="Rimuovi"><i class="fas fa-times"></i></button>' +
                '</span>'
            ).join('');
        }

        function fwAddCidr(kind) {
            const input = document.getElementById(kind === 'wl' ? 'fwWlInput' : 'fwBlInput');
            const cidr = (input.value || '').trim();
            if (!cidr) { alert('Inserisci un IP/CIDR'); return; }
            fwPost({ action: kind === 'wl' ? 'add_cidr_wl' : 'add_cidr_bl', cidr: cidr }, (data) => {
                if (data.success) input.value = '';
                else alert(data.message || 'Errore');
                loadFirewall();
            });
        }

        function fwRemoveCidr(kind, cidr) {
            if (!confirm('Rimuovere ' + cidr + ' dalla ' + (kind === 'wl' ? 'whitelist' : 'blacklist') + '?')) return;
            fwPost({ action: kind === 'wl' ? 'remove_cidr_wl' : 'remove_cidr_bl', cidr: cidr }, () => loadFirewall());
        }

        // ===== Apply =====
        function fwApply() {
            if (!confirm('Applicare la configurazione firewall?\\n\\n' +
                'Verra\\' rigenerato l\\'anchor /etc/pf.anchors/panel-fw.conf,\\n' +
                'fatto un syntax check con pfctl -nf,\\n' +
                'creato un backup dell\\'anchor precedente,\\n' +
                'e caricato nel kernel.\\n\\n' +
                'Assicurati di aver aggiunto il TUO IP alla whitelist CIDR\\n' +
                'se stai usando la modalita\\' Geo Whitelist.')) return;
            fwPost({ action: 'apply' }, (data) => {
                let msg = data.message || '';
                if (data.backup_path) msg += '\\n\\nBackup: ' + data.backup_path;
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
            }).catch(e => alert('Errore rete: ' + e.message));
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
        return getHead("Cloudflare", extraStyles) + getNavbar("cloudflare") + """
    <div class="content container mt-4" style="max-width: 1100px">

        <div class="d-flex justify-content-between align-items-center mb-3 flex-wrap gap-2">
            <h2 class="mb-0"><i class="fas fa-cloud me-2" style="color:#f6821f"></i>Cloudflare <small class="text-muted fs-6">— certificato hostname server mail (<code>{{MAIL_HOSTNAME}}</code>)</small></h2>
            <button class="btn btn-outline-secondary btn-sm" onclick="cfLoad()" title="Ricarica">
                <i class="fas fa-sync"></i> Ricarica
            </button>
        </div>

        <p class="text-muted">
            Collega uno o più account Cloudflare al pannello inserendo un <strong>API token</strong>.
            Il token viene usato per pubblicare automaticamente i record DNS (DKIM, validazione SSL/ACME)
            e per il <strong>rinnovo automatico del certificato del server mail</strong> qui sotto.
            L'assegnazione degli account ai <strong>domini delle caselle</strong> si gestisce nella pagina
            <a href="/dns">DNS</a>.
        </p>

        <!-- ===== Form: aggiungi / modifica account ===== -->
        <div class="card mb-4 cf-form-card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <span><i class="fas fa-plus-circle me-2"></i><span id="cfFormTitle">Aggiungi account Cloudflare</span></span>
                <button class="btn btn-sm btn-outline-secondary" id="cfCancelEditBtn" style="display:none" onclick="cfResetForm()">
                    <i class="fas fa-times me-1"></i>Annulla modifica
                </button>
            </div>
            <div class="card-body">
                <input type="hidden" id="cfEditingId" value="0">
                <div class="row g-3">
                    <div class="col-md-6">
                        <label class="form-label">Descrizione / Etichetta <span class="text-danger">*</span></label>
                        <input type="text" class="form-control" id="cfLabel" maxlength="100"
                               placeholder="es. Account personale, Cliente Rossi...">
                        <small class="text-muted">Promemoria personale per ricordarti a cosa serve questo token.</small>
                    </div>
                    <div class="col-md-6">
                        <label class="form-label">Email Cloudflare associata</label>
                        <input type="email" class="form-control" id="cfEmail" maxlength="200"
                               placeholder="es. mario@example.com">
                        <small class="text-muted">Solo informativa: a quale account/email è legato il token.</small>
                    </div>
                    <div class="col-12">
                        <label class="form-label">API Token <span class="text-danger">*</span></label>
                        <div class="input-group">
                            <input type="password" class="form-control" id="cfToken" autocomplete="off"
                                   placeholder="Incolla qui l'API token Cloudflare">
                            <button class="btn btn-outline-secondary" type="button" onclick="cfToggleToken()" title="Mostra/nascondi">
                                <i class="fas fa-eye" id="cfTokenEye"></i>
                            </button>
                            <button class="btn btn-outline-info" type="button" onclick="cfTest()">
                                <i class="fas fa-vial me-1"></i>Verifica token
                            </button>
                        </div>
                        <small class="text-muted" id="cfTokenHint">
                            In modifica: lascia vuoto per <strong>mantenere</strong> il token attuale.
                        </small>
                        <div id="cfTestResult" class="mt-2"></div>
                    </div>
                </div>
                <div class="mt-3">
                    <button class="btn btn-primary" onclick="cfSave()">
                        <i class="fas fa-save me-1"></i><span id="cfSaveLabel">Verifica e salva account</span>
                    </button>
                </div>
            </div>
        </div>

        <!-- ===== Lista account ===== -->
        <div class="card mb-4 cf-account-card">
            <div class="card-header"><i class="fas fa-key me-2"></i>Account configurati</div>
            <div class="card-body">
                <div id="cfAccountsBox">
                    <p class="text-muted mb-0"><i class="fas fa-spinner fa-spin me-1"></i>Caricamento...</p>
                </div>
            </div>
        </div>

        <!-- ===== Certificato del server mail (Mail Hostname) ===== -->
        <div class="card mb-4" style="border-left:4px solid #198754">
            <div class="card-header"><i class="fas fa-server me-2"></i>Certificato SSL del server mail</div>
            <div class="card-body">
                <p class="small text-muted mb-2">
                    Questo è il certificato del <strong>Mail Hostname</strong> (il nome del server mail,
                    es. <code>mail.tuodominio.com</code>) usato da Postfix e Dovecot. È un certificato a sé,
                    <strong>diverso dai domini delle caselle</strong>: il suo dominio base potrebbe
                    non essere tra i domini mail. Collega l'account Cloudflare che gestisce il DNS di
                    <strong>questo</strong> hostname per abilitare il rinnovo automatico del certificato.
                </p>
                <div id="cfMailServerBox">
                    <p class="text-muted mb-0"><i class="fas fa-spinner fa-spin me-1"></i>Caricamento...</p>
                </div>
            </div>
        </div>


        <!-- ===== Aiuto: come creare il token ===== -->
        <div class="card mb-4 cf-help">
            <div class="card-header"><i class="fas fa-circle-question me-2"></i>Come ottenere l'API token</div>
            <div class="card-body small">
                <ol class="mb-2">
                    <li>Vai su <code>dash.cloudflare.com</code> → in alto a destra, <strong>My Profile</strong> → <strong>API Tokens</strong>.</li>
                    <li>Clicca <strong>Create Token</strong> → usa il template <strong>Edit zone DNS</strong> (oppure "Custom token").</li>
                    <li>Assegna i permessi: <code>Zone → DNS → Edit</code> e <code>Zone → Zone → Read</code>.</li>
                    <li>In <em>Zone Resources</em> includi le zone (domini) che gestisci con questo pannello.</li>
                    <li>Crea il token, copialo e incollalo qui sopra.</li>
                </ol>
                <div class="alert alert-warning py-2 mb-0">
                    <i class="fas fa-shield-halved me-1"></i>
                    Il token viene salvato nel database del pannello e mostrato solo in forma mascherata.
                    Usa un token "scoped" con i soli permessi indicati, mai la Global API Key.
                </div>
            </div>
        </div>

    </div>

""" + getFooter() + """
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
              .catch(e => alert('Errore di rete: ' + e.message));
        }

        function cfLoad() {
            fetch('/api/cloudflare').then(r => r.json()).then(data => {
                cfState.accounts = data.accounts || [];
                cfState.mailServer = data.mail_server || null;
                cfRenderAccounts();
                cfRenderMailServer();
            }).catch(e => {
                document.getElementById('cfAccountsBox').innerHTML =
                    '<div class="alert alert-danger mb-0">Errore caricamento: ' + escCf(e.message) + '</div>';
            });
        }

        function cfRenderAccounts() {
            const box = document.getElementById('cfAccountsBox');
            if (!cfState.accounts.length) {
                box.innerHTML = '<p class="text-muted mb-0">Nessun account Cloudflare configurato. Aggiungine uno qui sopra.</p>';
                return;
            }
            let html = '<div class="table-responsive"><table class="table table-striped align-middle mb-0">'
                + '<thead><tr><th>Descrizione</th><th>Email</th><th>Token</th><th>Verificato</th><th class="text-end">Azioni</th></tr></thead><tbody>';
            cfState.accounts.forEach(a => {
                const verified = a.verified_at ? ('<span class="text-success"><i class="fas fa-check-circle me-1"></i>'
                    + escCf((a.verified_at || '').replace('T', ' ').substring(0, 16)) + '</span>')
                    : '<span class="text-muted">—</span>';
                html += '<tr>'
                    + '<td><strong>' + escCf(a.label || '(senza nome)') + '</strong></td>'
                    + '<td>' + (a.email ? escCf(a.email) : '<span class="text-muted">—</span>') + '</td>'
                    + '<td class="cf-token-cell">' + escCf(a.token_masked || '••••') + '</td>'
                    + '<td>' + verified + '</td>'
                    + '<td class="text-end">'
                    + '<button class="btn btn-sm btn-outline-primary me-1" onclick="cfEdit(' + a.id + ')"><i class="fas fa-pen"></i></button>'
                    + '<button class="btn btn-sm btn-outline-danger" onclick="cfDelete(' + a.id + ')"><i class="fas fa-trash"></i></button>'
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
            if (!host || host === 'Non configurato' || host.indexOf('{{') === 0) host = ms.hostname || '';
            if (!host) {
                box.innerHTML = '<div class="alert alert-warning py-2 mb-0">Mail Hostname non configurato. Completa prima l\\'installazione del server mail.</div>';
                return;
            }
            const cur = ms.cloudflare_account_id || 0;
            let opts = '<option value="0"' + (cur === 0 ? ' selected' : '') + '>Manuale (nessun account)</option>';
            cfState.accounts.forEach(a => {
                opts += '<option value="' + a.id + '"' + (cur === a.id ? ' selected' : '') + '>'
                    + escCf(a.label || ('account #' + a.id)) + '</option>';
            });
            let status = cur > 0
                ? '<span class="badge bg-success"><i class="fas fa-check me-1"></i>Rinnovo automatico attivo</span>'
                : '<span class="badge bg-secondary"><i class="fas fa-hand me-1"></i>Manuale</span>';
            box.innerHTML = '<div class="table-responsive"><table class="table align-middle mb-2">'
                + '<thead><tr><th>Mail Hostname (certificato SSL)</th><th style="width:340px">Account Cloudflare</th></tr></thead><tbody>'
                + '<tr>'
                + '<td><i class="fas fa-server me-1 text-success"></i><strong>' + escCf(host) + '</strong> ' + status + '</td>'
                + '<td><select class="form-select form-select-sm" id="cfMailServerSelect" onchange="cfAssignMailServer(this.value)">' + opts + '</select></td>'
                + '</tr></tbody></table></div>'
                + '<button class="btn btn-outline-info btn-sm" onclick="cfTestMailServer()">'
                + '<i class="fas fa-plug me-1"></i>Verifica collegamento</button>'
                + '<div id="cfMailServerTest" class="mt-2"></div>'
                + '<div class="small text-muted mt-2"><i class="fas fa-info-circle me-1"></i>Il token dell\\'account scelto deve avere accesso alla zona DNS di <code>' + escCf(host) + '</code> (permessi Zone:DNS:Edit + Zone:Read).</div>';
        }

        function cfTestMailServer() {
            const sel = document.getElementById('cfMailServerSelect');
            const accountId = sel ? (parseInt(sel.value, 10) || 0) : 0;
            const out = document.getElementById('cfMailServerTest');
            if (accountId <= 0) {
                out.innerHTML = '<div class="alert alert-warning py-2 mb-0">Seleziona prima un account Cloudflare dal menu.</div>';
                return;
            }
            out.innerHTML = '<span class="text-muted"><i class="fas fa-spinner fa-spin me-1"></i>Verifica token e zona DNS in corso...</span>';
            cfPost({ action: 'test_mailserver', account_id: accountId }, data => {
                if (data.success) {
                    out.innerHTML = '<div class="alert alert-success py-2 mb-0"><i class="fas fa-check-circle me-1"></i>'
                        + escCf(data.message || 'Collegamento OK') + '</div>';
                } else {
                    out.innerHTML = '<div class="alert alert-danger py-2 mb-0"><i class="fas fa-times-circle me-1"></i>'
                        + escCf(data.error || data.message || 'Verifica fallita') + '</div>';
                }
            });
        }

        function cfAssignMailServer(accountId) {
            cfPost({ action: 'assign_mailserver', account_id: parseInt(accountId, 10) || 0 }, data => {
                if (!data.success) { alert('✗ ' + (data.message || data.error || 'Assegnazione fallita')); }
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
            if (!token) { out.innerHTML = '<div class="alert alert-warning py-2 mb-0">Inserisci un token da verificare.</div>'; return; }
            out.innerHTML = '<span class="text-muted"><i class="fas fa-spinner fa-spin me-1"></i>Verifica in corso...</span>';
            cfPost({ action: 'test', token: token }, data => {
                if (data.success) {
                    out.innerHTML = '<div class="alert alert-success py-2 mb-0"><i class="fas fa-check-circle me-1"></i>'
                        + escCf(data.message || 'Token valido') + '</div>';
                } else {
                    out.innerHTML = '<div class="alert alert-danger py-2 mb-0"><i class="fas fa-times-circle me-1"></i>'
                        + escCf(data.message || data.error || 'Token non valido') + '</div>';
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
            document.getElementById('cfFormTitle').textContent = 'Modifica account: ' + (a.label || ('#' + id));
            document.getElementById('cfSaveLabel').textContent = 'Salva modifiche';
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
            document.getElementById('cfFormTitle').textContent = 'Aggiungi account Cloudflare';
            document.getElementById('cfSaveLabel').textContent = 'Verifica e salva account';
            document.getElementById('cfCancelEditBtn').style.display = 'none';
            document.getElementById('cfTestResult').innerHTML = '';
        }

        function cfSave() {
            const id = parseInt(document.getElementById('cfEditingId').value, 10) || 0;
            const label = document.getElementById('cfLabel').value.trim();
            const email = document.getElementById('cfEmail').value.trim();
            const token = document.getElementById('cfToken').value.trim();

            if (!label) { alert('Inserisci una descrizione/etichetta.'); return; }
            if (id === 0 && !token) { alert('Inserisci l\\'API token.'); return; }

            const body = id > 0
                ? { action: 'update', account_id: id, label: label, email: email }
                : { action: 'add', label: label, email: email, token: token };
            if (token) body.token = token;

            cfPost(body, data => {
                if (data.success) {
                    cfResetForm();
                    cfLoad();
                    alert('✓ ' + (data.message || 'Salvato'));
                } else {
                    alert('✗ ' + (data.message || data.error || 'Operazione fallita'));
                }
            });
        }

        function cfDelete(id) {
            const a = cfState.accounts.find(x => x.id === id);
            const name = a ? (a.label || ('#' + id)) : ('#' + id);
            if (!confirm('Eliminare l\\'account "' + name + '"?\\nI domini collegati torneranno in modalità manuale.')) return;
            cfPost({ action: 'delete', account_id: id }, data => {
                alert((data.success ? '✓ ' : '✗ ') + (data.message || data.error || ''));
                cfLoad();
            });
        }

        // Init
        cfLoad();
""" + getLogoutScript() + """
    </script>
</body>
</html>
""";
    }

    // ============== PATHS.HTML — Diagnostic page con tutti i path usati dal pannello ==============
    public static String getPathsHtml() {
        String extraStyles = """
        .path-entry { display: flex; flex-direction: column; padding: 12px; border-left: 4px solid #6c757d; background: #f8f9fa; border-radius: 4px; margin-bottom: 8px; }
        .path-entry.exists { border-color: #28a745; }
        .path-entry.missing { border-color: #dc3545; }
        .path-entry.directory { border-color: #17a2b8; }
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
        .copy-btn.copied { background: #28a745; color: white; border-color: #28a745; }
        """;
        return getHead("Path di Sistema", extraStyles) + getNavbar("paths") + """
    <div class="content container mt-4">
        <div class="content-container">
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h2><i class="fas fa-folder-tree me-2"></i>Path di Sistema</h2>
                <button class="btn btn-outline-primary btn-sm" onclick="loadPaths()">
                    <i class="fas fa-sync me-1"></i>Aggiorna
                </button>
            </div>
            <p class="text-muted mb-3">Tutti i file e directory che il pannello sta usando. Verde = esiste, rosso = mancante. Clicca un path per selezionarlo, o usa il pulsante Copia.</p>

            <div class="d-flex gap-3 mb-3 align-items-center">
                <input type="text" id="pathSearch" class="form-control form-control-sm" style="max-width:300px" placeholder="🔎 Filtra path o etichetta..." oninput="filterPaths()">
                <span class="small text-muted" id="pathStats">-</span>
            </div>

            <div id="pathsContainer">
                <p class="text-muted"><i class="fas fa-spinner fa-spin me-1"></i>Caricamento...</p>
            </div>
        </div>
    </div>
""" + getFooter() + """
    <script>
        let allCategories = [];

        function loadPaths() {
            const c = document.getElementById('pathsContainer');
            c.innerHTML = '<p class="text-muted"><i class="fas fa-spinner fa-spin me-1"></i>Caricamento...</p>';
            fetch('/api/system_paths')
                .then(r => r.json())
                .then(data => {
                    if (!data.success) {
                        c.innerHTML = '<div class="alert alert-danger">Errore: ' + (data.error || 'sconosciuto') + '</div>';
                        return;
                    }
                    allCategories = data.categories || [];
                    renderPaths(allCategories);
                })
                .catch(e => {
                    c.innerHTML = '<div class="alert alert-danger">Errore rete: ' + e.message + '</div>';
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
                    if (entry.exists) html += '<i class="fas fa-' + (entry.is_directory ? 'folder' : 'file') + ' text-' + (entry.is_directory ? 'info' : 'success') + ' me-1"></i>';
                    else html += '<i class="fas fa-times-circle text-danger me-1"></i>';
                    html += escapePathHtml(entry.label) + '</div>';
                    if (entry.description) html += '<div class="path-desc text-muted">' + escapePathHtml(entry.description) + '</div>';
                    html += '<div class="mt-1"><code class="path-code">' + escapePathHtml(entry.path) + '</code></div>';
                    // Meta
                    let meta = [];
                    if (entry.exists) {
                        if (entry.size !== undefined) meta.push(formatSize(entry.size));
                        if (entry.perms) meta.push('perms: ' + entry.perms);
                        if (entry.modified) meta.push('mtime: ' + entry.modified.substring(0, 19).replace('T', ' '));
                        if (entry.readable === false) meta.push('<span class="text-warning">non leggibile</span>');
                    } else {
                        meta.push('<span class="text-danger">non esiste</span>');
                    }
                    if (meta.length > 0) html += '<div class="path-meta mt-1">' + meta.join(' • ') + '</div>';
                    html += '</div>';
                    html += '<button class="copy-btn" onclick="copyPath(this, \\'' + escapeForJs(entry.path) + '\\')"><i class="fas fa-copy"></i> Copia</button>';
                    html += '</div>';
                    html += '</div>';
                });
                html += '</div></div>';
            });
            c.innerHTML = html;
            document.getElementById('pathStats').textContent =
                totalExists + '/' + totalEntries + ' path esistenti';
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
                btn.innerHTML = '<i class="fas fa-check"></i> Copiato';
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
""" + getLogoutScript() + """
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
        return getHead("Aggiornamenti", "updates", extraStyles) + """
    <div class="content container mt-4">
        <div class="content-container">
            <h2><i class="fas fa-arrow-up-right-dots me-2"></i>Aggiornamenti e protezione</h2>
            <p class="text-muted">
                Il pannello non si limita a dire che esistono aggiornamenti: verifica se <strong>questo</strong>
                aggiornamento romperebbe <strong>questo</strong> server di posta, e impedisce quelli che lo romperebbero.
            </p>

            <div class="card mb-4 border-primary">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-list-check me-2"></i><strong>Piano di manutenzione</strong>
                        <span class="small text-muted ms-2">cosa va fatto su questa macchina, in ordine</span></span>
                    <button class="btn btn-sm btn-primary" onclick="planLoad()"><i class="fas fa-rotate me-1"></i>Calcola il piano</button>
                </div>
                <div class="card-body">
                    <p class="small text-muted mb-2">
                        Lo stato di ogni passo non &egrave; memorizzato: viene ricavato ogni volta dal sistema reale,
                        cos&igrave; non pu&ograve; dire &ldquo;fatto&rdquo; per qualcosa che non lo &egrave; pi&ugrave;.
                        Le <strong>fasi</strong> hanno una lettera fissa; i <strong>pacchetti</strong> si chiamano col proprio
                        nome e spariscono dall&rsquo;elenco quando non hanno pi&ugrave; nulla da fare. Nessuna etichetta cambia
                        significato mentre lavori. &Egrave; attivo solo il primo passo da fare, dall&rsquo;alto.
                    </p>
                    <div id="plan-body"><span class="text-muted">Premi "Calcola il piano": legge lo stato, non modifica niente.</span></div>
                    <pre id="plan-log" class="upd-log mt-2" style="display:none"></pre>
                </div>
            </div>

            <div class="card mb-4">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-vial me-2"></i><strong>Compatibilità della configurazione</strong>
                        <span class="small text-muted ms-2">non i numeri di versione: cosa c&rsquo;è scritto nei file</span></span>
                    <div class="text-nowrap">
                        <button class="btn btn-sm btn-outline-primary me-1" onclick="updCompat()"><i class="fas fa-magnifying-glass me-1"></i>Verifica</button>
                        <button class="btn btn-sm btn-outline-secondary me-1" onclick="updDumpDovecot()" title="Mostra i file che Dovecot legge davvero"><i class="fas fa-file-code me-1"></i>Mostra config Dovecot</button>
                        <button class="btn btn-sm btn-outline-warning" onclick="updRegenDovecot()" title="Riscrive la configurazione dalla sorgente unica, senza toccare i pacchetti"><i class="fas fa-wand-magic-sparkles me-1"></i>Rigenera config Dovecot</button>
                    </div>
                </div>
                <div class="card-body">
                    <div id="upd-compat"><span class="text-muted">Premi "Verifica": legge i file di configurazione, non modifica niente.</span></div>
                    <div id="upd-dovecot-dump" class="mt-3"></div>
                </div>
            </div>

            <div class="card mb-4">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-shield-halved me-2"></i><strong>Protezione pacchetti</strong>
                        <span class="small text-muted ms-2">impedisce che un aggiornamento sostituisca o rimuova un pezzo dello stack</span></span>
                    <div class="text-nowrap">
                        <button class="btn btn-sm btn-outline-success me-1" onclick="updLockAll(true)"><i class="fas fa-lock me-1"></i>Proteggi tutto</button>
                        <button class="btn btn-sm btn-outline-secondary me-1" onclick="updLockAll(false)"><i class="fas fa-lock-open me-1"></i>Sblocca tutto</button>
                        <button class="btn btn-sm btn-outline-primary" onclick="updPackages()"><i class="fas fa-sync-alt me-1"></i>Aggiorna</button>
                    </div>
                </div>
                <div class="card-body">
                    <div id="upd-packages"><span class="text-muted">Premi "Aggiorna" per vedere lo stato dei pacchetti.</span></div>
                </div>
            </div>

            <div class="card mb-4">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-download me-2"></i><strong>Aggiornamenti e vulnerabilità</strong>
                        <span class="small text-muted ms-2">simulazione: non modifica niente</span></span>
                    <div class="text-nowrap">
                        <button class="btn btn-sm btn-outline-primary me-1" onclick="updStatus()"><i class="fas fa-magnifying-glass me-1"></i>Verifica</button>
                        <button class="btn btn-sm btn-outline-warning me-1" onclick="updApply()" title="Aggiorna solo i pacchetti NON protetti"><i class="fas fa-download me-1"></i>Aggiorna non protetti</button>
                        <button class="btn btn-sm btn-outline-danger" onclick="updMaintPreview()" title="Sblocca, aggiorna, riprotegge"><i class="fas fa-screwdriver-wrench me-1"></i>Manutenzione completa</button>
                    </div>
                </div>
                <div class="card-body">
                    <div id="upd-status"><span class="text-muted">Premi "Verifica" per la simulazione.</span></div>
                    <pre id="upd-log" class="upd-log mt-2" style="display:none"></pre>
                </div>
            </div>

            <div class="card mb-4 border-warning">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-database me-2"></i><strong>Migrazione MySQL 8.0 &rarr; 8.4</strong>
                        <span class="small text-muted ms-2">il port mysql80 sar&agrave; rimosso da FreeBSD dopo il 31/12/2026</span></span>
                    <button class="btn btn-sm btn-outline-warning" onclick="my84Pre()"><i class="fas fa-clipboard-check me-1"></i>Verifica prerequisiti</button>
                </div>
                <div class="card-body">
                    <p class="small text-muted mb-2">
                        Su FreeBSD la 8.4 &egrave; un pacchetto <strong>diverso e in conflitto</strong>: nessun aggiornamento
                        ci arriva. Qui il punto delicato non &egrave; il database ma la <strong>libreria client</strong>:
                        Postfix e Dovecot leggono le caselle attraverso di essa, e vanno verificati prima di sostituirla.
                    </p>
                    <div id="my84-pre"><span class="text-muted">Premi "Verifica prerequisiti": legge e basta, non modifica niente.</span></div>
                </div>
            </div>

            <div class="card mb-4">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span><i class="fas fa-route me-2"></i><strong>Aggiornamento guidato di un pacchetto protetto</strong>
                        <span class="small text-muted ms-2">sblocca, aggiorna, riavvia i servizi, riprotegge &mdash; e verifica ogni passo</span></span>
                    <button class="btn btn-sm btn-outline-primary" onclick="guidList()"><i class="fas fa-list me-1"></i>Elenca candidati</button>
                </div>
                <div class="card-body">
                    <p class="small text-muted mb-2">
                        Aggiornare il pacchetto non aggiorna il processo gi&agrave; in esecuzione: senza riavviare i servizi
                        che lo usano, la correzione risulta installata ma <strong>non &egrave; in servizio</strong>.
                        Qui lo fa il pannello, e verifica che sia successo davvero confrontando il pid prima e dopo.
                    </p>
                    <div id="guid-list"><span class="text-muted">Premi "Elenca candidati" per vedere i pacchetti protetti che hanno un aggiornamento.</span></div>
                    <div id="guid-detail" class="mt-3"></div>
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
        return """
        let updBusy = false;

        // Le operazioni su pkg toccano la rete e durano decine di secondi, tenendo occupato
        // un thread HTTP del pannello: due click o due schede bastano a saturarlo. La guardia
        // sta qui, in un punto solo, invece che dentro ogni funzione.
        async function updApi(action, extra) {
            if (updBusy) return { success: false, error: 'Operazione gia\\' in corso: attendi che finisca.' };
            const lento = action !== 'job_status';
            if (lento) updBusy = true;
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
                return { success: false, error: 'Errore di rete: ' + e.message };
            } finally {
                if (lento) updBusy = false;
            }
        }

        function updEsc(t) {
            const d = document.createElement('div');
            d.textContent = t === null || t === undefined ? '' : String(t);
            return d.innerHTML;
        }

        function updBadge(level) {
            if (level === 'ok') return '<span class="badge upd-badge-ok">OK</span>';
            if (level === 'verifica') return '<span class="badge upd-badge-warn">VERIFICA</span>';
            return '<span class="badge upd-badge-stop">ATTENDI</span>';
        }

        // ---------- compatibilita' ----------
        async function updCompat() {
            const el = document.getElementById('upd-compat');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Leggo i file di configurazione...';
            const r = await updApi('compatibility');
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            let h = '';

            const d = r.dovecot || {};
            h += '<h6 class="mb-1"><i class="fas fa-inbox me-1"></i>Dovecot</h6>';
            h += '<div class="small text-muted mb-2">installato ' + updEsc(d.installed || '?')
               + ' &middot; disponibile nel repository ' + updEsc(d.available || '?')
               + ' &middot; ' + updEsc(d.configFilesScanned || 0) + ' file letti (solo quelli che Dovecot apre davvero)</div>';

            if ((d.repoPackages || []).length) {
                h += '<div class="small mb-2"><strong>Pacchetti Dovecot nel repository:</strong> '
                   + d.repoPackages.map(p => updEsc(p.name) + ' ' + updEsc(p.version)).join(' &middot; ')
                   + '</div>';
            }

            if (d.doveconfAvailable === false) {
                h += '<div class="small text-muted mb-2">doveconf non disponibile: impossibile chiedere a Dovecot se accetta la configurazione.</div>';
            } else if (d.doveconfOk) {
                h += '<div class="small text-success mb-2"><i class="fas fa-check me-1"></i>'
                   + 'Il Dovecot installato accetta la configurazione attuale (<code>doveconf -n</code> non segnala nulla).</div>';
            } else {
                h += '<div class="alert alert-warning py-2 small mb-2"><strong>Il Dovecot installato segnala qualcosa sulla configurazione attuale:</strong>'
                   + '<pre class="upd-log mt-1 mb-0">' + updEsc(d.doveconfOutput || '') + '</pre></div>';
            }
            if (!d.scanned) {
                h += '<div class="alert alert-secondary py-2 small">' + updEsc(d.note || 'configurazione non trovata') + '</div>';
            } else if (d.compatible24) {
                h += '<div class="alert alert-success py-2 small"><i class="fas fa-check me-1"></i>'
                   + 'Nessun costrutto incompatibile con Dovecot 2.4.</div>';
            } else {
                h += '<div class="alert alert-danger py-2 small mb-2"><strong>La configurazione non sopravvive a Dovecot 2.4.</strong> '
                   + 'La 2.4 non degrada: <strong>si rifiuta di partire</strong>. Se questo pacchetto viene aggiornato, la posta si ferma. '
                   + (d.breakingUpgradeAvailable
                        ? 'E il repository offre già una versione più recente: il rischio è attuale, non teorico.'
                        : 'Al momento il repository non offre ancora quella versione.')
                   + '</div>';
                h += '<div class="table-responsive"><table class="table table-sm"><thead><tr>'
                   + '<th style="width:30%">Costrutto</th><th>Cosa vuole la 2.4</th><th style="width:30%">Dove</th></tr></thead><tbody>';
                (d.issues || []).forEach(i => {
                    h += '<tr class="upd-cell"><td><code>' + updEsc(i.costrutto) + '</code></td>'
                       + '<td>' + updEsc(i.sostituto) + '</td>'
                       + '<td class="small text-muted">' + (i.files || []).map(f => updEsc(f)).join('<br>') + '</td></tr>';
                });
                h += '</tbody></table></div>';
                h += '<p class="small text-muted">Finché questi costrutti sono presenti, la manutenzione automatica '
                   + '<strong>non sblocca Dovecot</strong>: non è un avviso, è un blocco.</p>';
            }

            const m = r.mysql || {};
            h += '<hr><h6 class="mb-1"><i class="fas fa-database me-1"></i>MySQL</h6>';
            if (!m.present) {
                h += '<div class="small text-muted">' + updEsc(m.note || 'non installato') + '</div>';
            } else {
                h += '<div class="small text-muted mb-2">' + updEsc(m.package) + ' ' + updEsc(m.version) + '</div>';
                if (m.eol) {
                    h += '<div class="alert alert-warning py-2 small">MySQL 8.0 è a <strong>fine vita</strong>: non riceve più '
                       + 'correzioni di sicurezza. Su FreeBSD la 8.4 è un pacchetto diverso e in conflitto, quindi nessun '
                       + '<code>pkg upgrade</code> ci arriva: serve una migrazione dedicata, con copia fredda a database spento.</div>';
                }
                if ((m.issues || []).length) {
                    h += '<div class="alert alert-danger py-2 small"><strong>Il my.cnf contiene ' + m.issues.length
                       + ' opzioni rimosse nella 8.4.</strong> Con una sola di queste il server non parte:<ul class="mb-0 mt-1">';
                    m.issues.forEach(i => { h += '<li><code>' + updEsc(i.opzione) + '</code> &rarr; ' + updEsc(i.sostituto) + '</li>'; });
                    h += '</ul></div>';
                } else if (m.mycnfPresent) {
                    h += '<div class="small text-success"><i class="fas fa-check me-1"></i>Nessuna opzione rimossa nella 8.4 è attiva nel my.cnf.</div>';
                }
            }

            const w = r.webmail || {};
            h += '<hr><h6 class="mb-1"><i class="fas fa-globe me-1"></i>Webmail e PHP</h6>';
            h += '<div class="small text-muted mb-2">' + updEsc(w.php || 'php assente') + ' ' + updEsc(w.phpVersion || '')
               + ' &middot; ' + updEsc(w.roundcube || 'roundcube assente') + ' ' + updEsc(w.roundcubeVersion || '') + '</div>';
            if (w.consistent) {
                h += '<div class="small text-success"><i class="fas fa-check me-1"></i>PHP, webmail e script del pannello nominano la stessa versione.</div>';
            } else {
                h += '<div class="alert alert-warning py-2 small"><ul class="mb-0">'
                   + (w.notes || []).map(n => '<li>' + updEsc(n) + '</li>').join('') + '</ul></div>';
            }
            el.innerHTML = h;
        }

        async function updDumpDovecot() {
            const el = document.getElementById('upd-dovecot-dump');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Leggo i file...';
            const r = await updApi('dovecot_config_dump');
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            let h = '<hr><div class="small text-muted mb-2">'
                  + r.count + ' file letti. Le password sono oscurate.</div>';
            (r.files || []).forEach(f => {
                h += '<details class="mb-1"><summary class="small"><code>' + updEsc(f.path) + '</code> '
                   + '<span class="text-muted">(' + f.lines + ' righe)</span></summary>'
                   + '<pre class="upd-log mt-1">' + updEsc(f.content) + '</pre></details>';
            });
            el.innerHTML = h;
        }

        async function updRegenDovecot() {
            if (!confirm('Riscrivere la configurazione di Dovecot dalla sorgente unica del pannello? Non tocca i pacchetti: la configurazione attuale viene salvata prima, e se Dovecot non accettasse quella nuova viene rimessa a posto senza riavviare il servizio.')) return;
            if (prompt('Conferma: scrivi RIGENERA per procedere.') !== 'RIGENERA') return;
            const el = document.getElementById('upd-status');
            const pre = document.getElementById('upd-log');
            const r = await updApi('dovecot_config_regen', { confirm: 'RIGENERA' });
            if (!r.success) { alert(r.error || 'operazione fallita'); return; }
            el.innerHTML = '<span class="text-info"><i class="fas fa-spinner fa-spin me-1"></i>Rigenerazione della configurazione Dovecot in corso...</span>';
            pre.style.display = 'block';
            updPoll(r.jobId, el, pre);
        }

        // ---------- piano di manutenzione ----------
        function planBadge(stato) {
            if (stato === 'fatto')   return '<span class="badge upd-badge-ok"><i class="fas fa-check me-1"></i>fatto</span>';
            if (stato === 'manuale') return '<span class="badge upd-badge-warn">procedura dedicata</span>';
            return '<span class="badge upd-badge-stop">da fare</span>';
        }

        let planAzioni = [];

        async function planLoad() {
            planAzioni = [];
            const el = document.getElementById('plan-body');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Leggo lo stato del sistema: pacchetti, vulnerabilità, configurazione. Ci vuole qualche secondo...';
            const r = await updApi('plan');
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }

            let primoDaFare = true;
            const lettere = ['A','B','C','D','E','F','G','H'];
            let iFase = 0;

            function riga(p, etichetta) {
                const attivo = p.stato === 'dafare' && primoDaFare;
                if (p.stato === 'dafare') primoDaFare = false;
                let h = '<div class="border rounded p-2 mb-2' + (attivo ? ' border-primary' : '') + '">'
                      + '<div class="d-flex justify-content-between align-items-center">'
                      + '<span><strong>' + etichetta + updEsc(p.titolo) + '</strong> ' + planBadge(p.stato) + '</span>';
                if (attivo && p.azione) {
                    const idx = planAzioni.push(p.azione) - 1;
                    h += '<button class="btn btn-sm btn-primary" onclick="planRun(' + idx + ')">'
                       + '<i class="fas fa-play me-1"></i>Esegui questo passo</button>';
                }
                h += '</div>'
                   + '<div class="small mt-1">' + updEsc(p.situazione) + '</div>'
                   + '<div class="small text-muted mt-1">' + updEsc(p.perche) + '</div>'
                   + '</div>';
                return h;
            }

            const passi = r.passi || [];
            let h = '<div class="mb-2 small">' + (r.daFare === 0
                ? '<span class="text-success"><i class="fas fa-circle-check me-1"></i><strong>Niente da fare.</strong></span>'
                : '<strong>' + r.daFare + ' passi da fare.</strong> È attivo solo il primo, in ordine dall&rsquo;alto.')
                + '</div>';

            // I passi si presentano nell'ordine di esecuzione, ma con identita' stabili:
            // le fasi hanno una lettera fissa, i pacchetti si chiamano col proprio nome.
            // Cosi' nessuna etichetta cambia significato quando un passo viene completato.
            let gruppoCorrente = '';
            passi.forEach(p => {
                if (p.gruppo !== gruppoCorrente) {
                    gruppoCorrente = p.gruppo;
                    h += '<h6 class="mt-3 mb-2 text-muted">'
                       + (p.gruppo === 'fase'
                            ? '<i class="fas fa-flag me-1"></i>Fasi'
                            : '<i class="fas fa-box me-1"></i>Pacchetti da aggiornare')
                       + '</h6>';
                }
                const etichetta = p.gruppo === 'fase'
                    ? 'Fase ' + (lettere[iFase++] || '?') + ' &mdash; '
                    : '';
                h += riga(p, etichetta);
            });

            if ((r.senzaRimedio || []).length) {
                h += '<div class="alert alert-secondary py-2 small mb-0"><strong>Senza rimedio disponibile:</strong> '
                   + r.senzaRimedio.map(x => updEsc(x)).join(', ')
                   + '. Hanno vulnerabilità note ma il repository non offre ancora una correzione: non c&rsquo;è un passo da fare, va solo saputo.</div>';
            }
            el.innerHTML = h;
        }

        async function planRun(idx) {
            const azione = planAzioni[idx];
            if (!azione) { alert('Passo non piu valido: ricalcola il piano.'); return; }
            const el = document.getElementById('plan-body');
            const pre = document.getElementById('plan-log');
            let r;
            if (azione.tipo === 'packages_lock_all') {
                r = await updApi('packages_lock', { lock: true, package: '' });
                if (!r.success) { alert(r.error || 'operazione fallita'); return; }
                planLoad();
                return;
            }
            if (azione.tipo === 'updates_apply') {
                if (prompt('Conferma: scrivi AGGIORNA per procedere.') !== 'AGGIORNA') return;
                r = await updApi('updates_apply', { confirm: 'AGGIORNA' });
            } else if (azione.tipo === 'package_update') {
                if (prompt('Per confermare scrivi esattamente il nome del pacchetto: ' + azione.package) !== azione.package) return;
                r = await updApi('package_update', { package: azione.package, confirm: azione.package });
            } else if (azione.tipo === 'dovecot_config_regen') {
                if (prompt('Conferma: scrivi RIGENERA per procedere.') !== 'RIGENERA') return;
                r = await updApi('dovecot_config_regen', { confirm: 'RIGENERA' });
            } else {
                alert('Passo senza azione automatica.');
                return;
            }
            if (!r.success) { alert(r.error || 'operazione fallita'); return; }
            el.innerHTML = '<span class="text-info"><i class="fas fa-spinner fa-spin me-1"></i>Passo in corso: non chiudere la pagina.</span>';
            pre.style.display = 'block';
            planPoll(r.jobId, el, pre);
        }

        async function planPoll(id, el, pre) {
            const s = await updApi('job_status', { jobId: id });
            if (s.success && s.job) {
                pre.textContent = s.job.consoleLog || '';
                pre.scrollTop = pre.scrollHeight;
                if (s.job.status === 'completed') {
                    el.innerHTML = '<span class="text-success"><i class="fas fa-check me-1"></i>Passo completato in '
                                 + s.job.elapsedSeconds + 's. Ricalcolo il piano...</span>';
                    setTimeout(planLoad, 1500);
                    return;
                }
                if (s.job.status === 'error') {
                    el.innerHTML = '<div class="alert alert-danger py-2"><strong>Passo non riuscito:</strong> '
                                 + updEsc(s.job.errorMessage) + '<br>Leggi il log qui sotto prima di proseguire.</div>'
                                 + '<button class="btn btn-sm btn-outline-primary" onclick="planLoad()">Ricalcola il piano</button>';
                    return;
                }
            }
            setTimeout(() => planPoll(id, el, pre), 3000);
        }

        // ---------- migrazione MySQL 8.4: solo verifica ----------
        async function my84Pre() {
            const el = document.getElementById('my84-pre');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Controlli in corso: pacchetti, libreria client, configurazione, account, spazio, inventario...';
            const r = await updApi('mysql84_preflight');
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            let h = '<div class="table-responsive"><table class="table table-sm align-middle mb-2"><thead><tr>'
                  + '<th style="width:8rem">Esito</th><th style="width:16rem">Controllo</th><th>Dettaglio</th></tr></thead><tbody>';
            (r.checks || []).forEach(c => {
                h += '<tr class="upd-cell"><td>' + updBadge(c.level === 'block' ? 'attendi' : c.level) + '</td>'
                   + '<td><strong>' + updEsc(c.label) + '</strong></td><td>' + updEsc(c.detail) + '</td></tr>';
            });
            h += '</tbody></table></div>';
            if ((r.dependents || []).length) {
                h += '<div class="small mb-2"><strong>Pacchetti collegati alla libreria client:</strong><ul class="mb-0">';
                r.dependents.forEach(d => {
                    h += '<li><code>' + updEsc(d.name) + '</code> richiede <code>' + updEsc(d.richiede) + '</code> '
                       + (d.compatibile ? '<span class="text-success">compatibile</span>'
                                        : '<span class="text-danger">NON compatibile con la 8.4</span>') + '</li>';
                });
                h += '</ul></div>';
            }
            if (r.alreadyDone) {
                h += '<div class="alert alert-success py-2 mb-0">Sei gia&rsquo; sulla 8.4.</div>';
            } else if (r.blocked) {
                h += '<div class="alert alert-danger py-2 mb-0"><strong>Migrazione non avviabile.</strong> '
                   + 'Ogni riga rossa descrive una situazione che finirebbe con il server di posta fermo. '
                   + 'La procedura di esecuzione verr&agrave; costruita solo dopo che questi controlli passano.</div>';
            } else {
                h += '<div class="alert alert-warning py-2"><strong>I prerequisiti sono superati.</strong> '
                   + 'Postfix e Dovecot verranno fermati, MySQL sostituito, e alla fine il pannello verifica che '
                   + 'entrambi risolvano davvero una casella: non basta che il servizio risulti avviato.</div>'
                   + '<button class="btn btn-danger" onclick="my84Run()"><i class="fas fa-play me-1"></i>Migra a MySQL 8.4</button>';
            }
            el.innerHTML = h;
        }

        async function my84Run() {
            if (prompt('Conferma: scrivi MIGRA A 8.4 per procedere.') !== 'MIGRA A 8.4') return;
            const el = document.getElementById('my84-pre');
            const pre = document.getElementById('plan-log');
            const r = await updApi('mysql84_migrate', { confirm: 'MIGRA A 8.4' });
            if (!r.success) { alert(r.error || 'operazione fallita'); return; }
            el.innerHTML = '<span class="text-info"><i class="fas fa-spinner fa-spin me-1"></i>Migrazione in corso: '
                         + 'non chiudere la pagina e non riavviare il pannello.</span>';
            pre.style.display = 'block';
            planPoll(r.jobId, el, pre);
        }

        // ---------- aggiornamento guidato ----------
        async function guidList() {
            const el = document.getElementById('guid-list');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Cerco i pacchetti protetti con un aggiornamento...';
            const r = await updApi('maintenance_preview');
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            const pk = r.packages || [];
            if (!pk.length) { el.innerHTML = '<span class="text-muted">Nessun pacchetto protetto ha aggiornamenti disponibili.</span>'; return; }
            let h = '<div class="table-responsive"><table class="table table-sm align-middle mb-0"><thead><tr>'
                  + '<th>Pacchetto</th><th>Da</th><th>A</th><th>Esito</th><th class="text-end"></th></tr></thead><tbody>';
            pk.forEach(p => {
                const a = p.advisory;
                const bloccante = a && a.level === 'attendi';
                h += '<tr class="upd-cell"><td><code>' + updEsc(p.name) + '</code><br>'
                   + '<span class="small text-muted">' + updEsc(p.role || '') + '</span></td>'
                   + '<td class="small">' + updEsc(p.current) + '</td>'
                   + '<td class="small">' + updEsc(p.available) + '</td>'
                   + '<td>' + (a ? updBadge(a.level) : '<span class="badge bg-secondary">-</span>') + '</td>'
                   + '<td class="text-end">'
                   + (bloccante
                        ? '<span class="small text-muted">procedura dedicata</span>'
                        : '<button class="btn btn-sm btn-outline-primary" onclick="guidPreflight(\\'' + updEsc(p.name) + '\\')">'
                          + '<i class="fas fa-clipboard-check me-1"></i>Prepara</button>')
                   + '</td></tr>';
            });
            h += '</tbody></table></div>';
            el.innerHTML = h;
        }

        async function guidPreflight(nome) {
            const el = document.getElementById('guid-detail');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Controlli su ' + updEsc(nome) + '...';
            const r = await updApi('package_preflight', { package: nome });
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            let h = '<hr><h6><i class="fas fa-cube me-1"></i>' + updEsc(r.name) + ' &mdash; '
                  + updEsc(r.current) + ' &rarr; ' + updEsc(r.available) + '</h6>';
            h += '<div class="table-responsive"><table class="table table-sm align-middle mb-2">'
               + '<thead><tr><th style="width:8rem">Esito</th><th style="width:16rem">Controllo</th><th>Dettaglio</th></tr></thead><tbody>';
            (r.checks || []).forEach(c => {
                h += '<tr class="upd-cell"><td>' + updBadge(c.level === 'block' ? 'attendi' : c.level) + '</td>'
                   + '<td><strong>' + updEsc(c.label) + '</strong></td><td>' + updEsc(c.detail) + '</td></tr>';
            });
            h += '</tbody></table></div>';
            if ((r.cve || []).length) {
                h += '<div class="small mb-2"><strong>Chiude:</strong> <span class="badge bg-dark me-1">'
                   + r.cve.map(c => updEsc(c)).join('</span><span class="badge bg-dark me-1">') + '</span></div>';
            }
            if ((r.services || []).length) {
                h += '<div class="small mb-2"><strong>Servizi che verranno riavviati:</strong> '
                   + r.services.map(s => updEsc(s.name) + (s.running ? '' : ' (fermo, non verra\\' avviato)')).join(', ')
                   + '</div>';
            }
            if (r.blocked) {
                h += '<div class="alert alert-danger py-2 small mb-0">Non avviabile: risolvi le righe rosse qui sopra.</div>';
            } else {
                h += '<button class="btn btn-danger" onclick="guidRun(\\'' + updEsc(r.name) + '\\')">'
                   + '<i class="fas fa-play me-1"></i>Aggiorna ' + updEsc(r.name) + '</button>';
            }
            el.innerHTML = h;
        }

        async function guidRun(nome) {
            if (prompt('Per confermare scrivi esattamente il nome del pacchetto: ' + nome) !== nome) return;
            const el = document.getElementById('guid-detail');
            const pre = document.getElementById('upd-log');
            const r = await updApi('package_update', { package: nome, confirm: nome });
            if (!r.success) { alert(r.error || 'operazione fallita'); return; }
            el.innerHTML = '<span class="text-info"><i class="fas fa-spinner fa-spin me-1"></i>Aggiornamento di '
                         + updEsc(nome) + ' in corso: non chiudere la pagina.</span>';
            pre.style.display = 'block';
            updPoll(r.jobId, el, pre);
        }

        // ---------- protezione pacchetti ----------
        async function updPackages() {
            const el = document.getElementById('upd-packages');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Lettura pacchetti...';
            const r = await updApi('packages_status');
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            let rows = '';
            (r.packages || []).forEach(p => {
                rows += '<tr class="upd-cell"><td><code>' + updEsc(p.name) + '</code></td>'
                      + '<td class="small">' + updEsc(p.role) + '</td>'
                      + '<td class="small">' + updEsc(p.version) + '</td>'
                      + '<td>' + (p.locked
                          ? '<span class="badge upd-badge-ok"><i class="fas fa-lock me-1"></i>protetto</span>'
                          : '<span class="badge upd-badge-warn"><i class="fas fa-lock-open me-1"></i>non protetto</span>') + '</td>'
                      + '<td class="text-end"><button class="btn btn-sm btn-outline-secondary" onclick="updLockOne(\\''
                      + updEsc(p.name) + '\\',' + (p.locked ? 'false' : 'true') + ')">'
                      + (p.locked ? 'Sblocca' : 'Proteggi') + '</button></td></tr>';
            });
            el.innerHTML = '<div class="small text-muted mb-2">' + r.lockedCount + ' protetti su ' + r.installedCount
                         + ' pacchetti dello stack di posta installati.</div>'
                         + '<div class="table-responsive"><table class="table table-sm table-striped"><thead><tr>'
                         + '<th>Pacchetto</th><th>Ruolo</th><th>Versione</th><th>Stato</th><th></th></tr></thead><tbody>'
                         + rows + '</tbody></table></div>';
        }

        async function updLockOne(nome, blocca) {
            const r = await updApi('packages_lock', { lock: blocca, package: nome });
            if (!r.success) { alert(r.error || 'operazione fallita'); return; }
            updPackages();
        }

        async function updLockAll(blocca) {
            if (!blocca && !confirm('Sbloccare TUTTI i pacchetti dello stack di posta?\\n\\nDa quel momento un pkg upgrade potrebbe sostituirli o rimuoverli.')) return;
            const el = document.getElementById('upd-packages');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>' + (blocca ? 'Protezione' : 'Sblocco') + ' in corso...';
            const r = await updApi('packages_lock', { lock: blocca, package: '' });
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            updPackages();
        }

        // ---------- aggiornamenti e vulnerabilita' ----------
        async function updStatus() {
            const el = document.getElementById('upd-status');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Simulazione in corso: aggiorno l\\'indice, calcolo e controllo le vulnerabilità...';
            const r = await updApi('updates_status');
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            let h = '';

            if (r.rebootPending) {
                h += '<div class="alert alert-warning py-2 small"><strong>Manca un riavvio.</strong> Kernel '
                   + updEsc(r.kernel) + ', in esecuzione ' + updEsc(r.running) + ': finché non riavvii, il sistema '
                   + 'gira su un kernel diverso da quello installato.</div>';
            }

            const vuln = r.vulnerable || [];
            if (vuln.length) {
                h += '<div class="alert alert-danger py-2 small"><strong>' + vuln.length
                   + ' pacchetti con vulnerabilità note.</strong><ul class="mb-0 mt-1">';
                vuln.forEach(v => {
                    h += '<li class="mb-2"><code>' + updEsc(v.name) + '</code>'
                       + (v.role ? ' <span class="text-muted">(' + updEsc(v.role) + ')</span>' : '')
                       + (v.locked
                            ? ' &mdash; <strong>protetto, quindi NON riceve la correzione</strong>'
                            : (v.fixedByUpgrade ? ' &mdash; si risolve aggiornando' : ' &mdash; nessun aggiornamento disponibile'));
                    if ((v.cve || []).length) {
                        h += '<br><span class="badge bg-dark me-1">'
                           + v.cve.map(c => updEsc(c)).join('</span><span class="badge bg-dark me-1">')
                           + '</span>';
                    }
                    if (v.descrizione) {
                        h += '<br><span class="text-muted">' + updEsc(v.descrizione) + '</span>';
                    }
                    (v.riferimenti || []).forEach(u => {
                        h += '<br><a href="' + updEsc(u) + '" target="_blank" rel="noopener noreferrer" class="small">'
                           + updEsc(u) + '</a>';
                    });
                    h += '</li>';
                });
                h += '</ul>';
                if (r.notaRiavvio) {
                    h += '<div class="mt-2 pt-2 border-top small"><i class="fas fa-triangle-exclamation me-1"></i>'
                       + '<strong>' + updEsc(r.notaRiavvio) + '</strong></div>';
                }
                h += '</div>';
            } else {
                h += '<div class="alert alert-success py-2 small"><i class="fas fa-check me-1"></i>Nessuna vulnerabilità nota nei pacchetti installati.</div>';
            }

            const locked = r.lockedUpdates || [];
            if (locked.length) {
                h += '<h6 class="mt-3">Aggiornamenti disponibili per i pacchetti protetti</h6>'
                   + '<div class="small text-muted mb-2">Sono fermi perché protetti. Qui c&rsquo;è a quale versione andrebbero e cosa comporta.</div>'
                   + '<div class="table-responsive"><table class="table table-sm"><thead><tr>'
                   + '<th>Pacchetto</th><th>Da</th><th>A</th><th>Esito</th><th>Perché</th></tr></thead><tbody>';
                locked.forEach(p => {
                    const a = p.advisory;
                    h += '<tr class="upd-cell"><td><code>' + updEsc(p.name) + '</code><br><span class="small text-muted">'
                       + updEsc(p.role) + '</span></td>'
                       + '<td class="small">' + updEsc(p.current) + '</td>'
                       + '<td class="small">' + updEsc(p.available)
                       + (p.majorJump ? ' <span class="badge bg-secondary">maggiore</span>' : '') + '</td>'
                       + '<td>' + (a ? updBadge(a.level) : '<span class="badge bg-secondary">-</span>') + '</td>'
                       + '<td class="small">' + (a ? updEsc(a.text) : '') + '</td></tr>';
                });
                h += '</tbody></table></div>';
            }

            const aff = r.affectedMailPackages || [];
            if (aff.length) {
                h += '<div class="small mb-2"><strong>Pacchetti dello stack toccati da un aggiornamento normale:</strong> '
                   + aff.map(p => updEsc(p.name) + (p.locked ? ' (protetto)' : '')).join(', ') + '</div>';
            }

            h += '<details class="mt-2"><summary class="small text-muted">Simulazione completa di pkg</summary>'
               + '<pre class="upd-log mt-2">' + updEsc(r.dryRun) + '</pre></details>';
            if (r.audit) {
                h += '<details class="mt-1"><summary class="small text-muted">Referto completo di pkg audit</summary>'
                   + '<pre class="upd-log mt-2">' + updEsc(r.audit) + '</pre></details>';
            }
            el.innerHTML = h;
        }

        async function updApply() {
            if (!confirm('Aggiornare i pacchetti NON protetti?\\n\\nI protetti non vengono toccati: è il lock a difenderli.\\nEsegui prima "Verifica" per vedere cosa cambierebbe.')) return;
            if (prompt('Conferma: scrivi AGGIORNA per procedere.') !== 'AGGIORNA') return;
            const el = document.getElementById('upd-status');
            const pre = document.getElementById('upd-log');
            const r = await updApi('updates_apply', { confirm: 'AGGIORNA' });
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            el.innerHTML = '<span class="text-info"><i class="fas fa-spinner fa-spin me-1"></i>Aggiornamento in corso: non chiudere la pagina.</span>';
            pre.style.display = 'block';
            updPoll(r.jobId, el, pre);
        }

        async function updMaintPreview() {
            const el = document.getElementById('upd-status');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Calcolo cosa cambierebbe...';
            const r = await updApi('maintenance_preview');
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            let h = '<div class="alert alert-secondary py-2 small">' + updEsc(r.generalNote) + '</div>';
            const pk = r.packages || [];
            if (!pk.length) {
                h += '<div class="small text-muted">Nessun aggiornamento disponibile per i pacchetti protetti.</div>';
                el.innerHTML = h;
                return;
            }
            h += '<div class="table-responsive"><table class="table table-sm"><thead><tr>'
               + '<th>Pacchetto</th><th>Da</th><th>A</th><th>Esito</th></tr></thead><tbody>';
            pk.forEach(p => {
                const a = p.advisory;
                h += '<tr class="upd-cell"><td><code>' + updEsc(p.name) + '</code></td>'
                   + '<td class="small">' + updEsc(p.current) + '</td>'
                   + '<td class="small">' + updEsc(p.available) + '</td>'
                   + '<td>' + (a ? updBadge(a.level) : '<span class="badge bg-secondary">-</span>') + '</td></tr>';
            });
            h += '</tbody></table></div>';
            if (r.waitCount > 0) {
                h += '<div class="alert alert-warning py-2 small"><strong>' + r.waitCount
                   + ' pacchetti resteranno protetti</strong> perché la loro avvertenza dice di attendere. '
                   + 'La manutenzione non li sblocca: l&rsquo;avvertenza agisce, non si limita a comparire.</div>';
            }
            h += '<button class="btn btn-sm btn-danger" onclick="updMaintRun()"><i class="fas fa-play me-1"></i>Esegui manutenzione completa</button>';
            el.innerHTML = h;
        }

        async function updMaintRun() {
            if (!confirm('Eseguire il ciclo completo?\\n\\n1. Sblocca i pacchetti protetti (tranne quelli trattenuti)\\n2. Aggiorna\\n3. Li riprotegge automaticamente\\n\\nIl riblocco avviene anche se l\\'aggiornamento fallisce.')) return;
            if (prompt('Conferma: scrivi MANUTENZIONE per procedere.') !== 'MANUTENZIONE') return;
            const el = document.getElementById('upd-status');
            const pre = document.getElementById('upd-log');
            const r = await updApi('maintenance_run', { confirm: 'MANUTENZIONE' });
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            el.innerHTML = '<span class="text-info"><i class="fas fa-spinner fa-spin me-1"></i>Manutenzione in corso: non chiudere la pagina e non riavviare il pannello.</span>';
            pre.style.display = 'block';
            updPoll(r.jobId, el, pre);
        }

        async function updPoll(id, el, pre) {
            const s = await updApi('job_status', { jobId: id });
            if (s.success && s.job) {
                pre.textContent = s.job.consoleLog || '';
                pre.scrollTop = pre.scrollHeight;
                if (s.job.status === 'completed') {
                    el.innerHTML = '<span class="text-success"><i class="fas fa-check me-1"></i>Operazione completata in '
                                 + s.job.elapsedSeconds + 's. Rileggi il log qui sotto.</span>';
                    updPackages();
                    return;
                }
                if (s.job.status === 'error') {
                    el.innerHTML = '<div class="alert alert-danger py-2 mb-0"><strong>Operazione non riuscita:</strong> '
                                 + updEsc(s.job.errorMessage) + '<br>Leggi il log per capire a che punto si è fermata.</div>';
                    updPackages();
                    return;
                }
            }
            setTimeout(() => updPoll(id, el, pre), 3000);
        }
""";
    }

}
