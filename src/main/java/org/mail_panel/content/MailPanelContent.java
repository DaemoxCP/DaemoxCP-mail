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
            writeFile(adminDir + "/install.html", getInstallHtml());
            writeFile(adminDir + "/settings.html", getSettingsHtml());
            writeFile(adminDir + "/statistics.html", getStatisticsHtml());
            writeFile(adminDir + "/admins.html", getAdminsHtml());
            writeFile(adminDir + "/ratelimits.html", getRateLimitsHtml());

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
        return """
<footer class="footer bg-light text-center mt-4">
    <div class="text-center p-3" style="background-color: rgba(0, 0, 0, 0.2);">&copy; <script>document.write(new Date().getFullYear())</script> FreeBSD 15 - Mail Control Panel</div>
</footer>
""";
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
        return """
    <footer class="footer bg-dark text-white py-3 mt-4">
        <div class="container text-center">
            <small>FreeBSD Mail Panel - Pannello di controllo mail</small>
        </div>
    </footer>
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
                                   pattern="^[a-zA-Z0-9_-]{3,50}$" minlength="3" maxlength="50" autocomplete="username">
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
        <div class="text-center p-3" style="background-color: rgba(0, 0, 0, 0.2);">&copy; <script>document.write(new Date().getFullYear())</script> FreeBSD Mail Control Panel</div>
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
""";
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
            });
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
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h2><i class="fas fa-inbox me-2"></i>Caselle Email</h2>
                <button class="btn btn-mail" data-bs-toggle="modal" data-bs-target="#addMailboxModal"><i class="fas fa-plus me-1"></i>Aggiungi Casella</button>
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
                        <input type="password" class="form-control" id="editMbPass" placeholder="Nuova password...">
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

    <!-- Mail Client Config Modal -->
    <div class="modal fade" id="mailConfigModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-mobile-alt me-2"></i>Configurazione Client Email</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="alert alert-primary">
                        <i class="fas fa-envelope me-2"></i>
                        <strong id="configEmail"></strong>
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
                        <div class="tab-pane fade show active" id="configGeneral">
                            <table class="table table-bordered">
                                <thead><tr><th>Impostazione</th><th>IMAP (Consigliato)</th><th>POP3</th></tr></thead>
                                <tbody>
                                    <tr><td><strong>Server Posta in Arrivo</strong></td><td id="cfgImapServer"></td><td id="cfgPop3Server"></td></tr>
                                    <tr><td><strong>Porta</strong></td><td id="cfgImapPort"></td><td id="cfgPop3Port"></td></tr>
                                    <tr><td><strong>Sicurezza</strong></td><td>SSL/TLS</td><td>SSL/TLS</td></tr>
                                </tbody>
                            </table>
                            <table class="table table-bordered mt-3">
                                <thead><tr><th>Impostazione</th><th>SMTP (Posta in Uscita)</th></tr></thead>
                                <tbody>
                                    <tr><td><strong>Server</strong></td><td id="cfgSmtpServer"></td></tr>
                                    <tr><td><strong>Porta</strong></td><td id="cfgSmtpPort"></td></tr>
                                    <tr><td><strong>Sicurezza</strong></td><td>STARTTLS</td></tr>
                                    <tr><td><strong>Autenticazione</strong></td><td>Password normale</td></tr>
                                </tbody>
                            </table>
                            <div class="alert alert-warning mt-3">
                                <i class="fas fa-user me-2"></i><strong>Username:</strong> L'indirizzo email completo<br>
                                <i class="fas fa-key me-2"></i><strong>Password:</strong> La password dell'account email
                            </div>
                        </div>
                        <div class="tab-pane fade" id="configOutlook">
                            <h6><i class="fab fa-microsoft me-2"></i>Microsoft Outlook</h6>
                            <ol class="mt-3">
                                <li>Apri Outlook e vai su <strong>File > Aggiungi Account</strong></li>
                                <li>Inserisci l'indirizzo email e clicca <strong>Connetti</strong></li>
                                <li>Seleziona <strong>IMAP</strong></li>
                                <li>Inserisci i seguenti dati:<br>
                                    <code>Server IMAP: <span id="cfgOutlookImap"></span></code><br>
                                    <code>Porta: 993, SSL/TLS</code><br>
                                    <code>Server SMTP: <span id="cfgOutlookSmtp"></span></code><br>
                                    <code>Porta: 587, STARTTLS</code>
                                </li>
                                <li>Inserisci la password e completa la configurazione</li>
                            </ol>
                        </div>
                        <div class="tab-pane fade" id="configApple">
                            <h6><i class="fab fa-apple me-2"></i>iPhone / iPad / Mac</h6>
                            <ol class="mt-3">
                                <li>Vai in <strong>Impostazioni > Mail > Account > Aggiungi Account</strong></li>
                                <li>Seleziona <strong>Altro > Aggiungi account Mail</strong></li>
                                <li>Inserisci nome, email e password</li>
                                <li>Seleziona <strong>IMAP</strong></li>
                                <li>Server posta in arrivo: <code id="cfgAppleImap"></code></li>
                                <li>Server posta in uscita: <code id="cfgAppleSmtp"></code></li>
                                <li>Salva e attendi la verifica</li>
                            </ol>
                        </div>
                        <div class="tab-pane fade" id="configAndroid">
                            <h6><i class="fab fa-android me-2"></i>Android (Gmail App)</h6>
                            <ol class="mt-3">
                                <li>Apri l'app Gmail e vai su <strong>Impostazioni > Aggiungi account</strong></li>
                                <li>Seleziona <strong>Altro</strong></li>
                                <li>Inserisci l'indirizzo email</li>
                                <li>Seleziona <strong>Personale (IMAP)</strong></li>
                                <li>Inserisci la password</li>
                                <li>Server in arrivo: <code id="cfgAndroidImap"></code>, Porta: 993, SSL</li>
                                <li>Server in uscita: <code id="cfgAndroidSmtp"></code>, Porta: 587, STARTTLS</li>
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
                                <button class="btn btn-sm btn-info" onclick="showMailConfig('${m.email}')" title="Configurazione Client">
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
                    new bootstrap.Modal(document.getElementById('editMailboxModal')).show();
                } else {
                    alert('Errore: impossibile caricare i dati della mailbox');
                }
            });
        }

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

        function showMailConfig(email) {
            document.getElementById('configEmail').textContent = email;

            fetch('/api/mailconfig').then(r => r.json()).then(data => {
                if (data.success) {
                    const server = data.server;

                    // General tab
                    document.getElementById('cfgImapServer').textContent = server;
                    document.getElementById('cfgPop3Server').textContent = server;
                    document.getElementById('cfgImapPort').textContent = '993 (SSL)';
                    document.getElementById('cfgPop3Port').textContent = '995 (SSL)';
                    document.getElementById('cfgSmtpServer').textContent = server;
                    document.getElementById('cfgSmtpPort').textContent = '587 (STARTTLS)';

                    // Outlook tab
                    document.getElementById('cfgOutlookImap').textContent = server;
                    document.getElementById('cfgOutlookSmtp').textContent = server;

                    // Apple tab
                    document.getElementById('cfgAppleImap').textContent = server;
                    document.getElementById('cfgAppleSmtp').textContent = server;

                    // Android tab
                    document.getElementById('cfgAndroidImap').textContent = server;
                    document.getElementById('cfgAndroidSmtp').textContent = server;
                }

                new bootstrap.Modal(document.getElementById('mailConfigModal')).show();
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
                    const ar = data.autoresponder || {};
                    document.getElementById('arEnabled').checked = ar.enabled || false;
                    document.getElementById('arSubject').value = ar.subject || '';
                    document.getElementById('arBody').value = ar.body || '';
                    document.getElementById('arStartDate').value = ar.start_date || '';
                    document.getElementById('arEndDate').value = ar.end_date || '';
                    document.getElementById('arInterval').value = ar.interval_hours || 24;
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
        """;
        return getHead("DNS", extraStyles) + getNavbar("dns") + """
    <div class="content container mt-4">
        <div class="content-container">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h2><i class="fas fa-server me-2"></i>Configurazione DNS</h2>
                <div>
                    <select class="form-select d-inline-block w-auto me-2" id="domainSelect">
                        <option value="">Seleziona dominio...</option>
                    </select>
                    <button class="btn btn-mail" onclick="loadDnsRecords()"><i class="fas fa-sync me-1"></i>Genera</button>
                    <button class="btn btn-success" onclick="verifyDns()"><i class="fas fa-check me-1"></i>Verifica</button>
                </div>
            </div>

            <div class="alert alert-info">
                <i class="fas fa-info-circle me-2"></i>
                <strong>Come funziona:</strong> Seleziona un dominio, genera i record DNS e copiali nel tuo pannello DNS (Cloudflare, Route53, etc.).
                Poi clicca "Verifica" per controllare che siano configurati correttamente.
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

            <!-- DKIM Section -->
            <div class="card mt-4">
                <div class="card-header bg-primary text-white">
                    <i class="fas fa-key me-2"></i>DKIM - Firma Digitale Email
                </div>
                <div class="card-body">
                    <p>DKIM firma digitalmente le email in uscita, permettendo ai destinatari di verificare l'autenticita'.</p>
                    <div id="dkimStatus">Seleziona un dominio per vedere lo stato DKIM.</div>
                    <button class="btn btn-warning mt-2" id="generateDkimBtn" onclick="generateDkim()" disabled>
                        <i class="fas fa-key me-1"></i>Genera Chiavi DKIM
                    </button>
                </div>
            </div>
        </div>
    </div>
""" + getFooter() + """
    <script>
        let currentDomainId = null;

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
        });

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
                    html += '<div class="dns-record ' + reqClass + '">';
                    html += '<div class="d-flex justify-content-between align-items-start">';
                    html += '<div><span class="record-type">' + r.type + '</span> ' + badge;
                    if (r.dnsZone) {
                        html += ' <small class="text-muted">su ' + r.dnsZone + '</small>';
                    }
                    html += '</div>';
                    html += '<i class="fas fa-copy copy-btn" onclick="copyToClipboard(this.parentElement.parentElement)" title="Copia"></i>';
                    html += '</div>';
                    html += '<div class="mt-2"><strong>Nome:</strong> <code>' + r.name + '</code></div>';
                    html += '<div class="mt-1"><strong>Valore:</strong> <code style="word-break:break-all">' + r.value + '</code></div>';
                    html += '<small class="text-muted">' + r.description + '</small>';
                    if (r.explanation) {
                        html += '<details class="mt-2"><summary><i class="fas fa-cog me-1"></i>Istruzioni dettagliate Cloudflare</summary><div class="mt-2 p-3 bg-white border rounded" style="font-size:0.9rem">' + r.explanation + '</div></details>';
                    }
                    html += '</div>';
                });

                document.getElementById('dnsRecordsContainer').innerHTML = html;

                // Load DKIM status
                loadDkimStatus(currentDomainId);
            });
        }

        function loadDkimStatus(domainId) {
            fetch('/api/dkim?id=' + domainId).then(r => r.json()).then(data => {
                const status = document.getElementById('dkimStatus');
                if (data.configured) {
                    status.innerHTML = '<div class="alert alert-success"><i class="fas fa-check-circle me-2"></i><strong>DKIM Configurato!</strong><br>' +
                        'Selector: ' + data.selector + '<br>' +
                        'Record DNS: <code>' + data.dns_record_name + '</code></div>';
                } else {
                    status.innerHTML = '<div class="alert alert-warning"><i class="fas fa-exclamation-triangle me-2"></i>DKIM non configurato per questo dominio.</div>';
                }
            });
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
""" + getLogoutScript() + """
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

            <!-- SSL Configuration Options -->
            <h4 class="mb-3"><i class="fas fa-cogs me-2"></i>Configura Certificato SSL</h4>

            <div class="row mb-4">
                <!-- Option 1: Let's Encrypt HTTP-01 -->
                <div class="col-md-4 mb-3">
                    <div class="card option-card h-100" onclick="selectOption(1)">
                        <div class="card-body text-center">
                            <i class="fas fa-bolt fa-3x text-success mb-3"></i>
                            <h5>Let's Encrypt (HTTP-01)</h5>
                            <p class="text-muted small">Automatico - richiede porta 80 accessibile da internet</p>
                            <span class="badge bg-success">Consigliato</span>
                        </div>
                    </div>
                </div>

                <!-- Option 2: Let's Encrypt DNS-01 -->
                <div class="col-md-4 mb-3">
                    <div class="card option-card h-100" onclick="selectOption(2)">
                        <div class="card-body text-center">
                            <i class="fas fa-globe fa-3x text-primary mb-3"></i>
                            <h5>Let's Encrypt (DNS-01)</h5>
                            <p class="text-muted small">Via record DNS TXT - funziona anche dietro firewall</p>
                            <span class="badge bg-primary">Universale</span>
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
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle me-2"></i>
                        Incolla il contenuto del certificato (fullchain.pem) e della chiave privata (privkey.pem).
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
        .log-entry { padding: 2px 0; border-bottom: 1px solid #333; }
        .log-entry:hover { background: #2d2d2d; }
        .log-ERROR { color: #f44336; }
        .log-WARNING { color: #ff9800; }
        .log-INFO { color: #4caf50; }
        .log-DEBUG { color: #9e9e9e; }
        .stat-number { font-size: 2rem; font-weight: bold; color: #e94560; }
        """;
        return getHead("Logs", extraStyles) + getNavbar("logs") + """
    <div class="content container mt-4">
        <!-- Statistics -->
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="card stat-card"><div class="card-body text-center">
                    <div class="stat-number" id="statReceived">-</div>
                    <div>Email Ricevute</div>
                </div></div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card"><div class="card-body text-center">
                    <div class="stat-number" id="statSent">-</div>
                    <div>Email Inviate</div>
                </div></div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card"><div class="card-body text-center">
                    <div class="stat-number" id="statSpam">-</div>
                    <div>Spam Bloccato</div>
                </div></div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card"><div class="card-body text-center">
                    <div class="stat-number" id="statUsers">-</div>
                    <div>Utenti Attivi</div>
                </div></div>
            </div>
        </div>

        <div class="content-container">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h2><i class="fas fa-file-alt me-2"></i>Log Server</h2>
                <div>
                    <select class="form-select d-inline-block w-auto" id="logSelect">
                        <option value="">Caricamento...</option>
                    </select>
                    <input type="text" class="form-control d-inline-block w-auto ms-2" id="logFilter" placeholder="Filtra...">
                    <button class="btn btn-mail ms-2" onclick="loadLogs()"><i class="fas fa-sync"></i></button>
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
                document.getElementById('statReceived').textContent = data.smtp.received;
                document.getElementById('statSent').textContent = data.smtp.sent;
                document.getElementById('statSpam').textContent = data.security.spam_detected;
                document.getElementById('statUsers').textContent = data.imap.active_users;
            }
        });

        // Load available logs
        fetch('/api/logs').then(r => r.json()).then(data => {
            const select = document.getElementById('logSelect');
            select.innerHTML = '';
            (data.logs || []).forEach(log => {
                const opt = document.createElement('option');
                opt.value = log.id;
                opt.textContent = log.description + (log.exists ? '' : ' (non esiste)');
                opt.disabled = !log.exists;
                select.appendChild(opt);
            });
        });

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

                viewer.innerHTML = data.entries.map(e => {
                    const levelClass = 'log-' + (e.level || 'INFO');
                    const ts = e.timestamp || '';
                    const proc = e.process ? '[' + e.process + '] ' : '';
                    return '<div class="log-entry ' + levelClass + '">' + ts + ' ' + proc + e.message + '</div>';
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

                results.innerHTML = '<div class="log-viewer" style="max-height:200px">' +
                    data.results.map(r => '<div class="log-entry">' + r.raw + '</div>').join('') +
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
                    <!-- Mail Hostname (Read-only) -->
                    <div class="card mb-4">
                        <div class="card-header"><i class="fas fa-server me-2"></i>Mail Hostname</div>
                        <div class="card-body">
                            <div class="form-control bg-light" id="mailHostnameDisplay" style="background-color: #e9ecef !important;">
                                {{MAIL_HOSTNAME}}
                            </div>
                            <small class="text-muted"><i class="fas fa-lock me-1"></i>Configurato durante l'installazione dal terminale</small>
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

        // Load on page load
        load2FAStatus();
        loadPasskeys();

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
        .ip-badge { font-family: monospace; background: #f8f9fa; padding: 2px 6px; border-radius: 3px; }
        """;
        return getHead("Sicurezza", extraStyles) + getNavbar("") + """
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
                        <div class="card-header d-flex justify-content-between">
                            <span><i class="fas fa-lock me-2"></i>Jail Attive</span>
                            <button class="btn btn-sm btn-success" onclick="installMailJails()">
                                <i class="fas fa-plus"></i> Installa Jail Mail
                            </button>
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
                </div>

                <!-- Recent Bans & Banned IPs -->
                <div class="col-md-6">
                    <div class="card mb-4">
                        <div class="card-header"><i class="fas fa-history me-2"></i>Attività Recente</div>
                        <div class="card-body" style="max-height: 300px; overflow-y: auto;" id="recentBans">
                            <p class="text-muted">Caricamento...</p>
                        </div>
                    </div>

                    <div class="card">
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
                    document.getElementById('totalBanned').textContent = data.total_banned || 0;
                    document.getElementById('totalJails').textContent = data.active_jails?.length || 0;
                    document.getElementById('totalBannedAll').textContent = data.total_banned_total || 0;

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
                    `).join('') || '<p class="text-muted">Nessuna jail attiva</p>';
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
                                <button class="btn btn-link btn-sm p-0 ms-1" onclick="showIpInfo('${ban.ip}')">
                                    <i class="fas fa-info-circle"></i>
                                </button>
                            </td>
                            <td><small>${ban.jail}</small></td>
                            <td>
                                <button class="btn btn-sm btn-outline-success" onclick="unbanIp('${ban.ip}', '${ban.jail}')">
                                    <i class="fas fa-unlock"></i>
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
            document.getElementById('ipInfo').innerHTML = '<p>Caricamento...</p>';
            new bootstrap.Modal(document.getElementById('ipModal')).show();

            fetch('/api/fail2ban?action=ip_info&ip=' + ip)
                .then(r => r.json())
                .then(data => {
                    let html = `<p><strong>IP:</strong> ${data.ip}</p>`;
                    if (data.country) html += `<p><strong>Paese:</strong> ${data.country}</p>`;
                    if (data.organization) html += `<p><strong>Organizzazione:</strong> ${data.organization}</p>`;
                    if (data.net_range) html += `<p><strong>Network:</strong> ${data.net_range}</p>`;
                    document.getElementById('ipInfo').innerHTML = html;
                });
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

        // Load on page load
        loadStatus();
        // Auto-refresh every minute
        setInterval(loadStatus, 60000);
""" + getLogoutScript() + """
    </script>
</body>
</html>
""";
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
                                   pattern="^[a-zA-Z0-9_-]{3,50}$" minlength="3" maxlength="50">
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
}
