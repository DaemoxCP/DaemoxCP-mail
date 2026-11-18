package org.daemoxcp.mail.content;

import org.daemoxcp.mail.i18n.I18n;

import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * La cornice di ogni pagina: la barra laterale a sezioni e la barra in alto, come nel pannello web.
 *
 * Le pagine mettono {{LAYOUT:pagina}} dove va la cornice (lo scrive getHead) e il server la
 * completa a ogni richiesta con expand(): la pagina in cui ti trovi e' evidenziata, e i testi
 * restano {{t:chiave}} per il passo della lingua. Da 992px la barra laterale e' fissa a sinistra;
 * sotto si apre dal pulsante in alto (offcanvas di Bootstrap, che chiude con Esc e tiene il fuoco
 * dentro finche' e' aperta).
 *
 * Prima il menu era una riga in alto con tredici voci, che sotto i 1700px non ci stavano piu' e
 * restavano solo icone; e quattro pagine (coda, limiti di invio, statistiche, amministratori) non
 * erano raggiungibili da nessun link.
 *
 * Ogni voce dice quale permesso serve per vederla e quale per cambiare qualcosa (gli stessi della
 * sua rotta in SSLMailServer.setupRoutes): il menu mostra solo le voci che il ruolo di chi guarda
 * puo' aprire, e nella barra in alto una pagina che il ruolo puo' solo guardare porta "Sola lettura".
 *
 * Per aggiungere una pagina al menu: una riga in MENU, nella sezione giusta, con la chiave del
 * nome in lang/it.json e lang/en.json.
 */
public final class Layout {

    /**
     * Una voce: la pagina (quella che passa a getHead), l'indirizzo, l'icona, la chiave del nome, il
     * permesso per vederla e quello per cambiare (o null se la pagina non cambia niente).
     */
    public record Item(String page, String href, String icon, String key, String view, String manage) {}

    /** Chi guarda la pagina: il nome, il ruolo e i permessi del ruolo. */
    public record Viewer(String username, String role, Set<String> permissions) {
        public static final Viewer NOBODY = new Viewer(null, null, Set.of());

        public boolean may(String permission) {
            return permission == null || permissions.contains(permission);
        }
    }

    /** Una sezione del menu, con la chiave del titolo (null: le voci stanno in cima, senza titolo). */
    public record Section(String key, List<Item> items) {}

    public static final List<Section> MENU = List.of(
        new Section(null, List.of(
            new Item("home", "/home", "fas fa-gauge-high", "nav.home", "home.view", null))),
        new Section("nav.section.mail", List.of(
            new Item("domains", "/domains", "fas fa-globe", "nav.domains", "mail.view", "domains.manage"),
            new Item("mailboxes", "/mailboxes", "fas fa-inbox", "nav.mailboxes", "mail.view", "mailboxes.manage"),
            new Item("aliases", "/aliases", "fas fa-share", "nav.aliases", "mail.view", "domains.manage"),
            new Item("queue", "/queue", "fas fa-list-ol", "nav.queue", "queue.view", "queue.manage"),
            new Item("ratelimits", "/ratelimits", "fas fa-stopwatch", "nav.rateLimits", "mail.view", "domains.manage"),
            new Item("statistics", "/statistics", "fas fa-chart-line", "nav.statistics", "mail.view", null))),
        new Section("nav.section.dns", List.of(
            new Item("dns", "/dns", "fas fa-sitemap", "nav.dns", "dns.view", "dns.manage"),
            new Item("ssl", "/ssl", "fas fa-lock", "nav.ssl", "dns.view", "dns.manage"),
            new Item("cloudflare", "/cloudflare", "fas fa-cloud icon-cloudflare", "nav.cloudflare", "dns.view", "dns.manage"))),
        new Section("nav.section.security", List.of(
            new Item("security", "/security", "fas fa-shield-halved", "nav.security", "security.view", "security.manage"),
            new Item("firewall", "/firewall", "fas fa-fire", "nav.firewall", "security.view", "security.manage"))),
        new Section("nav.section.system", List.of(
            new Item("updates", "/updates", "fas fa-arrow-up-right-dots", "nav.updates", "system.view", "system.manage"),
            new Item("diagnostics", "/diagnostics", "fas fa-stethoscope", "nav.diagnostics", "system.view", "system.manage"),
            new Item("logs", "/logs", "fas fa-file-lines", "nav.logs", "system.view", "system.manage"),
            new Item("paths", "/paths", "fas fa-folder-tree", "nav.paths", "system.view", null),
            new Item("admins", "/admins", "fas fa-users-gear", "nav.admins", "admins.manage", "admins.manage"),
            new Item("settings", "/settings", "fas fa-gear", "nav.settings", "settings.manage", "settings.manage")))
    );

    /** Le pagine fuori dal menu che hanno comunque un nome nella barra in alto. */
    private static final List<Item> OTHER_PAGES = List.of(
        new Item("account", "/account", "fas fa-user-gear", "nav.account", "account.self", null),
        new Item("forbidden", "/home", "fas fa-ban", "access.title", null, null));

    private static final Pattern PLACEHOLDER = Pattern.compile("\\{\\{LAYOUT:([a-z_]{0,40})\\}\\}");
    /** Le pagine senza cornice (accesso e installazione) mettono qui solo i pulsanti della lingua. */
    public static final String LANGUAGE_SWITCH = "{{LANGUAGE_SWITCH}}";

    private Layout() {}

    /**
     * I due script della cornice sono file registrati quando questa classe si carica: chi scrive i
     * file (PanelContent.generateAllContent) la fa caricare prima, chiamando questo metodo.
     */
    static void registerAssets() {
        // Basta il riferimento: i campi statici sono gia' inizializzati.
        if (LANGUAGE_SCRIPT.isEmpty() || SIDEBAR_SCRIPT.isEmpty() || REBOOT_SCRIPT.isEmpty() || CONFIRM_SCRIPT.isEmpty())
            throw new IllegalStateException();
    }

    /** Il segnaposto che una pagina mette al posto della cornice. */
    public static String placeholder(String page) {
        return "{{LAYOUT:" + page + "}}";
    }

    /** La cornice al posto del segnaposto, per chi guarda e nella lingua di questa richiesta. */
    public static String expand(String html, String lang, Viewer viewer) {
        if (html.contains(LANGUAGE_SWITCH)) html = html.replace(LANGUAGE_SWITCH, languageSwitch(lang) + LANGUAGE_SCRIPT);
        Matcher m = PLACEHOLDER.matcher(html);
        if (!m.find()) return html;
        String frame = sidebar(m.group(1), viewer) + topbar(m.group(1), lang, viewer);
        return html.substring(0, m.start()) + frame + html.substring(m.end());
    }

    /** Un testo nell'HTML: niente tag e niente {{ che il passo della lingua leggerebbe come una chiave. */
    private static String text(String s) {
        return I18n.escapeHtml(s == null ? "" : s).replace("{", "&#123;").replace("}", "&#125;");
    }

    /** Il selettore della lingua con le lingue del pannello. */
    static String languageSwitch(String lang) {
        return languageSwitch(lang, I18n.LANGUAGES);
    }

    /**
     * Il selettore della lingua. Con due lingue i pulsanti IT/EN, con premuto quello della lingua attuale: con due
     * scelte sono i piu' veloci e stanno in poco spazio. Con tre o piu' un menu (un select nativo, accessibile con la
     * tastiera e dagli screen reader, stretto anche a 375 px), con ogni lingua scritta nella lingua stessa. Il nome
     * della lingua (title e opzioni) e' sempre nella sua lingua, con lang= perche' lo screen reader lo pronunci bene.
     */
    public static String languageSwitch(String lang, java.util.List<String> languages) {
        if (languages.size() <= 2) {
            StringBuilder buttons = new StringBuilder();
            for (String l : languages) {
                boolean current = l.equals(lang);
                buttons.append("<button type=\"button\" class=\"btn btn-outline-secondary").append(current ? " active" : "")
                       .append("\" data-set-lang=\"").append(l).append("\" lang=\"").append(l).append("\" aria-pressed=\"")
                       .append(current).append("\" title=\"").append(text(I18n.nativeName(l))).append("\">")
                       .append(l.toUpperCase(java.util.Locale.ROOT)).append("</button>");
            }
            return "<div class=\"btn-group btn-group-sm\" role=\"group\" aria-label=\"{{t:layout.language}}\">" + buttons + "</div>";
        }
        StringBuilder options = new StringBuilder();
        for (String l : languages) {
            options.append("<option value=\"").append(l).append("\" lang=\"").append(l).append("\"")
                   .append(l.equals(lang) ? " selected" : "").append(">").append(text(I18n.nativeName(l))).append("</option>");
        }
        return "<label class=\"visually-hidden\" for=\"languageSelect\">{{t:layout.language}}</label>"
                + "<select id=\"languageSelect\" class=\"form-select form-select-sm w-auto\" data-set-lang-select>" + options + "</select>";
    }

    /**
     * Il cambio di lingua: si salva (nell'account e in un cookie di questo browser) e si ricarica
     * la pagina, che il server rimanda gia' tradotta. Il token CSRF e' quello della pagina: della
     * sessione, o prima di entrare quello della pagina di accesso.
     */
    private static final String LANGUAGE_SCRIPT = PageAssets.script("""
function panelSetLanguage(lang) {
    if (lang === document.documentElement.lang) return;
    var token = document.getElementById('csrf_token');
    fetch('/api/language', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ language: lang, csrf_token: token ? token.value : '' })
    }).then(function (r) { return r.json(); }).then(function (d) {
        if (d.success) location.reload(); else panelSay('danger', t('layout.languageError'));
    }).catch(function () { panelSay('danger', t('layout.languageError')); });
}
document.querySelectorAll('[data-set-lang]').forEach(function (button) {
    button.addEventListener('click', function () { panelSetLanguage(button.getAttribute('data-set-lang')); });
});
document.querySelectorAll('[data-set-lang-select]').forEach(function (select) {
    select.addEventListener('change', function () { panelSetLanguage(select.value); });
});
""", true);

    static String sidebar(String page, Viewer viewer) {
        StringBuilder menu = new StringBuilder();
        int n = 0;
        for (Section section : MENU) {
            StringBuilder links = new StringBuilder();
            for (Item item : section.items()) {
                if (item.view() == null || !viewer.may(item.view())) continue;
                boolean active = item.page().equals(page);
                links.append("<li><a class=\"sidebar-link").append(active ? " active\" aria-current=\"page" : "")
                     .append("\" href=\"").append(item.href()).append("\"><i class=\"").append(item.icon())
                     .append("\" aria-hidden=\"true\"></i><span>{{t:").append(item.key()).append("}}</span></a></li>\n");
            }
            if (links.isEmpty()) continue;
            if (section.key() == null) {
                menu.append(links);
            } else {
                String id = "sidebar-section-" + (++n);
                menu.append("<li class=\"sidebar-section\"><span class=\"sidebar-section-title\" id=\"").append(id)
                    .append("\">{{t:").append(section.key()).append("}}</span>\n<ul aria-labelledby=\"").append(id)
                    .append("\">\n").append(links).append("</ul></li>\n");
            }
        }
        return """
<a class="visually-hidden-focusable skip-link" href="#main">{{t:layout.skipToContent}}</a>
<aside class="offcanvas-lg offcanvas-start sidebar" tabindex="-1" id="sidebar" aria-labelledby="sidebarTitle">
    <div class="offcanvas-header">
        <span class="offcanvas-title sidebar-brand p-0" id="sidebarTitle"><i class="fas fa-envelope" aria-hidden="true"></i>{{t:brand.name}}</span>
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="offcanvas" data-bs-target="#sidebar" aria-label="{{t:layout.closeMenu}}"></button>
    </div>
    <div class="offcanvas-body">
        <a class="sidebar-brand d-none d-lg-flex" href="/home"><i class="fas fa-envelope" aria-hidden="true"></i>{{t:brand.name}}</a>
        <nav aria-label="{{t:layout.mainMenu}}">
            <ul class="sidebar-menu">
""" + menu + """
            </ul>
        </nav>
    </div>
</aside>
""";
    }

    static String topbar(String page, String lang, Viewer viewer) {
        String section = null;
        Item current = null;
        for (Section s : MENU) {
            for (Item item : s.items()) {
                if (item.page().equals(page)) {
                    section = s.key();
                    current = item;
                }
            }
        }
        for (Item item : OTHER_PAGES) if (item.page().equals(page)) current = item;
        String where = (section == null ? "" : "<span class=\"topbar-section\">{{t:" + section + "}}</span> "
                + "<span class=\"topbar-sep\" aria-hidden=\"true\">&rsaquo;</span> ")
                + (current == null ? "" : "<span class=\"topbar-page\">{{t:" + current.key() + "}}</span>");
        // La pagina si vede ma non si cambia: si dice subito, invece di far scoprire il divieto a ogni pulsante.
        if (current != null && current.manage() != null && viewer.may(current.view()) && !viewer.may(current.manage())) {
            where += " <span class=\"badge rounded-pill text-bg-secondary topbar-readonly\" title=\"{{t:layout.readOnlyHint}}\">"
                    + "<i class=\"fas fa-eye me-1\" aria-hidden=\"true\"></i>{{t:layout.readOnly}}</span>";
        }
        boolean account = page.equals("account");
        // Chi e' collegato e con che ruolo, sul pulsante del proprio account.
        String who = viewer.username() == null ? "{{t:nav.account}}" : text(viewer.username());
        String role = viewer.role() == null || !org.daemoxcp.mail.security.AuthStore.ROLES.contains(viewer.role()) ? ""
                : "<span class=\"badge role-badge " + viewer.role() + " ms-1 d-none d-lg-inline-block\">{{t:adm.r"
                  + Character.toUpperCase(viewer.role().charAt(0)) + viewer.role().substring(1) + "}}</span>";
        String accountButton = viewer.username() == null ? "" : "<a class=\"btn btn-sm btn-outline-secondary"
                + (account ? " active\" aria-current=\"page" : "") + "\" href=\"/account\" title=\"{{t:nav.account}}\">"
                + "<i class=\"fas fa-user-gear\" aria-hidden=\"true\"></i><span class=\"d-none d-md-inline ms-1\">" + who + "</span>"
                + role + "</a>";
        return """
<header class="topbar">
    <button type="button" class="btn topbar-toggle d-lg-none" data-bs-toggle="offcanvas" data-bs-target="#sidebar" aria-controls="sidebar" aria-label="{{t:layout.openMenu}}"><i class="fas fa-bars" aria-hidden="true"></i></button>
    <div class="topbar-title">""" + where + """
</div>
    <div class="topbar-actions">
        """ + languageSwitch(lang) + """
        <button type="button" class="theme-toggle" id="themeToggle" title="{{t:layout.theme}}" aria-label="{{t:layout.theme}}"><i class="fas fa-sun" id="themeIcon" aria-hidden="true"></i></button>
        """ + accountButton + """
        <a class="btn btn-sm btn-logout text-white" href="#" id="logoutButton" title="{{t:nav.logout}}"><i class="fas fa-right-from-bracket" aria-hidden="true"></i><span class="d-none d-md-inline ms-1">{{t:nav.logout}}</span></a>
    </div>
</header>
""" + SIDEBAR_SCRIPT + LANGUAGE_SCRIPT + CONFIRM_TEMPLATE + CONFIRM_SCRIPT + rebootFrame(viewer);
    }

    /**
     * La finestra della conferma per le operazioni pericolose, in ogni pagina:
     * la apre panel-confirm.js quando il server la chiede. Le strade sono quelle dell'account: passkey o codice via
     * email per chi ha una passkey, solo il codice per chi non ne ha.
     */
    private static final String CONFIRM_TEMPLATE = """
<template id="panelConfirmTemplate">
<div class="modal fade" id="panelConfirmModal" tabindex="-1" aria-labelledby="panelConfirmTitle" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header">
                <h2 class="modal-title h5" id="panelConfirmTitle"><i class="fas fa-user-shield me-2" aria-hidden="true"></i>{{t:acc.stepUpTitle}}</h2>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="{{t:common.close}}"></button>
            </div>
            <div class="modal-body">
                <p class="text-muted" data-confirm="choose">{{t:acc.stepUpIntro}}</p>
                <p class="text-muted" data-confirm="passkey-only" hidden>{{t:confirm.passkeyOnly}}</p>
                <p class="text-muted" data-confirm="email-only" hidden>{{t:confirm.emailOnly}}</p>
                <p class="text-muted" data-confirm="none" hidden>{{t:confirm.noMethod}}</p>
                <div class="d-grid gap-2">
                    <button type="button" class="btn btn-primary touch-target" data-confirm="passkey"><i class="fas fa-fingerprint me-2" aria-hidden="true"></i>{{t:acc.stepUpPasskey}}</button>
                    <button type="button" class="btn btn-outline-secondary touch-target" data-confirm="email"><i class="fas fa-paper-plane me-2" aria-hidden="true"></i>{{t:acc.stepUpEmail}}</button>
                    <button type="button" class="btn btn-outline-secondary touch-target" data-confirm="console" aria-expanded="false" aria-controls="panelConfirmConsoleBox"><i class="fas fa-terminal me-2" aria-hidden="true"></i>{{t:confirm.consoleButton}}</button>
                </div>
                <div class="mt-3" id="panelConfirmConsoleBox" data-confirm="console-code" hidden>
                    <label class="form-label" for="panelConfirmConsoleCode">{{t:login.consoleLabel}}</label>
                    <p class="small text-muted mb-2" id="panelConfirmConsoleHint">{{t:confirm.consoleHint}} <code id="panelConfirmConsoleCommand"></code></p>
                    <div class="input-group">
                        <input type="text" class="form-control" id="panelConfirmConsoleCode" maxlength="9" minlength="8" inputmode="numeric" autocomplete="off" placeholder="0000 0000" required aria-describedby="panelConfirmConsoleHint">
                        <button type="button" class="btn btn-primary touch-target" data-confirm="console-verify">{{t:login.verify}}</button>
                    </div>
                </div>
                <div class="mt-3" data-confirm="code" hidden>
                    <label class="form-label" for="panelConfirmCode">{{t:login.codeLabel}}</label>
                    <div class="input-group">
                        <input type="text" class="form-control" id="panelConfirmCode" maxlength="6" minlength="6" pattern="[0-9]{6}" inputmode="numeric" autocomplete="one-time-code" required aria-describedby="panelConfirmMsg">
                        <button type="button" class="btn btn-primary touch-target" data-confirm="verify">{{t:login.verify}}</button>
                    </div>
                </div>
                <div id="panelConfirmMsg" class="small mt-2" role="status" aria-live="polite"></div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-outline-secondary touch-target" data-bs-dismiss="modal">{{t:common.cancel}}</button>
            </div>
        </div>
    </div>
</div>
</template>
""";

    /** Lo script della finestra, con le funzioni WebAuthn delle pagine d'accesso, chiuso in una funzione sua. */
    private static final String CONFIRM_SCRIPT = PageAssets.script("(function () {\n" + PanelContent.getWebAuthnScript()
            + readPage("pages/panel-confirm.js") + "})();\n", false);

    /**
     * La striscia "il server va riavviato" sotto la barra in alto di ogni pagina, la finestra del
     * riavvio e quella di conferma (reperto 185). La striscia a chi vede il sistema; il pulsante e le
     * finestre a chi puo' cambiarlo. Lo script chiede lo stato al server (reboot_state, letture leggere)
     * e la mostra solo se serve.
     */
    static String rebootFrame(Viewer viewer) {
        if (!viewer.may("system.view")) return "";
        boolean manage = viewer.may("system.manage");
        return "<div class=\"px-3 pt-3\" id=\"panelRebootBanner\" hidden data-can-reboot=\"" + manage + "\"></div>\n"
                + (manage ? REBOOT_MODALS : "") + REBOOT_SCRIPT;
    }

    private static final String REBOOT_MODALS = """
<template id="panelRebootTemplates">
<div class="modal fade" id="panelRebootModal" tabindex="-1" aria-labelledby="panelRebootTitle" aria-hidden="true">
    <div class="modal-dialog modal-dialog-scrollable">
        <div class="modal-content">
            <div class="modal-header">
                <h2 class="modal-title h5" id="panelRebootTitle"><i class="fas fa-rotate-right me-2" aria-hidden="true"></i>{{t:rb.title}}</h2>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="{{t:common.close}}"></button>
            </div>
            <div class="modal-body">
                <div id="panelRebootBody" role="status" aria-live="polite"></div>
                <fieldset class="mt-2" id="panelRebootWhen">
                    <legend class="fs-6 fw-semibold">{{t:rb.when}}</legend>
                    <div class="form-check"><input class="form-check-input" type="radio" name="panelRebootMinutes" id="panelRebootIn1" value="1" checked>
                        <label class="form-check-label" for="panelRebootIn1">{{t:rb.in1}}</label></div>
                    <div class="form-check"><input class="form-check-input" type="radio" name="panelRebootMinutes" id="panelRebootIn5" value="5">
                        <label class="form-check-label" for="panelRebootIn5">{{t:rb.in5}}</label></div>
                    <div class="form-check"><input class="form-check-input" type="radio" name="panelRebootMinutes" id="panelRebootIn15" value="15">
                        <label class="form-check-label" for="panelRebootIn15">{{t:rb.in15}}</label></div>
                </fieldset>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-outline-secondary touch-target" data-bs-dismiss="modal">{{t:common.close}}</button>
                <button type="button" class="btn btn-danger touch-target" id="panelRebootGo" data-on-click="panelRebootGo()"><i class="fas fa-rotate-right me-1" aria-hidden="true"></i>{{t:rb.go}}</button>
            </div>
        </div>
    </div>
</div>
<div class="modal fade" id="panelAskModal" tabindex="-1" aria-labelledby="panelAskTitle" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h2 class="modal-title h5" id="panelAskTitle"></h2>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="{{t:common.close}}"></button>
            </div>
            <div class="modal-body" id="panelAskBody"></div>
            <div class="modal-footer">
                <button type="button" class="btn btn-outline-secondary touch-target" data-bs-dismiss="modal">{{t:common.cancel}}</button>
                <button type="button" class="btn btn-primary touch-target" id="panelAskGo" data-on-click="panelAskYes()"></button>
            </div>
        </div>
    </div>
</div>
</template>
""";

    private static final String REBOOT_SCRIPT = PageAssets.script(readPage("pages/panel-reboot.js"), false);

    private static String readPage(String path) {
        try (java.io.InputStream in = Layout.class.getClassLoader().getResourceAsStream(path)) {
            if (in == null) throw new IllegalStateException("missing resource " + path);
            return new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        } catch (java.io.IOException e) {
            throw new IllegalStateException("cannot read " + path, e);
        }
    }

    /**
     * La voce della pagina in cui ti trovi sempre a vista, anche in fondo a un menu lungo. Come
     * file, non in linea: la Content-Security-Policy non ha 'unsafe-inline' (reperto 178).
     */
    private static final String SIDEBAR_SCRIPT = PageAssets.script("""
(function () {
    var active = document.querySelector('.sidebar-link.active');
    var sidebar = document.getElementById('sidebar');
    // Solo dove la barra e' fissa e visibile: sul telefono e' chiusa, e scorrere non serve.
    if (active && sidebar && window.matchMedia('(min-width: 992px)').matches
            && active.offsetTop + active.offsetHeight > sidebar.clientHeight) {
        sidebar.scrollTop = active.offsetTop - sidebar.clientHeight / 2;
    }
})();
""", true);
}
