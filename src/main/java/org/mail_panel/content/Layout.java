package org.mail_panel.content;

import org.mail_panel.i18n.I18n;

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
            new Item("cloudflare", "/cloudflare", "fas fa-cloud icona-cloudflare", "nav.cloudflare", "dns.view", "dns.manage"))),
        new Section("nav.section.security", List.of(
            new Item("security", "/security", "fas fa-shield-halved", "nav.security", "security.view", "security.manage"),
            new Item("firewall", "/firewall", "fas fa-fire", "nav.firewall", "security.view", "security.manage"))),
        new Section("nav.section.system", List.of(
            new Item("updates", "/updates", "fas fa-arrow-up-right-dots", "nav.updates", "system.view", "system.manage"),
            new Item("logs", "/logs", "fas fa-file-lines", "nav.logs", "system.view", "system.manage"),
            new Item("paths", "/paths", "fas fa-folder-tree", "nav.paths", "system.view", null),
            new Item("admins", "/admins", "fas fa-users-gear", "nav.admins", "admins.manage", "admins.manage"),
            new Item("settings", "/settings", "fas fa-gear", "nav.settings", "settings.manage", "settings.manage")))
    );

    /** Le pagine fuori dal menu che hanno comunque un nome nella barra in alto. */
    private static final List<Item> OTHER_PAGES = List.of(
        new Item("install", "/install", "fas fa-download", "nav.install", null, null),
        new Item("account", "/account", "fas fa-user-gear", "nav.account", "account.self", null),
        new Item("forbidden", "/home", "fas fa-ban", "access.title", null, null));

    private static final Pattern PLACEHOLDER = Pattern.compile("\\{\\{LAYOUT:([a-z_]{0,40})\\}\\}");
    /** Le pagine senza cornice (accesso e installazione) mettono qui solo i pulsanti della lingua. */
    public static final String LANGUAGE_SWITCH = "{{LANGUAGE_SWITCH}}";

    private Layout() {}

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

    /** I pulsanti IT/EN, con premuto quello della lingua attuale. */
    static String languageSwitch(String lang) {
        StringBuilder languages = new StringBuilder();
        for (String l : I18n.LANGUAGES) {
            boolean current = l.equals(lang);
            languages.append("<button type=\"button\" class=\"btn btn-outline-secondary").append(current ? " active" : "")
                     .append("\" data-set-lang=\"").append(l).append("\" lang=\"").append(l).append("\" aria-pressed=\"")
                     .append(current).append("\" title=\"{{t:layout.language.").append(l).append("}}\">")
                     .append(l.toUpperCase()).append("</button>");
        }
        return "<div class=\"btn-group btn-group-sm\" role=\"group\" aria-label=\"{{t:layout.language}}\">" + languages + "</div>";
    }

    /**
     * Il cambio di lingua: si salva (nell'account e in un cookie di questo browser) e si ricarica
     * la pagina, che il server rimanda gia' tradotta. Il token CSRF e' quello della pagina: della
     * sessione, o prima di entrare quello della pagina di accesso.
     */
    private static final String LANGUAGE_SCRIPT = """
<script>
document.querySelectorAll('[data-set-lang]').forEach(function (button) {
    button.addEventListener('click', function () {
        var lang = button.getAttribute('data-set-lang');
        if (lang === document.documentElement.lang) return;
        var token = document.getElementById('csrf_token');
        fetch('/api/language', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ language: lang, csrf_token: token ? token.value : '' })
        }).then(function (r) { return r.json(); }).then(function (d) {
            if (d.success) location.reload(); else alert(t('layout.languageError'));
        }).catch(function () { alert(t('layout.languageError')); });
    });
});
</script>
""";

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
        <span class="offcanvas-title sidebar-brand p-0" id="sidebarTitle"><i class="fas fa-envelope" aria-hidden="true"></i>Mail Control Panel</span>
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="offcanvas" data-bs-target="#sidebar" aria-label="{{t:layout.closeMenu}}"></button>
    </div>
    <div class="offcanvas-body">
        <a class="sidebar-brand d-none d-lg-flex" href="/home"><i class="fas fa-envelope" aria-hidden="true"></i>Mail Control Panel</a>
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
        String role = viewer.role() == null || !org.mail_panel.security.AuthStore.ROLES.contains(viewer.role()) ? ""
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
<script>
// La voce della pagina in cui ti trovi sempre a vista, anche in fondo a un menu lungo.
(function () {
    var active = document.querySelector('.sidebar-link.active');
    var sidebar = document.getElementById('sidebar');
    // Solo dove la barra e' fissa e visibile: sul telefono e' chiusa, e scorrere non serve.
    if (active && sidebar && window.matchMedia('(min-width: 992px)').matches
            && active.offsetTop + active.offsetHeight > sidebar.clientHeight) {
        sidebar.scrollTop = active.offsetTop - sidebar.clientHeight / 2;
    }
})();
</script>
""" + LANGUAGE_SCRIPT;
    }
}
