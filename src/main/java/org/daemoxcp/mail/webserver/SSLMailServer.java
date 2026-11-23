package org.daemoxcp.mail.webserver;

import org.daemoxcp.mail.util.ErrorText;
import org.daemoxcp.mail.database.SqlCatalog;

import com.sun.net.httpserver.*;
import org.json.JSONArray;
import org.json.JSONObject;
import org.daemoxcp.mail.Main;
import org.daemoxcp.mail.content.Layout;
import org.daemoxcp.mail.database.MailDatabase;
import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.integration.RoundcubeSsoManager;
import org.daemoxcp.mail.integration.RspamdManager;
import org.daemoxcp.mail.integration.SieveGenerator;
import org.daemoxcp.mail.monitoring.LogManager;
import org.daemoxcp.mail.monitoring.MailQueueManager;
import org.daemoxcp.mail.scripts.*;
import org.daemoxcp.mail.security.AcmeManager;
import org.daemoxcp.mail.security.DkimManager;
import org.daemoxcp.mail.security.DkimRotationScheduler;
import org.daemoxcp.mail.security.DnsRecordsGenerator;
import org.daemoxcp.mail.security.Fail2banManager;
import org.daemoxcp.mail.security.AuthStore;
import org.daemoxcp.mail.system.UpdateManager;

import javax.net.ssl.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * HTTPS Server for DaemoxCP Mail
 * With login system, sessions, and CSRF protection
 *
 * Uses MySQL only (no SQLite)
 */
public class SSLMailServer {

    /**
     * How this server runs:
     * <ul>
     *   <li>LEGACY: today's mode, a single root process that serves everything;</li>
     *   <li>ROOT_PART: the root part of the separated panel. No port: it only serves the APIs that the web part
     *       passes to it on the socket (serveForwarded), and does repairs and background jobs as today;</li>
     *   <li>WEB_PART: the web part, with the daemoxcp_mail user. The panel's port, the filters, the login, the
     *       pages and the public routes; the APIs of logged-in users it passes to the root part
     *       (forwardToRoot). No repairs and no background jobs.</li>
     * </ul>
     */
    public enum Mode { LEGACY, ROOT_PART, WEB_PART }

    /**
     * The APIs that the web part serves by itself, with the daemoxcp_mail user: they do not need root
     * (MySQL, SQLite read-only, the vault key read-only, the network). Domains
     * and mailboxes ask the root part for one thing only, the closed operation "mail-folders" (rootOperations),
     * without parameters. All the other APIs go to the root part, /api/account included: administrators,
     * passkeys, codes and sessions are written only by the root part (0.8.2, A).
     */
    static final java.util.Set<String> WEB_LOCAL_API = java.util.Set.of("/api/theme", "/api/domains",
            "/api/mailboxes", "/api/mailconfig", "/api/webmail", "/api/statistics", "/api/apple-profile",
            "/api/blacklist_check");
    // /apple-profile (the download) has been gone since 2026-11-23: the profile is signed with the key of the
    // mail certificate, which only root can read (AppleProfile.sign). The status and the preview
    // (/api/apple-profile) stay here.

    /**
     * The operations that the web part asks the root part for by name, without parameters, instead of passing
     * it a request: the name, who can ask for it (one of the permissions), what it does. The root part rereads
     * the session and the role from the database, as for forwarded requests.
     */
    private record RootOperation(java.util.Set<String> anyOf,
                                 java.util.function.BiConsumer<WebSessions.Current, RootChannel.Request> work) {}

    private Map<String, RootOperation> rootOperations() {
        return Map.of(
                // The mail folders of the mailboxes (from the names in MySQL, rechecked by SafeNames) and the reload
                // of Postfix and Dovecot, after adding or removing a domain or a mailbox.
                "mail-folders", new RootOperation(java.util.Set.of(DOMAINS, MAILBOXES), (s, r) -> regenerateMailConfigs()),
                // Logout: the session of whoever asks for it, and no other. Sessions are removed only by the root
                // part (A).
                "logout", new RootOperation(java.util.Set.of(ACCOUNT), (s, r) -> {
                    Main.sessions.revokeById(s.id(), s.admin().id());
                    logAudit("LOGOUT", r.clientIp(), "user=" + s.admin().username());
                }));
    }

    /** The HTTPS server; null in the root part, which has no ports (becomeLegacy creates it if needed). */
    private HttpsServer server;
    private SSLContext tlsContext;
    /** The routes in the order they are declared: becomeLegacy registers them on the server it creates. */
    private final java.util.List<Object[]> declared = new java.util.ArrayList<>();
    private final int port;
    private volatile Mode mode = Mode.LEGACY;
    private static final Logger LOGGER = Logger.getLogger(SSLMailServer.class.getName());

    // Managers for advanced features
    private DkimManager dkimManager;
    private DkimRotationScheduler dkimRotationScheduler;
    private org.daemoxcp.mail.security.CloudflareManager cloudflareManager;
    private RspamdManager rspamdManager;
    private SieveGenerator sieveGenerator;
    private DnsRecordsGenerator dnsGenerator;
    private AcmeManager acmeManager;
    private org.daemoxcp.mail.system.PeriodicReport periodicReport;
    private LogManager logManager;
    private MailQueueManager queueManager;
    private RoundcubeSsoManager ssoManager;
    private Fail2banManager fail2banManager;
    private org.daemoxcp.mail.security.PfFirewallManager firewallManager;
    /** Passwordless login: /api/login and /api/account. */
    private final AuthHandlers auth = new AuthHandlers(this);
    final WebmailPasswordHandler webmail = new WebmailPasswordHandler(this);

    // SSL certificate content (for constructor with PEM)
    private String sslCertContent;
    private String sslKeyContent;

    public SSLMailServer(int port) throws Exception {
        this.port = port;
        this.server = HttpsServer.create(new InetSocketAddress(port), 0);

        // Setup SSL
        SSLContext sslContext = createSSLContext();
        server.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
            public void configure(HttpsParameters params) {
                try {
                    SSLContext context = getSSLContext();
                    SSLParameters sslParams = context.getDefaultSSLParameters();
                    params.setSSLParameters(sslParams);
                } catch (Exception e) {
                    LOGGER.log(Level.SEVERE, "Error configuring SSL", e);
                }
            }
        });

        // Setup routes
        setupRoutes();
    }

    /**
     * Constructor with SSL certificate and key content from SQLite config
     */
    public SSLMailServer(int port, String certContent, String keyContent) throws Exception {
        this(port, certContent, keyContent, Mode.LEGACY);
    }

    /**
     * With the mode. In ROOT_PART no HTTPS server is created: the routes are there (routes, handlers) but
     * there is not even a socket. HttpsServer.create() without an address still opens an unbound TCP socket,
     * which sockstat shows (measured on the VM on 2026-11-07). If the web part does not start,
     * becomeLegacy() creates the server on the port and the panel serves everything from root as before.
     */
    public SSLMailServer(int port, String certContent, String keyContent, Mode mode) throws Exception {
        this.port = port;
        this.mode = mode;
        this.sslCertContent = certContent;
        this.sslKeyContent = keyContent;

        // Setup SSL from provided content
        this.tlsContext = createSSLContextFromPEM(certContent, keyContent);
        if (mode != Mode.ROOT_PART) this.server = newHttpsServer();

        // Setup routes
        setupRoutes();
    }

    /** The HTTPS server on the port, with the panel's TLS context. */
    private HttpsServer newHttpsServer() throws IOException {
        HttpsServer s = HttpsServer.create(new InetSocketAddress(port), 0);
        s.setHttpsConfigurator(new HttpsConfigurator(tlsContext) {
            public void configure(HttpsParameters params) {
                try {
                    SSLContext context = getSSLContext();
                    SSLParameters sslParams = context.getDefaultSSLParameters();
                    params.setSSLParameters(sslParams);
                } catch (Exception e) {
                    LOGGER.log(Level.SEVERE, "Error configuring SSL", e);
                }
            }
        });
        return s;
    }

    // The permissions, by name: the same strings as AuthStore.
    private static final String HOME = "home.view", ACCOUNT = "account.self";
    private static final String MAIL_VIEW = "mail.view", MAILBOXES = "mailboxes.manage", DOMAINS = "domains.manage";
    private static final String QUEUE_VIEW = "queue.view", QUEUE_MANAGE = "queue.manage";
    private static final String DNS_VIEW = "dns.view", DNS_MANAGE = "dns.manage";
    private static final String SECURITY_VIEW = "security.view", SECURITY_MANAGE = "security.manage";
    private static final String SYSTEM_VIEW = "system.view", SYSTEM_MANAGE = "system.manage";
    private static final String SETTINGS = "settings.manage", ADMINS = "admins.manage", VAULT = "vault.manage", SSH_KEYS = "ssh.manage";

    /**
     * The header of the 403 for a dangerous operation without a recent confirmation: the pages' fetch wrapper
     * opens the common confirmation window (panel-confirm.js) and repeats the request.
     */
    static final String CONFIRMATION_HEADER = "X-Panel-Confirmation";

    /**
     * The header of the 401 for a session that does not exist (any more): the open page goes to the login
     * (finding 184).
     */
    static final String SESSION_ENDED_HEADER = "X-Panel-Session";
    /**
     * The database does not answer, so the session could not be read: 503 with this header, never 401.
     * On the production server, on 2026-11-09, MySQL restarted inside "Update all": for 9 seconds every request
     * got "unauthorized", the tab lost the job in progress and filled up with errors, and a page opened at that
     * moment led to the login with a good session (finding 209). The request is stopped before doing anything:
     * the pages repeat it by themselves when the database comes back (the fetch wrapper in the head).
     */
    static final String DATABASE_HEADER = "X-Panel-Database";

    /** /api/updates: the actions that read (previews, states, diagnoses). All the others change the system. */
    static final Map<String, String> UPDATES_ACTIONS = Access.actions(SYSTEM_VIEW,
        "packages_status", "packages_overview", "updates_status", "compatibility", "dovecot_config_dump", "maintenance_preview", "plan",
        "mysql84_preflight", "dovecot24_preflight", "broken_libs", "mysql_client_diag", "defaults_check", "branch_status", "branch_preview",
        "system_report", "os_status", "reboot_preview", "reboot_state", "rc_state", "system_summary", "cf_intervals",
        "rc_remove_preview", "rc_preview", "os_upgrade_targets", "os_upgrade_preflight", "os_upgrade_instructions",
        "os_upgrade_verify", "jump_state", "be_list", "ssl_usage", "removal_candidates", "panel_uses", "deep_scan",
        "panel_env", "dovecot24_preview", "rspamd_timeout", "web_diagnosis", "web443_status", "web443_config",
        "panel_release", "panel_release_check",
        "mtasts_plan", "watch", "watch_changes", "openssl_expiry", "port465_status",
        "python_preflight", "python_leftovers", "java_preflight", "java_status", "roundcube_preflight",
        "roundcube_diag", "roundcube_nginx_preview", "package_preflight", "job_status", "interruption_status",
        "journal_list", "journal_read", "package_turn", "provider_firewall", "smtp_out");

    /** The declared routes, with their access: the tests check that they are all there. */
    private final Map<String, Access> routes = new java.util.LinkedHashMap<>();
    /** The handler of each route: the root part calls it for the requests that the web part passes to it. */
    private final Map<String, HttpHandler> handlers = new java.util.HashMap<>();

    /** Every registered route and who can use it. */
    public Map<String, Access> routes() {
        return java.util.Collections.unmodifiableMap(routes);
    }

    private void setupRoutes() {
        // ---------- Public ----------
        // A route that is PUBLIC by necessity: it is Thunderbird that asks for it, before the user has
        // even entered a password. It returns only server names and port numbers, already public
        // in the DNS records, and only for the domains that this panel really hosts.
        context("/autoconfig", Access.PUBLIC, this::handlePublicAutoconfig);
        // The MTA-STS policy is read by sending servers all over the world, without credentials: it
        // contains only the name of our own MX, which is already in the DNS records.
        context("/mta-sts", Access.PUBLIC, this::handlePublicMtaSts);
        // Font Awesome and Bootstrap from the jar: the login page needs them too.
        context("/fa", Access.PUBLIC, this::handleStatic);
        context("/vendor", Access.PUBLIC, this::handleStatic);
        // The scripts' dictionary and the language switch: the login and installation pages
        // already have the IT/EN choice. /api/language checks the page token by itself.
        context("/i18n/", Access.PUBLIC, this::handleI18nScript);
        // The pages' scripts and stylesheets as files (PageAssets): those of the protected pages
        // only to logged-in users, the handler checks it.
        context("/assets/", Access.PUBLIC, this::handleAsset);
        context("/api/language", Access.PUBLIC, this::handleApiLanguage);
        context("/", Access.PUBLIC, this::handleRoot);
        context("/index", Access.PUBLIC, this::handleIndex);
        context("/api/login", Access.PUBLIC, auth::handleLogin);
        context("/setup", Access.PUBLIC, this::handleSetup);
        // Closes only the session of the caller.
        context("/api/logout", Access.PUBLIC, this::handleLogout);
        // Only for the webmail on the same server (loopback + key): password change and copy into the vault
        context(org.daemoxcp.mail.integration.WebmailPasswordConfig.PATH, Access.PUBLIC, webmail::handlePasswordChange);
        context(org.daemoxcp.mail.integration.WebmailPasswordConfig.VAULT_PATH, Access.PUBLIC, webmail::handleVaultCopy);
        context(org.daemoxcp.mail.integration.WebmailPasswordConfig.CLEANUP_PATH, Access.PUBLIC, webmail::handleCleanup);

        // ---------- Home e account ----------
        context("/home", Access.page(HOME), this::handleProtectedPage);
        context("/api/status", Access.api(HOME), this::handleApiStatus);
        context("/api/stats", Access.api(HOME), this::handleApiStats);
        context("/api/versions", Access.api(HOME), this::handleApiVersions);
        context("/account", Access.page(ACCOUNT), this::handleProtectedPage);
        context("/api/account", Access.api(ACCOUNT), auth::handleAccount);
        context("/api/theme", Access.api(ACCOUNT), this::handleApiTheme);

        // ---------- Posta ----------
        context("/domains", Access.page(MAIL_VIEW), this::handleProtectedPage);
        context("/api/domains", Access.api(MAIL_VIEW, DOMAINS), this::handleApiDomains);
        context("/mailboxes", Access.page(MAIL_VIEW), this::handleProtectedPage);
        context("/api/mailboxes", Access.api(MAIL_VIEW, MAILBOXES), this::handleApiMailboxes);
        // "Show password": the copy in the vault is read only by the root part, which alone has the
        // private key (0.8, point 3).
        context("/api/mailbox-password", Access.api(MAILBOXES).confirmingAlways(), this::handleApiMailboxPassword);
        context("/api/mailconfig", Access.api(MAIL_VIEW), this::handleApiMailConfig);
        context("/aliases", Access.page(MAIL_VIEW), this::handleProtectedPage);
        context("/api/aliases", Access.api(MAIL_VIEW, DOMAINS), this::handleApiAliases);
        // How much of its limit each mailbox uses (DovecotQuota, doveadm quota get): read-only, from the root part.
        context("/api/mailbox-quota", Access.api(MAIL_VIEW), this::handleApiMailboxQuota);
        // Entering a mailbox's webmail means reading its mail.
        context("/api/webmail", Access.api(MAILBOXES), this::handleApiWebmail);
        context("/api/webmail/open", Access.api(MAILBOXES), this::handleApiWebmailOpen);
        context("/api/autoresponder", Access.api(MAIL_VIEW, MAILBOXES), this::handleApiAutoResponder);
        context("/api/sieve", Access.api(MAIL_VIEW, MAILBOXES), this::handleApiSieve);
        context("/api/forwarding", Access.api(MAIL_VIEW, MAILBOXES), this::handleApiForwarding);
        context("/queue", Access.page(QUEUE_VIEW), this::handleProtectedPage);
        // The content of a queued message is someone's mail: ?action=message requires queue.manage.
        context("/api/queue", Access.api(QUEUE_VIEW, QUEUE_MANAGE, Access.actions(QUEUE_MANAGE, "message")), this::handleApiQueue);
        context("/ratelimits", Access.page(MAIL_VIEW), this::handleProtectedPage);
        context("/api/ratelimits", Access.api(MAIL_VIEW, DOMAINS), this::handleApiRateLimits);
        context("/statistics", Access.page(MAIL_VIEW), this::handleProtectedPage);
        context("/api/statistics", Access.api(MAIL_VIEW), this::handleApiStatistics);
        context("/api/apple-profile", Access.api(MAIL_VIEW, DNS_MANAGE, Access.actions(MAIL_VIEW, "status", "preview")), this::handleApiAppleProfile);
        context("/apple-profile", Access.api(MAIL_VIEW), this::handleDownloadAppleProfile);

        // ---------- DNS and certificates ----------
        context("/dns", Access.page(DNS_VIEW), this::handleProtectedPage);
        context("/api/dns", Access.api(DNS_VIEW, DNS_MANAGE), this::handleApiDns);
        // The actions that only read (checked method by method: no writes): they pass even during a scheduled
        // restart. rotate_check and verify_active_dns write the state or the log of the rotation: they change things.
        context("/api/dkim", Access.api(DNS_VIEW, DNS_MANAGE).reading("domains_summary", "orphans_scan", "rotate_status", "schedule_get"),
                this::handleApiDkim);
        context("/ssl", Access.page(DNS_VIEW), this::handleProtectedPage);
        context("/api/ssl", Access.api(DNS_VIEW, DNS_MANAGE, Access.actions(DNS_VIEW, "get_auto_renewal_settings", "check_self_signed")), this::handleApiSsl);
        context("/cloudflare", Access.page(DNS_VIEW), this::handleProtectedPage);
        context("/api/cloudflare", Access.api(DNS_VIEW, DNS_MANAGE), this::handleApiCloudflare);
        context("/api/autodns", Access.api(DNS_VIEW, DNS_MANAGE, Access.actions(
                DNS_VIEW, "status", "mtasts_status", "job_status",
                MAIL_VIEW, "mailboxes",
                MAILBOXES, "mailbox_create",
                DOMAINS, "alias_create")), this::handleApiAutoDns);
        context("/api/autoconfig", Access.api(DNS_VIEW, DNS_MANAGE, Access.actions(DNS_VIEW, "status", "preview")), this::handleApiAutoconfig);

        // ---------- Security ----------
        context("/security", Access.page(SECURITY_VIEW), this::handleProtectedPage);
        context("/firewall", Access.page(SECURITY_VIEW), this::handleProtectedPage);
        context("/api/fail2ban", Access.api(SECURITY_VIEW, SECURITY_MANAGE, Access.actions(SECURITY_VIEW, "verify_filter", "pf_comparison"))
                .reading("banned", "get_jail_config", "ip_info", "jail", "live_state", "live_state_all", "permaban_list", "status"), this::handleApiFail2ban);
        context("/api/fail2ban_health", Access.api(SECURITY_VIEW, SECURITY_MANAGE), this::handleApiFail2banHealth);
        context("/api/clamav_health", Access.api(SECURITY_VIEW, SECURITY_MANAGE, Access.actions(SECURITY_VIEW, "test_eicar")), this::handleApiClamavHealth);
        context("/api/unbound_health", Access.api(SECURITY_VIEW, SECURITY_MANAGE, Access.actions(SECURITY_VIEW, "test_query")), this::handleApiUnboundHealth);
        context("/api/blacklist_check", Access.api(SECURITY_VIEW), this::handleApiBlacklistCheck);
        context("/api/firewall", Access.api(SECURITY_VIEW, SECURITY_MANAGE), this::handleApiFirewall);
        context("/api/rspamd", Access.api(SECURITY_VIEW, SECURITY_MANAGE).reading("quarantine", "stats", "scan"), this::handleApiRspamd);

        // ---------- Sistema ----------
        context("/updates", Access.page(SYSTEM_VIEW), this::handleProtectedPage);
        context("/diagnostics", Access.page(SYSTEM_VIEW), this::handleProtectedPage);
        context("/api/updates", Access.api(SYSTEM_VIEW, SYSTEM_MANAGE, UPDATES_ACTIONS).reading("service_users"), this::handleApiUpdates);
        context("/logs", Access.page(SYSTEM_VIEW), this::handleProtectedPage);
        context("/api/logs", Access.api(SYSTEM_VIEW, SYSTEM_MANAGE).reading("search"), this::handleApiLogs);
        context("/paths", Access.page(SYSTEM_VIEW), this::handleProtectedPage);
        context("/api/system_paths", Access.api(SYSTEM_VIEW), this::handleApiSystemPaths);
        // The panel card at the top of the dashboard (finding 183): since it runs for whoever sees the
        // dashboard, the technical details (version, build, jar fingerprint, process) require system.view.
        context("/api/panel_info", Access.api(HOME, HOME, Access.actions(SYSTEM_VIEW, "details")), this::handleApiPanelInfo);
        context("/api/service", Access.api(SYSTEM_MANAGE), this::handleApiService);
        context("/api/timezone-diag", Access.api(SYSTEM_VIEW, SYSTEM_MANAGE), this::handleApiTimezoneDiag);
        context("/api/postfix-aliases-health", Access.api(SYSTEM_VIEW, SYSTEM_MANAGE), this::handleApiPostfixAliases);
        context("/api/sso", Access.api(SYSTEM_VIEW, SYSTEM_MANAGE).reading("status"), this::handleApiSso);
        context("/admins", Access.page(ADMINS), this::handleProtectedPage);
        // The vault key: exporting or changing it requires vault.manage (and a recent confirmation).
        context("/api/admins", Access.api(ADMINS, ADMINS, Access.actions(VAULT, "vault_backup_key", "vault_rotate_key")), this::handleApiAdmins);
        context("/settings", Access.page(SETTINGS), this::handleProtectedPage);
        context("/api/report", Access.api(SETTINGS).reading("identity", "preview", "status"), this::handleApiReport);
        context("/api/hostname", Access.api(SETTINGS).reading("check_dns"), this::handleApiHostname);
        context("/api/roundcube-domain", Access.api(SETTINGS).reading("check_dns"), this::handleApiRoundcubeDomain);
        // Root's SSH keys: viewing them, adding some, removing some (with a recent confirmation). Never sshd_config.
        context("/api/ssh-keys", Access.api(SSH_KEYS), this::handleApiSshKeys);
        // POP3 on or off: Dovecot, the pf ports and those of the country rules (Pop3, PfPolicy).
        context("/api/pop3", Access.api(SETTINGS), this::handleApiPop3);
        // IPv4, IPv6 or both: Postfix, Dovecot, nginx and pf (IpFamily). SSH never follows the choice.
        context("/api/ip-family", Access.api(SETTINGS), this::handleApiIpFamily);
        // The server's addresses and the guide between IPv4 and IPv6, in both directions (ServerAddresses).
        context("/api/server-addresses", Access.api(SETTINGS), this::handleApiServerAddresses);
    }

    /**
     * A route, with the request's language fixed for the whole time the handler
     * serves it: the server's messages (I18n.tr) come out in the requester's language. Here the language
     * cookie is enough (or, without it, the browser's language): every page aligns it with the choice saved
     * in the account (renderPage), and the scripts' calls come from a page.
     */
    private void context(String path, Access access, HttpHandler handler) {
        java.util.Objects.requireNonNull(access, "every route declares its access");
        if (routes.put(path, access) != null) throw new IllegalStateException("Route declared twice: " + path);
        handlers.put(path, handler);
        declared.add(new Object[]{path, access, handler});
        if (server != null) createContext(path, access, handler);
    }

    /** The route on the HTTPS server, with the filters: Host, language, permission, CSRF. */
    private HttpContext createContext(String path, Access access, HttpHandler handler) {
        // In the web part the APIs of logged-in users go to the root part, after all the filters below; and
        // so does the login, which the root part decides (A).
        HttpHandler served = handler;
        if (mode == Mode.WEB_PART && access.kind() == Access.Kind.API && !WEB_LOCAL_API.contains(path))
            served = exchange -> forwardToRoot(exchange, path);
        else if (mode == Mode.WEB_PART && path.equals("/api/login"))
            served = this::forwardSignIn;
        else if (mode == Mode.WEB_PART && WEBMAIL_ROUTES.contains(path))
            served = exchange -> forwardWebmail(exchange, path);
        HttpContext context = server.createContext(path, served);
        // First of all, a HEAD becomes a GET without a body for all those that follow (HeadExchange): every
        // handler writes the response as always, and nobody needs to know about HEADs.
        context.getFilters().add(new Filter() {
            @Override
            public void doFilter(HttpExchange exchange, Chain chain) throws IOException {
                chain.doFilter("HEAD".equals(exchange.getRequestMethod()) ? new HeadExchange(exchange) : exchange);
            }

            @Override
            public String description() {
                return "HEAD answered like GET, without the body";
            }
        });
        if (!HOST_CHECK_EXEMPT.contains(path)) {
            context.getFilters().add(new Filter() {
                @Override
                public void doFilter(HttpExchange exchange, Chain chain) throws IOException {
                    if (hostAllowed(exchange)) chain.doFilter(exchange);
                    else sendMisdirected(exchange);
                }

                @Override
                public String description() {
                    return "the Host this panel answers to";
                }
            });
        }
        context.getFilters().add(new Filter() {
            @Override
            public void doFilter(HttpExchange exchange, Chain chain) throws IOException {
                I18n.setCurrent(I18n.languageOf(exchange, null));
                try {
                    chain.doFilter(exchange);
                } finally {
                    I18n.clearCurrent();
                    forgetCurrentSession();
                }
            }

            @Override
            public String description() {
                return "request language";
            }
        });
        if (access.kind() != Access.Kind.PUBLIC) {
            context.getFilters().add(new Filter() {
                @Override
                public void doFilter(HttpExchange exchange, Chain chain) throws IOException {
                    if (accessAllowed(exchange, access)) chain.doFilter(exchange);
                }

                @Override
                public String description() {
                    return "named permission of the route";
                }
            });
        }
        if (!CSRF_EXEMPT.contains(path)) {
            context.getFilters().add(new Filter() {
                @Override
                public void doFilter(HttpExchange exchange, Chain chain) throws IOException {
                    if (csrfAllowed(exchange)) chain.doFilter(exchange);
                    else sendCsrfError(exchange);
                }

                @Override
                public String description() {
                    return "CSRF token on every state-changing request";
                }
            });
        }
        if (access.kind() == Access.Kind.API) {
            // Before the recent confirmation: with a scheduled restart we do not ask for the passkey only to
            // refuse afterwards.
            context.getFilters().add(new Filter() {
                @Override
                public void doFilter(HttpExchange exchange, Chain chain) throws IOException {
                    if (!restartLocked(exchange, access, path)) chain.doFilter(exchange);
                }

                @Override
                public String description() {
                    return "no change while a restart of the server is scheduled";
                }
            });
            context.getFilters().add(new Filter() {
                @Override
                public void doFilter(HttpExchange exchange, Chain chain) throws IOException {
                    if (!confirmationMissing(exchange, access)) chain.doFilter(exchange);
                }

                @Override
                public String description() {
                    return "a recent confirmation (passkey or email code) for dangerous operations";
                }
            });
        }
        return context;
    }

    /**
     * The route's permission for this request. True if the request can go on; false if
     * the response has already been sent: without a session a page redirects to the login and an API says
     * 401; without the permission a page shows "access denied" (403) in the panel frame and
     * an API answers 403 with forbidden: true. For action-based APIs the action comes from ?action= or
     * from the JSON body, which is put back in its place for the handler.
     */
    /** Where accessAllowed leaves the action of the request it has read (from the body, for a POST). */
    private static final String ACTION_ATTRIBUTE = "daemoxcp.mail.action";

    /**
     * A dangerous operation without a recent confirmation (Access.needsConfirmation): true, and the response
     * has already been sent (sendConfirmationNeeded). The confirmation date is written only by the root part,
     * which verifies passkeys and codes (A); the root part rereads it from the database for every request that
     * reaches it and checks it too, so a web part that skipped this check would gain nothing. It comes after
     * the permission, and in the web part also after the CSRF: a request from another site does not get this
     * far.
     */
    private boolean confirmationMissing(HttpExchange exchange, Access access) throws IOException {
        Object action = exchange.getAttribute(ACTION_ATTRIBUTE);
        if (!access.needsConfirmation(exchange.getRequestMethod(), action instanceof String a ? a : null)) return false;
        Optional<WebSessions.Current> session = currentSession(exchange);
        if (session.isPresent() && session.get().reauthenticatedWithin(AuthHandlers.REAUTH_SECONDS)) return false;
        sendConfirmationNeeded(exchange);
        return true;
    }

    /** The header of the response that refuses a change during a scheduled restart: the pages reread the banner. */
    static final String RESTART_HEADER = "X-Panel-Restart";

    /**
     * A server restart is scheduled and this request would change something (Access.changes): true, and the
     * response has already been sent (409). Reads, cancelling the restart and restarting now remain allowed
     * (RestartLock.exempt). Whoever knows decides: the root part and the single-piece panel look at the
     * shutdown process; the web part, which cannot see the root's processes, asks the root part, for every
     * change (before the recent confirmation, which otherwise would ask for the passkey for a request that the
     * root part will refuse); the root part checks again for those it is passed. If it cannot be known, the
     * request is refused: a change postponed by a minute costs less than one left half-done.
     */
    private boolean restartLocked(HttpExchange exchange, Access access, String route) throws IOException {
        if (access.kind() != Access.Kind.API) return false;
        Object a = exchange.getAttribute(ACTION_ATTRIBUTE);
        String action = a instanceof String x ? x : null;
        if (!access.changes(exchange.getRequestMethod(), action)
                || org.daemoxcp.mail.system.RestartLock.exempt(route, action)) return false;
        org.daemoxcp.mail.system.RestartLock.State st = mode == Mode.WEB_PART ? askRootRestartState()
                : org.daemoxcp.mail.system.RestartLock.current();
        if (st.known() && !st.scheduled()) return false;
        logAudit("RESTART_LOCK_REFUSED", getClientIp(exchange), "route=" + route + (action == null ? "" : " action=" + action)
                + (st.known() ? "" : " (restart state unknown)"));
        JSONObject body = new JSONObject().put("success", false).put("restart_scheduled", st.scheduled())
                .put("error", I18n.tr(st.known() ? "server.restartLock.refused" : "server.restartLock.unknown"));
        if (st.at() > 0) body.put("restart_at", st.at());
        byte[] json = body.toString().getBytes(StandardCharsets.UTF_8);
        addSecurityHeaders(exchange);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.getResponseHeaders().set(RESTART_HEADER, "scheduled");
        exchange.sendResponseHeaders(409, json.length);
        try (OutputStream os = exchange.getResponseBody()) { os.write(json); }
        return true;
    }

    /**
     * The web part asks the root part whether a restart is scheduled, on behalf of whoever made the current
     * request.
     */
    @SuppressWarnings("unchecked")
    private org.daemoxcp.mail.system.RestartLock.State askRootRestartState() {
        Object[] cached = CURRENT_SESSION.get();
        Optional<WebSessions.Current> s = cached == null ? Optional.empty() : (Optional<WebSessions.Current>) cached[1];
        if (s.isEmpty()) return org.daemoxcp.mail.system.RestartLock.State.UNKNOWN;
        HttpExchange ex = (HttpExchange) cached[0];
        String route = "/op/restart-state";
        RootChannel.Request req = new RootChannel.Request(route, "POST", route, null, Map.of(), getClientIp(ex), I18n.current(),
                s.get().admin().id(), s.get().id(), null);
        try (RootChannel.Exchange answer = RootChannel.send(org.daemoxcp.mail.system.PanelSeparation.socket(), req)) {
            JSONObject j = new JSONObject(new String(answer.body().readAllBytes(), StandardCharsets.UTF_8));
            if (answer.head().status() != 200 || !j.optBoolean("success")) return org.daemoxcp.mail.system.RestartLock.State.UNKNOWN;
            return new org.daemoxcp.mail.system.RestartLock.State(j.optBoolean("scheduled"), j.optLong("at"), true);
        } catch (Exception e) {
            LOGGER.warning("Web part: the root part did not say whether a restart is scheduled: " + e.getMessage());
            return org.daemoxcp.mail.system.RestartLock.State.UNKNOWN;
        }
    }

    /**
     * 403 with needs_reauth: a recent confirmation is needed (passkey or code by email), then the request is
     * repeated.
     */
    private void sendConfirmationNeeded(HttpExchange exchange) throws IOException {
        byte[] json = new JSONObject().put("success", false).put("needs_reauth", true)
                .put("error", I18n.tr("server.reauth.needed")).toString().getBytes(StandardCharsets.UTF_8);
        addSecurityHeaders(exchange);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.getResponseHeaders().set(CONFIRMATION_HEADER, "needed");
        exchange.sendResponseHeaders(403, json.length);
        try (OutputStream os = exchange.getResponseBody()) { os.write(json); }
    }

    private boolean accessAllowed(HttpExchange exchange, Access access) throws IOException {
        Optional<WebSessions.Current> session = currentSession(exchange);
        boolean pageGet = access.kind() == Access.Kind.PAGE && "GET".equals(exchange.getRequestMethod());
        if (session.isEmpty() && Main.mysqlAvailable && !Main.setupRequired && WebSessions.lastCheckFailed()) {
            databaseUnavailable(exchange, pageGet);
            return false;
        }
        if (session.isEmpty()) {
            // A session cookie that is not valid (the jar has restarted, or the session has expired): it is
            // removed, and the login page says why you are there again (finding 184).
            // With the database down nobody knows: the cookie stays, and when the database comes back the
            // session is still valid. Down also means a read that has just failed (MySQL restarting, or shutting
            // down before the panel during a server restart: finding 185).
            boolean known = Main.mysqlAvailable && !Main.setupRequired && !WebSessions.lastCheckFailed();
            boolean ended = known && WebSessions.wellFormed(cookieValue(exchange, WebSessions.COOKIE));
            if (ended) exchange.getResponseHeaders().add("Set-Cookie", WebSessions.clearCookieHeader());
            if (pageGet) {
                redirect(exchange, ended ? "/index?session=ended" : "/index");
            } else {
                // The signal for the open pages (the fetch wrapper in the head): this 401 is the
                // session that no longer exists, not a wrong confirmation code (that is 401 too).
                if (known) exchange.getResponseHeaders().set(SESSION_ENDED_HEADER, "ended");
                sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
            }
            return false;
        }
        String method = exchange.getRequestMethod();
        String action = null;
        if (access.byAction()) {
            if ("GET".equals(method) || "HEAD".equals(method)) {
                action = extractParamFromQuery(exchange.getRequestURI().getQuery(), "action");
            } else {
                String body = readRequestBodyWithLimit(exchange);
                if (body == null) {
                    sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge"));
                    return false;
                }
                exchange.setStreams(new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)), null);
                try {
                    if (body.trim().startsWith("{")) action = new JSONObject(body).optString("action", null);
                } catch (org.json.JSONException e) {
                    // It is not JSON: no action, the method's permission applies. The handler will answer 400.
                }
            }
        }
        String permission = access.permissionFor(method, action);
        AuthStore.Admin admin = session.get().admin();
        if (AuthStore.may(admin, permission)) {
            // The action read here is also used by the recent confirmation (confirmationMissing), which comes
            // after the CSRF.
            if (action != null) exchange.setAttribute(ACTION_ATTRIBUTE, action);
            return true;
        }
        LOGGER.info("Permission " + permission + " denied to " + admin.username() + " (" + admin.role() + ") on "
                + method + " " + exchange.getRequestURI().getPath());
        logAudit("PERMISSION_DENIED", getClientIp(exchange), "user=" + admin.username() + " permission=" + permission
                + " path=" + exchange.getRequestURI().getPath());
        if (pageGet) {
            addSecurityHeaders(exchange);
            // Built here as before, with the scripts in files (PageAssets): they are the ones that
            // generateAllContent has already written at startup (it also writes forbidden.html).
            byte[] html = renderPage(exchange, withTheme(exchange, org.daemoxcp.mail.content.PageAssets.externalize(
                    org.daemoxcp.mail.content.PanelContent.getForbiddenHtml(), false)), getCsrfToken(exchange)).getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
            exchange.sendResponseHeaders(403, html.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(html); }
        } else {
            byte[] json = new JSONObject().put("success", false).put("forbidden", true)
                    .put("error", I18n.tr("server.access.forbidden")).toString().getBytes(StandardCharsets.UTF_8);
            addSecurityHeaders(exchange);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(403, json.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(json); }
        }
        return false;
    }

    /**
     * The routes used BEFORE logging in: there is no session yet to bind the token to.
     * They check the token by themselves: the page's token, bound to the browser by the cookie
     * __Host-DaemoxCPMailPre (/api/language also the session's one).
     */
    private static final java.util.Set<String> CSRF_EXEMPT = java.util.Set.of(
        "/api/login", "/api/language",
        // Called by the webmail, not by a browser: no cookie, it authenticates with its key
        org.daemoxcp.mail.integration.WebmailPasswordConfig.PATH, org.daemoxcp.mail.integration.WebmailPasswordConfig.VAULT_PATH, org.daemoxcp.mail.integration.WebmailPasswordConfig.CLEANUP_PATH);

    /**
     * The routes that receive a Host other than the panel's by their very nature.
     *
     * <p>The first two are public by necessity and their Host is <em>a mail domain</em>,
     * not the panel's name: Thunderbird asks for autoconfiguration at
     * {@code autoconfig.esempio.it} and a sending server asks for the MTA-STS policy at
     * {@code mta-sts.esempio.it}. They are not left unchecked: the two handlers compare
     * that name by themselves with the list of domains that this panel really hosts, and answer
     * 404 if it is not one of them.
     *
     * <p>The other two are called by the webmail on the same machine, at
     * {@code https://127.0.0.1:&lt;porta&gt;}: with a name configured in "Modify Data", a Host
     * {@code 127.0.0.1} would be refused and the webmail's password change would stop
     * working. They are not left exposed: WebmailPasswordHandler requires the connection
     * to really come from the loopback, with no proxy headers in front, and with the
     * webmail's key.
     */
    private static final java.util.Set<String> HOST_CHECK_EXEMPT = java.util.Set.of(
        "/autoconfig", "/mta-sts",
        org.daemoxcp.mail.integration.WebmailPasswordConfig.PATH, org.daemoxcp.mail.integration.WebmailPasswordConfig.VAULT_PATH, org.daemoxcp.mail.integration.WebmailPasswordConfig.CLEANUP_PATH);

    /**
     * The two webmail routes: with the separated panel they are served by the root part, which alone writes
     * the mailboxes' passwords (forwardWebmail, serveWebmail).
     */
    static final java.util.Set<String> WEBMAIL_ROUTES = java.util.Set.of(
        org.daemoxcp.mail.integration.WebmailPasswordConfig.PATH, org.daemoxcp.mail.integration.WebmailPasswordConfig.VAULT_PATH, org.daemoxcp.mail.integration.WebmailPasswordConfig.CLEANUP_PATH);

    /**
     * Does the request's Host reach this panel? See {@link HostCheck} for why the comparison
     * is exact, why the port is left out of it and why DNS is never queried.
     *
     * <p>Also from Cloudflare: Cloudflare passes the Host as it is, so whoever opens the panel with
     * its name gets through. Before, any Host was accepted if the request came from Cloudflare (or
     * from a private network with Cloudflare's headers): any Cloudflare zone pointed at this server
     * was enough to reach the panel under another name.
     */
    private boolean hostAllowed(HttpExchange exchange) {
        String host = exchange.getRequestHeaders().getFirst("Host");
        String configured = "";
        try (java.sql.ResultSet r = Main.dbManager.get_data_config()) {
            if (r.next()) configured = r.getString("panel_host");
        } catch (Exception e) {
            // It is not known which name the panel answers to: only the loopback is let through,
            // so the machine stays manageable and no outside name gets in.
            LOGGER.warning("Cannot read the configured panel host: " + e.getMessage());
            String name = HostCheck.hostName(host);
            return name.equals("localhost") || "127.0.0.1".equals(HostCheck.literalIp(name))
                    || "0:0:0:0:0:0:0:1".equals(HostCheck.literalIp(name));
        }
        if (HostCheck.allowed(host, configured)) return true;
        LOGGER.warning(HostCheck.why(host, configured));
        return false;
    }

    /** 421: this server is not the one for the requested name. No details to the requester. */
    private void sendMisdirected(HttpExchange exchange) throws IOException {
        byte[] body = "Misdirected request\n".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=UTF-8");
        exchange.sendResponseHeaders(421, body.length);
        try (java.io.OutputStream os = exchange.getResponseBody()) { os.write(body); }
        exchange.close();
    }

    /**
     * The CSRF token for every request that changes something, in a single place instead of handler by
     * handler: twenty-five authenticated routes accepted POSTs without asking for it. The pages
     * send it in the X-CSRF-Token header (the script in getHead adds it to every fetch); a
     * JSON body with csrf_token works as well, and the body read to look at it is put back in its
     * place for the handler. Without a valid session the request is let through: the handler answers,
     * with its 401.
     */
    private boolean csrfAllowed(HttpExchange exchange) throws IOException {
        String method = exchange.getRequestMethod();
        if ("GET".equals(method) || "HEAD".equals(method) || "OPTIONS".equals(method)) return true;
        Optional<WebSessions.Current> session = currentSession(exchange);
        if (session.isEmpty()) return true;
        String expected = WebSessions.csrfToken(session.get().token());
        if (expected == null) return false;
        String header = exchange.getRequestHeaders().getFirst("X-CSRF-Token");
        if (header != null) return SecurityUtils.validateCsrfToken(expected, header);
        String body = readRequestBodyWithLimit(exchange);
        if (body == null) return false;
        exchange.setStreams(new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)), null);
        try {
            JSONObject json = body.isBlank() ? new JSONObject() : new JSONObject(body);
            return SecurityUtils.validateCsrfToken(expected, json.optString("csrf_token", ""));
        } catch (org.json.JSONException e) {
            return false;
        }
    }

    private void initializeManagers() {
        if (Main.mailDatabase != null && Main.mysqlAvailable) {
            this.dkimManager = new DkimManager(Main.mailDatabase);
            this.cloudflareManager = new org.daemoxcp.mail.security.CloudflareManager(Main.mailDatabase);
            this.dkimManager.setCloudflareManager(this.cloudflareManager);
            this.dnsGenerator = new DnsRecordsGenerator(Main.mailDatabase);
            this.acmeManager = new AcmeManager(Main.mailDatabase);
            this.logManager = new LogManager();
            this.queueManager = new MailQueueManager();
            this.ssoManager = new RoundcubeSsoManager(Main.mailDatabase);
            this.ssoManager.setPanelPort(port);
            this.fail2banManager = new Fail2banManager();
            this.firewallManager = new org.daemoxcp.mail.security.PfFirewallManager();
            this.rspamdManager = new RspamdManager();
            this.sieveGenerator = new SieveGenerator();

            // The columns of later versions (the login tables are set up by Main before startup)
            ensureSchemaUpgrades();

            // The Cloudflare tokens written in clear text by earlier versions: encrypted, one row at a time, only
            // if nobody changed it in the meantime (CloudflareTokens). After the columns, which create the table.
            org.daemoxcp.mail.security.CloudflareTokens.ensureAtBoot(Main.mailDatabase);

            // Auto-setup Fail2ban: log file + filter + jail + log rotation + reload
            // Idempotent, fail-safe: skips everything if Fail2ban is not installed.
            org.daemoxcp.mail.security.Fail2banAutoSetup.run();

            // pf lets in only what is needed (SSH as before, mail, web, webmail, panel): on the
            // panel's pf.conf, after Fail2banAutoSetup, which adds the anchor and the permaban table to it.
            org.daemoxcp.mail.security.PfPolicy.ensureAtBoot();

            // The public surface on 443 with today's name (daemoxcp-mail-public) on servers
            // installed earlier: nginx, its log, fail2ban's filter and jail, all together or
            // nothing. After Fail2banAutoSetup, which reloads fail2ban on its own.
            org.daemoxcp.mail.system.PublicSurfaceRename.ensureAtBoot();

            // The MTA-STS policy readable by nginx on servers where it was created with the service's
            // permissions (0700 and 0600): nginx answered 403, and MTA-STS did not activate (finding 250).
            // Only permissions, never through links.
            org.daemoxcp.mail.system.PublicPolicyAccess.ensureAtBoot();

            // The signatures of the panel's files in English on servers installed earlier: comment lines
            // only, so no reload. After the rename, which brings the files to today's names.
            org.daemoxcp.mail.system.PanelMarker.ensureAtBoot();

            // The comments that a rename done on the text had damaged in php.ini, nginx.conf,
            // in the permaban list and in the installation scripts: here too, comments only.
            org.daemoxcp.mail.system.CommentRepair.ensureAtBoot();

            // The backup copies of configuration files beyond the last ten per file: earlier versions did not
            // delete any (on the production server hundreds of pf.conf and of the firewall anchor). After
            // PfPolicy and Fail2banAutoSetup, which can make one (ConfigBackups).
            org.daemoxcp.mail.system.ConfigBackups.ensureAtBoot();

            // MySQL root with its own password on servers installed before the installer
            // set it: without it, anyone with a user on the machine got in as root. Before
            // everything that later talks to MySQL as root (RoundcubeDbUser, the updater).
            org.daemoxcp.mail.database.MysqlRoot.ensureAtBoot();

            // The Dovecot process that looks up passwords no longer runs as root: it looks them up in MySQL,
            // it does not need root. It is verified with a real lookup, and if that fails it is put back as it
            // was.
            org.daemoxcp.mail.system.DovecotAuthWorker.ensureAtBoot();

            // The Dovecot sockets open to everyone (0666) that the panel does not use: indexer, imap-urlauth,
            // auth-token. Only in 2.4; a restart is needed, verified, and if Dovecot does not come back up the
            // file is removed (DovecotSockets).
            org.daemoxcp.mail.system.DovecotSockets.ensureAtBoot();

            // ManageSieve (4190) only on 127.0.0.1, where the webmail uses it: before, it listened on all
            // interfaces and only pf stopped it. Restart verified, and if something does not add up the file is
            // removed (ManageSieveLocal).
            org.daemoxcp.mail.system.ManageSieveLocal.ensureAtBoot();

            // nginx does not reveal its version and the webmail sends HSTS, nosniff and Referrer-Policy: on servers
            // installed earlier only the missing lines are added, with nginx -t, reload and a real request;
            // otherwise it goes back as it was.
            org.daemoxcp.mail.system.NginxMain.ensureAtBoot();

            // VRFY off: it told anyone on port 25 which mailboxes exist (r6). postconf -e, postfix check, reload
            // and a real VRFY that must get 502; otherwise it goes back as it was (PostfixVrfy).
            org.daemoxcp.mail.system.PostfixVrfy.ensureAtBoot();

            // AUTH only on the submission ports (587, 465), not on 25: only if master.cf turns it on for both,
            // with the real test with STARTTLS; otherwise it goes back as it was (PostfixSubmissionAuth).
            org.daemoxcp.mail.system.PostfixSubmissionAuth.ensureAtBoot();
            // DANE for outgoing mail, with the local resolver that validates DNSSEC (PostfixDane).
            org.daemoxcp.mail.system.PostfixDane.ensureAtBoot();

            // POP3 as the administrator chose it, off if no choice was made: nobody used it, and its ports
            // were only targets (Pop3 verifies and rolls back).
            org.daemoxcp.mail.system.Pop3.ensureAtBoot();

            // /var/mail with the sticky bit: whoever has the mail group (postfix, clamav, dma) can no longer
            // rename the folder of the panel's Sieve rules to put another one in its place. Before
            // SieveForcedKeep: root writes the rules only if nobody else can change the path (RootOnlyPath).
            // And Dovecot's mailbox processes without the mail group, which was needed only for mbox INBOXes
            // (finding 221; both verify and roll back). Even before that, the rules folder owned by root
            // again, where the earlier installation had given it to vmail: otherwise RootOnlyPath does not
            // write there and MailSpoolSticky reports it (finding 225; it touches nothing if it finds links
            // or files of others, and if something does not add up it puts things back as they were).
            org.daemoxcp.mail.system.SieveRulesOwner.ensureAtBoot();
            org.daemoxcp.mail.system.MailSpoolSticky.ensureAtBoot();
            org.daemoxcp.mail.system.DovecotPrivilegedGroup.ensureAtBoot();

            // Dovecot's home for each mailbox in its home/ folder, not in the mail root: Dovecot's files
            // (the memory of auto-replies and forwards) showed up among the webmail's folders (DovecotHome
            // moves them into the home as vmail, verifies with doveadm user, and if it fails goes back as it
            // was).
            org.daemoxcp.mail.system.DovecotHome.ensureAtBoot();

            // The empty Maildir/ folders that the mailbox script created and Dovecot did not use (the mail is in
            // the root of the mailbox): removed with rmdir as vmail, which removes nothing that is not empty
            // (UnusedMaildir).
            org.daemoxcp.mail.system.UnusedMaildir.ensureAtBoot();

            // Postfix delivers to Dovecot through the socket in its own queue (0600, its own) and no longer
            // through port 24 or the 0666 socket, from which any process on the machine could deliver into any
            // mailbox (finding 234). In three stages, the mail is never left without a route; if something goes
            // wrong it goes back as it was.
            org.daemoxcp.mail.system.LmtpSocket.ensureAtBoot();
            // The user's Sieve scripts (ManageSieve, the webmail's "Filters") in their mail folder, and the
            // panel's rules before them: before, nothing was saved, the folder belonged to root (SieveStorage
            // verifies and rolls back).
            org.daemoxcp.mail.system.SieveStorage.ensureAtBoot();
            // The panel's Sieve rules already written without the forced keep at the end: with that, "Move" also
            // left the message in the INBOX and "Forward" without a copy kept one (SieveForcedKeep recompiles,
            // and if sievec does not accept it goes back as it was).
            org.daemoxcp.mail.system.SieveForcedKeep.ensureAtBoot();
            // The panel's rules rewritten from the database the way it writes them now, where they differ:
            // "Move" and "Copy" create the folder that does not exist (finding 229). Only the panel's files;
            // on the second boot it writes nothing.
            org.daemoxcp.mail.system.SieveRulesRefresh.ensureAtBoot(this.sieveGenerator);
            // The compiled form of the panel's rules that the auto-reply reset removed: without it, Dovecot
            // recompiles them at every delivery and writes an error in the maillog (VacationTracking recompiles
            // only the rules in that state).
            org.daemoxcp.mail.system.VacationTracking.ensureAtBoot();
            // The compiled form of the panel's rules made by another Pigeonhole (2.3 before the move to 2.4):
            // Dovecot recompiled them at every delivery with two errors in the maillog. It is replaced only where
            // it differs from what the installed sievec produces (finding 241); on the second boot it writes
            // nothing.
            org.daemoxcp.mail.system.SieveBinaries.ensureAtBoot();
            // The special folders (Drafts, Sent, Trash, Junk) marked for mail clients, and the spam that Rspamd
            // flags filed into Junk before any rule: no auto-reply nor forward on spam (SpecialFolders verifies
            // with IMAP, and if it fails goes back as it was).
            org.daemoxcp.mail.system.SpecialFolders.ensureAtBoot();
            // Rspamd learns from users: moved into Junk is spam, moved out of Junk is good mail (SpamLearning,
            // Dovecot 2.4: IMAPSieve deposits the message, the root part hands it to Rspamd with SpamLearner,
            // after RspamdController).
            org.daemoxcp.mail.system.SpamLearning.ensureAtBoot();

            // MySQL only from this machine and without the X protocol (33060 on all addresses),
            // syslogd without port 514, the mail in /var/vmail readable only by vmail, inside too.
            // Each one is verified, and if it fails goes back as it was; on the second boot they do nothing.
            org.daemoxcp.mail.system.MysqlListen.ensureAtBoot();
            // Postfix and Dovecot in MySQL with their own users, which read only the columns they use, and no
            // longer with the panel's one: after MysqlRoot (it needs MySQL's root) and MysqlListen (MySQL as it
            // really is).
            org.daemoxcp.mail.system.MailDbUsers.ensureAtBoot();
            // Every mailbox points to itself after the aliases (MailboxAddressMap): a catch-all takes only the
            // addresses that are neither aliases nor mailboxes. After MailDbUsers: the map copies the connection
            // of the aliases map.
            org.daemoxcp.mail.system.MailboxAddressMap.ensureAtBoot();
            // Whoever authenticates sends only from their own addresses (the mailbox, the aliases pointing to
            // it): before, a mailbox could send as another one, DKIM-signed, or as anyone (SenderLoginMap). Same
            // connection.
            org.daemoxcp.mail.system.SenderLoginMap.ensureAtBoot();

            // Mailbox quotas enforced by Dovecot 2.4, and checked by Postfix before accepting (DovecotQuota).
            // After MailDbUsers: Dovecot's MySQL user must already be able to read quota_mb.
            org.daemoxcp.mail.system.DovecotQuota.ensureAtBoot();

            // The mailboxes' sending limits: the panel acts as a policy service for Postfix (SendingLimits),
            // then Postfix asks it before every message that a mailbox sends.
            if (org.daemoxcp.mail.system.SendingLimits.start()) org.daemoxcp.mail.system.SendingLimits.ensurePostfix();

            // The counts of sent and received mail, from Postfix's log, every minute (MailLogStats): the
            // Statistics page reads them from email_statistics.
            org.daemoxcp.mail.system.MailLogStats.start();
            org.daemoxcp.mail.system.SyslogNetwork.ensureAtBoot();
            org.daemoxcp.mail.system.VmailPermissions.ensureAtBoot();
            // rspamd entirely with its own user, the main process included: its ports are above 1023 and
            // its files are already its own (RspamdUser, with a real scan before and after).
            org.daemoxcp.mail.system.RspamdUser.ensureAtBoot();
            // The services behind rspamd only for it: redis on the Unix socket of the redis group (RedisSocket,
            // finding 235), clamd on the socket of the clamav group (ClamdSocket, 237), the controller only with
            // the password (RspamdController, 236).
            org.daemoxcp.mail.system.RedisSocket.ensureAtBoot();
            org.daemoxcp.mail.system.ClamdSocket.ensureAtBoot();
            org.daemoxcp.mail.system.RspamdController.ensureAtBoot();
            // Whoever authenticates writes in From only an address of their own: the envelope is checked by
            // Postfix (SenderLoginMap), the From by an Rspamd rule, which knows from the milter who authenticated
            // (HeaderFromCheck).
            org.daemoxcp.mail.system.HeaderFromCheck.ensureAtBoot();
            // Rspamd signs only the domains with their own DKIM key: no more "cannot load dkim key" for the
            // others (DkimFallback).
            org.daemoxcp.mail.system.DkimFallback.ensureAtBoot();
            // The messages that users move into Junk or out of it, to Rspamd with the controller's password
            // (SpamLearning).
            org.daemoxcp.mail.system.SpamLearner.start();

            // Auto-setup Postfix aliases: creates /etc/aliases (or /etc/mail/aliases) if missing
            // + compiles the .db. Fixes the common error "open database /etc/aliases.db: No such file".
            // Idempotent: if everything is OK it does nothing.
            try {
                new org.daemoxcp.mail.security.PostfixAliasesManager().ensureAtBoot();
            } catch (Throwable t) {
                LOGGER.warning("PostfixAliases ensureAtBoot failed: " + t.getMessage());
            }

            // Postfix as the local MTA on servers installed before the installer did it:
            // after the aliases, because without aliases.db the system mail would stay in the queue.
            // Idempotent, and it activates nothing if the system mail would bounce.
            org.daemoxcp.mail.system.LocalMtaRepair.ensureAtBoot();
            // The Cloudflare record comments written in Italian before 2026-10-30 switch to English
            // (finding 211): only the comment, in a thread of its own.
            org.daemoxcp.mail.security.CloudflareCommentsEnglish.ensureAtBoot(cloudflareManager, Main.mailDatabase);
            // inet_protocols written explicitly with the value in use: without it, the script of every postfix
            // update writes ipv4 and on restart IPv6 disappears (findings 42, 207). It changes nothing in what
            // Postfix does.
            org.daemoxcp.mail.system.PostfixInetProtocols.ensureAtBoot();
            // The address family chosen in Settings (IpFamily): Postfix, Dovecot, nginx. Without a choice it does
            // nothing.
            org.daemoxcp.mail.system.IpFamily.ensureAtBoot();
            // The jar name without a version (0.9.0): on earlier servers, the daemoxcp-mail.jar link.
            org.daemoxcp.mail.system.JarName.ensureAtBoot();

            // Roundcube with its own user and its own php-fpm pool, no longer with nginx's user: on
            // servers installed earlier. Before the SSO plugin, which gives its configuration to the group
            // the webmail runs with.
            // php.ini if missing (the production server ran on the values compiled in) and
            // security.limit_extensions in Roundcube's pool (PhpHardening, finding 238); before RoundcubeUser,
            // which goes over the owners again.
            org.daemoxcp.mail.system.PhpHardening.ensureAtBoot();
            org.daemoxcp.mail.system.RoundcubeUser.ensureAtBoot();
            // php-fpm's master as roundcube, not root (after RoundcubeUser: the pool must be its own already).
            org.daemoxcp.mail.system.PhpFpmMaster.ensureAtBoot();

            // The Dovecot master user with which "Open webmail" logs in: the installation scripts
            // left it without a hash (or in a file that Dovecot could not read). Before the SSO plugin
            // and whatever later tries a real login with it.
            org.daemoxcp.mail.system.DovecotMasterUser.ensureAtBoot();

            // Start auto-renewal for certificates (before that, in the same thread, acme.sh moves from root
            // to the acme user: AcmeUser.ensureAtBoot)
            acmeManager.startAutoRenewal();

            // Start DKIM rotation scheduler (polls DNS propagation hourly)
            this.dkimRotationScheduler = new DkimRotationScheduler(Main.mailDatabase, dkimManager);
            this.dkimRotationScheduler.start();

            // The periodic report: it can read the certificate only if it is given to it.
            org.daemoxcp.mail.system.PeriodicReport.link(this.acmeManager);
            this.periodicReport = new org.daemoxcp.mail.system.PeriodicReport();
            this.periodicReport.start();

            // A new version of the panel among the GitHub releases, once a day (ReleaseCheck): the dashboard, the
            // Updates page and the periodic report say so. Nothing is downloaded and nothing is installed.
            org.daemoxcp.mail.system.ReleaseCheck.start();

            // Auto-install/update Roundcube SSO plugin if Roundcube is installed
            // (and the webmail password change that goes through the panel)
            autoInstallSsoPlugin();

            // The webmail logs into MySQL with its own user (roundcube, only Roundcube's database) and
            // no longer with the panel's: on servers installed earlier. After the SSO plugin,
            // because the check does a real login like the "Open webmail" button.
            org.daemoxcp.mail.system.RoundcubeDbUser.ensureAtBoot(ssoManager);
            // AES-256-CBC for the IMAP password in the Roundcube session, not DES-EDE3-CBC (RoundcubeCipher,
            // finding 239).
            org.daemoxcp.mail.system.RoundcubeCipher.ensureAtBoot(ssoManager);

            // The password of the panel's MySQL user changed once: on servers installed earlier it sat for years
            // in the webmail's config.inc.php (finding 232). After RoundcubeDbUser and MailDbUsers: nobody else
            // uses it any more. With MySQL's dual password nothing stops; if something does not add up, MySQL
            // goes back as it was.
            org.daemoxcp.mail.system.PanelDbPassword.ensureAtBoot();

            // After: the webmail no longer writes passwords in clear text, the remaining ones get fixed
            repairPlaintextMailboxPasswords();

            // Which user each service runs as, and the warnings in the log: the renewal thread
            // reports it, after the acme.sh migration (AcmeManager.startAutoRenewal).
        }
    }

    /**
     * The mailboxes whose password the webmail had written in clear text (the sql driver of Roundcube's
     * password plugin, algorithm 'clear'): bcrypt hash and copy into the vault. On an already running
     * server it happens at the first boot of the new version; after that it finds nothing more.
     */
    private void repairPlaintextMailboxPasswords() {
        try {
            int n = Main.mailDatabase.repairPlaintextMailboxPasswords();
            if (n > 0) {
                LOGGER.warning("Mailbox passwords stored in clear text by the webmail: " + n + " rewritten as bcrypt hash with the encrypted copy");
                logAudit("MAILBOX_PASSWORDS_REPAIRED", "127.0.0.1", "count=" + n);
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Repairing clear-text mailbox passwords failed", e);
        }
    }

    /** The columns added by later versions, for earlier installations. */
    private void ensureSchemaUpgrades() {
        try {
            Main.mailDatabase.ensureColumnUpgrades();
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Schema upgrade failed", e);
        }
        // The asymmetric-key vault: the key pair, then the earlier copies re-encrypted with the public key.
        try {
            org.daemoxcp.mail.security.PasswordVault.ensureKeyPair();
            org.daemoxcp.mail.security.PasswordVault.Reencrypted r = org.daemoxcp.mail.security.PasswordVault.reencryptOldCopies(Main.mailDatabase);
            if (r.failed() > 0)
                LOGGER.warning("[PasswordVault] " + r.failed() + " password copies of before not readable: they stay as they are (master.key, root only)");
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "[PasswordVault] the copies of before were not encrypted again", e);
        }
    }

    /**
     * Automatically install or update the Roundcube SSO plugin at startup.
     * This ensures the plugin is always up-to-date with the panel version.
     */
    private void autoInstallSsoPlugin() {
        if (ssoManager == null) return;

        try {
            RoundcubeSsoManager.SsoStatus status = ssoManager.getStatus();

            // If Roundcube is installed, ensure SSO plugin is installed and up-to-date
            if (status.roundcubeInstalled) {
                LOGGER.info("Roundcube detected, checking SSO plugin...");

                // Always reinstall to ensure plugin is up-to-date
                RoundcubeSsoManager.InstallResult result = ssoManager.installPlugin();

                if (result.success) {
                    LOGGER.info("Roundcube SSO plugin installed/updated successfully");
                } else {
                    LOGGER.warning("Failed to install SSO plugin: " + result.error);
                }
            }
        } catch (Exception e) {
            LOGGER.warning("Error during SSO plugin auto-install: " + e.getMessage());
        }
    }

    public void start() {
        // Virtual threads (Java 21+): each request runs on a very lightweight
        // virtual thread instead of a platform thread from a fixed pool of 10.
        // Advantages:
        //  - no practical limit on the number of concurrent requests
        //  - when a request blocks on I/O (e.g. fail2ban-client, shell command,
        //    DB query), the carrier thread goes on to serve another -> no starvation
        //  - memory: ~200 bytes/virtual thread vs ~1MB/platform thread
        if (mode == Mode.ROOT_PART) {
            // No port: the APIs arrive from the socket (serveForwarded). Sessions are created and removed by
            // the root part (A), with this boot's key, which the web part asks it for: those of the previous
            // boot are already invalid, and here they are removed from the database too. Then the repairs and
            // the background jobs, as today.
            if (Main.mysqlAvailable && !Main.setupRequired && Main.sessions != null) {
                int closed = Main.sessions.beginRun();
                if (closed > 0) LOGGER.info("Closed " + closed + " panel session(s) of the previous start: every administrator signs in again");
            }
            initializeManagers();
            LOGGER.info(org.daemoxcp.mail.system.Product.NAME + " root part ready: no network port, the web part forwards the API on "
                    + org.daemoxcp.mail.system.PanelSeparation.socket());
            return;
        }
        server.setExecutor(java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor());
        // Sessions belong to this boot of the jar (finding 184): those from before are already
        // invalid (WebSessions has a new key), and here they are removed from the database too. The port
        // is already taken (the constructor): a second process that cannot serve touches nothing. Not the
        // web part: the key belongs to the root part, which has already removed them, and the web part does
        // not write sessions (A).
        if (mode != Mode.WEB_PART && Main.mysqlAvailable && !Main.setupRequired && Main.sessions != null) {
            int closed = Main.sessions.beginRun();
            if (closed > 0) LOGGER.info("Closed " + closed + " panel session(s) of the previous start: every administrator signs in again");
        }
        server.start();
        if (mode == Mode.WEB_PART) {
            // The web part's handlers that use it (the blacklist check): MySQL and network, no root.
            if (Main.mailDatabase != null && Main.mysqlAvailable) this.dnsGenerator = new DnsRecordsGenerator(Main.mailDatabase);
            LOGGER.info(org.daemoxcp.mail.system.Product.NAME + " web part started on port " + port + " as " + System.getProperty("user.name")
                    + ": the signed-in API go to the root part");
            return;
        }
        initializeManagers();
        LOGGER.info(org.daemoxcp.mail.system.Product.NAME + " server started on port " + port + " (virtual threads enabled)");
    }

    public Mode mode() { return mode; }

    /**
     * The web part did not start: this server takes the port and serves everything from root, as before.
     * The routes already have the real handlers (forwarding exists only in WEB_PART).
     */
    public void becomeLegacy() throws IOException {
        if (mode != Mode.ROOT_PART) return;
        mode = Mode.LEGACY;
        server = newHttpsServer();
        for (Object[] d : declared) createContext((String) d[0], (Access) d[1], (HttpHandler) d[2]);
    }

    public void stop() {
        LOGGER.info("Stopping " + org.daemoxcp.mail.system.Product.NAME + " server...");

        // Stop ACME auto-renewal scheduler first
        if (acmeManager != null) {
            try {
                acmeManager.stopAutoRenewal();
            } catch (Exception e) {
                // Ignore
            }
        }

        // Stop HTTP server immediately
        try {
            if (server != null) server.stop(0);
        } catch (Exception e) {
            // Ignore
        }

        LOGGER.info(org.daemoxcp.mail.system.Product.NAME + " server stopped");

        // Force exit after a short delay if still hanging
        new Thread(() -> {
            try {
                Thread.sleep(2000);
                System.out.println("Forcing exit...");
                System.exit(0);
            } catch (InterruptedException e) {
                // Ignore
            }
        }).start();
    }

    // ============== SSL SETUP ==============

    private SSLContext createSSLContext() throws Exception {
        String jarDir = getJarDirectory();
        Path keystorePath = Paths.get(jarDir, org.daemoxcp.mail.system.Product.SLUG + ".jks");
        String keystorePassword = org.daemoxcp.mail.system.Product.SLUG;

        if (!Files.exists(keystorePath)) {
            LOGGER.info("Generating self-signed SSL certificate...");
            generateSelfSignedCertificate(keystorePath.toString(), keystorePassword);
        }

        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(keystorePath.toFile())) {
            keyStore.load(fis, keystorePassword.toCharArray());
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(keyStore, keystorePassword.toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(keyStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        return sslContext;
    }

    /**
     * Create SSL context from PEM certificate and key content
     * The certificate (with its chain) and the private key both come as PEM text.
     */
    private SSLContext createSSLContextFromPEM(String certContent, String keyContent) throws Exception {
        System.out.println("\n========== SSL CONTEXT CREATION DEBUG ==========");

        // Normalize certificate content (fix newlines)
        certContent = normalizePEM(certContent);
        keyContent = normalizePEM(keyContent);

        System.out.println("Certificate content length: " + certContent.length());
        System.out.println("Key content length: " + keyContent.length());
        System.out.println("Certificate starts with: " + certContent.substring(0, Math.min(50, certContent.length())));

        java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");

        // Load all certificates from the cert content (may contain chain)
        List<java.security.cert.X509Certificate> certChain = new ArrayList<>();
        try (java.io.InputStream certStream = new java.io.ByteArrayInputStream(certContent.getBytes(java.nio.charset.StandardCharsets.UTF_8))) {
            java.util.Collection<? extends java.security.cert.Certificate> certs = cf.generateCertificates(certStream);
            for (java.security.cert.Certificate c : certs) {
                java.security.cert.X509Certificate x509 = (java.security.cert.X509Certificate) c;
                certChain.add(x509);
                System.out.println("Loaded certificate: " + x509.getSubjectX500Principal().getName());
            }
        } catch (Exception e) {
            System.err.println("ERROR loading certificate: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }

        if (certChain.isEmpty()) {
            throw new IllegalArgumentException("No valid certificates found in certificate content");
        }
        System.out.println("Loaded " + certChain.size() + " certificate(s)");

        // Load private key
        System.out.println("Loading private key...");
        java.security.PrivateKey privateKey = loadPrivateKeyFromString(keyContent);
        System.out.println("Private key loaded successfully. Algorithm: " + privateKey.getAlgorithm());

        // Build certificate chain array
        java.security.cert.Certificate[] chainArray = certChain.toArray(new java.security.cert.Certificate[0]);

        // Create key store with full certificate chain
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(null, null);

        // Set the private key with the FULL certificate chain
        keystore.setKeyEntry("server-key", privateKey, new char[0], chainArray);

        // Also add certificates to trust store
        for (int i = 0; i < certChain.size(); i++) {
            keystore.setCertificateEntry("cert-" + i, certChain.get(i));
        }

        // Create key manager factory
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keystore, new char[0]);

        // Create trust manager factory
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keystore);

        // Create SSL context - try TLS 1.3 first, fallback to TLS
        SSLContext sslContext;
        try {
            sslContext = SSLContext.getInstance("TLSv1.3");
            System.out.println("Using TLSv1.3");
        } catch (Exception e) {
            sslContext = SSLContext.getInstance("TLS");
            System.out.println("Fallback to TLS (TLSv1.3 not available)");
        }
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        System.out.println("SSL Context created successfully with " + certChain.size() + " certificate(s)");
        System.out.println("================================================\n");

        LOGGER.info("SSL context created from PEM content");
        return sslContext;
    }

    /**
     * Normalizes PEM content by fixing newlines and removing extra whitespace.
     */
    private String normalizePEM(String pem) {
        return org.daemoxcp.mail.security.PemTls.normalize(pem);
    }

    /**
     * Load private key from PEM string
     */
    private java.security.PrivateKey loadPrivateKeyFromString(String keyContent) throws Exception {
        // The same read as the check of menu option 2 (PemTls, finding 243).
        return org.daemoxcp.mail.security.PemTls.privateKey(keyContent);
    }

    private void generateSelfSignedCertificate(String keystorePath, String password) {
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder(
                "keytool", "-genkeypair",
                "-alias", org.daemoxcp.mail.system.Product.SLUG,
                "-keyalg", "RSA",
                "-keysize", "2048",
                "-validity", "3650",
                "-keystore", keystorePath,
                "-storepass", password,
                "-keypass", password,
                "-dname", "CN=DaemoxCP Mail, OU=Mail, O=FreeBSD, L=Unknown, ST=Unknown, C=US"
            );
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.inheritIO();
            Process p = pb.start();
            p.waitFor();
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to generate certificate", e);
        }
    }

    // ============== AUTH HELPERS ==============

    /** The session of the current request, looked up only once: {exchange, result}. */
    private static final ThreadLocal<Object[]> CURRENT_SESSION = new ThreadLocal<>();

    /**
     * The valid session of this request (cookie __Host-DaemoxCPMail, in the database). It is looked
     * up once: the CSRF filter, the handler and the page all ask for it. Each route's filter
     * forgets it at the end of the request.
     */
    @SuppressWarnings("unchecked")
    Optional<WebSessions.Current> currentSession(HttpExchange exchange) {
        Object[] cached = CURRENT_SESSION.get();
        if (cached != null && cached[0] == exchange) return (Optional<WebSessions.Current>) cached[1];
        Optional<WebSessions.Current> session = Optional.empty();
        if (Main.mysqlAvailable && !Main.setupRequired && Main.sessions != null) {
            session = Main.sessions.check(cookieValue(exchange, WebSessions.COOKIE),
                    exchange.getRequestHeaders().getFirst("User-Agent"));
        }
        CURRENT_SESSION.set(new Object[]{exchange, session});
        return session;
    }

    /** After a login or a logout the request's session changes: the one looked up is forgotten. */
    static void forgetCurrentSession() {
        CURRENT_SESSION.remove();
        org.daemoxcp.mail.database.CatalogGuard.forgetSession();
    }

    // ============== THE SEPARATED PANEL: FORWARDING ==============

    /**
     * The route that HttpServer chooses for a path: the context with the longest prefix. The root part
     * accepts a forwarded request only if the route the web part names is exactly this one: otherwise the
     * web part could have the permission of one route checked and serve the path of another.
     */
    String routeFor(String path) {
        String best = null;
        for (String r : routes.keySet())
            if (path.startsWith(r) && (best == null || r.length() > best.length())) best = r;
        return best;
    }

    /**
     * The root part: a request that the web part passed to it on the socket (RootChannel). Only an API of
     * a logged-in user is accepted, and not one of those that stay in the web part. The logged-in user is
     * reread from the database: the session must still exist and belong to that administrator, and role,
     * permissions and recent confirmation are those in the database, not those the web part claims. Then
     * the same permission check as for every request (accessAllowed) and the same handler as today.
     */
    public void serveForwarded(RootChannel.Request r, ForwardedExchange exchange) throws IOException {
        if (r.route().startsWith("/op/")) {
            serveOperation(r, exchange);
            return;
        }
        if (r.route().equals("/api/login")) {
            serveSignIn(r, exchange);
            return;
        }
        if (WEBMAIL_ROUTES.contains(r.route())) {
            serveWebmail(r, exchange);
            return;
        }
        Access access = routes.get(r.route());
        HttpHandler handler = handlers.get(r.route());
        I18n.setCurrent(I18n.LANGUAGES.contains(r.lang()) ? r.lang() : I18n.FALLBACK_LANGUAGE);
        try {
            if (mode != Mode.ROOT_PART || access == null || handler == null || access.kind() != Access.Kind.API
                    || WEB_LOCAL_API.contains(r.route()) || !r.route().equals(routeFor(r.path()))) {
                LOGGER.warning("Root part: forwarded request refused (route " + r.route() + ", path " + r.path() + ")");
                logAudit("FORWARD_REFUSED", r.clientIp(), "route=" + r.route() + " path=" + r.path());
                sendJsonError(exchange, 404, I18n.tr("server.access.forbidden"));
                return;
            }
            // The closed list (RootGate): the route's method, the shape of each value, the strict one for
            // parameters that end up in commands and configurations. The reason goes in the log, never the value.
            String refused = RootGate.check(r);
            if (refused != null) {
                LOGGER.warning("Root part: forwarded request refused: " + refused);
                logAudit("FORWARD_REFUSED", r.clientIp(), "route=" + r.route() + " " + refused);
                sendJsonError(exchange, 400, I18n.tr("server.rootPart.refused"));
                return;
            }
            Optional<WebSessions.Current> session = Main.sessions.forwarded(r.sessionId(), r.adminId());
            if (session.isEmpty() && WebSessions.lastCheckFailed()) {
                databaseUnavailable(exchange, false);
                return;
            }
            if (session.isEmpty()) {
                if (!WebSessions.lastCheckFailed()) exchange.getResponseHeaders().set(SESSION_ENDED_HEADER, "ended");
                sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
                return;
            }
            // As on the port (HeadExchange): the handler serves a HEAD like a GET, and the body is discarded.
            // The web part already passes them as GET; a HEAD arrives here only if someone writes it on the
            // socket.
            HttpExchange ex = "HEAD".equals(r.method()) ? new HeadExchange(exchange) : exchange;
            CURRENT_SESSION.set(new Object[]{ex, session});
            if (!accessAllowed(ex, access)) return;
            if (restartLocked(ex, access, r.route())) return;
            if (confirmationMissing(ex, access)) return;
            handler.handle(ex);
        } finally {
            I18n.clearCurrent();
            forgetCurrentSession();
        }
    }

    /**
     * The root part: the login (POST /api/login), which the web part passes to it without an administrator
     * (A). The web part has already checked Host and the CSRF token of the login page, which is bound to its
     * cookie __Host-DaemoxCPMailPre: that cookie does not arrive here. The rest is decided by the root part:
     * passkeys and codes with the challenges in its memory, the session in the database, the cookie in the
     * response, which the web part lets through only from here.
     */
    private void serveSignIn(RootChannel.Request r, ForwardedExchange exchange) throws IOException {
        I18n.setCurrent(I18n.LANGUAGES.contains(r.lang()) ? r.lang() : I18n.FALLBACK_LANGUAGE);
        try {
            if (mode != Mode.ROOT_PART || !r.route().equals(r.path()) || r.query() != null || r.adminId() != 0 || r.sessionId() != 0) {
                LOGGER.warning("Root part: sign-in request refused (" + r.method() + " " + r.path() + ")");
                logAudit("FORWARD_REFUSED", r.clientIp(), "route=" + r.route() + " path=" + r.path());
                sendJsonError(exchange, 404, I18n.tr("server.access.forbidden"));
                return;
            }
            String refused = RootGate.check(r);
            if (refused != null) {
                LOGGER.warning("Root part: sign-in request refused: " + refused);
                logAudit("FORWARD_REFUSED", r.clientIp(), "route=" + r.route() + " " + refused);
                sendJsonError(exchange, 400, I18n.tr("server.rootPart.refused"));
                return;
            }
            auth.handleLogin(exchange, false);
        } finally {
            I18n.clearCurrent();
            forgetCurrentSession();
        }
    }

    /**
     * The root part: one of the two webmail routes (password change, copy into the vault), which the web
     * part passes to it without an administrator after checking that the caller is the webmail on the same
     * machine. The root part does not see that check and does not need it: it changes or copies a password
     * only if the current one matches the hash (bcrypt), with its own attempt limit per mailbox. Whoever had
     * taken over the web part gets no more than someone who already knows the mailbox's password.
     */
    private void serveWebmail(RootChannel.Request r, ForwardedExchange exchange) throws IOException {
        I18n.setCurrent(I18n.LANGUAGES.contains(r.lang()) ? r.lang() : I18n.FALLBACK_LANGUAGE);
        try {
            if (mode != Mode.ROOT_PART || !r.route().equals(r.path()) || r.query() != null || r.adminId() != 0
                    || r.sessionId() != 0 || !"POST".equals(r.method())) {
                LOGGER.warning("Root part: webmail request refused (" + r.method() + " " + r.path() + ")");
                logAudit("FORWARD_REFUSED", r.clientIp(), "route=" + r.route() + " path=" + r.path());
                sendJsonError(exchange, 404, I18n.tr("server.access.forbidden"));
                return;
            }
            String refused = RootGate.check(r);
            if (refused != null) {
                LOGGER.warning("Root part: webmail request refused: " + refused);
                logAudit("FORWARD_REFUSED", r.clientIp(), "route=" + r.route() + " " + refused);
                sendJsonError(exchange, 400, I18n.tr("server.rootPart.refused"));
                return;
            }
            if (r.route().equals(org.daemoxcp.mail.integration.WebmailPasswordConfig.PATH)) webmail.handlePasswordChange(exchange, false);
            else if (r.route().equals(org.daemoxcp.mail.integration.WebmailPasswordConfig.CLEANUP_PATH)) webmail.handleCleanup(exchange, false);
            else webmail.handleVaultCopy(exchange, false);
        } finally {
            I18n.clearCurrent();
            forgetCurrentSession();
        }
    }

    /**
     * The root part: a closed operation (rootOperations) requested by the web part. POST only, no body,
     * the path equal to the name; the session must still exist, and the role from the database must have
     * one of the operation's permissions. Without a session there is only session-key: the session key of
     * this boot, which the web part asks for at startup (only the web part's user gets into the socket,
     * SO_PEERCRED).
     */
    private void serveOperation(RootChannel.Request r, ForwardedExchange exchange) throws IOException {
        I18n.setCurrent(I18n.LANGUAGES.contains(r.lang()) ? r.lang() : I18n.FALLBACK_LANGUAGE);
        try {
            if (r.route().equals("/op/session-key")) {
                if (mode != Mode.ROOT_PART || !"POST".equals(r.method()) || !r.route().equals(r.path())
                        || r.body().length > 0 || r.query() != null || r.adminId() != 0 || r.sessionId() != 0) {
                    sendJsonError(exchange, 404, I18n.tr("server.access.forbidden"));
                    return;
                }
                byte[] key = WebSessions.runKeyForWebPart();
                sendJsonResponse(exchange, new JSONObject().put("success", true).put("key", Base64.getEncoder().encodeToString(key)));
                java.util.Arrays.fill(key, (byte) 0);
                return;
            }
            if (r.route().equals("/op/restart-state")) {
                // The web part cannot see the root's processes (see_other_uids=0): it asks here, for its routes.
                // A valid session is enough: it is the same fact that the banner shows to whoever can see the
                // system.
                if (mode != Mode.ROOT_PART || !"POST".equals(r.method()) || !r.route().equals(r.path())
                        || r.body().length > 0 || r.query() != null) {
                    sendJsonError(exchange, 404, I18n.tr("server.access.forbidden"));
                    return;
                }
                if (Main.sessions.forwarded(r.sessionId(), r.adminId()).isEmpty()) {
                    sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
                    return;
                }
                org.daemoxcp.mail.system.RestartLock.State st = org.daemoxcp.mail.system.RestartLock.current();
                sendJsonResponse(exchange, new JSONObject().put("success", st.known())
                        .put("scheduled", st.scheduled()).put("at", st.at()));
                return;
            }
            RootOperation op = rootOperations().get(r.route().substring("/op/".length()));
            if (mode != Mode.ROOT_PART || op == null || !"POST".equals(r.method()) || !r.route().equals(r.path())
                    || r.body().length > 0 || r.query() != null) {
                LOGGER.warning("Root part: operation refused (" + r.method() + " " + r.route() + ")");
                logAudit("FORWARD_REFUSED", r.clientIp(), "operation=" + r.route());
                sendJsonError(exchange, 404, I18n.tr("server.access.forbidden"));
                return;
            }
            Optional<WebSessions.Current> session = Main.sessions.forwarded(r.sessionId(), r.adminId());
            if (session.isEmpty()) {
                sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
                return;
            }
            if (op.anyOf().stream().noneMatch(p -> AuthStore.may(session.get().admin(), p))) {
                logAudit("PERMISSION_DENIED", r.clientIp(), "user=" + session.get().admin().username() + " operation=" + r.route());
                sendJsonError(exchange, 403, I18n.tr("server.access.forbidden"));
                return;
            }
            op.work().accept(session.get(), r);
            sendJsonResponse(exchange, new JSONObject().put("success", true));
        } finally {
            I18n.clearCurrent();
        }
    }

    /**
     * The web part asks the root part for a closed operation, on behalf of whoever made the current request
     * (the thread's session). If the root part does not answer, the log says so: the change in MySQL is
     * there anyway, and Dovecot creates the folders at the first login.
     */
    @SuppressWarnings("unchecked")
    private void askRoot(String operation) {
        Object[] cached = CURRENT_SESSION.get();
        Optional<WebSessions.Current> s = cached == null ? Optional.empty() : (Optional<WebSessions.Current>) cached[1];
        if (s.isEmpty()) {
            LOGGER.warning("Web part: root operation " + operation + " asked outside a signed-in request: not sent");
            return;
        }
        HttpExchange ex = (HttpExchange) cached[0];
        String route = "/op/" + operation;
        RootChannel.Request req = new RootChannel.Request(route, "POST", route, null, Map.of(), getClientIp(ex), I18n.current(),
                s.get().admin().id(), s.get().id(), null);
        try (RootChannel.Exchange answer = RootChannel.send(org.daemoxcp.mail.system.PanelSeparation.socket(), req)) {
            String body = new String(answer.body().readAllBytes(), StandardCharsets.UTF_8);
            if (answer.head().status() != 200)
                LOGGER.warning("Web part: the root part refused " + operation + " (" + answer.head().status() + " " + body + ")");
        } catch (IOException e) {
            LOGGER.warning("Web part: the root part did not do " + operation + ": " + e.getMessage());
        }
    }

    /**
     * The web part: an API of a logged-in user, which has already passed Host, language, permission and
     * CSRF, goes to the root part with who asked for it (administrator and session id), the IP and the
     * language. Never the cookies nor the token: see RootChannel. The response comes back as it is,
     * without Set-Cookie.
     */
    private void forwardToRoot(HttpExchange exchange, String route) throws IOException {
        try {
            Optional<WebSessions.Current> session = currentSession(exchange);
            if (session.isEmpty()) {
                sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
                return;
            }
            byte[] body = RootChannel.readBody(exchange.getRequestBody());
            if (body == null) {
                sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge"));
                return;
            }
            relay(exchange, route, session.get().admin().id(), session.get().id(), body, false);
        } catch (IOException e) {
            if (exchange.getResponseCode() == -1) {
                try { sendJsonError(exchange, 502, I18n.tr("server.rootPart.unavailable")); } catch (IOException ignored) { }
            }
            LOGGER.log(Level.FINE, "Web part: forwarding " + route + " failed", e);
        } finally {
            exchange.close();
        }
    }

    /**
     * The web part: one of the two webmail routes. Here only what the root part cannot see, i.e. that the
     * caller is the webmail on the same machine (loopback without a proxy, with its key), and a POST;
     * otherwise 404 or 405 as today, without bothering the root part. Then the request goes to the root
     * part without an administrator.
     */
    private void forwardWebmail(HttpExchange exchange, String route) throws IOException {
        try {
            if (WebmailPasswordHandler.callerRefused(exchange)) return;
            byte[] body = RootChannel.readBody(exchange.getRequestBody());
            if (body == null || body.length > WebmailPasswordHandler.maxBody()) {
                sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge"));
                return;
            }
            relay(exchange, route, 0, 0, body, false);
        } catch (IOException e) {
            if (exchange.getResponseCode() == -1) {
                try { sendJsonError(exchange, 502, I18n.tr("server.rootPart.unavailable")); } catch (IOException ignored) { }
            }
            LOGGER.log(Level.FINE, "Web part: forwarding " + route + " failed", e);
        } finally {
            exchange.close();
        }
    }

    /** How large a login request can be (like AuthHandlers). */
    private static final int SIGN_IN_MAX_BODY = 32 * 1024;

    /**
     * The web part: the login (POST /api/login) is decided by the root part (A). Here only what the root
     * part cannot see: the CSRF token of the login page, bound to this browser's __Host-DaemoxCPMailPre
     * cookie. Then the request goes to the root part without an administrator, and from its response only
     * one cookie passes, the one of the session that the root part created.
     */
    private void forwardSignIn(HttpExchange exchange) throws IOException {
        try {
            addSecurityHeaders(exchange);
            if (!"POST".equals(exchange.getRequestMethod())) {
                exchange.getResponseHeaders().set("Allow", "POST");
                sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
                return;
            }
            byte[] body = RootChannel.readBody(exchange.getRequestBody());
            if (body == null || body.length > SIGN_IN_MAX_BODY) {
                sendJsonError(exchange, 400, I18n.tr("server.badRequest"));
                return;
            }
            JSONObject req;
            try {
                req = new JSONObject(new String(body, StandardCharsets.UTF_8));
            } catch (org.json.JSONException e) {
                sendJsonError(exchange, 400, I18n.tr("server.badRequest"));
                return;
            }
            if (!WebSessions.validPreLoginCsrf(cookieValue(exchange, WebSessions.PRE_COOKIE), req.optString("csrf_token", ""))) {
                logAudit("CSRF_FAILURE", getClientIp(exchange), "login page token");
                sendJsonError(exchange, 403, I18n.tr("server.csrfInvalid"));
                return;
            }
            relay(exchange, "/api/login", 0, 0, body, true);
            forgetCurrentSession();
        } catch (IOException e) {
            if (exchange.getResponseCode() == -1) {
                try { sendJsonError(exchange, 502, I18n.tr("server.rootPart.unavailable")); } catch (IOException ignored) { }
            }
            LOGGER.log(Level.FINE, "Web part: forwarding the sign-in failed", e);
        } finally {
            exchange.close();
        }
    }

    /**
     * The request to the root part and its response to the browser. No Set-Cookie passes from the root
     * part, except, if sessionCookie, the session's one (the login).
     */
    private void relay(HttpExchange exchange, String route, long adminId, long sessionId, byte[] body,
                       boolean sessionCookie) throws IOException {
        Map<String, String> headers = new java.util.LinkedHashMap<>();
        for (String h : RootChannel.HEADERS) {
            String v = exchange.getRequestHeaders().getFirst(h);
            if (v == null) continue;
            if (v.length() > 512) v = v.substring(0, 512);
            // A value outside printable ASCII would be refused by the root part: it is not sent, and that is it.
            if (v.matches("[\\x20-\\x7E]*")) headers.put(h, v);
        }
        java.net.URI uri = exchange.getRequestURI();
        RootChannel.Request request = new RootChannel.Request(route, exchange.getRequestMethod(), uri.getRawPath(),
                uri.getRawQuery(), headers, getClientIp(exchange), I18n.current(), adminId, sessionId, body);
        RootChannel.Exchange answer;
        try {
            answer = RootChannel.send(org.daemoxcp.mail.system.PanelSeparation.socket(), request);
        } catch (IOException e) {
            LOGGER.warning("Web part: the root part does not answer on " + org.daemoxcp.mail.system.PanelSeparation.socket()
                    + ": " + e.getMessage());
            sendJsonError(exchange, 503, I18n.tr("server.rootPart.unavailable"));
            return;
        }
        try (answer) {
            // The root part's headers replace those with the same name that the web part may have already set
            // (the root part sets the security headers too): no duplicates.
            Headers out = exchange.getResponseHeaders();
            Set<String> fromRoot = new HashSet<>();
            for (String[] kv : answer.head().headers()) {
                String k = kv[0].toLowerCase(java.util.Locale.ROOT);
                if (ForwardedExchange.HOP_BY_HOP.contains(k)) continue;
                if (k.equals("set-cookie") && !(sessionCookie && kv[1].startsWith(WebSessions.COOKIE + "="))) {
                    LOGGER.warning("Web part: a Set-Cookie from the root part on " + route + " was dropped");
                    continue;
                }
                if (fromRoot.add(k)) out.set(kv[0], kv[1]);
                else out.add(kv[0], kv[1]);
            }
            long length = answer.head().length();
            exchange.sendResponseHeaders(answer.head().status(), length);
            if (length == -1) return;
            try (OutputStream os = exchange.getResponseBody()) {
                if (length > 0) {
                    long copied = answer.body().transferTo(os);
                    if (copied != length) LOGGER.warning("Web part: " + route + " answered " + copied + " bytes of " + length);
                } else {
                    answer.body().transferTo(os);
                }
            }
        }
    }

    /**
     * The web part, at startup: the session key of this boot of the root part (A). It tries for a while,
     * because the root part opens the socket before starting the web part but may still be busy. Null if it
     * does not answer: then the web part does not start (daemon restarts it).
     */
    public static byte[] sessionKeyFromRoot(long waitMs) {
        long until = System.currentTimeMillis() + waitMs;
        String last = "";
        while (true) {
            RootChannel.Request req = new RootChannel.Request("/op/session-key", "POST", "/op/session-key", null, Map.of(),
                    "127.0.0.1", "en", 0, 0, null);
            try (RootChannel.Exchange answer = RootChannel.send(org.daemoxcp.mail.system.PanelSeparation.socket(), req)) {
                String body = new String(answer.body().readAllBytes(), StandardCharsets.UTF_8);
                if (answer.head().status() == 200) {
                    byte[] key = Base64.getDecoder().decode(new JSONObject(body).getString("key"));
                    if (key.length == 32) return key;
                }
                last = "status " + answer.head().status();
            } catch (Exception e) {
                last = e.getMessage();
            }
            if (System.currentTimeMillis() > until) {
                LOGGER.warning("Web part: no session key from the root part (" + last + ")");
                return null;
            }
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return null;
            }
        }
    }

    private boolean isAuthenticated(HttpExchange exchange) {
        return currentSession(exchange).isPresent();
    }

    /** The value of a request cookie, or null. */
    static String cookieValue(HttpExchange exchange, String name) {
        List<String> headers = exchange.getRequestHeaders().get("Cookie");
        if (headers == null) return null;
        for (String header : headers) {
            for (String part : header.split(";")) {
                String p = part.trim();
                if (p.startsWith(name + "=")) return p.substring(name.length() + 1);
            }
        }
        return null;
    }

    private String getCsrfToken(HttpExchange exchange) {
        return currentSession(exchange).map(s -> WebSessions.csrfToken(s.token())).orElse(null);
    }

    /**
     * The CSRF token of the pages before login (login, installation): the HMAC of the cookie
     * __Host-DaemoxCPMailPre, which is created here if missing. Nothing on the server: before, every
     * visit to the login page opened a session in memory.
     */
    private String preLoginToken(HttpExchange exchange) {
        String current = cookieValue(exchange, WebSessions.PRE_COOKIE);
        String value = WebSessions.preLoginCookieValue(current);
        if (!value.equals(current)) exchange.getResponseHeaders().add("Set-Cookie", WebSessions.preCookieHeader(value));
        return WebSessions.preLoginCsrf(value);
    }

    // ============== PAGE HANDLERS ==============

    /**
     * What to show when MySQL does not answer: the panel cannot read domains, mailboxes and
     * administrators. It says what is happening and how to fix it, in the requester's language.
     */
    private void pageUnavailable(HttpExchange exchange) throws IOException {
        String lang = I18n.current();
        String html = "<!doctype html><html lang=\"" + lang + "\"><head><meta charset=\"utf-8\">"
                + "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
                + "<title>" + I18n.escapeHtml(I18n.tr("server.unavailable.title")) + "</title>"
                + org.daemoxcp.mail.content.PanelContent.UNAVAILABLE_STYLE
                + "</head><body><main class=\"c\">"
                + "<h1>" + I18n.escapeHtml(I18n.tr("server.unavailable.title")) + "</h1>"
                + "<p>" + I18n.escapeHtml(I18n.tr("server.unavailable.mysql")) + "</p>"
                + "<p>" + I18n.escapeHtml(I18n.tr("server.unavailable.mysqlFix")) + "</p>"
                + "</main></body></html>";
        byte[] data = html.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        addSecurityHeaders(exchange);
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
        exchange.getResponseHeaders().set("Content-Language", lang);
        exchange.sendResponseHeaders(503, data.length);
        try (java.io.OutputStream os = exchange.getResponseBody()) { os.write(data); }
        exchange.close();
    }

    /**
     * Where the front door leads: MySQL down -> the page that says so; no administrator
     * -> /setup, which explains how to create one from the console. True if the response has already
     * been sent.
     */
    private boolean notReady(HttpExchange exchange) throws IOException {
        Main.refreshSetupState();
        if (!Main.mysqlAvailable) {
            pageUnavailable(exchange);
            return true;
        }
        if (Main.setupRequired) {
            redirect(exchange, "/setup");
            return true;
        }
        return false;
    }

    private void handleRoot(HttpExchange exchange) throws IOException {
        try {
            if (notReady(exchange)) return;
            redirect(exchange, isAuthenticated(exchange) ? "/home" : "/index");
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error in handleRoot", e);
            redirect(exchange, "/index");
        }
    }

    private void handleIndex(HttpExchange exchange) throws IOException {
        try {
            if (notReady(exchange)) return;
            if (isAuthenticated(exchange)) {
                redirect(exchange, "/home");
                return;
            }
            sendHtml(exchange, renderPage(exchange, readHtmlFile("index.html"), preLoginToken(exchange)));
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error in handleIndex", e);
            sendJsonError(exchange, 500, I18n.tr("server.requestFailed"));
        }
    }

    /**
     * /setup: the panel has no administrator yet. It is not created from here (whoever arrived
     * first would become administrator): the page shows the command to run on the server,
     * --create-admin. With an administrator already present it goes to the login.
     */
    private void handleSetup(HttpExchange exchange) throws IOException {
        Main.refreshSetupState();
        if (!Main.mysqlAvailable) {
            pageUnavailable(exchange);
            return;
        }
        if (!Main.setupRequired) {
            redirect(exchange, "/index");
            return;
        }
        // The page token is only needed for the language switch.
        sendHtml(exchange, renderPage(exchange, readHtmlFile("setup.html"), preLoginToken(exchange)));
    }

    private void handleProtectedPage(HttpExchange exchange) throws IOException {
        try {
            String path = exchange.getRequestURI().getPath();
            if (!isAuthenticated(exchange)) {
                redirect(exchange, "/index");
                return;
            }
            String pageName = path.equals("/") ? "home" : path.substring(1);
            String csrfToken = getCsrfToken(exchange);

            String html = readHtmlFile(pageName + ".html");
            if (html == null) {
                html = readHtmlFile("home.html");
            }
            // The theme chosen by the admin, inside the page: the <head> applies it before the first
            // paint, instead of finding it out later with /api/theme (that was the white flash).
            html = withTheme(exchange, html);
            // Replace system info placeholders
            html = html.replace("{{JAVA_VERSION}}", "Java " + System.getProperty("java.version") + " (OpenJDK)");
            html = html.replace("{{PLATFORM}}", System.getProperty("os.name") + " " + System.getProperty("os.version"));
            html = html.replace("{{DATABASE}}", Main.mysqlAvailable ? "MySQL" : I18n.tr("server.notConnected"));
            // The mail server's name (configured at installation) and the webmail's domain,
            // escaped: they end up in the page's text and inside script strings.
            String notConfigured = I18n.tr("server.notConfigured");
            String mailHostname = Main.dbManager != null ? Main.dbManager.getMailHostname() : null;
            html = html.replace("{{MAIL_HOSTNAME}}", I18n.escapeHtml(mailHostname != null && !mailHostname.isEmpty() ? mailHostname : notConfigured));
            String rcDomain = Main.dbManager != null ? Main.dbManager.getRoundcubeDomain() : "";
            html = html.replace("{{ROUNDCUBE_DOMAIN}}", I18n.escapeHtml(rcDomain != null && !rcDomain.isEmpty() ? rcDomain : notConfigured));
            sendHtml(exchange, renderPage(exchange, html, csrfToken));
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error in handleProtectedPage", e);
            sendJsonError(exchange, 500, I18n.tr("server.internalError"));
        }
    }

    /**
     * The theme chosen by the admin, inside the page: the <head> applies it before the first paint,
     * instead of finding it out later with /api/theme (that was the white flash).
     */
    private String withTheme(HttpExchange exchange, String html) {
        String theme = savedTheme(exchange);
        return html.replace("{{THEME}}", theme).replace("{{COLOR_SCHEME}}", "auto".equals(theme) ? "light dark" : theme);
    }

    // ============== LANGUAGE ==============

    /**
     * The step common to every HTML page, on every request: the CSRF token, the frame (sidebar
     * and top bar) and the texts in the requester's language. The language: the one saved
     * in the account, then this browser's cookie, then the browser's own; for a browser that
     * asks for neither Italian nor English, English.
     */
    private String renderPage(HttpExchange exchange, String html, String csrfToken) {
        String saved = savedLanguage(exchange);
        String lang = I18n.languageOf(exchange, saved);
        // The choice saved in the account also applies to the scripts' calls, which read the
        // cookie: if the cookie says otherwise (a new browser), it is aligned.
        if (saved != null && !saved.equals(I18n.fromCookie(exchange.getRequestHeaders().get("Cookie")))) {
            exchange.getResponseHeaders().add("Set-Cookie", I18n.cookieHeader(saved));
        }
        exchange.getResponseHeaders().set("Content-Language", lang);
        String page = html.replace("{{CSRF_TOKEN}}", I18n.escapeHtml(csrfToken == null ? "" : csrfToken));
        page = Layout.expand(page, lang, viewer(exchange));
        return I18n.render(page, lang);
    }

    /**
     * Who is looking at the page: name, role and permissions of the session's administrator; before login,
     * nobody.
     */
    private Layout.Viewer viewer(HttpExchange exchange) {
        return currentSession(exchange).map(s -> new Layout.Viewer(s.admin().username(), s.admin().role(),
                AuthStore.permissionsOf(s.admin().role()))).orElse(Layout.Viewer.NOBODY);
    }

    /** The language saved by this session's administrator, or null (before login, or never chosen). */
    private String savedLanguage(HttpExchange exchange) {
        try {
            if (Main.mailDatabase == null || !isAuthenticated(exchange)) return null;
            return Main.mailDatabase.getAdminLanguage(getSessionUsername(exchange));
        } catch (Exception e) {
            LOGGER.log(Level.FINE, "admin language", e);
            return null;
        }
    }

    /**
     * GET /i18n/(language).js: the scripts' dictionary, with t() and tn(). Public (it holds only the
     * interface texts, and the login page needs it too) and cacheable:
     * the address changes with the texts (?v=fingerprint).
     */
    /**
     * GET /assets/...: a script or stylesheet of a page (PageAssets). The name is the
     * fingerprint of the content, so the file never changes and is cached for a year.
     * Those of the protected pages only to logged-in users: to the others 404, as if they did not exist.
     */
    private void handleAsset(HttpExchange exchange) throws IOException {
        try (exchange) {
            Path f = "GET".equals(exchange.getRequestMethod())
                    ? org.daemoxcp.mail.content.PageAssets.resolve(Paths.get(getJarDirectory(), "admin"),
                            exchange.getRequestURI().getPath(), isAuthenticated(exchange))
                    : null;
            if (f == null) {
                exchange.sendResponseHeaders(404, -1);
                return;
            }
            byte[] body = Files.readAllBytes(f);
            boolean open = exchange.getRequestURI().getPath().startsWith("/" + org.daemoxcp.mail.content.PageAssets.DIR + "/"
                    + org.daemoxcp.mail.content.PageAssets.OPEN + "/");
            addSecurityHeaders(exchange);
            exchange.getResponseHeaders().set("Content-Type", org.daemoxcp.mail.content.PageAssets.contentType(f));
            exchange.getResponseHeaders().set("Cache-Control", (open ? "public" : "private") + ", max-age=31536000, immutable");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body);
            }
        }
    }

    private void handleI18nScript(HttpExchange exchange) throws IOException {
        try (exchange) {
            String path = exchange.getRequestURI().getPath();
            String lang = path.startsWith("/i18n/") && path.endsWith(".js") ? path.substring(6, path.length() - 3) : "";
            if (!"GET".equals(exchange.getRequestMethod()) || !I18n.LANGUAGES.contains(lang)) {
                exchange.sendResponseHeaders(404, -1);
                return;
            }
            byte[] body = I18n.script(lang).getBytes(StandardCharsets.UTF_8);
            addSecurityHeaders(exchange);
            exchange.getResponseHeaders().set("Content-Type", "application/javascript; charset=UTF-8");
            exchange.getResponseHeaders().set("Cache-Control", "public, max-age=31536000, immutable");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body);
            }
        }
    }

    /**
     * POST /api/language: changes the language. For a logged-in user it is saved in the account (it
     * follows them on every browser) and in the cookie; on the login and installation pages only in the
     * cookie. Always with the CSRF token: the session's one, or before login the page's one.
     */
    private void handleApiLanguage(HttpExchange exchange) throws IOException {
        try {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
                return;
            }
            String body = readRequestBodyWithLimit(exchange);
            if (body == null) {
                sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge"));
                return;
            }
            JSONObject request;
            try {
                request = new JSONObject(body);
            } catch (Exception e) {
                sendJsonError(exchange, 400, I18n.tr("server.badRequest"));
                return;
            }
            String lang = request.optString("language", "");
            if (!I18n.LANGUAGES.contains(lang)) {
                sendJsonError(exchange, 400, I18n.tr("server.unknownLanguage"));
                return;
            }
            if (isAuthenticated(exchange)) {
                if (!validateCsrfForRequest(exchange, request)) {
                    sendCsrfError(exchange);
                    return;
                }
                Main.mailDatabase.setAdminLanguage(getSessionUsername(exchange), lang);
            } else if (!WebSessions.validPreLoginCsrf(cookieValue(exchange, WebSessions.PRE_COOKIE), request.optString("csrf_token", ""))) {
                sendCsrfError(exchange);
                return;
            }
            exchange.getResponseHeaders().add("Set-Cookie", I18n.cookieHeader(lang));
            sendJsonResponse(exchange, new JSONObject().put("success", true).put("language", lang));
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error in handleApiLanguage", e);
            sendJsonError(exchange, 500, I18n.tr("server.internalError"));
        }
    }

    /** POST /api/logout: closes the session, in the database too, and removes the cookie. */
    private void handleLogout(HttpExchange exchange) throws IOException {
        if (!"POST".equals(exchange.getRequestMethod())) {
            sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
            return;
        }
        currentSession(exchange).ifPresent(s -> {
            // With the separated panel the session is removed by the root part, which alone writes sessions (A);
            // the cookie is removed below anyway, even if the root part does not answer.
            if (mode == Mode.WEB_PART) {
                askRoot("logout");
                return;
            }
            Main.sessions.revoke(s.token());
            logAudit("LOGOUT", getClientIp(exchange), "user=" + s.admin().username());
        });
        forgetCurrentSession();
        exchange.getResponseHeaders().add("Set-Cookie", WebSessions.clearCookieHeader());
        // r14: on logout the browser also forgets the cache and data of the panel's pages. Not
        // "cookies": it would apply to the whole domain, the webmail on neighbouring names included.
        exchange.getResponseHeaders().add("Clear-Site-Data", "\"cache\", \"storage\"");
        // Cookies with the earlier names (before __Host-, then the panel's old name), if a browser still has
        // them: the names are in the data file, section "sessionCookies"
        for (String[] old : org.daemoxcp.mail.system.LegacyNames.pairs("sessionCookies"))
            exchange.getResponseHeaders().add("Set-Cookie", old[0] + "=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0");
        sendJsonResponse(exchange, new JSONObject().put("success", true));
    }

    // ============== API HANDLERS ==============

    private void handleApiStatus(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
            return;
        }

        // Sync installed components based on actual package presence
        syncInstalledComponents();

        JSONObject status = new JSONObject();

        // Service status (check if running)
        status.put("postfix", checkServiceRunning("postfix"));
        status.put("dovecot", checkServiceRunning("dovecot"));
        status.put("rspamd", checkServiceRunning("rspamd"));
        status.put("clamav", checkServiceRunning("clamav_clamd"));
        status.put("mysql", checkServiceRunning("mysql-server"));
        status.put("redis", checkServiceRunning("redis"));
        status.put("roundcube", checkServiceRunning("nginx") && checkServiceRunning("php_fpm"));

        // Installed components from database (now synced)
        if (Main.mysqlAvailable) {
            status.put("installed_postfix", Main.mailDatabase.isComponentInstalled("postfix"));
            status.put("installed_dovecot", Main.mailDatabase.isComponentInstalled("dovecot"));
            status.put("installed_rspamd", Main.mailDatabase.isComponentInstalled("rspamd"));
            status.put("installed_roundcube", Main.mailDatabase.isComponentInstalled("roundcube"));
            status.put("installed_clamav", Main.mailDatabase.isComponentInstalled("clamav"));
            status.put("installed_redis", Main.mailDatabase.isComponentInstalled("redis"));

            // Stats
            status.put("domains", Main.mailDatabase.getDomainCount());
            status.put("mailboxes", Main.mailDatabase.getMailboxCount());
            status.put("aliases", Main.mailDatabase.getAliasCount());

            // Mail server hostname and IP for DNS warning on home page
            String mailHostname = Main.mailDatabase.getSetting("mail_hostname", "");
            status.put("mail_hostname", mailHostname);

            // Get server IP
            String serverIp = dnsGenerator != null ? dnsGenerator.detectServerIp() : "";
            status.put("server_ip", serverIp);

            // SSL certificate mismatch check
            if (acmeManager != null && !mailHostname.isEmpty()) {
                AcmeManager.CertificateInfo certInfo = acmeManager.getCertificateInfo();
                if (certInfo != null && certInfo.installed) {
                    String certCn = certInfo.commonName != null ? certInfo.commonName : "";
                    boolean sslMatch = certCn.equalsIgnoreCase(mailHostname);
                    // Also check SAN (Subject Alternative Names)
                    if (!sslMatch && certInfo.subjectAltNames != null) {
                        for (String san : certInfo.subjectAltNames) {
                            if (san.equalsIgnoreCase(mailHostname)) {
                                sslMatch = true;
                                break;
                            }
                        }
                    }
                    status.put("ssl_cn", certCn);
                    status.put("ssl_match", sslMatch);
                    status.put("ssl_self_signed", acmeManager.isSelfSigned());
                } else {
                    status.put("ssl_cn", "");
                    status.put("ssl_match", false);
                    status.put("ssl_self_signed", true);
                }
            }
        }

        sendJsonResponse(exchange, status);
    }

    private void handleApiDomains(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
            return;
        }

        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();

        try {
            switch (method) {
                case "GET" -> {
                    JSONArray domains = new JSONArray();
                    for (MailDatabase.Domain d : Main.mailDatabase.getDomains()) {
                        JSONObject domainJson = new JSONObject();
                        domainJson.put("id", d.id);
                        domainJson.put("domain", d.domain);
                        domainJson.put("description", d.description != null ? d.description : "");
                        domainJson.put("active", d.active);
                        domainJson.put("mailbox_count", d.mailboxCount);
                        domainJson.put("alias_count", d.aliasCount);
                        domainJson.put("has_dkim", d.hasDkim);
                        domainJson.put("created_at", d.createdAt != null ? d.createdAt.toString() : "");
                        domains.put(domainJson);
                    }
                    response.put("success", true);
                    response.put("domains", domains);
                }
                case "POST" -> {
                    String body = readRequestBodyWithLimit(exchange);
                    if (body == null) {
                        sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge"));
                        return;
                    }
                    JSONObject req = new JSONObject(body);

                    // Validate CSRF token
                    if (!validateCsrfForRequest(exchange, req)) {
                        sendCsrfError(exchange);
                        return;
                    }

                    String domain = req.optString("domain", "").toLowerCase().trim();
                    String description = req.optString("description", "");

                    if (!SecurityUtils.isValidDomain(domain)) {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.domain.invalid"));
                    } else {
                        int id = Main.mailDatabase.addDomain(domain, description);
                        if (id > 0) {
                            response.put("success", true);
                            response.put("id", id);
                            logAudit("DOMAIN_CREATED", getClientIp(exchange), "Domain: " + domain);
                            // Regenerate configs
                            regenerateMailConfigs();
                        } else {
                            response.put("success", false);
                            response.put("error", I18n.tr("server.domain.exists"));
                        }
                    }
                }
                case "PUT" -> {
                    String body = readRequestBodyWithLimit(exchange);
                    if (body == null) {
                        sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge"));
                        return;
                    }
                    JSONObject req = new JSONObject(body);

                    if (!validateCsrfForRequest(exchange, req)) {
                        sendCsrfError(exchange);
                        return;
                    }

                    int id = req.optInt("id", 0);
                    String description = req.optString("description", "");

                    if (id > 0) {
                        boolean updated = Main.mailDatabase.updateDomainDescription(id, description);
                        response.put("success", updated);
                        if (updated) {
                            logAudit("DOMAIN_UPDATED", getClientIp(exchange), "Domain ID: " + id);
                        }
                    } else {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.badId"));
                    }
                }
                case "DELETE" -> {
                    String query = exchange.getRequestURI().getQuery();
                    int id = extractIdFromQuery(query);
                    if (id > 0) {
                        boolean deleted = Main.mailDatabase.deleteDomain(id);
                        response.put("success", deleted);
                        if (deleted) {
                            logAudit("DOMAIN_DELETED", getClientIp(exchange), "Domain ID: " + id);
                            regenerateMailConfigs();
                        }
                    } else {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.badId"));
                    }
                }
                default -> {
                    sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
                    return;
                }
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", ErrorText.forPage("handleApiDomains", e));
        }

        sendJsonResponse(exchange, response);
    }

    private void handleApiMailboxes(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
            return;
        }

        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();

        try {
            switch (method) {
                case "GET" -> {
                    String transform = queryParameter(exchange.getRequestURI().getRawQuery(), "transform");
                    if (transform != null) {
                        // Preview of "mailbox -> alias": what is lost, what remains. It changes nothing.
                        int tid;
                        try { tid = Integer.parseInt(transform); } catch (NumberFormatException e) { tid = 0; }
                        MailDatabase.Mailbox tm = tid > 0 ? Main.mailDatabase.getMailbox(tid) : null;
                        if (tm == null) {
                            response.put("success", false).put("error", I18n.tr("server.mailbox.notFound"));
                        } else {
                            response = org.daemoxcp.mail.system.AddressTransform.previewToAlias(
                                    org.daemoxcp.mail.system.AddressTransform.state(Main.mailDatabase, tm.email.toLowerCase(java.util.Locale.ROOT)),
                                    java.time.ZoneId.systemDefault()).put("success", true).put("id", tm.id);
                        }
                        break;
                    }
                    // Check if requesting a single mailbox by ID
                    String query = exchange.getRequestURI().getQuery();
                    int singleId = extractIdFromQuery(query);

                    if (singleId > 0) {
                        // Return single mailbox for editing
                        MailDatabase.Mailbox m = Main.mailDatabase.getMailbox(singleId);
                        if (m != null) {
                            JSONObject mbox = new JSONObject();
                            mbox.put("id", m.id);
                            mbox.put("email", m.email);
                            mbox.put("name", m.name != null ? m.name : "");
                            mbox.put("domain", m.domainName);
                            mbox.put("quota_mb", m.quotaMb);
                            mbox.put("active", m.active);
                            mbox.put("receive_enabled", m.receiveEnabled);
                            mbox.put("junk_expunge_days", m.junkExpungeDays);
                            mbox.put("trash_expunge_days", m.trashExpungeDays);
                            mbox.put("last_login", m.lastLogin != null ? m.lastLogin.toString() : I18n.tr("server.never"));
                            // Flag: does the mailbox have a password stored in the vault?
                            // Used by the UI to show/hide the "reveal password" icon.
                            try {
                                mbox.put("has_encrypted_password",
                                    Main.mailDatabase.mailboxHasEncryptedPassword(m.id));
                            } catch (Exception ignore) {
                                mbox.put("has_encrypted_password", false);
                            }
                            response.put("success", true);
                            response.put("mailbox", mbox);
                        } else {
                            response.put("success", false);
                            response.put("error", I18n.tr("server.mailbox.notFound"));
                        }
                    } else {
                        // Return all mailboxes
                        JSONArray mailboxes = new JSONArray();
                        for (MailDatabase.Mailbox m : Main.mailDatabase.getAllMailboxes()) {
                            JSONObject mbox = new JSONObject();
                            mbox.put("id", m.id);
                            mbox.put("email", m.email);
                            mbox.put("name", m.name != null ? m.name : "");
                            mbox.put("domain", m.domainName);
                            mbox.put("quota_mb", m.quotaMb);
                            mbox.put("active", m.active);
                            mbox.put("receive_enabled", m.receiveEnabled);
                            mbox.put("junk_expunge_days", m.junkExpungeDays);
                            mbox.put("trash_expunge_days", m.trashExpungeDays);
                            mbox.put("last_login", m.lastLogin != null ? m.lastLogin.toString() : I18n.tr("server.never"));
                            mbox.put("autoresponder_enabled", m.autoresponderEnabled);
                            mbox.put("forwarding_count", m.forwardingCount);
                            mbox.put("filters_count", m.filtersCount);
                            mailboxes.put(mbox);
                        }
                        response.put("success", true);
                        response.put("mailboxes", mailboxes);
                    }
                }
                case "POST" -> {
                    String body = readRequestBodyWithLimit(exchange);
                    if (body == null) {
                        sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge"));
                        return;
                    }
                    JSONObject req = new JSONObject(body);

                    // Validate CSRF token
                    if (!validateCsrfForRequest(exchange, req)) {
                        sendCsrfError(exchange);
                        return;
                    }

                    // Sub-routing for specific actions (no email/password required)
                    String action = req.optString("action", "");

                    if ("transform_to_alias".equals(action)) {
                        sendJsonResponse(exchange, mailboxToAlias(req, getClientIp(exchange)));
                        return;
                    }

                    if ("bulk_rotate_passwords".equals(action)) {
                        // Generates + bulk-updates the passwords of N mailboxes.
                        // The plain-text passwords come back ONLY ONCE in the response
                        // (because they are then encrypted in the vault with the current master key).
                        //
                        // INPUT:
                        //   mailbox_ids: array of INT (or "all" as a string for "all of them")
                        //   length:      password length (default 20)
                        //
                        // OUTPUT:
                        //   results: array of {id, email, password, success, error?}
                        //   summary: {total, succeeded, failed}
                        Object ids = req.opt("mailbox_ids");
                        java.util.List<Integer> idList = new java.util.ArrayList<>();
                        // Pattern matching for instanceof (Java 16+): the variable 'idsArr'
                        // is typed and in scope only in the branch where it is needed.
                        if ("all".equals(ids)) {
                            for (MailDatabase.Mailbox m : Main.mailDatabase.getAllMailboxes()) idList.add(m.id);
                        } else if (ids instanceof org.json.JSONArray idsArr) {
                            for (int i = 0; i < idsArr.length(); i++) idList.add(idsArr.getInt(i));
                        }
                        if (idList.isEmpty()) {
                            response.put("success", false);
                            response.put("error", I18n.tr("server.mailbox.noneGiven"));
                            sendJsonResponse(exchange, response);
                            return;
                        }
                        int length = req.optInt("length", 20);
                        // Advanced options (same scheme as generate_password)
                        String type = req.optString("type", "easy_to_read");
                        boolean inclLocal = req.optBoolean("include_lowercase", true);
                        boolean inclUpdated = req.optBoolean("include_uppercase", true);
                        boolean inclNew = req.optBoolean("include_numbers", true);
                        boolean inclSystem = req.optBoolean("include_symbols", true);
                        org.daemoxcp.mail.security.PasswordVault vault = org.daemoxcp.mail.security.PasswordVault.getInstance();
                        org.json.JSONArray results = new org.json.JSONArray();
                        int succeeded = 0, failed = 0;
                        for (int mid : idList) {
                            org.json.JSONObject r = new org.json.JSONObject();
                            r.put("id", mid);
                            try {
                                MailDatabase.Mailbox mb = Main.mailDatabase.getMailbox(mid);
                                if (mb == null) {
                                    r.put("success", false);
                                    r.put("error", I18n.tr("server.mailbox.notFound"));
                                    results.put(r);
                                    failed++;
                                    continue;
                                }
                                r.put("email", mb.email);
                                String pw = vault.generatePassword(length, type, inclLocal, inclUpdated, inclNew, inclSystem);
                                boolean ok = Main.mailDatabase.updateMailboxPassword(mid, pw);
                                if (ok) {
                                    r.put("success", true);
                                    r.put("password", pw);
                                    succeeded++;
                                    logAudit("MAILBOX_PASSWORD_BULK_ROTATED", getClientIp(exchange),
                                        "mailbox_id=" + mid + " email=" + mb.email);
                                } else {
                                    r.put("success", false);
                                    r.put("error", I18n.tr("server.mailbox.updateFailed"));
                                    failed++;
                                }
                            } catch (Exception ex) {
                                r.put("success", false);
                                r.put("error", ErrorText.forPage("handleApiMailboxes", ex));
                                failed++;
                            }
                            results.put(r);
                        }
                        try { regenerateMailConfigs(); } catch (Exception ignore) {}
                        response.put("success", true);
                        response.put("results", results);
                        org.json.JSONObject summary = new org.json.JSONObject();
                        summary.put("total", idList.size());
                        summary.put("succeeded", succeeded);
                        summary.put("failed", failed);
                        response.put("summary", summary);
                        response.put("warning", I18n.tr("server.mailbox.bulkKept"));
                        sendJsonResponse(exchange, response);
                        return;
                    }

                    if ("generate_password".equals(action)) {
                        // Generates a secure random password -- does not save it, only returns it to the UI.
                        // Accepts advanced options (type, include lower/upper/numbers/symbols).
                        int len = req.optInt("length", 20);
                        String type = req.optString("type", "easy_to_read"); // easy_to_say / easy_to_read / all_chars
                        boolean lo = req.optBoolean("include_lowercase", true);
                        boolean up = req.optBoolean("include_uppercase", true);
                        boolean nu = req.optBoolean("include_numbers", true);
                        boolean sy = req.optBoolean("include_symbols", true);
                        String pw = org.daemoxcp.mail.security.PasswordVault.getInstance()
                            .generatePassword(len, type, lo, up, nu, sy);
                        response.put("success", true);
                        response.put("password", pw);
                        response.put("length", pw.length());
                        response.put("type", type);
                        // Entropy estimate, on the same sets that the generator has just used.
                        // The level is a code (weak, fair, strong, very_strong): the name to
                        // show is set by the page, in the viewer's language.
                        int poolSize = org.daemoxcp.mail.security.PasswordVault.poolSize(type, lo, up, nu, sy);
                        double entropy = org.daemoxcp.mail.security.PasswordVault.estimateEntropy(pw.length(), poolSize);
                        response.put("entropy_bits", Math.round(entropy * 10.0) / 10.0);
                        String strength;
                        if (entropy < 50) strength = "weak";
                        else if (entropy < 75) strength = "fair";
                        else if (entropy < 100) strength = "strong";
                        else strength = "very_strong";
                        response.put("strength", strength);
                        sendJsonResponse(exchange, response);
                        return;
                    }


                    // Default: mailbox creation (existing code)
                    String email = req.optString("email", "").toLowerCase().trim();
                    String password = req.optString("password", "");
                    String name = req.optString("name", "");
                    int quotaMb = req.optInt("quota_mb", 1024);
                    boolean receiveEnabled = req.optBoolean("receive_enabled", true);

                    if (!SecurityUtils.isValidEmail(email)) {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.badEmail"));
                    } else if (!SecurityUtils.isValidMailboxPassword(password)) {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.mailbox.badPassword", Map.of("rule", SecurityUtils.passwordRule())));
                    } else {
                        // Extract domain from email
                        String domainName = email.substring(email.indexOf("@") + 1);
                        MailDatabase.Domain domain = Main.mailDatabase.getDomainByName(domainName);

                        if (domain == null) {
                            response.put("success", false);
                            response.put("error", I18n.tr("server.domain.unknown", Map.of("domain", domainName)));
                        } else {
                            int id = Main.mailDatabase.addMailbox(domain.id, email, password, name, quotaMb, receiveEnabled);
                            if (id > 0) {
                                response.put("success", true);
                                response.put("id", id);
                                regenerateMailConfigs();
                            } else {
                                response.put("success", false);
                                response.put("error", I18n.tr("server.mailbox.exists"));
                            }
                        }
                    }
                }
                case "PUT" -> {
                    // Update existing mailbox
                    String body = readRequestBodyWithLimit(exchange);
                    if (body == null) {
                        sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge"));
                        return;
                    }
                    JSONObject req = new JSONObject(body);

                    // Validate CSRF token
                    if (!validateCsrfForRequest(exchange, req)) {
                        sendCsrfError(exchange);
                        return;
                    }

                    int id = req.optInt("id", 0);
                    if (id <= 0) {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.mailbox.badId"));
                    } else {
                        String name = req.optString("name", "");
                        int quotaMb = req.optInt("quota_mb", 1024);  // 0 = unlimited
                        boolean active = req.optBoolean("active", true);
                        boolean receiveEnabled = req.optBoolean("receive_enabled", true);
                        String newPassword = req.optString("password", "");
                        // Automatic emptying: only the days in the list (0 = never); if the request does not carry
                        // them, the current ones remain, so an older client does not reset them.
                        MailDatabase.Mailbox current = Main.mailDatabase.getMailboxById(id);
                        int junkDays = req.has("junk_expunge_days") ? req.optInt("junk_expunge_days", -1) : current != null ? current.junkExpungeDays : 0;
                        int trashDays = req.has("trash_expunge_days") ? req.optInt("trash_expunge_days", -1) : current != null ? current.trashExpungeDays : 0;
                        if (!MailDatabase.cleanupDaysAllowed(junkDays) || !MailDatabase.cleanupDaysAllowed(trashDays)) {
                            response.put("success", false);
                            response.put("error", I18n.tr("server.mailbox.badCleanupDays"));
                            sendJsonResponse(exchange, response);
                            return;
                        }

                        // Update mailbox
                        boolean updated = Main.mailDatabase.updateMailbox(id, name, quotaMb, active, receiveEnabled, junkDays, trashDays);

                        // If password provided, update it too
                        if (updated && !newPassword.isEmpty()) {
                            if (SecurityUtils.isValidMailboxPassword(newPassword)) {
                                Main.mailDatabase.updateMailboxPassword(id, newPassword);
                            } else {
                                response.put("warning", I18n.tr("server.mailbox.passwordNotUpdated", Map.of("rule", SecurityUtils.passwordRule())));
                            }
                        }

                        if (updated) {
                            response.put("success", true);
                            response.put("message", I18n.tr("server.mailbox.updated"));
                            // Automatic emptying in the audit log, with the before and after (r22)
                            if (current != null && (current.junkExpungeDays != junkDays || current.trashExpungeDays != trashDays))
                                logAudit("MAILBOX_CLEANUP_CHANGED", getClientIp(exchange), "mailbox_id=" + id + " email=" + current.email
                                        + " junk_days=" + current.junkExpungeDays + "->" + junkDays + " trash_days=" + current.trashExpungeDays + "->" + trashDays);
                            regenerateMailConfigs();
                        } else {
                            response.put("success", false);
                            response.put("error", I18n.tr("server.mailbox.updateFailed"));
                        }
                    }
                }
                case "DELETE" -> {
                    // Deleting changes state: same CSRF check as creation and modification (it was missing before).
                    String body = readRequestBodyWithLimit(exchange);
                    if (body == null) {
                        sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge"));
                        return;
                    }
                    if (!validateCsrfForRequest(exchange, body.isBlank() ? new JSONObject() : new JSONObject(body))) {
                        sendCsrfError(exchange);
                        return;
                    }
                    String query = exchange.getRequestURI().getQuery();
                    int id = extractIdFromQuery(query);
                    if (id > 0) {
                        MailDatabase.Mailbox via = Main.mailDatabase.getMailbox(id);
                        boolean deleted = Main.mailDatabase.deleteMailbox(id);
                        response.put("success", deleted);
                        if (deleted) {
                            logAudit("MAILBOX_DELETED", getClientIp(exchange), via != null ? via.email : "Mailbox ID: " + id);
                            regenerateMailConfigs();
                        }
                    } else {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.badId"));
                    }
                }
                default -> {
                    sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
                    return;
                }
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", ErrorText.forPage("handleApiMailboxes", e));
        }

        sendJsonResponse(exchange, response);
    }

    /**
     * API endpoint for mail client configuration info
     * Returns IMAP/SMTP settings for configuring email clients, and POP3 when the administrator turned it on (Pop3)
     */
    private void handleApiMailConfig(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
            return;
        }

        JSONObject response = new JSONObject();

        try {
            // Get mail server hostname from SQLite config
            String mailServer = Main.dbManager.getMailHostname();
            if (mailServer == null || mailServer.isEmpty()) {
                mailServer = "mail.example.com";
            }

            response.put("success", true);
            response.put("server", mailServer);

            // IMAP Configuration
            JSONObject imap = new JSONObject();
            imap.put("server", mailServer);
            imap.put("port_ssl", 993);
            imap.put("port_starttls", 143);
            imap.put("security", "SSL/TLS");
            imap.put("auth_method", I18n.tr("server.autoconf.normalPassword"));
            response.put("imap", imap);

            // POP3 only if the administrator has turned it on (Settings): when off, its ports are closed.
            if (org.daemoxcp.mail.system.Pop3.wanted()) {
                JSONObject pop3 = new JSONObject();
                pop3.put("server", mailServer);
                pop3.put("port_ssl", 995);
                pop3.put("port_starttls", 110);
                pop3.put("security", "SSL/TLS");
                pop3.put("auth_method", I18n.tr("server.autoconf.normalPassword"));
                response.put("pop3", pop3);
            }

            // SMTP Configuration
            JSONObject smtp = new JSONObject();
            smtp.put("server", mailServer);
            smtp.put("port_ssl", 465);
            smtp.put("port_starttls", 587);
            smtp.put("security", "STARTTLS");
            smtp.put("auth_method", I18n.tr("server.autoconf.normalPassword"));
            response.put("smtp", smtp);

            // General info
            response.put("username_format", I18n.tr("server.mailconfig.usernameFormat"));
            response.put("password_info", I18n.tr("server.mailconfig.passwordInfo"));

            // Client-specific instructions
            JSONObject clients = new JSONObject();

            // Outlook
            JSONObject outlook = new JSONObject();
            outlook.put("name", "Microsoft Outlook");
            outlook.put("imap_port", 993);
            outlook.put("smtp_port", 587);
            outlook.put("security", I18n.tr("server.mailconfig.securityTls"));
            clients.put("outlook", outlook);

            // Thunderbird
            JSONObject thunderbird = new JSONObject();
            thunderbird.put("name", "Mozilla Thunderbird");
            thunderbird.put("imap_port", 993);
            thunderbird.put("smtp_port", 587);
            thunderbird.put("security", I18n.tr("server.mailconfig.securityTls"));
            thunderbird.put("note", I18n.tr("server.mailconfig.thunderbirdNote"));
            clients.put("thunderbird", thunderbird);

            // Apple Mail
            JSONObject appleMail = new JSONObject();
            appleMail.put("name", "Apple Mail (macOS/iOS)");
            appleMail.put("imap_port", 993);
            appleMail.put("smtp_port", 587);
            appleMail.put("security", I18n.tr("server.mailconfig.securitySsl"));
            clients.put("apple", appleMail);

            // Android
            JSONObject android = new JSONObject();
            android.put("name", "Gmail App / Android");
            android.put("imap_port", 993);
            android.put("smtp_port", 587);
            android.put("security", "SSL/TLS");
            android.put("note", I18n.tr("server.mailconfig.androidNote"));
            clients.put("android", android);

            response.put("clients", clients);

        } catch (Exception e) {
            response.put("success", false);
            response.put("error", ErrorText.forPage("handleApiMailConfig", e));
        }

        sendJsonResponse(exchange, response);
    }

    /**
     * Why an "address -> itself" alias is refused when the address is not a mailbox.
     * On a mailbox it is allowed: it is precisely the way to keep a copy (review:
     * the note recommended it and the check refused it).
     */
    private static String aliasOnItself(String address) {
        return I18n.tr("server.alias.selfOnlyMailbox", Map.of("address", address));
    }

    /**
     * What happens now to the mail for {@code address}, when it is worth knowing; null otherwise.
     *
     * Postfix reads only the aliases with active=1, and applies them before the mailboxes: a mailbox with
     * active aliases but without an active "itself -> itself" no longer receives anything, and an address
     * that is not a mailbox exists only as long as it has an active alias (or the domain a catch-all).
     * Needed after every change: create, modify, deactivate, delete.
     */
    private static String afterAliases(String address, int domainId) throws java.sql.SQLException {
        return afterAliases(address, Main.mailDatabase.getMailboxByEmail(address) != null,
                Main.mailDatabase.getAliases(domainId));
    }

    /**
     * The decision of {@link #afterAliases(String, int)} without a database: exercised by
     * tests/.../AliasMessagesTest.
     */
    static String afterAliases(String address, boolean mailbox, List<MailDatabase.Alias> ofDomain) {
        int at = address.indexOf('@');
        String catchAll = at >= 0 ? address.substring(at) : null;
        List<String> elsewhere = new ArrayList<>();
        boolean copy = false, copyOff = false, collection = false;
        for (MailDatabase.Alias a : ofDomain) {
            if (a.active && a.source.equals(catchAll)) collection = true;
            if (!a.source.equals(address)) continue;
            if (a.destination.equals(address)) {
                if (a.active) copy = true; else copyOff = true;
            } else if (a.active) {
                elsewhere.add(a.destination);
            }
        }
        if (mailbox) {
            if (copy || elsewhere.isEmpty()) return null;
            return I18n.tr(copyOff ? "server.alias.mailboxCopyOff" : "server.alias.mailboxNoCopy",
                    Map.of("address", address, "targets", String.join(", ", elsewhere)));
        }
        if (copy || !elsewhere.isEmpty() || collection) return null;
        return I18n.tr("server.alias.nowRejected", Map.of("address", address));
    }

    /** The source of a catch-all: @ and a valid domain name, 254 characters in total. */
    static boolean validCatchAllSource(String source) {
        return source != null && source.length() <= 254 && source.startsWith("@") && SecurityUtils.isValidDomain(source.substring(1));
    }

    /**
     * Why a catch-all cannot be created or pointed there, or null if it can.
     * <ul>
     *   <li>Postfix must have the mailbox map after the aliases (MailboxAddressMap): without it, the
     *       catch-all would take the mailboxes' mail too;</li>
     *   <li>a destination in the same domain must be an active mailbox that receives: an address that
     *       does not exist, or a mailbox that is off or does not receive, would go back to the catch-all
     *       itself, and Postfix would stop the mail for the endless loop.</li>
     * </ul>
     */
    private static String catchAllRefused(String source, String destination) throws java.sql.SQLException {
        String notReady = org.daemoxcp.mail.system.MailboxAddressMap.notReady();
        if (notReady != null) return I18n.tr("server.alias.catchAllNotReady", Map.of("reason", notReady));
        MailDatabase.Mailbox m = Main.mailDatabase.getMailboxByEmail(destination);
        return catchAllLoop(source, destination, m != null && m.active && m.receiveEnabled);
    }

    /** The second rule of {@link #catchAllRefused}, without a database: exercised by CatchAllTest. */
    static String catchAllLoop(String source, String destination, boolean destinationIsMailbox) {
        String domain = source.substring(1);
        int at = destination.lastIndexOf('@');
        if (at >= 0 && destination.substring(at + 1).equals(domain) && !destinationIsMailbox)
            return I18n.tr("server.alias.catchAllLoop", Map.of("domain", domain, "destination", destination));
        return null;
    }

    /**
     * An address for an alias: the characters allowed by isValidEmail and the limits of RFC 5321
     * (254 in total, 64 before the @).
     */
    private static boolean validAliasAddress(String email) {
        return email != null && email.length() <= 254 && SecurityUtils.isValidEmail(email) && email.indexOf('@') <= 64;
    }

    /**
     * Modifies an alias: the destination ({@code destination}) and/or whether it is active
     * ({@code active}).
     *
     * Before, the page did not allow it: the only way was to delete and recreate it, and between the two
     * operations the source was left without an alias. Here it is a single UPDATE, and Postfix, which reads
     * the table at every message, follows the new rule from the next message. Deactivating
     * leaves the row where it is: Postfix considers only the aliases with active=1.
     */
    private JSONObject editAlias(JSONObject req, String ip) throws java.sql.SQLException {
        JSONObject r = new JSONObject();
        int id = req.optInt("id", 0);
        MailDatabase.Alias alias = id > 0 ? Main.mailDatabase.getAliasById(id) : null;
        if (alias == null) return r.put("success", false).put("error", I18n.tr("server.aliasNotFound"));

        boolean changeDestination = req.has("destination");
        Object state = req.opt("active");
        if (!changeDestination && state == null) return r.put("success", false).put("error", I18n.tr("server.alias.nothingToChange"));
        if (state != null && !(state instanceof Boolean)) return r.put("success", false).put("error", I18n.tr("server.alias.badState"));

        String destination = changeDestination ? req.optString("destination", "").toLowerCase().trim() : alias.destination;
        if (changeDestination && !validAliasAddress(destination))
            return r.put("success", false).put("error", I18n.tr("server.badEmail"));
        if (changeDestination && destination.equals(alias.source) && Main.mailDatabase.getMailboxByEmail(alias.source) == null)
            return r.put("success", false).put("error", aliasOnItself(alias.source));
        if (changeDestination && alias.source.startsWith("@")) {
            String refused = catchAllRefused(alias.source, destination);
            if (refused != null) return r.put("success", false).put("error", refused);
        }

        boolean newDestination = !destination.equals(alias.destination);
        if (newDestination) {
            try {
                if (!Main.mailDatabase.updateAliasDestination(id, destination))
                    return r.put("success", false).put("error", I18n.tr("server.aliasNotFound"));
            } catch (java.sql.SQLIntegrityConstraintViolationException dup) {
                return r.put("success", false).put("error", I18n.tr("server.alias.exists", Map.of("source", alias.source, "target", destination)));
            }
            logAudit("ALIAS_UPDATED", ip, alias.source + ": " + alias.destination + " -> " + destination);
        }

        boolean active = state == null ? alias.active : (Boolean) state;
        boolean newState = active != alias.active;
        if (newState) {
            if (!Main.mailDatabase.updateAliasStatus(id, active))
                return r.put("success", false).put("error", I18n.tr("server.aliasNotFound"));
            logAudit(active ? "ALIAS_ENABLED" : "ALIAS_DISABLED", ip, alias.source + " -> " + destination);
        }
        if (!newDestination && !newState) return r.put("success", true);

        regenerateMailConfigs();
        String note = afterAliases(alias.source, alias.domainId);
        if (note != null)
            r.put("note", I18n.tr(newState ? (active ? "server.alias.reactivated" : "server.alias.deactivated") : "server.alias.modified") + " " + note);
        return r.put("success", true);
    }

    private void handleApiAliases(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
            return;
        }

        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();

        try {
            switch (method) {
                case "GET" -> {
                    String transform = queryParameter(exchange.getRequestURI().getRawQuery(), "transform");
                    if (transform != null) {
                        // Preview of "alias -> mailbox": what happens, or why it cannot be done. It changes nothing.
                        String address = transform.trim().toLowerCase(java.util.Locale.ROOT);
                        if (address.length() > 254) {
                            response.put("success", false).put("error", I18n.tr("server.badAddress"));
                        } else {
                            response = org.daemoxcp.mail.system.AddressTransform.previewToMailbox(
                                    org.daemoxcp.mail.system.AddressTransform.state(Main.mailDatabase, address),
                                    java.time.ZoneId.systemDefault()).put("success", true);
                        }
                        break;
                    }
                    JSONArray aliases = new JSONArray();
                    for (MailDatabase.Alias a : Main.mailDatabase.getAllAliases()) {
                        JSONObject alias = new JSONObject();
                        alias.put("id", a.id);
                        alias.put("source", a.source);
                        alias.put("destination", a.destination);
                        alias.put("domain", a.domainName);
                        alias.put("active", a.active);
                        aliases.put(alias);
                    }
                    response.put("success", true);
                    response.put("aliases", aliases);
                }
                case "POST" -> {
                    String body = readRequestBodyWithLimit(exchange);
                    if (body == null) {
                        sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge"));
                        return;
                    }
                    JSONObject req = new JSONObject(body);

                    // Validate CSRF token
                    if (!validateCsrfForRequest(exchange, req)) {
                        sendCsrfError(exchange);
                        return;
                    }

                    if ("transform_to_mailbox".equals(req.optString("action", ""))) {
                        response = aliasToMailbox(req, getClientIp(exchange));
                        break;
                    }

                    String source = req.optString("source", "").toLowerCase().trim();
                    String destination = req.optString("destination", "").toLowerCase().trim();
                    // A catch-all is an alias with source @domain: the mail of every address of the domain that is
                    // neither an alias nor a mailbox (MailboxAddressMap).
                    boolean catchAll = source.startsWith("@");
                    String catchAllRefused = null;

                    if (!(catchAll ? validCatchAllSource(source) : validAliasAddress(source)) || !validAliasAddress(destination)) {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.badEmail"));
                    } else if (catchAll && (catchAllRefused = catchAllRefused(source, destination)) != null) {
                        response.put("success", false);
                        response.put("error", catchAllRefused);
                    } else if (source.equals(destination) && Main.mailDatabase.getMailboxByEmail(source) == null) {
                        // "mailbox -> itself" is the way to keep a copy when the mail is
                        // forwarded elsewhere; on an address that is not a mailbox it leads nowhere.
                        response.put("success", false);
                        response.put("error", aliasOnItself(source));
                    } else {
                        String domainName = source.substring(source.indexOf("@") + 1);
                        MailDatabase.Domain domain = Main.mailDatabase.getDomainByName(domainName);

                        if (domain == null) {
                            response.put("success", false);
                            response.put("error", I18n.tr("server.domain.unknown", Map.of("domain", domainName)));
                        } else {
                            int id;
                            try {
                                id = Main.mailDatabase.addAlias(domain.id, source, destination);
                            } catch (java.sql.SQLIntegrityConstraintViolationException dup) {
                                // UNIQUE constraint (source, destination): before, MySQL's text came back.
                                id = -1;
                            }
                            if (id > 0) {
                                response.put("success", true);
                                response.put("id", id);
                                logAudit("ALIAS_CREATED", getClientIp(exchange), source + " -> " + destination);
                                regenerateMailConfigs();
                                // If the source is also a mailbox, from now on its mail goes only to the destinations.
                                String note = afterAliases(source, domain.id);
                                if (note != null) response.put("note", I18n.tr("server.alias.created") + " " + note);
                                // A catch-all also collects spam to made-up addresses: say so right away.
                                if (catchAll) response.put("note", I18n.tr("server.alias.catchAllCreated",
                                        Map.of("domain", domainName, "destination", destination)));
                            } else {
                                response.put("success", false);
                                response.put("error", I18n.tr("server.alias.alreadyExists"));
                            }
                        }
                    }
                }
                case "PUT" -> {
                    // Edit: new target and/or active yes/no, same CSRF check.
                    String body = readRequestBodyWithLimit(exchange);
                    if (body == null) {
                        sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge"));
                        return;
                    }
                    JSONObject req = new JSONObject(body);
                    if (!validateCsrfForRequest(exchange, req)) {
                        sendCsrfError(exchange);
                        return;
                    }
                    response = editAlias(req, getClientIp(exchange));
                }
                case "DELETE" -> {
                    // Deleting also changes state: same CSRF check as creation.
                    String body = readRequestBodyWithLimit(exchange);
                    if (body == null) {
                        sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge"));
                        return;
                    }
                    if (!validateCsrfForRequest(exchange, body.isBlank() ? new JSONObject() : new JSONObject(body))) {
                        sendCsrfError(exchange);
                        return;
                    }
                    String query = exchange.getRequestURI().getQuery();
                    int id = extractIdFromQuery(query);
                    if (id > 0) {
                        // Read before: afterwards it is gone, and it is needed to say what remains for the source.
                        MailDatabase.Alias via = Main.mailDatabase.getAliasById(id);
                        boolean deleted = Main.mailDatabase.deleteAlias(id);
                        response.put("success", deleted);
                        if (deleted) {
                            logAudit("ALIAS_DELETED", getClientIp(exchange),
                                    via != null ? via.source + " -> " + via.destination + " (ID " + id + ")" : "Alias ID: " + id);
                            regenerateMailConfigs();
                            String note = via != null ? afterAliases(via.source, via.domainId) : null;
                            if (note != null) response.put("note", I18n.tr("server.alias.deleted") + " " + note);
                        }
                    } else {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.badId"));
                    }
                }
                default -> {
                    sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
                    return;
                }
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", ErrorText.forPage("handleApiAliases", e));
        }

        sendJsonResponse(exchange, response);
    }

    private void handleApiWebmail(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
            return;
        }

        String body = readRequestBodyWithLimit(exchange);
        if (body == null) {
            sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge"));
            return;
        }
        JSONObject req = new JSONObject(body);
        int mailboxId = req.optInt("mailbox_id", 0);

        JSONObject response = new JSONObject();

        try {
            if (mailboxId > 0) {
                String token = Main.mailDatabase.createAutoLoginToken(mailboxId);
                response.put("success", true);
                response.put("url", "/roundcube/?_autologin=" + token);
            } else {
                response.put("success", false);
                response.put("error", I18n.tr("server.mailbox.badId"));
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", ErrorText.forPage("handleApiWebmail", e));
        }

        sendJsonResponse(exchange, response);
    }

    private void handleApiService(HttpExchange exchange) throws IOException {
        try {
            if (!isAuthenticated(exchange)) {
                sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
                return;
            }

            if (!"POST".equals(exchange.getRequestMethod())) {
                sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
                return;
            }

            String body = readRequestBodyWithLimit(exchange);
            if (body == null) {
                sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge"));
                return;
            }
            JSONObject req = new JSONObject(body);
            // Starting, stopping and restarting a service changes the server's state: without a token
            // a page from another site opened by the administrator could stop the mail.
            if (!validateCsrfForRequest(exchange, req)) {
                sendCsrfError(exchange);
                return;
            }
            String service = req.optString("service", "");
            String action = req.optString("action", "");

            System.out.println("[SERVICE] Request: " + action + " " + service);

            // Validate service name and normalize
            // Accept both "clamav" and "clamav_clamd" for ClamAV
            if (service.equals("clamav")) {
                service = "clamav_clamd";
            }
            if (!Set.of("postfix", "dovecot", "rspamd", "clamav_clamd", "redis", "mysql-server", "roundcube").contains(service)) {
                System.out.println("[SERVICE] Invalid service: " + service);
                sendJsonError(exchange, 400, I18n.tr("server.service.invalid", Map.of("service", service)));
                return;
            }

            // Validate action
            if (!Set.of("start", "stop", "restart").contains(action)) {
                System.out.println("[SERVICE] Invalid action: " + action);
                sendJsonError(exchange, 400, I18n.tr("server.badActionNamed", Map.of("action", action)));
                return;
            }

            boolean success;
            // Roundcube uses nginx + php_fpm, handle specially
            if (service.equals("roundcube")) {
                boolean phpSuccess = executeServiceCommand("php_fpm", action);
                boolean nginxSuccess = executeServiceCommand("nginx", action);
                success = phpSuccess && nginxSuccess;
            } else {
                success = executeServiceCommand(service, action);
            }
            System.out.println("[SERVICE] Result: " + (success ? "OK" : "FAILED"));
            logAudit("SERVICE_" + action.toUpperCase(Locale.ROOT), getClientIp(exchange),
                    "service=" + service + (success ? "" : " (failed)"));
            // After a restart "needs restart" must disappear immediately, not in thirty seconds. Without
            // taking the reads lock: a read in progress must not hold back this response.
            ACTION_VERSIONS.incrementAndGet();

            JSONObject response = new JSONObject();
            response.put("success", success);
            if (!success) {
                response.put("error", I18n.tr("server.service.commandFailed", Map.of("command", "service " + service + " " + action)));
            }
            sendJsonResponse(exchange, response);
        } catch (Exception e) {
            System.err.println("[SERVICE] Exception: " + e.getMessage());
            e.printStackTrace();
            sendJsonError(exchange, 500, I18n.tr("server.internalErrorWith", Map.of("error", ErrorText.detail("handleApiService", e))));
        }
    }

    /**
     * Last reading of the versions (SoftwareVersions), when it was done and how many actions on the
     * services there had been when it started: an action arriving afterwards makes it stale.
     */
    private static final Object VERSIONS_LOCK = new Object();
    private static final java.util.concurrent.atomic.AtomicLong ACTION_VERSIONS = new java.util.concurrent.atomic.AtomicLong();
    private static JSONObject readVersions;
    private static long readVersionsMs, readActionVersions;

    /**
     * The software versions for the Home page (Version column of "Mail Services" and "Other software").
     * A reading launches about fifteen short commands: it is kept for thirty seconds, so that several
     * open or reloaded tabs do not relaunch them every time. "?fresh=1" (the "Reload" button)
     * reads again immediately, but not more than once every three seconds; after an action on a service
     * it reads again anyway. Readings go one at a time.
     */
    private void handleApiVersions(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
            return;
        }
        if (!"GET".equals(exchange.getRequestMethod())) {
            sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
            return;
        }
        String fresh = queryParameter(exchange.getRequestURI().getRawQuery(), "fresh");
        if (fresh != null && !fresh.equals("1")) {
            sendJsonError(exchange, 400, I18n.tr("server.badParameter"));
            return;
        }
        JSONObject r;
        try {
            synchronized (VERSIONS_LOCK) {
                long age = System.currentTimeMillis() - readVersionsMs;
                long actions = ACTION_VERSIONS.get();
                if (readVersions == null || actions != readActionVersions || age > 30_000 || (fresh != null && age > 3_000)) {
                    readVersions = org.daemoxcp.mail.system.SoftwareVersions.read(org.daemoxcp.mail.system.SoftwareVersions.real(
                            () -> Main.mysqlAvailable && Main.mailDatabase != null ? Main.mailDatabase.serverVersion() : null));
                    // The branch next to the versions: which versions arrive depends on it.
                    JSONObject branch = org.daemoxcp.mail.system.PkgBranch.state(org.daemoxcp.mail.system.PkgBranch.real());
                    if (branch.optBoolean("success")) readVersions.put("branch", branch.getString("branch"));
                    readVersionsMs = System.currentTimeMillis();
                    readActionVersions = actions;
                }
                r = readVersions;
            }
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Reading the software versions failed", e);
            sendJsonError(exchange, 500, I18n.tr("server.versions.readFailed"));
            return;
        }
        sendJsonResponse(exchange, r);
    }

    /**
     * Runs a package installation on the package turn (see
     * PackageQueue): one at a time. If another job is changing the packages, or the list
     * of one that never closed is still there, it does not start and the response says why.
     */
    /** A time zone for MySQL: offset (+02:00), SYSTEM or an IANA name (Europe/Rome). */
    private static final java.util.regex.Pattern TIME_ZONE_VALUE =
            java.util.regex.Pattern.compile("[+-](0\\d|1[0-4]):[0-5]\\d|SYSTEM|[A-Za-z][A-Za-z0-9_+-]{0,30}(/[A-Za-z0-9_+-]{1,30}){0,2}");

    private static JSONObject onPackageTurn(String description, java.util.function.Supplier<JSONObject> work) {
        String id = "install-" + System.nanoTime();
        String refusal = org.daemoxcp.mail.system.PackageQueue.take(id, description);
        if (refusal != null) return new JSONObject().put("success", false).put("error", refusal).put("message", refusal);
        try { return work.get(); }
        finally { org.daemoxcp.mail.system.PackageQueue.release(id); }
    }

    // ============== HELPER METHODS ==============

    /** A query parameter (raw), decoded; null if absent. */
    static String queryParameter(String rawQuery, String name) {
        if (rawQuery == null) return null;
        for (String pair : rawQuery.split("&")) {
            int same = pair.indexOf('=');
            if (same > 0 && pair.substring(0, same).equals(name)) {
                try {
                    return java.net.URLDecoder.decode(pair.substring(same + 1), StandardCharsets.UTF_8);
                } catch (IllegalArgumentException e) {
                    return null;
                }
            }
        }
        return null;
    }

    /**
     * Alias -> mailbox (AddressTransform): checks, earlier mail set aside if requested,
     * one database transaction, the leftover filters of an earlier mailbox rewritten empty.
     * If something fails, nothing changes.
     */
    private JSONObject aliasToMailbox(JSONObject req, String ip) throws Exception {
        JSONObject r = new JSONObject();
        String address = req.optString("source", "").trim().toLowerCase(java.util.Locale.ROOT);
        if (address.length() > 254) return r.put("success", false).put("error", I18n.tr("server.badAddress"));
        org.daemoxcp.mail.system.AddressTransform.AddressState s = org.daemoxcp.mail.system.AddressTransform.state(Main.mailDatabase, address);
        String no = org.daemoxcp.mail.system.AddressTransform.noMailboxReason(s);
        if (no != null) return r.put("success", false).put("error", no);
        if (!org.daemoxcp.mail.system.AddressTransform.fingerprint(s).equals(req.optString("fingerprint", "")))
            return r.put("success", false).put("changed", true).put("error",
                    I18n.tr("server.convert.changedToMailbox"));
        String password = req.optString("password", "");
        if (!SecurityUtils.isValidMailboxPassword(password))
            return r.put("success", false).put("error", I18n.tr("server.mailbox.badPassword", Map.of("rule", SecurityUtils.passwordRule())));
        String name = req.optString("name", "").trim();
        if (name.length() > 100 || !org.daemoxcp.mail.system.AddressTransform.printable(name))
            return r.put("success", false).put("error", I18n.tr("server.convert.badName"));
        int quota = req.opt("quota_mb") instanceof Number n ? n.intValue() : 1024;
        if (quota < 0 || quota > 1_048_576) return r.put("success", false).put("error", I18n.tr("server.convert.badQuota"));
        if (!(req.opt("keep_forwards") instanceof Boolean keep))
            return r.put("success", false).put("error", I18n.tr("server.convert.keepMissing"));
        String old = req.optString("old_mail", "");
        boolean archive = false;
        if (s.mail().present()) {
            if (!old.equals("recover") && !old.equals("archive"))
                return r.put("success", false).put("error",
                        I18n.tr("server.convert.oldMailChoice"));
            archive = old.equals("archive");
        }
        MailDatabase.Domain domain = Main.mailDatabase.getDomainByName(address.substring(address.lastIndexOf('@') + 1));
        if (domain == null) return r.put("success", false).put("error", I18n.tr("server.convert.domainNotInPanel"));

        List<java.nio.file.Path[]> moved = List.of();
        if (archive) {
            try {
                moved = org.daemoxcp.mail.system.AddressTransform.archive(address, System.currentTimeMillis());
            } catch (IOException e) {
                return r.put("success", false).put("error", I18n.tr("server.convert.archiveFailed", Map.of("error", ErrorText.detail("aliasToMailbox", e))));
            }
        }
        int id;
        try {
            id = Main.mailDatabase.transformAliasToMailbox(domain.id, address, password, name, quota, keep);
        } catch (java.sql.SQLException e) {
            org.daemoxcp.mail.system.AddressTransform.restore(moved);
            LOGGER.log(Level.WARNING, "Alias -> mailbox failed for " + address, e);
            return r.put("success", false).put("error", I18n.tr("server.convert.failed", Map.of("error", ErrorText.detail("aliasToMailbox", e))));
        }
        logAudit("ALIAS_TO_MAILBOX", ip, address + (keep ? " (forwards kept, copy in the mailbox)" : " (aliases removed)")
                + (archive ? ", old mail set aside" : s.mail().present() ? ", old mail found again" : ""));
        regenerateMailConfigs();
        // The compiled filters of an earlier mailbox must not apply to this one: they are rewritten, empty.
        // If they cannot be written the mailbox exists anyway, but those filters still apply and the page
        // must say so, not answer that it is done (finding 223).
        boolean oldFiltersKept = !archive && s.mail().filters() && !regenerateSieveScript(id);
        StringBuilder msg = new StringBuilder(I18n.tr("server.convert.nowMailbox", Map.of("address", address)));
        if (keep) msg.append(' ').append(I18n.tr("server.convert.forwardsKept"));
        if (!moved.isEmpty()) msg.append(' ').append(I18n.tr("server.convert.oldMailIn", Map.of("path", String.valueOf(moved.get(0)[1]))));
        else if (s.mail().present()) msg.append(' ').append(I18n.tr("server.convert.oldMailFound"));
        if (oldFiltersKept) {
            msg.append(' ').append(I18n.tr("server.convert.oldFiltersKept"));
            return r.put("success", false).put("saved", true).put("id", id).put("error", msg.toString());
        }
        return r.put("success", true).put("id", id).put("message", msg.toString());
    }

    /**
     * Mailbox -> alias (AddressTransform): the address typed for confirmation, destinations
     * checked (valid, existing if they are yours, no loops), one database transaction.
     * The mail that has already arrived stays on disk.
     */
    private JSONObject mailboxToAlias(JSONObject req, String ip) throws Exception {
        JSONObject r = new JSONObject();
        int id = req.optInt("id", 0);
        MailDatabase.Mailbox m = id > 0 ? Main.mailDatabase.getMailbox(id) : null;
        if (m == null) return r.put("success", false).put("error", I18n.tr("server.mailbox.notFound"));
        String address = m.email.toLowerCase(java.util.Locale.ROOT);
        if (!address.equals(req.optString("confirmation", "").trim().toLowerCase(java.util.Locale.ROOT)))
            return r.put("success", false).put("error", I18n.tr("server.convert.typeAddress", Map.of("address", address)));
        org.daemoxcp.mail.system.AddressTransform.AddressState s = org.daemoxcp.mail.system.AddressTransform.state(Main.mailDatabase, address);
        if (!org.daemoxcp.mail.system.AddressTransform.fingerprint(s).equals(req.optString("fingerprint", "")))
            return r.put("success", false).put("changed", true).put("error",
                    I18n.tr("server.convert.changedToAlias"));
        List<String> destinations;
        try {
            destinations = org.daemoxcp.mail.system.AddressTransform.destinations(s, req.optJSONArray("destinations"),
                    org.daemoxcp.mail.system.AddressTransform.network(Main.mailDatabase));
        } catch (IllegalArgumentException e) {
            return r.put("success", false).put("error", ErrorText.forPage("mailboxToAlias", e));
        }
        try {
            Main.mailDatabase.transformMailboxToAlias(m.id, m.domainId, address, destinations);
        } catch (java.sql.SQLException e) {
            LOGGER.log(Level.WARNING, "Mailbox -> alias failed for " + address, e);
            return r.put("success", false).put("error", I18n.tr("server.convert.failed", Map.of("error", ErrorText.detail("mailboxToAlias", e))));
        }
        logAudit("MAILBOX_TO_ALIAS", ip, address + " -> " + String.join(", ", destinations));
        regenerateMailConfigs();
        String msg = I18n.tr("server.convert.nowAlias", Map.of("address", address, "targets", String.join(", ", destinations)));
        if (s.mail().present())
            msg += " " + I18n.tr("server.convert.mailStaysOnDisk", Map.of("path", String.valueOf(org.daemoxcp.mail.system.AddressTransform.mailFolder(address))));
        return r.put("success", true).put("message", msg);
    }

    private int extractIdFromQuery(String query) {
        if (query == null) return -1;
        for (String param : query.split("&")) {
            if (param.startsWith("id=")) {
                try {
                    return Integer.parseInt(param.substring(3));
                } catch (NumberFormatException e) {
                    return -1;
                }
            }
        }
        return -1;
    }

    private void regenerateMailConfigs() {
        // In the web part no script: it asks the root part, which builds it from the rechecked MySQL names.
        if (mode == Mode.WEB_PART) {
            askRoot("mail-folders");
            return;
        }
        try {
            if (Main.mailDatabase != null && Main.mysqlAvailable) {
                String script = new ConfigRegeneratorScript(Main.mailDatabase).getScriptContent();
                // The script's warnings in the log: before, the output was thrown away, and nobody saw a file
                // with several names left as it was (SafeOwnership, finding 252) or a mailbox with the wrong
                // name.
                for (String line : executeScript(script, "config_regen").split("\n"))
                    if (line.startsWith("WARNING") || line.startsWith("[WARNING]") || line.startsWith("[ERROR]"))
                        LOGGER.warning("[ConfigRegenerator] " + line);
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Failed to regenerate mail configs", e);
        }
    }

    private boolean checkServiceRunning(String serviceName) {
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("service", serviceName, "status");
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();

            // Read output
            StringBuilder output = new StringBuilder();
            try (java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }

            // Timeout of 5 seconds to prevent hanging
            boolean finished = p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            if (!finished) {
                p.destroyForcibly();
                System.out.println("[STATUS] " + serviceName + ": TIMEOUT");
                return false;
            }

            int exitCode = p.exitValue();
            String out = output.toString().trim();
            System.out.println("[STATUS] " + serviceName + ": exit=" + exitCode + ", output=" + out);

            // Some services return non-zero but are running (check output for "running")
            if (exitCode == 0) {
                return true;
            }
            // Fallback: check if output contains "running" or "is running"
            return out.toLowerCase().contains("running");
        } catch (Exception e) {
            System.out.println("[STATUS] " + serviceName + ": exception=" + e.getMessage());
            return false;
        }
    }

    /**
     * Check if a package is installed on FreeBSD using pkg info
     */
    private boolean checkPackageInstalled(String packageName) {
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("pkg", "info", "-e", packageName);
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            boolean finished = p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            if (!finished) {
                p.destroyForcibly();
                return false;
            }
            return p.exitValue() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Check if any package matching a pattern is installed (for flavored packages like roundcube-php*)
     */
    private boolean checkPackageInstalledByPattern(String pattern) {
        try {
            // SECURITY: pattern comes from internal calls with constants, but defense-in-depth:
            // accepts only letters, digits, dash, underscore, dot, asterisk and percent
            // (characters typical of pkg package names). Blocks quotes, ;, |, &, $, backtick.
            if (pattern == null || !pattern.matches("^[a-zA-Z0-9._%*-]+$")) {
                return false;
            }
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("sh", "-c", "pkg info | grep -q '^" + pattern + "'");
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            boolean finished = p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            if (!finished) {
                p.destroyForcibly();
                return false;
            }
            return p.exitValue() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Sync installed components based on actual package presence on the system.
     * This ensures the database reflects reality when installation was done via terminal.
     *
     * IMPORTANT: For Postfix, we also check postfix-mysql because without it,
     * Postfix cannot use MySQL for virtual mailboxes and will fail with
     * "unsupported dictionary type: mysql"
     */
    private void syncInstalledComponents() {
        if (!Main.mysqlAvailable) return;

        // Standard packages (exact name match)
        // Format: {componentName, packageName}
        String[][] components = {
            {"rspamd", "rspamd"},
            {"clamav", "clamav"},
            {"redis", "redis"}
        };

        for (String[] comp : components) {
            String componentName = comp[0];
            String packageName = comp[1];

            boolean isInstalled = checkPackageInstalled(packageName);
            boolean markedInstalled = Main.mailDatabase.isComponentInstalled(componentName);

            if (isInstalled && !markedInstalled) {
                Main.mailDatabase.markComponentInstalled(componentName, "auto-detected");
                System.out.println("[SYNC] Marked " + componentName + " as installed (detected via pkg)");
            }
        }

        // Dovecot: check for dovecot-mysql (required for SQL auth) or base dovecot
        // On FreeBSD, dovecot-mysql REPLACES dovecot package
        // After the guided move to 2.4 (finding 213) the MySQL flavor is dovecot24-mysql.
        boolean dovecotInstalled = checkPackageInstalled("dovecot") || checkPackageInstalled("dovecot24");
        boolean dovecotMysqlInstalled = checkPackageInstalled("dovecot-mysql") || checkPackageInstalled("dovecot24-mysql");
        boolean dovecotMarked = Main.mailDatabase.isComponentInstalled("dovecot");

        // dovecot-mysql is preferred as it includes SQL authentication support
        if (dovecotMysqlInstalled && !dovecotMarked) {
            Main.mailDatabase.markComponentInstalled("dovecot", "auto-detected");
            System.out.println("[SYNC] Marked dovecot as installed (dovecot-mysql detected)");
        } else if (dovecotInstalled && !dovecotMysqlInstalled) {
            // Plain dovecot without MySQL support - SQL auth won't work!
            System.out.println("[SYNC] WARNING: dovecot installed but dovecot-mysql is MISSING!");
            System.out.println("[SYNC] SQL authentication will fail. Run: pkg install dovecot-mysql");
            if (dovecotMarked) {
                Main.mailDatabase.markComponentUninstalled("dovecot");
                System.out.println("[SYNC] Unmarked dovecot as installed (dovecot-mysql missing)");
            }
        }

        // Special handling for Postfix:
        // On FreeBSD, postfix-mysql REPLACES postfix package, so we need to check for either.
        // If only postfix is installed (without mysql), virtual mailbox lookups will fail.
        boolean postfixInstalled = checkPackageInstalled("postfix");
        boolean postfixMysqlInstalled = checkPackageInstalled("postfix-mysql");
        boolean postfixMarked = Main.mailDatabase.isComponentInstalled("postfix");

        // postfix-mysql includes full postfix functionality + MySQL support
        if (postfixMysqlInstalled && !postfixMarked) {
            Main.mailDatabase.markComponentInstalled("postfix", "auto-detected");
            System.out.println("[SYNC] Marked postfix as installed (postfix-mysql detected)");
        } else if (postfixInstalled && !postfixMysqlInstalled) {
            // Plain postfix without MySQL support - this won't work for virtual mailboxes!
            System.out.println("[SYNC] WARNING: postfix installed but postfix-mysql is MISSING!");
            System.out.println("[SYNC] Virtual mailbox lookups will fail. Run: pkg install postfix-mysql");
            // Do NOT mark as installed since it's incomplete for our use case
            if (postfixMarked) {
                Main.mailDatabase.markComponentUninstalled("postfix");
                System.out.println("[SYNC] Unmarked postfix as installed (postfix-mysql missing)");
            }
        }

        // Roundcube is a flavored package (roundcube-php81, roundcube-php82, roundcube-php83, etc.)
        boolean roundcubeInstalled = checkPackageInstalledByPattern("roundcube-php");
        boolean roundcubeMarked = Main.mailDatabase.isComponentInstalled("roundcube");
        if (roundcubeInstalled && !roundcubeMarked) {
            Main.mailDatabase.markComponentInstalled("roundcube", "auto-detected");
            System.out.println("[SYNC] Marked roundcube as installed (detected via pkg pattern)");
        }
    }

    private boolean executeServiceCommand(String service, String action) {
        try {
            System.out.println("[EXEC] Running: service " + service + " " + action);
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("service", service, action);
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();

            // Read output
            StringBuilder output = new StringBuilder();
            try (java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }

            // Timeout of 30 seconds for service commands
            boolean finished = p.waitFor(30, java.util.concurrent.TimeUnit.SECONDS);
            if (!finished) {
                System.out.println("[EXEC] Timeout! Killing process");
                p.destroyForcibly();
                return false;
            }

            int exitCode = p.exitValue();
            System.out.println("[EXEC] Exit code: " + exitCode);
            if (output.length() > 0) {
                System.out.println("[EXEC] Output: " + output.toString().trim());
            }
            return exitCode == 0;
        } catch (Exception e) {
            System.err.println("[EXEC] Exception: " + e.getMessage());
            return false;
        }
    }

    private String executeScript(String scriptContent, String scriptName) throws Exception {
        return executeScript(scriptContent, scriptName, Map.of());
    }

    private String executeScript(String scriptContent, String scriptName, Map<String, String> env) throws Exception {
        String jarDir = getJarDirectory();
        Path scriptPath = Paths.get(jarDir, "install_scripts", "install_" + scriptName + ".sh");
        Files.createDirectories(scriptPath.getParent());
        Files.writeString(scriptPath, scriptContent);
        scriptPath.toFile().setExecutable(true);

        // TODO: migrate to Shell.run when touched
        ProcessBuilder pb = new ProcessBuilder("/bin/sh", scriptPath.toString());
        org.daemoxcp.mail.util.Shell.applyPath(pb);
        pb.environment().putAll(env);
        pb.redirectErrorStream(true);
        Process process = pb.start();

        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
        }

        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new RuntimeException("Script failed with exit code " + exitCode + "\n" + output);
        }

        return output.toString();
    }

    private String readHtmlFile(String filename) {
        try {
            String jarDir = getJarDirectory();
            Path filePath = Paths.get(jarDir, "admin", filename);
            if (Files.exists(filePath)) {
                return Files.readString(filePath);
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Could not read HTML file: " + filename, e);
        }
        return "<html><body><h1>" + I18n.escapeHtml(I18n.tr("server.pageNotFound")) + "</h1></body></html>";
    }

    /**
     * Serves the static files from the jar's resources: Font Awesome under /fa, Bootstrap and
     * Chart.js under /vendor.
     *
     * Before, they came from a CDN, stuck at 6.0.0-beta3, where two of the icons used did not
     * exist at all. Now they travel inside the jar (356 KB in all): the panel no longer
     * depends on an external site, and the version is the chosen one, not the one that
     * the CDN address carries with it.
     *
     * The requested path is cleaned before being used: it is the only place in the
     * panel where a string coming from the network becomes the name of a resource to
     * read, so "../" and strange names must not get through.
     */
    /**
     * The file that Thunderbird looks for by itself. No authentication: it is the client that asks
     * for it before knowing anything about the user.
     *
     * The domain is taken from the emailaddress parameter, and failing that from the Host header
     * that nginx forwards. In both cases it is compared with the list of managed
     * domains: if it is not one of them, 404. So the value that comes from outside never ends up
     * inside the file: what gets written is always the name taken from the database.
     */
    private void handlePublicAutoconfig(HttpExchange exchange) throws IOException {
        try {
            String path = exchange.getRequestURI().getPath();
            if (!"/autoconfig/mail/config-v1.1.xml".equals(path)) {
                exchange.sendResponseHeaders(404, -1);
                exchange.close();
                return;
            }

            String address = parameter(exchange.getRequestURI().getRawQuery(), "emailaddress");
            String candidate = org.daemoxcp.mail.system.Autoconfig.domainFromAddress(address);
            if (candidate == null) {
                java.util.List<String> host = exchange.getRequestHeaders().get("Host");
                if (host != null && !host.isEmpty()) candidate = host.get(0);
            }

            String domain = org.daemoxcp.mail.system.Autoconfig.managedDomain(candidate);
            String mailHost2 = org.daemoxcp.mail.system.Autoconfig.mailHost();
            if (domain == null || mailHost2 == null || mailHost2.isBlank()) {
                exchange.sendResponseHeaders(404, -1);
                exchange.close();
                return;
            }

            byte[] data = org.daemoxcp.mail.system.Autoconfig.xml(domain, mailHost2)
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "text/xml; charset=UTF-8");
            exchange.getResponseHeaders().set("Cache-Control", "public, max-age=3600");
            exchange.sendResponseHeaders(200, data.length);
            try (java.io.OutputStream os = exchange.getResponseBody()) { os.write(data); }
        } catch (Exception e) {
            try { exchange.sendResponseHeaders(500, -1); } catch (Exception ignore) {}
        } finally {
            exchange.close();
        }
    }

    /** A parameter from the query, without dragging in a library to do it. */
    private static String parameter(String query, String name) {
        if (query == null || query.isEmpty()) return null;
        for (String pair : query.split("&")) {
            int i = pair.indexOf('=');
            if (i <= 0) continue;
            if (!java.net.URLDecoder.decode(pair.substring(0, i),
                    java.nio.charset.StandardCharsets.UTF_8).equals(name)) continue;
            return java.net.URLDecoder.decode(pair.substring(i + 1),
                    java.nio.charset.StandardCharsets.UTF_8);
        }
        return null;
    }

    /**
     * The MTA-STS policy, as a sending server asks for it. The domain is taken
     * from the Host header that nginx forwards, and it is compared with the list of
     * managed domains: if it is not one of them, 404.
     */
    private void handlePublicMtaSts(HttpExchange exchange) throws IOException {
        try {
            if (!"/mta-sts/policy".equals(exchange.getRequestURI().getPath())) {
                exchange.sendResponseHeaders(404, -1);
                return;
            }
            java.util.List<String> host = exchange.getRequestHeaders().get("Host");
            String domain = org.daemoxcp.mail.system.MtaSts.managedDomain(
                    host == null || host.isEmpty() ? null : host.get(0));
            String mail = org.daemoxcp.mail.system.MtaSts.mailHost();
            if (domain == null || mail == null || mail.isBlank()) {
                exchange.sendResponseHeaders(404, -1);
                return;
            }
            String mode = org.daemoxcp.mail.system.MtaSts.currentMode();
            byte[] data = org.daemoxcp.mail.system.MtaSts
                    .policy(mail, mode, org.daemoxcp.mail.system.MtaSts.recommendedMaxAge(mode))
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=UTF-8");
            exchange.getResponseHeaders().set("Cache-Control", "public, max-age=3600");
            exchange.sendResponseHeaders(200, data.length);
            try (java.io.OutputStream os = exchange.getResponseBody()) { os.write(data); }
        } catch (Exception e) {
            try { exchange.sendResponseHeaders(500, -1); } catch (Exception ignore) {}
        } finally {
            exchange.close();
        }
    }

    private void handleApiAutoconfig(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) { sendJsonError(exchange, 401, I18n.tr("server.unauthorized")); return; }
        if (!"POST".equals(exchange.getRequestMethod())) { sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed")); return; }
        String body = readRequestBodyWithLimit(exchange);
        if (body == null) { sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge")); return; }
        String ip = getClientIp(exchange);
        JSONObject req;
        try { req = new JSONObject(body); }
        catch (Exception e) { sendJsonError(exchange, 400, I18n.tr("server.badJson")); return; }

        JSONObject response;
        switch (req.optString("action", "")) {
            case "status" -> response = org.daemoxcp.mail.system.Autoconfig.state();
            case "preview" -> response = org.daemoxcp.mail.system.Autoconfig.preview();
            case "install" -> {
                if (!"INSTALL".equals(req.optString("confirm", ""))) {
                    response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                    break;
                }
                response = org.daemoxcp.mail.system.Autoconfig.install();
                logAudit("AUTOCONFIG_INSTALL", ip, response.optBoolean("success")
                        ? "nginx configured" : "NOT configured: " + response.optString("error", "?"));
            }
            default -> response = new JSONObject().put("success", false).put("error", I18n.tr("server.unknownAction"));
        }
        sendJsonResponse(exchange, response);
    }

    /**
     * Downloads the configuration profile for Apple Mail. It is a GET because it must be a
     * link that the browser downloads, but it requires the session: the profile contains the name
     * of a mailbox, and has no reason to be public. It does not contain the password.
     */
    private void handleDownloadAppleProfile(HttpExchange exchange) throws IOException {
        try {
            if (!isAuthenticated(exchange)) {
                exchange.sendResponseHeaders(401, -1);
                return;
            }
            String email = parameter(exchange.getRequestURI().getRawQuery(), "email");
            var mailbox = org.daemoxcp.mail.system.AppleProfile.mailbox(email);
            String host = org.daemoxcp.mail.system.AppleProfile.mailHost();
            if (mailbox == null || host == null || host.isBlank()) {
                exchange.sendResponseHeaders(404, -1);
                return;
            }

            String profile = org.daemoxcp.mail.system.AppleProfile
                    .mobileconfig(mailbox.email(), mailbox.name(), host, host);
            if (!org.daemoxcp.mail.system.AppleProfile.wellFormed(profile)) {
                // A broken file is not delivered: Mail would reject it without explaining why.
                exchange.sendResponseHeaders(500, -1);
                return;
            }
            byte[] data = profile.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            // Signed with the mail certificate when a phone trusts it (AppleProfile.signer): the iPhone shows
            // it as "Verified". If signing fails the unsigned one is delivered, and the log says so.
            boolean signed = false;
            if (org.daemoxcp.mail.system.AppleProfile.signer(host).ok()) {
                byte[] der = org.daemoxcp.mail.system.AppleProfile.sign(data);
                if (der != null) { data = der; signed = true; }
                else LOGGER.warning("[AppleProfile] signing the profile for " + mailbox.email()
                        + " failed: it goes out unsigned");
            }
            String name = org.daemoxcp.mail.system.AppleProfile.fileName(mailbox.email());
            exchange.getResponseHeaders().set("Content-Type", "application/x-apple-aspen-config");
            exchange.getResponseHeaders().set("Content-Disposition", "attachment; filename=\"" + name + "\"");
            exchange.sendResponseHeaders(200, data.length);
            try (java.io.OutputStream os = exchange.getResponseBody()) { os.write(data); }
            logAudit("APPLE_PROFILE", getClientIp(exchange), "downloaded for " + mailbox.email() + (signed ? ", signed" : ", unsigned"));
        } catch (Exception e) {
            try { exchange.sendResponseHeaders(500, -1); } catch (Exception ignore) {}
        } finally {
            exchange.close();
        }
    }

    private void handleApiAppleProfile(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) { sendJsonError(exchange, 401, I18n.tr("server.unauthorized")); return; }
        if (!"POST".equals(exchange.getRequestMethod())) { sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed")); return; }
        String body = readRequestBodyWithLimit(exchange);
        if (body == null) { sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge")); return; }
        JSONObject req;
        try { req = new JSONObject(body); }
        catch (Exception e) { sendJsonError(exchange, 400, I18n.tr("server.badJson")); return; }

        JSONObject response = switch (req.optString("action", "")) {
            case "status" -> org.daemoxcp.mail.system.AppleProfile.state();
            case "preview" -> org.daemoxcp.mail.system.AppleProfile.preview(req.optString("email", ""));
            default -> new JSONObject().put("success", false).put("error", I18n.tr("server.unknownAction"));
        };
        sendJsonResponse(exchange, response);
    }

    private void handleStatic(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        String resource = null;
        if (path.startsWith("/fa/")) {
            String rel = path.substring(4);                        // css/... or webfonts/...
            if (rel.matches("(css|webfonts)/[A-Za-z0-9._-]{1,64}")) resource = "/fa/" + rel;
        } else if (path.startsWith("/vendor/")) {
            String rel = path.substring(8);                        // one level only, no folders
            if (rel.matches("[A-Za-z0-9._-]{1,64}")) resource = "/vendor/" + rel;
        }
        if (resource == null) {
            exchange.sendResponseHeaders(404, -1);
            exchange.close();
            return;
        }
        String type = resource.endsWith(".css") ? "text/css; charset=UTF-8"
                    : resource.endsWith(".js") ? "application/javascript; charset=UTF-8"
                    : resource.endsWith(".woff2") ? "font/woff2"
                    : resource.endsWith(".woff") ? "font/woff"
                    : resource.endsWith(".ttf") ? "font/ttf"
                    // The pages' icon (vendor/favicon.svg): a file of our own, without scripts.
                    : resource.endsWith(".svg") ? "image/svg+xml"
                    : "application/octet-stream";
        byte[] data;
        try (java.io.InputStream in = getClass().getResourceAsStream(resource)) {
            if (in == null) {
                exchange.sendResponseHeaders(404, -1);
                exchange.close();
                return;
            }
            data = in.readAllBytes();
        }
        exchange.getResponseHeaders().add("Content-Type", type);
        exchange.getResponseHeaders().add("X-Content-Type-Options", "nosniff");
        // The content changes only when the jar changes: it can be cached for a long time.
        exchange.getResponseHeaders().add("Cache-Control", "public, max-age=604800");
        exchange.sendResponseHeaders(200, data.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(data);
        }
    }

    private void sendHtml(HttpExchange exchange, String html) throws IOException {
        byte[] bytes = html.getBytes(StandardCharsets.UTF_8);
        addSecurityHeaders(exchange);
        exchange.getResponseHeaders().add("Content-Type", "text/html; charset=UTF-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private void sendJsonResponse(HttpExchange exchange, JSONObject json) throws IOException {
        byte[] bytes = json.toString().getBytes(StandardCharsets.UTF_8);
        addSecurityHeaders(exchange);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private void sendJsonError(HttpExchange exchange, int code, String message) throws IOException {
        JSONObject error = new JSONObject().put("error", message);
        byte[] bytes = error.toString().getBytes(StandardCharsets.UTF_8);
        addSecurityHeaders(exchange);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    /**
     * The response when the session could not be read because the database does not answer
     * (DATABASE_HEADER): to the pages' requests a 503 that tells them to repeat; to a page opened at that
     * moment a page that says so and reloads by itself, instead of the login.
     */
    private void databaseUnavailable(HttpExchange exchange, boolean page) throws IOException {
        exchange.getResponseHeaders().set(DATABASE_HEADER, "unavailable");
        exchange.getResponseHeaders().set("Retry-After", "3");
        if (!page) {
            sendJsonError(exchange, 503, I18n.tr("server.databaseWait"));
            return;
        }
        String title = escapeHtmlSimple(I18n.tr("server.databaseWaitTitle"));
        byte[] html = ("<!doctype html>\n<html lang=\"" + escapeHtmlSimple(I18n.current()) + "\"><head><meta charset=\"utf-8\">"
                + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
                + "<meta http-equiv=\"refresh\" content=\"5\"><title>" + title + "</title></head>"
                + "<body><main><h1>" + title + "</h1><p role=\"status\">" + escapeHtmlSimple(I18n.tr("server.databaseWaitText"))
                + "</p></main></body></html>\n").getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        exchange.sendResponseHeaders(503, html.length);
        try (OutputStream os = exchange.getResponseBody()) { os.write(html); }
    }

    private void redirect(HttpExchange exchange, String location) throws IOException {
        exchange.getResponseHeaders().add("Location", location);
        exchange.sendResponseHeaders(302, -1);
    }

    void addSecurityHeaders(HttpExchange exchange) {
        Headers headers = exchange.getResponseHeaders();
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("X-Frame-Options", "DENY");
        headers.set("X-XSS-Protection", "1; mode=block");
        headers.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
        headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
        // HSTS: one year of HTTPS-only for this name, subdomains included.
        //
        // The "preload" token was there and was removed on 2026-09-02. It did nothing: the preload
        // list is compiled into the browser, and serving the token is only a REQUIREMENT for
        // applying -- the application must be submitted at hstspreload.org. Verified that day:
        // neither domain-b.test nor mail.domain-b.test is on the list ("status": "unknown").
        // So it was a public declaration never submitted: the same shape as the MTA-STS TXT
        // record published without a policy that answers.
        //
        // And removing it protects against the worst case: that some day someone applies for the
        // domain seeing the token already there. From that moment the rule lives inside the
        // browsers' binary, and removing it takes months -- while here it is enough for the
        // panel's certificate to break once to be locked out exactly when you need to get in to
        // fix it (HSTS removes the "proceed anyway" on certificate warnings).
        //
        // What remains, and why: max-age is renewed at every visit and includeSubDomains applies
        // to the subdomains of THIS name. They are kept because the certificate renews itself and
        // the panel watches its expiry. Note: the rule is per NAME, not per port
        // (RFC 6797 section 8.1), so served from 2096 it applies to that name everywhere.
        headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        // Content Security Policy without 'unsafe-inline' (SecurityHeaders, finding 178).
        headers.set("Content-Security-Policy", SecurityHeaders.CONTENT_SECURITY_POLICY);
        // Permissions Policy - Disable unnecessary features
        headers.set("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
    }

    /** Converts an ISO LocalDateTime to a readable format, in the request's language; "Never" if empty */
    private static String humanizeDateTime(String iso) {
        if (iso == null || iso.isEmpty()) return I18n.tr("server.never");
        try {
            java.time.LocalDateTime dt = java.time.LocalDateTime.parse(iso);
            java.time.Duration diff = java.time.Duration.between(dt, java.time.LocalDateTime.now());
            String formatted = dt.format(java.time.format.DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm"));
            long minutes = diff.toMinutes();
            if (minutes < 1)        return formatted + " " + I18n.tr("server.ago.now");
            else if (minutes < 60)  return formatted + " " + I18n.tr("server.ago.min", java.util.Map.of("n", String.valueOf(minutes)));
            else if (minutes < 1440) return formatted + " " + I18n.tr("server.ago.hours", java.util.Map.of("n", String.valueOf((minutes/60))));
            else                    return formatted + " " + I18n.tr("server.ago.days", java.util.Map.of("n", String.valueOf((minutes/1440))));
        } catch (Exception e) {
            return iso;
        }
    }

    private static String escapeHtmlSimple(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }

    private String getJarDirectory() {
        try {
            String jarPath = SSLMailServer.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath();
            return new File(jarPath).getParent();
        } catch (Exception e) {
            return System.getProperty("user.dir");
        }
    }

    // ============== DKIM API ==============

    /**
     * Serializes a {@link java.sql.Timestamp} as ISO 8601 UTC ("2026-05-15T21:00:00Z").
     * Built from the epoch milliseconds, completely bypassing the JVM's timezone.
     */
    private static String tsIso(java.sql.Timestamp ts) {
        return ts == null ? null : java.time.Instant.ofEpochMilli(ts.getTime()).toString();
    }

    /**
     * Helper that writes a timestamp to JSON as TWO fields:
     *   key       -> ISO 8601 UTC ("2026-05-15T21:00:00Z")
     *   key + "_ms" -> epoch milliseconds (long, unambiguous)
     * The browser prefers _ms when present, otherwise the ISO fallback.
     */
    private static void putTs(org.json.JSONObject obj, String key, java.sql.Timestamp ts) {
        if (ts == null) return;
        obj.put(key, tsIso(ts));
        obj.put(key + "_ms", ts.getTime());
    }

    private void handleApiDkim(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
            return;
        }

        if (dkimManager == null) {
            sendJsonError(exchange, 503, I18n.tr("server.partNotReady", Map.of("part", "DKIM")));
            return;
        }

        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();

        try {
            if ("GET".equals(method)) {
                // Get DKIM info for a domain
                String query = exchange.getRequestURI().getQuery();
                int domainId = extractIdFromQuery(query);

                if (domainId > 0) {
                    DkimManager.DkimInfo info = dkimManager.getDkimInfo(domainId);
                    if (info != null) {
                        response.put("success", true);
                        response.put("domain", info.domain);
                        response.put("selector", info.selector);
                        response.put("configured", info.configured);
                        if (info.configured) {
                            response.put("dns_record_name", info.dnsRecordName);
                            response.put("dns_record_value", info.dnsRecordValue);
                            response.put("key_file_exists", info.keyFileExists);
                        }
                    } else {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.domainNotFound"));
                    }
                } else {
                    response.put("success", false);
                    response.put("error", I18n.tr("server.domain.idRequired"));
                }

            } else if ("POST".equals(method)) {
                String body = readRequestBodyWithLimit(exchange);
        if (body == null) {
            sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge"));
            return;
        }
                JSONObject req = new JSONObject(body);
                String action = req.optString("action", "generate");

                if ("generate".equals(action)) {
                    int domainId = req.optInt("domain_id", 0);
                    String selector = req.optString("selector", "mail");

                    MailDatabase.Domain domain = Main.mailDatabase.getDomain(domainId);
                    if (domain == null) {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.domainNotFound"));
                    } else if (domain.hasDkim) {
                        // SAFETY: 'generate' is only for the INITIAL SETUP. If DKIM is already configured,
                        // overwriting the key without a rotation would cause DKIM-fail on mail in transit.
                        // The user MUST use 'rotate_start' to change the key on a domain that is already active.
                        response.put("success", false);
                        response.put("error",
                            I18n.tr("server.dkim.alreadyConfigured", Map.of("selector", String.valueOf(domain.dkimSelector))));
                    } else {
                        DkimManager.DkimResult result = dkimManager.generateDkimKeys(domainId, domain.domain, selector);
                        response.put("success", result.success);
                        if (result.success) {
                            response.put("selector", result.selector);
                            response.put("dns_record", result.dnsRecord);
                            response.put("message", I18n.tr("server.dkim.generated"));
                        } else {
                            response.put("error", result.error);
                        }
                    }

                } else if ("verify".equals(action)) {
                    String domain = req.optString("domain", "");
                    String selector = req.optString("selector", "mail");

                    DkimManager.DkimVerifyResult result = dkimManager.verifyDkimDns(domain, selector);
                    response.put("success", true);
                    response.put("valid", result.valid);
                    response.put("message", result.message);

                } else if ("delete".equals(action)) {
                    int domainId = req.optInt("domain_id", 0);
                    boolean deleted = dkimManager.deleteDkim(domainId);
                    response.put("success", deleted);

                } else if ("rotate_start".equals(action)) {
                    // PHASE 1: generate a new pending key, return the DNS record to publish.
                    // If "auto"=true and Cloudflare is configured, the record is created through the API.
                    int domainId = req.optInt("domain_id", 0);
                    boolean auto = req.optBoolean("auto", false);
                    DkimManager.RotationStartResult r = dkimManager.startRotation(domainId, auto);
                    response.put("success", r.success);
                    if (r.success) {
                        response.put("pending_selector", r.pendingSelector);
                        response.put("dns_record_name", r.dnsRecordName);
                        response.put("dns_record_value", r.dnsRecordValue);
                        // r.error is used here as a non-blocking "warning" (e.g. CF not found)
                        if (r.error != null && !r.error.isEmpty()) {
                            response.put("warning", r.error);
                            response.put("message", I18n.tr("server.dkim.generatedWarning", Map.of("warning", String.valueOf(r.error))));
                        } else if (auto && cloudflareManager != null && cloudflareManager.hasAccountForDomain(domainId)) {
                            response.put("message", I18n.tr("server.dkim.generatedPublished"));
                        } else {
                            response.put("message", I18n.tr("server.dkim.generatedAddRecord"));
                        }
                    } else {
                        response.put("error", r.error);
                    }

                } else if ("rotate_check".equals(action)) {
                    // PHASE 2: check the DNS propagation of the pending key
                    int domainId = req.optInt("domain_id", 0);
                    DkimManager.PropagationCheckResult r = dkimManager.checkPropagation(domainId);
                    response.put("success", r.success);
                    response.put("propagated", r.propagated);
                    response.put("message", r.message);
                    if (r.rawDigOutput != null && !r.rawDigOutput.isEmpty()) {
                        response.put("raw_output", r.rawDigOutput);
                    }

                } else if ("rotate_activate".equals(action)) {
                    // PHASE 3: pending -> active, active -> previous, reload Rspamd
                    int domainId = req.optInt("domain_id", 0);
                    boolean force = req.optBoolean("force", false);
                    DkimManager.RotationActionResult r = dkimManager.activatePending(domainId, force);
                    response.put("success", r.success);
                    response.put("message", r.message);

                } else if ("rotate_complete".equals(action)) {
                    // PHASE 4: removes the previous key (end of the grace period)
                    int domainId = req.optInt("domain_id", 0);
                    DkimManager.RotationActionResult r = dkimManager.completeRotation(domainId);
                    response.put("success", r.success);
                    response.put("message", r.message);

                } else if ("rotate_cancel".equals(action)) {
                    // Cancel a rotation before activation
                    int domainId = req.optInt("domain_id", 0);
                    DkimManager.RotationActionResult r = dkimManager.cancelRotation(domainId);
                    response.put("success", r.success);
                    response.put("message", r.message);

                } else if ("rotate_status".equals(action)) {
                    // Current state of the rotation (for the UI)
                    int domainId = req.optInt("domain_id", 0);
                    DkimManager.RotationInfo info = dkimManager.getRotationInfo(domainId);
                    if (info == null) {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.domainNotFound"));
                    } else {
                        response.put("success", true);
                        response.put("domain", info.domain);
                        response.put("has_dkim", info.hasDkim);
                        // Current schedule (for the "next rotation" banner)
                        DkimManager.ScheduleResult sched = dkimManager.getRotationSchedule(domainId);
                        if (sched != null && sched.success) {
                            response.put("schedule_interval_days", sched.intervalDays);
                            putTs(response, "schedule_last_rotation_at", sched.lastRotationAt);
                            putTs(response, "schedule_next_rotation_at", sched.nextRotationAt);
                        }
                        // Cloudflare account assigned to this domain (if any)
                        if (cloudflareManager != null) {
                            MailDatabase.CloudflareAccount acct = cloudflareManager.getAccountForDomain(domainId);
                            response.put("cloudflare_configured", acct != null);
                            if (acct != null) {
                                response.put("cloudflare_account_label", acct.label);
                                if (acct.email != null && !acct.email.isEmpty())
                                    response.put("cloudflare_account_email", acct.email);
                            }
                        } else {
                            response.put("cloudflare_configured", false);
                        }
                        response.put("current_selector", info.currentSelector);
                        response.put("rotation_state", info.rotationState == null ? "" : info.rotationState);
                        // The two durations are ALWAYS sent, not only in the grace-period branch:
                        // the card already shows them in the "propagated" state, to say when
                        // the automatic activation kicks in. Without them, it would fall back on the 24
                        // and 7 written in the page: numbers that are right today and silently wrong
                        // the day someone changes the constants.
                        response.put("auto_activate_after_hours",
                            org.daemoxcp.mail.security.DkimRotationScheduler.AUTO_ACTIVATE_AFTER_HOURS);
                        response.put("grace_period_days",
                            org.daemoxcp.mail.security.DkimRotationScheduler.GRACE_PERIOD_DAYS);
                        // The scheduler lives inside this web server: if the panel does not
                        // restart on its own after a reboot, steps 3 and 4 stay stuck. The
                        // card must be able to SAY so, not leave it to be discovered.
                        response.put("auto_start",
                            UpdateManager.autoStart().optBoolean("active", false));
                        putTs(response, "started_at", info.startedAt);
                        if (info.activatedAt != null) {
                            putTs(response, "activated_at", info.activatedAt);
                            response.put("grace_period_days", org.daemoxcp.mail.security.DkimRotationScheduler.GRACE_PERIOD_DAYS);
                            response.put("grace_period_over",
                                org.daemoxcp.mail.security.DkimRotationScheduler.isGracePeriodOver(info.activatedAt));
                        }
                        if (info.pendingSelector != null) {
                            response.put("pending_selector", info.pendingSelector);
                            response.put("pending_dns_name", info.pendingDnsName);
                            response.put("pending_dns_value", info.pendingDnsValue);
                        }
                        if (info.previousSelector != null) {
                            response.put("previous_selector", info.previousSelector);
                            response.put("previous_dns_name", info.previousDnsName);
                            // The card stated "the old key must stay in the DNS for
                            // 7 days" without checking whether it was there. On domain-b.test it
                            // was already missing before the rotation -- the panel had checked it
                            // three times and written it in the log -- and the card stated it anyway.
                            // An instruction to follow about something that does not exist sends
                            // you looking for a fault where there is none, and hides the real one:
                            // that the key was never published.
                            try {
                                DkimManager.DkimVerifyResult pv =
                                    dkimManager.verifyDkimDns(info.domain, info.previousSelector);
                                response.put("previous_in_dns", pv != null && pv.valid);
                            } catch (Exception e) {
                                // Not knowing is neither yes nor no: the field is omitted and the
                                // card goes back to saying the cautious thing.
                            }
                        }
                    }

                } else if ("orphans_scan".equals(action)) {
                    // Scans Cloudflare to find ALL the _domainkey records of the domain,
                    // telling current/pending/previous (active) apart from orphan (to be cleaned up).
                    int domainId = req.optInt("domain_id", 0);
                    DkimManager.OrphanScanResult r = dkimManager.scanDkimRecords(domainId);
                    response.put("success", r.success);
                    if (!r.success) {
                        response.put("error", r.message);
                    } else {
                        response.put("domain", r.domain);
                        if (r.cloudflareAccountLabel != null) response.put("cloudflare_account_label", r.cloudflareAccountLabel);
                        if (r.currentSelector != null)  response.put("current_selector",  r.currentSelector);
                        if (r.pendingSelector != null)  response.put("pending_selector",  r.pendingSelector);
                        if (r.previousSelector != null) response.put("previous_selector", r.previousSelector);
                        JSONArray arr = new JSONArray();
                        for (DkimManager.DkimRecordEntry e : r.records) {
                            JSONObject o = new JSONObject();
                            o.put("record_id", e.recordId);
                            o.put("name", e.name);
                            o.put("selector", e.selector);
                            o.put("content_preview", e.contentPreview);
                            if (e.comment != null) o.put("comment", e.comment);
                            o.put("is_current",  e.isCurrent);
                            o.put("is_pending",  e.isPending);
                            o.put("is_previous", e.isPrevious);
                            o.put("is_orphan",   e.isOrphan);
                            o.put("in_grace_period", e.inGracePeriod);
                            putTs(o, "deactivated_at",       e.deactivatedAt);
                            putTs(o, "grace_period_ends_at", e.gracePeriodEndsAt);
                            arr.put(o);
                        }
                        response.put("records", arr);
                        response.put("grace_period_days", org.daemoxcp.mail.security.DkimRotationScheduler.GRACE_PERIOD_DAYS);
                    }

                } else if ("orphans_delete".equals(action)) {
                    // Deletes a single record (by record_id) via the Cloudflare API.
                    int domainId = req.optInt("domain_id", 0);
                    String recordId = req.optString("record_id", "");
                    if (domainId <= 0 || recordId.isEmpty()) {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.dkim.idsRequired"));
                    } else {
                        DkimManager.RotationActionResult r = dkimManager.deleteDkimRecordById(domainId, recordId);
                        response.put("success", r.success);
                        response.put("message", r.message);
                    }

                } else if ("last_rotation_reset".equals(action)) {
                    // Overwrites dkim_last_rotation_at with NOW (Java JVM clock).
                    // Use it to clean up "fossil" values stored with the wrong tz.
                    int domainId = req.optInt("domain_id", 0);
                    if (domainId <= 0) {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.domain.idRequired"));
                    } else {
                        Main.mailDatabase.markDkimRotationActivated(domainId);
                        response.put("success", true);
                        response.put("message", I18n.tr("server.dkim.rotationReset"));
                    }

                } else if ("last_rotation_clear".equals(action)) {
                    // Reset to NULL -- the UI will show "Never done"
                    int domainId = req.optInt("domain_id", 0);
                    if (domainId <= 0) {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.domain.idRequired"));
                    } else {
                        Main.mailDatabase.clearDkimLastRotation(domainId);
                        response.put("success", true);
                        response.put("message", I18n.tr("server.dkim.lastRotationCleared"));
                    }

                } else if ("schedule_get".equals(action)) {
                    int domainId = req.optInt("domain_id", 0);
                    DkimManager.ScheduleResult s = dkimManager.getRotationSchedule(domainId);
                    response.put("success", s.success);
                    if (!s.success) {
                        response.put("error", s.message);
                    } else {
                        response.put("interval_days", s.intervalDays);
                        putTs(response, "last_rotation_at", s.lastRotationAt);
                        putTs(response, "next_rotation_at", s.nextRotationAt);
                        // Server clock in epoch ms (to diagnose drift against the browser)
                        response.put("server_now_ms", System.currentTimeMillis());
                        // If a rotation is ALREADY in progress, the "Next rotation" box
                        // must know it: without this field it kept writing "Due, starts
                        // at the next check" while the new key had already been generated
                        // and published. A promise about the future on something that had
                        // already happened.
                        try {
                            DkimManager.RotationInfo ri = dkimManager.getRotationInfo(domainId);
                            if (ri != null && ri.rotationState != null && !ri.rotationState.isBlank()) {
                                response.put("rotation_state", ri.rotationState);
                                if (ri.pendingSelector != null)
                                    response.put("rotation_pending_selector", ri.pendingSelector);
                            }
                        } catch (Exception ignore) {
                            // No state: the box goes back to saying the cautious thing.
                        }
                        response.put("auto_activate_after_hours", org.daemoxcp.mail.security.DkimRotationScheduler.AUTO_ACTIVATE_AFTER_HOURS);
                        response.put("grace_period_days", org.daemoxcp.mail.security.DkimRotationScheduler.GRACE_PERIOD_DAYS);
                        // If the domain has a Cloudflare account, THIS response says so.
                        //
                        // The card read it from a global variable that was set by
                        // ANOTHER loader, the rotation-state one. If that one arrived
                        // first, the global was still false and the warning "without CF
                        // the schedule stays inactive" appeared -- right under the box that
                        // said "linked account: <name>". A value read out of thin air depends
                        // on the order of two requests, and sooner or later that order changes.
                        response.put("auto_start",
                            UpdateManager.autoStart().optBoolean("active", false));
                        try {
                            response.put("cloudflare_configured",
                                dkimManager.getRotationInfo(domainId) != null
                                && Main.mailDatabase.getDomain(domainId) != null
                                && Main.mailDatabase.getDomain(domainId).cloudflareAccountId > 0);
                        } catch (Exception ignore) { }
                        // Recommended presets (for the UI)
                        JSONArray presets = new JSONArray();
                        presets.put(new JSONObject().put("days", 0).put("label", I18n.tr("server.dkim.preset.off")));
                        presets.put(new JSONObject().put("days", DkimManager.PRESET_AGGRESSIVE).put("label", I18n.tr("server.dkim.preset.monthly")));
                        presets.put(new JSONObject().put("days", DkimManager.PRESET_RECOMMENDED).put("label", I18n.tr("server.dkim.preset.quarterly")));
                        presets.put(new JSONObject().put("days", DkimManager.PRESET_BALANCED).put("label", I18n.tr("server.dkim.preset.halfYearly")));
                        presets.put(new JSONObject().put("days", DkimManager.PRESET_MINIMAL).put("label", I18n.tr("server.dkim.preset.yearly")));
                        response.put("presets", presets);
                    }

                } else if ("schedule_set".equals(action)) {
                    int domainId = req.optInt("domain_id", 0);
                    int days = req.optInt("interval_days", 0);
                    DkimManager.ScheduleResult s = dkimManager.setRotationSchedule(domainId, days);
                    response.put("success", s.success);
                    response.put("message", s.success
                        ? (days == 0 ? I18n.tr("server.dkim.scheduleOff")
                                     : I18n.tr("server.dkim.scheduleEvery", Map.of("days", days)))
                        : s.message);
                    response.put("interval_days", s.intervalDays);
                    putTs(response, "last_rotation_at", s.lastRotationAt);
                    putTs(response, "next_rotation_at", s.nextRotationAt);

                } else if ("rotate_history".equals(action)) {
                    int domainId = req.optInt("domain_id", 0);
                    int limit = req.optInt("limit", 50);
                    if (domainId <= 0) {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.domain.idRequired"));
                    } else {
                        java.util.List<MailDatabase.DkimRotationEvent> events =
                            Main.mailDatabase.getDkimRotationHistory(domainId, limit);
                        JSONArray arr = new JSONArray();
                        for (MailDatabase.DkimRotationEvent ev : events) {
                            JSONObject o = new JSONObject();
                            o.put("id", ev.id);
                            o.put("event_type", ev.eventType);
                            if (ev.selector != null) o.put("selector", ev.selector);
                            if (ev.mode != null) o.put("mode", ev.mode);
                            if (ev.triggeredBy != null) o.put("triggered_by", ev.triggeredBy);
                            if (ev.cloudflareAccountLabel != null) o.put("cloudflare_account_label", ev.cloudflareAccountLabel);
                            o.put("success", ev.success);
                            if (ev.message != null) o.put("message", ev.message);
                            putTs(o, "occurred_at", ev.occurredAt);
                            arr.put(o);
                        }
                        response.put("success", true);
                        response.put("events", arr);
                    }

                } else if ("domains_summary".equals(action)) {
                    // Queries the DNS once per domain: it is as slow as a single check
                    // multiplied by the number of domains, and that is the price of a
                    // true answer instead of a database read.
                    response = dkimManager.allDomainsSummary();

                } else if ("verify_active_dns".equals(action)) {
                    int domainId = req.optInt("domain_id", 0);
                    DkimManager.ActiveKeyVerifyResult vr = dkimManager.verifyActiveKeyInDns(domainId);
                    response.put("success", vr.success);
                    response.put("match", vr.match);
                    if (vr.domain != null) response.put("domain", vr.domain);
                    if (vr.selector != null) response.put("selector", vr.selector);
                    if (vr.dnsRecordName != null) response.put("dns_record_name", vr.dnsRecordName);
                    if (vr.message != null) response.put("message", vr.message);
                    if (vr.expectedPublicKey != null) response.put("expected_public_key", vr.expectedPublicKey);
                    if (vr.actualPublicKey != null) response.put("actual_public_key", vr.actualPublicKey);
                    if (vr.rawDigOutput != null && !vr.rawDigOutput.isEmpty()) response.put("raw_output", vr.rawDigOutput);

                } else {
                    response.put("success", false);
                    response.put("error", I18n.tr("server.badAction"));
                }

            } else {
                sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
                return;
            }

        } catch (Exception e) {
            response.put("success", false);
            response.put("error", ErrorText.forPage("handleApiDkim", e));
        }

        sendJsonResponse(exchange, response);
    }

    // ============== DNS API ==============

    private void handleApiDns(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
            return;
        }

        if (dnsGenerator == null) {
            sendJsonError(exchange, 503, I18n.tr("server.partNotReady", Map.of("part", "DNS")));
            return;
        }

        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();

        try {
            if ("GET".equals(method)) {
                String query = exchange.getRequestURI().getQuery();
                String domain = extractParamFromQuery(query, "domain");

                if (domain == null || domain.isEmpty()) {
                    response.put("success", false);
                    response.put("error", I18n.tr("server.domain.required"));
                } else {
                    // Get server IP and hostname
                    String serverIp = dnsGenerator.detectServerIp();
                    String mailHostname = Main.mailDatabase.getSetting("mail_hostname", "mail." + domain);

                    // Only for display, for whoever writes the records by hand: a placeholder you can
                    // see, not an empty "ip4:". None of this goes to Cloudflare (AutoDns computes the
                    // SPF on its own and does not write it without an IP).
                    DnsRecordsGenerator.DnsRecordSet records = dnsGenerator.generateAllRecords(domain, mailHostname,
                            serverIp.isEmpty() ? "YOUR_SERVER_IP" : serverIp);

                    response.put("success", true);
                    response.put("domain", records.domain);
                    response.put("server_ip", records.serverIp);
                    response.put("mail_hostname", records.mailServerHostname);

                    JSONArray recordsArray = new JSONArray();
                    for (DnsRecordsGenerator.DnsRecord record : records.records) {
                        JSONObject recordJson = new JSONObject();
                        recordJson.put("type", record.type);
                        recordJson.put("name", record.name);
                        recordJson.put("value", record.value);
                        recordJson.put("ttl", record.ttl);
                        recordJson.put("description", record.description);
                        recordJson.put("required", record.required);
                        if (record.checkType != null) recordJson.put("checkType", record.checkType);
                        if (record.fullValue != null) recordJson.put("fullValue", record.fullValue);
                        if (record.dnsZone != null) {
                            recordJson.put("dnsZone", record.dnsZone);
                        }
                        if (record.explanation != null) {
                            recordJson.put("explanation", record.explanation);
                        }
                        recordsArray.put(recordJson);
                    }
                    response.put("records", recordsArray);
                }

            } else if ("POST".equals(method)) {
                String body = readRequestBodyWithLimit(exchange);
        if (body == null) {
            sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge"));
            return;
        }
                JSONObject req = new JSONObject(body);
                String action = req.optString("action", "verify");

                if ("verify".equals(action)) {
                    String domain = req.optString("domain", "");

                    DnsRecordsGenerator.DnsVerificationResult result = dnsGenerator.verifyAllRecords(domain);

                    response.put("success", true);
                    response.put("domain", result.domain);
                    response.put("all_passed", result.allPassed);
                    response.put("score", result.score);

                    JSONArray checksArray = new JSONArray();
                    for (DnsRecordsGenerator.DnsCheck check : result.checks) {
                        JSONObject checkJson = new JSONObject();
                        checkJson.put("type", check.recordType);
                        checkJson.put("name", check.recordName);
                        checkJson.put("passed", check.passed);
                        checkJson.put("informational", check.informational);
                        checkJson.put("message", check.message);
                        if (check.currentValue != null) {
                            checkJson.put("current_value", check.currentValue);
                        }
                        if (check.expectedValue != null) {
                            checkJson.put("expected_value", check.expectedValue);
                        }
                        checksArray.put(checkJson);
                    }
                    response.put("checks", checksArray);

                } else if ("set_hostname".equals(action)) {
                    String hostname = req.optString("hostname", "");
                    if (!hostname.isEmpty()) {
                        Main.mailDatabase.setSetting("mail_hostname", hostname);
                        // Keep SQLite in sync
                        if (Main.dbManager != null) {
                            Main.dbManager.setMailHostname(hostname);
                        }
                        response.put("success", true);
                    } else {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.hostnameRequired"));
                    }

                } else {
                    response.put("success", false);
                    response.put("error", I18n.tr("server.badAction"));
                }

            } else {
                sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
                return;
            }

        } catch (Exception e) {
            response.put("success", false);
            response.put("error", ErrorText.forPage("handleApiDns", e));
        }

        sendJsonResponse(exchange, response);
    }

    // ============== Cloudflare API integration ==============

    /**
     * Endpoint /api/cloudflare -- multi-account.
     *
     * GET                                 -> account list + domain assignment
     * POST { action: "test", token }      -> verify token (no save)
     * POST { action: "add", label, email, token } -> add account (verify and save)
     * POST { action: "update", account_id, label, email, token? } -> update account
     * POST { action: "delete", account_id } -> delete account (unlinks the domains)
     * POST { action: "assign", domain_id, account_id } -> link a domain to an account (account_id=0 = manual)
     */
    private void handleApiCloudflare(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
            return;
        }
        if (cloudflareManager == null) {
            sendJsonError(exchange, 503, I18n.tr("server.partNotReady", Map.of("part", "Cloudflare")));
            return;
        }
        String method = exchange.getRequestMethod();
        org.json.JSONObject response = new org.json.JSONObject();

        try {
            if ("GET".equals(method)) {
                org.json.JSONArray accounts = new org.json.JSONArray();
                for (MailDatabase.CloudflareAccount a : cloudflareManager.listAccounts()) {
                    org.json.JSONObject obj = new org.json.JSONObject();
                    obj.put("id", a.id);
                    obj.put("label", a.label == null ? "" : a.label);
                    obj.put("email", a.email == null ? "" : a.email);
                    obj.put("token_masked", org.daemoxcp.mail.security.CloudflareManager.maskToken(a.apiToken));
                    if (a.verifiedAt != null) obj.put("verified_at", a.verifiedAt.toString());
                    if (a.createdAt != null)  obj.put("created_at", a.createdAt.toString());
                    accounts.put(obj);
                }
                response.put("success", true);
                response.put("accounts", accounts);

                // List of domains with the current assignment
                org.json.JSONArray domains = new org.json.JSONArray();
                for (MailDatabase.Domain d : Main.mailDatabase.getDomains()) {
                    org.json.JSONObject obj = new org.json.JSONObject();
                    obj.put("id", d.id);
                    obj.put("domain", d.domain);
                    obj.put("cloudflare_account_id", d.cloudflareAccountId);
                    domains.put(obj);
                }
                response.put("domains", domains);

                // Mail server (Mail Hostname): the SSL certificate is issued for this
                // hostname, whose base domain may NOT be among the mail domains.
                org.json.JSONObject mailServer = new org.json.JSONObject();
                String mailHostname = Main.dbManager != null ? Main.dbManager.getMailHostname() : null;
                mailServer.put("hostname", mailHostname == null ? "" : mailHostname);
                // Return the id only if the account really exists: that way badge/select stay
                // consistent with the renewal logic (which ignores orphan ids).
                int msAccId = acmeManager != null ? acmeManager.getMailCertCloudflareAccountId() : 0;
                if (msAccId > 0 && Main.mailDatabase.getCloudflareAccount(msAccId) == null) {
                    msAccId = 0;
                }
                mailServer.put("cloudflare_account_id", msAccId);
                response.put("mail_server", mailServer);

                sendJsonResponse(exchange, response);
                return;
            }

            if (!"POST".equals(method)) {
                sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
                return;
            }

            String body = readRequestBodyWithLimit(exchange);
            if (body == null) {
                sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge"));
                return;
            }
            org.json.JSONObject req = new org.json.JSONObject(body);
            String action = req.optString("action", "");

            if ("test".equals(action)) {
                String token = req.optString("token", "").trim();
                if (token.isEmpty()) {
                    response.put("success", false);
                    response.put("error", I18n.tr("server.cf.tokenMissing"));
                } else {
                    org.daemoxcp.mail.security.CloudflareManager.TokenCheck tc = cloudflareManager.verifyToken(token);
                    response.put("success", tc.valid);
                    response.put("message", tc.message);
                    if (tc.status != null) response.put("status", tc.status);
                }

            } else if ("add".equals(action)) {
                String label = req.optString("label", "").trim();
                String email = req.optString("email", "").trim();
                String token = req.optString("token", "").trim();
                org.daemoxcp.mail.security.CloudflareManager.AddAccountResult r =
                    cloudflareManager.addAccount(label, email, token);
                response.put("success", r.success);
                response.put("message", r.message);
                if (r.success) response.put("account_id", r.accountId);

            } else if ("update".equals(action)) {
                int id = req.optInt("account_id", 0);
                String label = req.optString("label", null);
                String email = req.optString("email", null);
                String token = req.has("token") ? req.optString("token", "").trim() : null;
                org.daemoxcp.mail.security.CloudflareManager.AddAccountResult r =
                    cloudflareManager.updateAccount(id, label, email, token);
                response.put("success", r.success);
                response.put("message", r.message);

            } else if ("delete".equals(action)) {
                int id = req.optInt("account_id", 0);
                if (id <= 0) {
                    response.put("success", false);
                    response.put("error", I18n.tr("server.cf.accountIdRequired"));
                } else {
                    boolean ok = cloudflareManager.deleteAccount(id);
                    response.put("success", ok);
                    response.put("message", ok ? I18n.tr("server.cf.accountRemoved") : I18n.tr("server.cf.accountNotFound"));
                }

            } else if ("assign".equals(action)) {
                int domainId = req.optInt("domain_id", 0);
                int accountId = req.optInt("account_id", 0); // 0 = manual
                if (domainId <= 0) {
                    response.put("success", false);
                    response.put("error", I18n.tr("server.domain.idRequired"));
                } else {
                    boolean ok = cloudflareManager.assignDomain(domainId, accountId);
                    response.put("success", ok);
                    response.put("message", ok
                        ? (accountId > 0 ? I18n.tr("server.cf.domainAssigned") : I18n.tr("server.cf.domainManual"))
                        : I18n.tr("server.operationFailed"));
                }

            } else if ("test_mailserver".equals(action)) {
                // Checks that the chosen account: (1) has a valid token and (2) manages
                // the DNS zone of the Mail Hostname (so the dns_cf renewal will really work).
                int accountId = req.optInt("account_id", 0);
                String mh = Main.dbManager != null ? Main.dbManager.getMailHostname() : null;
                if (mh == null || mh.isBlank()) {
                    response.put("success", false);
                    response.put("error", I18n.tr("server.cf.noMailHostname"));
                } else if (accountId <= 0) {
                    response.put("success", false);
                    response.put("error", I18n.tr("server.cf.chooseAccount"));
                } else {
                    MailDatabase.CloudflareAccount acct = Main.mailDatabase.getCloudflareAccount(accountId);
                    if (acct == null || acct.apiToken == null || acct.apiToken.isBlank()) {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.cf.accountOrTokenMissing"));
                    } else {
                        org.daemoxcp.mail.security.CloudflareManager.TokenCheck tc =
                            cloudflareManager.verifyToken(acct.apiToken);
                        if (!tc.valid) {
                            response.put("success", false);
                            response.put("error", I18n.tr("server.cf.tokenInvalid", Map.of("reason", String.valueOf(tc.message))));
                        } else {
                            org.daemoxcp.mail.security.CloudflareManager.ZoneLookup zl =
                                cloudflareManager.findZone(acct.apiToken, mh);
                            if (zl.found) {
                                response.put("success", true);
                                response.put("zone", zl.zoneName);
                                response.put("message", I18n.tr("server.cf.zoneOkRenewal", Map.of("zone", String.valueOf(zl.zoneName), "name", mh)));
                            } else {
                                response.put("success", false);
                                response.put("error", I18n.tr("server.cf.zoneMissing", Map.of("name", mh, "error", String.valueOf(zl.error))));
                            }
                        }
                    }
                }

            } else if ("test_domain".equals(action)) {
                // Checks that the account assigned to a mailbox domain has a valid
                // token and manages the DNS zone of that domain.
                int domainId = req.optInt("domain_id", 0);
                if (domainId <= 0) {
                    response.put("success", false);
                    response.put("error", I18n.tr("server.domain.idRequired"));
                } else {
                    MailDatabase.Domain dom = Main.mailDatabase.getDomain(domainId);
                    MailDatabase.CloudflareAccount acct = cloudflareManager.getAccountForDomain(domainId);
                    if (dom == null) {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.domainNotFound"));
                    } else if (acct == null || acct.apiToken == null || acct.apiToken.isBlank()) {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.cf.noAccountForDomain"));
                    } else {
                        org.daemoxcp.mail.security.CloudflareManager.TokenCheck tc =
                            cloudflareManager.verifyToken(acct.apiToken);
                        if (!tc.valid) {
                            response.put("success", false);
                            response.put("error", I18n.tr("server.cf.tokenInvalid", Map.of("reason", String.valueOf(tc.message))));
                        } else {
                            org.daemoxcp.mail.security.CloudflareManager.ZoneLookup zl =
                                cloudflareManager.findZone(acct.apiToken, dom.domain);
                            if (zl.found) {
                                response.put("success", true);
                                response.put("zone", zl.zoneName);
                                response.put("message", I18n.tr("server.cf.zoneOk", Map.of("zone", String.valueOf(zl.zoneName), "name", dom.domain)));
                            } else {
                                response.put("success", false);
                                response.put("error", I18n.tr("server.cf.zoneMissing", Map.of("name", dom.domain, "error", String.valueOf(zl.error))));
                            }
                        }
                    }
                }

            } else if ("assign_mailserver".equals(action)) {
                // Cloudflare account for the mail server's certificate (Mail Hostname)
                int accountId = req.optInt("account_id", 0); // 0 = manual
                if (acmeManager == null) {
                    response.put("success", false);
                    response.put("error", I18n.tr("server.acme.notReady"));
                } else if (accountId > 0 && Main.mailDatabase.getCloudflareAccount(accountId) == null) {
                    response.put("success", false);
                    response.put("error", I18n.tr("server.cf.accountNotFound"));
                } else {
                    acmeManager.setMailCertCloudflareAccountId(accountId);
                    response.put("success", true);
                    response.put("message", accountId > 0
                        ? I18n.tr("server.cf.mailCertLinked")
                        : I18n.tr("server.cf.mailCertManual"));
                }

            } else {
                response.put("success", false);
                response.put("error", I18n.tr("server.badAction"));
            }

        } catch (Exception e) {
            response.put("success", false);
            response.put("error", ErrorText.forPage("handleApiCloudflare", e));
        }

        sendJsonResponse(exchange, response);
    }

    // ============== Timezone diagnostics & fix ==============

    /**
     * Endpoint /api/timezone-diag -- diagnostic tool to align time zones.
     *
     * GET -> returns the current state:
     *   - server OS time (epoch ms) and JVM tz
     *   - MySQL @@global.time_zone, @@session.time_zone, NOW(), UTC_TIMESTAMP()
     *   - "alignment": OK if mysql NOW() ~= jvm now (delta < 60s), MISMATCH otherwise
     *
     * POST { action: "sync_to_system" } -> sets MySQL global+session time_zone
     *   to the current JVM offset (e.g. "+02:00"). Requires the SUPER privilege on MySQL.
     *
     * POST { action: "set", value: "+02:00" | "SYSTEM" | "Europe/Rome" } -> manual.
     */
    private void handleApiTimezoneDiag(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
            return;
        }
        String method = exchange.getRequestMethod();
        org.json.JSONObject response = new org.json.JSONObject();

        try {
            if ("GET".equals(method)) {
                fillTimezoneDiagnostics(response);
                sendJsonResponse(exchange, response);
                return;
            }
            if (!"POST".equals(method)) {
                sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
                return;
            }
            String body = readRequestBodyWithLimit(exchange);
            if (body == null) { sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge")); return; }
            org.json.JSONObject req = new org.json.JSONObject(body);
            String action = req.optString("action", "");

            if ("sync_to_system".equals(action) || "set".equals(action)) {
                String desired;
                if ("set".equals(action)) {
                    desired = req.optString("value", "").trim();
                    if (desired.isEmpty()) {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.tz.valueRequired"));
                        sendJsonResponse(exchange, response);
                        return;
                    }
                } else {
                    // Compute the JVM's current offset from UTC in "+HH:MM" format
                    java.time.ZoneOffset off = java.time.ZonedDateTime.now().getOffset();
                    int sec = off.getTotalSeconds();
                    String sign = sec >= 0 ? "+" : "-";
                    int abs = Math.abs(sec);
                    desired = String.format("%s%02d:%02d", sign, abs / 3600, (abs % 3600) / 60);
                }

                StringBuilder log = new StringBuilder();
                boolean ok = true;
                String errMsg = null;
                if (!TIME_ZONE_VALUE.matcher(desired).matches()) {
                    response.put("success", false);
                    response.put("error", I18n.tr("server.tz.badValue"));
                    sendJsonResponse(exchange, response);
                    return;
                }
                // The value is passed as a parameter, never pasted into the query
                try (java.sql.PreparedStatement global = Main.mailDatabase.getConnection().prepareStatement(SqlCatalog.SERVER_HANDLE_API_TIMEZONE_DIAG);
                     java.sql.PreparedStatement session = Main.mailDatabase.getConnection().prepareStatement(SqlCatalog.SERVER_HANDLE_API_TIMEZONE_DIAG_2)) {
                    // Try global (requires SUPER), then session
                    try {
                        global.setString(1, desired);
                        global.executeUpdate();
                        log.append("✓ ").append(I18n.tr("server.tz.globalSet", Map.of("value", desired))).append("\n");
                    } catch (Exception ex) {
                        log.append("✗ ").append(I18n.tr("server.tz.globalFailed", Map.of("error", String.valueOf(ex.getMessage())))).append("\n");
                        // Go on setting session for the current connection anyway
                    }
                    try {
                        session.setString(1, desired);
                        session.executeUpdate();
                        log.append("✓ ").append(I18n.tr("server.tz.sessionSet", Map.of("value", desired))).append("\n");
                    } catch (Exception ex) {
                        log.append("✗ ").append(I18n.tr("server.tz.sessionFailed", Map.of("error", String.valueOf(ex.getMessage())))).append("\n");
                        ok = false;
                        errMsg = ErrorText.forPage("handleApiTimezoneDiag", ex);
                    }
                } catch (Exception e) {
                    ok = false;
                    errMsg = ErrorText.forPage("handleApiTimezoneDiag", e);
                }

                response.put("success", ok);
                if (errMsg != null) response.put("error", errMsg);
                response.put("log", log.toString());
                response.put("desired_value", desired);
                fillTimezoneDiagnostics(response);
                sendJsonResponse(exchange, response);
                return;
            }

            response.put("success", false);
            response.put("error", I18n.tr("server.badAction"));
            sendJsonResponse(exchange, response);
        } catch (Exception e) {
            sendJsonError(exchange, 500, I18n.tr("server.errorWith", Map.of("error", ErrorText.detail("handleApiTimezoneDiag", e))));
        }
    }

    /** Fills response with the timezone diagnostic fields. */
    private void fillTimezoneDiagnostics(org.json.JSONObject response) {
        response.put("success", true);

        // 1) JVM / OS Java
        long jvmNowMs = System.currentTimeMillis();
        response.put("jvm_now_ms", jvmNowMs);
        response.put("jvm_now_iso", java.time.Instant.ofEpochMilli(jvmNowMs).toString());
        response.put("jvm_default_zone", java.util.TimeZone.getDefault().getID());
        java.time.ZoneOffset off = java.time.ZonedDateTime.now().getOffset();
        response.put("jvm_offset", off.getId().equals("Z") ? "+00:00" : off.getId());

        // 2) OS clock via the "date" command (FreeBSD/Linux): more reliable when the JVM
        //    is set to a different tz than the OS
        try {
            // TODO: migrate to Shell.run when touched
            Process p = new ProcessBuilder("date", "+%s|%z|%Z").redirectErrorStream(true).start();
            try (java.io.BufferedReader r = new java.io.BufferedReader(new java.io.InputStreamReader(p.getInputStream()))) {
                String line = r.readLine();
                if (line != null) {
                    String[] parts = line.trim().split("\\|");
                    if (parts.length >= 1) response.put("os_now_ms", Long.parseLong(parts[0]) * 1000L);
                    if (parts.length >= 2) response.put("os_offset", parts[1]);
                    if (parts.length >= 3) response.put("os_tz", parts[2]);
                }
            }
            p.waitFor();
        } catch (Exception ignore) {}

        // 3) MySQL: @@global.time_zone, @@session.time_zone, NOW(), UTC_TIMESTAMP()
        try (java.sql.Statement stmt = Main.mailDatabase.getConnection().createStatement();
             java.sql.ResultSet rs = stmt.executeQuery(SqlCatalog.SERVER_FILL_TIMEZONE_DIAGNOSTICS)) {
            if (rs.next()) {
                response.put("mysql_global_tz", rs.getString(1));
                response.put("mysql_session_tz", rs.getString(2));
                response.put("mysql_now", rs.getString(3));
                response.put("mysql_utc_now", rs.getString(4));
                response.put("mysql_system_tz", rs.getString(5));
                long unixTs = rs.getLong(6);
                response.put("mysql_now_ms", unixTs * 1000L);

                // Skew = mysql_now_ms - jvm_now_ms
                long skewMs = (unixTs * 1000L) - jvmNowMs;
                response.put("skew_mysql_vs_jvm_ms", skewMs);
                response.put("alignment", Math.abs(skewMs) < 60_000 ? "OK" : "MISMATCH");
            }
        } catch (Exception e) {
            response.put("mysql_error", ErrorText.forPage("fillTimezoneDiagnostics", e));
        }
    }

    // ============== Postfix Aliases Health / Fix ==============

    /**
     * Endpoint /api/postfix-aliases-health.
     *   GET                       -> diagnose
     *   POST { action: "fix" }    -> auto-fix (create source + postalias + reload)
     *   POST { action: "set_root_forward", forward_to: "..." } -> update root forward
     */
    private void handleApiPostfixAliases(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
            return;
        }
        String method = exchange.getRequestMethod();
        org.json.JSONObject response = new org.json.JSONObject();
        try {
            org.daemoxcp.mail.security.PostfixAliasesManager mgr = new org.daemoxcp.mail.security.PostfixAliasesManager();

            if ("GET".equals(method)) {
                org.daemoxcp.mail.security.PostfixAliasesManager.AliasesStatus s = mgr.diagnose();
                fillAliasesStatus(response, s);
                sendJsonResponse(exchange, response);
                return;
            }
            if (!"POST".equals(method)) {
                sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
                return;
            }
            String body = readRequestBodyWithLimit(exchange);
            if (body == null) { sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge")); return; }
            org.json.JSONObject req = new org.json.JSONObject(body);
            String action = req.optString("action", "");

            if ("fix".equals(action)) {
                org.daemoxcp.mail.security.PostfixAliasesManager.FixResult r = mgr.fix();
                response.put("success", r.success);
                response.put("message", r.message);
                response.put("log", r.log.toString());
                if (r.aliasFile != null)   response.put("alias_file",    r.aliasFile);
                if (r.aliasDbFile != null) response.put("alias_db_file", r.aliasDbFile);
                logAudit(r.success ? "POSTFIX_ALIASES_FIXED" : "POSTFIX_ALIASES_FIX_FAILED",
                    getClientIp(exchange), "msg=" + r.message);
                // Also include the updated status
                fillAliasesStatus(response, mgr.diagnose());
                sendJsonResponse(exchange, response);
                return;
            }

            if ("set_root_forward".equals(action)) {
                String forwardTo = req.optString("forward_to", "").trim();
                org.daemoxcp.mail.security.PostfixAliasesManager.FixResult r = mgr.setRootForward(forwardTo);
                response.put("success", r.success);
                response.put("message", r.message);
                response.put("log", r.log.toString());
                logAudit(r.success ? "POSTFIX_ROOT_FORWARD_SET" : "POSTFIX_ROOT_FORWARD_FAILED",
                    getClientIp(exchange), "forward_to=" + forwardTo + " msg=" + r.message);
                fillAliasesStatus(response, mgr.diagnose());
                sendJsonResponse(exchange, response);
                return;
            }

            response.put("success", false);
            response.put("error", I18n.tr("server.aliasesHealth.badAction"));
            sendJsonResponse(exchange, response);
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", ErrorText.forPage("handleApiPostfixAliases", e));
            sendJsonResponse(exchange, response);
        }
    }

    private void fillAliasesStatus(org.json.JSONObject obj,
                                    org.daemoxcp.mail.security.PostfixAliasesManager.AliasesStatus s) {
        if (s == null) return;
        obj.put("success", s.success);
        if (s.error != null) obj.put("error", s.error);
        if (s.overall != null) obj.put("overall", s.overall);
        if (s.summary != null) obj.put("summary", s.summary);
        if (s.aliasFile != null) obj.put("alias_file", s.aliasFile);
        if (s.aliasDbFile != null) obj.put("alias_db_file", s.aliasDbFile);
        if (s.aliasMapsRaw != null) obj.put("alias_maps_raw", s.aliasMapsRaw);
        if (s.aliasDatabaseRaw != null) obj.put("alias_database_raw", s.aliasDatabaseRaw);
        obj.put("source_exists", s.sourceExists);
        obj.put("db_exists", s.dbExists);
        obj.put("db_stale_vs_source", s.dbStaleVsSource);
        if (s.rootForward != null) obj.put("root_forward", s.rootForward);
        if (s.sourceContent != null) obj.put("source_content", s.sourceContent);
    }

    /**
     * Helper: fills a JSONObject with the structured output of a JailLiveState.
     */
    private void fillJailLiveStateJson(org.json.JSONObject obj, Fail2banManager.JailLiveState s) {
        if (s == null) return;
        obj.put("name", s.name == null ? "" : s.name);
        if (s.error != null) obj.put("error", s.error);
        // Raw output of the "get" commands
        obj.put("maxretry", s.maxretry == null ? "" : s.maxretry);
        obj.put("findtime", s.findtime == null ? "" : s.findtime);
        obj.put("bantime", s.bantime == null ? "" : s.bantime);
        obj.put("logpath", s.logpath == null ? "" : s.logpath);
        obj.put("ignoreip", s.ignoreip == null ? "" : s.ignoreip);
        obj.put("filter", s.filter == null ? "" : s.filter);
        // Full output of "fail2ban-client status <jail>"
        obj.put("status_raw", s.statusRaw == null ? "" : s.statusRaw);
        // Parsed fields
        obj.put("currently_failed", s.currentlyFailed);
        obj.put("total_failed", s.totalFailed);
        obj.put("currently_banned", s.currentlyBanned);
        obj.put("total_banned", s.totalBanned);
        if (s.bannedIpsRaw != null) obj.put("banned_ips_raw", s.bannedIpsRaw);
        if (s.fileListRaw != null) obj.put("file_list_raw", s.fileListRaw);
    }

    // ============== SSL/Let's Encrypt API ==============

    private void handleApiSsl(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
            return;
        }

        if (acmeManager == null) {
            sendJsonError(exchange, 503, I18n.tr("server.partNotReady", Map.of("part", "ACME")));
            return;
        }

        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();

        try {
            if ("GET".equals(method)) {
                // Get certificate status
                response.put("success", true);
                response.put("acme_installed", acmeManager.isAcmeInstalled());
                response.put("acme_account", acmeManager.hasAccount());

                AcmeManager.CertificateInfo certInfo = acmeManager.getCertificateInfo();
                if (certInfo != null && certInfo.installed) {
                    response.put("certificate_installed", true);
                    response.put("common_name", certInfo.commonName);
                    response.put("issuer", certInfo.issuer);
                    response.put("lets_encrypt", certInfo.letsEncrypt);
                    response.put("self_signed", acmeManager.isSelfSigned());
                    response.put("days_until_expiry", certInfo.daysUntilExpiry);
                    response.put("expired", certInfo.expired);
                    response.put("expiring_soon", certInfo.expiringSoon);
                    if (certInfo.issuedAt != null) {
                        response.put("issued_at", certInfo.issuedAt.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
                        response.put("valid_from", certInfo.issuedAt.format(DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm")));
                    }
                    if (certInfo.expiresAt != null) {
                        response.put("expires_at", certInfo.expiresAt.format(DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm")));
                    }
                    if (certInfo.subjectAltNames != null) {
                        response.put("san", new JSONArray(certInfo.subjectAltNames));
                    }
                    if (certInfo.algorithm != null) {
                        response.put("algorithm", certInfo.algorithm);
                    }
                    if (certInfo.serial != null) {
                        response.put("serial", certInfo.serial);
                    }
                } else {
                    response.put("certificate_installed", false);
                    response.put("self_signed", false);
                }

            } else if ("POST".equals(method)) {
                String body = readRequestBodyWithLimit(exchange);
        if (body == null) {
            sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge"));
            return;
        }
                JSONObject req = new JSONObject(body);
                String action = req.optString("action", "");

                switch (action) {
                    case "install_acme" -> {
                        String email = req.optString("email", "");
                        if (email.isEmpty() || !email.contains("@")) {
                            response.put("success", false);
                            response.put("error", I18n.tr("server.acme.emailRequired"));
                        } else {
                            // installAcme runs "pkg install curl socat": it waits for the package turn.
                            JSONObject outcome = onPackageTurn(I18n.tr("server.install.jobName", Map.of("component", "acme.sh")), () -> {
                                AcmeManager.InstallResult result = acmeManager.installAcme(email);
                                JSONObject r = new JSONObject().put("success", result.success).put("message", result.message);
                                if (result.output != null) r.put("output", result.output);
                                return r;
                            });
                            for (String k : outcome.keySet()) response.put(k, outcome.get(k));
                        }
                    }
                    case "issue" -> {
                        String domain = req.optString("domain", "");
                        String mailHostname = req.optString("mail_hostname", "mail." + domain);
                        String challengeType = req.optString("challenge_type", "http");
                        String webroot = req.optString("webroot", "");

                        if (domain.isEmpty()) {
                            response.put("success", false);
                            response.put("error", I18n.tr("server.domain.required"));
                        } else {
                            AcmeManager.CertificateResult result = acmeManager.issueCertificate(domain, mailHostname, challengeType, webroot);
                            response.put("success", result.success);
                            response.put("message", result.message);
                            if (result.output != null) {
                                response.put("output", result.output);
                            }
                        }
                    }
                    case "renew" -> {
                        String mailHostname = req.optString("mail_hostname", "");
                        if (mailHostname.isEmpty()) {
                            // Get from certificate
                            AcmeManager.CertificateInfo info = acmeManager.getCertificateInfo();
                            if (info != null) {
                                mailHostname = info.commonName;
                            }
                        }

                        if (mailHostname == null || mailHostname.isEmpty()) {
                            response.put("success", false);
                            response.put("error", I18n.tr("server.hostnameRequired"));
                        } else {
                            AcmeManager.CertificateResult result = acmeManager.renewCertificate(mailHostname);
                            response.put("success", result.success);
                            response.put("message", result.message);
                            if (result.output != null) {
                                response.put("output", result.output);
                            }
                            logAudit(result.success ? "SSL_CERT_RENEWED" : "SSL_CERT_RENEW_FAILED",
                                getClientIp(exchange), "hostname=" + mailHostname + " msg=" + result.message);
                        }
                    }

                    // ============== AUTO-RENEWAL ==============

                    case "get_auto_renewal_settings" -> {
                        try {
                            response.put("success", true);
                            response.put("enabled", acmeManager.isAutoRenewalEnabled());
                            response.put("threshold_days", acmeManager.getRenewalThresholdDays());

                            String lastCheck = acmeManager.getLastCheckTime();
                            String lastResult = acmeManager.getLastCheckResult();
                            String lastRenewal = acmeManager.getLastRenewalTime();

                            response.put("last_check", lastCheck);
                            response.put("last_check_human", humanizeDateTime(lastCheck));
                            response.put("last_renewal", lastRenewal);
                            response.put("last_renewal_human", humanizeDateTime(lastRenewal));

                            // Format last result as colored badge
                            if (lastResult != null && !lastResult.isEmpty()) {
                                int sep = lastResult.indexOf('|');
                                String code = sep > 0 ? lastResult.substring(0, sep) : "";
                                String msg  = sep > 0 ? lastResult.substring(sep + 1) : lastResult;
                                String cls  = switch (code) {
                                    case "OK"   -> "bg-success";
                                    case "FAIL" -> "bg-danger";
                                    case "SKIP" -> "bg-secondary";
                                    case "INFO" -> "bg-info text-dark";
                                    default     -> "bg-secondary";
                                };
                                response.put("last_result_html", "<span class=\"badge " + cls + "\">" + code + "</span> " + escapeHtmlSimple(msg));
                            } else {
                                response.put("last_result_html", "<span class=\"text-muted\">-</span>");
                            }

                            // Compute the next check (if enabled): 24h after the last one
                            if (acmeManager.isAutoRenewalEnabled() && lastCheck != null && !lastCheck.isEmpty()) {
                                try {
                                    java.time.LocalDateTime last = java.time.LocalDateTime.parse(lastCheck);
                                    java.time.LocalDateTime next = last.plusHours(24);
                                    response.put("next_check_human", next.format(java.time.format.DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm")));
                                } catch (Exception ignored) {
                                    response.put("next_check_human", I18n.tr("server.ssl.within24h"));
                                }
                            } else if (acmeManager.isAutoRenewalEnabled()) {
                                response.put("next_check_human", I18n.tr("server.ssl.within24h"));
                            } else {
                                response.put("next_check_human", I18n.tr("server.ssl.autoOff"));
                            }
                        } catch (Exception e) {
                            response.put("success", false);
                            response.put("error", ErrorText.forPage("handleApiSsl", e));
                        }
                    }

                    case "set_auto_renewal_settings" -> {
                        try {
                            boolean enabled = req.optBoolean("enabled", true);
                            int thresholdDays = req.optInt("threshold_days", 30);
                            acmeManager.setAutoRenewalEnabled(enabled);
                            acmeManager.setRenewalThresholdDays(thresholdDays);
                            response.put("success", true);
                            response.put("message", I18n.tr("server.settingsSaved"));
                            logAudit("SSL_AUTO_RENEWAL_SETTINGS_CHANGED", getClientIp(exchange),
                                "enabled=" + enabled + " threshold=" + thresholdDays);
                        } catch (Exception e) {
                            response.put("success", false);
                            response.put("error", ErrorText.forPage("handleApiSsl", e));
                        }
                    }

                    case "trigger_manual_check" -> {
                        try {
                            AcmeManager.CertificateResult res = acmeManager.checkAndRenewCertificates(true);
                            response.put("success", res.success);
                            response.put("message", res.message);
                            logAudit("SSL_MANUAL_CHECK_TRIGGERED", getClientIp(exchange),
                                "success=" + res.success + " msg=" + res.message);
                        } catch (Exception e) {
                            response.put("success", false);
                            response.put("error", ErrorText.forPage("handleApiSsl", e));
                        }
                    }

                    // ============== NEW SSL OPTIONS ==============

                    case "issue_http01" -> {
                        // Let's Encrypt HTTP-01 (standalone, requires port 80)
                        String hostname = req.optString("hostname", "");
                        if (hostname.isEmpty()) {
                            response.put("success", false);
                            response.put("error", I18n.tr("server.ssl.hostnameRequired"));
                        } else {
                            // Extract domain from hostname
                            String domain = hostname.replaceFirst("^[^.]+\\.", "");
                            AcmeManager.CertificateResult result = acmeManager.issueCertificate(domain, hostname, "http", "");
                            response.put("success", result.success);
                            response.put("message", result.message);
                            if (result.output != null) {
                                response.put("output", result.output);
                            }
                            logAudit(result.success ? "SSL_CERT_ISSUED_HTTP01" : "SSL_CERT_ISSUE_FAILED",
                                getClientIp(exchange), "hostname=" + hostname + " msg=" + result.message);
                        }
                    }

                    case "generate_dns_challenge" -> {
                        // Let's Encrypt DNS-01 Step 1: Generate TXT record
                        String hostname = req.optString("hostname", "");
                        boolean forceRegenerate = req.optBoolean("force", false);
                        if (hostname.isEmpty()) {
                            response.put("success", false);
                            response.put("error", I18n.tr("server.ssl.hostnameRequired"));
                        } else {
                            AcmeManager.DnsChallengeResult result = acmeManager.generateDnsChallenge(hostname, forceRegenerate);
                            response.put("success", result.success);
                            response.put("message", result.message);
                            if (result.txtDomain != null) {
                                response.put("txt_domain", result.txtDomain);
                            }
                            if (result.txtValue != null) {
                                response.put("txt_value", result.txtValue);
                            }
                        }
                    }

                    case "deploy_existing_cert" -> {
                        // Deploy existing certificate without regenerating
                        String hostname = req.optString("hostname", "");
                        if (hostname.isEmpty()) {
                            response.put("success", false);
                            response.put("error", I18n.tr("server.hostnameRequired"));
                        } else {
                            AcmeManager.DeployResult result = acmeManager.deployCertificate(hostname);
                            response.put("success", result.success);
                            response.put("message", result.message);
                            if (result.output != null) {
                                response.put("output", result.output);
                            }
                            logAudit(result.success ? "SSL_CERT_DEPLOYED" : "SSL_CERT_DEPLOY_FAILED",
                                getClientIp(exchange), "hostname=" + hostname + " msg=" + result.message);
                        }
                    }

                    case "verify_dns_and_issue" -> {
                        // Let's Encrypt DNS-01 Step 2: Verify TXT and issue certificate
                        String hostname = req.optString("hostname", "");
                        if (hostname.isEmpty()) {
                            response.put("success", false);
                            response.put("error", I18n.tr("server.ssl.hostnameRequired"));
                        } else {
                            AcmeManager.CertificateResult result = acmeManager.verifyDnsAndIssue(hostname);
                            response.put("success", result.success);
                            response.put("message", result.message);
                            if (result.output != null) {
                                response.put("output", result.output);
                            }
                            logAudit(result.success ? "SSL_CERT_ISSUED_DNS01" : "SSL_CERT_ISSUE_FAILED",
                                getClientIp(exchange), "hostname=" + hostname + " msg=" + result.message);
                        }
                    }

                    case "upload_manual" -> {
                        // Manual certificate upload
                        String cert = req.optString("certificate", "");
                        String key = req.optString("private_key", "");
                        String hostname = req.optString("hostname", "");

                        if (cert.isEmpty() || key.isEmpty()) {
                            response.put("success", false);
                            response.put("error", I18n.tr("server.ssl.certKeyRequired"));
                        } else {
                            AcmeManager.CertificateResult result = acmeManager.installManualCertificate(cert, key, hostname);
                            response.put("success", result.success);
                            response.put("message", result.message);
                            if (result.output != null) {
                                response.put("output", result.output);
                            }
                            logAudit(result.success ? "SSL_CERT_INSTALLED_MANUAL" : "SSL_CERT_MANUAL_FAILED",
                                getClientIp(exchange), "hostname=" + hostname + " msg=" + result.message);
                        }
                    }

                    case "check_self_signed" -> {
                        // Check if current certificate is self-signed
                        boolean selfSigned = acmeManager.isSelfSigned();
                        response.put("success", true);
                        response.put("self_signed", selfSigned);
                    }

                    default -> {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.badAction"));
                    }
                }

            } else {
                sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
                return;
            }

        } catch (Exception e) {
            response.put("success", false);
            response.put("error", ErrorText.forPage("handleApiSsl", e));
        }

        sendJsonResponse(exchange, response);
    }

    // ============== LOGS API ==============

    private void handleApiLogs(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
            return;
        }

        if (logManager == null) {
            logManager = new LogManager();
        }

        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();

        try {
            if ("GET".equals(method)) {
                String query = exchange.getRequestURI().getQuery();
                String logId = extractParamFromQuery(query, "log");
                String filter = extractParamFromQuery(query, "filter");
                String linesStr = extractParamFromQuery(query, "lines");
                int lines = 100;
                try {
                    if (linesStr != null) lines = Integer.parseInt(linesStr);
                } catch (NumberFormatException e) {
                    // use default
                }

                if (logId == null || logId.isEmpty()) {
                    // Return list of available logs
                    response.put("success", true);
                    JSONArray logsArray = new JSONArray();
                    for (LogManager.LogFile logFile : logManager.getAvailableLogFiles()) {
                        JSONObject logJson = new JSONObject();
                        logJson.put("id", logFile.id);
                        logJson.put("path", logFile.path);
                        logJson.put("description", org.daemoxcp.mail.i18n.I18n.tr(logFile.description));
                        logJson.put("type", logFile.type.toString());
                        logJson.put("exists", logFile.exists);
                        logsArray.put(logJson);
                    }
                    response.put("logs", logsArray);

                } else {
                    // Return log entries
                    List<LogManager.LogEntry> entries = logManager.readLog(logId, lines, filter);

                    response.put("success", true);
                    response.put("log_id", logId);
                    response.put("count", entries.size());

                    JSONArray entriesArray = new JSONArray();
                    DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
                    for (LogManager.LogEntry entry : entries) {
                        JSONObject entryJson = new JSONObject();
                        if (entry.timestamp != null) {
                            entryJson.put("timestamp", entry.timestamp.format(formatter));
                        }
                        entryJson.put("level", entry.level != null ? entry.level.toString() : "INFO");
                        entryJson.put("message", entry.message);
                        if (entry.process != null) {
                            entryJson.put("process", entry.process);
                        }
                        if (entry.eventType != null) {
                            entryJson.put("event_type", entry.eventType);
                        }
                        if (entry.from != null) {
                            entryJson.put("from", entry.from);
                        }
                        if (entry.to != null) {
                            entryJson.put("to", entry.to);
                        }
                        entriesArray.put(entryJson);
                    }
                    response.put("entries", entriesArray);
                }

            } else if ("POST".equals(method)) {
                String body = readRequestBodyWithLimit(exchange);
        if (body == null) {
            sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge"));
            return;
        }
                JSONObject req = new JSONObject(body);
                String action = req.optString("action", "search");

                if ("search".equals(action)) {
                    String logId = req.optString("log_id", "maillog");
                    String pattern = req.optString("pattern", "");
                    int maxResults = req.optInt("max_results", 100);

                    List<LogManager.LogEntry> results = logManager.searchLogs(logId, pattern, maxResults, null, null);

                    response.put("success", true);
                    response.put("count", results.size());

                    JSONArray resultsArray = new JSONArray();
                    for (LogManager.LogEntry entry : results) {
                        JSONObject entryJson = new JSONObject();
                        entryJson.put("raw", entry.raw);
                        if (entry.timestamp != null) {
                            entryJson.put("timestamp", entry.timestamp.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
                        }
                        entryJson.put("level", entry.level != null ? entry.level.toString() : "INFO");
                        resultsArray.put(entryJson);
                    }
                    response.put("results", resultsArray);

                } else {
                    response.put("success", false);
                    response.put("error", I18n.tr("server.badAction"));
                }

            } else {
                sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
                return;
            }

        } catch (Exception e) {
            response.put("success", false);
            response.put("error", ErrorText.forPage("handleApiLogs", e));
        }

        sendJsonResponse(exchange, response);
    }

    // ============== STATS API ==============

    // Stats cache, to avoid parsing maillog on every request (TTL 60s)
    private static volatile JSONObject CACHED_STATS = null;
    private static volatile long CACHED_STATS_AT = 0;
    private static final long STATS_CACHE_TTL_MS = 60_000;

    private void handleApiStats(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
            return;
        }

        // Cache hit?
        long now = System.currentTimeMillis();
        if (CACHED_STATS != null && (now - CACHED_STATS_AT) < STATS_CACHE_TTL_MS) {
            sendJsonResponse(exchange, CACHED_STATS);
            return;
        }

        JSONObject response = new JSONObject();

        try {
            // Get stats from Rspamd (accurate spam counting)
            RspamdManager.RspamdStats rspamdStats = null;
            if (rspamdManager != null) {
                rspamdStats = rspamdManager.getStatistics();
            }

            // Get active users count from database
            int activeMailboxes = Main.mailDatabase.getMailboxCount();

            response.put("success", true);
            response.put("generated_at", java.time.LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            response.put("period", "total");

            // SMTP stats -- only basic counts from Rspamd (no log parsing)
            JSONObject smtp = new JSONObject();
            smtp.put("rejected", rspamdStats != null ? rspamdStats.spamCount : 0);
            smtp.put("source", "rspamd");
            response.put("smtp", smtp);

            // IMAP stats
            JSONObject imap = new JSONObject();
            imap.put("logins", 0);
            imap.put("active_users", activeMailboxes);
            imap.put("auth_failures", 0);
            response.put("imap", imap);

            // Security stats from Rspamd
            JSONObject security = new JSONObject();
            if (rspamdStats != null) {
                security.put("spam_detected", rspamdStats.spamCount);
                security.put("viruses_found", 0);
                security.put("spam_percentage", Math.round(rspamdStats.spamPercent * 100) / 100.0);
            } else {
                security.put("spam_detected", 0);
                security.put("viruses_found", 0);
                security.put("spam_percentage", 0);
            }
            response.put("security", security);

        } catch (Exception e) {
            response.put("success", false);
            response.put("error", ErrorText.forPage("handleApiStats", e));
        }

        // Cache updated
        CACHED_STATS = response;
        CACHED_STATS_AT = System.currentTimeMillis();

        sendJsonResponse(exchange, response);
    }

    // ============== MAIL QUEUE API ==============

    private void handleApiQueue(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
            return;
        }

        if (queueManager == null) {
            queueManager = new MailQueueManager();
        }

        String method = exchange.getRequestMethod();
        String query = exchange.getRequestURI().getQuery();
        JSONObject response = new JSONObject();

        try {
            if ("GET".equals(method)) {
                String action = extractParamFromQuery(query, "action");

                if ("stats".equals(action)) {
                    MailQueueManager.QueueStats stats = queueManager.getStats();
                    response.put("success", true);
                    response.put("total", stats.totalMessages);
                    response.put("total_size", stats.totalSize);
                    response.put("active", stats.active);
                    response.put("deferred", stats.deferred);
                    response.put("hold", stats.hold);
                    response.put("incoming", stats.incoming);
                    response.put("permanent", stats.permanent);
                    // UTC with the Z: the local time is added by the viewer's browser
                    if (stats.oldestMessage != null) response.put("oldest_message", stats.oldestMessage.toString());
                    response.put("top_senders", topFive(stats.topSenders));
                    response.put("top_destinations", topFive(stats.topDestinations));

                } else if ("message".equals(action)) {
                    MailQueueManager.MessageContent content = queueManager.getMessage(extractParamFromQuery(query, "id"));
                    response.put("success", content.found);
                    if (content.found) {
                        response.put("from", content.fromHeader == null ? "" : content.fromHeader);
                        response.put("to", content.toHeader == null ? "" : content.toHeader);
                        response.put("subject", content.subject == null ? "" : content.subject);
                        response.put("date", content.dateHeader == null ? "" : content.dateHeader);
                        response.put("body_preview", content.bodyPreview);
                        response.put("body_truncated", content.bodyTruncated);
                    } else {
                        response.put("error", content.error);
                    }

                } else {
                    java.util.List<MailQueueManager.QueuedMessage> messages = queueManager.getQueue();
                    response.put("success", true);
                    response.put("count", messages.size());
                    JSONArray list = new JSONArray();
                    for (MailQueueManager.QueuedMessage msg : messages) list.put(queueMessageJson(msg));
                    response.put("messages", list);
                }

            } else if ("POST".equals(method)) {
                String body = readRequestBodyWithLimit(exchange);
                if (body == null) {
                    sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge"));
                    return;
                }
                JSONObject json = body.isBlank() ? new JSONObject() : new JSONObject(body);
                // Every action changes the queue: without the session token nothing starts.
                if (!validateCsrfForRequest(exchange, json)) {
                    sendCsrfError(exchange);
                    return;
                }
                String action = json.optString("action", "");
                String ip = getClientIp(exchange);
                MailQueueManager.QueueAction result = null;

                switch (action) {
                    case "remove" -> {
                        String id = json.optString("id", "");
                        result = queueManager.removeMessage(id);
                        if (result.success) logAudit("QUEUE_REMOVE", ip, "Deleted queued message " + id);
                    }
                    case "schedule" -> {
                        String id = json.optString("id", "");
                        result = queueManager.scheduleMessage(id);
                        if (result.success) logAudit("QUEUE_REQUEUE", ip, "Requeued message " + id);
                    }
                    case "flush" -> {
                        result = queueManager.flushQueue();
                        if (result.success) logAudit("QUEUE_FLUSH", ip, "Asked Postfix to retry the whole queue");
                    }
                    case "hold" -> {
                        result = queueManager.holdAll();
                        if (result.success) logAudit("QUEUE_HOLD", ip, "Put every queued message on hold");
                    }
                    case "release" -> {
                        result = queueManager.releaseAll();
                        if (result.success) logAudit("QUEUE_RELEASE", ip, "Released every held message");
                    }
                    case "purge_permfails" -> {
                        // First show WHAT would be deleted, then delete. Deleting mail is
                        // irreversible: a confirmation dialog that does not say how many and
                        // which messages it touches is not a confirmation, it is a button. The
                        // confirmation carries the identifiers seen and their number, typed by hand.
                        JSONArray ids = json.optJSONArray("ids");
                        if (ids == null) {
                            java.util.List<MailQueueManager.QueuedMessage> perm = queueManager.permanentFailures();
                            JSONArray list = new JSONArray();
                            for (MailQueueManager.QueuedMessage m : perm) list.put(queueMessageJson(m));
                            response.put("success", true).put("preview", true)
                                    .put("count", perm.size()).put("messages", list)
                                    .put("message", perm.isEmpty() ? I18n.tr("server.queue.noPermanent")
                                            : I18n.trn("server.queue.permanentPreview", perm.size(), Map.of()));
                            break;
                        }
                        java.util.List<String> confirmed = new java.util.ArrayList<>();
                        for (int i = 0; i < ids.length() && i < 10000; i++) confirmed.add(ids.optString(i, ""));
                        if (confirmed.isEmpty() || !String.valueOf(confirmed.size()).equals(json.optString("confirm", ""))) {
                            response.put("success", false).put("error", I18n.tr("server.queue.confirmMismatch"));
                            break;
                        }
                        result = queueManager.purgePermanentFailures(confirmed);
                        logAudit("QUEUE_PURGE_PERMFAILS", ip, result.count + " of " + confirmed.size()
                                + " confirmed messages deleted" + (result.success ? "" : ", some failed"));
                    }
                    default -> response.put("success", false).put("error", I18n.tr("server.queue.unknownAction"));
                }
                if (result != null) {
                    response.put("success", result.success);
                    response.put("message", result.message);
                }
            } else {
                sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
                return;
            }

        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Mail queue request failed", e);
            response = new JSONObject().put("success", false).put("error", I18n.tr("server.queue.unreadable"));
        }

        sendJsonResponse(exchange, response);
    }

    /** A queue message for the page: every field is text, the page passes it through escHtml. */
    private static JSONObject queueMessageJson(MailQueueManager.QueuedMessage msg) {
        JSONArray recipients = new JSONArray();
        for (MailQueueManager.Recipient r : msg.recipients) {
            recipients.put(new JSONObject().put("address", r.address()).put("reason", r.reason() == null ? "" : r.reason()));
        }
        String error = msg.errorReason();
        return new JSONObject()
                .put("id", msg.id)
                .put("state", msg.state.name())
                .put("sender", msg.sender == null ? "" : msg.sender)
                .put("recipients", recipients)
                .put("size", msg.size)
                .put("arrival", msg.arrival == null ? "" : msg.arrival.toString())
                .put("error", error == null ? "" : error)
                .put("permanent", msg.isPermanentFailure());
    }

    /** The five most frequent entries, in order. */
    private static JSONArray topFive(Map<String, Integer> counts) {
        JSONArray out = new JSONArray();
        counts.entrySet().stream()
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed().thenComparing(Map.Entry.comparingByKey()))
            .limit(5)
            .forEach(e -> out.put(new JSONObject().put("name", e.getKey()).put("count", e.getValue())));
        return out;
    }

    // ============== ROUNDCUBE SSO API ==============

    private void handleApiSso(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
            return;
        }

        if (ssoManager == null && Main.mailDatabase != null) {
            ssoManager = new RoundcubeSsoManager(Main.mailDatabase);
            ssoManager.setPanelPort(port);
        }

        String method = exchange.getRequestMethod();
        String query = exchange.getRequestURI().getQuery();
        JSONObject response = new JSONObject();

        try {
            if ("GET".equals(method)) {
                String action = extractParamFromQuery(query, "action");

                if ("status".equals(action)) {
                    // Get SSO status
                    RoundcubeSsoManager.SsoStatus status = ssoManager.getStatus();
                    response.put("success", true);
                    response.put("configured", status.configured);
                    response.put("roundcube_installed", status.roundcubeInstalled);
                    response.put("roundcube_path", status.roundcubePath);
                    response.put("plugin_installed", status.pluginInstalled);
                    response.put("plugin_path", status.pluginPath);
                    response.put("secret_configured", status.secretConfigured);
                    response.put("plugin_enabled", status.pluginEnabled);
                    response.put("roundcube_url", status.roundcubeUrl);
                    if (status.error != null) {
                        response.put("error", status.error);
                    }
                } else {
                    response.put("success", false);
                    response.put("error", I18n.tr("server.unknownAction"));
                }

            } else if ("POST".equals(method)) {
                String body = readRequestBodyWithLimit(exchange);
        if (body == null) {
            sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge"));
            return;
        }
                JSONObject json = new JSONObject(body);
                String action = json.optString("action", "");

                switch (action) {
                    case "install" -> {
                        RoundcubeSsoManager.InstallResult result = ssoManager.installPlugin();
                        response.put("success", result.success);
                        response.put("message", result.message);
                        if (result.pluginPath != null) {
                            response.put("plugin_path", result.pluginPath);
                        }
                        if (result.error != null) {
                            response.put("error", result.error);
                        }
                    }
                    case "uninstall" -> {
                        boolean success = ssoManager.uninstallPlugin();
                        response.put("success", success);
                        response.put("message", success ? "SSO plugin uninstalled" : "Failed to uninstall plugin");
                    }
                    case "set_url" -> {
                        String url = json.getString("url");
                        ssoManager.setRoundcubeUrl(url);
                        response.put("success", true);
                        response.put("message", I18n.tr("server.rcUrlUpdated"));
                    }
                    default -> {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.badActionNamed", Map.of("action", String.valueOf(action))));
                    }
                }
            }

        } catch (Exception e) {
            response.put("success", false);
            response.put("error", ErrorText.forPage("handleApiSso", e));
        }

        sendJsonResponse(exchange, response);
    }

    private void handleApiWebmailOpen(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
            return;
        }

        if (ssoManager == null && Main.mailDatabase != null) {
            ssoManager = new RoundcubeSsoManager(Main.mailDatabase);
            ssoManager.setPanelPort(port);
        }

        JSONObject response = new JSONObject();

        try {
            String body = readRequestBodyWithLimit(exchange);
            if (body == null) {
                sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge"));
                return;
            }
            JSONObject json = new JSONObject(body);
            String email = json.getString("email");

            // Get client IP for token binding (use CF-Connecting-IP if available)
            String clientIp = getClientIp(exchange);

            // Generate SSO token using master user (no password needed)
            RoundcubeSsoManager.SsoToken token = ssoManager.generateToken(email, clientIp);

            response.put("success", token.success);
            response.put("sso", token.success);
            if (token.success) {
                response.put("redirect_url", token.redirectUrl);
                response.put("expires_at", token.expiresAt);
            } else {
                response.put("error", token.error);
            }

        } catch (Exception e) {
            response.put("success", false);
            response.put("error", ErrorText.forPage("handleApiWebmailOpen", e));
        }

        sendJsonResponse(exchange, response);
    }

    // ============== FAIL2BAN API ==============

    private void handleApiFail2ban(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
            return;
        }

        if (fail2banManager == null) {
            fail2banManager = new Fail2banManager();
        }

        String method = exchange.getRequestMethod();
        String query = exchange.getRequestURI().getQuery();
        JSONObject response = new JSONObject();

        try {
            if ("GET".equals(method)) {
                String action = extractParamFromQuery(query, "action");

                if ("status".equals(action)) {
                    // Get overall status
                    Fail2banManager.Fail2banStatus status = fail2banManager.getStatus();
                    response.put("success", true);
                    response.put("installed", status.installed);
                    response.put("running", status.running);
                    response.put("total_banned", status.totalBanned);
                    response.put("total_banned_total", status.totalBannedTotal);

                    // Active jails
                    JSONArray jailsArray = new JSONArray();
                    for (String jail : status.activeJails) {
                        jailsArray.put(jail);
                    }
                    response.put("active_jails", jailsArray);

                    // Jail details
                    JSONArray jailDetails = new JSONArray();
                    for (Fail2banManager.JailStatus jail : status.jails) {
                        JSONObject jailJson = new JSONObject();
                        jailJson.put("name", jail.name);
                        jailJson.put("enabled", jail.enabled);
                        jailJson.put("currently_banned", jail.currentlyBanned);
                        jailJson.put("total_banned", jail.totalBanned);
                        jailJson.put("currently_failed", jail.currentlyFailed);
                        jailJson.put("total_failed", jail.totalFailed);
                        jailJson.put("ports", jail.ports);
                        jailJson.put("declared_port", jail.declaredPort);
                        jailJson.put("ban_uses_port", jail.banUsesPort);
                        jailJson.put("ban_command", jail.banCommand);
                        if (jail.logFile != null) jailJson.put("log", jail.logFile);

                        JSONArray bannedIps = new JSONArray();
                        for (String ip : jail.bannedIps) {
                            bannedIps.put(ip);
                        }
                        jailJson.put("banned_ips", bannedIps);
                        jailDetails.put(jailJson);
                    }
                    response.put("jails", jailDetails);

                    // Recent bans
                    JSONArray recentBans = new JSONArray();
                    for (Fail2banManager.BanEvent event : status.recentBans) {
                        JSONObject eventJson = new JSONObject();
                        eventJson.put("action", event.action());
                        eventJson.put("jail", event.jail());
                        eventJson.put("ip", event.ip());
                        if (event.timestamp() != null) {
                            eventJson.put("timestamp", event.timestamp().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
                        }
                        recentBans.put(eventJson);
                    }
                    response.put("recent_bans", recentBans);

                    if (status.error != null) {
                        response.put("error", status.error);
                    }

                } else if ("jail".equals(action)) {
                    // Get specific jail status
                    String jailName = extractParamFromQuery(query, "name");
                    if (jailName == null) {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.jailNameRequired"));
                    } else if (!org.daemoxcp.mail.security.InputValidator.isValidJailName(jailName)) {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.f2b.badJail"));
                    } else {
                        Fail2banManager.JailStatus jail = fail2banManager.getJailStatus(jailName);
                        response.put("success", jail.exists);
                        response.put("name", jail.name);
                        response.put("enabled", jail.enabled);
                        response.put("currently_banned", jail.currentlyBanned);
                        response.put("total_banned", jail.totalBanned);
                        response.put("currently_failed", jail.currentlyFailed);
                        response.put("total_failed", jail.totalFailed);

                        JSONArray bannedIps = new JSONArray();
                        for (String ip : jail.bannedIps) {
                            bannedIps.put(ip);
                        }
                        response.put("banned_ips", bannedIps);
                    }

                } else if ("live_state".equals(action)) {
                    // For ONE single jail: output of fail2ban-client get maxretry/findtime/bantime/...
                    // + fail2ban-client status <jail>. We return both the raw output and the parsed fields.
                    String jailName = extractParamFromQuery(query, "name");
                    if (jailName == null || !org.daemoxcp.mail.security.InputValidator.isValidJailName(jailName)) {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.f2b.badJail"));
                    } else {
                        Fail2banManager.JailLiveState s = fail2banManager.getJailLiveState(jailName);
                        response.put("success", s.success);
                        if (s.error != null) response.put("error", s.error);
                        fillJailLiveStateJson(response, s);
                    }

                } else if ("live_state_all".equals(action)) {
                    // For ALL the active jails: the live state of each one IN PARALLEL.
                    // With N jails, it used to take N * ~1s. Now ~1s in total, because
                    // all the jails are queried in parallel via virtual
                    // threads, and inside each one the 6 fail2ban-client get calls
                    // are parallel too.
                    Fail2banManager.Fail2banStatus overall = fail2banManager.getStatus();
                    response.put("success", true);
                    response.put("installed", overall.installed);
                    response.put("running", overall.running);
                    JSONArray arr = new JSONArray();
                    try (var exec = java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor()) {
                        java.util.List<java.util.concurrent.CompletableFuture<Fail2banManager.JailLiveState>> futures
                            = new java.util.ArrayList<>();
                        for (String jail : overall.activeJails) {
                            futures.add(java.util.concurrent.CompletableFuture.supplyAsync(
                                I18n.withCurrentSupplier(() -> fail2banManager.getJailLiveState(jail)), exec));
                        }
                        for (var f : futures) {
                            Fail2banManager.JailLiveState s = f.get(20, java.util.concurrent.TimeUnit.SECONDS);
                            JSONObject one = new JSONObject();
                            fillJailLiveStateJson(one, s);
                            arr.put(one);
                        }
                    }
                    response.put("jails", arr);

                } else if ("banned".equals(action)) {
                    // Get all banned IPs
                    java.util.List<Fail2banManager.BannedIp> banned = fail2banManager.getAllBannedIps();
                    response.put("success", true);
                    response.put("count", banned.size());

                    JSONArray bannedArray = new JSONArray();
                    for (Fail2banManager.BannedIp ban : banned) {
                        JSONObject banJson = new JSONObject();
                        banJson.put("ip", ban.ip());
                        banJson.put("jail", ban.jail());
                        banJson.put("active", ban.active());
                        bannedArray.put(banJson);
                    }
                    response.put("banned", bannedArray);

                } else if ("permaban_list".equals(action)) {
                    // Get permaban list (read-only, GET-friendly)
                    java.util.List<String> fileList = fail2banManager.listPermanentBans();
                    java.util.Set<String> runtimeSet = fail2banManager.listPermanentBanRuntime();
                    JSONArray arr = new JSONArray();
                    for (String ip : fileList) {
                        arr.put(new JSONObject()
                            .put("ip", ip)
                            .put("at_runtime", runtimeSet.contains(ip)));
                    }
                    response.put("success", true);
                    response.put("permabans", arr);
                    response.put("count", fileList.size());
                    response.put("runtime_count", runtimeSet.size());
                } else if ("ip_info".equals(action)) {
                    // Get IP whois info
                    String ip = extractParamFromQuery(query, "ip");
                    if (ip == null) {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.ipRequired"));
                    } else if (!org.daemoxcp.mail.security.InputValidator.isValidIp(ip)) {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.badIp"));
                    } else {
                        Fail2banManager.IpInfo info = fail2banManager.getIpInfo(ip);
                        response.put("success", info.found);
                        response.put("ip", info.ip);
                        response.put("country", info.country);
                        if (info.countryName != null) response.put("country_name", info.countryName);
                        if (info.region != null) response.put("region", info.region);
                        if (info.city != null) response.put("city", info.city);
                        response.put("organization", info.organization);
                        if (info.isp != null) response.put("isp", info.isp);
                        if (info.asn != null) response.put("asn", info.asn);
                        response.put("net_range", info.netRange);
                        if (info.latitude != null) response.put("latitude", info.latitude);
                        if (info.longitude != null) response.put("longitude", info.longitude);
                        if (info.geoSource != null) response.put("geo_source", info.geoSource);
                    }

                } else {
                    // Default: return status
                    Fail2banManager.Fail2banStatus status = fail2banManager.getStatus();
                    response.put("success", true);
                    response.put("installed", status.installed);
                    response.put("running", status.running);
                    response.put("total_banned", status.totalBanned);
                }

            } else if ("POST".equals(method)) {
                String body = readRequestBodyWithLimit(exchange);
        if (body == null) {
            sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge"));
            return;
        }
                JSONObject json = new JSONObject(body);
                String action = json.optString("action", "");

                switch (action) {
                    // Read-only: runs fail2ban-regex on the jail's log and says whether the
                    // filter matches anything. It tells "nobody attacked" apart from
                    // "the jail sees nothing", which on screen are the same zero.
                    case "verify_filter" -> {
                        String jail = json.optString("jail", "");
                        Fail2banManager.FilterCheck c = fail2banManager.verifyFilter(jail);
                        response.put("success", true)
                                .put("jail", c.jail).put("log", c.log)
                                .put("verified", c.verified).put("hooks", c.hooks)
                                .put("log_lines", c.logLines2).put("messageText", c.message)
                                .put("output", c.output);
                    }
                    // Read-only: compares the addresses Fail2ban believes are
                    // banned with the ones pf really blocks. "Currently banned" says that the
                    // ban command was run, not that the address is blocked.
                    case "pf_comparison" -> {
                        Fail2banManager.PfComparison c = fail2banManager.compareBansWithPf();
                        JSONArray jj = new JSONArray();
                        for (Fail2banManager.JailPf j : c.jails) {
                            jj.put(new JSONObject()
                                .put("jail", j.jail).put("anchor", j.anchor).put("table", j.table)
                                .put("read", j.read).put("missing_table", j.missingTable)
                                .put("rule_present", j.rulePresent)
                                .put("note", j.note)
                                .put("believed_banned", new JSONArray(j.believedBanned))
                                .put("in_firewall", new JSONArray(j.inFirewall))
                                .put("only_in_fail2ban", new JSONArray(j.onlyInFail2ban))
                                .put("only_in_pf", new JSONArray(j.onlyInPf))
                                .put("ban_commands", new JSONArray(j.banCommands))
                                .put("actions_output", j.actionsOutput)
                                .put("log", j.logFail2ban)
                                .put("sections", j.sections)
                                .put("dump", j.dump));
                        }
                        response.put("success", true).put("jails", jj)
                                .put("not_applied", c.totalNotApplied())
                                .put("unmeasured", c.totalUnmeasured())
                                .put("unverified_bans", c.unverifiedBans())
                                .put("without_rule", c.totalWithoutRule());
                    }
                    case "ban" -> {
                        String ip = json.getString("ip");
                        String jail = json.getString("jail");
                        // SECURITY: validate before passing them to the shell
                        if (!org.daemoxcp.mail.security.InputValidator.isValidIp(ip)) {
                            response.put("success", false);
                            response.put("message", I18n.tr("server.badIp"));
                            break;
                        }
                        if (!org.daemoxcp.mail.security.InputValidator.isValidJailName(jail)) {
                            response.put("success", false);
                            response.put("message", I18n.tr("server.f2b.badJail"));
                            break;
                        }
                        Fail2banManager.BanAction result = fail2banManager.banIp(ip, jail);
                        response.put("success", result.success);
                        response.put("message", result.message);
                        logAudit(result.success ? "FAIL2BAN_IP_BANNED" : "FAIL2BAN_BAN_FAILED",
                            getClientIp(exchange), "target_ip=" + ip + " jail=" + jail);
                    }
                    case "unban" -> {
                        String ip = json.getString("ip");
                        String jail = json.optString("jail", null);
                        if (!org.daemoxcp.mail.security.InputValidator.isValidIp(ip)) {
                            response.put("success", false);
                            response.put("message", I18n.tr("server.badIp"));
                            break;
                        }
                        if (jail != null && !jail.isEmpty() && !org.daemoxcp.mail.security.InputValidator.isValidJailName(jail)) {
                            response.put("success", false);
                            response.put("message", I18n.tr("server.f2b.badJail"));
                            break;
                        }
                        Fail2banManager.BanAction result;
                        if (jail != null && !jail.isEmpty()) {
                            result = fail2banManager.unbanIp(ip, jail);
                        } else {
                            result = fail2banManager.unbanIpFromAll(ip);
                        }
                        response.put("success", result.success);
                        response.put("message", result.message);
                        logAudit(result.success ? "FAIL2BAN_IP_UNBANNED" : "FAIL2BAN_UNBAN_FAILED",
                            getClientIp(exchange), "target_ip=" + ip + " jail=" + (jail != null ? jail : "ALL"));
                    }
                    case "reload" -> {
                        Fail2banManager.BanAction result = fail2banManager.reload();
                        response.put("success", result.success);
                        response.put("message", result.message);
                    }
                    case "start" -> {
                        Fail2banManager.BanAction result = fail2banManager.start();
                        response.put("success", result.success);
                        response.put("message", result.message);
                    }
                    case "stop" -> {
                        Fail2banManager.BanAction result = fail2banManager.stop();
                        response.put("success", result.success);
                        response.put("message", result.message);
                    }
                    case "install_mail_jails" -> {
                        Fail2banManager.InstallResult result = fail2banManager.installMailJails();
                        response.put("success", result.success);
                        response.put("message", result.message);
                        if (result.configPath != null) {
                            response.put("config_path", result.configPath);
                        }
                        if (result.error != null) {
                            response.put("error", result.error);
                        }
                    }
                    case "update_jail_config" -> {
                        String jailName = json.getString("jail");
                        // SECURITY: validate jail name (concatenated into a shell command)
                        if (!org.daemoxcp.mail.security.InputValidator.isValidJailName(jailName)) {
                            response.put("success", false);
                            response.put("message", I18n.tr("server.f2b.badJail"));
                            break;
                        }
                        int maxRetry = json.optInt("max_retry", 5);
                        int findTime = json.optInt("find_time", 600);
                        int banTime = json.optInt("ban_time", 3600);
                        // Sane ranges to avoid nonsense config
                        if (maxRetry < 1 || maxRetry > 100 ||
                            findTime < 30 || findTime > 86400 ||
                            banTime  < 60 || banTime  > 31_536_000) {
                            response.put("success", false);
                            response.put("message", I18n.tr("server.f2b.outOfRange"));
                            break;
                        }
                        Fail2banManager.BanAction result = fail2banManager.updateJailConfig(jailName, maxRetry, findTime, banTime);
                        response.put("success", result.success);
                        response.put("message", result.message);
                        logAudit(result.success ? "FAIL2BAN_JAIL_UPDATED" : "FAIL2BAN_JAIL_UPDATE_FAILED",
                            getClientIp(exchange),
                            "jail=" + jailName + " maxRetry=" + maxRetry + " findTime=" + findTime + " banTime=" + banTime);
                    }
                    case "update_all_jails_config" -> {
                        int maxRetry = json.optInt("max_retry", 5);
                        int findTime = json.optInt("find_time", 600);
                        int banTime  = json.optInt("ban_time", 3600);
                        if (maxRetry < 1 || maxRetry > 100 ||
                            findTime < 30 || findTime > 86400 ||
                            banTime  < 60 || banTime  > 31_536_000) {
                            response.put("success", false);
                            response.put("message", I18n.tr("server.f2b.outOfRange"));
                            break;
                        }
                        Fail2banManager.BulkJailConfigResult bulk =
                            fail2banManager.updateAllJailsConfig(maxRetry, findTime, banTime);
                        response.put("success", bulk.success);
                        response.put("success_count", bulk.successCount);
                        response.put("fail_count", bulk.failCount);
                        if (bulk.error != null) response.put("error", bulk.error);
                        JSONArray jarr = new JSONArray();
                        for (Fail2banManager.JailConfigOutcome o : bulk.results) {
                            JSONObject jo = new JSONObject();
                            jo.put("jail", o.jail());
                            jo.put("success", o.success());
                            jo.put("message", o.message());
                            jarr.put(jo);
                        }
                        response.put("results", jarr);
                        response.put("message", bulk.error != null
                            ? bulk.error
                            : (I18n.tr("server.f2b.appliedTo", Map.of("n", bulk.successCount))
                               + (bulk.failCount > 0 ? " " + I18n.tr("server.f2b.errors", Map.of("n", bulk.failCount)) : "")));
                        logAudit(bulk.success ? "FAIL2BAN_ALL_JAILS_UPDATED" : "FAIL2BAN_ALL_JAILS_UPDATE_PARTIAL",
                            getClientIp(exchange),
                            "maxRetry=" + maxRetry + " findTime=" + findTime + " banTime=" + banTime
                            + " ok=" + bulk.successCount + " fail=" + bulk.failCount);
                    }
                    case "permaban_add" -> {
                        String ip = json.optString("ip", "");
                        if (!org.daemoxcp.mail.security.InputValidator.isValidIp(ip)) {
                            response.put("success", false);
                            response.put("message", I18n.tr("server.badIp"));
                            break;
                        }
                        try {
                            boolean added = fail2banManager.addPermanentBan(ip);
                            response.put("success", true);
                            response.put("added", added);
                            response.put("message", I18n.tr(added ? "server.f2b.permabanAdded" : "server.f2b.permabanPresent"));
                            logAudit(added ? "PERMABAN_ADDED" : "PERMABAN_ALREADY_PRESENT",
                                getClientIp(exchange), "target_ip=" + ip);
                            // Also unban from all the Fail2ban jails (the user might already be temporarily banned)
                            try { fail2banManager.unbanIpFromAll(ip); } catch (Exception ignored) {}
                        } catch (Exception e) {
                            response.put("success", false);
                            response.put("message", ErrorText.forPage("handleApiFail2ban", e));
                        }
                    }
                    case "permaban_remove" -> {
                        String ip = json.optString("ip", "");
                        if (!org.daemoxcp.mail.security.InputValidator.isValidIp(ip)) {
                            response.put("success", false);
                            response.put("message", I18n.tr("server.badIp"));
                            break;
                        }
                        try {
                            boolean removed = fail2banManager.removePermanentBan(ip);
                            response.put("success", true);
                            response.put("removed", removed);
                            response.put("message", I18n.tr(removed ? "server.f2b.permabanRemoved" : "server.f2b.permabanAbsent"));
                            logAudit(removed ? "PERMABAN_REMOVED" : "PERMABAN_NOT_FOUND",
                                getClientIp(exchange), "target_ip=" + ip);
                        } catch (Exception e) {
                            response.put("success", false);
                            response.put("message", ErrorText.forPage("handleApiFail2ban", e));
                        }
                    }
                    case "permaban_list" -> {
                        java.util.List<String> fileList = fail2banManager.listPermanentBans();
                        java.util.Set<String> runtimeSet = fail2banManager.listPermanentBanRuntime();
                        JSONArray arr = new JSONArray();
                        for (String ip : fileList) {
                            arr.put(new JSONObject()
                                .put("ip", ip)
                                .put("at_runtime", runtimeSet.contains(ip)));
                        }
                        response.put("success", true);
                        response.put("permabans", arr);
                        response.put("count", fileList.size());
                        response.put("runtime_count", runtimeSet.size());
                    }
                    case "permaban_reload" -> {
                        boolean ok = fail2banManager.reloadPermanentBanFromFile();
                        response.put("success", ok);
                        response.put("message", ok
                            ? I18n.tr("server.f2b.permabanReloaded")
                            : I18n.tr("server.f2b.permabanReloadFailed"));
                        logAudit(ok ? "PERMABAN_RELOADED" : "PERMABAN_RELOAD_FAILED",
                            getClientIp(exchange), "");
                    }
                    case "get_jail_config" -> {
                        String jailName = json.getString("jail");
                        if (!org.daemoxcp.mail.security.InputValidator.isValidJailName(jailName)) {
                            response.put("success", false);
                            response.put("message", I18n.tr("server.f2b.badJail"));
                            break;
                        }
                        Fail2banManager.JailConfig cfg = fail2banManager.getJailConfig(jailName);
                        if (cfg == null || !cfg.found) {
                            response.put("success", false);
                            response.put("message", I18n.tr("server.f2b.jailNotFound"));
                        } else {
                            response.put("success", true);
                            response.put("jail", cfg.name);
                            response.put("max_retry", cfg.maxRetry);
                            response.put("find_time", cfg.findTime);
                            response.put("ban_time", cfg.banTime);
                            response.put("enabled", cfg.enabled);
                            response.put("filter", cfg.filter == null ? "" : cfg.filter);
                            response.put("logpath", cfg.logpath == null ? "" : cfg.logpath);
                            // List of the ignoreip entries at runtime (more reliable than from the file)
                            JSONArray ignArr = new JSONArray();
                            for (String s : fail2banManager.getIgnoreIps(jailName)) ignArr.put(s);
                            response.put("ignoreip", ignArr);
                        }
                    }
                    case "set_jail_filter" -> {
                        String jailName = json.getString("jail");
                        String filter = json.optString("filter", "");
                        if (!org.daemoxcp.mail.security.InputValidator.isValidJailName(jailName)) {
                            response.put("success", false);
                            response.put("message", I18n.tr("server.f2b.badJail"));
                            break;
                        }
                        Fail2banManager.BanAction r = fail2banManager.setJailFilter(jailName, filter);
                        response.put("success", r.success);
                        response.put("message", r.message);
                        logAudit(r.success ? "FAIL2BAN_FILTER_CHANGED" : "FAIL2BAN_FILTER_CHANGE_FAILED",
                            getClientIp(exchange),
                            "jail=" + jailName + " filter=" + filter);
                    }
                    case "add_jail_ignoreip" -> {
                        String jailName = json.getString("jail");
                        String ip = json.optString("ip", "").trim();
                        if (!org.daemoxcp.mail.security.InputValidator.isValidJailName(jailName)) {
                            response.put("success", false);
                            response.put("message", I18n.tr("server.f2b.badJail"));
                            break;
                        }
                        Fail2banManager.BanAction r = fail2banManager.addIgnoreIp(jailName, ip);
                        response.put("success", r.success);
                        response.put("message", r.message);
                        logAudit(r.success ? "FAIL2BAN_IGNOREIP_ADDED" : "FAIL2BAN_IGNOREIP_ADD_FAILED",
                            getClientIp(exchange),
                            "jail=" + jailName + " ip=" + ip);
                    }
                    case "remove_jail_ignoreip" -> {
                        String jailName = json.getString("jail");
                        String ip = json.optString("ip", "").trim();
                        if (!org.daemoxcp.mail.security.InputValidator.isValidJailName(jailName)) {
                            response.put("success", false);
                            response.put("message", I18n.tr("server.f2b.badJail"));
                            break;
                        }
                        Fail2banManager.BanAction r = fail2banManager.removeIgnoreIp(jailName, ip);
                        response.put("success", r.success);
                        response.put("message", r.message);
                        logAudit(r.success ? "FAIL2BAN_IGNOREIP_REMOVED" : "FAIL2BAN_IGNOREIP_REMOVE_FAILED",
                            getClientIp(exchange),
                            "jail=" + jailName + " ip=" + ip);
                    }
                    default -> {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.badActionNamed", Map.of("action", String.valueOf(action))));
                    }
                }
            }

        } catch (Exception e) {
            response.put("success", false);
            response.put("error", ErrorText.forPage("handleApiFail2ban", e));
        }

        sendJsonResponse(exchange, response);
    }

    // ============== FAIL2BAN HEALTH CHECK ==============

    /** Endpoint for Fail2ban diagnosis and automatic setup. */
    // ============== UNBOUND HEALTH CHECK (Resolver DNS locale) ==============
    // ============== FIREWALL API ==============

    /**
     * Endpoint /api/firewall -- pf firewall management with CIDR + GeoIP.
     *
     * GET  /api/firewall                -> returns the current state (mode, lists, selected countries,
     *                                     size of the pf tables at runtime, country catalogue)
     * POST /api/firewall  action=...    -> mutations
     *      Supported actions:
     *        - set_mode           {mode: DISABLED|CIDR_ONLY|GEO_WHITELIST|GEO_BLACKLIST}
     *        - set_port25_geo     {value: true|false}    (applies geo to port 25 too)
     *        - add_cidr_wl        {cidr: "..."}
     *        - remove_cidr_wl     {cidr: "..."}
     *        - add_cidr_bl        {cidr: "..."}
     *        - remove_cidr_bl     {cidr: "..."}
     *        - add_country        {country: "it"}
     *        - remove_country     {country: "it"}
     *        - sync_geo           {country: "it"}        (downloads the zone file from ipdeny)
     *        - sync_geo_all       (downloads the zone files for all the selected countries)
     *        - apply              (regenerates the anchor + syntax check + loads it into the kernel)
     */
    private void handleApiFirewall(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) { sendJsonError(exchange, 401, I18n.tr("server.unauthorized")); return; }
        if (firewallManager == null) {
            firewallManager = new org.daemoxcp.mail.security.PfFirewallManager();
        }
        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();
        try {
            if ("GET".equals(method)) {
                response = buildFirewallStatusJson();
            } else if ("POST".equals(method)) {
                String body = readRequestBodyWithLimit(exchange);
                if (body == null) { sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge")); return; }
                JSONObject req = new JSONObject(body);
                if (!validateCsrfForRequest(exchange, req)) { sendCsrfError(exchange); return; }
                String action = req.optString("action", "");
                String clientIp = getClientIp(exchange);

                switch (action) {
                    case "set_mode" -> {
                        String modeStr = req.optString("mode", "CIDR_ONLY");
                        try {
                            org.daemoxcp.mail.security.PfFirewallManager.Mode m =
                                org.daemoxcp.mail.security.PfFirewallManager.Mode.valueOf(modeStr);
                            firewallManager.setMode(m);
                            response.put("success", true);
                            response.put("message", I18n.tr("server.fw.modeSet", Map.of("mode", String.valueOf(m))));
                            logAudit("FW_MODE_CHANGED", clientIp, "mode=" + m);
                        } catch (IllegalArgumentException e) {
                            response.put("success", false);
                            response.put("error", I18n.tr("server.fw.badMode", Map.of("mode", modeStr)));
                        }
                    }
                    case "set_port25_geo" -> {
                        boolean v = req.optBoolean("value", false);
                        firewallManager.setApplyGeoToPort25(v);
                        response.put("success", true);
                        response.put("message", I18n.tr(v ? "server.fw.geo25On" : "server.fw.geo25Off"));
                        logAudit("FW_PORT25_GEO_TOGGLED", clientIp, "value=" + v);
                    }
                    case "add_cidr_wl" -> {
                        String cidr = req.optString("cidr", "").trim();
                        boolean ok = firewallManager.addCidrWhitelist(cidr);
                        response.put("success", ok);
                        response.put("message", ok ? I18n.tr("server.fw.whitelistAdded", Map.of("cidr", cidr))
                                                   : I18n.tr("server.fw.cidrInvalidOrPresent"));
                        if (ok) logAudit("FW_CIDR_WL_ADD", clientIp, "cidr=" + cidr);
                    }
                    case "remove_cidr_wl" -> {
                        String cidr = req.optString("cidr", "").trim();
                        boolean ok = firewallManager.removeCidrWhitelist(cidr);
                        response.put("success", ok);
                        response.put("message", ok ? I18n.tr("server.fw.whitelistRemoved", Map.of("cidr", cidr)) : I18n.tr("server.fw.notPresent"));
                        if (ok) logAudit("FW_CIDR_WL_REMOVE", clientIp, "cidr=" + cidr);
                    }
                    case "add_cidr_bl" -> {
                        String cidr = req.optString("cidr", "").trim();
                        boolean ok = firewallManager.addCidrBlacklist(cidr);
                        response.put("success", ok);
                        response.put("message", ok ? I18n.tr("server.fw.blacklistAdded", Map.of("cidr", cidr))
                                                   : I18n.tr("server.fw.cidrInvalidOrPresent"));
                        if (ok) logAudit("FW_CIDR_BL_ADD", clientIp, "cidr=" + cidr);
                    }
                    case "remove_cidr_bl" -> {
                        String cidr = req.optString("cidr", "").trim();
                        boolean ok = firewallManager.removeCidrBlacklist(cidr);
                        response.put("success", ok);
                        response.put("message", ok ? I18n.tr("server.fw.blacklistRemoved", Map.of("cidr", cidr)) : I18n.tr("server.fw.notPresent"));
                        if (ok) logAudit("FW_CIDR_BL_REMOVE", clientIp, "cidr=" + cidr);
                    }
                    case "add_country" -> {
                        String cc = req.optString("country", "").trim().toLowerCase();
                        boolean ok = firewallManager.addGeoCountry(cc);
                        response.put("success", ok);
                        response.put("message", ok ? I18n.tr("server.fw.countryAdded", Map.of("cc", cc)) : I18n.tr("server.fw.codeInvalidOrPresent"));
                        if (ok) logAudit("FW_COUNTRY_ADD", clientIp, "cc=" + cc);
                    }
                    case "remove_country" -> {
                        String cc = req.optString("country", "").trim().toLowerCase();
                        boolean ok = firewallManager.removeGeoCountry(cc);
                        response.put("success", ok);
                        response.put("message", ok ? I18n.tr("server.fw.countryRemoved", Map.of("cc", cc)) : I18n.tr("server.fw.notPresent"));
                        if (ok) logAudit("FW_COUNTRY_REMOVE", clientIp, "cc=" + cc);
                    }
                    case "bulk_add_countries" -> {
                        JSONArray arr = req.optJSONArray("countries");
                        java.util.List<String> codes = new java.util.ArrayList<>();
                        if (arr != null) for (int i = 0; i < arr.length(); i++) codes.add(arr.getString(i));
                        int added = firewallManager.bulkAddCountries(codes);
                        response.put("success", true);
                        response.put("added", added);
                        response.put("total_requested", codes.size());
                        response.put("message", I18n.tr("server.fw.countriesAdded", Map.of("n", added, "requested", codes.size())));
                        logAudit("FW_BULK_COUNTRY_ADD", clientIp, "added=" + added + " requested=" + codes.size());
                    }
                    case "bulk_remove_countries" -> {
                        JSONArray arr = req.optJSONArray("countries");
                        java.util.List<String> codes = new java.util.ArrayList<>();
                        if (arr != null) for (int i = 0; i < arr.length(); i++) codes.add(arr.getString(i));
                        int removed = firewallManager.bulkRemoveCountries(codes);
                        response.put("success", true);
                        response.put("removed", removed);
                        response.put("message", I18n.tr("server.fw.countriesRemoved", Map.of("n", removed)));
                        logAudit("FW_BULK_COUNTRY_REMOVE", clientIp, "removed=" + removed);
                    }
                    case "clear_countries" -> {
                        int n = firewallManager.clearCountries();
                        response.put("success", true);
                        response.put("removed", n);
                        response.put("message", I18n.tr("server.fw.countriesCleared", Map.of("n", n)));
                        logAudit("FW_CLEAR_COUNTRIES", clientIp, "removed=" + n);
                    }
                    case "set_auto_sync" -> {
                        boolean enabled = req.optBoolean("enabled", false);
                        int interval = Math.max(1, Math.min(req.optInt("interval_days", 7), 365));
                        firewallManager.setAutoSync(enabled, interval);
                        response.put("success", true);
                        response.put("message", I18n.tr(enabled ? "server.fw.autosyncOn" : "server.fw.autosyncOff", Map.of("days", interval)));
                        logAudit("FW_AUTOSYNC_SET", clientIp, "enabled=" + enabled + " interval=" + interval);
                    }
                    case "apply_preset_group" -> {
                        String groupId = req.optString("group_id", "");
                        org.daemoxcp.mail.security.CountryCatalog.CountryGroup grp = null;
                        for (var g : org.daemoxcp.mail.security.CountryCatalog.getGroups()) {
                            if (g.id().equals(groupId)) { grp = g; break; }
                        }
                        if (grp == null) {
                            response.put("success", false);
                            response.put("error", I18n.tr("server.fw.unknownPreset", Map.of("group", groupId)));
                        } else {
                            // Completely replaces the current selection with the group's one
                            firewallManager.clearCountries();
                            int added = firewallManager.bulkAddCountries(grp.codes());
                            response.put("success", true);
                            response.put("group", groupId);
                            response.put("added", added);
                            response.put("message", I18n.tr("server.fw.presetApplied", Map.of("group", groupId, "n", added)));
                            logAudit("FW_PRESET_APPLIED", clientIp, "group=" + groupId + " added=" + added);
                        }
                    }
                    case "sync_geo" -> {
                        String cc = req.optString("country", "").trim().toLowerCase();
                        org.daemoxcp.mail.security.PfFirewallManager.SyncResult sr = firewallManager.syncCountry(cc);
                        response.put("success", sr.success);
                        response.put("message", sr.success ? sr.message : I18n.tr("server.errorWith", Map.of("error", String.valueOf(sr.error))));
                        response.put("country", sr.country);
                        response.put("cidr_count", sr.cidrCount);
                        logAudit(sr.success ? "FW_GEO_SYNC_OK" : "FW_GEO_SYNC_FAIL", clientIp,
                            "cc=" + cc + " count=" + sr.cidrCount);
                    }
                    case "sync_geo_all" -> {
                        java.util.List<org.daemoxcp.mail.security.PfFirewallManager.SyncResult> results =
                            firewallManager.syncAllSelectedCountries();
                        JSONArray arr = new JSONArray();
                        int ok = 0;
                        for (var sr : results) {
                            arr.put(new JSONObject()
                                .put("country", sr.country)
                                .put("success", sr.success)
                                .put("cidr_count", sr.cidrCount)
                                .put("message", sr.success ? sr.message : sr.error));
                            if (sr.success) ok++;
                        }
                        response.put("success", ok == results.size());
                        response.put("results", arr);
                        response.put("message", I18n.tr("server.fw.synced", Map.of("ok", ok, "total", results.size())));
                        logAudit("FW_GEO_SYNC_ALL", clientIp, "ok=" + ok + "/" + results.size());
                    }
                    case "apply" -> {
                        org.daemoxcp.mail.security.PfFirewallManager.ApplyResult ar =
                            firewallManager.applyConfiguration();
                        response.put("success", ar.success);
                        response.put("message", ar.message);
                        if (ar.backupPath != null) response.put("backup_path", ar.backupPath);
                        if (ar.anchorContent != null) response.put("anchor_content", ar.anchorContent);
                        logAudit(ar.success ? "FW_APPLY_OK" : "FW_APPLY_FAIL", clientIp, ar.message);
                    }
                    default -> {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.badActionNamed", Map.of("action", action)));
                    }
                }
            }
            sendJsonResponse(exchange, response);
        } catch (Exception e) {
            sendJsonError(exchange, 500, I18n.tr("server.internalErrorWith", Map.of("error", ErrorText.detail("handleApiFirewall", e))));
        }
    }

    /** Builds the status JSON for /api/firewall GET. */
    private JSONObject buildFirewallStatusJson() {
        JSONObject out = new JSONObject();
        org.daemoxcp.mail.security.PfFirewallManager.FirewallState s = firewallManager.getState();
        out.put("success", true);
        out.put("mode", s.mode.name());
        out.put("enabled", s.enabled);
        out.put("apply_geo_to_port25", s.applyGeoToPort25);
        out.put("whitelist_cidrs", new JSONArray(s.whitelistCidrs));
        out.put("blacklist_cidrs", new JSONArray(s.blacklistCidrs));
        out.put("geo_countries", new JSONArray(s.geoCountries));

        // For each selected country: last sync + number of CIDRs + freshness
        JSONArray geoDetail = new JSONArray();
        for (String cc : s.geoCountries) {
            JSONObject c = new JSONObject();
            c.put("code", cc);
            c.put("cidr_count", firewallManager.getCountryCidrCount(cc));
            Long last = s.geoLastSync.get(cc);
            long lastMs = last == null ? 0L : last;
            c.put("last_sync_ms", lastMs);
            org.daemoxcp.mail.security.PfFirewallManager.Freshness fresh =
                org.daemoxcp.mail.security.PfFirewallManager.computeFreshness(lastMs, s.autoSyncIntervalDays);
            c.put("freshness", fresh.name());
            // ago_seconds: useful for the UI ("3 days ago")
            c.put("ago_seconds", lastMs > 0 ? (System.currentTimeMillis() - lastMs) / 1000 : 0);
            org.daemoxcp.mail.security.CountryCatalog.Country meta =
                org.daemoxcp.mail.security.CountryCatalog.byCode(cc);
            if (meta != null) {
                c.put("name", meta.localName());
                c.put("flag", meta.flag());
            }
            geoDetail.put(c);
        }
        out.put("geo_detail", geoDetail);

        // Auto-sync settings + statistics
        JSONObject autoSync = new JSONObject();
        autoSync.put("enabled", s.autoSyncEnabled);
        autoSync.put("interval_days", s.autoSyncIntervalDays);
        autoSync.put("last_check_ms", s.lastAutoSyncCheck);
        autoSync.put("last_run_ms", s.lastAutoSyncRun);
        // Count stale countries (needing an update)
        int staleCount = 0;
        for (String cc : s.geoCountries) {
            long lm = s.geoLastSync.getOrDefault(cc, 0L);
            org.daemoxcp.mail.security.PfFirewallManager.Freshness f =
                org.daemoxcp.mail.security.PfFirewallManager.computeFreshness(lm, s.autoSyncIntervalDays);
            if (f != org.daemoxcp.mail.security.PfFirewallManager.Freshness.FRESH) staleCount++;
        }
        autoSync.put("stale_countries_count", staleCount);
        out.put("auto_sync", autoSync);

        // pf tables at runtime
        java.util.Map<String, Integer> sizes = firewallManager.getTableSizes();
        JSONObject tableSizes = new JSONObject();
        sizes.forEach(tableSizes::put);
        out.put("table_sizes", tableSizes);

        // Country catalog (for the UI)
        out.put("country_catalog", org.daemoxcp.mail.security.CountryCatalog.toJsonArray());

        // Preset groups (EU, G7, `NATO`, etc.) for the UI
        out.put("preset_groups", org.daemoxcp.mail.security.CountryCatalog.groupsToJsonArray());

        return out;
    }

    private void handleApiUnboundHealth(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) { sendJsonError(exchange, 401, I18n.tr("server.unauthorized")); return; }
        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();
        try {
            if ("GET".equals(method)) {
                response = buildUnboundHealthReport();
            } else if ("POST".equals(method)) {
                String body = readRequestBodyWithLimit(exchange);
                if (body == null) { sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge")); return; }
                JSONObject req = new JSONObject(body);
                if (!validateCsrfForRequest(exchange, req)) { sendCsrfError(exchange); return; }
                String action = req.optString("action", "");
                String clientIp = getClientIp(exchange);
                switch (action) {
                    case "install_unbound" -> {
                        JSONObject r = installUnbound();
                        response = r;
                        logAudit(r.optBoolean("success") ? "UNBOUND_INSTALLED" : "UNBOUND_INSTALL_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "configure_unbound" -> {
                        JSONObject r = writeUnboundConfig();
                        response = r;
                        logAudit(r.optBoolean("success") ? "UNBOUND_CONFIGURED" : "UNBOUND_CONFIGURE_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "enable_unbound_at_boot" -> {
                        JSONObject r = sysrcSet("unbound_enable", "YES");
                        response = r;
                        logAudit(r.optBoolean("success") ? "UNBOUND_ENABLED_AT_BOOT" : "UNBOUND_ENABLE_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "start_unbound" -> {
                        JSONObject r = serviceCommand("unbound", "start", 30);
                        response = r;
                        logAudit(r.optBoolean("success") ? "UNBOUND_STARTED" : "UNBOUND_START_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "enable_local_unbound_at_boot" -> {
                        JSONObject r = sysrcSet("local_unbound_enable", "YES");
                        response = r;
                        logAudit(r.optBoolean("success") ? "LOCAL_UNBOUND_ENABLED_AT_BOOT" : "LOCAL_UNBOUND_ENABLE_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "start_local_unbound" -> {
                        JSONObject r = serviceCommand("local_unbound", "start", 30);
                        response = r;
                        logAudit(r.optBoolean("success") ? "LOCAL_UNBOUND_STARTED" : "LOCAL_UNBOUND_START_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "switch_resolv_conf" -> {
                        JSONObject r = switchResolvConfToUnbound();
                        response = r;
                        logAudit(r.optBoolean("success") ? "RESOLV_CONF_SWITCHED" : "RESOLV_CONF_SWITCH_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "test_query" -> {
                        JSONObject r = testUnboundQuery();
                        response = r;
                        logAudit(r.optBoolean("success") ? "UNBOUND_TEST_OK" : "UNBOUND_TEST_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "fix_all" -> {
                        JSONObject r = runUnboundFixAll();
                        response = r;
                        logAudit(r.optBoolean("success") ? "UNBOUND_FIX_ALL_OK" : "UNBOUND_FIX_ALL_PARTIAL",
                            clientIp, r.optString("message", ""));
                    }
                    case "disable_forwarder" -> {
                        JSONObject r = disableUnboundForwarder();
                        response = r;
                        logAudit(r.optBoolean("success") ? "UNBOUND_FORWARDER_DISABLED" : "UNBOUND_FORWARDER_DISABLE_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "rollback_resolv_conf" -> {
                        JSONObject r = rollbackResolvConf();
                        response = r;
                        logAudit(r.optBoolean("success") ? "RESOLV_CONF_ROLLBACK_OK" : "RESOLV_CONF_ROLLBACK_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    default -> {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.badActionNamed", Map.of("action", action)));
                    }
                }
            } else {
                sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
                return;
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", ErrorText.forPage("handleApiUnboundHealth", e));
        }
        sendJsonResponse(exchange, response);
    }

    private static final String UNBOUND_CONF_PATH = "/usr/local/etc/unbound/unbound.conf";

    private static final String UNBOUND_CONF_CONTENT = ""
        + "# /usr/local/etc/unbound/unbound.conf\n"
        + "# Generated by DaemoxCP Mail: LOCAL DNS resolver for this server\n"
        + "# Listens ONLY on 127.0.0.1, not reachable from the internet\n"
        + "\n"
        + "server:\n"
        + "    # Loopback only (security: invisible from outside)\n"
        + "    interface: 127.0.0.1\n"
        + "    interface: ::1\n"
        + "    port: 53\n"
        + "    do-ip4: yes\n"
        + "    do-ip6: yes\n"
        + "    do-udp: yes\n"
        + "    do-tcp: yes\n"
        + "\n"
        + "    # Only localhost may query\n"
        + "    access-control: 127.0.0.0/8 allow\n"
        + "    access-control: ::1 allow\n"
        + "    access-control: 0.0.0.0/0 refuse\n"
        + "    access-control: ::/0 refuse\n"
        + "\n"
        + "    # Privacy and security\n"
        + "    hide-identity: yes\n"
        + "    hide-version: yes\n"
        + "    harden-glue: yes\n"
        + "    harden-dnssec-stripped: yes\n"
        + "    use-caps-for-id: yes\n"
        + "\n"
        + "    # Performance\n"
        + "    num-threads: 2\n"
        + "    cache-min-ttl: 300\n"
        + "    cache-max-ttl: 86400\n"
        + "    prefetch: yes\n"
        + "    prefetch-key: yes\n"
        + "\n"
        + "    # Logging\n"
        + "    use-syslog: yes\n"
        + "    verbosity: 1\n"
        + "\n"
        + "    # Allow private addresses in answers (needed by some DNSBLs)\n"
        + "    private-address: 192.168.0.0/16\n"
        + "    private-address: 10.0.0.0/8\n"
        + "    private-address: 172.16.0.0/12\n"
        + "    private-address: 169.254.0.0/16\n"
        + "    private-address: fd00::/8\n"
        + "    private-address: fe80::/10\n";

    private JSONObject buildUnboundHealthReport() {
        JSONObject r = new JSONObject();
        JSONArray checks = new JSONArray();

        // 1. Local resolver available (unbound pkg OR local_unbound from the base system)
        //    On FreeBSD there is 'local_unbound' in the base system: same effect, already installed by default.
        boolean pkgInstalled;
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/pkg", "info", "-e", "unbound");
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            pkgInstalled = p.exitValue() == 0;
        } catch (Exception e) { pkgInstalled = false; }

        boolean baseUnboundAvailable = java.nio.file.Files.exists(java.nio.file.Paths.get("/usr/sbin/local-unbound"));
        boolean baseUnboundRunning = isServiceRunning("local_unbound");
        boolean installed = pkgInstalled || baseUnboundAvailable;

        String installedStatus;
        if (pkgInstalled && baseUnboundRunning) installedStatus = I18n.tr("server.unbound.statusBoth");
        else if (pkgInstalled) installedStatus = I18n.tr("server.unbound.statusPkg");
        else if (baseUnboundRunning) installedStatus = I18n.tr("server.unbound.statusBaseRunning");
        else if (baseUnboundAvailable) installedStatus = I18n.tr("server.unbound.statusBaseStopped");
        else installedStatus = I18n.tr("server.unbound.statusNone");

        checks.put(makeCheck("unbound-installed", I18n.tr("server.unbound.checkInstalled"), installed,
            installedStatus,
            installed ? null : I18n.tr("server.unbound.impactInstalled"),
            installed ? null : "install_unbound",
            I18n.tr("server.unbound.fixInstalled")));

        // 2. Config file: only if you use the pkg package, not needed for local_unbound (config in /var/unbound/)
        boolean confPresent = java.nio.file.Files.exists(java.nio.file.Paths.get(UNBOUND_CONF_PATH));
        boolean baseConfPresent = java.nio.file.Files.exists(java.nio.file.Paths.get("/var/unbound/unbound.conf"));
        boolean confValid = false;
        if (confPresent) {
            try {
                String c = java.nio.file.Files.readString(java.nio.file.Paths.get(UNBOUND_CONF_PATH));
                confValid = c.contains("interface: 127.0.0.1") && c.contains("access-control");
            } catch (Exception ignored) {}
        }
        // If local_unbound is already active, consider the config "OK" even without the pkg file
        boolean configOk = confValid || baseConfPresent || baseUnboundRunning;
        String configStatus;
        if (confValid) configStatus = UNBOUND_CONF_PATH + " (pkg unbound)";
        else if (baseConfPresent) configStatus = "/var/unbound/unbound.conf (local_unbound base system)";
        else if (baseUnboundRunning) configStatus = I18n.tr("server.unbound.configAuto");
        else if (confPresent) configStatus = I18n.tr("server.unbound.configInvalid");
        else configStatus = I18n.tr("server.unbound.configNone");
        checks.put(makeCheck("unbound-config", I18n.tr("server.unbound.checkConfig"),
            configOk,
            configStatus,
            configOk ? null : I18n.tr("server.unbound.impactConfig"),
            (configOk || !installed || baseUnboundAvailable) ? null : "configure_unbound",
            I18n.tr("server.unbound.fixConfig", Map.of("path", UNBOUND_CONF_PATH))));

        // 3. Enabled at boot -- check both unbound_enable and local_unbound_enable
        boolean unboundEnabledBoot = isSysrcYes("unbound_enable");
        boolean localUnboundEnabledBoot = isSysrcYes("local_unbound_enable");
        boolean enabledBoot = unboundEnabledBoot || localUnboundEnabledBoot;
        String bootStatus;
        if (unboundEnabledBoot && localUnboundEnabledBoot) bootStatus = "unbound_enable + local_unbound_enable=YES";
        else if (unboundEnabledBoot) bootStatus = "unbound_enable=YES (pkg)";
        else if (localUnboundEnabledBoot) bootStatus = "local_unbound_enable=YES (base system)";
        else bootStatus = I18n.tr("server.unbound.bootNone");
        // Appropriate fix: if the base system one exists, enable that, otherwise pkg
        String bootFixAction = enabledBoot ? null : (baseUnboundAvailable && !pkgInstalled ? "enable_local_unbound_at_boot" : "enable_unbound_at_boot");
        String bootFixDesc = baseUnboundAvailable && !pkgInstalled
            ? I18n.tr("server.unbound.fixBootBase")
            : "sysrc unbound_enable=YES";
        checks.put(makeCheck("unbound-enabled-boot", I18n.tr("server.unbound.checkBoot"),
            enabledBoot,
            bootStatus,
            enabledBoot ? null : I18n.tr("server.unbound.impactBoot"),
            (enabledBoot || !installed) ? null : bootFixAction,
            bootFixDesc));

        // 4. Running (pkg unbound OR local_unbound)
        boolean pkgRunning = isServiceRunning("unbound");
        boolean running = pkgRunning || baseUnboundRunning;
        String runningStatus;
        if (pkgRunning && baseUnboundRunning) runningStatus = I18n.tr("server.unbound.runningBoth");
        else if (pkgRunning) runningStatus = I18n.tr("server.unbound.runningPkg");
        else if (baseUnboundRunning) runningStatus = I18n.tr("server.unbound.runningBase");
        else runningStatus = I18n.tr("server.unbound.runningNone");
        String runningFixAction = running ? null : (baseUnboundAvailable && !pkgInstalled ? "start_local_unbound" : "start_unbound");
        String runningFixDesc = baseUnboundAvailable && !pkgInstalled
            ? "service local_unbound start"
            : "service unbound start";
        checks.put(makeCheck("unbound-running", I18n.tr("server.unbound.checkRunning"),
            running,
            runningStatus,
            running ? null : I18n.tr("server.unbound.impactRunning"),
            (running || !installed) ? null : runningFixAction,
            runningFixDesc));

        // 5. Listens on 127.0.0.1:53
        boolean listening53 = isPortListeningOnLocalhost(53);
        checks.put(makeCheck("unbound-listening", I18n.tr("server.unbound.checkListening"),
            listening53,
            listening53 ? I18n.tr("server.unbound.listeningYes") : I18n.tr("server.unbound.listeningNo"),
            listening53 ? null : I18n.tr("server.unbound.impactListening"),
            null, null));

        // 6. /etc/resolv.conf points to 127.0.0.1
        boolean resolvOk = false;
        try {
            String resolv = java.nio.file.Files.readString(java.nio.file.Paths.get("/etc/resolv.conf"));
            // The first useful nameserver line must be 127.0.0.1
            for (String line : resolv.split("\n")) {
                String t = line.trim();
                if (t.startsWith("#")) continue;
                if (t.startsWith("nameserver")) {
                    String ns = t.replaceFirst("nameserver\\s+", "").trim();
                    if (ns.equals("127.0.0.1") || ns.equals("::1")) resolvOk = true;
                    break;
                }
            }
        } catch (Exception ignored) {}
        checks.put(makeCheck("resolv-conf", I18n.tr("server.unbound.checkResolv"),
            resolvOk,
            resolvOk ? I18n.tr("server.unbound.resolvYes") : I18n.tr("server.unbound.resolvNo"),
            resolvOk ? null : I18n.tr("server.unbound.impactResolv"),
            (resolvOk || !running || !listening53) ? null : "switch_resolv_conf",
            I18n.tr("server.unbound.fixResolv")));

        // 7. Test query works
        boolean queryOk = testUnboundQuerySimple();
        checks.put(makeCheck("unbound-query-works", I18n.tr("server.unbound.checkQuery"),
            queryOk,
            queryOk ? I18n.tr("server.unbound.queryYes")
                    : I18n.tr(listening53 ? "server.unbound.queryFailed" : "server.unbound.querySkipped"),
            queryOk ? null : I18n.tr("server.unbound.impactQuery"),
            null, null));

        // 8. RECURSIVE mode (no forwarder) -- essential for Spamhaus/SURBL
        //    If local_unbound uses a forward-zone towards 1.1.1.1, Spamhaus still sees the queries
        //    coming from a public resolver -> 127.255.255.254 (blocked).
        boolean isForwarding = isUnboundUsingForwarder();
        boolean dnsblWorking = testDnsblQuery();
        checks.put(makeCheck("unbound-recursive", I18n.tr("server.unbound.checkRecursive"),
            !isForwarding && dnsblWorking,
            !isForwarding
                ? I18n.tr(dnsblWorking ? "server.unbound.recursiveYes" : "server.unbound.recursiveNoAnswer")
                : I18n.tr("server.unbound.forwarding"),
            (!isForwarding && dnsblWorking) ? null : I18n.tr("server.unbound.impactRecursive"),
            (!isForwarding || !running) ? null : "disable_forwarder",
            I18n.tr("server.unbound.fixRecursive")));

        boolean allOk = installed && configOk && enabledBoot && running && listening53 && resolvOk && queryOk
            && !isForwarding && dnsblWorking;
        r.put("success", true);
        r.put("all_ok", allOk);
        r.put("can_fix_all", !allOk);
        r.put("checks", checks);
        return r;
    }

    private boolean isPortListeningOnLocalhost(int port) {
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/bin/sockstat", "-l", "-4", "-6");
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(p.getInputStream()));
            String line;
            // FreeBSD sockstat uses "IP.PORT" (with a dot), Linux uses "IP:PORT"
            String[] patterns = {
                "127.0.0.1:" + port, "127.0.0.1." + port,
                "*:" + port, "*." + port,
                "::1:" + port, "::1." + port
            };
            while ((line = reader.readLine()) != null) {
                // We check that it ends with the pattern or is followed by a space (part of the address field)
                for (String pat : patterns) {
                    if (line.contains(pat + " ") || line.endsWith(pat) || line.contains(pat + "\t")) {
                        p.waitFor(2, java.util.concurrent.TimeUnit.SECONDS);
                        return true;
                    }
                }
            }
            p.waitFor(2, java.util.concurrent.TimeUnit.SECONDS);
            return false;
        } catch (Exception e) { return false; }
    }

    /**
     * Checks whether local_unbound is configured as a FORWARDER (forward-zone defined).
     * If so, the DNSBL queries go through the public forwarders and Spamhaus blocks them.
     */
    private boolean isUnboundUsingForwarder() {
        try {
            // Look for forward-zone in all the possible config files of local_unbound
            String[] confFiles = {
                "/var/unbound/forward.conf",
                "/var/unbound/unbound.conf",
                "/usr/local/etc/unbound/unbound.conf",
                "/usr/local/etc/unbound/forward.conf"
            };
            for (String path : confFiles) {
                java.nio.file.Path p = java.nio.file.Paths.get(path);
                if (!java.nio.file.Files.exists(p)) continue;
                String content = java.nio.file.Files.readString(p);
                // Look for an uncommented 'forward-zone:' directive
                for (String line : content.split("\n")) {
                    String t = line.trim();
                    if (t.startsWith("#")) continue;
                    if (t.startsWith("forward-zone:")) return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false; // Default: assume NOT forwarding if we cannot read it
        }
    }

    /**
     * Runs a test DNSBL query against Spamhaus.
     * 2.0.0.127.zen.spamhaus.org is an "always listed" IP used for testing.
     * If the answer is 127.0.0.X (excluding 127.255.X) -> the resolver works fine for DNSBL.
     * If it is 127.255.255.254 -> Spamhaus is blocking us (forwarder/public resolver).
     * If it is empty -> the query failed.
     */
    private boolean testDnsblQuery() {
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("dig", "@127.0.0.1", "+short", "+time=3", "+tries=1",
                "A", "2.0.0.127.zen.spamhaus.org");
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.redirectError(ProcessBuilder.Redirect.DISCARD);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            boolean done = p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            if (!done) { p.destroyForcibly(); return false; }
            if (p.exitValue() != 0) return false;
            for (String line : out.split("\n")) {
                String t = line.trim();
                if (t.isEmpty()) continue;
                // 127.0.0.X (excluding 127.255.255.X) = really LISTED = query works
                if (t.matches("^127\\.0\\.0\\.\\d{1,3}$")) return true;
                // 127.255.255.X = Spamhaus block = does NOT work
                if (t.startsWith("127.255.255.")) return false;
            }
            return false;
        } catch (Exception e) { return false; }
    }

    private boolean testUnboundQuerySimple() {
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("dig", "@127.0.0.1", "+short", "+time=3", "+tries=1", "A", "freebsd.org");
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            // NO redirectErrorStream: dig's stderr (e.g. "communications error") must be kept separate
            // so we do not mistake it for a valid answer.
            pb.redirectError(ProcessBuilder.Redirect.DISCARD);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            boolean done = p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            if (!done) { p.destroyForcibly(); return false; }
            // dig +short prints ONLY the value (e.g. "1.2.3.4") on stdout if it succeeds,
            // nothing if there is no answer. Errors go to stderr (discarded above).
            // Also: dig's exit code is != 0 when it fails.
            if (p.exitValue() != 0) return false;
            // Check that the FIRST useful line is a valid IPv4 (not some odd message)
            for (String line : out.split("\n")) {
                String t = line.trim();
                if (t.isEmpty()) continue;
                // It must be a pure IPv4 (possibly CNAME -> IP on the following lines)
                if (t.matches("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")) return true;
                // If the first useful line is a CNAME, check the next one
                if (t.endsWith(".") && t.matches("^[a-zA-Z0-9.-]+\\.$")) continue;
                // Otherwise it is something odd: fail
                return false;
            }
            return false;
        } catch (Exception e) { return false; }
    }

    private JSONObject installUnbound() {
        return onPackageTurn(I18n.tr("server.install.jobName", Map.of("component", "unbound")), this::runInstallUnbound);
    }

    private JSONObject runInstallUnbound() {
        JSONObject r = new JSONObject();
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/pkg", "install", "-y", "unbound");
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            boolean done = p.waitFor(180, java.util.concurrent.TimeUnit.SECONDS);
            if (!done) { p.destroyForcibly(); r.put("success", false); r.put("message", I18n.tr("server.install.timeout")); return r; }
            r.put("success", p.exitValue() == 0);
            r.put("message", p.exitValue() == 0 ? I18n.tr("server.unbound.installed") : "pkg install exit=" + p.exitValue());
            r.put("output", out.length() > 4000 ? out.substring(out.length() - 4000) : out);
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", I18n.tr("server.errorWith", Map.of("error", ErrorText.detail("runInstallUnbound", e))));
        }
        return r;
    }

    private JSONObject writeUnboundConfig() {
        JSONObject r = new JSONObject();
        try {
            java.nio.file.Path confPath = java.nio.file.Paths.get(UNBOUND_CONF_PATH);
            java.nio.file.Path parent = confPath.getParent();
            if (parent != null && !java.nio.file.Files.exists(parent)) {
                java.nio.file.Files.createDirectories(parent);
            }
            // Backup if it exists
            if (java.nio.file.Files.exists(confPath)) {
                org.daemoxcp.mail.system.ConfigBackups.copy(confPath);
            }
            java.nio.file.Files.writeString(confPath, UNBOUND_CONF_CONTENT, java.nio.charset.StandardCharsets.UTF_8);
            try { java.nio.file.Files.setPosixFilePermissions(confPath,
                java.nio.file.attribute.PosixFilePermissions.fromString("rw-r--r--")); } catch (Exception ignored) {}

            // Syntax test with unbound-checkconf if available
            try {
                // TODO: migrate to Shell.run when touched
                ProcessBuilder pb = new ProcessBuilder("/usr/local/sbin/unbound-checkconf", UNBOUND_CONF_PATH);
                org.daemoxcp.mail.util.Shell.applyPath(pb);
                pb.redirectErrorStream(true);
                Process p = pb.start();
                String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
                if (p.exitValue() != 0) {
                    r.put("success", false);
                    r.put("message", I18n.tr("server.unbound.checkconfErrors", Map.of("output", out)));
                    return r;
                }
            } catch (Exception ignored) {}

            r.put("success", true);
            r.put("message", I18n.tr("server.unbound.configWritten", Map.of("path", UNBOUND_CONF_PATH)));
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", I18n.tr("server.errorWith", Map.of("error", ErrorText.detail("writeUnboundConfig", e))));
        }
        return r;
    }

    /**
     * Replaces /etc/resolv.conf in a SAFE way:
     *  - automatic backup with a timestamp
     *  - pre-flight test: first checks that dig @127.0.0.1 resolves, and goes on ONLY if OK
     *  - writes 127.0.0.1 as primary + 1.1.1.1 as fallback
     *  - post-flight test: after writing, checks again that the system still resolves
     *  - automatic rollback if the post-flight fails
     */
    private JSONObject switchResolvConfToUnbound() {
        JSONObject r = new JSONObject();
        java.nio.file.Path resolvPath = java.nio.file.Paths.get("/etc/resolv.conf");
        try {
            // 1. Pre-flight: unbound must answer
            if (!testUnboundQuerySimple()) {
                r.put("success", false);
                r.put("message", I18n.tr("server.unbound.preflightFail"));
                return r;
            }
            // 2. Backup
            java.nio.file.Path bak = java.nio.file.Files.exists(resolvPath) ? org.daemoxcp.mail.system.ConfigBackups.copy(resolvPath) : null;
            // 3. Write the new one
            String content = ""
                + "# Configured by DaemoxCP Mail\n"
                + "# Primary resolver: local unbound\n"
                + "# Fallback: public DNS if unbound does not answer\n"
                + "nameserver 127.0.0.1\n"
                + "nameserver 1.1.1.1\n"
                + "nameserver 9.9.9.9\n"
                + "options timeout:2 attempts:3\n";
            java.nio.file.Files.writeString(resolvPath, content, java.nio.charset.StandardCharsets.UTF_8);

            // 4. Post-flight test (resolve with the system, no longer @127.0.0.1)
            try {
                // TODO: migrate to Shell.run when touched
                ProcessBuilder pb = new ProcessBuilder("dig", "+short", "+time=3", "+tries=2", "A", "freebsd.org");
                org.daemoxcp.mail.util.Shell.applyPath(pb);
                pb.redirectErrorStream(true);
                Process p = pb.start();
                String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).trim();
                p.waitFor(8, java.util.concurrent.TimeUnit.SECONDS);
                boolean ok = out.matches("(?s).*\\b\\d+\\.\\d+\\.\\d+\\.\\d+\\b.*");
                if (!ok) {
                    // Rollback
                    if (bak != null) java.nio.file.Files.copy(bak, resolvPath, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                    r.put("success", false);
                    r.put("message", I18n.tr("server.unbound.postflightFail"));
                    return r;
                }
            } catch (Exception e) {
                // Rollback su exception
                try { if (bak != null) java.nio.file.Files.copy(bak, resolvPath, java.nio.file.StandardCopyOption.REPLACE_EXISTING); } catch (Exception ignored) {}
                r.put("success", false);
                r.put("message", I18n.tr("server.unbound.postflightError", Map.of("error", ErrorText.detail("switchResolvConfToUnbound", e))));
                return r;
            }

            r.put("success", true);
            r.put("message", I18n.tr("server.unbound.resolvUpdated", Map.of("backup", bak != null ? bak.toString() : "-")));
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", I18n.tr("server.errorWith", Map.of("error", ErrorText.detail("switchResolvConfToUnbound", e))));
        }
        return r;
    }

    /**
     * Turns local_unbound from a forwarder into a recursive resolver:
     *  1. Backup of /var/unbound/forward.conf (and /var/unbound/unbound.conf if it contains forward-zone)
     *  2. Empty forward.conf
     *  3. Reload local_unbound
     *
     * After this operation, local_unbound asks the root servers directly
     * instead of passing the queries on to external forwarders (1.1.1.1, etc). Spamhaus sees
     * the query coming from your server's IP -> it answers correctly.
     */
    private JSONObject disableUnboundForwarder() {
        JSONObject r = new JSONObject();
        StringBuilder log = new StringBuilder();
        try {
            int touched = 0;
            String[] paths = { "/var/unbound/forward.conf", "/var/unbound/unbound.conf" };
            for (String path : paths) {
                java.nio.file.Path p = java.nio.file.Paths.get(path);
                if (!java.nio.file.Files.exists(p)) continue;
                String content = java.nio.file.Files.readString(p);
                // Detect whether there really is a forward-zone (there may be commented ones too: we strip
                // only the real ones)
                boolean hasForwardZone = false;
                StringBuilder cleaned = new StringBuilder();
                boolean inForwardZone = false;
                for (String line : content.split("\n", -1)) {
                    String t = line.trim();
                    if (!inForwardZone) {
                        if (!t.startsWith("#") && t.startsWith("forward-zone:")) {
                            hasForwardZone = true;
                            inForwardZone = true;
                            cleaned.append("# Disabled by DaemoxCP Mail (the forwarder got Spamhaus queries blocked)\n");
                            cleaned.append("# ").append(line).append("\n");
                        } else {
                            cleaned.append(line).append("\n");
                        }
                    } else {
                        // We are inside a forward-zone block -- comment out everything up to the next block
                        if (t.isEmpty() || (!t.startsWith("forward-") && !t.startsWith("name:") && !t.startsWith("#"))) {
                            // End of the block
                            inForwardZone = false;
                            cleaned.append(line).append("\n");
                        } else {
                            cleaned.append("# ").append(line).append("\n");
                        }
                    }
                }
                if (hasForwardZone) {
                    org.daemoxcp.mail.system.ConfigBackups.copy(p);
                    String result = cleaned.toString();
                    java.nio.file.Files.writeString(p, result, java.nio.charset.StandardCharsets.UTF_8);
                    touched++;
                    log.append("✓ ").append(I18n.tr("server.unbound.log.forwardZoneCommented", Map.of("path", path))).append("\n");
                }
            }

            // === FIX FOR PERSISTENCE ACROSS REBOOTS ===
            // FreeBSD regenerates /var/unbound/forward.conf on various triggers (pkg upgrade,
            // local-unbound-setup, dhclient newresolv hook), reading two references:
            //   1. local_unbound_forwarders in /etc/rc.conf
            //   2. /etc/resolv.conf  (nameserver != 127.0.0.1 entries are taken as forwarders)
            // If we do not fix both, after a reboot we are back in forwarder mode.

            // 1) Empty local_unbound_forwarders in rc.conf (if present)
            try {
                // TODO: migrate to Shell.run when touched
                ProcessBuilder pbGet = new ProcessBuilder("/usr/sbin/sysrc", "-n", "local_unbound_forwarders");
                org.daemoxcp.mail.util.Shell.applyPath(pbGet);
                pbGet.redirectErrorStream(true);
                Process pg = pbGet.start();
                String currentVal = new String(pg.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).trim();
                pg.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
                if (!currentVal.isEmpty()) {
                    // TODO: migrate to Shell.run when touched
                    ProcessBuilder pbDel = new ProcessBuilder("/usr/sbin/sysrc", "-x", "local_unbound_forwarders");
                    org.daemoxcp.mail.util.Shell.applyPath(pbDel);
                    pbDel.redirectErrorStream(true);
                    Process pd = pbDel.start();
                    pd.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
                    log.append("✓ ").append(I18n.tr("server.unbound.log.forwardersRemoved", Map.of("value", currentVal))).append("\n");
                } else {
                    log.append("• ").append(I18n.tr("server.unbound.log.forwardersEmpty")).append("\n");
                }
            } catch (Exception e) {
                log.append("⚠ ").append(I18n.tr("server.unbound.log.rcConfFailed", Map.of("error", String.valueOf(e.getMessage())))).append("\n");
            }

            // 2) Make sure /etc/resolv.conf has 127.0.0.1 as the FIRST nameserver
            try {
                java.nio.file.Path resolv = java.nio.file.Paths.get("/etc/resolv.conf");
                if (java.nio.file.Files.exists(resolv)) {
                    String rc = java.nio.file.Files.readString(resolv);
                    String firstNs = null;
                    for (String line : rc.split("\n")) {
                        String t = line.trim();
                        if (t.startsWith("#") || t.isEmpty()) continue;
                        if (t.startsWith("nameserver")) {
                            firstNs = t.replaceFirst("nameserver\\s+", "").trim();
                            break;
                        }
                    }
                    if (firstNs == null || (!firstNs.equals("127.0.0.1") && !firstNs.equals("::1"))) {
                        org.daemoxcp.mail.system.ConfigBackups.copy(resolv);
                        String newContent = "# Generated by DaemoxCP Mail\n# Loopback as the FIRST nameserver for local_unbound\nnameserver 127.0.0.1\noptions edns0\n";
                        java.nio.file.Files.writeString(resolv, newContent, java.nio.charset.StandardCharsets.UTF_8);
                        log.append("✓ ").append(I18n.tr("server.unbound.log.resolvRewritten")).append("\n");
                    } else {
                        log.append("• ").append(I18n.tr("server.unbound.log.resolvOk")).append("\n");
                    }
                }
            } catch (Exception e) {
                log.append("⚠ ").append(I18n.tr("server.unbound.log.resolvFailed", Map.of("error", String.valueOf(e.getMessage())))).append("\n");
            }

            // 3) Disable resolvconf if active (otherwise DHCP rewrites resolv.conf at reboot)
            try {
                // TODO: migrate to Shell.run when touched
                ProcessBuilder pbGet = new ProcessBuilder("/usr/sbin/sysrc", "-n", "resolvconf_enable");
                org.daemoxcp.mail.util.Shell.applyPath(pbGet);
                pbGet.redirectErrorStream(true);
                Process pg = pbGet.start();
                String currentVal = new String(pg.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).trim();
                pg.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
                if (currentVal.equalsIgnoreCase("YES")) {
                    // TODO: migrate to Shell.run when touched
                    ProcessBuilder pbSet = new ProcessBuilder("/usr/sbin/sysrc", "resolvconf_enable=NO");
                    org.daemoxcp.mail.util.Shell.applyPath(pbSet);
                    pbSet.redirectErrorStream(true);
                    Process ps = pbSet.start();
                    ps.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
                    log.append("✓ ").append(I18n.tr("server.unbound.log.resolvconfDisabled")).append("\n");
                }
            } catch (Exception e) {
                log.append("⚠ ").append(I18n.tr("server.unbound.log.resolvconfFailed", Map.of("error", String.valueOf(e.getMessage())))).append("\n");
            }

            // 4) DEFINITIVE FIX: remove 'include: forward.conf' from unbound.conf.
            //    Even if forward.conf were regenerated by local-unbound-setup
            //    (pkg upgrade, DHCP hook, etc), it would no longer be loaded.
            try {
                java.nio.file.Path ucPath = java.nio.file.Paths.get("/var/unbound/unbound.conf");
                if (java.nio.file.Files.exists(ucPath)) {
                    String uc = java.nio.file.Files.readString(ucPath);
                    String[] lines = uc.split("\n", -1);
                    boolean changed = false;
                    StringBuilder sb = new StringBuilder();
                    for (String line : lines) {
                        String trimmed = line.trim();
                        // Catch "include: ..forward.conf" even with quotes or spaces
                        if (!trimmed.startsWith("#") && trimmed.toLowerCase().startsWith("include:")
                                && trimmed.toLowerCase().contains("forward.conf")) {
                            sb.append("# Disabled by DaemoxCP Mail (the forward-zone got Spamhaus queries blocked): ").append(line).append("\n");
                            changed = true;
                        } else {
                            sb.append(line).append("\n");
                        }
                    }
                    if (changed) {
                        org.daemoxcp.mail.system.ConfigBackups.copy(ucPath);
                        // toString adds an extra \n at the end -- we remove it if needed
                        String newContent = sb.toString();
                        if (newContent.endsWith("\n\n")) newContent = newContent.substring(0, newContent.length() - 1);
                        java.nio.file.Files.writeString(ucPath, newContent, java.nio.charset.StandardCharsets.UTF_8);
                        log.append("✓ ").append(I18n.tr("server.unbound.log.includeCommented")).append("\n");
                    } else {
                        log.append("• ").append(I18n.tr("server.unbound.log.noInclude")).append("\n");
                    }
                }
            } catch (Exception e) {
                log.append("⚠ ").append(I18n.tr("server.unbound.log.unboundConfFailed", Map.of("error", String.valueOf(e.getMessage())))).append("\n");
            }

            // 5) Empty forward.conf (even though it is no longer included, for tidiness)
            try {
                java.nio.file.Path fcPath = java.nio.file.Paths.get("/var/unbound/forward.conf");
                if (java.nio.file.Files.exists(fcPath)) {
                    // Remove the immutable flag if already present (to be able to overwrite)
                    try {
                        // TODO: migrate to Shell.run when touched
                        new ProcessBuilder("/bin/chflags", "noschg", "/var/unbound/forward.conf")
                            .redirectErrorStream(true).start().waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
                    } catch (Exception ignored) {}
                    org.daemoxcp.mail.system.ConfigBackups.copy(fcPath);
                    java.nio.file.Files.writeString(fcPath,
                        "# DaemoxCP Mail: direct recursive mode, forward-zones DISABLED\n",
                        java.nio.charset.StandardCharsets.UTF_8);
                    log.append("✓ ").append(I18n.tr("server.unbound.log.forwardConfEmptied")).append("\n");
                }
            } catch (Exception e) {
                log.append("⚠ ").append(I18n.tr("server.unbound.log.forwardConfFailed", Map.of("error", String.valueOf(e.getMessage())))).append("\n");
            }

            // 6) Make forward.conf IMMUTABLE -- local-unbound-setup can no longer overwrite it
            try {
                // TODO: migrate to Shell.run when touched
                Process pCh = new ProcessBuilder("/bin/chflags", "schg", "/var/unbound/forward.conf")
                    .redirectErrorStream(true).start();
                pCh.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
                if (pCh.exitValue() == 0) {
                    log.append("✓ ").append(I18n.tr("server.unbound.log.chflagsDone")).append("\n");
                } else {
                    log.append("⚠ ").append(I18n.tr("server.unbound.log.chflagsFailed")).append("\n");
                }
            } catch (Exception e) {
                log.append("⚠ ").append(I18n.tr("server.unbound.log.chflagsError", Map.of("error", String.valueOf(e.getMessage())))).append("\n");
            }

            // 7) RESTART (not reload) -- reload does not reread forward.conf if the include has changed
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/service", "local_unbound", "restart");
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String reloadOut = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            p.waitFor(20, java.util.concurrent.TimeUnit.SECONDS);
            log.append("✓ ").append(I18n.tr("server.unbound.log.restarted")).append("\n");
            if (!reloadOut.isEmpty()) log.append("  output: ").append(reloadOut.trim()).append("\n");

            try { Thread.sleep(1500); } catch (Exception ignored) {}
            boolean stillForwarding = isUnboundUsingForwarder();
            boolean dnsblWorks = testDnsblQuery();
            r.put("success", !stillForwarding);
            r.put("message", I18n.tr("server.unbound.recursiveOn") + " "
                + (touched == 0 ? I18n.tr("server.unbound.forwardAlreadyClean") : I18n.tr("server.unbound.filesCommented", Map.of("n", touched))) + " "
                + I18n.tr(dnsblWorks ? "server.unbound.spamhausOk" : "server.unbound.spamhausNotYet"));
            r.put("output", log.toString());
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", I18n.tr("server.errorWith", Map.of("error", ErrorText.detail("disableUnboundForwarder", e))));
            r.put("output", log.toString());
        }
        return r;
    }

    /** Restores the last backup of /etc/resolv.conf created by the panel. */
    private JSONObject rollbackResolvConf() {
        JSONObject r = new JSONObject();
        try {
            java.nio.file.Path etc = java.nio.file.Paths.get("/etc");
            String latest = null;
            long latestMtime = 0;
            try (java.util.stream.Stream<java.nio.file.Path> s = java.nio.file.Files.list(etc)) {
                for (java.nio.file.Path p : s.toArray(java.nio.file.Path[]::new)) {
                    if (p.getFileName().toString().startsWith("resolv.conf.bak.")) {
                        long m = java.nio.file.Files.getLastModifiedTime(p).toMillis();
                        if (m > latestMtime) { latestMtime = m; latest = p.toString(); }
                    }
                }
            }
            if (latest == null) {
                r.put("success", false);
                r.put("message", I18n.tr("server.unbound.noBackup"));
                return r;
            }
            java.nio.file.Files.copy(java.nio.file.Paths.get(latest), java.nio.file.Paths.get("/etc/resolv.conf"),
                java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            r.put("success", true);
            r.put("message", I18n.tr("server.unbound.restoredFrom", Map.of("file", String.valueOf(latest))));
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", I18n.tr("server.errorWith", Map.of("error", ErrorText.detail("rollbackResolvConf", e))));
        }
        return r;
    }

    private JSONObject testUnboundQuery() {
        JSONObject r = new JSONObject();
        try {
            // Test 1: simple query
            boolean basic = testUnboundQuerySimple();
            // Test 2: Spamhaus DNSBL query with a standard IP (1.0.0.127.zen.spamhaus.org always TRUE)
            //         "127.0.0.2" reverse = "2.0.0.127.zen.spamhaus.org" -> always listed (test address)
            String dnsblOut = "";
            boolean dnsblOk = false;
            try {
                // TODO: migrate to Shell.run when touched
                ProcessBuilder pb = new ProcessBuilder("dig", "@127.0.0.1", "+short", "+time=3", "A", "2.0.0.127.zen.spamhaus.org");
                org.daemoxcp.mail.util.Shell.applyPath(pb);
                pb.redirectErrorStream(true);
                Process p = pb.start();
                dnsblOut = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).trim();
                p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
                // If the answer starts with 127.0.0.* (excluding 127.255.*) -> the Spamhaus query works
                if (!dnsblOut.isEmpty()) {
                    String first = dnsblOut.split("\n")[0].trim();
                    dnsblOk = first.startsWith("127.0.0.") || first.startsWith("127.0.0.2");
                }
            } catch (Exception ignored) {}

            r.put("success", basic);
            StringBuilder msg = new StringBuilder();
            msg.append(I18n.tr("server.unbound.testBasic", Map.of("result", basic ? "OK" : "FAIL"))).append("\n");
            msg.append(I18n.tr("server.unbound.testSpamhaus")).append(" ");
            if (dnsblOk) msg.append(I18n.tr("server.unbound.testSpamhausOk"));
            else if (dnsblOut.startsWith("127.255.255.")) msg.append(I18n.tr("server.unbound.testSpamhausBlocked"));
            else msg.append(I18n.tr("server.unbound.testNoAnswer", Map.of("answer", dnsblOut.isEmpty() ? I18n.tr("server.unbound.empty") : dnsblOut)));
            r.put("message", msg.toString());
            r.put("basic_ok", basic);
            r.put("dnsbl_ok", dnsblOk);
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", I18n.tr("server.errorWith", Map.of("error", ErrorText.detail("testUnboundQuery", e))));
        }
        return r;
    }

    private JSONObject runUnboundFixAll() {
        JSONObject r = new JSONObject();
        JSONArray steps = new JSONArray();
        boolean anyFailed = false;

        // Strategy: prefer local_unbound (base system, already installed)
        //           if it is not available, use pkg unbound
        boolean baseAvailable = java.nio.file.Files.exists(java.nio.file.Paths.get("/usr/sbin/local-unbound"));
        boolean pkgInstalled;
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/pkg", "info", "-e", "unbound");
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            pkgInstalled = p.exitValue() == 0;
        } catch (Exception e) { pkgInstalled = false; }

        // If local_unbound is available, we use it (zero install, already in the base)
        String svcName;
        String sysrcKey;
        if (baseAvailable) {
            svcName = "local_unbound";
            sysrcKey = "local_unbound_enable";
            steps.put(buildSkipStep("install_unbound", I18n.tr("server.unbound.step.baseAvailable")));
        } else if (pkgInstalled) {
            svcName = "unbound";
            sysrcKey = "unbound_enable";
            steps.put(buildSkipStep("install_unbound", I18n.tr("server.unbound.step.pkgInstalled")));
        } else {
            // Nothing available: install pkg
            JSONObject res = installUnbound();
            steps.put(buildStep("install_unbound", I18n.tr("server.unbound.step.installPkg"), res));
            if (!res.optBoolean("success")) {
                anyFailed = true;
                r.put("success", false); r.put("steps", steps); r.put("message", I18n.tr("server.install.failed"));
                return r;
            }
            svcName = "unbound";
            sysrcKey = "unbound_enable";
        }

        // 2. Config -- only for pkg unbound (local_unbound has its config in /var/unbound, managed by the base)
        if ("unbound".equals(svcName)) {
            boolean confValid = false;
            if (java.nio.file.Files.exists(java.nio.file.Paths.get(UNBOUND_CONF_PATH))) {
                try {
                    String c = java.nio.file.Files.readString(java.nio.file.Paths.get(UNBOUND_CONF_PATH));
                    confValid = c.contains("interface: 127.0.0.1") && c.contains("access-control");
                } catch (Exception ignored) {}
            }
            if (!confValid) {
                JSONObject res = writeUnboundConfig();
                steps.put(buildStep("configure_unbound", I18n.tr("server.unbound.step.writeConfig"), res));
                if (!res.optBoolean("success")) anyFailed = true;
            } else {
                steps.put(buildSkipStep("configure_unbound", I18n.tr("server.unbound.step.configValid")));
            }
        } else {
            steps.put(buildSkipStep("configure_unbound", I18n.tr("server.unbound.step.baseConfig")));
        }

        // 3. Enable at boot
        if (!isSysrcYes(sysrcKey)) {
            JSONObject res = sysrcSet(sysrcKey, "YES");
            steps.put(buildStep("enable_at_boot", I18n.tr("server.unbound.step.enableBoot", Map.of("service", svcName, "key", sysrcKey)), res));
            if (!res.optBoolean("success")) anyFailed = true;
        } else {
            steps.put(buildSkipStep("enable_at_boot", I18n.tr("server.unbound.step.bootAlready", Map.of("service", svcName))));
        }

        // 4. Start
        if (!isServiceRunning(svcName)) {
            JSONObject res = serviceCommand(svcName, "start", 30);
            steps.put(buildStep("start_resolver", I18n.tr("server.unbound.step.start", Map.of("service", svcName)), res));
            if (!res.optBoolean("success")) anyFailed = true;
        } else {
            steps.put(buildSkipStep("start_resolver", I18n.tr("server.unbound.step.running", Map.of("service", svcName))));
        }

        // 5. Wait a moment for unbound to be ready
        try { Thread.sleep(1500); } catch (Exception ignored) {}

        // 6. Switch /etc/resolv.conf (with safety)
        // Preliminary check
        boolean unboundReady = testUnboundQuerySimple();
        if (!unboundReady) {
            steps.put(buildErrorStep("switch_resolv_conf", I18n.tr("server.unbound.preflightFail")));
            anyFailed = true;
        } else {
            boolean resolvOk = false;
            try {
                String resolv = java.nio.file.Files.readString(java.nio.file.Paths.get("/etc/resolv.conf"));
                for (String line : resolv.split("\n")) {
                    String t = line.trim();
                    if (t.startsWith("#")) continue;
                    if (t.startsWith("nameserver")) {
                        String ns = t.replaceFirst("nameserver\\s+", "").trim();
                        if (ns.equals("127.0.0.1") || ns.equals("::1")) resolvOk = true;
                        break;
                    }
                }
            } catch (Exception ignored) {}
            if (!resolvOk) {
                JSONObject res = switchResolvConfToUnbound();
                steps.put(buildStep("switch_resolv_conf", I18n.tr("server.unbound.step.switchResolv"), res));
                if (!res.optBoolean("success")) anyFailed = true;
            } else {
                steps.put(buildSkipStep("switch_resolv_conf", I18n.tr("server.unbound.step.resolvAlready")));
            }
        }

        // 7. Disable the forwarder (forward-zone in unbound.conf) -- needed for DNSBL
        if (isUnboundUsingForwarder()) {
            JSONObject res = disableUnboundForwarder();
            steps.put(buildStep("disable_forwarder", I18n.tr("server.unbound.step.disableForwarder"), res));
            if (!res.optBoolean("success")) anyFailed = true;
        } else {
            steps.put(buildSkipStep("disable_forwarder", I18n.tr("server.unbound.step.recursiveAlready")));
        }

        r.put("success", !anyFailed);
        r.put("steps", steps);
        r.put("message", I18n.tr(anyFailed ? "server.unbound.someFailed" : "server.unbound.allDone"));
        return r;
    }

    // ============== BLACKLIST CHECK (DNSBL + RHSBL) ==============
    private void handleApiBlacklistCheck(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) { sendJsonError(exchange, 401, I18n.tr("server.unauthorized")); return; }
        if (!"GET".equals(exchange.getRequestMethod())) {
            sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed")); return;
        }
        JSONObject response = new JSONObject();
        try {
            String query = exchange.getRequestURI().getQuery();
            String ip = extractParamFromQuery(query, "ip");
            String domain = extractParamFromQuery(query, "domain");

            org.daemoxcp.mail.security.BlacklistChecker checker = new org.daemoxcp.mail.security.BlacklistChecker();
            JSONArray reports = new JSONArray();

            // If not specified, use the server IP + all the domains in the DB
            if ((ip == null || ip.isEmpty()) && (domain == null || domain.isEmpty())) {
                String serverIp = dnsGenerator != null ? dnsGenerator.detectServerIp() : null;
                if (serverIp != null && !serverIp.isEmpty()) {
                    reports.put(reportToJson(checker.checkIp(serverIp)));
                }
                // Domains configured in the panel
                try {
                    java.util.List<MailDatabase.Domain> domains = Main.mailDatabase.getDomains();
                    for (MailDatabase.Domain d : domains) {
                        if (d.domain != null && !d.domain.isEmpty()) {
                            reports.put(reportToJson(checker.checkDomain(d.domain)));
                        }
                    }
                } catch (Exception ignored) {}
            } else {
                if (ip != null && !ip.isEmpty()) {
                    if (!org.daemoxcp.mail.security.InputValidator.isValidIp(ip)) {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.badIp"));
                        sendJsonResponse(exchange, response); return;
                    }
                    reports.put(reportToJson(checker.checkIp(ip)));
                }
                if (domain != null && !domain.isEmpty()) {
                    if (!org.daemoxcp.mail.security.InputValidator.isValidDomain(domain)) {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.domain.invalid"));
                        sendJsonResponse(exchange, response); return;
                    }
                    reports.put(reportToJson(checker.checkDomain(domain)));
                }
            }

            response.put("success", true);
            response.put("reports", reports);
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", ErrorText.forPage("handleApiBlacklistCheck", e));
        }
        sendJsonResponse(exchange, response);
    }

    private JSONObject reportToJson(org.daemoxcp.mail.security.BlacklistChecker.BlacklistReport rep) {
        JSONObject jo = new JSONObject();
        jo.put("target", rep.target);
        jo.put("type", rep.type);
        jo.put("listed_count", rep.listedCount);
        jo.put("clean_count", rep.cleanCount);
        jo.put("error_count", rep.errorCount);
        jo.put("web_only_count", rep.webOnlyCount);
        jo.put("elapsed_ms", rep.elapsedMs);
        JSONArray arr = new JSONArray();
        for (org.daemoxcp.mail.security.BlacklistChecker.CheckResult cr : rep.results) {
            JSONObject e = new JSONObject();
            e.put("blacklist", cr.blacklistName);
            e.put("zone", cr.blacklistZone);
            e.put("lookup_url", cr.lookupUrl);
            e.put("listed", cr.listed);
            e.put("error", cr.error);
            e.put("web_only", cr.webOnly);
            if (cr.responseCode != null) e.put("response_code", cr.responseCode);
            e.put("message", cr.message);
            arr.put(e);
        }
        jo.put("results", arr);
        return jo;
    }

    // ============== CLAMAV HEALTH CHECK ==============
    /**
     * Package protection, updates and vulnerabilities.
     *
     * GET returns the state of the packages, which is the lightest read. Everything else
     * goes through POST with a CSRF token: even the pure reads, because they query the network
     * and last tens of seconds, and because the real actions (unlock, update) must not be
     * triggerable by a request prepared elsewhere.
     */
    private void handleApiUpdates(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) { sendJsonError(exchange, 401, I18n.tr("server.unauthorized")); return; }
        try {
            if ("GET".equals(exchange.getRequestMethod())) {
                sendJsonResponse(exchange, UpdateManager.packagesStatus());
                return;
            }
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
                return;
            }
            String body = readRequestBodyWithLimit(exchange);
            if (body == null) { sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge")); return; }
            JSONObject req = new JSONObject(body);
            if (!validateCsrfForRequest(exchange, req)) { sendCsrfError(exchange); return; }
            String action = req.optString("action", "");
            String ip = getClientIp(exchange);
            JSONObject response;

            switch (action) {
                case "packages_status" -> response = UpdateManager.packagesStatus();
                case "packages_overview" -> response = UpdateManager.packagesOverview();
                case "updates_status" -> response = UpdateManager.updatesStatus();
                case "compatibility" -> response = UpdateManager.compatibilityReport();
                case "dovecot_config_dump" -> response = UpdateManager.dumpDovecotConfig();
                case "dovecot_config_regen" -> {
                    // Rewrites only the configuration, without touching the packages. The
                    // confirmation typed by hand is there because the operation reloads a live service.
                    if (!"REGENERATE".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                        break;
                    }
                    response = UpdateManager.startDovecotRegeneration();
                    logAudit("DOVECOT_CONFIG_REGEN", ip, response.optString("jobId", ""));
                }
                case "maintenance_preview" -> {
                    String now = org.daemoxcp.mail.system.PackageQueue.planNotNow();
                    response = now != null ? new JSONObject().put("success", false).put("error", now)
                             : UpdateManager.maintenancePreview();
                }
                case "plan" -> response = UpdateManager.maintenancePlan();
                case "mysql84_preflight" -> response = UpdateManager.mysql84Preflight();
                case "dovecot24_preflight" -> response = UpdateManager.dovecot24Preflight();
                case "broken_libs" -> response = UpdateManager.packagesWithMissingLibraries();
                case "mysql_client_diag" -> response = UpdateManager.mysqlClientDiagnostics();
                case "defaults_check" -> response = UpdateManager.defaultsConsistency();
                case "branch_status" -> response = UpdateManager.branchStatus();
                case "package_turn" -> response = UpdateManager.packageTurn();
                case "branch_preview" -> response = UpdateManager.branchPreview(req.optString("destination", ""));
                case "branch_change" -> {
                    // The confirmation is the name of the branch typed by hand, and the fingerprint is the
                    // one of the preview: only what was seen gets changed.
                    String target = req.optString("destination", "");
                    if (target.isEmpty() || !target.equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", I18n.tr("server.updates.typeBranch"));
                        break;
                    }
                    response = UpdateManager.startBranchChange(target, req.optString("fingerprint", ""));
                    logAudit("PKG_BRANCH_CHANGE", ip, "to " + target + (response.optBoolean("success")
                            ? " (started, job " + response.optString("jobId") + ")" : " (not started: " + response.optString("error") + ")"));
                }
                // The panel version and the GitHub releases (ReleaseCheck): reading, checking now, the
                // daily check on or off.
                case "panel_release" -> response = org.daemoxcp.mail.system.ReleaseCheck.status();
                case "panel_release_check" -> response = org.daemoxcp.mail.system.ReleaseCheck.checkNow();
                case "panel_release_auto" -> {
                    boolean on = req.optBoolean("enabled", true);
                    response = org.daemoxcp.mail.system.ReleaseCheck.setEnabled(on);
                    logAudit(on ? "RELEASE_CHECK_ON" : "RELEASE_CHECK_OFF", ip, "daily check of " + org.daemoxcp.mail.system.ReleaseCheck.REPOSITORY + " releases");
                }
                case "system_report" -> response = UpdateManager.systemReport();
                case "os_status" -> response = UpdateManager.operatingSystem();
                case "reboot_preview" -> response = UpdateManager.restartServer(false, 1);
                // For the strip at the top of every page: is a restart needed? (finding 185)
                case "reboot_state" -> response = UpdateManager.rebootState();
                case "reboot_cancel" -> {
                    response = UpdateManager.cancelReboot();
                    logAudit("SERVER_REBOOT_CANCEL", ip, response.optString("pid", ""));
                }
                case "reboot_now" -> {
                    if (!"REBOOT THE SERVER".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                        break;
                    }
                    logAudit("SERVER_REBOOT", ip, "requested from the panel");
                    response = UpdateManager.restartServer(true, req.optInt("minutes", 1));
                }
                case "rc_state" -> response = UpdateManager.autoStart();
                case "system_summary" -> response = UpdateManager.systemSummary();
                case "cf_intervals" -> response = UpdateManager.cloudflareRanges();
                // The provider's firewall: the Cloudflare list to put in it, and whether it is the
                // confirmed one (finding 245).
                case "provider_firewall" -> response = org.daemoxcp.mail.security.ProviderFirewall.state();
                // Outbound port 25 (finding 246): only the greeting of a big mail server is read.
                case "smtp_out" -> response = org.daemoxcp.mail.system.OutboundSmtp.check();
                case "provider_firewall_ack" -> {
                    if (!"UPDATED".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                        break;
                    }
                    response = org.daemoxcp.mail.security.ProviderFirewall.acknowledge(req.optString("fingerprint", ""));
                    logAudit("PROVIDER_FIREWALL", ip, response.optBoolean("success")
                            ? "Cloudflare list confirmed in the provider firewall"
                            : "NOT confirmed: " + response.optString("error", "?"));
                }
                case "rc_remove_preview" -> response = UpdateManager.removePanelRcScript(false);
                case "rc_remove" -> {
                    if (!"REMOVE RC".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                        break;
                    }
                    response = UpdateManager.removePanelRcScript(true);
                    logAudit("RC_REMOVE", ip, response.optBoolean("success")
                            ? "boot start removed" : "NOT removed: " + response.optString("error", "?"));
                }
                case "rc_preview" -> response = UpdateManager.panelRcScript(false);
                case "rc_install" -> {
                    if (!"INSTALL RC".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                        break;
                    }
                    response = UpdateManager.panelRcScript(true);
                    logAudit("RC_SCRIPT_INSTALL", ip, response.optString("path", ""));
                }
                case "os_upgrade_targets" -> response = UpdateManager.targetVersions();
                case "os_upgrade_preflight" -> response = UpdateManager.systemUpgradePreflight(
                        req.optString("target", "15.1"));
                case "os_upgrade_instructions" -> response = UpdateManager.systemUpgradeInstructions(
                        req.optString("target", "15.1"));
                case "os_upgrade_verify" -> response = UpdateManager.verifyAfterUpdate();
                case "jump_state" -> response = UpdateManager.versionJumpStatus();
                case "be_list" -> response = UpdateManager.bootEnvironments();
                // An interrupted package job: the warning, and closing it after checking.
                case "interruption_status" -> response = org.daemoxcp.mail.system.PackageRecovery.status();
                // Going back to the server as it was before a full reinstall (ReinstallReturn): the
                // current mail merged into it, bectl activate, and the restart in one minute.
                case "reinstall_way_back" -> {
                    if (!"GO BACK".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                        break;
                    }
                    String name = req.optString("name", "");
                    org.json.JSONArray lines = new org.json.JSONArray();
                    response = org.daemoxcp.mail.system.ReinstallReturn.goBack(name, lines::put);
                    response.put("log", lines);
                    logAudit("REINSTALL_WAY_BACK", ip, (response.optBoolean("success") ? "activated " : "refused ")
                            + name + (response.optBoolean("success") ? ", " + response.optInt("merged") + " mail files merged" : ": " + response.optString("error")));
                    if (response.optBoolean("success")) response.put("reboot", UpdateManager.restartServer(true, 1));
                }
                case "interruption_dismiss" -> {
                    response = org.daemoxcp.mail.system.PackageRecovery.dismiss();
                    logAudit("PKG_INTERRUPTION_CHECKED", ip, response.optBoolean("success")
                            ? "interrupted package job notice closed" : "close refused: packages still unprotected");
                }
                case "ssl_usage" -> response = UpdateManager.opensslUsage();
                case "removal_candidates" -> response = UpdateManager.removalCandidates();
                case "panel_uses" -> response = UpdateManager.panelUsage(req.optString("name", ""));
                case "deep_scan" -> response = UpdateManager.deepAnalysis(req.optString("name", ""));
                case "panel_env" -> response = UpdateManager.panelBootEnvironment();
                case "dovecot24_preview" -> response = UpdateManager.dovecot24Preview();
                case "rspamd_timeout" -> response = UpdateManager.rspamdTimeoutDiagnostics();
                case "web_diagnosis" -> response = org.daemoxcp.mail.system.WebDiagnostics.state();
                case "service_users" -> response = org.daemoxcp.mail.system.ServiceUsers.state();
                case "web443_status" -> response = org.daemoxcp.mail.system.WebProtection.state();
                case "web443_config" -> response = new JSONObject().put("success", true)
                        .put("configuration", org.daemoxcp.mail.system.WebProtection.configuration(
                                "/usr/local/etc/ssl/mail/fullchain.pem",
                                "/usr/local/etc/ssl/mail/privkey.pem"))
                        .put("filter", org.daemoxcp.mail.system.WebProtection.filter())
                        .put("jail", org.daemoxcp.mail.system.WebProtection.jail());
                case "mtasts_plan" -> response = org.daemoxcp.mail.system.MtaStsSetup.plan();
                case "mtasts_enable" -> {
                    if (!"ENABLE".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                        break;
                    }
                    response = UpdateManager.startMtaStsActivation();
                    logAudit("MTASTS_ENABLE", ip, "started as job " + response.optString("jobId", ""));
                }
                case "web443_include" -> {
                    if (!"ADD".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                        break;
                    }
                    response = org.daemoxcp.mail.system.WebProtection.addInclude();
                    logAudit("NGINX_INCLUDE", ip, response.optBoolean("success")
                            ? "include added" : "NOT added: " + response.optString("error", "?"));
                }
                case "web443_install" -> {
                    if (!"OPEN".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                        break;
                    }
                    response = org.daemoxcp.mail.system.WebProtection.install("", "");
                    logAudit("WEB443_INSTALL", ip, response.optBoolean("success")
                            ? "443 open with minimal surface" : "NOT open: " + response.optString("error", "?"));
                }
                case "web443_jail" -> {
                    if (!"ENABLE".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                        break;
                    }
                    response = org.daemoxcp.mail.system.WebProtection.installJail();
                    logAudit("WEB443_JAIL", ip, response.optBoolean("success")
                            ? "jail active" : "NOT active: " + response.optString("error", "?"));
                }
                case "watch" -> response = org.daemoxcp.mail.system.StandardsWatch.check();
                case "watch_changes" -> response = org.daemoxcp.mail.system.StandardsWatch.whatChanged(
                        req.optString("rfc", ""),
                        // For an update, the new document and the panel's specification
                        // are two different numbers: the identifiers to cross-check are those
                        // of the specification, not of the document that updates it.
                        req.optString("reference", req.optString("rfc", "")));
                case "openssl_expiry" -> response = org.daemoxcp.mail.system.OpensslExpiry.state();
                case "port465_status" -> response = org.daemoxcp.mail.system.SubmissionPort.state();
                case "port465_apply" -> {
                    if (!"APPLY".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                        break;
                    }
                    response = org.daemoxcp.mail.system.SubmissionPort.apply();
                    logAudit("PORT_465", ip, response.optBoolean("success")
                            ? "restriction applied" : "NOT applied: " + response.optString("error", "?"));
                }
                case "postfix_level" -> {
                    if (!"RAISE".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                        break;
                    }
                    response = UpdateManager.raisePostfixCompatibilityLevel(req.optString("level", ""));
                    logAudit("POSTFIX_LEVEL", ip, req.optString("level", "")
                            + (response.optBoolean("success") ? " - done" : " - NOT done: "
                               + response.optString("error", "?")));
                }
                case "pkg_remove" -> {
                    if (!"REMOVE".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                        break;
                    }
                    response = UpdateManager.removePackage(req.optString("name", ""));
                    logAudit("PKG_REMOVE", ip, req.optString("name", "")
                            + (response.optBoolean("success") ? " - removed" : " - NOT removed: "
                               + response.optString("error", "?")));
                }
                case "be_destroy" -> {
                    if (!"DELETE".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                        break;
                    }
                    response = UpdateManager.deleteBootEnvironment(req.optString("name", ""));
                    logAudit("BE_DESTROY", ip, req.optString("name", "")
                            + (response.optBoolean("success") ? " - deleted"
                               : " - NOT deleted: " + response.optString("error", "?")));
                }
                case "jump_continue" -> {
                    if (!"CONTINUE".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                        break;
                    }
                    response = UpdateManager.startResumeVersionJump(req.optString("target", ""));
                    logAudit("RELEASE_JUMP_CONTINUE", ip, response.optString("jobId", ""));
                }
                case "jump_cancel" -> {
                    if (!"CANCEL".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                        break;
                    }
                    response = UpdateManager.cancelVersionJump();
                    logAudit("RELEASE_JUMP_CANCELLED", ip, response.optBoolean("success") ? "cancelled" : "refused");
                }
                case "os_upgrade_prepare" -> {
                    if (!"PREPARE UPGRADE".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                        break;
                    }
                    response = UpdateManager.startSystemPreparation(req.optString("target", "15.1"));
                    logAudit("OS_UPGRADE_PREPARE", ip, req.optString("target", ""));
                }
                case "updates_search" -> {
                    // Downloads catalogues, vulnerabilities and patches: installs nothing (finding 186).
                    if (!"SEARCH".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                        break;
                    }
                    response = UpdateManager.startUpdatesSearch();
                    logAudit("UPDATES_SEARCH", ip, response.optString("jobId", response.optString("error", "")));
                }
                case "os_patch_install" -> {
                    // Downloads and installs the base system patches, with a boot environment first (finding 185).
                    if (!"INSTALL PATCHES".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                        break;
                    }
                    response = UpdateManager.startOsPatchInstall();
                    logAudit("OS_PATCH_INSTALL", ip, response.optString("jobId", response.optString("error", "")));
                }
                case "os_fetch" -> {
                    if (!"FETCH UPDATES".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                        break;
                    }
                    response = UpdateManager.startSystemUpdateSearch();
                    logAudit("OS_UPDATE_FETCH", ip, response.optString("jobId", ""));
                }
                case "python_preflight" -> response = UpdateManager.pythonPreflight();
                case "python_leftovers" -> response = UpdateManager.pythonLeftovers(false);
                case "python_leftovers_clean" -> {
                    if (!"CLEAN PYTHON".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                        break;
                    }
                    response = UpdateManager.pythonLeftovers(true);
                    logAudit("PYTHON_LEFTOVERS_CLEAN", ip, response.optString("removed", ""));
                }
                case "python_move" -> {
                    if (!"MOVE PYTHON".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                        break;
                    }
                    response = UpdateManager.startPythonTransition(req.optString("signature", ""));
                    logAudit("PYTHON_MOVE_STARTED", ip, response.optString("jobId", ""));
                }
                case "java_preflight" -> response = UpdateManager.javaPreflight();
                case "java_status" -> response = UpdateManager.javaUpdateStatus();
                case "java_update" -> {
                    if (!"UPGRADE JAVA".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                        break;
                    }
                    logAudit("JAVA_UPDATE_STARTED", ip, "the panel will shut down");
                    response = UpdateManager.startJavaUpdate(req.optString("signature", ""));
                }
                case "roundcube_preflight" -> response = UpdateManager.roundcubePreflight();
                case "roundcube_diag" -> response = UpdateManager.roundcubeDiagnostics();
                case "roundcube_nginx_preview" -> response = UpdateManager.repairNginxPathInfo(false);
                case "roundcube_nginx_fix" -> {
                    if (!"FIX NGINX".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                        break;
                    }
                    response = UpdateManager.repairNginxPathInfo(true);
                    logAudit("ROUNDCUBE_NGINX_FIX", ip, response.optString("backup", ""));
                }
                case "roundcube_update" -> {
                    if (!"UPGRADE ROUNDCUBE".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                        break;
                    }
                    response = UpdateManager.startRoundcubeUpdate(req.optString("signature", ""));
                    logAudit("ROUNDCUBE_UPDATE_STARTED", ip, response.optString("jobId", ""));
                }
                case "clean_client" -> {
                    if (!"REMOVE".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                        break;
                    }
                    response = UpdateManager.startForeignClientCleanup(
                            req.optString("foreign", ""), req.optString("correct", ""));
                    logAudit("MYSQL_CLIENT_CLEANUP", ip, req.optString("foreign", ""));
                }
                case "relink" -> {
                    if (!"RELINK".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                        break;
                    }
                    response = UpdateManager.startRelinking();
                    logAudit("RELINK_STARTED", ip, response.optString("jobId", ""));
                }
                case "rspamd_clean_cache" -> {
                    // It is a deletion: the confirmation is typed by hand, and the path does not
                    // come from the request but is fixed in the code.
                    if (!"DELETE CACHE".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                        break;
                    }
                    response = UpdateManager.startRspamdCacheCleanup();
                    logAudit("RSPAMD_CACHE_CLEANED", ip, response.optString("jobId", ""));
                }
                case "mysql84_migrate" -> {
                    if (!"MIGRATE TO 8.4".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                        break;
                    }
                    response = UpdateManager.startMysql84Migration(req.optString("signature", ""));
                    logAudit("MYSQL84_MIGRATION_STARTED", ip, response.optString("jobId", ""));
                }
                case "dovecot24_move" -> {
                    if (!"MOVE TO DOVECOT 2.4".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                        break;
                    }
                    response = UpdateManager.startDovecot24Move(req.optString("signature", ""));
                    logAudit("DOVECOT24_MOVE_STARTED", ip, response.optString("jobId", ""));
                }
                case "package_preflight" -> {
                    String now = org.daemoxcp.mail.system.PackageQueue.planNotNow();
                    response = now != null ? new JSONObject().put("success", false).put("error", now)
                             : UpdateManager.packagePreflight(req.optString("package", ""));
                }
                case "package_update" -> {
                    // The confirmation is the PACKAGE NAME typed by hand: that way you cannot
                    // update the wrong one by mistake after reading the report of
                    // another. An "are you sure?" would not prevent it.
                    String pk = req.optString("package", "");
                    if (!pk.equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false)
                                .put("error", I18n.tr("server.updates.typePackage"));
                        break;
                    }
                    response = UpdateManager.startGuidedUpdate(pk, req.optString("signature", ""));
                    logAudit("GUIDED_UPDATE_STARTED", ip, pk + " -> " + response.optString("jobId", ""));
                }
                case "update_everything" -> {
                    // "Update all" (finding 207): the steps in order, each one with the fingerprint of the plan
                    // read, and the changes that the confirmation showed. The confirmation is the panel dialog
                    // that lists them all; the page sends the word, as for the plan of the other packages.
                    if (!"UPDATE".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                        break;
                    }
                    java.util.List<UpdateManager.EverythingStep> steps = new java.util.ArrayList<>();
                    JSONArray list = req.optJSONArray("steps");
                    for (int i = 0; list != null && i < list.length(); i++) {
                        JSONObject st = list.optJSONObject(i);
                        steps.add(st == null ? null : new UpdateManager.EverythingStep(st.optString("kind", ""),
                                st.optString("package", ""), st.optString("signature", "")));
                    }
                    java.util.Map<String, String> approved = new java.util.HashMap<>();
                    JSONArray shown = req.optJSONArray("approved");
                    for (int i = 0; shown != null && i < shown.length(); i++) {
                        JSONObject a = shown.optJSONObject(i);
                        if (a != null) approved.put(a.optString("name", ""), a.optString("to", ""));
                    }
                    response = UpdateManager.startEverything(steps, approved);
                    java.util.List<String> names = new java.util.ArrayList<>();
                    for (UpdateManager.EverythingStep st : steps) if (st != null) names.add(st.name().isEmpty() ? st.kind() : st.name());
                    logAudit("UPDATE_EVERYTHING_STARTED", ip, String.join(", ", names) + " -> " + response.optString("jobId", ""));
                }
                case "packages_lock" -> {
                    boolean lock = req.optBoolean("lock", true);
                    String only = req.optString("package", "");
                    response = UpdateManager.packagesLock(lock, only);
                    logAudit(lock ? "PACKAGES_LOCKED" : "PACKAGES_UNLOCKED", ip,
                            (only.isEmpty() ? "all" : only) + " -> " + response.optInt("changed", 0) + " changed");
                }
                case "updates_apply" -> {
                    // The confirmation typed by hand is not red tape: it tells a reflex click
                    // apart from a decision. Here a live mail server is being modified.
                    if (!"UPDATE".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                        break;
                    }
                    response = UpdateManager.startUnlockedPackagesUpdate(req.optString("signature", ""));
                    logAudit("UPDATES_APPLY_STARTED", ip, response.optString("jobId", ""));
                }
                case "maintenance_run" -> {
                    if (!"MAINTENANCE".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                        break;
                    }
                    response = UpdateManager.startMaintenance(req.optString("signature", ""));
                    logAudit("MAINTENANCE_STARTED", ip, response.optString("jobId", ""));
                }
                case "job_status" -> response = UpdateManager.jobStatus(req.optString("jobId", ""));
                // The on-disk logs of the jobs (JobJournal): they survive restarts, and are read from Diagnostics.
                case "journal_list" -> response = org.daemoxcp.mail.system.JobJournal.list(40);
                case "journal_read" -> response = org.daemoxcp.mail.system.JobJournal.read(req.optString("name", ""));
                default -> response = new JSONObject().put("success", false).put("error", I18n.tr("server.unknownAction"));
            }
            sendJsonResponse(exchange, response);
        } catch (java.io.IOException e) {
            // "Broken pipe" is not a server fault: it is the browser that closed before the
            // response was written, typically because the operation was taking long. The job
            // was done, the response was lost. Logging it as SEVERE with the whole stack trace
            // makes people believe something crashed, and that is exactly what happened on
            // 2026-08-31: an alarming message for a client that had gone away.
            String m = e.getMessage() == null ? "" : e.getMessage().toLowerCase();
            if (m.contains("broken pipe") || m.contains("insufficient bytes")
                    || m.contains("connection reset")) {
                LOGGER.info("/api/updates: the client closed the connection before the answer "
                        + "(the operation had already run). " + e.getMessage());
            } else {
                LOGGER.log(Level.SEVERE, "I/O error in /api/updates", e);
                try { sendJsonError(exchange, 500, I18n.tr("server.internalError")); } catch (Exception ignored) { }
            }
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error in /api/updates", e);
            sendJsonError(exchange, 500, I18n.tr("server.internalError"));
        }
    }

    private void handleApiClamavHealth(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) { sendJsonError(exchange, 401, I18n.tr("server.unauthorized")); return; }
        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();
        try {
            if ("GET".equals(method)) {
                response = buildClamavHealthReport();
            } else if ("POST".equals(method)) {
                String body = readRequestBodyWithLimit(exchange);
                if (body == null) { sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge")); return; }
                JSONObject req = new JSONObject(body);
                if (!validateCsrfForRequest(exchange, req)) { sendCsrfError(exchange); return; }
                String action = req.optString("action", "");
                String clientIp = getClientIp(exchange);
                switch (action) {
                    case "install_clamav" -> {
                        JSONObject r = installClamav();
                        response = r;
                        logAudit(r.optBoolean("success") ? "CLAMAV_INSTALLED" : "CLAMAV_INSTALL_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "enable_freshclam_at_boot" -> {
                        JSONObject r = sysrcSet("clamav_freshclam_enable", "YES");
                        response = r;
                        logAudit(r.optBoolean("success") ? "CLAMAV_FRESHCLAM_ENABLED" : "CLAMAV_FRESHCLAM_ENABLE_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "enable_clamd_at_boot" -> {
                        JSONObject r = sysrcSet("clamav_clamd_enable", "YES");
                        response = r;
                        logAudit(r.optBoolean("success") ? "CLAMAV_CLAMD_ENABLED" : "CLAMAV_CLAMD_ENABLE_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "update_db" -> {
                        JSONObject r = runFreshclam();
                        response = r;
                        logAudit(r.optBoolean("success") ? "CLAMAV_DB_UPDATED" : "CLAMAV_DB_UPDATE_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "start_clamd" -> {
                        JSONObject r = serviceCommand("clamav_clamd", "start", 60);
                        response = r;
                        logAudit(r.optBoolean("success") ? "CLAMAV_CLAMD_STARTED" : "CLAMAV_CLAMD_START_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "start_freshclam" -> {
                        JSONObject r = serviceCommand("clamav_freshclam", "start", 30);
                        response = r;
                        logAudit(r.optBoolean("success") ? "CLAMAV_FRESHCLAM_STARTED" : "CLAMAV_FRESHCLAM_START_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "ensure_rspamd_antivirus" -> {
                        JSONObject r = ensureRspamdAntivirusConfig();
                        response = r;
                        logAudit(r.optBoolean("success") ? "RSPAMD_ANTIVIRUS_CONFIGURED" : "RSPAMD_ANTIVIRUS_CONFIG_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "fix_all" -> {
                        JSONObject r = runClamavFixAll();
                        response = r;
                        logAudit(r.optBoolean("success") ? "CLAMAV_FIX_ALL_OK" : "CLAMAV_FIX_ALL_PARTIAL",
                            clientIp, r.optString("message", ""));
                    }
                    case "test_eicar" -> {
                        JSONObject r = runEicarTest();
                        response = r;
                        logAudit(r.optBoolean("success") ? "CLAMAV_EICAR_TEST_OK" : "CLAMAV_EICAR_TEST_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    default -> {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.badActionNamed", Map.of("action", action)));
                    }
                }
            } else {
                sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
                return;
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", ErrorText.forPage("handleApiClamavHealth", e));
        }
        sendJsonResponse(exchange, response);
    }

    private JSONObject buildClamavHealthReport() {
        JSONObject r = new JSONObject();
        JSONArray checks = new JSONArray();

        // 1. ClamAV installed
        boolean installed;
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/pkg", "info", "-e", "clamav");
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            installed = p.exitValue() == 0;
        } catch (Exception e) { installed = false; }
        checks.put(makeCheck("clamav-installed", I18n.tr("server.clam.checkInstalled"), installed,
            installed ? I18n.tr("server.clam.pkgPresent") : I18n.tr("server.clam.pkgMissing"),
            installed ? null : I18n.tr("server.clam.impactInstalled"),
            installed ? null : "install_clamav",
            I18n.tr("server.runs", Map.of("command", "pkg install -y clamav"))));

        // 2. freshclam enabled at boot
        boolean freshclamEnabledBoot = isSysrcYes("clamav_freshclam_enable");
        checks.put(makeCheck("freshclam-enabled-boot", I18n.tr("server.clam.checkFreshclamBoot"),
            freshclamEnabledBoot,
            freshclamEnabledBoot ? "clamav_freshclam_enable=YES" : I18n.tr("server.clam.freshclamNoBoot"),
            freshclamEnabledBoot ? null : I18n.tr("server.clam.impactFreshclamBoot"),
            (freshclamEnabledBoot || !installed) ? null : "enable_freshclam_at_boot",
            "sysrc clamav_freshclam_enable=YES"));

        // 3. clamd enabled at boot
        boolean clamdEnabledBoot = isSysrcYes("clamav_clamd_enable");
        checks.put(makeCheck("clamd-enabled-boot", I18n.tr("server.clam.checkClamdBoot"),
            clamdEnabledBoot,
            clamdEnabledBoot ? "clamav_clamd_enable=YES" : I18n.tr("server.clam.clamdNoBoot"),
            clamdEnabledBoot ? null : I18n.tr("server.clam.impactClamdBoot"),
            (clamdEnabledBoot || !installed) ? null : "enable_clamd_at_boot",
            "sysrc clamav_clamd_enable=YES"));

        // 4. Virus databases present (look for .cvd, .cld, .cud -- all the ClamAV formats)
        boolean dbPresent = false;
        long dbAgeDays = -1;
        try {
            java.nio.file.Path dbDir = java.nio.file.Paths.get("/var/db/clamav");
            if (java.nio.file.Files.isDirectory(dbDir)) {
                try (java.util.stream.Stream<java.nio.file.Path> s = java.nio.file.Files.walk(dbDir, 2)) {
                    java.util.List<java.nio.file.Path> dbFiles = s
                        .filter(p -> {
                            String n = p.getFileName().toString().toLowerCase();
                            // ClamAV signature formats: .cvd (compressed), .cld (downloaded),
                            // .cud (compressed updates), .hdb, .ndb, .ldb, .fp
                            return (n.endsWith(".cvd") || n.endsWith(".cld") || n.endsWith(".cud"))
                                && (n.startsWith("main") || n.startsWith("daily") || n.startsWith("bytecode"));
                        }).collect(java.util.stream.Collectors.toList());
                    if (!dbFiles.isEmpty()) {
                        dbPresent = true;
                        java.time.Instant newest = dbFiles.stream()
                            .map(p -> { try { return java.nio.file.Files.getLastModifiedTime(p).toInstant(); } catch (Exception e) { return java.time.Instant.EPOCH; } })
                            .max(java.time.Instant::compareTo).orElse(java.time.Instant.EPOCH);
                        dbAgeDays = java.time.Duration.between(newest, java.time.Instant.now()).toDays();
                    }
                }
            }
        } catch (Exception ignored) {}
        // Fallback: if clamd answers clamdscan, the DB is there even if we do not recognise its files
        if (!dbPresent) {
            try {
                // TODO: migrate to Shell.run when touched
                ProcessBuilder pb = new ProcessBuilder("/usr/local/bin/clamdscan", "--version");
                org.daemoxcp.mail.util.Shell.applyPath(pb);
                pb.redirectErrorStream(true);
                Process p = pb.start();
                String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
                // clamdscan --version returns info on clamd including the database version
                // e.g.: "ClamAV 1.5.1/27582/Wed May 14 ..."
                if (out.contains("/") && out.matches("(?s).*\\d+/.*")) {
                    dbPresent = true;
                    // estimated age 0 because clamd answers correctly
                    if (dbAgeDays < 0) dbAgeDays = 0;
                }
            } catch (Exception ignored) {}
        }
        String dbStatus = dbPresent
            ? I18n.tr("server.clam.dbFound", Map.of("days", dbAgeDays))
            : I18n.tr("server.clam.dbNone");
        boolean dbOk = dbPresent && dbAgeDays <= 7;
        checks.put(makeCheck("clamav-db", I18n.tr("server.clam.checkDb"),
            dbOk,
            dbPresent
                ? (dbAgeDays > 7 ? I18n.tr("server.clam.dbOld", Map.of("status", dbStatus)) : dbStatus)
                : dbStatus,
            dbOk ? null
                : (dbPresent ? I18n.tr("server.clam.impactDbOld")
                             : I18n.tr("server.clam.impactDbMissing")),
            (dbOk || !installed) ? null : "update_db",
            I18n.tr("server.clam.fixDb")));

        // 5. clamd running
        boolean clamdRunning = isServiceRunning("clamav_clamd");
        checks.put(makeCheck("clamd-running", I18n.tr("server.clam.checkClamdRunning"),
            clamdRunning,
            clamdRunning ? I18n.tr("server.clam.clamdRunning")
                         : (dbPresent ? I18n.tr("server.serviceStopped") : I18n.tr("server.clam.clamdNoDb")),
            clamdRunning ? null
                : I18n.tr("server.clam.impactClamdRunning"),
            (clamdRunning || !installed || !dbPresent) ? null : "start_clamd",
            I18n.tr("server.clam.fixClamdRunning")));

        // 6. freshclam running (auto-update) -- strict check
        boolean freshclamRunning = isServiceRunning("clamav_freshclam");
        // Log analysis: look for "is up to date" or "downloading" in the last 48h
        FreshclamLogStatus fcLog = analyzeFreshclamLog();
        boolean autoUpdateOk = freshclamRunning && fcLog.lastUpdateAgeHours >= 0 && fcLog.lastUpdateAgeHours <= 48;
        String fcStatusText;
        if (!freshclamRunning) {
            fcStatusText = I18n.tr("server.serviceStopped");
        } else if (fcLog.lastUpdateAgeHours < 0) {
            fcStatusText = I18n.tr("server.clam.fcNoUpdates");
        } else if (fcLog.lastUpdateAgeHours <= 2) {
            fcStatusText = I18n.tr("server.clam.fcRecent", Map.of("hours", fcLog.lastUpdateAgeHours));
        } else if (fcLog.lastUpdateAgeHours <= 48) {
            fcStatusText = I18n.tr("server.clam.fcHoursAgo", Map.of("hours", fcLog.lastUpdateAgeHours));
        } else {
            fcStatusText = I18n.tr("server.clam.fcOld", Map.of("days", fcLog.lastUpdateAgeHours / 24));
        }
        if (fcLog.lastErrorMessage != null) {
            fcStatusText += " | " + I18n.tr("server.clam.fcLastError", Map.of("error", fcLog.lastErrorMessage));
        }
        checks.put(makeCheck("freshclam-running", I18n.tr("server.clam.checkFreshclamRunning"),
            autoUpdateOk,
            fcStatusText,
            autoUpdateOk ? null
                : (freshclamRunning
                    ? I18n.tr("server.clam.impactFcNotUpdating")
                    : I18n.tr("server.clam.impactFcStopped")),
            (autoUpdateOk || !installed) ? null
                : (freshclamRunning ? "update_db" : "start_freshclam"),
            freshclamRunning ? I18n.tr("server.clam.fixFcForce") : "service clamav_freshclam start"));

        // 7. Rspamd -> ClamAV configured
        boolean rspamdHasAntivirus = false;
        try {
            java.nio.file.Path conf = java.nio.file.Paths.get("/usr/local/etc/rspamd/local.d/antivirus.conf");
            if (java.nio.file.Files.exists(conf)) {
                String c = java.nio.file.Files.readString(conf);
                rspamdHasAntivirus = c.contains("clamav") && c.contains("clamd.sock");
            }
        } catch (Exception ignored) {}
        checks.put(makeCheck("rspamd-antivirus", I18n.tr("server.clam.checkRspamd"),
            rspamdHasAntivirus,
            rspamdHasAntivirus ? I18n.tr("server.clam.rspamdOk")
                               : I18n.tr("server.clam.rspamdMissing"),
            rspamdHasAntivirus ? null
                : I18n.tr("server.clam.impactRspamd"),
            (rspamdHasAntivirus || !installed) ? null : "ensure_rspamd_antivirus",
            I18n.tr("server.clam.fixRspamd")));

        boolean allOk = installed && freshclamEnabledBoot && clamdEnabledBoot && dbOk
            && clamdRunning && freshclamRunning && rspamdHasAntivirus;
        r.put("success", true);
        r.put("all_ok", allOk);
        r.put("can_fix_all", !allOk);
        r.put("checks", checks);
        return r;
    }

    /** freshclam status from its log. */
    private static class FreshclamLogStatus {
        /** Age in hours of the latest evidence of an update/check. -1 if none. */
        long lastUpdateAgeHours = -1;
        /** Any recent error message. */
        String lastErrorMessage = null;
    }

    /**
     * Analyses /var/log/clamav/freshclam.log to establish WHETHER freshclam is
     * really updating the databases or has errors. Looks for typical patterns:
     *   - "Time: ... update completed"
     *   - "main.cvd is up to date"
     *   - "Downloading"
     *   - "ERROR:" / "WARNING:"
     */
    private FreshclamLogStatus analyzeFreshclamLog() {
        FreshclamLogStatus result = new FreshclamLogStatus();
        java.nio.file.Path logPath = java.nio.file.Paths.get("/var/log/clamav/freshclam.log");
        if (!java.nio.file.Files.exists(logPath)) return result;

        try {
            // Read the last ~200 lines of the log
            java.util.List<String> lines = new java.util.ArrayList<>();
            try (java.io.RandomAccessFile raf = new java.io.RandomAccessFile(logPath.toFile(), "r")) {
                long fileSize = raf.length();
                long start = Math.max(0, fileSize - 32 * 1024); // last 32KB
                raf.seek(start);
                if (start > 0) raf.readLine(); // discard the partial line
                String line;
                while ((line = raf.readLine()) != null) lines.add(line);
            }

            // Search from the last line back to the first for the line showing a successful update or check
            // Positive patterns: "up-to-date", "is up to date", "updated", "Downloading", "Time:"
            // Negative patterns (error): "ERROR:", "Can't download", "Mirror error"
            java.util.regex.Pattern timestampPat = java.util.regex.Pattern.compile(
                "(?:^|\\s)([A-Z][a-z]{2}\\s+\\w+\\s+\\d+\\s+\\d{2}:\\d{2}:\\d{2}\\s+\\d{4})"
            );
            String lastErrorLine = null;
            for (int i = lines.size() - 1; i >= 0; i--) {
                String ln = lines.get(i);
                String lower = ln.toLowerCase();
                if (lastErrorLine == null && (lower.contains("error:") || lower.contains("can't download") || lower.contains("mirror error") || lower.contains("warning:"))) {
                    String snippet = ln.length() > 200 ? ln.substring(0, 200) : ln;
                    lastErrorLine = snippet.trim();
                }
                if (lower.contains("up to date") || lower.contains("up-to-date")
                    || lower.contains("updated.") || lower.contains("downloading")
                    || lower.contains("daily.cvd updated") || lower.contains("main.cvd updated")) {
                    // Find a timestamp in the line (look for the pattern "Mon Day HH:MM:SS YYYY" or ISO)
                    java.util.regex.Matcher m = timestampPat.matcher(ln);
                    if (m.find()) {
                        try {
                            // Pattern: "Wed May 14 18:30:00 2026"
                            java.text.SimpleDateFormat dateFormat = new java.text.SimpleDateFormat("EEE MMM d HH:mm:ss yyyy", java.util.Locale.US);
                            java.util.Date d = dateFormat.parse(m.group(1).trim());
                            long diffMs = System.currentTimeMillis() - d.getTime();
                            result.lastUpdateAgeHours = diffMs / (1000L * 60 * 60);
                            break;
                        } catch (Exception ignored) {}
                    }
                    // If it cannot parse the timestamp but the "up to date" line is there,
                    // mark it anyway as "present but age unknown" -> 0 (we assume recent)
                    if (result.lastUpdateAgeHours < 0) result.lastUpdateAgeHours = 0;
                    break;
                }
            }
            result.lastErrorMessage = lastErrorLine;
        } catch (Exception e) {
            LOGGER.warning("analyzeFreshclamLog: " + e.getMessage());
        }
        return result;
    }

    private boolean isSysrcYes(String key) {
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/sysrc", "-n", key);
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).trim();
            p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            return out.equalsIgnoreCase("YES");
        } catch (Exception e) { return false; }
    }

    private boolean isServiceRunning(String name) {
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/service", name, "status");
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            return out.toLowerCase().contains("is running");
        } catch (Exception e) { return false; }
    }

    private JSONObject sysrcSet(String key, String value) {
        JSONObject r = new JSONObject();
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/sysrc", key + "=" + value);
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
            r.put("success", p.exitValue() == 0);
            r.put("message", p.exitValue() == 0 ? "OK: " + key + "=" + value : "sysrc exit=" + p.exitValue());
            r.put("output", out);
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", I18n.tr("server.errorWith", Map.of("error", ErrorText.detail("sysrcSet", e))));
        }
        return r;
    }

    private JSONObject serviceCommand(String svc, String cmd, int timeoutSeconds) {
        JSONObject r = new JSONObject();
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/service", svc, cmd);
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            p.waitFor(timeoutSeconds, java.util.concurrent.TimeUnit.SECONDS);
            boolean ok = p.exitValue() == 0;
            r.put("success", ok);
            r.put("message", ok ? I18n.tr("server.service.cmdOk", java.util.Map.of("svc", String.valueOf(svc), "cmd", String.valueOf(cmd))) : "service " + svc + " " + cmd + " exit=" + p.exitValue());
            r.put("output", out);
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", I18n.tr("server.errorWith", Map.of("error", ErrorText.detail("serviceCommand", e))));
        }
        return r;
    }

    private JSONObject installClamav() {
        return onPackageTurn(I18n.tr("server.install.jobName", Map.of("component", "ClamAV")), this::runInstallClamav);
    }

    private JSONObject runInstallClamav() {
        JSONObject r = new JSONObject();
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/pkg", "install", "-y", "clamav");
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            boolean done = p.waitFor(300, java.util.concurrent.TimeUnit.SECONDS);
            if (!done) { p.destroyForcibly(); r.put("success", false); r.put("message", I18n.tr("server.install.timeout5")); return r; }
            r.put("success", p.exitValue() == 0);
            r.put("message", p.exitValue() == 0 ? I18n.tr("server.clam.installed") : "pkg install exit=" + p.exitValue());
            r.put("output", out.length() > 4000 ? out.substring(out.length() - 4000) : out);
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", I18n.tr("server.errorWith", Map.of("error", ErrorText.detail("runInstallClamav", e))));
        }
        return r;
    }

    private JSONObject runFreshclam() {
        JSONObject r = new JSONObject();
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/local/bin/freshclam", "--foreground", "--stdout");
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            boolean done = p.waitFor(600, java.util.concurrent.TimeUnit.SECONDS); // 10 min
            if (!done) { p.destroyForcibly(); r.put("success", false); r.put("message", I18n.tr("server.clam.timeout")); return r; }
            r.put("success", p.exitValue() == 0);
            r.put("message", p.exitValue() == 0 ? I18n.tr("server.clam.dbUpdated") : I18n.tr("server.clam.exit", Map.of("code", String.valueOf(p.exitValue()))));
            r.put("output", out.length() > 4000 ? out.substring(out.length() - 4000) : out);
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", I18n.tr("server.errorWith", Map.of("error", ErrorText.detail("runFreshclam", e))));
        }
        return r;
    }

    /**
     * End-to-end EICAR test:
     *  1. Creates a temporary file with the EICAR payload (harmless standard virus)
     *  2. Runs clamdscan on the file
     *  3. Checks that the answer contains "FOUND" (clamd detected the virus)
     *  4. Cleans up the file
     *
     * This confirms that the clamd->clamdscan pipeline works end to end.
     * If it passes, ClamAV really protects. If it fails, there is a concrete problem.
     */
    private JSONObject runEicarTest() {
        JSONObject r = new JSONObject();
        java.nio.file.Path tmp = null;
        try {
            // EICAR standard test string -- recognised by ALL antivirus software, harmless
            String eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
            tmp = java.nio.file.Files.createTempFile("eicar-test-", ".txt");
            java.nio.file.Files.writeString(tmp, eicar, java.nio.charset.StandardCharsets.US_ASCII);
            // Perm 644 so the clamav user can read it
            try {
                java.nio.file.Files.setPosixFilePermissions(tmp,
                    java.nio.file.attribute.PosixFilePermissions.fromString("rw-r--r--"));
            } catch (Exception ignored) {}

            // Run clamdscan
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/local/bin/clamdscan", "--no-summary", tmp.toString());
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            boolean done = p.waitFor(30, java.util.concurrent.TimeUnit.SECONDS);
            if (!done) { p.destroyForcibly(); r.put("success", false); r.put("message", I18n.tr("server.clam.scanTimeout")); return r; }
            int exit = p.exitValue();

            // Interpreting the clamdscan exit code:
            //   0 = no virus
            //   1 = VIRUS FOUND (that is what we want!)
            //   2 = error
            if (exit == 1 && out.contains("FOUND") && (out.contains("EICAR") || out.contains("Eicar"))) {
                r.put("success", true);
                r.put("message", "✅ " + I18n.tr("server.clam.eicarOk"));
                r.put("scan_output", out.trim());
                r.put("detected", true);
            } else if (exit == 2) {
                r.put("success", false);
                r.put("message", "❌ " + I18n.tr("server.clam.eicarError"));
                r.put("scan_output", out.trim());
            } else if (exit == 0) {
                r.put("success", false);
                r.put("message", "⚠️ " + I18n.tr("server.clam.eicarMissed"));
                r.put("scan_output", out.trim());
            } else {
                r.put("success", false);
                r.put("message", "❓ " + I18n.tr("server.clam.eicarUnexpected", Map.of("exit", exit)));
                r.put("scan_output", out.trim());
            }
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", I18n.tr("server.errorWith", Map.of("error", ErrorText.detail("runEicarTest", e))));
        } finally {
            if (tmp != null) {
                try { java.nio.file.Files.deleteIfExists(tmp); } catch (Exception ignored) {}
            }
        }
        return r;
    }

    private JSONObject ensureRspamdAntivirusConfig() {
        JSONObject r = new JSONObject();
        try {
            java.nio.file.Path confDir = java.nio.file.Paths.get("/usr/local/etc/rspamd/local.d");
            if (!java.nio.file.Files.isDirectory(confDir)) {
                java.nio.file.Files.createDirectories(confDir);
            }
            java.nio.file.Path conf = confDir.resolve("antivirus.conf");
            String content = ""
                + "# Managed by DaemoxCP Mail: Rspamd → ClamAV\n"
                + "clamav {\n"
                + "  action = \"reject\";\n"
                + "  symbol = \"CLAM_VIRUS\";\n"
                + "  type = \"clamav\";\n"
                + "  servers = \"/var/run/clamav/clamd.sock\";\n"
                + "  scan_mime_parts = true;\n"
                + "  scan_text_mime = false;\n"
                + "  scan_image_mime = false;\n"
                + "}\n";
            // Backup if it exists
            if (java.nio.file.Files.exists(conf)) {
                org.daemoxcp.mail.system.ConfigBackups.copy(conf);
            }
            java.nio.file.Files.writeString(conf, content, java.nio.charset.StandardCharsets.UTF_8);
            // Reload rspamd
            try {
                // TODO: migrate to Shell.run when touched
                ProcessBuilder pb = new ProcessBuilder("/usr/sbin/service", "rspamd", "reload");
                org.daemoxcp.mail.util.Shell.applyPath(pb);
                pb.redirectErrorStream(true);
                Process p = pb.start();
                p.waitFor(15, java.util.concurrent.TimeUnit.SECONDS);
            } catch (Exception ignored) {}
            r.put("success", true);
            r.put("message", I18n.tr("server.clamav.confWritten"));
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", I18n.tr("server.errorWith", Map.of("error", ErrorText.detail("ensureRspamdAntivirusConfig", e))));
        }
        return r;
    }

    /** Runs all the fixes needed for ClamAV in the correct order. */
    private JSONObject runClamavFixAll() {
        JSONObject r = new JSONObject();
        JSONArray steps = new JSONArray();
        boolean anyFailed = false;

        // 1. Install
        boolean installed;
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/pkg", "info", "-e", "clamav");
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            installed = p.exitValue() == 0;
        } catch (Exception e) { installed = false; }
        if (!installed) {
            JSONObject res = installClamav();
            steps.put(buildStep("install_clamav", I18n.tr("server.clam.step.install"), res));
            if (!res.optBoolean("success")) anyFailed = true;
            installed = res.optBoolean("success");
        } else {
            steps.put(buildSkipStep("install_clamav", I18n.tr("server.clam.step.installed")));
        }

        if (!installed) {
            r.put("success", false);
            r.put("steps", steps);
            r.put("message", I18n.tr("server.clam.installFailed"));
            return r;
        }

        // 2. Enable freshclam at boot
        if (!isSysrcYes("clamav_freshclam_enable")) {
            JSONObject res = sysrcSet("clamav_freshclam_enable", "YES");
            steps.put(buildStep("enable_freshclam_boot", I18n.tr("server.step.enableBoot", Map.of("service", "freshclam")), res));
            if (!res.optBoolean("success")) anyFailed = true;
        } else {
            steps.put(buildSkipStep("enable_freshclam_boot", I18n.tr("server.unbound.step.bootAlready", Map.of("service", "freshclam"))));
        }

        // 3. Enable clamd at boot
        if (!isSysrcYes("clamav_clamd_enable")) {
            JSONObject res = sysrcSet("clamav_clamd_enable", "YES");
            steps.put(buildStep("enable_clamd_boot", I18n.tr("server.step.enableBoot", Map.of("service", "clamd")), res));
            if (!res.optBoolean("success")) anyFailed = true;
        } else {
            steps.put(buildSkipStep("enable_clamd_boot", I18n.tr("server.unbound.step.bootAlready", Map.of("service", "clamd"))));
        }

        // 4. Update the database (may take minutes)
        boolean dbPresent = false;
        try {
            java.nio.file.Path dbDir = java.nio.file.Paths.get("/var/db/clamav");
            if (java.nio.file.Files.isDirectory(dbDir)) {
                try (java.util.stream.Stream<java.nio.file.Path> s = java.nio.file.Files.list(dbDir)) {
                    dbPresent = s.anyMatch(p -> {
                        String n = p.getFileName().toString();
                        return n.endsWith(".cvd") || n.endsWith(".cld");
                    });
                }
            }
        } catch (Exception ignored) {}
        if (!dbPresent) {
            JSONObject res = runFreshclam();
            steps.put(buildStep("update_db", I18n.tr("server.clam.step.downloadDb"), res));
            if (!res.optBoolean("success")) anyFailed = true;
        } else {
            steps.put(buildSkipStep("update_db", I18n.tr("server.clam.step.dbPresent")));
        }

        // 5. Start freshclam
        if (!isServiceRunning("clamav_freshclam")) {
            JSONObject res = serviceCommand("clamav_freshclam", "start", 30);
            steps.put(buildStep("start_freshclam", I18n.tr("server.unbound.step.start", Map.of("service", "freshclam")), res));
            if (!res.optBoolean("success")) anyFailed = true;
        } else {
            steps.put(buildSkipStep("start_freshclam", I18n.tr("server.unbound.step.running", Map.of("service", "freshclam"))));
        }

        // 6. Start clamd
        if (!isServiceRunning("clamav_clamd")) {
            JSONObject res = serviceCommand("clamav_clamd", "start", 60);
            steps.put(buildStep("start_clamd", I18n.tr("server.clam.step.startClamd"), res));
            if (!res.optBoolean("success")) anyFailed = true;
        } else {
            steps.put(buildSkipStep("start_clamd", I18n.tr("server.unbound.step.running", Map.of("service", "clamd"))));
        }

        // 7. Configure Rspamd -> ClamAV
        boolean rspamdConfigured = false;
        try {
            java.nio.file.Path conf = java.nio.file.Paths.get("/usr/local/etc/rspamd/local.d/antivirus.conf");
            if (java.nio.file.Files.exists(conf)) {
                String c = java.nio.file.Files.readString(conf);
                rspamdConfigured = c.contains("clamav") && c.contains("clamd.sock");
            }
        } catch (Exception ignored) {}
        if (!rspamdConfigured) {
            JSONObject res = ensureRspamdAntivirusConfig();
            steps.put(buildStep("ensure_rspamd_antivirus", I18n.tr("server.clam.step.rspamd"), res));
            if (!res.optBoolean("success")) anyFailed = true;
        } else {
            steps.put(buildSkipStep("ensure_rspamd_antivirus", I18n.tr("server.clam.step.rspamdDone")));
        }

        r.put("success", !anyFailed);
        r.put("steps", steps);
        r.put("message", I18n.tr(anyFailed ? "server.unbound.someFailed" : "server.clam.allDone"));
        return r;
    }

    private void handleApiFail2banHealth(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
            return;
        }
        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();
        try {
            if ("GET".equals(method)) {
                response = buildFail2banHealthReport();
            } else if ("POST".equals(method)) {
                String body = readRequestBodyWithLimit(exchange);
                if (body == null) { sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge")); return; }
                JSONObject req = new JSONObject(body);
                if (!validateCsrfForRequest(exchange, req)) { sendCsrfError(exchange); return; }
                String action = req.optString("action", "");
                String clientIp = getClientIp(exchange);
                switch (action) {
                    case "install_fail2ban" -> {
                        JSONObject r = installFail2ban();
                        response = r;
                        logAudit(r.optBoolean("success", false) ? "FAIL2BAN_INSTALLED" : "FAIL2BAN_INSTALL_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "enable_at_boot" -> {
                        JSONObject r = enableFail2banAtBoot();
                        response = r;
                        logAudit(r.optBoolean("success", false) ? "FAIL2BAN_ENABLED_AT_BOOT" : "FAIL2BAN_ENABLE_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "start_service" -> {
                        JSONObject r = startFail2banService();
                        response = r;
                        logAudit(r.optBoolean("success", false) ? "FAIL2BAN_STARTED" : "FAIL2BAN_START_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "setup_mail_jail" -> {
                        org.daemoxcp.mail.security.Fail2banAutoSetup.run();
                        response.put("success", true);
                        response.put("message", I18n.tr("server.f2b.setupDone"));
                        logAudit("FAIL2BAN_AUTOSETUP_TRIGGERED", clientIp, "manual trigger from health page");
                    }
                    case "install_mail_jails" -> {
                        Fail2banManager.InstallResult res = fail2banManager.installMailJails();
                        response.put("success", res.success);
                        response.put("message", res.success ? res.message : (res.error != null ? res.error : I18n.tr("server.install.failed")));
                        if (res.configPath != null) response.put("config_path", res.configPath);
                        logAudit(res.success ? "FAIL2BAN_MAIL_JAILS_INSTALLED" : "FAIL2BAN_MAIL_JAILS_FAILED",
                            clientIp, res.success ? res.configPath : (res.error != null ? res.error : ""));
                    }
                    case "repair_ban_action" -> {
                        JSONObject rr = org.daemoxcp.mail.security.BanActionRepair.repair();
                        response = rr;
                        logAudit(rr.optBoolean("success", false) ? "FAIL2BAN_BANACTION_REPAIRED"
                                                                 : "FAIL2BAN_BANACTION_REPAIR_FAILED",
                            clientIp, rr.optString("message", ""));
                    }
                    case "start_pf" -> {
                        JSONObject r = startPfService();
                        response = r;
                        logAudit(r.optBoolean("success", false) ? "PF_STARTED" : "PF_START_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "enable_pf_at_boot" -> {
                        JSONObject r = enablePfAtBoot();
                        response = r;
                        logAudit(r.optBoolean("success", false) ? "PF_ENABLED_AT_BOOT" : "PF_ENABLE_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "add_pf_anchor" -> {
                        JSONObject r = addPfAnchorF2b();
                        response = r;
                        logAudit(r.optBoolean("success", false) ? "PF_ANCHOR_ADDED" : "PF_ANCHOR_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "create_pf_conf_minimal" -> {
                        JSONObject r = createPfConfMinimal();
                        response = r;
                        logAudit(r.optBoolean("success", false) ? "PF_CONF_CREATED" : "PF_CONF_CREATE_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "load_pf_module" -> {
                        JSONObject r = loadPfModule();
                        response = r;
                        logAudit(r.optBoolean("success", false) ? "PF_MODULE_LOADED" : "PF_MODULE_LOAD_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "reload_fail2ban" -> {
                        JSONObject r = reloadFail2banAction();
                        response = r;
                        logAudit(r.optBoolean("success", false) ? "FAIL2BAN_RELOADED" : "FAIL2BAN_RELOAD_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "restart_service" -> {
                        JSONObject r = restartFail2banService();
                        response = r;
                        logAudit(r.optBoolean("success", false) ? "FAIL2BAN_RESTARTED" : "FAIL2BAN_RESTART_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "fix_all" -> {
                        JSONObject r = runFixAll();
                        response = r;
                        logAudit(r.optBoolean("success", false) ? "FAIL2BAN_FIX_ALL_OK" : "FAIL2BAN_FIX_ALL_PARTIAL",
                            clientIp, r.optString("message", ""));
                    }
                    default -> {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.badActionNamed", Map.of("action", action)));
                    }
                }
            } else {
                sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
                return;
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", ErrorText.forPage("handleApiFail2banHealth", e));
        }
        sendJsonResponse(exchange, response);
    }

    /**
     * GET /api/panel_info?action=uptime|details: the panel card at the top of the dashboard
     * (PanelInfo, finding 183). The filter (Access) has already checked the permission: uptime with
     * home.view, details with system.view. The uptime response says whether the viewer can also
     * ask for the details, so that the page shows the eye only to them.
     */
    private void handleApiMailboxQuota(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
            return;
        }
        sendJsonResponse(exchange, org.daemoxcp.mail.system.DovecotQuota.usage());
    }

    private void handleApiPanelInfo(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
            return;
        }
        String action = extractParamFromQuery(exchange.getRequestURI().getQuery(), "action");
        switch (action == null ? "" : action) {
            case "uptime" -> {
                boolean details = currentSession(exchange).map(s -> AuthStore.may(s.admin(), SYSTEM_VIEW)).orElse(false);
                JSONObject r = org.daemoxcp.mail.system.PanelInfo.uptime(java.time.Instant.now(), details);
                // A new version on GitHub (ReleaseCheck), for whoever sees the system pages: the last saved
                // result, without the network.
                if (details) r.put("release", org.daemoxcp.mail.system.ReleaseCheck.available());
                sendJsonResponse(exchange, r);
            }
            case "details" -> sendJsonResponse(exchange, org.daemoxcp.mail.system.PanelInfo.details(port));
            default -> sendJsonError(exchange, 400, I18n.tr("server.unknownAction"));
        }
    }

    /**
     * Diagnostic endpoint: returns all the paths the panel is using,
     * grouped by category, each one with a status (exists / size / mtime).
     * Useful for debugging and for quick copy/paste during troubleshooting.
     */
    private void handleApiSystemPaths(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
            return;
        }
        if (!"GET".equals(exchange.getRequestMethod())) {
            sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
            return;
        }
        JSONObject response = new JSONObject();
        try {
            JSONArray categories = new JSONArray();

            // === Roundcube (auto-detect) ===
            JSONArray rcEntries = new JSONArray();
            String rcInstall = fail2banManager.detectRoundcubeInstallPath();
            if (rcInstall != null) {
                rcEntries.put(pathEntry(I18n.tr("server.paths.install"), rcInstall, I18n.tr("server.paths.installDesc")));
                rcEntries.put(pathEntry(I18n.tr("server.paths.configFile"), rcInstall + "/config/config.inc.php", I18n.tr("server.paths.configFileDesc")));
                rcEntries.put(pathEntry(I18n.tr("server.paths.logsDir"), rcInstall + "/logs", I18n.tr("server.paths.logsDirDesc")));
                rcEntries.put(pathEntry(I18n.tr("server.paths.loginLog"), rcInstall + "/logs/userlogins", I18n.tr("server.paths.loginLogDesc")));
                rcEntries.put(pathEntry(I18n.tr("server.paths.errorsLog"), rcInstall + "/logs/errors", I18n.tr("server.paths.errorsLogDesc")));
            } else {
                rcEntries.put(new JSONObject().put("label", I18n.tr("server.paths.rcNotFound"))
                    .put("path", I18n.tr("server.paths.rcNotFoundDesc"))
                    .put("exists", false));
            }
            categories.put(new JSONObject().put("name", "Roundcube").put("entries", rcEntries));

            // === Fail2ban ===
            JSONArray f2bEntries = new JSONArray();
            f2bEntries.put(pathEntry(I18n.tr("server.paths.f2bClient"), "/usr/local/bin/fail2ban-client", I18n.tr("server.paths.f2bClientDesc")));
            f2bEntries.put(pathEntry(I18n.tr("server.paths.jailMain"), "/usr/local/etc/fail2ban/jail.local", I18n.tr("server.paths.jailMainDesc")));
            f2bEntries.put(pathEntry(I18n.tr("server.paths.jailMail"), "/usr/local/etc/fail2ban/jail.d/mail.local", I18n.tr("server.paths.jailMailDesc")));
            f2bEntries.put(pathEntry(I18n.tr("server.paths.filterDir"), "/usr/local/etc/fail2ban/filter.d", I18n.tr("server.paths.filterDirDesc")));
            f2bEntries.put(pathEntry(I18n.tr("server.paths.filterPanel"), "/usr/local/etc/fail2ban/filter.d/daemoxcp-mail-auth.conf", I18n.tr("server.paths.filterPanelDesc")));
            f2bEntries.put(pathEntry(I18n.tr("server.paths.filterRc"), "/usr/local/etc/fail2ban/filter.d/roundcube-auth.conf", I18n.tr("server.paths.filterRcDesc")));
            f2bEntries.put(pathEntry(I18n.tr("server.paths.f2bLog"), "/var/log/fail2ban.log", I18n.tr("server.paths.f2bLogDesc")));
            categories.put(new JSONObject().put("name", "Fail2ban").put("entries", f2bEntries));

            // === DaemoxCP Mail ===
            JSONArray panelEntries = new JSONArray();
            panelEntries.put(pathEntry(I18n.tr("server.paths.panelAuthLog"), "/var/log/daemoxcp-mail-auth.log", I18n.tr("server.paths.panelAuthLogDesc")));
            panelEntries.put(pathEntry(I18n.tr("server.paths.newsyslog"), "/usr/local/etc/newsyslog.conf.d/daemoxcp-mail-auth.conf", I18n.tr("server.paths.newsyslogDesc")));
            // The separated panel (PanelSeparation): the web part's log and the root's socket.
            panelEntries.put(pathEntry(I18n.tr("server.paths.panelWebLog"), "/var/db/daemoxcp-mail/panel-web.log", I18n.tr("server.paths.panelWebLogDesc")));
            panelEntries.put(pathEntry(I18n.tr("server.paths.rootSocket"), org.daemoxcp.mail.system.PanelSeparation.socket().toString(), I18n.tr("server.paths.rootSocketDesc")));
            categories.put(new JSONObject().put("name", I18n.tr("brand.name")).put("entries", panelEntries));

            // === pf (firewall) ===
            JSONArray pfEntries = new JSONArray();
            pfEntries.put(pathEntry(I18n.tr("server.paths.pfConf"), "/etc/pf.conf", I18n.tr("server.paths.pfConfDesc")));
            pfEntries.put(pathEntry(I18n.tr("server.paths.pfctl"), "/sbin/pfctl", I18n.tr("server.paths.pfctlDesc")));
            pfEntries.put(pathEntry(I18n.tr("server.paths.rcConf"), "/etc/rc.conf", I18n.tr("server.paths.rcConfDesc")));
            pfEntries.put(pathEntry(I18n.tr("server.paths.loaderConf"), "/boot/loader.conf", I18n.tr("server.paths.loaderConfDesc")));
            categories.put(new JSONObject().put("name", "pf (firewall)").put("entries", pfEntries));

            // === Mail services ===
            JSONArray mailEntries = new JSONArray();
            mailEntries.put(pathEntry(I18n.tr("server.paths.postfixConf"), "/usr/local/etc/postfix/main.cf", I18n.tr("server.paths.postfixConfDesc")));
            mailEntries.put(pathEntry(I18n.tr("server.paths.postfixMaster"), "/usr/local/etc/postfix/master.cf", I18n.tr("server.paths.postfixMasterDesc")));
            mailEntries.put(pathEntry(I18n.tr("server.paths.dovecotConf"), "/usr/local/etc/dovecot/dovecot.conf", I18n.tr("server.paths.dovecotConfDesc")));
            mailEntries.put(pathEntry(I18n.tr("server.paths.maillog"), "/var/log/maillog", I18n.tr("server.paths.maillogDesc")));
            mailEntries.put(pathEntry(I18n.tr("server.paths.rspamdLog"), "/var/log/rspamd/rspamd.log", I18n.tr("server.paths.rspamdLogDesc")));
            mailEntries.put(pathEntry(I18n.tr("server.paths.rspamdConf"), "/usr/local/etc/rspamd/local.d", I18n.tr("server.paths.rspamdConfDesc")));
            categories.put(new JSONObject().put("name", I18n.tr("server.paths.mailServices")).put("entries", mailEntries));

            // === SSL ===
            JSONArray sslEntries = new JSONArray();
            sslEntries.put(pathEntry(I18n.tr("server.paths.certChain"), "/usr/local/etc/ssl/mail/fullchain.pem", I18n.tr("server.paths.certChainDesc")));
            sslEntries.put(pathEntry(I18n.tr("server.paths.privKey"), "/usr/local/etc/ssl/mail/privkey.pem", I18n.tr("server.paths.privKeyDesc")));
            // Where it really is: in /var/db/acme as acme, in /root/.acme.sh until the migration has moved it.
            org.daemoxcp.mail.security.AcmeUser.Layout acmeAt = org.daemoxcp.mail.security.AcmeUser.layout();
            sslEntries.put(pathEntry(I18n.tr("server.paths.acmeHome"), acmeAt == null ? org.daemoxcp.mail.security.AcmeUser.HOME : acmeAt.home(), I18n.tr("server.paths.acmeHomeDesc")));
            sslEntries.put(pathEntry(I18n.tr("server.paths.acmeBin"), acmeAt == null ? org.daemoxcp.mail.security.AcmeUser.SCRIPT : acmeAt.script(), I18n.tr("server.paths.acmeBinDesc")));
            sslEntries.put(pathEntry(I18n.tr("server.paths.acmeCerts"), acmeAt == null ? org.daemoxcp.mail.security.AcmeUser.CERT_HOME : acmeAt.certHome(), I18n.tr("server.paths.acmeCertsDesc")));
            categories.put(new JSONObject().put("name", "SSL/TLS").put("entries", sslEntries));

            // === Web server (nginx) ===
            JSONArray webEntries = new JSONArray();
            webEntries.put(pathEntry(I18n.tr("server.paths.nginxConf"), "/usr/local/etc/nginx/nginx.conf", I18n.tr("server.paths.nginxConfDesc")));
            webEntries.put(pathEntry(I18n.tr("server.paths.sitesEnabled"), "/usr/local/etc/nginx/sites-enabled", I18n.tr("server.paths.sitesEnabledDesc")));
            webEntries.put(pathEntry(I18n.tr("server.paths.rcVhost"), "/usr/local/etc/nginx/sites-enabled/roundcube.conf", I18n.tr("server.paths.rcVhostDesc")));
            webEntries.put(pathEntry(I18n.tr("server.paths.nginxAccess"), "/var/log/nginx/access.log", I18n.tr("server.paths.nginxAccessDesc")));
            webEntries.put(pathEntry(I18n.tr("server.paths.nginxError"), "/var/log/nginx/error.log", I18n.tr("server.paths.nginxErrorDesc")));
            categories.put(new JSONObject().put("name", "Nginx / Web").put("entries", webEntries));

            // === Database (panel) ===
            // SQLite path of the panel: relative to the execution CWD, usually /home/panel/
            JSONArray dbEntries = new JSONArray();
            String sqliteDbPath = "./database/daemoxcp-mail.db";
            try {
                java.nio.file.Path abs = java.nio.file.Paths.get(sqliteDbPath).toAbsolutePath().normalize();
                sqliteDbPath = abs.toString();
            } catch (Exception ignored) {}
            dbEntries.put(pathEntry(I18n.tr("server.paths.sqlite"), sqliteDbPath, I18n.tr("server.paths.sqliteDesc")));
            dbEntries.put(pathEntry(I18n.tr("server.paths.mycnf"), "/usr/local/etc/mysql/my.cnf", I18n.tr("server.paths.mycnfDesc")));
            dbEntries.put(pathEntry(I18n.tr("server.paths.mysqlData"), "/var/db/mysql", I18n.tr("server.paths.mysqlDataDesc")));
            categories.put(new JSONObject().put("name", "Database").put("entries", dbEntries));

            response.put("success", true);
            response.put("categories", categories);
            // Hostname: multiple attempts, never blocking
            String hostname = I18n.tr("server.notAvailable");
            try {
                hostname = java.net.InetAddress.getLocalHost().getHostName();
            } catch (Exception ignoredEx) {
                // Fallback 1: HOSTNAME environment variable
                String envHost = System.getenv("HOSTNAME");
                if (envHost != null && !envHost.isEmpty()) {
                    hostname = envHost;
                } else {
                    // Fallback 2: hostname command
                    try {
                        // TODO: migrate to Shell.run when touched
                        ProcessBuilder pb = new ProcessBuilder("/bin/hostname");
                        org.daemoxcp.mail.util.Shell.applyPath(pb);
                        pb.redirectErrorStream(true);
                        Process p = pb.start();
                        String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).trim();
                        p.waitFor(3, java.util.concurrent.TimeUnit.SECONDS);
                        if (!out.isEmpty()) hostname = out;
                    } catch (Exception ignored2) {}
                }
            }
            response.put("hostname", hostname);

        } catch (Exception e) {
            response.put("success", false);
            response.put("error", ErrorText.forPage("handleApiSystemPaths", e));
        }
        sendJsonResponse(exchange, response);
    }

    /** Builds a JSON entry with the metadata of the file/directory. */
    private JSONObject pathEntry(String label, String path, String description) {
        JSONObject e = new JSONObject();
        e.put("label", label);
        e.put("path", path);
        e.put("description", description);
        try {
            java.nio.file.Path p = java.nio.file.Paths.get(path);
            boolean exists = java.nio.file.Files.exists(p);
            e.put("exists", exists);
            if (exists) {
                e.put("is_directory", java.nio.file.Files.isDirectory(p));
                e.put("readable", java.nio.file.Files.isReadable(p));
                try {
                    java.nio.file.attribute.BasicFileAttributes attrs =
                        java.nio.file.Files.readAttributes(p, java.nio.file.attribute.BasicFileAttributes.class);
                    if (!attrs.isDirectory()) {
                        e.put("size", attrs.size());
                    }
                    e.put("modified", attrs.lastModifiedTime().toString());
                } catch (Exception ignored) {}
                try {
                    java.util.Set<java.nio.file.attribute.PosixFilePermission> perms =
                        java.nio.file.Files.getPosixFilePermissions(p);
                    e.put("perms", java.nio.file.attribute.PosixFilePermissions.toString(perms));
                } catch (Exception ignored) {}
            }
        } catch (Exception ex) {
            e.put("exists", false);
            e.put("error", ErrorText.forPage("pathEntry", ex));
        }
        return e;
    }

    private JSONObject buildFail2banHealthReport() {
        JSONObject r = new JSONObject();
        JSONArray checks = new JSONArray();
        boolean f2bInstalled = java.nio.file.Files.exists(java.nio.file.Paths.get("/usr/local/bin/fail2ban-client"));
        checks.put(makeCheck("fail2ban-installed",
            I18n.tr("server.f2b.checkInstalled"),
            f2bInstalled,
            f2bInstalled ? (I18n.tr("server.f2b.pkgPresent") + " " + fail2banVersion())
                         : I18n.tr("server.f2b.pkgMissing"),
            f2bInstalled ? null : I18n.tr("server.f2b.impactInstalled"),
            f2bInstalled ? null : "install_fail2ban",
            f2bInstalled ? null : I18n.tr("server.runs", Map.of("command", "pkg install -y " + FAIL2BAN_ORIGIN))));
        boolean enabledAtBoot = isFail2banEnabledAtBoot();
        checks.put(makeCheck("fail2ban-enabled-boot",
            I18n.tr("server.f2b.checkBoot"),
            enabledAtBoot,
            enabledAtBoot ? "fail2ban_enable=YES in rc.conf" : I18n.tr("server.f2b.noBoot"),
            enabledAtBoot ? null : I18n.tr("server.f2b.impactBoot"),
            (enabledAtBoot || !f2bInstalled) ? null : "enable_at_boot",
            I18n.tr("server.runs", Map.of("command", "sysrc fail2ban_enable=YES"))));
        boolean f2bRunning = isFail2banRunning();
        checks.put(makeCheck("fail2ban-running",
            I18n.tr("server.f2b.checkRunning"),
            f2bRunning,
            f2bRunning ? I18n.tr("server.serviceRunning") : I18n.tr("server.serviceStopped"),
            f2bRunning ? null : I18n.tr("server.f2b.impactRunning"),
            (f2bRunning || !f2bInstalled) ? null : "start_service",
            I18n.tr("server.runs", Map.of("command", "service fail2ban start"))));
        boolean filterPresent = java.nio.file.Files.exists(java.nio.file.Paths.get("/usr/local/etc/fail2ban/filter.d/daemoxcp-mail-auth.conf"));
        boolean logPresent = java.nio.file.Files.exists(java.nio.file.Paths.get("/var/log/daemoxcp-mail-auth.log"));
        boolean jailPresent = false;
        try {
            java.nio.file.Path jl = java.nio.file.Paths.get("/usr/local/etc/fail2ban/jail.local");
            if (java.nio.file.Files.exists(jl)) {
                String c = java.nio.file.Files.readString(jl);
                jailPresent = c.contains("[daemoxcp-mail-auth]");
            }
        } catch (Exception ignored) {}
        boolean panelSetupOk = filterPresent && logPresent && jailPresent;
        String missingDetails = I18n.tr("server.f2b.missing", Map.of("items", ((filterPresent ? "" : "filter ") + (jailPresent ? "" : "jail ") + (logPresent ? "" : "log-file")).trim()));
        checks.put(makeCheck("panel-jail-configured",
            I18n.tr("server.f2b.checkPanelJail"),
            panelSetupOk,
            panelSetupOk ? I18n.tr("server.f2b.panelJailOk") : missingDetails.trim(),
            panelSetupOk ? null : I18n.tr("server.f2b.impactPanelJail"),
            (panelSetupOk || !f2bInstalled) ? null : "setup_mail_jail",
            I18n.tr("server.f2b.fixPanelJail")));

        // Jails for the mail services (Postfix, Dovecot, Roundcube, Rspamd)
        // DOUBLE check: the file exists AND the jails are really active in the Fail2ban runtime
        java.util.List<String> expectedMailJails = java.util.Arrays.asList("dovecot", "postfix-auth", "roundcube-auth", "rspamd");
        boolean mailFileExists = false;
        java.util.Set<String> jailsInFile = new java.util.HashSet<>();
        try {
            java.nio.file.Path mailLocal = java.nio.file.Paths.get("/usr/local/etc/fail2ban/jail.d/mail.local");
            if (java.nio.file.Files.exists(mailLocal)) {
                mailFileExists = true;
                String c = java.nio.file.Files.readString(mailLocal);
                for (String j : expectedMailJails) {
                    if (c.contains("[" + j + "]")) jailsInFile.add(j);
                }
            }
        } catch (Exception ignored) {}

        // Which jails are ACTIVE at runtime?
        // FIX (regression of the previous check): we used to parse the "Jail list:" line
        // of the global `fail2ban-client status` output. That parsing was fragile --
        // if the output format changes (whitespace, tab, encoding), ALL the jails
        // were marked as "not active" even if they were actually running normally.
        //
        // Robust approach: for each expected jail we run `status <jail>` --
        // if it returns normal output (not "does not exist") it means that the jail
        // IS loaded and active in the Fail2ban runtime.
        java.util.Set<String> activeJails = new java.util.HashSet<>();
        if (f2bRunning) {
            for (String jail : expectedMailJails) {
                var statusRes = org.daemoxcp.mail.util.Shell.run(java.time.Duration.ofSeconds(5),
                    "/usr/local/bin/fail2ban-client", "status", jail);
                String statusOut = statusRes.output();
                boolean notExists = statusOut.contains("does not exist") || statusOut.contains("not found")
                                 || statusOut.contains("Sorry, but the jail");
                if (statusRes.success() && !notExists) {
                    activeJails.add(jail);
                }
            }
        }

        // For every jail missing at runtime, find out WHY
        java.util.List<String> missingActive = new java.util.ArrayList<>();
        java.util.List<String> reasons = new java.util.ArrayList<>();
        for (String jail : expectedMailJails) {
            if (!activeJails.contains(jail)) {
                missingActive.add(jail);
                reasons.add(jail + ": " + diagnoseMailJailIssue(jail, jailsInFile.contains(jail)));
            }
        }

        boolean mailJailsActive = mailFileExists && missingActive.isEmpty();
        String detailStatus;
        if (mailJailsActive) {
            detailStatus = I18n.tr("server.f2b.mailJailsAll", Map.of("jails", String.join(", ", expectedMailJails)));
        } else if (mailFileExists) {
            detailStatus = I18n.tr("server.f2b.mailJailsSome", Map.of("n", missingActive.size(), "reasons", String.join(" | ", reasons)));
        } else {
            detailStatus = I18n.tr("server.f2b.mailJailsNone");
        }
        String impact = mailJailsActive ? null
            : I18n.tr("server.f2b.impactMailJails");

        // Appropriate fix:
        //   - missing file or jails not active at runtime -> install_mail_jails (regenerates mail.local
        //     with the correct paths, creates missing log files, rewrites filters, reload)
        //   - install_mail_jails is idempotent and handles all the cases, so it is always the
        //     safer choice compared with a reload alone
        String fixAction = null;
        String fixDesc = null;
        if (f2bInstalled && (!mailFileExists || !missingActive.isEmpty())) {
            fixAction = "install_mail_jails";
            fixDesc = I18n.tr("server.f2b.fixMailJails");
        }

        checks.put(makeCheck("mail-services-jails",
            I18n.tr("server.f2b.checkMailJails"),
            mailJailsActive,
            detailStatus,
            impact,
            fixAction,
            fixDesc));

        // ========== Are the jails watching files that can tell them something? ==========
        // The check above asks "is the jail loaded". roundcube-auth was, and the page
        // showed green while it was watching "userlogins" instead of the "userlogins.log" written
        // next to it: it would not have banned anyone, and precisely because the diagnosis saw
        // nothing wrong the "Fix all" button stayed hidden. This is the second question.
        // The green of this check must say "I looked at N jails and they are fine", never
        // "I found no problems" when the reason is that I looked at nothing: an empty list
        // as a result and an empty list from a failure are indistinguishable, and that
        // ambiguity is exactly the shape of the defect this check exists to
        // uncover. So we count, and the count ends up on screen.
        Fail2banManager.LogReview review = null;
        String reviewError = null;
        try {
            if (f2bRunning) review = fail2banManager.reviewWatchedLogs();
        } catch (Exception e) { reviewError = ErrorText.detail("buildFail2banHealthReport", e); }

        boolean logOk;
        StringBuilder logDetail = new StringBuilder();
        if (!f2bRunning) {
            logOk = false;
            logDetail.append(I18n.tr("server.f2b.log.notRunning"));
        } else if (review == null) {
            logOk = false;
            logDetail.append(I18n.tr("server.f2b.log.examFailed"))
                        .append(reviewError != null ? (": " + reviewError) : "")
                        .append(". ").append(I18n.tr("server.f2b.log.lookedAtNothing"));
        } else if (review.reviewed.isEmpty()) {
            logOk = false;
            logDetail.append(I18n.tr("server.f2b.log.noFiles"));
        } else if (review.issues.isEmpty()) {
            logOk = true;
            logDetail.append(I18n.tr("server.f2b.log.allOk", Map.of("n", review.reviewed.size(), "jails", String.join(", ", review.reviewed))));
            if (!review.withoutLog.isEmpty())
                logDetail.append(". ").append(I18n.tr("server.f2b.log.withoutLog", Map.of("jails", String.join(", ", review.withoutLog))));
        } else {
            logOk = false;
            logDetail.append(I18n.tr("server.f2b.log.someBlind", Map.of("total", review.reviewed.size(), "n", review.issues.size()))).append(" ");
            boolean first = true;
            for (Fail2banManager.WrongLog sb : review.issues) {
                if (!first) logDetail.append(" | ");
                logDetail.append(sb.jail).append(": ").append(sb.reason);
                first = false;
            }
        }
        // ========== Does the command that bans exist on this system? ==========
        // The real cause of the most serious fault found so far. Five jails declared
        // "action = pf[...]", two did not: by not declaring it they inherited the default value of
        // jail.conf, built on iptables, which does not exist on FreeBSD. Those two detected,
        // counted the attempts and incremented the bans -- 14,370 and 46 on the 443 jail --
        // without blocking anything, and no screen could notice it because none of them
        // checked whether the ban command was a command. This one checks it.
        JSONObject diagBan = new JSONObject().put("broken", new JSONArray());
        boolean banRunnable = true;
        String banDetail;
        try {
            if (f2bRunning) diagBan = org.daemoxcp.mail.security.BanActionRepair.diagnosis();
        } catch (Exception ignored) { }
        JSONArray broken = diagBan.optJSONArray("broken");
        if (broken == null) broken = new JSONArray();
        if (!f2bRunning) {
            banRunnable = false;
            banDetail = I18n.tr("server.f2b.ban.notRunning");
        } else if (broken.length() == 0) {
            int reviewedBans = diagBan.optInt("reviewed", 0);
            JSONArray notJudged = diagBan.optJSONArray("not_judged");
            if (reviewedBans == 0) {
                banRunnable = false;
                banDetail = I18n.tr("server.f2b.ban.noneJudged");
            } else {
                banDetail = I18n.tr("server.f2b.ban.allOk", Map.of("n", reviewedBans));
                if (notJudged != null && notJudged.length() > 0) {
                    // Not judged is not passed. If a jail does not report its own action,
                    // most of the time it is because that action did not load -- that is, it
                    // does not ban at all -- and leaving the check green for the others would
                    // hide exactly the worst case behind the healthy majority.
                    banRunnable = false;
                    StringBuilder ng = new StringBuilder();
                    for (int i = 0; i < notJudged.length(); i++) {
                        JSONObject x = notJudged.getJSONObject(i);
                        if (ng.length() > 0) ng.append(" | ");
                        ng.append(x.optString("jail")).append(": ").append(x.optString("why"));
                        // The evidence next to the verdict: what fail2ban answered, and what it
                        // wrote in its own log. Without it, the line only says that it is not known.
                        String u = x.optString("output", "");
                        if (!u.isEmpty()) ng.append(" [").append(I18n.tr("server.f2b.ban.answers", Map.of("answer", u))).append("]");
                        String lg = x.optString("log", "");
                        if (!lg.isEmpty()) ng.append(" [fail2ban.log: ").append(lg.replace("\n", " ⏎ ")).append("]");
                    }
                    banDetail += ". " + I18n.tr("server.f2b.ban.notJudged", Map.of("jails", ng.toString()));
                }
            }
        } else {
            banRunnable = false;
            StringBuilder b = new StringBuilder();
            for (int i = 0; i < broken.length(); i++) {
                JSONObject x = broken.getJSONObject(i);
                if (b.length() > 0) b.append(" | ");
                b.append(x.optString("jail")).append(": ").append(I18n.tr("server.f2b.ban.missingCommand", Map.of("command", x.optString("runnable"))));
            }
            banDetail = b.toString();
        }
        checks.put(makeCheck("ban-runnable",
            I18n.tr("server.f2b.ban.check"),
            banRunnable,
            banDetail,
            banRunnable ? null
                : I18n.tr("server.f2b.ban.impact"),
            (banRunnable || !f2bRunning) ? null : "repair_ban_action",
            I18n.tr("server.f2b.ban.fix")));

        // ========== Do the bans really reach pf? ==========
        // It is the deepest check the panel can do, and until now it lived only
        // in the comparison card: the verdict at the top said "All OK" while recidive
        // had a table that no rule reads. A summary that does not include the
        // most severe check is not a summary: it is the same half-truth that kept
        // a blind jail, and two that banned into thin air, hidden for months.
        boolean appliedBans = true;
        // Only jails that could not be read, and no fault found: it is not a fault, it is an "I could not
        // look" (2026-11-09: on the production server mailpanel-public "not measured" for a moment, with
        // the mail jails remedy, which does not touch it, and "if you do not fix it"). The reason is given
        // and a retry is asked for.
        boolean appliedBansUnmeasured = false;
        String appliedBansDetail;
        try {
            if (!f2bRunning) {
                appliedBans = false;
                appliedBansDetail = I18n.tr("server.f2b.pf.notRunning");
            } else {
                Fail2banManager.PfComparison cf = fail2banManager.compareBansWithPf();
                if (cf.totalUnmeasured() > 0) {
                    // Fail2ban not answering in time (a reload, a big log to reread) lasts a moment:
                    // a second read after a few seconds, before saying anything.
                    try { Thread.sleep(3000); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
                    cf = fail2banManager.compareBansWithPf();
                }
                int withoutRule = cf.totalWithoutRule();
                int notApplied = cf.totalNotApplied();
                int unmeasured = cf.totalUnmeasured();
                int ok = 0;
                for (Fail2banManager.JailPf j : cf.jails)
                    if (j.read && j.ruleVerified && j.rulePresent && !j.missingTable) ok++;

                StringBuilder d = new StringBuilder();
                if (withoutRule == 0 && notApplied == 0 && unmeasured == 0) {
                    d.append(I18n.tr("server.f2b.pf.allOk", Map.of("n", ok)));
                } else {
                    appliedBans = false;
                    appliedBansUnmeasured = withoutRule == 0 && notApplied == 0;
                    d.append(I18n.tr("server.f2b.pf.someOk", Map.of("ok", ok, "total", cf.jails.size())));
                    for (Fail2banManager.JailPf j : cf.jails) {
                        if (!j.read) {
                            d.append(" | ").append(j.jail).append(": ").append(j.note == null || j.note.isBlank()
                                    ? I18n.tr("server.f2b.pf.notMeasured")
                                    : I18n.tr("server.f2b.pf.notMeasuredWhy", Map.of("why", j.note.strip())));
                            continue;
                        }
                        if (j.missingTable) { d.append(" | ").append(j.jail).append(": ").append(I18n.tr("server.f2b.pf.noTable")); continue; }
                        if (j.ruleVerified && !j.rulePresent) {
                            d.append(" | ").append(j.jail).append(": ").append(I18n.tr("server.f2b.pf.noRule", Map.of("table", String.valueOf(j.table))));
                            continue;
                        }
                        if (!j.onlyInFail2ban.isEmpty())
                            d.append(" | ").append(j.jail).append(": ").append(I18n.tr("server.f2b.pf.notInFirewall", Map.of("ips", String.join(", ", j.onlyInFail2ban))));
                    }
                }
                appliedBansDetail = d.toString();
            }
        } catch (Exception e) {
            appliedBans = false;
            appliedBansDetail = I18n.tr("server.f2b.pf.compareFailed", Map.of("error", ErrorText.detail("buildFail2banHealthReport", e)));
        }
        if (appliedBansUnmeasured) {
            // No remedy to offer: regenerating the mail jails does not touch a jail that could not be read.
            checks.put(makeCheck("bans-applied-in-pf", I18n.tr("server.f2b.pf.check"), false, appliedBansDetail,
                    I18n.tr("server.f2b.pf.unmeasuredImpact"), null, null).put("unknown", true));
        } else {
            checks.put(makeCheck("bans-applied-in-pf",
                I18n.tr("server.f2b.pf.check"),
                appliedBans,
                appliedBansDetail,
                appliedBans ? null
                    : I18n.tr("server.f2b.pf.impact"),
                (appliedBans || !f2bInstalled) ? null : "install_mail_jails",
                I18n.tr("server.f2b.pf.fix")));
        }

        checks.put(makeCheck("mail-jails-logpath",
            I18n.tr("server.f2b.log.check"),
            logOk,
            logDetail.toString(),
            logOk ? null
                  : I18n.tr("server.f2b.log.impact"),
            (logOk || !f2bInstalled) ? null : "install_mail_jails",
            I18n.tr("server.f2b.log.fix")));

        // ========== pf check (FreeBSD firewall) ==========
        boolean pfEnabledAtBoot = isPfEnabledAtBoot();
        boolean pfRunning = isPfRunning();
        boolean pfConfExists = java.nio.file.Files.exists(java.nio.file.Paths.get("/etc/pf.conf"));
        boolean pfAnchorPresent = false;
        try {
            if (pfConfExists) {
                String pfConf = java.nio.file.Files.readString(java.nio.file.Paths.get("/etc/pf.conf"));
                pfAnchorPresent = org.daemoxcp.mail.security.Fail2banAutoSetup.hasF2bAnchor(pfConf);
            }
        } catch (Exception ignored) {}

        // Check of the pf kernel module (must come BEFORE all the rest of pf)
        boolean pfModuleLoaded = isPfModuleLoaded();
        boolean inJail = isRunningInsideFreebsdJail();
        checks.put(makeCheck("pf-module-loaded",
            I18n.tr("server.pf.checkModule"),
            pfModuleLoaded,
            pfModuleLoaded ? I18n.tr("server.pf.moduleLoaded")
                           : (inJail ? I18n.tr("server.pf.inJail")
                                     : I18n.tr("server.pf.moduleMissing")),
            pfModuleLoaded ? null
                : (inJail ? I18n.tr("server.pf.impactInJail")
                          : I18n.tr("server.pf.impactModule")),
            (pfModuleLoaded || inJail) ? null : "load_pf_module",
            I18n.tr("server.pf.fixModule")));

        // ========== Is the Fail2ban anchor reached? ==========
        // pf evaluates the rules in order and "quick" stops the evaluation at the first one that
        // matches. The Fail2ban rules are "block quick", but a "pass ... quick" that
        // comes BEFORE the f2b anchor wins: from those sources you do not get banned, and the bans
        // look executed. The panel writes its own anchor panel-fw at the end of pf.conf,
        // and that anchor contains "pass in quick from <panel_wl_cidrs>" and the geographic list:
        // if it ends up before f2b, the whitelist is no longer an intended precedence but an
        // exemption from bans that nobody knows about. Here the real order of the file is checked.
        boolean orderOk = true;
        String detailOrder;
        java.util.List<String> beforeF2b = new java.util.ArrayList<>();
        int f2bLine = -1;
        try {
            if (pfConfExists && pfAnchorPresent) {
                String[] lines = java.nio.file.Files.readString(
                    java.nio.file.Paths.get("/etc/pf.conf")).split("\n", -1);
                for (int i = 0; i < lines.length; i++) {
                    String t = lines[i].trim();
                    if (t.isEmpty() || t.startsWith("#")) continue;
                    if (f2bLine < 0 && (t.contains("anchor \"f2b/*\"") || t.contains("anchor f2b/*"))) {
                        f2bLine = i;
                        break;
                    }
                    // Only what can really make an inbound ban be bypassed.
                    // "pass out ... quick" concerns outbound traffic and is irrelevant:
                    // flagging it would turn a healthy pf.conf red, and a check that
                    // cries wolf stops being read.
                    if (t.startsWith("pass") && t.contains("quick")
                            && !t.matches("^pass\\s+out\\b.*")) {
                        beforeF2b.add(I18n.tr("server.pf.line", Map.of("n", i + 1)) + ": " + t);
                        continue;
                    }
                    // A preceding anchor counts only if it really contains a pass quick: we
                    // ask pf instead of assuming it from the name. If it cannot be read,
                    // we say so -- we do not acquit it.
                    if (t.startsWith("anchor ")) {
                        String name = t.substring(7).trim().replace("\"", "");
                        int sp = name.indexOf(' ');
                        if (sp > 0) name = name.substring(0, sp);
                        if (name.isEmpty() || name.equals("f2b/*")) continue;
                        var reg = org.daemoxcp.mail.util.Shell.run(java.time.Duration.ofSeconds(10),
                            "/sbin/pfctl", "-a", name.replace("/*", ""), "-sr");
                        if (!reg.success()) {
                            beforeF2b.add(I18n.tr("server.pf.line", Map.of("n", i + 1)) + ": " + I18n.tr("server.pf.anchorUnreadable", Map.of("anchor", name)));
                            continue;
                        }
                        for (String rr : reg.output().split("\n")) {
                            String u = rr.trim();
                            if (u.startsWith("pass") && u.contains("quick")
                                    && !u.matches("^pass\\s+out\\b.*")) {
                                beforeF2b.add(I18n.tr("server.pf.line", Map.of("n", i + 1)) + ": " + I18n.tr("server.pf.anchorContains", Map.of("anchor", name, "rule", u)));
                                break;
                            }
                        }
                    }
                }
            }
        } catch (Exception ignored) { }

        if (!pfConfExists || !pfAnchorPresent) {
            detailOrder = I18n.tr("server.pf.order.noAnchor");
            orderOk = pfAnchorPresent;
        } else if (f2bLine < 0) {
            orderOk = false;
            detailOrder = I18n.tr("server.pf.order.lineNotFound");
        } else if (beforeF2b.isEmpty()) {
            detailOrder = I18n.tr("server.pf.order.ok", Map.of("n", f2bLine + 1));
        } else {
            orderOk = false;
            detailOrder = I18n.tr("server.pf.order.blocked", Map.of("n", f2bLine + 1, "count", beforeF2b.size(), "rules", String.join(" | ", beforeF2b)));
        }
        checks.put(makeCheck("pf-anchor-order",
            I18n.tr("server.pf.order.check"),
            orderOk,
            detailOrder,
            orderOk ? null
                : I18n.tr("server.pf.order.impact"),
            null,
            null));

        // Separate check for the existence of pf.conf (must come first)
        checks.put(makeCheck("pf-conf-exists",
            I18n.tr("server.pf.checkConf"),
            pfConfExists,
            pfConfExists ? I18n.tr("server.pf.confFound")
                         : I18n.tr("server.pf.confMissing"),
            pfConfExists ? null
                : I18n.tr("server.pf.impactConf"),
            pfConfExists ? null : "create_pf_conf_minimal",
            I18n.tr("server.pf.fixConf")));

        checks.put(makeCheck("pf-running",
            I18n.tr("server.pf.checkRunning"),
            pfRunning,
            pfRunning ? I18n.tr("server.pf.running")
                      : (pfConfExists ? I18n.tr("server.pf.confButStopped")
                                      : I18n.tr("server.pf.confMissingCannotStart")),
            pfRunning ? null
                : I18n.tr("server.pf.impactRunning"),
            (pfRunning || !pfConfExists) ? null : "start_pf",
            pfConfExists ? I18n.tr("server.pf.fixRunning") : null));

        checks.put(makeCheck("pf-enabled-boot",
            I18n.tr("server.pf.checkBoot"),
            pfEnabledAtBoot,
            pfEnabledAtBoot ? "pf_enable=YES in rc.conf" : I18n.tr("server.pf.noBoot"),
            pfEnabledAtBoot ? null : I18n.tr("server.pf.impactBoot"),
            (pfEnabledAtBoot || !pfConfExists) ? null : "enable_pf_at_boot",
            I18n.tr("server.runs", Map.of("command", "sysrc pf_enable=YES"))));

        checks.put(makeCheck("pf-anchor-f2b",
            I18n.tr("server.pf.checkAnchor"),
            pfAnchorPresent,
            pfAnchorPresent ? I18n.tr("server.pf.anchorPresent")
                            : (pfConfExists ? I18n.tr("server.pf.anchorMissing")
                                            : I18n.tr("server.pf.confNotExists")),
            pfAnchorPresent ? null
                : I18n.tr("server.pf.impactAnchor"),
            (pfAnchorPresent || !pfConfExists) ? null : "add_pf_anchor",
            I18n.tr("server.pf.fixAnchor")));

        // The overall verdict is read from the checks, not from a list of booleans written
        // by hand. That list was a second version of the same truth, and the two
        // diverged as soon as a check was added: the new check appeared red in the
        // list while at the top "All OK" remained and the button to fix it stayed hidden,
        // because nobody had remembered to name it here as well. By counting the red rows
        // the oversight is no longer possible.
        boolean allOk = true;
        boolean somethingToRepair = false;
        int unchecked = 0;
        for (int i = 0; i < checks.length(); i++) {
            JSONObject c = checks.getJSONObject(i);
            if (c.optBoolean("ok", false)) continue;
            // A check that could not look is not a fault: it does not ask for remedies, it asks for a retry.
            if (c.optBoolean("unknown", false)) { unchecked++; continue; }
            allOk = false;
            if (c.has("fix_action")) somethingToRepair = true;
        }
        r.put("can_fix_all", somethingToRepair);
        r.put("success", true);
        r.put("all_ok", allOk);
        r.put("unchecked", unchecked);
        r.put("checks", checks);
        // CSRF token state for the following POSTs
        try {
            // we reuse the exchange's session token -- it is obtained outside. Here we generate the check.
        } catch (Exception ignored) {}
        return r;
    }

    /**
     * Exact version of Fail2ban and of the package, as text.
     *
     * It serves to read the right documentation. The options of an action change between versions,
     * and a page read for the wrong version leads to writing a configuration that the
     * system rejects -- made worse by the fact that the rejection can be silent, as when a
     * jail is loaded without any action and keeps counting the attempts.
     */
    private String fail2banVersion() {
        StringBuilder b = new StringBuilder();
        try {
            var v = org.daemoxcp.mail.util.Shell.run(java.time.Duration.ofSeconds(10),
                "/usr/local/bin/fail2ban-client", "--version");
            if (v.success() && v.output() != null && !v.output().isBlank())
                b.append(I18n.tr("server.f2b.versionIs", java.util.Map.of("v", String.valueOf(v.output().trim().split("\n")[0]))));
        } catch (Exception ignored) { }
        try {
            var p2 = org.daemoxcp.mail.util.Shell.run(java.time.Duration.ofSeconds(10),
                "/usr/sbin/pkg", "query", "-g", "%n-%v", FAIL2BAN_PACKAGE_GLOB);
            if (p2.success() && p2.output() != null && !p2.output().isBlank()) {
                if (b.length() > 0) b.append(" — ");
                b.append(I18n.tr("server.f2b.packageIs", java.util.Map.of("p", String.valueOf(p2.output().trim().split("\n")[0]))));
            }
        } catch (Exception ignored) { }
        return b.length() == 0 ? I18n.tr("server.f2b.versionUnknown") : b.toString();
    }

    private JSONObject makeCheck(String id, String label, boolean ok, String statusText,
                                 String impactIfMissing, String fixAction, String fixDescription) {
        JSONObject c = new JSONObject();
        c.put("id", id);
        c.put("label", label);
        c.put("ok", ok);
        c.put("status", statusText);
        if (impactIfMissing != null) c.put("impact", impactIfMissing);
        if (fixAction != null) {
            c.put("fix_action", fixAction);
            c.put("fix_description", fixDescription != null ? fixDescription : "");
        }
        return c;
    }

    /**
     * The fail2ban package is named by ORIGIN, not by name.
     *
     * <p>The name carries the Python version of the moment in front, and it changes by itself under
     * your feet: here {@code py311-fail2ban} was written in three places, and on FreeBSD 15.1 today
     * that package no longer exists -- {@code pkg install -y py311-fail2ban} answers "No
     * packages available to install matching", while the good one is called
     * {@code py312-fail2ban}. That is, the "install fail2ban" button of the Firewall page could
     * not work. The origin, instead, never changes.
     */
    private static final String FAIL2BAN_ORIGIN = "security/py-fail2ban";

    /** To ASK for the installed version: pkg query wants a name, and here it goes by pattern. */
    private static final String FAIL2BAN_PACKAGE_GLOB = "py*-fail2ban";

    private boolean isFail2banEnabledAtBoot() {
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/sysrc", "-n", "fail2ban_enable");
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).trim();
            p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            return out.equalsIgnoreCase("YES");
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isFail2banRunning() {
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/service", "fail2ban", "status");
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            return out.toLowerCase().contains("is running");
        } catch (Exception e) {
            return false;
        }
    }

    private JSONObject installFail2ban() {
        return onPackageTurn(I18n.tr("server.install.jobName", Map.of("component", "fail2ban")), this::runInstallFail2ban);
    }

    private JSONObject runInstallFail2ban() {
        JSONObject r = new JSONObject();
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/pkg", "install", "-y", FAIL2BAN_ORIGIN);
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            boolean done = p.waitFor(180, java.util.concurrent.TimeUnit.SECONDS);
            if (!done) { p.destroyForcibly(); r.put("success", false); r.put("message", I18n.tr("server.install.timeout")); return r; }
            int exit = p.exitValue();
            r.put("success", exit == 0);
            r.put("message", exit == 0 ? I18n.tr("server.f2b.installed") : "pkg install exit=" + exit);
            r.put("output", out.length() > 4000 ? out.substring(out.length() - 4000) : out);
            return r;
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", I18n.tr("server.errorWith", Map.of("error", ErrorText.detail("runInstallFail2ban", e))));
            return r;
        }
    }

    private JSONObject enableFail2banAtBoot() {
        JSONObject r = new JSONObject();
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/sysrc", "fail2ban_enable=YES");
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
            r.put("success", p.exitValue() == 0);
            r.put("message", p.exitValue() == 0 ? I18n.tr("server.bootEnabled") : "sysrc exit=" + p.exitValue());
            r.put("output", out);
            return r;
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", I18n.tr("server.errorWith", Map.of("error", ErrorText.detail("enableFail2banAtBoot", e))));
            return r;
        }
    }

    /** Checks whether the pf kernel module is loaded (kldstat). */
    /** The pf module in the kernel. Same implementation as Fail2banAutoSetup. */
    private boolean isPfModuleLoaded() {
        return org.daemoxcp.mail.security.Fail2banAutoSetup.pfModuleLoaded();
    }

    /** Checks whether the panel is running inside a FreeBSD jail (security.jail.jailed). */
    /** Inside a FreeBSD jail modules cannot be loaded. Same implementation. */
    private boolean isRunningInsideFreebsdJail() {
        return org.daemoxcp.mail.security.Fail2banAutoSetup.insideFreebsdJail();
    }

    /** Loads the pf kernel module with kldload. */
    private JSONObject loadPfModule() {
        JSONObject r = new JSONObject();
        try {
            if (isRunningInsideFreebsdJail()) {
                r.put("success", false);
                r.put("message", I18n.tr("server.pf.loadInJail"));
                return r;
            }
            if (isPfModuleLoaded()) {
                r.put("success", true);
                r.put("message", I18n.tr("server.pf.alreadyLoaded"));
                return r;
            }
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/sbin/kldload", "pf");
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
            boolean ok = p.exitValue() == 0 && isPfModuleLoaded();
            r.put("success", ok);
            r.put("message", ok ? I18n.tr("server.pf.loaded") : I18n.tr("server.pf.loadFailed", Map.of("exit", p.exitValue())));
            r.put("output", out);

            // Persistence: add pf_load=YES to /boot/loader.conf if missing
            if (ok) {
                try {
                    java.nio.file.Path loaderConf = java.nio.file.Paths.get("/boot/loader.conf");
                    String content = java.nio.file.Files.exists(loaderConf)
                        ? java.nio.file.Files.readString(loaderConf) : "";
                    if (!content.contains("pf_load=")) {
                        java.nio.file.Files.writeString(loaderConf,
                            content + (content.endsWith("\n") || content.isEmpty() ? "" : "\n") + "pf_load=\"YES\"\n",
                            java.nio.file.StandardOpenOption.CREATE,
                            java.nio.file.StandardOpenOption.WRITE);
                    }
                } catch (Exception ignored) {}
            }
            return r;
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", I18n.tr("server.errorWith", Map.of("error", ErrorText.detail("loadPfModule", e))));
            return r;
        }
    }

    private boolean isPfEnabledAtBoot() {
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/sysrc", "-n", "pf_enable");
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).trim();
            p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            return out.equalsIgnoreCase("YES");
        } catch (Exception e) { return false; }
    }

    /** pf on. The implementation lives in Fail2banAutoSetup, a single one for the whole panel. */
    private boolean isPfRunning() {
        return org.daemoxcp.mail.security.Fail2banAutoSetup.pfEnabled();
    }

    private JSONObject startPfService() {
        JSONObject r = new JSONObject();
        try {
            // PRE-FLIGHT 1: check that pf.conf exists
            java.nio.file.Path pfConfPath = java.nio.file.Paths.get("/etc/pf.conf");
            if (!java.nio.file.Files.exists(pfConfPath)) {
                r.put("success", false);
                r.put("message", I18n.tr("server.pf.startNoConf"));
                return r;
            }

            // PRE-FLIGHT 2: pfctl -nf checks the syntax without loading the rules.
            // If the syntax is invalid, we do not start the service.
            // TODO: migrate to Shell.run when touched
            ProcessBuilder testPb = new ProcessBuilder("/sbin/pfctl", "-nf", "/etc/pf.conf");
            org.daemoxcp.mail.util.Shell.applyPath(testPb);
            testPb.redirectErrorStream(true);
            Process tp = testPb.start();
            String testOut = new String(tp.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            tp.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
            if (tp.exitValue() != 0) {
                r.put("success", false);
                r.put("message", I18n.tr("server.pf.startBadSyntax", Map.of("errors", testOut.trim())));
                r.put("output", testOut);
                return r;
            }

            // OK -- start
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/service", "pf", "start");
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            p.waitFor(15, java.util.concurrent.TimeUnit.SECONDS);
            boolean ok = p.exitValue() == 0;
            // Check that it is now really in the "Enabled" state
            if (ok && !isPfRunning()) {
                ok = false;
                out += "\n\n" + I18n.tr("server.pf.stillDisabled");
            }
            r.put("success", ok);
            r.put("message", ok ? I18n.tr("server.pf.started") : I18n.tr("server.pf.startFailed", Map.of("exit", p.exitValue())));
            r.put("output", out);
            return r;
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", I18n.tr("server.errorWith", Map.of("error", ErrorText.detail("startPfService", e))));
            return r;
        }
    }

    private JSONObject enablePfAtBoot() {
        JSONObject r = new JSONObject();
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/sysrc", "pf_enable=YES");
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
            r.put("success", p.exitValue() == 0);
            r.put("message", p.exitValue() == 0 ? I18n.tr("server.pf.bootEnabled") : "sysrc exit=" + p.exitValue());
            r.put("output", out);
            return r;
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", I18n.tr("server.errorWith", Map.of("error", ErrorText.detail("enablePfAtBoot", e))));
            return r;
        }
    }

    /**
     * Creates /etc/pf.conf from scratch with MINIMAL and SAFE rules:
     *   - skip on lo (loopback is not filtered)
     *   - anchor "f2b/*" (Fail2ban can insert its block-quick rules here)
     *   - pass (permissive default: nothing is blocked apart from the banned IPs)
     *
     * The pf.conf of PfPolicy: SSH (the ports sshd listens on, and 22), mail, web, webmail
     * and the panel get in; the rest is dropped. The fail2ban blocks come first.
     *
     * Refused if pf.conf already exists (so as not to overwrite custom configs).
     */
    private JSONObject createPfConfMinimal() {
        JSONObject r = new JSONObject();
        try {
            java.nio.file.Path pfConfPath = java.nio.file.Paths.get("/etc/pf.conf");
            if (java.nio.file.Files.exists(pfConfPath)) {
                r.put("success", false);
                r.put("message", I18n.tr("server.pf.confExistsUseAnchor"));
                return r;
            }
            // The same pf.conf the panel keeps at every start (PfPolicy): only what is needed gets in,
            // SSH included on the ports sshd listens on.
            String content = org.daemoxcp.mail.security.PfPolicy.renderNow();

            // Syntax test before writing to /etc/pf.conf:
            // we first write to a temp file, validate, then copy.
            java.nio.file.Path tmp = java.nio.file.Files.createTempFile("pf-conf-", ".tmp");
            java.nio.file.Files.writeString(tmp, content, java.nio.charset.StandardCharsets.UTF_8);
            // TODO: migrate to Shell.run when touched
            ProcessBuilder testPb = new ProcessBuilder("/sbin/pfctl", "-nf", tmp.toString());
            org.daemoxcp.mail.util.Shell.applyPath(testPb);
            testPb.redirectErrorStream(true);
            Process tp = testPb.start();
            String testOut = new String(tp.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            tp.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
            if (tp.exitValue() != 0) {
                java.nio.file.Files.deleteIfExists(tmp);
                r.put("success", false);
                r.put("message", I18n.tr("server.pf.badSyntax", Map.of("output", testOut)));
                return r;
            }
            // All OK, write
            java.nio.file.Files.move(tmp, pfConfPath);
            try { java.nio.file.Files.setPosixFilePermissions(pfConfPath,
                java.nio.file.attribute.PosixFilePermissions.fromString("rw-r--r--")); } catch (Exception ignored) {}
            r.put("success", true);
            r.put("message", I18n.tr("server.pf.confCreated"));
            return r;
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", I18n.tr("server.errorWith", Map.of("error", ErrorText.detail("createPfConfMinimal", e))));
            return r;
        }
    }

    /**
     * Runs all the necessary fixes in the correct order.
     * Returns a step-by-step report of what was done and what went wrong.
     *
     * Order:
     *  1. Install Fail2ban
     *  2. Enable Fail2ban at boot
     *  3. Setup daemoxcp-mail-auth jail
     *  4. Install mail jails (Postfix/Dovecot/Roundcube/Rspamd)
     *  5. Create a minimal /etc/pf.conf if missing
     *  6. Add anchor "f2b/*" to pf.conf if missing
     *  7. Enable pf at boot
     *  8. Start pf service
     *  9. Start Fail2ban service
     */
    private JSONObject runFixAll() {
        JSONObject r = new JSONObject();
        org.json.JSONArray steps = new org.json.JSONArray();
        boolean anyFailed = false;

        // Step 1: install Fail2ban
        boolean f2bInstalled = java.nio.file.Files.exists(java.nio.file.Paths.get("/usr/local/bin/fail2ban-client"));
        if (!f2bInstalled) {
            JSONObject res = installFail2ban();
            steps.put(buildStep("install_fail2ban", I18n.tr("server.f2bfix.installPkg"), res));
            if (!res.optBoolean("success")) anyFailed = true;
            f2bInstalled = res.optBoolean("success");
        } else {
            steps.put(buildSkipStep("install_fail2ban", I18n.tr("server.f2bfix.installed")));
        }

        // Step 2: enable at boot
        if (f2bInstalled && !isFail2banEnabledAtBoot()) {
            JSONObject res = enableFail2banAtBoot();
            steps.put(buildStep("enable_fail2ban_at_boot", I18n.tr("server.step.enableBoot", Map.of("service", "Fail2ban")), res));
            if (!res.optBoolean("success")) anyFailed = true;
        } else if (f2bInstalled) {
            steps.put(buildSkipStep("enable_fail2ban_at_boot", I18n.tr("server.f2bfix.bootAlready")));
        }

        // Step 3: setup daemoxcp-mail-auth jail (filter, log, jail entry)
        org.daemoxcp.mail.security.Fail2banAutoSetup.run();
        steps.put(buildStep("setup_panel_jail", I18n.tr("server.f2bfix.panelJail"),
            new JSONObject().put("success", true).put("message", I18n.tr("server.f2bfix.doneIdempotent"))));

        // Step 4: install mail jails (check file + runtime)
        try {
            java.nio.file.Path mailLocal = java.nio.file.Paths.get("/usr/local/etc/fail2ban/jail.d/mail.local");
            boolean mailFileOk = false;
            if (java.nio.file.Files.exists(mailLocal)) {
                String c = java.nio.file.Files.readString(mailLocal);
                mailFileOk = c.contains("[dovecot]") && c.contains("[postfix-auth]");
            }
            // Runtime check: all 4 jails active?
            java.util.Set<String> activeJailsNow = new java.util.HashSet<>();
            if (isFail2banRunning()) {
                try {
                    // TODO: migrate to Shell.run when touched
                    ProcessBuilder pb = new ProcessBuilder("/usr/local/bin/fail2ban-client", "status");
                    org.daemoxcp.mail.util.Shell.applyPath(pb);
                    pb.redirectErrorStream(true);
                    Process p = pb.start();
                    String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                    p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
                    java.util.regex.Matcher m = java.util.regex.Pattern.compile("Jail list:\\s*(.*)").matcher(out);
                    if (m.find()) for (String n : m.group(1).split(",")) activeJailsNow.add(n.trim());
                } catch (Exception ignored) {}
            }
            boolean allActive = activeJailsNow.contains("dovecot") && activeJailsNow.contains("postfix-auth");

            // "The file names the jails" and "the jails are on" do not say that they are watching
            // anything. With roundcube-auth both were true while the jail was watching an
            // empty file next to the one being written: here the step was skipped with the reason
            // "already configured and active", and the wrong path would have stayed forever.
            boolean wrongLogs = false;
            try {
                wrongLogs = !fail2banManager.reviewWatchedLogs(activeJailsNow).issues.isEmpty();
            } catch (Exception ignored) { }

            // And not even "the jails are there and watch the right file" is enough: recidive had the
            // pf table and no rule reading it, so it banned into thin air, and this step
            // was skipped because the file named it and it was active. Every time the
            // gate looked at something easier than what matters, the fault got through.
            boolean withoutRule = false;
            try {
                withoutRule = fail2banManager.compareBansWithPf().totalWithoutRule() > 0;
            } catch (Exception ignored) { }

            if (f2bInstalled && (!mailFileOk || !allActive || wrongLogs || withoutRule)) {
                // Missing file OR runtime not aligned -> install (regenerates everything: correct
                // paths from the auto-detect, missing log files, updated filters, reload).
                // install_mail_jails is idempotent: safe to call even if almost everything is OK.
                Fail2banManager.InstallResult res = fail2banManager.installMailJails();
                JSONObject jres = new JSONObject().put("success", res.success)
                    .put("message", res.success ? res.message : (res.error != null ? res.error : I18n.tr("server.operationFailed")));
                steps.put(buildStep("install_mail_jails",
                    I18n.tr("server.f2bfix.mailJails"), jres));
                if (!res.success) anyFailed = true;
            } else if (mailFileOk) {
                steps.put(buildSkipStep("install_mail_jails",
                    I18n.tr("server.f2bfix.mailJailsOk")));
            }
        } catch (Exception e) {
            steps.put(buildErrorStep("install_mail_jails", I18n.tr("server.errorWith", Map.of("error", ErrorText.detail("runFixAll", e)))));
            anyFailed = true;
        }

        // Step 4b: do the jails ban with a command that exists on this system?
        // Installing them is not enough: two of them inherited an action based on iptables, which
        // does not exist on FreeBSD, and banned into thin air, counting the bans as successful.
        try {
            JSONObject diag = org.daemoxcp.mail.security.BanActionRepair.diagnosis();
            JSONArray broken = diag.optJSONArray("broken");
            JSONArray notJudged = diag.optJSONArray("not_judged");
            boolean toRepair = (broken != null && broken.length() > 0)
                              || (notJudged != null && notJudged.length() > 0);
            if (toRepair) {
                JSONObject rr = org.daemoxcp.mail.security.BanActionRepair.repair();
                steps.put(buildStep("repair_ban_action",
                    I18n.tr("server.f2bfix.banAction"), rr));
                if (!rr.optBoolean("success", false)) anyFailed = true;
            } else {
                steps.put(buildSkipStep("repair_ban_action",
                    I18n.tr("server.f2bfix.banActionOk")));
            }
        } catch (Exception e) {
            steps.put(buildErrorStep("repair_ban_action", I18n.tr("server.errorWith", Map.of("error", ErrorText.detail("runFixAll", e)))));
            anyFailed = true;
        }

        // Step 5a: PRE-step -- check that we are NOT in a jail, and load the pf module
        boolean inJail = isRunningInsideFreebsdJail();
        if (inJail) {
            steps.put(buildErrorStep("load_pf_module",
                I18n.tr("server.f2bfix.inJail")));
            // skip all the pf steps
            r.put("success", false);
            r.put("steps", steps);
            r.put("message", I18n.tr("server.f2bfix.inJailDone"));
            return r;
        }
        boolean pfModuleLoaded = isPfModuleLoaded();
        if (!pfModuleLoaded) {
            JSONObject res = loadPfModule();
            steps.put(buildStep("load_pf_module", I18n.tr("server.f2bfix.loadModule"), res));
            if (!res.optBoolean("success")) {
                anyFailed = true;
                // Without the pf module, all the following steps would fail: stop here
                r.put("success", false);
                r.put("steps", steps);
                r.put("message", I18n.tr("server.f2bfix.moduleFailed"));
                return r;
            }
            pfModuleLoaded = true;
        } else {
            steps.put(buildSkipStep("load_pf_module", I18n.tr("server.pf.alreadyLoaded")));
        }

        // Step 5b: create /etc/pf.conf if missing
        boolean pfConfExists = java.nio.file.Files.exists(java.nio.file.Paths.get("/etc/pf.conf"));
        if (!pfConfExists) {
            JSONObject res = createPfConfMinimal();
            steps.put(buildStep("create_pf_conf", I18n.tr("server.f2bfix.createConf"), res));
            if (!res.optBoolean("success")) anyFailed = true;
            pfConfExists = res.optBoolean("success");
        } else {
            steps.put(buildSkipStep("create_pf_conf", I18n.tr("server.f2bfix.confExists")));
        }

        // Step 6: add anchor f2b if missing
        if (pfConfExists) {
            boolean anchorPresent = false;
            try {
                String c = java.nio.file.Files.readString(java.nio.file.Paths.get("/etc/pf.conf"));
                anchorPresent = org.daemoxcp.mail.security.Fail2banAutoSetup.hasF2bAnchor(c);
            } catch (Exception ignored) {}
            if (!anchorPresent) {
                JSONObject res = addPfAnchorF2b();
                steps.put(buildStep("add_pf_anchor", I18n.tr("server.f2bfix.addAnchor"), res));
                if (!res.optBoolean("success")) anyFailed = true;
            } else {
                steps.put(buildSkipStep("add_pf_anchor", I18n.tr("server.f2bfix.anchorPresent")));
            }
        }

        // Step 7: enable pf at boot
        if (pfConfExists && !isPfEnabledAtBoot()) {
            JSONObject res = enablePfAtBoot();
            steps.put(buildStep("enable_pf_at_boot", I18n.tr("server.step.enableBoot", Map.of("service", "pf")), res));
            if (!res.optBoolean("success")) anyFailed = true;
        } else if (pfConfExists) {
            steps.put(buildSkipStep("enable_pf_at_boot", I18n.tr("server.unbound.step.bootAlready", Map.of("service", "pf"))));
        }

        // Step 8: start pf
        if (pfConfExists && !isPfRunning()) {
            JSONObject res = startPfService();
            steps.put(buildStep("start_pf", I18n.tr("server.f2bfix.startPf"), res));
            if (!res.optBoolean("success")) anyFailed = true;
        } else if (pfConfExists) {
            steps.put(buildSkipStep("start_pf", I18n.tr("server.unbound.step.running", Map.of("service", "pf"))));
        }

        // Step 9: start Fail2ban
        if (f2bInstalled && !isFail2banRunning()) {
            JSONObject res = startFail2banService();
            steps.put(buildStep("start_fail2ban", I18n.tr("server.unbound.step.start", Map.of("service", "Fail2ban")), res));
            if (!res.optBoolean("success")) anyFailed = true;
        } else if (f2bInstalled) {
            steps.put(buildSkipStep("start_fail2ban", I18n.tr("server.unbound.step.running", Map.of("service", "Fail2ban"))));
        }

        r.put("success", !anyFailed);
        r.put("steps", steps);
        r.put("message", I18n.tr(anyFailed ? "server.unbound.someFailed" : "server.f2bfix.allDone"));
        return r;
    }

    private JSONObject buildStep(String id, String label, JSONObject result) {
        return new JSONObject()
            .put("id", id)
            .put("label", label)
            .put("success", result.optBoolean("success", false))
            .put("status", "executed")
            .put("message", result.optString("message", ""))
            .put("output", result.optString("output", ""));
    }
    private JSONObject buildSkipStep(String id, String reason) {
        return new JSONObject()
            .put("id", id)
            .put("label", reason)
            .put("success", true)
            .put("status", "skipped")
            .put("message", I18n.tr("server.f2bfix.nothingToDo"));
    }
    private JSONObject buildErrorStep(String id, String msg) {
        return new JSONObject()
            .put("id", id)
            .put("label", I18n.tr("server.f2bfix.unexpectedError"))
            .put("success", false)
            .put("status", "error")
            .put("message", msg);
    }

    /**
     * Adds the f2b anchor to /etc/pf.conf if missing. Safe operation:
     *  - does not remove existing rules
     *  - adds a single line "anchor \"f2b/*\""
     *  - backs up the file with a timestamp
     *  - if added, reloads pf with pfctl -f /etc/pf.conf
     */
    private JSONObject addPfAnchorF2b() {
        JSONObject r = new JSONObject();
        try {
            java.nio.file.Path pfConfPath = java.nio.file.Paths.get("/etc/pf.conf");
            if (!java.nio.file.Files.exists(pfConfPath)) {
                r.put("success", false);
                r.put("message", I18n.tr("server.f2bfix.anchorNoConf"));
                return r;
            }
            String content = java.nio.file.Files.readString(pfConfPath);
            if (org.daemoxcp.mail.security.Fail2banAutoSetup.hasF2bAnchor(content)) {
                r.put("success", true);
                r.put("message", I18n.tr("server.f2bfix.anchorAlready"));
                return r;
            }
            // Backup
            String bakPath = org.daemoxcp.mail.system.ConfigBackups.copy(pfConfPath).toString();
            // The anchor should go BEFORE the pass/block rules. The recommended position
            // is right after the tables, before the filter rules. Safe approach:
            // we append it at the end with a comment -- pf evaluates the anchors in order,
            // and for fail2ban (which blocks) at the end is fine anyway.
            String append = "\n# Fail2ban anchor (added by the panel)\nanchor \"f2b/*\"\n";
            java.nio.file.Files.writeString(pfConfPath,
                content + append,
                java.nio.charset.StandardCharsets.UTF_8);

            // Syntax test before reloading
            // TODO: migrate to Shell.run when touched
            ProcessBuilder testPb = new ProcessBuilder("/sbin/pfctl", "-nf", "/etc/pf.conf");
            org.daemoxcp.mail.util.Shell.applyPath(testPb);
            testPb.redirectErrorStream(true);
            Process tp = testPb.start();
            String testOut = new String(tp.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            tp.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
            if (tp.exitValue() != 0) {
                // Rollback
                java.nio.file.Files.copy(java.nio.file.Paths.get(bakPath), pfConfPath,
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                r.put("success", false);
                r.put("message", I18n.tr("server.f2bfix.anchorBadSyntax", Map.of("output", testOut)));
                return r;
            }
            // Live reload (only if pf is running, otherwise the anchor will be
            // loaded at the next start)
            String loadOut = "";
            if (isPfRunning()) {
                // TODO: migrate to Shell.run when touched
                ProcessBuilder loadPb = new ProcessBuilder("/sbin/pfctl", "-f", "/etc/pf.conf");
                org.daemoxcp.mail.util.Shell.applyPath(loadPb);
                loadPb.redirectErrorStream(true);
                Process lp = loadPb.start();
                loadOut = new String(lp.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                lp.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
                if (lp.exitValue() != 0) {
                    // Rollback if the load fails at runtime (the config was valid but the reload is refused?)
                    java.nio.file.Files.copy(java.nio.file.Paths.get(bakPath), pfConfPath,
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                    // Re-load the backup version
                    // TODO: migrate to Shell.run when touched
                    new ProcessBuilder("/sbin/pfctl", "-f", "/etc/pf.conf").redirectErrorStream(true).start().waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
                    r.put("success", false);
                    r.put("message", I18n.tr("server.f2bfix.anchorReloadFailed", Map.of("output", loadOut)));
                    return r;
                }
            } else {
                loadOut = I18n.tr("server.f2bfix.anchorPfStopped");
            }

            r.put("success", true);
            r.put("message", I18n.tr("server.f2bfix.anchorAdded", Map.of("backup", bakPath)));
            r.put("output", loadOut);
            return r;
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", I18n.tr("server.errorWith", Map.of("error", ErrorText.detail("addPfAnchorF2b", e))));
            return r;
        }
    }

    /**
     * Diagnoses why a mail jail is not active at runtime.
     * Checks in order: file, existing logpath, existing filter, errors from fail2ban-client.
     */
    private String diagnoseMailJailIssue(String jailName, boolean inFile) {
        if (!inFile) return I18n.tr("server.f2bfix.diag.notInFile");

        // Expected logpath for each mail jail (roundcube path auto-detected)
        String logpath = switch (jailName) {
            case "dovecot", "postfix-auth" -> "/var/log/maillog";
            case "roundcube-auth" -> {
                String detected = fail2banManager.getRoundcubeUserloginsPath();
                yield detected != null ? detected : "/usr/local/www/roundcube/logs/userlogins";
            }
            case "rspamd" -> "/var/log/rspamd/rspamd.log";
            default -> null;
        };
        if (logpath != null && !java.nio.file.Files.exists(java.nio.file.Paths.get(logpath))) {
            return I18n.tr("server.f2bfix.diag.noLogpath", Map.of("path", logpath));
        }

        // Filter file
        String filterName = switch (jailName) {
            case "postfix-auth" -> "postfix-sasl";
            default -> jailName;
        };
        java.nio.file.Path filterPath = java.nio.file.Paths.get("/usr/local/etc/fail2ban/filter.d/" + filterName + ".conf");
        if (!java.nio.file.Files.exists(filterPath)) {
            return I18n.tr("server.f2bfix.diag.noFilter", Map.of("filter", filterName));
        }

        // Ask fail2ban-client for the specific reason
        var r = org.daemoxcp.mail.util.Shell.run(java.time.Duration.ofSeconds(5),
            "/usr/local/bin/fail2ban-client", "status", jailName);
        String out = r.output();
        if (out.contains("does not exist") || out.contains("not found")
                || out.contains("Sorry, but the jail")) {
            return I18n.tr("server.f2bfix.diag.notLoaded");
        }
        if (!r.success()) {
            return "exit=" + r.exitCode() + " (" + (out.isBlank() ? I18n.tr("server.f2bfix.diag.noOutput") : out.trim().replace('\n', ' ')) + ")";
        }
        // If we are here, the status command answered normally (with the counters
        // "Currently failed", "Banned IP list", etc). The jail IS loaded and active,
        // but for some reason the calling check did not detect it. It is not an error
        // of the jail: we return a string that makes clear it is a false alarm.
        return I18n.tr("server.f2bfix.diag.activeAfterAll");
    }

    /**
     * Reloads Fail2ban with fail2ban-client reload.
     * Before the reload it ensures the prerequisites that could make the loading of
     * some jails fail (e.g. Roundcube's userlogins file).
     * If a single jail fails, fail2ban rejects the WHOLE reload -- so
     * it is always better to be proactive.
     */
    /**
     * Helper: converts a {@link org.daemoxcp.mail.util.Shell.Result} into a JSONObject
     * with success/message/output fields, reducing boilerplate.
     */
    private JSONObject shellResultToJson(org.daemoxcp.mail.util.Shell.Result r, String okMessage, String failPrefix) {
        return new JSONObject()
            .put("success", r.success())
            .put("message", r.success() ? okMessage
                : (r.timedOut() ? "TIMEOUT: " + failPrefix
                                : failPrefix + " exit=" + r.exitCode()))
            .put("output", r.output());
    }

    private JSONObject reloadFail2banAction() {
        // Prereq: Roundcube log file (if missing, the roundcube-auth jail makes the whole reload fail)
        try { fail2banManager.ensureRoundcubeLoggingEnabled(); } catch (Exception ignored) {}
        var r = org.daemoxcp.mail.util.Shell.run(java.time.Duration.ofSeconds(15),
            "/usr/local/bin/fail2ban-client", "reload");
        return shellResultToJson(r, "Fail2ban reload OK", "Reload");
    }

    private JSONObject startFail2banService() {
        var r = org.daemoxcp.mail.util.Shell.run(java.time.Duration.ofSeconds(20),
            "/usr/sbin/service", "fail2ban", "start");
        return shellResultToJson(r, I18n.tr("server.f2bfix.serviceStarted"), "service start");
    }

    /**
     * Clean restart of the fail2ban service (equivalent of `service fail2ban restart`).
     * Unlike "reload", this kills the daemon and restarts it from scratch -- useful to
     * get out of confused states (e.g. after many consecutive reloads).
     * NB: it also resets the "Currently failed" and "Total failed" counters of all the jails.
     */
    private JSONObject restartFail2banService() {
        var r = org.daemoxcp.mail.util.Shell.run(java.time.Duration.ofSeconds(30),
            "/usr/sbin/service", "fail2ban", "restart");
        return shellResultToJson(r, I18n.tr("server.f2bfix.restarted"), "service restart");
    }

    // ============== ADMIN MANAGEMENT API ==============

    /**
     * The periodic report belongs to the SETTINGS, not to the updates: recipient,
     * sender and frequency are choices, not diagnosis. It had ended up in the Updates
     * page only because the call plumbing already existed there -- convenient for
     * whoever writes the code, not for whoever uses it -- and on top of that the email
     * footer already said to look for it here.
     */
    /**
     * Automatic creation on Cloudflare of the records that until now were added by hand.
     * The automation already existed, but only inside the DKIM rotation: same tools, not
     * connected to anything else.
     */
    private void handleApiAutoDns(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) { sendJsonError(exchange, 401, I18n.tr("server.unauthorized")); return; }
        if (!"POST".equals(exchange.getRequestMethod())) { sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed")); return; }
        String body = readRequestBodyWithLimit(exchange);
        if (body == null) { sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge")); return; }
        String ip = getClientIp(exchange);
        JSONObject req;
        try { req = new JSONObject(body); }
        catch (Exception e) { sendJsonError(exchange, 400, I18n.tr("server.badJson")); return; }

        org.daemoxcp.mail.security.AutoDns auto =
                new org.daemoxcp.mail.security.AutoDns(Main.mailDatabase,
                        new org.daemoxcp.mail.security.CloudflareManager(Main.mailDatabase));
        int domainId = req.optInt("domain_id", 0);
        JSONObject response;
        switch (req.optString("action", "")) {
            case "status" -> response = auto.state(domainId);
            case "create" -> {
                if (!"CREATE".equals(req.optString("confirm", ""))) {
                    response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                    break;
                }
                String which = req.optString("which", "");
                // The default is "none", not "quarantine": RFC 9989 section 5.1.5. A default
                // value that blocks mail is a trap for whoever presses without choosing.
                response = auto.create(domainId, which, req.optString("policy", "none"));
                logAudit("AUTODNS_CREATE", ip, which + " on domain " + domainId
                        + (response.optBoolean("success") ? " - created" : " - NOT created: "
                           + response.optString("error", "?")));
            }
            case "change_policy" -> {
                response = auto.changePolicy(domainId, req.optString("policy", ""),
                        "CHANGE".equals(req.optString("confirm", "")));
                if ("CHANGE".equals(req.optString("confirm", "")))
                    logAudit("AUTODNS_POLICY", ip, "domain " + domainId + " -> p="
                            + req.optString("policy", "") + (response.optBoolean("success")
                            ? " - done" : " - NOT done: " + response.optString("error", "?")));
            }
            case "mtasts_status" -> response = org.daemoxcp.mail.system.MtaSts.state();
            case "mtasts_mode" -> response = org.daemoxcp.mail.system.MtaSts.setMode(req.optString("mode", ""));
            case "mtasts_txt" -> {
                if (!"CREATE".equals(req.optString("confirm", ""))) {
                    response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                    break;
                }
                response = auto.createTxtMtaSts(domainId);
                // The extra MTA-STS records that the write removes are deletions in the DNS:
                // they stay written here too, not only in the response.
                JSONArray removed = response.optJSONArray("removed");
                logAudit("MTASTS_TXT", ip, "domain " + domainId
                        + (response.optBoolean("success") ? " - published" : " - NOT published: "
                           + response.optString("error", "?"))
                        + (removed == null || removed.length() == 0 ? ""
                           : " - removed " + removed.length() + " extra MTA-STS records: " + removed.join("  ||  ")));
            }
            case "create_optional" -> {
                if (!"CREATE".equals(req.optString("confirm", ""))) {
                    response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                    break;
                }
                String q = req.optString("which", "");
                response = auto.createOptional(domainId, q);
                logAudit("AUTODNS_OPTIONAL", ip, q + " on domain " + domainId
                        + (response.optBoolean("success") ? " - created" : " - NOT created: "
                           + response.optString("error", "?")));
            }
            // The DNS page must be able to follow the job it has just started: without this
            // case it would be left with an identifier and no way to know how it ended.
            case "job_status" -> response = UpdateManager.jobStatus(req.optString("jobId", ""));
            case "configure_all" -> {
                if (!"CONFIGURE".equals(req.optString("confirm", ""))) {
                    response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                    break;
                }
                // Before touching anything: a Cloudflare account that sees the zone, assigned to the domain
                // if it is the only one that sees it (finding 250).
                org.daemoxcp.mail.system.DomainSetup.CloudflareChoice cfc = org.daemoxcp.mail.system.DomainSetup.cloudflareFor(domainId);
                if (!cfc.ready()) {
                    response = new JSONObject().put("success", false).put("error", cfc.error());
                    logAudit("DOMAIN_CONFIGURE", ip, "domain " + domainId + " - NOT started: no Cloudflare account that sees its zone");
                    break;
                }
                if (cfc.assigned() != null)
                    logAudit("CLOUDFLARE_ASSIGN", ip, "domain " + domainId + " to Cloudflare account " + cfc.assigned().id
                            + " (the only one whose token sees the zone)");
                response = UpdateManager.startDomainSetup(domainId);
                logAudit("DOMAIN_CONFIGURE", ip, "domain " + domainId
                        + " - started as job " + response.optString("jobId", ""));
            }
            case "mailboxes" -> response = auto.availableMailboxes();
            case "mailbox_create" -> {
                if (!"CREATE".equals(req.optString("confirm", ""))) {
                    response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                    break;
                }
                response = auto.createReportMailbox(domainId);
                logAudit("AUTODNS_MAILBOX", ip, "mailbox dmarc@ domain " + domainId
                        + (response.optBoolean("success") ? " - created" : " - NOT created: "
                           + response.optString("error", "?")));
            }
            case "alias_create" -> {
                if (!"CREATE".equals(req.optString("confirm", ""))) {
                    response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                    break;
                }
                String target = req.optString("destination", "");
                response = auto.createReportAlias(domainId, target);
                logAudit("AUTODNS_ALIAS", ip, "alias dmarc@ domain " + domainId + " to " + target
                        + (response.optBoolean("success") ? " - created" : " - NOT created: "
                           + response.optString("error", "?")));
            }
            default -> response = new JSONObject().put("success", false).put("error", I18n.tr("server.unknownAction"));
        }
        sendJsonResponse(exchange, response);
    }

    private void handleApiReport(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) { sendJsonError(exchange, 401, I18n.tr("server.unauthorized")); return; }
        if (!"POST".equals(exchange.getRequestMethod())) { sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed")); return; }
        String body = readRequestBodyWithLimit(exchange);
        if (body == null) { sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge")); return; }
        String ip = getClientIp(exchange);
        JSONObject req;
        try { req = new JSONObject(body); }
        catch (Exception e) { sendJsonError(exchange, 400, I18n.tr("server.badJson")); return; }

        JSONObject response;
        switch (req.optString("action", "")) {
            case "status" -> response = org.daemoxcp.mail.system.PeriodicReport.state();
            case "identity" -> response = org.daemoxcp.mail.system.PeriodicReport.identityState();
            case "preview" -> response = org.daemoxcp.mail.system.PeriodicReport.preview();
            case "save" -> response = org.daemoxcp.mail.system.PeriodicReport.saveSettings(
                    req.optString("recipient", ""), req.optString("sender", ""),
                    req.optString("frequency", ""), req.optString("now", ""),
                    req.optBoolean("active", false));
            case "identity_create" -> {
                if (!"CREATE".equals(req.optString("confirm", ""))) {
                    response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                    break;
                }
                response = org.daemoxcp.mail.system.PeriodicReport.createIdentity(req.optString("address", ""));
                logAudit("REPORT_IDENTITY", ip, req.optString("address", "")
                        + (response.optBoolean("success") ? " - created" : " - NOT created"));
            }
            case "send" -> {
                if (!"SEND".equals(req.optString("confirm", ""))) {
                    response = new JSONObject().put("success", false).put("error", I18n.tr("server.confirmMissing"));
                    break;
                }
                response = org.daemoxcp.mail.system.PeriodicReport.sendNow(req.optString("recipient", ""));
                logAudit("REPORT_SEND", ip, req.optString("recipient", "")
                        + (response.optBoolean("success") ? " - sent" : " - NOT sent"));
            }
            default -> response = new JSONObject().put("success", false).put("error", I18n.tr("server.unknownAction"));
        }
        sendJsonResponse(exchange, response);
    }

    /**
     * /api/admins: the administrators (permission admins.manage) and the key of the mailbox password
     * vault (permission vault.manage).
     *
     * No passwords: a new administrator has a name, an email and a role, and gets in with a
     * code sent to that email. The two vault operations used to ask for the current password;
     * now they want a recent confirmation with a passkey or with a code (REAUTH_SECONDS).
     *
     *  GET  ?action=list
     *  POST {action: create, username, email, role} | {action: update, id, role, email}
     *       | {action: delete, id} | {action: vault_backup_key} | {action: vault_rotate_key}
     */
    private void handleApiAdmins(HttpExchange exchange) throws IOException {
        Optional<WebSessions.Current> session = currentSession(exchange);
        if (session.isEmpty()) {
            sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
            return;
        }
        AuthStore.Admin me = session.get().admin();
        String ip = getClientIp(exchange);
        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();
        try {
            if ("GET".equals(method)) {
                if (!AuthStore.may(me, "admins.manage")) {
                    sendJsonError(exchange, 403, I18n.tr("server.admins.forbidden"));
                    return;
                }
                JSONArray admins = new JSONArray();
                for (AuthStore.Admin a : AuthStore.admins()) {
                    admins.put(new JSONObject().put("id", a.id()).put("username", a.username()).put("role", a.role())
                            .put("active", a.active()).put("email", a.email())
                            .put("passkeys", AuthStore.passkeysOf(a.id()).size())
                            .put("created_at", AuthHandlers.iso(a.createdAt()))
                            .put("last_login", AuthHandlers.iso(a.lastLogin()))
                            .put("is_current", a.id() == me.id()));
                }
                sendJsonResponse(exchange, response.put("success", true).put("admins", admins));
                return;
            }
            if (!"POST".equals(method)) {
                sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
                return;
            }
            String body = readRequestBodyWithLimit(exchange);
            if (body == null) {
                sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge"));
                return;
            }
            JSONObject req = new JSONObject(body);
            String action = req.optString("action", "");

            if ("vault_backup_key".equals(action) || "vault_rotate_key".equals(action)) {
                if (!AuthStore.may(me, "vault.manage")) {
                    sendJsonError(exchange, 403, I18n.tr("server.admins.forbidden"));
                    return;
                }
                // The recent confirmation was already asked for by the route's filter (Access.needsConfirmation).
                if ("vault_backup_key".equals(action)) vaultBackupKey(response, me, ip);
                else vaultRotateKey(response, me, ip);
                sendJsonResponse(exchange, response);
                return;
            }

            if (!AuthStore.may(me, "admins.manage")) {
                sendJsonError(exchange, 403, I18n.tr("server.admins.forbidden"));
                return;
            }
            switch (action) {
                case "create" -> {
                    String username = req.optString("username", "").trim();
                    String email = req.optString("email", "").trim();
                    String role = req.optString("role", "admin");
                    if (!SecurityUtils.isValidUsername(username)) {
                        response.put("success", false).put("error", I18n.tr("server.account.badUsername"));
                    } else if (!org.daemoxcp.mail.security.LoginCodes.validEmail(email)) {
                        response.put("success", false).put("error", I18n.tr("server.login.badEmail"));
                    } else if (!AuthStore.ROLES.contains(role)) {
                        response.put("success", false).put("error", I18n.tr("server.admins.badRole"));
                    } else {
                        AuthStore.Created created = AuthStore.createAdmin(username, email, role);
                        switch (created.result()) {
                            case CREATED -> {
                                logAudit("ADMIN_CREATED", ip, "by=" + me.username() + " admin_id=" + created.id() + " role=" + role);
                                response.put("success", true).put("id", created.id());
                            }
                            case NAME_TAKEN -> response.put("success", false).put("error", I18n.tr("server.account.usernameTaken"));
                            case EMAIL_TAKEN -> response.put("success", false).put("error", I18n.tr("server.account.emailTaken"));
                            default -> response.put("success", false).put("error", I18n.tr("server.requestFailed"));
                        }
                    }
                }
                case "update" -> {
                    long id = req.optLong("id", 0);
                    String role = req.optString("role", "");
                    String email = req.optString("email", "").trim();
                    Optional<AuthStore.Admin> target = AuthStore.admins().stream().filter(a -> a.id() == id).findFirst();
                    if (target.isEmpty()) {
                        response.put("success", false).put("error", I18n.tr("server.account.badId"));
                    } else if (!AuthStore.ROLES.contains(role)) {
                        response.put("success", false).put("error", I18n.tr("server.admins.badRole"));
                    } else if (id == me.id() && !role.equals(me.role())) {
                        response.put("success", false).put("error", I18n.tr("server.admins.notSelf"));
                    } else if ("superadmin".equals(target.get().role()) && !"superadmin".equals(role)
                            && AuthStore.activeSuperadmins() <= 1) {
                        response.put("success", false).put("error", I18n.tr("server.admins.lastSuperadmin"));
                    } else if (!email.isEmpty() && !org.daemoxcp.mail.security.LoginCodes.validEmail(email)) {
                        response.put("success", false).put("error", I18n.tr("server.login.badEmail"));
                    } else {
                        AuthStore.CreateResult emailResult = AuthStore.CreateResult.CREATED;
                        if (!email.isEmpty() && !email.equalsIgnoreCase(target.get().email()))
                            emailResult = AuthStore.setEmail(id, email);
                        if (emailResult == AuthStore.CreateResult.EMAIL_TAKEN) {
                            response.put("success", false).put("error", I18n.tr("server.account.emailTaken"));
                        } else if (emailResult != AuthStore.CreateResult.CREATED || !AuthStore.setRole(id, role)) {
                            response.put("success", false).put("error", I18n.tr("server.requestFailed"));
                        } else {
                            logAudit("ADMIN_UPDATED", ip, "by=" + me.username() + " admin_id=" + id + " role=" + role);
                            response.put("success", true);
                        }
                    }
                }
                case "delete" -> {
                    long id = req.optLong("id", 0);
                    Optional<AuthStore.Admin> target = AuthStore.admins().stream().filter(a -> a.id() == id).findFirst();
                    if (target.isEmpty()) {
                        response.put("success", false).put("error", I18n.tr("server.account.badId"));
                    } else if (id == me.id()) {
                        response.put("success", false).put("error", I18n.tr("server.admins.notSelf"));
                    } else if ("superadmin".equals(target.get().role()) && AuthStore.activeSuperadmins() <= 1) {
                        response.put("success", false).put("error", I18n.tr("server.admins.lastSuperadmin"));
                    } else if (AuthStore.deleteAdmin(id)) {
                        // Along with them go, via ON DELETE CASCADE, their passkeys, sessions and codes.
                        logAudit("ADMIN_DELETED", ip, "by=" + me.username() + " admin_id=" + id);
                        response.put("success", true);
                    } else {
                        response.put("success", false).put("error", I18n.tr("server.requestFailed"));
                    }
                }
                default -> response.put("success", false).put("error", I18n.tr("server.unknownAction"));
            }
        } catch (org.json.JSONException e) {
            sendJsonError(exchange, 400, I18n.tr("server.badRequest"));
            return;
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Admin request failed", e);
            response = new JSONObject().put("success", false).put("error", I18n.tr("server.requestFailed"));
        }
        sendJsonResponse(exchange, response);
    }

    /** Exports the private key of the vault in base64, for the backup copy. Only the root (the route is its own). */
    private void vaultBackupKey(JSONObject response, AuthStore.Admin me, String ip) {
        try {
            org.daemoxcp.mail.security.PasswordVault vault = org.daemoxcp.mail.security.PasswordVault.getInstance();
            response.put("success", true)
                    .put("key_base64", vault.exportPrivateKeyBase64())
                    .put("key_file_path", org.daemoxcp.mail.security.PasswordVault.privateKeyLocation())
                    .put("message", I18n.tr("server.vault.exported"));
            logAudit("VAULT_KEY_EXPORTED", ip, "admin_id=" + me.id());
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Vault key export failed", e);
            response.put("success", false).put("error", I18n.tr("server.vault.exportFailed"));
        }
    }

    /**
     * Rotation of the vault keys: a new pair, all the password copies re-encrypted with its public key,
     * the previous private key kept alongside in root's file (PasswordVault.rotate).
     */
    private void vaultRotateKey(JSONObject response, AuthStore.Admin me, String ip) {
        try {
            org.daemoxcp.mail.security.PasswordVault.Reencrypted r = org.daemoxcp.mail.security.PasswordVault.getInstance().rotate(Main.mailDatabase);
            if (r.reencrypted() == 0 && r.total() > 0) {
                // None can be decrypted: the current keys are already broken. The new pair is not saved.
                response.put("success", false).put("error", I18n.tr("server.vault.allFailed", java.util.Map.of("total", r.total())));
                return;
            }
            response.put("success", true)
                    .put("summary", new JSONObject().put("total", r.total()).put("reencrypted", r.reencrypted()).put("failed", r.failed()))
                    .put("message", I18n.tr("server.vault.rotated", java.util.Map.of(
                            "path", org.daemoxcp.mail.security.PasswordVault.privateKeyLocation())));
            logAudit("VAULT_KEY_ROTATED", ip, "admin_id=" + me.id() + " total=" + r.total()
                    + " reencrypted=" + r.reencrypted() + " failed=" + r.failed());
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Vault key rotation failed", e);
            response.put("success", false).put("error", I18n.tr("server.vault.rotateFailed"));
        }
    }

    // ============== AUTO-RESPONDER API ==============

    private void handleApiAutoResponder(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
            return;
        }

        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();

        try {
            switch (method) {
                case "GET" -> {
                    String mailboxIdStr = extractParamFromQuery(exchange.getRequestURI().getQuery(), "mailbox_id");
                    if (mailboxIdStr != null) {
                        int mailboxId = Integer.parseInt(mailboxIdStr);
                        MailDatabase.AutoResponder ar = Main.mailDatabase.getAutoResponder(mailboxId);

                        response.put("success", true);
                        if (ar != null) {
                            response.put("enabled", ar.enabled);
                            response.put("subject", ar.subject);
                            response.put("body", ar.body);
                            response.put("start_date", ar.startDate != null ? ar.startDate.toString() : "");
                            response.put("end_date", ar.endDate != null ? ar.endDate.toString() : "");
                            response.put("interval_hours", ar.intervalHours);
                        } else {
                            response.put("enabled", false);
                        }
                    } else {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.mailbox.idRequired"));
                    }
                }
                case "POST" -> {
                    String body = readRequestBodyWithLimit(exchange);
        if (body == null) {
            sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge"));
            return;
        }
                    JSONObject req = new JSONObject(body);
                    String action = req.optString("action", "save");

                    if ("reset_tracking".equals(action)) {
                        // Clears the memory of the automatic replies: only .dovecot.lda-dupes in the mailbox's home.
                        // No longer the compiled rules (Dovecot cannot save them again in root's folder, and it
                        // recompiled them on every delivery with an error in the maillog) nor the restart of the
                        // whole of Dovecot (the memory is reread on every delivery): VacationTracking, finding 219.
                        int mailboxId = req.optInt("mailbox_id", 0);
                        MailDatabase.Mailbox mailbox = Main.mailDatabase.getMailboxById(mailboxId);
                        if (mailbox != null) {
                            String[] parts = mailbox.email.split("@");
                            if (parts.length == 2) {
                                try {
                                    if (org.daemoxcp.mail.system.VacationTracking.reset(mailbox.email)) {
                                        response.put("success", true);
                                    } else {
                                        response.put("success", false);
                                        response.put("error", I18n.tr("server.badEmail"));
                                    }
                                } catch (Exception e) {
                                    response.put("success", false);
                                    response.put("error", I18n.tr("server.errorWith", Map.of("error", ErrorText.detail("handleApiAutoResponder", e))));
                                }
                            } else {
                                response.put("success", false);
                                response.put("error", I18n.tr("server.badEmail"));
                            }
                        } else {
                            response.put("success", false);
                            response.put("error", I18n.tr("server.mailbox.notFound"));
                        }
                    } else {
                        // Save auto-responder
                        int mailboxId = req.optInt("mailbox_id", 0);
                        boolean enabled = req.optBoolean("enabled", false);
                        String subject = req.optString("subject", "Out of Office");
                        String bodyText = req.optString("body", "");
                        String startDateStr = req.optString("start_date", "");
                        String endDateStr = req.optString("end_date", "");
                        int intervalHours = req.optInt("interval_hours", 24);

                        java.sql.Date startDate = startDateStr.isEmpty() ? null : java.sql.Date.valueOf(startDateStr);
                        java.sql.Date endDate = endDateStr.isEmpty() ? null : java.sql.Date.valueOf(endDateStr);

                        if (Main.mailDatabase.saveAutoResponder(mailboxId, enabled, subject, bodyText, startDate, endDate, intervalHours)) {
                            putRulesOutcome(response, regenerateSieveScript(mailboxId));
                        } else {
                            response.put("success", false);
                            response.put("error", I18n.tr("server.autoresponder.saveFailed"));
                        }
                    }
                }
                default -> {
                    sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
                    return;
                }
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", ErrorText.forPage("handleApiAutoResponder", e));
        }

        sendJsonResponse(exchange, response);
    }

    // ============== SIEVE FILTERS API ==============

    /**
     * The Sieve filters of a mailbox. Until finding 224 the filters dialog could not do anything: it
     * sent conditions and actions as JSON text, which optJSONArray reads as null (NullPointerException,
     * with its English message in the page); to edit, it asked for ?id=, which the GET did not know,
     * and it sent id instead of filter_id. Now conditions and actions are arrays of objects, and
     * whatever is not is rejected with a message, before touching the database. Edit and delete
     * rewrite the rules of the ROW's mailbox, read from the database: the mailbox named by the
     * request does not count (with a wrong number another mailbox was rewritten, and the filter's
     * mailbox kept its old rules).
     */
    private void handleApiSieve(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
            return;
        }

        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();

        try {
            switch (method) {
                case "GET" -> {
                    String query = exchange.getRequestURI().getQuery();
                    String filterIdStr = extractParamFromQuery(query, "id");
                    String mailboxIdStr = extractParamFromQuery(query, "mailbox_id");
                    if (filterIdStr != null) {
                        // A single filter: the one the dialog opens to edit it.
                        MailDatabase.SieveFilter f = Main.mailDatabase.getSieveFilter(positiveId(filterIdStr));
                        if (f != null) {
                            response.put("success", true);
                            response.put("filter", sieveFilterJson(f));
                        } else {
                            response.put("success", false);
                            response.put("error", I18n.tr("server.filter.notFound"));
                        }
                    } else if (mailboxIdStr != null) {
                        JSONArray filters = new JSONArray();
                        for (MailDatabase.SieveFilter f : Main.mailDatabase.getSieveFilters(positiveId(mailboxIdStr))) {
                            filters.put(sieveFilterJson(f));
                        }
                        response.put("success", true);
                        response.put("filters", filters);
                    } else {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.mailbox.idRequired"));
                    }
                }
                case "POST" -> {
                    String body = readRequestBodyWithLimit(exchange);
        if (body == null) {
            sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge"));
            return;
        }
                    JSONObject req = new JSONObject(body);
                    String action = req.optString("action", "create");

                    switch (action) {
                        case "create" -> {
                            int mailboxId = req.optInt("mailbox_id", 0);
                            String name = req.optString("name", "");
                            int priority = req.optInt("priority", 0);
                            boolean enabled = req.optBoolean("enabled", true);
                            JSONArray conditions = sieveRules(req.optJSONArray("conditions"));
                            JSONArray actions = sieveRules(req.optJSONArray("actions"));

                            if (conditions == null || actions == null) {
                                response.put("success", false);
                                response.put("error", I18n.tr("server.filter.badRules"));
                            } else if (Main.mailDatabase.createSieveFilter(mailboxId, name, priority, enabled,
                                    conditions.toString(), actions.toString())) {
                                // The mailbox of the row just created: the one that exists (the table's constraint).
                                putRulesOutcome(response, regenerateSieveScript(mailboxId));
                            } else {
                                response.put("success", false);
                                response.put("error", I18n.tr("server.filter.createFailed"));
                            }
                        }
                        case "update" -> {
                            int filterId = req.optInt("filter_id", 0);
                            String name = req.optString("name", "");
                            int priority = req.optInt("priority", 0);
                            boolean enabled = req.optBoolean("enabled", true);
                            JSONArray conditions = sieveRules(req.optJSONArray("conditions"));
                            JSONArray actions = sieveRules(req.optJSONArray("actions"));
                            MailDatabase.SieveFilter row = Main.mailDatabase.getSieveFilter(filterId);

                            if (row == null) {
                                response.put("success", false);
                                response.put("error", I18n.tr("server.filter.notFound"));
                            } else if (conditions == null || actions == null) {
                                response.put("success", false);
                                response.put("error", I18n.tr("server.filter.badRules"));
                            } else if (Main.mailDatabase.updateSieveFilter(filterId, name, priority, enabled,
                                    conditions.toString(), actions.toString())) {
                                putRulesOutcome(response, regenerateSieveScript(row.mailboxId));
                            } else {
                                response.put("success", false);
                                response.put("error", I18n.tr("server.filter.updateFailed"));
                            }
                        }
                        case "delete" -> {
                            int filterId = req.optInt("filter_id", 0);
                            // Read before deleting it: afterwards we could no longer tell which mailbox it was.
                            MailDatabase.SieveFilter row = Main.mailDatabase.getSieveFilter(filterId);

                            if (row == null) {
                                response.put("success", false);
                                response.put("error", I18n.tr("server.filter.notFound"));
                            } else if (Main.mailDatabase.deleteSieveFilter(filterId)) {
                                putRulesOutcome(response, regenerateSieveScript(row.mailboxId));
                            } else {
                                response.put("success", false);
                                response.put("error", I18n.tr("server.filter.deleteFailed"));
                            }
                        }
                        default -> {
                            response.put("success", false);
                            response.put("error", I18n.tr("server.unknownAction"));
                        }
                    }
                }
                default -> {
                    sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
                    return;
                }
            }
        } catch (Exception e) {
            // The exception's message is in English and talks about the code: in the log, not in the page.
            LOGGER.log(Level.WARNING, "Sieve filters request failed", e);
            response = new JSONObject();
            response.put("success", false);
            response.put("error", I18n.tr("server.internalError"));
        }

        sendJsonResponse(exchange, response);
    }

    /** A filter as the dialog reads it: conditions and actions as arrays, not as the column's text. */
    private static JSONObject sieveFilterJson(MailDatabase.SieveFilter f) {
        JSONObject filter = new JSONObject();
        filter.put("id", f.id);
        filter.put("mailbox_id", f.mailboxId);
        filter.put("name", f.name);
        filter.put("priority", f.priority);
        filter.put("enabled", f.enabled);
        filter.put("conditions", new JSONArray(f.conditions));
        filter.put("actions", new JSONArray(f.actions));
        return filter;
    }

    /**
     * The conditions or the actions of a filter as the page sends them: a non-empty array of objects.
     * Null for everything else, including the same array written as text (what the page sent before
     * finding 224, and which optJSONArray gives as null): SieveGenerator does not write a filter
     * without conditions or without actions, and the panel would report as saved a filter that does
     * nothing.
     */
    static JSONArray sieveRules(JSONArray rules) {
        if (rules == null || rules.isEmpty()) return null;
        for (int i = 0; i < rules.length(); i++) {
            if (!(rules.opt(i) instanceof JSONObject)) return null;
        }
        return rules;
    }

    /** The number of a row from the query: 0 (no row) if it is not a positive integer, instead of an exception. */
    private static int positiveId(String value) {
        try {
            int id = Integer.parseInt(value.trim());
            return id > 0 ? id : 0;
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    /**
     * Rewrites the mailbox's Sieve rules from the database: automatic reply, forwards and filters, all
     * together. False if they were not written: the mailbox does not exist, or SieveGenerator refuses (the
     * address, or a folder on the path from / to the mailbox's one that others can change, RootOnlyPath of
     * finding 221), with the reason in the panel log. Then Dovecot carries on with the previous rules.
     */
    private boolean regenerateSieveScript(int mailboxId) {
        if (sieveGenerator == null) {
            LOGGER.warning("Sieve rules of mailbox " + mailboxId + " not written: no Sieve generator (MySQL was not there at start)");
            return false;
        }
        MailDatabase.Mailbox mailbox = Main.mailDatabase.getMailboxById(mailboxId);
        if (mailbox == null) {
            LOGGER.warning("Sieve rules of mailbox " + mailboxId + " not written: no such mailbox");
            return false;
        }
        return sieveGenerator.saveSieveScript(mailbox.email, sieveGenerator.generateSieveScript(mailboxId, Main.mailDatabase));
    }

    /**
     * The response of a save that has already changed the database and then rewrote the Sieve rules.
     * Before, the outcome of the write was lost and the page said it was done, while Dovecot carried on
     * with the previous rules (finding 223). The database stays as it is and the response says so
     * ("saved"): the page shows the saved row, and whoever retries does not create it twice. The rules
     * are rewritten in full at the next successful save of the mailbox.
     */
    private static void putRulesOutcome(JSONObject response, boolean written) {
        if (written) {
            response.put("success", true);
            return;
        }
        response.put("success", false);
        response.put("saved", true);
        response.put("error", I18n.tr("server.sieve.notWritten"));
    }

    // ============== FORWARDING API ==============

    private void handleApiForwarding(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
            return;
        }

        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();

        try {
            switch (method) {
                case "GET" -> {
                    String mailboxIdStr = extractParamFromQuery(exchange.getRequestURI().getQuery(), "mailbox_id");
                    if (mailboxIdStr != null) {
                        int mailboxId = positiveId(mailboxIdStr);
                        JSONArray rules = new JSONArray();
                        for (MailDatabase.ForwardingRule r : Main.mailDatabase.getForwardingRules(mailboxId)) {
                            JSONObject rule = new JSONObject();
                            rule.put("id", r.id);
                            rule.put("destination", r.destination);
                            rule.put("keep_copy", r.keepCopy);
                            rule.put("enabled", r.enabled);
                            rules.put(rule);
                        }
                        response.put("success", true);
                        response.put("rules", rules);
                    } else {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.mailbox.idRequired"));
                    }
                }
                case "POST" -> {
                    String body = readRequestBodyWithLimit(exchange);
        if (body == null) {
            sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge"));
            return;
        }
                    JSONObject req = new JSONObject(body);
                    String action = req.optString("action", "create");

                    // Edit and delete rewrite the rules of the ROW's mailbox, read from the database, not
                    // of the one the request names (finding 224: the page, when deleting, did not even send it).
                    switch (action) {
                        case "create" -> {
                            int mailboxId = req.optInt("mailbox_id", 0);
                            String destination = req.optString("destination", "");
                            boolean keepCopy = req.optBoolean("keep_copy", true);

                            if (Main.mailDatabase.createForwardingRule(mailboxId, destination, keepCopy)) {
                                putRulesOutcome(response, regenerateSieveScript(mailboxId));
                            } else {
                                response.put("success", false);
                                response.put("error", I18n.tr("server.forward.createFailed"));
                            }
                        }
                        case "update" -> {
                            int ruleId = req.optInt("rule_id", 0);
                            String destination = req.optString("destination", "");
                            boolean keepCopy = req.optBoolean("keep_copy", true);
                            boolean enabled = req.optBoolean("enabled", true);
                            MailDatabase.ForwardingRule row = Main.mailDatabase.getForwardingRule(ruleId);

                            if (row == null) {
                                response.put("success", false);
                                response.put("error", I18n.tr("server.forward.notFound"));
                            } else if (Main.mailDatabase.updateForwardingRule(ruleId, destination, keepCopy, enabled)) {
                                putRulesOutcome(response, regenerateSieveScript(row.mailboxId));
                            } else {
                                response.put("success", false);
                                response.put("error", I18n.tr("server.forward.updateFailed"));
                            }
                        }
                        case "delete" -> {
                            int ruleId = req.optInt("rule_id", 0);
                            // Read before deleting it: afterwards we could no longer tell which mailbox it was.
                            MailDatabase.ForwardingRule row = Main.mailDatabase.getForwardingRule(ruleId);

                            if (row == null) {
                                response.put("success", false);
                                response.put("error", I18n.tr("server.forward.notFound"));
                            } else if (Main.mailDatabase.deleteForwardingRule(ruleId)) {
                                putRulesOutcome(response, regenerateSieveScript(row.mailboxId));
                            } else {
                                response.put("success", false);
                                response.put("error", I18n.tr("server.forward.deleteFailed"));
                            }
                        }
                        default -> {
                            response.put("success", false);
                            response.put("error", I18n.tr("server.unknownAction"));
                        }
                    }
                }
                default -> {
                    sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
                    return;
                }
            }
        } catch (Exception e) {
            // The exception's message is in English and talks about the code: in the log, not in the page.
            LOGGER.log(Level.WARNING, "Forwarding request failed", e);
            response = new JSONObject();
            response.put("success", false);
            response.put("error", I18n.tr("server.internalError"));
        }

        sendJsonResponse(exchange, response);
    }

    // ============== RATE LIMITS API ==============

    private void handleApiRateLimits(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
            return;
        }

        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();

        try {
            switch (method) {
                case "GET" -> {
                    // The page read "limits.hourly" from what was an ARRAY, and the fields
                    // of the rows with names the server never produced: the table
                    // showed "undefined" and the form filled up with default values.
                    // Here the response takes the shape the page really reads.
                    JSONArray limits = new JSONArray();
                    JSONObject global = null;
                    for (MailDatabase.RateLimit rl : Main.mailDatabase.getRateLimits()) {
                        if ("global".equalsIgnoreCase(rl.targetType)) {
                            global = new JSONObject()
                                    .put("hourly", rl.maxPerHour)
                                    .put("daily", rl.maxPerDay)
                                    .put("max_recipients", rl.maxRecipients);
                            continue;
                        }
                        limits.put(new JSONObject()
                                .put("id", rl.id)
                                .put("email", rl.targetName == null ? "" : rl.targetName)
                                .put("target_id", rl.targetId)
                                .put("hourly_limit", rl.maxPerHour)
                                .put("daily_limit", rl.maxPerDay)
                                .put("max_recipients", rl.maxRecipients)
                                .put("enabled", rl.enabled));
                    }
                    if (global == null)
                        global = new JSONObject().put("hourly", 50).put("daily", 500)
                                                 .put("max_recipients", 50).put("notSet", true);
                    // The maximum size is not in the database: it is a Postfix parameter,
                    // and it is read from there instead of keeping a copy of it that diverges.
                    int mb = org.daemoxcp.mail.system.MessageSizeLimit.readMegabytes();
                    global.put("max_size_mb", mb < 0 ? JSONObject.NULL : mb);
                    if (mb < 0) global.put("max_size_note", I18n.tr("server.rl.sizeUnreadable"));

                    response.put("success", true);
                    response.put("limits", limits);
                    response.put("global", global);
                    // Whether the limits apply, and how much each mailbox sent in the last hour and in the last 24
                    // (SendingLimits).
                    response.put("enforcement", org.daemoxcp.mail.system.SendingLimits.status());
                }
                case "POST" -> {
                    String body = readRequestBodyWithLimit(exchange);
                    if (body == null) {
                        sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge"));
                        return;
                    }
                    JSONObject req = body.isBlank() ? new JSONObject() : new JSONObject(body);
                    if (!validateCsrfForRequest(exchange, req)) {
                        sendCsrfError(exchange);
                        return;
                    }
                    String action = req.optString("action", "");

                    switch (action) {
                        case "save_mailbox" -> {
                            // A limit for a mailbox: the row (mailbox, id) is unique, so
                            // saving the same mailbox again updates it instead of duplicating it.
                            int mailboxId = req.optInt("mailbox_id", 0);
                            int hourly = req.optInt("hourly", 0);
                            int daily = req.optInt("daily", 0);
                            String problem = mailboxId < 1 ? I18n.tr("server.rl.chooseMailbox") : rateLimitProblem(hourly, daily);
                            if (problem != null) {
                                response.put("success", false).put("error", problem);
                                break;
                            }
                            int recipients = 50;
                            for (MailDatabase.RateLimit rl : Main.mailDatabase.getRateLimits())
                                if ("mailbox".equalsIgnoreCase(rl.targetType) && rl.targetId != null && rl.targetId == mailboxId)
                                    recipients = rl.maxRecipients;
                            boolean ok = Main.mailDatabase.saveRateLimit("mailbox", mailboxId, hourly, daily, recipients,
                                    req.optBoolean("enabled", true));
                            org.daemoxcp.mail.system.SendingLimits.invalidate();
                            response.put("success", ok);
                            if (ok) {
                                response.put("message", I18n.tr("server.rl.mailboxSaved"));
                                logAudit("RATELIMIT_MAILBOX", getClientIp(exchange), "Mailbox " + mailboxId
                                        + ": " + hourly + " per hour, " + daily + " per day");
                            } else {
                                response.put("error", I18n.tr("server.rl.saveFailed"));
                            }
                        }
                        case "save_global" -> {
                            int hourly = req.optInt("hourly", 0);
                            int daily = req.optInt("daily", 0);
                            int maxSize = req.optInt("max_size_mb", 0);
                            String problem = rateLimitProblem(hourly, daily);
                            if (problem != null) {
                                response.put("success", false).put("error", problem);
                                break;
                            }
                            // The count of recipients per message is not in this form:
                            // the one already saved is kept instead of being silently reset.
                            int recipients = 50;
                            for (MailDatabase.RateLimit rl : Main.mailDatabase.getRateLimits())
                                if ("global".equalsIgnoreCase(rl.targetType)) recipients = rl.maxRecipients;

                            boolean okDb = Main.mailDatabase.saveRateLimit("global", null, hourly, daily, recipients, true);
                            org.daemoxcp.mail.system.SendingLimits.invalidate();
                            response.put("success", okDb);
                            if (!okDb) {
                                response.put("error", I18n.tr("server.rl.saveFailed"));
                                break;
                            }
                            String note = I18n.tr("server.rl.globalSaved", Map.of("hourly", hourly, "daily", daily));
                            if (maxSize > 0) {
                                JSONObject dim = org.daemoxcp.mail.system.MessageSizeLimit.set(maxSize);
                                response.put("size", dim);
                                if (dim.optBoolean("success", false)) {
                                    note += " " + dim.optString("note", "");
                                } else {
                                    // The limits are saved, the size is not: we say exactly
                                    // this, instead of a generic "error" that would make people
                                    // believe that nothing was saved.
                                    response.put("success", false).put("error", note + " "
                                            + I18n.tr("server.rl.sizeNotChanged", Map.of("error", dim.optString("error", ""))));
                                    break;
                                }
                            }
                            response.put("message", note);
                            logAudit("RATELIMIT_GLOBAL", getClientIp(exchange), "Global limits: " + hourly
                                    + " per hour, " + daily + " per day" + (maxSize > 0 ? ", max size " + maxSize + " MB" : ""));
                        }
                        case "delete" -> {
                            int limitId = req.optInt("id", 0);
                            boolean ok = limitId > 0 && Main.mailDatabase.deleteRateLimit(limitId);
                            org.daemoxcp.mail.system.SendingLimits.invalidate();
                            response.put("success", ok);
                            if (ok) logAudit("RATELIMIT_DELETE", getClientIp(exchange), "Deleted rate limit " + limitId);
                            else response.put("error", I18n.tr("server.rl.deleteFailed"));
                        }
                        default -> response.put("success", false).put("error", I18n.tr("server.queue.unknownAction"));
                    }
                }
                default -> {
                    sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
                    return;
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Rate limit request failed", e);
            response = new JSONObject().put("success", false).put("error", I18n.tr("server.requestFailed"));
        }

        sendJsonResponse(exchange, response);
    }

    /**
     * What is wrong with an hourly and daily limit, or null. Zero does not mean "no limit":
     * it would mean that nothing goes out any more. And a daily limit lower than the hourly one
     * would make the hourly one unreachable.
     */
    static String rateLimitProblem(int hourly, int daily) {
        if (hourly < 1 || daily < 1 || hourly > 1_000_000 || daily > 10_000_000) return I18n.tr("server.rl.atLeastOne");
        if (daily < hourly) return I18n.tr("server.rl.dailyBelowHourly", Map.of("hourly", hourly, "daily", daily));
        return null;
    }

    // ============== RSPAMD TRAINING API ==============

    private void handleApiRspamd(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
            return;
        }

        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();

        try {
            switch (method) {
                case "GET" -> {
                    String action = extractParamFromQuery(exchange.getRequestURI().getQuery(), "action");

                    if ("stats".equals(action)) {
                        RspamdManager.RspamdStats stats = rspamdManager.getStatistics();
                        if (stats != null) {
                            response.put("success", true);
                            response.put("scanned", stats.scanned);
                            response.put("learned", stats.learned);
                            response.put("spam_count", stats.spamCount);
                            response.put("ham_count", stats.hamCount);
                            response.put("spam_percent", stats.spamPercent);
                            response.put("uptime", stats.uptime);
                            response.put("version", stats.version);
                        } else {
                            response.put("success", false);
                            response.put("error", I18n.tr("server.stats.rspamdUnreachable"));
                        }
                    } else if ("quarantine".equals(action)) {
                        JSONArray messages = new JSONArray();
                        for (RspamdManager.QuarantinedMessage msg : rspamdManager.getQuarantinedMessages(100)) {
                            JSONObject m = new JSONObject();
                            m.put("id", msg.id);
                            m.put("from", msg.from);
                            m.put("to", msg.to);
                            m.put("subject", msg.subject);
                            m.put("score", msg.score);
                            m.put("timestamp", msg.timestamp);
                            messages.put(m);
                        }
                        response.put("success", true);
                        response.put("messages", messages);
                    } else {
                        response.put("success", true);
                        response.put("running", rspamdManager.isRunning());
                    }
                }
                case "POST" -> {
                    String body = readRequestBodyWithLimit(exchange);
        if (body == null) {
            sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge"));
            return;
        }
                    JSONObject req = new JSONObject(body);
                    String action = req.optString("action", "");

                    int adminId = getSessionAdminId(exchange);

                    switch (action) {
                        case "train_spam" -> {
                            String content = req.optString("content", "");
                            RspamdManager.TrainingResult result = rspamdManager.trainSpam(content);
                            response.put("success", result.success);
                            response.put("message", result.message);
                            if (result.success) {
                                Main.mailDatabase.logRspamdTraining("manual", "spam", adminId);
                            }
                        }
                        case "train_ham" -> {
                            String content = req.optString("content", "");
                            RspamdManager.TrainingResult result = rspamdManager.trainHam(content);
                            response.put("success", result.success);
                            response.put("message", result.message);
                            if (result.success) {
                                Main.mailDatabase.logRspamdTraining("manual", "ham", adminId);
                            }
                        }
                        case "release" -> {
                            String messageId = req.optString("message_id", "");
                            boolean released = rspamdManager.releaseFromQuarantine(messageId);
                            response.put("success", released);
                        }
                        case "delete_quarantine" -> {
                            String messageId = req.optString("message_id", "");
                            boolean deleted = rspamdManager.deleteFromQuarantine(messageId);
                            response.put("success", deleted);
                        }
                        case "scan" -> {
                            String content = req.optString("content", "");
                            RspamdManager.ScanResult result = rspamdManager.scanMessage(content);
                            if (result != null) {
                                response.put("success", true);
                                response.put("is_spam", result.isSpam);
                                response.put("score", result.score);
                                response.put("required_score", result.requiredScore);
                                response.put("action", result.action);
                                response.put("symbols", new JSONArray(result.symbols));
                            } else {
                                response.put("success", false);
                                response.put("error", I18n.tr("server.scanFailed"));
                            }
                        }
                        default -> {
                            response.put("success", false);
                            response.put("error", I18n.tr("server.unknownAction"));
                        }
                    }
                }
                default -> {
                    sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
                    return;
                }
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", ErrorText.forPage("handleApiRspamd", e));
        }

        sendJsonResponse(exchange, response);
    }

    // ============== EMAIL STATISTICS API ==============

    private void handleApiStatistics(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
            return;
        }

        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();

        try {
            if ("GET".equals(method)) {
                // Only the periods the page offers: any number (negative, huge, not a
                // number) went straight into the query or into an exception shown as it was.
                String daysStr = extractParamFromQuery(exchange.getRequestURI().getQuery(), "days");
                int days = switch (daysStr == null ? "7" : daysStr) {
                    case "1" -> 1;
                    case "7" -> 7;
                    case "30" -> 30;
                    case "365" -> 365;
                    default -> -1;
                };
                if (days < 0) {
                    sendJsonError(exchange, 400, I18n.tr("server.stats.badPeriod"));
                    return;
                }

                // email_statistics has one row per day and per (mailbox, domain): the rows with neither
                // mailbox nor domain are the server total, those with only the domain the total
                // of the domain. They are summed here, once, instead of in the page.
                long[] totals = new long[5];
                java.util.TreeMap<String, long[]> daily = new java.util.TreeMap<>();
                java.util.TreeMap<String, long[]> perDomain = new java.util.TreeMap<>();
                for (MailDatabase.EmailStat stat : Main.mailDatabase.getEmailStatistics(days)) {
                    long[] v = {stat.sentCount, stat.receivedCount, stat.spamCount, stat.virusCount, stat.bouncedCount};
                    if (stat.mailboxId == null && stat.domainId == null) {
                        for (int i = 0; i < 5; i++) totals[i] += v[i];
                        long[] d = daily.computeIfAbsent(stat.statDate == null ? "" : stat.statDate.toString(), k -> new long[5]);
                        for (int i = 0; i < 5; i++) d[i] += v[i];
                    } else if (stat.mailboxId == null && stat.name != null) {
                        long[] d = perDomain.computeIfAbsent(stat.name, k -> new long[5]);
                        for (int i = 0; i < 5; i++) d[i] += v[i];
                    }
                }
                JSONArray dailyJson = new JSONArray();
                daily.forEach((date, v) -> dailyJson.put(statJson(v).put("date", date)));
                JSONArray domainsJson = new JSONArray();
                perDomain.forEach((domain, v) -> domainsJson.put(statJson(v).put("domain", domain)));

                response.put("success", true);
                response.put("days", days);
                response.put("totals", statJson(totals));
                response.put("daily", dailyJson);
                response.put("domains", domainsJson);
                response.put("spam_trained", Main.mailDatabase.getTrainingCount("spam", days));
                response.put("ham_trained", Main.mailDatabase.getTrainingCount("ham", days));
            } else {
                sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
                return;
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Statistics request failed", e);
            response = new JSONObject().put("success", false).put("error", I18n.tr("server.requestFailed"));
        }

        sendJsonResponse(exchange, response);
    }

    /** The five counts of email_statistics, in the order of handleApiStatistics. */
    private static JSONObject statJson(long[] v) {
        return new JSONObject().put("sent", v[0]).put("received", v[1]).put("spam", v[2]).put("virus", v[3]).put("bounced", v[4]);
    }

    // ============== THEME API ==============

    /** The theme preference of this session's admin, to write into the page: auto, light or dark, never anything else. */
    private String savedTheme(HttpExchange exchange) {
        try {
            String theme = Main.mailDatabase != null ? Main.mailDatabase.getAdminTheme(getSessionUsername(exchange)) : null;
            return "light".equals(theme) || "dark".equals(theme) ? theme : "auto";
        } catch (Exception e) {
            return "auto";
        }
    }

    private void handleApiTheme(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
            return;
        }

        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();

        try {
            String username = getSessionUsername(exchange);
            if (username == null || username.isEmpty()) {
                response.put("success", false);
                response.put("error", I18n.tr("server.userNotFound"));
                sendJsonResponse(exchange, response);
                return;
            }

            if ("GET".equals(method)) {
                // Get current theme preference
                String theme = Main.mailDatabase.getAdminTheme(username);
                response.put("success", true);
                response.put("theme", theme);
            } else if ("POST".equals(method)) {
                String body = readRequestBodyWithLimit(exchange);
                if (body == null) {
                    sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge"));
                    return;
                }
                JSONObject req = new JSONObject(body);
                // Changes a saved preference: same CSRF check as every other change.
                if (!validateCsrfForRequest(exchange, req)) {
                    sendCsrfError(exchange);
                    return;
                }

                String theme = req.optString("theme", "auto");
                boolean saved = Main.mailDatabase.setAdminTheme(username, theme);

                response.put("success", saved);
                if (saved) {
                    response.put("theme", theme);
                    response.put("message", I18n.tr("server.themeSaved"));
                } else {
                    response.put("error", I18n.tr("server.themeSaveFailed"));
                }
            } else {
                sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
                return;
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", ErrorText.forPage("handleApiTheme", e));
        }

        sendJsonResponse(exchange, response);
    }

    // ============== HOSTNAME CHANGE API ==============

    /**
     * API endpoint for changing the mail server hostname.
     *
     * GET  /api/hostname           - Returns current hostname state and consistency checks
     * POST /api/hostname           - Performs the hostname change with full orchestration
     *
     * The change process:
     *   1. Validate the new hostname format
     *   2. Read the old hostname from both SQLite and MySQL
     *   3. Update SQLite config.mail_hostname
     *   4. Update MySQL panel_settings.mail_hostname
     *   5. Update Postfix main.cf (myhostname, mydomain)
     *   6. Clean stale SSL/DNS settings in MySQL
     *   7. Reload Postfix, Dovecot, Nginx
     *   8. Return a checklist of what was done and what the user must do manually (DNS, SSL cert)
     */
    /**
     * GET: whether POP3 is on. POST {"enabled": true|false}: turns it on or off (Pop3.choose), then the
     * country rules, if active, are redone with the current ports. A choice that cannot be applied
     * leaves everything as it was.
     */
    /**
     * "Show password" (POST {id}): the copy of the password from the vault, only if it is still the
     * mailbox's password (compared with the current hash), because an old copy is not shown. The root
     * serves it: the web part does not have the private key of the vault.
     * Every reveal goes into the audit log.
     */
    private void handleApiMailboxPassword(HttpExchange exchange) throws IOException {
        if (!"POST".equals(exchange.getRequestMethod())) {
            exchange.getResponseHeaders().set("Allow", "POST");
            sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
            return;
        }
        JSONObject response = new JSONObject();
        try {
            String body = readRequestBodyWithLimit(exchange);
            if (body == null) {
                sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge"));
                return;
            }
            int mid = new JSONObject(body).optInt("id", 0);
            MailDatabase.Mailbox mbox = mid > 0 ? Main.mailDatabase.getMailbox(mid) : null;
            String ip = getClientIp(exchange);
            if (mbox == null) {
                response.put("success", false).put("error", I18n.tr(mid > 0 ? "server.mailbox.notFound" : "server.mailbox.missingId"));
            } else {
                String encrypted = Main.mailDatabase.getMailboxPasswordEncrypted(mid);
                String plain = null;
                if (encrypted == null || encrypted.isEmpty()) {
                    response.put("success", false).put("error", I18n.tr("server.mailbox.noCopy"));
                    logAudit("MAILBOX_PASSWORD_REVEAL_NOT_AVAILABLE", ip, "mailbox_id=" + mid + " email=" + mbox.email);
                } else {
                    try {
                        plain = org.daemoxcp.mail.security.PasswordVault.getInstance().decrypt(encrypted);
                    } catch (RuntimeException e) {
                        response.put("success", false).put("error", I18n.tr("server.mailbox.unreadableCopy"));
                        logAudit("MAILBOX_PASSWORD_REVEAL_FAILED", ip, "mailbox_id=" + mid + " email=" + mbox.email + " reason=decrypt");
                    }
                }
                if (plain != null && !Main.mailDatabase.mailboxPasswordMatches(mid, plain)) {
                    response.put("success", false).put("error", I18n.tr("server.mailbox.staleCopy"));
                    logAudit("MAILBOX_PASSWORD_REVEAL_FAILED", ip, "mailbox_id=" + mid + " email=" + mbox.email + " reason=stale");
                } else if (plain != null) {
                    response.put("success", true).put("password", plain);
                    logAudit("MAILBOX_PASSWORD_REVEALED", ip, "mailbox_id=" + mid + " email=" + mbox.email);
                }
            }
        } catch (org.json.JSONException e) {
            sendJsonError(exchange, 400, I18n.tr("server.badRequest"));
            return;
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Password reveal failed", e);
            response = new JSONObject().put("success", false).put("error", I18n.tr("server.requestFailed"));
        }
        sendJsonResponse(exchange, response);
    }

    private void handleApiPop3(HttpExchange exchange) throws IOException {
        JSONObject response = new JSONObject();
        try {
            String method = exchange.getRequestMethod();
            if ("GET".equals(method)) {
                response.put("success", true).put("enabled", org.daemoxcp.mail.system.Pop3.wanted());
            } else if ("POST".equals(method)) {
                JSONObject req = new JSONObject(readRequestBodyWithLimit(exchange));
                if (!(req.opt("enabled") instanceof Boolean on)) {
                    sendJsonError(exchange, 400, I18n.tr("server.badRequest"));
                    return;
                }
                String problem = org.daemoxcp.mail.system.Pop3.choose(on);
                if (problem == null) {
                    if (firewallManager != null) {
                        org.daemoxcp.mail.security.PfFirewallManager.FirewallState fw = firewallManager.getState();
                        if (fw.enabled && fw.mode != org.daemoxcp.mail.security.PfFirewallManager.Mode.DISABLED) firewallManager.applyConfiguration();
                    }
                    logAudit(on ? "POP3_ENABLED" : "POP3_DISABLED", getClientIp(exchange), "");
                    response.put("success", true).put("enabled", on);
                } else {
                    LOGGER.warning("[Pop3] the administrator's choice was not applied: " + problem);
                    logAudit("POP3_CHANGE_FAILED", getClientIp(exchange), on ? "on" : "off");
                    response.put("success", false).put("enabled", org.daemoxcp.mail.system.Pop3.wanted())
                            .put("error", I18n.tr("server.pop3.notApplied"));
                }
            } else {
                exchange.getResponseHeaders().set("Allow", "GET, POST");
                sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
                return;
            }
        } catch (Exception e) {
            LOGGER.warning("[Pop3] request failed: " + e.getMessage());
            response = new JSONObject().put("success", false).put("error", I18n.tr("server.requestFailed"));
        }
        sendJsonResponse(exchange, response);
    }

    /**
     * GET: the chosen family (or null) and the one in use. POST {"family": "both"|"ipv4"|"ipv6", "confirmed": bool}:
     * applies it (IpFamily.choose). Without confirmation, if there are warnings, it returns them and changes nothing.
     */
    private void handleApiIpFamily(HttpExchange exchange) throws IOException {
        JSONObject response = new JSONObject();
        try {
            String method = exchange.getRequestMethod();
            // Who chooses, as the panel sees it: with the separated panel it is the IP that the web part derived
            // (r18, behind Cloudflare the browser's one).
            String via = exchange.getRemoteAddress() == null || exchange.getRemoteAddress().getAddress() == null
                    ? null : exchange.getRemoteAddress().getAddress().getHostAddress();
            if ("GET".equals(method)) {
                org.daemoxcp.mail.system.IpFamily.Family c = org.daemoxcp.mail.system.IpFamily.chosen();
                response.put("success", true).put("chosen", c == null ? JSONObject.NULL : c.key)
                        .put("effective", org.daemoxcp.mail.system.IpFamily.effective().key);
                // ?family=...: the warnings that choice would give, without making it. The guide's checkbox "Mail
                // also comes in over IPv6" puts them in its single confirmation, before applying.
                String asked = extractParamFromQuery(exchange.getRequestURI().getQuery(), "family");
                if (asked != null) {
                    org.daemoxcp.mail.system.IpFamily.Family f = org.daemoxcp.mail.system.IpFamily.Family.of(asked);
                    if (f == null) {
                        sendJsonError(exchange, 400, I18n.tr("server.badRequest"));
                        return;
                    }
                    response.put("family", f.key).put("warnings", new JSONArray(org.daemoxcp.mail.system.IpFamily.preview(f, via)));
                }
            } else if ("POST".equals(method)) {
                JSONObject req = new JSONObject(readRequestBodyWithLimit(exchange));
                org.daemoxcp.mail.system.IpFamily.Family f = org.daemoxcp.mail.system.IpFamily.Family.of(req.optString("family", ""));
                if (f == null) {
                    sendJsonError(exchange, 400, I18n.tr("server.badRequest"));
                    return;
                }
                org.daemoxcp.mail.system.IpFamily.Outcome o = org.daemoxcp.mail.system.IpFamily.choose(f, req.optBoolean("confirmed", false), via);
                if (o.done()) {
                    if (firewallManager != null) {
                        org.daemoxcp.mail.security.PfFirewallManager.FirewallState fw = firewallManager.getState();
                        if (fw.enabled && fw.mode != org.daemoxcp.mail.security.PfFirewallManager.Mode.DISABLED) firewallManager.applyConfiguration();
                    }
                    logAudit("IP_FAMILY_CHANGED", getClientIp(exchange), f.key);
                }
                else if (!o.confirm()) {
                    LOGGER.warning("[IpFamily] the administrator's choice was not applied: " + o.error());
                    logAudit("IP_FAMILY_CHANGE_FAILED", getClientIp(exchange), f.key);
                }
                response.put("success", o.done()).put("confirm", o.confirm()).put("warnings", new JSONArray(o.warnings()))
                        .put("effective", org.daemoxcp.mail.system.IpFamily.effective().key);
                if (o.error() != null) response.put("error", o.error());
            } else {
                exchange.getResponseHeaders().set("Allow", "GET, POST");
                sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
                return;
            }
        } catch (Exception e) {
            LOGGER.warning("[IpFamily] request failed: " + e.getMessage());
            response = new JSONObject().put("success", false).put("error", I18n.tr("server.requestFailed"));
        }
        sendJsonResponse(exchange, response);
    }

    /**
     * /api/server-addresses: the server's addresses and the guide for switching between IPv4 and IPv6, IPv4
     * only, IPv6 only, in both directions (ServerAddresses, AddressGuide, HostRecords, ReverseDns). Permission
     * settings.manage: every change wants a recent confirmation (Access.CONFIRMED). SSH is never touched.
     *
     *  GET  ?goal=both|ipv4|ipv6|send6  the state, the facts and the guide's steps towards that goal
     *  POST {action: add-ipv6 (address, prefix, gateway) | remove-ipv6 | add-ipv4 | clean-ipv4 | confirm-firewall |
     *        dns (type A|AAAA, op add|remove) | web-aaaa | web-a}
     */
    private void handleApiServerAddresses(HttpExchange exchange) throws IOException {
        JSONObject response;
        try {
            String method = exchange.getRequestMethod();
            String via = exchange.getRemoteAddress() == null || exchange.getRemoteAddress().getAddress() == null
                    ? null : exchange.getRemoteAddress().getAddress().getHostAddress();
            org.daemoxcp.mail.system.IpFamily.Family viaFamily = org.daemoxcp.mail.system.IpFamily.connectionFamily(via);
            if ("GET".equals(method)) {
                org.daemoxcp.mail.system.AddressGuide.Goal goal =
                        org.daemoxcp.mail.system.AddressGuide.Goal.of(String.valueOf(extractParamFromQuery(exchange.getRequestURI().getQuery(), "goal")));
                response = addressGuideState(goal == null ? org.daemoxcp.mail.system.AddressGuide.Goal.BOTH : goal, viaFamily);
            } else if ("POST".equals(method)) {
                JSONObject req = new JSONObject(readRequestBodyWithLimit(exchange));
                response = addressGuideAction(req, viaFamily, getClientIp(exchange));
            } else {
                exchange.getResponseHeaders().set("Allow", "GET, POST");
                sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
                return;
            }
        } catch (Exception e) {
            LOGGER.warning("[ServerAddresses] request failed: " + e.getMessage());
            response = new JSONObject().put("success", false).put("error", I18n.tr("server.requestFailed"));
        }
        sendJsonResponse(exchange, response);
    }

    /** The administrator has looked at the provider's firewall and lets IPv6 in (UTC instant), empty if not. */
    private static final String ADDRESS_V6_FIREWALL = "address_v6_firewall_confirmed";

    /** The state of the addresses, the DNS facts and the guide's steps towards the goal. */
    private JSONObject addressGuideState(org.daemoxcp.mail.system.AddressGuide.Goal goal,
                                         org.daemoxcp.mail.system.IpFamily.Family viaFamily) throws Exception {
        org.daemoxcp.mail.system.ServerAddresses.State s = org.daemoxcp.mail.system.ServerAddresses.readForGuide();
        boolean v4Out = s.v4().present() && org.daemoxcp.mail.system.ServerAddresses.goesOut("ipv4");
        boolean v6Out = !s.v6().addresses().isEmpty() && s.v6().route() && org.daemoxcp.mail.system.ServerAddresses.goesOut("ipv6");
        String host = Main.mailDatabase == null ? "" : Main.mailDatabase.getSetting("mail_hostname", "");
        boolean hostOk = host != null && host.matches("[A-Za-z0-9.-]{1,253}") && host.contains(".");
        String ip4 = v4Out && dnsGenerator != null ? dnsGenerator.detectServerIp() : "";
        String ip6 = s.v6().addresses().isEmpty() ? "" : s.v6().addresses().get(0);
        Boolean a = hostOk && !ip4.isEmpty() ? org.daemoxcp.mail.security.HostRecords.published(host, "A", ip4)
                : hostOk ? org.daemoxcp.mail.security.HostRecords.hasAny(host, "A") : null;
        Boolean aaaa = hostOk && !ip6.isEmpty() ? org.daemoxcp.mail.security.HostRecords.published(host, "AAAA", ip6)
                : hostOk ? org.daemoxcp.mail.security.HostRecords.hasAny(host, "AAAA") : null;
        // The reverse DNS step is done when the PTR gives the mail name (givesName): the way back to the address
        // (A or AAAA) is the next step, the panel's, and mail in that family waits for both (AddressGuide).
        org.daemoxcp.mail.security.ReverseDns.Check ptr4Check = hostOk && !ip4.isEmpty() ? org.daemoxcp.mail.security.ReverseDns.check(ip4, host) : null;
        Boolean ptr4 = ptr4Check == null ? null : ptr4Check.givesName();
        org.daemoxcp.mail.security.ReverseDns.Check ptr6Check = hostOk && !ip6.isEmpty()
                ? org.daemoxcp.mail.security.ReverseDns.check(ip6, host) : null;
        Boolean ptr6 = ptr6Check == null ? null : ptr6Check.givesName();
        Boolean webAaaa = webNamesOn(true, ip4, ip6);
        Boolean webA = webNamesOn(false, ip4, ip6);
        org.daemoxcp.mail.system.IpFamily.Family mail = org.daemoxcp.mail.system.IpFamily.effective();
        boolean v6Firewall = Main.mailDatabase != null && !Main.mailDatabase.getSetting(ADDRESS_V6_FIREWALL, "").isEmpty();
        org.daemoxcp.mail.system.AddressGuide.Facts f = new org.daemoxcp.mail.system.AddressGuide.Facts(
                s.v4().present(), v4Out, !s.v4().rcLine().isEmpty(), !s.v6().addresses().isEmpty(), v6Out, v6Firewall,
                a, aaaa, ptr4, ptr6, webAaaa, webA, mail, viaFamily, s.sshOnV6());
        java.util.List<org.daemoxcp.mail.system.AddressGuide.Step> plan = org.daemoxcp.mail.system.AddressGuide.plan(f, goal);

        JSONArray steps = new JSONArray();
        for (org.daemoxcp.mail.system.AddressGuide.Step st : plan)
            steps.put(new JSONObject().put("id", st.id()).put("who", st.who()).put("status", st.status())
                    .put("blocked", st.blocked() == null ? JSONObject.NULL : I18n.tr(st.blocked())));
        JSONObject state = new JSONObject()
                .put("iface", s.iface() == null ? JSONObject.NULL : s.iface())
                .put("v4", new JSONObject().put("addresses", new JSONArray(s.v4().addresses())).put("route", s.v4().route()).put("internet", v4Out)
                        .put("public", ip4))
                .put("v6", new JSONObject().put("addresses", new JSONArray(s.v6().addresses())).put("route", s.v6().route()).put("internet", v6Out)
                        .put("hostPart", org.daemoxcp.mail.system.ServerAddresses.hostPartNow(s) == null ? JSONObject.NULL
                                : org.daemoxcp.mail.system.ServerAddresses.hostPartNow(s)));
        JSONObject dns = new JSONObject().put("host", hostOk ? host : JSONObject.NULL)
                .put("a", a == null ? JSONObject.NULL : a).put("aaaa", aaaa == null ? JSONObject.NULL : aaaa)
                .put("ptr4", ptr4 == null ? JSONObject.NULL : ptr4).put("ptr6", ptr6 == null ? JSONObject.NULL : ptr6)
                .put("ptr6Found", ptr6Check == null || ptr6Check.ptr() == null ? JSONObject.NULL : ptr6Check.ptr())
                .put("ptr4Found", ptr4Check == null || ptr4Check.ptr() == null ? JSONObject.NULL : ptr4Check.ptr())
                .put("webAaaa", webAaaa == null ? JSONObject.NULL : webAaaa)
                .put("webA", webA == null ? JSONObject.NULL : webA)
                .put("cloudflare", hostOk && org.daemoxcp.mail.security.HostRecords.canWrite(Main.mailDatabase, cloudflareManager, host));
        org.daemoxcp.mail.system.ServerAddresses.Suggestion sg = s.suggestion();
        // Recommended: the way mail already is if it also receives over IPv6 (or IPv6 only), otherwise
        // IPv6 outbound only.
        String recommended = mail == org.daemoxcp.mail.system.IpFamily.Family.BOTH ? "both"
                : mail == org.daemoxcp.mail.system.IpFamily.Family.IPV6 ? "ipv6" : "send6";
        return new JSONObject().put("success", true).put("goal", goal.key).put("recommended", recommended)
                .put("provider", org.daemoxcp.mail.system.ServerAddresses.provider())
                .put("reached", org.daemoxcp.mail.system.AddressGuide.reached(plan))
                .put("state", state).put("dns", dns).put("mail", mail.key)
                .put("via", viaFamily == null ? JSONObject.NULL : viaFamily.key).put("sshOnV6", s.sshOnV6())
                .put("suggestion", sg == null ? JSONObject.NULL
                        : new JSONObject().put("address", sg.address()).put("prefix", sg.prefix()).put("gateway", sg.gateway()).put("source", sg.source()))
                .put("steps", steps);
    }

    /**
     * Whether the names of the panel and the webmail, on Cloudflare, reach the server over IPv6 (v6 true:
     * AAAA towards the IPv6 and no A towards the IPv4) or over IPv4 (v6 false: A towards the IPv4 and no
     * AAAA towards the IPv6). With A and AAAA together Cloudflare uses IPv4. No names: TRUE (nothing to
     * do). No account that sees the zone: null.
     */
    private Boolean webNamesOn(boolean v6, String ip4, String ip6) {
        String want = v6 ? ip6 : ip4, other = v6 ? ip4 : ip6;
        if (want == null || want.isEmpty()) return null;
        java.util.List<String> names = webNames();
        if (names.isEmpty()) return true;
        for (String n : names) {
            org.daemoxcp.mail.security.HostRecords.Outcome has =
                    org.daemoxcp.mail.security.HostRecords.check(Main.mailDatabase, cloudflareManager, n, v6 ? "AAAA" : "A", want);
            if (has == null) return null;
            if (!has.ok()) return false;
            if (other != null && !other.isEmpty()) {
                org.daemoxcp.mail.security.HostRecords.Outcome also =
                        org.daemoxcp.mail.security.HostRecords.check(Main.mailDatabase, cloudflareManager, n, v6 ? "A" : "AAAA", other);
                if (also != null && also.ok()) return false;
            }
        }
        return true;
    }

    /** The panel and webmail names, from the configuration (those that go through Cloudflare with the proxy). */
    private java.util.List<String> webNames() {
        java.util.List<String> names = new java.util.ArrayList<>();
        if (Main.dbManager == null) return names;
        try (java.sql.ResultSet r = Main.dbManager.get_data_config()) {
            if (r.next()) {
                for (String col : java.util.List.of("panel_host", "roundcube_domain")) {
                    String h = r.getString(col);
                    if (h != null && h.trim().matches("[A-Za-z0-9.-]{3,253}") && h.contains(".") && !h.endsWith(".example.com"))
                        names.add(h.trim().toLowerCase(java.util.Locale.ROOT));
                }
            }
        } catch (Exception ignored) {
            // no configuration: no name
        }
        return names;
    }

    /** A step of the guide: who asks for it, what it does, and the log of the actions. */
    private JSONObject addressGuideAction(JSONObject req, org.daemoxcp.mail.system.IpFamily.Family viaFamily, String clientIp) throws Exception {
        String action = req.optString("action", "");
        org.daemoxcp.mail.system.ServerAddresses.Result r;
        switch (action) {
            case "add-ipv6" -> r = org.daemoxcp.mail.system.ServerAddresses.addIpv6(req.optString("address", "").trim(),
                    req.optInt("prefix", 64), req.optString("gateway", "").trim());
            case "remove-ipv6" -> {
                if (viaFamily == org.daemoxcp.mail.system.IpFamily.Family.IPV6)
                    return new JSONObject().put("success", false).put("error", I18n.tr("guide.blocked.viaV6"));
                r = org.daemoxcp.mail.system.ServerAddresses.removeIpv6();
            }
            case "add-ipv4" -> r = org.daemoxcp.mail.system.ServerAddresses.addIpv4();
            case "confirm-firewall" -> {
                // The provider's firewall cannot be seen from the server: the administrator confirms it, and it
                // stays as long as there is IPv6.
                if (Main.mailDatabase == null) return new JSONObject().put("success", false).put("error", I18n.tr("server.requestFailed"));
                Main.mailDatabase.setSetting(ADDRESS_V6_FIREWALL, java.time.Instant.now().toString());
                logAudit("SERVER_ADDRESSES_V6_FIREWALL_CONFIRMED", clientIp, "provider firewall lets IPv6 in");
                return new JSONObject().put("success", true).put("message", I18n.tr("server.addr.firewallConfirmed"));
            }
            case "clean-ipv4" -> r = org.daemoxcp.mail.system.ServerAddresses.cleanIpv4();
            case "dns" -> {
                return addressDnsAction(req.optString("type", ""), req.optString("op", ""), clientIp);
            }
            case "web-aaaa" -> {
                return addressWebNames(true, clientIp);
            }
            case "web-a" -> {
                return addressWebNames(false, clientIp);
            }
            default -> {
                return new JSONObject().put("success", false).put("error", I18n.tr("server.badRequest"));
            }
        }
        // Without IPv6 the firewall confirmation is no longer valid: if it comes back, it is looked at again.
        if (r.ok() && "remove-ipv6".equals(action) && Main.mailDatabase != null) Main.mailDatabase.setSetting(ADDRESS_V6_FIREWALL, "");
        logAudit(r.ok() ? "SERVER_ADDRESSES_" + action.toUpperCase(java.util.Locale.ROOT).replace('-', '_')
                : "SERVER_ADDRESSES_" + action.toUpperCase(java.util.Locale.ROOT).replace('-', '_') + "_FAILED", clientIp, r.journal());
        return new JSONObject().put("success", r.ok()).put(r.ok() ? "message" : "error", I18n.tr(r.message())).put("journal", r.journal());
    }

    /** The A or AAAA record of the mail name: create it (without proxy) or remove it. */
    private JSONObject addressDnsAction(String type, String op, String clientIp) {
        if (!"A".equals(type) && !"AAAA".equals(type)) return new JSONObject().put("success", false).put("error", I18n.tr("server.badRequest"));
        if (!"add".equals(op) && !"remove".equals(op)) return new JSONObject().put("success", false).put("error", I18n.tr("server.badRequest"));
        String host = Main.mailDatabase == null ? "" : Main.mailDatabase.getSetting("mail_hostname", "");
        org.daemoxcp.mail.system.ServerAddresses.State s = org.daemoxcp.mail.system.ServerAddresses.read();
        String ip = "A".equals(type) ? (dnsGenerator != null ? dnsGenerator.detectServerIp() : "")
                : s.v6().addresses().isEmpty() ? "" : s.v6().addresses().get(0);
        if ("remove".equals(op) && ip.isEmpty()) {
            // Without that address the server no longer knows which one it was: the record of the name that the
            // public DNS shows is removed.
            ip = org.daemoxcp.mail.security.FreshDns.query(type, host).split("\n")[0].trim();
        }
        if (ip.isEmpty()) return new JSONObject().put("success", false).put("error", I18n.tr("server.hr.noIp", Map.of("t", type)));
        org.daemoxcp.mail.security.HostRecords.Outcome o = "add".equals(op)
                ? org.daemoxcp.mail.security.HostRecords.ensure(Main.mailDatabase, cloudflareManager, host, type, ip, false)
                : org.daemoxcp.mail.security.HostRecords.remove(Main.mailDatabase, cloudflareManager, host, type, ip);
        logAudit("SERVER_ADDRESSES_DNS_" + type + "_" + op.toUpperCase(java.util.Locale.ROOT) + (o.ok() ? "" : "_FAILED"), clientIp, host + " " + ip);
        return new JSONObject().put("success", o.ok()).put(o.ok() ? "message" : "error", I18n.tr(o.key(), o.args()));
    }

    /**
     * The names of the panel and the webmail on Cloudflare (with the proxy) towards a single family: v6
     * true AAAA towards the IPv6 and away with the A records towards the IPv4 (for a server that will stay
     * IPv6 only), v6 false the opposite (to go back to IPv4 only). First the new record is created, then
     * the other one is removed: in between the names always work.
     */
    private JSONObject addressWebNames(boolean v6, String clientIp) {
        org.daemoxcp.mail.system.ServerAddresses.State s = org.daemoxcp.mail.system.ServerAddresses.read();
        String ip6 = s.v6().addresses().isEmpty() ? "" : s.v6().addresses().get(0);
        String ip4 = s.v4().present() && dnsGenerator != null ? dnsGenerator.detectServerIp() : "";
        String want = v6 ? ip6 : ip4, other = v6 ? ip4 : ip6;
        String type = v6 ? "AAAA" : "A", otherType = v6 ? "A" : "AAAA";
        if (want.isEmpty()) return new JSONObject().put("success", false).put("error", I18n.tr("server.hr.noIp", Map.of("t", type)));
        java.util.List<String> names = webNames();
        if (names.isEmpty()) return new JSONObject().put("success", false).put("error", I18n.tr("server.hr.noWebNames"));
        StringBuilder done = new StringBuilder();
        for (String n : names) {
            org.daemoxcp.mail.security.HostRecords.Outcome o =
                    org.daemoxcp.mail.security.HostRecords.ensure(Main.mailDatabase, cloudflareManager, n, type, want, true);
            if (o.ok() && !other.isEmpty())
                o = org.daemoxcp.mail.security.HostRecords.remove(Main.mailDatabase, cloudflareManager, n, otherType, other);
            if (!o.ok()) {
                logAudit("SERVER_ADDRESSES_WEB_" + type + "_FAILED", clientIp, n);
                return new JSONObject().put("success", false).put("error", I18n.tr(o.key(), o.args()));
            }
            done.append(done.length() == 0 ? "" : ", ").append(n);
        }
        logAudit("SERVER_ADDRESSES_WEB_" + type, clientIp, done.toString());
        return new JSONObject().put("success", true)
                .put("message", I18n.tr(v6 ? "server.hr.webDone" : "server.hr.webDoneV4", Map.of("names", done.toString())));
    }

    /**
     * /api/ssh-keys: root's SSH keys (RootSshKeys), permission ssh.manage. Adding and removing also want
     * a recent confirmation with a passkey or with a code (REAUTH_SECONDS), like the vault: a root
     * key is full access to the server. Only root's authorized_keys file: sshd_config, port 22 and
     * pf are not touched.
     *
     *  GET  the keys: type, fingerprint, comment, whether it has options written by hand
     *  POST {action: add, key} | {action: remove, fingerprint}
     */
    private void handleApiSshKeys(HttpExchange exchange) throws IOException {
        Optional<WebSessions.Current> session = currentSession(exchange);
        if (session.isEmpty()) {
            sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
            return;
        }
        AuthStore.Admin me = session.get().admin();
        String ip = getClientIp(exchange);
        JSONObject response = new JSONObject();
        try {
            String method = exchange.getRequestMethod();
            if ("GET".equals(method)) {
                JSONArray keys = new JSONArray();
                for (org.daemoxcp.mail.system.RootSshKeys.Key k : org.daemoxcp.mail.system.RootSshKeys.list())
                    keys.put(new JSONObject().put("type", k.type()).put("fingerprint", k.fingerprint())
                            .put("comment", k.comment()).put("has_options", !k.options().isEmpty()));
                sendJsonResponse(exchange, response.put("success", true).put("keys", keys));
                return;
            }
            if (!"POST".equals(method)) {
                exchange.getResponseHeaders().set("Allow", "GET, POST");
                sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
                return;
            }
            String body = readRequestBodyWithLimit(exchange);
            if (body == null) {
                sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge"));
                return;
            }
            JSONObject req = new JSONObject(body);
            String action = req.optString("action", "");
            if (!action.equals("add") && !action.equals("remove")) {
                sendJsonError(exchange, 400, I18n.tr("server.unknownAction"));
                return;
            }
            // The recent confirmation was already asked for by the route's filter (Access.needsConfirmation).
            org.daemoxcp.mail.system.RootSshKeys.Outcome o = action.equals("add")
                    ? org.daemoxcp.mail.system.RootSshKeys.add(req.optString("key", ""))
                    : org.daemoxcp.mail.system.RootSshKeys.remove(req.optString("fingerprint", ""));
            if (o.success()) {
                logAudit(action.equals("add") ? "SSH_KEY_ADDED" : "SSH_KEY_REMOVED", ip, "user=" + me.username()
                        + " fingerprint=" + o.key().fingerprint() + " type=" + o.key().type());
                response.put("success", true).put("fingerprint", o.key().fingerprint());
            } else {
                logAudit("SSH_KEY_REFUSED", ip, "user=" + me.username() + " action=" + action + " reason=" + o.errorKey());
                response.put("success", false).put("error", I18n.tr(o.errorKey(), o.params()));
            }
        } catch (java.io.IOException | org.json.JSONException e) {
            LOGGER.warning("[RootSshKeys] request failed: " + e.getMessage());
            response = new JSONObject().put("success", false).put("error", I18n.tr("server.ssh.failed"));
        }
        sendJsonResponse(exchange, response);
    }

    private void handleApiHostname(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
            return;
        }

        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();

        try {
            if ("GET".equals(method)) {
                // Return current hostname state and consistency info
                String sqliteHostname = Main.dbManager != null ? Main.dbManager.getMailHostname() : "";
                if (sqliteHostname == null) sqliteHostname = "";

                String mysqlHostname = "";
                if (Main.mailDatabase != null && Main.mysqlAvailable) {
                    mysqlHostname = Main.mailDatabase.getSetting("mail_hostname", "");
                }

                // Read Postfix myhostname from main.cf
                String postfixHostname = readPostfixHostname();

                // Read current SSL certificate CN
                String sslHostname = "";
                if (Main.mailDatabase != null && Main.mysqlAvailable) {
                    sslHostname = Main.mailDatabase.getSetting("ssl_hostname", "");
                }

                // Detect server IP
                String serverIp = dnsGenerator != null ? dnsGenerator.detectServerIp() : "";

                // Consistency check
                boolean allConsistent = !sqliteHostname.isEmpty()
                        && sqliteHostname.equals(mysqlHostname)
                        && (postfixHostname.isEmpty() || sqliteHostname.equals(postfixHostname));

                response.put("success", true);
                response.put("sqlite_hostname", sqliteHostname);
                response.put("mysql_hostname", mysqlHostname);
                response.put("postfix_hostname", postfixHostname);
                response.put("ssl_hostname", sslHostname);
                response.put("server_ip", serverIp);
                response.put("consistent", allConsistent);

                // Current SSL cert info
                if (acmeManager != null) {
                    AcmeManager.CertificateInfo certInfo = acmeManager.getCertificateInfo();
                    if (certInfo != null && certInfo.installed) {
                        response.put("ssl_cn", certInfo.commonName);
                        response.put("ssl_self_signed", acmeManager.isSelfSigned());
                        response.put("ssl_days_until_expiry", certInfo.daysUntilExpiry);
                    }
                }

            } else if ("POST".equals(method)) {
                String body = readRequestBodyWithLimit(exchange);
                if (body == null) {
                    sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge"));
                    return;
                }
                JSONObject req = new JSONObject(body);

                // Validate CSRF token
                if (!validateCsrfForRequest(exchange, req)) {
                    sendCsrfError(exchange);
                    return;
                }

                String action = req.optString("action", "");

                if ("change".equals(action)) {
                    // Full hostname change orchestration
                    String newHostname = req.optString("hostname", "").trim().toLowerCase();

                    // Validate hostname format
                    if (newHostname.isEmpty() || !newHostname.contains(".") || newHostname.length() > 253) {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.hostname.invalid"));
                        sendJsonResponse(exchange, response);
                        return;
                    }
                    // Must match domain pattern (allow subdomain.domain.tld)
                    if (!newHostname.matches("^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$")) {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.hostname.badChars"));
                        sendJsonResponse(exchange, response);
                        return;
                    }

                    // Get old hostname
                    String oldHostname = Main.dbManager != null ? Main.dbManager.getMailHostname() : "";
                    if (oldHostname == null) oldHostname = "";

                    JSONArray steps = new JSONArray();

                    // Step 1: Update SQLite
                    boolean sqliteOk = false;
                    if (Main.dbManager != null) {
                        sqliteOk = Main.dbManager.setMailHostname(newHostname);
                    }
                    steps.put(new JSONObject()
                            .put("step", "SQLite config.mail_hostname")
                            .put("success", sqliteOk)
                            .put("detail", sqliteOk ? oldHostname + " -> " + newHostname : I18n.tr("server.sqliteUpdateFailed")));

                    // Step 2: Update MySQL
                    boolean mysqlOk = false;
                    if (Main.mailDatabase != null && Main.mysqlAvailable) {
                        try {
                            Main.mailDatabase.setSetting("mail_hostname", newHostname);
                            mysqlOk = true;
                        } catch (Exception e) {
                            // setSetting does not throw, but handle just in case
                        }
                    }
                    steps.put(new JSONObject()
                            .put("step", "MySQL panel_settings.mail_hostname")
                            .put("success", mysqlOk)
                            .put("detail", mysqlOk ? oldHostname + " -> " + newHostname : I18n.tr("server.hostname.mysqlFailed")));

                    // Step 3: Update Postfix main.cf
                    boolean postfixOk = updatePostfixHostname(newHostname);
                    steps.put(new JSONObject()
                            .put("step", "Postfix main.cf (myhostname)")
                            .put("success", postfixOk)
                            .put("detail", postfixOk ? I18n.tr("server.hostname.postfixUpdated", Map.of("name", newHostname)) : I18n.tr("server.hostname.fileWriteFailed")));

                    // Step 4: Clean stale MySQL settings
                    boolean cleanOk = false;
                    if (Main.mailDatabase != null && Main.mysqlAvailable) {
                        try {
                            Main.mailDatabase.deleteSetting("ssl_hostname");
                            Main.mailDatabase.deleteSetting("ssl_domain");
                            Main.mailDatabase.deleteSetting("dns_challenge_hostname");
                            cleanOk = true;
                        } catch (Exception e) {
                            // best effort
                        }
                    }
                    steps.put(new JSONObject()
                            .put("step", I18n.tr("server.hostname.stepCleanup"))
                            .put("success", cleanOk)
                            .put("detail", cleanOk ? I18n.tr("server.hostname.cleaned") : I18n.tr("server.hostname.cleanFailed")));

                    // Step 5: Reload services
                    boolean postfixReload = executeServiceCommand("postfix", "reload");
                    steps.put(new JSONObject()
                            .put("step", "Reload Postfix")
                            .put("success", postfixReload)
                            .put("detail", postfixReload ? I18n.tr("server.hostname.reloaded", Map.of("service", "Postfix")) : I18n.tr("server.hostname.reloadFailed", Map.of("service", "Postfix"))));

                    boolean dovecotReload = executeServiceCommand("dovecot", "reload");
                    steps.put(new JSONObject()
                            .put("step", "Reload Dovecot")
                            .put("success", dovecotReload)
                            .put("detail", dovecotReload ? I18n.tr("server.hostname.reloaded", Map.of("service", "Dovecot")) : I18n.tr("server.hostname.reloadFailed", Map.of("service", "Dovecot"))));

                    boolean nginxReload = executeServiceCommand("nginx", "reload");
                    steps.put(new JSONObject()
                            .put("step", "Reload Nginx")
                            .put("success", nginxReload)
                            .put("detail", nginxReload ? I18n.tr("server.hostname.reloaded", Map.of("service", "Nginx")) : I18n.tr("server.nginxReloadFailed")));

                    // Determine overall success (core steps must succeed)
                    boolean overallSuccess = sqliteOk && mysqlOk;

                    // Build manual actions needed
                    String domain = newHostname.contains(".") ? newHostname.substring(newHostname.indexOf('.') + 1) : newHostname;
                    JSONArray manualActions = new JSONArray();

                    manualActions.put(new JSONObject()
                            .put("action", I18n.tr("server.hostname.actA"))
                            .put("detail", I18n.tr("server.hostname.actADetail", Map.of("name", newHostname)))
                            .put("type", "dns"));
                    manualActions.put(new JSONObject()
                            .put("action", I18n.tr("server.hostname.actMx"))
                            .put("detail", I18n.tr("server.hostname.actMxDetail", Map.of("domain", domain, "name", newHostname)))
                            .put("type", "dns"));
                    manualActions.put(new JSONObject()
                            .put("action", I18n.tr("server.hostname.actPtr"))
                            .put("detail", I18n.tr("server.hostname.actPtrDetail", Map.of("name", newHostname)))
                            .put("type", "dns"));
                    manualActions.put(new JSONObject()
                            .put("action", I18n.tr("server.hostname.actAutoconfig"))
                            .put("detail", I18n.tr("server.hostname.actAutoconfigDetail", Map.of("domain", domain, "name", newHostname)))
                            .put("type", "dns"));
                    manualActions.put(new JSONObject()
                            .put("action", I18n.tr("server.hostname.actCert"))
                            .put("detail", oldHostname.isEmpty() ? I18n.tr("server.hostname.actCertDetail", Map.of("name", newHostname)) : I18n.tr("server.hostname.actCertDetailOld", Map.of("name", newHostname, "old", oldHostname)))
                            .put("type", "ssl"));
                    manualActions.put(new JSONObject()
                            .put("action", I18n.tr("server.hostname.actVerify"))
                            .put("detail", I18n.tr("server.hostname.actVerifyDetail"))
                            .put("type", "verify"));

                    // Roundcube domain reminder
                    String rcDomain = Main.dbManager != null ? Main.dbManager.getRoundcubeDomain() : "";
                    if (rcDomain != null && !rcDomain.isEmpty()) {
                        manualActions.put(new JSONObject()
                                .put("action", I18n.tr("server.hostname.actRc"))
                                .put("detail", I18n.tr("server.hostname.actRcDetail", Map.of("domain", rcDomain)))
                                .put("type", "roundcube"));
                    }

                    response.put("success", overallSuccess);
                    response.put("steps", steps);
                    response.put("manual_actions", manualActions);
                    response.put("old_hostname", oldHostname);
                    response.put("new_hostname", newHostname);

                    // Audit log
                    logAudit("HOSTNAME_CHANGED", getClientIp(exchange),
                            "Hostname changed: " + oldHostname + " -> " + newHostname);

                } else if ("check_dns".equals(action)) {
                    // Quick DNS consistency check for the current hostname
                    String hostname = req.optString("hostname", "");
                    if (hostname.isEmpty()) {
                        hostname = Main.dbManager != null ? Main.dbManager.getMailHostname() : "";
                    }
                    if (hostname == null || hostname.isEmpty()) {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.hostname.none"));
                        sendJsonResponse(exchange, response);
                        return;
                    }

                    JSONArray checks = new JSONArray();

                    // A and AAAA according to the family chosen in the Settings (IpFamily): with IPv6 only the A is
                    // not needed; with both, the AAAA is checked when the server has a public IPv6, with IPv6 only
                    // always.
                    org.daemoxcp.mail.system.IpFamily.Family family = org.daemoxcp.mail.system.IpFamily.effective();
                    boolean aOk = true, aaaaOk = true;
                    String serverIp = "";
                    if (family.v4()) {
                        String aResult = digRecord(hostname, "A");
                        serverIp = dnsGenerator != null ? dnsGenerator.detectServerIp() : "";
                        aOk = !serverIp.isEmpty() && DnsRecordsGenerator.containsAddress(aResult, serverIp);
                        checks.put(new JSONObject()
                                .put("type", "A").put("name", hostname)
                                .put("passed", aOk)
                                .put("current", aResult.isEmpty() ? I18n.tr("server.dns.notFound") : aResult)
                                .put("expected", serverIp.isEmpty() ? I18n.tr("server.dns.serverIp") : serverIp));
                    }
                    String serverIp6 = family.v6() && dnsGenerator != null ? dnsGenerator.detectServerIpv6() : "";
                    if (family == org.daemoxcp.mail.system.IpFamily.Family.IPV6 || !serverIp6.isEmpty()) {
                        String aaaaResult = digRecord(hostname, "AAAA");
                        aaaaOk = !serverIp6.isEmpty() && DnsRecordsGenerator.containsAddress(aaaaResult, serverIp6);
                        checks.put(new JSONObject()
                                .put("type", "AAAA").put("name", hostname)
                                .put("passed", aaaaOk)
                                .put("current", aaaaResult.isEmpty() ? I18n.tr("server.dns.notFound") : aaaaResult)
                                .put("expected", serverIp6.isEmpty() ? I18n.tr("server.dns.serverIp") : serverIp6));
                    }

                    // Check MX record
                    String domain = hostname.contains(".") ? hostname.substring(hostname.indexOf('.') + 1) : hostname;
                    String mxResult = digRecord(domain, "MX");
                    boolean mxOk = !mxResult.isEmpty() && mxResult.toLowerCase().contains(hostname.toLowerCase());
                    checks.put(new JSONObject()
                            .put("type", "MX").put("name", domain)
                            .put("passed", mxOk)
                            .put("current", mxResult.isEmpty() ? I18n.tr("server.dns.notFound") : mxResult)
                            .put("expected", "10 " + hostname + "."));

                    // The reverse DNS of every address the server uses: IPv4 and/or IPv6, as above.
                    boolean ptrOk = true;
                    java.util.List<String> ptrIps = new java.util.ArrayList<>();
                    if (family.v4()) ptrIps.add(serverIp);
                    if (family == org.daemoxcp.mail.system.IpFamily.Family.IPV6 || !serverIp6.isEmpty()) ptrIps.add(serverIp6);
                    for (String ip : ptrIps) {
                        String ptrResult = ip.isEmpty() ? "" : digPtrRecord(ip);
                        boolean ok = !ptrResult.isEmpty() && ptrResult.toLowerCase().contains(hostname.toLowerCase());
                        ptrOk &= ok;
                        checks.put(new JSONObject()
                                .put("type", "PTR").put("name", ip.isEmpty() ? I18n.tr("server.dns.serverIp") : ip)
                                .put("passed", ok)
                                .put("current", ptrResult.isEmpty() ? I18n.tr("server.dns.notFound") : ptrResult)
                                .put("expected", hostname + "."));
                    }

                    response.put("success", true);
                    response.put("hostname", hostname);
                    response.put("checks", checks);
                    response.put("all_passed", aOk && aaaaOk && mxOk && ptrOk);

                } else {
                    response.put("success", false);
                    response.put("error", I18n.tr("server.hostname.badAction"));
                }

            } else {
                sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
                return;
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", ErrorText.forPage("handleApiHostname", e));
        }

        sendJsonResponse(exchange, response);
    }

    /**
     * Handle Roundcube domain GET (read) and POST (change)
     */
    private void handleApiRoundcubeDomain(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, I18n.tr("server.unauthorized"));
            return;
        }

        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();

        try {
            if ("GET".equals(method)) {
                // Return current Roundcube domain + DNS check
                String rcDomain = Main.dbManager != null ? Main.dbManager.getRoundcubeDomain() : "";
                if (rcDomain == null) rcDomain = "";
                String rcPort = Main.dbManager != null ? Main.dbManager.getRoundcubePort() : "8443";
                if (rcPort == null) rcPort = "8443";

                String serverIp = dnsGenerator != null ? dnsGenerator.detectServerIp() : "";

                // Check DNS for Roundcube domain
                // For webmail, Cloudflare proxy (orange cloud) is perfectly fine
                boolean dnsOk = false;
                boolean dnsProxied = false;
                String dnsResult = "";
                if (!rcDomain.isEmpty()) {
                    dnsResult = digRecord(rcDomain, "A");
                    if (!dnsResult.isEmpty()) {
                        if (!serverIp.isEmpty() && dnsResult.contains(serverIp)) {
                            dnsOk = true;  // Direct IP match
                        } else {
                            // Check if it resolves to known CDN/proxy IPs (Cloudflare etc.)
                            // If it resolves to ANY IP, the domain is configured (might be proxied)
                            dnsProxied = true;
                            dnsOk = true;
                        }
                    }
                }

                // Read actual SSL paths from nginx.conf
                String[] nginxSslPaths = readNginxRoundcubeSslPaths();
                String certPath = nginxSslPaths[0].isEmpty() ? "/usr/local/etc/ssl/mail/fullchain.pem" : nginxSslPaths[0];
                String keyPath = nginxSslPaths[1].isEmpty() ? "/usr/local/etc/ssl/mail/privkey.pem" : nginxSslPaths[1];

                // Read SSL file contents to show in textarea
                String certContent = "";
                String keyContent = "";
                String chainContent = "";
                try {
                    if (Files.exists(Path.of(certPath))) certContent = Files.readString(Path.of(certPath));
                } catch (Exception ignored) {}
                try {
                    if (Files.exists(Path.of(keyPath))) keyContent = Files.readString(Path.of(keyPath));
                } catch (Exception ignored) {}
                // Chain: check if separate chain file exists in same dir
                String rcSslChain = Main.dbManager != null ? Main.dbManager.getRoundcubeSslChain() : "";
                if (rcSslChain != null && !rcSslChain.isEmpty()) {
                    try {
                        if (Files.exists(Path.of(rcSslChain))) chainContent = Files.readString(Path.of(rcSslChain));
                    } catch (Exception ignored) {}
                }

                response.put("success", true);
                response.put("domain", rcDomain);
                response.put("port", rcPort);
                response.put("server_ip", serverIp);
                response.put("dns_result", dnsResult.isEmpty() ? I18n.tr("server.dns.notFound") : dnsResult);
                response.put("dns_ok", dnsOk);
                response.put("dns_proxied", dnsProxied);
                response.put("nginx_ssl_cert", certPath);
                response.put("nginx_ssl_key", keyPath);
                response.put("ssl_cert_content", certContent);
                response.put("ssl_key_content", keyContent);
                response.put("ssl_chain_content", chainContent);

            } else if ("POST".equals(method)) {
                String body = readRequestBodyWithLimit(exchange);
                if (body == null) {
                    sendJsonError(exchange, 413, I18n.tr("server.requestTooLarge"));
                    return;
                }
                JSONObject req = new JSONObject(body);

                // Validate CSRF token
                if (!validateCsrfForRequest(exchange, req)) {
                    sendCsrfError(exchange);
                    return;
                }

                String action = req.optString("action", "");

                if ("change".equals(action)) {
                    String newDomain = req.optString("domain", "").trim().toLowerCase();

                    // Validate domain format
                    if (newDomain.isEmpty() || !newDomain.contains(".") || newDomain.length() > 253) {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.rcdomain.invalid"));
                        sendJsonResponse(exchange, response);
                        return;
                    }
                    if (!newDomain.matches("^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$")) {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.rcdomain.badChars"));
                        sendJsonResponse(exchange, response);
                        return;
                    }

                    // Get old domain
                    String oldDomain = Main.dbManager != null ? Main.dbManager.getRoundcubeDomain() : "";
                    if (oldDomain == null) oldDomain = "";

                    JSONArray steps = new JSONArray();

                    // Read current settings before updating
                    String currentPort = Main.dbManager != null ? Main.dbManager.getRoundcubePort() : "8443";
                    String currentCert = Main.dbManager != null ? Main.dbManager.getRoundcubeSslCert() : "";
                    String currentKey = Main.dbManager != null ? Main.dbManager.getRoundcubeSslKey() : "";
                    String currentChain = Main.dbManager != null ? Main.dbManager.getRoundcubeSslChain() : "";

                    // Step 1: Update SQLite roundcube_domain
                    boolean sqliteOk = false;
                    if (Main.dbManager != null) {
                        sqliteOk = Main.dbManager.updateRoundcubeConfig(
                            newDomain,
                            currentPort != null ? currentPort : "8443",
                            currentCert != null ? currentCert : "",
                            currentKey != null ? currentKey : "",
                            currentChain != null ? currentChain : ""
                        );
                    }
                    steps.put(new JSONObject()
                            .put("step", "SQLite config.roundcube_domain")
                            .put("success", sqliteOk)
                            .put("detail", sqliteOk ? oldDomain + " -> " + newDomain : I18n.tr("server.sqliteUpdateFailed")));

                    // Step 2: Regenerate entire nginx.conf with new domain
                    String rcCert = currentCert != null && !currentCert.isEmpty() ? currentCert : "/usr/local/etc/ssl/mail/fullchain.pem";
                    String rcKey = currentKey != null && !currentKey.isEmpty() ? currentKey : "/usr/local/etc/ssl/mail/privkey.pem";
                    boolean nginxOk = regenerateNginxRoundcubeConfig(newDomain, currentPort, rcCert, rcKey);
                    steps.put(new JSONObject()
                            .put("step", I18n.tr("server.rcdomain.stepNginx"))
                            .put("success", nginxOk)
                            .put("detail", nginxOk ? I18n.tr("server.rcdomain.nginxOnly", Map.of("domain", newDomain)) : I18n.tr("server.nginxConfWriteFailed")));

                    // Step 3: Reload Nginx
                    boolean nginxReload = executeServiceCommand("nginx", "reload");
                    steps.put(new JSONObject()
                            .put("step", "Reload Nginx")
                            .put("success", nginxReload)
                            .put("detail", nginxReload ? I18n.tr("server.hostname.reloaded", Map.of("service", "Nginx")) : I18n.tr("server.nginxReloadFailed")));

                    // Step 4: Refresh SSO manager URL
                    boolean ssoOk = false;
                    if (ssoManager != null) {
                        try {
                            String rcPort = currentPort != null ? currentPort : "8443";
                            String newUrl = "https://" + newDomain;
                            if (rcPort != null && !rcPort.isEmpty() && !rcPort.equals("443")) {
                                newUrl += ":" + rcPort;
                            }
                            ssoManager.setRoundcubeUrl(newUrl);
                            ssoOk = true;
                        } catch (Exception e) {
                            // best effort
                        }
                    }
                    steps.put(new JSONObject()
                            .put("step", I18n.tr("server.rcdomain.stepSso"))
                            .put("success", ssoOk)
                            .put("detail", ssoOk ? I18n.tr("server.rcdomain.ssoUpdated", Map.of("domain", newDomain)) : I18n.tr("server.rcdomain.ssoFailed")));

                    boolean overallSuccess = sqliteOk;

                    // Manual actions
                    JSONArray manualActions = new JSONArray();
                    manualActions.put(new JSONObject()
                            .put("action", I18n.tr("server.rcdomain.actA"))
                            .put("detail", I18n.tr("server.hostname.actADetail", Map.of("name", newDomain)))
                            .put("type", "dns"));
                    manualActions.put(new JSONObject()
                            .put("action", I18n.tr("server.rcdomain.actCert"))
                            .put("detail", I18n.tr("server.rcdomain.actCertDetail", Map.of("domain", newDomain)))
                            .put("type", "ssl"));

                    response.put("success", overallSuccess);
                    response.put("steps", steps);
                    response.put("manual_actions", manualActions);
                    response.put("old_domain", oldDomain);
                    response.put("new_domain", newDomain);

                    // Audit log
                    logAudit("ROUNDCUBE_DOMAIN_CHANGED", getClientIp(exchange),
                            "Roundcube domain changed: " + oldDomain + " -> " + newDomain);

                } else if ("update_ssl".equals(action)) {
                    // Receive PEM content, save to disk, update nginx
                    String certContent = req.optString("ssl_cert", "").trim();
                    String keyContent = req.optString("ssl_key", "").trim();
                    String chainContent = req.optString("ssl_chain", "").trim();

                    // Validate PEM format
                    if (!certContent.isEmpty() && !certContent.contains("BEGIN")) {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.rcdomain.certPem"));
                        sendJsonResponse(exchange, response);
                        return;
                    }
                    if (!keyContent.isEmpty() && !keyContent.contains("BEGIN")) {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.rcdomain.keyPem"));
                        sendJsonResponse(exchange, response);
                        return;
                    }

                    // The same check as menu option 3 (PemTls): the certificate can be read, is valid now, covers the
                    // webmail's name, and the key really is its own. Before, files and database were saved even with
                    // a wrong key, and only nginx noticed (live test on the VM, 2026-11-20): the database was left
                    // with certificates that do not work. Nothing is written until the check passes.
                    if (!certContent.isEmpty() || !keyContent.isEmpty()) {
                        String rcDomain = Main.dbManager != null ? Main.dbManager.getRoundcubeDomain() : null;
                        org.daemoxcp.mail.security.PemTls.Check pair = org.daemoxcp.mail.security.PemTls.check("webmail",
                                rcDomain == null ? "" : rcDomain,
                                chainContent.isEmpty() ? certContent : certContent + "\n" + chainContent, keyContent, java.time.Instant.now());
                        if (!pair.ok()) {
                            response.put("success", false);
                            response.put("error", String.join(" ", pair.errors()));
                            sendJsonResponse(exchange, response);
                            return;
                        }
                    }

                    JSONArray steps = new JSONArray();

                    // Determine file paths
                    String sslDir = "/usr/local/etc/ssl/roundcube";
                    String certPath, keyPath, chainPath;

                    if (certContent.isEmpty() && keyContent.isEmpty()) {
                        // Use mail server certs
                        certPath = "/usr/local/etc/ssl/mail/fullchain.pem";
                        keyPath = "/usr/local/etc/ssl/mail/privkey.pem";
                        chainPath = "";
                        steps.put(new JSONObject()
                                .put("step", I18n.tr("server.rcdomain.stepUseMailCert"))
                                .put("success", true)
                                .put("detail", I18n.tr("server.rcdomain.mailCertFiles")));
                    } else {
                        // Save PEM content to /usr/local/etc/ssl/roundcube/
                        certPath = sslDir + "/fullchain.pem";
                        keyPath = sslDir + "/privkey.pem";
                        chainPath = chainContent.isEmpty() ? "" : sslDir + "/chain.pem";

                        try {
                            Files.createDirectories(Path.of(sslDir));

                            // If chain provided, concatenate cert + chain into fullchain.pem
                            // This is how fullchain works: cert first, then intermediate CA(s)
                            String fullchainContent = certContent;
                            if (!chainContent.isEmpty()) {
                                fullchainContent = certContent + "\n" + chainContent;
                                // Also save chain separately for reference
                                Files.writeString(Path.of(chainPath), chainContent);
                            }

                            Files.writeString(Path.of(certPath), fullchainContent);
                            Files.writeString(Path.of(keyPath), keyContent);

                            // Secure permissions
                            // TODO: migrate to Shell.run when touched
                            new ProcessBuilder("chmod", "600", keyPath).start().waitFor();
                            // TODO: migrate to Shell.run when touched
                            new ProcessBuilder("chmod", "644", certPath).start().waitFor();

                            String detail = I18n.tr("server.rcdomain.savedIn", Map.of("dir", sslDir + "/"));
                            if (!chainContent.isEmpty()) {
                                detail += " " + I18n.tr("server.rcdomain.chainIncluded");
                            }

                            steps.put(new JSONObject()
                                    .put("step", I18n.tr("server.rcdomain.stepSaved"))
                                    .put("success", true)
                                    .put("detail", detail));
                        } catch (Exception e) {
                            steps.put(new JSONObject()
                                    .put("step", I18n.tr("server.rcdomain.stepSaving"))
                                    .put("success", false)
                                    .put("detail", I18n.tr("server.errorWith", Map.of("error", ErrorText.detail("handleApiRoundcubeDomain", e)))));
                            response.put("success", false);
                            response.put("steps", steps);
                            sendJsonResponse(exchange, response);
                            return;
                        }
                    }

                    // Step 2: Update SQLite (preserve domain and port, update SSL paths)
                    boolean sqliteOk = false;
                    if (Main.dbManager != null) {
                        String currentDomain = Main.dbManager.getRoundcubeDomain();
                        String currentPort = Main.dbManager.getRoundcubePort();
                        sqliteOk = Main.dbManager.updateRoundcubeConfig(
                            currentDomain != null ? currentDomain : "",
                            currentPort != null ? currentPort : "8443",
                            certPath, keyPath, chainPath
                        );
                    }
                    steps.put(new JSONObject()
                            .put("step", I18n.tr("server.rcdomain.stepSqlite"))
                            .put("success", sqliteOk)
                            .put("detail", sqliteOk ? I18n.tr("server.rcdomain.pathsSaved") : I18n.tr("server.sqliteUpdateFailed")));

                    // Step 3: Regenerate nginx.conf
                    String currentDomainForSsl = Main.dbManager != null ? Main.dbManager.getRoundcubeDomain() : "";
                    String currentPortForSsl = Main.dbManager != null ? Main.dbManager.getRoundcubePort() : "8443";
                    boolean nginxOk = regenerateNginxRoundcubeConfig(
                        currentDomainForSsl != null ? currentDomainForSsl : "",
                        currentPortForSsl != null ? currentPortForSsl : "8443",
                        certPath, keyPath
                    );
                    steps.put(new JSONObject()
                            .put("step", I18n.tr("server.rcdomain.stepNginxRegen"))
                            .put("success", nginxOk)
                            .put("detail", nginxOk ? I18n.tr("server.rcdomain.nginxNewCerts") : I18n.tr("server.nginxConfWriteFailed")));

                    // Step 4: Reload Nginx
                    boolean nginxReload = executeServiceCommand("nginx", "reload");
                    steps.put(new JSONObject()
                            .put("step", "Reload Nginx")
                            .put("success", nginxReload)
                            .put("detail", nginxReload ? I18n.tr("server.hostname.reloaded", Map.of("service", "Nginx")) : I18n.tr("server.nginxReloadFailed")));

                    response.put("success", sqliteOk && nginxOk);
                    response.put("steps", steps);

                    logAudit("ROUNDCUBE_SSL_UPDATED", getClientIp(exchange),
                            "Roundcube SSL updated: cert=" + certPath + " key=" + keyPath);

                } else if ("check_dns".equals(action)) {
                    String domain = req.optString("domain", "");
                    if (domain.isEmpty() && Main.dbManager != null) {
                        domain = Main.dbManager.getRoundcubeDomain();
                    }
                    if (domain == null || domain.isEmpty()) {
                        response.put("success", false);
                        response.put("error", I18n.tr("server.rcdomain.none"));
                        sendJsonResponse(exchange, response);
                        return;
                    }

                    String serverIp = dnsGenerator != null ? dnsGenerator.detectServerIp() : "";
                    String aResult = digRecord(domain, "A");
                    boolean aOk = false;
                    boolean aProxied = false;
                    if (!aResult.isEmpty()) {
                        if (!serverIp.isEmpty() && aResult.contains(serverIp)) {
                            aOk = true;
                        } else {
                            // Resolves to different IP = likely CDN/proxy, fine for web traffic
                            aProxied = true;
                            aOk = true;
                        }
                    }

                    response.put("success", true);
                    response.put("domain", domain);
                    response.put("server_ip", serverIp);
                    response.put("a_record", aResult.isEmpty() ? I18n.tr("server.dns.notFound") : aResult);
                    response.put("a_ok", aOk);
                    response.put("a_proxied", aProxied);

                } else {
                    response.put("success", false);
                    response.put("error", I18n.tr("server.hostname.badAction"));
                }

            } else {
                sendJsonError(exchange, 405, I18n.tr("server.methodNotAllowed"));
                return;
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", ErrorText.forPage("handleApiRoundcubeDomain", e));
        }

        sendJsonResponse(exchange, response);
    }

    /**
     * Read current ssl_certificate and ssl_certificate_key from Nginx config.
     * Checks sites-enabled/roundcube.conf first (RoundcubeScript), then nginx.conf (FullMailServerScript).
     */
    private String[] readNginxRoundcubeSslPaths() {
        String[] result = {"", ""};
        Path nginxConf = Path.of("/usr/local/etc/nginx/sites-enabled/roundcube.conf");
        if (!Files.exists(nginxConf)) {
            nginxConf = Path.of("/usr/local/etc/nginx/nginx.conf");
        }
        if (!Files.exists(nginxConf)) return result;

        try {
            List<String> lines = Files.readAllLines(nginxConf);
            for (String line : lines) {
                String trimmed = line.trim();
                if (trimmed.startsWith("ssl_certificate ") && !trimmed.startsWith("ssl_certificate_key")) {
                    result[0] = trimmed.replace("ssl_certificate", "").replace(";", "").trim();
                } else if (trimmed.startsWith("ssl_certificate_key ")) {
                    result[1] = trimmed.replace("ssl_certificate_key", "").replace(";", "").trim();
                }
            }
        } catch (Exception e) {
            LOGGER.warning("Could not read Nginx SSL paths: " + e.getMessage());
        }
        return result;
    }

    /**
     * Regenerate the entire /usr/local/etc/nginx/nginx.conf from current SQLite settings.
     * Produces a config identical to FullMailServerScript but with a default_server block
     * that rejects requests on non-matching hostnames (returns 444 = close connection).
     */
    private boolean regenerateNginxRoundcubeConfig(String domain, String port, String sslCert, String sslKey) {
        try {
            // Defaults
            if (port == null || port.isEmpty()) port = "8443";
            if (sslCert == null || sslCert.isEmpty()) sslCert = "/usr/local/etc/ssl/mail/fullchain.pem";
            if (sslKey == null || sslKey.isEmpty()) sslKey = "/usr/local/etc/ssl/mail/privkey.pem";

            // Since 1.7 Roundcube no longer serves the files from the application's root but from the
            // public_html subfolder: it is a deliberate protection, and with the old root the
            // webmail answers 404 to everything. The choice is not made on the version number but on
            // what is really on disk, so the same line holds before and after the jump.
            String rcRoot = "/usr/local/www/roundcube";
            if (Files.isDirectory(Path.of(rcRoot, "public_html"))) rcRoot = rcRoot + "/public_html";

            // The whole file from a single source (NginxMain, the same as the installer's). Before, there was
            // another template here: it rewrote the file from scratch removing the include of the 443 (MTA-STS,
            // autoconfig), and wrote it without nginx -t and without a copy (install from the README, 2026-11-20).
            String config = org.daemoxcp.mail.system.NginxMain.content(domain, port, sslCert, sslKey, rcRoot,
                    // The Roundcube pool: its socket, or the previous one if the migration is not there yet.
                    org.daemoxcp.mail.system.RoundcubeUser.fastcgiPass());
            // The listen lines of the family chosen in the Settings (IpFamily); with no choice they stay as they are.
            if (port.trim().matches("[0-9]{1,5}"))
                config = org.daemoxcp.mail.system.IpFamily.withNginxListen(config, Integer.parseInt(port.trim()),
                        org.daemoxcp.mail.system.IpFamily.chosen());

            Path nginxConf = Path.of("/usr/local/etc/nginx/nginx.conf");
            String current = Files.exists(nginxConf) ? Files.readString(nginxConf) : null;
            config = org.daemoxcp.mail.system.NginxMain.keepIncludes(config, current);
            String problem = org.daemoxcp.mail.system.NginxMain.write(config);
            if (problem != null) {
                LOGGER.warning("Nginx roundcube config not written: " + problem);
                return false;
            }
            return true;
        } catch (Exception e) {
            LOGGER.warning("Could not regenerate Nginx roundcube config: " + e.getMessage());
            return false;
        }
    }

    /**
     * Read the current 'myhostname' value from Postfix main.cf
     */
    private String readPostfixHostname() {
        try {
            Path mainCf = Path.of("/usr/local/etc/postfix/main.cf");
            if (!Files.exists(mainCf)) return "";
            List<String> lines = Files.readAllLines(mainCf);
            for (String line : lines) {
                String trimmed = line.trim();
                if (trimmed.startsWith("myhostname") && trimmed.contains("=")) {
                    String value = trimmed.substring(trimmed.indexOf('=') + 1).trim();
                    // Remove possible inline comments
                    if (value.contains("#")) {
                        value = value.substring(0, value.indexOf('#')).trim();
                    }
                    return value;
                }
            }
        } catch (Exception e) {
            LOGGER.warning("Could not read Postfix hostname: " + e.getMessage());
        }
        return "";
    }

    /**
     * Update 'myhostname' and 'mydomain' in Postfix main.cf
     */
    private boolean updatePostfixHostname(String newHostname) {
        try {
            Path mainCf = Path.of("/usr/local/etc/postfix/main.cf");
            if (!Files.exists(mainCf)) return false;

            List<String> lines = Files.readAllLines(mainCf);
            List<String> updated = new ArrayList<>();
            boolean foundMyhostname = false;
            boolean foundMydomain = false;

            for (String line : lines) {
                String trimmed = line.trim();
                if (trimmed.startsWith("myhostname") && trimmed.contains("=")) {
                    updated.add("myhostname = " + newHostname);
                    foundMyhostname = true;
                } else if (trimmed.startsWith("mydomain") && trimmed.contains("=") && !trimmed.startsWith("mydestination")) {
                    updated.add("mydomain = " + newHostname);
                    foundMydomain = true;
                } else {
                    updated.add(line);
                }
            }

            // If not found, append them
            if (!foundMyhostname) {
                updated.add("myhostname = " + newHostname);
            }
            if (!foundMydomain) {
                updated.add("mydomain = " + newHostname);
            }

            Files.write(mainCf, updated);
            return true;
        } catch (Exception e) {
            LOGGER.warning("Could not update Postfix hostname: " + e.getMessage());
            return false;
        }
    }

    /**
     * Run dig to resolve a DNS record
     */
    private String digRecord(String name, String type) {
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("dig", "+short", name, type);
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            StringBuilder output = new StringBuilder();
            try (java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append(" ");
                }
            }
            p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
            return output.toString().trim();
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * Run dig -x to resolve a PTR record
     */
    private String digPtrRecord(String ip) {
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("dig", "+short", "-x", ip);
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            StringBuilder output = new StringBuilder();
            try (java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append(" ");
                }
            }
            p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
            return output.toString().trim();
        } catch (Exception e) {
            return "";
        }
    }

    private int getSessionAdminId(HttpExchange exchange) {
        return currentSession(exchange).map(s -> (int) s.admin().id()).orElse(0);
    }

    // ============== HELPER FOR QUERY PARAMS ==============

    /**
     * Extract and URL-decode a parameter from query string
     * Prevents URL encoding attacks by properly decoding values
     */
    private String extractParamFromQuery(String query, String param) {
        if (query == null) return null;
        for (String pair : query.split("&")) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2 && kv[0].equals(param)) {
                try {
                    // URL decode the value to handle encoded characters
                    return URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                } catch (Exception e) {
                    LOGGER.warning("Failed to decode URL parameter: " + param);
                    return null;
                }
            }
        }
        return null;
    }

    // ============== REQUEST SIZE LIMITING ==============

    private static final int MAX_REQUEST_SIZE = 10 * 1024 * 1024; // 10 MB max

    /**
     * Read request body with size limit to prevent DoS
     * @return body string or null if too large
     */
    private String readRequestBodyWithLimit(HttpExchange exchange) throws IOException {
        String contentLengthHeader = exchange.getRequestHeaders().getFirst("Content-Length");
        if (contentLengthHeader != null) {
            try {
                long contentLength = Long.parseLong(contentLengthHeader);
                if (contentLength > MAX_REQUEST_SIZE) {
                    return null; // Too large
                }
            } catch (NumberFormatException ignored) {}
        }

        // Read with limit
        InputStream is = exchange.getRequestBody();
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] data = new byte[8192];
        int totalRead = 0;
        int bytesRead;
        while ((bytesRead = is.read(data)) != -1) {
            totalRead += bytesRead;
            if (totalRead > MAX_REQUEST_SIZE) {
                return null; // Exceeded limit during read
            }
            buffer.write(data, 0, bytesRead);
        }
        return buffer.toString(StandardCharsets.UTF_8);
    }

    // ============== CSRF VALIDATION ==============

    /**
     * Validate CSRF token for state-changing requests
     * @return true if valid, false if invalid
     */
    private boolean validateCsrfForRequest(HttpExchange exchange, JSONObject request) {
        Optional<WebSessions.Current> session = currentSession(exchange);
        if (session.isEmpty()) return false;
        // A request forwarded by the web part: the token was checked by its CSRF filter, and here it is
        // not there (the root receives neither the session token nor the CSRF one).
        if (HeadExchange.unwrap(exchange) instanceof ForwardedExchange) return true;
        // The header that every page's script adds (getHead), or else the body field
        String header = exchange.getRequestHeaders().getFirst("X-CSRF-Token");
        String providedToken = header != null ? header : request.optString("csrf_token", "");
        return WebSessions.validCsrf(session.get().token(), providedToken);
    }

    /**
     * Send CSRF error response
     */
    private void sendCsrfError(HttpExchange exchange) throws IOException {
        sendJsonError(exchange, 403, I18n.tr("server.csrfInvalid"));
        logAudit("CSRF_FAILURE", getClientIp(exchange), "Invalid CSRF token attempt");
    }

    // ============== AUDIT LOGGING ==============

    /**
     * Log an audit event to database AND to a parallel text file
     * for external tooling (Fail2ban, log shippers, etc.).
     *
     * File path (default): /var/log/daemoxcp-mail-auth.log
     * Configurable via the setting "audit_log_file_path" in the DB.
     * If the file is not writable, the error does not block the app.
     *
     * Line format (parsable by Fail2ban with a simple regex), in UTC:
     *   2026-10-17T21:20:28Z [ACTION] ip=1.2.3.4 user=admin details="..."
     */
    void logAudit(String action, String ipAddress, String details) {
        String username = getSessionUsername();
        // 1) DB
        try {
            if (Main.mailDatabase != null) {
                Main.mailDatabase.logAuditEvent(action, ipAddress, details, username);
            }
        } catch (Exception e) {
            LOGGER.warning("Failed to log audit event to DB: " + e.getMessage());
        }
        // 2) Parallel text file for Fail2ban / log shippers
        try {
            writeAuditToFile(action, ipAddress, username, details);
        } catch (Exception e) {
            // Do not propagate -- logging must never break the app
        }
    }

    private static volatile String CACHED_AUDIT_LOG_PATH = null;

    private static String getAuditLogPath() {
        if (CACHED_AUDIT_LOG_PATH != null) return CACHED_AUDIT_LOG_PATH;
        String path = "/var/log/daemoxcp-mail-auth.log";
        try {
            // With the separated panel the root does not take the path from the database (audit_log_file_path,
            // which the tests use): the database is written by the web part too, and the root would write
            // wherever the web part tells it to.
            if (Main.mailDatabase != null && !org.daemoxcp.mail.system.PanelSeparation.rootPart()) {
                String fromDb = Main.mailDatabase.getSetting("audit_log_file_path", null);
                if (fromDb != null && !fromDb.isEmpty()) path = fromDb;
            }
        } catch (Exception ignored) {}
        CACHED_AUDIT_LOG_PATH = path;
        return path;
    }

    /**
     * A line of the authentication log, the one fail2ban reads.
     *
     * <p>The moment is in UTC with the Z, to the second. Before, it was
     * {@code LocalDateTime.now()} with {@code ISO_LOCAL_DATE_TIME}: the server's <em>local</em> time,
     * with nothing saying which time zone it was, against r13 -- and with the nanosecond
     * decimals attached, because that format prints them when they are there. Those decimals
     * were holding up fail2ban's filter by chance: they acted as the first field after
     * fail2ban had removed the date, and the few lines that fell on a whole second were not
     * recognised.
     *
     * <p>This form is half of a contract: the other half is
     * {@code Fail2banAutoSetup.filterContent()}. Changing only one of them breaks nothing
     * visibly -- simply nobody gets blocked any more.
     */
    public static String auditLine(String action, String ip, String username, String details) {
        // Sanitize newlines / quotes to avoid CRLF injection in the logs
        String safeAction = action == null ? "-" : action.replaceAll("[\\r\\n\\t]", " ");
        String safeIp = ip == null ? "-" : ip.replaceAll("[\\r\\n\\t\\s]", "");
        String safeUser = username == null || username.isEmpty() ? "-" : username.replaceAll("[\\r\\n\\t\"]", "_");
        String safeDetails = details == null ? "" : details.replaceAll("[\\r\\n\\t\"]", " ");
        String ts = java.time.Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS).toString();
        return ts + " [" + safeAction + "] ip=" + safeIp + " user=" + safeUser
                + " details=\"" + safeDetails + "\"\n";
    }

    private static void writeAuditToFile(String action, String ip, String username, String details) {
        String path = getAuditLogPath();
        String line = auditLine(action, ip, username, details);

        java.nio.file.Path p = java.nio.file.Paths.get(path);
        try {
            // Create the directory if it does not exist (best effort)
            java.nio.file.Path parent = p.getParent();
            if (parent != null && !java.nio.file.Files.exists(parent)) {
                java.nio.file.Files.createDirectories(parent);
            }
            java.nio.file.Files.writeString(
                p,
                line,
                java.nio.charset.StandardCharsets.UTF_8,
                java.nio.file.StandardOpenOption.CREATE,
                java.nio.file.StandardOpenOption.APPEND
            );
        } catch (java.io.IOException e) {
            // Missing permissions, full disk, etc. -- silent, do not block
        }
    }

    String getClientIp(HttpExchange exchange) {
        // The TCP address cannot be made up; CF-Connecting-IP can, and it counts only if the connection
        // really comes from Cloudflare (r18, TrustedProxy.clientAddress). X-Forwarded-For and X-Real-IP never.
        return org.daemoxcp.mail.security.TrustedProxy.clientAddress(
                exchange.getRemoteAddress().getAddress().getHostAddress(),
                exchange.getRequestHeaders().getFirst("CF-Connecting-IP"));
    }

    private String getSessionUsername() {
        // This is a simplified version - ideally pass exchange as parameter
        return "system";
    }

    private String getSessionUsername(HttpExchange exchange) {
        return currentSession(exchange).map(s -> s.admin().username()).orElse("anonymous");
    }
}
