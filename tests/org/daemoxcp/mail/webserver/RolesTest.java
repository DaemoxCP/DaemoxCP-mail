package org.daemoxcp.mail.webserver;

import com.sun.net.httpserver.HttpsServer;
import org.daemoxcp.mail.Main;
import org.daemoxcp.mail.content.Layout;
import org.daemoxcp.mail.database.MailDatabase;
import org.daemoxcp.mail.security.AuthStore;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.lang.reflect.Field;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;

/**
 * Roles and named permissions on the REAL server, over HTTPS, with the test MySQL: the route table
 * (every route declares who may use it, the menu asks the same permissions) and the check in
 * front of every route for each role. Before, only the administrators and the vault were
 * superadmin's: a viewer could change everything else.
 *
 * The requests that must pass use probes the handlers refuse without touching anything (an
 * unknown job, an action that does not exist, a confirmation that is missing).
 *
 * Usage (with the test MySQL of README.md):
 *   java -Dmysql.port=33062 -Dmysql.user=daemoxcp_mail -Dmysql.password=... -Dmysql.database=daemoxcp_mail_test \
 *        -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.webserver.RolesTest
 */
public class RolesTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static HttpClient http;
    static String base;
    static final String UA = "RolesTest/1.0";

    record Who(String cookie, String csrf) {}

    static HttpResponse<String> send(String method, String path, String body, Who who) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path)).header("User-Agent", UA);
        if (who != null) b.header("Cookie", who.cookie()).header("X-CSRF-Token", who.csrf());
        if (body != null) b.header("Content-Type", "application/json");
        b.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    static Who session(String name, String role) throws Exception {
        AuthStore.Created c = AuthStore.createAdmin(name, name + "@example.test", role);
        long id = c.id() > 0 ? c.id() : AuthStore.adminByUsername(name).orElseThrow().id();
        String token = Main.sessions.create(id, UA, "127.0.0.1");
        return new Who("__Host-DaemoxCPMail=" + token + "; __Host-lang=en", WebSessions.csrfToken(token));
    }

    /** The session of that administrator confirmed now, as the root part writes it after a passkey or a code. */
    static void confirm(Who who) throws Exception {
        String token = who.cookie().replaceAll("^__Host-DaemoxCPMail=([^;]+).*$", "$1");
        Main.sessions.markReauthenticated(Main.sessions.check(token, UA).orElseThrow().id());
    }

    static boolean asksConfirmation(HttpResponse<String> r) {
        return r.statusCode() == 403 && "needed".equals(r.headers().firstValue("X-Panel-Confirmation").orElse(""))
                && r.body().contains("\"needs_reauth\":true") && !r.body().contains("\"forbidden\":true");
    }

    static boolean refused(HttpResponse<String> r) {
        return r.statusCode() == 403 && r.body().contains("\"forbidden\":true");
    }

    static boolean passed(HttpResponse<String> r) {
        return r.statusCode() != 401 && r.statusCode() != 403;
    }

    public static void main(String[] args) throws Exception {
        permissions();
        String port = System.getProperty("mysql.port");
        if (port == null) {
            System.out.println("No MySQL given (-Dmysql.port=...): the route checks need the test MySQL, skipped.");
            System.exit(failed == 0 ? 0 : 1);
        }
        System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
        Path dir = Files.createTempDirectory("roles");
        Path audit = dir.resolve("audit.log");
        MailDatabase db = new MailDatabase();
        db.setCredentials(System.getProperty("mysql.user", "daemoxcp_mail"), System.getProperty("mysql.password", ""));
        db.setConnection("127.0.0.1", Integer.parseInt(port), System.getProperty("mysql.database", "daemoxcp_mail_test"));
        check("connected to MySQL", db.connect());
        // The schema BEFORE the entry, and the entry read back: see TestSessions.auditLogTo.
        // Written before the tables existed, it was not saved and the panel wrote to the real
        // log.
        TestSessions.auditLogTo(db, audit);
        Main.mailDatabase = db;
        Main.mysqlAvailable = true;
        Main.setupRequired = false;
        TestSessions.prepare(db);

        Process cert = new ProcessBuilder("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=localhost", "-keyout", dir.resolve("k.pem").toString(), "-out", dir.resolve("c.pem").toString())
                .redirectErrorStream(true).start();
        cert.getInputStream().readAllBytes();
        check("test certificate", cert.waitFor() == 0);
        SSLMailServer srv = new SSLMailServer(0, Files.readString(dir.resolve("c.pem")), Files.readString(dir.resolve("k.pem")));
        Field f = SSLMailServer.class.getDeclaredField("server");
        f.setAccessible(true);
        HttpsServer https = (HttpsServer) f.get(srv);
        https.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        https.start();
        base = "https://127.0.0.1:" + https.getAddress().getPort();
        SSLContext trustAll = SSLContext.getInstance("TLS");
        trustAll.init(null, new TrustManager[]{new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] x, String a) { }
            public void checkServerTrusted(X509Certificate[] x, String a) { }
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }}, new SecureRandom());
        http = HttpClient.newBuilder().sslContext(trustAll).build();

        try {
            routeTable(srv.routes());
            guard(audit);
        } finally {
            https.stop(0);
            db.close();
            Files.deleteIfExists(audit);
            Files.deleteIfExists(dir.resolve("k.pem"));
            Files.deleteIfExists(dir.resolve("c.pem"));
            Files.deleteIfExists(dir);
        }
        System.out.println("\n" + (failed == 0 ? "ALL GREEN" : failed + " CHECKS FAILED"));
        System.exit(failed == 0 ? 0 : 1);
    }

    static void permissions() {
        System.out.println("== Permissions by name ==");
        check("four roles, from the widest", AuthStore.ROLES.equals(List.of("superadmin", "admin", "operator", "viewer")));
        check("superadmin has every permission", AuthStore.permissionsOf("superadmin").equals(AuthStore.ALL_PERMISSIONS));
        for (String p : new String[]{"admins.manage", "vault.manage", "settings.manage", "system.manage", "security.manage"})
            check("only superadmin has " + p, AuthStore.ROLES.stream().filter(r -> AuthStore.permissionsOf(r).contains(p)).toList()
                    .equals(List.of("superadmin")));
        check("admin: domains, mailboxes, aliases and DNS", AuthStore.permissionsOf("admin")
                .containsAll(Set.of("domains.manage", "mailboxes.manage", "dns.manage", "queue.manage")));
        check("operator: mailboxes and queue, domains and DNS only to look", AuthStore.permissionsOf("operator")
                .containsAll(Set.of("mailboxes.manage", "queue.manage", "mail.view", "dns.view"))
                && !AuthStore.permissionsOf("operator").contains("domains.manage") && !AuthStore.permissionsOf("operator").contains("dns.manage"));
        check("viewer: nothing that changes", AuthStore.permissionsOf("viewer").stream().noneMatch(p -> p.endsWith(".manage")));
        check("every role manages its own account", AuthStore.ROLES.stream().allMatch(r -> AuthStore.permissionsOf(r).contains("account.self")));
        check("a role that does not exist has no permission", AuthStore.permissionsOf("root").isEmpty() && AuthStore.permissionsOf(null).isEmpty());
        boolean typo;
        try { Access.api("mail.veiw"); typo = false; } catch (IllegalArgumentException e) { typo = true; }
        check("a misspelled permission in a route stops the panel at start", typo);
        Access queue = Access.api("queue.view", "queue.manage", Access.actions("queue.manage", "message"));
        check("an action in the table wins over the method (GET ?action=message)", "queue.manage".equals(queue.permissionFor("GET", "message"))
                && "queue.view".equals(queue.permissionFor("GET", "stats")) && "queue.manage".equals(queue.permissionFor("POST", "flush")));
    }

    static void routeTable(Map<String, Access> routes) {
        System.out.println("\n== Route table ==");
        check("every route declares who may use it (" + routes.size() + " routes)", routes.size() > 70
                && routes.values().stream().allMatch(java.util.Objects::nonNull));
        Set<String> pub = new HashSet<>();
        routes.forEach((p, a) -> { if (a.kind() == Access.Kind.PUBLIC) pub.add(p); });
        check("public: only sign-in, setup, static files, dictionary, language, logout, autoconfig, MTA-STS and the webmail's own",
                // /assets/ (finding 178): the pages' scripts and styles as files. It is public like
                // /vendor, but the handler gives those of the protected pages only to whoever signed
                // in (LoginRoutesTest checks it).
                pub.equals(Set.of("/autoconfig", "/mta-sts", "/fa", "/vendor", "/i18n/", "/assets/", "/api/language", "/", "/index", "/api/login",
                        "/setup", "/api/logout", org.daemoxcp.mail.integration.WebmailPasswordConfig.PATH, "/api/internal/mailbox-vault",
                        "/api/internal/mailbox-cleanup")));
        StringBuilder mismatch = new StringBuilder();
        for (Layout.Section s : Layout.MENU)
            for (Layout.Item item : s.items()) {
                Access a = routes.get(item.href());
                if (a == null || !item.view().equals(a.readPermission())) mismatch.append(' ').append(item.href());
            }
        check("every menu item is a route asking the same permission to look" + mismatch, mismatch.isEmpty());
        check("revealing a mailbox password (a POST, served by the root part) asks mailboxes.manage",
                "mailboxes.manage".equals(routes.get("/api/mailbox-password").permissionFor("POST", null)));
        check("opening a mailbox's webmail asks mailboxes.manage, even with GET", "mailboxes.manage".equals(routes.get("/api/webmail/open").permissionFor("GET", null)));
        check("/api/updates: reading the status is system.view, rebooting is system.manage",
                "system.view".equals(routes.get("/api/updates").permissionFor("POST", "updates_status"))
                && "system.manage".equals(routes.get("/api/updates").permissionFor("POST", "reboot_now")));
        check("/api/updates: going back to the server before a reinstallation is system.manage (reperto 172)",
                "system.manage".equals(routes.get("/api/updates").permissionFor("POST", "reinstall_way_back")));
        check("/api/admins: the vault key asks vault.manage", "vault.manage".equals(routes.get("/api/admins").permissionFor("POST", "vault_backup_key")));
        check("/api/panel_info: how long the panel runs is home.view, its details system.view (reperto 183)",
                "home.view".equals(routes.get("/api/panel_info").permissionFor("GET", "uptime"))
                && "system.view".equals(routes.get("/api/panel_info").permissionFor("GET", "details")));
        check("Account for every role, Settings for the superadmin", "account.self".equals(routes.get("/account").readPermission())
                && "settings.manage".equals(routes.get("/settings").readPermission()));
    }

    static void guard(Path audit) throws Exception {
        System.out.println("\n== The check in front of the handler ==");
        Who viewer = session("vera", "viewer"), operator = session("otto", "operator"), admin = session("ada", "admin"),
            superadmin = session("boss", "superadmin");

        HttpResponse<String> page = send("GET", "/mailboxes", null, null);
        check("no session, a page: 302 to the sign-in page", page.statusCode() == 302
                && "/index".equals(page.headers().firstValue("Location").orElse("")));
        check("no session, an API: 401", send("GET", "/api/domains", null, null).statusCode() == 401);
        check("a public route needs no session", send("GET", "/i18n/en.js", null, null).statusCode() == 200);

        check("viewer opens the mailboxes page", send("GET", "/mailboxes", null, viewer).statusCode() == 200);
        HttpResponse<String> settings = send("GET", "/settings", null, viewer);
        check("viewer opening Settings: 403 page inside the panel frame, with no Settings in its menu", settings.statusCode() == 403
                && settings.body().contains("Access denied") && settings.body().contains("class=\"topbar\"")
                && !settings.body().contains("href=\"/settings\""));
        check("viewer opens Account", send("GET", "/account", null, viewer).statusCode() == 200);
        check("viewer cannot reveal a mailbox password", refused(send("POST", "/api/mailbox-password", "{\"id\":1}", viewer)));
        check("viewer cannot read a queued message", refused(send("GET", "/api/queue?action=message&id=ABCDEF1234", null, viewer)));
        check("viewer cannot open a mailbox's webmail", refused(send("POST", "/api/webmail/open", "{\"email\":\"a@b.test\"}", viewer)));
        check("viewer cannot restart a service", refused(send("POST", "/api/service", "{\"service\":\"redis\",\"action\":\"stop\"}", viewer)));
        check("viewer reads the domains list", passed(send("GET", "/api/domains", null, viewer)));
        HttpResponse<String> job = send("POST", "/api/updates", "{\"action\":\"job_status\",\"jobId\":\"none\"}", viewer);
        check("viewer reads a job status (a read action of /api/updates), and the handler got the body back",
                job.statusCode() == 200 && job.body().contains("\"success\":false") && !job.body().contains("Unknown action"));
        check("viewer cannot reboot", refused(send("POST", "/api/updates", "{\"action\":\"reboot_now\"}", viewer)));
        HttpResponse<String> uptime = send("GET", "/api/panel_info?action=uptime", null, viewer);
        check("viewer reads how long the panel runs, and may open its details (system.view)", uptime.statusCode() == 200
                && uptime.body().contains("\"startedAt\"") && uptime.body().contains("\"details\":true"));
        HttpResponse<String> details = send("GET", "/api/panel_info?action=details", null, viewer);
        check("viewer reads the details: version, jar fingerprint, process", details.statusCode() == 200
                && details.body().contains("\"version\"") && details.body().contains("\"jarSha256\"") && details.body().contains("\"pid\""));
        check("no session: 401, nothing about the panel", send("GET", "/api/panel_info?action=details", null, null).statusCode() == 401);
        check("/api/panel_info only reads: a POST is 405", send("POST", "/api/panel_info", "{\"action\":\"uptime\"}", viewer).statusCode() == 405);
        check("/api/panel_info: an unknown action is 400", send("GET", "/api/panel_info?action=nothing", null, viewer).statusCode() == 400);

        check("operator cannot create a domain", refused(send("POST", "/api/domains", "{\"domain\":\"x.test\"}", operator)));
        check("operator manages mailboxes (the handler answers)", passed(send("POST", "/api/mailboxes", "{\"action\":\"nothing\"}", operator)));
        check("operator manages the queue (the handler answers)", passed(send("POST", "/api/queue", "{\"action\":\"nothing\"}", operator)));
        check("admin cannot reboot (system.manage is superadmin's)", refused(send("POST", "/api/updates", "{\"action\":\"reboot_now\"}", admin)));
        check("admin cannot open Administrators", send("GET", "/admins", null, admin).statusCode() == 403);
        check("admin cannot export the vault key", refused(send("POST", "/api/admins", "{\"action\":\"vault_backup_key\"}", admin)));
        check("admin cannot change the firewall", refused(send("POST", "/api/firewall", "{\"action\":\"apply\"}", admin)));
        // The "back to the server before the reinstallation" button (ReinstallReturn, finding 170).
        check("viewer cannot go back to the server before a reinstallation", refused(send("POST", "/api/updates",
                "{\"action\":\"reinstall_way_back\",\"name\":\"reinstall-before-2000-01-01-000000\",\"confirm\":\"GO BACK\"}", viewer)));
        check("admin cannot either (system.manage is superadmin's)", refused(send("POST", "/api/updates",
                "{\"action\":\"reinstall_way_back\",\"name\":\"reinstall-before-2000-01-01-000000\",\"confirm\":\"GO BACK\"}", admin)));
        System.out.println("\n== The fresh confirmation for dangerous operations ==");
        check("superadmin without a recent confirmation, rebooting: 403 with X-Panel-Confirmation and needs_reauth",
                asksConfirmation(send("POST", "/api/updates", "{\"action\":\"reboot_now\"}", superadmin)));
        check("  stopping a service, changing the firewall, a Settings change, the root's SSH keys, Show password: the same",
                asksConfirmation(send("POST", "/api/service", "{\"service\":\"nothing\",\"action\":\"status\"}", superadmin))
                && asksConfirmation(send("POST", "/api/firewall", "{\"action\":\"apply\"}", superadmin))
                && asksConfirmation(send("POST", "/api/hostname", "{\"action\":\"change\"}", superadmin))
                && asksConfirmation(send("POST", "/api/ssh-keys", "{\"action\":\"remove\",\"fingerprint\":\"SHA256:x\"}", superadmin))
                && asksConfirmation(send("POST", "/api/mailbox-password", "{\"id\":1}", superadmin)));
        check("  a read sent with a POST does not ask it (a job status, the logs' search, the DNS check of the host name)",
                passed(send("POST", "/api/updates", "{\"action\":\"job_status\",\"jobId\":\"none\"}", superadmin))
                && passed(send("POST", "/api/logs", "{\"action\":\"search\",\"query\":\"x\"}", superadmin))
                && passed(send("POST", "/api/hostname", "{\"action\":\"check_dns\"}", superadmin)));
        check("  nor a GET, nor an everyday write (a mailbox, the queue)", passed(send("GET", "/api/admins", null, superadmin))
                && passed(send("POST", "/api/mailboxes", "{\"action\":\"nothing\"}", superadmin))
                && passed(send("POST", "/api/queue", "{\"action\":\"nothing\"}", superadmin)));
        check("  a role without the permission is refused first, with no confirmation asked",
                refused(send("POST", "/api/service", "{\"service\":\"nothing\",\"action\":\"status\"}", admin)));
        confirm(superadmin);
        check("after the confirmation the request reaches the handler", passed(send("POST", "/api/mailbox-password", "{\"id\":999999999}", superadmin)));
        try (java.sql.PreparedStatement p = org.daemoxcp.mail.TestSql.mysql().prepareStatement(
                "UPDATE panel_sessions SET reauth_at = UTC_TIMESTAMP() - INTERVAL 6 MINUTE WHERE admin_id = ?")) {
            p.setLong(1, AuthStore.adminByUsername("boss").orElseThrow().id());
            p.executeUpdate();
        }
        check("  six minutes later it is asked again", asksConfirmation(send("POST", "/api/mailbox-password", "{\"id\":999999999}", superadmin)));
        confirm(superadmin);

        HttpResponse<String> back = send("POST", "/api/updates",
                "{\"action\":\"reinstall_way_back\",\"name\":\"reinstall-before-2000-01-01-000000\"}", superadmin);
        check("superadmin without the confirmation: refused by the handler, nothing touched", back.statusCode() == 200
                && back.body().contains("\"success\":false") && !back.body().contains("reinstall-before-2000-01-01-000000"));
        back = send("POST", "/api/updates",
                "{\"action\":\"reinstall_way_back\",\"name\":\"reinstall-before-2000-01-01-000000\",\"confirm\":\"GO BACK\"}", superadmin);
        check("superadmin with the confirmation reaches the way back, which refuses a name that is not there", back.statusCode() == 200
                && back.body().contains("\"success\":false") && back.body().contains("reinstall-before-2000-01-01-000000"));
        HttpResponse<String> reboot = send("POST", "/api/updates", "{\"action\":\"reboot_now\"}", superadmin);
        check("superadmin passes (and the handler still asks for the written confirmation)", reboot.statusCode() == 200
                && reboot.body().contains("\"success\":false"));

        long id = AuthStore.adminByUsername("vera").orElseThrow().id();
        AuthStore.setRole(id, "operator");
        check("a changed role applies at the next request, no new sign-in",
                passed(send("POST", "/api/mailboxes", "{\"action\":\"nothing\"}", viewer)));
        AuthStore.deleteAdmin(id);
        check("a deleted administrator: the next request is 401", send("GET", "/api/domains", null, viewer).statusCode() == 401);

        boolean logged = false;
        for (int i = 0; i < 40 && !logged; i++) {
            logged = Files.exists(audit) && Files.readString(audit).contains("PERMISSION_DENIED");
            if (!logged) Thread.sleep(50);
        }
        check("every refusal is in the audit log (PERMISSION_DENIED)", logged);
    }
}
