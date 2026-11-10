package org.mail_panel.webserver;

import com.sun.net.httpserver.HttpsServer;
import org.mail_panel.Main;
import org.mail_panel.content.MailPanelContent;
import org.mail_panel.database.MailDatabase;
import org.mail_panel.integration.SieveGenerator;
import org.mail_panel.sqli.dataBaseManager;

import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.concurrent.Executors;

/**
 * The real panel server for sieve-rules-browser-test.js (reperto 223): the Java handlers, the generated pages, the test
 * MySQL and the REAL SieveGenerator, which writes as root under /var/mail/sieve. Over HTTPS with the name
 * panel.localhost; a superadmin's session goes to stdout ("SESSION ..."), valid only with the User-Agent
 * "SieveRulesE2EServer" (WebSessions ties it to the browser).
 *
 * <p>Seeded: the domain sieve-rules-shown.test, the mailbox alice@, the alias bob@ -> alice@ and, for bob, filters left
 * on the disk by a mailbox of before (/var/mail/sieve/sieve-rules-shown.test/bob/.dovecot.sieve). Whether root writes
 * the rules is the machine's say: with /var/mail without its sticky bit (FreeBSD's 0775, a server where it was lost)
 * every save is refused; with 1775, as the panel leaves it at start, the rules are written.
 *
 * <p>Turning bob into a mailbox makes the server run its mail configuration script as root (folders in /var/vmail,
 * Postfix and Dovecot reloaded), which on a shared test machine is not wanted: next to the jar there must be a plain
 * FILE named install_scripts, so the script cannot be written and nothing runs. Without it the server does not start.
 *
 * <p>Usage (as root on the test VM, from an empty folder with a copy of the jar and that file):
 * <pre>
 *   java -Dmysql.port=... -Dmysql.user=... -Dmysql.password=... -Dmysql.database=... \
 *        -cp "tests:$D/freebsd-mail-panel-1.0.jar" org.mail_panel.webserver.SieveRulesE2EServer PORT
 * </pre>
 * READY on stderr when it listens. At the end: {@code rm -r /var/mail/sieve/sieve-rules-shown.test}.
 */
public class SieveRulesE2EServer {

    static final String DOMAIN = "sieve-rules-shown.test";

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(args[0]);
        Path dir = Path.of("").toAbsolutePath();
        // The panel's secrets and the vault's old key in this test folder, unless given: by default PanelSecrets and
        // PasswordVault use /usr/local/etc/mail-panel, and update_mysql_config and update_panel_config below would
        // overwrite the RUNNING panel's MySQL password and TLS key on the test machine. Measured on 10/11/2026: the
        // VM's panel kept working until its next start, then could not reach MySQL and stopped separating.
        if (System.getProperty("mailpanel.secrets.dir") == null)
            System.setProperty("mailpanel.secrets.dir", Files.createDirectories(dir.resolve("secrets")).toString());
        if (System.getProperty("mailpanel.vault.key") == null)
            System.setProperty("mailpanel.vault.key", dir.resolve("secrets").resolve("master.key").toString());
        Path jarDir = Path.of(SSLMailServer.class.getProtectionDomain().getCodeSource().getLocation().toURI()).getParent();
        if (!Files.isRegularFile(jarDir.resolve("install_scripts"), LinkOption.NOFOLLOW_LINKS))
            throw new IllegalStateException(jarDir.resolve("install_scripts") + " must be a plain file: otherwise the"
                    + " conversion runs the mail configuration script as root");
        String mysqlPort = System.getProperty("mysql.port");
        String user = System.getProperty("mysql.user", "mailpanel");
        String password = System.getProperty("mysql.password", "");
        String database = System.getProperty("mysql.database", "mailpanel_test");

        Files.createDirectories(dir.resolve("database"));
        Main.dbManager = new dataBaseManager();
        if (Main.dbManager.check_tables() < 1) {
            Main.dbManager.create_tables();
            Main.dbManager.insert_data_default();
        }
        Main.dbManager.update_mysql_config("127.0.0.1", mysqlPort, user, password, database);

        MailDatabase db = new MailDatabase();
        db.setCredentials(user, password);
        db.setConnection("127.0.0.1", Integer.parseInt(mysqlPort), database);
        if (!db.connect()) throw new IllegalStateException("MySQL not reachable");
        TestSessions.auditLogTo(db, dir.resolve("audit.log"));
        db.ensureMailboxPasswordVaultColumns();
        Main.mysqlAvailable = true;
        Main.setupRequired = false;

        MailDatabase.Domain dom = db.getDomainByName(DOMAIN);
        int domainId = dom != null ? dom.id : db.addDomain(DOMAIN, "reperto 223");
        if (db.getMailboxByEmail("alice@" + DOMAIN) == null)
            db.addMailbox(domainId, "alice@" + DOMAIN, "A-long-test-password-42", "Alice", 100);
        if (db.getMailboxByEmail("bob@" + DOMAIN) == null
                && db.getAliases(domainId).stream().noneMatch(a -> a.source.equals("bob@" + DOMAIN)))
            db.addAlias(domainId, "bob@" + DOMAIN, "alice@" + DOMAIN);
        Path oldFilters = Path.of("/var/mail/sieve", DOMAIN, "bob");
        Files.createDirectories(oldFilters);
        Files.writeString(oldFilters.resolve(".dovecot.sieve"), "require \"fileinto\";\nfileinto \"INBOX.Old\";\n");

        MailPanelContent.generateAllContent();
        Process cert = new ProcessBuilder("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=panel.localhost",
                "-addext", "subjectAltName=DNS:panel.localhost", "-keyout", dir.resolve("k.pem").toString(), "-out", dir.resolve("c.pem").toString())
                .redirectErrorStream(true).start();
        cert.getInputStream().readAllBytes();
        if (cert.waitFor() != 0) throw new IllegalStateException("openssl failed");
        // The panel's name: HostCheck accepts only that (and localhost), and the browser comes as panel.localhost.
        Main.dbManager.update_panel_config("panel.localhost", "0", Files.readString(dir.resolve("c.pem")),
                Files.readString(dir.resolve("k.pem")), "", "mailpanel-");
        SSLMailServer srv = new SSLMailServer(port, Files.readString(dir.resolve("c.pem")), Files.readString(dir.resolve("k.pem")));
        // What initializeManagers (not run here: it also starts the repairs of a real start) gives the server.
        Field g = SSLMailServer.class.getDeclaredField("sieveGenerator");
        g.setAccessible(true);
        g.set(srv, new SieveGenerator());
        Field f = SSLMailServer.class.getDeclaredField("server");
        f.setAccessible(true);
        HttpsServer https = (HttpsServer) f.get(srv);
        https.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        https.start();

        System.out.println("CLOSED " + Main.sessions.beginRun());
        String[] session = TestSessions.open(db, "sieve-rules-boss", "SieveRulesE2EServer");
        System.out.println("SESSION " + session[0]);
        System.out.println("PORT " + port);
        System.out.flush();
        System.err.println("READY");
        Thread.currentThread().join();
    }
}
