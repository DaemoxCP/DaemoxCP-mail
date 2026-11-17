package org.daemoxcp.mail.webserver;

import com.sun.net.httpserver.HttpsServer;
import org.daemoxcp.mail.Main;
import org.daemoxcp.mail.content.PanelContent;
import org.daemoxcp.mail.database.MailDatabase;
import org.daemoxcp.mail.scripts.InstallScripts;
import org.daemoxcp.mail.sqli.dataBaseManager;

import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Executors;

/**
 * The real panel server for home-panel-browser-test.js and session-restart-browser-test.js in REMOTE
 * mode (reperti 183-184): the Java handlers, the generated pages, /api/panel_info with the machine's
 * real data, the test MySQL, over HTTPS with the name panel.localhost. A superadmin and a test
 * session of theirs: the token goes to stdout ("SESSION ..."), for the browser cookie, which thus
 * does not go through the sign-in (login-browser-test.js covers that). The session is valid only
 * with the User-Agent "HomePanelE2EServer" (WebSessions ties it to the browser): the tests use it.
 *
 * It also prints the jar's fingerprint ("SHA256 ...") and the port: the browser test compares them
 * with what the card shows.
 *
 * Usage (from an empty folder with the jar inside; READY on stderr when it listens):
 *   java -Dmysql.port=... -Dmysql.user=... -Dmysql.password=... -Dmysql.database=... \
 *        -cp "tests:$D/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.webserver.HomePanelE2EServer PORT
 */
public class HomePanelE2EServer {

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(args[0]);
        Path dir = Path.of("").toAbsolutePath();
        // The panel's secrets and the vault's old key in this test folder, unless given: by default PanelSecrets and
        // PasswordVault use /usr/local/etc/mail-panel, and update_mysql_config and update_panel_config below would
        // overwrite the RUNNING panel's MySQL password and TLS key on the test machine. Measured on 10/11/2026: the
        // VM's panel kept working until its next start, then could not reach MySQL and stopped separating.
        if (System.getProperty("daemoxcp.mail.secrets.dir") == null)
            System.setProperty("daemoxcp.mail.secrets.dir", Files.createDirectories(dir.resolve("secrets")).toString());
        if (System.getProperty("daemoxcp.mail.vault.key") == null)
            System.setProperty("daemoxcp.mail.vault.key", dir.resolve("secrets").resolve("master.key").toString());
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
        Main.mysqlAvailable = true;
        Main.setupRequired = false;

        PanelContent.generateAllContent();
        Process cert = new ProcessBuilder("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=panel.localhost",
                "-addext", "subjectAltName=DNS:panel.localhost", "-keyout", dir.resolve("k.pem").toString(), "-out", dir.resolve("c.pem").toString())
                .redirectErrorStream(true).start();
        cert.getInputStream().readAllBytes();
        if (cert.waitFor() != 0) throw new IllegalStateException("openssl failed");
        // The panel's name: HostCheck accepts only that (and localhost), and the browser comes as panel.localhost.
        Main.dbManager.update_panel_config("panel.localhost", "0", Files.readString(dir.resolve("c.pem")),
                Files.readString(dir.resolve("k.pem")), "", "mailpanel-");
        SSLMailServer srv = new SSLMailServer(port, Files.readString(dir.resolve("c.pem")), Files.readString(dir.resolve("k.pem")));
        Field f = SSLMailServer.class.getDeclaredField("server");
        f.setAccessible(true);
        HttpsServer https = (HttpsServer) f.get(srv);
        https.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        https.start();

        // Like SSLMailServer.start (reperto 184): the sessions of the previous start go. The same
        // database across two starts of this server is a jar started again.
        System.out.println("CLOSED " + Main.sessions.beginRun());
        String[] session = TestSessions.open(db, "dashboard-boss", "HomePanelE2EServer");
        System.out.println("SESSION " + session[0]);
        System.out.println("SHA256 " + InstallScripts.jarSha256());
        System.out.println("PORT " + port);
        System.out.flush();
        System.err.println("READY");
        Thread.currentThread().join();
    }
}
