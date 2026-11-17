package org.daemoxcp.mail.webserver;

import com.sun.net.httpserver.HttpsServer;
import org.daemoxcp.mail.Main;
import org.daemoxcp.mail.content.PanelContent;
import org.daemoxcp.mail.database.MailDatabase;
import org.daemoxcp.mail.security.LoginCodes;
import org.daemoxcp.mail.sqli.dataBaseManager;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.Executors;

/**
 * The real mail panel server for login-browser-test.js: the Java handlers, the test MySQL, the
 * sessions and the WebAuthn checks, over HTTPS with a certificate for panel.localhost.
 *
 * The database starts empty: no administrator. The page says to create it from the console
 * (java ... Main --create-admin), which the test runs in the working directory. The emails the panel would send go to
 * mail.log in the working directory. The SQLite configuration in the working directory points
 * to the test MySQL, so that "java ... Main --access-code" run there finds the same database.
 *
 * Usage (from an empty working directory with the jar inside; prints READY on stderr):
 *   java -Dmysql.port=... -Dmysql.user=... -Dmysql.password=... -Dmysql.database=... \
 *        -Ddaemoxcp.mail.secrets.dir=$D/secrets -Ddaemoxcp.mail.vault.key=$D/master.key \
 *        -cp "tests:$D/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.webserver.LoginE2EServer PORT
 */
public class LoginE2EServer {

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(args[0]);
        Path dir = Path.of("").toAbsolutePath();
        String mysqlPort = System.getProperty("mysql.port");
        String user = System.getProperty("mysql.user", "daemoxcp_mail");
        String password = System.getProperty("mysql.password", "");
        String database = System.getProperty("mysql.database", "daemoxcp_mail_test");

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
        Main.mailDatabase = db;
        db.dropAllTables();
        db.setSetting("audit_log_file_path", dir.resolve("audit.log").toString());
        TestSessions.prepare(db);
        db.setSetting("audit_log_file_path", dir.resolve("audit.log").toString());
        Main.mysqlAvailable = true;
        Main.setupRequired = !db.hasAdminUser();

        AuthHandlers.codeRequestMinMs = 200;
        LoginCodes.synchronousMail = true;
        Path mailLog = dir.resolve("mail.log");
        LoginCodes.mailer = (to, subject, body) -> Files.writeString(mailLog,
                "TO " + to + "\nSUBJECT " + subject + "\n\n" + body + "\n.\n", StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);

        PanelContent.generateAllContent();
        Process cert = new ProcessBuilder("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=panel.localhost", "-addext", "subjectAltName=DNS:panel.localhost",
                "-keyout", dir.resolve("k.pem").toString(), "-out", dir.resolve("c.pem").toString())
                .redirectErrorStream(true).start();
        cert.getInputStream().readAllBytes();
        if (cert.waitFor() != 0) throw new IllegalStateException("openssl failed");
        // The panel's name: HostCheck (since 17/10/2026), with the "listen everywhere" address, only
        // accepts localhost and the machine's addresses, and the browser arrives as panel.localhost
        // (the passkeys' name). Without this line every page answered 421 and the test no longer
        // passed; found by running it against the test machine (reperto 178).
        Main.dbManager.update_panel_config("panel.localhost", "0", Files.readString(dir.resolve("c.pem")),
                Files.readString(dir.resolve("k.pem")), "", "mailpanel-");
        SSLMailServer srv = new SSLMailServer(port, Files.readString(dir.resolve("c.pem")), Files.readString(dir.resolve("k.pem")));
        Field f = SSLMailServer.class.getDeclaredField("server");
        f.setAccessible(true);
        HttpsServer https = (HttpsServer) f.get(srv);
        https.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        https.start();
        System.err.println("READY");
        Thread.currentThread().join();
    }
}
