package org.mail_panel.webserver;

import com.sun.net.httpserver.HttpsServer;
import org.mail_panel.Main;
import org.mail_panel.content.MailPanelContent;
import org.mail_panel.database.MailDatabase;
import org.mail_panel.scripts.InstallScripts;
import org.mail_panel.sqli.dataBaseManager;

import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Executors;

/**
 * Il server vero del pannello per home-panel-browser-test.js in modo REMOTE (reperto 183): i
 * gestori Java, le pagine generate, /api/panel_info con i dati veri della macchina, il MySQL di
 * prova, su HTTPS col nome panel.localhost. Un superadmin e una sua sessione di prova: il token
 * esce su stdout ("SESSION ..."), per il cookie del browser, che cosi' non passa dall'accesso
 * (lo prova login-browser-test.js).
 *
 * Stampa anche l'impronta del jar ("SHA256 ...") e la porta: la prova da browser le confronta con
 * quello che la scheda mostra.
 *
 * Uso (da una cartella vuota col jar dentro; READY su stderr quando ascolta):
 *   java -Dmysql.port=... -Dmysql.user=... -Dmysql.password=... -Dmysql.database=... \
 *        -cp "tests:$D/freebsd-mail-panel-1.0.jar" org.mail_panel.webserver.HomePanelE2EServer PORT
 */
public class HomePanelE2EServer {

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(args[0]);
        Path dir = Path.of("").toAbsolutePath();
        String mysqlPort = System.getProperty("mysql.port");
        String user = System.getProperty("mysql.user", "mailpanel");
        String password = System.getProperty("mysql.password", "");
        String database = System.getProperty("mysql.database", "mailpanel_prova");

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

        MailPanelContent.generateAllContent();
        Process cert = new ProcessBuilder("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=panel.localhost",
                "-addext", "subjectAltName=DNS:panel.localhost", "-keyout", dir.resolve("k.pem").toString(), "-out", dir.resolve("c.pem").toString())
                .redirectErrorStream(true).start();
        cert.getInputStream().readAllBytes();
        if (cert.waitFor() != 0) throw new IllegalStateException("openssl failed");
        // Il nome del pannello: HostCheck accetta solo quello (e localhost), e il browser arriva come panel.localhost.
        Main.dbManager.update_panel_config("panel.localhost", "0", Files.readString(dir.resolve("c.pem")),
                Files.readString(dir.resolve("k.pem")), "", "mailpanel-");
        SSLMailServer srv = new SSLMailServer(port, Files.readString(dir.resolve("c.pem")), Files.readString(dir.resolve("k.pem")));
        Field f = SSLMailServer.class.getDeclaredField("server");
        f.setAccessible(true);
        HttpsServer https = (HttpsServer) f.get(srv);
        https.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        https.start();

        String[] session = TestSessions.open(db, "dashboard-boss", "HomePanelE2EServer");
        System.out.println("SESSION " + session[0]);
        System.out.println("SHA256 " + InstallScripts.jarSha256());
        System.out.println("PORT " + port);
        System.out.flush();
        System.err.println("READY");
        Thread.currentThread().join();
    }
}
