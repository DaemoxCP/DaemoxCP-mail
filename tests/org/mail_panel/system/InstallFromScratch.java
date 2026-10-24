package org.mail_panel.system;

import org.mail_panel.Main;
import org.mail_panel.scripts.FullMailServerScript;
import org.mail_panel.security.PanelSecrets;
import org.mail_panel.sqli.dataBaseManager;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/**
 * Il conduttore dell'installazione completa, per provarla su una macchina pulita senza
 * passare dal menu a schermo (che vuole un terminale e una persona che digita).
 *
 * Fa gli stessi passi di Main.installMailServer, con le stesse chiamate: configurazione in
 * SQLite, le due password dal generatore del pannello, lo script scritto da
 * FullMailServerScript, e l'avvio con Main.executeScriptWithSecrets, cioe' proprio la
 * funzione che il pannello usa. L'elenco degli argomenti e' l'unico pezzo ricopiato, ed e'
 * quello che MysqlRootPasswordTest confronta con lo script.
 *
 * Tutto quello che il pannello stampa finisce anche in un file, cosi' dopo si puo' cercare
 * dentro se per caso c'e' una password.
 *
 * Uso (dalla cartella del pannello, come root, su una macchina senza altro):
 *   java -cp "tests:freebsd-mail-panel-1.0.jar" \
 *        org.mail_panel.system.InstallFromScratch mail.test.local webmail.test.local 8443
 */
public class InstallFromScratch {

    public static void main(String[] args) throws Exception {
        String mailHostname = args.length > 0 ? args[0] : "mail.prova.local";
        String roundcubeDomain = args.length > 1 ? args[1] : "webmail.prova.local";
        String roundcubePort = args.length > 2 ? args[2] : "8443";

        // Gli stessi preparativi che fa Main all'avvio (Main.java, intorno a riga 350 e 374):
        // le cartelle e le colonne aggiunte dalle versioni successive.
        Main.createDirectoryIfNotExists("./database/");
        Main.createDirectoryIfNotExists("./install_scripts/");

        Main.dbManager = new dataBaseManager();
        Main.dbManager.create_tables();
        Main.dbManager.insert_data_default();
        Main.dbManager.ensureMailHostnameColumn();
        Main.dbManager.ensureSslChainColumn();
        Main.dbManager.ensureRoundcubeColumns();
        Main.dbManager.ensurePostfixColumn();
        Main.dbManager.setMailHostname(mailHostname);
        Main.dbManager.updateRoundcubeConfig(roundcubeDomain, roundcubePort, "", "", "");

        String mysqlHost = "127.0.0.1", mysqlPort = "3306";
        String mysqlUser = "mailpanel", mysqlDatabase = "mailserver";

        String mysqlPassword = PanelSecrets.newAlphanumericPassword(24);
        Main.dbManager.update_mysql_config(mysqlHost, mysqlPort, mysqlUser, mysqlPassword, mysqlDatabase);
        String mysqlRootPassword = PanelSecrets.ensureMysqlRootPassword();

        // Le password si scrivono QUI, in due file leggibili solo da root, perche' chi guarda
        // l'esito deve poterle confrontare con quello che e' finito in MySQL. Nel pannello
        // vero stanno solo nel file dei segreti.
        write(Path.of("installed-mysql-password"), mysqlPassword);
        write(Path.of("installed-mysql-root-password"), mysqlRootPassword);

        new FullMailServerScript().write_file();

        System.out.println("=== installazione, hostname " + mailHostname + " ===");
        boolean ok = Main.executeScriptWithSecrets("./install_scripts/install_mail_server.sh",
                "Complete Mail Server Installation",
                Map.of("MYSQL_PASSWORD", mysqlPassword, "MYSQL_ROOT_PASSWORD", mysqlRootPassword),
                mysqlHost, mysqlPort, mysqlUser, mysqlDatabase, mailHostname,
                roundcubeDomain, roundcubePort, "", "", "");
        System.out.println("=== esito: " + (ok ? "riuscita" : "FALLITA") + " ===");
        System.exit(ok ? 0 : 1);
    }

    static void write(Path p, String value) throws Exception {
        Files.writeString(p, value, StandardCharsets.UTF_8);
        try {
            Files.setPosixFilePermissions(p, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        } catch (Exception ignored) {}
    }
}
