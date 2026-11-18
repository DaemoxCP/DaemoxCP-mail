package org.daemoxcp.mail.system;

import org.daemoxcp.mail.Main;
import org.daemoxcp.mail.scripts.FullMailServerScript;
import org.daemoxcp.mail.security.PanelSecrets;
import org.daemoxcp.mail.sqli.dataBaseManager;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/**
 * The driver of the full installation, to try it on a clean machine without going through the
 * on-screen menu (which wants a terminal and a person typing).
 *
 * It takes the same steps as Main.installMailServer, with the same calls: configuration in SQLite,
 * the two passwords from the panel's generator, the script written by FullMailServerScript, and the
 * start with Main.executeScriptWithSecrets, that is the very function the panel uses. The list of
 * arguments is the only piece copied, and it is the one MysqlRootPasswordTest compares with the
 * script.
 *
 * Everything the panel prints also ends up in a file, so afterwards one can search it for a
 * password that might be there.
 *
 * Usage (from the panel's folder, as root, on a machine with nothing else):
 *   java -cp "tests:daemoxcp-mail.jar" \
 *        org.daemoxcp.mail.system.InstallFromScratch mail.test.local webmail.test.local 8443
 */
public class InstallFromScratch {

    public static void main(String[] args) throws Exception {
        String mailHostname = args.length > 0 ? args[0] : "mail.test.local";
        String roundcubeDomain = args.length > 1 ? args[1] : "webmail.test.local";
        String roundcubePort = args.length > 2 ? args[2] : "8443";

        // The same preparations Main makes at start (Main.java, around lines 350 and 374):
        // the folders and the columns added by later versions.
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
        String mysqlUser = "daemoxcp_mail", mysqlDatabase = "daemoxcp_mail";

        String mysqlPassword = PanelSecrets.newAlphanumericPassword(24);
        Main.dbManager.update_mysql_config(mysqlHost, mysqlPort, mysqlUser, mysqlPassword, mysqlDatabase);
        String mysqlRootPassword = PanelSecrets.ensureMysqlRootPassword();
        String roundcubeDbPassword = PanelSecrets.ensureRoundcubeDbPassword();

        // The passwords are written HERE, in two files only root can read, because whoever looks at
        // the outcome must be able to compare them with what ended up in MySQL. In the real panel
        // they live only in the secrets file.
        write(Path.of("installed-mysql-password"), mysqlPassword);
        write(Path.of("installed-mysql-root-password"), mysqlRootPassword);

        new FullMailServerScript().write_file();

        System.out.println("=== installation, hostname " + mailHostname + " ===");
        boolean ok = Main.executeScriptWithSecrets("./install_scripts/install_mail_server.sh",
                "Complete Mail Server Installation",
                Map.of("MYSQL_PASSWORD", mysqlPassword, "MYSQL_ROOT_PASSWORD", mysqlRootPassword,
                       "ROUNDCUBE_DB_PASSWORD", roundcubeDbPassword),
                mysqlHost, mysqlPort, mysqlUser, mysqlDatabase, mailHostname,
                roundcubeDomain, roundcubePort, "", "", "");
        System.out.println("=== outcome: " + (ok ? "succeeded" : "FAILED") + " ===");
        System.exit(ok ? 0 : 1);
    }

    static void write(Path p, String value) throws Exception {
        Files.writeString(p, value, StandardCharsets.UTF_8);
        try {
            Files.setPosixFilePermissions(p, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        } catch (Exception ignored) {}
    }
}
