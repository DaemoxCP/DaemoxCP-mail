package org.daemoxcp.mail.system;

import org.daemoxcp.mail.Main;
import org.daemoxcp.mail.scripts.FullMailServerScript;
import org.daemoxcp.mail.sqli.dataBaseManager;

/**
 * The driver of the full reinstallation from the menu, on a server where the panel has already
 * started (so the stack packages are protected): it does what the menu item does after the name
 * window, that is ReinstallJob.runFromMenu, the same function: the detached reinstallation
 * (Main --reinstall under daemon(8)) and its log followed until the outcome. The on-screen menu
 * wants a terminal and a person typing; this does not.
 *
 * It prepares nothing: it uses the configuration in the panel's folder (SQLite, the secrets in
 * /usr/local/etc/mail-panel), as the menu does. So it stops mail, empties /var/vmail, changes the
 * panel's MySQL password: ONLY on a clone of a boot environment, from a COPY of the panel's folder
 * if that is outside the boot environment (/home).
 *
 * Usage (from the panel's folder, as root):
 *   java -cp "tests:daemoxcp-mail-1.0.jar" org.daemoxcp.mail.system.MenuReinstall [hostname]
 * Without a hostname it uses the saved one, like the menu window that proposes it.
 */
public class MenuReinstall {

    public static void main(String[] args) throws Exception {
        // The same preparations Main does at start before the menu.
        Main.createDirectoryIfNotExists("./install_scripts/");
        Main.dbManager = new dataBaseManager();
        Main.dbManager.ensureMailHostnameColumn();
        Main.dbManager.ensureSslChainColumn();
        Main.dbManager.ensureRoundcubeColumns();
        Main.dbManager.ensurePostfixColumn();
        // The menu writes the scripts again at every start (generateInstallScripts).
        new FullMailServerScript().write_file();

        String saved = Main.dbManager.getMailHostname();
        String host = args.length > 0 ? args[0] : saved;
        if (host == null || host.isBlank()) {
            System.out.println("No mail hostname saved and none given: nothing done.");
            System.exit(2);
        }
        System.out.println("=== reinstallation from the menu, hostname " + host + ", pid " + ProcessHandle.current().pid() + " ===");
        // Like the menu item: detached (ReinstallJob), and followed until the outcome.
        boolean ok = ReinstallJob.runFromMenu(host.trim(), System.out);
        System.out.println("=== outcome: " + (ok ? "succeeded" : "FAILED") + " ===");
        System.exit(ok ? 0 : 1);
    }
}
