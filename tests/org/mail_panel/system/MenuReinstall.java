package org.mail_panel.system;

import org.mail_panel.Main;
import org.mail_panel.scripts.FullMailServerScript;
import org.mail_panel.sqli.dataBaseManager;

/**
 * Il conduttore della reinstallazione completa dal menu, su un server dove il pannello e' gia'
 * partito (e quindi i pacchetti dello stack sono protetti): fa quello che fa la voce del menu
 * dopo la finestra del nome, cioe' Main.runInstallation, la stessa funzione. Il menu a schermo
 * vuole un terminale e una persona che digita; questo no.
 *
 * Non prepara niente: usa la configurazione che c'e' nella cartella del pannello (SQLite, i
 * segreti in /usr/local/etc/mail-panel), come la usa il menu. Quindi ferma la posta, svuota
 * /var/vmail, cambia la password di MySQL del pannello: SOLO su un clone di un boot environment,
 * da una COPIA della cartella del pannello se questa sta fuori dal boot environment (/home).
 *
 * Uso (dalla cartella del pannello, come root):
 *   java -cp "tests:freebsd-mail-panel-1.0.jar" org.mail_panel.system.MenuReinstall [hostname]
 * Senza hostname usa quello salvato, come la finestra del menu che lo propone.
 */
public class MenuReinstall {

    public static void main(String[] args) throws Exception {
        // Gli stessi preparativi che fa Main all'avvio prima del menu.
        Main.createDirectoryIfNotExists("./install_scripts/");
        Main.dbManager = new dataBaseManager();
        Main.dbManager.ensureMailHostnameColumn();
        Main.dbManager.ensureSslChainColumn();
        Main.dbManager.ensureRoundcubeColumns();
        Main.dbManager.ensurePostfixColumn();
        // Il menu riscrive gli script a ogni avvio (generateInstallScripts).
        new FullMailServerScript().write_file();

        String saved = Main.dbManager.getMailHostname();
        String host = args.length > 0 ? args[0] : saved;
        if (host == null || host.isBlank()) {
            System.out.println("No mail hostname saved and none given: nothing done.");
            System.exit(2);
        }
        System.out.println("=== reinstallazione dal menu, hostname " + host + ", pid " + ProcessHandle.current().pid() + " ===");
        boolean ok = Main.runInstallation(host.trim());
        System.out.println("=== esito: " + (ok ? "riuscita" : "FALLITA") + " ===");
        System.exit(ok ? 0 : 1);
    }
}
