package org.mail_panel.system;

import org.mail_panel.i18n.I18n;

/**
 * Per le prove del menu a schermo: crea la via di ritorno di una reinstallazione (come la crea la
 * reinstallazione, PackageWayBack.beforeInstallation) e stampa il nome. Solo su un clone di prova.
 *   java -cp "tests:freebsd-mail-panel-1.0.jar" org.mail_panel.system.MakeReinstallWayBack
 */
public class MakeReinstallWayBack {
    public static void main(String[] args) {
        I18n.setCurrent("en");
        PackageWayBack.Prepared p = PackageWayBack.beforeInstallation(line -> { });
        System.out.println(p.name());
        System.exit(p.name().isEmpty() ? 1 : 0);
    }
}
