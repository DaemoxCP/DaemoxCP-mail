package org.mail_panel.system;

import java.io.PrintStream;

/**
 * Che cosa fa il pannello, all'avvio, su un server installato prima che l'installatore rendesse
 * Postfix l'MTA locale (LocalMtaRepair.decide). La decisione e' separata dal sistema apposta:
 * qui si provano le configurazioni che i tre script di `main` lasciavano davvero, piu' i casi
 * limite. L'effetto vero su una macchina lo misura la prova sulla VM (reperti).
 *
 * Il caso che conta e' il primo: l'installazione completa di main lasciava myorigin = $mydomain
 * (il nome del server) e mydestination = localhost. Attivare mailer.conf cosi' com'e' fa
 * rimbalzare la posta di sistema (punto 67): prima va myorigin = localhost.
 *
 * Si lancia ovunque (non chiama niente):
 *   java -cp "tests:&lt;dir&gt;/freebsd-mail-panel-1.0.jar" org.mail_panel.system.LocalMtaRepairTest
 */
public class LocalMtaRepairTest {

    static int failed = 0;
    static final PrintStream OUT = System.out;

    static void check(String what, boolean ok) {
        OUT.println((ok ? "  OK   " : "  FALLITO ") + what);
        if (!ok) failed++;
    }

    static final String DMA = "sendmail\t/usr/libexec/dma\nmailq\t\t/usr/libexec/dma\nnewaliases\t/usr/libexec/dma\n";
    static final String POSTFIX = "sendmail\t/usr/local/sbin/sendmail\nsend-mail\t/usr/local/sbin/sendmail\n"
            + "mailq\t\t/usr/local/sbin/sendmail\nnewaliases\t/usr/local/sbin/sendmail\n";

    static LocalMtaRepair.Action act(boolean installed, String mailer, String origin, String dest, String transport) {
        LocalMtaRepair.Decision d = LocalMtaRepair.decide(installed, mailer, origin, dest, transport);
        OUT.println("        -> " + d.action() + ": " + d.reason());
        return d.action();
    }

    public static void main(String[] args) {
        OUT.println("\n== I server che lasciava main ==");
        check("installazione completa (myorigin = nome del server, mydestination = localhost): "
                + "PRIMA myorigin = localhost, poi mailer.conf",
                act(true, null, "mail.prova.local", "localhost", "local:mail.prova.local")
                        == LocalMtaRepair.Action.SET_MYORIGIN_THEN_ACTIVATE);
        check("componente «postfix» dopo il nome vero (mydestination predefinito, il nome e' locale): "
                + "mailer.conf e basta",
                act(true, null, "mail.prova.local", "mail.prova.local, localhost.mail.prova.local, localhost",
                        "local:mail.prova.local") == LocalMtaRepair.Action.ACTIVATE);
        check("pulsante «all» (consegna locale spenta): NON si attiva, la posta di sistema rimbalzerebbe",
                act(true, null, "localhost", "", "error:no local mail delivery")
                        == LocalMtaRepair.Action.REFUSE);

        OUT.println("\n== Gia' a posto, o niente da fare ==");
        check("mailer.conf gia' per Postfix: niente",
                act(true, POSTFIX, "mail.prova.local", "localhost", "local:x") == LocalMtaRepair.Action.NOTHING);
        check("Postfix non installato: niente, anche con mailer.conf assente",
                act(false, null, "", "", "") == LocalMtaRepair.Action.NOTHING);
        check("installato da questo ramo (myorigin = localhost): mailer.conf gia' giusto, niente",
                act(true, POSTFIX, "localhost", "localhost", "local:mail.prova.local") == LocalMtaRepair.Action.NOTHING);

        OUT.println("\n== Casi limite ==");
        check("mailer.conf che passa a dma conta come da riparare",
                act(true, DMA, "localhost", "localhost", "local:x") == LocalMtaRepair.Action.ACTIVATE);
        check("una riga commentata non conta: '#sendmail /usr/local/sbin/sendmail'",
                act(true, "#sendmail\t/usr/local/sbin/sendmail\n" + DMA, "localhost", "localhost", "local:x")
                        == LocalMtaRepair.Action.ACTIVATE);
        check("mydestination senza localhost e myorigin non locale: NON si attiva",
                act(true, null, "mail.prova.local", "example.org", "local:x") == LocalMtaRepair.Action.REFUSE);
        check("maiuscole e virgole: Mail.Prova.Local e' in 'localhost,mail.prova.local'",
                act(true, null, "Mail.Prova.Local", "localhost,mail.prova.local", "local:x")
                        == LocalMtaRepair.Action.ACTIVATE);
        check("mydestination vuoto con consegna accesa: NON si attiva",
                act(true, null, "mail.prova.local", "", "local:x") == LocalMtaRepair.Action.REFUSE);
        check("local_transport vuoto (postconf non ha risposto) non e' 'spenta': decide il resto",
                act(true, null, "localhost", "localhost", "") == LocalMtaRepair.Action.ACTIVATE);

        OUT.println("\n" + (failed == 0 ? "TUTTO VERDE" : failed + " CONTROLLI FALLITI"));
        System.exit(failed == 0 ? 0 : 1);
    }
}
