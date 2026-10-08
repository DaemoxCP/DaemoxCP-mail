package org.mail_panel.content;

import java.io.*;
import java.lang.reflect.Method;

/**
 * Genera OGNI pagina del pannello su disco, per poterne controllare il JavaScript con un parser.
 *
 * Perche' esiste. Le pagine sono HTML e JavaScript dentro text block Java, dove la sequenza
 * barra-n e' un escape JAVA: scritta singola diventa un a capo VERO e spezza la stringa
 * JavaScript. Il parser del browser si ferma li' e l'INTERO blocco di script non viene
 * eseguito — la pagina resta con tutti gli indicatori che girano, e sembra che le chiamate
 * non finiscano mentre non sono nemmeno partite.
 *
 * Il compilatore Java questo non lo vede: per lui e' una stringa valida. Serve un parser
 * JavaScript sul risultato, ed e' quello che questa classe rende possibile.
 *
 * Il 02/09/2026 ha trovato due pagine rotte da giorni: Sicurezza e Amministratori. Su
 * Amministratori anche un difetto che nessun parser avrebbe segnalato — una sostituzione di
 * apici che, per lo stesso motivo, sostituiva un apice con se' stesso e lasciava scoperto
 * cio' che doveva proteggere.
 *
 * Uso:
 *   javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/content/PageGenerator.java
 *   java  -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.content.PageGenerator /tmp/pagine
 *   poi si estraggono i blocchi script e si passano a "node --check" (vedi README.md).
 */
public class PageGenerator {
    public static void main(String[] a) throws Exception {
        int fatte = 0, saltate = 0;
        for (Method m : MailPanelContent.class.getDeclaredMethods()) {
            String n = m.getName();
            if (!n.startsWith("get") || !n.endsWith("Html")) continue;
            if (m.getParameterCount() != 0) continue;
            try {
                Object out = m.invoke(null);
                String nome = n.substring(3, n.length() - 4).toLowerCase();
                try (PrintWriter w = new PrintWriter(new File(a[0], nome + ".html"), "UTF-8")) {
                    w.print(String.valueOf(out));
                }
                System.out.println("  " + nome + ".html  " + String.valueOf(out).length());
                fatte++;
            } catch (Throwable t) {
                System.out.println("  SALTATA " + n + ": " + t.getCause());
                saltate++;
            }
        }
        System.out.println("generate " + fatte + ", saltate " + saltate);
    }
}
