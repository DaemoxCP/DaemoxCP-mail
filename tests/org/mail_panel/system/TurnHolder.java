package org.mail_panel.system;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Un altro processo del pannello che tiene il turno dei lavori sui pacchetti: per le prove del
 * turno fra processi (PackageTurnAcrossProcessesTest, e a mano sulla VM).
 *
 * Prende il turno con PackageQueue.take, cioe' come un lavoro vero; se gli si da' un elenco di
 * pacchetti lo scrive su disco come un lavoro che li ha sbloccati. Scrive "HELD" quando lo tiene,
 * poi aspetta che lo stdin si chiuda (o di essere ucciso) e rilascia.
 *
 * Uso: java -cp tests:<jar> org.mail_panel.system.TurnHolder <elenco> <descrizione> [pacchetto...]
 *      <elenco> e' il percorso dell'elenco ("-" per quello vero, /var/db/mail-panel-maintenance-locks):
 *      il file del turno gli sta accanto.
 */
public class TurnHolder {
    public static void main(String[] args) throws Exception {
        if (!"-".equals(args[0])) {
            PackageQueue.list = Path.of(args[0]);
            PackageQueue.turnLock = PackageQueue.list.resolveSibling("package-turn.lock");
        }
        String id = "holder-" + ProcessHandle.current().pid();
        String refusal = PackageQueue.take(id, args[1]);
        if (refusal != null) {
            System.out.println("REFUSED " + refusal);
            System.exit(3);
        }
        if (args.length > 2) {
            String e = PackageQueue.writeState(List.of(args).subList(2, args.length));
            if (e != null) { System.out.println("NOLIST " + e); PackageQueue.release(id); System.exit(4); }
        }
        System.out.println("HELD " + ProcessHandle.current().pid());
        System.out.flush();
        while (System.in.read() != -1) { }
        if (args.length > 2) Files.deleteIfExists(PackageQueue.list);
        PackageQueue.release(id);
        System.out.println("RELEASED");
    }
}
