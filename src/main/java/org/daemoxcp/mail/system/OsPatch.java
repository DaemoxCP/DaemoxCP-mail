package org.daemoxcp.mail.system;

import org.json.JSONObject;

import java.time.Instant;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Le patch del sistema di base installate dal pannello, e il riavvio che chiedono (reperto 185).
 *
 * <p>Fino al 07/11/2026 il pannello sapeva solo SCARICARE le patch ("freebsd-update fetch"):
 * installarle era possibile solo dentro il passaggio a una release nuova. Sul server vero le patch
 * fino alla p6 aspettavano scaricate dal 22/10, e nessuno lo vedeva se non in una riga della
 * scheda del sistema. Il lavoro vero e' in UpdateManager.runOsPatchInstall; qui le decisioni, che
 * si provano senza un sistema sotto.
 */
public final class OsPatch {

    private OsPatch() {}

    /** Il file "tag" di freebsd-update: "freebsd-update|arm64|15.1-RELEASE|6|<hash>|<fine supporto>". */
    private static final Pattern TAG = Pattern.compile("^freebsd-update\\|[^|]+\\|([0-9]{1,2}\\.[0-9]{1,2}-[A-Z]+[A-Z0-9-]*)\\|([0-9]{1,4})\\|");

    /**
     * La versione a cui portano le patch scaricate, dal file tag: "15.1-RELEASE-p6". Vuota se il
     * tag non c'e' o non ha quella forma; "15.1-RELEASE" per il livello 0.
     */
    static String target(String tag) {
        if (tag == null) return "";
        Matcher m = TAG.matcher(tag.trim());
        if (!m.find()) return "";
        int p = Integer.parseInt(m.group(2));
        return p == 0 ? m.group(1) : m.group(1) + "-p" + p;
    }

    /**
     * freebsd-update install ha installato il kernel e chiede di riavviare PRIMA di proseguire
     * (succede nei passaggi di release: "Please reboot and run freebsd-update install again").
     * Fra due patch della stessa release installa tutto in un giro solo.
     */
    static boolean asksRebootFirst(String output) {
        String o = output == null ? "" : output.toLowerCase();
        return o.contains("reboot") && o.contains("install") && o.contains("again");
    }

    /** L'uscita di freebsd-update quando non c'e' niente da installare. */
    static boolean nothingToInstall(String output) {
        String o = output == null ? "" : output.toLowerCase();
        return o.contains("no updates are available to install");
    }

    /** L'uscita di "freebsd-update fetch" quando la release e' gia' all'ultima patch. */
    static boolean nothingToFetch(String output) {
        String o = output == null ? "" : output.toLowerCase();
        return o.contains("no updates needed") || o.contains("has no updates available");
    }

    /**
     * Se il server va riavviato, e perche'.
     *
     * <ul>
     *   <li>"needed": il kernel installato non e' quello in esecuzione (il criterio dell'Handbook):
     *   le patch del kernel non valgono finche' non si riavvia;</li>
     *   <li>"advised": le patch sono state installate dopo l'ultima accensione, ma il kernel e'
     *   quello giusto. I servizi accesi usano ancora le librerie di prima (libc, OpenSSL del
     *   sistema) finche' non ripartono: il riavvio li fa ripartire tutti insieme;</li>
     *   <li>"none": niente da fare. Se il pannello ha installato patch prima dell'ultima
     *   accensione, "done" dice quali.</li>
     * </ul>
     *
     * @param installedAt quando il pannello ha installato le ultime patch (secondi epoch), 0 se mai
     * @param boot        quando si e' acceso il server, null se non si sa
     */
    static JSONObject rebootState(String installedKernel, String runningKernel, long installedAt, Instant boot, String installedTo) {
        String installed = installedKernel == null ? "" : installedKernel.trim();
        String running = runningKernel == null ? "" : runningKernel.trim();
        boolean kernel = !installed.isEmpty() && !running.isEmpty() && !installed.equals(running);
        boolean afterBoot = installedAt > 0 && boot != null && installedAt > boot.getEpochSecond();
        String state = kernel ? "needed" : afterBoot ? "advised" : "none";
        JSONObject r = new JSONObject().put("success", true).put("state", state)
                .put("installedKernel", installed).put("runningKernel", running)
                .put("bootedAt", boot == null ? "" : boot.toString())
                .put("patchesInstalledAt", installedAt > 0 ? Instant.ofEpochSecond(installedAt).toString() : "");
        if (installedAt > 0 && boot != null && !afterBoot && !kernel) r.put("done", installedTo == null ? "" : installedTo);
        return r;
    }

    /**
     * Il file di configurazione con cui il pannello lancia "freebsd-update install": quello del
     * sistema, con CreateBootEnv no. L'ambiente di avvio lo crea il pannello prima, con un nome che
     * dice cosa c'era dentro, e controlla che esista: senza, non installa. Lasciato a freebsd-update,
     * se bectl non lo crea (bectl check fallisce) l'installazione prosegue lo stesso, senza via di
     * ritorno. Una riga CreateBootEnv gia' attiva si toglie: freebsd-update rifiuta i doppioni.
     */
    static String installConfig(String system) {
        StringBuilder out = new StringBuilder();
        for (String line : (system == null ? "" : system).split("\n", -1)) {
            if (line.trim().matches("(?i)CreateBootEnv\\s+.*")) continue;
            out.append(line).append('\n');
        }
        while (out.length() > 1 && out.charAt(out.length() - 1) == '\n' && out.charAt(out.length() - 2) == '\n') out.setLength(out.length() - 1);
        out.append("# The panel creates its own boot environment before installing (finding 185).\n");
        out.append("CreateBootEnv no\n");
        return out.toString();
    }
}
