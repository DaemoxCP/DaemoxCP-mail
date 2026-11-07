package org.mail_panel.system;

import org.mail_panel.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * rspamd tutto con l'utente rspamd, anche il processo principale.
 *
 * Misurato il 07/11/2026 sul server vero: "rspamd: main process" gira da root, i worker come rspamd.
 * Dal sorgente di rspamd (src/rspamd.c, detect_priv; src/libserver/worker_util.c): da root il processo
 * principale apre le porte, prepara i log e cede i privilegi solo ai worker con -u/-g; avviato
 * direttamente da un utente qualunque gira con quello, e -u/-g non contano. Qui root non serve a niente:
 * le porte sono 11332-11334 (sopra la 1023), e pid, log e database (/var/run/rspamd, /var/log/rspamd,
 * /var/db/rspamd) sono gia' di rspamd. Lo script rc.d del port usa rc.subr, che con rspamd_user avvia il
 * comando come quell'utente (su -m): e' il modo previsto, senza toccare lo script.
 *
 * Si cambia solo se il processo principale gira da root e rspamd_user non e' gia' scritto. Dopo il
 * riavvio: tutti i processi di rspamd sono suoi, le tre porte ascoltano, il controller risponde e una
 * scansione vera da' un'azione. Se no rspamd_user si toglie e rspamd riparte come prima.
 */
public final class RspamdUser {

    private static final Logger LOGGER = Logger.getLogger(RspamdUser.class.getName());

    static final String RSPAMC = "/usr/local/bin/rspamc";
    static final String USER = "rspamd";
    static final List<String> PORTS = List.of("127.0.0.1:11332", "127.0.0.1:11333", "127.0.0.1:11334");

    /** Un messaggio qualunque da far analizzare: deve tornare un'azione, qualunque sia. */
    static final String PROBE = "From: probe@mailpanel.invalid\nTo: probe@mailpanel.invalid\nSubject: mailpanel rspamd probe\n"
            + "Message-ID: <rspamd-probe@mailpanel.invalid>\n\nThis message only checks that rspamd answers.\n";

    private RspamdUser() {}

    /** Gli utenti dei processi di rspamd: la riga del processo principale per prima, se c'e'. */
    static List<String[]> processes() {
        List<String[]> out = new ArrayList<>();
        for (String l : Shell.run(Duration.ofSeconds(10), "ps", "-axww", "-o", "user=", "-o", "command=").outputTrim().split("\n")) {
            String[] p = l.trim().split("\\s+", 2);
            if (p.length == 2 && p[1].startsWith("rspamd: ")) out.add(p);
        }
        return out;
    }

    static String mainUser() {
        for (String[] p : processes()) if (p[1].startsWith("rspamd: main process")) return p[0];
        return null;
    }

    public static void ensureAtBoot() {
        try {
            if (!Files.isExecutable(Path.of("/usr/local/bin/rspamd"))) return;
            if (!"root".equals(mainUser())) return;   // spento, o gia' con il suo utente
            Shell.Result rcUser = Shell.run(Duration.ofSeconds(10), "sysrc", "-n", "rspamd_user");
            if (rcUser.success() && !rcUser.outputTrim().isEmpty()) {
                LOGGER.info("[RspamdUser] rspamd_user is already set to '" + rcUser.outputTrim() + "' but the main process runs"
                        + " as root: left as it is");
                return;
            }
            if (Shell.run(Duration.ofSeconds(10), "id", "-u", USER).exitCode() != 0) return;
            apply();
        } catch (Throwable t) {
            LOGGER.warning("[RspamdUser] ensureAtBoot exception: " + t.getMessage());
        }
    }

    static boolean apply() throws Exception {
        String before = scan();
        if (before == null) {
            LOGGER.warning("[RspamdUser] rspamd does not scan a message before any change: left as it is");
            return false;
        }
        // L'ordine conta. Con rspamd_user scritto, rc.subr manda anche i segnali di stop come quell'utente,
        // e allora non riesce a fermare il processo principale che gira da root ("kill: No such process"),
        // e l'avvio trova rspamd "already running". Misurato sulla VM il 07/11/2026. Quindi: si ferma
        // con l'impostazione di prima, si scrive rspamd_user, si avvia; e per tornare indietro lo stesso
        // al contrario.
        if (!stop()) {
            Shell.run(Duration.ofSeconds(120), "service", "rspamd", "start");
            LOGGER.warning("[RspamdUser] NOT_APPLIED: rspamd did not stop within 120 seconds; started again as it was");
            return false;
        }
        Shell.run(Duration.ofSeconds(10), "sysrc", "rspamd_user=" + USER);
        Shell.run(Duration.ofSeconds(120), "service", "rspamd", "start");
        String problem = verify();
        if (problem != null) {
            stop();
            Shell.run(Duration.ofSeconds(10), "sysrc", "-x", "rspamd_user");
            Shell.run(Duration.ofSeconds(120), "service", "rspamd", "start");
            Thread.sleep(3000);
            String again = scan() != null ? "rspamd scans again" : "rspamd DOES NOT SCAN";
            LOGGER.warning("[RspamdUser] ROLLED_BACK: " + problem + "; rspamd_user removed and rspamd restarted (" + again + ")");
            return false;
        }
        LOGGER.info("[RspamdUser] DONE: rspamd runs entirely as " + USER + ", the main process no longer as root"
                + " (rspamd_user in rc.conf); a real scan checked");
        return true;
    }

    /** Ferma rspamd con l'impostazione di adesso e aspetta che il processo principale non ci sia piu'. */
    static boolean stop() throws InterruptedException {
        Shell.run(Duration.ofSeconds(120), "service", "rspamd", "stop");
        for (int i = 0; i < 60; i++) {
            if (mainUser() == null) return true;
            Thread.sleep(1000);
        }
        return false;
    }

    /** Dopo il riavvio: tutti i processi suoi, le porte aperte, una scansione vera. */
    static String verify() throws InterruptedException {
        for (int i = 0; i < 30; i++) {
            Thread.sleep(1000);
            List<String[]> ps = processes();
            boolean hasMain = ps.stream().anyMatch(p -> p[1].startsWith("rspamd: main process"));
            boolean allOwn = !ps.isEmpty() && ps.stream().allMatch(p -> USER.equals(p[0]));
            String listening = Shell.run(Duration.ofSeconds(15), "sockstat", "-4l").outputTrim();
            boolean ports = PORTS.stream().allMatch(listening::contains);
            if (hasMain && allOwn && ports && scan() != null) return null;
            if (i == 29) {
                if (!hasMain) return "rspamd is not running after the restart";
                if (!allOwn) return "rspamd processes still as " + ps.stream().map(p -> p[0]).distinct().toList();
                if (!ports) return "rspamd does not listen on " + PORTS;
                return "rspamd does not scan a message after the restart";
            }
        }
        return "unreachable";
    }

    /** Una scansione vera sul worker normale: l'azione che rspamd decide, o null. */
    static String scan() {
        try {
            Path f = Files.createTempFile(Path.of("/var/tmp"), "rspamd-probe-", ".eml");
            try {
                Files.writeString(f, PROBE);
                Shell.Result r = Shell.runShell(Duration.ofSeconds(30), RSPAMC + " -h 127.0.0.1:11333 symbols < " + f);
                for (String l : r.outputTrim().split("\n"))
                    if (l.trim().startsWith("Action:")) return l.trim().substring(7).trim();
                return null;
            } finally {
                Files.deleteIfExists(f);
            }
        } catch (Exception e) {
            return null;
        }
    }
}
