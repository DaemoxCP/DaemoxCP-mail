package org.daemoxcp.mail.system;

import org.daemoxcp.mail.scripts.DovecotConfig;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * The three Dovecot sockets open to anyone (0666) that the panel does not use, closed (DovecotSockets): indexer 0660
 * root:vmail, imap-urlauth and auth-token 0600 root; dns-client stays.
 *  1. the decision: only on Dovecot 2.4; no file or another file: write it; the right file with sockets still open: a
 *     restart; the right file and the right sockets: nothing;
 *  2. the file: the three listeners in their own services (imap-urlauth in imap-urlauth-login: in imap-urlauth Dovecot
 *     does not start, seen on the VM), signed by the panel; the installer and the move to 2.4 write the same file;
 *  3. with -De2e.vm=yes (as root on the TEST VM, Dovecot 2.4 running, before the panel itself applied it): the mistake
 *     that stopped Dovecot on the VM (the imap-urlauth listener in the imap-urlauth service) written by the migration:
 *     doveconf accepts it, the restart does not, and the migration must take the file away and bring Dovecot back, with
 *     authentication, LMTP and IMAP answering and the sockets as before.
 *   java [-De2e.vm=yes] -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.DovecotSocketsTest
 */
public class DovecotSocketsTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        String right = DovecotSockets.fileContent();
        System.out.println("== 1. The decision");
        check("Dovecot 2.3: nothing (not tried there)", DovecotSockets.decide("2.3.21.1 (d492236fa0)", null, List.of("indexer rw-rw-rw-"))
                == DovecotSockets.Action.NOT_24);
        check("2.4 without the file: write it", DovecotSockets.decide("2.4.5 (0cbb641e3e)", null, List.of("indexer rw-rw-rw-"))
                == DovecotSockets.Action.APPLY);
        check("2.4 with another file: write it", DovecotSockets.decide("2.4.5", "service indexer {}\n", List.of())
                == DovecotSockets.Action.APPLY);
        check("2.4, the right file, sockets still open (never restarted): restart", DovecotSockets.decide("2.4.5", right,
                List.of("auth-token rw-rw-rw-")) == DovecotSockets.Action.RESTART_ONLY);
        check("2.4, the right file and the right sockets: nothing", DovecotSockets.decide("2.4.5", right, List.of())
                == DovecotSockets.Action.NOTHING);

        System.out.println("\n== 2. The file");
        check("indexer 0660 root:vmail", right.contains("service indexer {\n  unix_listener indexer {\n    mode = 0660\n    user = root\n    group = vmail\n"));
        check("imap-urlauth in imap-urlauth-login, 0600", right.contains("service imap-urlauth-login {\n  unix_listener imap-urlauth {\n    mode = 0600\n"));
        check("auth-token in auth, 0600", right.contains("service auth {\n  unix_listener auth-token {\n    mode = 0600\n"));
        check("dns-client not touched", !right.contains("dns-client"));
        check("signed by the panel", right.startsWith("# " + PanelMarker.WRITTEN));
        check("the 2.4 installation and the move to 2.4 write it", DovecotConfig.file24().stream().anyMatch(f ->
                f.path().equals("conf.d/" + DovecotSockets.FILE_NAME) && f.content().equals(right)));

        if (!"yes".equals(System.getProperty("e2e.vm"))) {
            System.out.println("\n  (part 3 skipped: it restarts Dovecot, turned on with -De2e.vm=yes on the TEST VM)");
        } else {
            System.out.println("\n== 3. The migration takes back a file Dovecot refuses at the restart");
            Path file = Path.of(DovecotAuthWorker.CONF_D, DovecotSockets.FILE_NAME);
            check("before: Dovecot answers, no file of the panel's, the sockets open", DovecotSockets.verifyRunning() == null
                    && !Files.exists(file) && !DovecotSockets.wrong(DovecotSockets.RUN).isEmpty());
            String mistake = right.replace("service imap-urlauth-login {", "service imap-urlauth {");
            long t0 = System.currentTimeMillis();
            boolean applied = DovecotSockets.apply(file, mistake);
            System.out.println("    (" + (System.currentTimeMillis() - t0) / 1000 + " s)");
            check("the mistake is not applied", !applied);
            check("the file is taken away", !Files.exists(file));
            check("Dovecot runs again: authentication, LMTP and IMAP answer", DovecotSockets.verifyRunning() == null);
            check("the sockets as before (open, Dovecot's own)", DovecotSockets.wrong(DovecotSockets.RUN).size() == DovecotSockets.WANTED.size());
        }
        System.out.println("\n" + (failed == 0 ? "ALL OK" : failed + " CHECKS FAILED"));
        System.exit(failed == 0 ? 0 : 1);
    }
}
