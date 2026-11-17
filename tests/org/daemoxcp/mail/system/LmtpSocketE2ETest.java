package org.daemoxcp.mail.system;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

import org.daemoxcp.mail.util.Shell;

/**
 * The LMTP move (reperto 234) on the VM's real Dovecot and Postfix, as root with -De2e.vm=yes. The VM must start with
 * the block of before (conf.d/10-master.conf as the installer of main 09924051 wrote it, Postfix on
 * lmtp:inet:127.0.0.1:24) and the mailbox given with -De2e.mailbox (default alice@rehearsal.test).
 *  1. before: port 24 listening, /var/run/dovecot/lmtp open to everyone; `nobody` can talk LMTP (the fault);
 *  2. LmtpSocket.run: DONE; Postfix on lmtp:unix:private/dovecot-lmtp; the socket postfix's 0600; port 24 closed;
 *     /var/run/dovecot/lmtp root's 0600; `nobody` can no longer reach Dovecot's LMTP (neither socket); a real
 *     delivery through Postfix reaches the mailbox through the socket; the second run does nothing;
 *  3. back to the files of before, then a run where Postfix refuses the transport: ROLLED_BACK, port 24 again,
 *     Postfix on it, a delivery still arrives;
 *  4. the move again: DONE (the VM stays as an upgraded server would be).
 *   java -De2e.vm=yes -cp "tests:freebsd-mail-panel-1.0.jar" org.daemoxcp.mail.system.LmtpSocketE2ETest
 */
public class LmtpSocketE2ETest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static String sh(String cmd) {
        return Shell.runShell(Duration.ofSeconds(120), cmd).outputTrim();
    }

    /** `nobody` talks LMTP on that socket: true if Dovecot greets it. */
    static boolean nobodyGreeted(String socket) {
        return sh("su -m nobody -c 'echo QUIT | nc -U -w 3 " + socket + "' 2>&1").contains("220");
    }

    /** A real message through Postfix; true if Dovecot stored it, and through which relay Postfix delivered it. */
    static String deliver(String mailbox, String tag) {
        int before = Integer.parseInt(sh("wc -l < /var/log/maillog").trim());
        sh("printf 'From: root@localhost\\nTo: " + mailbox + "\\nSubject: lmtp-234 " + tag + "\\n\\n" + tag + "\\n' | sendmail -f root " + mailbox);
        for (int i = 0; i < 60; i++) {
            String log = sh("tail -n +" + (before + 1) + " /var/log/maillog");
            if (log.contains("lmtp(" + mailbox + ")") && log.contains("saved mail to INBOX") || log.contains("stored mail into mailbox 'INBOX'")) {
                String relay = sh("tail -n +" + (before + 1) + " /var/log/maillog | grep 'postfix/lmtp' | grep -o 'relay=[^,]*' | tail -1");
                return relay.isEmpty() ? "stored" : relay;
            }
            try { Thread.sleep(1000); } catch (InterruptedException e) { return null; }
        }
        return null;
    }

    public static void main(String[] args) throws Exception {
        if (!"yes".equals(System.getProperty("e2e.vm"))) {
            System.out.println("Turned on with -De2e.vm=yes, as root, on the VM: it changes Dovecot and Postfix.");
            System.exit(0);
        }
        String mailbox = System.getProperty("e2e.mailbox", "alice@rehearsal.test");
        Path master = LmtpSocket.MASTER_CONF, main = LmtpSocket.DOVECOT_CONF;
        String masterBefore = Files.readString(master), mainBefore = Files.readString(main);
        String transportBefore = sh("postconf -h virtual_transport");

        System.out.println("== 1. Before");
        check("the block of before and Postfix on port 24", (masterBefore.contains(LmtpSocket.OLD23) || masterBefore.contains(LmtpSocket.OLD24))
                && LmtpSocket.OLD_TRANSPORT.equals(transportBefore));
        check("port 24 listening", !sh("sockstat -46lq -p 24").isEmpty());
        check("`nobody` is greeted on /var/run/dovecot/lmtp (the fault this fixes)", nobodyGreeted("/var/run/dovecot/lmtp"));

        System.out.println("\n== 2. The move");
        LmtpSocket.Result r = LmtpSocket.run(LmtpSocket.real(), master, main);
        check("DONE (" + r.detail() + ")", r.outcome() == LmtpSocket.Outcome.DONE);
        check("  Postfix on " + LmtpSocket.TRANSPORT, LmtpSocket.TRANSPORT.equals(sh("postconf -h virtual_transport")));
        check("  the socket: postfix:postfix 0600", sh("stat -f '%Su:%Sg %Sp' " + LmtpSocket.SOCKET).equals("postfix:postfix srw-------"));
        check("  port 24 closed", sh("sockstat -46lq -p 24").isEmpty());
        check("  /var/run/dovecot/lmtp: root 0600", sh("stat -f '%Su %Sp' /var/run/dovecot/lmtp").equals("root srw-------"));
        check("  last_valid_uid/gid in doveconf", sh("doveconf -h last_valid_uid last_valid_gid 2>/dev/null").replace("\n", " ").equals("5000 5000"));
        check("  `nobody` is not greeted on either socket", !nobodyGreeted("/var/run/dovecot/lmtp") && !nobodyGreeted(LmtpSocket.SOCKET));
        String how = deliver(mailbox, "after-move");
        check("  a real delivery through Postfix arrives, through the socket (" + how + ")", how != null && how.contains("private/dovecot-lmtp"));
        r = LmtpSocket.run(LmtpSocket.real(), master, main);
        check("  a second run: NOTHING", r.outcome() == LmtpSocket.Outcome.NOTHING);

        System.out.println("\n== 3. Back to before, then a fault: Postfix refuses the transport");
        LmtpSocket.Services real = LmtpSocket.real();
        real.write(master, masterBefore);
        real.write(main, mainBefore);
        real.setTransport(LmtpSocket.OLD_TRANSPORT);
        real.dovecotReload(false);
        check("before again: port 24 listening", !sh("sockstat -46lq -p 24").isEmpty());
        LmtpSocket.Services faulty = new LmtpSocket.Services() {
            @Override public String read(Path f) throws java.io.IOException { return real.read(f); }
            @Override public void write(Path f, String t) throws java.io.IOException { real.write(f, t); }
            @Override public String transport() { return real.transport(); }
            @Override public boolean setTransport(String t) { return !LmtpSocket.TRANSPORT.equals(t) && real.setTransport(t); }
            @Override public boolean dovecotAccepts() { return real.dovecotAccepts(); }
            @Override public boolean dovecotReload(boolean e) { return real.dovecotReload(e); }
            @Override public String probe() { return real.probe(); }
            @Override public boolean port24Listening() { return real.port24Listening(); }
            @Override public boolean baseSocketRootOnly() { return real.baseSocketRootOnly(); }
            @Override public void flushQueue() { real.flushQueue(); }
        };
        r = LmtpSocket.run(faulty, master, main);
        check("ROLLED_BACK (" + r.detail() + ")", r.outcome() == LmtpSocket.Outcome.ROLLED_BACK);
        check("  the files as before, Postfix on port 24, port 24 listening", Files.readString(master).equals(masterBefore)
                && Files.readString(main).equals(mainBefore) && LmtpSocket.OLD_TRANSPORT.equals(sh("postconf -h virtual_transport"))
                && !sh("sockstat -46lq -p 24").isEmpty());
        how = deliver(mailbox, "after-rollback");
        check("  a delivery still arrives (" + how + ")", how != null);

        System.out.println("\n== 4. The move again");
        r = LmtpSocket.run(LmtpSocket.real(), master, main);
        check("DONE (" + r.detail() + ")", r.outcome() == LmtpSocket.Outcome.DONE && sh("sockstat -46lq -p 24").isEmpty());
        how = deliver(mailbox, "final");
        check("  and a delivery arrives through the socket (" + how + ")", how != null && how.contains("private/dovecot-lmtp"));

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
