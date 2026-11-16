package org.mail_panel.system;

import org.mail_panel.scripts.DovecotConfig;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

/**
 * Postfix delivers to Dovecot through a socket in its own queue, 0600 postfix's, no longer through port 24 or the
 * 0666 socket in /var/run/dovecot (reperto 234). Against a fake Postfix and a fake Dovecot whose listeners are the
 * ones its configuration declares:
 *  1. what the panel writes now (2.3 and 2.4) is exactly LmtpSocket.NEW, with no TCP listener; the installers set
 *     Postfix's transport to the socket; last_valid_uid/gid are added only to the panel's two lines;
 *  2. the move from the block of before (2.3 and 2.4): DONE, Postfix on the socket, port 24 closed, the base socket
 *     root only, the queue flushed; the second run does nothing;
 *  3. what does not start: a block that is not the panel's, Postfix delivering somewhere else, no Dovecot config;
 *  4. a fault in each of the first two steps (doveconf refuses, no socket after the reload, the probe fails,
 *     Postfix refuses the transport): everything back as it was, port 24 still the way, Postfix on it;
 *  5. a fault in the last step (Dovecot refuses closing port 24): INCOMPLETE, the middle state works (both ways),
 *     and the next run finishes;
 *  6. the process killed after step 1 and after step 2: the next run finishes, mail always had a way.
 *   java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.LmtpSocketTest
 */
public class LmtpSocketTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static final Path MASTER = Path.of("/fake/conf.d/10-master.conf");
    static final Path MAIN = Path.of("/fake/dovecot.conf");
    static final String MAIN23 = "protocols = imap lmtp sieve\nlisten = *, ::\nfirst_valid_uid = 5000\nfirst_valid_gid = 5000\nsendmail_path = /usr/local/sbin/sendmail\n";
    static final String MAIN24 = "dovecot_config_version = 2.4.0\nprotocols = imap lmtp\n" + MAIN23.substring(MAIN23.indexOf("listen"));
    static final String AROUND = "service imap-login {\n}\n\n%s\nservice auth {\n}\n";

    /** Dovecot and Postfix: the files, the transport, and what is listening after the last reload. */
    static final class Machine implements LmtpSocket.Services {
        final Map<Path, String> files = new HashMap<>();
        String transport = LmtpSocket.OLD_TRANSPORT;
        // what Dovecot listens on now (set by reload from the written config)
        boolean port24 = true, postfixSocket = false, baseOpen = true;
        String refuse;      // step to fail: "doveconf", "reload", "probe", "transport", "close"
        String kill;        // step to die at: "after-step1", "after-step2"
        int writes = 0, flushed = 0;

        Machine(String master, String main) { files.put(MASTER, master); files.put(MAIN, main); }

        @Override public String read(Path f) { return files.get(f); }
        @Override public void write(Path f, String text) throws IOException {
            if ("after-step2".equals(kill) && f.equals(MASTER) && text.contains(LmtpSocket.NEW) && !text.contains("port = 24"))
                throw new RuntimeException("killed before closing port 24");
            writes++;
            files.put(f, text);
        }
        @Override public String transport() { return transport; }
        @Override public boolean setTransport(String t) {
            if ("transport".equals(refuse) && LmtpSocket.TRANSPORT.equals(t)) return false;
            if ("after-step1".equals(kill) && LmtpSocket.TRANSPORT.equals(t)) throw new RuntimeException("killed before Postfix moved");
            transport = t;
            return true;
        }
        @Override public boolean dovecotAccepts() {
            if ("doveconf".equals(refuse)) return false;
            return !("close".equals(refuse) && closingPort24());
        }
        private boolean closingPort24() {
            String m = files.get(MASTER);
            return m.contains(LmtpSocket.NEW) && !m.contains("port = 24");
        }
        @Override public boolean dovecotReload(boolean expectSocket) {
            String m = files.get(MASTER);
            if ("reload".equals(refuse) && m.contains("dovecot-lmtp")) { postfixSocket = false; return false; }
            port24 = m.contains("port = 24");
            postfixSocket = m.contains("unix_listener /var/spool/postfix/private/dovecot-lmtp");
            baseOpen = m.contains("mode = 0666");
            return !expectSocket || postfixSocket;
        }
        @Override public String probe() {
            if ("probe".equals(refuse)) return "LMTP RCPT TO: 550 no such user";
            return postfixSocket ? null : "no socket";
        }
        @Override public boolean port24Listening() { return port24; }
        @Override public boolean baseSocketRootOnly() { return !baseOpen; }
        @Override public void flushQueue() { flushed++; }

        /** Mail has a way: Postfix's transport is one Dovecot listens on. */
        boolean mailFlows() {
            return LmtpSocket.TRANSPORT.equals(transport) ? postfixSocket : port24;
        }
        boolean moved() {
            return LmtpSocket.TRANSPORT.equals(transport) && postfixSocket && !port24 && !baseOpen
                    && files.get(MASTER).contains(LmtpSocket.NEW) && !files.get(MASTER).contains("port = 24");
        }
        boolean asBefore(String master, String main) {
            return LmtpSocket.OLD_TRANSPORT.equals(transport) && port24 && files.get(MASTER).equals(master) && files.get(MAIN).equals(main);
        }
    }

    static LmtpSocket.Result run(Machine m) {
        return LmtpSocket.run(m, MASTER, MAIN);
    }

    public static void main(String[] args) {
        System.out.println("== 1. What the panel writes now");
        StringBuilder c24 = new StringBuilder();
        for (DovecotConfig.FileConf f : DovecotConfig.file24()) c24.append(f.content()).append('\n');
        String fragment = DovecotConfig.fromPanelConfig().scriptFragment();
        check("2.4: the block is LmtpSocket.NEW, no TCP listener for LMTP", c24.toString().contains(LmtpSocket.NEW)
                && !c24.toString().contains("inet_listener lmtp"));
        check("2.3 (the script): the same block, no TCP listener for LMTP", fragment.contains(LmtpSocket.NEW)
                && !fragment.contains("inet_listener lmtp"));
        check("  the socket in Postfix's queue, 0600, postfix:postfix; the base socket 0600", LmtpSocket.NEW.contains(
                "unix_listener /var/spool/postfix/private/dovecot-lmtp {\n    mode = 0600\n    user = postfix\n    group = postfix\n  }")
                && LmtpSocket.NEW.contains("unix_listener lmtp {\n    mode = 0600\n  }"));
        check("  last_valid_uid/gid = 5000 in both", c24.toString().contains("last_valid_uid = 5000\nlast_valid_gid = 5000")
                && fragment.contains("last_valid_uid = 5000\nlast_valid_gid = 5000"));
        check("the installers set Postfix's transport to the socket",
                new org.mail_panel.scripts.FullMailServerScript().getScriptContent().contains("virtual_transport = lmtp:unix:private/dovecot-lmtp")
                        && new org.mail_panel.scripts.FullMailStackScript().getScriptContent().contains("virtual_transport = lmtp:unix:private/dovecot-lmtp")
                        && !new org.mail_panel.scripts.FullMailServerScript().getScriptContent().contains("lmtp:inet:127.0.0.1:24"));
        check("withUidRange: added after the panel's two lines", LmtpSocket.withUidRange(MAIN23).contains(
                "first_valid_uid = 5000\nfirst_valid_gid = 5000\nlast_valid_uid = 5000\nlast_valid_gid = 5000\nsendmail_path"));
        check("  not twice, not on a file without them, not on one that already has a last_valid",
                LmtpSocket.withUidRange(LmtpSocket.withUidRange(MAIN23)).equals(LmtpSocket.withUidRange(MAIN23))
                        && LmtpSocket.withUidRange("listen = *\n").equals("listen = *\n")
                        && LmtpSocket.withUidRange(MAIN23 + "last_valid_uid = 6000\n").equals(MAIN23 + "last_valid_uid = 6000\n"));

        System.out.println("\n== 2. From the block of before");
        for (String v : new String[]{"2.3", "2.4"}) {
            String master = String.format(AROUND, "2.3".equals(v) ? LmtpSocket.OLD23 : LmtpSocket.OLD24);
            String main = "2.3".equals(v) ? MAIN23 : MAIN24;
            Machine m = new Machine(master, main);
            LmtpSocket.Result r = run(m);
            check(v + ": DONE (" + r.detail() + ")", r.outcome() == LmtpSocket.Outcome.DONE);
            check("  Postfix on the socket, port 24 closed, the base socket root only, mail flows", m.moved() && m.mailFlows());
            check("  the rest of 10-master.conf untouched", m.files.get(MASTER).equals(String.format(AROUND, LmtpSocket.NEW)));
            check("  last_valid_uid/gid added", m.files.get(MAIN).contains("last_valid_uid = 5000\nlast_valid_gid = 5000"));
            check("  " + ("2.4".equals(v) ? "the middle state used listen = (2.4)" : "the middle state used address = (2.3)"),
                    LmtpSocket.transition("2.4".equals(v)).contains("2.4".equals(v) ? "listen = 127.0.0.1" : "address = 127.0.0.1"));
            check("  the queue flushed", m.flushed == 1);
            int w = m.writes;
            r = run(m);
            check("  a second run: NOTHING, nothing written", r.outcome() == LmtpSocket.Outcome.NOTHING && m.writes == w);
        }

        System.out.println("\n== 3. What does not start");
        Machine own = new Machine(String.format(AROUND, LmtpSocket.OLD23.replace("mode = 0666", "mode = 0660")), MAIN23);
        LmtpSocket.Result r = run(own);
        check("a block that is not the panel's: LEFT, nothing written", r.outcome() == LmtpSocket.Outcome.LEFT && own.writes == 0
                && own.transport.equals(LmtpSocket.OLD_TRANSPORT));
        Machine other = new Machine(String.format(AROUND, LmtpSocket.OLD23), MAIN23);
        other.transport = "lmtp:inet:10.0.0.5:24";
        r = run(other);
        check("Postfix delivering somewhere else: LEFT, nothing written", r.outcome() == LmtpSocket.Outcome.LEFT && other.writes == 0);
        Machine none = new Machine(null, null);
        check("no Dovecot configuration: NOTHING", run(none).outcome() == LmtpSocket.Outcome.NOTHING);

        System.out.println("\n== 4. A fault in the first two steps: back as it was");
        for (String fault : new String[]{"doveconf", "reload", "probe", "transport"}) {
            String master = String.format(AROUND, LmtpSocket.OLD23);
            Machine m = new Machine(master, MAIN23);
            m.refuse = fault;
            r = run(m);
            check(fault + ": ROLLED_BACK (" + r.detail() + ")", r.outcome() == LmtpSocket.Outcome.ROLLED_BACK);
            check("  files, transport and port 24 as before; mail flows", m.asBefore(master, MAIN23) && m.mailFlows());
            m.refuse = null;
            r = run(m);
            check("  the next run: DONE", r.outcome() == LmtpSocket.Outcome.DONE && m.moved());
        }

        System.out.println("\n== 5. A fault in the last step");
        Machine c = new Machine(String.format(AROUND, LmtpSocket.OLD24), MAIN24);
        c.refuse = "close";
        r = run(c);
        check("INCOMPLETE (" + r.detail() + ")", r.outcome() == LmtpSocket.Outcome.INCOMPLETE);
        check("  Postfix on the socket, Dovecot listens both ways: mail flows", LmtpSocket.TRANSPORT.equals(c.transport) && c.postfixSocket
                && c.port24 && c.mailFlows() && c.files.get(MASTER).contains(LmtpSocket.transition(true)));
        c.refuse = null;
        r = run(c);
        check("  the next run finishes: DONE", r.outcome() == LmtpSocket.Outcome.DONE && c.moved());

        System.out.println("\n== 6. Killed half way");
        for (String when : new String[]{"after-step1", "after-step2"}) {
            Machine k = new Machine(String.format(AROUND, LmtpSocket.OLD23), MAIN23);
            k.kill = when;
            boolean died = false;
            try { run(k); } catch (RuntimeException e) { died = true; }
            check(when + ": the process dies, and mail still flows", died && k.mailFlows());
            k.kill = null;
            r = run(k);
            check("  the next run: DONE (" + r.detail() + ")", r.outcome() == LmtpSocket.Outcome.DONE && k.moved() && k.mailFlows());
        }

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
