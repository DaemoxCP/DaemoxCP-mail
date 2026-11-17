package org.daemoxcp.mail.system;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * clamd's socket only for the group clamav, 0660, with rspamd in that group (reperto 237). Against a fake clamd whose
 * socket gets the mode its clamd.conf says when it starts, and a fake rspamd that reaches it only if the socket is open
 * to everyone or rspamd was started in the group clamav:
 *  1. the installer appends exactly ClamdSocket.BLOCK and puts rspamd in the group before clamd and rspamd start;
 *     the EICAR probe is the real test string with 1 to 40 trailing blanks, never the same twice, and the jar does not
 *     carry it in clear;
 *  2. from the package's clamd.conf (the VM's, with LocalSocket twice): DONE, the socket 0660, rspamd in the group and
 *     still finding EICAR; the second run does nothing;
 *  3. what does not start: a group or mode already set, another socket, no clamd.conf, clamd or rspamd not answering;
 *  4. a fault (the group not really taken, clamd not coming back, rspamd not scanning after joining): everything back,
 *     byte for byte, the socket 0666 again, rspamd out of the group and finding EICAR;
 *  5. rspamd without the antivirus: DONE all the same, and said.
 *   java -cp "tests:target/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.system.ClamdSocketTest
 */
public class ClamdSocketTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static final Path CONF = Path.of("/fake/clamd.conf");
    /** The socket lines of the VM's clamd.conf (ClamAV 1.5.4, 16/11/2026): LocalSocket twice, group and mode commented. */
    static final String PACKAGE = "# Path to a local socket file the daemon will listen on.\nLocalSocket /var/run/clamav/clamd.sock\n"
            + "LocalSocket /var/run/clamav/clamd.sock\n\n#LocalSocketGroup virusgroup\n\n#LocalSocketMode 660\n\nFixStaleSocket yes\nUser clamav\n";

    static class Machine implements ClamdSocket.Services {
        final Map<Path, String> files = new HashMap<>();
        final Set<String> clamavGroup = new HashSet<>();
        boolean socket660 = false, clamdUp = true, rspamdInGroup = false, antivirus = true;
        String fault;   // "group-lies", "clamd-down", "rspamd-down"
        int clamdRestarts = 0, rspamdRestarts = 0, probes = 0;

        Machine(String conf) { if (conf != null) files.put(CONF, conf); }

        @Override public String read(Path f) { return files.get(f); }
        @Override public void write(Path f, String text) { files.put(f, text); }
        @Override public boolean isMember(String g, String u) { return clamavGroup.contains(u); }
        @Override public boolean setMember(String g, String u, boolean m) {
            if ("group-lies".equals(fault)) return true;
            if (m) clamavGroup.add(u); else clamavGroup.remove(u);
            return true;
        }
        @Override public boolean restartRspamd() {
            rspamdRestarts++;
            rspamdInGroup = clamavGroup.contains("rspamd");
            return !"rspamd-down".equals(fault);
        }
        @Override public boolean restartClamd() {
            clamdRestarts++;
            if ("clamd-down".equals(fault)) { clamdUp = false; return false; }
            clamdUp = true;
            String c = files.get(CONF);
            socket660 = c.contains("\nLocalSocketMode 660\n") && c.contains("\nLocalSocketGroup clamav\n");
            return true;
        }
        @Override public boolean socketGroupOnly() { return clamdUp && socket660; }
        @Override public boolean rspamdFindsEicar() {
            probes++;
            return antivirus && clamdUp && (!socket660 || rspamdInGroup);
        }
        @Override public boolean clamdAnswers() { return clamdUp; }
        @Override public boolean rspamdScans() { return !"rspamd-down".equals(fault); }
    }

    static ClamdSocket.Result run(Machine m) { return ClamdSocket.run(m, CONF); }

    public static void main(String[] args) throws IOException {
        System.out.println("== 1. What the installer writes, and the probe");
        String installer = new org.daemoxcp.mail.scripts.FullMailServerScript().getScriptContent();
        check("clamd.conf gets ClamdSocket.BLOCK once, guarded", installer.contains("\n" + ClamdSocket.BLOCK + "CLAMD_SOCKET\n")
                && installer.contains("grep -qF 'reperto 237' /usr/local/etc/clamd.conf"));
        int member = installer.indexOf("pw groupmod clamav -m rspamd");
        check("rspamd in the group clamav before clamd and rspamd start", member > 0 && member < installer.indexOf("service clamav_clamd start")
                && member < installer.indexOf("service rspamd start"));
        check("BLOCK: group clamav, mode 660", ClamdSocket.BLOCK.endsWith("LocalSocketGroup clamav\nLocalSocketMode 660\n"));
        String e1 = ClamdSocket.eicar(), e2 = ClamdSocket.eicar();
        String eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR" + "-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        check("the probe starts with the EICAR test string", e1.startsWith(eicar) && e2.startsWith(eicar));
        check("  followed by 1 to 40 blanks, and at most 128 bytes", e1.substring(68).matches("[ \\t]{1,40}") && e1.length() <= 128);
        boolean differ = false;
        for (int i = 0; i < 20 && !differ; i++) differ = !ClamdSocket.eicar().equals(e1);
        check("  never the same twice (rspamd caches the result per attachment)", differ);
        check("  the message is MIME with it as an attachment", ClamdSocket.eicarMessage().contains("Content-Disposition: attachment"));
        byte[] cls = ClamdSocket.class.getResourceAsStream("ClamdSocket.class").readAllBytes();
        check("  the class file does not carry it in clear", !new String(cls, java.nio.charset.StandardCharsets.ISO_8859_1).contains("EICAR-STANDARD"));

        System.out.println("\n== 2. From the package's clamd.conf");
        Machine m = new Machine(PACKAGE);
        ClamdSocket.Result r = run(m);
        check("DONE (" + r.detail() + ")", r.outcome() == ClamdSocket.Outcome.DONE);
        check("  clamd.conf: the package's text, then BLOCK", m.files.get(CONF).equals(PACKAGE + "\n" + ClamdSocket.BLOCK));
        check("  the socket 0660, rspamd in the group, finding EICAR", m.socket660 && m.rspamdInGroup && m.rspamdFindsEicar());
        int restarts = m.clamdRestarts + m.rspamdRestarts;
        r = run(m);
        check("  a second run: NOTHING, nothing restarted", r.outcome() == ClamdSocket.Outcome.NOTHING && m.clamdRestarts + m.rspamdRestarts == restarts);
        Machine fresh = new Machine(PACKAGE + "\n" + ClamdSocket.BLOCK);
        fresh.clamavGroup.add("rspamd");
        fresh.restartClamd();
        fresh.restartRspamd();
        fresh.clamdRestarts = 0;
        r = run(fresh);
        check("the installer's state: NOTHING", r.outcome() == ClamdSocket.Outcome.NOTHING && fresh.clamdRestarts == 0);

        System.out.println("\n== 3. What does not start");
        for (String[] c : new String[][]{
                {"a group already set", PACKAGE.replace("#LocalSocketGroup virusgroup", "LocalSocketGroup virusgroup")},
                {"a mode already set", PACKAGE.replace("#LocalSocketMode 660", "LocalSocketMode 600")},
                {"another socket", PACKAGE.replace("LocalSocket /var/run/clamav/clamd.sock\n\n", "LocalSocket /tmp/clamd.sock\n\n")},
                {"no LocalSocket", PACKAGE.replace("LocalSocket /var/run/clamav/clamd.sock\n", "")}}) {
            Machine x = new Machine(c[1]);
            r = run(x);
            check(c[0] + ": LEFT, untouched, nothing restarted", r.outcome() == ClamdSocket.Outcome.LEFT && x.files.get(CONF).equals(c[1])
                    && x.clamdRestarts == 0 && x.clamavGroup.isEmpty());
        }
        check("no clamd.conf: NOTHING", run(new Machine(null)).outcome() == ClamdSocket.Outcome.NOTHING);
        Machine off = new Machine(PACKAGE);
        off.clamdUp = false;
        r = run(off);
        check("clamd not answering: LEFT, untouched", r.outcome() == ClamdSocket.Outcome.LEFT && off.files.get(CONF).equals(PACKAGE) && off.clamdRestarts == 0);
        Machine noRspamd = new Machine(PACKAGE);
        noRspamd.fault = "rspamd-down";
        r = run(noRspamd);
        check("rspamd not scanning: LEFT, untouched", r.outcome() == ClamdSocket.Outcome.LEFT && noRspamd.files.get(CONF).equals(PACKAGE));

        System.out.println("\n== 4. A fault: everything back");
        for (String fault : new String[]{"group-lies", "clamd-down"}) {
            Machine x = new Machine(PACKAGE);
            x.fault = fault;
            r = run(x);
            boolean outcome = "clamd-down".equals(fault) ? r.outcome() == ClamdSocket.Outcome.INCOMPLETE : r.outcome() == ClamdSocket.Outcome.ROLLED_BACK;
            check(fault + ": " + r.outcome() + " (" + r.detail() + ")", outcome);
            x.fault = null;
            x.restartClamd();
            check("  the file byte for byte, rspamd out of the group, the socket 0666, EICAR found", x.files.get(CONF).equals(PACKAGE)
                    && !x.clamavGroup.contains("rspamd") && !x.socket660 && x.rspamdFindsEicar());
        }
        Machine afterJoin = new Machine(PACKAGE) {
            @Override public boolean restartRspamd() {
                super.restartRspamd();
                return rspamdRestarts > 1;   // the first restart (after joining) does not come back to scanning
            }
        };
        r = run(afterJoin);
        check("rspamd not scanning after joining: ROLLED_BACK, untouched, out of the group", r.outcome() == ClamdSocket.Outcome.ROLLED_BACK
                && afterJoin.files.get(CONF).equals(PACKAGE) && !afterJoin.clamavGroup.contains("rspamd") && afterJoin.clamdRestarts <= 1);

        System.out.println("\n== 5. rspamd without the antivirus");
        Machine noAv = new Machine(PACKAGE);
        noAv.antivirus = false;
        r = run(noAv);
        check("DONE, saying it (" + r.detail() + ")", r.outcome() == ClamdSocket.Outcome.DONE && r.detail().contains("did not find EICAR before")
                && noAv.socket660);

        System.out.println("\n== packageLike");
        check("the VM's (LocalSocket twice): yes", ClamdSocket.packageLike(PACKAGE));
        check("two different sockets: no", !ClamdSocket.packageLike(PACKAGE + "LocalSocket /tmp/x.sock\n"));

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
