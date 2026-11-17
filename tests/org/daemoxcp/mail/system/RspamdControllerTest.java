package org.daemoxcp.mail.system;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * rspamd's controller only with the panel's password (reperto 236). Against a fake rspamd that, after a reload, lets
 * 127.0.0.1 and ::1 in without a password unless override.d sets secure_ip = [], and checks the password against the
 * hash in the file:
 *  1. the file: the hash in password and enable_password, secure_ip empty, the mark first; the hash only if it looks
 *     like rspamadm pw's; new passwords are long, URL-safe and never the same;
 *  2. from the package's controller: DONE, the secret stored, 401 without the password on both addresses, 200 with
 *     it; the second run does nothing;
 *  3. what does not start: a file the panel did not write, the admin's own password or secure_ip in local.d (override.d
 *     would silently win over them), the controller not answering, rspamadm giving no hash;
 *  4. a fault (configtest refuses, the reload does not take it, the file cannot be written): the file gone, the old
 *     secret back, the controller as before;
 *  5. the panel's file but the secret lost, or a wrong one: a new password, DONE; ::1 not listening: DONE.
 *   java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.RspamdControllerTest
 */
public class RspamdControllerTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static final Path FILE = Path.of("/fake/override.d/worker-controller.inc");
    static final Path LOCAL = Path.of("/fake/local.d/worker-controller.inc");

    /** A fake hash in rspamadm pw's alphabet: the password in lowercase hex. */
    static String fakeHash(String password) {
        StringBuilder b = new StringBuilder("$2$saltsaltsalt$");
        for (byte c : password.getBytes(java.nio.charset.StandardCharsets.US_ASCII)) b.append(String.format("%02x", c));
        return b.toString();
    }

    static class Machine implements RspamdController.Services {
        final Map<Path, String> files = new HashMap<>();
        String secret = "";
        // what the controller does now (set by the last reload from the file)
        String hash = null;            // null: the package's "q1" in clear, secure_ip localhost
        boolean secureIpEmpty = false;
        boolean up = true, v6 = true;
        String fault;                  // "configtest", "reload", "write", "hash"
        final Set<String> secretsSeen = new HashSet<>();
        int reloads = 0;

        @Override public String read(Path f) { return files.get(f); }
        @Override public void write(Path f, String text) throws IOException {
            if ("write".equals(fault)) throw new IOException("disk full");
            files.put(f, text);
        }
        @Override public void delete(Path f) { files.remove(f); }
        @Override public String secret() { return secret; }
        @Override public void setSecret(String v) { secret = v == null ? "" : v; secretsSeen.add(secret); }
        @Override public String hash(String password) { return "hash".equals(fault) ? "Usage: rspamadm lua" : fakeHash(password); }
        @Override public boolean configOk() { return !"configtest".equals(fault); }
        @Override public void reload() {
            reloads++;
            if ("reload".equals(fault)) return;
            String f = files.get(FILE);
            if (f == null) { hash = null; secureIpEmpty = false; return; }
            java.util.regex.Matcher mm = java.util.regex.Pattern.compile("(?m)^password = \"([^\"]+)\";$").matcher(f);
            hash = mm.find() ? mm.group(1) : null;
            secureIpEmpty = f.contains("\nsecure_ip = [];\n");
        }
        @Override public int status(String host, String password) {
            if (!up) return -1;
            if (host.equals("[::1]") && !v6) return -1;
            if (!secureIpEmpty) return 200;                       // localhost is secure_ip
            if (password == null) return 401;
            if (hash == null) return "q1".equals(password) ? 200 : 401;
            return fakeHash(password).equals(hash) ? 200 : 401;
        }
    }

    static RspamdController.Result run(Machine m) { return RspamdController.run(m, FILE, LOCAL, 2); }

    public static void main(String[] args) {
        System.out.println("== 1. The file and the password");
        String h = fakeHash("abc");
        String t = RspamdController.text(h);
        check("the mark first", t.startsWith(RspamdController.MARK));
        check("the hash in password and enable_password, secure_ip empty", t.contains("\npassword = \"" + h + "\";\n")
                && t.contains("\nenable_password = \"" + h + "\";\n") && t.endsWith("\nsecure_ip = [];\n"));
        check("a real rspamadm pw hash is accepted", RspamdController.HASH.matcher(
                "$2$hpxgi4y7e8wqdrxfpxepkagnippdcaaa$ct7s8sjbp6grh3rm3ecior6b8rkjofsok7s1rg5q59hr8skkr3gb").matches());
        check("a usage message, a hash with a quote or a newline is not", !RspamdController.HASH.matcher("Usage: rspamadm").matches()
                && !RspamdController.HASH.matcher("$2$abcdefgh$\"; secure_ip = [\"0.0.0.0/0\"]").matches()
                && !RspamdController.HASH.matcher("$2$abcdefgh$abcdefghijklmnopq\n").matches());
        String p1 = RspamdController.newPassword(), p2 = RspamdController.newPassword();
        check("passwords: 32 URL-safe characters, never the same", p1.matches("[A-Za-z0-9_-]{32}") && !p1.equals(p2));

        System.out.println("\n== 2. From the package's controller");
        Machine m = new Machine();
        check("before: in without a password", m.status("127.0.0.1", null) == 200 && m.status("[::1]", null) == 200);
        RspamdController.Result r = run(m);
        check("DONE (" + r.detail() + ")", r.outcome() == RspamdController.Outcome.DONE);
        check("  the secret stored, the file with its hash", !m.secret.isEmpty() && m.files.get(FILE).equals(RspamdController.text(fakeHash(m.secret))));
        check("  401 without the password on 127.0.0.1 and ::1, 200 with it, 401 with q1", m.status("127.0.0.1", null) == 401
                && m.status("[::1]", null) == 401 && m.status("127.0.0.1", m.secret) == 200 && m.status("127.0.0.1", "q1") == 401);
        String secret = m.secret;
        int reloads = m.reloads;
        r = run(m);
        check("  a second run: NOTHING, same password, no reload", r.outcome() == RspamdController.Outcome.NOTHING && m.secret.equals(secret)
                && m.reloads == reloads);

        System.out.println("\n== 3. What does not start");
        Machine own = new Machine();
        own.files.put(FILE, "password = \"$2$x$y\";\n");
        r = run(own);
        check("a file the panel did not write: LEFT, untouched, no secret", r.outcome() == RspamdController.Outcome.LEFT
                && own.files.get(FILE).equals("password = \"$2$x$y\";\n") && own.secret.isEmpty() && own.reloads == 0);
        for (String admin : new String[]{"secure_ip = \"10.0.0.0/8\";\n", "password = \"$2$abc$def\";\n", "  enable_password \"x\";\n",
                "secure_ip [\"192.168.1.0/24\"];\n"}) {
            Machine x = new Machine();
            x.files.put(LOCAL, "bind_socket = \"127.0.0.1:11334\";\n" + admin);
            r = run(x);
            check("local.d with the admin's " + admin.trim() + ": LEFT, nothing written", r.outcome() == RspamdController.Outcome.LEFT
                    && !x.files.containsKey(FILE) && x.secret.isEmpty() && x.reloads == 0);
        }
        Machine bind = new Machine();
        bind.files.put(LOCAL, "bind_socket = \"127.0.0.1:11334\";\n# password = \"q1\";\n");
        check("local.d with only bind_socket (FullMailStackScript) and a comment: DONE", run(bind).outcome() == RspamdController.Outcome.DONE);
        Machine down = new Machine();
        down.up = false;
        r = run(down);
        check("the controller not answering: LEFT, nothing written", r.outcome() == RspamdController.Outcome.LEFT && down.files.isEmpty()
                && down.secret.isEmpty());
        Machine noHash = new Machine();
        noHash.fault = "hash";
        r = run(noHash);
        check("rspamadm giving no hash: LEFT, nothing written", r.outcome() == RspamdController.Outcome.LEFT && noHash.files.isEmpty()
                && noHash.secret.isEmpty());

        System.out.println("\n== 4. A fault: everything back");
        for (String fault : new String[]{"configtest", "reload", "write"}) {
            Machine x = new Machine();
            x.secret = "old-one";
            x.fault = fault;
            r = run(x);
            x.fault = null;
            x.reload();
            check(fault + ": ROLLED_BACK (" + r.detail() + ")", r.outcome() == RspamdController.Outcome.ROLLED_BACK);
            check("  the file gone, the old secret back, the controller as before", !x.files.containsKey(FILE) && x.secret.equals("old-one")
                    && x.status("127.0.0.1", null) == 200);
            check("  the secret was stored before the file was written", x.secretsSeen.size() == 2);
        }

        System.out.println("\n== 5. The panel's file, the secret lost or wrong; ::1 not listening");
        Machine lost = new Machine();
        run(lost);
        String before = lost.secret;
        lost.secret = "";
        r = run(lost);
        check("secret lost: DONE with a new password", r.outcome() == RspamdController.Outcome.DONE && !lost.secret.isEmpty()
                && !lost.secret.equals(before) && lost.status("127.0.0.1", lost.secret) == 200);
        lost.secret = "not-the-one";
        r = run(lost);
        check("a wrong secret: DONE with a new password", r.outcome() == RspamdController.Outcome.DONE && lost.status("127.0.0.1", lost.secret) == 200);
        Machine noV6 = new Machine();
        noV6.v6 = false;
        r = run(noV6);
        check("::1 not listening: DONE", r.outcome() == RspamdController.Outcome.DONE);
        r = run(noV6);
        check("  and then NOTHING", r.outcome() == RspamdController.Outcome.NOTHING);
        Machine noReload = new Machine() {
            @Override public void reload() { reloads++; }   // rspamd never takes the new file
        };
        r = run(noReload);
        check("rspamd never taking the file: ROLLED_BACK, the file gone, no secret", r.outcome() == RspamdController.Outcome.ROLLED_BACK
                && !noReload.files.containsKey(FILE) && noReload.secret.isEmpty());

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
