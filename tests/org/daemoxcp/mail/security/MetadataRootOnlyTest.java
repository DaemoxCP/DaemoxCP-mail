package org.daemoxcp.mail.security;

import java.time.Duration;
import java.util.List;

import org.daemoxcp.mail.util.Shell;

/**
 * The provider's metadata service only for root, on the VM's live pf (PfPolicy.METADATA_RULE). On the real server, on
 * 18/11/2026, Hetzner's metadata service handed out in plain text the configuration the server was created with, an
 * initial root password included, to any program on the machine: www, the panel's web part, Roundcube.
 *
 *  1. The live rules (pfctl -sr) block 169.254.169.254 for every user but root, TCP and UDP.
 *  2. As www: a connection to it is refused at once ("Connection refused", within 2 seconds).
 *  3. As root: pf does not refuse it (the VM has no metadata service: a timeout or another error, never "refused").
 *  4. As www, another link-local address on the same route is not refused: the rule names only that address.
 *
 * Usage, on the VM as root, after the panel has started with PfPolicy (it writes and loads the rule at its start):
 *   java -De2e.vm=yes -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.security.MetadataRootOnlyTest
 */
public class MetadataRootOnlyTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    /**
     * A block with «return» on a socket of the machine itself shows up as EACCES («Permission denied»), measured on the
     * VM on 18/11/2026; a refusal from the other side would be «Connection refused». Both mean: not let through.
     */
    record Try(String output, long millis) {
        boolean refused() { return output.contains("Permission denied") || output.contains("Connection refused"); }
    }

    /** A live rule (pfctl -sr writes «block return out quick inet proto tcp from any to ... user != 0»). */
    static boolean blocks(String rule, String proto) {
        String t = rule.trim();
        return t.startsWith("block return out quick") && t.contains("proto " + proto) && t.contains("to 169.254.169.254") && t.endsWith("user != 0");
    }

    /** fetch with a short timeout, as that user (root: directly), and how long it took. */
    static Try fetch(String user, String url) {
        long t = System.nanoTime();
        Shell.Result r = "root".equals(user) ? Shell.run(Duration.ofSeconds(20), "fetch", "-T", "4", "-o", "/dev/null", url)
                : Shell.run(Duration.ofSeconds(20), "su", "-m", user, "-c", "fetch -T 4 -o /dev/null " + url);
        return new Try(r.outputTrim(), (System.nanoTime() - t) / 1_000_000);
    }

    public static void main(String[] args) {
        if (!"yes".equals(System.getProperty("e2e.vm")) || !"root".equals(System.getProperty("user.name"))) {
            System.out.println("(needs the VM, as root, with -De2e.vm=yes: skipped)");
            return;
        }
        System.out.println("== 1. The live rules ==");
        List<String> rules = Shell.run(Duration.ofSeconds(15), "/sbin/pfctl", "-sr").output().lines()
                .filter(l -> l.contains("169.254.169.254")).toList();
        rules.forEach(l -> System.out.println("         " + l.trim()));
        check("TCP and UDP to 169.254.169.254 blocked with a refusal for every user but root",
                rules.stream().anyMatch(l -> blocks(l, "tcp")) && rules.stream().anyMatch(l -> blocks(l, "udp")));

        System.out.println("\n== 2. As www ==");
        Try www = fetch("www", "http://169.254.169.254/hetzner/v1/metadata");
        check("refused at once (" + www.millis() + " ms: " + www.output() + ")", www.refused() && www.millis() < 2000);

        System.out.println("\n== 3. As root ==");
        Try root = fetch("root", "http://169.254.169.254/hetzner/v1/metadata");
        check("not refused by pf (" + root.millis() + " ms: " + root.output() + ")", !root.refused());

        System.out.println("\n== 4. Another address, as www ==");
        Try other = fetch("www", "http://169.254.169.253/");
        check("not refused: the rule names only the metadata address (" + other.millis() + " ms: " + other.output() + ")", !other.refused());

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        if (failed > 0) System.exit(1);
    }
}
