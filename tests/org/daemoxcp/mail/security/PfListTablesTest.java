package org.daemoxcp.mail.security;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * The allow and block lists of the Firewall page in pf (PfFirewallManager.tableLine). Found walking every function of
 * the 0.9.0 panel on FreeBSD 15.1 (18/11/2026): the last address taken off a list stayed in pf until a restart,
 * because an empty list was written as "table <x> persist" with no braces, and pf keeps a table's contents when the
 * anchor is loaded again with such a line.
 *
 *  1. The line: an empty list is "{ }", one or more addresses are listed in the braces.
 *  2. On the VM, as root (-De2e.vm=yes): the real pfctl, in an anchor of its own that no rule uses. A table with one
 *     address, loaded again with the line of an empty list, is empty; loaded again with the line of 0.9.0 (no braces)
 *     it keeps the address, which is the defect this test sees. The anchor is flushed and its table killed at the end.
 *
 * Usage: java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.security.PfListTablesTest [-De2e.vm=yes]
 */
public class PfListTablesTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static final String ANCHOR = "daemoxcp-test-lists";
    static final String TABLE = "test_list_cidrs";
    static final String ADDRESS = "198.51.100.88";

    public static void main(String[] args) throws Exception {
        System.out.println("== 1. The line of a table ==");
        check("an empty list: { }", "table <panel_bl_cidrs> persist { }\n".equals(PfFirewallManager.tableLine("panel_bl_cidrs", List.of())));
        check("one address", "table <panel_wl_cidrs> persist { 198.51.100.7 }\n".equals(PfFirewallManager.tableLine("panel_wl_cidrs", List.of("198.51.100.7"))));
        check("two, comma separated", "table <panel_wl_cidrs> persist { 198.51.100.7, 203.0.113.0/24 }\n"
                .equals(PfFirewallManager.tableLine("panel_wl_cidrs", List.of("198.51.100.7", "203.0.113.0/24"))));
        check("never a line without braces, never a comment inside them", !PfFirewallManager.tableLine("x", List.of()).contains("#"));

        if (!"yes".equals(System.getProperty("e2e.vm")) || !"root".equals(System.getProperty("user.name"))) {
            System.out.println("\n(2. needs the VM, as root, with -De2e.vm=yes: skipped)");
        } else {
            System.out.println("\n== 2. The real pfctl, in an anchor of its own ==");
            Path dir = Files.createTempDirectory("pf-lists");
            try {
                Path full = dir.resolve("full.conf"), empty = dir.resolve("empty.conf"), old = dir.resolve("old.conf");
                Files.writeString(full, PfFirewallManager.tableLine(TABLE, List.of(ADDRESS)));
                Files.writeString(empty, PfFirewallManager.tableLine(TABLE, List.of()));
                Files.writeString(old, "table <" + TABLE + "> persist  # the line of 0.9.0\n");
                check("pfctl accepts the line of an empty list", run("/sbin/pfctl", "-a", ANCHOR, "-nf", empty.toString()) == 0);
                load(full);
                check("loaded with one address: pf has it", show().contains(ADDRESS));
                load(empty);
                check("loaded again as an empty list: the table is empty", show().isBlank());
                load(full);
                load(old);
                check("(the line of 0.9.0, without braces, kept the address: the defect this test sees)", show().contains(ADDRESS));
            } finally {
                run("/sbin/pfctl", "-a", ANCHOR, "-F", "all");
                run("/sbin/pfctl", "-a", ANCHOR, "-t", TABLE, "-T", "kill");
                try (var s = Files.list(dir)) { for (Path p : s.toList()) Files.deleteIfExists(p); }
                Files.deleteIfExists(dir);
            }
            check("the anchor is left empty", output("/sbin/pfctl", "-a", ANCHOR, "-s", "Tables").isBlank());
        }
        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        if (failed > 0) System.exit(1);
    }

    static void load(Path conf) throws Exception {
        if (run("/sbin/pfctl", "-a", ANCHOR, "-f", conf.toString()) != 0) throw new IllegalStateException("pfctl refused " + conf);
    }

    static String show() throws Exception {
        return output("/sbin/pfctl", "-a", ANCHOR, "-t", TABLE, "-T", "show").trim();
    }

    static int run(String... cmd) throws Exception {
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
        return p.waitFor(30, TimeUnit.SECONDS) ? p.exitValue() : -1;
    }

    static String output(String... cmd) throws Exception {
        Process p = new ProcessBuilder(cmd).redirectError(ProcessBuilder.Redirect.DISCARD).start();
        String out = new String(p.getInputStream().readAllBytes());
        p.waitFor(30, TimeUnit.SECONDS);
        return out;
    }
}
