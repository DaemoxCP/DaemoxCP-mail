package org.mail_panel.security;

import org.mail_panel.scripts.FullMailServerScript;

import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * pf: that a fail2ban block really stops a packet.
 *
 * The defect, measured on a freshly installed FreeBSD 15.1 with the mail panel installed and
 * running:
 *
 *   fail2ban says:    203.0.113.77
 *   pf has:           pfctl: /dev/pf: No such file or directory
 *   /etc/pf.conf:     does not exist
 *
 * That is, fail2ban detects, declares the block, and the packet goes through. It is the worst
 * case: it leaves no trace to notice it from, because a firewall that does not block looks the
 * same as a machine nobody is trying on.
 *
 * What must be tested here, and that reading the code would not tell:
 *  - pf **accepts** the pf.conf the installation writes: the text is not looked at, "pfctl -nf" is
 *    really run;
 *  - that pf.conf **cannot lock anybody out**. It is not an opinion on the text: pfctl is made to
 *    print the rules as it understood them, and the only block must be the one of the permanent
 *    blocks table and the default must be "pass";
 *  - the order matters: the anchor must come BEFORE the pass, otherwise the pass wins and the
 *    block is never applied;
 *  - the diagnosis says which piece is missing, and in the right order: without the module in the
 *    kernel, looking at pf.conf makes no sense.
 *
 * It runs on the VM, where pfctl talks to the kernel:
 *   java -cp "tests:&lt;dir&gt;/freebsd-mail-panel-1.0.jar" org.mail_panel.security.PfSetupTest
 */
public class PfSetupTest {

    static int failed = 0;
    static final PrintStream OUT = System.out;

    static void check(String what, boolean ok) {
        OUT.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        Path home = Files.createTempDirectory("pf-setup");
        String script = new FullMailServerScript().getScriptContent();

        OUT.println("\n== The diagnosis: which piece is missing, and in the order that matters ==");
        check("everything in place: no reason",
                Fail2banAutoSetup.whyBansWouldNotBite(true, true, true, true).isEmpty());
        check("without the module in the kernel, it says so (and it is the first: without it, pfctl"
                + " does not even talk to the kernel)",
                Fail2banAutoSetup.whyBansWouldNotBite(false, true, true, true).contains("kernel module"));
        check("the module is blamed before everything else",
                Fail2banAutoSetup.whyBansWouldNotBite(false, false, false, false).contains("kernel module"));
        check("without /etc/pf.conf, it says so",
                Fail2banAutoSetup.whyBansWouldNotBite(true, false, true, true).contains("/etc/pf.conf does not exist"));
        check("without the anchor, it says so",
                Fail2banAutoSetup.whyBansWouldNotBite(true, true, false, true).contains("f2b/*"));
        check("with pf off, it says so",
                Fail2banAutoSetup.whyBansWouldNotBite(true, true, true, false).contains("Status: Disabled"));
        // No incomplete combination must give "all is well": it is what the panel did, that is
        // keeping quiet.
        int silences = 0;
        for (int c = 0; c < 16; c++) {
            boolean m = (c & 1) != 0, f = (c & 2) != 0, a = (c & 4) != 0, e = (c & 8) != 0;
            boolean everything = m && f && a && e;
            if (!everything && Fail2banAutoSetup.whyBansWouldNotBite(m, f, a, e).isEmpty()) silences++;
        }
        check("none of the 15 incomplete combinations passes in silence", silences == 0);

        OUT.println("\n== The installation sets up pf ==");
        // The line is looked for in the form the script writes it: if it is not found, indexOf
        // gives -1, which is less than everything, and the check would pass without looking.
        int fail2banInstall = script.indexOf("install_packages security/py-fail2ban");
        check("it does it after installing fail2ban",
                fail2banInstall >= 0 && fail2banInstall < script.indexOf("Setting up pf"));
        check("and before configuring MySQL, that is inside the installation and not after",
                script.indexOf("Setting up pf") < script.indexOf("[PHASE 3/10]"));
        check("inside a FreeBSD jail it does not try",
                script.contains("security.jail.jailed") && script.contains("belongs to the host"));
        check("and if ipfw is already there it does not switch on a second firewall by surprise",
                script.contains("ipfw.ko") && script.contains("already has a firewall"));
        check("an /etc/pf.conf already there is not rewritten, and pf is NOT enabled",
                script.contains("left untouched, and pf NOT enabled"));
        check("it tests the syntax before switching on", script.contains("pfctl -nf /etc/pf.conf"));
        // The restart is not fussiness: the pf action creates its own rule in "actionstart", only
        // once. If pf was not there that time, fail2ban never tries again, and from then on the bans
        // create a table WITHOUT the rule that reads it -- that is nothing, while fail2ban-client
        // says "Banned IP list". Measured on a reinstallation.
        check("it restarts fail2ban instead of just starting it",
                script.contains("service fail2ban restart"));
        check("and it does it AFTER setting up pf, not before",
                script.indexOf("Setting up pf") < script.indexOf("service fail2ban restart"));
        check("and afterwards it looks at \"Status: Enabled\", not at the exit code (pfctl -s info exits 0"
                + " even with pf off)", script.contains("grep -q \"Status: Enabled\""));
        Path generated = home.resolve("install.sh");
        Files.writeString(generated, script, StandardCharsets.UTF_8);
        check("the generated script passes sh -n", run("/bin/sh", "-n", generated.toString()) == 0);

        OUT.println("\n== The pf.conf it writes: pf accepts it, and it blocks no service ==");
        String pfConf = between(script, "cat > /etc/pf.conf << 'PFCONF'\n", "\nPFCONF\n");
        check("there is a pf.conf in the script", pfConf != null && !pfConf.isBlank());
        if (pfConf == null) { OUT.println("\n" + (++failed) + " CHECKS FAILED"); System.exit(1); }
        check("the anchor comes BEFORE the pass (after it, the pass would win and the block would"
                + " never apply)", pfConf.indexOf("anchor \"f2b/*\"") < pfConf.lastIndexOf("\npass"));

        if (!Files.isExecutable(Path.of("/sbin/pfctl"))) {
            check("pfctl is there (this test must be run on the VM, not on the Mac)", false);
            OUT.println("\n" + failed + " CHECKS FAILED");
            System.exit(1);
        }
        // Without the pf module in the kernel, pfctl does not talk to the kernel and whatever it is
        // asked fails with "Failed to open netlink": the checks below would say "pfctl refused the
        // file" while the file was never read. Telling the two cases apart is the point: one is a
        // wrong pf.conf, the other a machine without pf.
        if (!Fail2banAutoSetup.pfModuleLoaded()) {
            check("the pf module is loaded — without it, pfctl reads NOTHING and the checks below"
                    + " would measure not the pf.conf but the missing module: kldload pf", false);
            OUT.println("\n" + failed + " CHECKS FAILED");
            System.exit(1);
        }
        // The list of the permanent blocks must exist, otherwise pfctl refuses the table persist
        // file: it is the same order the script keeps.
        Files.createDirectories(Path.of("/var/db/mail-panel"));
        if (!Files.exists(Path.of("/var/db/mail-panel/permaban.list")))
            Files.writeString(Path.of("/var/db/mail-panel/permaban.list"), "");
        Path candidate = home.resolve("pf.conf");
        Files.writeString(candidate, pfConf + "\n", StandardCharsets.UTF_8);
        check("pfctl -nf accepts it", run("/sbin/pfctl", "-nf", candidate.toString()) == 0);

        // The text is not judged: pfctl is made to print the rules as it understood them.
        List<String> rules = rulesAsPfParsesThem(candidate);
        for (String r : rules) OUT.println("      " + r);
        List<String> blocks = new ArrayList<>();
        for (String r : rules) if (r.startsWith("block")) blocks.add(r);
        check("pf sees a single block, and it is the panel's permanent blocks: "
                + blocks.size() + " block(s)", blocks.size() == 1 && blocks.get(0).contains("<permaban>"));
        boolean passesAll = false;
        for (String r : rules) if (r.startsWith("pass all") || r.equals("pass")) passesAll = true;
        check("and the default is to pass everything: switching pf on locks nobody out", passesAll);
        boolean anchorBeforePass = false;
        int iAnchor = -1, iPass = -1;
        for (int i = 0; i < rules.size(); i++) {
            if (rules.get(i).startsWith("anchor") && rules.get(i).contains("f2b/")) iAnchor = i;
            if (rules.get(i).startsWith("pass")) iPass = i;
        }
        anchorBeforePass = iAnchor >= 0 && iPass >= 0 && iAnchor < iPass;
        check("for pf too, the anchor is before the pass", anchorBeforePass);
        check("and the panel recognises its own anchor in that file",
                Fail2banAutoSetup.hasF2bAnchor(pfConf));

        OUT.println("\n" + (failed == 0 ? "ALL GREEN" : failed + " CHECKS FAILED"));
        System.exit(failed == 0 ? 0 : 1);
    }

    /** The rules as pf understood them: "pfctl -nvf" prints them again normalized. */
    static List<String> rulesAsPfParsesThem(Path file) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("/sbin/pfctl", "-nvf", file.toString());
        pb.redirectErrorStream(true);
        Process p = pb.start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        p.waitFor();
        List<String> rules = new ArrayList<>();
        for (String line : out.split("\n")) {
            String t = line.trim();
            if (t.isEmpty() || t.startsWith("#")) continue;
            rules.add(t);
        }
        return rules;
    }

    static int run(String... command) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        int code = p.waitFor();
        if (code != 0) OUT.print(out);
        return code;
    }

    static String between(String text, String start, String end) {
        int a = text.indexOf(start);
        if (a < 0) return null;
        int b = text.indexOf(end, a + start.length());
        return b < 0 ? null : text.substring(a + start.length(), b);
    }
}
