package org.mail_panel.system;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * The Italian names that the older versions left on the servers live ONLY in the data file
 * legacy-names.json (the committente's choice, 30/10/2026): the code asks LegacyNames for them and
 * never writes them.
 *
 * First part: the file is read from the jar, it has every section the code asks for, and every pair
 * goes from one name to another. Second part: no old name appears in the sources, outside the
 * comments. A name shaped like a name (with dashes, dots, slashes, colons or spaces:
 * "mailpanel-pubblico", "servizi.txt") must not appear in any line of code, text blocks included,
 * of the panel or of the tests. A plain word ("attivo") must not be a whole string in the panel's
 * code: in the tests the same word may serve another purpose (english-pages-browser-test.js has a
 * list of Italian words on purpose, to catch them).
 *
 *   java -cp "tests:&lt;dir&gt;/freebsd-mail-panel-1.0.jar" org.mail_panel.system.LegacyNamesTest &lt;source root&gt;
 */
public class LegacyNamesTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    /** The sections the code asks for: if one is missing, that migration does nothing. */
    static final String[] SECTIONS = {"files", "vmailFolders", "publicSurface", "publicFolder", "bootEnvironmentPrefix",
            "jumpKeys", "jumpStepKeys", "jumpAsks", "jumpPhases", "inventoryFiles", "inventoryServiceStates",
            "javaScriptOutcomes", "reportFrequencies", "reportFailedPrefix",
            "panelSignature", "dovecotSignature", "fail2banFilterSignature", "autoconfigMarker",
            "damagedComments"};

    static int countOf(String text, String part) {
        int n = 0;
        for (int i = text.indexOf(part); i >= 0; i = text.indexOf(part, i + 1)) n++;
        return n;
    }

    /** Dovecot's two configurations as the script writes them (config23 and config24 are private). */
    static String dovecotScripts() throws Exception {
        StringBuilder b = new StringBuilder();
        for (String m : new String[]{"config23", "config24"}) {
            java.lang.reflect.Method x = org.mail_panel.scripts.DovecotConfig.class.getDeclaredMethod(m);
            x.setAccessible(true);
            b.append((String) x.invoke(null));
        }
        return b.toString();
    }

    public static void main(String[] args) throws Exception {
        System.out.println("\n== The data file ==");
        List<String> oldNames = new ArrayList<>();
        for (String section : SECTIONS) {
            List<String[]> p = LegacyNames.pairs(section);
            Set<String> seen = new HashSet<>();
            boolean distinct = true, unique = true;
            for (String[] x : p) {
                distinct &= !x[0].isEmpty() && !x[0].equals(x[1]);
                unique &= seen.add(x[0]);
                oldNames.add(x[0]);
            }
            check(section + ": " + p.size() + " pairs, each from an old name to a different one, no duplicates",
                    !p.isEmpty() && distinct && unique);
        }
        check("current(): an old name becomes today's, a name of today stays",
                "awaiting-restart".equals(LegacyNames.current("jumpPhases", LegacyNames.oldNamesOf("jumpPhases", "awaiting-restart").get(0)))
                        && "finished".equals(LegacyNames.current("jumpPhases", "finished")));
        check("a section that is not there is empty, not an error", LegacyNames.pairs("does-not-exist").isEmpty());

        System.out.println("\n== Who uses it ==");
        String oldBe = LegacyNames.oldNamesOf("bootEnvironmentPrefix", UpdateManager.BE_PREFIX).get(0);
        check("a boot environment with the old prefix still belongs to the panel",
                UpdateManager.panelBootEnvironment(oldBe + "151-20261020-101010")
                        && UpdateManager.panelBootEnvironment(UpdateManager.BE_PREFIX + "151-20261030-101010")
                        && !UpdateManager.panelBootEnvironment("15.1-RELEASE_2026-10-30_101010")
                        && !UpdateManager.panelBootEnvironment("default"));
        String list = "default\tNR\t/\t2G\t2026-10-01 10:00\n"
                + UpdateManager.BE_PREFIX + "151-20261030-101010\t-\t-\t1G\t2026-10-30 10:10\n"
                + oldBe + "151-20261020-101010\t-\t-\t1G\t2026-10-20 10:10\n";
        check("the most recent way back is the one with today's prefix, even if it comes first in the list",
                (UpdateManager.BE_PREFIX + "151-20261030-101010").equals(UpdateManager.lastPanelBootEnvironment(list)));
        check("  and without it, the last one with the old prefix",
                (oldBe + "151-20261020-101010").equals(UpdateManager.lastPanelBootEnvironment(
                        "default\tNR\t/\t2G\t2026-10-01 10:00\n" + oldBe + "151-20261020-101010\t-\t-\t1G\t2026-10-20 10:10\n")));
        String cat = UpdateManager.inventoryCat("/var/db/mailpanel/system/x", "services.txt");
        check("the inventory is read with today's name and then with the old one: " + cat,
                cat.startsWith("cat /var/db/mailpanel/system/x/services.txt 2>/dev/null || cat /var/db/mailpanel/system/x/")
                        && cat.contains(LegacyNames.oldNamesOf("inventoryFiles", "services.txt").get(0)));

        // The signatures: whoever reads back recognises today's and the old ones, and the old lines
        // become exactly the ones the code writes today.
        List<String> oldSignatures = LegacyNames.oldNamesOf(PanelMarker.SIGNATURE, PanelMarker.WRITTEN);
        boolean recognized = PanelMarker.writtenByPanel("# " + PanelMarker.WRITTEN + "\n");
        for (String o : oldSignatures) recognized &= PanelMarker.writtenByPanel("# " + o + ".\n[x]\n");
        check("the panel's signature, today's and the old ones (" + oldSignatures.size() + "), is recognised; a file without it is not",
                !oldSignatures.isEmpty() && recognized && !PanelMarker.writtenByPanel("# my file\n[x]\n"));
        boolean same = true;
        for (String o : oldSignatures)
            for (String now : List.of(WebProtection.configuration("/c", "/k"), WebProtection.filter(), WebProtection.jail()))
                same &= now.contains(PanelMarker.WRITTEN)
                        && PanelMarker.current(now.replace(PanelMarker.WRITTEN, o), PanelMarker.SIGNATURE).equals(now);
        check("the three files of the 443 with an old signature come back identical to today's", same);
        check("  but only in the comments: a line that is not a comment stays as it was",
                PanelMarker.current("x = " + oldSignatures.get(0) + "\n", PanelMarker.SIGNATURE).contains(oldSignatures.get(0)));
        check("the locks note and the branch file have today's signature",
                UpdateManager.lockNoteText(List.of("nginx"), "2026-10-30T01:00:00Z").startsWith("# " + PanelMarker.WRITTEN)
                        && PkgBranch.MARK.equals("# " + PanelMarker.WRITTEN));
        String dovecotOld = LegacyNames.oldNamesOf(PanelMarker.DOVECOT, org.mail_panel.scripts.DovecotConfig.SIGNATURE).get(0);
        String options = UpdateManager.dovecotSignatureOptions();
        check("maintenance looks in dovecot.conf for today's signature and the old one: " + options,
                options.contains("-e '" + org.mail_panel.scripts.DovecotConfig.SIGNATURE + "'") && options.contains("-e '" + dovecotOld + "'"));
        check("the Dovecot generator writes today's signature, in both versions",
                countOf(dovecotScripts(), "— " + org.mail_panel.scripts.DovecotConfig.SIGNATURE + "\n") == 2);
        String autoconfigOld = LegacyNames.oldNamesOf("autoconfigMarker", Autoconfig.MARKER).get(0);
        check("the autoconfig block is recognised with today's marker and with the old one",
                Autoconfig.hasBlock("server {\n" + Autoconfig.MARKER + "\n") && Autoconfig.hasBlock("server {\n    " + autoconfigOld + "\n")
                        && !Autoconfig.hasBlock("server {\n    location / {}\n"));

        System.out.println("\n== In the sources, outside the data file ==");
        Path root = Path.of(args.length > 0 ? args[0] : ".");
        List<Path> files = new ArrayList<>();
        for (String dir : new String[]{"src/main/java", "src/main/resources/pages", "tests"}) {
            Path d = root.resolve(dir);
            if (!Files.isDirectory(d)) continue;
            try (Stream<Path> s = Files.walk(d)) {
                s.filter(p -> p.toString().endsWith(".java") || p.toString().endsWith(".js")).forEach(files::add);
            }
        }
        check("sources found in " + root.toAbsolutePath() + " (" + files.size() + " files)", files.size() > 100);
        Pattern literal = Pattern.compile("\"((?:[^\"\\\\\\n]|\\\\.)*)\"|'((?:[^'\\\\\\n]|\\\\.)*)'");
        List<String> found = new ArrayList<>();
        for (Path f : files) {
            List<String> lines = Files.readAllLines(f);
            for (int i = 0; i < lines.size(); i++) {
                String line = lines.get(i), t = line.trim();
                if (t.startsWith("//") || t.startsWith("*") || t.startsWith("/*")) continue;
                int cut = line.indexOf(" // ");
                String code = cut >= 0 ? line.substring(0, cut) : line;
                boolean panel = !root.relativize(f).toString().startsWith("tests");
                for (String old : oldNames) {
                    boolean shaped = old.matches(".*[-._/:= ].*");
                    boolean hit = false;
                    if (shaped) hit = code.contains(old);
                    else if (panel) {
                        Matcher m = literal.matcher(code);
                        while (m.find() && !hit) hit = old.equals(m.group(1) != null ? m.group(1) : m.group(2));
                    }
                    if (hit) found.add(root.relativize(f) + ":" + (i + 1) + "  \"" + old + "\"");
                }
            }
        }
        found.stream().limit(15).forEach(x -> System.out.println("        " + x));
        check("none of the " + oldNames.size() + " old names is written in the code", found.isEmpty());

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        if (failed > 0) System.exit(1);
    }
}
