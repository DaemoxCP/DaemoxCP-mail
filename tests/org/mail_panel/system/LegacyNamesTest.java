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
 * I nomi italiani che le versioni di prima hanno lasciato sui server stanno SOLO nel file di dati
 * legacy-names.json (scelta del committente, 30/10/2026): il codice li chiede a LegacyNames e non
 * li scrive mai.
 *
 * Prima parte: il file si legge dal jar, ha tutte le sezioni che il codice chiede, e ogni coppia
 * va da un nome a un altro. Seconda parte: nessun nome vecchio compare nei sorgenti, fuori dai
 * commenti. Un nome a forma di nome (con trattini, punti, barre, due punti o spazi:
 * "mailpanel-pubblico", "servizi.txt") non deve comparire in nessuna riga di codice, blocchi di
 * testo compresi, ne' del pannello ne' delle prove. Una parola semplice ("attivo") non deve
 * essere una stringa intera nel codice del pannello: nelle prove la stessa parola puo' servire ad
 * altro (english-pages-browser-test.js ha un elenco di parole italiane apposta, per scovarle).
 *
 *   java -cp "tests:&lt;dir&gt;/freebsd-mail-panel-1.0.jar" org.mail_panel.system.LegacyNamesTest &lt;radice dei sorgenti&gt;
 */
public class LegacyNamesTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FALLITO ") + what);
        if (!ok) failed++;
    }

    /** Le sezioni che il codice chiede: se ne manca una, quella migrazione non fa niente. */
    static final String[] SECTIONS = {"files", "vmailFolders", "publicSurface", "bootEnvironmentPrefix",
            "jumpKeys", "jumpStepKeys", "jumpAsks", "jumpPhases", "inventoryFiles", "inventoryServiceStates",
            "javaScriptOutcomes", "reportFrequencies", "reportFailedPrefix",
            "panelSignature", "dovecotSignature", "fail2banFilterSignature", "autoconfigMarker"};

    static int countOf(String text, String part) {
        int n = 0;
        for (int i = text.indexOf(part); i >= 0; i = text.indexOf(part, i + 1)) n++;
        return n;
    }

    /** Le due configurazioni di Dovecot come le scrive lo script (config23 e config24 sono private). */
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
        System.out.println("\n== Il file di dati ==");
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
            check(section + ": " + p.size() + " coppie, ognuna da un nome vecchio a uno diverso, senza doppioni",
                    !p.isEmpty() && distinct && unique);
        }
        check("current(): un nome vecchio diventa quello di adesso, un nome di adesso resta",
                "awaiting-restart".equals(LegacyNames.current("jumpPhases", LegacyNames.oldNamesOf("jumpPhases", "awaiting-restart").get(0)))
                        && "finished".equals(LegacyNames.current("jumpPhases", "finished")));
        check("una sezione che non c'e' e' vuota, non un errore", LegacyNames.pairs("does-not-exist").isEmpty());

        System.out.println("\n== Chi lo usa ==");
        String oldBe = LegacyNames.oldNamesOf("bootEnvironmentPrefix", UpdateManager.BE_PREFIX).get(0);
        check("un boot environment col prefisso di prima e' ancora del pannello",
                UpdateManager.panelBootEnvironment(oldBe + "151-20261020-101010")
                        && UpdateManager.panelBootEnvironment(UpdateManager.BE_PREFIX + "151-20261030-101010")
                        && !UpdateManager.panelBootEnvironment("15.1-RELEASE_2026-10-30_101010")
                        && !UpdateManager.panelBootEnvironment("default"));
        String list = "default\tNR\t/\t2G\t2026-10-01 10:00\n"
                + UpdateManager.BE_PREFIX + "151-20261030-101010\t-\t-\t1G\t2026-10-30 10:10\n"
                + oldBe + "151-20261020-101010\t-\t-\t1G\t2026-10-20 10:10\n";
        check("la via di ritorno piu' recente e' quella col prefisso di adesso, anche se in ordine viene prima",
                (UpdateManager.BE_PREFIX + "151-20261030-101010").equals(UpdateManager.lastPanelBootEnvironment(list)));
        check("  e senza quella, l'ultima col prefisso di prima",
                (oldBe + "151-20261020-101010").equals(UpdateManager.lastPanelBootEnvironment(
                        "default\tNR\t/\t2G\t2026-10-01 10:00\n" + oldBe + "151-20261020-101010\t-\t-\t1G\t2026-10-20 10:10\n")));
        String cat = UpdateManager.inventoryCat("/var/db/mailpanel/system/x", "services.txt");
        check("l'inventario si legge col nome di adesso e poi con quello di prima: " + cat,
                cat.startsWith("cat /var/db/mailpanel/system/x/services.txt 2>/dev/null || cat /var/db/mailpanel/system/x/")
                        && cat.contains(LegacyNames.oldNamesOf("inventoryFiles", "services.txt").get(0)));

        // Le firme: chi rilegge riconosce quella di adesso e quelle di prima, e le righe di prima
        // diventano esattamente quelle che il codice scrive oggi.
        List<String> oldSignatures = LegacyNames.oldNamesOf(PanelMarker.SIGNATURE, PanelMarker.WRITTEN);
        boolean recognized = PanelMarker.writtenByPanel("# " + PanelMarker.WRITTEN + "\n");
        for (String o : oldSignatures) recognized &= PanelMarker.writtenByPanel("# " + o + ".\n[x]\n");
        check("la firma del pannello, di adesso e di prima (" + oldSignatures.size() + "), si riconosce; un file senza no",
                !oldSignatures.isEmpty() && recognized && !PanelMarker.writtenByPanel("# il mio file\n[x]\n"));
        boolean same = true;
        for (String o : oldSignatures)
            for (String now : List.of(WebProtection.configuration("/c", "/k"), WebProtection.filter(), WebProtection.jail()))
                same &= now.contains(PanelMarker.WRITTEN)
                        && PanelMarker.current(now.replace(PanelMarker.WRITTEN, o), PanelMarker.SIGNATURE).equals(now);
        check("i tre file della 443 con una firma di prima tornano identici a quelli di oggi", same);
        check("  ma solo nei commenti: una riga che non e' un commento resta com'era",
                PanelMarker.current("x = " + oldSignatures.get(0) + "\n", PanelMarker.SIGNATURE).contains(oldSignatures.get(0)));
        check("la nota dei blocchi e il file del ramo hanno la firma di adesso",
                UpdateManager.lockNoteText(List.of("nginx"), "2026-10-30T01:00:00Z").startsWith("# " + PanelMarker.WRITTEN)
                        && PkgBranch.MARK.equals("# " + PanelMarker.WRITTEN));
        String dovecotOld = LegacyNames.oldNamesOf(PanelMarker.DOVECOT, org.mail_panel.scripts.DovecotConfig.SIGNATURE).get(0);
        String options = UpdateManager.dovecotSignatureOptions();
        check("la manutenzione cerca in dovecot.conf la firma di adesso e quella di prima: " + options,
                options.contains("-e '" + org.mail_panel.scripts.DovecotConfig.SIGNATURE + "'") && options.contains("-e '" + dovecotOld + "'"));
        check("il generatore di Dovecot scrive la firma di adesso, nelle due versioni",
                countOf(dovecotScripts(), "— " + org.mail_panel.scripts.DovecotConfig.SIGNATURE + "\n") == 2);
        String autoconfigOld = LegacyNames.oldNamesOf("autoconfigMarker", Autoconfig.MARKER).get(0);
        check("il blocco di autoconfig si riconosce col marcatore di adesso e con quello di prima",
                Autoconfig.hasBlock("server {\n" + Autoconfig.MARKER + "\n") && Autoconfig.hasBlock("server {\n    " + autoconfigOld + "\n")
                        && !Autoconfig.hasBlock("server {\n    location / {}\n"));

        System.out.println("\n== Nei sorgenti, fuori dal file di dati ==");
        Path root = Path.of(args.length > 0 ? args[0] : ".");
        List<Path> files = new ArrayList<>();
        for (String dir : new String[]{"src/main/java", "src/main/resources/pages", "tests"}) {
            Path d = root.resolve(dir);
            if (!Files.isDirectory(d)) continue;
            try (Stream<Path> s = Files.walk(d)) {
                s.filter(p -> p.toString().endsWith(".java") || p.toString().endsWith(".js")).forEach(files::add);
            }
        }
        check("trovati i sorgenti in " + root.toAbsolutePath() + " (" + files.size() + " file)", files.size() > 100);
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
        check("nessuno dei " + oldNames.size() + " nomi di prima e' scritto nel codice", found.isEmpty());

        System.out.println(failed == 0 ? "\nTUTTO OK" : "\n" + failed + " PROVE FALLITE");
        if (failed > 0) System.exit(1);
    }
}
