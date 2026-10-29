package org.mail_panel.system;

import org.mail_panel.scripts.FullMailServerScript;
import org.mail_panel.util.Shell;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * L'installazione completa installa davvero i pacchetti che chiede, e si ferma se pkg ne
 * toglie uno.
 *
 * Il difetto, misurato il 24/10/2026 su FreeBSD 15.1 con un'installazione da zero col jar di
 * main (reperto 52):
 *
 *   pkg install -y dovecot-mysql dovecot-pigeonhole
 *   - dovecot-2.3.21.1_3 conflicts with dovecot-mysql-2.3.21.1_3 on /usr/local/bin/doveadm
 *   Cannot solve problem using SAT solver, trying another plan
 *   New packages to be INSTALLED: dovecot, dovecot-pigeonhole          (codice d'uscita 0)
 *   [SUCCESS] Complete Mail Server Installation completed successfully!
 *
 * e poi, alla prima casella: «auth: Fatal: Support not compiled in for passdb driver 'sql'».
 * Nessun login IMAP, e la 587 chiusa («no SASL authentication mechanisms»).
 *
 * Tre parti, perche' sono tre cose diverse e ognuna puo' sbagliare da sola:
 *
 *  A. il testo dello script: chiede il Dovecot con MySQL e il Pigeonhole COSTRUITO per lui,
 *     e ogni pacchetto passa dalla funzione che controlla;
 *  B. la funzione si comporta come dice: si fanno girare le righe vere dello script contro un
 *     pkg finto che fa la cosa misurata (toglie un pacchetto chiesto ed esce con 0), e lo
 *     script deve fermarsi LI', non arrivare in fondo. Il pkg finto e' l'unico modo di
 *     provare il ramo «pkg mente» senza aspettare che il risolutore lo rifaccia;
 *  C. il risolutore VERO, sul catalogo vero: per ogni riga dello script si chiede a pkg il
 *     piano come su una macchina appena installata (database dei pacchetti vuoto, in una
 *     copia) e coi pacchetti gia' scaricati, perche' i conflitti sui file pkg li vede solo
 *     dopo averli scaricati (reperto 14). Ogni pacchetto chiesto deve stare nel piano finale.
 *     Scarica ~180 MB in una cartella temporanea: si accende con -De2e.vm=yes, da root, su
 *     FreeBSD; non installa niente e non tocca il database vero di pkg.
 *
 * Piu' una parte D sulle etichette dell'updater, perche' l'installazione adesso mette
 * dovecot-mysql e dovecot-pigeonhole-mysql invece dei pacchetti senza sapore.
 *
 * Uso, sulla VM:
 *   java -cp "tests:freebsd-mail-panel-1.0.jar" org.mail_panel.system.InstallPackagesTest
 *   java -De2e.vm=yes -cp "tests:freebsd-mail-panel-1.0.jar" org.mail_panel.system.InstallPackagesTest
 */
public class InstallPackagesTest {

    static int failures = 0, skipped = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK       " : "  FALLITO  ") + what);
        if (!ok) failures++;
    }

    public static void main(String[] args) throws Exception {
        String script = new FullMailServerScript().getScriptContent();
        List<List<String>> lines = installLines(script);

        scriptText(script, lines);
        functionBehaviour(script);
        if ("yes".equals(System.getProperty("e2e.vm"))) {
            if (onFreeBsdAsRoot()) realSolver(lines);
            else { skipped++; System.out.println("\n  SALTATA  parte C: serve FreeBSD e root"); }
        } else {
            skipped++;
            System.out.println("\n  SALTATA  parte C: scarica ~180 MB, si accende con -De2e.vm=yes (FreeBSD, root)");
        }
        updaterLabels();

        System.out.println(failures == 0 ? "\nTUTTO OK" + (skipped > 0 ? " (" + skipped + " parti saltate, dette sopra)" : "")
                                         : "\n" + failures + " PROVE FALLITE");
        if (failures > 0) System.exit(1);
    }

    // ------------------------------------------------------------------ A

    static void scriptText(String script, List<List<String>> lines) {
        System.out.println("\n== A. Il testo dello script ==");
        Set<String> asked = new LinkedHashSet<>();
        for (List<String> l : lines) asked.addAll(l);
        System.out.println("  righe d'installazione trovate: " + lines.size() + ", pacchetti chiesti: " + asked.size());

        check("chiede dovecot-mysql (l'autenticazione delle caselle sta in MySQL)", asked.contains("dovecot-mysql"));
        check("chiede dovecot-pigeonhole-mysql, il Sieve costruito per dovecot-mysql",
                asked.contains("dovecot-pigeonhole-mysql"));
        check("non chiede dovecot-pigeonhole, che dipende da \"dovecot\" senza MySQL", !asked.contains("dovecot-pigeonhole"));
        check("non chiede \"dovecot\" senza sapore", !asked.contains("dovecot"));
        check("dovecot-mysql e il suo Pigeonhole stanno sulla STESSA riga (un solo piano, un solo controllo)",
                lines.stream().anyMatch(l -> l.contains("dovecot-mysql") && l.contains("dovecot-pigeonhole-mysql")));

        int def = script.indexOf("\ninstall_packages() {");
        int firstUse = script.indexOf("\ninstall_packages ");
        check("la funzione install_packages e' definita", def >= 0);
        check("ed e' definita prima del suo primo uso", def >= 0 && firstUse > def);
        check("la funzione controlla ogni pacchetto con pkg info -e",
                functionText(script).contains("pkg info -e \"$pkg_wanted\""));

        // Nessun "pkg install" fuori dalla funzione: uno nudo e' un pacchetto che puo' mancare
        // senza che nessuno se ne accorga.
        List<String> bare = new ArrayList<>();
        String fn = functionText(script);
        String outside = fn.isEmpty() ? script : script.replace(fn, "");
        for (String l : outside.split("\n")) {
            String t = l.trim();
            if (t.startsWith("#")) continue;
            if (t.matches(".*\\bpkg\\s+install\\b.*")) bare.add(t);
        }
        check("nessun \"pkg install\" fuori da install_packages" + (bare.isEmpty() ? "" : ": " + bare), bare.isEmpty());

        List<String> swallowed = new ArrayList<>();
        for (String l : script.split("\n")) {
            String t = l.trim();
            if (t.startsWith("install_packages ") && (t.contains("|| true") || t.contains("2>/dev/null"))) swallowed.add(t);
        }
        check("nessuna riga d'installazione ne nasconde l'esito (|| true, 2>/dev/null)"
                + (swallowed.isEmpty() ? "" : ": " + swallowed), swallowed.isEmpty());
    }

    // ------------------------------------------------------------------ B

    /** Le righe vere dello script contro un pkg finto che toglie un pacchetto ed esce con 0. */
    static void functionBehaviour(String script) throws Exception {
        System.out.println("\n== B. La funzione, con un pkg che toglie un pacchetto in silenzio ==");
        Path dir = Files.createTempDirectory("install-packages-test");
        try {
            Files.createDirectories(dir.resolve("bin"));
            // Il pkg finto. "install -y A B C": registra come installati tutti tranne quelli in
            // FAKE_DROP, scrive la riga del risolutore se ne toglie uno, ed esce con FAKE_RC
            // (0 se non detto): e' esattamente quello che ha fatto il pkg vero. "info -e X":
            // 0 solo se X e' stato registrato.
            Path fakePkg = dir.resolve("bin/pkg");
            Files.writeString(fakePkg, """
                    #!/bin/sh
                    case "$1" in
                      install)
                        shift; [ "$1" = "-y" ] && shift
                        echo "$*" >> "$FAKE_DIR/asked"
                        for p in "$@"; do
                          case " $FAKE_DROP " in
                            *" $p "*) echo "Cannot solve problem using SAT solver, trying another plan" ;;
                            *) echo "$p" >> "$FAKE_DIR/installed" ;;
                          esac
                        done
                        exit "${FAKE_RC:-0}" ;;
                      info)
                        [ "$2" = "-e" ] || exit 2
                        grep -qxF -- "$3" "$FAKE_DIR/installed" 2>/dev/null ;;
                      *) exit 0 ;;
                    esac
                    """, StandardCharsets.UTF_8);
            fakePkg.toFile().setExecutable(true);

            // Il banco: la funzione com'e' nello script, poi le righe d'installazione com'e'
            // nello script e nello stesso ordine, poi un segno che dice «sono arrivato in fondo».
            // Le righe si prendono sia nella forma nuova (install_packages) sia in quella vecchia
            // (pkg install -y), cosi' lo stesso banco misura anche lo script di prima.
            // Il "pkg install" DENTRO la funzione non e' una riga dello script: si guarda fuori.
            StringBuilder bench = new StringBuilder("RED=''\nNC=''\n");
            String fn = functionText(script);
            bench.append(fn).append('\n');
            for (String l : (fn.isEmpty() ? script : script.replace(fn, "")).split("\n")) {
                String t = l.trim();
                if (t.startsWith("install_packages ") || t.startsWith("pkg install -y ")) bench.append(t).append('\n');
            }
            bench.append("echo REACHED-THE-END\n");
            Files.writeString(dir.resolve("bench.sh"), bench.toString(), StandardCharsets.UTF_8);

            List<List<String>> lines = installLines(script);
            Run all = run(dir, "", "0");
            check("con pkg onesto: arriva in fondo", all.out.contains("REACHED-THE-END"));
            check("con pkg onesto: esce con 0", all.code == 0);
            check("con pkg onesto: il banco ha fatto tutte le " + lines.size() + " righe dello script",
                    all.asked.size() == lines.size() && lines.size() > 0);

            // Si toglie, uno alla volta, ciascun pacchetto della riga di Dovecot com'e' nello
            // script: il risolutore vero ha tolto ora l'uno ora l'altro.
            List<String> dovecotLine = lines.stream().filter(l -> l.contains("dovecot-mysql")).findFirst().orElse(List.of());
            check("lo script ha una riga con dovecot-mysql " + dovecotLine, !dovecotLine.isEmpty());
            for (String drop : dovecotLine) {
                Run r = run(dir, drop, "0");
                check("pkg toglie " + drop + " ed esce con 0: lo script NON arriva in fondo",
                        !r.out.contains("REACHED-THE-END"));
                check("pkg toglie " + drop + ": lo script esce diverso da 0", r.code != 0);
                check("pkg toglie " + drop + ": il messaggio lo nomina",
                        r.out.contains("NOT installed: " + drop) || r.out.matches("(?s).*NOT installed:.* " + drop + "\\b.*"));
                check("pkg toglie " + drop + ": si ferma sulla riga di Dovecot, la riga dopo (rspamd) non parte",
                        r.asked.stream().noneMatch(a -> a.contains("rspamd")));
            }

            Run last = run(dir, "php84-gd", "0");
            check("anche sull'ULTIMA riga (php84-gd tolto) non arriva in fondo", !last.out.contains("REACHED-THE-END"));
            check("e lo dice", last.out.contains("php84-gd") && last.out.contains("NOT installed"));

            Run fails = run(dir, "", "1");
            check("pkg esce con 1 anche senza togliere niente: lo script si ferma",
                    !fails.out.contains("REACHED-THE-END") && fails.code != 0);
            check("e dice il codice d'uscita di pkg", fails.out.contains("pkg exit code: 1"));
        } finally {
            Shell.runShell(Duration.ofSeconds(30), "rm -rf '" + dir + "'");
        }
    }

    record Run(int code, String out, List<String> asked) {}

    static Run run(Path dir, String drop, String rc) throws Exception {
        Files.deleteIfExists(dir.resolve("installed"));
        Files.deleteIfExists(dir.resolve("asked"));
        Shell.Result r = Shell.runShell(Duration.ofSeconds(60),
                "cd '" + dir + "' && PATH='" + dir + "/bin':/bin:/usr/bin FAKE_DIR='" + dir + "' FAKE_DROP='" + drop
                        + "' FAKE_RC=" + rc + " sh bench.sh 2>&1");
        Path asked = dir.resolve("asked");
        List<String> a = Files.exists(asked) ? Files.readAllLines(asked) : List.of();
        return new Run(r.exitCode(), r.output(), a);
    }

    // ------------------------------------------------------------------ C

    /** Il piano di pkg come su una macchina appena installata, riga per riga e tutto insieme. */
    static void realSolver(List<List<String>> lines) {
        System.out.println("\n== C. Il risolutore vero di pkg, sul catalogo vero ==");
        String db = sh("pkg config PKG_DBDIR 2>/dev/null", 30).trim();
        if (!db.matches("/[A-Za-z0-9._/-]{1,200}")) db = "/var/db/pkg";
        String tmp = sh("mktemp -d /var/tmp/install-packages-test.XXXXXX", 30).trim();
        if (!tmp.matches("/var/tmp/install-packages-test\\.[A-Za-z0-9]{6,}")) {
            check("cartella temporanea creata (" + tmp + ")", false);
            return;
        }
        try {
            // Una copia del database di pkg: il catalogo com'e', e i pacchetti installati tolti
            // tutti tranne pkg stesso. E' la macchina appena installata, vista dal risolutore.
            // Lo svuotamento tocca solo la copia: PKG_DBDIR punta li'.
            Shell.Result cp = Shell.runShell(Duration.ofSeconds(300),
                    "cp -Rp " + db + "/repos " + tmp + "/ && cp -p " + db + "/local.sqlite " + tmp + "/ && mkdir " + tmp + "/cache 2>&1");
            check("copia del catalogo e del database", cp.success());
            String p = "pkg -o PKG_DBDIR=" + tmp + " -o PKG_CACHEDIR=" + tmp + "/cache";
            Shell.Result empty = Shell.runShell(Duration.ofSeconds(60),
                    "printf 'PRAGMA foreign_keys=ON;\\nDELETE FROM packages WHERE name <> \\047pkg\\047;\\nSELECT count(*) FROM packages;\\n' | "
                            + p + " shell 2>&1");
            check("nella copia resta installato solo pkg (" + empty.outputTrim() + ")", empty.outputTrim().equals("1"));

            List<List<String>> plans = new ArrayList<>(lines);
            List<String> together = new ArrayList<>();
            for (List<String> l : lines) for (String n : l) if (!together.contains(n)) together.add(n);
            plans.add(together);

            for (int i = 0; i < plans.size(); i++) {
                List<String> asked = plans.get(i);
                String label = i < lines.size() ? "riga " + (i + 1) + " " + asked : "tutte le righe insieme (" + asked.size() + " pacchetti)";
                String list = String.join(" ", asked);
                // Prima si scaricano: senza i file pkg non vede i conflitti fra pacchetti.
                Shell.Result f = Shell.runShell(Duration.ofSeconds(900), p + " fetch -d -U -y " + list + " 2>&1");
                if (!f.success()) {
                    check(label + ": pkg fetch riuscito", false);
                    System.out.println(indent(tail(f.outputTrim(), 15)));
                    continue;
                }
                Shell.Result plan = Shell.runShell(Duration.ofSeconds(300), p + " install -n -U " + list + " 2>&1");
                Set<String> planned = lastInstallBlock(plan.output());
                List<String> missing = new ArrayList<>();
                for (String a : asked) {
                    String name = a.contains("/") ? sh(p + " rquery -U %n " + a + " 2>/dev/null", 60).trim() : a;
                    if (!planned.contains(name)) missing.add(a);
                }
                check(label + ": nel piano c'e' ogni pacchetto chiesto"
                        + (missing.isEmpty() ? "" : " -- MANCANO " + missing), missing.isEmpty() && !planned.isEmpty());
                if (plan.output().contains("Cannot solve problem")) {
                    for (String l : plan.output().split("\n"))
                        if (l.contains("conflicts with") || l.contains("Cannot solve")) System.out.println("           pkg: " + l.trim());
                }
            }
        } finally {
            Shell.runShell(Duration.ofSeconds(300), "rm -rf " + tmp);
        }
    }

    /** I nomi dell'ULTIMO elenco «New packages to be INSTALLED»: dopo un ripiego, quello vale. */
    static Set<String> lastInstallBlock(String out) {
        Set<String> names = new LinkedHashSet<>();
        int at = out.lastIndexOf("New packages to be INSTALLED:");
        if (at < 0) return names;
        for (String l : out.substring(at).split("\n")) {
            if (l.startsWith("New packages")) continue;
            if (l.isBlank()) break;
            String t = l.trim();
            int colon = t.indexOf(':');
            if (colon > 0) names.add(t.substring(0, colon));
        }
        return names;
    }

    // ------------------------------------------------------------------ D

    static void updaterLabels() throws Exception {
        System.out.println("\n== D. L'updater riconosce i pacchetti coi sapori ==");
        Method role = UpdateManager.class.getDeclaredMethod("roleOf", String.class);
        role.setAccessible(true);
        Object dovecot = role.invoke(null, "dovecot");
        check("dovecot-mysql ha lo stesso ruolo di dovecot (" + dovecot + ")",
                dovecot != null && dovecot.equals(role.invoke(null, "dovecot-mysql")));
        check("dovecot24-mysql anche", dovecot != null && dovecot.equals(role.invoke(null, "dovecot24-mysql")));
        Object sieve = role.invoke(null, "dovecot-pigeonhole");
        check("dovecot-pigeonhole-mysql ha il ruolo di Sieve (" + sieve + ")",
                sieve != null && sieve.equals(role.invoke(null, "dovecot-pigeonhole-mysql")));

        Method services = UpdateManager.class.getDeclaredMethod("directServices", String.class);
        services.setAccessible(true);
        check("aggiornare dovecot-mysql riavvia dovecot", List.of("dovecot").equals(services.invoke(null, "dovecot-mysql")));
        check("aggiornare dovecot-pigeonhole-mysql riavvia dovecot",
                List.of("dovecot").equals(services.invoke(null, "dovecot-pigeonhole-mysql")));

        String family = UpdateManager.famigliaDi("dovecot-mysql");
        check("dovecot-mysql e dovecot-pigeonhole-mysql si muovono insieme (stessa famiglia)",
                family != null && family.equals(UpdateManager.famigliaDi("dovecot-pigeonhole-mysql")));
    }

    // ------------------------------------------------------------------ attrezzi

    /** Le righe d'installazione dello script, ognuna come elenco di pacchetti. */
    static List<List<String>> installLines(String script) {
        List<List<String>> out = new ArrayList<>();
        for (String l : script.split("\n")) {
            String t = l.trim();
            String rest;
            if (t.startsWith("install_packages ")) rest = t.substring("install_packages ".length());
            else if (t.startsWith("pkg install -y ")) rest = t.substring("pkg install -y ".length());
            else continue;
            List<String> names = new ArrayList<>();
            for (String w : rest.split("\\s+")) {
                if (w.startsWith("2>") || w.equals("||") || w.equals("true") || w.equals("&&")) break;
                if (w.matches("[A-Za-z0-9._/+-]{1,80}")) names.add(w);
            }
            if (!names.isEmpty()) out.add(names);
        }
        return out;
    }

    /** Il testo della funzione install_packages com'e' nello script, o "" se non c'e'. */
    static String functionText(String script) {
        int a = script.indexOf("install_packages() {");
        if (a < 0) return "";
        int b = script.indexOf("\n}\n", a);
        return b < 0 ? "" : script.substring(a, b + 2);
    }

    static boolean onFreeBsdAsRoot() {
        return sh("uname -s", 10).trim().equals("FreeBSD") && sh("id -u", 10).trim().equals("0");
    }

    static String sh(String cmd, int seconds) {
        return Shell.runShell(Duration.ofSeconds(seconds), cmd).output();
    }

    static String tail(String s, int n) {
        String[] l = s.split("\n");
        return String.join("\n", java.util.Arrays.copyOfRange(l, Math.max(0, l.length - n), l.length));
    }

    static String indent(String s) {
        return s.replaceAll("(?m)^", "           ");
    }
}
