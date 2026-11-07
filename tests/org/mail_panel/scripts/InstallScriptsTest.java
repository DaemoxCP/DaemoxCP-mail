package org.mail_panel.scripts;

import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;

/**
 * Gli script d'installazione su disco sono sempre quelli del jar che gira (InstallScripts, reperto 169).
 *
 *  1. La scrittura e' tutto o niente: chi ha aperto lo script di prima (uno script che sta girando)
 *     continua a leggere il suo; il nuovo c'e' intero, 700, senza file temporanei rimasti.
 *  2. Uno script vecchio su disco si riscrive (prima sei classi su sette scrivevano «solo se manca»).
 *  3. Gli script che nessuno scrive piu' si mettono da parte (.retired); ripetere non cambia niente; con
 *     un .retired gia' accanto si lasciano tutti e due.
 *  4. L'impronta del jar e il controllo stanno subito dopo la riga #!, anche dove la #! era rientrata.
 *  5. Con -De2e.vm=yes (VM, root): un avvio vero del pannello (Main --create-admin senza argomenti:
 *     passa dall'avvio e si ferma sull'uso) riscrive lo script vecchio e mette da parte quelli in pensione.
 * Tutto in una cartella temporanea come cartella del pannello.
 *
 * Uso: java [-De2e.vm=yes] -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.scripts.InstallScriptsTest
 */
public class InstallScriptsTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && args[0].equals("child")) { child(args); return; }
        Path d = Files.createTempDirectory("install-scripts");
        try {
            String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
            Process p = new ProcessBuilder(java, "-cp", absolute(System.getProperty("java.class.path")),
                    InstallScriptsTest.class.getName(), "child").directory(d.toFile()).inheritIO().start();
            int code = p.waitFor();
            if (code != 0) failed++;
            if ("yes".equals(System.getProperty("e2e.vm"))) wiring(d);
            else System.out.println("\n(saltato: l'avvio vero del pannello, serve -De2e.vm=yes)");
        } finally {
            removeTree(d);
        }
        System.out.println(failed == 0 ? "\nTutte le prove passate." : "\n" + failed + " prove FALLITE.");
        System.exit(failed == 0 ? 0 : 1);
    }

    /** Le prove 1-4, con la cartella temporanea come cartella corrente. */
    static void child(String[] a) throws Exception {
        Path dir = Path.of(InstallScripts.DIR);
        Files.createDirectories(dir);

        System.out.println("== 1. Tutto o niente, anche con lo script di prima aperto ==");
        Path script = dir.resolve("install_mail_server.sh");
        Files.writeString(script, "#!/bin/sh\necho prima\n");
        try (RandomAccessFile running = new RandomAccessFile(script.toFile(), "r")) {
            check("riscritto", InstallScripts.write(script.toString(), "#!/bin/sh\necho dopo, molto piu' lungo di prima\n"));
            byte[] b = new byte[(int) running.length()];
            running.readFully(b);
            check("chi l'aveva aperto legge ancora quello di prima", new String(b, StandardCharsets.UTF_8).equals("#!/bin/sh\necho prima\n"));
        }
        String now = Files.readString(script);
        check("il nuovo c'e' intero", now.startsWith("#!/bin/sh\n") && now.endsWith("echo dopo, molto piu' lungo di prima\n"));
        check("700", PosixFilePermissions.toString(Files.getPosixFilePermissions(script)).equals("rwx------"));
        check("nessun file temporaneo rimasto", !Files.exists(dir.resolve("install_mail_server.sh.tmp")));

        System.out.println("\n== 2. Uno script vecchio si riscrive ==");
        Files.writeString(script, "#!/bin/sh\n# uno script di una versione di prima\nexit 42\n");
        Path tz = dir.resolve("setup_timezone_and_dns.sh");
        Files.writeString(tz, "#!/bin/sh\n# vecchio anche lui\nexit 43\n");
        InstallScripts.refreshAtStartup();
        String fresh = new FullMailServerScript().getScriptContent();
        check("install_mail_server.sh e' quello del jar", Files.readString(script).equals(InstallScripts.stamped(fresh)));
        check("setup_timezone_and_dns.sh e' quello del jar", !Files.readString(tz).contains("exit 43")
                && Files.readString(tz).contains("System Time and DNS Configuration"));

        System.out.println("\n== 3. Gli script che nessuno scrive piu' ==");
        List<Path> old = new ArrayList<>();
        for (String n : InstallScripts.RETIRED) {
            Path f = dir.resolve(n);
            Files.writeString(f, "#!/bin/sh\n# di una versione di prima\n");
            old.add(f);
        }
        InstallScripts.refreshAtStartup();
        boolean allAside = true;
        for (Path f : old) allAside &= !Files.exists(f) && Files.exists(Path.of(f + ".retired"));
        check("messi da parte tutti e cinque, con il contenuto", allAside
                && Files.readString(Path.of(old.get(0) + ".retired")).contains("di una versione di prima"));
        InstallScripts.refreshAtStartup();
        check("ripetere non cambia niente", allAside && old.stream().noneMatch(Files::exists));
        Files.writeString(old.get(0), "#!/bin/sh\n# tornato\n");
        InstallScripts.refreshAtStartup();
        check("con un .retired gia' accanto: tutti e due restano", Files.exists(old.get(0)) && Files.exists(Path.of(old.get(0) + ".retired")));

        System.out.println("\n== 4. L'impronta e il controllo dopo la #! ==");
        String s = InstallScripts.stamped("#!/bin/sh\necho x\n");
        check("la riga #! resta la prima", s.startsWith("#!/bin/sh\n# --- Written by the mail panel"));
        check("l'impronta e' quella del jar che gira", s.contains("MAIL_PANEL_WRITTEN_BY_JAR=\"" + InstallScripts.jarSha256() + "\"")
                && InstallScripts.jarSha256().matches("[0-9a-f]{64}"));
        check("una #! rientrata torna a inizio file", Files.readString(tz).startsWith("#!/bin/sh\n# --- Written by the mail panel"));
        System.exit(failed == 0 ? 0 : 1);
    }

    /** 5: l'avvio vero del pannello (Main.main) riscrive e mette da parte. */
    static void wiring(Path d) throws Exception {
        System.out.println("\n== 5. Un avvio vero del pannello ==");
        Path panel = d.resolve("panel");
        Path dir = panel.resolve("install_scripts");
        Files.createDirectories(dir);
        Files.writeString(dir.resolve("install_mail_server.sh"), "#!/bin/sh\nexit 42\n");
        Files.writeString(dir.resolve("install_dovecot.sh"), "#!/bin/sh\n# vecchio\n");
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        Process p = new ProcessBuilder(java, "-Dmailpanel.secrets.dir=" + d.resolve("secrets"), "-cp",
                absolute(System.getProperty("java.class.path")), "org.mail_panel.Main", "--create-admin")
                .directory(panel.toFile()).redirectErrorStream(true)
                .redirectInput(ProcessBuilder.Redirect.from(new java.io.File("/dev/null"))).start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        p.waitFor();
        check("il pannello e' partito e si e' fermato sull'uso", out.contains("Usage"));
        check("lo script vecchio e' riscritto", !Files.readString(dir.resolve("install_mail_server.sh")).contains("exit 42"));
        check("quello in pensione e' messo da parte", !Files.exists(dir.resolve("install_dovecot.sh"))
                && Files.exists(dir.resolve("install_dovecot.sh.retired")));
    }

    static String absolute(String cp) {
        StringBuilder b = new StringBuilder();
        for (String part : cp.split(java.io.File.pathSeparator)) {
            if (b.length() > 0) b.append(java.io.File.pathSeparator);
            b.append(Path.of(part).toAbsolutePath());
        }
        return b.toString();
    }

    static void removeTree(Path p) throws Exception {
        if (!Files.exists(p)) return;
        try (var walk = Files.walk(p)) {
            for (Path q : walk.sorted((x, y) -> y.compareTo(x)).toList()) Files.deleteIfExists(q);
        }
    }
}
