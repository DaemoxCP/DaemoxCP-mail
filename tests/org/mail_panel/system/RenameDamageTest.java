package org.mail_panel.system;

import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import java.util.stream.*;

/**
 * Le rinomine fatte sul testo possono colpire stringhe che non sono nomi del codice.
 *
 * Il 25/10/2026 la rinomina delle chiavi JSON (so -> os, prova -> test, posta -> mail) aveva
 * cambiato anche: le dieci righe "extension=pdo_mysql.so" del php.ini di Roundcube (diventate
 * ".os": PHP non avrebbe caricato le estensioni), sette comandi di shell su libssl.so e
 * libmysqlclient.so.24, i due nomi vecchi in PathMigration (la migrazione di quei file non
 * avveniva piu', e la guardia old == new lo taceva) e l'identificatore del profilo Apple.
 * Nessuna prova lo vedeva: servono FreeBSD, Roundcube, un iPhone. Questa guarda i sorgenti.
 */
public class RenameDamageTest {

    private static int failures = 0;

    public static void main(String[] args) throws Exception {
        Path root = Path.of(args.length > 0 ? args[0] : ".");
        List<Path> java;
        try (Stream<Path> s = Files.walk(root.resolve("src/main/java"))) {
            java = s.filter(p -> p.toString().endsWith(".java")).sorted().toList();
        }

        // 1. una libreria condivisa si chiama .so: ".os" dopo un nome e' una rinomina sbagliata.
        //    L'unica eccezione e' la chiave di lingua up.os ({{t:up.os}}).
        Pattern os = Pattern.compile("[A-Za-z0-9_)]\\.os(?![A-Za-z0-9_])");
        List<String> bad = new ArrayList<>();
        for (Path f : java) {
            List<String> lines = Files.readAllLines(f);
            for (int i = 0; i < lines.size(); i++) {
                String l = lines.get(i).replace("up.os", "");
                if (os.matcher(l).find()) bad.add(root.relativize(f) + ":" + (i + 1) + ": " + lines.get(i).trim());
            }
        }
        bad.stream().limit(10).forEach(b -> System.out.println("  " + b));
        check("nessuna stringa nomina una libreria .os invece di .so", bad.isEmpty());

        // 2. PathMigration: un passo con lo stesso nome di qua e di la' non migra niente.
        String pm = Files.readString(root.resolve("src/main/java/org/mail_panel/system/PathMigration.java"));
        Matcher m = Pattern.compile("rename\\((?:db \\+ )?\"([^\"]+)\",\\s*(?:db \\+ )?\"([^\"]+)\"\\)").matcher(pm);
        int pairs = 0; List<String> same = new ArrayList<>();
        while (m.find()) { pairs++; if (m.group(1).equals(m.group(2))) same.add(m.group(1)); }
        same.forEach(x -> System.out.println("  stesso nome: " + x));
        check("PathMigration: " + pairs + " passi, ognuno da un nome vecchio a uno nuovo", pairs > 0 && same.isEmpty());

        // 3. il php.ini di Roundcube carica le estensioni col loro nome vero.
        String rc = Files.readString(root.resolve("src/main/java/org/mail_panel/scripts/RoundcubeScript.java"));
        check("Roundcube: extension=pdo_mysql.so e intl.so nel php.ini",
                rc.contains("extension=pdo_mysql.so") && rc.contains("extension=intl.so"));

        // 4. il profilo Apple tiene l'identificatore che i dispositivi conoscono.
        String ap = Files.readString(root.resolve("src/main/java/org/mail_panel/system/AppleProfile.java"));
        check("profilo Apple: PayloadIdentifier ...posta e seme \"posta:\" invariati",
                ap.contains("<string>%s.posta</string>") && ap.contains("deterministic(\"posta:\""));

        System.out.println(failures == 0 ? "\nTUTTO OK" : "\n" + failures + " PROVE FALLITE");
        if (failures > 0) System.exit(1);
    }

    private static void check(String what, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + what);
        if (!ok) failures++;
    }
}
