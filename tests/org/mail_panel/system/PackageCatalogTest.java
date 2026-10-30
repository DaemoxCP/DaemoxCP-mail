package org.mail_panel.system;

import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.util.List;
import java.util.stream.Stream;

/**
 * Prova la data del catalogo dei pacchetti (PkgCatalog) e la riga che ne fa il rapporto.
 *
 * Lavora su una cartella di pkg costruita qui, con la disposizione di FreeBSD 15 e le date
 * decise dalla prova: dove sta il catalogo e che data ha lo dice il sorgente di pkg
 * (libpkg/repo/binary/common.c: "repos/%s/db"; update.c: la data e' quella del server).
 * L'uscita di pkg -vv ha la forma esatta di print_repository() in src/utils.c.
 *
 * Il caso che l'ha motivata: Home e rapporto dicevano "eta' sconosciuta" perche' guardavano
 * /var/db/pkg/repo-FreeBSD.sqlite. In fondo la prova mostra che su FreeBSD 15 quel file non c'e'.
 */
public class PackageCatalogTest {

    static int failed = 0;

    static void require(String what, boolean condition) {
        System.out.println((condition ? "  OK   " : "  FALLITO ") + what);
        if (!condition) failed++;
    }

    static final long NOW = 1_790_000_000L;   // un istante fisso: le eta' non dipendono dal giorno della prova

    static void file(Path p, long hoursAgo) throws Exception {
        Files.createDirectories(p.getParent());
        if (!Files.exists(p)) Files.writeString(p, "SQLite format 3");
        Files.setLastModifiedTime(p, FileTime.from(Instant.ofEpochSecond(NOW - hoursAgo * 3600)));
    }

    /** Un repository come lo stampa "pkg -vv" (print_repository con pad). */
    static String block(String name, String url, String enabled) {
        return "  " + name + ": { \n"
             + "    url             : \"" + url + "\",\n"
             + "    enabled         : " + enabled + ",\n"
             + "    priority        : 0,\n"
             + "    mirror_type     : \"SRV\",\n"
             + "    signature_type  : \"FINGERPRINTS\",\n"
             + "    fingerprints    : \"/usr/share/keys/pkg\"\n"
             + "  }\n";
    }

    static final String PKG_VV = "Version                 : 2.3.1\n"
            + "PKG_DBDIR = \"/var/db/pkg\";\n"
            + "\nRepositories:\n"
            + block("FreeBSD-ports", "pkg+https://pkg.FreeBSD.org/FreeBSD:15:aarch64/quarterly", "yes")
            + block("FreeBSD-ports-kmods", "pkg+https://pkg.FreeBSD.org/FreeBSD:15:aarch64/kmods_quarterly_1",
                     "yes (overridden by pkg)")
            + block("FreeBSD-base", "pkg+https://pkg.FreeBSD.org/FreeBSD:15:aarch64/base_release_1", "no");

    public static void main(String[] a) throws Exception {
        Path root = Files.createTempDirectory("prova-catalogo");
        try {
            tests(root);
        } finally {
            try (Stream<Path> s = Files.walk(root)) {
                s.sorted((x, y) -> y.compareTo(x)).forEach(p -> p.toFile().delete());
            }
        }
        System.out.println("\n" + (failed == 0 ? "TUTTO VERDE" : failed + " CONTROLLI FALLITI"));
        if (failed > 0) System.exit(1);
    }

    static void tests(Path root) throws Exception {
        System.out.println("\n== pkg -vv: quali repository sono accesi ==");
        List<String> enabledOnes = PkgCatalog.enabledOnes(PKG_VV);
        require("accesi FreeBSD-ports e FreeBSD-ports-kmods (anche \"yes (overridden by pkg)\"): " + enabledOnes,
                List.of("FreeBSD-ports", "FreeBSD-ports-kmods").equals(enabledOnes));
        require("un'uscita senza repository e' \"non so\" (null), non \"nessuno\"",
                PkgCatalog.enabledOnes("pkg: errore qualsiasi\n") == null);
        require("repository tutti spenti: elenco vuoto, non null",
                PkgCatalog.enabledOnes("Repositories:\n" + block("FreeBSD-ports", "x", "no")).isEmpty());

        System.out.println("\n== FreeBSD 15: due accesi, uno spento, il vecchio FreeBSD, local.sqlite ==");
        Path pkg = root.resolve("db1");
        file(pkg.resolve("repos/FreeBSD-ports/db"), 26);
        file(pkg.resolve("repos/FreeBSD-ports-kmods/db"), 50);
        file(pkg.resolve("repos/FreeBSD-base/db"), 24 * 90);
        file(pkg.resolve("repos/FreeBSD/db"), 24 * 400);
        file(pkg.resolve("local.sqlite"), 0);
        JSONObject c = PkgCatalog.data(pkg.toString(), enabledOnes, NOW);
        require("vale il piu' vecchio fra gli accesi: " + c.optString("piuVecchio") + ", " + c.optLong("giorni") + " giorni",
                "FreeBSD-ports-kmods".equals(c.optString("piuVecchio")) && c.optLong("giorni") == 2 && c.optLong("ore") == 50);
        require("solo i due accesi", c.getJSONArray("repository").length() == 2);
        String note = PkgCatalog.note(c);
        System.out.println("  nota: " + note);
        require("la nota ha le due date, \"ieri\" e \"2 giorni fa\"", note.contains("FreeBSD-ports il ")
                && note.contains("(ieri)") && note.contains("(2 giorni fa)"));
        require("e dice che e' la data del server", note.contains("non dell'ultimo controllo"));

        System.out.println("\n== un acceso senza catalogo; nessun catalogo; repository tutti spenti ==");
        Path pkg2 = root.resolve("db2");
        file(pkg2.resolve("repos/FreeBSD-ports/db"), 3);
        c = PkgCatalog.data(pkg2.toString(), enabledOnes, NOW);
        require("oggi, e FreeBSD-ports-kmods fra i mancanti", c.optLong("giorni") == 0
                && c.getJSONArray("mancanti").toList().equals(List.of("FreeBSD-ports-kmods")));
        require("la nota lo dice", PkgCatalog.note(c).contains("Il repository FreeBSD-ports-kmods è acceso ma non ha"));
        Path pkg3 = root.resolve("db3");
        Files.createDirectories(pkg3);
        c = PkgCatalog.data(pkg3.toString(), enabledOnes, NOW);
        note = PkgCatalog.note(c);
        require("nessun catalogo: giorni -1, e la nota dice dove ha guardato: " + note,
                c.optLong("giorni") == -1 && note.contains("repos/FreeBSD-ports/db"));
        c = PkgCatalog.data(pkg.toString(), List.of(), NOW);
        require("tutti spenti: lo dice, invece di \"non so\": " + PkgCatalog.note(c),
                PkgCatalog.note(c).startsWith("Nessun repository di pkg è acceso"));

        System.out.println("\n== pkg vecchio, pkg -vv muto, nome strano, orologio indietro ==");
        Path pkg4 = root.resolve("db4");
        file(pkg4.resolve("repo-FreeBSD.sqlite"), 30);
        c = PkgCatalog.data(pkg4.toString(), List.of("FreeBSD"), NOW);
        require("repo-<nome>.sqlite ancora riconosciuto", c.optString("file").endsWith("repo-FreeBSD.sqlite"));
        c = PkgCatalog.data(pkg.toString(), null, NOW);
        require("senza pkg -vv si prendono i cataloghi che ci sono (4)", c.getJSONArray("repository").length() == 4);
        c = PkgCatalog.data(pkg.toString(), List.of("../../etc"), NOW);
        require("un nome con ../ non finisce in un percorso", c.getJSONArray("repository").getJSONObject(0).has("errore"));
        Path pkg5 = root.resolve("db5");
        file(pkg5.resolve("repos/FreeBSD-ports/db"), -2);
        c = PkgCatalog.data(pkg5.toString(), List.of("FreeBSD-ports"), NOW);
        require("data nel futuro: oggi, non un'eta' negativa", c.optLong("giorni") == 0);

        System.out.println("\n== il rapporto ==");
        c = PkgCatalog.data(pkg.toString(), enabledOnes, NOW);
        c.put("nota", PkgCatalog.note(c));
        String t = PeriodicReport.compose(new JSONObject()
                .put("catalogo", c).put("catalogoGiorni", c.optLong("giorni")).put("catalogoData", c.optString("data"))
                .put("catalogoRinfrescato", true).put("vulnDbGiorni", 0),
                "freebsd", "noreply@esempio.it", "admin@esempio.it");
        String line = t.lines().filter(l -> l.startsWith("Database delle vulnerabilità")).findFirst().orElse("");
        System.out.println("  " + line);
        require("il rapporto dice quando e' stato pubblicato, e che e' stato controllato adesso",
                line.contains("Catalogo dei pacchetti: pubblicato 2 giorni fa (") && line.contains("controllato adesso"));
        require("e con due repository aggiunge la frase intera", t.contains("I conteggi sono freschi quanto il più vecchio"));
        require("niente piu' \"eta' sconosciuta\" per il catalogo", !line.contains("Catalogo dei pacchetti: età sconosciuta"));

        System.out.println("\n== dove guardava prima ==");
        require("su FreeBSD 15 /var/db/pkg/repo-FreeBSD.sqlite non c'e': di qui \"eta' sconosciuta\"",
                !Files.exists(pkg.resolve("repo-FreeBSD.sqlite")));
    }
}
