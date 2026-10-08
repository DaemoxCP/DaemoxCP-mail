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
 * Prova la data del catalogo dei pacchetti (CatalogoPkg) e la riga che ne fa il rapporto.
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

    static int falliti = 0;

    static void esigi(String cosa, boolean condizione) {
        System.out.println((condizione ? "  OK   " : "  FALLITO ") + cosa);
        if (!condizione) falliti++;
    }

    static final long ADESSO = 1_790_000_000L;   // un istante fisso: le eta' non dipendono dal giorno della prova

    static void file(Path p, long oreFa) throws Exception {
        Files.createDirectories(p.getParent());
        if (!Files.exists(p)) Files.writeString(p, "SQLite format 3");
        Files.setLastModifiedTime(p, FileTime.from(Instant.ofEpochSecond(ADESSO - oreFa * 3600)));
    }

    /** Un repository come lo stampa "pkg -vv" (print_repository con pad). */
    static String blocco(String nome, String url, String acceso) {
        return "  " + nome + ": { \n"
             + "    url             : \"" + url + "\",\n"
             + "    enabled         : " + acceso + ",\n"
             + "    priority        : 0,\n"
             + "    mirror_type     : \"SRV\",\n"
             + "    signature_type  : \"FINGERPRINTS\",\n"
             + "    fingerprints    : \"/usr/share/keys/pkg\"\n"
             + "  }\n";
    }

    static final String PKG_VV = "Version                 : 2.3.1\n"
            + "PKG_DBDIR = \"/var/db/pkg\";\n"
            + "\nRepositories:\n"
            + blocco("FreeBSD-ports", "pkg+https://pkg.FreeBSD.org/FreeBSD:15:aarch64/quarterly", "yes")
            + blocco("FreeBSD-ports-kmods", "pkg+https://pkg.FreeBSD.org/FreeBSD:15:aarch64/kmods_quarterly_1",
                     "yes (overridden by pkg)")
            + blocco("FreeBSD-base", "pkg+https://pkg.FreeBSD.org/FreeBSD:15:aarch64/base_release_1", "no");

    public static void main(String[] a) throws Exception {
        Path radice = Files.createTempDirectory("prova-catalogo");
        try {
            prove(radice);
        } finally {
            try (Stream<Path> s = Files.walk(radice)) {
                s.sorted((x, y) -> y.compareTo(x)).forEach(p -> p.toFile().delete());
            }
        }
        System.out.println("\n" + (falliti == 0 ? "TUTTO VERDE" : falliti + " CONTROLLI FALLITI"));
        if (falliti > 0) System.exit(1);
    }

    static void prove(Path radice) throws Exception {
        System.out.println("\n== pkg -vv: quali repository sono accesi ==");
        List<String> accesi = CatalogoPkg.accesi(PKG_VV);
        esigi("accesi FreeBSD-ports e FreeBSD-ports-kmods (anche \"yes (overridden by pkg)\"): " + accesi,
                List.of("FreeBSD-ports", "FreeBSD-ports-kmods").equals(accesi));
        esigi("un'uscita senza repository e' \"non so\" (null), non \"nessuno\"",
                CatalogoPkg.accesi("pkg: errore qualsiasi\n") == null);
        esigi("repository tutti spenti: elenco vuoto, non null",
                CatalogoPkg.accesi("Repositories:\n" + blocco("FreeBSD-ports", "x", "no")).isEmpty());

        System.out.println("\n== FreeBSD 15: due accesi, uno spento, il vecchio FreeBSD, local.sqlite ==");
        Path pkg = radice.resolve("db1");
        file(pkg.resolve("repos/FreeBSD-ports/db"), 26);
        file(pkg.resolve("repos/FreeBSD-ports-kmods/db"), 50);
        file(pkg.resolve("repos/FreeBSD-base/db"), 24 * 90);
        file(pkg.resolve("repos/FreeBSD/db"), 24 * 400);
        file(pkg.resolve("local.sqlite"), 0);
        JSONObject c = CatalogoPkg.data(pkg.toString(), accesi, ADESSO);
        esigi("vale il piu' vecchio fra gli accesi: " + c.optString("piuVecchio") + ", " + c.optLong("giorni") + " giorni",
                "FreeBSD-ports-kmods".equals(c.optString("piuVecchio")) && c.optLong("giorni") == 2 && c.optLong("ore") == 50);
        esigi("solo i due accesi", c.getJSONArray("repository").length() == 2);
        String nota = CatalogoPkg.nota(c);
        System.out.println("  nota: " + nota);
        esigi("la nota ha le due date, \"ieri\" e \"2 giorni fa\"", nota.contains("FreeBSD-ports il ")
                && nota.contains("(ieri)") && nota.contains("(2 giorni fa)"));
        esigi("e dice che e' la data del server", nota.contains("non dell'ultimo controllo"));

        System.out.println("\n== un acceso senza catalogo; nessun catalogo; repository tutti spenti ==");
        Path pkg2 = radice.resolve("db2");
        file(pkg2.resolve("repos/FreeBSD-ports/db"), 3);
        c = CatalogoPkg.data(pkg2.toString(), accesi, ADESSO);
        esigi("oggi, e FreeBSD-ports-kmods fra i mancanti", c.optLong("giorni") == 0
                && c.getJSONArray("mancanti").toList().equals(List.of("FreeBSD-ports-kmods")));
        esigi("la nota lo dice", CatalogoPkg.nota(c).contains("Il repository FreeBSD-ports-kmods e' acceso ma non ha"));
        Path pkg3 = radice.resolve("db3");
        Files.createDirectories(pkg3);
        c = CatalogoPkg.data(pkg3.toString(), accesi, ADESSO);
        nota = CatalogoPkg.nota(c);
        esigi("nessun catalogo: giorni -1, e la nota dice dove ha guardato: " + nota,
                c.optLong("giorni") == -1 && nota.contains("repos/FreeBSD-ports/db"));
        c = CatalogoPkg.data(pkg.toString(), List.of(), ADESSO);
        esigi("tutti spenti: lo dice, invece di \"non so\": " + CatalogoPkg.nota(c),
                CatalogoPkg.nota(c).startsWith("Nessun repository di pkg e' acceso"));

        System.out.println("\n== pkg vecchio, pkg -vv muto, nome strano, orologio indietro ==");
        Path pkg4 = radice.resolve("db4");
        file(pkg4.resolve("repo-FreeBSD.sqlite"), 30);
        c = CatalogoPkg.data(pkg4.toString(), List.of("FreeBSD"), ADESSO);
        esigi("repo-<nome>.sqlite ancora riconosciuto", c.optString("file").endsWith("repo-FreeBSD.sqlite"));
        c = CatalogoPkg.data(pkg.toString(), null, ADESSO);
        esigi("senza pkg -vv si prendono i cataloghi che ci sono (4)", c.getJSONArray("repository").length() == 4);
        c = CatalogoPkg.data(pkg.toString(), List.of("../../etc"), ADESSO);
        esigi("un nome con ../ non finisce in un percorso", c.getJSONArray("repository").getJSONObject(0).has("errore"));
        Path pkg5 = radice.resolve("db5");
        file(pkg5.resolve("repos/FreeBSD-ports/db"), -2);
        c = CatalogoPkg.data(pkg5.toString(), List.of("FreeBSD-ports"), ADESSO);
        esigi("data nel futuro: oggi, non un'eta' negativa", c.optLong("giorni") == 0);

        System.out.println("\n== il rapporto ==");
        c = CatalogoPkg.data(pkg.toString(), accesi, ADESSO);
        c.put("nota", CatalogoPkg.nota(c));
        String t = RapportoPeriodico.componi(new JSONObject()
                .put("catalogo", c).put("catalogoGiorni", c.optLong("giorni")).put("catalogoData", c.optString("data"))
                .put("catalogoRinfrescato", true).put("vulnDbGiorni", 0),
                "freebsd", "noreply@esempio.it", "admin@esempio.it");
        String riga = t.lines().filter(l -> l.startsWith("Database delle vulnerabilita'")).findFirst().orElse("");
        System.out.println("  " + riga);
        esigi("il rapporto dice quando e' stato pubblicato, e che e' stato controllato adesso",
                riga.contains("Catalogo dei pacchetti: pubblicato 2 giorni fa (") && riga.contains("controllato adesso"));
        esigi("e con due repository aggiunge la frase intera", t.contains("I conteggi sono freschi quanto il piu' vecchio"));
        esigi("niente piu' \"eta' sconosciuta\" per il catalogo", !riga.contains("Catalogo dei pacchetti: eta' sconosciuta"));

        System.out.println("\n== dove guardava prima ==");
        esigi("su FreeBSD 15 /var/db/pkg/repo-FreeBSD.sqlite non c'e': di qui \"eta' sconosciuta\"",
                !Files.exists(pkg.resolve("repo-FreeBSD.sqlite")));
    }
}
