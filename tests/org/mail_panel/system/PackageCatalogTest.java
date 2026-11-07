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
 * Tests the date of the package catalog (PkgCatalog) and the report's line about it.
 *
 * It works on a pkg folder built here, with the FreeBSD 15 layout and dates decided by the test:
 * where the catalog lives and what date it has is said by pkg's source
 * (libpkg/repo/binary/common.c: "repos/%s/db"; update.c: the date is the server's).
 * The output of pkg -vv has the exact shape of print_repository() in src/utils.c.
 *
 * The case that prompted it: Home and the report said "age unknown" because they looked at
 * /var/db/pkg/repo-FreeBSD.sqlite. At the end the test shows that on FreeBSD 15 that file is not there.
 *
 * The panel's texts are read in English (I18n.setCurrent): outside a request it writes Italian.
 */
public class PackageCatalogTest {

    static int failed = 0;

    static void require(String what, boolean condition) {
        System.out.println((condition ? "  OK   " : "  FAILED ") + what);
        if (!condition) failed++;
    }

    static final long NOW = 1_790_000_000L;   // a fixed instant: the ages do not depend on the day of the test

    static void file(Path p, long hoursAgo) throws Exception {
        Files.createDirectories(p.getParent());
        if (!Files.exists(p)) Files.writeString(p, "SQLite format 3");
        Files.setLastModifiedTime(p, FileTime.from(Instant.ofEpochSecond(NOW - hoursAgo * 3600)));
    }

    /** A repository as "pkg -vv" prints it (print_repository with pad). */
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
        org.mail_panel.i18n.I18n.setCurrent("en");
        Path root = Files.createTempDirectory("catalog-test");
        try {
            tests(root);
        } finally {
            try (Stream<Path> s = Files.walk(root)) {
                s.sorted((x, y) -> y.compareTo(x)).forEach(p -> p.toFile().delete());
            }
        }
        System.out.println("\n" + (failed == 0 ? "ALL GREEN" : failed + " CHECKS FAILED"));
        if (failed > 0) System.exit(1);
    }

    static void tests(Path root) throws Exception {
        System.out.println("\n== pkg -vv: which repositories are enabled ==");
        List<String> enabledOnes = PkgCatalog.enabledOnes(PKG_VV);
        require("enabled FreeBSD-ports and FreeBSD-ports-kmods (also \"yes (overridden by pkg)\"): " + enabledOnes,
                List.of("FreeBSD-ports", "FreeBSD-ports-kmods").equals(enabledOnes));
        require("an output without repositories is \"I don't know\" (null), not \"none\"",
                PkgCatalog.enabledOnes("pkg: some error\n") == null);
        require("repositories all disabled: empty list, not null",
                PkgCatalog.enabledOnes("Repositories:\n" + block("FreeBSD-ports", "x", "no")).isEmpty());

        System.out.println("\n== FreeBSD 15: two enabled, one disabled, the old FreeBSD, local.sqlite ==");
        Path pkg = root.resolve("db1");
        file(pkg.resolve("repos/FreeBSD-ports/db"), 26);
        file(pkg.resolve("repos/FreeBSD-ports-kmods/db"), 50);
        file(pkg.resolve("repos/FreeBSD-base/db"), 24 * 90);
        file(pkg.resolve("repos/FreeBSD/db"), 24 * 400);
        file(pkg.resolve("local.sqlite"), 0);
        JSONObject c = PkgCatalog.data(pkg.toString(), enabledOnes, NOW);
        require("the oldest among the enabled ones counts: " + c.optString("oldest") + ", " + c.optLong("days") + " days",
                "FreeBSD-ports-kmods".equals(c.optString("oldest")) && c.optLong("days") == 2 && c.optLong("hours") == 50);
        require("only the two enabled ones", c.getJSONArray("repository").length() == 2);
        String note = PkgCatalog.note(c);
        System.out.println("  note: " + note);
        require("the note has the two dates, \"yesterday\" and \"2 days ago\"", note.contains("FreeBSD-ports on ")
                && note.contains("(yesterday)") && note.contains("(2 days ago)"));
        require("and it says it is the server's date", note.contains("not of the last check"));

        System.out.println("\n== an enabled one without a catalog; no catalog; repositories all disabled ==");
        Path pkg2 = root.resolve("db2");
        file(pkg2.resolve("repos/FreeBSD-ports/db"), 3);
        c = PkgCatalog.data(pkg2.toString(), enabledOnes, NOW);
        require("today, and FreeBSD-ports-kmods among the missing", c.optLong("days") == 0
                && c.getJSONArray("missing").toList().equals(List.of("FreeBSD-ports-kmods")));
        require("the note says so", PkgCatalog.note(c).contains("The repository FreeBSD-ports-kmods is enabled but has no"));
        Path pkg3 = root.resolve("db3");
        Files.createDirectories(pkg3);
        c = PkgCatalog.data(pkg3.toString(), enabledOnes, NOW);
        note = PkgCatalog.note(c);
        require("no catalog: days -1, and the note says where it looked: " + note,
                c.optLong("days") == -1 && note.contains("repos/FreeBSD-ports/db"));
        c = PkgCatalog.data(pkg.toString(), List.of(), NOW);
        require("all disabled: it says so, instead of \"I don't know\": " + PkgCatalog.note(c),
                PkgCatalog.note(c).startsWith("No pkg repository is enabled"));

        System.out.println("\n== old pkg, silent pkg -vv, odd name, clock behind ==");
        Path pkg4 = root.resolve("db4");
        file(pkg4.resolve("repo-FreeBSD.sqlite"), 30);
        c = PkgCatalog.data(pkg4.toString(), List.of("FreeBSD"), NOW);
        require("repo-<name>.sqlite still recognised", c.optString("file").endsWith("repo-FreeBSD.sqlite"));
        c = PkgCatalog.data(pkg.toString(), null, NOW);
        require("without pkg -vv the catalogs that are there are taken (4)", c.getJSONArray("repository").length() == 4);
        c = PkgCatalog.data(pkg.toString(), List.of("../../etc"), NOW);
        require("a name with ../ does not end up in a path", c.getJSONArray("repository").getJSONObject(0).has("error"));
        Path pkg5 = root.resolve("db5");
        file(pkg5.resolve("repos/FreeBSD-ports/db"), -2);
        c = PkgCatalog.data(pkg5.toString(), List.of("FreeBSD-ports"), NOW);
        require("date in the future: today, not a negative age", c.optLong("days") == 0);

        System.out.println("\n== the report ==");
        c = PkgCatalog.data(pkg.toString(), enabledOnes, NOW);
        c.put("note", PkgCatalog.note(c));
        PanelMail.Message report = ReportMail.message(new ReportMail.Context("en", "mail.example.org", "admin@example.org",
                true, "weekly", java.time.ZonedDateTime.now()), new JSONObject()
                .put("catalog", c).put("catalogDays", c.optLong("days")).put("catalogDate", c.optString("data"))
                .put("refreshedCatalog", true).put("vulnDbDays", 0));
        // In the text the lines wrap at 72 columns: it is searched with the spaces reduced to one.
        String t = report.text().replaceAll("\\s+", " ");
        int at = t.indexOf("Package catalog: published 2 days ago (");
        System.out.println("  " + (at < 0 ? "(the catalog line is missing)" : t.substring(at, Math.min(t.length(), at + 90))));
        require("the report says when it was published, and that it was checked just now",
                at >= 0 && t.indexOf("checked just now", at) > at && t.indexOf("checked just now", at) - at < 100);
        require("and with two repositories it adds the whole sentence", t.contains("The counts are as fresh as the oldest"));
        require("no more \"age unknown\" for the catalog", !t.contains("Package catalog: age unknown")
                && !t.contains("publication date unknown"));
        require("the HTML says it too", report.html().contains("published 2 days ago (") && report.html().contains("checked just now"));

        System.out.println("\n== where it looked before ==");
        require("on FreeBSD 15 /var/db/pkg/repo-FreeBSD.sqlite is not there: hence \"age unknown\"",
                !Files.exists(pkg.resolve("repo-FreeBSD.sqlite")));
    }
}
