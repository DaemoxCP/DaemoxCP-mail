package org.mail_panel.system;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Il ramo dei pacchetti (PkgBranch): leggerlo e cambiarlo.
 *
 * Il sistema finto fa quello che fa pkg (libpkg/pkg_config.c, letto il 03/10/2026): parte da
 * /etc/pkg/FreeBSD.conf di FreeBSD 15.0 RELEASE (quarterly, moduli con la versione minore,
 * FreeBSD-base spento), poi legge i *.conf di /usr/local/etc/pkg/repos in ordine alfabetico, e
 * ogni blocco sovrascrive i campi del repository con lo stesso nome; ${ABI} e ${VERSION_MINOR}
 * si espandono. pkg -vv lo stampa come print_repository. Cosi' il cambio di ramo e i suoi
 * ripristini si provano contro le regole vere: il file del pannello che vince perche' e'
 * l'ultimo, un file dell'utente letto dopo che vince lui, un catalogo che non si scarica.
 *
 * Uso: java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PkgBranchTest
 */
public class PkgBranchTest {

    static int failed = 0;

    static void real(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FALLITO ") + what);
        if (!ok) failed++;
    }

    static final String STOCK = """
            FreeBSD-ports: {
              url: "pkg+https://pkg.FreeBSD.org/${ABI}/quarterly",
              mirror_type: "srv",
              signature_type: "fingerprints",
              fingerprints: "/usr/share/keys/pkg",
              enabled: yes
            }
            FreeBSD-ports-kmods: {
              url: "pkg+https://pkg.FreeBSD.org/${ABI}/kmods_quarterly_${VERSION_MINOR}",
              mirror_type: "srv",
              signature_type: "fingerprints",
              fingerprints: "/usr/share/keys/pkg",
              enabled: yes
            }
            FreeBSD-base: {
              url: "pkg+https://pkg.FreeBSD.org/${ABI}/base_release_${VERSION_MINOR}",
              mirror_type: "srv",
              signature_type: "fingerprints",
              fingerprints: "/usr/share/keys/pkgbase-${VERSION_MAJOR}",
              enabled: no
            }
            """;

    /** Un FreeBSD finto, con la configurazione di pkg in memoria. */
    static class FakeSystem implements PkgBranch.SystemAccess {
        String stock = STOCK;
        final TreeMap<String, String> folder = new TreeMap<>();   // nome -> contenuto, in ordine come scandir
        String unreachable = null;                               // un pezzo di indirizzo che "pkg update" non scarica
        boolean pkgBroken = false, brokenWrite = false;
        final List<String> log = new ArrayList<>();
        int updates = 0;
        String latestVersions = "nginx-1.28.0_3,3          <   needs updating (remote has 1.28.1,3)\n"
                + "php84-8.4.13                <   needs updating (remote has 8.4.14)\n";
        String quarterlyVersions = "nginx-1.28.1,3          >   succeeds index (remote has 1.28.0_3,3)\n"
                + "php84-8.4.14                >   succeeds index (remote has 8.4.13)\n"
                + "curl-8.16.0                 <   needs updating (remote has 8.16.0_1)\n";

        /** Le regole di pkg_config.c: ogni blocco sovrascrive i campi che nomina. */
        Map<String, Map<String, String>> config() {
            Map<String, Map<String, String>> repos = new LinkedHashMap<>();
            join(repos, stock);
            for (String f : folder.keySet()) if (f.endsWith(".conf") && !f.startsWith(".")) join(repos, folder.get(f));
            return repos;
        }

        static void join(Map<String, Map<String, String>> repos, String text) {
            // Le graffe di ${ABI} non chiudono il blocco: si mettono da parte prima di dividerlo.
            text = text.replaceAll("\\$\\{(\\w+)\\}", "\u0001$1\u0002");
            Matcher b = Pattern.compile("(?m)^\\s*([A-Za-z0-9._-]+)\\s*:\\s*\\{([^}]*)\\}").matcher(text);
            while (b.find()) {
                Map<String, String> r = repos.computeIfAbsent(b.group(1), k -> new LinkedHashMap<>(Map.of("enabled", "yes", "priority", "0")));
                r.put("priority", "0");   // add_repo: un blocco senza priority la rimette a 0
                Matcher c = Pattern.compile("(\\w+)\\s*:\\s*(\"[^\"]*\"|[\\w-]+)").matcher(b.group(2));
                while (c.find()) r.put(c.group(1), c.group(2).replace("\"", "").replaceAll("\u0001(\\w+)\u0002", "\\${$1}"));
            }
        }

        static String expand(String url) {
            return url.replace("${ABI}", "FreeBSD:15:amd64").replace("${VERSION_MINOR}", "0").replace("${VERSION_MAJOR}", "15");
        }

        public String pkgVv() {
            if (pkgBroken) return null;
            StringBuilder o = new StringBuilder("Version                 : 2.3.1\nPKG_DBDIR = \"/var/db/pkg\";\n\nRepositories:\n");
            for (Map.Entry<String, Map<String, String>> e : config().entrySet()) {
                Map<String, String> r = e.getValue();
                o.append("  ").append(e.getKey()).append(": { \n")
                 .append("    url             : \"").append(expand(r.getOrDefault("url", ""))).append("\",\n")
                 .append("    enabled         : ").append("no".equals(r.get("enabled")) ? "no" : "yes").append(",\n")
                 .append("    priority        : ").append(r.get("priority"));
                o.append(",\n    mirror_type     : \"SRV\",\n    signature_type  : \"FINGERPRINTS\"");
                if (r.containsKey("ip_version")) o.append(",\n    ip_version      : ").append(r.get("ip_version"));
                o.append("\n  }\n");
            }
            return o.toString();
        }
        public String read(Path p) {
            return p.getParent().equals(PkgBranch.FOLDER) ? folder.get(p.getFileName().toString()) : null;
        }
        public List<String> fileConf(Path c) {
            List<String> l = new ArrayList<>();
            for (String f : folder.keySet()) if (f.endsWith(".conf") && !f.startsWith(".")) l.add(f);
            return l;
        }
        public void write(Path p, String content) throws IOException {
            if (brokenWrite) throw new IOException("Read-only file system");
            folder.put(p.getFileName().toString(), content);
        }
        public void delete(Path p) { folder.remove(p.getFileName().toString()); }
        public PkgBranch.Outcome pkgUpdate(PkgBranch.LineSink r) {
            updates++;
            for (Map.Entry<String, Map<String, String>> e : config().entrySet()) {
                if ("no".equals(e.getValue().get("enabled"))) continue;
                String u = expand(e.getValue().get("url"));
                r.line("Updating " + e.getKey() + " repository catalogue...");
                if (unreachable != null && u.contains(unreachable)) {
                    r.line("pkg: " + u + "/meta.conf: Not Found");
                    r.line("Error updating repositories!");
                    return new PkgBranch.Outcome(1, "Not Found");
                }
            }
            r.line("All repositories are up to date.");
            return new PkgBranch.Outcome(0, "ok");
        }
        public String pkgVersions() {
            String ports = expand(config().get("FreeBSD-ports").get("url"));
            return ports.endsWith("/latest") ? latestVersions : quarterlyVersions;
        }
        public Instant now() { return Instant.parse("2026-10-03T12:00:00Z"); }

        String seenBranch() { return PkgBranch.state(this).optString("branch"); }
    }

    static PkgBranch.LineSink logInto(FakeSystem f) { return f.log::add; }

    public static void main(String[] args) throws Exception {
        System.out.println("\n== Leggere i repository da pkg -vv ==");
        FakeSystem f = new FakeSystem();
        JSONObject st = PkgBranch.state(f);
        real("FreeBSD 15 di serie: ramo quarterly", st.getBoolean("success") && st.getString("branch").equals("quarterly"));
        JSONArray rep = st.getJSONArray("repository");
        real("tre repository: pacchetti, moduli del kernel, sistema base (spento)", rep.length() == 3
                && rep.getJSONObject(0).getString("type").equals("packages") && rep.getJSONObject(1).getString("type").equals("modules")
                && rep.getJSONObject(2).getString("type").equals("base") && !rep.getJSONObject(2).getBoolean("enabled"));
        real("si puo' cambiare, verso latest", st.getBoolean("changeable") && st.getJSONArray("destination").toList().equals(List.of("latest")));
        real("nessun file del pannello", !st.getBoolean("panelOwnedFile"));
        PkgBranch.Repo k = PkgBranch.classify("FreeBSD-ports-kmods", "pkg+https://pkg.FreeBSD.org/FreeBSD:15:amd64/kmods_quarterly_0", true, 0, null);
        real("i moduli con la versione minore: kmods_latest_${VERSION_MINOR}",
                PkgBranch.address(k, "latest").equals("pkg+https://pkg.FreeBSD.org/${ABI}/kmods_latest_${VERSION_MINOR}"));
        PkgBranch.Repo ks = PkgBranch.classify("FreeBSD-ports-kmods", "pkg+https://pkg.FreeBSD.org/FreeBSD:15:amd64/kmods_quarterly", true, 0, null);
        real("su -STABLE i moduli senza versione minore: kmods_latest",
                PkgBranch.address(ks, "latest").equals("pkg+https://pkg.FreeBSD.org/${ABI}/kmods_latest"));
        PkgBranch.Repo old = PkgBranch.classify("FreeBSD", "pkg+http://pkg.FreeBSD.org/FreeBSD:14:amd64/latest", true, 0, null);
        real("FreeBSD 14 (repository \"FreeBSD\", http): pacchetti, ramo latest", old.type().equals("packages") && old.branch().equals("latest"));
        real("un mirror o un repository proprio non e' ufficiale",
                PkgBranch.classify("poudriere", "file:///usr/local/poudriere/data/packages/15amd64-default", true, 0, null).type().equals("external")
                && PkgBranch.classify("FreeBSD-ports", "pkg+https://mirror.example.org/FreeBSD:15:amd64/quarterly", true, 0, null).type().equals("external"));

        FakeSystem own = new FakeSystem();
        own.folder.put("FreeBSD.conf", "FreeBSD-ports: { enabled: no }\nFreeBSD-ports-kmods: { enabled: no }\n");
        own.folder.put("poudriere.conf", "poudriere: { url: \"file:///usr/local/poudriere/data/packages/15amd64-default\" }\n");
        st = PkgBranch.state(own);
        real("pacchetti da un repository proprio: non si cambia, e si dice perche'", st.getString("branch").equals("none")
                && !st.getBoolean("changeable") && st.getString("reason").contains("repository che usi"));

        FakeSystem mixed = new FakeSystem();
        mixed.folder.put("FreeBSD.conf", "FreeBSD-ports: { url: \"pkg+https://pkg.FreeBSD.org/${ABI}/latest\" }\n");
        st = PkgBranch.state(mixed);
        real("pacchetti latest e moduli quarterly: \"misti\", e si puo' allineare a tutti e due",
                st.getString("branch").equals("mixed") && st.getJSONArray("destination").length() == 2);

        FakeSystem base = new FakeSystem();
        base.folder.put("FreeBSD.conf", "FreeBSD-base: { enabled: yes }\n");
        st = PkgBranch.state(base);
        real("FreeBSD-base acceso: lo si dice, e resta fuori", st.optString("base").contains("non lo tocca"));

        FakeSystem pr = new FakeSystem();
        pr.pkgBroken = true;
        real("pkg che non risponde: lo si dice, niente ramo inventato", !PkgBranch.state(pr).getBoolean("success"));

        System.out.println("\n== Anteprima ==");
        f = new FakeSystem();
        JSONObject an = PkgBranch.preview(f, "latest");
        real("verso latest: possibile, con i due indirizzi nuovi", an.getBoolean("possible") && an.getJSONArray("changes").length() == 2
                && an.getJSONArray("changes").getJSONObject(0).getString("to").equals("pkg+https://pkg.FreeBSD.org/${ABI}/latest"));
        real("il file che scriverebbe, con le variabili di pkg (non l'ABI di oggi)", an.getString("content").contains(
                "FreeBSD-ports-kmods: { url: \"pkg+https://pkg.FreeBSD.org/${ABI}/kmods_latest_${VERSION_MINOR}\" }")
                && !an.getString("content").contains("FreeBSD:15"));
        real("FreeBSD-base non compare nel file", !an.getString("content").contains("FreeBSD-base"));
        real("dice che non aggiorna nessun pacchetto", an.getJSONArray("warnings").getString(0).startsWith("Non si aggiorna nessun pacchetto"));
        real("verso il ramo in cui si e' gia': no", !PkgBranch.preview(f, "quarterly").getBoolean("possible"));
        real("un ramo inventato: no", !PkgBranch.preview(f, "weekly").getBoolean("success"));
        real("l'anteprima non tocca niente", f.folder.isEmpty() && f.updates == 0);
        FakeSystem priority = new FakeSystem();
        priority.folder.put("FreeBSD.conf", "FreeBSD-ports: { priority: 5, ip_version: 4 }\n");
        real("una priority e un ip_version diversi da quelli di serie si riscrivono uguali (un blocco li azzererebbe)",
                PkgBranch.preview(priority, "latest").getString("content").contains("latest\", priority: 5, ip_version: 4 }"));

        System.out.println("\n== Cambiare: quarterly -> latest ==");
        f = new FakeSystem();
        String imp = PkgBranch.state(f).getString("fingerprint");
        JSONObject r = PkgBranch.change(f, logInto(f), "latest", imp);
        real("riuscito: " + r.optString("messageText", r.optString("error")), r.getBoolean("success") && r.getString("branch").equals("latest"));
        real("pkg ora vede latest, anche per i moduli", f.seenBranch().equals("latest"));
        real("il file del pannello c'e', con la marca", f.folder.get("zz-panel-branch.conf").startsWith(PkgBranch.MARK));
        real("catalogo scaricato una volta", f.updates == 1);
        real("conta gli aggiornabili dal catalogo nuovo (2), senza aggiornarli", r.getInt("updatable") == 2
                && r.getString("messageText").contains("Nessun pacchetto è stato cambiato"));

        System.out.println("\n== Cambiare: latest -> quarterly (il file del pannello si toglie) ==");
        imp = PkgBranch.state(f).getString("fingerprint");
        r = PkgBranch.change(f, logInto(f), "quarterly", imp);
        real("riuscito", r.getBoolean("success") && f.seenBranch().equals("quarterly"));
        real("di serie e' gia' quarterly: il file del pannello e' tolto, non riscritto", !f.folder.containsKey("zz-panel-branch.conf"));
        real("i pacchetti piu' nuovi del ramo sono detti, e restano come sono: " + r.getJSONArray("mostRecent"),
                r.getJSONArray("mostRecent").length() == 2 && r.getString("messageText").contains("restano come sono"));

        System.out.println("\n== Il file dell'utente non si tocca ==");
        FakeSystem u = new FakeSystem();
        String its = "FreeBSD-ports: { url: \"pkg+https://pkg.FreeBSD.org/${ABI}/latest\" }\nFreeBSD-ports-kmods: { url: \"pkg+https://pkg.FreeBSD.org/${ABI}/kmods_latest_${VERSION_MINOR}\" }\n";
        u.folder.put("FreeBSD.conf", its);
        imp = PkgBranch.state(u).getString("fingerprint");
        r = PkgBranch.change(u, logInto(u), "quarterly", imp);
        real("latest dal suo FreeBSD.conf -> quarterly: riuscito con un file del pannello, letto dopo il suo", r.getBoolean("success")
                && u.seenBranch().equals("quarterly") && u.folder.get("zz-panel-branch.conf").contains("/quarterly\""));
        real("il suo FreeBSD.conf e' intatto", its.equals(u.folder.get("FreeBSD.conf")));

        System.out.println("\n== Quando non riesce, torna tutto com'era ==");
        FakeSystem after = new FakeSystem();
        after.folder.put("zzz-mio.conf", "FreeBSD-ports: { url: \"pkg+https://pkg.FreeBSD.org/${ABI}/quarterly\" }\n");
        imp = PkgBranch.state(after).getString("fingerprint");
        real("l'anteprima avverte del file letto dopo", PkgBranch.preview(after, "latest").getJSONArray("warnings").toString().contains("zzz-mio.conf"));
        r = PkgBranch.change(after, logInto(after), "latest", imp);
        real("un file letto dopo quello del pannello rimette quarterly: rifiutato, e lo nomina — " + r.optString("error"),
                !r.getBoolean("success") && r.getString("error").contains("zzz-mio.conf"));
        real("il file del pannello non e' rimasto, il catalogo non si e' scaricato", !after.folder.containsKey("zz-panel-branch.conf")
                && after.updates == 0 && after.seenBranch().equals("quarterly"));

        FakeSystem network = new FakeSystem();
        network.unreachable = "kmods_latest";
        imp = PkgBranch.state(network).getString("fingerprint");
        r = PkgBranch.change(network, logInto(network), "latest", imp);
        real("il catalogo dei moduli latest non si scarica: rifiutato — " + r.optString("error"),
                !r.getBoolean("success") && r.getString("error").contains("non si scarica"));
        real("la configurazione e' tornata quarterly e il file del pannello non c'e'", network.seenBranch().equals("quarterly")
                && !network.folder.containsKey("zz-panel-branch.conf"));
        real("nel registro c'e' l'errore di pkg", String.join("\n", network.log).contains("Not Found"));

        FakeSystem alreadyLatest = new FakeSystem();
        alreadyLatest.folder.put("zz-panel-branch.conf", PkgBranch.content(PkgBranch.repository(new FakeSystem().pkgVv()), "latest", alreadyLatest.now()));
        String beforeFault = alreadyLatest.folder.get("zz-panel-branch.conf");
        alreadyLatest.unreachable = "/quarterly";
        imp = PkgBranch.state(alreadyLatest).getString("fingerprint");
        r = PkgBranch.change(alreadyLatest, logInto(alreadyLatest), "quarterly", imp);
        real("latest (dal pannello) -> quarterly che non si scarica: il file del pannello torna, identico", !r.getBoolean("success")
                && beforeFault.equals(alreadyLatest.folder.get("zz-panel-branch.conf")) && alreadyLatest.seenBranch().equals("latest"));

        FakeSystem ro = new FakeSystem();
        ro.brokenWrite = true;
        imp = PkgBranch.state(ro).getString("fingerprint");
        r = PkgBranch.change(ro, logInto(ro), "latest", imp);
        real("cartella non scrivibile: errore detto, niente scaricato", !r.getBoolean("success") && r.getString("error").contains("Read-only")
                && ro.updates == 0);

        System.out.println("\n== L'fingerprint: si cambia solo cio' che si e' visto ==");
        FakeSystem changed = new FakeSystem();
        imp = PkgBranch.state(changed).getString("fingerprint");
        changed.folder.put("FreeBSD.conf", "FreeBSD-ports-kmods: { enabled: no }\n");
        r = PkgBranch.change(changed, logInto(changed), "latest", imp);
        real("la configurazione cambia dopo l'anteprima: rifiutato senza toccare niente", !r.getBoolean("success")
                && r.getString("error").contains("dopo l'anteprima") && !changed.folder.containsKey("zz-panel-branch.conf"));

        System.out.println("\n== Il file vero, su disco ==");
        Path dir = Files.createTempDirectory("ramo-prova");
        PkgBranch.SystemAccess real = PkgBranch.real();
        Path p = dir.resolve("zz-panel-branch.conf");
        real.write(p, "prova\n");
        real("scritto, con i permessi rw-r--r--, senza file temporanei rimasti", "prova\n".equals(real.read(p))
                && java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(p)).equals("rw-r--r--")
                && real.fileConf(dir).equals(List.of("zz-panel-branch.conf")) && Files.list(dir).count() == 1);
        Files.writeString(dir.resolve("FreeBSD.conf"), "x");
        Files.writeString(dir.resolve("FreeBSD.conf.before"), "x");
        Files.writeString(dir.resolve(".nascosto.conf"), "x");
        real("i .conf come li legge pkg: in ordine, senza nascosti e altre estensioni: " + real.fileConf(dir),
                real.fileConf(dir).equals(List.of("FreeBSD.conf", "zz-panel-branch.conf")));
        real.delete(p);
        real("eliminato", real.read(p) == null);
        try (var s = Files.list(dir)) { s.forEach(x -> x.toFile().delete()); }
        Files.delete(dir);

        System.out.println("\n" + (failed == 0 ? "TUTTO VERDE" : failed + " CONTROLLI FALLITI"));
        System.exit(failed == 0 ? 0 : 1);
    }
}
