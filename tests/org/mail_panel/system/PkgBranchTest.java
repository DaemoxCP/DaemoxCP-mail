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

    static int falliti = 0;

    static void vero(String cosa, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FALLITO ") + cosa);
        if (!ok) falliti++;
    }

    static final String DI_SERIE = """
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
    static class FakeSystem implements PkgBranch.Sistema {
        String diSerie = DI_SERIE;
        final TreeMap<String, String> cartella = new TreeMap<>();   // nome -> contenuto, in ordine come scandir
        String nonRaggiungibile = null;                               // un pezzo di indirizzo che "pkg update" non scarica
        boolean pkgRotto = false, scritturaRotta = false;
        final List<String> registro = new ArrayList<>();
        int aggiornamenti = 0;
        String versioniLatest = "nginx-1.28.0_3,3          <   needs updating (remote has 1.28.1,3)\n"
                + "php84-8.4.13                <   needs updating (remote has 8.4.14)\n";
        String versioniQuarterly = "nginx-1.28.1,3          >   succeeds index (remote has 1.28.0_3,3)\n"
                + "php84-8.4.14                >   succeeds index (remote has 8.4.13)\n"
                + "curl-8.16.0                 <   needs updating (remote has 8.16.0_1)\n";

        /** Le regole di pkg_config.c: ogni blocco sovrascrive i campi che nomina. */
        Map<String, Map<String, String>> config() {
            Map<String, Map<String, String>> repos = new LinkedHashMap<>();
            unisci(repos, diSerie);
            for (String f : cartella.keySet()) if (f.endsWith(".conf") && !f.startsWith(".")) unisci(repos, cartella.get(f));
            return repos;
        }

        static void unisci(Map<String, Map<String, String>> repos, String testo) {
            // Le graffe di ${ABI} non chiudono il blocco: si mettono da parte prima di dividerlo.
            testo = testo.replaceAll("\\$\\{(\\w+)\\}", "\u0001$1\u0002");
            Matcher b = Pattern.compile("(?m)^\\s*([A-Za-z0-9._-]+)\\s*:\\s*\\{([^}]*)\\}").matcher(testo);
            while (b.find()) {
                Map<String, String> r = repos.computeIfAbsent(b.group(1), k -> new LinkedHashMap<>(Map.of("enabled", "yes", "priority", "0")));
                r.put("priority", "0");   // add_repo: un blocco senza priority la rimette a 0
                Matcher c = Pattern.compile("(\\w+)\\s*:\\s*(\"[^\"]*\"|[\\w-]+)").matcher(b.group(2));
                while (c.find()) r.put(c.group(1), c.group(2).replace("\"", "").replaceAll("\u0001(\\w+)\u0002", "\\${$1}"));
            }
        }

        static String espandi(String url) {
            return url.replace("${ABI}", "FreeBSD:15:amd64").replace("${VERSION_MINOR}", "0").replace("${VERSION_MAJOR}", "15");
        }

        public String pkgVv() {
            if (pkgRotto) return null;
            StringBuilder o = new StringBuilder("Version                 : 2.3.1\nPKG_DBDIR = \"/var/db/pkg\";\n\nRepositories:\n");
            for (Map.Entry<String, Map<String, String>> e : config().entrySet()) {
                Map<String, String> r = e.getValue();
                o.append("  ").append(e.getKey()).append(": { \n")
                 .append("    url             : \"").append(espandi(r.getOrDefault("url", ""))).append("\",\n")
                 .append("    enabled         : ").append("no".equals(r.get("enabled")) ? "no" : "yes").append(",\n")
                 .append("    priority        : ").append(r.get("priority"));
                o.append(",\n    mirror_type     : \"SRV\",\n    signature_type  : \"FINGERPRINTS\"");
                if (r.containsKey("ip_version")) o.append(",\n    ip_version      : ").append(r.get("ip_version"));
                o.append("\n  }\n");
            }
            return o.toString();
        }
        public String leggi(Path p) {
            return p.getParent().equals(PkgBranch.FOLDER) ? cartella.get(p.getFileName().toString()) : null;
        }
        public List<String> fileConf(Path c) {
            List<String> l = new ArrayList<>();
            for (String f : cartella.keySet()) if (f.endsWith(".conf") && !f.startsWith(".")) l.add(f);
            return l;
        }
        public void scrivi(Path p, String contenuto) throws IOException {
            if (scritturaRotta) throw new IOException("Read-only file system");
            cartella.put(p.getFileName().toString(), contenuto);
        }
        public void elimina(Path p) { cartella.remove(p.getFileName().toString()); }
        public PkgBranch.Esito pkgUpdate(PkgBranch.Registro r) {
            aggiornamenti++;
            for (Map.Entry<String, Map<String, String>> e : config().entrySet()) {
                if ("no".equals(e.getValue().get("enabled"))) continue;
                String u = espandi(e.getValue().get("url"));
                r.riga("Updating " + e.getKey() + " repository catalogue...");
                if (nonRaggiungibile != null && u.contains(nonRaggiungibile)) {
                    r.riga("pkg: " + u + "/meta.conf: Not Found");
                    r.riga("Error updating repositories!");
                    return new PkgBranch.Esito(1, "Not Found");
                }
            }
            r.riga("All repositories are up to date.");
            return new PkgBranch.Esito(0, "ok");
        }
        public String pkgVersioni() {
            String porte = espandi(config().get("FreeBSD-ports").get("url"));
            return porte.endsWith("/latest") ? versioniLatest : versioniQuarterly;
        }
        public Instant adesso() { return Instant.parse("2026-10-03T12:00:00Z"); }

        String ramoVisto() { return PkgBranch.stato(this).optString("ramo"); }
    }

    static PkgBranch.Registro nel(FakeSystem f) { return f.registro::add; }

    public static void main(String[] args) throws Exception {
        System.out.println("\n== Leggere i repository da pkg -vv ==");
        FakeSystem f = new FakeSystem();
        JSONObject st = PkgBranch.stato(f);
        vero("FreeBSD 15 di serie: ramo quarterly", st.getBoolean("success") && st.getString("ramo").equals("quarterly"));
        JSONArray rep = st.getJSONArray("repository");
        vero("tre repository: pacchetti, moduli del kernel, sistema base (spento)", rep.length() == 3
                && rep.getJSONObject(0).getString("tipo").equals("pacchetti") && rep.getJSONObject(1).getString("tipo").equals("moduli")
                && rep.getJSONObject(2).getString("tipo").equals("base") && !rep.getJSONObject(2).getBoolean("acceso"));
        vero("si puo' cambiare, verso latest", st.getBoolean("changeable") && st.getJSONArray("verso").toList().equals(List.of("latest")));
        vero("nessun file del pannello", !st.getBoolean("panelOwnedFile"));
        PkgBranch.Repo k = PkgBranch.classifica("FreeBSD-ports-kmods", "pkg+https://pkg.FreeBSD.org/FreeBSD:15:amd64/kmods_quarterly_0", true, 0, null);
        vero("i moduli con la versione minore: kmods_latest_${VERSION_MINOR}",
                PkgBranch.indirizzo(k, "latest").equals("pkg+https://pkg.FreeBSD.org/${ABI}/kmods_latest_${VERSION_MINOR}"));
        PkgBranch.Repo ks = PkgBranch.classifica("FreeBSD-ports-kmods", "pkg+https://pkg.FreeBSD.org/FreeBSD:15:amd64/kmods_quarterly", true, 0, null);
        vero("su -STABLE i moduli senza versione minore: kmods_latest",
                PkgBranch.indirizzo(ks, "latest").equals("pkg+https://pkg.FreeBSD.org/${ABI}/kmods_latest"));
        PkgBranch.Repo vecchio = PkgBranch.classifica("FreeBSD", "pkg+http://pkg.FreeBSD.org/FreeBSD:14:amd64/latest", true, 0, null);
        vero("FreeBSD 14 (repository \"FreeBSD\", http): pacchetti, ramo latest", vecchio.tipo().equals("pacchetti") && vecchio.ramo().equals("latest"));
        vero("un mirror o un repository proprio non e' ufficiale",
                PkgBranch.classifica("poudriere", "file:///usr/local/poudriere/data/packages/15amd64-default", true, 0, null).tipo().equals("esterno")
                && PkgBranch.classifica("FreeBSD-ports", "pkg+https://mirror.example.org/FreeBSD:15:amd64/quarterly", true, 0, null).tipo().equals("esterno"));

        FakeSystem proprio = new FakeSystem();
        proprio.cartella.put("FreeBSD.conf", "FreeBSD-ports: { enabled: no }\nFreeBSD-ports-kmods: { enabled: no }\n");
        proprio.cartella.put("poudriere.conf", "poudriere: { url: \"file:///usr/local/poudriere/data/packages/15amd64-default\" }\n");
        st = PkgBranch.stato(proprio);
        vero("pacchetti da un repository proprio: non si cambia, e si dice perche'", st.getString("ramo").equals("nessuno")
                && !st.getBoolean("changeable") && st.getString("reason").contains("repository che usi"));

        FakeSystem misti = new FakeSystem();
        misti.cartella.put("FreeBSD.conf", "FreeBSD-ports: { url: \"pkg+https://pkg.FreeBSD.org/${ABI}/latest\" }\n");
        st = PkgBranch.stato(misti);
        vero("pacchetti latest e moduli quarterly: \"misti\", e si puo' allineare a tutti e due",
                st.getString("ramo").equals("misti") && st.getJSONArray("verso").length() == 2);

        FakeSystem base = new FakeSystem();
        base.cartella.put("FreeBSD.conf", "FreeBSD-base: { enabled: yes }\n");
        st = PkgBranch.stato(base);
        vero("FreeBSD-base acceso: lo si dice, e resta fuori", st.optString("base").contains("non lo tocca"));

        FakeSystem pr = new FakeSystem();
        pr.pkgRotto = true;
        vero("pkg che non risponde: lo si dice, niente ramo inventato", !PkgBranch.stato(pr).getBoolean("success"));

        System.out.println("\n== Anteprima ==");
        f = new FakeSystem();
        JSONObject an = PkgBranch.anteprima(f, "latest");
        vero("verso latest: possibile, con i due indirizzi nuovi", an.getBoolean("possibile") && an.getJSONArray("changes").length() == 2
                && an.getJSONArray("changes").getJSONObject(0).getString("a").equals("pkg+https://pkg.FreeBSD.org/${ABI}/latest"));
        vero("il file che scriverebbe, con le variabili di pkg (non l'ABI di oggi)", an.getString("contenuto").contains(
                "FreeBSD-ports-kmods: { url: \"pkg+https://pkg.FreeBSD.org/${ABI}/kmods_latest_${VERSION_MINOR}\" }")
                && !an.getString("contenuto").contains("FreeBSD:15"));
        vero("FreeBSD-base non compare nel file", !an.getString("contenuto").contains("FreeBSD-base"));
        vero("dice che non aggiorna nessun pacchetto", an.getJSONArray("warnings").getString(0).startsWith("Non si aggiorna nessun pacchetto"));
        vero("verso il ramo in cui si e' gia': no", !PkgBranch.anteprima(f, "quarterly").getBoolean("possibile"));
        vero("un ramo inventato: no", !PkgBranch.anteprima(f, "weekly").getBoolean("success"));
        vero("l'anteprima non tocca niente", f.cartella.isEmpty() && f.aggiornamenti == 0);
        FakeSystem prio = new FakeSystem();
        prio.cartella.put("FreeBSD.conf", "FreeBSD-ports: { priority: 5, ip_version: 4 }\n");
        vero("una priority e un ip_version diversi da quelli di serie si riscrivono uguali (un blocco li azzererebbe)",
                PkgBranch.anteprima(prio, "latest").getString("contenuto").contains("latest\", priority: 5, ip_version: 4 }"));

        System.out.println("\n== Cambiare: quarterly -> latest ==");
        f = new FakeSystem();
        String imp = PkgBranch.stato(f).getString("fingerprint");
        JSONObject r = PkgBranch.cambia(f, nel(f), "latest", imp);
        vero("riuscito: " + r.optString("messaggio", r.optString("error")), r.getBoolean("success") && r.getString("ramo").equals("latest"));
        vero("pkg ora vede latest, anche per i moduli", f.ramoVisto().equals("latest"));
        vero("il file del pannello c'e', con la marca", f.cartella.get("zz-panel-branch.conf").startsWith(PkgBranch.MARCA));
        vero("catalogo scaricato una volta", f.aggiornamenti == 1);
        vero("conta gli aggiornabili dal catalogo nuovo (2), senza aggiornarli", r.getInt("aggiornabili") == 2
                && r.getString("messaggio").contains("Nessun pacchetto è stato cambiato"));

        System.out.println("\n== Cambiare: latest -> quarterly (il file del pannello si toglie) ==");
        imp = PkgBranch.stato(f).getString("fingerprint");
        r = PkgBranch.cambia(f, nel(f), "quarterly", imp);
        vero("riuscito", r.getBoolean("success") && f.ramoVisto().equals("quarterly"));
        vero("di serie e' gia' quarterly: il file del pannello e' tolto, non riscritto", !f.cartella.containsKey("zz-panel-branch.conf"));
        vero("i pacchetti piu' nuovi del ramo sono detti, e restano come sono: " + r.getJSONArray("piuRecenti"),
                r.getJSONArray("piuRecenti").length() == 2 && r.getString("messaggio").contains("restano come sono"));

        System.out.println("\n== Il file dell'utente non si tocca ==");
        FakeSystem u = new FakeSystem();
        String suo = "FreeBSD-ports: { url: \"pkg+https://pkg.FreeBSD.org/${ABI}/latest\" }\nFreeBSD-ports-kmods: { url: \"pkg+https://pkg.FreeBSD.org/${ABI}/kmods_latest_${VERSION_MINOR}\" }\n";
        u.cartella.put("FreeBSD.conf", suo);
        imp = PkgBranch.stato(u).getString("fingerprint");
        r = PkgBranch.cambia(u, nel(u), "quarterly", imp);
        vero("latest dal suo FreeBSD.conf -> quarterly: riuscito con un file del pannello, letto dopo il suo", r.getBoolean("success")
                && u.ramoVisto().equals("quarterly") && u.cartella.get("zz-panel-branch.conf").contains("/quarterly\""));
        vero("il suo FreeBSD.conf e' intatto", suo.equals(u.cartella.get("FreeBSD.conf")));

        System.out.println("\n== Quando non riesce, torna tutto com'era ==");
        FakeSystem dopo = new FakeSystem();
        dopo.cartella.put("zzz-mio.conf", "FreeBSD-ports: { url: \"pkg+https://pkg.FreeBSD.org/${ABI}/quarterly\" }\n");
        imp = PkgBranch.stato(dopo).getString("fingerprint");
        vero("l'anteprima avverte del file letto dopo", PkgBranch.anteprima(dopo, "latest").getJSONArray("warnings").toString().contains("zzz-mio.conf"));
        r = PkgBranch.cambia(dopo, nel(dopo), "latest", imp);
        vero("un file letto dopo quello del pannello rimette quarterly: rifiutato, e lo nomina — " + r.optString("error"),
                !r.getBoolean("success") && r.getString("error").contains("zzz-mio.conf"));
        vero("il file del pannello non e' rimasto, il catalogo non si e' scaricato", !dopo.cartella.containsKey("zz-panel-branch.conf")
                && dopo.aggiornamenti == 0 && dopo.ramoVisto().equals("quarterly"));

        FakeSystem rete = new FakeSystem();
        rete.nonRaggiungibile = "kmods_latest";
        imp = PkgBranch.stato(rete).getString("fingerprint");
        r = PkgBranch.cambia(rete, nel(rete), "latest", imp);
        vero("il catalogo dei moduli latest non si scarica: rifiutato — " + r.optString("error"),
                !r.getBoolean("success") && r.getString("error").contains("non si scarica"));
        vero("la configurazione e' tornata quarterly e il file del pannello non c'e'", rete.ramoVisto().equals("quarterly")
                && !rete.cartella.containsKey("zz-panel-branch.conf"));
        vero("nel registro c'e' l'errore di pkg", String.join("\n", rete.registro).contains("Not Found"));

        FakeSystem giaLatest = new FakeSystem();
        giaLatest.cartella.put("zz-panel-branch.conf", PkgBranch.contenuto(PkgBranch.repository(new FakeSystem().pkgVv()), "latest", giaLatest.adesso()));
        String primaDelGuasto = giaLatest.cartella.get("zz-panel-branch.conf");
        giaLatest.nonRaggiungibile = "/quarterly";
        imp = PkgBranch.stato(giaLatest).getString("fingerprint");
        r = PkgBranch.cambia(giaLatest, nel(giaLatest), "quarterly", imp);
        vero("latest (dal pannello) -> quarterly che non si scarica: il file del pannello torna, identico", !r.getBoolean("success")
                && primaDelGuasto.equals(giaLatest.cartella.get("zz-panel-branch.conf")) && giaLatest.ramoVisto().equals("latest"));

        FakeSystem ro = new FakeSystem();
        ro.scritturaRotta = true;
        imp = PkgBranch.stato(ro).getString("fingerprint");
        r = PkgBranch.cambia(ro, nel(ro), "latest", imp);
        vero("cartella non scrivibile: errore detto, niente scaricato", !r.getBoolean("success") && r.getString("error").contains("Read-only")
                && ro.aggiornamenti == 0);

        System.out.println("\n== L'fingerprint: si cambia solo cio' che si e' visto ==");
        FakeSystem cambiato = new FakeSystem();
        imp = PkgBranch.stato(cambiato).getString("fingerprint");
        cambiato.cartella.put("FreeBSD.conf", "FreeBSD-ports-kmods: { enabled: no }\n");
        r = PkgBranch.cambia(cambiato, nel(cambiato), "latest", imp);
        vero("la configurazione cambia dopo l'anteprima: rifiutato senza toccare niente", !r.getBoolean("success")
                && r.getString("error").contains("dopo l'anteprima") && !cambiato.cartella.containsKey("zz-panel-branch.conf"));

        System.out.println("\n== Il file vero, su disco ==");
        Path dir = Files.createTempDirectory("ramo-prova");
        PkgBranch.Sistema vero = PkgBranch.reale();
        Path p = dir.resolve("zz-panel-branch.conf");
        vero.scrivi(p, "prova\n");
        vero("scritto, con i permessi rw-r--r--, senza file temporanei rimasti", "prova\n".equals(vero.leggi(p))
                && java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(p)).equals("rw-r--r--")
                && vero.fileConf(dir).equals(List.of("zz-panel-branch.conf")) && Files.list(dir).count() == 1);
        Files.writeString(dir.resolve("FreeBSD.conf"), "x");
        Files.writeString(dir.resolve("FreeBSD.conf.prima"), "x");
        Files.writeString(dir.resolve(".nascosto.conf"), "x");
        vero("i .conf come li legge pkg: in ordine, senza nascosti e altre estensioni: " + vero.fileConf(dir),
                vero.fileConf(dir).equals(List.of("FreeBSD.conf", "zz-panel-branch.conf")));
        vero.elimina(p);
        vero("eliminato", vero.leggi(p) == null);
        try (var s = Files.list(dir)) { s.forEach(x -> x.toFile().delete()); }
        Files.delete(dir);

        System.out.println("\n" + (falliti == 0 ? "TUTTO VERDE" : falliti + " CONTROLLI FALLITI"));
        System.exit(falliti == 0 ? 0 : 1);
    }
}
