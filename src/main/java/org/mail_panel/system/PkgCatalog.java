package org.mail_panel.system;

import org.json.JSONArray;
import org.mail_panel.i18n.I18n;
import org.json.JSONObject;
import org.mail_panel.util.Shell;

import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Il catalogo dei pacchetti gia' scaricato: per ogni repository acceso, dov'e' e di quando e'.
 *
 * Dove sta lo dice il sorgente di pkg (libpkg/repo/binary/common.c): ogni repository ha il
 * suo catalogo in $PKG_DBDIR/repos/<nome>/db, senza estensione. Prima il pannello guardava
 * /var/db/pkg/repo-FreeBSD.sqlite, cioe' il nome delle versioni vecchie di pkg e del
 * repository "FreeBSD" di prima di FreeBSD 15 (che lo ha diviso in FreeBSD-ports e
 * FreeBSD-ports-kmods): su un sistema di oggi quel file non c'e', e la Home e il rapporto
 * dicevano "eta' sconosciuta".
 *
 * La data di quel file NON e' quella dell'ultimo "pkg update". Alla fine di un aggiornamento
 * pkg gli mette la data del catalogo sul server, presa dalla risposta ("Set mtime from http
 * request if possible", libpkg/repo/binary/update.c), e se il server risponde che non e'
 * cambiato non lo tocca. Quindi e' la data di PUBBLICAZIONE dell'elenco con cui pkg confronta:
 * esattamente il termine di paragone dei conteggi, e si legge senza andare in rete.
 *
 * Contano solo i repository accesi: uno spento puo' aver lasciato un catalogo vecchio, ma non
 * entra nel confronto. Se sono piu' d'uno vale il piu' vecchio, perche' un conteggio e' fresco
 * quanto il suo elenco meno fresco.
 */
public final class PkgCatalog {

    private PkgCatalog() {}


    /** Un nome di repository finisce in un percorso: solo questi caratteri, e non troppi. */
    private static final Pattern REPO_NAME = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._+-]{0,63}");

    /** Legge davvero: cartella di pkg, repository accesi, date dei cataloghi. Nessuna rete. */
    public static JSONObject leggi() {
        String dir = "/var/db/pkg";
        for (String riga : Shell.run(Duration.ofSeconds(15), "pkg", "config", "PKG_DBDIR").outputTrim().split("\n"))
            if (riga.trim().matches("/[A-Za-z0-9._/+-]*")) dir = riga.trim();
        Shell.Result vv = Shell.run(Duration.ofSeconds(60), "pkg", "-vv");
        List<String> accesi = vv.success() ? accesi(vv.output()) : null;
        JSONObject c = data(dir, accesi, System.currentTimeMillis() / 1000).put("cartella", dir);
        return c.put("nota", nota(c));
    }

    /**
     * I repository accesi, dall'uscita di "pkg -vv". La forma e' quella di print_repository()
     * nel sorgente di pkg (src/utils.c): "  <nome>: { ", poi "enabled : yes," o "no,", e "}".
     * Restituisce null se non riconosce nessun repository: "non so" non e' "nessuno".
     */
    static List<String> accesi(String output) {
        List<String> tutti = new ArrayList<>(), accesi = new ArrayList<>();
        String nome = null;
        boolean dentro = false;
        Pattern apre = Pattern.compile("^\\s+(\\S+):\\s*\\{");
        Pattern acceso = Pattern.compile("^\\s*enabled\\s*:\\s*(\\w+)");
        for (String riga : (output == null ? "" : output).split("\n")) {
            if (riga.startsWith("Repositories:")) { dentro = true; continue; }
            if (!dentro) continue;
            Matcher m = apre.matcher(riga);
            if (m.find()) { nome = m.group(1); tutti.add(nome); continue; }
            if (nome == null) continue;
            Matcher e = acceso.matcher(riga);
            if (e.find() && "yes".equalsIgnoreCase(e.group(1))) accesi.add(nome);
            if (riga.trim().startsWith("}")) nome = null;
        }
        return tutti.isEmpty() ? null : accesi;
    }

    /**
     * Di quando e' il catalogo di ogni repository acceso, dalle date dei file nella cartella di
     * pkg. Non lancia comandi: legge date di file. Sta da sola perche' le prove la verifichino
     * su una cartella costruita da loro, con le date che decidono loro.
     *
     * @param accesi i repository accesi; null se pkg -vv non ha risposto, e allora si prendono
     *               i cataloghi che ci sono
     * @param adesso l'ora attuale in secondi dal 1970, UTC
     */
    static JSONObject data(String dir, List<String> accesi, long adesso) {
        List<String> nomi = new ArrayList<>();
        boolean daPkg = accesi != null;
        if (daPkg) {
            nomi.addAll(accesi);
        } else {
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(Paths.get(dir, "repos"))) {
                for (Path p : ds)
                    if (Files.isRegularFile(p.resolve("db"))) nomi.add(p.getFileName().toString());
            } catch (Exception e) { /* nessuna cartella repos: si prova il nome vecchio */ }
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(Paths.get(dir), "repo-*.sqlite")) {
                for (Path p : ds) {
                    String f = p.getFileName().toString();
                    String n = f.substring("repo-".length(), f.length() - ".sqlite".length());
                    if (!nomi.contains(n)) nomi.add(n);
                }
            } catch (Exception e) { /* nemmeno quello */ }
            Collections.sort(nomi);
        }

        JSONArray list = new JSONArray();
        JSONArray mancanti = new JSONArray();
        JSONObject piuVecchio = null;
        for (String nome : nomi) {
            JSONObject o = new JSONObject().put("nome", nome);
            list.put(o);
            if (!REPO_NAME.matcher(nome).matches()) {
                o.put("trovato", false).put("errore", I18n.tr("server.catalog.badRepoName"));
                mancanti.put(nome);
                continue;
            }
            // Prima il posto di adesso, poi quello delle versioni vecchie di pkg.
            Path file = null;
            for (Path p : List.of(Paths.get(dir, "repos", nome, "db"), Paths.get(dir, "repo-" + nome + ".sqlite")))
                if (Files.isRegularFile(p)) { file = p; break; }
            long pubblicato = -1;
            try {
                if (file != null) pubblicato = Files.getLastModifiedTime(file).to(TimeUnit.SECONDS);
            } catch (Exception e) { /* resta -1 */ }
            if (pubblicato < 0) {
                o.put("trovato", false).put("cercato", Paths.get(dir, "repos", nome, "db").toString());
                mancanti.put(nome);
                continue;
            }
            // Un orologio un po' indietro rispetto al server darebbe un'eta' negativa: e' "oggi".
            long secondi = Math.max(0, adesso - pubblicato);
            o.put("trovato", true).put("file", file.toString()).put("pubblicato", pubblicato)
             .put("data", DateTimeFormatter.ofPattern(I18n.tr("server.catalog.dateTime")).format(Instant.ofEpochSecond(pubblicato).atZone(ZoneId.systemDefault())))
             .put("ore", secondi / 3600).put("giorni", secondi / 86400);
            if (piuVecchio == null || secondi / 3600 > piuVecchio.getLong("ore")) piuVecchio = o;
        }

        return new JSONObject().put("repository", list).put("mancanti", mancanti).put("daPkg", daPkg)
                .put("datato", piuVecchio != null)
                .put("ore", piuVecchio == null ? -1 : piuVecchio.getLong("ore"))
                .put("giorni", piuVecchio == null ? -1 : piuVecchio.getLong("giorni"))
                .put("data", piuVecchio == null ? "" : piuVecchio.getString("data"))
                .put("file", piuVecchio == null ? "" : piuVecchio.getString("file"))
                .put("piuVecchio", piuVecchio == null ? "" : piuVecchio.getString("nome"));
    }

    /** "oggi", "ieri", "N giorni fa". */
    static String quanto(long giorni) {
        return giorni < 0 ? I18n.tr("server.catalog.unknownDate") : giorni == 0 ? I18n.tr("server.catalog.today")
                : giorni == 1 ? I18n.tr("server.catalog.yesterday") : I18n.tr("server.catalog.daysAgo", java.util.Map.of("n", String.valueOf(giorni)));
    }

    /** La frase sul catalogo, per la Home e per il rapporto: una sola, scritta qui. */
    static String nota(JSONObject c) {
        JSONArray el = c.optJSONArray("repository");
        JSONArray manc = c.optJSONArray("mancanti");
        StringBuilder t = new StringBuilder();
        if (c.optBoolean("datato")) {
            List<String> date = new ArrayList<>();
            for (int i = 0; el != null && i < el.length(); i++) {
                JSONObject o = el.getJSONObject(i);
                if (o.optBoolean("trovato"))
                    date.add(I18n.tr("server.catalog.repoOn", java.util.Map.of("name", String.valueOf(o.getString("nome")), "date", String.valueOf(o.getString("data")), "ago", String.valueOf(quanto(o.getLong("giorni"))))));
            }
            t.append(date.size() == 1
                     ? I18n.tr("server.catalog.published.one", java.util.Map.of("list", String.valueOf(String.join("; ", date))))
                     : I18n.tr("server.catalog.published.other", java.util.Map.of("list", String.valueOf(String.join("; ", date)))));
            if (date.size() > 1)
                t.append(" ").append(I18n.tr("server.catalog.oldest", java.util.Map.of("name", String.valueOf(c.optString("piuVecchio")))));
            t.append(" ").append(I18n.tr("server.catalog.serverDate"));
            if (manc != null && manc.length() > 0) {
                List<String> n = new ArrayList<>();
                for (int i = 0; i < manc.length(); i++) n.add(manc.getString(i));
                t.append(" ").append(n.size() == 1
                         ? I18n.tr("server.catalog.missing.one", java.util.Map.of("list", String.valueOf(n.get(0))))
                         : I18n.tr("server.catalog.missing.other", java.util.Map.of("list", String.valueOf(String.join(", ", n)))));
            }
        } else if (c.optBoolean("daPkg") && (el == null || el.length() == 0)) {
            t.append(I18n.tr("server.catalog.noRepo"));
        } else {
            List<String> cercati = new ArrayList<>();
            for (int i = 0; el != null && i < el.length(); i++)
                cercati.add(el.getJSONObject(i).optString("cercato", el.getJSONObject(i).optString("nome")));
            t.append(cercati.isEmpty()
                     ? I18n.tr("server.catalog.unknownNoRepos", java.util.Map.of("dir", String.valueOf(c.optString("cartella", "/var/db/pkg"))))
                     : I18n.tr("server.catalog.unknownMissing", java.util.Map.of("list", String.valueOf(String.join(", ", cercati)))));
        }
        return t.toString();
    }
}
