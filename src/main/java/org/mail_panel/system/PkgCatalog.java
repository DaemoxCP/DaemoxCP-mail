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
    public static JSONObject read() {
        String dir = "/var/db/pkg";
        for (String line : Shell.run(Duration.ofSeconds(15), "pkg", "config", "PKG_DBDIR").outputTrim().split("\n"))
            if (line.trim().matches("/[A-Za-z0-9._/+-]*")) dir = line.trim();
        Shell.Result vv = Shell.run(Duration.ofSeconds(60), "pkg", "-vv");
        List<String> enabledOnes = vv.success() ? enabledOnes(vv.output()) : null;
        JSONObject c = data(dir, enabledOnes, System.currentTimeMillis() / 1000).put("cartella", dir);
        return c.put("nota", note(c));
    }

    /**
     * I repository accesi, dall'uscita di "pkg -vv". La forma e' quella di print_repository()
     * nel sorgente di pkg (src/utils.c): "  <nome>: { ", poi "enabled : yes," o "no,", e "}".
     * Restituisce null se non riconosce nessun repository: "non so" non e' "nessuno".
     */
    static List<String> enabledOnes(String output) {
        List<String> tutti = new ArrayList<>(), enabledOnes = new ArrayList<>();
        String name = null;
        boolean inside = false;
        Pattern opens = Pattern.compile("^\\s+(\\S+):\\s*\\{");
        Pattern enabled = Pattern.compile("^\\s*enabled\\s*:\\s*(\\w+)");
        for (String line : (output == null ? "" : output).split("\n")) {
            if (line.startsWith("Repositories:")) { inside = true; continue; }
            if (!inside) continue;
            Matcher m = opens.matcher(line);
            if (m.find()) { name = m.group(1); tutti.add(name); continue; }
            if (name == null) continue;
            Matcher e = enabled.matcher(line);
            if (e.find() && "yes".equalsIgnoreCase(e.group(1))) enabledOnes.add(name);
            if (line.trim().startsWith("}")) name = null;
        }
        return tutti.isEmpty() ? null : enabledOnes;
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
    static JSONObject data(String dir, List<String> enabledOnes, long now) {
        List<String> names = new ArrayList<>();
        boolean daPkg = enabledOnes != null;
        if (daPkg) {
            names.addAll(enabledOnes);
        } else {
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(Paths.get(dir, "repos"))) {
                for (Path p : ds)
                    if (Files.isRegularFile(p.resolve("db"))) names.add(p.getFileName().toString());
            } catch (Exception e) { /* nessuna cartella repos: si prova il nome vecchio */ }
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(Paths.get(dir), "repo-*.sqlite")) {
                for (Path p : ds) {
                    String f = p.getFileName().toString();
                    String n = f.substring("repo-".length(), f.length() - ".sqlite".length());
                    if (!names.contains(n)) names.add(n);
                }
            } catch (Exception e) { /* nemmeno quello */ }
            Collections.sort(names);
        }

        JSONArray list = new JSONArray();
        JSONArray missing = new JSONArray();
        JSONObject oldest = null;
        for (String name : names) {
            JSONObject o = new JSONObject().put("nome", name);
            list.put(o);
            if (!REPO_NAME.matcher(name).matches()) {
                o.put("trovato", false).put("errore", I18n.tr("server.catalog.badRepoName"));
                missing.put(name);
                continue;
            }
            // Prima il posto di adesso, poi quello delle versioni vecchie di pkg.
            Path file = null;
            for (Path p : List.of(Paths.get(dir, "repos", name, "db"), Paths.get(dir, "repo-" + name + ".sqlite")))
                if (Files.isRegularFile(p)) { file = p; break; }
            long published = -1;
            try {
                if (file != null) published = Files.getLastModifiedTime(file).to(TimeUnit.SECONDS);
            } catch (Exception e) { /* resta -1 */ }
            if (published < 0) {
                o.put("trovato", false).put("cercato", Paths.get(dir, "repos", name, "db").toString());
                missing.put(name);
                continue;
            }
            // Un orologio un po' indietro rispetto al server darebbe un'eta' negativa: e' "oggi".
            long seconds = Math.max(0, now - published);
            o.put("trovato", true).put("file", file.toString()).put("pubblicato", published)
             .put("data", DateTimeFormatter.ofPattern(I18n.tr("server.catalog.dateTime")).format(Instant.ofEpochSecond(published).atZone(ZoneId.systemDefault())))
             .put("ore", seconds / 3600).put("giorni", seconds / 86400);
            if (oldest == null || seconds / 3600 > oldest.getLong("ore")) oldest = o;
        }

        return new JSONObject().put("repository", list).put("mancanti", missing).put("daPkg", daPkg)
                .put("datato", oldest != null)
                .put("ore", oldest == null ? -1 : oldest.getLong("ore"))
                .put("giorni", oldest == null ? -1 : oldest.getLong("giorni"))
                .put("data", oldest == null ? "" : oldest.getString("data"))
                .put("file", oldest == null ? "" : oldest.getString("file"))
                .put("piuVecchio", oldest == null ? "" : oldest.getString("nome"));
    }

    /** "oggi", "ieri", "N giorni fa". */
    static String howMuch(long days) {
        return days < 0 ? I18n.tr("server.catalog.unknownDate") : days == 0 ? I18n.tr("server.catalog.today")
                : days == 1 ? I18n.tr("server.catalog.yesterday") : I18n.tr("server.catalog.daysAgo", java.util.Map.of("n", String.valueOf(days)));
    }

    /** La frase sul catalogo, per la Home e per il rapporto: una sola, scritta qui. */
    static String note(JSONObject c) {
        JSONArray el = c.optJSONArray("repository");
        JSONArray missing = c.optJSONArray("mancanti");
        StringBuilder t = new StringBuilder();
        if (c.optBoolean("datato")) {
            List<String> date = new ArrayList<>();
            for (int i = 0; el != null && i < el.length(); i++) {
                JSONObject o = el.getJSONObject(i);
                if (o.optBoolean("trovato"))
                    date.add(I18n.tr("server.catalog.repoOn", java.util.Map.of("name", String.valueOf(o.getString("nome")), "date", String.valueOf(o.getString("data")), "ago", String.valueOf(howMuch(o.getLong("giorni"))))));
            }
            t.append(date.size() == 1
                     ? I18n.tr("server.catalog.published.one", java.util.Map.of("list", String.valueOf(String.join("; ", date))))
                     : I18n.tr("server.catalog.published.other", java.util.Map.of("list", String.valueOf(String.join("; ", date)))));
            if (date.size() > 1)
                t.append(" ").append(I18n.tr("server.catalog.oldest", java.util.Map.of("name", String.valueOf(c.optString("piuVecchio")))));
            t.append(" ").append(I18n.tr("server.catalog.serverDate"));
            if (missing != null && missing.length() > 0) {
                List<String> n = new ArrayList<>();
                for (int i = 0; i < missing.length(); i++) n.add(missing.getString(i));
                t.append(" ").append(n.size() == 1
                         ? I18n.tr("server.catalog.missing.one", java.util.Map.of("list", String.valueOf(n.get(0))))
                         : I18n.tr("server.catalog.missing.other", java.util.Map.of("list", String.valueOf(String.join(", ", n)))));
            }
        } else if (c.optBoolean("daPkg") && (el == null || el.length() == 0)) {
            t.append(I18n.tr("server.catalog.noRepo"));
        } else {
            List<String> searched = new ArrayList<>();
            for (int i = 0; el != null && i < el.length(); i++)
                searched.add(el.getJSONObject(i).optString("cercato", el.getJSONObject(i).optString("nome")));
            t.append(searched.isEmpty()
                     ? I18n.tr("server.catalog.unknownNoRepos", java.util.Map.of("dir", String.valueOf(c.optString("cartella", "/var/db/pkg"))))
                     : I18n.tr("server.catalog.unknownMissing", java.util.Map.of("list", String.valueOf(String.join(", ", searched)))));
        }
        return t.toString();
    }
}
