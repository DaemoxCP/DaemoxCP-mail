package org.mail_panel.system;

import org.json.JSONArray;
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
public final class CatalogoPkg {

    private CatalogoPkg() {}

    private static final DateTimeFormatter DATA_ORA = DateTimeFormatter.ofPattern("dd/MM/yyyy 'alle' HH:mm");

    /** Un nome di repository finisce in un percorso: solo questi caratteri, e non troppi. */
    private static final Pattern NOME_REPO = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._+-]{0,63}");

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
    static List<String> accesi(String uscita) {
        List<String> tutti = new ArrayList<>(), accesi = new ArrayList<>();
        String nome = null;
        boolean dentro = false;
        Pattern apre = Pattern.compile("^\\s+(\\S+):\\s*\\{");
        Pattern acceso = Pattern.compile("^\\s*enabled\\s*:\\s*(\\w+)");
        for (String riga : (uscita == null ? "" : uscita).split("\n")) {
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

        JSONArray elenco = new JSONArray();
        JSONArray mancanti = new JSONArray();
        JSONObject piuVecchio = null;
        for (String nome : nomi) {
            JSONObject o = new JSONObject().put("nome", nome);
            elenco.put(o);
            if (!NOME_REPO.matcher(nome).matches()) {
                o.put("trovato", false).put("errore", "nome di repository che non uso in un percorso");
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
             .put("data", DATA_ORA.format(Instant.ofEpochSecond(pubblicato).atZone(ZoneId.systemDefault())))
             .put("ore", secondi / 3600).put("giorni", secondi / 86400);
            if (piuVecchio == null || secondi / 3600 > piuVecchio.getLong("ore")) piuVecchio = o;
        }

        return new JSONObject().put("repository", elenco).put("mancanti", mancanti).put("daPkg", daPkg)
                .put("datato", piuVecchio != null)
                .put("ore", piuVecchio == null ? -1 : piuVecchio.getLong("ore"))
                .put("giorni", piuVecchio == null ? -1 : piuVecchio.getLong("giorni"))
                .put("data", piuVecchio == null ? "" : piuVecchio.getString("data"))
                .put("file", piuVecchio == null ? "" : piuVecchio.getString("file"))
                .put("piuVecchio", piuVecchio == null ? "" : piuVecchio.getString("nome"));
    }

    /** "oggi", "ieri", "N giorni fa". */
    static String quanto(long giorni) {
        return giorni < 0 ? "data sconosciuta" : giorni == 0 ? "oggi" : giorni == 1 ? "ieri" : giorni + " giorni fa";
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
                    date.add(o.getString("nome") + " il " + o.getString("data") + " (" + quanto(o.getLong("giorni")) + ")");
            }
            t.append(date.size() == 1 ? "Catalogo pubblicato: " : "Cataloghi pubblicati: ")
             .append(String.join("; ", date)).append('.');
            if (date.size() > 1)
                t.append(" I conteggi sono freschi quanto il piu' vecchio, ").append(c.optString("piuVecchio")).append('.');
            t.append(" E' la data del catalogo sul server di pkg, non dell'ultimo controllo: se sul server "
                   + "non c'e' niente di nuovo, pkg update non la cambia.");
            if (manc != null && manc.length() > 0) {
                List<String> n = new ArrayList<>();
                for (int i = 0; i < manc.length(); i++) n.add(manc.getString(i));
                t.append(n.size() == 1
                         ? " Il repository " + n.get(0) + " e' acceso ma non ha un catalogo scaricato: i suoi pacchetti"
                         : " I repository " + String.join(", ", n) + " sono accesi ma non hanno un catalogo scaricato: i loro pacchetti")
                 .append(" non entrano nei conteggi.");
            }
        } else if (c.optBoolean("daPkg") && (el == null || el.length() == 0)) {
            t.append("Nessun repository di pkg e' acceso: non c'e' un catalogo con cui confrontare.");
        } else {
            List<String> cercati = new ArrayList<>();
            for (int i = 0; el != null && i < el.length(); i++)
                cercati.add(el.getJSONObject(i).optString("cercato", el.getJSONObject(i).optString("nome")));
            t.append("Non so di quando sia il catalogo dei pacchetti: ")
             .append(cercati.isEmpty()
                     ? "pkg non mi ha detto quali repository sono accesi, e nella cartella "
                       + c.optString("cartella", "di pkg") + " non ho trovato cataloghi."
                     : "non c'e' " + String.join(", ", cercati) + ".");
        }
        return t.toString();
    }
}
