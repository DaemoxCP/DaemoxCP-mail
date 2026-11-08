package org.mail_panel.system;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Il registro su disco dei lavori del pannello (reperto 196): uno per lavoro, in /var/db/mailpanel/jobs.
 *
 * Il registro che la pagina mostra sta in memoria: un riavvio del pannello o del server lo cancella, proprio quando
 * servirebbe capire cosa e' successo (un passaggio di release attraversa dei riavvii). Qui ogni riga si scrive anche su
 * disco, con l'ora in UTC, fra una riga d'inizio (che lavoro, quando) e una di fine (stato, errore, durata). La cartella
 * e' della sola root (0700), i file 0600: dentro ci sono percorsi e nomi di pacchetti, niente segreti, ma restano
 * comunque del sistema. Se ne tengono gli ultimi KEEP. Un registro che non si scrive non ferma il lavoro: lo si dice
 * nel registro del pannello, una volta.
 */
public final class JobJournal {

    private static final Logger LOGGER = Logger.getLogger(JobJournal.class.getName());

    /** La cartella; un'altra solo nelle prove (-Dmailpanel.jobs.dir). */
    static Path dir = Paths.get(System.getProperty("mailpanel.jobs.dir", "/var/db/mailpanel/jobs"));
    /** Quanti registri restano: i piu' vecchi oltre questo numero si tolgono quando ne nasce uno nuovo. */
    static int keep = 200;
    /** Il nome di un registro: data e ora UTC, tipo, "__", id del lavoro. Nient'altro e' leggibile da fuori. */
    static final Pattern NAME = Pattern.compile("[0-9]{8}-[0-9]{6}-[A-Za-z0-9._-]{1,120}\\.log");
    private static final DateTimeFormatter FILE_TIME = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss").withZone(ZoneOffset.UTC);
    private static volatile boolean warned;

    private JobJournal() { }

    /** Apre il registro di un lavoro che comincia adesso; null se non si puo' (e lo si dice una volta). */
    static Path open(String id, String type, long startedAt) {
        try {
            if (!Files.isDirectory(dir)) {
                Files.createDirectories(dir);
                Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
            }
            Path f = dir.resolve(FILE_TIME.format(Instant.ofEpochMilli(startedAt)) + "-" + safe(type) + "__" + safe(id) + ".log");
            Files.writeString(f, "", StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            Files.setPosixFilePermissions(f, PosixFilePermissions.fromString("rw-------"));
            Files.writeString(f, "=== job " + id + " (" + type + ") started " + utc(startedAt) + " ===\n",
                    StandardCharsets.UTF_8, StandardOpenOption.APPEND);
            prune();
            return f;
        } catch (IOException | RuntimeException e) {
            if (!warned) {
                warned = true;
                LOGGER.log(Level.WARNING, "[JobJournal] the jobs' log cannot be written in " + dir + ": " + e.getMessage());
            }
            return null;
        }
    }

    /** Una riga, con l'ora UTC davanti. */
    static void append(Path f, String line) {
        if (f == null) return;
        try {
            Files.writeString(f, utc(System.currentTimeMillis()) + " " + line + "\n", StandardCharsets.UTF_8, StandardOpenOption.APPEND);
        } catch (IOException | RuntimeException e) {
            if (!warned) {
                warned = true;
                LOGGER.log(Level.WARNING, "[JobJournal] cannot append to " + f + ": " + e.getMessage());
            }
        }
    }

    /** La fine: stato, errore se c'e', esito se c'e', durata. */
    static void end(Path f, String status, String error, String outcome, long seconds) {
        append(f, "=== end: " + status + " after " + seconds + " s"
                + (error == null || error.isEmpty() ? "" : "; error: " + error.replace('\n', ' '))
                + (outcome == null || outcome.isEmpty() ? "" : "; outcome: " + outcome.replace('\n', ' ')) + " ===");
    }

    /** I registri, dal piu' recente: nome, tipo, inizio (UTC), dimensione, e lo stato scritto alla fine (o "running"). */
    public static JSONObject list(int max) {
        JSONArray out = new JSONArray();
        for (Path f : files()) {
            if (out.length() >= max) break;
            String name = f.getFileName().toString();
            String rest = name.substring(16, name.length() - 4);
            // Fra tipo e id due trattini bassi: gli id hanno trattini loro (jump-1731...), i tipi anche (os-patch).
            String type = rest.contains("__") ? rest.substring(0, rest.indexOf("__")) : rest;
            String start = name.substring(0, 4) + "-" + name.substring(4, 6) + "-" + name.substring(6, 8) + "T"
                    + name.substring(9, 11) + ":" + name.substring(11, 13) + ":" + name.substring(13, 15) + "Z";
            String end = lastLine(f);
            String status = end.contains("=== end: completed") ? "completed" : end.contains("=== end: error") ? "error"
                    : end.contains("=== end: ") ? "ended" : "unfinished";
            long size;
            try { size = Files.size(f); } catch (IOException e) { size = -1; }
            out.put(new JSONObject().put("name", name).put("type", type).put("startedUtc", start).put("status", status).put("bytes", size));
        }
        return new JSONObject().put("success", true).put("dir", dir.toString()).put("journals", out);
    }

    /** Un registro per nome: solo un nome della forma giusta, solo dentro la cartella; gli ultimi 400 KB al massimo. */
    public static JSONObject read(String name) {
        if (name == null || !NAME.matcher(name).matches())
            return new JSONObject().put("success", false).put("error", org.mail_panel.i18n.I18n.tr("server.journal.badName"));
        Path f = dir.resolve(name).normalize();
        if (!f.getParent().equals(dir.normalize()) || !Files.isRegularFile(f))
            return new JSONObject().put("success", false).put("error", org.mail_panel.i18n.I18n.tr("server.journal.notFound"));
        try {
            byte[] all = Files.readAllBytes(f);
            int from = Math.max(0, all.length - 400_000);
            return new JSONObject().put("success", true).put("name", name).put("truncated", from > 0)
                    .put("text", new String(all, from, all.length - from, StandardCharsets.UTF_8));
        } catch (IOException e) {
            return new JSONObject().put("success", false).put("error", e.getMessage());
        }
    }

    /** I registri, dal piu' recente (il nome comincia con data e ora UTC: l'ordine dei nomi e' l'ordine nel tempo). */
    static List<Path> files() {
        List<Path> out = new ArrayList<>();
        if (!Files.isDirectory(dir)) return out;
        try (Stream<Path> s = Files.list(dir)) {
            s.filter(p -> NAME.matcher(p.getFileName().toString()).matches()).forEach(out::add);
        } catch (IOException e) {
            return out;
        }
        out.sort((a, b) -> b.getFileName().toString().compareTo(a.getFileName().toString()));
        return out;
    }

    private static void prune() {
        List<Path> all = files();
        for (int i = keep; i < all.size(); i++) {
            try { Files.deleteIfExists(all.get(i)); } catch (IOException ignored) { }
        }
    }

    private static String lastLine(Path f) {
        try {
            long size = Files.size(f);
            byte[] tail;
            try (var ch = Files.newByteChannel(f)) {
                ch.position(Math.max(0, size - 2000));
                java.nio.ByteBuffer b = java.nio.ByteBuffer.allocate((int) Math.min(2000, size));
                ch.read(b);
                tail = b.array();
            }
            String t = new String(tail, StandardCharsets.UTF_8).trim();
            int nl = t.lastIndexOf('\n');
            return nl < 0 ? t : t.substring(nl + 1);
        } catch (IOException e) {
            return "";
        }
    }

    static String utc(long millis) {
        return Instant.ofEpochMilli(millis).truncatedTo(ChronoUnit.SECONDS).toString();
    }

    static String safe(String s) {
        String v = s == null ? "" : s.replaceAll("[^A-Za-z0-9._-]", "_");
        return v.isEmpty() ? "job" : v.length() > 60 ? v.substring(0, 60) : v;
    }
}
