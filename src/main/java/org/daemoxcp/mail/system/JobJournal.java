package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.ErrorText;
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
 * The on-disk log of the panel's jobs (finding 196): one per job, in /var/db/daemoxcp-mail/jobs.
 *
 * The log the page shows lives in memory: a restart of the panel or of the server wipes it, exactly when it would be
 * needed to understand what happened (a release upgrade goes through restarts). Here every line is also written to
 * disk, with the time in UTC, between a start line (which job, when) and an end line (status, error, duration). The
 * folder belongs to root only (0700), the files are 0600: they contain paths and package names, no secrets, but they
 * still belong to the system. The last KEEP are kept. A log that cannot be written does not stop the job: this is
 * said in the panel's log, once.
 */
public final class JobJournal {

    private static final Logger LOGGER = Logger.getLogger(JobJournal.class.getName());

    /** The folder; a different one only in tests (-Ddaemoxcp.mail.jobs.dir). */
    static Path dir = Paths.get(System.getProperty("daemoxcp.mail.jobs.dir", "/var/db/daemoxcp-mail/jobs"));
    /** How many logs are kept: the oldest ones beyond this number are removed when a new one is created. */
    static int keep = 200;
    /** The name of a log: UTC date and time, type, "__", job id. Nothing else is readable from outside. */
    static final Pattern NAME = Pattern.compile("[0-9]{8}-[0-9]{6}-[A-Za-z0-9._-]{1,120}\\.log");
    private static final DateTimeFormatter FILE_TIME = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss").withZone(ZoneOffset.UTC);
    private static volatile boolean warned;

    private JobJournal() { }

    /** Opens the log of a job that starts now; null if it cannot (and says so once). */
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

    /** A line, with the UTC time in front. */
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

    /** The end: status, error if any, outcome if any, duration. */
    static void end(Path f, String status, String error, String outcome, long seconds) {
        append(f, "=== end: " + status + " after " + seconds + " s"
                + (error == null || error.isEmpty() ? "" : "; error: " + error.replace('\n', ' '))
                + (outcome == null || outcome.isEmpty() ? "" : "; outcome: " + outcome.replace('\n', ' ')) + " ===");
    }

    /** The logs, most recent first: name, type, start (UTC), size, and the status written at the end (or "running"). */
    public static JSONObject list(int max) {
        JSONArray out = new JSONArray();
        for (Path f : files()) {
            if (out.length() >= max) break;
            String name = f.getFileName().toString();
            String rest = name.substring(16, name.length() - 4);
            // Two underscores between type and id: ids have hyphens of their own (jump-1731...), and so do types
            // (os-patch).
            String type = rest.contains("__") ? rest.substring(0, rest.indexOf("__")) : rest;
            String start = name.substring(0, 4) + "-" + name.substring(4, 6) + "-" + name.substring(6, 8) + "T"
                    + name.substring(9, 11) + ":" + name.substring(11, 13) + ":" + name.substring(13, 15) + "Z";
            String end = endLine(f);
            String status = end.contains("=== end: completed") ? "completed" : end.contains("=== end: error") ? "error"
                    : end.contains("=== end: ") ? "ended" : "unfinished";
            long size;
            try { size = Files.size(f); } catch (IOException e) { size = -1; }
            out.put(new JSONObject().put("name", name).put("type", type).put("startedUtc", start).put("status", status).put("bytes", size));
        }
        settle(out);
        return new JSONObject().put("success", true).put("dir", dir.toString()).put("journals", out);
    }

    /** A log by name: only a name of the right form, only inside the folder; at most the last 400 KB. */
    public static JSONObject read(String name) {
        if (name == null || !NAME.matcher(name).matches())
            return new JSONObject().put("success", false).put("error", org.daemoxcp.mail.i18n.I18n.tr("server.journal.badName"));
        Path f = dir.resolve(name).normalize();
        if (!f.getParent().equals(dir.normalize()) || !Files.isRegularFile(f))
            return new JSONObject().put("success", false).put("error", org.daemoxcp.mail.i18n.I18n.tr("server.journal.notFound"));
        try {
            byte[] all = Files.readAllBytes(f);
            int from = Math.max(0, all.length - 400_000);
            return new JSONObject().put("success", true).put("name", name).put("truncated", from > 0)
                    .put("text", new String(all, from, all.length - from, StandardCharsets.UTF_8));
        } catch (IOException e) {
            return new JSONObject().put("success", false).put("error", ErrorText.forPage("read", e));
        }
    }

    /**
     * The logs, most recent first (the name starts with the UTC date and time: the order of the names is the order
     * in time).
     */
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

    /**
     * A job that ended badly and was followed by one of the same family that ended well: "settled". Diagnostics
     * counted them forever among those to look at: on the production server, on 2026-11-09, three errors already redone
     * successfully (finding 212). The list, most recent first: each successful job met remembers its family.
     */
    static void settle(JSONArray journals) {
        java.util.Set<String> doneLater = new java.util.HashSet<>();
        for (int i = 0; i < journals.length(); i++) {
            JSONObject j = journals.getJSONObject(i);
            String fam = family(j.optString("type"));
            String st = j.optString("status");
            if ("completed".equals(st)) doneLater.add(fam);
            j.put("settled", ("error".equals(st) || "unfinished".equals(st)) && doneLater.contains(fam));
        }
    }

    /** The family of a job: the packages (the jobs that change them), the base system, or the type itself. */
    static String family(String type) {
        return switch (type) {
            case "update", "guided_update", "guided_update_all", "update_everything", "roundcube", "maintenance",
                 "mysql84_migration", "python" -> "packages";
            case "os-patch", "os-fetch", "jump", "system" -> "os";
            default -> type;
        };
    }

    /**
     * The end line: the last "=== end:" among the last lines, if there is one, otherwise the last line. Before build
     * 554 the cleanup of the way back wrote a line AFTER the end, and those logs showed up as "without an end" although
     * they had finished (finding 207): they stay on disk, and are read correctly.
     */
    static String endLine(Path f) {
        String tail = lastLines(f);
        String[] lines = tail.split("\n");
        for (int i = lines.length - 1; i >= Math.max(0, lines.length - 6); i--)
            if (lines[i].contains("=== end: ")) return lines[i];
        return lines.length == 0 ? "" : lines[lines.length - 1];
    }

    private static String lastLines(Path f) {
        try {
            long size = Files.size(f);
            byte[] tail;
            try (var ch = Files.newByteChannel(f)) {
                ch.position(Math.max(0, size - 4000));
                java.nio.ByteBuffer b = java.nio.ByteBuffer.allocate((int) Math.min(4000, size));
                ch.read(b);
                tail = b.array();
            }
            return new String(tail, StandardCharsets.UTF_8).trim();
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
