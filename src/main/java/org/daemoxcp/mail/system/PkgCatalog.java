package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.daemoxcp.mail.i18n.I18n;
import org.json.JSONObject;
import org.daemoxcp.mail.util.Shell;

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
 * The package catalog already downloaded: for every enabled repository, where it is and how old it is.
 *
 * Where it lives is stated by pkg's source (libpkg/repo/binary/common.c): every repository has its
 * own catalog in $PKG_DBDIR/repos/<name>/db, without an extension. Before, the panel looked at
 * /var/db/pkg/repo-FreeBSD.sqlite, that is the name used by old versions of pkg and by the
 * "FreeBSD" repository from before FreeBSD 15 (which split it into FreeBSD-ports and
 * FreeBSD-ports-kmods): on a current system that file does not exist, and the Home page and the
 * report said "age unknown".
 *
 * The date of that file is NOT the date of the last "pkg update". At the end of an update pkg
 * sets it to the date of the catalog on the server, taken from the response ("Set mtime from http
 * request if possible", libpkg/repo/binary/update.c), and if the server answers that it has not
 * changed it does not touch it. So it is the PUBLICATION date of the list pkg compares against:
 * exactly the reference point of the counts, and it is read without going to the network.
 *
 * Only the enabled repositories count: a disabled one may have left an old catalog, but it does
 * not take part in the comparison. If there is more than one, the oldest counts, because a count
 * is only as fresh as its least fresh list.
 */
public final class PkgCatalog {

    private PkgCatalog() {}


    /** A repository name ends up in a path: only these characters, and not too many. */
    private static final Pattern REPO_NAME = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._+-]{0,63}");

    /** Really reads: pkg's folder, enabled repositories, catalog dates. No network. */
    public static JSONObject read() {
        String dir = "/var/db/pkg";
        for (String line : Shell.run(Duration.ofSeconds(15), "pkg", "config", "PKG_DBDIR").outputTrim().split("\n"))
            if (line.trim().matches("/[A-Za-z0-9._/+-]*")) dir = line.trim();
        Shell.Result vv = Shell.run(Duration.ofSeconds(60), "pkg", "-vv");
        List<String> enabledOnes = vv.success() ? enabledOnes(vv.output()) : null;
        JSONObject c = data(dir, enabledOnes, System.currentTimeMillis() / 1000).put("folder", dir);
        return c.put("note", note(c));
    }

    /**
     * The enabled repositories, from the output of "pkg -vv". The shape is the one of
     * print_repository() in pkg's source (src/utils.c): "  <name>: { ", then "enabled : yes," or
     * "no,", and "}". Returns null if it recognizes no repository: "I don't know" is not "none".
     */
    static List<String> enabledOnes(String output) {
        List<String> allItems = new ArrayList<>(), enabledOnes = new ArrayList<>();
        String name = null;
        boolean inside = false;
        Pattern opens = Pattern.compile("^\\s+(\\S+):\\s*\\{");
        Pattern enabled = Pattern.compile("^\\s*enabled\\s*:\\s*(\\w+)");
        for (String line : (output == null ? "" : output).split("\n")) {
            if (line.startsWith("Repositories:")) { inside = true; continue; }
            if (!inside) continue;
            Matcher m = opens.matcher(line);
            if (m.find()) { name = m.group(1); allItems.add(name); continue; }
            if (name == null) continue;
            Matcher e = enabled.matcher(line);
            if (e.find() && "yes".equalsIgnoreCase(e.group(1))) enabledOnes.add(name);
            if (line.trim().startsWith("}")) name = null;
        }
        return allItems.isEmpty() ? null : enabledOnes;
    }

    /**
     * How old the catalog of every enabled repository is, from the dates of the files in pkg's
     * folder. It runs no commands: it reads file dates. It stands on its own so that the tests can
     * verify it on a folder they build themselves, with the dates they choose.
     *
     * @param enabledOnes the enabled repositories; null if pkg -vv did not answer, and then the
     *               catalogs that exist are taken
     * @param now the current time in seconds since 1970, UTC
     */
    static JSONObject data(String dir, List<String> enabledOnes, long now) {
        List<String> names = new ArrayList<>();
        boolean fromPkg = enabledOnes != null;
        if (fromPkg) {
            names.addAll(enabledOnes);
        } else {
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(Paths.get(dir, "repos"))) {
                for (Path p : ds)
                    if (Files.isRegularFile(p.resolve("db"))) names.add(p.getFileName().toString());
            } catch (Exception e) { /* no repos folder: the old name is tried */ }
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(Paths.get(dir), "repo-*.sqlite")) {
                for (Path p : ds) {
                    String f = p.getFileName().toString();
                    String n = f.substring("repo-".length(), f.length() - ".sqlite".length());
                    if (!names.contains(n)) names.add(n);
                }
            } catch (Exception e) { /* not even that */ }
            Collections.sort(names);
        }

        JSONArray list = new JSONArray();
        JSONArray missing = new JSONArray();
        JSONObject oldest = null;
        for (String name : names) {
            JSONObject o = new JSONObject().put("name", name);
            list.put(o);
            if (!REPO_NAME.matcher(name).matches()) {
                o.put("found", false).put("error", I18n.tr("server.catalog.badRepoName"));
                missing.put(name);
                continue;
            }
            // First the current location, then the one of old pkg versions.
            Path file = null;
            for (Path p : List.of(Paths.get(dir, "repos", name, "db"), Paths.get(dir, "repo-" + name + ".sqlite")))
                if (Files.isRegularFile(p)) { file = p; break; }
            long published = -1;
            try {
                if (file != null) published = Files.getLastModifiedTime(file).to(TimeUnit.SECONDS);
            } catch (Exception e) { /* stays -1 */ }
            if (published < 0) {
                o.put("found", false).put("searched", Paths.get(dir, "repos", name, "db").toString());
                missing.put(name);
                continue;
            }
            // A clock slightly behind the server's would give a negative age: it is "today".
            long seconds = Math.max(0, now - published);
            o.put("found", true).put("file", file.toString()).put("published", published)
             .put("data", DateTimeFormatter.ofPattern(I18n.tr("server.catalog.dateTime")).format(Instant.ofEpochSecond(published).atZone(ZoneId.systemDefault())))
             .put("hours", seconds / 3600).put("days", seconds / 86400);
            if (oldest == null || seconds / 3600 > oldest.getLong("hours")) oldest = o;
        }

        return new JSONObject().put("repository", list).put("missing", missing).put("fromPkg", fromPkg)
                .put("dated", oldest != null)
                .put("hours", oldest == null ? -1 : oldest.getLong("hours"))
                .put("days", oldest == null ? -1 : oldest.getLong("days"))
                .put("data", oldest == null ? "" : oldest.getString("data"))
                .put("file", oldest == null ? "" : oldest.getString("file"))
                .put("oldest", oldest == null ? "" : oldest.getString("name"));
    }

    /** "today", "yesterday", "N days ago". */
    static String howMuch(long days) {
        return days < 0 ? I18n.tr("server.catalog.unknownDate") : days == 0 ? I18n.tr("server.catalog.today")
                : days == 1 ? I18n.tr("server.catalog.yesterday") : I18n.tr("server.catalog.daysAgo", java.util.Map.of("n", String.valueOf(days)));
    }

    /** The sentence about the catalog, for the Home page and for the report: only one, written here. */
    static String note(JSONObject c) {
        JSONArray el = c.optJSONArray("repository");
        JSONArray missing = c.optJSONArray("missing");
        StringBuilder t = new StringBuilder();
        if (c.optBoolean("dated")) {
            List<String> date = new ArrayList<>();
            for (int i = 0; el != null && i < el.length(); i++) {
                JSONObject o = el.getJSONObject(i);
                if (o.optBoolean("found"))
                    date.add(I18n.tr("server.catalog.repoOn", java.util.Map.of("name", String.valueOf(o.getString("name")), "date", String.valueOf(o.getString("data")), "ago", String.valueOf(howMuch(o.getLong("days"))))));
            }
            t.append(date.size() == 1
                     ? I18n.tr("server.catalog.published.one", java.util.Map.of("list", String.valueOf(String.join("; ", date))))
                     : I18n.tr("server.catalog.published.other", java.util.Map.of("list", String.valueOf(String.join("; ", date)))));
            if (date.size() > 1)
                t.append(" ").append(I18n.tr("server.catalog.oldest", java.util.Map.of("name", String.valueOf(c.optString("oldest")))));
            t.append(" ").append(I18n.tr("server.catalog.serverDate"));
            if (missing != null && missing.length() > 0) {
                List<String> n = new ArrayList<>();
                for (int i = 0; i < missing.length(); i++) n.add(missing.getString(i));
                t.append(" ").append(n.size() == 1
                         ? I18n.tr("server.catalog.missing.one", java.util.Map.of("list", String.valueOf(n.get(0))))
                         : I18n.tr("server.catalog.missing.other", java.util.Map.of("list", String.valueOf(String.join(", ", n)))));
            }
        } else if (c.optBoolean("fromPkg") && (el == null || el.length() == 0)) {
            t.append(I18n.tr("server.catalog.noRepo"));
        } else {
            List<String> searched = new ArrayList<>();
            for (int i = 0; el != null && i < el.length(); i++)
                searched.add(el.getJSONObject(i).optString("searched", el.getJSONObject(i).optString("name")));
            t.append(searched.isEmpty()
                     ? I18n.tr("server.catalog.unknownNoRepos", java.util.Map.of("dir", String.valueOf(c.optString("folder", "/var/db/pkg"))))
                     : I18n.tr("server.catalog.unknownMissing", java.util.Map.of("list", String.valueOf(String.join(", ", searched)))));
        }
        return t.toString();
    }
}
