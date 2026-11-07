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
 * The package branch (PkgBranch): reading it and changing it.
 *
 * The fake system does what pkg does (libpkg/pkg_config.c, read on 03/10/2026): it starts from
 * /etc/pkg/FreeBSD.conf of FreeBSD 15.0 RELEASE (quarterly, modules with the minor version,
 * FreeBSD-base off), then reads the *.conf files of /usr/local/etc/pkg/repos in alphabetical order,
 * and every block overwrites the fields of the repository with the same name; ${ABI} and
 * ${VERSION_MINOR} expand. pkg -vv prints it like print_repository. So the branch change and its
 * restores are tested against the real rules: the panel's file that wins because it is the last,
 * a user's file read after it that wins, a catalog that does not download.
 *
 * The panel's messages are read in English (I18n.setCurrent): outside a request it writes Italian.
 *
 * Uso: java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PkgBranchTest
 */
public class PkgBranchTest {

    static int failed = 0;

    static void real(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
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

    /** A fake FreeBSD, with pkg's configuration in memory. */
    static class FakeSystem implements PkgBranch.SystemAccess {
        String stock = STOCK;
        final TreeMap<String, String> folder = new TreeMap<>();   // name -> content, in order like scandir
        String unreachable = null;                               // a piece of address "pkg update" does not download
        boolean pkgBroken = false, brokenWrite = false;
        final List<String> log = new ArrayList<>();
        int updates = 0;
        String latestVersions = "nginx-1.28.0_3,3          <   needs updating (remote has 1.28.1,3)\n"
                + "php84-8.4.13                <   needs updating (remote has 8.4.14)\n";
        String quarterlyVersions = "nginx-1.28.1,3          >   succeeds index (remote has 1.28.0_3,3)\n"
                + "php84-8.4.14                >   succeeds index (remote has 8.4.13)\n"
                + "curl-8.16.0                 <   needs updating (remote has 8.16.0_1)\n";

        /** The rules of pkg_config.c: every block overwrites the fields it names. */
        Map<String, Map<String, String>> config() {
            Map<String, Map<String, String>> repos = new LinkedHashMap<>();
            join(repos, stock);
            for (String f : folder.keySet()) if (f.endsWith(".conf") && !f.startsWith(".")) join(repos, folder.get(f));
            return repos;
        }

        static void join(Map<String, Map<String, String>> repos, String text) {
            // The braces of ${ABI} do not close the block: they are set aside before splitting it.
            text = text.replaceAll("\\$\\{(\\w+)\\}", "\u0001$1\u0002");
            Matcher b = Pattern.compile("(?m)^\\s*([A-Za-z0-9._-]+)\\s*:\\s*\\{([^}]*)\\}").matcher(text);
            while (b.find()) {
                Map<String, String> r = repos.computeIfAbsent(b.group(1), k -> new LinkedHashMap<>(Map.of("enabled", "yes", "priority", "0")));
                r.put("priority", "0");   // add_repo: a block without priority puts it back to 0
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
        org.mail_panel.i18n.I18n.setCurrent("en");
        System.out.println("\n== Reading the repositories from pkg -vv ==");
        FakeSystem f = new FakeSystem();
        JSONObject st = PkgBranch.state(f);
        real("stock FreeBSD 15: quarterly branch", st.getBoolean("success") && st.getString("branch").equals("quarterly"));
        JSONArray rep = st.getJSONArray("repository");
        real("three repositories: packages, kernel modules, base system (off)", rep.length() == 3
                && rep.getJSONObject(0).getString("type").equals("packages") && rep.getJSONObject(1).getString("type").equals("modules")
                && rep.getJSONObject(2).getString("type").equals("base") && !rep.getJSONObject(2).getBoolean("enabled"));
        real("it can be changed, towards latest", st.getBoolean("changeable") && st.getJSONArray("destination").toList().equals(List.of("latest")));
        real("no panel file", !st.getBoolean("panelOwnedFile"));
        PkgBranch.Repo k = PkgBranch.classify("FreeBSD-ports-kmods", "pkg+https://pkg.FreeBSD.org/FreeBSD:15:amd64/kmods_quarterly_0", true, 0, null);
        real("the modules with the minor version: kmods_latest_${VERSION_MINOR}",
                PkgBranch.address(k, "latest").equals("pkg+https://pkg.FreeBSD.org/${ABI}/kmods_latest_${VERSION_MINOR}"));
        PkgBranch.Repo ks = PkgBranch.classify("FreeBSD-ports-kmods", "pkg+https://pkg.FreeBSD.org/FreeBSD:15:amd64/kmods_quarterly", true, 0, null);
        real("on -STABLE the modules without the minor version: kmods_latest",
                PkgBranch.address(ks, "latest").equals("pkg+https://pkg.FreeBSD.org/${ABI}/kmods_latest"));
        PkgBranch.Repo old = PkgBranch.classify("FreeBSD", "pkg+http://pkg.FreeBSD.org/FreeBSD:14:amd64/latest", true, 0, null);
        real("FreeBSD 14 (\"FreeBSD\" repository, http): packages, latest branch", old.type().equals("packages") && old.branch().equals("latest"));
        real("a mirror or an own repository is not official",
                PkgBranch.classify("poudriere", "file:///usr/local/poudriere/data/packages/15amd64-default", true, 0, null).type().equals("external")
                && PkgBranch.classify("FreeBSD-ports", "pkg+https://mirror.example.org/FreeBSD:15:amd64/quarterly", true, 0, null).type().equals("external"));

        FakeSystem own = new FakeSystem();
        own.folder.put("FreeBSD.conf", "FreeBSD-ports: { enabled: no }\nFreeBSD-ports-kmods: { enabled: no }\n");
        own.folder.put("poudriere.conf", "poudriere: { url: \"file:///usr/local/poudriere/data/packages/15amd64-default\" }\n");
        st = PkgBranch.state(own);
        real("packages from an own repository: it is not changed, and it says why", st.getString("branch").equals("none")
                && !st.getBoolean("changeable") && st.getString("reason").contains("repository you use"));

        FakeSystem mixed = new FakeSystem();
        mixed.folder.put("FreeBSD.conf", "FreeBSD-ports: { url: \"pkg+https://pkg.FreeBSD.org/${ABI}/latest\" }\n");
        st = PkgBranch.state(mixed);
        real("latest packages and quarterly modules: \"mixed\", and it can be aligned to both",
                st.getString("branch").equals("mixed") && st.getJSONArray("destination").length() == 2);

        FakeSystem base = new FakeSystem();
        base.folder.put("FreeBSD.conf", "FreeBSD-base: { enabled: yes }\n");
        st = PkgBranch.state(base);
        real("FreeBSD-base on: it is said, and it stays out", st.optString("base").contains("does not touch it"));

        FakeSystem pr = new FakeSystem();
        pr.pkgBroken = true;
        real("pkg not answering: it is said, no branch made up", !PkgBranch.state(pr).getBoolean("success"));

        System.out.println("\n== Preview ==");
        f = new FakeSystem();
        JSONObject an = PkgBranch.preview(f, "latest");
        real("towards latest: possible, with the two new addresses", an.getBoolean("possible") && an.getJSONArray("changes").length() == 2
                && an.getJSONArray("changes").getJSONObject(0).getString("to").equals("pkg+https://pkg.FreeBSD.org/${ABI}/latest"));
        real("the file it would write, with pkg's variables (not today's ABI)", an.getString("content").contains(
                "FreeBSD-ports-kmods: { url: \"pkg+https://pkg.FreeBSD.org/${ABI}/kmods_latest_${VERSION_MINOR}\" }")
                && !an.getString("content").contains("FreeBSD:15"));
        real("FreeBSD-base does not appear in the file", !an.getString("content").contains("FreeBSD-base"));
        real("it says it updates no package", an.getJSONArray("warnings").getString(0).startsWith("No package is updated"));
        real("it says how to go back even at the first change, with the file to delete: " + an.optString("howToReturn"),
                an.optString("howToReturn").contains("quarterly") && an.optString("howToReturn").contains("zz-panel-branch.conf"));
        real("towards the branch it is already on: no", !PkgBranch.preview(f, "quarterly").getBoolean("possible"));
        real("a made-up branch: no", !PkgBranch.preview(f, "weekly").getBoolean("success"));
        real("the preview touches nothing", f.folder.isEmpty() && f.updates == 0);
        FakeSystem priority = new FakeSystem();
        priority.folder.put("FreeBSD.conf", "FreeBSD-ports: { priority: 5, ip_version: 4 }\n");
        real("a priority and an ip_version different from the stock ones are rewritten the same (a block would reset them)",
                PkgBranch.preview(priority, "latest").getString("content").contains("latest\", priority: 5, ip_version: 4 }"));

        System.out.println("\n== Changing: quarterly -> latest ==");
        f = new FakeSystem();
        String imp = PkgBranch.state(f).getString("fingerprint");
        JSONObject r = PkgBranch.change(f, logInto(f), "latest", imp);
        real("succeeded: " + r.optString("messageText", r.optString("error")), r.getBoolean("success") && r.getString("branch").equals("latest"));
        real("pkg now sees latest, for the modules too", f.seenBranch().equals("latest"));
        real("the panel's file is there, with the mark", f.folder.get("zz-panel-branch.conf").startsWith(PkgBranch.MARK));
        real("catalog downloaded once", f.updates == 1);
        real("it counts the upgradable ones from the new catalog (2), without upgrading them", r.getInt("updatable") == 2
                && r.getString("messageText").contains("No package was changed"));

        System.out.println("\n== Changing: latest -> quarterly (the panel's file is removed) ==");
        imp = PkgBranch.state(f).getString("fingerprint");
        r = PkgBranch.change(f, logInto(f), "quarterly", imp);
        real("succeeded", r.getBoolean("success") && f.seenBranch().equals("quarterly"));
        real("stock is already quarterly: the panel's file is removed, not rewritten", !f.folder.containsKey("zz-panel-branch.conf"));
        real("the packages newer than the branch are named, and stay as they are: " + r.getJSONArray("mostRecent"),
                r.getJSONArray("mostRecent").length() == 2 && r.getString("messageText").contains("stay as they are"));

        System.out.println("\n== The user's file is not touched ==");
        FakeSystem u = new FakeSystem();
        String its = "FreeBSD-ports: { url: \"pkg+https://pkg.FreeBSD.org/${ABI}/latest\" }\nFreeBSD-ports-kmods: { url: \"pkg+https://pkg.FreeBSD.org/${ABI}/kmods_latest_${VERSION_MINOR}\" }\n";
        u.folder.put("FreeBSD.conf", its);
        imp = PkgBranch.state(u).getString("fingerprint");
        r = PkgBranch.change(u, logInto(u), "quarterly", imp);
        real("latest from their FreeBSD.conf -> quarterly: succeeded with a panel file, read after theirs", r.getBoolean("success")
                && u.seenBranch().equals("quarterly") && u.folder.get("zz-panel-branch.conf").contains("/quarterly\""));
        real("their FreeBSD.conf is untouched", its.equals(u.folder.get("FreeBSD.conf")));

        System.out.println("\n== When it does not succeed, everything goes back as it was ==");
        FakeSystem after = new FakeSystem();
        after.folder.put("zzz-mine.conf", "FreeBSD-ports: { url: \"pkg+https://pkg.FreeBSD.org/${ABI}/quarterly\" }\n");
        imp = PkgBranch.state(after).getString("fingerprint");
        real("the preview warns about the file read after", PkgBranch.preview(after, "latest").getJSONArray("warnings").toString().contains("zzz-mine.conf"));
        r = PkgBranch.change(after, logInto(after), "latest", imp);
        real("a file read after the panel's puts quarterly back: refused, and it names it — " + r.optString("error"),
                !r.getBoolean("success") && r.getString("error").contains("zzz-mine.conf"));
        real("the panel's file did not stay, the catalog was not downloaded", !after.folder.containsKey("zz-panel-branch.conf")
                && after.updates == 0 && after.seenBranch().equals("quarterly"));

        FakeSystem network = new FakeSystem();
        network.unreachable = "kmods_latest";
        imp = PkgBranch.state(network).getString("fingerprint");
        r = PkgBranch.change(network, logInto(network), "latest", imp);
        real("the catalog of the latest modules does not download: refused — " + r.optString("error"),
                !r.getBoolean("success") && r.getString("error").contains("does not download"));
        real("the configuration went back to quarterly and the panel's file is not there", network.seenBranch().equals("quarterly")
                && !network.folder.containsKey("zz-panel-branch.conf"));
        real("the log has pkg's error", String.join("\n", network.log).contains("Not Found"));

        FakeSystem alreadyLatest = new FakeSystem();
        alreadyLatest.folder.put("zz-panel-branch.conf", PkgBranch.content(PkgBranch.repository(new FakeSystem().pkgVv()), "latest", alreadyLatest.now()));
        String beforeFault = alreadyLatest.folder.get("zz-panel-branch.conf");
        alreadyLatest.unreachable = "/quarterly";
        imp = PkgBranch.state(alreadyLatest).getString("fingerprint");
        r = PkgBranch.change(alreadyLatest, logInto(alreadyLatest), "quarterly", imp);
        real("latest (from the panel) -> quarterly that does not download: the panel's file comes back, identical", !r.getBoolean("success")
                && beforeFault.equals(alreadyLatest.folder.get("zz-panel-branch.conf")) && alreadyLatest.seenBranch().equals("latest"));

        FakeSystem ro = new FakeSystem();
        ro.brokenWrite = true;
        imp = PkgBranch.state(ro).getString("fingerprint");
        r = PkgBranch.change(ro, logInto(ro), "latest", imp);
        real("folder not writable: error said, nothing downloaded", !r.getBoolean("success") && r.getString("error").contains("Read-only")
                && ro.updates == 0);

        System.out.println("\n== The fingerprint: only what was seen is changed ==");
        FakeSystem changed = new FakeSystem();
        imp = PkgBranch.state(changed).getString("fingerprint");
        changed.folder.put("FreeBSD.conf", "FreeBSD-ports-kmods: { enabled: no }\n");
        r = PkgBranch.change(changed, logInto(changed), "latest", imp);
        real("the configuration changes after the preview: refused without touching anything", !r.getBoolean("success")
                && r.getString("error").contains("after the preview") && !changed.folder.containsKey("zz-panel-branch.conf"));

        System.out.println("\n== The real file, on disk ==");
        Path dir = Files.createTempDirectory("branch-test");
        PkgBranch.SystemAccess real = PkgBranch.real();
        Path p = dir.resolve("zz-panel-branch.conf");
        real.write(p, "test\n");
        real("written, with rw-r--r-- permissions, no temporary files left", "test\n".equals(real.read(p))
                && java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(p)).equals("rw-r--r--")
                && real.fileConf(dir).equals(List.of("zz-panel-branch.conf")) && Files.list(dir).count() == 1);
        Files.writeString(dir.resolve("FreeBSD.conf"), "x");
        Files.writeString(dir.resolve("FreeBSD.conf.before"), "x");
        Files.writeString(dir.resolve(".hidden.conf"), "x");
        real("the .conf files as pkg reads them: in order, without hidden ones and other extensions: " + real.fileConf(dir),
                real.fileConf(dir).equals(List.of("FreeBSD.conf", "zz-panel-branch.conf")));
        real.delete(p);
        real("deleted", real.read(p) == null);
        try (var s = Files.list(dir)) { s.forEach(x -> x.toFile().delete()); }
        Files.delete(dir);

        System.out.println("\n" + (failed == 0 ? "ALL GREEN" : failed + " CHECKS FAILED"));
        System.exit(failed == 0 ? 0 : 1);
    }
}
