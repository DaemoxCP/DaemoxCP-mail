package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * The public surface moves from "mailpanel-pubblico" (and from "mailpanel-public", its name before DaemoxCP
 * Mail) to "daemoxcp-mail-public" on the servers already installed (PublicSurfaceRename.migrate), in temporary folders and with a fake nginx and fail2ban.
 * The fake fail2ban does what the real one does: it keeps the bans in a database by jail name, and at
 * every reload it activates the jails it finds in jail.d taking back each one's bans from the
 * database. A jail with the new name finds its bans again only if the state in the database moved
 * to it. It also counts the bans given by hand (the "Ban" lines the recidive jail counts): a rename
 * must give none. With the surface the folder of its files moves too (mta-sts.txt), which the nginx
 * file quotes by path: on the real server, on 31/10/2026, that path stayed the old one. The effect
 * on the real nginx, fail2ban and pf is measured by the test on the VM (reperti).
 *
 * It runs anywhere (it calls nothing):
 *   java -cp "tests:&lt;dir&gt;/daemoxcp-mail.jar" org.daemoxcp.mail.system.PublicSurfaceRenameTest
 */
public class PublicSurfaceRenameTest {

    static int failed = 0;
    static final PrintStream OUT = System.out;

    static void check(String what, boolean ok) {
        OUT.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    /** The old name, from the data file: the test does not write it. The last part moves to the next old name. */
    static String OLD = LegacyNames.single("publicSurface");
    static final String NEW = "daemoxcp-mail-public";
    static final String CERT = "/usr/local/etc/ssl/mail/fullchain.pem";
    static final String KEY = "/usr/local/etc/ssl/mail/privkey.pem";

    /**
     * The old signatures, from the data file: the longer one ("... di posta") was in filter and
     * jail, the shorter one in the nginx file.
     */
    static final List<String> OLD_SIGNATURES = LegacyNames.oldNamesOf("panelSignature", PanelMarker.WRITTEN);
    static String signedBefore(String content, String signature) { return content.replace(PanelMarker.WRITTEN, signature); }

    /**
     * The three files as main wrote them before the rename: today's with yesterday's name and
     * signature, and the nginx file with yesterday's public files folder (folder).
     */
    static String oldConf(Path folder) {
        return signedBefore(WebProtection.configuration(CERT, KEY), OLD_SIGNATURES.get(OLD_SIGNATURES.size() - 1))
                .replace(NEW, OLD).replace(WebProtection.PUBLIC_DIR, folder.toString());
    }
    /** Today's nginx file, with the given public files folder. */
    static String conf(Path folder) { return WebProtection.configuration(CERT, KEY).replace(WebProtection.PUBLIC_DIR, folder.toString()); }
    /** The name of the old public files folder, from the data file. */
    static final String OLD_FOLDER = Path.of(LegacyNames.single("publicFolder")).getFileName().toString();
    static String oldFilter() { return signedBefore(WebProtection.filter(), OLD_SIGNATURES.get(0)).replace(NEW, OLD); }
    static String oldJail() { return signedBefore(WebProtection.jail(), OLD_SIGNATURES.get(0)).replace(NEW, OLD); }

    static final class FakeServices implements PublicSurfaceRename.Services {
        final Path jailDir;
        List<String> folders;
        boolean nginxRunning = true, f2bRunning = true;
        boolean nginxTestFails, f2bReloadFails, f2bIgnoresNewJail, databaseFails;
        int foldersCalls, nginxTests, nginxReloads, f2bReloads, manualBans, stateMoves;
        /** The active jails, with their bans. */
        final Map<String, List<String>> jails = new LinkedHashMap<>();
        /** fail2ban's database: the bans by jail name, and the position in the log. */
        final Map<String, List<String>> database = new LinkedHashMap<>();
        final Map<String, String> logOf = new LinkedHashMap<>();

        FakeServices(Path jailDir, List<String> folders) { this.jailDir = jailDir; this.folders = folders; }

        static Shell.Result ok() { return new Shell.Result(0, "", false, List.of()); }
        static Shell.Result ko(String why) { return new Shell.Result(1, why, false, List.of()); }

        @Override public List<String> nginxFolders() { foldersCalls++; return folders; }
        @Override public boolean nginxRunning() { return nginxRunning; }
        @Override public Shell.Result nginxTest() { nginxTests++; return nginxTestFails ? ko("emerg: test fault") : ok(); }
        @Override public Shell.Result nginxReload() { nginxReloads++; return ok(); }
        @Override public boolean fail2banRunning() { return f2bRunning; }
        @Override public Shell.Result fail2banReload() {
            f2bReloads++;
            if (f2bReloadFails && f2bReloads == 1) return ko("ERROR test fault");
            jails.clear();
            try (Stream<Path> s = Files.list(jailDir)) {
                for (Path p : s.toList()) {
                    String n = p.getFileName().toString().replace(".conf", "");
                    if (f2bIgnoresNewJail && n.equals(NEW)) continue;
                    // Every jail that starts takes back its bans from the database, and only its own.
                    jails.put(n, database.computeIfAbsent(n, k -> new ArrayList<>()));
                }
            } catch (Exception e) { return ko(e.toString()); }
            return ok();
        }
        @Override public List<String> banned(String jail) {
            List<String> b = jails.get(jail);
            return b == null ? null : new ArrayList<>(b);
        }
        @Override public boolean moveJailState(String from, String to, String fromLog, String toLog) {
            stateMoves++;
            if (databaseFails) return false;
            List<String> b = database.remove(from);
            if (b != null) database.put(to, b);
            if (fromLog.equals(logOf.get(from))) { logOf.remove(from); logOf.put(to, toLog); }
            return true;
        }

        /** A ban given by hand: in the real fail2ban it writes a "Ban" line recidive counts. */
        void manualBan(String jail, String ip) {
            manualBans++;
            database.computeIfAbsent(jail, k -> new ArrayList<>()).add(ip);
        }
    }

    /** A server installed with main before the rename, in a temporary folder. */
    static final class Server {
        final Path root, f2b, jailD, filterD, logs, confD, sites, oldFolder, newFolder;
        final PublicSurfaceRename.Places places;
        final FakeServices sv;

        Server(boolean withConf, boolean withJail, boolean withLog) throws Exception {
            root = Files.createTempDirectory("public-surface-rename");
            f2b = root.resolve("fail2ban");
            jailD = Files.createDirectories(f2b.resolve("jail.d"));
            filterD = Files.createDirectories(f2b.resolve("filter.d"));
            logs = Files.createDirectories(root.resolve("log/nginx"));
            confD = Files.createDirectories(root.resolve("nginx/conf.d"));
            sites = Files.createDirectories(root.resolve("nginx/sites-enabled"));
            oldFolder = root.resolve("db").resolve(OLD_FOLDER);
            newFolder = root.resolve("db").resolve(Path.of(WebProtection.PUBLIC_DIR).getFileName().toString());
            places = new PublicSurfaceRename.Places(f2b, logs, confD, oldFolder, newFolder);
            sv = new FakeServices(jailD, List.of(confD.toString()));
            // Other people's things that must not move.
            Files.writeString(logs.resolve("access.log"), "webmail\n");
            Files.writeString(jailD.resolve("postfix-sasl.conf"), "[postfix-sasl]\n");
            if (withConf) {
                Files.writeString(confD.resolve(OLD + ".conf"), oldConf(oldFolder));
                Files.createDirectories(oldFolder);
                Files.writeString(oldFolder.resolve("mta-sts.txt"), "version: STSv1\nmode: enforce\n");
            }
            if (withJail) {
                Files.writeString(filterD.resolve(OLD + ".conf"), oldFilter());
                Path j = jailD.resolve(OLD + ".conf");
                Files.writeString(j, oldJail());
                Files.setPosixFilePermissions(j, PosixFilePermissions.fromString("rw-r-----"));
            }
            if (withLog) {
                Files.writeString(logs.resolve(OLD + "-access.log"), "1.2.3.4 - - \"GET /x\" 404\n");
                Files.writeString(logs.resolve(OLD + "-access.log.0.bz2"), "archive\n");
            }
            if (withJail) {
                sv.database.put(OLD, new ArrayList<>(List.of("203.0.113.7", "198.51.100.9")));
                sv.logOf.put(OLD, logs.resolve(OLD + "-access.log").toString());
            }
            sv.fail2banReload();   // fail2ban running with the old jail and its two bans
            sv.f2bReloads = 0;
        }

        PublicSurfaceRename.Report run() throws Exception {
            PublicSurfaceRename.Report r = PublicSurfaceRename.migrate(places, sv);
            OUT.println("        -> " + r.outcome() + ": " + r.detail());
            return r;
        }

        String read(Path p) throws Exception { return Files.exists(p) ? Files.readString(p) : null; }

        /** All the files under the root with their content: to say "nothing changed". */
        Map<String, String> snapshot() throws Exception {
            Map<String, String> m = new LinkedHashMap<>();
            try (Stream<Path> s = Files.walk(root)) {
                for (Path p : s.sorted(Comparator.naturalOrder()).toList())
                    if (Files.isRegularFile(p)) m.put(root.relativize(p).toString(), Files.readString(p));
            }
            return m;
        }
    }

    public static void main(String[] args) throws Exception {
        OUT.println("\n== The names ==");
        // By reflection: javac copies the constants into this class, and the direct comparison would
        // look at the names of when the test was compiled, not those of the jar.
        String oldName = (String) PublicSurfaceRename.class.getDeclaredField("OLD_NAME").get(null);
        String newName = (String) WebProtection.class.getDeclaredField("NAME").get(null);
        check("the old name comes from the data file and the new one is different",
                !oldName.isEmpty() && oldName.equals(OLD) && newName.equals(NEW) && !oldName.equals(newName));
        check("today's code no longer writes the old name (configuration, filter, jail), nor the old folder",
                !WebProtection.configuration(CERT, KEY).contains(OLD) && !WebProtection.jail().contains(OLD)
                        && !WebProtection.filter().contains(OLD) && !WebProtection.ACCESS_LOG.contains(OLD)
                        && !WebProtection.configuration(CERT, KEY).contains(LegacyNames.single("publicFolder"))
                        && WebProtection.configuration(CERT, KEY).contains(WebProtection.PUBLIC_DIR + "/mta-sts.txt"));
        check("today's jail: section, filter, log and pf anchor with the new name",
                WebProtection.jail().contains("[" + NEW + "]") && WebProtection.jail().contains("filter   = " + NEW + "\n")
                        && WebProtection.jail().contains("logpath  = /var/log/nginx/" + NEW + "-access.log")
                        && WebProtection.jail().contains("action   = pf[name=" + NEW + ", port=\"http,https\"]"));
        check("the database file is read from \"fail2ban-client get dbfile\"",
                "/var/db/fail2ban/fail2ban.sqlite3".equals(PublicSurfaceRename.fail2banDatabase(
                        "Current database file is:\n`- /var/db/fail2ban/fail2ban.sqlite3\n"))
                        && PublicSurfaceRename.fail2banDatabase("Database currently disabled") == null);
        check("main's three files have the old signature, and the panel recognises it",
                OLD_SIGNATURES.size() == 3 && !oldConf(Path.of("/x")).contains(PanelMarker.WRITTEN) && !oldJail().contains(PanelMarker.WRITTEN)
                        && !oldFilter().contains(PanelMarker.WRITTEN) && PanelMarker.writtenByPanel(oldConf(Path.of("/x")))
                        && PanelMarker.writtenByPanel(oldFilter()) && PanelMarker.writtenByPanel(oldJail()));
        check("the fail2ban-client status line is read",
                PublicSurfaceRename.bannedFrom("|- Actions\n   |- Currently banned:\t2\n   |- Total banned:\t46\n"
                        + "   `- Banned IP list:\t203.0.113.7 198.51.100.9\n").equals(List.of("203.0.113.7", "198.51.100.9"))
                        && PublicSurfaceRename.bannedFrom("   `- Banned IP list:\t\n").isEmpty());

        OUT.println("\n== A server installed with main: everything moves ==");
        Server s = new Server(true, true, true);
        PublicSurfaceRename.Report r = s.run();
        check("outcome DONE", r.outcome() == PublicSurfaceRename.Outcome.DONE);
        check("nginx: the new file is the one the panel writes today, with the new folder; the old one is gone",
                conf(s.newFolder).equals(s.read(s.confD.resolve(NEW + ".conf")))
                        && !Files.exists(s.confD.resolve(OLD + ".conf")));
        check("the public files folder has the new name, with mta-sts.txt inside, and the old one is gone",
                "version: STSv1\nmode: enforce\n".equals(s.read(s.newFolder.resolve("mta-sts.txt"))) && !Files.exists(s.oldFolder));
        check("fail2ban: new jail and filter equal to today's, the old ones removed",
                WebProtection.jail().equals(s.read(s.jailD.resolve(NEW + ".conf")))
                        && WebProtection.filter().equals(s.read(s.filterD.resolve(NEW + ".conf")))
                        && !Files.exists(s.jailD.resolve(OLD + ".conf")) && !Files.exists(s.filterD.resolve(OLD + ".conf")));
        check("the moved jail keeps its permissions (0640)",
                PosixFilePermissions.toString(Files.getPosixFilePermissions(s.jailD.resolve(NEW + ".conf"))).equals("rw-r-----"));
        check("the log and its rotated copy with the new name, content untouched",
                "1.2.3.4 - - \"GET /x\" 404\n".equals(s.read(s.logs.resolve(NEW + "-access.log")))
                        && "archive\n".equals(s.read(s.logs.resolve(NEW + "-access.log.0.bz2")))
                        && !Files.exists(s.logs.resolve(OLD + "-access.log"))
                        && !Files.exists(s.logs.resolve(OLD + "-access.log.0.bz2")));
        check("other people's files do not move",
                "webmail\n".equals(s.read(s.logs.resolve("access.log"))) && Files.exists(s.jailD.resolve("postfix-sasl.conf")));
        check("nginx -t and reload of nginx and fail2ban, once each",
                s.sv.nginxTests == 1 && s.sv.nginxReloads == 1 && s.sv.f2bReloads == 1);
        check("the two bans of the old jail are in the new one, the old one is gone",
                s.sv.jails.containsKey(NEW) && s.sv.jails.get(NEW).equals(List.of("203.0.113.7", "198.51.100.9"))
                        && !s.sv.jails.containsKey(OLD));
        check("  taken back from the database, with no ban given by hand (recidive counts nothing)",
                s.sv.stateMoves == 1 && s.sv.manualBans == 0);
        check("  and the new jail takes the log back from the point where the old one was",
                s.logs.resolve(NEW + "-access.log").toString().equals(s.sv.logOf.get(NEW)) && !s.sv.logOf.containsKey(OLD));

        OUT.println("\n== The second start ==");
        Map<String, String> after = s.snapshot();
        int calls = s.sv.foldersCalls;
        r = s.run();
        check("nothing to do, not even nginx -T", r.outcome() == PublicSurfaceRename.Outcome.NOTHING
                && s.sv.foldersCalls == calls && after.equals(s.snapshot()));

        OUT.println("\n== nginx refuses: everything is put back as it was ==");
        s = new Server(true, true, true);
        s.sv.nginxTestFails = true;
        Map<String, String> before = s.snapshot();
        r = s.run();
        check("outcome ROLLED_BACK", r.outcome() == PublicSurfaceRename.Outcome.ROLLED_BACK);
        check("every file goes back to its name and its content", before.equals(s.snapshot()));
        check("no reload: neither nginx nor fail2ban, and the bans stay where they were",
                s.sv.nginxReloads == 0 && s.sv.f2bReloads == 0 && s.sv.jails.get(OLD).size() == 2);

        OUT.println("\n== fail2ban refuses the reload: everything is put back, nginx included ==");
        s = new Server(true, true, true);
        s.sv.f2bReloadFails = true;
        before = s.snapshot();
        r = s.run();
        check("outcome ROLLED_BACK", r.outcome() == PublicSurfaceRename.Outcome.ROLLED_BACK);
        check("every file goes back as it was", before.equals(s.snapshot()));
        check("nginx reloaded twice (forward and back), fail2ban twice (the refusal and the return)",
                s.sv.nginxReloads == 2 && s.sv.f2bReloads == 2);
        check("the old jail is active again, with its two bans taken back from the database",
                s.sv.jails.containsKey(OLD) && !s.sv.jails.containsKey(NEW) && s.sv.jails.get(OLD).size() == 2
                        && s.sv.manualBans == 0);

        OUT.println("\n== fail2ban reloads but does not see the new jail: back ==");
        s = new Server(true, true, true);
        s.sv.f2bIgnoresNewJail = true;
        before = s.snapshot();
        r = s.run();
        check("outcome ROLLED_BACK and files as they were",
                r.outcome() == PublicSurfaceRename.Outcome.ROLLED_BACK && before.equals(s.snapshot()));
        check("after the return the old jail is there again, with its two bans",
                s.sv.jails.containsKey(OLD) && s.sv.jails.get(OLD).equals(List.of("203.0.113.7", "198.51.100.9")));

        OUT.println("\n== fail2ban's database cannot be updated ==");
        s = new Server(true, true, true);
        s.sv.databaseFails = true;
        r = s.run();
        check("the rename goes on all the same, and says so", r.outcome() == PublicSurfaceRename.Outcome.DONE
                && r.detail().contains("not carried over") && s.sv.jails.containsKey(NEW) && !s.sv.jails.containsKey(OLD));
        check("  without banning again by hand", s.sv.manualBans == 0);

        OUT.println("\n== Things that are not touched ==");
        s = new Server(true, true, true);
        Files.writeString(s.jailD.resolve(OLD + ".conf"), "[" + OLD + "]\nenabled = true\n# written by hand\n");
        before = s.snapshot();
        r = s.run();
        check("a jail written by hand: NOT_OURS, nothing moved, no service touched",
                r.outcome() == PublicSurfaceRename.Outcome.NOT_OURS && before.equals(s.snapshot())
                        && s.sv.nginxTests == 0 && s.sv.f2bReloads == 0);

        s = new Server(true, true, true);
        Files.writeString(s.confD.resolve(NEW + ".conf"), conf(s.newFolder));
        before = s.snapshot();
        r = s.run();
        check("old and new name together: BOTH_NAMES, nothing moved",
                r.outcome() == PublicSurfaceRename.Outcome.BOTH_NAMES && before.equals(s.snapshot()));

        s = new Server(true, true, true);
        Files.writeString(s.sites.resolve(OLD + ".conf"), oldConf(s.oldFolder));
        s.sv.folders = List.of(s.confD.toString(), s.sites.toString());
        before = s.snapshot();
        r = s.run();
        check("two old files in two included folders: AMBIGUOUS, nothing moved",
                r.outcome() == PublicSurfaceRename.Outcome.AMBIGUOUS && before.equals(s.snapshot()));

        s = new Server(true, true, true);
        s.sv.folders = null;
        before = s.snapshot();
        r = s.run();
        check("nginx -T does not answer: NGINX_UNREADABLE, nothing moved",
                r.outcome() == PublicSurfaceRename.Outcome.NGINX_UNREADABLE && before.equals(s.snapshot()));

        OUT.println("\n== Services off or missing ==");
        s = new Server(true, true, true);
        s.sv.f2bRunning = false;
        s.sv.nginxRunning = false;
        r = s.run();
        check("fail2ban and nginx off: everything moves, nginx -t yes, no reload",
                r.outcome() == PublicSurfaceRename.Outcome.DONE && Files.exists(s.jailD.resolve(NEW + ".conf"))
                        && Files.exists(s.confD.resolve(NEW + ".conf")) && s.sv.nginxTests == 1
                        && s.sv.nginxReloads == 0 && s.sv.f2bReloads == 0);

        s = new Server(false, true, true);
        s.sv.folders = List.of();
        r = s.run();
        check("without nginx (only jail and log): those move, without nginx -t",
                r.outcome() == PublicSurfaceRename.Outcome.DONE && WebProtection.jail().equals(s.read(s.jailD.resolve(NEW + ".conf")))
                        && Files.exists(s.logs.resolve(NEW + "-access.log")) && s.sv.nginxTests == 0
                        && s.sv.jails.get(NEW).size() == 2);

        s = new Server(true, false, true);
        r = s.run();
        check("without a jail (the 443 is there, fail2ban does not have it): nginx moves, fail2ban is not touched",
                r.outcome() == PublicSurfaceRename.Outcome.DONE && Files.exists(s.confD.resolve(NEW + ".conf"))
                        && s.sv.f2bReloads == 0 && s.sv.nginxReloads == 1);

        OUT.println("\n== The public files folder ==");
        check("only this migration moves the folder: it is not among the files PathMigration moves",
                !LegacyNames.single("publicFolder").isEmpty()
                        && LegacyNames.pairs("files").stream().noneMatch(p -> p[0].equals(LegacyNames.single("publicFolder"))));
        s = new Server(true, true, true);
        Files.createDirectories(s.newFolder);
        before = s.snapshot();
        r = s.run();
        check("old and new folder together: BOTH_NAMES, nothing moved",
                r.outcome() == PublicSurfaceRename.Outcome.BOTH_NAMES && before.equals(s.snapshot()) && Files.exists(s.oldFolder));

        s = new Server(true, true, true);
        s.sv.nginxTestFails = true;
        r = s.run();
        check("nginx refuses: the folder goes back to the old name, and nginx still quotes it",
                r.outcome() == PublicSurfaceRename.Outcome.ROLLED_BACK && Files.exists(s.oldFolder.resolve("mta-sts.txt"))
                        && !Files.exists(s.newFolder) && oldConf(s.oldFolder).equals(s.read(s.confD.resolve(OLD + ".conf"))));

        // A server main had already brought to the new name before this fix: PathMigration moved the
        // folder, and the nginx file still quotes the old one.
        s = new Server(false, false, false);
        Files.createDirectories(s.newFolder);
        Files.writeString(s.newFolder.resolve("mta-sts.txt"), "version: STSv1\n");
        Files.writeString(s.confD.resolve(NEW + ".conf"), conf(s.oldFolder));
        r = s.run();
        check("already renamed but with the old path: only the nginx file is rewritten, nginx -t and reload",
                r.outcome() == PublicSurfaceRename.Outcome.DONE && conf(s.newFolder).equals(s.read(s.confD.resolve(NEW + ".conf")))
                        && s.sv.nginxTests == 1 && s.sv.nginxReloads == 1 && s.sv.f2bReloads == 0);
        calls = s.sv.foldersCalls;
        r = s.run();
        check("  and at the second start there is nothing left to do, not even nginx -T",
                r.outcome() == PublicSurfaceRename.Outcome.NOTHING && s.sv.foldersCalls == calls);

        s = new Server(false, false, false);
        Files.createDirectories(s.newFolder);
        Files.writeString(s.confD.resolve(NEW + ".conf"), conf(s.oldFolder));
        s.sv.nginxTestFails = true;
        before = s.snapshot();
        r = s.run();
        check("  if nginx refuses the rewritten file, it goes back as it was", r.outcome() == PublicSurfaceRename.Outcome.ROLLED_BACK
                && before.equals(s.snapshot()));

        s = new Server(false, false, false);
        Files.createDirectories(s.oldFolder);
        Files.writeString(s.oldFolder.resolve("mta-sts.txt"), "version: STSv1\n");
        r = s.run();
        check("only the old folder, no nginx file quoting it: it moves, without nginx -t",
                r.outcome() == PublicSurfaceRename.Outcome.DONE && Files.exists(s.newFolder.resolve("mta-sts.txt"))
                        && !Files.exists(s.oldFolder) && s.sv.nginxTests == 0);

        check("the path counts only whole: another folder starting the same way does not change",
                PublicSurfaceRename.renamed("alias /d/" + OLD_FOLDER + "-bis/x;\n", Path.of("/d/" + OLD_FOLDER), Path.of("/d/public"))
                        .contains("/d/" + OLD_FOLDER + "-bis/x;")
                        && PublicSurfaceRename.renamed("alias /d/" + OLD_FOLDER + "/x;\n", Path.of("/d/" + OLD_FOLDER), Path.of("/d/public"))
                        .contains("/d/public/x;"));

        OUT.println("\n== A server already at the name before DaemoxCP Mail: it moves to today's too ==");
        List<String[]> chain = LegacyNames.pairs("publicSurface");
        check("the data file has the Italian name, then the one before DaemoxCP Mail, both to today's",
                chain.size() == 2 && chain.get(0)[0].equals(OLD) && chain.stream().allMatch(p -> p[1].equals(NEW)));
        java.lang.reflect.Field oldNameField = PublicSurfaceRename.class.getDeclaredField("OLD_NAME");
        oldNameField.setAccessible(true);
        String italian = OLD;
        OLD = chain.get(chain.size() - 1)[0];
        oldNameField.set(null, OLD);
        try {
            s = new Server(true, true, true);
            r = s.run();
            check("outcome DONE (" + OLD + " -> " + NEW + ")", r.outcome() == PublicSurfaceRename.Outcome.DONE);
            check("nginx, jail and filter are today's, with the new name, and the old files are gone",
                    conf(s.newFolder).equals(s.read(s.confD.resolve(NEW + ".conf")))
                            && WebProtection.jail().equals(s.read(s.jailD.resolve(NEW + ".conf")))
                            && WebProtection.filter().equals(s.read(s.filterD.resolve(NEW + ".conf")))
                            && !Files.exists(s.confD.resolve(OLD + ".conf")) && !Files.exists(s.jailD.resolve(OLD + ".conf"))
                            && !Files.exists(s.filterD.resolve(OLD + ".conf")));
            check("the log moves, and the two bans go to the new jail from the database, none given by hand",
                    "1.2.3.4 - - \"GET /x\" 404\n".equals(s.read(s.logs.resolve(NEW + "-access.log")))
                            && s.sv.jails.containsKey(NEW) && s.sv.jails.get(NEW).equals(List.of("203.0.113.7", "198.51.100.9"))
                            && !s.sv.jails.containsKey(OLD) && s.sv.stateMoves == 1 && s.sv.manualBans == 0);
        } finally {
            OLD = italian;
            oldNameField.set(null, italian);
        }

        OUT.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        if (failed > 0) System.exit(1);
    }
}
