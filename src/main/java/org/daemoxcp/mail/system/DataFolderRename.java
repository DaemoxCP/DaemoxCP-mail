package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFileAttributes;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * At service startup: the panel's data folders take the new name (DaemoxCP Mail, 2026-11-17).
 *
 * <p>Up to this version the panel had two folders in /var/db: /var/db/mailpanel (its logs, the state of the
 * updates, the webmail and Dovecot keys, Roundcube's PHP sessions, the public MTA-STS files) and
 * /var/db/mail-panel (the list of permanent bans, the firewall's geographic zones, the fail2ban copies). They
 * become a single one, /var/db/daemoxcp-mail: no name in one is also in the other.
 *
 * <p>It is not a rename of the panel alone: the two folders are also read by other services, and an old path
 * left in one of their files becomes an error without warning. Measured in the inventory of 2026-11-17:
 * <ul>
 *   <li>php.ini, session.save_path: Roundcube's sessions (php-fpm looks for them where it was told at startup);</li>
 *   <li>the nginx file of the public surface, alias of the MTA-STS file: a 404 and the policy disappears;</li>
 *   <li>/etc/pf.conf (the permaban table) and the panel-fw anchor (the geographic zones): they are re-read by the
 *       next load of pf, which without the file would fail entirely;</li>
 *   <li>fail2ban's permanent-ban action, and the panel's startup script (its log).</li>
 * </ul>
 * So everything together: the folders are moved, the paths are rewritten in every file that mentions them among
 * those of the services involved, every service touched is checked (php-fpm -t, nginx -t, pfctl -n, doveconf,
 * postfix check) and the ones that read the paths only at startup are reloaded (php-fpm, nginx, fail2ban, Dovecot,
 * Postfix). Then it checks that www can read the files the nginx aliases point to. At the first step that does not
 * add up, everything is put back as it was, files and folders, and reloaded: at the next startup it tries again.
 *
 * <p>pf is not reloaded: the permaban table and the zones are already in the kernel, and the path matters only at
 * the next load, which at that point finds the new file. An extra pf reload at startup would serve no purpose.
 *
 * <p>A path is changed only where it is whole: "/var/db/mailpanel" followed by "/" or by the end of the word, never
 * "/var/db/mailpanel-something". The previous names are in legacy-names.json (section "dataFolders").
 */
public final class DataFolderRename {

    private static final Logger LOGGER = Logger.getLogger(DataFolderRename.class.getName());

    /** The current folder, from the data file: it is the second name of each pair. */
    static final String NEW = "/var/db/" + Product.SLUG;

    /** The files that may mention the folders, one by one. */
    static final List<String> FILES = List.of(
            "/usr/local/etc/php.ini", "/usr/local/etc/php-fpm.conf", "/etc/pf.conf",
            "/usr/local/etc/fail2ban/jail.local", "/usr/local/etc/nginx/nginx.conf",
            "/usr/local/etc/postfix/main.cf", "/usr/local/etc/postfix/master.cf",
            "/usr/local/etc/dovecot/dovecot.conf", "/etc/rc.conf",
            "/usr/local/etc/rc.d/mailpanel", "/usr/local/etc/rc.d/" + Product.ID);

    /** The folders whose files (not their subfolders) may mention them. */
    static final List<String> FOLDERS = List.of(
            "/usr/local/etc/php-fpm.d", "/etc/pf.anchors", "/usr/local/etc/newsyslog.conf.d",
            "/usr/local/etc/fail2ban/jail.d", "/usr/local/etc/fail2ban/action.d", "/usr/local/etc/fail2ban/filter.d",
            "/usr/local/www/roundcube/config", "/usr/local/etc/nginx/conf.d", "/usr/local/etc/dovecot/conf.d",
            "/usr/local/etc/rspamd/local.d", "/usr/local/etc/rspamd/override.d");

    enum Outcome { NOTHING, DONE, LEFT, ROLLED_BACK }

    record Report(Outcome outcome, String detail) {}

    /** What is needed from the services, kept separate to test it without the real services. */
    interface Services {
        /** The folders that nginx includes (nginx -T); empty without nginx, null if nginx does not answer. */
        List<String> nginxFolders();
        /** The configuration check of a service: null if it is fine, otherwise what it says. */
        String test(Kind kind);
        /** The reload: null if it went through, otherwise what it says. A stopped service is not reloaded. */
        String reload(Kind kind);
        /** True if the www user can read the file. */
        boolean readableByWww(Path file);
    }

    /** The services a file belongs to, to know what to check and what to reload. */
    enum Kind { PHP, NGINX, PF, FAIL2BAN, DOVECOT, POSTFIX, RSPAMD, OTHER }

    private DataFolderRename() {}

    public static void ensureAtBoot() {
        try {
            Report r = migrate(LegacyNames.pairs("dataFolders"), new RealServices());
            if (r.outcome() == Outcome.NOTHING) return;
            String line = "[DataFolderRename] " + r.outcome() + ": " + r.detail();
            if (r.outcome() == Outcome.DONE) LOGGER.info(line); else LOGGER.warning(line);
        } catch (Throwable t) {
            LOGGER.warning("[DataFolderRename] failed: " + t);
        }
    }

    // ===================== pure functions =====================

    /** The text with the paths of the previous folders replaced by the current ones, only where the name is whole. */
    static String rewritten(String text, List<String[]> pairs) {
        String out = text;
        for (String[] p : pairs) {
            Pattern old = Pattern.compile(Pattern.quote(p[0]) + "(?![A-Za-z0-9_.-])");
            out = old.matcher(out).replaceAll(Matcher.quoteReplacement(p[1]));
        }
        return out;
    }

    /** Which service a file belongs to, from its path. */
    static Kind kindOf(String path, Set<String> nginxFolders) {
        if (path.startsWith("/usr/local/etc/php")) return Kind.PHP;
        if (path.startsWith("/etc/pf.")) return Kind.PF;
        if (path.startsWith("/usr/local/etc/fail2ban/")) return Kind.FAIL2BAN;
        if (path.startsWith("/usr/local/etc/dovecot/")) return Kind.DOVECOT;
        if (path.startsWith("/usr/local/etc/postfix/")) return Kind.POSTFIX;
        if (path.startsWith("/usr/local/etc/rspamd/")) return Kind.RSPAMD;
        if (path.startsWith("/usr/local/etc/nginx/")) return Kind.NGINX;
        for (String f : nginxFolders) if (path.startsWith(f.endsWith("/") ? f : f + "/")) return Kind.NGINX;
        return Kind.OTHER;
    }

    /** The nginx aliases (the file they point to) that are in the current folder. */
    static List<Path> aliasesInto(String nginxText) {
        List<Path> out = new ArrayList<>();
        Matcher m = Pattern.compile("(?m)^\\s*alias\\s+(" + Pattern.quote(NEW) + "/[^;\\s]+)\\s*;").matcher(nginxText);
        while (m.find()) out.add(Path.of(m.group(1)));
        return out;
    }

    // ===================== the migration =====================

    /** A changed file: where it is, how it was, how it is now. */
    private record Changed(Path path, String before, String after, Kind kind) {}

    /** A moved folder or file, so that it can be put back. */
    private record Moved(Path from, Path to) {}

    static Report migrate(List<String[]> pairs, Services sv) {
        List<String[]> present = new ArrayList<>();
        for (String[] p : pairs) if (!p[0].equals(p[1]) && Files.exists(Path.of(p[0]), LinkOption.NOFOLLOW_LINKS)) present.add(p);
        if (present.isEmpty()) return new Report(Outcome.NOTHING, "");

        // Before touching anything: no name of an old folder already present in the new one.
        for (String[] p : present) {
            Path from = Path.of(p[0]), to = Path.of(p[1]);
            if (Files.isSymbolicLink(from) || !Files.isDirectory(from, LinkOption.NOFOLLOW_LINKS))
                return new Report(Outcome.LEFT, from + " is not a folder: left as it is");
            if (!Files.exists(to, LinkOption.NOFOLLOW_LINKS)) continue;
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(from)) {
                for (Path c : ds) if (Files.exists(to.resolve(c.getFileName()), LinkOption.NOFOLLOW_LINKS))
                    return new Report(Outcome.LEFT, c + " and " + to.resolve(c.getFileName())
                            + " both exist: nothing moved, deciding which one counts is not a migration's job");
            } catch (IOException e) {
                return new Report(Outcome.LEFT, from + " cannot be read: " + e.getMessage());
            }
        }

        List<String> folders = sv.nginxFolders();
        if (folders == null) return new Report(Outcome.LEFT, "nginx -T failed: nothing moved, retrying at the next start");
        Set<String> nginxFolders = new LinkedHashSet<>(folders);

        // The files that mention the folders, with the new text: all read before moving anything.
        Set<Path> candidates = new LinkedHashSet<>();
        for (String f : FILES) candidates.add(Path.of(f));
        Set<String> scan = new LinkedHashSet<>(FOLDERS);
        scan.addAll(nginxFolders);
        for (String d : scan) {
            Path dir = Path.of(d);
            if (!Files.isDirectory(dir)) continue;
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir)) {
                for (Path c : ds) candidates.add(c);
            } catch (IOException e) {
                return new Report(Outcome.LEFT, d + " cannot be read: " + e.getMessage());
            }
        }
        List<Changed> changes = new ArrayList<>();
        for (Path c : candidates) {
            try {
                if (!Files.isRegularFile(c) || Files.size(c) > 4L * 1024 * 1024) continue;
                Path real = c.toRealPath();
                String before = Files.readString(real, StandardCharsets.UTF_8);
                String after = rewritten(before, present);
                if (after.equals(before)) continue;
                if (changes.stream().anyMatch(x -> x.path().equals(real))) continue;
                changes.add(new Changed(real, before, after, kindOf(real.toString(), nginxFolders)));
            } catch (IOException | RuntimeException e) {
                // A file that cannot be read as text (binary, different encoding) does not mention the folders.
            }
        }

        List<Moved> moved = new ArrayList<>();
        List<Changed> written = new ArrayList<>();
        try {
            for (String[] p : present) moveFolder(Path.of(p[0]), Path.of(p[1]), moved);
            for (Changed c : changes) {
                PanelMarker.replaceKeeping(c.path(), c.after());
                written.add(c);
            }
        } catch (IOException | RuntimeException e) {
            String back = putBack(moved, written);
            return new Report(Outcome.ROLLED_BACK, "moving failed (" + e.getMessage() + ")" + back);
        }

        Set<Kind> touched = new LinkedHashSet<>();
        for (Changed c : changes) touched.add(c.kind());
        for (Kind k : touched) {
            if (k == Kind.OTHER) continue;
            String problem = sv.test(k);
            if (problem != null) {
                String back = putBack(moved, written);
                return new Report(Outcome.ROLLED_BACK, k + " refuses the new paths (" + problem + ")" + back);
            }
        }
        List<Kind> reloaded = new ArrayList<>();
        for (Kind k : touched) {
            if (k == Kind.OTHER || k == Kind.PF) continue;
            String problem = sv.reload(k);
            if (problem != null) {
                String back = putBack(moved, written);
                for (Kind r : reloaded) sv.reload(r);
                sv.reload(k);
                return new Report(Outcome.ROLLED_BACK, k + " did not reload (" + problem + ")" + back);
            }
            reloaded.add(k);
        }
        for (Changed c : changes) {
            if (c.kind() != Kind.NGINX) continue;
            for (Path a : aliasesInto(c.after())) {
                if (Files.exists(a) && !sv.readableByWww(a)) {
                    String back = putBack(moved, written);
                    for (Kind r : reloaded) sv.reload(r);
                    return new Report(Outcome.ROLLED_BACK, "www cannot read " + a + " after the move" + back);
                }
            }
        }

        List<String> what = new ArrayList<>();
        for (String[] p : present) what.add(p[0] + " -> " + p[1]);
        List<String> files = new ArrayList<>();
        for (Changed c : changes) files.add(c.path().toString());
        return new Report(Outcome.DONE, String.join(", ", what)
                + (files.isEmpty() ? "" : "; paths updated in " + String.join(", ", files))
                + (reloaded.isEmpty() ? "" : "; reloaded " + reloaded));
    }

    /**
     * Moves a folder: with a rename if the new one does not exist, otherwise one name at a time (the old folder,
     * now empty, goes away). Each step stays in {@code moved}, so that it can be put back.
     */
    private static void moveFolder(Path from, Path to, List<Moved> moved) throws IOException {
        if (!Files.exists(to, LinkOption.NOFOLLOW_LINKS)) {
            Files.move(from, to, StandardCopyOption.ATOMIC_MOVE);
            moved.add(new Moved(from, to));
            return;
        }
        List<Path> children = new ArrayList<>();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(from)) {
            for (Path c : ds) children.add(c);
        }
        for (Path c : children) {
            Path t = to.resolve(c.getFileName());
            Files.move(c, t, StandardCopyOption.ATOMIC_MOVE);
            moved.add(new Moved(c, t));
        }
        PosixFileAttributes a = Files.readAttributes(from, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        Files.delete(from);
        moved.add(new Moved(from, null));
        // To put it back: with the permissions and owner it had before.
        removedFolders.put(from, a);
    }

    /** The old folders removed because they were left empty, with their attributes: to recreate them identical. */
    private static final Map<Path, PosixFileAttributes> removedFolders = new LinkedHashMap<>();

    /** Puts everything back as it was, in reverse: the files, then the moves. Says what did not succeed. */
    private static String putBack(List<Moved> moved, List<Changed> written) {
        List<String> problems = new ArrayList<>();
        for (int i = written.size() - 1; i >= 0; i--) {
            Changed c = written.get(i);
            try {
                PanelMarker.replaceKeeping(c.path(), c.before());
            } catch (IOException | RuntimeException e) {
                problems.add(c.path() + ": " + e.getMessage());
            }
        }
        for (int i = moved.size() - 1; i >= 0; i--) {
            Moved m = moved.get(i);
            try {
                if (m.to() == null) {
                    Files.createDirectory(m.from());
                    PosixFileAttributes a = removedFolders.get(m.from());
                    if (a != null) {
                        Files.setPosixFilePermissions(m.from(), a.permissions());
                        Files.setOwner(m.from(), a.owner());
                        Files.setAttribute(m.from(), "posix:group", a.group());
                    }
                } else {
                    Files.move(m.to(), m.from(), StandardCopyOption.ATOMIC_MOVE);
                }
            } catch (IOException | RuntimeException e) {
                problems.add(m.from() + ": " + e.getMessage());
            }
        }
        return problems.isEmpty() ? "; everything put back as it was" : "; NOT put back: " + String.join(", ", problems);
    }

    // ===================== the real services =====================

    static final class RealServices implements Services {
        private static final Duration SHORT = Duration.ofSeconds(30);
        private static final Duration LONG = Duration.ofSeconds(120);

        @Override public List<String> nginxFolders() {
            if (Shell.resolve("nginx") == null) return List.of();
            Shell.Result r = Shell.run(SHORT, "nginx", "-T");
            return r.success() ? WebProtection.includedFolders(r.output()) : null;
        }

        @Override public String test(Kind kind) {
            Shell.Result r = switch (kind) {
                case PHP -> Shell.resolve("php-fpm") == null ? null : Shell.run(SHORT, "php-fpm", "-t");
                case NGINX -> Shell.resolve("nginx") == null ? null : Shell.run(SHORT, "nginx", "-t");
                case PF -> Shell.run(SHORT, "pfctl", "-nf", "/etc/pf.conf");
                case FAIL2BAN -> Shell.resolve("fail2ban-client") == null ? null : Shell.run(LONG, "fail2ban-client", "-t");
                case DOVECOT -> Shell.resolve("doveconf") == null ? null : Shell.run(SHORT, "doveconf", "-n");
                case POSTFIX -> Shell.resolve("postfix") == null ? null : Shell.run(LONG, "postfix", "check");
                case RSPAMD -> Shell.resolve("rspamadm") == null ? null : Shell.run(LONG, "rspamadm", "configtest");
                case OTHER -> null;
            };
            return r == null || r.success() ? null : firstLine(r.outputTrim());
        }

        @Override public String reload(Kind kind) {
            Shell.Result r = switch (kind) {
                case PHP -> running("php_fpm") ? Shell.run(LONG, "service", "php_fpm", "onereload") : null;
                case NGINX -> running("nginx") ? Shell.run(LONG, "service", "nginx", "onereload") : null;
                case FAIL2BAN -> Shell.resolve("fail2ban-client") != null && Shell.run(SHORT, "fail2ban-client", "ping").success()
                        ? Shell.run(LONG, "fail2ban-client", "reload") : null;
                case DOVECOT -> running("dovecot") ? Shell.run(LONG, "doveadm", "reload") : null;
                case POSTFIX -> running("postfix") ? Shell.run(LONG, "postfix", "reload") : null;
                case RSPAMD -> running("rspamd") ? Shell.run(LONG, "service", "rspamd", "onereload") : null;
                case PF, OTHER -> null;
            };
            return r == null || r.success() ? null : firstLine(r.outputTrim());
        }

        private static boolean running(String service) {
            return Shell.run(SHORT, "service", service, "onestatus").success();
        }

        @Override public boolean readableByWww(Path file) {
            return Shell.run(SHORT, "env", "-i", "/usr/sbin/chroot", "-u", "www", "-g", "www", "/", "/bin/test", "-r",
                    file.toString()).success();
        }

        private static String firstLine(String s) {
            int i = s.indexOf('\n');
            return i < 0 ? s : s.substring(0, i);
        }
    }
}
