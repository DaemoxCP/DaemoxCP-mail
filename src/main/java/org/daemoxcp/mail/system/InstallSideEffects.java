package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.util.Shell;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.logging.Logger;
import java.util.stream.Stream;

/**
 * What a package update changes OUTSIDE the files that pkg installs: the
 * live configuration and the listening addresses.
 *
 * The updater's jobs compared packages, versions, locks and active services.
 * None of these things sees an installation script that rewrites a
 * configuration file. Measured on the FreeBSD 15.1 VM on 2026-10-24 (finding 42): upgrading
 * postfix-mysql 3.11.7_1,1 -> 3.11.7_3,1 the script wrote {@code inet_protocols = ipv4}
 * in /usr/local/etc/postfix/main.cf while postfix was listening on IPv4 and IPv6. At the
 * restart IPv6 disappears, and by every check there was the job succeeded: valid
 * configuration, active service, changed pid. A mail server with an AAAA record stops
 * receiving over IPv6 and the panel says "in service".
 *
 * There are two questions, and neither depends on the package:
 *
 *  - which configuration files changed without being files of a package that the
 *    job changed. On FreeBSD the live configuration belongs to no package: pkg
 *    installs main.cf.sample, main.cf belongs to the administrator. A file that no upgraded
 *    package owns, and that changed during the installation, was changed by a script.
 *  - which addresses were listening before and no longer are after.
 *
 * Listing by hand the "important" files of each service would have gone stale at the first
 * new package, and it is the same mistake this class has to catch: the whole
 * configuration is looked at and pkg is asked who owns each file.
 */
final class InstallSideEffects {

    private static final Logger LOGGER = Logger.getLogger(InstallSideEffects.class.getName());

    private InstallSideEffects() {}

    /**
     * Where the live configuration is: all of /usr/local/etc, all of /etc, and the loader
     * configuration. To these are added, one by one, the folders in which an installed
     * package keeps its .sample files outside /usr/local/etc (Roundcube, in
     * /usr/local/www/roundcube/config): the configuration lives where its example lives.
     *
     * Of /etc, before, only the rc.conf files were looked at, and a script that wrote to
     * /etc/periodic.conf would not have been seen. Measured on the VM on 2026-10-24: 574 files,
     * 3 MB, none belonging to a package. What changes there by itself, again measured on the VM
     * over the last two days, has a rule of its own and raises no alarm: the users a package
     * creates (see {@link #ACCOUNT_FILES}), the files regenerated from another one (see
     * {@link #isDerived}), and resolv.conf (see {@link #EXCLUDED}).
     */
    static final List<String> CONFIG_ROOTS = List.of(
            "/usr/local/etc", "/etc", "/boot/loader.conf", "/boot/loader.conf.local", "/boot/loader.conf.d");

    /**
     * What gets written by itself, at any moment, and that no package installs:
     *  - the panel's folder: the panel itself writes it (the firewall
     *    configuration, the secrets);
     *  - /etc/resolv.conf: dhclient and resolvconf rewrite it at every address renewal.
     *    Measured: rewritten at VM startup. Inside an update it would be an alarm
     *    against a script that has nothing to do with it, and an alarm stops the guided restarts.
     * A change of theirs during the update says nothing about the installation scripts.
     */
    static final List<String> EXCLUDED = excludedPaths();

    /**
     * The secrets folder, with the current name and with the previous ones (section "productFiles"), and
     * resolv.conf.
     */
    private static List<String> excludedPaths() {
        List<String> e = new ArrayList<>(List.of(SECRETS_DIR, "/etc/resolv.conf"));
        e.addAll(LegacyNames.oldNamesOf("productFiles", SECRETS_DIR));
        return List.copyOf(e);
    }

    static final String SECRETS_DIR = "/usr/local/etc/daemoxcp-mail";

    /**
     * The lists of users and groups. A package that needs a user creates it in its
     * pre-installation script ("===> Creating users", measured in postfix's output): a
     * LINE ADDED here is a package doing its job, and it is reported without an alarm. A
     * line removed or changed is not: it is an existing user touched by a script.
     */
    static final Set<String> ACCOUNT_FILES = Set.of("/etc/passwd", "/etc/group", "/etc/master.passwd");

    /**
     * The previous version of the files that a script changed, so that it can be put back. Under
     * /var/db/daemoxcp-mail, next to the locks note, and not next to the files: in folders like
     * /usr/local/etc/newsyslog.conf.d or /usr/local/etc/periodic every file there is read, or
     * EXECUTED, and a copy put there would become configuration too.
     */
    static final Path BEFORE_UPDATE_DIR = Paths.get("/var/db/daemoxcp-mail/config-before-update");

    /**
     * How many copies are kept: the oldest are removed. They also contain passwords, like the files they come
     * from.
     */
    static final int BEFORE_UPDATE_KEPT = 10;

    /** The content is kept, to show what changed, only up to this size. */
    static final int MAX_KEPT_BYTES = 256 * 1024;

    /** Lines shown per file, per side: the rest is counted and reported. */
    static final int MAX_SHOWN_LINES = 12;

    /** How long, at most, a missing address is waited for: a daemon just restarted may take a few seconds to open it. */
    static final int LISTEN_GRACE_SECONDS = 60;

    /**
     * The state of a file: the fingerprint of the content, the permissions with owner and group, and the
     * content itself if it is small enough. The content is used to say what changed;
     * it is shown only if the file is readable by everyone (see {@link #configChanges}).
     */
    record FileState(String sha256, String permissions, boolean worldReadable, byte[] content) {}

    /** The configuration at one instant: path -> state, and path -> package that owns it. */
    record ConfigSnapshot(Map<String, FileState> files, Map<String, String> owners) {}

    // ===================== the configuration =====================

    /** The configuration of this machine, now. */
    static ConfigSnapshot configSnapshot() {
        Map<String, String> owners = owners(Shell.runShell(Duration.ofSeconds(60),
                "pkg query -a '%n\t%Fp' 2>/dev/null").output(), CONFIG_ROOTS);
        List<Path> recursive = new ArrayList<>();
        for (String r : CONFIG_ROOTS) recursive.add(Paths.get(r));
        return configSnapshot(recursive, sampleDirsOutside(owners, CONFIG_ROOTS), owners);
    }

    /**
     * The snapshot of a set of folders, without asking pkg anything: this is how it is tested.
     *
     * @param recursive files or folders to look at entirely
     * @param flat      folders to look at without going down into subfolders
     * @param owners    path -> package, from {@link #owners(String)}
     */
    static ConfigSnapshot configSnapshot(List<Path> recursive, List<Path> flat, Map<String, String> owners) {
        Map<String, FileState> files = new TreeMap<>();
        for (Path root : recursive) collect(root, Integer.MAX_VALUE, files);
        for (Path dir : flat) collect(dir, 1, files);
        return new ConfigSnapshot(files, owners);
    }

    private static void collect(Path root, int depth, Map<String, FileState> into) {
        if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) return;
        // walkFileTree and not Files.walk: with Files.walk a file that disappears while the folder
        // is being traversed (someone's temporary file) interrupts the WHOLE snapshot, and
        // /usr/local/etc would be left out because of a single file. Here that file is simply skipped.
        // Without FOLLOW_LINKS: a link to / does not make it snapshot the entire disk.
        try {
            Files.walkFileTree(root, Set.of(), depth, new java.nio.file.SimpleFileVisitor<>() {
                @Override
                public java.nio.file.FileVisitResult preVisitDirectory(Path d, java.nio.file.attribute.BasicFileAttributes a) {
                    return excluded(d.toString()) ? java.nio.file.FileVisitResult.SKIP_SUBTREE
                                                  : java.nio.file.FileVisitResult.CONTINUE;
                }

                @Override
                public java.nio.file.FileVisitResult visitFile(Path p, java.nio.file.attribute.BasicFileAttributes a) {
                    if (a.isRegularFile() && !excluded(p.toString())) {
                        FileState st = state(p);
                        if (st != null) into.put(p.toString(), st);
                    }
                    return java.nio.file.FileVisitResult.CONTINUE;
                }

                @Override
                public java.nio.file.FileVisitResult visitFileFailed(Path p, IOException e) {
                    return java.nio.file.FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            LOGGER.warning("configuration snapshot: could not read " + root + ": " + e.getMessage());
        }
    }

    static boolean excluded(String path) {
        for (String e : EXCLUDED) if (path.equals(e) || path.startsWith(e + "/")) return true;
        return false;
    }

    /** The state of a file, or null if it could not be read. */
    static FileState state(Path p) {
        try {
            PosixFileAttributes a = Files.readAttributes(p, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            Set<PosixFilePermission> perm = a.permissions();
            String permissions = PosixFilePermissions.toString(perm) + " " + a.owner().getName() + ":" + a.group().getName();
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] kept = null;
            if (a.size() <= MAX_KEPT_BYTES) {
                kept = Files.readAllBytes(p);
                md.update(kept);
            } else {
                try (InputStream in = Files.newInputStream(p, LinkOption.NOFOLLOW_LINKS)) {
                    byte[] buf = new byte[65536];
                    for (int n; (n = in.read(buf)) > 0; ) md.update(buf, 0, n);
                }
            }
            return new FileState(HexFormat.of().formatHex(md.digest()), permissions,
                    perm.contains(PosixFilePermission.OTHERS_READ), kept);
        } catch (IOException | UnsupportedOperationException | java.security.NoSuchAlgorithmException e) {
            return null;
        }
    }

    /**
     * Who owns each file, from {@code pkg query -a '%n\t%Fp'}: path -> package name.
     * Only the files that may matter are kept: those under the roots, and those of the
     * folders in which a package keeps a .sample or a .dist. All of the latter, not only
     * the examples: next to config.inc.php.sample Roundcube installs defaults.inc.php, and a
     * package file taken for nobody's configuration would raise the alarm at every one of its
     * updates.
     *
     * And the files that a .sample which is a link points to (see {@link #linkedSample}): they
     * are needed to say that the link leads to a file of the same package.
     */
    static Map<String, String> owners(String pkgQueryOutput, List<String> roots) {
        List<String[]> all = new ArrayList<>();
        Set<String> sampleDirs = new TreeSet<>();
        Set<String> linkTargets = new TreeSet<>();
        for (String line : (pkgQueryOutput == null ? "" : pkgQueryOutput).split("\n")) {
            int tab = line.indexOf('\t');
            if (tab <= 0) continue;
            String name = line.substring(0, tab).trim(), path = line.substring(tab + 1).trim();
            if (!UpdateManager.isValidName(name) || !path.startsWith("/")) continue;
            all.add(new String[]{path, name});
            if (isSample(path) && !underRoots(path, roots)) sampleDirs.add(parentOf(path));
            if (isSample(path)) {
                Path target = linkTarget(Paths.get(path));
                if (target != null) linkTargets.add(target.toString());
            }
        }
        Map<String, String> r = new TreeMap<>();
        for (String[] e : all)
            if (underRoots(e[0], roots) || sampleDirs.contains(parentOf(e[0])) || linkTargets.contains(e[0]))
                r.put(e[0], e[1]);
        return r;
    }

    /** Where a link leads, a single step; null if it is not a link or cannot be read. */
    static Path linkTarget(Path link) {
        try {
            if (!Files.isSymbolicLink(link)) return null;
            return link.resolveSibling(Files.readSymbolicLink(link)).normalize();
        } catch (IOException | UnsupportedOperationException | SecurityException e) {
            return null;
        }
    }

    private static String parentOf(String path) {
        int s = path.lastIndexOf('/');
        return s <= 0 ? "/" : path.substring(0, s);
    }

    private static boolean isSample(String path) {
        return path.endsWith(".sample") || path.endsWith(".dist");
    }

    private static boolean underRoots(String path, List<String> roots) {
        for (String r : roots) if (path.equals(r) || path.startsWith(r + "/")) return true;
        return false;
    }

    /** The folders that contain a .sample or a .dist of a package, outside the roots. */
    static List<Path> sampleDirsOutside(Map<String, String> owners, List<String> roots) {
        Set<String> dirs = new TreeSet<>();
        for (String p : owners.keySet())
            if (isSample(p) && !underRoots(p, roots)) dirs.add(parentOf(p));
        List<Path> r = new ArrayList<>();
        for (String d : dirs) r.add(Paths.get(d));
        return r;
    }

    /**
     * What changed between the two snapshots, and whether it is something to report.
     *
     * Four cases, and only the last one triggers the alarm:
     *  - "package": the file belongs to a package that the job changed. It is the update
     *    itself, it is just counted.
     *  - "newDefault": the live file belongs to nobody and is now identical to the new .sample
     *    of its package. It had never been modified and pkg replaced it with the
     *    new default, which is what it does with an untouched example.
     *  - "rebuilt": the SASL users database recreated with the same users (see
     *    {@link #SASLDB_NAME}). It is reported, without an alarm.
     *  - "commentsOnly": changed by a script, but only in comment or empty lines. It is reported,
     *    it changes nothing of what the service reads. Measured: the postfix script
     *    adds four commented-out entries to master.cf.
     *  - "script": changed, created, removed or with other permissions, without any package of
     *    the job owning it. It is the main.cf of finding 42.
     *
     * @param changedPackages the packages that the job installed, upgraded, reinstalled
     *        or removed: those in the plan and those changed outside the plan
     * @return an object for each changed file: path, happened (changed, created, removed,
     *         permissions), owner, kind, alarm; for the files that can be shown
     *         removedLines and addedLines, for the others hidden with the reason
     */
    static JSONArray configChanges(ConfigSnapshot before, ConfigSnapshot after, Set<String> changedPackages) {
        JSONArray r = new JSONArray();
        Set<String> paths = new TreeSet<>(before.files().keySet());
        paths.addAll(after.files().keySet());
        for (String p : paths) {
            FileState b = before.files().get(p), a = after.files().get(p);
            if (b != null && a != null && b.sha256().equals(a.sha256()) && b.permissions().equals(a.permissions()))
                continue;
            String happened = b == null ? "created" : a == null ? "removed"
                    : !b.sha256().equals(a.sha256()) ? "changed" : "permissions";
            String owner = after.owners().getOrDefault(p, before.owners().get(p));
            JSONObject c = new JSONObject().put("path", p).put("happened", happened)
                    .put("owner", owner == null ? "" : owner);
            if (b != null && a != null && !b.permissions().equals(a.permissions()))
                c.put("permissionsFrom", b.permissions()).put("permissionsTo", a.permissions());

            String kind;
            if (owner != null && changedPackages.contains(owner)) kind = "package";
            else if (owner == null && isDerived(p, before, after)) kind = "derived";
            else if (owner == null && a != null && isNewDefault(p, a, after, changedPackages)) kind = "newDefault";
            else if (owner == null && a == null && sampleWentWithPackage(p, before, after, changedPackages)) kind = "package";
            else kind = "script";

            // What changed inside, when it can be known. The content is read
            // to decide whether it is only comments even when it cannot be shown.
            if (!"package".equals(kind) && !"newDefault".equals(kind) && !"derived".equals(kind)) {
                byte[] oldC = b == null ? new byte[0] : b.content();
                byte[] newC = a == null ? new byte[0] : a.content();
                if (oldC != null && newC != null && isText(oldC) && isText(newC)) {
                    List<List<String>> d = lineDiff(new String(oldC, StandardCharsets.UTF_8),
                                                    new String(newC, StandardCharsets.UTF_8));
                    // Not with changed permissions: a file made unreadable to the daemon, or
                    // readable by everyone, counts even if only the comments changed inside it.
                    if ("changed".equals(happened) && !c.has("permissionsFrom")
                            && (!d.get(0).isEmpty() || !d.get(1).isEmpty())
                            && allComments(d.get(0)) && allComments(d.get(1)))
                        kind = "commentsOnly";
                    else if ("changed".equals(happened) && !c.has("permissionsFrom")
                            && ACCOUNT_FILES.contains(p) && d.get(0).isEmpty() && !d.get(1).isEmpty())
                        kind = "accounts";
                    boolean readable = (b == null || b.worldReadable()) && (a == null || a.worldReadable());
                    if ("changed".equals(happened) && d.get(0).isEmpty() && d.get(1).isEmpty()) {
                        // Same lines, different order: in a configuration file the order
                        // can matter (nginx rules, postfix maps), so it stays
                        // an alarm, but there is no line to show.
                        c.put("hidden", "sameLines");
                    } else if (readable) {
                        c.put("removedLines", shown(d.get(0))).put("removedCount", d.get(0).size());
                        c.put("addedLines", shown(d.get(1))).put("addedCount", d.get(1).size());
                    } else {
                        // A file that not everyone can read may contain a password
                        // (postfix's MySQL maps, dovecot's SQL connection): its
                        // content does not end up in the job's log, not even masked.
                        c.put("hidden", "notWorldReadable");
                    }
                } else if (!"permissions".equals(happened)) {
                    c.put("hidden", oldC == null || newC == null ? "tooLarge" : "binary");
                }
            }
            if ("script".equals(kind) && "changed".equals(happened) && !c.has("permissionsFrom")
                    && p.endsWith("/" + SASLDB_NAME) && b.content() != null && a.content() != null) {
                String usersBefore = saslUsers(b.content()), usersAfter = saslUsers(a.content());
                if (usersBefore != null && usersBefore.equals(usersAfter)) kind = "rebuilt";
            }
            c.put("kind", kind).put("alarm", "script".equals(kind));
            r.put(c);
        }
        return r;
    }

    /**
     * A file regenerated from another one, which therefore changes when its source changes:
     * the alarm, if any, is raised by the source.
     *  - X.db, X.lmdb, X.cdb next to X: the maps of postmap and newaliases (/etc/aliases.db),
     *    /etc/login.conf.db;
     *  - /etc/pwd.db and /etc/spwd.db, which pwd_mkdb derives from /etc/master.passwd;
     *  - /etc/ssl/cert.pem, /etc/ssl/certs and /etc/ssl/untrusted, which certctl derives
     *    from the certificate store. Measured: about 190 files regenerated on the VM over the
     *    last two days, none written by a person.
     */
    static boolean isDerived(String p, ConfigSnapshot before, ConfigSnapshot after) {
        if (p.equals("/etc/pwd.db") || p.equals("/etc/spwd.db") || p.equals("/etc/ssl/cert.pem")
                || p.startsWith("/etc/ssl/certs/") || p.startsWith("/etc/ssl/untrusted/")) return true;
        for (String ext : new String[]{".db", ".lmdb", ".cdb"}) {
            if (!p.endsWith(ext)) continue;
            String source = p.substring(0, p.length() - ext.length());
            if (before.files().containsKey(source) || after.files().containsKey(source)) return true;
        }
        return false;
    }

    /**
     * Sets aside the previous version of the given files, under {@code dir} with their
     * full path, with the same permissions, owner and group: so that {@code cp -p} puts it
     * back as it was. The folder is readable only by root, because among those files are the
     * maps with the passwords.
     *
     * @return path -> where the copy is, or the reason why there is none ("created": it was not
     *         there before; "tooLarge": its content was not kept; "error: ...")
     */
    static Map<String, String> saveBefore(ConfigSnapshot before, List<String> paths, Path dir) {
        Map<String, String> r = new LinkedHashMap<>();
        for (String p : paths) {
            FileState b = before.files().get(p);
            if (b == null) { r.put(p, "created"); continue; }
            if (b.content() == null) { r.put(p, "tooLarge"); continue; }
            try {
                Files.createDirectories(dir, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
                Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
                Path copy = dir.resolve(p.substring(1));
                Files.createDirectories(copy.getParent());
                Files.write(copy, b.content());
                String[] perm = b.permissions().split(" ", 2);
                Files.setPosixFilePermissions(copy, PosixFilePermissions.fromString(perm[0]));
                String[] og = perm.length > 1 ? perm[1].split(":", 2) : new String[0];
                var lookup = copy.getFileSystem().getUserPrincipalLookupService();
                if (og.length == 2) {
                    Files.setOwner(copy, lookup.lookupPrincipalByName(og[0]));
                    Files.getFileAttributeView(copy, java.nio.file.attribute.PosixFileAttributeView.class)
                         .setGroup(lookup.lookupPrincipalByGroupName(og[1]));
                }
                r.put(p, copy.toString());
            } catch (IOException | RuntimeException e) {
                r.put(p, "error: " + e.getMessage());
            }
        }
        return r;
    }

    /**
     * Removes the oldest copies, keeping the last {@code kept}: the names are UTC dates, so the order is that
     * of the names.
     */
    static void pruneBefore(Path root, int kept) {
        try (var s = Files.list(root)) {
            List<Path> dirs = new ArrayList<>(s.filter(Files::isDirectory).sorted().toList());
            for (int i = 0; i < dirs.size() - kept; i++) {
                try (var w = Files.walk(dirs.get(i))) {
                    for (Path x : w.sorted(java.util.Comparator.reverseOrder()).toList()) Files.deleteIfExists(x);
                }
            }
        } catch (IOException | RuntimeException e) {
            LOGGER.warning("could not prune " + root + ": " + e.getMessage());
        }
    }

    /** The live file is identical to its package's .sample, that is it is the new default. */
    private static boolean isNewDefault(String p, FileState a, ConfigSnapshot after, Set<String> changedPackages) {
        for (String suffix : new String[]{".sample", ".dist"}) {
            String sampleOwner = after.owners().get(p + suffix);
            if (sampleOwner == null || !changedPackages.contains(sampleOwner)) continue;
            FileState sample = after.files().get(p + suffix);
            if (sample == null) sample = linkedSample(Paths.get(p + suffix), sampleOwner, after.owners());
            if (sample != null && sample.sha256().equals(a.sha256())) return true;
        }
        return false;
    }

    /**
     * The .sample that is a link: the content of the file it leads to, if it is a regular file
     * of the SAME package; otherwise null, and the change remains to be reported.
     *
     * Seen on the production server on 2026-11-09 (finding 201): ca_root_nss installs
     * etc/ssl/cert.pem.sample as a link to share/certs/ca-root-nss.crt, and when upgrading it
     * pkg put back into cert.pem, untouched, the new list of certificate authorities. The
     * snapshot does not follow links (one to / would snapshot the disk), so the .sample
     * was not there, and the new default was taken for a script: "Step failed" on an
     * update that went fine. Here only this link is followed, by one step.
     */
    static FileState linkedSample(Path link, String owner, Map<String, String> owners) {
        Path target = linkTarget(link);
        if (target == null || !owner.equals(owners.get(target.toString()))) return null;
        if (!Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS)) return null;
        return state(target);
    }

    /** The live file went away together with the .sample of the package that the job removed. */
    private static boolean sampleWentWithPackage(String p, ConfigSnapshot before, ConfigSnapshot after,
                                                 Set<String> changedPackages) {
        for (String suffix : new String[]{".sample", ".dist"}) {
            String owner = before.owners().get(p + suffix);
            if (owner != null && changedPackages.contains(owner) && !after.files().containsKey(p + suffix))
                return true;
        }
        return false;
    }

    /**
     * The SASL users database. At every reinstallation of cyrus-sasl the uninstall
     * script deletes it if it contains no users, and the install script recreates it
     * empty: same content, different bytes. Measured on latest on 2026-10-24, in the update
     * of the unlocked packages ("reinstall cyrus-sasl 2.1.28_6"): an alarm that would have gone
     * off at every reinstallation, and that in the guided update would have stopped the restart
     * of postfix, which depends on cyrus-sasl. With users inside, the script leaves it alone.
     */
    static final String SASLDB_NAME = "sasldb2.db";

    /**
     * The users of a SASL database read by its tool, {@code sasldblistusers2}: lines
     * "user@domain: attribute type", never the values. These are compared, not the bytes, which
     * for a recreated database always change. Null if it could not be read (tool
     * missing, unreadable file): then the alarm stays.
     */
    static String saslUsers(byte[] content) {
        Path dir = null;
        try {
            // The tool adds ".db" by itself to the name it is given: with -f .../sasldb2.db
            // it looks for sasldb2.db.db, does not find it, writes "listusers failed" and exits with 0.
            // Measured on the VM: taken that way, any two files came out as "same users".
            dir = Files.createTempDirectory("sasldb",
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
            Files.write(dir.resolve(SASLDB_NAME), content);
            Shell.Result r = Shell.runShell(Duration.ofSeconds(20),
                    "sasldblistusers2 -f '" + dir.resolve("sasldb2") + "' 2>&1");
            if (r.exitCode() != 0) return null;
            List<String> lines = new ArrayList<>();
            for (String l : r.output().split("\n")) {
                if (l.isBlank()) continue;
                // Only "user@domain: attribute" lines: anything else (including
                // "listusers failed", which exits with 0) means it did not read the database.
                if (!l.trim().matches("[^\\s:]+@[^\\s:]*: \\S+")) return null;
                lines.add(l.trim());
            }
            java.util.Collections.sort(lines);
            return String.join("\n", lines);
        } catch (IOException | RuntimeException e) {
            return null;
        } finally {
            if (dir != null) {
                try (Stream<Path> w = Files.walk(dir)) {
                    for (Path x : w.sorted(java.util.Comparator.reverseOrder()).toList()) Files.deleteIfExists(x);
                } catch (IOException ignored) {}
            }
        }
    }

    static boolean isText(byte[] b) {
        for (byte x : b) if (x == 0) return false;
        return true;
    }

    /**
     * The removed lines and the added ones, counted as a multiset: [removed, added], each
     * in the order of its own file. For a configuration file it is the answer that is needed
     * ("+ inet_protocols = ipv4") without the cost of a real diff, which on two files of a few
     * thousand lines would need a table of millions of cells.
     */
    static List<List<String>> lineDiff(String oldText, String newText) {
        Map<String, Integer> count = new LinkedHashMap<>();
        String[] o = lines(oldText), n = lines(newText);
        for (String l : o) count.merge(l, 1, Integer::sum);
        List<String> added = new ArrayList<>();
        for (String l : n) {
            Integer k = count.get(l);
            if (k != null && k > 0) count.put(l, k - 1);
            else added.add(l);
        }
        List<String> removed = new ArrayList<>();
        Map<String, Integer> left = new LinkedHashMap<>(count);
        for (String l : o) {
            Integer k = left.get(l);
            if (k != null && k > 0) { removed.add(l); left.put(l, k - 1); }
        }
        return List.of(removed, added);
    }

    /** The lines of a text. The empty piece after the last newline is not a line of the file. */
    private static String[] lines(String text) {
        if (text.isEmpty()) return new String[0];
        String t = text.endsWith("\n") ? text.substring(0, text.length() - 1) : text;
        return t.split("\n", -1);
    }

    /** Comment or empty line, in the two notations of the files in /usr/local/etc: # and ; (php.ini). */
    static boolean allComments(List<String> lines) {
        for (String l : lines) {
            String t = l.trim();
            if (!t.isEmpty() && !t.startsWith("#") && !t.startsWith(";")) return false;
        }
        return true;
    }

    /** The lines to show: at most MAX_SHOWN_LINES, shortened, with the credentials masked. */
    private static JSONArray shown(List<String> lines) {
        JSONArray r = new JSONArray();
        for (int i = 0; i < lines.size() && i < MAX_SHOWN_LINES; i++) {
            String l = UpdateManager.maskCredentials(lines.get(i)).replace('\t', ' ');
            r.put(l.length() > 160 ? l.substring(0, 160) + "..." : l);
        }
        return r;
    }

    // ===================== the listening addresses =====================

    /**
     * The TCP addresses listening right now: "tcp6 *:25" -> "master". Null if they could not be
     * asked for, which is not "nobody listening".
     *
     * Only TCP. In UDP {@code sockstat -l} also lists the sockets with which rspamd makes its
     * DNS queries, bound to *:* and different at every restart: measured 25 out of 63 lines on
     * the VM. Comparing them would raise an alarm at every rspamd update.
     */
    static Map<String, String> listening() {
        Shell.Result r = Shell.runShell(Duration.ofSeconds(20), "sockstat -46lq -P tcp 2>/dev/null");
        return r.success() ? parseSockstat(r.output()) : null;
    }

    /**
     * From {@code sockstat -46lq}: USER COMMAND PID FD PROTO LOCAL FOREIGN. The key is
     * protocol and local address, not the pid: the pid changes at every restart, the address
     * must stay.
     */
    static Map<String, String> parseSockstat(String out) {
        Map<String, String> r = new TreeMap<>();
        for (String line : (out == null ? "" : out).split("\n")) {
            String[] t = line.trim().split("\\s+");
            if (t.length < 6 || !t[4].startsWith("tcp")) continue;
            r.putIfAbsent(t[4] + " " + t[5], t[1]);
        }
        return r;
    }

    /** The addresses lost and those that appeared: {lost: [...], gained: [...]}, each {address, command}. */
    static JSONObject compareListening(Map<String, String> before, Map<String, String> after) {
        JSONArray lost = new JSONArray(), gained = new JSONArray();
        for (Map.Entry<String, String> e : before.entrySet())
            if (!after.containsKey(e.getKey()))
                lost.put(new JSONObject().put("address", e.getKey()).put("command", e.getValue()));
        for (Map.Entry<String, String> e : after.entrySet())
            if (!before.containsKey(e.getKey()))
                gained.put(new JSONObject().put("address", e.getKey()).put("command", e.getValue()));
        return new JSONObject().put("lost", lost).put("gained", gained);
    }

    // ===================== a job =====================

    /**
     * The two snapshots of a job and the problems the comparison found. A job
     * creates one, takes the snapshot right before pkg upgrade and queries it afterwards; at the
     * end it puts {@link #problems()} in its own outcome.
     *
     * It is in a single place because three jobs ask for it (guided update, full
     * maintenance, update of the unlocked packages), and the same decision written three times
     * has already become, in this area, three different decisions.
     */
    static final class Watch {
        private boolean taken;
        private boolean changedByScript;
        private ConfigSnapshot configBefore;
        private Map<String, String> listeningBefore;
        private final List<String> problems = new ArrayList<>();

        /** Right before pkg upgrade: the configuration and the addresses as the administrator left them. */
        void takeBefore() {
            taken = true;
            try {
                configBefore = configSnapshot();
            } catch (RuntimeException e) {
                LOGGER.warning("configuration snapshot failed: " + e);
            }
            listeningBefore = listening();
        }

        /**
         * After pkg upgrade: what changed in the configuration, outside the packages'
         * files. It is called also when pkg exited non-zero: that is exactly the case in
         * which a machine may have been left halfway.
         *
         * @param plan          the signed plan, to know which packages the job changed
         * @param outsidePlan   the packages changed outside the plan (already reported separately)
         * @param restartFollows true if the job restarts the services right afterwards (the guided
         *                      update): then the change takes effect shortly, not at the
         *                      next restart
         */
        void checkConfig(UpdateManager.Job job, JSONObject plan, JSONArray outsidePlan, boolean restartFollows) {
            // A job that stopped before pkg upgrade changed nothing: there is no
            // before to compare, and an "I could not check" would be false.
            if (!taken) return;
            job.write("  " + I18n.tr("server.drift.configHeader"));
            if (configBefore == null) {
                job.write("    ?   " + I18n.tr("server.drift.configUnknown"));
                return;
            }
            JSONArray changes;
            try {
                changes = configChanges(configBefore, configSnapshot(), changedPackages(plan, outsidePlan));
            } catch (RuntimeException e) {
                LOGGER.warning("configuration comparison failed: " + e);
                job.write("    ?   " + I18n.tr("server.drift.configUnknown"));
                return;
            }
            int packageFiles = 0, derivedFiles = 0;
            List<String> alarmed = new ArrayList<>();
            for (int i = 0; i < changes.length(); i++) {
                JSONObject c = changes.getJSONObject(i);
                String kind = c.getString("kind");
                if ("package".equals(kind)) { packageFiles++; continue; }
                if ("derived".equals(kind)) { derivedFiles++; continue; }
                String mark = c.getBoolean("alarm") ? "NO  " : "--  ";
                job.write("    " + mark + c.getString("path") + ": "
                        + I18n.tr("server.drift.happened." + c.getString("happened"))
                        + ", " + I18n.tr("server.drift.kind." + kind));
                if (c.has("permissionsFrom"))
                    job.write("          " + I18n.tr("server.drift.permissions",
                            Map.of("from", c.getString("permissionsFrom"), "to", c.getString("permissionsTo"))));
                writeLines(job, c, "removedLines", "removedCount", "- ");
                writeLines(job, c, "addedLines", "addedCount", "+ ");
                if (c.has("hidden"))
                    job.write("          " + I18n.tr("server.drift.hidden." + c.getString("hidden")));
                if (c.getBoolean("alarm")) alarmed.add(c.getString("path"));
            }
            if (alarmed.isEmpty() && changes.length() == packageFiles + derivedFiles) {
                job.write("    ok  " + I18n.tr("server.drift.configClean", Map.of("n", String.valueOf(packageFiles))));
                if (derivedFiles > 0)
                    job.write("    " + I18n.tr("server.drift.derivedFiles", Map.of("n", String.valueOf(derivedFiles))));
                return;
            }
            if (packageFiles > 0)
                job.write("    " + I18n.tr("server.drift.packageFiles", Map.of("n", String.valueOf(packageFiles))));
            if (derivedFiles > 0)
                job.write("    " + I18n.tr("server.drift.derivedFiles", Map.of("n", String.valueOf(derivedFiles))));
            if (alarmed.isEmpty()) return;
            changedByScript = true;
            writeSaved(job, saveBefore(configBefore, alarmed, BEFORE_UPDATE_DIR.resolve(
                    java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'")
                            .withZone(java.time.ZoneOffset.UTC).format(java.time.Instant.now()))));
            pruneBefore(BEFORE_UPDATE_DIR, BEFORE_UPDATE_KEPT);
            job.write("  " + I18n.tr(restartFollows ? "server.drift.configNoteHeld" : "server.drift.configNoteLater"));
            problems.add(I18n.tr("server.drift.configProblem", Map.of("files", String.join(", ", alarmed))));
            // Outside the job's log, which lives in memory: a changed configuration that
            // nobody approved must stay written down. Only the paths, no content (r19).
            LOGGER.warning("configuration changed by an installation script: " + alarmed);
        }

        /**
         * At the end of the job: are the addresses that were listening before still there?
         * A missing one is waited for up to {@link #LISTEN_GRACE_SECONDS}, because a daemon
         * just restarted may take a few seconds to open it.
         */
        void checkListening(UpdateManager.Job job) {
            if (!taken) return;
            job.write("  " + I18n.tr("server.drift.listenHeader"));
            if (listeningBefore == null) {
                job.write("    ?   " + I18n.tr("server.drift.listenUnknown"));
                return;
            }
            Map<String, String> now = listening();
            long deadline = System.currentTimeMillis() + LISTEN_GRACE_SECONDS * 1000L;
            while ((now == null || !compareListening(listeningBefore, now).getJSONArray("lost").isEmpty())
                    && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(3000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); break; }
                now = listening();
            }
            if (now == null) {
                job.write("    ?   " + I18n.tr("server.drift.listenUnknown"));
                return;
            }
            JSONObject cmp = compareListening(listeningBefore, now);
            JSONArray lost = cmp.getJSONArray("lost"), gained = cmp.getJSONArray("gained");
            List<String> lostNames = new ArrayList<>();
            for (int i = 0; i < lost.length(); i++) {
                JSONObject l = lost.getJSONObject(i);
                lostNames.add(l.getString("address"));
                job.write("    NO  " + l.getString("address") + " (" + l.getString("command") + "): "
                        + I18n.tr("server.drift.lost"));
            }
            for (int i = 0; i < gained.length(); i++) {
                JSONObject g = gained.getJSONObject(i);
                job.write("    +   " + g.getString("address") + " (" + g.getString("command") + "): "
                        + I18n.tr("server.drift.gained"));
            }
            if (lost.isEmpty()) {
                job.write("    ok  " + I18n.tr("server.drift.listenSame", Map.of("n", String.valueOf(listeningBefore.size()))));
                return;
            }
            problems.add(I18n.tr("server.drift.listenProblem", Map.of("list", String.join(", ", lostNames))));
            LOGGER.warning("listening addresses lost after an update: " + lostNames);
        }

        /** The problems to put in the job's outcome; empty if the comparison found nothing. */
        List<String> problems() { return new ArrayList<>(problems); }

        /**
         * True if a script changed the configuration outside the packages' files (an
         * alarm, not a restored default or some comments). The guided update
         * asks for it before restarting: see runGuidedUpdate.
         */
        boolean configChangedByScript() { return changedByScript; }

        /** Where the previous version of each file is, and how to put it back. */
        private static void writeSaved(UpdateManager.Job job, Map<String, String> saved) {
            String dir = null;
            for (Map.Entry<String, String> e : saved.entrySet()) {
                String v = e.getValue();
                if (v.equals("created")) job.write("    " + I18n.tr("server.drift.savedCreated", Map.of("path", e.getKey())));
                else if (v.equals("tooLarge")) job.write("    " + I18n.tr("server.drift.savedTooLarge", Map.of("path", e.getKey())));
                else if (v.startsWith("error: ")) job.write("    " + I18n.tr("server.drift.savedError",
                        Map.of("path", e.getKey(), "error", v.substring(7))));
                else {
                    if (dir == null) {
                        dir = v.substring(0, v.length() - e.getKey().length());
                        job.write("  " + I18n.tr("server.drift.savedHeader", Map.of("dir", dir)));
                    }
                    job.write("      cp -p " + v + " " + e.getKey());
                }
            }
        }

        private static void writeLines(UpdateManager.Job job, JSONObject c, String key, String countKey, String sign) {
            JSONArray lines = c.optJSONArray(key);
            if (lines == null) return;
            for (int i = 0; i < lines.length(); i++) job.write("          " + sign + lines.getString(i));
            int more = c.optInt(countKey) - lines.length();
            if (more > 0) job.write("          " + I18n.tr("server.drift.moreLines", Map.of("n", String.valueOf(more))));
        }
    }

    /** The packages that the job changed: the lines of the plan and those changed outside the plan. */
    static Set<String> changedPackages(JSONObject plan, JSONArray outsidePlan) {
        Set<String> r = new TreeSet<>();
        JSONArray changes = plan == null ? null : plan.optJSONArray("changes");
        for (int i = 0; changes != null && i < changes.length(); i++) {
            String n = changes.getJSONObject(i).optString("name");
            if (!n.isEmpty()) r.add(n);
        }
        for (int i = 0; outsidePlan != null && i < outsidePlan.length(); i++) {
            String n = outsidePlan.getJSONObject(i).optString("name");
            if (!n.isEmpty()) r.add(n);
        }
        return r;
    }
}
