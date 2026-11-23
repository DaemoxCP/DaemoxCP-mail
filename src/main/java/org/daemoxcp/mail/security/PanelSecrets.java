package org.daemoxcp.mail.security;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Properties;
import java.util.Set;

/**
 * The panel's keys and secrets, in a file readable only by root, never in the database nor in the
 * repository: data encryption (administrators' email addresses, session addresses), blind
 * index, fingerprints of the one-time codes, webmail key; and the text secrets that
 * used to be in the SQLite configuration database (MySQL password, TLS private key).
 *
 * The file is /usr/local/etc/daemoxcp-mail/panel-secrets.properties, next to the vault's master.key.
 * The folder is 700 and the file 600; the keys are generated on first use with SecureRandom.
 * Whoever copies the database without this file cannot read the encrypted email addresses and cannot forge a
 * valid code. Tests move the folder with -Ddaemoxcp.mail.secrets.dir=...
 */
public final class PanelSecrets {

    private PanelSecrets() {}

    static final String DATA_KEY = "data_key";
    static final String INDEX_KEY = "index_key";
    static final String CODE_KEY = "code_key";
    // The "session_key" key (CSRF token) is no longer created: the session, CSRF and pre-login
    // tokens depend on a key that lives only in the process memory (WebSessions,
    // finding 184). In older files it remains, unused.
    /** The key the webmail (Roundcube) sends to the panel to change a mailbox password. */
    static final String WEBMAIL_KEY = "webmail_key";
    /** The password of the panel's MySQL user (it used to be in the SQLite configuration database). */
    public static final String MYSQL_PASSWORD = "mysql_password";
    /**
     * The new password of the panel's MySQL user until MySQL has accepted it: the installation writes it
     * before the script, and it becomes {@link #MYSQL_PASSWORD} only once MySQL
     * knows it (org.daemoxcp.mail.system.PendingDbPassword). Usually it is not there.
     */
    public static final String MYSQL_PASSWORD_PENDING = "mysql_password_pending";
    /**
     * The state of the one-time change of the panel's MySQL user password (org.daemoxcp.mail.system.PanelDbPassword,
     * finding 232): "retained:" and the old one's fingerprint halfway through, "done " and the date once done. Root only.
     */
    public static final String MYSQL_PASSWORD_ROTATION = "mysql_password_rotation";
    /** The MySQL root password: it used not to exist, and root logged in with nothing. */
    public static final String MYSQL_ROOT_PASSWORD = "mysql_root_password";
    /**
     * The password of the webmail's MySQL user (roundcube), which can touch only the Roundcube
     * database. The webmail used to log in with the panel's user: see RoundcubeDbUser.
     */
    public static final String ROUNDCUBE_DB_PASSWORD = "roundcube_db_password";
    /** The panel's TLS private key (PEM) (it used to be in the SQLite configuration database). */
    public static final String PANEL_TLS_KEY = "panel_tls_key";
    /**
     * The password of the web part's MySQL user (daemoxcp_mail_web), which can only call the web's procedures.
     * The root part writes it when the user is ready and tested.
     */
    public static final String MYSQL_WEB_PASSWORD = "mysql_web_password";
    /**
     * The vault's private key (RSA, PKCS#8 in base64): it reads the copies of the mailbox passwords. Only in the
     * root file (PasswordVault); the one from before the last rotation next to it.
     */
    public static final String VAULT_PRIVATE_KEY = "vault_private_key";
    public static final String VAULT_PREVIOUS_PRIVATE_KEY = "vault_previous_private_key";
    /** The vault's public key (X.509 in base64): the web part uses it to encrypt the copies of new passwords. */
    public static final String VAULT_PUBLIC_KEY = "vault_public_key";
    /** The passwords of the Postfix and Dovecot MySQL users (MailDbUsers): root only, and in their configuration files. */
    public static final String POSTFIX_DB_PASSWORD = "postfix_db_password";
    public static final String DOVECOT_DB_PASSWORD = "dovecot_db_password";
    /** The rspamd controller password (RspamdController): root only, and in the rspamd configuration only its hash. */
    public static final String RSPAMD_CONTROLLER_PASSWORD = "rspamd_controller_password";

    /** The folder of the files; tests move it to a temporary folder. */
    static Path dir = Paths.get(System.getProperty("daemoxcp.mail.secrets.dir", "/usr/local/etc/daemoxcp-mail"));
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * The secrets that stay root only. The web part of the panel
     * runs as the daemoxcp_mail user and reads its own file; these two are used only by installers and
     * migrations, which run as root, and with the MySQL root password whoever broke into the web part would have
     * the whole database. They live in a separate file, 0600 owned by root, in the same folder.
     */
    public static final Set<String> ROOT_ONLY = Set.of(MYSQL_ROOT_PASSWORD, ROUNDCUBE_DB_PASSWORD, VAULT_PRIVATE_KEY,
            VAULT_PREVIOUS_PRIVATE_KEY, POSTFIX_DB_PASSWORD, DOVECOT_DB_PASSWORD, MYSQL_PASSWORD_ROTATION, RSPAMD_CONTROLLER_PASSWORD);

    /**
     * The secrets that move to the root file once the web part has its own MySQL user ({@link #MYSQL_WEB_PASSWORD}
     * in the web file): the password of the panel's MySQL user, which can do anything in the database, and the
     * pending one of the installation. Until the web part has its own, they stay in the web file, which uses them.
     *
     * <p>They are read from both files, the right one first (halfway through a move they are in both,
     * identical). The web part never reads the root file: for it, only its own exists.
     */
    static final Set<String> MOVE_TO_ROOT = Set.of(MYSQL_PASSWORD, MYSQL_PASSWORD_PENDING);

    /**
     * The group of the web part of the separated panel. With the separated panel (PanelSeparation) the folder
     * is 0750 root:daemoxcp_mail and the web file 0640 root:daemoxcp_mail: the web part reads it and never writes it (the
     * keys are generated by the root part at startup, before starting it). Every rewrite by root creates a new file
     * (a rename): it takes the group and permissions of the one it replaces, so whoever writes (the root part,
     * the menu, a console command) leaves the web part able to read. The root file stays 0600.
     */
    static final String WEB_GROUP = org.daemoxcp.mail.system.Product.ID;

    static final Store WEB = new Store("panel-secrets.properties", "panel-secrets.lock", true);
    static final Store ROOT = new Store("root-secrets.properties", "root-secrets.lock", false);

    private static Store storeFor(String name) {
        if (ROOT_ONLY.contains(name)) return ROOT;
        if (MOVE_TO_ROOT.contains(name) && webHasItsOwnUser()) return ROOT;
        return WEB;
    }

    /** The web part logs in to MySQL with its own user: the secrets of MOVE_TO_ROOT are in the root file. */
    static boolean webHasItsOwnUser() {
        return !WEB.load().getProperty(MYSQL_WEB_PASSWORD, "").isEmpty();
    }

    static synchronized void reset() { WEB.reset(); ROOT.reset(); }

    private static boolean runningAsRoot() { return "root".equals(System.getProperty("user.name")); }

    /*
     * Each file is used by several processes: the panel and the console commands (--access-code); with the
     * separated panel also its two parts. Each keeps a copy in memory; if another one has written the
     * file, the copy is reread (date and size changed). Writes reread from disk under a
     * file system lock, so a missing key is generated by one process only: if each generated its
     * own, the code given by the console would never be right for the panel.
     */
    static final class Store {
        private final String fileName;
        private final String lockName;
        private final boolean web;
        private Properties cache;
        private String cacheStamp = "";

        Store(String fileName, String lockName, boolean web) {
            this.fileName = fileName;
            this.lockName = lockName;
            this.web = web;
        }

        synchronized void reset() { cache = null; cacheStamp = ""; }

        Path file() { return dir.resolve(fileName); }

        private String stamp() {
            try {
                Path f = file();
                return Files.exists(f) ? Files.getLastModifiedTime(f).toMillis() + ":" + Files.size(f) : "";
            } catch (IOException e) {
                return "?";
            }
        }

        Properties readFile() {
            Properties p = new Properties();
            Path f = file();
            if (Files.exists(f)) {
                try (Reader r = Files.newBufferedReader(f, StandardCharsets.UTF_8)) {
                    p.load(r);
                } catch (IOException e) {
                    throw new IllegalStateException("Panel secrets file unreadable: " + f.toAbsolutePath(), e);
                }
            }
            return p;
        }

        synchronized Properties load() {
            String now = stamp();
            if (cache != null && now.equals(cacheStamp)) return cache;
            cache = readFile();
            cacheStamp = now;
            return cache;
        }

        /** Reads, changes and rewrites the file while holding the lock: one process at a time. */
        synchronized Properties update(java.util.function.UnaryOperator<Properties> change) {
            try {
                if (runningAsRoot() || !Files.isDirectory(dir)) {
                    Files.createDirectories(dir);
                    setPermissions(dir, webGroup(dir) ? "rwxr-x---" : "rwx------");
                }
                Path lock = dir.resolve(lockName);
                try (java.nio.channels.FileChannel ch = java.nio.channels.FileChannel.open(lock,
                        java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.WRITE);
                     java.nio.channels.FileLock ignored = ch.lock()) {
                    setPermissions(lock, "rw-------");
                    rootOnly(lock);
                    Properties p = readFile();
                    Properties changed = change.apply(p);
                    if (changed != null) store(changed);
                    else { cache = p; cacheStamp = stamp(); }
                    return cache;
                }
            } catch (IOException e) {
                throw new IllegalStateException("Panel secrets file not writable: " + file().toAbsolutePath(), e);
            }
        }

        private void store(Properties p) throws IOException {
            Path tmp = dir.resolve(fileName + ".tmp");
            Files.deleteIfExists(tmp);
            Files.createFile(tmp);
            setPermissions(tmp, "rw-------");
            try (Writer w = Files.newBufferedWriter(tmp, StandardCharsets.UTF_8)) {
                p.store(w, web ? "DaemoxCP Mail secrets - the panel only, never in the database or the repository"
                               : "DaemoxCP Mail root secrets - root only, never in the database or the repository");
            }
            // The web file, with the separated panel: the new one stays readable by the web group like
            // the one it replaces. Before the rename, so there is no instant in which the web part cannot read.
            boolean forWeb = web && Files.exists(file()) && webGroup(file());
            if (forWeb) {
                setGroup(tmp, WEB_GROUP);
                setPermissions(tmp, "rw-r-----");
            } else {
                rootOnly(tmp);
            }
            try {
                Files.move(tmp, file(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, file(), StandardCopyOption.REPLACE_EXISTING);
            }
            setPermissions(file(), forWeb ? "rw-r-----" : "rw-------");
            cache = p;
            cacheStamp = stamp();
        }
    }

    /** True if the file belongs to the web part's group (the separated panel has opened it to the web part). */
    static boolean webGroup(Path p) {
        try {
            return WEB_GROUP.equals(Files.readAttributes(p, java.nio.file.attribute.PosixFileAttributes.class,
                    java.nio.file.LinkOption.NOFOLLOW_LINKS).group().getName());
        } catch (IOException | UnsupportedOperationException e) {
            return false;
        }
    }

    private static void setPermissions(Path p, String perms) throws IOException {
        try {
            Set<PosixFilePermission> s = PosixFilePermissions.fromString(perms);
            Files.setPosixFilePermissions(p, s);
        } catch (UnsupportedOperationException ignored) {
            // File system without POSIX permissions: whatever is there stays.
        }
    }

    /**
     * A root-only file with the root group. On FreeBSD a new file takes the folder's group
     * (open(2)), and with the separated panel the folder belongs to the web group: at 0600 the group cannot read
     * anyway, but whoever looks must see root:wheel, and a wrong chmod tomorrow opens nothing.
     */
    private static void rootOnly(Path p) throws IOException {
        if (runningAsRoot() && webGroup(p)) setGroup(p, "wheel");
    }

    private static void setGroup(Path p, String group) throws IOException {
        Files.getFileAttributeView(p, java.nio.file.attribute.PosixFileAttributeView.class)
                .setGroup(p.getFileSystem().getUserPrincipalLookupService().lookupPrincipalByGroupName(group));
    }

    private static String get(String name) {
        if (MOVE_TO_ROOT.contains(name)) {
            Store first = storeFor(name), other = first == ROOT ? WEB : ROOT;
            String v = first == ROOT && !runningAsRoot() ? "" : first.load().getProperty(name, "");
            if (!v.isEmpty() || (other == ROOT && !runningAsRoot())) return v;
            return other.load().getProperty(name, "");
        }
        return storeFor(name).load().getProperty(name, "");
    }

    /** A 32-byte key, generated and written the first time it is needed (by one process only). */
    static synchronized byte[] key(String name) {
        String v = get(name);
        if (v.isEmpty()) {
            v = storeFor(name).update(p -> {
                if (!p.getProperty(name, "").isEmpty()) return null;     // the other process just wrote it
                byte[] k = new byte[32];
                RANDOM.nextBytes(k);
                p.setProperty(name, Base64.getEncoder().encodeToString(k));
                return p;
            }).getProperty(name, "");
        }
        byte[] k = Base64.getDecoder().decode(v);
        if (k.length != 32) throw new IllegalStateException("Panel secret " + name + " is not a 32-byte key");
        return k;
    }

    /** A text secret (password, PEM key); "" if it is not there. */
    public static String text(String name) {
        return get(name);
    }

    /**
     * A text secret read right now from disk, not from the in-memory copy: for whoever must know
     * that a password really is in the file before putting it into a service (MysqlRoot).
     */
    public static synchronized String reread(String name) {
        return storeFor(name).readFile().getProperty(name, "");
    }

    /** Where the panel's file is, to tell in messages to whoever has to go and look for it. */
    public static String location() {
        return WEB.file().toAbsolutePath().toString();
    }

    /** Where the file holding this secret is. */
    public static String location(String name) {
        return storeFor(name).file().toAbsolutePath().toString();
    }

    /** Writes (or with "" or null removes) a text secret; one process at a time, file 600. */
    public static synchronized void setText(String name, String value) {
        String v = value == null ? "" : value;
        Store store = storeFor(name);
        store.update(p -> {
            if (v.equals(p.getProperty(name, ""))) return null;
            if (v.isEmpty()) p.remove(name);
            else p.setProperty(name, v);
            return p;
        });
        // Moved to the root file: no old value must remain in the other one.
        if (store == ROOT && MOVE_TO_ROOT.contains(name)) {
            WEB.update(p -> p.remove(name) == null ? null : p);
        }
    }

    /**
     * WebDbAccess, as root, when the web's MySQL user is ready and tested: its password into the web
     * file, and the secrets of {@link #MOVE_TO_ROOT} from that file to the root one. First the root file is written and
     * reread; then, in a single write of the web file, the web password goes in and the others
     * go out. Halfway through every secret is in at least one file, and whoever reads finds it (get). True if it
     * changed something: on the second startup it writes nothing.
     */
    public static synchronized boolean giveWebItsOwnUser(String webPassword) {
        if (webPassword == null || webPassword.isEmpty()) throw new IllegalArgumentException("no password for the web part's MySQL user");
        Properties web = WEB.readFile();
        boolean changed = false;
        for (String name : MOVE_TO_ROOT) {
            String v = web.getProperty(name, "");
            if (v.isEmpty()) continue;
            ROOT.update(p -> {
                if (v.equals(p.getProperty(name, ""))) return null;
                p.setProperty(name, v);
                return p;
            });
            if (!v.equals(ROOT.readFile().getProperty(name, "")))
                throw new IllegalStateException("Root secret " + name + " not saved in " + ROOT.file());
            changed = true;
        }
        if (changed || !webPassword.equals(web.getProperty(MYSQL_WEB_PASSWORD, ""))) {
            WEB.update(p -> {
                p.setProperty(MYSQL_WEB_PASSWORD, webPassword);
                for (String name : MOVE_TO_ROOT) p.remove(name);
                return p;
            });
            changed = true;
        }
        return changed;
    }

    /**
     * At startup, as root: the root-only secrets still in the panel's file (servers from
     * before) move to the root file and then disappear from the panel's one. First the root file is written
     * and reread, then the secret is removed from the other: halfway through the secret is always in at least one
     * file. If the root file already has a different value, its value wins, being the one written later. The names
     * moved, or none.
     */
    public static synchronized java.util.List<String> splitRootSecrets() {
        Properties web = WEB.readFile();
        java.util.List<String> moved = new java.util.ArrayList<>();
        for (String name : ROOT_ONLY) {
            String v = web.getProperty(name, "");
            if (v.isEmpty()) continue;
            ROOT.update(p -> {
                if (!p.getProperty(name, "").isEmpty()) return null;
                p.setProperty(name, v);
                return p;
            });
            if (ROOT.readFile().getProperty(name, "").isEmpty())
                throw new IllegalStateException("Root secret " + name + " not saved in " + ROOT.file());
            moved.add(name);
        }
        if (!moved.isEmpty()) {
            WEB.update(p -> {
                for (String name : moved) p.remove(name);
                return p;
            });
        }
        return moved;
    }

    /**
     * The characters a password is generated from.
     *
     * <p>The single quote, the double quote, the backslash and the backtick are left out on purpose: the
     * password ends up inside {@code IDENTIFIED BY '...'} in a here-document of the installation
     * script, and one of those characters would break it or be taken for a MySQL
     * escape. The dollar stays: the here-document expansion happens only once,
     * so a dollar <em>inside</em> the password is not expanded again.
     */
    private static final char[] ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=".toCharArray();

    /**
     * Only letters and digits: the alphabet for the password of the panel's user and for the
     * webmail's.
     *
     * <p>It is not a lazy choice. Those passwords, unlike the root one, end up
     * in places that are <em>not</em> SQL: Roundcube's connection URL
     * ({@code mysql://user:password@127.0.0.1/roundcubemail}), the Postfix files and the
     * Dovecot configuration. In a URL an at sign breaks the address, a
     * {@code %} opens a decoding sequence and a slash changes the path; in configuration
     * files a {@code #} can open a comment. Here an extra character does not
     * add any defence worth those breakages: twenty-four alphanumeric characters are
     * about 143 bits.
     */
    private static final char[] ALPHANUMERIC =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toCharArray();

    /** A new password for SQL, taken from a cryptographic generator. */
    public static String newPassword(int length) {
        return newPassword(length, ALPHABET);
    }

    /** A new password of letters and digits only, for the places that are not SQL. */
    public static String newAlphanumericPassword(int length) {
        return newPassword(length, ALPHANUMERIC);
    }

    private static String newPassword(int length, char[] alphabet) {
        StringBuilder b = new StringBuilder(length);
        for (int i = 0; i < length; i++) b.append(alphabet[RANDOM.nextInt(alphabet.length)]);
        return b.toString();
    }

    /**
     * The MySQL root password, generating it if it is not there yet.
     *
     * <p>There used to be none: the installation script ran {@code mysql -u root} and
     * then {@code mysql -u root --password=}, that is it took for granted that root logged in without a
     * secret. On FreeBSD that is exactly how a freshly installed MySQL stays, and root without a
     * password means that <em>any</em> local user, including {@code www}, which
     * runs Roundcube, has full powers over the database.
     *
     * <p>The <strong>first</strong> password is not configured: it is generated, once only, with
     * a cryptographic generator; from then on <em>that</em> is the password, and it is
     * reread from here. Otherwise the one in the file and the one set in MySQL would no
     * longer be the same secret. A password set by hand is never replaced.
     *
     * <p>It can be called from several processes at once: the generation happens under the file
     * lock, and whoever arrives second finds the first one's password, instead of overwriting it with its own
     * that was never set in MySQL.
     */
    public static synchronized String ensureMysqlRootPassword() {
        return ensureGenerated(MYSQL_ROOT_PASSWORD, () -> newPassword(28));
    }

    /**
     * The password of the webmail's MySQL user, generating it if it is not there yet. Like the root
     * one it is generated once only and then reread: the installation scripts and the
     * boot migration use it, and they must give MySQL and config.inc.php the same secret. Only
     * letters and digits, because it ends up in the db_dsnw URL.
     */
    public static synchronized String ensureRoundcubeDbPassword() {
        return ensureGenerated(ROUNDCUBE_DB_PASSWORD, () -> newAlphanumericPassword(24));
    }

    /**
     * The password of one of the Postfix and Dovecot MySQL users (MailDbUsers), generating it if it is not there yet:
     * 32 letters and digits, because it ends up in the Postfix maps and in Dovecot's connect line, where a space,
     * a quote or a hash sign would change the meaning of the line.
     */
    public static synchronized String ensureServiceDbPassword(String name) {
        if (!POSTFIX_DB_PASSWORD.equals(name) && !DOVECOT_DB_PASSWORD.equals(name))
            throw new IllegalArgumentException("not a mail service password: " + name);
        return ensureGenerated(name, () -> newAlphanumericPassword(32));
    }

    /**
     * The secret if it is there; otherwise it generates it under the file lock, and whoever arrives second finds the
     * first one.
     */
    private static synchronized String ensureGenerated(String name, java.util.function.Supplier<String> generator) {
        String v = get(name);
        if (!v.isEmpty()) return v;
        return storeFor(name).update(p -> {
            if (!p.getProperty(name, "").isEmpty()) return null;   // someone else just wrote it
            p.setProperty(name, generator.get());
            return p;
        }).getProperty(name, "");
    }

    /**
     * The webmail key in base64url without '=': it has to be written into the Roundcube configuration
     * (readable only by www), which sends it in the X-DaemoxCP-Key header.
     */
    public static String webmailKey() {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(key(WEBMAIL_KEY));
    }

    /** At startup: all the keys exist before another process can use them. */
    public static void ensureKeys() {
        key(DATA_KEY);
        key(INDEX_KEY);
        key(CODE_KEY);
        key(WEBMAIL_KEY);
    }
}
