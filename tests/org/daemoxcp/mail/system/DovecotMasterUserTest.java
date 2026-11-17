package org.daemoxcp.mail.system;

import org.daemoxcp.mail.integration.RoundcubeSsoManager;
import org.daemoxcp.mail.scripts.DovecotScript;
import org.daemoxcp.mail.scripts.FullMailServerScript;
import org.daemoxcp.mail.scripts.FullMailStackScript;
import org.daemoxcp.mail.util.Shell;
import org.mindrot.jbcrypt.BCrypt;

import java.io.PrintStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Dovecot's master user for «Open webmail» (DovecotMasterUser): the repair at start and the piece of the installation
 * scripts.
 *
 * <p>The repair runs on real files, with real owners, groups and modes, in a temporary folder; Dovecot is fake but
 * reads master-users like the real one: as the user dovecot (a root:wheel 640 file it does not open), one line
 * "admin:{BLF-CRYPT}hash", the key compared with bcrypt. Every step that can go wrong has a planted fault, and after a
 * rollback the file must be as it was: content, owner, group and mode, compared with a snapshot.
 *
 * <p>The shell piece really runs, with the real doveadm, in a temporary folder: also in the installation's condition,
 * that is with a doveadm that cannot find the configuration. There the piece of before (main's) must leave "admin:"
 * without a hash, or the test does not see the fault.
 *
 * <p>It touches real owners and needs doveadm: run it as root on the FreeBSD VM with the mail panel installed (group
 * dovecot).
 *   java -cp "tests:&lt;dir&gt;/daemoxcp-mail.jar" org.daemoxcp.mail.system.DovecotMasterUserTest
 */
public class DovecotMasterUserTest {

    static int failed = 0;
    static final PrintStream OUT = System.out;

    static void check(String what, boolean ok) {
        OUT.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static final String KEY = "Q7rTz2KpLm9WxV4cN8bHs3Fd";
    static final String OTHER_KEY = "AAAAbbbbCCCCddddEEEEffff";
    static final String BOX = "alice@probe.test";
    static final String DOVEADM = "/usr/local/bin/doveadm";

    /** FullMailServerScript's piece on main, before this version: to see the fault. */
    static String oldFragment(String key, String users) {
        return """
            MASTER_PASSWORD=$(openssl rand -base64 24 | tr -d '/+=' | head -c 24)
            mkdir -p "$(dirname '__KEY__')"
            echo "$MASTER_PASSWORD" > '__KEY__'
            chmod 600 '__KEY__'

            if command -v doveadm >/dev/null 2>&1; then
                MASTER_PASSWORD_HASH=$(doveadm pw -s BLF-CRYPT -p "$MASTER_PASSWORD" 2>/dev/null)
            else
                MASTER_PASSWORD_HASH='{PLAIN}'$MASTER_PASSWORD
            fi

            cat > '__USERS__' << MASTER_EOF
            admin:$MASTER_PASSWORD_HASH
            MASTER_EOF

            chmod 640 '__USERS__'
            chown root:dovecot '__USERS__'
            """.replace("__KEY__", key).replace("__USERS__", users);
    }

    // ===================== the fake Dovecot =====================

    static final class FakeDovecot implements DovecotMasterUser.Services {
        final Path masterUsers;
        List<DovecotMasterUser.Mailbox> boxes = new ArrayList<>(List.of(new DovecotMasterUser.Mailbox(7, BOX)));
        boolean answering = true, listFails = false, rejectMaster = false, pwRefuses = false;
        int calls = 0, authTests = 0, verifies = 0;

        FakeDovecot(Path masterUsers) { this.masterUsers = masterUsers; }

        @Override public DovecotMasterUser.Mailbox testMailbox() throws Exception {
            calls++;
            if (listFails) throw new java.sql.SQLException("Communications link failure");
            return boxes.isEmpty() ? null : boxes.get(0);
        }
        @Override public Shell.Result lookup(String email) {
            calls++;
            boolean ok = answering && boxes.stream().anyMatch(b -> b.email().equals(email));
            return new Shell.Result(ok ? 0 : (answering ? 67 : 75),
                    ok ? "field\tvalue\nuid\t5000\n" : "Error: auth-master: connect(/var/run/dovecot/auth-userdb) failed", false, List.of());
        }
        /** Like Dovecot's auth process, which runs as dovecot: it opens the file only if dovecot can. */
        @Override public Shell.Result authTest(String login, String password) {
            calls++; authTests++;
            if (!answering) return new Shell.Result(75, "Fatal: Couldn't connect to auth socket", false, List.of());
            String[] p = login.split("\\*", -1);
            boolean known = p.length == 2 && p[1].equals(DovecotMasterUser.USER)
                    && boxes.stream().anyMatch(b -> b.email().equals(p[0]));
            if (!known || rejectMaster || !readableByDovecot(masterUsers))
                return new Shell.Result(77, "passdb: " + login + " auth failed\nextra fields:\n  user=admin\n", false, List.of());
            String content;
            try { content = Files.readString(masterUsers, StandardCharsets.US_ASCII); } catch (Exception e) { content = ""; }
            String prefix = DovecotMasterUser.USER + ":";
            String line = content.endsWith("\n") ? content.substring(0, content.length() - 1) : content;
            boolean ok = line.startsWith(prefix) && !line.contains("\n")
                    && DovecotMasterUser.matches(password, line.substring(prefix.length()));
            return ok ? new Shell.Result(0, "passdb: " + login + " auth succeeded\nextra fields:\n  user=" + p[0] + "\n", false, List.of())
                      : new Shell.Result(77, "passdb: " + login + " auth failed\nextra fields:\n  user=admin\n", false, List.of());
        }
        @Override public Shell.Result verifyHash(String hash, String password) {
            calls++; verifies++;
            if (pwRefuses || !DovecotMasterUser.matches(password, hash))
                return new Shell.Result(75, "Fatal: reverse password verification check failed: Password mismatch", false, List.of());
            return new Shell.Result(0, hash + " (verified)\n", false, List.of());
        }
    }

    static boolean readableByDovecot(Path p) {
        try {
            PosixFileAttributes a = Files.readAttributes(p, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            Set<PosixFilePermission> m = a.permissions();
            if ("dovecot".equals(a.owner().getName())) return m.contains(PosixFilePermission.OWNER_READ);
            if ("dovecot".equals(a.group().getName())) return m.contains(PosixFilePermission.GROUP_READ);
            return m.contains(PosixFilePermission.OTHERS_READ);
        } catch (Exception e) {
            return false;
        }
    }

    // ===================== the bench =====================

    static final class Bench {
        final Path root, etc, db, masterUsers, key;
        final DovecotMasterUser.Places at;

        Bench() throws Exception {
            root = Files.createTempDirectory(Path.of("/var/tmp"), "dovecot-master-");
            etc = Files.createDirectories(root.resolve("etc"));
            db = Files.createDirectories(root.resolve("db"));
            masterUsers = etc.resolve("master-users");
            key = db.resolve("dovecot_master.key");
            at = new DovecotMasterUser.Places(masterUsers, key);
        }

        void users(String content, String owner, String group, String mode) throws Exception {
            Files.deleteIfExists(masterUsers);
            Files.writeString(masterUsers, content, StandardCharsets.US_ASCII);
            attrs(masterUsers, owner, group, mode);
        }

        void key(String content) throws Exception {
            Files.deleteIfExists(key);
            Files.writeString(key, content, StandardCharsets.US_ASCII);
            attrs(key, "root", "wheel", "rw-------");
        }

        /** Everything in the two folders: no temporary file may be left. */
        List<String> files() throws Exception {
            List<String> out = new ArrayList<>();
            for (Path d : List.of(etc, db))
                try (Stream<Path> s = Files.list(d)) { s.forEach(p -> out.add(root.relativize(p).toString())); }
            out.sort(null);
            return out;
        }

        void close() throws Exception {
            try (Stream<Path> s = Files.walk(root)) {
                for (Path p : s.sorted(java.util.Comparator.reverseOrder()).toList()) Files.deleteIfExists(p);
            }
        }
    }

    static void attrs(Path p, String owner, String group, String mode) throws Exception {
        UserPrincipalLookupService names = p.getFileSystem().getUserPrincipalLookupService();
        PosixFileAttributeView v = Files.getFileAttributeView(p, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        v.setOwner(names.lookupPrincipalByName(owner));
        v.setGroup(names.lookupPrincipalByGroupName(group));
        v.setPermissions(PosixFilePermissions.fromString(mode));
    }

    /** Content, owner, group and mode: the snapshot of a file. */
    static String photo(Path p) throws Exception {
        if (!Files.exists(p, LinkOption.NOFOLLOW_LINKS)) return "(missing)";
        PosixFileAttributes a = Files.readAttributes(p, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        String body = a.isSymbolicLink() ? "-> " + Files.readSymbolicLink(p)
                : HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(p)));
        return a.owner().getName() + ":" + a.group().getName() + " " + PosixFilePermissions.toString(a.permissions()) + " " + body;
    }

    static String bcrypt(String key, int cost) { return "{BLF-CRYPT}" + BCrypt.hashpw(key, BCrypt.gensalt(cost)); }

    /** No log message carries the key or the mailbox's address. */
    static void noSecrets(String what, DovecotMasterUser.Report r) {
        check(what + ": neither the key nor the address in the message",
                !r.detail().contains(KEY) && !r.detail().contains(BOX) && !r.detail().contains("\n"));
    }

    // ===================== the repair =====================

    static void repairCases() throws Exception {
        OUT.println("== the line without a hash, as FullMailServerScript left it");
        for (String content : List.of("admin:\n", "admin:")) {
            Bench b = new Bench();
            b.users(content, "root", "dovecot", "rw-r-----");
            b.key(KEY + "\n");
            FakeDovecot d = new FakeDovecot(b.masterUsers);
            check("[" + content.replace("\n", "\\n") + "] before, the fake Dovecot refuses the master user (it sees the fault)",
                    !d.authTest(BOX + "*admin", KEY).success());
            d.authTests = 0; d.calls = 0;
            DovecotMasterUser.Report r = DovecotMasterUser.repair(b.at, d);
            check("DONE (" + r + ")", r.outcome() == DovecotMasterUser.Outcome.DONE);
            String after = Files.readString(b.masterUsers, StandardCharsets.US_ASCII);
            check("one line admin:{BLF-CRYPT}$2a$12$...", Pattern.matches("admin:\\{BLF-CRYPT\\}\\$2a\\$12\\$[./A-Za-z0-9]{53}\\n", after));
            check("the hash is the key's", DovecotMasterUser.matches(KEY, after.substring(6).trim()));
            check("and not another key's", !DovecotMasterUser.matches(OTHER_KEY, after.substring(6).trim()));
            check("root:dovecot rw-r-----", photo(b.masterUsers).startsWith("root:dovecot rw-r----- "));
            check("verified with a real master login (auth test called once)", d.authTests == 1);
            check("the message names the mailbox by its number", r.detail().contains("mailbox #7*admin"));
            noSecrets("DONE", r);
            check("no temporary file", b.files().equals(List.of("db/dovecot_master.key", "etc/master-users")));
            check("the key was not touched", Files.readString(b.key).equals(KEY + "\n"));
            String once = photo(b.masterUsers);
            d.calls = 0;
            DovecotMasterUser.Report again = DovecotMasterUser.repair(b.at, d);
            check("the second time NOTHING (" + again + ")", again.outcome() == DovecotMasterUser.Outcome.NOTHING);
            check("the second time it asks Dovecot nothing", d.calls == 0);
            check("the second time the file is identical", photo(b.masterUsers).equals(once));
            b.close();
        }

        OUT.println("== faults before changing: nothing changes");
        {
            Bench b = new Bench();
            b.users("admin:\n", "root", "dovecot", "rw-r-----"); b.key(KEY + "\n");
            String before = photo(b.masterUsers);
            FakeDovecot d = new FakeDovecot(b.masterUsers); d.answering = false;
            DovecotMasterUser.Report r = DovecotMasterUser.repair(b.at, d);
            check("Dovecot off: NOT_ANSWERING (" + r + ")", r.outcome() == DovecotMasterUser.Outcome.NOT_ANSWERING);
            check("Dovecot off: file identical", photo(b.masterUsers).equals(before));
            check("Dovecot off: no auth test", d.authTests == 0);
            noSecrets("NOT_ANSWERING", r);

            d = new FakeDovecot(b.masterUsers); d.listFails = true;
            r = DovecotMasterUser.repair(b.at, d);
            check("the mailboxes' database does not answer: NOT_ANSWERING (" + r + ")", r.outcome() == DovecotMasterUser.Outcome.NOT_ANSWERING);
            check("the mailboxes' database does not answer: file identical", photo(b.masterUsers).equals(before));
            b.close();
        }

        OUT.println("== faults after writing: the file goes back as it was");
        {
            Bench b = new Bench();
            b.users("admin:\n", "root", "dovecot", "rw-r-----"); b.key(KEY + "\n");
            String before = photo(b.masterUsers);
            FakeDovecot d = new FakeDovecot(b.masterUsers); d.rejectMaster = true;
            DovecotMasterUser.Report r = DovecotMasterUser.repair(b.at, d);
            check("the master user does not get in: ROLLED_BACK (" + r + ")", r.outcome() == DovecotMasterUser.Outcome.ROLLED_BACK);
            check("the master user does not get in: file identical, owner and mode included", photo(b.masterUsers).equals(before));
            check("the master user does not get in: no temporary file", b.files().equals(List.of("db/dovecot_master.key", "etc/master-users")));
            check("the master user does not get in: the message says so", r.detail().contains("auth test") && r.detail().contains("put back"));
            noSecrets("ROLLED_BACK", r);
            d.rejectMaster = false;
            r = DovecotMasterUser.repair(b.at, d);
            check("fault removed, at the next start DONE (" + r + ")", r.outcome() == DovecotMasterUser.Outcome.DONE);
            b.close();

            // The rollback also puts back an owner and mode other than the right ones.
            b = new Bench();
            b.users("admin:\n", "root", "wheel", "rw-r--r--"); b.key(KEY + "\n");
            before = photo(b.masterUsers);
            d = new FakeDovecot(b.masterUsers); d.rejectMaster = true;
            r = DovecotMasterUser.repair(b.at, d);
            check("root:wheel 644 without a hash, does not get in: ROLLED_BACK", r.outcome() == DovecotMasterUser.Outcome.ROLLED_BACK);
            check("root:wheel 644 without a hash, does not get in: back to root:wheel 644", photo(b.masterUsers).equals(before));
            b.close();
        }

        OUT.println("== without mailboxes: doveadm pw -t checks the hash");
        {
            Bench b = new Bench();
            b.users("admin:\n", "root", "dovecot", "rw-r-----"); b.key(KEY + "\n");
            String before = photo(b.masterUsers);
            FakeDovecot d = new FakeDovecot(b.masterUsers); d.boxes.clear(); d.pwRefuses = true;
            DovecotMasterUser.Report r = DovecotMasterUser.repair(b.at, d);
            check("pw -t refuses: ROLLED_BACK (" + r + ")", r.outcome() == DovecotMasterUser.Outcome.ROLLED_BACK);
            check("pw -t refuses: file identical", photo(b.masterUsers).equals(before));
            d.pwRefuses = false;
            r = DovecotMasterUser.repair(b.at, d);
            check("pw -t accepts: DONE (" + r + ")", r.outcome() == DovecotMasterUser.Outcome.DONE);
            check("pw -t accepts: the message says a real login is missing", r.detail().contains("no active mailbox"));
            check("pw -t accepts: no auth test, one check", d.authTests == 0 && d.verifies == 2);
            check("pw -t accepts: the hash is the key's", DovecotMasterUser.matches(KEY, Files.readString(b.masterUsers).substring(6).trim()));
            b.close();
        }

        OUT.println("== FullMailStackScript's file: the hash is there, but root:wheel");
        {
            Bench b = new Bench();
            // doveadm pw writes $2y$: it must be recognised as the key's
            String h = bcrypt(KEY, 5).replace("$2a$", "$2y$");
            b.users("admin:" + h + "\n", "root", "wheel", "rw-r-----"); b.key(KEY + "\n");
            String content = Files.readString(b.masterUsers);
            FakeDovecot d = new FakeDovecot(b.masterUsers);
            check("before, the fake Dovecot does not open the file (like the real one: Permission denied)", !d.authTest(BOX + "*admin", KEY).success());
            d.authTests = 0;
            DovecotMasterUser.Report r = DovecotMasterUser.repair(b.at, d);
            check("DONE (" + r + ")", r.outcome() == DovecotMasterUser.Outcome.DONE);
            check("root:dovecot rw-r-----", photo(b.masterUsers).startsWith("root:dovecot rw-r----- "));
            check("content identical", Files.readString(b.masterUsers).equals(content));
            check("the message says how it was", r.detail().contains("root:wheel rw-r-----"));
            check("verified with a real master login", d.authTests == 1);
            d.calls = 0;
            check("the second time NOTHING, asking nothing",
                    DovecotMasterUser.repair(b.at, d).outcome() == DovecotMasterUser.Outcome.NOTHING && d.calls == 0);
            b.close();

            b = new Bench();
            b.users("admin:" + h + "\n", "root", "wheel", "rw-r-----"); b.key(KEY + "\n");
            String before = photo(b.masterUsers);
            d = new FakeDovecot(b.masterUsers); d.rejectMaster = true;
            r = DovecotMasterUser.repair(b.at, d);
            check("root:wheel, still does not get in: ROLLED_BACK (" + r + ")", r.outcome() == DovecotMasterUser.Outcome.ROLLED_BACK);
            check("root:wheel, still does not get in: back to root:wheel, identical", photo(b.masterUsers).equals(before));
            b.close();

            b = new Bench();
            b.users("admin:" + bcrypt(KEY, 5) + "\n", "root", "dovecot", "rw-------"); b.key(KEY + "\n");
            d = new FakeDovecot(b.masterUsers);
            r = DovecotMasterUser.repair(b.at, d);
            check("root:dovecot 600 (dovecot cannot read): DONE, now 640", r.outcome() == DovecotMasterUser.Outcome.DONE
                    && photo(b.masterUsers).startsWith("root:dovecot rw-r----- "));
            b.close();
        }

        OUT.println("== nothing is decided for anybody else");
        {
            String okHash = bcrypt(KEY, 5);
            Map<String, String> notOurs = new LinkedHashMap<>();
            notOurs.put("{PLAIN} written by hand", "admin:{PLAIN}" + KEY + "\n");
            notOurs.put("two users", "admin:\nbackup:" + okHash + "\n");
            notOurs.put("a comment", "# master user\nadmin:\n");
            notOurs.put("admin with the hash and another user", "admin:" + okHash + "\nbob:" + okHash + "\n");
            notOurs.put("other passwd-file fields", "admin:" + okHash + "::::::\n");
            notOurs.put("another name", "root:\n");
            notOurs.put("an extra empty line", "admin:\n\n");
            notOurs.put("not ASCII", "admin:è\n");
            for (Map.Entry<String, String> e : notOurs.entrySet()) {
                Bench b = new Bench();
                Files.write(b.masterUsers, e.getValue().getBytes(StandardCharsets.UTF_8));
                attrs(b.masterUsers, "root", "wheel", "rw-r-----");
                b.key(KEY + "\n");
                String before = photo(b.masterUsers);
                FakeDovecot d = new FakeDovecot(b.masterUsers);
                DovecotMasterUser.Report r = DovecotMasterUser.repair(b.at, d);
                check(e.getKey() + ": NOT_OURS, file identical, no question to Dovecot (" + r.outcome() + ")",
                        r.outcome() == DovecotMasterUser.Outcome.NOT_OURS && photo(b.masterUsers).equals(before) && d.calls == 0);
                noSecrets(e.getKey(), r);
                b.close();
            }

            Bench b = new Bench();
            Path real = b.etc.resolve("elsewhere");
            Files.writeString(real, "admin:\n");
            attrs(real, "root", "dovecot", "rw-r-----");
            Files.createSymbolicLink(b.masterUsers, real);
            b.key(KEY + "\n");
            String target = photo(real);
            DovecotMasterUser.Report r = DovecotMasterUser.repair(b.at, new FakeDovecot(b.masterUsers));
            check("a link: NOT_OURS, the file it points to identical", r.outcome() == DovecotMasterUser.Outcome.NOT_OURS
                    && photo(real).equals(target) && Files.isSymbolicLink(b.masterUsers));
            b.close();

            b = new Bench();
            b.users("admin:" + bcrypt(OTHER_KEY, 5) + "\n", "root", "wheel", "rw-r-----"); b.key(KEY + "\n");
            String before = photo(b.masterUsers);
            FakeDovecot d = new FakeDovecot(b.masterUsers);
            r = DovecotMasterUser.repair(b.at, d);
            check("another key's hash: MISMATCH (" + r + ")", r.outcome() == DovecotMasterUser.Outcome.MISMATCH);
            check("another key's hash: file identical, root:wheel too", photo(b.masterUsers).equals(before) && d.calls == 0);
            noSecrets("MISMATCH", r);

            Map<String, String> badKeys = new LinkedHashMap<>();
            badKeys.put("empty key", "\n");
            badKeys.put("key with a space inside", "abcd efgh ijkl\n");
            badKeys.put("key too long for bcrypt", "x".repeat(73) + "\n");
            badKeys.put("key too short", "abc\n");
            for (Map.Entry<String, String> e : badKeys.entrySet()) {
                b.users("admin:\n", "root", "dovecot", "rw-r-----"); b.key(e.getValue());
                before = photo(b.masterUsers);
                d = new FakeDovecot(b.masterUsers);
                r = DovecotMasterUser.repair(b.at, d);
                check(e.getKey() + ": NO_KEY, file identical (" + r.outcome() + ")",
                        r.outcome() == DovecotMasterUser.Outcome.NO_KEY && photo(b.masterUsers).equals(before) && d.calls == 0);
            }
            b.users("admin:\n", "root", "dovecot", "rw-r-----");
            Files.delete(b.key);
            before = photo(b.masterUsers);
            r = DovecotMasterUser.repair(b.at, new FakeDovecot(b.masterUsers));
            check("no key: NO_KEY, file identical", r.outcome() == DovecotMasterUser.Outcome.NO_KEY && photo(b.masterUsers).equals(before));
            Path realKey = b.db.resolve("real.key");
            Files.writeString(realKey, KEY + "\n");
            Files.createSymbolicLink(b.key, realKey);
            r = DovecotMasterUser.repair(b.at, new FakeDovecot(b.masterUsers));
            check("the key is a link: NO_KEY", r.outcome() == DovecotMasterUser.Outcome.NO_KEY && photo(b.masterUsers).equals(before));
            b.close();

            b = new Bench();
            r = DovecotMasterUser.repair(b.at, new FakeDovecot(b.masterUsers));
            check("no master-users: NOTHING", r.outcome() == DovecotMasterUser.Outcome.NOTHING && !Files.exists(b.masterUsers));
            b.users("admin:" + bcrypt(KEY, 5) + "\n", "root", "dovecot", "rw-r-----"); b.key(KEY + "\n");
            FakeDovecot quiet = new FakeDovecot(b.masterUsers);
            r = DovecotMasterUser.repair(b.at, quiet);
            check("already right: NOTHING, asking nothing", r.outcome() == DovecotMasterUser.Outcome.NOTHING && quiet.calls == 0);
            b.close();
        }
    }

    // ===================== the scripts =====================

    static Shell.Result sh(Path script, Path fakeBin) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("sh", script.toString());
        Shell.applyPath(pb);
        if (fakeBin != null) pb.environment().put("PATH", fakeBin + ":" + Shell.fullPath());
        pb.redirectErrorStream(true);
        pb.redirectInput(ProcessBuilder.Redirect.from(new java.io.File("/dev/null")));
        Process p = pb.start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        return new Shell.Result(p.waitFor(), out, false, pb.command());
    }

    /** A fake doveadm in front of the real one: the text after #!/bin/sh. */
    static Path fakeDoveadm(Bench b, String name, String body) throws Exception {
        Path dir = Files.createDirectories(b.root.resolve("bin-" + name));
        Path f = dir.resolve("doveadm");
        Files.writeString(f, "#!/bin/sh\n" + body + "\n");
        Files.setPosixFilePermissions(f, PosixFilePermissions.fromString("rwx------"));
        return dir;
    }

    static void scriptCases() throws Exception {
        OUT.println("== the names that travel between the panel and the repair");
        Field u = RoundcubeSsoManager.class.getDeclaredField("MASTER_USER"); u.setAccessible(true);
        Field k = RoundcubeSsoManager.class.getDeclaredField("MASTER_PASSWORD_FILE"); k.setAccessible(true);
        check("USER is the SSO's master user", DovecotMasterUser.USER.equals(u.get(null)));
        check("KEY_FILE is the key the SSO reads", DovecotMasterUser.KEY_FILE.equals(k.get(null)));

        OUT.println("== the three scripts");
        Map<String, String> scripts = new LinkedHashMap<>();
        scripts.put("FullMailServerScript", new FullMailServerScript().getScriptContent());
        scripts.put("FullMailStackScript", new FullMailStackScript().getScriptContent());
        scripts.put("DovecotScript", new DovecotScript().getScriptContent());
        String fragment = DovecotMasterUser.shell();
        for (Map.Entry<String, String> e : scripts.entrySet()) {
            String s = e.getValue();
            check(e.getKey() + ": contains the piece, once", s.indexOf(fragment) >= 0 && s.indexOf(fragment) == s.lastIndexOf(fragment));
            // Outside the piece master-users appears only where Dovecot reads it (auth-master.conf.ext,
            // 2.3 and 2.4) or in a comment: nobody writes it, or changes its owner or mode.
            List<String> others = s.replace(fragment, "").lines()
                    .filter(l -> l.contains("master-users"))
                    .filter(l -> !l.trim().startsWith("#") && !l.trim().matches("(args|passwd_file_path)\\s*=\\s*" + Pattern.quote(DovecotMasterUser.MASTER_USERS)))
                    .toList();
            check(e.getKey() + ": nobody else writes master-users" + (others.isEmpty() ? "" : " " + others), others.isEmpty());
            check(e.getKey() + ": no password among doveadm's arguments, no {PLAIN}",
                    !s.contains("doveadm pw -s BLF-CRYPT -p") && !s.contains("{PLAIN}"));
            check(e.getKey() + ": no root:wheel for master-users", !s.contains("chown root:wheel /usr/local/etc/dovecot/master-users"));
            Path f = Files.createTempFile(Path.of("/var/tmp"), "dovecot-master-script-", ".sh");
            Files.writeString(f, s);
            Shell.Result n = Shell.run(java.time.Duration.ofSeconds(20), "sh", "-n", f.toString());
            check(e.getKey() + ": sh -n accepts it" + (n.success() ? "" : " (" + n.outputTrim() + ")"), n.success());
            Files.delete(f);
        }
        check("the piece uses doveadm -O and standard input, and checks with pw -t",
                fragment.contains("doveadm -O pw -s BLF-CRYPT 2>/dev/null") && fragment.contains("doveadm -O pw -t")
                        && !fragment.contains("-p \"$MASTER_PASSWORD\""));

        if (!Files.isExecutable(Path.of(DOVEADM))) {
            OUT.println("  SKIPPED the piece run: " + DOVEADM + " is not there (run it on the VM)");
            failed++;
            return;
        }

        OUT.println("== the piece run with the real doveadm");
        {
            Bench b = new Bench();
            Path run = b.root.resolve("fragment.sh");
            Files.writeString(run, DovecotMasterUser.shell(b.key.toString(), b.masterUsers.toString()));
            Shell.Result r = sh(run, null);
            check("exits 0 without [ERROR] (" + r.outputTrim() + ")", r.success() && !r.output().contains("[ERROR]"));
            checkFragmentResult(b, "real doveadm");
            b.close();
        }

        OUT.println("== as at installation: doveadm cannot find the configuration");
        {
            Bench b = new Bench();
            Path bin = fakeDoveadm(b, "noconf", "exec " + DOVEADM + " -c /nonexistent/dovecot.conf \"$@\"");
            Shell.Result probe = Shell.run(java.time.Duration.ofSeconds(20), bin.resolve("doveadm").toString(), "pw", "-s", "BLF-CRYPT", "-p", "x");
            check("without -O this doveadm exits with 75, as at installation (" + probe.exitCode() + ")", probe.exitCode() == 75);
            Path oldRun = b.root.resolve("old.sh");
            Files.writeString(oldRun, oldFragment(b.key.toString(), b.masterUsers.toString()));
            sh(oldRun, bin);
            String oldResult = Files.readString(b.masterUsers);
            check("the piece of before leaves 'admin:' without a hash (the test sees the fault)", oldResult.equals("admin:\n"));

            // What the piece of before left, the repair fixes: the real bytes, not a string written here.
            FakeDovecot d = new FakeDovecot(b.masterUsers);
            DovecotMasterUser.Report rep = DovecotMasterUser.repair(b.at, d);
            check("and the repair at start fixes it (" + rep.outcome() + ")", rep.outcome() == DovecotMasterUser.Outcome.DONE
                    && DovecotMasterUser.matches(Files.readString(b.key).trim(), Files.readString(b.masterUsers).substring(6).trim()));

            Path run = b.root.resolve("fragment.sh");
            Files.writeString(run, DovecotMasterUser.shell(b.key.toString(), b.masterUsers.toString()));
            Shell.Result r = sh(run, bin);
            check("the new piece exits 0 without [ERROR] (" + r.outputTrim() + ")", r.success() && !r.output().contains("[ERROR]"));
            checkFragmentResult(b, "without configuration");
            b.close();
        }

        OUT.println("== doveadm faults: no wrong hash, and the error is said");
        Map<String, String> faults = new LinkedHashMap<>();
        faults.put("doveadm exits with 75", "echo 'Fatal: Error reading configuration' >&2; exit 75");
        faults.put("doveadm prints an error with 0", "echo 'Error: something'; exit 0");
        faults.put("pw -s gives the empty password's hash (the two lines that do not match)",
                "case \"$*\" in *' -s '*) printf '\\n\\n' | " + DOVEADM + " -O pw -s BLF-CRYPT ;; *) exec " + DOVEADM + " \"$@\" ;; esac");
        faults.put("pw -s gives another password's hash",
                "case \"$*\" in *' -s '*) printf 'other\\nother\\n' | " + DOVEADM + " -O pw -s BLF-CRYPT ;; *) exec " + DOVEADM + " \"$@\" ;; esac");
        for (Map.Entry<String, String> e : faults.entrySet()) {
            Bench b = new Bench();
            Path bin = fakeDoveadm(b, "fault", e.getValue());
            Path run = b.root.resolve("fragment.sh");
            Files.writeString(run, DovecotMasterUser.shell(b.key.toString(), b.masterUsers.toString()));
            Shell.Result r = sh(run, bin);
            check(e.getKey() + ": [ERROR] in the output", r.output().contains("[ERROR]"));
            check(e.getKey() + ": master-users 'admin:' without a hash, root:dovecot 640",
                    Files.readString(b.masterUsers).equals("admin:\n") && photo(b.masterUsers).startsWith("root:dovecot rw-r----- "));
            check(e.getKey() + ": the key is there all the same (the repair at start needs it)",
                    Pattern.matches("[A-Za-z0-9]{24}\\n", Files.readString(b.key)));
            b.close();
        }
    }

    static void checkFragmentResult(Bench b, String what) throws Exception {
        String key = Files.readString(b.key);
        check(what + ": key of 24 letters and digits, root 600", Pattern.matches("[A-Za-z0-9]{24}\\n", key)
                && photo(b.key).startsWith("root:wheel rw------- "));
        String users = Files.readString(b.masterUsers);
        check(what + ": master-users one line admin:{BLF-CRYPT}$2y$ (" + users.length() + " bytes)",
                Pattern.matches("admin:\\{BLF-CRYPT\\}\\$2y\\$[0-9]{2}\\$[./A-Za-z0-9]{53}\\n", users));
        check(what + ": the hash is the key's", DovecotMasterUser.matches(key.trim(), users.substring(6).trim()));
        check(what + ": master-users root:dovecot 640", photo(b.masterUsers).startsWith("root:dovecot rw-r----- "));
        check(what + ": no .new left", b.files().equals(List.of("db/dovecot_master.key", "etc/master-users")));
        // And the repair at start recognises it as already right.
        FakeDovecot d = new FakeDovecot(b.masterUsers);
        check(what + ": the repair at start does nothing", DovecotMasterUser.repair(b.at, d).outcome()
                == DovecotMasterUser.Outcome.NOTHING && d.calls == 0);
    }

    public static void main(String[] args) throws Exception {
        repairCases();
        scriptCases();
        OUT.println(failed == 0 ? "ALL OK" : failed + " FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
