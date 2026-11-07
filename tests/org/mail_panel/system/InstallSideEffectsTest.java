package org.mail_panel.system;

import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * The mechanism that compares the configuration and the listening addresses before and after an
 * update, tested on its own: on a temporary folder, with the real output of {@code sockstat} and of
 * {@code pkg query} taken on the FreeBSD 15.1 VM on 24/10/2026.
 *
 * This test says the comparison tells the right things apart. That the three jobs really use it is
 * said by {@link InstallScriptDriftTest}, which runs the real jobs and fails with the jar without
 * the fix.
 *
 * Both directions, as for the fallen services: every real fault must raise the alarm, and what pkg
 * does by trade (replacing its own files, putting the new default in place of one never touched)
 * must not. An alarm that rings at every update teaches people to ignore it.
 */
public class InstallSideEffectsTest {

    private static int failures = 0;

    public static void main(String[] args) throws Exception {
        configuration();
        etc();
        sasl();
        savedCopies();
        lines();
        owners();
        listening();
        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        if (failures > 0) System.exit(1);
    }

    // ===== the configuration, on a real folder =====
    private static void configuration() throws Exception {
        Path d = Files.createTempDirectory("side-effects");
        try {
            Path etc = Files.createDirectories(d.resolve("etc/postfix"));
            Path other = Files.createDirectories(d.resolve("etc/other"));
            // An administrator's main.cf: different from its sample, owned by no package.
            write(etc.resolve("main.cf"), "myhostname = mx.example.org\ninet_interfaces = all\n", "rw-r--r--");
            write(etc.resolve("main.cf.sample"), "# example\n", "rw-r--r--");
            write(etc.resolve("master.cf"), "smtp      inet  n       -       n       -       -       smtpd\n", "rw-r--r--");
            // A MySQL map: password inside, readable only by root and the group.
            write(etc.resolve("mysql-virtual.cf"), "user = postfix\npassword = old-secret\nhosts = 127.0.0.1\n", "rw-r-----");
            // A file of the package: pkg replaces it, it is the update itself.
            write(etc.resolve("main.cf.default"), "compatibility_level = 3.6\n", "rw-r--r--");
            // The default never touched: identical to its sample.
            write(other.resolve("other.conf"), "port = 1\n", "rw-r--r--");
            write(other.resolve("other.conf.sample"), "port = 1\n", "rw-r--r--");
            write(etc.resolve("old.cf"), "x = 1\n", "rw-r--r--");
            write(etc.resolve("perms.cf"), "y = 2\n", "rw-------");
            write(etc.resolve("order.cf"), "a = 1\nb = 2\n", "rw-r--r--");
            write(etc.resolve("untouched.cf"), "z = 3\n", "rw-r--r--");
            write(etc.resolve("comments-perms.cf"), "w = 4\n", "rw-r-----");
            // A file of ANOTHER package, which the job did not touch.
            write(other.resolve("dovecot-owned.conf"), "protocols = imap\n", "rw-r--r--");

            Map<String, String> owners = new TreeMap<>();
            owners.put(etc.resolve("main.cf.sample").toString(), "postfix-mysql");
            owners.put(etc.resolve("main.cf.default").toString(), "postfix-mysql");
            owners.put(other.resolve("other.conf.sample").toString(), "other");
            owners.put(other.resolve("dovecot-owned.conf").toString(), "dovecot");
            Set<String> changed = Set.of("postfix-mysql", "other");

            InstallSideEffects.ConfigSnapshot before =
                    InstallSideEffects.configSnapshot(List.of(d.resolve("etc")), List.of(), owners);

            // Reperto 42: the script adds a line to main.cf.
            append(etc.resolve("main.cf"), "inet_protocols = ipv4\n");
            // And four commented entries to master.cf.
            append(etc.resolve("master.cf"), "#postscreen inet  n       -       n       -       1       postscreen\n#tlsproxy  unix  -       -       n       -       0       tlsproxy\n");
            write(etc.resolve("mysql-virtual.cf"), "user = postfix\npassword = new-secret\nhosts = 127.0.0.1\n", "rw-r-----");
            write(etc.resolve("main.cf.default"), "compatibility_level = 3.11\n", "rw-r--r--");
            write(other.resolve("other.conf"), "port = 2\n", "rw-r--r--");
            write(other.resolve("other.conf.sample"), "port = 2\n", "rw-r--r--");
            write(etc.resolve("created.cf"), "fresh = 1\n", "rw-r--r--");
            Files.delete(etc.resolve("old.cf"));
            Files.setPosixFilePermissions(etc.resolve("perms.cf"), PosixFilePermissions.fromString("rw-r--r--"));
            write(etc.resolve("order.cf"), "b = 2\na = 1\n", "rw-r--r--");
            write(other.resolve("dovecot-owned.conf"), "protocols = imap pop3\n", "rw-r--r--");
            write(etc.resolve("comments-perms.cf"), "w = 4\n# new comment\n", "rw-rw-rw-");

            InstallSideEffects.ConfigSnapshot after =
                    InstallSideEffects.configSnapshot(List.of(d.resolve("etc")), List.of(), owners);
            JSONArray c = InstallSideEffects.configChanges(before, after, changed);

            JSONObject mainCf = find(c, etc.resolve("main.cf"));
            check("main.cf changed by a script: alarm", mainCf != null && mainCf.getBoolean("alarm")
                    && "script".equals(mainCf.getString("kind")) && "changed".equals(mainCf.getString("happened")));
            check("  and the added line shows", mainCf != null && mainCf.optJSONArray("addedLines") != null
                    && mainCf.getJSONArray("addedLines").toList().contains("inet_protocols = ipv4"));
            check("  and no line removed", mainCf != null && mainCf.optInt("removedCount", -1) == 0);

            JSONObject master = find(c, etc.resolve("master.cf"));
            check("master.cf with comment lines only: said, but without an alarm", master != null
                    && "commentsOnly".equals(master.getString("kind")) && !master.getBoolean("alarm"));
            check("  and the lines show all the same", master != null && master.optInt("addedCount") == 2);

            JSONObject secret = find(c, etc.resolve("mysql-virtual.cf"));
            check("a map with the password changed: alarm", secret != null && secret.getBoolean("alarm"));
            check("  but the content is not shown", secret != null && "notWorldReadable".equals(secret.optString("hidden"))
                    && !secret.has("addedLines") && !secret.has("removedLines"));
            check("  and neither password shows up anywhere",
                    !c.toString().contains("old-secret") && !c.toString().contains("new-secret"));

            JSONObject packageFile = find(c, etc.resolve("main.cf.default"));
            check("a package file updated: it is the update, no alarm",
                    packageFile != null && "package".equals(packageFile.getString("kind")) && !packageFile.getBoolean("alarm"));

            JSONObject newDefault = find(c, other.resolve("other.conf"));
            check("the default never touched, now the new default: no alarm",
                    newDefault != null && "newDefault".equals(newDefault.getString("kind")) && !newDefault.getBoolean("alarm"));

            JSONObject created = find(c, etc.resolve("created.cf"));
            check("a created file that belongs to nobody: alarm", created != null && created.getBoolean("alarm")
                    && "created".equals(created.getString("happened")));
            JSONObject removed = find(c, etc.resolve("old.cf"));
            check("a configuration file removed: alarm", removed != null && removed.getBoolean("alarm")
                    && "removed".equals(removed.getString("happened")));
            JSONObject perms = find(c, etc.resolve("perms.cf"));
            check("same content, permissions changed: alarm, with before and after", perms != null
                    && perms.getBoolean("alarm") && "permissions".equals(perms.getString("happened"))
                    && perms.optString("permissionsFrom").startsWith("rw-------")
                    && perms.optString("permissionsTo").startsWith("rw-r--r--"));
            JSONObject order = find(c, etc.resolve("order.cf"));
            check("same lines in another order: alarm, and it says so", order != null && order.getBoolean("alarm")
                    && "sameLines".equals(order.optString("hidden")));
            JSONObject foreign = find(c, other.resolve("dovecot-owned.conf"));
            check("a file of a package the job did NOT change: alarm", foreign != null
                    && foreign.getBoolean("alarm") && "dovecot".equals(foreign.getString("owner")));
            JSONObject commentsPerms = find(c, etc.resolve("comments-perms.cf"));
            check("comments only, but with the permissions changed: alarm", commentsPerms != null
                    && commentsPerms.getBoolean("alarm") && "script".equals(commentsPerms.getString("kind")));
            check("an untouched file does not show up", find(c, etc.resolve("untouched.cf")) == null);
            check("and neither does the package's .sample, which is its own", find(c, etc.resolve("main.cf.sample")) == null);

            // --- and no change: nothing to say ---
            InstallSideEffects.ConfigSnapshot again =
                    InstallSideEffects.configSnapshot(List.of(d.resolve("etc")), List.of(), owners);
            check("two identical pictures: no change",
                    InstallSideEffects.configChanges(after, again, changed).isEmpty());

            // --- the panel's folder is not looked at ---
            check("the panel's folder is excluded", InstallSideEffects.excluded("/usr/local/etc/mail-panel/firewall.json"));
            check("  but only it, not a name that resembles it", !InstallSideEffects.excluded("/usr/local/etc/mail-panel2/x"));
        } finally {
            try (var s = Files.walk(d)) {
                s.sorted(java.util.Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }

    // ===== /etc: users, regenerated files, resolv.conf =====
    // Pictures built by hand with the real /etc paths: the rules depend on the path, and on a
    // temporary folder there is no /etc/passwd.
    private static void etc() {
        Map<String, InstallSideEffects.FileState> b = new TreeMap<>(), a = new TreeMap<>();
        String pw = "root:*:0:0:Charlie &:/root:/bin/sh\npostfix:*:125:125:Postfix:/var/spool/postfix:/usr/sbin/nologin\n";
        put(b, "/etc/passwd", pw, true);
        put(a, "/etc/passwd", pw + "driftprobe:*:1001:1001:drift probe:/nonexistent:/usr/sbin/nologin\n", true);
        put(b, "/etc/master.passwd", "root:$6$x:0:0::0:0:Charlie &:/root:/bin/sh\n", false);
        put(a, "/etc/master.passwd", "root:$6$x:0:0::0:0:Charlie &:/root:/bin/sh\ndriftprobe:*:1001:1001::0:0:drift probe:/nonexistent:/usr/sbin/nologin\n", false);
        put(b, "/etc/group", "wheel:*:0:root\n", true);
        put(a, "/etc/group", "wheel:*:0:root,driftprobe\n", true);       // an existing user touched
        put(b, "/etc/pwd.db", "\u0000one", true);   put(a, "/etc/pwd.db", "\u0000two", true);
        put(b, "/etc/aliases", "root: admin\n", true); put(a, "/etc/aliases", "root: admin\n", true);
        put(b, "/etc/aliases.db", "\u0000a", true);  put(a, "/etc/aliases.db", "\u0000b", true);
        put(b, "/etc/ssl/certs/0179095f.0", "certA", true); put(a, "/etc/ssl/certs/0179095f.0", "certB", true);
        put(b, "/etc/orphan.db", "\u0000a", true);   put(a, "/etc/orphan.db", "\u0000b", true);
        put(a, "/etc/periodic.conf", "daily_x_enable=\"YES\"\n", true);
        JSONArray c = InstallSideEffects.configChanges(new InstallSideEffects.ConfigSnapshot(b, Map.of()),
                new InstallSideEffects.ConfigSnapshot(a, Map.of()), Set.of());
        JSONObject passwd = find(c, "/etc/passwd"), master = find(c, "/etc/master.passwd"), group = find(c, "/etc/group");
        check("/etc/passwd with a user added: said, without an alarm", passwd != null
                && "accounts".equals(passwd.getString("kind")) && !passwd.getBoolean("alarm")
                && passwd.getJSONArray("addedLines").toList().toString().contains("driftprobe"));
        check("/etc/master.passwd the same, but without showing it", master != null && "accounts".equals(master.getString("kind"))
                && "notWorldReadable".equals(master.optString("hidden")) && !c.toString().contains("$6$x"));
        check("/etc/group with an existing user touched: alarm", group != null && group.getBoolean("alarm"));
        check("/etc/pwd.db, derived from master.passwd: no alarm", "derived".equals(kindOf(c, "/etc/pwd.db")));
        check("/etc/aliases.db next to aliases: no alarm", "derived".equals(kindOf(c, "/etc/aliases.db")));
        check("the certificates regenerated by certctl: no alarm", "derived".equals(kindOf(c, "/etc/ssl/certs/0179095f.0")));
        check("a .db without its source: alarm", "script".equals(kindOf(c, "/etc/orphan.db")));
        check("/etc/periodic.conf created: alarm", "script".equals(kindOf(c, "/etc/periodic.conf")));
        check("all of /etc and the loader are among the roots", InstallSideEffects.CONFIG_ROOTS.contains("/etc")
                && InstallSideEffects.CONFIG_ROOTS.contains("/boot/loader.conf"));
        check("/etc/resolv.conf not: dhclient rewrites it", InstallSideEffects.excluded("/etc/resolv.conf")
                && !InstallSideEffects.excluded("/etc/resolv.conf.d/x") && !InstallSideEffects.excluded("/etc/rc.conf"));
    }

    // ===== sasldb2.db: the users are compared, not the bytes =====
    // With real databases, made by saslpasswd2 as the cyrus-sasl script makes them: it creates the
    // cyrus user and removes it. It needs cyrus-sasl, so it runs only where that is installed.
    private static void sasl() throws Exception {
        if (org.mail_panel.util.Shell.runShell(java.time.Duration.ofSeconds(10), "command -v saslpasswd2").exitCode() != 0) {
            System.out.println("  --   SKIPPED: sasldb2.db, saslpasswd2 (cyrus-sasl) is not here: it runs on the VM");
            return;
        }
        Path d = Files.createTempDirectory("sasl");
        try {
            // saslpasswd2 adds ".db" to the name it is given.
            byte[] empty1 = emptySasldb(d.resolve("one")), empty2 = emptySasldb(d.resolve("two"));
            org.mail_panel.util.Shell.runShell(java.time.Duration.ofSeconds(10),
                    "echo x | saslpasswd2 -p -f " + d.resolve("user") + " -c probeuser");
            byte[] withUser = Files.readAllBytes(d.resolve("user.db"));
            check("two empty databases created again have different bytes (otherwise the test proves nothing)",
                    !java.util.Arrays.equals(empty1, empty2));
            String path = "/usr/local/etc/sasldb2.db";
            Map<String, InstallSideEffects.FileState> b = new TreeMap<>(), a = new TreeMap<>(), u = new TreeMap<>();
            b.put(path, new InstallSideEffects.FileState("x1", "rw-r----- cyrus:mail", false, empty1));
            a.put(path, new InstallSideEffects.FileState("x2", "rw-r----- cyrus:mail", false, empty2));
            u.put(path, new InstallSideEffects.FileState("x3", "rw-r----- cyrus:mail", false, withUser));
            JSONArray same = InstallSideEffects.configChanges(new InstallSideEffects.ConfigSnapshot(b, Map.of()),
                    new InstallSideEffects.ConfigSnapshot(a, Map.of()), Set.of());
            check("sasldb2.db created again empty as it was: said, without an alarm",
                    "rebuilt".equals(kindOf(same, path)) && !find(same, path).getBoolean("alarm"));
            JSONArray added = InstallSideEffects.configChanges(new InstallSideEffects.ConfigSnapshot(b, Map.of()),
                    new InstallSideEffects.ConfigSnapshot(u, Map.of()), Set.of());
            check("sasldb2.db with one more user: alarm", "script".equals(kindOf(added, path)));
            check("the users are read, never the passwords: 'user@domain: attribute'",
                    String.valueOf(InstallSideEffects.saslUsers(withUser)).matches("(?s)probeuser@\\S+: \\w+.*"));
            check("an empty database gives zero users, not 'not read'", "".equals(InstallSideEffects.saslUsers(empty1)));
            check("a file that is not a SASL database: not read, so no 'same users'",
                    InstallSideEffects.saslUsers("not a database".getBytes()) == null);
        } finally {
            try (var st = Files.walk(d)) { st.sorted(java.util.Comparator.reverseOrder()).forEach(x -> x.toFile().delete()); }
        }
    }

    /** Like the cyrus-sasl script: it creates the cyrus user and removes it. {@code base} without ".db". */
    private static byte[] emptySasldb(Path base) throws Exception {
        org.mail_panel.util.Shell.runShell(java.time.Duration.ofSeconds(10),
                "echo test | saslpasswd2 -p -f " + base + " -c cyrus && saslpasswd2 -f " + base + " -d cyrus");
        return Files.readAllBytes(Path.of(base + ".db"));
    }

    // ===== the version of before, set aside =====
    private static void savedCopies() throws Exception {
        Path d = Files.createTempDirectory("saved");
        try {
            Path src = Files.createDirectories(d.resolve("live/postfix"));
            write(src.resolve("main.cf"), "inet_protocols = all\n", "rw-r--r--");
            write(src.resolve("mysql.cf"), "password = secret\n", "rw-r-----");
            InstallSideEffects.ConfigSnapshot before =
                    InstallSideEffects.configSnapshot(List.of(d.resolve("live")), List.of(), Map.of());
            Map<String, InstallSideEffects.FileState> big = new TreeMap<>(before.files());
            big.put("/nowhere/huge.cf", new InstallSideEffects.FileState("x", "rw-r--r-- root:wheel", true, null));
            InstallSideEffects.ConfigSnapshot withBig = new InstallSideEffects.ConfigSnapshot(big, Map.of());
            Path backups = d.resolve("backups/20261024T090000Z");
            String mainCf = src.resolve("main.cf").toString(), mysqlCf = src.resolve("mysql.cf").toString();
            Map<String, String> r = InstallSideEffects.saveBefore(withBig,
                    List.of(mainCf, mysqlCf, "/nowhere/new.cf", "/nowhere/huge.cf"), backups);
            Path copy = Path.of(r.get(mainCf));
            check("the copy of main.cf is there, with the whole path under the folder", Files.exists(copy)
                    && copy.toString().equals(backups + mainCf));
            check("  with the content of before", Files.readString(copy).equals("inet_protocols = all\n"));
            check("  and the same permissions, so cp -p puts it back as it was",
                    PosixFilePermissions.toString(Files.getPosixFilePermissions(copy)).equals("rw-r--r--")
                    && PosixFilePermissions.toString(Files.getPosixFilePermissions(Path.of(r.get(mysqlCf)))).equals("rw-r-----"));
            check("the copies' folder is readable by the owner only",
                    PosixFilePermissions.toString(Files.getPosixFilePermissions(backups)).equals("rwx------"));
            check("a file that was not there before: no copy, and it says so", "created".equals(r.get("/nowhere/new.cf")));
            check("a file too large to keep its content: it says so", "tooLarge".equals(r.get("/nowhere/huge.cf")));

            for (String n : new String[]{"20261020T080000Z", "20261021T080000Z", "20261022T080000Z", "20261023T080000Z"})
                Files.createDirectories(d.resolve("backups/" + n + "/x"));
            InstallSideEffects.pruneBefore(d.resolve("backups"), 2);
            List<String> left;
            try (var st = Files.list(d.resolve("backups"))) { left = st.map(x -> x.getFileName().toString()).sorted().toList(); }
            check("the latest ones are kept, and the oldest are removed: " + left,
                    left.equals(List.of("20261023T080000Z", "20261024T090000Z")));
        } finally {
            try (var s = Files.walk(d)) {
                s.sorted(java.util.Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }

    private static void put(Map<String, InstallSideEffects.FileState> m, String path, String text, boolean worldReadable) {
        byte[] b = text.getBytes(StandardCharsets.UTF_8);
        m.put(path, new InstallSideEffects.FileState(Integer.toHexString(java.util.Arrays.hashCode(b)),
                (worldReadable ? "rw-r--r--" : "rw-------") + " root:wheel", worldReadable, b));
    }

    private static String kindOf(JSONArray c, String path) {
        JSONObject o = find(c, path);
        return o == null ? null : o.getString("kind");
    }

    private static JSONObject find(JSONArray c, String path) {
        for (int i = 0; i < c.length(); i++)
            if (c.getJSONObject(i).getString("path").equals(path)) return c.getJSONObject(i);
        return null;
    }

    // ===== the lines =====
    private static void lines() {
        List<List<String>> d = InstallSideEffects.lineDiff("a\nb\nc\n", "a\nc\nd\n");
        check("diff: b removed, d added", d.get(0).equals(List.of("b")) && d.get(1).equals(List.of("d")));
        d = InstallSideEffects.lineDiff("a\n", "a");
        check("diff: the final newline is not a line", d.get(0).isEmpty() && d.get(1).isEmpty());
        d = InstallSideEffects.lineDiff("x\nx\n", "x\n");
        check("diff: a double line turned single shows", d.get(0).equals(List.of("x")) && d.get(1).isEmpty());
        check("comments: # and ; and empty lines", InstallSideEffects.allComments(List.of("#a", "  ; b", "", "   ")));
        check("comments: a directive is not one", !InstallSideEffects.allComments(List.of("#a", "inet_protocols = ipv4")));
        check("text: a zero byte is not", !InstallSideEffects.isText(new byte[]{'a', 0, 'b'}));
    }

    // ===== whose files they are =====
    private static void owners() {
        String query = "postfix-mysql\t/usr/local/etc/postfix/main.cf.sample\n"
                + "postfix-mysql\t/usr/local/sbin/postfix\n"
                + "roundcube-php84\t/usr/local/www/roundcube/config/config.inc.php.sample\n"
                + "roundcube-php84\t/usr/local/www/roundcube/config/defaults.inc.php\n"
                + "roundcube-php84\t/usr/local/www/roundcube/index.php\n"
                + "bad name!\t/usr/local/etc/x\n";
        Map<String, String> o = InstallSideEffects.owners(query, InstallSideEffects.CONFIG_ROOTS);
        check("owners: a file under /usr/local/etc is there", "postfix-mysql".equals(o.get("/usr/local/etc/postfix/main.cf.sample")));
        check("  a binary outside the roots is not", !o.containsKey("/usr/local/sbin/postfix"));
        check("  Roundcube's .sample outside /usr/local/etc is", o.containsKey("/usr/local/www/roundcube/config/config.inc.php.sample"));
        check("  and so is the package's file next to it, otherwise every update would raise the alarm",
                "roundcube-php84".equals(o.get("/usr/local/www/roundcube/config/defaults.inc.php")));
        check("  but not the rest of Roundcube", !o.containsKey("/usr/local/www/roundcube/index.php"));
        check("  an invalid package name is discarded", !o.containsKey("/usr/local/etc/x"));
        List<Path> dirs = InstallSideEffects.sampleDirsOutside(o, InstallSideEffects.CONFIG_ROOTS);
        check("folders to look at outside the roots: only Roundcube's configuration one",
                dirs.size() == 1 && dirs.get(0).toString().equals("/usr/local/www/roundcube/config"));
    }

    // ===== the listening addresses =====
    private static void listening() {
        // Real lines from the VM, 24/10/2026, with rspamd's udp ones in between.
        String before = String.join("\n",
                "root   java       90871  9 tcp46 *:2096                *:*",
                "root   master     90660 13 tcp4  *:25                  *:*",
                "root   master     90660 14 tcp6  *:25                  *:*",
                "root   master     90660 18 tcp4  *:587                 *:*",
                "root   master     90660 19 tcp6  *:587                 *:*",
                "www    nginx      46458  6 tcp4  *:8443                *:*",
                "root   nginx      45720  6 tcp4  *:8443                *:*",
                "rspamd rspamd-4.1 28334 11 udp4  *:*                   *:*",
                "rspamd rspamd-4.1 28334 15 tcp4  127.0.0.1:11333       *:*",
                "redis  redis-serv 34997  7 tcp6  [::1]:6379            *:*");
        Map<String, String> p = InstallSideEffects.parseSockstat(before);
        check("sockstat: eight distinct TCP addresses (2096, 25 and 587 on v4 and v6, 8443, 11333, 6379)", p.size() == 8);
        check("  nginx's processes count once", p.containsKey("tcp4 *:8443"));
        check("  the udp ones do not", p.keySet().stream().noneMatch(k -> k.startsWith("udp")));
        check("  tcp46 does", "java".equals(p.get("tcp46 *:2096")));

        // Reperto 42 after the restart: postfix started again with another pid, without IPv6.
        String after = before.replace("90660", "91234")
                .replace("root   master     91234 14 tcp6  *:25                  *:*\n", "")
                .replace("root   master     91234 19 tcp6  *:587                 *:*\n", "")
                + "\nroot   nginx      45720  7 tcp4  *:80                  *:*";
        JSONObject cmp = InstallSideEffects.compareListening(p, InstallSideEffects.parseSockstat(after));
        JSONArray lost = cmp.getJSONArray("lost");
        check("lost tcp6 *:25 and tcp6 *:587, and the changed pid does not count", lost.length() == 2
                && lost.toString().contains("tcp6 *:25") && lost.toString().contains("tcp6 *:587"));
        check("  with the process name", lost.getJSONObject(0).getString("command").equals("master"));
        check("appeared tcp4 *:80", cmp.getJSONArray("gained").length() == 1
                && cmp.getJSONArray("gained").getJSONObject(0).getString("address").equals("tcp4 *:80"));
        check("same addresses with other pids: nothing lost, nothing appeared",
                InstallSideEffects.compareListening(p, InstallSideEffects.parseSockstat(before.replace("90660", "1"))).getJSONArray("lost").isEmpty());
    }

    private static JSONObject find(JSONArray c, Path p) {
        for (int i = 0; i < c.length(); i++)
            if (c.getJSONObject(i).getString("path").equals(p.toString())) return c.getJSONObject(i);
        return null;
    }

    private static void write(Path p, String text, String permissions) throws Exception {
        Files.writeString(p, text, StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(p, PosixFilePermissions.fromString(permissions));
    }

    private static void append(Path p, String text) throws Exception {
        Files.writeString(p, Files.readString(p) + text, StandardCharsets.UTF_8);
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failures++;
    }
}
