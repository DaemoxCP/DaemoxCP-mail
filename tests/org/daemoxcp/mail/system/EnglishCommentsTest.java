package org.daemoxcp.mail.system;

import org.daemoxcp.mail.scripts.ClamAVScript;
import org.daemoxcp.mail.scripts.DovecotConfig;
import org.daemoxcp.mail.scripts.DovecotScript;
import org.daemoxcp.mail.scripts.FullMailServerScript;
import org.daemoxcp.mail.scripts.FullMailStackScript;
import org.daemoxcp.mail.scripts.MySQLMailScript;
import org.daemoxcp.mail.scripts.PostfixScript;
import org.daemoxcp.mail.scripts.RedisScript;
import org.daemoxcp.mail.scripts.RoundcubeScript;
import org.daemoxcp.mail.scripts.RspamdScript;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * The comments the panel wrote in Italian on the server go to English (EnglishComments, 22/11/2026).
 *
 *  1. The data file: every Italian line of the section "italianComments" becomes its English line, and no English line
 *     holds an Italian text of the section (it would be turned again).
 *  2. The blocks of before that the panel recognizes as they are (LmtpSocket.OLD23 and OLD24, SieveStorage.OLD23 and
 *     OLD24) are not touched by the translation.
 *  3. A server whose blocks are still in Italian: RedisSocket, ClamdSocket, RspamdController, LmtpSocket and DovecotQuota
 *     recognize them as their own, and do nothing, instead of adding a second block or leaving the file as someone
 *     else's.
 *  4. The files of a server installed before, in a temporary folder: after EnglishComments.migrate every file is
 *     identical byte for byte to the one today's code writes, with the same permissions; the administrator's lines stay;
 *     a second pass finds nothing.
 *  5. Today's code writes no comment in Italian: the installation scripts and the files the panel writes at start.
 *
 * The "old" texts are built from today's by putting back the Italian lines of the data file: the test writes no
 * Italian. Against fakes; the real files are measured on the VM (upgrade from a server installed before).
 *
 *   java -cp "tests:&lt;dir&gt;/daemoxcp-mail.jar" org.daemoxcp.mail.system.EnglishCommentsTest
 */
public class EnglishCommentsTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static final List<String[]> PAIRS = LegacyNames.pairs(EnglishComments.SECTION);

    /**
     * The text as the panel wrote it before: in every comment line, each English text goes back to its Italian one. The
     * English pieces of a few characters (":", "\".") are left out: going back they would match anything.
     */
    static String italian(String english) {
        List<String[]> back = new ArrayList<>();
        for (String[] p : PAIRS) if (p[1].length() >= 8) back.add(p);
        back.sort(Comparator.comparingInt((String[] p) -> -p[1].length()));
        String[] lines = english.split("\n", -1);
        for (int i = 0; i < lines.length; i++) {
            if (!PanelMarker.comment(lines[i])) continue;
            for (String[] p : back) lines[i] = lines[i].replace(p[1], p[0]);
        }
        return String.join("\n", lines);
    }

    /** Words that are Italian and never English, in a comment line. */
    static final Pattern ITALIAN = Pattern.compile("(?i)(\\b(della|delle|degli|dello|nella|nelle|sono|questo|questa|quando"
            + "|senza|ogni|anche|niente|pannello|casella|caselle|che|gli|il|una|uno|dal|dalla|sul|sulla|nel|alla|perche|cioe)\\b"
            + "|\\bnon |\\b(e|piu|gia|cosi|puo|li)' )");

    static List<String> italianCommentLines(String text) {
        List<String> out = new ArrayList<>();
        for (String l : text.split("\n")) {
            String t = l.strip();
            if ((t.startsWith("#") || t.startsWith(";") || t.startsWith("//")) && ITALIAN.matcher(t).find()) out.add(t);
        }
        return out;
    }

    public static void main(String[] args) throws Exception {
        System.out.println("== 1. The data file");
        check("italianComments: " + PAIRS.size() + " lines", PAIRS.size() > 500);
        List<String> wrong = new ArrayList<>();
        for (String[] p : PAIRS) {
            String line = PanelMarker.comment(p[0]) ? p[0] : "# " + p[0];
            String want = PanelMarker.comment(p[0]) ? p[1] : "# " + p[1];
            if (!EnglishComments.english(line).equals(want)) wrong.add(p[0]);
        }
        wrong.forEach(x -> System.out.println("        not translated: " + x));
        check("every Italian line becomes its English one", wrong.isEmpty());
        List<String> back = new ArrayList<>();
        for (String[] p : PAIRS) for (String[] q : PAIRS) if (q[1].contains(p[0])) back.add(p[0]);
        check("no English line holds an Italian text of the section", back.isEmpty());
        check("a line that is not a comment is not touched",
                EnglishComments.english("echo \"" + PAIRS.get(0)[0] + "\"\n").equals("echo \"" + PAIRS.get(0)[0] + "\"\n"));

        System.out.println("\n== 2. The blocks of before stay as they are");
        for (Map.Entry<String, String> e : Map.of("LmtpSocket.OLD23", LmtpSocket.OLD23, "LmtpSocket.OLD24", LmtpSocket.OLD24,
                "SieveStorage.OLD23", SieveStorage.OLD23, "SieveStorage.OLD24", SieveStorage.OLD24).entrySet())
            check(e.getKey() + " unchanged", EnglishComments.english(e.getValue()).equals(e.getValue()));

        System.out.println("\n== 3. A server whose blocks are still in Italian");
        Map<String, String> marks = new LinkedHashMap<>();
        marks.put("RedisSocket.FINAL", RedisSocket.FINAL);
        marks.put("ClamdSocket.BLOCK", ClamdSocket.BLOCK);
        marks.put("RspamdController.text", RspamdController.text("$2$abcdefgh$abcdefghijklmnop"));
        marks.put("LmtpSocket.NEW", LmtpSocket.NEW);
        marks.put("LmtpSocket.transition (2.4)", LmtpSocket.transition(true));
        marks.put("DovecotConfig.QUOTA_USERDB", DovecotConfig.QUOTA_USERDB);
        marks.put("DovecotConfig.QUOTA_FILE", DovecotConfig.QUOTA_FILE);
        for (Map.Entry<String, String> e : marks.entrySet()) {
            String it = italian(e.getValue());
            check(e.getKey() + ": it was written in Italian, and goes back to today's", !it.equals(e.getValue())
                    && EnglishComments.english(it).equals(e.getValue()));
        }

        RedisSocketTest.Machine redis = new RedisSocketTest.Machine(RedisSocketTest.PACKAGE, RedisSocketTest.OLD_RS);
        check("redis: the move done", RedisSocketTest.run(redis).outcome() == RedisSocket.Outcome.DONE);
        String redisConf = italian(redis.files.get(RedisSocketTest.CONF));
        redis.files.put(RedisSocketTest.CONF, redisConf);
        int restarts = redis.redisRestarts;
        check("  with the block in Italian: NOTHING, redis.conf untouched, no restart",
                RedisSocketTest.run(redis).outcome() == RedisSocket.Outcome.NOTHING
                        && redis.files.get(RedisSocketTest.CONF).equals(redisConf) && redis.redisRestarts == restarts);

        ClamdSocketTest.Machine clamd = new ClamdSocketTest.Machine(ClamdSocketTest.PACKAGE);
        check("clamd: the move done", ClamdSocketTest.run(clamd).outcome() == ClamdSocket.Outcome.DONE);
        String clamdConf = italian(clamd.files.get(ClamdSocketTest.CONF));
        clamd.files.put(ClamdSocketTest.CONF, clamdConf);
        check("  with the block in Italian: NOTHING, no second block",
                ClamdSocketTest.run(clamd).outcome() == ClamdSocket.Outcome.NOTHING
                        && clamd.files.get(ClamdSocketTest.CONF).equals(clamdConf));

        RspamdControllerTest.Machine rspamd = new RspamdControllerTest.Machine();
        check("rspamd: the controller's password done", RspamdControllerTest.run(rspamd).outcome() == RspamdController.Outcome.DONE);
        String secret = rspamd.secret;
        rspamd.files.put(RspamdControllerTest.FILE, italian(rspamd.files.get(RspamdControllerTest.FILE)));
        int reloads = rspamd.reloads;
        check("  with the file in Italian: NOTHING, same password, no reload (not taken for someone else's file)",
                RspamdControllerTest.run(rspamd).outcome() == RspamdController.Outcome.NOTHING
                        && rspamd.secret.equals(secret) && rspamd.reloads == reloads);

        LmtpSocketTest.Machine lmtp = new LmtpSocketTest.Machine(String.format(LmtpSocketTest.AROUND, LmtpSocket.OLD24),
                LmtpSocketTest.MAIN24);
        check("LMTP: the move done", LmtpSocket.run(lmtp, LmtpSocketTest.MASTER, LmtpSocketTest.MAIN).outcome() == LmtpSocket.Outcome.DONE);
        String master = italian(lmtp.files.get(LmtpSocketTest.MASTER));
        lmtp.files.put(LmtpSocketTest.MASTER, master);
        check("  with the block in Italian: NOTHING, not LEFT", LmtpSocket.run(lmtp, LmtpSocketTest.MASTER, LmtpSocketTest.MAIN).outcome()
                == LmtpSocket.Outcome.NOTHING && lmtp.files.get(LmtpSocketTest.MASTER).equals(master));

        String authSql = "sql_driver = mysql\n\npassdb sql {\n  query = SELECT 1\n}\n\n" + DovecotConfig.QUOTA_USERDB
                + "userdb static {\n  fields = uid=vmail\n}\n";
        check("Dovecot's quotas: today's files are in place", DovecotQuota.decide("2.4.5", authSql, DovecotConfig.QUOTA_FILE).action()
                == DovecotQuota.Action.NOTHING);
        check("  the same in Italian: in place too, nothing to apply", DovecotQuota.decide("2.4.5", italian(authSql),
                italian(DovecotConfig.QUOTA_FILE)).action() == DovecotQuota.Action.NOTHING);

        System.out.println("\n== 4. The files of a server installed before");
        Map<String, String> files = new LinkedHashMap<>();
        files.put("10-auth-worker.conf", DovecotAuthWorker.fileContent("vmail"));
        files.put("10-sockets.conf", DovecotSockets.fileContent());
        files.put("15-special-folders.conf", SpecialFolders.fileContent(true));
        files.put("roundcube.conf", RoundcubeUser.poolConf(null));
        files.put("www.conf", RoundcubeUser.wwwPlaceholder());
        files.put("php.ini", PhpHardening.INI);
        files.put("redis.conf", RedisSocketTest.PACKAGE + "\n" + RedisSocket.FINAL);
        files.put("public-443.conf", WebProtection.configuration("/x/fullchain.pem", "/x/privkey.pem"));
        files.put("public-443-jail.conf", WebProtection.jail());
        files.put("auth-sql.conf.ext", authSql);
        Path dir = Files.createTempDirectory("english-comments");
        List<Path> paths = new ArrayList<>();
        int italianFiles = 0;
        for (Map.Entry<String, String> e : files.entrySet()) {
            Path p = dir.resolve(e.getKey());
            String before = italian(e.getValue());
            if (!before.equals(e.getValue())) italianFiles++;
            Files.writeString(p, before);
            Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rw-r-----"));
            paths.add(p);
        }
        check("the old files really have Italian comments (" + italianFiles + " of " + files.size() + ")", italianFiles == files.size());
        Path admin = dir.resolve("admin.conf");
        String adminText = "# a comment of my own\n" + italian("# The loopback is not filtered.\n") + "set skip on lo\n";
        Files.writeString(admin, adminText);
        paths.add(admin);
        paths.add(dir.resolve("does-not-exist.conf"));
        // The copies keep the file as it was: ConfigBackups, Fail2banManager, BanActionRepair, and the older ones, whose
        // prefix is the old name of "before-" (taken from the data file: the test writes no old name).
        String oldBefore = LegacyNames.oldNamesOf("bootEnvironmentPrefix", "before-").get(0);
        List<Path> copies = new ArrayList<>();
        for (String name : List.of("mail.local.bak.1779137852481", "mail.local.bak.20260903-174305", "jail.conf.before-pf-20261101",
                "public.conf." + oldBefore + "pf-20260903-125720", "dovecot-sql.conf.pre-2.4", "pf.conf.orig")) {
            Path c = dir.resolve(name);
            Files.writeString(c, italian(WebProtection.jail()));
            copies.add(c);
            paths.add(c);
        }
        EnglishComments.Report r = EnglishComments.migrate(paths);
        r.problems().forEach(x -> System.out.println("        " + x));
        check("moved " + r.done().size() + " files, without errors", r.done().size() == files.size() + 1 && r.problems().isEmpty());
        for (Map.Entry<String, String> e : files.entrySet()) {
            Path p = dir.resolve(e.getKey());
            check("  " + e.getKey() + " identical to today's, permissions rw-r-----", Files.readString(p).equals(e.getValue())
                    && PosixFilePermissions.toString(Files.getPosixFilePermissions(p)).equals("rw-r-----"));
        }
        check("  the administrator's own comment stays, the panel's line goes to English", Files.readString(admin)
                .equals("# a comment of my own\n# The loopback is not filtered.\nset skip on lo\n"));
        boolean copiesKept = true;
        for (Path c : copies) copiesKept &= Files.readString(c).equals(italian(WebProtection.jail()));
        check("  the copies (.bak, .before-pf-, the old-named ones, .pre-2.4, .orig) stay as they were", copiesKept);
        try (var s = Files.list(dir)) {
            check("  no temporary file left", s.noneMatch(p -> p.getFileName().toString().endsWith(".tmp")));
        }
        check("a second pass finds nothing", EnglishComments.migrate(paths).done().isEmpty());

        System.out.println("\n== 5. Today's code writes no comment in Italian");
        Map<String, String> written = new LinkedHashMap<>();
        written.put("install_mail_server.sh", new FullMailServerScript().getScriptContent());
        written.put("install_full_mail_stack.sh", new FullMailStackScript().getScriptContent());
        written.put("install_roundcube.sh", new RoundcubeScript().getScriptContent());
        written.put("install_postfix.sh", new PostfixScript().getScriptContent());
        written.put("install_dovecot.sh", new DovecotScript().getScriptContent());
        written.put("install_rspamd.sh", new RspamdScript().getScriptContent());
        written.put("install_redis.sh", new RedisScript().getScriptContent());
        written.put("install_clamav.sh", new ClamAVScript().getScriptContent());
        written.put("install_mysql.sh", new MySQLMailScript().getScriptContent());
        written.put("Dovecot blocks", DovecotConfig.SIEVE23 + DovecotConfig.SIEVE24 + DovecotConfig.QUOTA_FILE
                + DovecotConfig.QUOTA_USERDB + LmtpSocket.NEW + LmtpSocket.transition(false) + LmtpSocket.transition(true));
        written.put("Dovecot conf.d files", DovecotAuthWorker.fileContent("vmail") + DovecotSockets.fileContent()
                + ManageSieveLocal.fileContent(true) + ManageSieveLocal.fileContent(false) + SpecialFolders.fileContent(true)
                + SpecialFolders.fileContent(false) + SpecialFolders.scriptContent());
        written.put("php and Roundcube", PhpHardening.INI + PhpHardening.LIMIT_COMMENT + RoundcubeUser.poolConf(null)
                + RoundcubeUser.wwwPlaceholder() + RoundcubeUser.roundcubeRotation() + RoundcubeUser.shellPool()
                + RoundcubeCipher.lines("abcdefghijklmnopqrstuvwxyz012345"));
        written.put("nginx", NginxMain.template() + WebProtection.configuration("/x/a.pem", "/x/b.pem") + WebProtection.jail()
                + WebProtection.filter());
        written.put("redis, clamd, rspamd, MySQL", RedisSocket.FINAL + ClamdSocket.BLOCK + RspamdController.text("$2$x$y")
                + MysqlListen.harden(null));
        written.put("other scripts", DovecotMasterUser.shell("/x/key", "/x/users") + UnusedMaildir.SCRIPT + OsPatch.installConfig(""));
        written.put("fail2ban", org.daemoxcp.mail.security.Fail2banAutoSetup.filterContent()
                + org.daemoxcp.mail.security.Fail2banManager.PERMABAN_HEADER);
        for (Map.Entry<String, String> e : written.entrySet()) {
            List<String> it = italianCommentLines(e.getValue());
            it.forEach(x -> System.out.println("        " + x));
            check(e.getKey() + ": no Italian comment", it.isEmpty());
        }

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
