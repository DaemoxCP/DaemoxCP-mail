package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * PostfixMaps with the VM's real Postfix: regenerating the maps when the library reading them
 * changes.
 *
 * Two test lmdb tables are added to Postfix: a transport map with its text (e2e-transport, in front
 * of the ones that were there) and the address verification cache (e2e-verify). The library change
 * cannot really be caused (it would need a Postfix built with LMDB 1.0): PostfixMaps is given an
 * "old" signature different from the real one, which is what it would see after the change, and the
 * map's file is damaged, as a library that cannot read it would see it. So all the rest is tested on
 * the real system: postmap, postalias, the verification, the cache, the Postfix reload, and the
 * forecast from the plan with the real catalog. With a fake hash signature /etc/aliases is
 * regenerated too, with postalias (and at the end the old file is put back). The comparison between
 * database and text is tested with a hash map outside the configuration (the order of the entries, a
 * changed value, one more line). The rebuild from the content read before is tested without the
 * text, with an entry added with postmap -i, with an altered content (it must not go into use) and
 * with a lower memory ceiling (the map is not kept, and the plan stops). The updater's three real
 * jobs are tested by PostfixMapsJobsE2ETest.
 *
 * It touches Postfix's configuration and puts it back as it was, and checks it: it runs only with
 * -De2e.vm=yes, as root, on FreeBSD.
 *
 *   java -De2e.vm=yes -cp "tests:&lt;dir&gt;/daemoxcp-mail.jar" org.daemoxcp.mail.system.PostfixMapsE2ETest
 */
public class PostfixMapsE2ETest {

    private static int failures = 0;

    static final String SOURCE = "/usr/local/etc/postfix/e2e-transport";
    static final String CACHE = "/var/db/postfix/e2e-verify";
    static final String ANSWER = "smtp:[127.0.0.1]:2525";
    /** With an entry without a value at the top: postmap skips it, and the verification must not look for it. */
    static final String TEXT = "# PostfixMaps test\nbroken.invalid\nexample.invalid " + ANSWER + "\n";
    static final String ALIASES_BACKUP = "/var/tmp/postfix-maps-e2e-aliases.db";
    /** A hash map outside the configuration, for the order-independent comparison. */
    static final String ORDER = "/var/tmp/postfix-maps-e2e-order";
    static final String EXTRA = "smtp:[127.0.0.1]:2527";

    public static void main(String[] args) throws Exception {
        if (!"yes".equals(System.getProperty("e2e.vm"))
                || !sh("uname -s").trim().equals("FreeBSD") || !sh("id -u").trim().equals("0")
                || !sh("postconf -m").contains("lmdb")) {
            System.out.println("SKIPPED: it needs -De2e.vm=yes, as root, on FreeBSD with a Postfix that can read lmdb");
            return;
        }
        String transportSet = sh("postconf -n transport_maps").trim();
        String verifySet = sh("postconf -n address_verify_map").trim();
        String transportOld = sh("postconf -h transport_maps").trim();
        String aliasesBefore = sh("stat -f %m /etc/aliases.db").trim();
        String aliasesOwner = sh("stat -f '%Su:%Sg %Lp' /etc/aliases.db").trim();
        sh("cp -p /etc/aliases.db " + ALIASES_BACKUP);
        List<String> log = new ArrayList<>();
        long budget = PostfixMaps.maxSavedBytes;
        String name = "lmdb:" + SOURCE, label = name + " (transport_maps)";
        try {
            Files.writeString(Path.of(SOURCE), TEXT);
            sh("postmap lmdb:" + SOURCE + " 2>/dev/null");
            sh("postconf -e 'transport_maps = lmdb:" + SOURCE + (transportOld.isEmpty() ? "" : ", " + transportOld) + "'");
            sh("postconf -e 'address_verify_map = lmdb:" + CACHE + "'");
            Files.writeString(Path.of(CACHE + ".lmdb"), "test cache");
            sh("postfix reload");
            check("the test map answers, before anything", lookup().equals(ANSWER));

            System.out.println("\n== Nothing changed ==");
            Map<String, String> real = PostfixMaps.librarySignature();
            System.out.println("     signatures: " + real);
            check("lmdb is read by lmdb0's liblmdb.so.0, hash by the base system",
                    String.valueOf(real.get("lmdb")).contains("liblmdb.so.0") && String.valueOf(real.get("lmdb")).contains("(lmdb0)")
                            && "base".equals(real.get("hash")));
            PostfixMaps.Before snap = PostfixMaps.before();
            System.out.println("     kept aside: " + snap.saved() + ", not to regenerate: " + snap.lost());
            check("every map of the VM matches its text: nothing to keep aside, nothing lost",
                    snap.saved().isEmpty() && snap.lost().isEmpty());
            check("  and the comparison leaves no files next to it",
                    sh("ls " + SOURCE + ".panel-check* /etc/aliases.panel-check* 2>/dev/null").isBlank());
            PostfixMaps.Outcome o = PostfixMaps.afterUpgrade(snap, log::add);
            check("same library: nothing to do, nothing written", o.ok() && log.isEmpty());
            check("  and the cache stays where it is", Files.exists(Path.of(CACHE + ".lmdb")));

            System.out.println("\n== The database and the text, compared ==");
            PostfixMaps.Table order = new PostfixMaps.Table("transport_maps", "hash", ORDER, PostfixMaps.Kind.PUBLIC);
            Files.writeString(Path.of(ORDER), "k1 v1\nk2 v2\nk3 v3\nk4 v4\nk5 v5\n");
            sh("postmap hash:" + ORDER);
            Files.writeString(Path.of(ORDER), "k5 v5\nk4 v4\nk3 v3\nk2 v2\nk1 v1\n");
            check("hash: the same entries written in another order match the database (the dump comes out in another order)",
                    PostfixMaps.outOfSync(order) == null);
            Files.writeString(Path.of(ORDER), "k5 v5\nk4 v4\nk3 other\nk2 v2\nk1 v1\n");
            String values = PostfixMaps.outOfSync(order);
            check("a value changed in the text without postmap: different, with the same 5 entries (" + values + ")",
                    values != null && values.contains("5"));
            Files.writeString(Path.of(ORDER), "k5 v5\nk4 v4\nk3 v3\nk2 v2\nk1 v1\nk6 v6\n");
            String counts = PostfixMaps.outOfSync(order);
            check("one more line in the text without postmap: different, 5 entries against 6 (" + counts + ")",
                    counts != null && counts.contains("5") && counts.contains("6"));
            sh("rm -f " + ORDER + ".db");
            check("without a database there is only the text: nothing to lose, it matches", PostfixMaps.outOfSync(order) == null);
            sh("rm -f " + ORDER + " " + ORDER + ".db");

            System.out.println("\n== The lmdb library changed: from the text, which matches ==");
            // The database with a group and permissions of its own: the new map must have the same, not the text's.
            sh("chown root:mail " + SOURCE + ".lmdb; chmod 640 " + SOURCE + ".lmdb");
            String mapOwner = stat(SOURCE + ".lmdb");
            PostfixMaps.Before fromText = PostfixMaps.before();
            Files.writeString(Path.of(SOURCE + ".lmdb"), "this is not an lmdb database");
            check("file damaged: the map no longer answers", !lookup().equals(ANSWER));
            Map<String, String> before = new TreeMap<>(real);
            before.put("lmdb", "liblmdb.so.0=/usr/local/lib/liblmdb.so.0(old-lmdb)");
            int reloads = reloads();
            o = PostfixMaps.afterUpgrade(new PostfixMaps.Before(before, fromText.saved(), fromText.lost()), log::add);
            log.forEach(l -> System.out.println("       | " + l));
            check("the regeneration succeeds", o.ok());
            check("the regenerated map answers as before", lookup().equals(ANSWER));
            check("  with the owner and permissions of the old database (" + mapOwner + "), not the text's",
                    mapOwner.equals("root:mail 640") && stat(SOURCE + ".lmdb").equals(mapOwner));
            check("  and no build file next to it", sh("ls " + SOURCE + ".panel-rebuild* 2>/dev/null").isBlank());
            check("Postfix was really reloaded (maillog: \"refreshing the Postfix mail system\")", reloads() > reloads);
            check("the lmdb cache is deleted (Postfix recreates it)", !Files.exists(Path.of(CACHE + ".lmdb")));
            check("the log says what it regenerated, with the key tried (not the one without a value) and the cache",
                    String.join("\n", log).contains("e2e-transport") && String.join("\n", log).contains("«example.invalid»")
                            && !String.join("\n", log).contains("broken.invalid") && String.join("\n", log).contains("e2e-verify"));
            check("Postfix runs", sh("postfix status; echo $?").trim().endsWith("0"));
            check("the hash maps were not touched (/etc/aliases.db as it was)",
                    sh("stat -f %m /etc/aliases.db").trim().equals(aliasesBefore));

            System.out.println("\n== The hash library changed: the aliases, with postalias ==");
            Map<String, String> hashBefore = new TreeMap<>(real);
            hashBefore.put("hash", "libdb.so.5=/usr/local/lib/db5/libdb.so.5(db5)");
            PostfixMaps.Before aliases = PostfixMaps.before();
            log.clear();
            o = PostfixMaps.afterUpgrade(new PostfixMaps.Before(hashBefore, aliases.saved(), aliases.lost()), log::add);
            log.forEach(l -> System.out.println("       | " + l));
            check("the regeneration of the aliases succeeds", o.ok());
            check("  and the log says hash:/etc/aliases, tried with one of its keys",
                    String.join("\n", log).contains("hash:/etc/aliases (alias_") && String.join("\n", log).contains("«MAILER-DAEMON»"));
            check("the aliases answer (postalias -q MAILER-DAEMON)",
                    sh("postalias -q MAILER-DAEMON hash:/etc/aliases").trim().equals("postmaster"));
            check("  with the old owner and permissions (" + aliasesOwner + ")", stat("/etc/aliases.db").equals(aliasesOwner));
            check("  and the lmdb maps not touched this time", !String.join("\n", log).contains("e2e-transport"));

            System.out.println("\n== A map without its text: from the content read before ==");
            Files.delete(Path.of(SOURCE));
            PostfixMaps.Before noText = PostfixMaps.before();
            PostfixMaps.Saved saved = noText.saved().get(name);
            check("before the upgrade its content is kept aside: 1 entry", saved != null && saved.digest.entries() == 1);
            check("  and it ends up in no message", !noText.toString().contains(ANSWER) && !noText.toString().contains("example.invalid"));
            check("the card does not stop: the map could be regenerated the same", PostfixMaps.planBlocker(plan("remove lmdb0")) == null);
            Files.writeString(Path.of(SOURCE + ".lmdb"), "this is not an lmdb database");
            log.clear();
            o = PostfixMaps.afterUpgrade(new PostfixMaps.Before(before, noText.saved(), noText.lost()), log::add);
            log.forEach(l -> System.out.println("       | " + l));
            check("after the library change it is rebuilt from the old content, and it answers", o.ok() && lookup().equals(ANSWER));
            check("  with the old owner and permissions (" + mapOwner + ")", stat(SOURCE + ".lmdb").equals(mapOwner));
            check("  and the log says so, and says the text is missing", String.join("\n", log).contains(
                    I18n.tr("server.maps.textMissing", Map.of("table", label))) && String.join("\n", log).contains(
                    I18n.tr("server.maps.rebuiltFromSaved", Map.of("table", label, "n", "1"))));
            check("  and the content kept aside was cleared", saved.content() == null);
            check("  and no build file next to it", sh("ls " + SOURCE + ".panel-rebuild* 2>/dev/null").isBlank());
            log.clear();
            o = PostfixMaps.afterUpgrade(new PostfixMaps.Before(before), log::add);
            check("without the content read before (and without text): an error naming it", !o.ok() && o.problem().contains("e2e-transport"));

            System.out.println("\n== The ones that could not be regenerated, seen from the plan ==");
            PostfixMaps.maxSavedBytes = 1;
            String blocked = PostfixMaps.planBlocker(plan("remove lmdb0"));
            System.out.println("     " + blocked);
            check("without text and with the content bigger than what is kept: it stops before, and names the map",
                    blocked != null && blocked.contains("e2e-transport") && blocked.contains(I18n.tr("server.maps.reasonNoSource")));
            JSONObject replacement = PackageReplacement.judge(PackageReplacement.facts("lmdb0", "0.9.35",
                    Map.of("lmdb0", "remove"), List.of())).toJson();
            check("the verdict on lmdb0 removed names the map that would be lost",
                    replacement.getJSONArray("problems").toString().contains("e2e-transport") && !replacement.optBoolean("safe"));
            PostfixMaps.Before tight = PostfixMaps.before();
            check("  and before() does not keep it: it counts it as lost", tight.saved().isEmpty() && tight.lost().containsKey(name));
            PostfixMaps.maxSavedBytes = budget;
            Files.writeString(Path.of(SOURCE + ".lmdb"), "this is not an lmdb database");
            String unreadable = PostfixMaps.planBlocker(plan("remove lmdb0"));
            check("a database that already cannot be read: it stops before",
                    unreadable != null && unreadable.contains("e2e-transport") && unreadable.contains(I18n.tr("server.maps.dbUnreadable")));
            check("a plan that upgrades Postfix but the new version still requires liblmdb.so.0: it does not stop",
                    PostfixMaps.planBlocker(plan("upgrade postfix-mysql")) == null);
            // postmap does not rewrite a file it cannot read (measured, see PostfixMaps): it is removed first.
            Files.writeString(Path.of(SOURCE), TEXT);
            sh("rm -f " + SOURCE + ".lmdb; postmap lmdb:" + SOURCE + " 2>/dev/null");
            check("with the text put back and the map regenerated: the plan no longer stops", PostfixMaps.planBlocker(plan("remove lmdb0")) == null);

            System.out.println("\n== An entry added with postmap -i, which the text does not have ==");
            sh("echo 'extra.invalid " + EXTRA + "' | postmap -i lmdb:" + SOURCE);
            check("the added entry answers", lookup("extra.invalid").equals(EXTRA));
            PostfixMaps.Before withExtra = PostfixMaps.before();
            PostfixMaps.Saved extra = withExtra.saved().get(name);
            System.out.println("     " + (extra == null ? "not kept" : extra.textDiffers));
            check("the comparison sees it, and the content is kept aside: 2 entries, the text would give 1",
                    extra != null && extra.digest.entries() == 2 && extra.textDiffers != null
                            && extra.textDiffers.contains("2") && extra.textDiffers.contains("1"));
            check("  and it does not touch the database: the added entry still answers", lookup("extra.invalid").equals(EXTRA));
            check("  and the aliases still match", !withExtra.saved().containsKey("hash:/etc/aliases") && withExtra.lost().isEmpty());
            check("the card does not stop", PostfixMaps.planBlocker(plan("remove lmdb0")) == null);
            Files.writeString(Path.of(SOURCE + ".lmdb"), "this is not an lmdb database");
            log.clear();
            o = PostfixMaps.afterUpgrade(new PostfixMaps.Before(before, withExtra.saved(), withExtra.lost()), log::add);
            log.forEach(l -> System.out.println("       | " + l));
            check("after the change: rebuilt from the old content, with the added entry",
                    o.ok() && lookup("extra.invalid").equals(EXTRA) && lookup().equals(ANSWER));
            check("  and the log says the text differs; the text stayed as it was",
                    String.join("\n", log).contains(I18n.tr("server.maps.textDiffers", Map.of("table", label, "why", String.valueOf(extra.textDiffers))))
                            && Files.readString(Path.of(SOURCE)).equals(TEXT));

            System.out.println("\n== A content kept aside that no longer matches ==");
            PostfixMaps.Before tampered = PostfixMaps.before();
            byte[] content = tampered.saved().get(name).content();
            content[0] = (byte) (content[0] == 'e' ? 'f' : 'e');
            log.clear();
            o = PostfixMaps.afterUpgrade(new PostfixMaps.Before(before, tampered.saved(), tampered.lost()), log::add);
            log.forEach(l -> System.out.println("       | " + l));
            check("it does not put it into use: an error naming it", !o.ok() && o.problem().contains("e2e-transport"));
            check("  and the map is the old one: both entries answer", lookup().equals(ANSWER) && lookup("extra.invalid").equals(EXTRA));
            check("  and no build file next to it", sh("ls " + SOURCE + ".panel-rebuild* 2>/dev/null").isBlank());

            System.out.println("\n== An entry added, and the content too big to keep ==");
            PostfixMaps.maxSavedBytes = 1;
            PostfixMaps.Before big = PostfixMaps.before();
            check("it is not kept: counted as lost, with the why (2 entries against 1)", big.saved().isEmpty()
                    && big.lost().getOrDefault(name, "").contains("2") && big.lost().getOrDefault(name, "").contains("1"));
            check("the card stops", PostfixMaps.planBlocker(plan("remove lmdb0")) != null);
            log.clear();
            o = PostfixMaps.afterUpgrade(new PostfixMaps.Before(before, big.saved(), big.lost()), log::add);
            check("if the library changes anyway: it does not regenerate it, an error naming it, and the entry stays",
                    !o.ok() && o.problem().contains("e2e-transport") && lookup("extra.invalid").equals(EXTRA));
            PostfixMaps.maxSavedBytes = budget;
        } finally {
            PostfixMaps.maxSavedBytes = budget;
            if (transportSet.isEmpty()) sh("postconf -X transport_maps"); else sh("postconf -e '" + transportSet + "'");
            if (verifySet.isEmpty()) sh("postconf -X address_verify_map"); else sh("postconf -e '" + verifySet + "'");
            sh("rm -f " + SOURCE + " " + SOURCE + ".lmdb " + CACHE + ".lmdb " + CACHE + ".lmdb-lock");
            sh("rm -f " + ORDER + " " + ORDER + ".db");
            sh("[ -f " + ALIASES_BACKUP + " ] && cp -p " + ALIASES_BACKUP + " /etc/aliases.db && rm -f " + ALIASES_BACKUP);
            sh("postfix reload");
            check("at the end: transport_maps and address_verify_map as before",
                    sh("postconf -n transport_maps").trim().equals(transportSet) && sh("postconf -n address_verify_map").trim().equals(verifySet));
            check("at the end: no test files", !Files.exists(Path.of(SOURCE)) && !Files.exists(Path.of(SOURCE + ".lmdb"))
                    && !Files.exists(Path.of(CACHE + ".lmdb")));
            check("at the end: Postfix runs", sh("postfix status; echo $?").trim().endsWith("0"));
            check("at the end: /etc/aliases.db as it was", sh("stat -f %m /etc/aliases.db").trim().equals(aliasesBefore)
                    && sh("postalias -q MAILER-DAEMON hash:/etc/aliases").trim().equals("postmaster"));
        }
        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        if (failures > 0) System.exit(1);
    }

    /** How many times Postfix was reloaded, according to the maillog (syslog writes with a short delay). */
    static int reloads() {
        return Integer.parseInt(sh("sleep 1; grep -c 'refreshing the Postfix mail system' /var/log/maillog").trim());
    }

    static String stat(String file) {
        return sh("stat -f '%Su:%Sg %Lp' " + file).trim();
    }

    static String lookup() {
        return lookup("example.invalid");
    }

    static String lookup(String key) {
        return sh("postmap -q " + key + " lmdb:" + SOURCE + " 2>/dev/null").trim();
    }

    static JSONObject plan(String... typeAndName) {
        JSONArray c = new JSONArray();
        for (String s : typeAndName) {
            String[] p = s.split(" ");
            c.put(new JSONObject().put("type", p[0]).put("name", p[1]).put("from", "1").put("to", "2"));
        }
        return new JSONObject().put("changes", c);
    }

    static String sh(String cmd) {
        return Shell.runShell(Duration.ofSeconds(120), cmd).output();
    }

    static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failures++;
    }
}
