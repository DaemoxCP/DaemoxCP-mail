package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * PostfixMaps's reads and decisions, without Postfix: the outputs of postconf, ldd and
 * dynamicmaps.cf are written here, taken from the real ones of the VM (31/10/2026). What Postfix
 * really does with the regenerated maps is measured by PostfixMapsE2ETest on the VM.
 *
 *   java -cp "tests:&lt;dir&gt;/freebsd-mail-panel-1.0.jar" org.daemoxcp.mail.system.PostfixMapsTest
 */
public class PostfixMapsTest {

    private static int failures = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + what);
        if (!ok) failures++;
    }

    static PostfixMaps.Table find(List<PostfixMaps.Table> ts, String name) {
        for (PostfixMaps.Table t : ts) if (t.name().equals(name)) return t;
        return null;
    }

    static JSONObject plan(String... typeAndName) {
        JSONArray c = new JSONArray();
        for (String s : typeAndName) {
            String[] p = s.split(" ");
            c.put(new JSONObject().put("type", p[0]).put("name", p[1]).put("from", "1").put("to", "2"));
        }
        return new JSONObject().put("changes", c);
    }

    public static void main(String[] args) {
        System.out.println("\n== The tables in use, from postconf -x and -Px ==");
        String postconf = "alias_database = hash:/etc/aliases\n"
                + "alias_maps = hash:/etc/aliases\n"
                + "address_verify_map = btree:/var/db/postfix/verify_cache\n"
                + "transport_maps = proxy:lmdb:/usr/local/etc/postfix/transport, proxy:mysql:/usr/local/etc/postfix/mysql-transport.cf\n"
                + "virtual_alias_maps = proxy:mysql:/usr/local/etc/postfix/mysql-virtual.cf\n"
                + "smtpd_tls_session_cache_database = \n"
                + "relay_domains = $mydestination\n";
        String master = "submission/inet/smtpd_sender_login_maps = cdb:/usr/local/etc/postfix/senders\n"
                + "submission/inet/syslog_name = postfix/submission\n";
        List<PostfixMaps.Table> ts = PostfixMaps.tablesIn(postconf, master);
        check("the four file-type tables found (" + ts.size() + "), not mysql nor empty values",
                ts.size() == 4 && find(ts, "hash:/etc/aliases") != null && find(ts, "btree:/var/db/postfix/verify_cache") != null
                        && find(ts, "lmdb:/usr/local/etc/postfix/transport") != null && find(ts, "cdb:/usr/local/etc/postfix/senders") != null);
        check("the aliases are built with postalias (even if named by two parameters, only once)",
                find(ts, "hash:/etc/aliases").kind() == PostfixMaps.Kind.ALIAS);
        check("address_verify_map is a cache: it is deleted, not regenerated",
                find(ts, "btree:/var/db/postfix/verify_cache").kind() == PostfixMaps.Kind.CACHE);
        check("proxy:lmdb: is a public lmdb map", find(ts, "lmdb:/usr/local/etc/postfix/transport").kind() == PostfixMaps.Kind.PUBLIC
                && find(ts, "lmdb:/usr/local/etc/postfix/transport").parameter().equals("transport_maps"));
        check("a master.cf map (-P) counts, with the parameter's name", find(ts, "cdb:/usr/local/etc/postfix/senders") != null
                && find(ts, "cdb:/usr/local/etc/postfix/senders").parameter().equals("smtpd_sender_login_maps"));

        List<PostfixMaps.Table> inherited = PostfixMaps.tablesIn(
                "transport_maps = lmdb:/usr/local/etc/postfix/transport\n", "",
                "address_verify_transport_maps = lmdb:/usr/local/etc/postfix/transport\ntransport_maps = lmdb:/usr/local/etc/postfix/transport\n");
        check("an inherited map (address_verify_transport_maps = $transport_maps) carries the name of the parameter written in main.cf",
                inherited.size() == 1 && inherited.get(0).parameter().equals("transport_maps"));

        // Measured on the VM: proxy_write_maps lists the caches, and in -x it comes before smtp_*.
        List<PostfixMaps.Table> proxied = PostfixMaps.tablesIn("", "",
                "address_verify_map = btree:/var/db/postfix/verify_cache\n"
                        + "proxy_read_maps = proxy:unix:passwd.byname hash:/etc/aliases lmdb:/usr/local/etc/postfix/transport\n"
                        + "proxy_write_maps = btree:/var/db/postfix/verify_cache btree:/var/db/postfix/smtp_scache\n"
                        + "smtp_tls_session_cache_database = btree:/var/db/postfix/smtp_scache\n");
        check("proxymap's lists do not count: a cache that appears in them stays a cache, with its parameter",
                proxied.size() == 2 && find(proxied, "btree:/var/db/postfix/smtp_scache") != null
                        && find(proxied, "btree:/var/db/postfix/smtp_scache").kind() == PostfixMaps.Kind.CACHE
                        && find(proxied, "btree:/var/db/postfix/smtp_scache").parameter().equals("smtp_tls_session_cache_database"));
        List<PostfixMaps.Table> aliasAsMap = PostfixMaps.tablesIn("local_recipient_maps = hash:/etc/aliases\n", "",
                "alias_maps = hash:/etc/aliases\nlocal_recipient_maps = hash:/etc/aliases\n");
        check("hash:/etc/aliases written in local_recipient_maps stays an alias (postalias, not postmap)",
                aliasAsMap.size() == 1 && aliasAsMap.get(0).kind() == PostfixMaps.Kind.ALIAS
                        && aliasAsMap.get(0).parameter().equals("local_recipient_maps"));
        List<PostfixMaps.Table> union = PostfixMaps.tablesIn(
                "transport_maps = unionmap:{hash:/usr/local/etc/postfix/a, lmdb:/usr/local/etc/postfix/b}\n");
        check("the tables inside unionmap:{...} count", union.size() == 2
                && find(union, "hash:/usr/local/etc/postfix/a") != null && find(union, "lmdb:/usr/local/etc/postfix/b") != null);

        System.out.println("\n== Who reads each type ==");
        String dm = "# comment\ncdb\t/usr/local/lib/postfix/postfix-cdb.so\tdict_cdb_open\tmkmap_cdb_open\n"
                + "lmdb\t/usr/local/lib/postfix/postfix-lmdb.so\tdict_lmdb_open\tmkmap_lmdb_open\n"
                + "mysql\t/usr/local/lib/postfix/postfix-mysql.so\tdict_mysql_open\n";
        Map<String, String> plugins = PostfixMaps.pluginsFrom(dm);
        check("dynamicmaps: lmdb and cdb with their modules, mysql not (it is not a file)",
                plugins.equals(Map.of("cdb", "/usr/local/lib/postfix/postfix-cdb.so", "lmdb", "/usr/local/lib/postfix/postfix-lmdb.so")));
        String lddLmdb = "/usr/local/lib/postfix/postfix-lmdb.so:\n"
                + "\tliblmdb.so.0 => /usr/local/lib/liblmdb.so.0 (0x509c2c891000)\n"
                + "\tlibc.so.7 => /lib/libc.so.7 (0x509c2b200000)\n\tlibthr.so.3 => /lib/libthr.so.3 (0x1)\n";
        List<String[]> libs = PostfixMaps.librariesFrom(lddLmdb, false);
        check("ldd of the lmdb module: only liblmdb.so.0, libc belongs to the base system",
                libs.size() == 1 && libs.get(0)[0].equals("liblmdb.so.0") && libs.get(0)[1].equals("/usr/local/lib/liblmdb.so.0"));
        String lddUtil = "\tlibicuuc.so.76 => /usr/local/lib/libicuuc.so.76 (0x1)\n\tlibssl.so.35 => /usr/lib/libssl.so.35 (0x2)\n"
                + "\tlibc.so.7 => /lib/libc.so.7 (0x3)\n";
        check("libpostfix-util without libdb: hash and btree come from libc (no package library)",
                PostfixMaps.librariesFrom(lddUtil, true).isEmpty());
        check("  and with a package Berkeley DB it can be seen", PostfixMaps.librariesFrom(
                lddUtil + "\tlibdb-18.1.so => /usr/local/lib/db18/libdb-18.1.so (0x4)\n", true).size() == 1);
        PostfixMaps.Reader r = new PostfixMaps.Reader("lmdb", "/usr/local/lib/postfix/postfix-lmdb.so", "postfix-mysql",
                List.of(new PostfixMaps.Lib("liblmdb.so.0", "/usr/local/lib/liblmdb.so.0", "lmdb0")));
        check("a type's signature: library, path, package", r.signature().equals("liblmdb.so.0=/usr/local/lib/liblmdb.so.0(lmdb0)"));
        check("  and a base system type has the signature \"base\"",
                new PostfixMaps.Reader("hash", "x", "postfix-mysql", List.of()).signature().equals("base"));

        System.out.println("\n== What changed ==");
        Map<String, String> before = Map.of("lmdb", "liblmdb.so.0=/usr/local/lib/liblmdb.so.0(lmdb0)", "hash", "base",
                "cdb", "libcdb.so.1=/usr/local/lib/libcdb.so.1(tinycdb)");
        check("nothing changed: no type", PostfixMaps.changed(before, before).isEmpty());
        check("lmdb moves to LMDB 1.0: only lmdb changes", PostfixMaps.changed(before, Map.of("lmdb",
                "liblmdb.so.1=/usr/local/lib/liblmdb.so.1(lmdb)", "hash", "base", "cdb", "libcdb.so.1=/usr/local/lib/libcdb.so.1(tinycdb)"))
                .equals(Set.of("lmdb")));
        check("a type that vanishes (module removed) counts as changed", PostfixMaps.changed(before, Map.of("hash", "base",
                "cdb", "libcdb.so.1=/usr/local/lib/libcdb.so.1(tinycdb)")).equals(Set.of("lmdb")));

        System.out.println("\n== The first key of the text ==");
        check("a map: the first line that is not a comment", PostfixMaps.firstKey("# transports\n\nexample.org  smtp:[10.0.0.1]\n", false)
                .equals("example.org"));
        check("the aliases: the name before the colon, skipping the continuations",
                PostfixMaps.firstKey("# alias\n\troot: x\nMAILER-DAEMON: postmaster\n", true).equals("MAILER-DAEMON"));
        check("a text without keys: none", PostfixMaps.firstKey("# comments only\n\n", false).isEmpty());
        check("an entry without a value (postmap skips it with a warning) is not the first key",
                PostfixMaps.firstKey("example.invalid\nsecond.invalid smtp:x\n", false).equals("second.invalid"));
        check("an entry with the value on the next line (continuation) is an entry",
                PostfixMaps.firstKey("third.invalid\n  smtp:y\n", false).equals("third.invalid"));
        check("an alias with the value on the next line is an alias, one without a value is not",
                PostfixMaps.firstKey("nobody:\nroot:\n\tadmin\n", true).equals("root"));

        System.out.println("\n== The forecast from the plan ==");
        List<PostfixMaps.Reader> readers = List.of(r, new PostfixMaps.Reader("hash", "/usr/local/lib/postfix/libpostfix-util.so",
                "postfix-mysql", List.of()));
        java.util.function.Function<String, Set<String>> provides0 = p -> p.equals("lmdb0") ? Set.of("liblmdb.so.0") : Set.of();
        java.util.function.Function<String, Set<String>> requires0 = p -> Set.of("liblmdb.so.0", "libc.so.7");
        check("the plan removes lmdb0: lmdb changes",
                PostfixMaps.typesThePlanMayChange(plan("remove lmdb0"), readers, provides0, requires0).equals(Set.of("lmdb")));
        check("it upgrades lmdb0 and the new version still provides liblmdb.so.0: nothing",
                PostfixMaps.typesThePlanMayChange(plan("upgrade lmdb0"), readers, provides0, requires0).isEmpty());
        check("it upgrades lmdb0 and the new version provides liblmdb.so.1: lmdb changes",
                PostfixMaps.typesThePlanMayChange(plan("upgrade lmdb0"), readers, p -> Set.of("liblmdb.so.1"), requires0).equals(Set.of("lmdb")));
        check("it upgrades Postfix and the new version still requires liblmdb.so.0: nothing",
                PostfixMaps.typesThePlanMayChange(plan("upgrade postfix-mysql"), readers, provides0, requires0).isEmpty());
        check("it upgrades Postfix and the new version requires liblmdb.so.1 (the move to LMDB 1.0, without removals): lmdb changes",
                PostfixMaps.typesThePlanMayChange(plan("upgrade postfix-mysql", "install lmdb"), readers, provides0,
                        p -> Set.of("liblmdb.so.1")).equals(Set.of("lmdb")));
        check("hash comes from the base system: no plan changes it",
                !PostfixMaps.typesThePlanMayChange(plan("remove lmdb0", "upgrade postfix-mysql"), readers, p -> Set.of(), p -> Set.of())
                        .contains("hash"));
        check("a plan that touches neither Postfix nor its libraries: nothing",
                PostfixMaps.typesThePlanMayChange(plan("upgrade nginx"), readers, provides0, requires0).isEmpty());

        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        if (failures > 0) System.exit(1);
    }
}
