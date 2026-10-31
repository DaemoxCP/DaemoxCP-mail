package org.mail_panel.system;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Le letture e le decisioni di PostfixMaps, senza Postfix: le uscite di postconf, ldd e
 * dynamicmaps.cf sono scritte qui, prese da quelle vere della VM (31/10/2026). Quello che Postfix fa
 * davvero con le mappe rigenerate lo misura PostfixMapsE2ETest sulla VM.
 *
 *   java -cp "tests:&lt;dir&gt;/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PostfixMapsTest
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
        System.out.println("\n== Le tabelle in uso, da postconf -x e -Px ==");
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
        check("trovate le quattro tabelle di tipo file (" + ts.size() + "), non mysql ne' valori vuoti",
                ts.size() == 4 && find(ts, "hash:/etc/aliases") != null && find(ts, "btree:/var/db/postfix/verify_cache") != null
                        && find(ts, "lmdb:/usr/local/etc/postfix/transport") != null && find(ts, "cdb:/usr/local/etc/postfix/senders") != null);
        check("gli alias si costruiscono con postalias (anche se nominati da due parametri, una volta sola)",
                find(ts, "hash:/etc/aliases").kind() == PostfixMaps.Kind.ALIAS);
        check("address_verify_map e' una cache: si cancella, non si rigenera",
                find(ts, "btree:/var/db/postfix/verify_cache").kind() == PostfixMaps.Kind.CACHE);
        check("proxy:lmdb: e' una mappa lmdb pubblica", find(ts, "lmdb:/usr/local/etc/postfix/transport").kind() == PostfixMaps.Kind.PUBLIC
                && find(ts, "lmdb:/usr/local/etc/postfix/transport").parameter().equals("transport_maps"));
        check("una mappa di master.cf (-P) conta, col nome del parametro", find(ts, "cdb:/usr/local/etc/postfix/senders") != null
                && find(ts, "cdb:/usr/local/etc/postfix/senders").parameter().equals("smtpd_sender_login_maps"));

        List<PostfixMaps.Table> inherited = PostfixMaps.tablesIn(
                "transport_maps = lmdb:/usr/local/etc/postfix/transport\n", "",
                "address_verify_transport_maps = lmdb:/usr/local/etc/postfix/transport\ntransport_maps = lmdb:/usr/local/etc/postfix/transport\n");
        check("una mappa ereditata (address_verify_transport_maps = $transport_maps) porta il nome del parametro scritto in main.cf",
                inherited.size() == 1 && inherited.get(0).parameter().equals("transport_maps"));

        // Misurato sulla VM: proxy_write_maps elenca le cache, e in -x viene prima di smtp_*.
        List<PostfixMaps.Table> proxied = PostfixMaps.tablesIn("", "",
                "address_verify_map = btree:/var/db/postfix/verify_cache\n"
                        + "proxy_read_maps = proxy:unix:passwd.byname hash:/etc/aliases lmdb:/usr/local/etc/postfix/transport\n"
                        + "proxy_write_maps = btree:/var/db/postfix/verify_cache btree:/var/db/postfix/smtp_scache\n"
                        + "smtp_tls_session_cache_database = btree:/var/db/postfix/smtp_scache\n");
        check("gli elenchi di proxymap non contano: una cache che vi compare resta una cache, col suo parametro",
                proxied.size() == 2 && find(proxied, "btree:/var/db/postfix/smtp_scache") != null
                        && find(proxied, "btree:/var/db/postfix/smtp_scache").kind() == PostfixMaps.Kind.CACHE
                        && find(proxied, "btree:/var/db/postfix/smtp_scache").parameter().equals("smtp_tls_session_cache_database"));
        List<PostfixMaps.Table> aliasAsMap = PostfixMaps.tablesIn("local_recipient_maps = hash:/etc/aliases\n", "",
                "alias_maps = hash:/etc/aliases\nlocal_recipient_maps = hash:/etc/aliases\n");
        check("hash:/etc/aliases scritta in local_recipient_maps resta un alias (postalias, non postmap)",
                aliasAsMap.size() == 1 && aliasAsMap.get(0).kind() == PostfixMaps.Kind.ALIAS
                        && aliasAsMap.get(0).parameter().equals("local_recipient_maps"));
        List<PostfixMaps.Table> union = PostfixMaps.tablesIn(
                "transport_maps = unionmap:{hash:/usr/local/etc/postfix/a, lmdb:/usr/local/etc/postfix/b}\n");
        check("le tabelle dentro unionmap:{...} contano", union.size() == 2
                && find(union, "hash:/usr/local/etc/postfix/a") != null && find(union, "lmdb:/usr/local/etc/postfix/b") != null);

        System.out.println("\n== Chi legge ogni tipo ==");
        String dm = "# commento\ncdb\t/usr/local/lib/postfix/postfix-cdb.so\tdict_cdb_open\tmkmap_cdb_open\n"
                + "lmdb\t/usr/local/lib/postfix/postfix-lmdb.so\tdict_lmdb_open\tmkmap_lmdb_open\n"
                + "mysql\t/usr/local/lib/postfix/postfix-mysql.so\tdict_mysql_open\n";
        Map<String, String> plugins = PostfixMaps.pluginsFrom(dm);
        check("dynamicmaps: lmdb e cdb coi loro moduli, mysql no (non e' un file)",
                plugins.equals(Map.of("cdb", "/usr/local/lib/postfix/postfix-cdb.so", "lmdb", "/usr/local/lib/postfix/postfix-lmdb.so")));
        String lddLmdb = "/usr/local/lib/postfix/postfix-lmdb.so:\n"
                + "\tliblmdb.so.0 => /usr/local/lib/liblmdb.so.0 (0x509c2c891000)\n"
                + "\tlibc.so.7 => /lib/libc.so.7 (0x509c2b200000)\n\tlibthr.so.3 => /lib/libthr.so.3 (0x1)\n";
        List<String[]> libs = PostfixMaps.librariesFrom(lddLmdb, false);
        check("ldd del modulo lmdb: solo liblmdb.so.0, la libc e' del sistema base",
                libs.size() == 1 && libs.get(0)[0].equals("liblmdb.so.0") && libs.get(0)[1].equals("/usr/local/lib/liblmdb.so.0"));
        String lddUtil = "\tlibicuuc.so.76 => /usr/local/lib/libicuuc.so.76 (0x1)\n\tlibssl.so.35 => /usr/lib/libssl.so.35 (0x2)\n"
                + "\tlibc.so.7 => /lib/libc.so.7 (0x3)\n";
        check("libpostfix-util senza libdb: hash e btree vengono dalla libc (nessuna libreria di pacchetto)",
                PostfixMaps.librariesFrom(lddUtil, true).isEmpty());
        check("  e con un Berkeley DB di pacchetto lo si vede", PostfixMaps.librariesFrom(
                lddUtil + "\tlibdb-18.1.so => /usr/local/lib/db18/libdb-18.1.so (0x4)\n", true).size() == 1);
        PostfixMaps.Reader r = new PostfixMaps.Reader("lmdb", "/usr/local/lib/postfix/postfix-lmdb.so", "postfix-mysql",
                List.of(new PostfixMaps.Lib("liblmdb.so.0", "/usr/local/lib/liblmdb.so.0", "lmdb0")));
        check("la firma di un tipo: libreria, percorso, pacchetto", r.signature().equals("liblmdb.so.0=/usr/local/lib/liblmdb.so.0(lmdb0)"));
        check("  e un tipo del sistema base ha la firma «base»",
                new PostfixMaps.Reader("hash", "x", "postfix-mysql", List.of()).signature().equals("base"));

        System.out.println("\n== Cosa e' cambiato ==");
        Map<String, String> before = Map.of("lmdb", "liblmdb.so.0=/usr/local/lib/liblmdb.so.0(lmdb0)", "hash", "base",
                "cdb", "libcdb.so.1=/usr/local/lib/libcdb.so.1(tinycdb)");
        check("niente di cambiato: nessun tipo", PostfixMaps.changed(before, before).isEmpty());
        check("lmdb passa a LMDB 1.0: cambia solo lmdb", PostfixMaps.changed(before, Map.of("lmdb",
                "liblmdb.so.1=/usr/local/lib/liblmdb.so.1(lmdb)", "hash", "base", "cdb", "libcdb.so.1=/usr/local/lib/libcdb.so.1(tinycdb)"))
                .equals(Set.of("lmdb")));
        check("un tipo che sparisce (modulo tolto) conta come cambiato", PostfixMaps.changed(before, Map.of("hash", "base",
                "cdb", "libcdb.so.1=/usr/local/lib/libcdb.so.1(tinycdb)")).equals(Set.of("lmdb")));

        System.out.println("\n== La prima chiave del testo ==");
        check("una mappa: la prima riga che non e' commento", PostfixMaps.firstKey("# trasporti\n\nexample.org  smtp:[10.0.0.1]\n", false)
                .equals("example.org"));
        check("gli alias: il nome prima dei due punti, saltando le continuazioni",
                PostfixMaps.firstKey("# alias\n\troot: x\nMAILER-DAEMON: postmaster\n", true).equals("MAILER-DAEMON"));
        check("un testo senza chiavi: nessuna", PostfixMaps.firstKey("# solo commenti\n\n", false).isEmpty());
        check("una voce senza valore (postmap la salta con un avviso) non e' la prima chiave",
                PostfixMaps.firstKey("example.invalid\nsecond.invalid smtp:x\n", false).equals("second.invalid"));
        check("una voce col valore sulla riga dopo (continuazione) e' una voce",
                PostfixMaps.firstKey("third.invalid\n  smtp:y\n", false).equals("third.invalid"));
        check("un alias col valore sulla riga dopo e' un alias, uno senza valore no",
                PostfixMaps.firstKey("nobody:\nroot:\n\tadmin\n", true).equals("root"));

        System.out.println("\n== La previsione dal piano ==");
        List<PostfixMaps.Reader> readers = List.of(r, new PostfixMaps.Reader("hash", "/usr/local/lib/postfix/libpostfix-util.so",
                "postfix-mysql", List.of()));
        java.util.function.Function<String, Set<String>> provides0 = p -> p.equals("lmdb0") ? Set.of("liblmdb.so.0") : Set.of();
        java.util.function.Function<String, Set<String>> requires0 = p -> Set.of("liblmdb.so.0", "libc.so.7");
        check("il piano toglie lmdb0: cambia lmdb",
                PostfixMaps.typesThePlanMayChange(plan("remove lmdb0"), readers, provides0, requires0).equals(Set.of("lmdb")));
        check("aggiorna lmdb0 e la versione nuova fornisce ancora liblmdb.so.0: niente",
                PostfixMaps.typesThePlanMayChange(plan("upgrade lmdb0"), readers, provides0, requires0).isEmpty());
        check("aggiorna lmdb0 e la versione nuova fornisce liblmdb.so.1: cambia lmdb",
                PostfixMaps.typesThePlanMayChange(plan("upgrade lmdb0"), readers, p -> Set.of("liblmdb.so.1"), requires0).equals(Set.of("lmdb")));
        check("aggiorna Postfix e la versione nuova chiede ancora liblmdb.so.0: niente",
                PostfixMaps.typesThePlanMayChange(plan("upgrade postfix-mysql"), readers, provides0, requires0).isEmpty());
        check("aggiorna Postfix e la versione nuova chiede liblmdb.so.1 (il passaggio a LMDB 1.0, senza rimozioni): cambia lmdb",
                PostfixMaps.typesThePlanMayChange(plan("upgrade postfix-mysql", "install lmdb"), readers, provides0,
                        p -> Set.of("liblmdb.so.1")).equals(Set.of("lmdb")));
        check("hash viene dal sistema base: nessun piano lo cambia",
                !PostfixMaps.typesThePlanMayChange(plan("remove lmdb0", "upgrade postfix-mysql"), readers, p -> Set.of(), p -> Set.of())
                        .contains("hash"));
        check("un piano che non tocca ne' Postfix ne' le sue librerie: niente",
                PostfixMaps.typesThePlanMayChange(plan("upgrade nginx"), readers, provides0, requires0).isEmpty());

        System.out.println(failures == 0 ? "\nTUTTO OK" : "\n" + failures + " PROVE FALLITE");
        if (failures > 0) System.exit(1);
    }
}
