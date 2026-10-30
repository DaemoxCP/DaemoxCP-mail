package org.mail_panel.system;

import org.json.JSONArray;
import org.json.JSONObject;

import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Le versioni del software nella Home (SoftwareVersions).
 *
 * Un sistema finto risponde con le uscite VERE dei programmi su FreeBSD (postconf, dovecot,
 * rspamd, redis-server, nginx, php-fpm, openssl, freebsd-version, clamd, mysqld, pkg which,
 * pkg query): si controlla che ogni versione si riconosca, che il pacchetto si trovi dal binario
 * anche quando si chiama postfix-mysql, e che "da riavviare" compaia quando e solo quando si sa
 * (processo partito prima dell'installazione del pacchetto, o che risponde con un'altra versione).
 * Poi i casi storti: clamd che non risponde, firme vecchie, MySQL irraggiungibile, programmi che
 * rispondono altro, testo che non e' una versione. Infine il socket di clamd vero, con un demone
 * finto che risponde e uno che resta muto (la lettura deve arrendersi in tre secondi).
 *
 * Uso: java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.SoftwareVersionsTest
 * Con un MySQL di prova legge anche la versione dal server vero (solo letture):
 *   -Dmysql.port=33062 -Dmysql.utente=mailpanel -Dmysql.password=... -Dmysql.database=mailpanel_prova
 */
public class SoftwareVersionsTest {

    static int failed = 0;

    static void real(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FALLITO ") + what);
        if (!ok) failed++;
    }

    static final ZoneId ROME = ZoneId.of("Europe/Rome");

    /** Un server finto: file che esistono, uscite dei comandi, pidfile e ore di avvio. */
    static class FakeSystem implements SoftwareVersions.SystemAccess {
        final Set<String> file = new HashSet<>();
        final Map<String, String> outputs = new HashMap<>();
        final Map<String, String> contents = new HashMap<>();
        final Map<Long, Instant> processes = new HashMap<>();
        final java.util.List<String> launched = new java.util.ArrayList<>();
        String clamd, mysql, java = "25.0.1+8-1", javaFolder = "/usr/local/openjdk25";
        Instant now = Instant.parse("2026-10-03T12:00:00Z");

        public String run(String... argv) {
            String k = String.join(" ", argv);
            launched.add(k);
            if (k.startsWith(SoftwareVersions.PKG + " which ")) return outputs.get("pkg which");
            return outputs.get(k);
        }
        public boolean exists(String p) { return file.contains(p); }
        public String read(String p) { return contents.get(p); }
        public String askClamd2() { return clamd; }
        public String mysqlVersion() { return mysql; }
        public Instant startup(long pid) { return processes.get(pid); }
        public String javaVersion() { return java; }
        public String javaFolder() { return javaFolder; }
        public Instant now() { return now; }
        public ZoneId zone() { return ROME; }
    }

    static long epoch(String iso) { return Instant.parse(iso).getEpochSecond(); }

    /** Un server di posta completo come lo installa il pannello, con qualche servizio da riavviare. */
    static FakeSystem complete() {
        FakeSystem f = new FakeSystem();
        f.file.addAll(Arrays.asList(SoftwareVersions.PKG, "/usr/local/sbin/postconf", "/usr/local/sbin/dovecot",
                "/usr/local/bin/rspamd", "/usr/local/bin/redis-server", SoftwareVersions.CLAMD, SoftwareVersions.MYSQLD,
                "/usr/local/www/roundcube/index.php", "/usr/local/sbin/nginx", "/usr/local/sbin/php-fpm", "/usr/local/bin/sievec",
                "/usr/local/bin/fail2ban-client", "/usr/sbin/local-unbound", SoftwareVersions.OPENSSL_BASE,
                SoftwareVersions.FREEBSD_VERSION, "/usr/local/openjdk25/bin/java"));
        // pkg which: un file che nessun pacchetto possiede (local-unbound e' del sistema base).
        f.outputs.put("pkg which", String.join("\n",
                "/usr/local/sbin/postconf was installed by package postfix-mysql-3.10.4,1",
                "/usr/local/sbin/dovecot was installed by package dovecot-mysql-2.3.21.1_8",
                "/usr/local/bin/rspamd was installed by package rspamd-3.12.1",
                "/usr/local/bin/redis-server was installed by package redis-7.4.2",
                "/usr/local/sbin/clamd was installed by package clamav-1.4.3,1",
                "/usr/local/libexec/mysqld was installed by package mysql80-server-8.0.43",
                "/usr/local/www/roundcube/index.php was installed by package roundcube-php84-1.6.11,1",
                "/usr/local/sbin/nginx was installed by package nginx-1.28.0_3,3",
                "/usr/local/sbin/php-fpm was installed by package php84-8.4.13",
                "/usr/local/bin/sievec was installed by package dovecot-pigeonhole-0.5.21.1_1",
                "/usr/local/bin/fail2ban-client was installed by package py311-fail2ban-1.1.0_3",
                "/usr/sbin/local-unbound was not found in the database",
                "/usr/local/openjdk25/bin/java was installed by package openjdk25-25.0.1+8.1", ""));
        f.outputs.put(SoftwareVersions.PKG + " query %n %t", String.join("\n",
                "postfix-mysql " + epoch("2026-10-02T07:00:00Z"),
                "dovecot-mysql " + epoch("2026-09-20T07:00:00Z"),
                "rspamd " + epoch("2026-09-20T07:00:00Z"),
                "redis " + epoch("2026-09-20T07:00:00Z"),
                "py311-fail2ban " + epoch("2026-09-01T07:00:00Z"),
                "php84 " + epoch("2026-10-02T07:00:00Z"), ""));
        f.outputs.put("/usr/local/sbin/postconf -h mail_version", "3.10.4\n");
        f.outputs.put("/usr/local/sbin/dovecot --version", "2.3.21.1 (d492236fa0)\n");
        f.outputs.put("/usr/local/bin/rspamd --version", "Rspamd daemon version 3.12.1\n\nCPU architecture amd64; features: avx2, avx, sse2, sse3, ssse3, sse4.1, sse4.2, rdrand\n"
                + "Hyperscan enabled: TRUE\nJemalloc enabled: FALSE\nLuaJIT enabled: TRUE (LuaJIT version: LuaJIT 2.1.1736781742)\n");
        f.outputs.put("/usr/local/bin/redis-server --version", "Redis server v=7.4.2 sha=00000000:0 malloc=libc bits=64 build=7b2f3e4c3d2a1b0c\n");
        f.outputs.put("/usr/local/sbin/nginx -v", "nginx version: nginx/1.28.0\n");
        f.outputs.put("/usr/local/sbin/php-fpm -v", "PHP 8.4.13 (fpm-fcgi) (built: Sep 25 2025 01:23:45)\nCopyright (c) The PHP Group\nZend Engine v4.4.13, Copyright (c) Zend Technologies\n");
        f.outputs.put("/usr/sbin/local-unbound -V", "Version 1.22.0\n\nConfigure line: --with-ssl=/usr --with-libexpat=/usr\nLinked libs: libevent 2.1.12-stable (it uses kqueue), OpenSSL 3.5.1 1 Jul 2025\n");
        f.outputs.put(SoftwareVersions.OPENSSL_BASE + " version", "OpenSSL 3.5.1 1 Jul 2025\n");
        f.outputs.put(SoftwareVersions.FREEBSD_VERSION + " -u", "15.0-RELEASE-p3\n");
        f.outputs.put(SoftwareVersions.FREEBSD_VERSION + " -r", "15.0-RELEASE-p2\n");
        f.outputs.put(SoftwareVersions.FREEBSD_VERSION + " -k", "15.0-RELEASE-p3\n");
        f.contents.put("/usr/local/www/roundcube/program/include/iniset.php",
                "<?php\n\n// application constants\ndefine('RCMAIL_VERSION', '1.6.11');\ndefine('RCMAIL_START', microtime(true));\n");
        // Postfix: partito prima dell'aggiornamento del 02/10. Dovecot: dopo l'ultima installazione.
        // Rspamd: nessun pidfile. Redis: pidfile di un processo che non c'e' piu'. PHP-FPM: partito
        // prima del suo pacchetto, ma per lui l'ora di avvio non dice niente (reload).
        f.contents.put("/var/spool/postfix/pid/master.pid", "        812\n");
        f.processes.put(812L, Instant.parse("2026-09-28T06:15:00Z"));
        f.contents.put("/var/run/dovecot/master.pid", "901\n");
        f.processes.put(901L, Instant.parse("2026-09-21T08:00:00Z"));
        f.contents.put("/var/run/redis/redis.pid", "1203\n");
        f.contents.put("/var/run/php-fpm.pid", "1300\n");
        f.processes.put(1300L, Instant.parse("2026-09-01T08:00:00Z"));
        f.contents.put("/var/run/fail2ban/fail2ban.pid", "1400\n");
        f.processes.put(1400L, Instant.parse("2026-09-02T08:00:00Z"));
        f.contents.put(SoftwareVersions.PIDFILE_LOCAL_UNBOUND, "700\n");
        f.processes.put(700L, Instant.parse("2026-09-01T05:00:00Z"));
        f.clamd = "ClamAV 1.4.3/27780/Fri Oct  2 08:24:28 2026";
        f.mysql = "8.0.42";
        return f;
    }

    static JSONObject other(JSONObject r, String key) {
        JSONArray a = r.getJSONArray("altro");
        for (int i = 0; i < a.length(); i++) if (a.getJSONObject(i).getString("chiave").equals(key)) return a.getJSONObject(i);
        return null;
    }

    public static void main(String[] args) throws Exception {
        System.out.println("\n== Le parti: pacchetti, versioni, pid, clamd ==");
        real("versione del programma dal pacchetto: postfix-mysql-3.10.4,1 -> 3.10.4",
                SoftwareVersions.upstream("postfix-mysql-3.10.4,1").equals("3.10.4"));
        real("senza revisione del port: dovecot-mysql-2.3.21.1_8 -> 2.3.21.1",
                SoftwareVersions.upstream("dovecot-mysql-2.3.21.1_8").equals("2.3.21.1"));
        real("revisione ed epoca insieme: roundcube-php84-1.6.11_1,1 -> 1.6.11",
                SoftwareVersions.upstream("roundcube-php84-1.6.11_1,1").equals("1.6.11"));
        real("nome con trattini: roundcube-php84-1.6.11,1 -> roundcube-php84",
                SoftwareVersions.name("roundcube-php84-1.6.11,1").equals("roundcube-php84"));
        real("parte numerica per confrontare: 8.0.43-debug -> 8.0.43, 25.0.1+8-LTS -> 25.0.1",
                SoftwareVersions.numbers("8.0.43-debug").equals("8.0.43") && SoftwareVersions.numbers("25.0.1+8-LTS").equals("25.0.1")
                && SoftwareVersions.numbers("abc").isEmpty());
        real("pidfile di Postfix (allineato a destra): 812", Long.valueOf(812).equals(SoftwareVersions.pid("        812\n")));
        real("pidfile non validi: testo, 1 (init), 0, undici cifre",
                SoftwareVersions.pid("abc") == null && SoftwareVersions.pid("1") == null && SoftwareVersions.pid("0") == null
                && SoftwareVersions.pid("12345678901") == null && SoftwareVersions.pid(null) == null);
        SoftwareVersions.Clamd c = SoftwareVersions.clamd("ClamAV 1.4.3/27780/Fri Oct  2 08:24:28 2026", ROME);
        real("clamd: motore, firme e data (giorno a una cifra, due spazi)", c != null && c.engine().equals("1.4.3")
                && c.signatures().equals("27780") && c.del().equals(Instant.parse("2026-10-02T06:24:28Z")));
        c = SoftwareVersions.clamd("ClamAV 1.4.3/27791/Mon Oct 12 18:01:02 2026", ROME);
        real("clamd: giorno a due cifre", c != null && c.del().equals(Instant.parse("2026-10-12T16:01:02Z")));
        c = SoftwareVersions.clamd("ClamAV 1.0.9", ROME);
        real("clamd senza firme caricate: solo il motore", c != null && c.engine().equals("1.0.9") && c.signatures() == null && c.del() == null);
        real("risposta che non e' di clamd: niente", SoftwareVersions.clamd("ERROR: unknown command", ROME) == null);
        Map<String, String> p = SoftwareVersions.owners("/a/b was installed by package uno-1.0\n/c was not found in the database\n"
                + "/d was installed by package due due-1.0\n/e was installed by package <script>-1\n");
        real("pkg which: solo le righe valide (" + p + ")", p.size() == 1 && "uno-1.0".equals(p.get("/a/b")));
        Map<String, Long> t = SoftwareVersions.installs("rspamd 1790000000\nrotta\nnginx abc\n");
        real("pkg query %n %t: nome e secondi", t.size() == 1 && t.get("rspamd") == 1790000000L);
        real("una versione non si accetta se ha spazi o simboli", SoftwareVersions.validate("1.2 3") == null
                && SoftwareVersions.validate("<b>1</b>") == null && SoftwareVersions.validate("3.10.4").equals("3.10.4"));

        System.out.println("\n== Server completo, con qualcosa da riavviare ==");
        FakeSystem f = complete();
        JSONObject r = SoftwareVersions.read(f);
        JSONObject s = r.getJSONObject("servizi");
        real("letteAlle con i secondi anche quando sono zero, nell'ora del server: " + r.getString("letteAlle"),
                r.getString("letteAlle").equals("2026-10-03T14:00:00+02:00"));
        long pkgCalls = f.launched.stream().filter(x -> x.startsWith(SoftwareVersions.PKG)).count();
        real("pkg si chiama due volte in tutto (which e query), non una per programma: " + pkgCalls, pkgCalls == 2);
        JSONObject pf = s.getJSONObject("postfix");
        real("Postfix: 3.10.4 da postconf, pacchetto postfix-mysql (non \"postfix\")", pf.getString("versione").equals("3.10.4")
                && pf.getString("pacchetto").equals("postfix-mysql-3.10.4,1") && pf.getString("fonte").contains("mail_version"));
        real("Postfix partito il 28/09, pacchetto installato il 02/10: da riavviare, con le due date: " + pf.optString("notaRiavvio"),
                pf.optBoolean("riavvio") && pf.getString("notaRiavvio").contains("28/09/2026 08:15")
                && pf.getString("notaRiavvio").contains("02/10/2026 09:00"));
        JSONObject dv = s.getJSONObject("dovecot");
        real("Dovecot: 2.3.21.1, partito dopo l'installazione: niente da riavviare", dv.getString("versione").equals("2.3.21.1")
                && !dv.optBoolean("riavvio") && dv.getString("pacchetto").equals("dovecot-mysql-2.3.21.1_8"));
        JSONObject my = s.getJSONObject("mysql");
        real("MySQL: la versione in esecuzione (8.0.42), non quella del pacchetto", my.getString("versione").equals("8.0.42")
                && my.optBoolean("inEsecuzione") && my.getString("fonte").startsWith("SELECT VERSION()"));
        real("MySQL: il pacchetto e' la 8.0.43, quindi da riavviare: " + my.optString("notaRiavvio"), my.optBoolean("riavvio")
                && my.getString("installata").equals("8.0.43") && my.getString("notaRiavvio").contains("riavvia MySQL"));
        JSONObject rs = s.getJSONObject("rspamd");
        real("Rspamd: 3.12.1; senza pidfile non si dice niente sul riavvio", rs.getString("versione").equals("3.12.1") && !rs.has("riavvio"));
        JSONObject rd = s.getJSONObject("redis");
        real("Redis: 7.4.2; pidfile di un processo che non c'e' piu': niente sul riavvio", rd.getString("versione").equals("7.4.2") && !rd.has("riavvio"));
        JSONObject cl = s.getJSONObject("clamav");
        real("ClamAV: dal demone, motore 1.4.3, firme 27780 del 02/10/2026 08:24: " + cl.optString("dettaglio"),
                cl.getString("versione").equals("1.4.3") && cl.optBoolean("inEsecuzione")
                && cl.getString("dettaglio").equals("firme 27780 del 02/10/2026 08:24") && !cl.has("avviso") && !cl.has("riavvio"));
        JSONObject rc = s.getJSONObject("roundcube");
        real("Roundcube: 1.6.11 da RCMAIL_VERSION, pacchetto roundcube-php84", rc.getString("versione").equals("1.6.11")
                && rc.getString("fonte").contains("RCMAIL_VERSION") && rc.getString("pacchetto").equals("roundcube-php84-1.6.11,1"));

        JSONObject fb = other(r, "freebsd");
        real("FreeBSD: userland 15.0-RELEASE-p3, kernel in esecuzione p2 ma installato p3: riavvio del server",
                fb.getString("versione").equals("15.0-RELEASE-p3") && fb.getString("dettaglio").equals("kernel in esecuzione 15.0-RELEASE-p2")
                && fb.optBoolean("riavvio") && fb.getString("notaRiavvio").contains("riavvio del server"));
        JSONObject os = other(r, "openssl");
        real("OpenSSL del sistema base: 3.5.1, rilasciata il 01/07/2025", os.getString("versione").equals("3.5.1")
                && os.getString("dettaglio").equals("rilasciata il 01/07/2025"));
        real("nessuna OpenSSL da pacchetto, nessun Unbound da pacchetto: non compaiono", other(r, "openssl_pkg") == null && other(r, "unbound") == null);
        real("nginx 1.28.0", other(r, "nginx").getString("versione").equals("1.28.0"));
        JSONObject php = other(r, "php");
        real("PHP-FPM 8.4.13; partito prima del pacchetto ma per lui l'ora non vale (reload): niente sul riavvio",
                php.getString("versione").equals("8.4.13") && !php.has("riavvio"));
        JSONObject ph = other(r, "pigeonhole");
        real("Pigeonhole dal pacchetto: 0.5.21.1", ph.getString("versione").equals("0.5.21.1") && ph.getString("fonte").startsWith("pkg which"));
        JSONObject jv = other(r, "java");
        real("Java del pannello: 25.0.1+8-1 in esecuzione, uguale al pacchetto openjdk25", jv.getString("versione").equals("25.0.1+8-1")
                && jv.optBoolean("inEsecuzione") && jv.getString("pacchetto").equals("openjdk25-25.0.1+8.1") && !jv.has("riavvio"));
        JSONObject f2b = other(r, "fail2ban");
        real("fail2ban dal pacchetto: 1.1.0, partito dopo l'installazione", f2b != null && f2b.getString("versione").equals("1.1.0") && !f2b.has("riavvio"));
        JSONObject lu = other(r, "local_unbound");
        real("Unbound del sistema base, perche' gira: 1.22.0, senza pacchetto", lu != null && lu.getString("versione").equals("1.22.0") && !lu.has("pacchetto"));
        boolean noHtml = !r.toString().contains("<");
        real("niente HTML nella risposta", noHtml);

        System.out.println("\n== Server appena installato: niente ==");
        FakeSystem empty = new FakeSystem();
        empty.javaFolder = "/usr/local/openjdk25";
        r = SoftwareVersions.read(empty);
        s = r.getJSONObject("servizi");
        boolean allAbsent = true;
        for (String k : s.keySet()) allAbsent &= !s.getJSONObject(k).getBoolean("installato");
        real("i sette servizi ci sono tutti, come non installati: " + s.keySet(), s.length() == 7 && allAbsent);
        real("senza pkg non si chiama pkg", empty.launched.stream().noneMatch(x -> x.startsWith(SoftwareVersions.PKG)));
        real("Java c'e' sempre (e' quella che fa girare il pannello)", other(r, "java").getBoolean("installato"));
        real("fail2ban e Unbound non installati: non compaiono", other(r, "fail2ban") == null && other(r, "local_unbound") == null);

        System.out.println("\n== Casi storti ==");
        FakeSystem st = complete();
        st.clamd = null;
        st.outputs.put(SoftwareVersions.CLAMD + " --version", "ClamAV 1.4.3/27700/Mon Sep 14 08:00:00 2026\n");
        st.mysql = null;
        st.outputs.put(SoftwareVersions.MYSQLD + " --version", "/usr/local/libexec/mysqld  Ver 8.0.43 for FreeBSD15.0 on amd64 (Source distribution)\n");
        st.outputs.put("/usr/local/sbin/postconf -h mail_version", "postconf: fatal: open /usr/local/etc/postfix/main.cf: No such file or directory\n");
        st.outputs.put("/usr/local/sbin/dovecot --version", "<script>alert(1)</script>\n");
        st.outputs.put("pkg which", st.outputs.get("pkg which").replace("openjdk25-25.0.1+8.1", "openjdk25-25.0.2+10.1"));
        st.contents.put("/usr/local/www/roundcube/program/include/iniset.php", "<?php // senza costante\n");
        r = SoftwareVersions.read(st);
        s = r.getJSONObject("servizi");
        cl = s.getJSONObject("clamav");
        real("clamd non risponde: versione dal binario, non \"in esecuzione\"", cl.getString("versione").equals("1.4.3")
                && !cl.has("inEsecuzione") && cl.getString("fonte").endsWith("--version"));
        real("firme del 14/09 (19 giorni): avviso — " + cl.optString("avviso"), cl.optString("avviso").contains("19 giorni"));
        real("e senza demone non si confronta con il pacchetto", !cl.has("riavvio"));
        my = s.getJSONObject("mysql");
        real("MySQL non risponde: versione da mysqld --version, con l'avviso che non e' quella in esecuzione",
                my.getString("versione").equals("8.0.43") && !my.has("inEsecuzione") && my.optString("avviso").contains("non risponde"));
        pf = s.getJSONObject("postfix");
        real("postconf risponde con un errore: versione dal pacchetto (3.10.4)", pf.getString("versione").equals("3.10.4")
                && pf.getString("fonte").startsWith("pkg which"));
        dv = s.getJSONObject("dovecot");
        real("una risposta che non e' una versione non passa: si usa il pacchetto", dv.getString("versione").equals("2.3.21.1")
                && !r.toString().contains("script"));
        real("iniset.php senza la costante: Roundcube dal pacchetto", s.getJSONObject("roundcube").getString("versione").equals("1.6.11"));
        jv = other(r, "java");
        real("Java aggiornata (pacchetto 25.0.2) ma il pannello gira sulla 25.0.1: riavvia il pannello — " + jv.optString("notaRiavvio"),
                jv.optBoolean("riavvio") && jv.getString("notaRiavvio").contains("riavvia il pannello"));
        FakeSystem odd = complete();
        odd.javaFolder = "/usr/local/openjdk25/../../etc";
        r = SoftwareVersions.read(odd);
        real("java.home con \"..\": non si chiede a pkg", odd.launched.stream().noneMatch(x -> x.contains("..")));

        System.out.println("\n== Il socket di clamd, vero ==");
        Path folder = Files.createTempDirectory("clamd-prova");
        Path sock = folder.resolve("clamd.sock");
        real("nessun socket: niente, subito", SoftwareVersions.askClamd(sock) == null);
        try (ServerSocketChannel srv = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            srv.bind(UnixDomainSocketAddress.of(sock));
            Thread daemon = Thread.ofVirtual().start(() -> {
                try (SocketChannel ch = srv.accept()) {
                    ByteBuffer b = ByteBuffer.allocate(64);
                    ch.read(b);
                    String asked = new String(b.array(), 0, b.position(), StandardCharsets.US_ASCII);
                    String answer = asked.equals("zVERSION\0") ? "ClamAV 1.4.3/27780/Fri Oct  2 08:24:28 2026\0" : "ERROR\0";
                    ch.write(ByteBuffer.wrap(answer.getBytes(StandardCharsets.US_ASCII)));
                } catch (Exception ignored) { }
            });
            String answer = SoftwareVersions.askClamd(sock);
            daemon.join();
            real("clamd risponde a zVERSION: " + answer, "ClamAV 1.4.3/27780/Fri Oct  2 08:24:28 2026".equals(answer));

            Thread silent = Thread.ofVirtual().start(() -> {
                try (SocketChannel ch = srv.accept()) {
                    Thread.sleep(6000);
                } catch (Exception ignored) { }
            });
            long t0 = System.nanoTime();
            String nothing = SoftwareVersions.askClamd(sock);
            long ms = (System.nanoTime() - t0) / 1_000_000;
            real("clamd muto: si arrende in circa tre secondi (" + ms + " ms) e non dice niente", nothing == null && ms >= 2900 && ms < 4500);
            silent.interrupt();
        } finally {
            Files.deleteIfExists(sock);
            Files.deleteIfExists(folder);
        }

        System.out.println("\n== Il sistema vero, per quello che si puo' qui ==");
        SoftwareVersions.SystemAccess system = SoftwareVersions.real(() -> "8.0.46");
        real("un comando che non esiste: null", system.run("/nonesiste/davvero", "-v") == null);
        real("un comando che esce con errore: la sua uscita c'e' comunque", system.run("sh", "-c", "echo versione; exit 3").contains("versione"));
        real("l'ora di avvio di questo processo si legge", system.startup(ProcessHandle.current().pid()) != null);
        real("un pid che non c'e': null", system.startup(999_999_999L) == null);
        real("la Java di questo processo: " + system.javaVersion(), system.javaVersion().equals(Runtime.version().toString()));
        real("MySQL dalla funzione data al pannello: " + system.mysqlVersion(), "8.0.46".equals(system.mysqlVersion()));

        // Il percorso intero, su un MySQL vero: MailDatabase.serverVersion() e la riga MySQL che ne
        // esce, con real() che lancia i comandi veri di questa macchina. Solo letture.
        String port = System.getProperty("mysql.porta");
        if (port == null) {
            System.out.println("\n== MySQL non indicato (-Dmysql.porta=...): salto la versione dal server vero ==");
        } else {
            System.out.println("\n== MySQL vero sulla porta " + port + " ==");
            org.mail_panel.database.MailDatabase db = new org.mail_panel.database.MailDatabase();
            db.setCredentials(System.getProperty("mysql.utente", "mailpanel"), System.getProperty("mysql.password", ""));
            db.setConnection("127.0.0.1", Integer.parseInt(port), System.getProperty("mysql.database", "mailpanel_prova"));
            real("connessione", db.connect());
            String v = db.serverVersion();
            real("versioneServer(): " + v, v != null && SoftwareVersions.numbers(v).matches("\\d+\\.\\d+\\.\\d+"));
            JSONObject everything = SoftwareVersions.read(SoftwareVersions.real(db::serverVersion));
            JSONObject line = everything.getJSONObject("servizi").getJSONObject("mysql");
            real("la riga MySQL la mostra in esecuzione: " + line.optString("versione"), v != null && v.equals(line.optString("versione"))
                    && line.optBoolean("inEsecuzione") && line.getBoolean("installato"));
            real("e la Java del pannello c'e': " + other(everything, "java").optString("versione"), other(everything, "java").optBoolean("inEsecuzione"));
            db.close();
        }

        System.out.println("\n" + (failed == 0 ? "TUTTO VERDE" : failed + " CONTROLLI FALLITI"));
        System.exit(failed == 0 ? 0 : 1);
    }
}
