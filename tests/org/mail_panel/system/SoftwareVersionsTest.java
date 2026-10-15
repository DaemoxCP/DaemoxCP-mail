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
 *   -Dmysql.porta=33062 -Dmysql.utente=mailpanel -Dmysql.password=... -Dmysql.database=mailpanel_prova
 */
public class SoftwareVersionsTest {

    static int falliti = 0;

    static void vero(String cosa, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FALLITO ") + cosa);
        if (!ok) falliti++;
    }

    static final ZoneId ROMA = ZoneId.of("Europe/Rome");

    /** Un server finto: file che esistono, uscite dei comandi, pidfile e ore di avvio. */
    static class FakeSystem implements SoftwareVersions.Sistema {
        final Set<String> file = new HashSet<>();
        final Map<String, String> uscite = new HashMap<>();
        final Map<String, String> contenuti = new HashMap<>();
        final Map<Long, Instant> processi = new HashMap<>();
        final java.util.List<String> lanciati = new java.util.ArrayList<>();
        String clamd, mysql, java = "25.0.1+8-1", cartellaJava = "/usr/local/openjdk25";
        Instant adesso = Instant.parse("2026-10-03T12:00:00Z");

        public String esegui(String... argv) {
            String k = String.join(" ", argv);
            lanciati.add(k);
            if (k.startsWith(SoftwareVersions.PKG + " which ")) return uscite.get("pkg which");
            return uscite.get(k);
        }
        public boolean esiste(String p) { return file.contains(p); }
        public String leggi(String p) { return contenuti.get(p); }
        public String chiediClamd() { return clamd; }
        public String versioneMysql() { return mysql; }
        public Instant avvio(long pid) { return processi.get(pid); }
        public String versioneJava() { return java; }
        public String cartellaJava() { return cartellaJava; }
        public Instant adesso() { return adesso; }
        public ZoneId zona() { return ROMA; }
    }

    static long epoca(String iso) { return Instant.parse(iso).getEpochSecond(); }

    /** Un server di posta completo come lo installa il pannello, con qualche servizio da riavviare. */
    static FakeSystem completo() {
        FakeSystem f = new FakeSystem();
        f.file.addAll(Arrays.asList(SoftwareVersions.PKG, "/usr/local/sbin/postconf", "/usr/local/sbin/dovecot",
                "/usr/local/bin/rspamd", "/usr/local/bin/redis-server", SoftwareVersions.CLAMD, SoftwareVersions.MYSQLD,
                "/usr/local/www/roundcube/index.php", "/usr/local/sbin/nginx", "/usr/local/sbin/php-fpm", "/usr/local/bin/sievec",
                "/usr/local/bin/fail2ban-client", "/usr/sbin/local-unbound", SoftwareVersions.OPENSSL_BASE,
                SoftwareVersions.FREEBSD_VERSION, "/usr/local/openjdk25/bin/java"));
        // pkg which: un file che nessun pacchetto possiede (local-unbound e' del sistema base).
        f.uscite.put("pkg which", String.join("\n",
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
        f.uscite.put(SoftwareVersions.PKG + " query %n %t", String.join("\n",
                "postfix-mysql " + epoca("2026-10-02T07:00:00Z"),
                "dovecot-mysql " + epoca("2026-09-20T07:00:00Z"),
                "rspamd " + epoca("2026-09-20T07:00:00Z"),
                "redis " + epoca("2026-09-20T07:00:00Z"),
                "py311-fail2ban " + epoca("2026-09-01T07:00:00Z"),
                "php84 " + epoca("2026-10-02T07:00:00Z"), ""));
        f.uscite.put("/usr/local/sbin/postconf -h mail_version", "3.10.4\n");
        f.uscite.put("/usr/local/sbin/dovecot --version", "2.3.21.1 (d492236fa0)\n");
        f.uscite.put("/usr/local/bin/rspamd --version", "Rspamd daemon version 3.12.1\n\nCPU architecture amd64; features: avx2, avx, sse2, sse3, ssse3, sse4.1, sse4.2, rdrand\n"
                + "Hyperscan enabled: TRUE\nJemalloc enabled: FALSE\nLuaJIT enabled: TRUE (LuaJIT version: LuaJIT 2.1.1736781742)\n");
        f.uscite.put("/usr/local/bin/redis-server --version", "Redis server v=7.4.2 sha=00000000:0 malloc=libc bits=64 build=7b2f3e4c3d2a1b0c\n");
        f.uscite.put("/usr/local/sbin/nginx -v", "nginx version: nginx/1.28.0\n");
        f.uscite.put("/usr/local/sbin/php-fpm -v", "PHP 8.4.13 (fpm-fcgi) (built: Sep 25 2025 01:23:45)\nCopyright (c) The PHP Group\nZend Engine v4.4.13, Copyright (c) Zend Technologies\n");
        f.uscite.put("/usr/sbin/local-unbound -V", "Version 1.22.0\n\nConfigure line: --with-ssl=/usr --with-libexpat=/usr\nLinked libs: libevent 2.1.12-stable (it uses kqueue), OpenSSL 3.5.1 1 Jul 2025\n");
        f.uscite.put(SoftwareVersions.OPENSSL_BASE + " version", "OpenSSL 3.5.1 1 Jul 2025\n");
        f.uscite.put(SoftwareVersions.FREEBSD_VERSION + " -u", "15.0-RELEASE-p3\n");
        f.uscite.put(SoftwareVersions.FREEBSD_VERSION + " -r", "15.0-RELEASE-p2\n");
        f.uscite.put(SoftwareVersions.FREEBSD_VERSION + " -k", "15.0-RELEASE-p3\n");
        f.contenuti.put("/usr/local/www/roundcube/program/include/iniset.php",
                "<?php\n\n// application constants\ndefine('RCMAIL_VERSION', '1.6.11');\ndefine('RCMAIL_START', microtime(true));\n");
        // Postfix: partito prima dell'aggiornamento del 02/10. Dovecot: dopo l'ultima installazione.
        // Rspamd: nessun pidfile. Redis: pidfile di un processo che non c'e' piu'. PHP-FPM: partito
        // prima del suo pacchetto, ma per lui l'ora di avvio non dice niente (reload).
        f.contenuti.put("/var/spool/postfix/pid/master.pid", "        812\n");
        f.processi.put(812L, Instant.parse("2026-09-28T06:15:00Z"));
        f.contenuti.put("/var/run/dovecot/master.pid", "901\n");
        f.processi.put(901L, Instant.parse("2026-09-21T08:00:00Z"));
        f.contenuti.put("/var/run/redis/redis.pid", "1203\n");
        f.contenuti.put("/var/run/php-fpm.pid", "1300\n");
        f.processi.put(1300L, Instant.parse("2026-09-01T08:00:00Z"));
        f.contenuti.put("/var/run/fail2ban/fail2ban.pid", "1400\n");
        f.processi.put(1400L, Instant.parse("2026-09-02T08:00:00Z"));
        f.contenuti.put(SoftwareVersions.PIDFILE_LOCAL_UNBOUND, "700\n");
        f.processi.put(700L, Instant.parse("2026-09-01T05:00:00Z"));
        f.clamd = "ClamAV 1.4.3/27780/Fri Oct  2 08:24:28 2026";
        f.mysql = "8.0.42";
        return f;
    }

    static JSONObject altro(JSONObject r, String chiave) {
        JSONArray a = r.getJSONArray("altro");
        for (int i = 0; i < a.length(); i++) if (a.getJSONObject(i).getString("chiave").equals(chiave)) return a.getJSONObject(i);
        return null;
    }

    public static void main(String[] args) throws Exception {
        System.out.println("\n== Le parti: pacchetti, versioni, pid, clamd ==");
        vero("versione del programma dal pacchetto: postfix-mysql-3.10.4,1 -> 3.10.4",
                SoftwareVersions.upstream("postfix-mysql-3.10.4,1").equals("3.10.4"));
        vero("senza revisione del port: dovecot-mysql-2.3.21.1_8 -> 2.3.21.1",
                SoftwareVersions.upstream("dovecot-mysql-2.3.21.1_8").equals("2.3.21.1"));
        vero("revisione ed epoca insieme: roundcube-php84-1.6.11_1,1 -> 1.6.11",
                SoftwareVersions.upstream("roundcube-php84-1.6.11_1,1").equals("1.6.11"));
        vero("nome con trattini: roundcube-php84-1.6.11,1 -> roundcube-php84",
                SoftwareVersions.nome("roundcube-php84-1.6.11,1").equals("roundcube-php84"));
        vero("parte numerica per confrontare: 8.0.43-debug -> 8.0.43, 25.0.1+8-LTS -> 25.0.1",
                SoftwareVersions.numeri("8.0.43-debug").equals("8.0.43") && SoftwareVersions.numeri("25.0.1+8-LTS").equals("25.0.1")
                && SoftwareVersions.numeri("abc").isEmpty());
        vero("pidfile di Postfix (allineato a destra): 812", Long.valueOf(812).equals(SoftwareVersions.pid("        812\n")));
        vero("pidfile non validi: testo, 1 (init), 0, undici cifre",
                SoftwareVersions.pid("abc") == null && SoftwareVersions.pid("1") == null && SoftwareVersions.pid("0") == null
                && SoftwareVersions.pid("12345678901") == null && SoftwareVersions.pid(null) == null);
        SoftwareVersions.Clamd c = SoftwareVersions.clamd("ClamAV 1.4.3/27780/Fri Oct  2 08:24:28 2026", ROMA);
        vero("clamd: motore, firme e data (giorno a una cifra, due spazi)", c != null && c.motore().equals("1.4.3")
                && c.firme().equals("27780") && c.del().equals(Instant.parse("2026-10-02T06:24:28Z")));
        c = SoftwareVersions.clamd("ClamAV 1.4.3/27791/Mon Oct 12 18:01:02 2026", ROMA);
        vero("clamd: giorno a due cifre", c != null && c.del().equals(Instant.parse("2026-10-12T16:01:02Z")));
        c = SoftwareVersions.clamd("ClamAV 1.0.9", ROMA);
        vero("clamd senza firme caricate: solo il motore", c != null && c.motore().equals("1.0.9") && c.firme() == null && c.del() == null);
        vero("risposta che non e' di clamd: niente", SoftwareVersions.clamd("ERROR: unknown command", ROMA) == null);
        Map<String, String> p = SoftwareVersions.proprietari("/a/b was installed by package uno-1.0\n/c was not found in the database\n"
                + "/d was installed by package due due-1.0\n/e was installed by package <script>-1\n");
        vero("pkg which: solo le righe valide (" + p + ")", p.size() == 1 && "uno-1.0".equals(p.get("/a/b")));
        Map<String, Long> t = SoftwareVersions.installazioni("rspamd 1790000000\nrotta\nnginx abc\n");
        vero("pkg query %n %t: nome e secondi", t.size() == 1 && t.get("rspamd") == 1790000000L);
        vero("una versione non si accetta se ha spazi o simboli", SoftwareVersions.valida("1.2 3") == null
                && SoftwareVersions.valida("<b>1</b>") == null && SoftwareVersions.valida("3.10.4").equals("3.10.4"));

        System.out.println("\n== Server completo, con qualcosa da riavviare ==");
        FakeSystem f = completo();
        JSONObject r = SoftwareVersions.leggi(f);
        JSONObject s = r.getJSONObject("servizi");
        vero("letteAlle con i secondi anche quando sono zero, nell'ora del server: " + r.getString("letteAlle"),
                r.getString("letteAlle").equals("2026-10-03T14:00:00+02:00"));
        long chiamatePkg = f.lanciati.stream().filter(x -> x.startsWith(SoftwareVersions.PKG)).count();
        vero("pkg si chiama due volte in tutto (which e query), non una per programma: " + chiamatePkg, chiamatePkg == 2);
        JSONObject pf = s.getJSONObject("postfix");
        vero("Postfix: 3.10.4 da postconf, pacchetto postfix-mysql (non \"postfix\")", pf.getString("versione").equals("3.10.4")
                && pf.getString("pacchetto").equals("postfix-mysql-3.10.4,1") && pf.getString("fonte").contains("mail_version"));
        vero("Postfix partito il 28/09, pacchetto installato il 02/10: da riavviare, con le due date: " + pf.optString("notaRiavvio"),
                pf.optBoolean("riavvio") && pf.getString("notaRiavvio").contains("28/09/2026 08:15")
                && pf.getString("notaRiavvio").contains("02/10/2026 09:00"));
        JSONObject dv = s.getJSONObject("dovecot");
        vero("Dovecot: 2.3.21.1, partito dopo l'installazione: niente da riavviare", dv.getString("versione").equals("2.3.21.1")
                && !dv.optBoolean("riavvio") && dv.getString("pacchetto").equals("dovecot-mysql-2.3.21.1_8"));
        JSONObject my = s.getJSONObject("mysql");
        vero("MySQL: la versione in esecuzione (8.0.42), non quella del pacchetto", my.getString("versione").equals("8.0.42")
                && my.optBoolean("inEsecuzione") && my.getString("fonte").startsWith("SELECT VERSION()"));
        vero("MySQL: il pacchetto e' la 8.0.43, quindi da riavviare: " + my.optString("notaRiavvio"), my.optBoolean("riavvio")
                && my.getString("installata").equals("8.0.43") && my.getString("notaRiavvio").contains("riavvia MySQL"));
        JSONObject rs = s.getJSONObject("rspamd");
        vero("Rspamd: 3.12.1; senza pidfile non si dice niente sul riavvio", rs.getString("versione").equals("3.12.1") && !rs.has("riavvio"));
        JSONObject rd = s.getJSONObject("redis");
        vero("Redis: 7.4.2; pidfile di un processo che non c'e' piu': niente sul riavvio", rd.getString("versione").equals("7.4.2") && !rd.has("riavvio"));
        JSONObject cl = s.getJSONObject("clamav");
        vero("ClamAV: dal demone, motore 1.4.3, firme 27780 del 02/10/2026 08:24: " + cl.optString("dettaglio"),
                cl.getString("versione").equals("1.4.3") && cl.optBoolean("inEsecuzione")
                && cl.getString("dettaglio").equals("firme 27780 del 02/10/2026 08:24") && !cl.has("avviso") && !cl.has("riavvio"));
        JSONObject rc = s.getJSONObject("roundcube");
        vero("Roundcube: 1.6.11 da RCMAIL_VERSION, pacchetto roundcube-php84", rc.getString("versione").equals("1.6.11")
                && rc.getString("fonte").contains("RCMAIL_VERSION") && rc.getString("pacchetto").equals("roundcube-php84-1.6.11,1"));

        JSONObject fb = altro(r, "freebsd");
        vero("FreeBSD: userland 15.0-RELEASE-p3, kernel in esecuzione p2 ma installato p3: riavvio del server",
                fb.getString("versione").equals("15.0-RELEASE-p3") && fb.getString("dettaglio").equals("kernel in esecuzione 15.0-RELEASE-p2")
                && fb.optBoolean("riavvio") && fb.getString("notaRiavvio").contains("riavvio del server"));
        JSONObject os = altro(r, "openssl");
        vero("OpenSSL del sistema base: 3.5.1, rilasciata il 01/07/2025", os.getString("versione").equals("3.5.1")
                && os.getString("dettaglio").equals("rilasciata il 01/07/2025"));
        vero("nessuna OpenSSL da pacchetto, nessun Unbound da pacchetto: non compaiono", altro(r, "openssl_pkg") == null && altro(r, "unbound") == null);
        vero("nginx 1.28.0", altro(r, "nginx").getString("versione").equals("1.28.0"));
        JSONObject php = altro(r, "php");
        vero("PHP-FPM 8.4.13; partito prima del pacchetto ma per lui l'ora non vale (reload): niente sul riavvio",
                php.getString("versione").equals("8.4.13") && !php.has("riavvio"));
        JSONObject ph = altro(r, "pigeonhole");
        vero("Pigeonhole dal pacchetto: 0.5.21.1", ph.getString("versione").equals("0.5.21.1") && ph.getString("fonte").startsWith("pkg which"));
        JSONObject jv = altro(r, "java");
        vero("Java del pannello: 25.0.1+8-1 in esecuzione, uguale al pacchetto openjdk25", jv.getString("versione").equals("25.0.1+8-1")
                && jv.optBoolean("inEsecuzione") && jv.getString("pacchetto").equals("openjdk25-25.0.1+8.1") && !jv.has("riavvio"));
        JSONObject f2b = altro(r, "fail2ban");
        vero("fail2ban dal pacchetto: 1.1.0, partito dopo l'installazione", f2b != null && f2b.getString("versione").equals("1.1.0") && !f2b.has("riavvio"));
        JSONObject lu = altro(r, "local_unbound");
        vero("Unbound del sistema base, perche' gira: 1.22.0, senza pacchetto", lu != null && lu.getString("versione").equals("1.22.0") && !lu.has("pacchetto"));
        boolean nessunHtml = !r.toString().contains("<");
        vero("niente HTML nella risposta", nessunHtml);

        System.out.println("\n== Server appena installato: niente ==");
        FakeSystem vuoto = new FakeSystem();
        vuoto.cartellaJava = "/usr/local/openjdk25";
        r = SoftwareVersions.leggi(vuoto);
        s = r.getJSONObject("servizi");
        boolean tuttiAssenti = true;
        for (String k : s.keySet()) tuttiAssenti &= !s.getJSONObject(k).getBoolean("installato");
        vero("i sette servizi ci sono tutti, come non installati: " + s.keySet(), s.length() == 7 && tuttiAssenti);
        vero("senza pkg non si chiama pkg", vuoto.lanciati.stream().noneMatch(x -> x.startsWith(SoftwareVersions.PKG)));
        vero("Java c'e' sempre (e' quella che fa girare il pannello)", altro(r, "java").getBoolean("installato"));
        vero("fail2ban e Unbound non installati: non compaiono", altro(r, "fail2ban") == null && altro(r, "local_unbound") == null);

        System.out.println("\n== Casi storti ==");
        FakeSystem st = completo();
        st.clamd = null;
        st.uscite.put(SoftwareVersions.CLAMD + " --version", "ClamAV 1.4.3/27700/Mon Sep 14 08:00:00 2026\n");
        st.mysql = null;
        st.uscite.put(SoftwareVersions.MYSQLD + " --version", "/usr/local/libexec/mysqld  Ver 8.0.43 for FreeBSD15.0 on amd64 (Source distribution)\n");
        st.uscite.put("/usr/local/sbin/postconf -h mail_version", "postconf: fatal: open /usr/local/etc/postfix/main.cf: No such file or directory\n");
        st.uscite.put("/usr/local/sbin/dovecot --version", "<script>alert(1)</script>\n");
        st.uscite.put("pkg which", st.uscite.get("pkg which").replace("openjdk25-25.0.1+8.1", "openjdk25-25.0.2+10.1"));
        st.contenuti.put("/usr/local/www/roundcube/program/include/iniset.php", "<?php // senza costante\n");
        r = SoftwareVersions.leggi(st);
        s = r.getJSONObject("servizi");
        cl = s.getJSONObject("clamav");
        vero("clamd non risponde: versione dal binario, non \"in esecuzione\"", cl.getString("versione").equals("1.4.3")
                && !cl.has("inEsecuzione") && cl.getString("fonte").endsWith("--version"));
        vero("firme del 14/09 (19 giorni): avviso — " + cl.optString("avviso"), cl.optString("avviso").contains("19 giorni"));
        vero("e senza demone non si confronta con il pacchetto", !cl.has("riavvio"));
        my = s.getJSONObject("mysql");
        vero("MySQL non risponde: versione da mysqld --version, con l'avviso che non e' quella in esecuzione",
                my.getString("versione").equals("8.0.43") && !my.has("inEsecuzione") && my.optString("avviso").contains("non risponde"));
        pf = s.getJSONObject("postfix");
        vero("postconf risponde con un errore: versione dal pacchetto (3.10.4)", pf.getString("versione").equals("3.10.4")
                && pf.getString("fonte").startsWith("pkg which"));
        dv = s.getJSONObject("dovecot");
        vero("una risposta che non e' una versione non passa: si usa il pacchetto", dv.getString("versione").equals("2.3.21.1")
                && !r.toString().contains("script"));
        vero("iniset.php senza la costante: Roundcube dal pacchetto", s.getJSONObject("roundcube").getString("versione").equals("1.6.11"));
        jv = altro(r, "java");
        vero("Java aggiornata (pacchetto 25.0.2) ma il pannello gira sulla 25.0.1: riavvia il pannello — " + jv.optString("notaRiavvio"),
                jv.optBoolean("riavvio") && jv.getString("notaRiavvio").contains("riavvia il pannello"));
        FakeSystem strana = completo();
        strana.cartellaJava = "/usr/local/openjdk25/../../etc";
        r = SoftwareVersions.leggi(strana);
        vero("java.home con \"..\": non si chiede a pkg", strana.lanciati.stream().noneMatch(x -> x.contains("..")));

        System.out.println("\n== Il socket di clamd, vero ==");
        Path cartella = Files.createTempDirectory("clamd-prova");
        Path sock = cartella.resolve("clamd.sock");
        vero("nessun socket: niente, subito", SoftwareVersions.chiediAClamd(sock) == null);
        try (ServerSocketChannel srv = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            srv.bind(UnixDomainSocketAddress.of(sock));
            Thread demone = Thread.ofVirtual().start(() -> {
                try (SocketChannel ch = srv.accept()) {
                    ByteBuffer b = ByteBuffer.allocate(64);
                    ch.read(b);
                    String chiesto = new String(b.array(), 0, b.position(), StandardCharsets.US_ASCII);
                    String risposta = chiesto.equals("zVERSION\0") ? "ClamAV 1.4.3/27780/Fri Oct  2 08:24:28 2026\0" : "ERROR\0";
                    ch.write(ByteBuffer.wrap(risposta.getBytes(StandardCharsets.US_ASCII)));
                } catch (Exception ignorata) { }
            });
            String risposta = SoftwareVersions.chiediAClamd(sock);
            demone.join();
            vero("clamd risponde a zVERSION: " + risposta, "ClamAV 1.4.3/27780/Fri Oct  2 08:24:28 2026".equals(risposta));

            Thread muto = Thread.ofVirtual().start(() -> {
                try (SocketChannel ch = srv.accept()) {
                    Thread.sleep(6000);
                } catch (Exception ignorata) { }
            });
            long t0 = System.nanoTime();
            String nulla = SoftwareVersions.chiediAClamd(sock);
            long ms = (System.nanoTime() - t0) / 1_000_000;
            vero("clamd muto: si arrende in circa tre secondi (" + ms + " ms) e non dice niente", nulla == null && ms >= 2900 && ms < 4500);
            muto.interrupt();
        } finally {
            Files.deleteIfExists(sock);
            Files.deleteIfExists(cartella);
        }

        System.out.println("\n== Il sistema vero, per quello che si puo' qui ==");
        SoftwareVersions.Sistema sistema = SoftwareVersions.reale(() -> "8.0.46");
        vero("un comando che non esiste: null", sistema.esegui("/nonesiste/davvero", "-v") == null);
        vero("un comando che esce con errore: la sua uscita c'e' comunque", sistema.esegui("sh", "-c", "echo versione; exit 3").contains("versione"));
        vero("l'ora di avvio di questo processo si legge", sistema.avvio(ProcessHandle.current().pid()) != null);
        vero("un pid che non c'e': null", sistema.avvio(999_999_999L) == null);
        vero("la Java di questo processo: " + sistema.versioneJava(), sistema.versioneJava().equals(Runtime.version().toString()));
        vero("MySQL dalla funzione data al pannello: " + sistema.versioneMysql(), "8.0.46".equals(sistema.versioneMysql()));

        // Il percorso intero, su un MySQL vero: MailDatabase.versioneServer() e la riga MySQL che ne
        // esce, con reale() che lancia i comandi veri di questa macchina. Solo letture.
        String porta = System.getProperty("mysql.porta");
        if (porta == null) {
            System.out.println("\n== MySQL non indicato (-Dmysql.porta=...): salto la versione dal server vero ==");
        } else {
            System.out.println("\n== MySQL vero sulla porta " + porta + " ==");
            org.mail_panel.database.MailDatabase db = new org.mail_panel.database.MailDatabase();
            db.setCredentials(System.getProperty("mysql.utente", "mailpanel"), System.getProperty("mysql.password", ""));
            db.setConnection("127.0.0.1", Integer.parseInt(porta), System.getProperty("mysql.database", "mailpanel_prova"));
            vero("connessione", db.connect());
            String v = db.versioneServer();
            vero("versioneServer(): " + v, v != null && SoftwareVersions.numeri(v).matches("\\d+\\.\\d+\\.\\d+"));
            JSONObject tutto = SoftwareVersions.leggi(SoftwareVersions.reale(db::versioneServer));
            JSONObject riga = tutto.getJSONObject("servizi").getJSONObject("mysql");
            vero("la riga MySQL la mostra in esecuzione: " + riga.optString("versione"), v != null && v.equals(riga.optString("versione"))
                    && riga.optBoolean("inEsecuzione") && riga.getBoolean("installato"));
            vero("e la Java del pannello c'e': " + altro(tutto, "java").optString("versione"), altro(tutto, "java").optBoolean("inEsecuzione"));
            db.close();
        }

        System.out.println("\n" + (falliti == 0 ? "TUTTO VERDE" : falliti + " CONTROLLI FALLITI"));
        System.exit(falliti == 0 ? 0 : 1);
    }
}
