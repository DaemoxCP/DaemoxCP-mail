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
 * Il meccanismo che confronta la configurazione e gli indirizzi in ascolto prima e dopo un
 * aggiornamento, provato da solo: su una cartella temporanea, con l'uscita vera di
 * {@code sockstat} e di {@code pkg query} presa sulla VM FreeBSD 15.1 il 24/10/2026.
 *
 * Questa prova dice che il confronto distingue le cose giuste. Che i tre lavori lo usino
 * davvero lo dice {@link InstallScriptDriftTest}, che fa girare i lavori veri e fallisce con
 * il jar senza la correzione.
 *
 * Le due direzioni, come per i servizi caduti: ogni guasto vero deve dare l'allarme, e
 * cio' che pkg fa per mestiere (sostituire i propri file, rimettere il predefinito nuovo al
 * posto di quello mai toccato) non deve darlo. Un allarme che suona a ogni aggiornamento
 * insegna a ignorarlo.
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
        System.out.println(failures == 0 ? "\nTUTTO OK" : "\n" + failures + " PROVE FALLITE");
        if (failures > 0) System.exit(1);
    }

    // ===== la configurazione, su una cartella vera =====
    private static void configuration() throws Exception {
        Path d = Files.createTempDirectory("side-effects");
        try {
            Path etc = Files.createDirectories(d.resolve("etc/postfix"));
            Path other = Files.createDirectories(d.resolve("etc/other"));
            // Il main.cf di un amministratore: diverso dal suo esempio, di nessun pacchetto.
            write(etc.resolve("main.cf"), "myhostname = mx.example.org\ninet_interfaces = all\n", "rw-r--r--");
            write(etc.resolve("main.cf.sample"), "# esempio\n", "rw-r--r--");
            write(etc.resolve("master.cf"), "smtp      inet  n       -       n       -       -       smtpd\n", "rw-r--r--");
            // Una mappa MySQL: password dentro, leggibile solo da root e dal gruppo.
            write(etc.resolve("mysql-virtual.cf"), "user = postfix\npassword = vecchia-segreta\nhosts = 127.0.0.1\n", "rw-r-----");
            // Un file del pacchetto: lo sostituisce pkg, e' l'aggiornamento stesso.
            write(etc.resolve("main.cf.default"), "compatibility_level = 3.6\n", "rw-r--r--");
            // Il predefinito mai toccato: identico al suo esempio.
            write(other.resolve("other.conf"), "port = 1\n", "rw-r--r--");
            write(other.resolve("other.conf.sample"), "port = 1\n", "rw-r--r--");
            write(etc.resolve("old.cf"), "x = 1\n", "rw-r--r--");
            write(etc.resolve("perms.cf"), "y = 2\n", "rw-------");
            write(etc.resolve("order.cf"), "a = 1\nb = 2\n", "rw-r--r--");
            write(etc.resolve("untouched.cf"), "z = 3\n", "rw-r--r--");
            write(etc.resolve("comments-perms.cf"), "w = 4\n", "rw-r-----");
            // Un file di un ALTRO pacchetto, che il lavoro non ha toccato.
            write(other.resolve("dovecot-owned.conf"), "protocols = imap\n", "rw-r--r--");

            Map<String, String> owners = new TreeMap<>();
            owners.put(etc.resolve("main.cf.sample").toString(), "postfix-mysql");
            owners.put(etc.resolve("main.cf.default").toString(), "postfix-mysql");
            owners.put(other.resolve("other.conf.sample").toString(), "other");
            owners.put(other.resolve("dovecot-owned.conf").toString(), "dovecot");
            Set<String> changed = Set.of("postfix-mysql", "other");

            InstallSideEffects.ConfigSnapshot before =
                    InstallSideEffects.configSnapshot(List.of(d.resolve("etc")), List.of(), owners);

            // Il reperto 42: lo script aggiunge una riga a main.cf.
            append(etc.resolve("main.cf"), "inet_protocols = ipv4\n");
            // E quattro voci commentate a master.cf.
            append(etc.resolve("master.cf"), "#postscreen inet  n       -       n       -       1       postscreen\n#tlsproxy  unix  -       -       n       -       0       tlsproxy\n");
            write(etc.resolve("mysql-virtual.cf"), "user = postfix\npassword = nuova-segreta\nhosts = 127.0.0.1\n", "rw-r-----");
            write(etc.resolve("main.cf.default"), "compatibility_level = 3.11\n", "rw-r--r--");
            write(other.resolve("other.conf"), "port = 2\n", "rw-r--r--");
            write(other.resolve("other.conf.sample"), "port = 2\n", "rw-r--r--");
            write(etc.resolve("created.cf"), "nuovo = 1\n", "rw-r--r--");
            Files.delete(etc.resolve("old.cf"));
            Files.setPosixFilePermissions(etc.resolve("perms.cf"), PosixFilePermissions.fromString("rw-r--r--"));
            write(etc.resolve("order.cf"), "b = 2\na = 1\n", "rw-r--r--");
            write(other.resolve("dovecot-owned.conf"), "protocols = imap pop3\n", "rw-r--r--");
            write(etc.resolve("comments-perms.cf"), "w = 4\n# nuovo commento\n", "rw-rw-rw-");

            InstallSideEffects.ConfigSnapshot after =
                    InstallSideEffects.configSnapshot(List.of(d.resolve("etc")), List.of(), owners);
            JSONArray c = InstallSideEffects.configChanges(before, after, changed);

            JSONObject mainCf = find(c, etc.resolve("main.cf"));
            check("main.cf cambiato da uno script: allarme", mainCf != null && mainCf.getBoolean("alarm")
                    && "script".equals(mainCf.getString("kind")) && "changed".equals(mainCf.getString("happened")));
            check("  e la riga aggiunta si vede", mainCf != null && mainCf.optJSONArray("addedLines") != null
                    && mainCf.getJSONArray("addedLines").toList().contains("inet_protocols = ipv4"));
            check("  e nessuna riga tolta", mainCf != null && mainCf.optInt("removedCount", -1) == 0);

            JSONObject master = find(c, etc.resolve("master.cf"));
            check("master.cf con sole righe di commento: detto, ma senza allarme", master != null
                    && "commentsOnly".equals(master.getString("kind")) && !master.getBoolean("alarm"));
            check("  e le righe si vedono lo stesso", master != null && master.optInt("addedCount") == 2);

            JSONObject secret = find(c, etc.resolve("mysql-virtual.cf"));
            check("una mappa con la password cambiata: allarme", secret != null && secret.getBoolean("alarm"));
            check("  ma il contenuto non si mostra", secret != null && "notWorldReadable".equals(secret.optString("hidden"))
                    && !secret.has("addedLines") && !secret.has("removedLines"));
            check("  e nessuna delle due password compare da nessuna parte",
                    !c.toString().contains("vecchia-segreta") && !c.toString().contains("nuova-segreta"));

            JSONObject packageFile = find(c, etc.resolve("main.cf.default"));
            check("un file del pacchetto aggiornato: e' l'aggiornamento, niente allarme",
                    packageFile != null && "package".equals(packageFile.getString("kind")) && !packageFile.getBoolean("alarm"));

            JSONObject newDefault = find(c, other.resolve("other.conf"));
            check("il predefinito mai toccato, diventato il predefinito nuovo: niente allarme",
                    newDefault != null && "newDefault".equals(newDefault.getString("kind")) && !newDefault.getBoolean("alarm"));

            JSONObject created = find(c, etc.resolve("created.cf"));
            check("un file creato che non e' di nessuno: allarme", created != null && created.getBoolean("alarm")
                    && "created".equals(created.getString("happened")));
            JSONObject removed = find(c, etc.resolve("old.cf"));
            check("un file di configurazione tolto: allarme", removed != null && removed.getBoolean("alarm")
                    && "removed".equals(removed.getString("happened")));
            JSONObject perms = find(c, etc.resolve("perms.cf"));
            check("stesso contenuto, permessi cambiati: allarme, con il prima e il dopo", perms != null
                    && perms.getBoolean("alarm") && "permissions".equals(perms.getString("happened"))
                    && perms.optString("permissionsFrom").startsWith("rw-------")
                    && perms.optString("permissionsTo").startsWith("rw-r--r--"));
            JSONObject order = find(c, etc.resolve("order.cf"));
            check("stesse righe in un altro ordine: allarme, e lo dice", order != null && order.getBoolean("alarm")
                    && "sameLines".equals(order.optString("hidden")));
            JSONObject foreign = find(c, other.resolve("dovecot-owned.conf"));
            check("un file di un pacchetto che il lavoro NON ha cambiato: allarme", foreign != null
                    && foreign.getBoolean("alarm") && "dovecot".equals(foreign.getString("owner")));
            JSONObject commentsPerms = find(c, etc.resolve("comments-perms.cf"));
            check("solo commenti, ma con i permessi cambiati: allarme", commentsPerms != null
                    && commentsPerms.getBoolean("alarm") && "script".equals(commentsPerms.getString("kind")));
            check("un file non toccato non compare", find(c, etc.resolve("untouched.cf")) == null);
            check("e nemmeno il .sample del pacchetto, che e' suo", find(c, etc.resolve("main.cf.sample")) == null);

            // --- e nessun cambiamento: niente da dire ---
            InstallSideEffects.ConfigSnapshot again =
                    InstallSideEffects.configSnapshot(List.of(d.resolve("etc")), List.of(), owners);
            check("due fotografie uguali: nessun cambiamento",
                    InstallSideEffects.configChanges(after, again, changed).isEmpty());

            // --- la cartella del pannello non si guarda ---
            check("la cartella del pannello e' esclusa", InstallSideEffects.excluded("/usr/local/etc/mail-panel/firewall.json"));
            check("  ma solo lei, non un nome che le somiglia", !InstallSideEffects.excluded("/usr/local/etc/mail-panel2/x"));
        } finally {
            try (var s = Files.walk(d)) {
                s.sorted(java.util.Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }

    // ===== /etc: utenti, file rigenerati, resolv.conf =====
    // Fotografie costruite a mano con i percorsi veri di /etc: le regole dipendono dal percorso,
    // e su una cartella temporanea /etc/passwd non c'e'.
    private static void etc() {
        Map<String, InstallSideEffects.FileState> b = new TreeMap<>(), a = new TreeMap<>();
        String pw = "root:*:0:0:Charlie &:/root:/bin/sh\npostfix:*:125:125:Postfix:/var/spool/postfix:/usr/sbin/nologin\n";
        put(b, "/etc/passwd", pw, true);
        put(a, "/etc/passwd", pw + "driftprobe:*:1001:1001:drift probe:/nonexistent:/usr/sbin/nologin\n", true);
        put(b, "/etc/master.passwd", "root:$6$x:0:0::0:0:Charlie &:/root:/bin/sh\n", false);
        put(a, "/etc/master.passwd", "root:$6$x:0:0::0:0:Charlie &:/root:/bin/sh\ndriftprobe:*:1001:1001::0:0:drift probe:/nonexistent:/usr/sbin/nologin\n", false);
        put(b, "/etc/group", "wheel:*:0:root\n", true);
        put(a, "/etc/group", "wheel:*:0:root,driftprobe\n", true);       // un utente esistente toccato
        put(b, "/etc/pwd.db", "\u0000uno", true);   put(a, "/etc/pwd.db", "\u0000due", true);
        put(b, "/etc/aliases", "root: admin\n", true); put(a, "/etc/aliases", "root: admin\n", true);
        put(b, "/etc/aliases.db", "\u0000a", true);  put(a, "/etc/aliases.db", "\u0000b", true);
        put(b, "/etc/ssl/certs/0179095f.0", "certA", true); put(a, "/etc/ssl/certs/0179095f.0", "certB", true);
        put(b, "/etc/orphan.db", "\u0000a", true);   put(a, "/etc/orphan.db", "\u0000b", true);
        put(a, "/etc/periodic.conf", "daily_x_enable=\"YES\"\n", true);
        JSONArray c = InstallSideEffects.configChanges(new InstallSideEffects.ConfigSnapshot(b, Map.of()),
                new InstallSideEffects.ConfigSnapshot(a, Map.of()), Set.of());
        JSONObject passwd = find(c, "/etc/passwd"), master = find(c, "/etc/master.passwd"), group = find(c, "/etc/group");
        check("/etc/passwd con un utente aggiunto: si dice, senza allarme", passwd != null
                && "accounts".equals(passwd.getString("kind")) && !passwd.getBoolean("alarm")
                && passwd.getJSONArray("addedLines").toList().toString().contains("driftprobe"));
        check("/etc/master.passwd uguale, ma senza mostrarlo", master != null && "accounts".equals(master.getString("kind"))
                && "notWorldReadable".equals(master.optString("hidden")) && !c.toString().contains("$6$x"));
        check("/etc/group con un utente esistente toccato: allarme", group != null && group.getBoolean("alarm"));
        check("/etc/pwd.db, ricavato da master.passwd: niente allarme", "derived".equals(kindOf(c, "/etc/pwd.db")));
        check("/etc/aliases.db accanto ad aliases: niente allarme", "derived".equals(kindOf(c, "/etc/aliases.db")));
        check("i certificati rigenerati da certctl: niente allarme", "derived".equals(kindOf(c, "/etc/ssl/certs/0179095f.0")));
        check("un .db senza la sua fonte: allarme", "script".equals(kindOf(c, "/etc/orphan.db")));
        check("/etc/periodic.conf creato: allarme", "script".equals(kindOf(c, "/etc/periodic.conf")));
        check("tutta /etc e il caricatore sono fra le radici", InstallSideEffects.CONFIG_ROOTS.contains("/etc")
                && InstallSideEffects.CONFIG_ROOTS.contains("/boot/loader.conf"));
        check("/etc/resolv.conf no: lo riscrive dhclient", InstallSideEffects.excluded("/etc/resolv.conf")
                && !InstallSideEffects.excluded("/etc/resolv.conf.d/x") && !InstallSideEffects.excluded("/etc/rc.conf"));
    }

    // ===== sasldb2.db: si confrontano gli utenti, non i byte =====
    // Con i database veri, fatti da saslpasswd2 come li fa lo script di cyrus-sasl: crea
    // l'utente cyrus e lo toglie. Serve cyrus-sasl, quindi gira solo dove c'e'.
    private static void sasl() throws Exception {
        if (org.mail_panel.util.Shell.runShell(java.time.Duration.ofSeconds(10), "command -v saslpasswd2").exitCode() != 0) {
            System.out.println("  --   SALTATA: sasldb2.db, qui non c'e' saslpasswd2 (cyrus-sasl): gira sulla VM");
            return;
        }
        Path d = Files.createTempDirectory("sasl");
        try {
            byte[] empty1 = emptySasldb(d.resolve("uno.db")), empty2 = emptySasldb(d.resolve("due.db"));
            org.mail_panel.util.Shell.runShell(java.time.Duration.ofSeconds(10),
                    "echo x | saslpasswd2 -p -f " + d.resolve("utente.db") + " -c probeuser");
            byte[] withUser = Files.readAllBytes(d.resolve("utente.db"));
            check("due database vuoti ricreati hanno byte diversi (se no la prova non prova niente)",
                    !java.util.Arrays.equals(empty1, empty2));
            String path = "/usr/local/etc/sasldb2.db";
            Map<String, InstallSideEffects.FileState> b = new TreeMap<>(), a = new TreeMap<>(), u = new TreeMap<>();
            b.put(path, new InstallSideEffects.FileState("x1", "rw-r----- cyrus:mail", false, empty1));
            a.put(path, new InstallSideEffects.FileState("x2", "rw-r----- cyrus:mail", false, empty2));
            u.put(path, new InstallSideEffects.FileState("x3", "rw-r----- cyrus:mail", false, withUser));
            JSONArray same = InstallSideEffects.configChanges(new InstallSideEffects.ConfigSnapshot(b, Map.of()),
                    new InstallSideEffects.ConfigSnapshot(a, Map.of()), Set.of());
            check("sasldb2.db ricreato vuoto com'era: si dice, senza allarme",
                    "rebuilt".equals(kindOf(same, path)) && !find(same, path).getBoolean("alarm"));
            JSONArray added = InstallSideEffects.configChanges(new InstallSideEffects.ConfigSnapshot(b, Map.of()),
                    new InstallSideEffects.ConfigSnapshot(u, Map.of()), Set.of());
            check("sasldb2.db con un utente in piu': allarme", "script".equals(kindOf(added, path)));
            check("gli utenti si leggono, mai le password: «utente@dominio: attributo»",
                    InstallSideEffects.saslUsers(withUser).matches("(?s)probeuser@\\S+: \\w+.*"));
        } finally {
            try (var st = Files.walk(d)) { st.sorted(java.util.Comparator.reverseOrder()).forEach(x -> x.toFile().delete()); }
        }
    }

    private static byte[] emptySasldb(Path f) throws Exception {
        org.mail_panel.util.Shell.runShell(java.time.Duration.ofSeconds(10),
                "echo test | saslpasswd2 -p -f " + f + " -c cyrus && saslpasswd2 -f " + f + " -d cyrus");
        return Files.readAllBytes(f);
    }

    // ===== la versione di prima, messa da parte =====
    private static void savedCopies() throws Exception {
        Path d = Files.createTempDirectory("saved");
        try {
            Path src = Files.createDirectories(d.resolve("live/postfix"));
            write(src.resolve("main.cf"), "inet_protocols = all\n", "rw-r--r--");
            write(src.resolve("mysql.cf"), "password = segreta\n", "rw-r-----");
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
            check("la copia di main.cf c'e', col percorso intero sotto la cartella", Files.exists(copy)
                    && copy.toString().equals(backups + mainCf));
            check("  con il contenuto di prima", Files.readString(copy).equals("inet_protocols = all\n"));
            check("  e gli stessi permessi, cosi' cp -p la rimette com'era",
                    PosixFilePermissions.toString(Files.getPosixFilePermissions(copy)).equals("rw-r--r--")
                    && PosixFilePermissions.toString(Files.getPosixFilePermissions(Path.of(r.get(mysqlCf)))).equals("rw-r-----"));
            check("la cartella delle copie la legge solo il proprietario",
                    PosixFilePermissions.toString(Files.getPosixFilePermissions(backups)).equals("rwx------"));
            check("un file che prima non c'era: niente copia, e lo dice", "created".equals(r.get("/nowhere/new.cf")));
            check("un file troppo grande per tenerne il contenuto: lo dice", "tooLarge".equals(r.get("/nowhere/huge.cf")));

            for (String n : new String[]{"20261020T080000Z", "20261021T080000Z", "20261022T080000Z", "20261023T080000Z"})
                Files.createDirectories(d.resolve("backups/" + n + "/x"));
            InstallSideEffects.pruneBefore(d.resolve("backups"), 2);
            List<String> left;
            try (var st = Files.list(d.resolve("backups"))) { left = st.map(x -> x.getFileName().toString()).sorted().toList(); }
            check("se ne tengono le ultime, e si tolgono le piu' vecchie: " + left,
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

    // ===== le righe =====
    private static void lines() {
        List<List<String>> d = InstallSideEffects.lineDiff("a\nb\nc\n", "a\nc\nd\n");
        check("diff: tolta b, aggiunta d", d.get(0).equals(List.of("b")) && d.get(1).equals(List.of("d")));
        d = InstallSideEffects.lineDiff("a\n", "a");
        check("diff: l'a capo finale non e' una riga", d.get(0).isEmpty() && d.get(1).isEmpty());
        d = InstallSideEffects.lineDiff("x\nx\n", "x\n");
        check("diff: una riga doppia diventata singola si vede", d.get(0).equals(List.of("x")) && d.get(1).isEmpty());
        check("commenti: # e ; e righe vuote", InstallSideEffects.allComments(List.of("#a", "  ; b", "", "   ")));
        check("commenti: una direttiva non lo e'", !InstallSideEffects.allComments(List.of("#a", "inet_protocols = ipv4")));
        check("testo: un byte zero no", !InstallSideEffects.isText(new byte[]{'a', 0, 'b'}));
    }

    // ===== di chi sono i file =====
    private static void owners() {
        String query = "postfix-mysql\t/usr/local/etc/postfix/main.cf.sample\n"
                + "postfix-mysql\t/usr/local/sbin/postfix\n"
                + "roundcube-php84\t/usr/local/www/roundcube/config/config.inc.php.sample\n"
                + "roundcube-php84\t/usr/local/www/roundcube/config/defaults.inc.php\n"
                + "roundcube-php84\t/usr/local/www/roundcube/index.php\n"
                + "nome sbagliato!\t/usr/local/etc/x\n";
        Map<String, String> o = InstallSideEffects.owners(query, InstallSideEffects.CONFIG_ROOTS);
        check("proprietari: un file sotto /usr/local/etc c'e'", "postfix-mysql".equals(o.get("/usr/local/etc/postfix/main.cf.sample")));
        check("  un binario fuori dalle radici no", !o.containsKey("/usr/local/sbin/postfix"));
        check("  il .sample di Roundcube fuori da /usr/local/etc si'", o.containsKey("/usr/local/www/roundcube/config/config.inc.php.sample"));
        check("  e anche il file del pacchetto accanto, se no darebbe l'allarme a ogni aggiornamento",
                "roundcube-php84".equals(o.get("/usr/local/www/roundcube/config/defaults.inc.php")));
        check("  ma non il resto di Roundcube", !o.containsKey("/usr/local/www/roundcube/index.php"));
        check("  un nome di pacchetto non valido si scarta", !o.containsKey("/usr/local/etc/x"));
        List<Path> dirs = InstallSideEffects.sampleDirsOutside(o, InstallSideEffects.CONFIG_ROOTS);
        check("cartelle da guardare fuori dalle radici: solo quella della configurazione di Roundcube",
                dirs.size() == 1 && dirs.get(0).toString().equals("/usr/local/www/roundcube/config"));
    }

    // ===== gli indirizzi in ascolto =====
    private static void listening() {
        // Righe vere della VM, 24/10/2026, con le udp di rspamd in mezzo.
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
        check("sockstat: otto indirizzi TCP distinti (2096, 25 e 587 in v4 e v6, 8443, 11333, 6379)", p.size() == 8);
        check("  i processi di nginx contano una volta", p.containsKey("tcp4 *:8443"));
        check("  le udp no", p.keySet().stream().noneMatch(k -> k.startsWith("udp")));
        check("  tcp46 si'", "java".equals(p.get("tcp46 *:2096")));

        // Il reperto 42 dopo il riavvio: postfix ripartito con un altro pid, senza IPv6.
        String after = before.replace("90660", "91234")
                .replace("root   master     91234 14 tcp6  *:25                  *:*\n", "")
                .replace("root   master     91234 19 tcp6  *:587                 *:*\n", "")
                + "\nroot   nginx      45720  7 tcp4  *:80                  *:*";
        JSONObject cmp = InstallSideEffects.compareListening(p, InstallSideEffects.parseSockstat(after));
        JSONArray lost = cmp.getJSONArray("lost");
        check("persi tcp6 *:25 e tcp6 *:587, e il pid cambiato non conta", lost.length() == 2
                && lost.toString().contains("tcp6 *:25") && lost.toString().contains("tcp6 *:587"));
        check("  con il nome del processo", lost.getJSONObject(0).getString("command").equals("master"));
        check("comparso tcp4 *:80", cmp.getJSONArray("gained").length() == 1
                && cmp.getJSONArray("gained").getJSONObject(0).getString("address").equals("tcp4 *:80"));
        check("stessi indirizzi con altri pid: niente perso, niente comparso",
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
