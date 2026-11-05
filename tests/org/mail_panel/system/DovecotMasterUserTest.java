package org.mail_panel.system;

import org.mail_panel.integration.RoundcubeSsoManager;
import org.mail_panel.scripts.DovecotScript;
import org.mail_panel.scripts.FullMailServerScript;
import org.mail_panel.scripts.FullMailStackScript;
import org.mail_panel.util.Shell;
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
 * L'utente master di Dovecot per «Apri webmail» (DovecotMasterUser): la riparazione all'avvio e il
 * pezzo degli script d'installazione.
 *
 * <p>La riparazione gira su file veri, con proprietari, gruppi e permessi veri, in una cartella
 * temporanea; Dovecot e' finto ma legge master-users come quello vero: come utente dovecot (un file
 * root:wheel 640 non lo apre), una riga "admin:{BLF-CRYPT}hash", la chiave confrontata con bcrypt.
 * Per ogni passo che puo' andare male c'e' un guasto piantato, e dopo un ritorno indietro il file
 * dev'essere com'era: contenuto, proprietario, gruppo e permessi, confrontati con una fotografia.
 *
 * <p>Il pezzo di shell si esegue davvero, col doveadm vero, in una cartella temporanea: anche nella
 * condizione dell'installazione, cioe' con un doveadm che non trova la configurazione. Li' il pezzo
 * di prima (quello di main) deve lasciare "admin:" senza hash, se no la prova non vede il difetto.
 *
 * <p>Tocca proprietari veri e vuole doveadm: va lanciata da root sulla VM FreeBSD col pannello mail
 * installato (gruppo dovecot).
 *   java -cp "tests:&lt;dir&gt;/freebsd-mail-panel-1.0.jar" org.mail_panel.system.DovecotMasterUserTest
 */
public class DovecotMasterUserTest {

    static int failed = 0;
    static final PrintStream OUT = System.out;

    static void check(String what, boolean ok) {
        OUT.println((ok ? "  OK   " : "  FALLITO ") + what);
        if (!ok) failed++;
    }

    static final String KEY = "Q7rTz2KpLm9WxV4cN8bHs3Fd";
    static final String OTHER_KEY = "AAAAbbbbCCCCddddEEEEffff";
    static final String BOX = "alice@prova.test";
    static final String DOVEADM = "/usr/local/bin/doveadm";

    /** Il pezzo di FullMailServerScript in main, prima di questa versione: per vedere il difetto. */
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

    // ===================== il Dovecot finto =====================

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
        /** Come il processo auth di Dovecot, che gira come dovecot: il file lo apre solo se dovecot puo'. */
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

    // ===================== il banco =====================

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

        /** Tutto quello che c'e' nelle due cartelle: nessun file temporaneo deve restare. */
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

    /** Contenuto, proprietario, gruppo e permessi: la fotografia di un file. */
    static String photo(Path p) throws Exception {
        if (!Files.exists(p, LinkOption.NOFOLLOW_LINKS)) return "(missing)";
        PosixFileAttributes a = Files.readAttributes(p, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        String body = a.isSymbolicLink() ? "-> " + Files.readSymbolicLink(p)
                : HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(p)));
        return a.owner().getName() + ":" + a.group().getName() + " " + PosixFilePermissions.toString(a.permissions()) + " " + body;
    }

    static String bcrypt(String key, int cost) { return "{BLF-CRYPT}" + BCrypt.hashpw(key, BCrypt.gensalt(cost)); }

    /** Nessun messaggio del log porta la chiave o l'indirizzo della casella. */
    static void noSecrets(String what, DovecotMasterUser.Report r) {
        check(what + ": nel messaggio ne' la chiave ne' l'indirizzo",
                !r.detail().contains(KEY) && !r.detail().contains(BOX) && !r.detail().contains("\n"));
    }

    // ===================== la riparazione =====================

    static void repairCases() throws Exception {
        OUT.println("== la riga senza hash, come la lasciava FullMailServerScript");
        for (String content : List.of("admin:\n", "admin:")) {
            Bench b = new Bench();
            b.users(content, "root", "dovecot", "rw-r-----");
            b.key(KEY + "\n");
            FakeDovecot d = new FakeDovecot(b.masterUsers);
            check("[" + content.replace("\n", "\\n") + "] prima, il Dovecot finto rifiuta l'utente master (vede il difetto)",
                    !d.authTest(BOX + "*admin", KEY).success());
            d.authTests = 0; d.calls = 0;
            DovecotMasterUser.Report r = DovecotMasterUser.repair(b.at, d);
            check("DONE (" + r + ")", r.outcome() == DovecotMasterUser.Outcome.DONE);
            String after = Files.readString(b.masterUsers, StandardCharsets.US_ASCII);
            check("una riga admin:{BLF-CRYPT}$2a$12$...", Pattern.matches("admin:\\{BLF-CRYPT\\}\\$2a\\$12\\$[./A-Za-z0-9]{53}\\n", after));
            check("l'hash e' quello della chiave", DovecotMasterUser.matches(KEY, after.substring(6).trim()));
            check("e non quello di un'altra chiave", !DovecotMasterUser.matches(OTHER_KEY, after.substring(6).trim()));
            check("root:dovecot rw-r-----", photo(b.masterUsers).startsWith("root:dovecot rw-r----- "));
            check("verificato con un accesso master vero (auth test chiamato una volta)", d.authTests == 1);
            check("il messaggio dice la casella col numero", r.detail().contains("mailbox #7*admin"));
            noSecrets("DONE", r);
            check("nessun file temporaneo", b.files().equals(List.of("db/dovecot_master.key", "etc/master-users")));
            check("la chiave non e' stata toccata", Files.readString(b.key).equals(KEY + "\n"));
            String once = photo(b.masterUsers);
            d.calls = 0;
            DovecotMasterUser.Report again = DovecotMasterUser.repair(b.at, d);
            check("la seconda volta NOTHING (" + again + ")", again.outcome() == DovecotMasterUser.Outcome.NOTHING);
            check("la seconda volta non chiede niente a Dovecot", d.calls == 0);
            check("la seconda volta il file e' identico", photo(b.masterUsers).equals(once));
            b.close();
        }

        OUT.println("== guasti prima di cambiare: niente cambia");
        {
            Bench b = new Bench();
            b.users("admin:\n", "root", "dovecot", "rw-r-----"); b.key(KEY + "\n");
            String before = photo(b.masterUsers);
            FakeDovecot d = new FakeDovecot(b.masterUsers); d.answering = false;
            DovecotMasterUser.Report r = DovecotMasterUser.repair(b.at, d);
            check("Dovecot spento: NOT_ANSWERING (" + r + ")", r.outcome() == DovecotMasterUser.Outcome.NOT_ANSWERING);
            check("Dovecot spento: file identico", photo(b.masterUsers).equals(before));
            check("Dovecot spento: nessun auth test", d.authTests == 0);
            noSecrets("NOT_ANSWERING", r);

            d = new FakeDovecot(b.masterUsers); d.listFails = true;
            r = DovecotMasterUser.repair(b.at, d);
            check("il database delle caselle non risponde: NOT_ANSWERING (" + r + ")", r.outcome() == DovecotMasterUser.Outcome.NOT_ANSWERING);
            check("il database delle caselle non risponde: file identico", photo(b.masterUsers).equals(before));
            b.close();
        }

        OUT.println("== guasti dopo aver scritto: il file torna com'era");
        {
            Bench b = new Bench();
            b.users("admin:\n", "root", "dovecot", "rw-r-----"); b.key(KEY + "\n");
            String before = photo(b.masterUsers);
            FakeDovecot d = new FakeDovecot(b.masterUsers); d.rejectMaster = true;
            DovecotMasterUser.Report r = DovecotMasterUser.repair(b.at, d);
            check("l'utente master non entra: ROLLED_BACK (" + r + ")", r.outcome() == DovecotMasterUser.Outcome.ROLLED_BACK);
            check("l'utente master non entra: file identico, proprietario e permessi compresi", photo(b.masterUsers).equals(before));
            check("l'utente master non entra: nessun file temporaneo", b.files().equals(List.of("db/dovecot_master.key", "etc/master-users")));
            check("l'utente master non entra: il messaggio lo dice", r.detail().contains("auth test") && r.detail().contains("put back"));
            noSecrets("ROLLED_BACK", r);
            d.rejectMaster = false;
            r = DovecotMasterUser.repair(b.at, d);
            check("tolto il guasto, al prossimo avvio DONE (" + r + ")", r.outcome() == DovecotMasterUser.Outcome.DONE);
            b.close();

            // Il ritorno indietro rimette anche proprietario e permessi diversi da quelli giusti.
            b = new Bench();
            b.users("admin:\n", "root", "wheel", "rw-r--r--"); b.key(KEY + "\n");
            before = photo(b.masterUsers);
            d = new FakeDovecot(b.masterUsers); d.rejectMaster = true;
            r = DovecotMasterUser.repair(b.at, d);
            check("root:wheel 644 senza hash, non entra: ROLLED_BACK", r.outcome() == DovecotMasterUser.Outcome.ROLLED_BACK);
            check("root:wheel 644 senza hash, non entra: torna root:wheel 644", photo(b.masterUsers).equals(before));
            b.close();
        }

        OUT.println("== senza caselle: l'hash lo verifica doveadm pw -t");
        {
            Bench b = new Bench();
            b.users("admin:\n", "root", "dovecot", "rw-r-----"); b.key(KEY + "\n");
            String before = photo(b.masterUsers);
            FakeDovecot d = new FakeDovecot(b.masterUsers); d.boxes.clear(); d.pwRefuses = true;
            DovecotMasterUser.Report r = DovecotMasterUser.repair(b.at, d);
            check("pw -t rifiuta: ROLLED_BACK (" + r + ")", r.outcome() == DovecotMasterUser.Outcome.ROLLED_BACK);
            check("pw -t rifiuta: file identico", photo(b.masterUsers).equals(before));
            d.pwRefuses = false;
            r = DovecotMasterUser.repair(b.at, d);
            check("pw -t accetta: DONE (" + r + ")", r.outcome() == DovecotMasterUser.Outcome.DONE);
            check("pw -t accetta: il messaggio dice che manca un accesso vero", r.detail().contains("no active mailbox"));
            check("pw -t accetta: nessun auth test, una verifica", d.authTests == 0 && d.verifies == 2);
            check("pw -t accetta: l'hash e' della chiave", DovecotMasterUser.matches(KEY, Files.readString(b.masterUsers).substring(6).trim()));
            b.close();
        }

        OUT.println("== il file di FullMailStackScript: l'hash c'e', ma root:wheel");
        {
            Bench b = new Bench();
            // doveadm pw scrive $2y$: deve riconoscerlo come quello della chiave
            String h = bcrypt(KEY, 5).replace("$2a$", "$2y$");
            b.users("admin:" + h + "\n", "root", "wheel", "rw-r-----"); b.key(KEY + "\n");
            String content = Files.readString(b.masterUsers);
            FakeDovecot d = new FakeDovecot(b.masterUsers);
            check("prima, il Dovecot finto non apre il file (come quello vero: Permission denied)", !d.authTest(BOX + "*admin", KEY).success());
            d.authTests = 0;
            DovecotMasterUser.Report r = DovecotMasterUser.repair(b.at, d);
            check("DONE (" + r + ")", r.outcome() == DovecotMasterUser.Outcome.DONE);
            check("root:dovecot rw-r-----", photo(b.masterUsers).startsWith("root:dovecot rw-r----- "));
            check("contenuto identico", Files.readString(b.masterUsers).equals(content));
            check("il messaggio dice com'era", r.detail().contains("root:wheel rw-r-----"));
            check("verificato con un accesso master vero", d.authTests == 1);
            d.calls = 0;
            check("la seconda volta NOTHING, senza chiedere niente",
                    DovecotMasterUser.repair(b.at, d).outcome() == DovecotMasterUser.Outcome.NOTHING && d.calls == 0);
            b.close();

            b = new Bench();
            b.users("admin:" + h + "\n", "root", "wheel", "rw-r-----"); b.key(KEY + "\n");
            String before = photo(b.masterUsers);
            d = new FakeDovecot(b.masterUsers); d.rejectMaster = true;
            r = DovecotMasterUser.repair(b.at, d);
            check("root:wheel, non entra lo stesso: ROLLED_BACK (" + r + ")", r.outcome() == DovecotMasterUser.Outcome.ROLLED_BACK);
            check("root:wheel, non entra lo stesso: torna root:wheel, identico", photo(b.masterUsers).equals(before));
            b.close();

            b = new Bench();
            b.users("admin:" + bcrypt(KEY, 5) + "\n", "root", "dovecot", "rw-------"); b.key(KEY + "\n");
            d = new FakeDovecot(b.masterUsers);
            r = DovecotMasterUser.repair(b.at, d);
            check("root:dovecot 600 (dovecot non legge): DONE, adesso 640", r.outcome() == DovecotMasterUser.Outcome.DONE
                    && photo(b.masterUsers).startsWith("root:dovecot rw-r----- "));
            b.close();
        }

        OUT.println("== non si sceglie per nessuno");
        {
            String okHash = bcrypt(KEY, 5);
            Map<String, String> notOurs = new LinkedHashMap<>();
            notOurs.put("{PLAIN} scritto a mano", "admin:{PLAIN}" + KEY + "\n");
            notOurs.put("due utenti", "admin:\nbackup:" + okHash + "\n");
            notOurs.put("un commento", "# master user\nadmin:\n");
            notOurs.put("admin con l'hash e un altro utente", "admin:" + okHash + "\nbob:" + okHash + "\n");
            notOurs.put("altri campi passwd-file", "admin:" + okHash + "::::::\n");
            notOurs.put("un altro nome", "root:\n");
            notOurs.put("riga vuota in piu'", "admin:\n\n");
            notOurs.put("non ASCII", "admin:è\n");
            for (Map.Entry<String, String> e : notOurs.entrySet()) {
                Bench b = new Bench();
                Files.write(b.masterUsers, e.getValue().getBytes(StandardCharsets.UTF_8));
                attrs(b.masterUsers, "root", "wheel", "rw-r-----");
                b.key(KEY + "\n");
                String before = photo(b.masterUsers);
                FakeDovecot d = new FakeDovecot(b.masterUsers);
                DovecotMasterUser.Report r = DovecotMasterUser.repair(b.at, d);
                check(e.getKey() + ": NOT_OURS, file identico, nessuna domanda a Dovecot (" + r.outcome() + ")",
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
            check("un link: NOT_OURS, il file a cui punta identico", r.outcome() == DovecotMasterUser.Outcome.NOT_OURS
                    && photo(real).equals(target) && Files.isSymbolicLink(b.masterUsers));
            b.close();

            b = new Bench();
            b.users("admin:" + bcrypt(OTHER_KEY, 5) + "\n", "root", "wheel", "rw-r-----"); b.key(KEY + "\n");
            String before = photo(b.masterUsers);
            FakeDovecot d = new FakeDovecot(b.masterUsers);
            r = DovecotMasterUser.repair(b.at, d);
            check("l'hash di un'altra chiave: MISMATCH (" + r + ")", r.outcome() == DovecotMasterUser.Outcome.MISMATCH);
            check("l'hash di un'altra chiave: file identico, anche root:wheel", photo(b.masterUsers).equals(before) && d.calls == 0);
            noSecrets("MISMATCH", r);

            Map<String, String> badKeys = new LinkedHashMap<>();
            badKeys.put("chiave vuota", "\n");
            badKeys.put("chiave con uno spazio dentro", "abcd efgh ijkl\n");
            badKeys.put("chiave troppo lunga per bcrypt", "x".repeat(73) + "\n");
            badKeys.put("chiave troppo corta", "abc\n");
            for (Map.Entry<String, String> e : badKeys.entrySet()) {
                b.users("admin:\n", "root", "dovecot", "rw-r-----"); b.key(e.getValue());
                before = photo(b.masterUsers);
                d = new FakeDovecot(b.masterUsers);
                r = DovecotMasterUser.repair(b.at, d);
                check(e.getKey() + ": NO_KEY, file identico (" + r.outcome() + ")",
                        r.outcome() == DovecotMasterUser.Outcome.NO_KEY && photo(b.masterUsers).equals(before) && d.calls == 0);
            }
            b.users("admin:\n", "root", "dovecot", "rw-r-----");
            Files.delete(b.key);
            before = photo(b.masterUsers);
            r = DovecotMasterUser.repair(b.at, new FakeDovecot(b.masterUsers));
            check("senza chiave: NO_KEY, file identico", r.outcome() == DovecotMasterUser.Outcome.NO_KEY && photo(b.masterUsers).equals(before));
            Path realKey = b.db.resolve("real.key");
            Files.writeString(realKey, KEY + "\n");
            Files.createSymbolicLink(b.key, realKey);
            r = DovecotMasterUser.repair(b.at, new FakeDovecot(b.masterUsers));
            check("la chiave e' un link: NO_KEY", r.outcome() == DovecotMasterUser.Outcome.NO_KEY && photo(b.masterUsers).equals(before));
            b.close();

            b = new Bench();
            r = DovecotMasterUser.repair(b.at, new FakeDovecot(b.masterUsers));
            check("master-users non c'e': NOTHING", r.outcome() == DovecotMasterUser.Outcome.NOTHING && !Files.exists(b.masterUsers));
            b.users("admin:" + bcrypt(KEY, 5) + "\n", "root", "dovecot", "rw-r-----"); b.key(KEY + "\n");
            FakeDovecot quiet = new FakeDovecot(b.masterUsers);
            r = DovecotMasterUser.repair(b.at, quiet);
            check("gia' giusto: NOTHING, senza chiedere niente", r.outcome() == DovecotMasterUser.Outcome.NOTHING && quiet.calls == 0);
            b.close();
        }
    }

    // ===================== gli script =====================

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

    /** Un doveadm finto davanti a quello vero: il testo dopo #!/bin/sh. */
    static Path fakeDoveadm(Bench b, String name, String body) throws Exception {
        Path dir = Files.createDirectories(b.root.resolve("bin-" + name));
        Path f = dir.resolve("doveadm");
        Files.writeString(f, "#!/bin/sh\n" + body + "\n");
        Files.setPosixFilePermissions(f, PosixFilePermissions.fromString("rwx------"));
        return dir;
    }

    static void scriptCases() throws Exception {
        OUT.println("== i nomi che viaggiano fra il pannello e la riparazione");
        Field u = RoundcubeSsoManager.class.getDeclaredField("MASTER_USER"); u.setAccessible(true);
        Field k = RoundcubeSsoManager.class.getDeclaredField("MASTER_PASSWORD_FILE"); k.setAccessible(true);
        check("USER e' l'utente master dell'SSO", DovecotMasterUser.USER.equals(u.get(null)));
        check("KEY_FILE e' la chiave che legge l'SSO", DovecotMasterUser.KEY_FILE.equals(k.get(null)));

        OUT.println("== i tre script");
        Map<String, String> scripts = new LinkedHashMap<>();
        scripts.put("FullMailServerScript", new FullMailServerScript().getScriptContent());
        scripts.put("FullMailStackScript", new FullMailStackScript().getScriptContent());
        scripts.put("DovecotScript", new DovecotScript().getScriptContent());
        String fragment = DovecotMasterUser.shell();
        for (Map.Entry<String, String> e : scripts.entrySet()) {
            String s = e.getValue();
            check(e.getKey() + ": contiene il pezzo, una volta", s.indexOf(fragment) >= 0 && s.indexOf(fragment) == s.lastIndexOf(fragment));
            // Fuori dal pezzo master-users compare solo dove Dovecot lo legge (auth-master.conf.ext,
            // 2.3 e 2.4) o in un commento: nessuno lo scrive, ne' gli cambia proprietario o permessi.
            List<String> others = s.replace(fragment, "").lines()
                    .filter(l -> l.contains("master-users"))
                    .filter(l -> !l.trim().startsWith("#") && !l.trim().matches("(args|passwd_file_path)\\s*=\\s*" + Pattern.quote(DovecotMasterUser.MASTER_USERS)))
                    .toList();
            check(e.getKey() + ": nessun altro scrive master-users" + (others.isEmpty() ? "" : " " + others), others.isEmpty());
            check(e.getKey() + ": niente password fra gli argomenti di doveadm, niente {PLAIN}",
                    !s.contains("doveadm pw -s BLF-CRYPT -p") && !s.contains("{PLAIN}"));
            check(e.getKey() + ": niente root:wheel per master-users", !s.contains("chown root:wheel /usr/local/etc/dovecot/master-users"));
            Path f = Files.createTempFile(Path.of("/var/tmp"), "dovecot-master-script-", ".sh");
            Files.writeString(f, s);
            Shell.Result n = Shell.run(java.time.Duration.ofSeconds(20), "sh", "-n", f.toString());
            check(e.getKey() + ": sh -n lo accetta" + (n.success() ? "" : " (" + n.outputTrim() + ")"), n.success());
            Files.delete(f);
        }
        check("il pezzo usa doveadm -O e lo standard input, e controlla con pw -t",
                fragment.contains("doveadm -O pw -s BLF-CRYPT 2>/dev/null") && fragment.contains("doveadm -O pw -t")
                        && !fragment.contains("-p \"$MASTER_PASSWORD\""));

        if (!Files.isExecutable(Path.of(DOVEADM))) {
            OUT.println("  SALTATO il pezzo eseguito: " + DOVEADM + " non c'e' (va lanciata sulla VM)");
            failed++;
            return;
        }

        OUT.println("== il pezzo eseguito col doveadm vero");
        {
            Bench b = new Bench();
            Path run = b.root.resolve("fragment.sh");
            Files.writeString(run, DovecotMasterUser.shell(b.key.toString(), b.masterUsers.toString()));
            Shell.Result r = sh(run, null);
            check("esce 0 senza [ERROR] (" + r.outputTrim() + ")", r.success() && !r.output().contains("[ERROR]"));
            checkFragmentResult(b, "doveadm vero");
            b.close();
        }

        OUT.println("== come all'installazione: doveadm non trova la configurazione");
        {
            Bench b = new Bench();
            Path bin = fakeDoveadm(b, "noconf", "exec " + DOVEADM + " -c /nonexistent/dovecot.conf \"$@\"");
            Shell.Result probe = Shell.run(java.time.Duration.ofSeconds(20), bin.resolve("doveadm").toString(), "pw", "-s", "BLF-CRYPT", "-p", "x");
            check("senza -O questo doveadm esce con 75, come all'installazione (" + probe.exitCode() + ")", probe.exitCode() == 75);
            Path oldRun = b.root.resolve("old.sh");
            Files.writeString(oldRun, oldFragment(b.key.toString(), b.masterUsers.toString()));
            sh(oldRun, bin);
            String oldResult = Files.readString(b.masterUsers);
            check("il pezzo di prima lascia 'admin:' senza hash (la prova vede il difetto)", oldResult.equals("admin:\n"));

            // Quello che il pezzo di prima ha lasciato, la riparazione lo sistema: i byte veri, non una stringa scritta qui.
            FakeDovecot d = new FakeDovecot(b.masterUsers);
            DovecotMasterUser.Report rep = DovecotMasterUser.repair(b.at, d);
            check("e la riparazione all'avvio lo sistema (" + rep.outcome() + ")", rep.outcome() == DovecotMasterUser.Outcome.DONE
                    && DovecotMasterUser.matches(Files.readString(b.key).trim(), Files.readString(b.masterUsers).substring(6).trim()));

            Path run = b.root.resolve("fragment.sh");
            Files.writeString(run, DovecotMasterUser.shell(b.key.toString(), b.masterUsers.toString()));
            Shell.Result r = sh(run, bin);
            check("il pezzo nuovo esce 0 senza [ERROR] (" + r.outputTrim() + ")", r.success() && !r.output().contains("[ERROR]"));
            checkFragmentResult(b, "senza configurazione");
            b.close();
        }

        OUT.println("== guasti di doveadm: niente hash sbagliato, e l'errore si dice");
        Map<String, String> faults = new LinkedHashMap<>();
        faults.put("doveadm esce con 75", "echo 'Fatal: Error reading configuration' >&2; exit 75");
        faults.put("doveadm stampa un errore con 0", "echo 'Error: something'; exit 0");
        faults.put("pw -s da' l'hash della password vuota (le due righe che non coincidono)",
                "case \"$*\" in *' -s '*) printf '\\n\\n' | " + DOVEADM + " -O pw -s BLF-CRYPT ;; *) exec " + DOVEADM + " \"$@\" ;; esac");
        faults.put("pw -s da' l'hash di un'altra password",
                "case \"$*\" in *' -s '*) printf 'other\\nother\\n' | " + DOVEADM + " -O pw -s BLF-CRYPT ;; *) exec " + DOVEADM + " \"$@\" ;; esac");
        for (Map.Entry<String, String> e : faults.entrySet()) {
            Bench b = new Bench();
            Path bin = fakeDoveadm(b, "fault", e.getValue());
            Path run = b.root.resolve("fragment.sh");
            Files.writeString(run, DovecotMasterUser.shell(b.key.toString(), b.masterUsers.toString()));
            Shell.Result r = sh(run, bin);
            check(e.getKey() + ": [ERROR] nell'uscita", r.output().contains("[ERROR]"));
            check(e.getKey() + ": master-users 'admin:' senza hash, root:dovecot 640",
                    Files.readString(b.masterUsers).equals("admin:\n") && photo(b.masterUsers).startsWith("root:dovecot rw-r----- "));
            check(e.getKey() + ": la chiave c'e' lo stesso (la riparazione all'avvio ne ha bisogno)",
                    Pattern.matches("[A-Za-z0-9]{24}\\n", Files.readString(b.key)));
            b.close();
        }
    }

    static void checkFragmentResult(Bench b, String what) throws Exception {
        String key = Files.readString(b.key);
        check(what + ": chiave di 24 lettere e cifre, root 600", Pattern.matches("[A-Za-z0-9]{24}\\n", key)
                && photo(b.key).startsWith("root:wheel rw------- "));
        String users = Files.readString(b.masterUsers);
        check(what + ": master-users una riga admin:{BLF-CRYPT}$2y$ (" + users.length() + " byte)",
                Pattern.matches("admin:\\{BLF-CRYPT\\}\\$2y\\$[0-9]{2}\\$[./A-Za-z0-9]{53}\\n", users));
        check(what + ": l'hash e' quello della chiave", DovecotMasterUser.matches(key.trim(), users.substring(6).trim()));
        check(what + ": master-users root:dovecot 640", photo(b.masterUsers).startsWith("root:dovecot rw-r----- "));
        check(what + ": nessun .new rimasto", b.files().equals(List.of("db/dovecot_master.key", "etc/master-users")));
        // E la riparazione all'avvio lo riconosce come gia' giusto.
        FakeDovecot d = new FakeDovecot(b.masterUsers);
        check(what + ": la riparazione all'avvio non fa niente", DovecotMasterUser.repair(b.at, d).outcome()
                == DovecotMasterUser.Outcome.NOTHING && d.calls == 0);
    }

    public static void main(String[] args) throws Exception {
        repairCases();
        scriptCases();
        OUT.println(failed == 0 ? "TUTTO OK" : failed + " FALLITI");
        System.exit(failed == 0 ? 0 : 1);
    }
}
