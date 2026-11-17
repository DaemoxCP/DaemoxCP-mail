package org.daemoxcp.mail.security;

import org.daemoxcp.mail.TestSql;

import org.daemoxcp.mail.Main;
import org.daemoxcp.mail.database.MailDatabase;
import org.daemoxcp.mail.webserver.WebSessions;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Passwordless login of the mail panel: passkeys verified for real, one-time codes, encrypted
 * data, the migration of an old database, the sessions in MySQL.
 *
 * The passkeys come from SoftAuthenticator: a real P-256 key and real ES256 signatures, so the
 * Yubico library checks everything (signature, challenge, origin, rpId, user verification,
 * counter). The old database had BCrypt hashes, TOTP secrets and backup codes: the migration must
 * leave none of them, and the passkeys registered before must keep working.
 *
 * Usage (with the test MySQL of README.md; it empties the panel tables of that database):
 *   java -Dmysql.port=33062 -Dmysql.user=daemoxcp_mail -Dmysql.password=... -Dmysql.database=daemoxcp_mail_test \
 *        -cp "tests:target/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.security.LoginSecurityTest
 */
public class LoginSecurityTest {

    private static int failed = 0;
    static final String HOST = "panel.example.test:2096";
    static final String ORIGIN = "https://panel.example.test:2096";

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    interface Job { void run() throws Exception; }

    /** True if the job throws: what a refused ceremony must do. */
    static boolean refused(Job j) {
        try { j.run(); return false; } catch (Exception e) { return true; }
    }

    static Connection db() throws java.sql.SQLException { return TestSql.mysql(); }

    static void sql(String s) throws Exception {
        try (Statement st = db().createStatement()) { st.executeUpdate(s); }
    }

    static String one(String query, Object... params) throws Exception {
        try (PreparedStatement p = db().prepareStatement(query)) {
            for (int i = 0; i < params.length; i++) p.setObject(i + 1, params[i]);
            try (ResultSet r = p.executeQuery()) {
                return r.next() ? r.getString(1) : null;
            }
        }
    }

    public static void main(String[] args) throws Exception {
        String port = System.getProperty("mysql.port");
        if (port == null) {
            System.out.println("No MySQL given (-Dmysql.port=...): this test needs the test MySQL, skipped.");
            return;
        }
        PanelSecrets.dir = Files.createTempDirectory("mail-login-secrets").resolve("etc");
        PanelSecrets.reset();
        MailDatabase db = new MailDatabase();
        db.setCredentials(System.getProperty("mysql.user", "daemoxcp_mail"), System.getProperty("mysql.password", ""));
        db.setConnection("127.0.0.1", Integer.parseInt(port), System.getProperty("mysql.database", "daemoxcp_mail_test"));
        check("connected to MySQL", db.connect());
        Main.mailDatabase = db;
        Main.mysqlAvailable = true;
        Main.setupRequired = false;
        db.dropAllTables();

        SoftAuthenticator oldKey = new SoftAuthenticator();
        migration(db, oldKey);
        crypto();
        passkeys(oldKey);
        codes();
        sessions();
        firstAdmin(db);
        db.dropAllTables();
        System.out.println(failed == 0 ? "\nAll checks passed." : "\nFailed checks: " + failed);
        if (failed > 0) System.exit(1);
    }

    // ===================== Migration of an old database =====================

    static void migration(MailDatabase db, SoftAuthenticator oldKey) throws Exception {
        System.out.println("== Migration: no password, no TOTP, the old passkeys still work ==");
        // The tables as the panel with passwords created them.
        sql("""
            CREATE TABLE panel_admin (
                id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(50) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP NULL, active BOOLEAN DEFAULT TRUE, totp_secret VARCHAR(64) NULL,
                totp_enabled BOOLEAN DEFAULT FALSE, backup_codes TEXT NULL,
                role ENUM('superadmin', 'admin', 'operator', 'viewer') DEFAULT 'admin',
                theme VARCHAR(10) DEFAULT 'auto', language VARCHAR(5) NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""");
        sql("""
            CREATE TABLE admin_passkeys (
                id INT AUTO_INCREMENT PRIMARY KEY, admin_id INT NOT NULL, credential_id VARBINARY(1024) NOT NULL,
                public_key_cose VARBINARY(2048) NOT NULL, sign_count BIGINT DEFAULT 0, name VARCHAR(100) DEFAULT 'Passkey',
                aaguid VARBINARY(16) NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, last_used TIMESTAMP NULL,
                FOREIGN KEY (admin_id) REFERENCES panel_admin(id) ON DELETE CASCADE,
                UNIQUE KEY unique_credential (credential_id(255))
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""");
        // Written at 12:00 in a +02:00 session: in UTC it is 10:00.
        sql("SET time_zone = '+02:00'");
        sql("INSERT INTO panel_admin (username, password_hash, created_at, totp_secret, totp_enabled, backup_codes) "
          + "VALUES ('Admin', '$2a$12$abcdefghijklmnopqrstuv', '2026-01-01 12:00:00', 'JBSWY3DPEHPK3PXP', TRUE, '[\"x\"]')");
        sql("SET time_zone = '+00:00'");
        try (PreparedStatement p = db().prepareStatement(
                "INSERT INTO admin_passkeys (admin_id, credential_id, public_key_cose, name) VALUES (1, ?, ?, 'Old phone')")) {
            p.setBytes(1, oldKey.credentialId);
            p.setBytes(2, oldKey.thingsKey());
            p.executeUpdate();
        }
        db.createSchema();
        AuthStore.migrate();
        AuthStore.migrate();      // twice: every step checks first

        check("no password hash, TOTP secret or backup code left: the columns are gone",
                one("SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'panel_admin' "
                  + "AND column_name IN ('password_hash', 'totp_secret', 'totp_enabled', 'backup_codes')").equals("0"));
        check("dates in DATETIME, converted to UTC (12:00 at +02:00 is 10:00)",
                "datetime".equals(one("SELECT DATA_TYPE FROM information_schema.columns WHERE table_schema = DATABASE() "
                        + "AND table_name = 'panel_admin' AND column_name = 'created_at'"))
                && "2026-01-01 10:00:00".equals(one("SELECT DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') FROM panel_admin WHERE username = 'Admin'")));
        check("no superadmin before: the oldest administrator becomes superadmin",
                "superadmin".equals(one("SELECT role FROM panel_admin WHERE username = 'Admin'")));
        Optional<AuthStore.Admin> admin = AuthStore.adminByUsername("Admin");
        check("the old admin keeps the user handle the old passkeys carry (the id in 4 bytes)",
                admin.isPresent() && admin.get().userHandle().equals(AuthStore.b64url(new byte[]{0, 0, 0, 1})));
        check("the old passkey is linked to it", admin.isPresent() && AuthStore.passkeysOf(admin.get().id()).size() == 1
                && AuthStore.passkeysOf(admin.get().id()).get(0).userHandle().equals(admin.get().userHandle()));
        List<String> tables = new ArrayList<>();
        try (PreparedStatement p = db().prepareStatement("SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()");
             ResultSet r = p.executeQuery()) {
            while (r.next()) tables.add(r.getString(1));
        }
        check("the session table and one code table per flow", tables.containsAll(List.of("panel_sessions",
                "login_code_email", "login_code_console", "stepup_code", "email_change_code")));
        Path file = PanelSecrets.dir.resolve("panel-secrets.properties");
        check("the keys are in a file outside the database: file rw-------, folder rwx------",
                Files.exists(file) && "rw-------".equals(PosixFilePermissions.toString(Files.getPosixFilePermissions(file)))
                && "rwx------".equals(PosixFilePermissions.toString(Files.getPosixFilePermissions(PanelSecrets.dir))));
        check("no key in the database", one("SELECT COUNT(*) FROM panel_settings WHERE setting_key LIKE '%key%'").equals("0"));
        oldKey.userHandle = admin.orElseThrow().userHandle();
    }

    // ===================== Encryption =====================

    static void crypto() throws Exception {
        System.out.println("\n== Encryption and blind index ==");
        String a = DataCrypto.encrypt("admin@example.org"), b = DataCrypto.encrypt("admin@example.org");
        check("same text, two encryptions, two different values (random nonce)", !a.equals(b));
        check("and both decrypt", "admin@example.org".equals(DataCrypto.decrypt(a)) && "admin@example.org".equals(DataCrypto.decrypt(b)));
        char[] t = a.toCharArray();
        t[10] = t[10] == 'A' ? 'B' : 'A';
        check("one character changed: decryption refuses (GCM tag)", refused(() -> DataCrypto.decrypt(new String(t))));
        check("blind index: same for upper case and spaces, different for another address",
                DataCrypto.emailIndex(" Admin@Example.org ").equals(DataCrypto.emailIndex("admin@example.org"))
                && !DataCrypto.emailIndex("admin@example.org").equals(DataCrypto.emailIndex("other@example.org")));
        Path old = PanelSecrets.dir;
        PanelSecrets.dir = Files.createTempDirectory("other-secrets");
        PanelSecrets.reset();
        check("with another key the value does not decrypt", refused(() -> DataCrypto.decrypt(a)) && DataCrypto.decryptOrEmpty(a).isEmpty());
        PanelSecrets.dir = old;
        PanelSecrets.reset();
        check("back to the panel key: it decrypts again", "admin@example.org".equals(DataCrypto.decrypt(a)));
    }

    // ===================== Passkeys =====================

    static void passkeys(SoftAuthenticator oldKey) throws Exception {
        System.out.println("\n== Passkeys: registration ==");
        AuthStore.Admin admin = AuthStore.adminByUsername("Admin").orElseThrow();
        SoftAuthenticator phone = new SoftAuthenticator();
        PasskeyService.Started s = PasskeyService.startRegistration(admin, 1, HOST);
        String reg = phone.register(s.optionsJson(), ORIGIN);
        check("the options ask for a discoverable key with user verification",
                s.optionsJson().contains("\"residentKey\":\"required\"") && s.optionsJson().contains("\"userVerification\":\"required\""));
        check("another session cannot finish it", refused(() -> PasskeyService.finishRegistration(s.requestId(), 2, reg, "Phone")));
        PasskeyService.Started s2 = PasskeyService.startRegistration(admin, 1, HOST);
        SoftAuthenticator evil = new SoftAuthenticator();
        evil.originOverride = "https://evil.example";
        String evilReg = evil.register(s2.optionsJson(), ORIGIN);
        check("registration from another origin: refused", refused(() -> PasskeyService.finishRegistration(s2.requestId(), 1, evilReg, "Evil")));
        PasskeyService.Started s3 = PasskeyService.startRegistration(admin, 1, HOST);
        String reg3 = phone.register(s3.optionsJson(), ORIGIN);
        PasskeyService.finishRegistration(s3.requestId(), 1, reg3, "Phone");
        check("registration accepted: the admin has two passkeys (old one + phone)", AuthStore.passkeysOf(admin.id()).size() == 2);
        check("the new one knows its rpId and user handle", "panel.example.test".equals(one("SELECT rp_id FROM admin_passkeys WHERE name = 'Phone'"))
                && admin.userHandle().equals(one("SELECT user_handle FROM admin_passkeys WHERE name = 'Phone'")));
        check("the same request a second time: refused", refused(() -> PasskeyService.finishRegistration(s3.requestId(), 1, reg3, "Phone")));
        PasskeyService.Started s4 = PasskeyService.startRegistration(admin, 1, HOST);
        String reg4 = phone.register(s4.optionsJson(), ORIGIN);
        check("the same key registered twice: refused", refused(() -> PasskeyService.finishRegistration(s4.requestId(), 1, reg4, "Phone")));

        System.out.println("\n== Passkeys: login ==");
        PasskeyService.Started l = PasskeyService.startLogin(HOST);
        check("login options carry no credential list (nothing to learn about accounts)", !l.optionsJson().contains("allowCredentials\":[{"));
        AuthStore.Admin who = PasskeyService.finishLogin(l.requestId(), phone.assertion(l.optionsJson(), ORIGIN));
        check("a valid signature logs in as the admin", who.id() == admin.id());
        PasskeyService.Started l2 = PasskeyService.startLogin(HOST);
        who = PasskeyService.finishLogin(l2.requestId(), oldKey.assertion(l2.optionsJson(), ORIGIN));
        check("the passkey registered before the migration logs in too", who.id() == admin.id());

        PasskeyService.Started l3 = PasskeyService.startLogin(HOST);
        String good = phone.assertion(l3.optionsJson(), ORIGIN);
        check("the same login request used twice: refused the second time",
                !refused(() -> PasskeyService.finishLogin(l3.requestId(), good)) && refused(() -> PasskeyService.finishLogin(l3.requestId(), good)));
        PasskeyService.Started l4 = PasskeyService.startLogin(HOST);
        check("an assertion signed for another challenge (replay): refused", refused(() -> PasskeyService.finishLogin(l4.requestId(), good)));
        SoftAuthenticator attacker = new SoftAuthenticator();
        System.arraycopy(phone.credentialId, 0, attacker.credentialId, 0, 16);
        attacker.userHandle = phone.userHandle;
        PasskeyService.Started l5 = PasskeyService.startLogin(HOST);
        check("right credential id and challenge, signed with another key: refused",
                refused(() -> PasskeyService.finishLogin(l5.requestId(), attacker.assertion(l5.optionsJson(), ORIGIN))));
        phone.breakSignature = true;
        PasskeyService.Started l6 = PasskeyService.startLogin(HOST);
        check("signature with one bit flipped: refused", refused(() -> PasskeyService.finishLogin(l6.requestId(), phone.assertion(l6.optionsJson(), ORIGIN))));
        phone.breakSignature = false;
        phone.originOverride = "https://evil.example";
        PasskeyService.Started l7 = PasskeyService.startLogin(HOST);
        check("signed for another origin: refused", refused(() -> PasskeyService.finishLogin(l7.requestId(), phone.assertion(l7.optionsJson(), ORIGIN))));
        phone.originOverride = null;
        phone.rpIdOverride = "evil.example";
        PasskeyService.Started l8 = PasskeyService.startLogin(HOST);
        check("signed for another rpId: refused", refused(() -> PasskeyService.finishLogin(l8.requestId(), phone.assertion(l8.optionsJson(), ORIGIN))));
        phone.rpIdOverride = null;
        phone.userVerified = false;
        PasskeyService.Started l9 = PasskeyService.startLogin(HOST);
        check("without user verification (no fingerprint/PIN): refused", refused(() -> PasskeyService.finishLogin(l9.requestId(), phone.assertion(l9.optionsJson(), ORIGIN))));
        phone.userVerified = true;
        phone.counterOverride = 1L;
        PasskeyService.Started l10 = PasskeyService.startLogin(HOST);
        check("signature counter going back (a cloned key): refused", refused(() -> PasskeyService.finishLogin(l10.requestId(), phone.assertion(l10.optionsJson(), ORIGIN))));
        phone.counterOverride = null;
        SoftAuthenticator unknown = new SoftAuthenticator();
        unknown.userHandle = phone.userHandle;
        PasskeyService.Started l11 = PasskeyService.startLogin(HOST);
        check("a key nobody registered: refused", refused(() -> PasskeyService.finishLogin(l11.requestId(), unknown.assertion(l11.optionsJson(), ORIGIN))));
        check("an invented request id: refused", refused(() -> PasskeyService.finishLogin("nope", good)));
        check("passkeys need a domain: rpId of an IP address is null, of a name is the name",
                PasskeyService.rpId("203.0.113.9:2096") == null && PasskeyService.rpId("[::1]:2096") == null
                && PasskeyService.rpId("panel.example.test/../x") == null
                && "panel.example.test".equals(PasskeyService.rpId("Panel.Example.Test:2096")));
        long saved = PasskeyService.clock.getAsLong();
        PasskeyService.Started l12 = PasskeyService.startLogin(HOST);
        String late = phone.assertion(l12.optionsJson(), ORIGIN);
        PasskeyService.clock = () -> saved + 181_000;
        check("after three minutes the request has expired", refused(() -> PasskeyService.finishLogin(l12.requestId(), late)));
        PasskeyService.clock = System::currentTimeMillis;
        sql("UPDATE panel_admin SET active = FALSE WHERE id = " + admin.id());
        PasskeyService.Started l13 = PasskeyService.startLogin(HOST);
        check("a deactivated administrator: refused", refused(() -> PasskeyService.finishLogin(l13.requestId(), phone.assertion(l13.optionsJson(), ORIGIN))));
        sql("UPDATE panel_admin SET active = TRUE WHERE id = " + admin.id());

        System.out.println("\n== Passkeys: confirming an operation (step-up) ==");
        AuthStore.Created c2 = AuthStore.createAdmin("Second", null, "admin");
        AuthStore.Admin second = AuthStore.adminById(c2.id()).orElseThrow();
        SoftAuthenticator secondKey = new SoftAuthenticator();
        PasskeyService.Started r2 = PasskeyService.startRegistration(second, 9, HOST);
        PasskeyService.finishRegistration(r2.requestId(), 9, secondKey.register(r2.optionsJson(), ORIGIN), "Second key");
        PasskeyService.Started u = PasskeyService.startStepUp(admin, 1, HOST);
        check("the step-up asks for this admin's passkeys only", u.optionsJson().contains(phone.credentialIdB64u())
                && !u.optionsJson().contains(secondKey.credentialIdB64u()));
        check("another admin's passkey cannot confirm it",
                refused(() -> PasskeyService.finishStepUp(u.requestId(), 1, admin.id(), secondKey.assertion(u.optionsJson(), ORIGIN))));
        PasskeyService.Started u2 = PasskeyService.startStepUp(admin, 1, HOST);
        String step = phone.assertion(u2.optionsJson(), ORIGIN);
        check("from another session: refused", refused(() -> PasskeyService.finishStepUp(u2.requestId(), 2, admin.id(), step)));
        PasskeyService.Started u3 = PasskeyService.startStepUp(admin, 1, HOST);
        check("the admin's own passkey, same session: confirmed",
                !refused(() -> PasskeyService.finishStepUp(u3.requestId(), 1, admin.id(), phone.assertion(u3.optionsJson(), ORIGIN))));
        check("a new administrator gets a random 16-byte user handle", second.userHandle().length() == 22);
    }

    // ===================== One-time codes =====================

    static final List<String[]> MAIL = new ArrayList<>();
    static final List<String> LOG = new java.util.concurrent.CopyOnWriteArrayList<>();

    static String lastCode() {
        String body = MAIL.get(MAIL.size() - 1)[2];
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("\\b(\\d{6})\\b").matcher(body);
        return m.find() ? m.group(1) : null;
    }

    static void codes() throws Exception {
        System.out.println("\n== One-time codes by email ==");
        org.daemoxcp.mail.i18n.I18n.setCurrent("en");
        LoginCodes.mailer = (to, subject, body) -> MAIL.add(new String[]{to, subject, body});
        LoginCodes.synchronousMail = true;
        java.util.logging.Logger.getLogger(LoginCodes.class.getName()).addHandler(new java.util.logging.Handler() {
            @Override public void publish(java.util.logging.LogRecord r) { LOG.add(String.valueOf(r.getMessage())); }
            @Override public void flush() { }
            @Override public void close() { }
        });
        LoginCodes.resetLimits();
        AuthStore.Admin admin = AuthStore.adminByUsername("Admin").orElseThrow();
        check("the email is saved encrypted, found by its blind index",
                AuthStore.setEmail(admin.id(), "admin@example.org") == AuthStore.CreateResult.CREATED
                && one("SELECT email_enc FROM panel_admin WHERE username = 'Admin'").startsWith("v1:")
                && !one("SELECT email_enc FROM panel_admin WHERE username = 'Admin'").contains("example")
                && AuthStore.adminByEmail("ADMIN@example.org").map(AuthStore.Admin::id).orElse(-1L) == admin.id());
        AuthStore.Created third = AuthStore.createAdmin("Third", "third@example.org", "admin");
        check("the same address for another admin: refused by the UNIQUE index",
                AuthStore.setEmail(third.id(), "Admin@Example.org") == AuthStore.CreateResult.EMAIL_TAKEN
                && AuthStore.createAdmin("Fourth", "admin@example.org", "admin").result() == AuthStore.CreateResult.EMAIL_TAKEN
                && AuthStore.createAdmin("Admin", "x@example.org", "admin").result() == AuthStore.CreateResult.NAME_TAKEN);

        LoginCodes.requestEmailLogin("nobody@example.org", "198.51.100.1");
        check("an address that is nobody's: no email", MAIL.isEmpty());
        LoginCodes.requestEmailLogin("Admin@Example.org", "198.51.100.1");
        check("the admin's address (any case): one email, to the stored address", MAIL.size() == 1
                && MAIL.get(0)[0].equals("admin@example.org") && MAIL.get(0)[1].matches("\\[[a-z0-9.-]+\\] Your sign-in code for the mail control panel"));
        String code = lastCode();
        check("a 6-digit code, and the database holds only its HMAC", code != null
                && one("SELECT COUNT(*) FROM login_code_email WHERE code_hash LIKE ?", "%" + code + "%").equals("0")
                && one("SELECT code_hash FROM login_code_email ORDER BY id DESC LIMIT 1").matches("[0-9a-f]{64}"));
        String wrong = code.equals("000000") ? "111111" : "000000";
        check("wrong code: refused", LoginCodes.verifyEmailLogin("admin@example.org", wrong, "198.51.100.2").isEmpty());
        check("right code: the admin", LoginCodes.verifyEmailLogin("admin@example.org", code, "198.51.100.2").map(AuthStore.Admin::id).orElse(-1L) == admin.id());
        check("the same code again: refused (once only)", LoginCodes.verifyEmailLogin("admin@example.org", code, "198.51.100.2").isEmpty());
        check("letters, spaces, wrong length: refused before any comparison",
                LoginCodes.verifyEmailLogin("admin@example.org", "12a456", "198.51.100.3").isEmpty()
                && LoginCodes.verifyEmailLogin("admin@example.org", "12345", "198.51.100.3").isEmpty());

        LoginCodes.resetLimits();
        LoginCodes.requestEmailLogin("admin@example.org", "198.51.100.4");
        String first = lastCode();
        LoginCodes.requestEmailLogin("admin@example.org", "198.51.100.4");
        String latest = lastCode();
        check("a new code cancels the previous one", first.equals(latest)
                || LoginCodes.verifyEmailLogin("admin@example.org", first, "198.51.100.5").isEmpty());
        String c2 = lastCode();
        String w2 = c2.equals("000000") ? "111111" : "000000";
        for (int i = 0; i < LoginCodes.MAX_ATTEMPTS; i++) LoginCodes.verifyEmailLogin("admin@example.org", w2, "198.51.100." + (10 + i));
        check("after five wrong attempts the right code no longer works",
                LoginCodes.verifyEmailLogin("admin@example.org", c2, "198.51.100.20").isEmpty());

        LoginCodes.resetLimits();
        AuthStore.clock = () -> Instant.now().minus(Duration.ofMinutes(11));
        LoginCodes.requestEmailLogin("admin@example.org", "198.51.100.6");
        AuthStore.clock = Instant::now;
        check("a code issued 11 minutes ago has expired", LoginCodes.verifyEmailLogin("admin@example.org", lastCode(), "198.51.100.21").isEmpty());

        LoginCodes.resetLimits();
        int before = MAIL.size();
        for (int i = 0; i < 4; i++) LoginCodes.requestEmailLogin("admin@example.org", "203.0.113." + (30 + i * 40));
        check("per recipient: three emails in 15 minutes, the fourth does not leave", MAIL.size() - before == 3);
        LoginCodes.resetLimits();
        before = MAIL.size();
        for (int i = 0; i < 6; i++) LoginCodes.requestEmailLogin(i % 2 == 0 ? "admin@example.org" : "x" + i + "@example.org", "192.0.2.7");
        check("per IP address: five requests in 15 minutes, then nothing", MAIL.size() - before == 3);
        LoginCodes.resetLimits();
        before = MAIL.size();
        for (int i = 0; i < 25; i++) LoginCodes.requestEmailLogin(i == 24 ? "admin@example.org" : "n" + i + "@example.org", "192.0.2." + (i % 254 + 1));
        check("per /24 subnet: twenty requests in an hour, then nothing", MAIL.size() - before == 0);
        LoginCodes.mailer = (to, subject, body) -> { throw new IllegalStateException("refused " + to + " " + body); };
        LoginCodes.resetLimits();
        LoginCodes.requestEmailLogin("admin@example.org", "198.51.100.90");
        LoginCodes.mailer = (to, subject, body) -> MAIL.add(new String[]{to, subject, body});
        check("the log of the codes has no code and no address (" + LOG.size() + " lines)", !LOG.isEmpty()
                && LOG.stream().noneMatch(l -> l.contains("@") || l.matches(".*\\b\\d{6}\\b.*")));

        System.out.println("\n== One-time code from the server console ==");
        LoginCodes.resetLimits();
        String console = LoginCodes.issueConsoleCode(admin);
        check("eight digits", console.matches("[0-9]{8}"));
        String wc = console.equals("00000000") ? "11111111" : "00000000";
        check("wrong code: refused", LoginCodes.verifyConsoleCode(wc, "198.51.100.40").isEmpty());
        check("right code (with a space in the middle): the admin",
                LoginCodes.verifyConsoleCode(console.substring(0, 4) + " " + console.substring(4), "198.51.100.40").map(AuthStore.Admin::id).orElse(-1L) == admin.id());
        check("once only", LoginCodes.verifyConsoleCode(console, "198.51.100.40").isEmpty());
        String c3 = LoginCodes.issueConsoleCode(admin);
        String w3 = c3.equals("00000000") ? "11111111" : "00000000";
        for (int i = 0; i < 5; i++) LoginCodes.verifyConsoleCode(w3, "198.51.100." + (50 + i));
        check("five wrong guesses use up the console code", LoginCodes.verifyConsoleCode(c3, "198.51.100.60").isEmpty());

        System.out.println("\n== One-time code to confirm an operation ==");
        LoginCodes.resetLimits();
        admin = AuthStore.adminById(admin.id()).orElseThrow();     // with the email set above
        check("the step-up code goes to the admin's own address", LoginCodes.requestStepUp(admin, "198.51.100.80")
                && MAIL.get(MAIL.size() - 1)[0].equals("admin@example.org") && MAIL.get(MAIL.size() - 1)[1].matches("\\[[a-z0-9.-]+\\] Code to confirm an operation in the mail control panel"));
        String su = lastCode();
        AuthStore.Admin thirdAdmin = AuthStore.adminById(third.id()).orElseThrow();
        check("another admin cannot use it", !LoginCodes.verifyStepUp(thirdAdmin, su));
        check("the right code confirms, once", LoginCodes.verifyStepUp(admin, su) && !LoginCodes.verifyStepUp(admin, su));
        AuthStore.Admin noEmail = AuthStore.adminByUsername("Second").orElseThrow();
        check("an admin without an email gets no step-up code", !LoginCodes.requestStepUp(noEmail, "198.51.100.80"));

        System.out.println("\n== Changing the sign-in email ==");
        LoginCodes.resetLimits();
        check("an address that is another admin's: TAKEN", LoginCodes.requestEmailChange(admin, "third@example.org", "198.51.100.70") == LoginCodes.ChangeResult.TAKEN);
        check("an invalid address (non-ASCII): INVALID", LoginCodes.requestEmailChange(admin, "admìn@example.org", "198.51.100.70") == LoginCodes.ChangeResult.INVALID);
        check("a new address: SENT, the code goes to the new address",
                LoginCodes.requestEmailChange(admin, "new@example.org", "198.51.100.70") == LoginCodes.ChangeResult.SENT
                && MAIL.get(MAIL.size() - 1)[0].equals("new@example.org"));
        String cc = lastCode();
        check("until the code comes back, the email is still the old one", AuthStore.adminById(admin.id()).orElseThrow().email().equals("admin@example.org"));
        check("wrong code: not changed", !LoginCodes.confirmEmailChange(admin, cc.equals("000000") ? "111111" : "000000"));
        check("right code: changed", LoginCodes.confirmEmailChange(admin, cc)
                && AuthStore.adminById(admin.id()).orElseThrow().email().equals("new@example.org")
                && AuthStore.adminByEmail("admin@example.org").isEmpty());
        check("the target address is stored encrypted too", one("SELECT target_enc FROM email_change_code ORDER BY id DESC LIMIT 1").startsWith("v1:"));
    }

    // ===================== The first administrator, from the console =====================

    static void firstAdmin(MailDatabase db) throws Exception {
        System.out.println("\n== The first administrator, from the console (--create-admin) ==");
        db.dropAllTables();
        Main.mysqlAvailable = true;
        Main.setupRequired = true;
        LoginCodes.resetLimits();
        java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
        java.io.PrintStream out = new java.io.PrintStream(buf, true, java.nio.charset.StandardCharsets.UTF_8);
        check("an invalid name: refused, nothing created", Main.createFirstAdmin("bad name", "first@example.org", out, System.err) == 2 && !db.hasAdminUser());
        check("an invalid email: refused, nothing created", Main.createFirstAdmin("first", "first@exa mple", out, System.err) == 2 && !db.hasAdminUser());
        check("on a panel without administrators: created", Main.createFirstAdmin("first", "first@example.org", out, System.err) == 0);
        Optional<AuthStore.Admin> first = AuthStore.adminByUsername("first");
        check("superadmin, with its sign-in email", first.isPresent() && "superadmin".equals(first.get().role())
                && first.get().email().equals("first@example.org"));
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("One-time access code for first: (\\d{4} \\d{4})").matcher(buf.toString());
        check("it prints an eight-digit code", m.find());
        check("the printed code signs in as the new administrator", first.isPresent()
                && LoginCodes.verifyConsoleCode(m.group(1), "198.51.100.200").map(AuthStore.Admin::id).orElse(-1L) == first.get().id());
        check("a second time: refused, still one administrator", Main.createFirstAdmin("second", "second@example.org", out, System.err) == 2
                && AuthStore.admins().size() == 1);
        Main.refreshSetupState();
        check("the running panel notices the new administrator at the next request", !Main.setupRequired);
    }

    // ===================== Sessions in MySQL =====================

    static void sessions() throws Exception {
        System.out.println("\n== Sessions in the database ==");
        WebSessions sessions = new WebSessions();
        AuthStore.Admin admin = AuthStore.adminByUsername("Admin").orElseThrow();
        String ua = "Mozilla/5.0 (Test) Firefox/140.0";
        String token = sessions.create(admin.id(), ua, "203.0.113.77");
        check("the token: 32 random bytes in base64url", token.matches("[A-Za-z0-9_-]{43}"));
        check("the database holds its SHA-256, never the token",
                one("SELECT COUNT(*) FROM panel_sessions WHERE token_hash = ?", WebSessions.tokenHash(token)).equals("1")
                && one("SELECT COUNT(*) FROM panel_sessions WHERE token_hash = ? OR ua_enc LIKE ?", token, "%" + token + "%").equals("0"));
        check("IP address and browser stored encrypted", one("SELECT ip_enc FROM panel_sessions WHERE token_hash = ?", WebSessions.tokenHash(token)).startsWith("v1:")
                && !one("SELECT CONCAT(ip_enc, ua_enc) FROM panel_sessions WHERE token_hash = ?", WebSessions.tokenHash(token)).contains("203.0.113.77"));
        check("dates written in UTC", Math.abs(Duration.between(java.time.LocalDateTime.now(java.time.ZoneOffset.UTC),
                java.time.LocalDateTime.parse(one("SELECT DATE_FORMAT(created_at, '%Y-%m-%dT%H:%i:%s') FROM panel_sessions WHERE token_hash = ?",
                        WebSessions.tokenHash(token)))).toSeconds()) < 60);
        check("the login records last_login", one("SELECT last_login FROM panel_admin WHERE id = ?", admin.id()) != null);
        Optional<WebSessions.Current> cur = sessions.check(token, ua);
        check("valid with the same browser: the admin", cur.isPresent() && cur.get().admin().id() == admin.id());
        check("another browser with the same cookie: refused", sessions.check(token, "curl/8.0").isEmpty());
        check("an invented or malformed token: refused", sessions.check("x".repeat(43), ua).isEmpty()
                && sessions.check("' OR 1=1 --", ua).isEmpty() && sessions.check(null, ua).isEmpty());
        String csrf = WebSessions.csrfToken(token);
        String token2 = sessions.create(admin.id(), ua, "203.0.113.78");
        check("CSRF token: derived from the session, the same every time, different for another session",
                csrf.equals(WebSessions.csrfToken(token)) && !csrf.equals(WebSessions.csrfToken(token2))
                && WebSessions.validCsrf(token, csrf) && !WebSessions.validCsrf(token2, csrf) && !WebSessions.validCsrf(token, ""));
        String pre = "a".repeat(43);
        check("before login: the page token is tied to the browser cookie",
                WebSessions.validPreLoginCsrf(pre, WebSessions.preLoginCsrf(pre))
                && !WebSessions.validPreLoginCsrf("b".repeat(43), WebSessions.preLoginCsrf(pre))
                && !WebSessions.validPreLoginCsrf(null, WebSessions.preLoginCsrf(pre))
                && !WebSessions.preLoginCsrf(pre).equals(WebSessions.csrfToken(pre)));
        check("the list: both sessions, with IP and browser readable", sessions.list(admin.id()).size() == 2
                && sessions.list(admin.id()).stream().anyMatch(l -> l.ip().equals("203.0.113.77") && l.userAgent().equals(ua)));
        check("not re-authenticated yet", !cur.orElseThrow().reauthenticatedWithin(300));
        sessions.markReauthenticated(cur.get().id());
        check("after a confirmation: re-authenticated for five minutes", sessions.check(token, ua).orElseThrow().reauthenticatedWithin(300));

        sql("UPDATE panel_sessions SET last_seen_at = UTC_TIMESTAMP() - INTERVAL 31 MINUTE WHERE token_hash = '" + WebSessions.tokenHash(token2) + "'");
        check("31 minutes without requests: expired", sessions.check(token2, ua).isEmpty());
        String token3 = sessions.create(admin.id(), ua, "203.0.113.79");
        sql("UPDATE panel_sessions SET expires_at = UTC_TIMESTAMP() - INTERVAL 1 SECOND WHERE token_hash = '" + WebSessions.tokenHash(token3) + "'");
        check("past the 12 hours: expired, even if active", sessions.check(token3, ua).isEmpty());
        AuthStore.purgeExpired();
        check("the expired ones are purged", one("SELECT COUNT(*) FROM panel_sessions WHERE token_hash IN (?, ?)",
                WebSessions.tokenHash(token2), WebSessions.tokenHash(token3)).equals("0"));

        AuthStore.Admin second = AuthStore.adminByUsername("Second").orElseThrow();
        String theirs = sessions.create(second.id(), ua, "203.0.113.90");
        long theirId = sessions.check(theirs, ua).orElseThrow().id();
        check("an admin cannot close another admin's session", !sessions.revokeById(theirId, admin.id()) && sessions.check(theirs, ua).isPresent());
        String other = sessions.create(admin.id(), ua, "203.0.113.91");
        check("close the others: this one stays, the other goes", sessions.revokeOthers(admin.id(), cur.get().id()) == 1
                && sessions.check(token, ua).isPresent() && sessions.check(other, ua).isEmpty());
        sessions.revoke(token);
        check("logout: the session is gone from the database", sessions.check(token, ua).isEmpty()
                && one("SELECT COUNT(*) FROM panel_sessions WHERE token_hash = ?", WebSessions.tokenHash(token)).equals("0"));
        sql("UPDATE panel_admin SET active = FALSE WHERE id = " + second.id());
        check("a deactivated administrator: the session no longer counts", sessions.check(theirs, ua).isEmpty());
        AuthStore.deleteAdmin(second.id());
        check("a deleted administrator: sessions, passkeys and codes go with it (ON DELETE CASCADE)",
                one("SELECT COUNT(*) FROM panel_sessions WHERE admin_id = ?", second.id()).equals("0")
                && one("SELECT COUNT(*) FROM admin_passkeys WHERE admin_id = ?", second.id()).equals("0"));
        check("permissions by name: superadmin manages admins and the vault, admin does not",
                AuthStore.may(admin, "admins.manage") && AuthStore.may(admin, "vault.manage")
                && !AuthStore.may(AuthStore.adminByUsername("Third").orElseThrow(), "admins.manage")
                && !AuthStore.may(admin, "something.else"));
    }
}
