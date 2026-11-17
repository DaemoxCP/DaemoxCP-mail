package org.daemoxcp.mail.webserver;

import org.daemoxcp.mail.Main;
import org.daemoxcp.mail.database.MailDatabase;
import org.daemoxcp.mail.security.AuthStore;

import java.nio.file.Files;

/**
 * A session like the login one, for the tests that drive the real server: an administrator in the
 * test MySQL and a session in panel_sessions. The panel keys go to a temporary folder unless
 * -Ddaemoxcp.mail.secrets.dir says where.
 */
final class TestSessions {

    private TestSessions() {}

    /** The login tables ready (schema and migration) for the database the test already connected. */
    static void prepare(MailDatabase db) throws Exception {
        if (System.getProperty("daemoxcp.mail.secrets.dir") == null)
            System.setProperty("daemoxcp.mail.secrets.dir", Files.createTempDirectory("mailpanel-secrets").toString());
        Main.mailDatabase = db;
        db.createSchema();
        AuthStore.migrate();
    }

    /**
     * Where the panel must write its audit log for this test, checking that it stuck.
     *
     * <p>It is needed because {@code db.setSetting} does not fail loudly: on a database where
     * {@code panel_settings} does not exist yet it prints "Failed to set setting" and returns, and
     * the panel keeps writing to the REAL log, {@code /var/log/mail-panel-auth.log}. The test then
     * counts zero lines in its own file and says "an audit log entry is missing", which is the
     * wrong thing: the log was there, just somewhere else.
     *
     * <p>It happened to every test that called {@code setSetting} BEFORE {@link #prepare} or
     * {@link #open}, that is before the schema existed. Measured: on a freshly created database the
     * FIRST run was red and the second green, because the first left the table created. Five tests
     * out of eleven behaved like that.
     *
     * <p>So here the schema is there for sure, and if the entry does not read back it shouts at
     * once instead of measuring something else.
     */
    static void auditLogTo(MailDatabase db, java.nio.file.Path log) throws Exception {
        prepare(db);
        db.setSetting("audit_log_file_path", log.toString());
        String read = db.getSetting("audit_log_file_path", null);
        if (!log.toString().equals(read))
            throw new IllegalStateException("the panel would not write the log to "
                    + log + " but to " + read + ": the audit_log_file_path entry was not"
                    + " saved (schema not created yet?), and the test would measure the wrong"
                    + " file");
    }

    /** The id of the administrator with that name, created (superadmin) if it is not there. */
    static long admin(String name) {
        AuthStore.Created c = AuthStore.createAdmin(name, null, "superadmin");
        return c.id() > 0 ? c.id() : AuthStore.adminByUsername(name).orElseThrow().id();
    }

    /**
     * The session of that token confirmed now (passkey or email code), as the root part writes it after checking one:
     * the dangerous operations ask it.
     */
    static void confirm(String token, String userAgent) {
        Main.sessions.markReauthenticated(Main.sessions.check(token, userAgent).orElseThrow().id());
    }

    /** {session token, CSRF token} of a new session for that administrator. */
    static String[] open(MailDatabase db, String adminName, String userAgent) throws Exception {
        prepare(db);
        String token = Main.sessions.create(admin(adminName), userAgent, "127.0.0.1");
        return new String[]{token, WebSessions.csrfToken(token)};
    }
}
