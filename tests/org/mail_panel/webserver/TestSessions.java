package org.mail_panel.webserver;

import org.mail_panel.Main;
import org.mail_panel.database.MailDatabase;
import org.mail_panel.security.AuthStore;

import java.nio.file.Files;

/**
 * A session like the login one, for the tests that drive the real server: an administrator in the
 * test MySQL and a session in panel_sessions. The panel keys go to a temporary folder unless
 * -Dmailpanel.secrets.dir says where.
 */
final class TestSessions {

    private TestSessions() {}

    /** The login tables ready (schema and migration) for the database the test already connected. */
    static void prepare(MailDatabase db) throws Exception {
        if (System.getProperty("mailpanel.secrets.dir") == null)
            System.setProperty("mailpanel.secrets.dir", Files.createTempDirectory("mailpanel-secrets").toString());
        Main.mailDatabase = db;
        db.createSchema();
        AuthStore.migrate();
    }

    /** The id of the administrator with that name, created (superadmin) if it is not there. */
    static long admin(String name) {
        AuthStore.Created c = AuthStore.createAdmin(name, null, "superadmin");
        return c.id() > 0 ? c.id() : AuthStore.adminByUsername(name).orElseThrow().id();
    }

    /** {session token, CSRF token} of a new session for that administrator. */
    static String[] open(MailDatabase db, String adminName, String userAgent) throws Exception {
        prepare(db);
        String token = Main.sessions.create(admin(adminName), userAgent, "127.0.0.1");
        return new String[]{token, WebSessions.csrfToken(token)};
    }
}
