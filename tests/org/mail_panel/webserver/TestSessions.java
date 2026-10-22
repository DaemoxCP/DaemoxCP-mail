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

    /**
     * Where the panel must write its audit log for this test, checking that it stuck.
     *
     * <p>Serve perche' {@code db.setSetting} non fallisce rumorosamente: su un database dove
     * {@code panel_settings} non esiste ancora stampa "Failed to set setting" e torna, e il
     * pannello continua a scrivere nel registro VERO, {@code /var/log/mail-panel-auth.log}.
     * La prova poi conta zero righe nel proprio file e dice "manca una voce nel registro di
     * audit", che e' la cosa sbagliata: il registro c'era, solo da un'altra parte.
     *
     * <p>Succedeva a tutte le prove che chiamavano {@code setSetting} PRIMA di
     * {@link #prepare} o {@link #open}, cioe' prima che lo schema esistesse. Misurato: su un
     * database appena creato il PRIMO giro era rosso e il secondo verde, perche' il primo la
     * tabella la lasciava creata. Cinque prove su undici si comportavano cosi'.
     *
     * <p>Quindi qui lo schema c'e' per forza, e se la voce non si rilegge si grida subito
     * invece di misurare un'altra cosa.
     */
    static void auditLogTo(MailDatabase db, java.nio.file.Path registro) throws Exception {
        prepare(db);
        db.setSetting("audit_log_file_path", registro.toString());
        String letto = db.getSetting("audit_log_file_path", null);
        if (!registro.toString().equals(letto))
            throw new IllegalStateException("il pannello non scriverebbe il registro in "
                    + registro + " ma in " + letto + ": la voce audit_log_file_path non si e'"
                    + " salvata (schema non ancora creato?), e la prova misurerebbe il file"
                    + " sbagliato");
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
