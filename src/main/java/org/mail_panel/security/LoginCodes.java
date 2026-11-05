package org.mail_panel.security;

import org.mail_panel.i18n.I18n;

import java.net.InetAddress;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.LongSupplier;
import java.util.logging.Logger;

/**
 * I codici monouso: accesso via email, accesso dalla console del server, conferma di
 * un'operazione delicata, cambio dell'email di accesso.
 *
 *  - il codice esiste solo nel messaggio (o sulla console): nel database c'e' l'impronta HMAC;
 *  - vale 10 minuti (15 dalla console e per il cambio dell'email), cinque tentativi, una volta;
 *  - chiedere un codice per un indirizzo che non e' di nessuno da' la stessa risposta, nello
 *    stesso tempo: l'invio parte da una coda a parte e chi risponde non aspetta sendmail;
 *  - limiti contro lo spam: per indirizzo IP, per sottorete e per destinatario. Oltre il limite
 *    la risposta resta la stessa, semplicemente il messaggio non parte;
 *  - nei log mai il codice ne' l'indirizzo email.
 *
 * Il messaggio parte dal Postfix di questo server (lo stesso sendmail del rapporto periodico):
 * il pannello sta sul server di posta e non ha bisogno di credenziali SMTP.
 */
public final class LoginCodes {

    private LoginCodes() {}

    private static final Logger LOGGER = Logger.getLogger(LoginCodes.class.getName());
    private static final SecureRandom RANDOM = new SecureRandom();

    static final long EMAIL_TTL_S = 600;
    static final long CONSOLE_TTL_S = 900;
    static final long STEP_UP_TTL_S = 600;
    static final long EMAIL_CHANGE_TTL_S = 900;
    public static final int MAX_ATTEMPTS = 5;

    static LongSupplier clock = System::currentTimeMillis;

    /**
     * Chi spedisce le email; i test lo sostituiscono con una lambda che riceve destinatario,
     * oggetto e testo. Il pannello vero riceve il messaggio intero (testo e HTML) dal secondo
     * metodo, che per una lambda ripiega sul primo.
     */
    public interface Mailer {
        void send(String to, String subject, String body) throws Exception;

        default void send(String to, org.mail_panel.system.PanelMail.Message message) throws Exception {
            send(to, message.subject(), message.text());
        }
    }

    public static Mailer mailer = new Mailer() {
        @Override
        public void send(String to, String subject, String body) throws Exception {
            send(to, new org.mail_panel.system.PanelMail.Message(subject, body,
                    "<pre>" + org.mail_panel.system.PanelMail.esc(body) + "</pre>", I18n.current()));
        }

        @Override
        public void send(String to, org.mail_panel.system.PanelMail.Message message) {
            if (!org.mail_panel.system.PeriodicReport.sendPanelMessage(to, message))
                throw new IllegalStateException("Postfix did not accept the message");
        }
    };

    private static final ExecutorService QUEUE = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "login-code-mail");
        t.setDaemon(true);
        return t;
    });

    /** Nei test l'invio avviene subito, per poterlo controllare. */
    public static boolean synchronousMail = false;

    /**
     * In coda, nella lingua di chi ha chiesto, con l'ora e l'indirizzo della richiesta: il
     * messaggio si compone nel thread della coda, perche' leggere il nome del server puo' voler
     * dire chiedere a Postfix, e chi risponde alla richiesta non deve aspettarlo.
     */
    static void queue(String to, org.mail_panel.system.CodeMail.Kind kind, String code, long minutes, String ip) {
        String lang = I18n.current();
        java.time.ZonedDateTime when = java.time.ZonedDateTime.now();
        Runnable job = () -> {
            try {
                mailer.send(to, org.mail_panel.system.CodeMail.message(kind, lang,
                        org.mail_panel.system.PanelMail.serverName(), code, minutes, ip, when));
            } catch (Exception e) {
                // Ne' l'indirizzo ne' il messaggio: dentro c'e' il codice. I dettagli sono nel log della posta.
                LOGGER.warning("Login code email not delivered");
            }
        };
        if (synchronousMail) job.run(); else QUEUE.submit(job);
    }

    // ===================== Limiti =====================

    private static final Map<String, Deque<Long>> HITS = new HashMap<>();

    /** Vero (e conta la richiesta) se nella finestra ce ne sono state meno di max. */
    static synchronized boolean allow(String key, int max, long windowMs) {
        long now = clock.getAsLong();
        Deque<Long> d = HITS.computeIfAbsent(key, k -> new ArrayDeque<>());
        while (!d.isEmpty() && now - d.peekFirst() >= windowMs) d.pollFirst();
        if (d.size() >= max) return false;
        d.addLast(now);
        if (HITS.size() > 20000) HITS.entrySet().removeIf(e -> e.getValue().isEmpty() || now - e.getValue().peekLast() > DAY);
        return true;
    }

    public static synchronized void resetLimits() { HITS.clear(); }

    /** La sottorete di un indirizzo: /24 per IPv4, /64 per IPv6. */
    static String subnet(String ip) {
        try {
            if (!InputValidator.isValidIp(ip)) return "?:" + ip;
            byte[] a = InetAddress.getByName(ip).getAddress();
            int keep = a.length == 4 ? 3 : 8;
            StringBuilder b = new StringBuilder(a.length == 4 ? "v4:" : "v6:");
            for (int i = 0; i < keep; i++) b.append(a[i] & 0xff).append('.');
            return b.toString();
        } catch (Exception e) {
            return "?:" + ip;
        }
    }

    private static final long MIN = 60_000L, HOUR = 3_600_000L, DAY = 86_400_000L;

    // ===================== Codici =====================

    static String digits(int n) {
        StringBuilder b = new StringBuilder(n);
        for (int i = 0; i < n; i++) b.append(RANDOM.nextInt(10));
        return b.toString();
    }

    private static Instant in(long seconds) { return AuthStore.now().plusSeconds(seconds); }

    /** Solo cifre e lunghezza giusta (spazi e trattini tolti): tutto il resto non arriva al confronto. */
    static String clean(String code, int length) {
        if (code == null || code.length() > 20) return null;
        String c = code.replace(" ", "").replace("-", "");
        return c.matches("[0-9]{" + length + "}") ? c : null;
    }

    /** Un indirizzo email accettabile: solo ASCII stampabile, al massimo 254 caratteri. */
    public static boolean validEmail(String email) {
        return email != null && email.length() <= 254 && org.mail_panel.webserver.SecurityUtils.isValidEmail(email);
    }

    /** Controlla l'ultimo codice valido dell'amministratore: conta il tentativo, e se e' giusto lo consuma. */
    private static boolean check(AuthStore.CodeFlow flow, String purpose, long adminId, String code) {
        List<AuthStore.CodeRow> rows = AuthStore.activeCodes(flow, adminId);
        if (rows.isEmpty()) return false;
        AuthStore.CodeRow row = rows.get(0);
        if (row.attempts() >= MAX_ATTEMPTS) return false;
        AuthStore.codeAttempt(flow, row.id());
        return DataCrypto.sameHash(row.codeHash(), DataCrypto.codeHash(purpose, adminId, code))
                && AuthStore.consumeCode(flow, row.id(), MAX_ATTEMPTS);
    }

    // ----- accesso via email -----

    /** Manda un codice se l'indirizzo e' di un amministratore e i limiti lo permettono. Non dice mai quale dei due. */
    public static void requestEmailLogin(String email, String ip) {
        if (!validEmail(email)) return;
        String index = DataCrypto.emailIndex(email);
        boolean ok = allow("email-req-ip:" + ip, 5, 15 * MIN)
                & allow("email-req-net:" + subnet(ip), 20, HOUR)
                & allow("email-req-to:" + index, 3, 15 * MIN)
                & allow("email-req-to-day:" + index, 10, DAY);
        if (!ok) {
            LOGGER.info("Login code request over the limit from " + ip);
            return;
        }
        Optional<AuthStore.Admin> admin = AuthStore.adminByEmail(email);
        if (admin.isEmpty()) return;
        String code = digits(6);
        if (!AuthStore.saveCode(AuthStore.CodeFlow.EMAIL_LOGIN, admin.get().id(),
                DataCrypto.codeHash("email_login", admin.get().id(), code), in(EMAIL_TTL_S), null, null)) return;
        queue(admin.get().email(), org.mail_panel.system.CodeMail.Kind.LOGIN, code, EMAIL_TTL_S / 60, ip);
    }

    /** L'amministratore, se il codice e' giusto, valido e non ancora usato. */
    public static Optional<AuthStore.Admin> verifyEmailLogin(String email, String code, String ip) {
        String c = clean(code, 6);
        if (!allow("email-verify-ip:" + ip, 10, 15 * MIN) || c == null || !validEmail(email)) return Optional.empty();
        Optional<AuthStore.Admin> admin = AuthStore.adminByEmail(email);
        if (admin.isEmpty()) {
            // Lo stesso lavoro di un confronto vero, per non rispondere prima.
            DataCrypto.sameHash(DataCrypto.codeHash("email_login", 0, c), DataCrypto.codeHash("email_login", 0, "000000"));
            return Optional.empty();
        }
        return check(AuthStore.CodeFlow.EMAIL_LOGIN, "email_login", admin.get().id(), c) ? admin : Optional.empty();
    }

    // ----- accesso dalla console del server -----

    /** Un codice da otto cifre per entrare senza email ne' passkey: lo genera chi ha accesso al server. */
    public static String issueConsoleCode(AuthStore.Admin admin) {
        String code = digits(8);
        if (!AuthStore.saveCode(AuthStore.CodeFlow.CONSOLE_LOGIN, admin.id(),
                DataCrypto.codeHash("console_login", admin.id(), code), in(CONSOLE_TTL_S), null, null))
            throw new IllegalStateException("Console code not saved");
        return code;
    }

    public static Optional<AuthStore.Admin> verifyConsoleCode(String code, String ip) {
        String c = clean(code, 8);
        if (!allow("console-verify-ip:" + ip, 10, 15 * MIN) || c == null) return Optional.empty();
        List<AuthStore.CodeRow> rows = AuthStore.activeCodes(AuthStore.CodeFlow.CONSOLE_LOGIN, -1);
        for (AuthStore.CodeRow row : rows) {
            if (row.attempts() >= MAX_ATTEMPTS) continue;
            if (DataCrypto.sameHash(row.codeHash(), DataCrypto.codeHash("console_login", row.adminId(), c))) {
                AuthStore.codeAttempt(AuthStore.CodeFlow.CONSOLE_LOGIN, row.id());
                return AuthStore.consumeCode(AuthStore.CodeFlow.CONSOLE_LOGIN, row.id(), MAX_ATTEMPTS)
                        ? AuthStore.adminById(row.adminId()) : Optional.empty();
            }
        }
        // Un codice sbagliato consuma un tentativo di ogni codice valido: non si provano tutti i numeri.
        for (AuthStore.CodeRow row : rows) AuthStore.codeAttempt(AuthStore.CodeFlow.CONSOLE_LOGIN, row.id());
        return Optional.empty();
    }

    // ----- conferma di un'operazione delicata (chi non ha una passkey) -----

    /** Manda un codice all'email dell'amministratore collegato. Falso se non ha un'email o e' oltre il limite. */
    public static boolean requestStepUp(AuthStore.Admin admin, String ip) {
        if (!admin.hasEmail()) return false;
        if (!(allow("stepup:" + admin.id(), 3, 15 * MIN) & allow("stepup-ip:" + ip, 5, 15 * MIN))) return false;
        String code = digits(6);
        if (!AuthStore.saveCode(AuthStore.CodeFlow.STEP_UP, admin.id(),
                DataCrypto.codeHash("step_up", admin.id(), code), in(STEP_UP_TTL_S), null, null)) return false;
        queue(admin.email(), org.mail_panel.system.CodeMail.Kind.STEP_UP, code, STEP_UP_TTL_S / 60, ip);
        return true;
    }

    public static boolean verifyStepUp(AuthStore.Admin admin, String code) {
        String c = clean(code, 6);
        return c != null && check(AuthStore.CodeFlow.STEP_UP, "step_up", admin.id(), c);
    }

    // ----- cambio dell'email -----

    public enum ChangeResult { SENT, INVALID, TAKEN, LIMIT }

    /** Manda un codice al nuovo indirizzo: l'email cambia solo quando quel codice torna indietro. */
    public static ChangeResult requestEmailChange(AuthStore.Admin admin, String newEmail, String ip) {
        if (!validEmail(newEmail)) return ChangeResult.INVALID;
        Optional<AuthStore.Admin> owner = AuthStore.adminByEmail(newEmail);
        if (owner.isPresent() && owner.get().id() != admin.id()) return ChangeResult.TAKEN;
        if (!(allow("email-change:" + admin.id(), 3, 15 * MIN) & allow("email-change-ip:" + ip, 5, 15 * MIN)))
            return ChangeResult.LIMIT;
        String code = digits(6);
        if (!AuthStore.saveCode(AuthStore.CodeFlow.EMAIL_CHANGE, admin.id(),
                DataCrypto.codeHash("email_change", admin.id(), code), in(EMAIL_CHANGE_TTL_S),
                DataCrypto.encrypt(newEmail.trim()), DataCrypto.emailIndex(newEmail)))
            return ChangeResult.LIMIT;
        queue(newEmail.trim(), org.mail_panel.system.CodeMail.Kind.EMAIL_CHANGE, code, EMAIL_CHANGE_TTL_S / 60, ip);
        return ChangeResult.SENT;
    }

    /** Vero se il codice e' giusto e l'indirizzo e' ancora libero: da quel momento l'email di accesso e' la nuova. */
    public static boolean confirmEmailChange(AuthStore.Admin admin, String code) {
        String c = clean(code, 6);
        if (c == null) return false;
        List<AuthStore.CodeRow> rows = AuthStore.activeCodes(AuthStore.CodeFlow.EMAIL_CHANGE, admin.id());
        if (rows.isEmpty()) return false;
        AuthStore.CodeRow row = rows.get(0);
        if (!check(AuthStore.CodeFlow.EMAIL_CHANGE, "email_change", admin.id(), c)) return false;
        return AuthStore.setEmail(admin.id(), DataCrypto.decrypt(row.targetEnc())) == AuthStore.CreateResult.CREATED;
    }
}
