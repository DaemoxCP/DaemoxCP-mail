package org.daemoxcp.mail.webserver;

import com.sun.net.httpserver.HttpExchange;
import org.json.JSONArray;
import org.json.JSONObject;
import org.daemoxcp.mail.Main;
import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.security.AuthStore;
import org.daemoxcp.mail.security.LoginCodes;
import org.daemoxcp.mail.security.PasskeyService;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Passwordless login and the Account tab of the Settings.
 *
 * There are three ways in (POST /api/login, action field):
 *  - with a passkey (WebAuthn, verified by PasskeyService), without typing the username;
 *  - with a one-time code sent to the administrator's email (LoginCodes);
 *  - with a code generated from the server console (java -jar ... --access-code), for the
 *    first login or when the email does not arrive.
 *
 * Before login the CSRF token is the page's, tied to the browser by the
 * __Host-DaemoxCPMailPre cookie. Asking for a code for an email always responds the same way and in the
 * same time, whether the address belongs to someone or not; so does verifying a wrong code. After
 * login, the session in the database and its CSRF token apply, checked by the filter of every route.
 *
 * /api/account (only with a session): GET the data of the logged-in administrator (email, passkeys,
 * sessions); POST the actions on one's own account: email, name, passkeys, sessions, confirmation.
 */
final class AuthHandlers {

    private static final Logger LOGGER = Logger.getLogger(AuthHandlers.class.getName());
    private static final int MAX_BODY = 32 * 1024;
    /** The minimum response time of "send me a code" and of the checks: it does not tell whether the address exists. */
    static long codeRequestMinMs = 900;   // i test lo abbassano
    /** How long a confirmation (passkey or code) lasts for sensitive operations. */
    static final long REAUTH_SECONDS = 300;
    private static final java.util.regex.Pattern PASSKEY_NAME = java.util.regex.Pattern.compile("[A-Za-z0-9 ._()-]{1,40}");

    private final SSLMailServer server;

    AuthHandlers(SSLMailServer server) { this.server = server; }

    // ===================== Utilita' =====================

    static void send(HttpExchange ex, int status, JSONObject body) throws IOException {
        byte[] b = body.toString().getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        ex.sendResponseHeaders(status, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }

    static JSONObject error(String key) {
        return new JSONObject().put("success", false).put("error", I18n.tr(key));
    }

    /** The JSON body, or null if it is missing, is not JSON or is too large. */
    static JSONObject body(HttpExchange ex) {
        try (InputStream in = ex.getRequestBody()) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) > 0) {
                if (out.size() + n > MAX_BODY) return null;
                out.write(buf, 0, n);
            }
            return new JSONObject(out.toString(StandardCharsets.UTF_8));
        } catch (Exception e) {
            return null;
        }
    }

    static String userAgent(HttpExchange ex) {
        String ua = ex.getRequestHeaders().getFirst("User-Agent");
        return ua == null ? "" : ua.trim();
    }

    static String host(HttpExchange ex) {
        String h = ex.getRequestHeaders().getFirst("Host");
        return h == null ? "" : h.trim();
    }

    /** Waits until codeRequestMinMs from start: the response does not tell how much work there was. */
    static void padTo(long start) throws InterruptedException {
        long wait = codeRequestMinMs - (System.currentTimeMillis() - start);
        if (wait > 0) Thread.sleep(wait);
    }

    /** A UTC date for the pages (ISO with the Z): they convert it to the browser's time zone. */
    static String iso(LocalDateTime t) {
        return t == null ? "" : t.withNano(0) + "Z";
    }

    /** After a successful login: the session in the database, the cookie, where to go. */
    private JSONObject startSession(HttpExchange ex, AuthStore.Admin admin, String how) {
        String ip = server.getClientIp(ex);
        String token = Main.sessions.create(admin.id(), userAgent(ex), ip);
        ex.getResponseHeaders().add("Set-Cookie", WebSessions.cookieHeader(token));
        SSLMailServer.forgetCurrentSession();
        server.logAudit("LOGIN_SUCCESS", ip, "user=" + admin.username() + " method=" + how);
        boolean noPasskey = AuthStore.passkeysOf(admin.id()).isEmpty();
        return new JSONObject().put("success", true).put("csrf_token", WebSessions.csrfToken(token))
                .put("redirect", noPasskey ? "/account?setup=passkey" : "/home");
    }

    // ===================== Before login =====================

    /** POST /api/login. */
    void handleLogin(HttpExchange ex) throws IOException {
        handleLogin(ex, true);
    }

    /**
     * The login. With the separated panel it is served by the root part (A), to which the web part passes it after
     * checking the page's CSRF token itself: the cookie that ties it to the browser stays with the web part
     * (checkPageToken false).
     */
    void handleLogin(HttpExchange ex, boolean checkPageToken) throws IOException {
        try {
            server.addSecurityHeaders(ex);
            if (!"POST".equals(ex.getRequestMethod())) {
                ex.getResponseHeaders().set("Allow", "POST");
                send(ex, 405, error("server.methodNotAllowed"));
                return;
            }
            Main.refreshSetupState();
            if (!Main.mysqlAvailable || Main.setupRequired) { send(ex, 503, error("server.login.unavailable")); return; }
            JSONObject req = body(ex);
            if (req == null) { send(ex, 400, error("server.badRequest")); return; }
            String ip = server.getClientIp(ex);
            if (checkPageToken && !WebSessions.validPreLoginCsrf(SSLMailServer.cookieValue(ex, WebSessions.PRE_COOKIE), req.optString("csrf_token", ""))) {
                server.logAudit("CSRF_FAILURE", ip, "login page token");
                send(ex, 403, error("server.csrfInvalid"));
                return;
            }
            switch (req.optString("action", "")) {
                case "passkey_options" -> {
                    try {
                        PasskeyService.Started s = PasskeyService.startLogin(host(ex));
                        send(ex, 200, new JSONObject().put("success", true).put("request", s.requestId())
                                .put("options", new JSONObject(s.optionsJson())));
                    } catch (PasskeyService.PasskeyException e) {
                        send(ex, 400, error(e.getMessage()));
                    }
                }
                case "passkey_verify" -> {
                    JSONObject credential = req.optJSONObject("credential");
                    if (credential == null) { send(ex, 400, error("server.badRequest")); return; }
                    try {
                        AuthStore.Admin admin = PasskeyService.finishLogin(req.optString("request", ""), credential.toString());
                        send(ex, 200, startSession(ex, admin, "passkey"));
                    } catch (PasskeyService.PasskeyException e) {
                        server.logAudit("LOGIN_FAILURE", ip, "passkey refused");
                        send(ex, 401, error(e.getMessage()));
                    }
                }
                case "code_request" -> {
                    long start = System.currentTimeMillis();
                    String email = req.optString("email", "").trim();
                    // Only the shape of the address: no response says whether it belongs to someone.
                    if (!LoginCodes.validEmail(email)) { send(ex, 400, error("server.login.badEmail")); return; }
                    LoginCodes.requestEmailLogin(email, ip);
                    padTo(start);
                    send(ex, 200, new JSONObject().put("success", true).put("message", I18n.tr("server.login.codeSent")));
                }
                case "code_verify" -> {
                    long start = System.currentTimeMillis();
                    Optional<AuthStore.Admin> admin = LoginCodes.verifyEmailLogin(req.optString("email", "").trim(), req.optString("code", ""), ip);
                    // An address nobody owns does not touch the database, a real one does: the same time for both.
                    padTo(start);
                    if (admin.isEmpty()) {
                        server.logAudit("LOGIN_FAILURE", ip, "email code refused");
                        send(ex, 401, error("server.login.codeWrong"));
                        return;
                    }
                    send(ex, 200, startSession(ex, admin.get(), "email-code"));
                }
                case "console_verify" -> {
                    long start = System.currentTimeMillis();
                    Optional<AuthStore.Admin> admin = LoginCodes.verifyConsoleCode(req.optString("code", ""), ip);
                    padTo(start);
                    if (admin.isEmpty()) {
                        server.logAudit("LOGIN_FAILURE", ip, "console code refused");
                        send(ex, 401, error("server.login.codeWrong"));
                        return;
                    }
                    send(ex, 200, startSession(ex, admin.get(), "console-code"));
                }
                default -> send(ex, 400, error("server.unknownAction"));
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Login request failed", e);
            send(ex, 500, error("server.requestFailed"));
        }
    }

    // ===================== After login: the account =====================

    /** GET/POST /api/account. The CSRF token of the POSTs is checked by the route filter. */
    void handleAccount(HttpExchange ex) throws IOException {
        try {
            server.addSecurityHeaders(ex);
            Optional<WebSessions.Current> session = server.currentSession(ex);
            if (session.isEmpty()) { send(ex, 401, error("server.unauthorized")); return; }
            WebSessions.Current s = session.get();
            AuthStore.Admin me = s.admin();
            if ("GET".equals(ex.getRequestMethod())) { send(ex, 200, info(ex, s)); return; }
            if (!"POST".equals(ex.getRequestMethod())) {
                ex.getResponseHeaders().set("Allow", "GET, POST");
                send(ex, 405, error("server.methodNotAllowed"));
                return;
            }
            JSONObject req = body(ex);
            if (req == null) { send(ex, 400, error("server.badRequest")); return; }
            String ip = server.getClientIp(ex);
            switch (req.optString("action", "")) {
                case "email_request" -> {
                    String email = req.optString("email", "").trim();
                    switch (LoginCodes.requestEmailChange(me, email, ip)) {
                        case SENT -> send(ex, 200, new JSONObject().put("success", true).put("message", I18n.tr("server.account.emailCodeSent")));
                        case INVALID -> send(ex, 400, error("server.login.badEmail"));
                        case TAKEN -> send(ex, 409, error("server.account.emailTaken"));
                        case LIMIT -> send(ex, 429, error("server.account.limit"));
                    }
                }
                case "email_confirm" -> {
                    if (!LoginCodes.confirmEmailChange(me, req.optString("code", ""))) { send(ex, 400, error("server.login.codeWrong")); return; }
                    server.logAudit("ADMIN_EMAIL_CHANGED", ip, "user=" + me.username());
                    send(ex, 200, new JSONObject().put("success", true)
                            .put("email", AuthStore.adminById(me.id()).map(AuthStore.Admin::email).orElse("")));
                }
                case "change_username" -> {
                    String name = req.optString("username", "").trim();
                    if (!SecurityUtils.isValidUsername(name)) { send(ex, 400, error("server.account.badUsername")); return; }
                    switch (AuthStore.renameAdmin(me.id(), name)) {
                        case CREATED -> {
                            server.logAudit("ADMIN_USERNAME_CHANGED", ip, "admin_id=" + me.id() + " old=" + me.username() + " new=" + name);
                            send(ex, 200, new JSONObject().put("success", true).put("username", name));
                        }
                        case NAME_TAKEN -> send(ex, 409, error("server.account.usernameTaken"));
                        default -> send(ex, 500, error("server.requestFailed"));
                    }
                }
                case "passkey_register_options" -> {
                    try {
                        PasskeyService.Started st = PasskeyService.startRegistration(me, s.id(), host(ex));
                        send(ex, 200, new JSONObject().put("success", true).put("request", st.requestId())
                                .put("options", new JSONObject(st.optionsJson())));
                    } catch (PasskeyService.PasskeyException e) {
                        send(ex, 400, error(e.getMessage()));
                    }
                }
                case "passkey_register" -> {
                    JSONObject credential = req.optJSONObject("credential");
                    String name = req.optString("name", "").trim();
                    if (credential == null) { send(ex, 400, error("server.badRequest")); return; }
                    if (name.isEmpty()) name = "Passkey";
                    if (!PASSKEY_NAME.matcher(name).matches()) { send(ex, 400, error("server.passkey.badName")); return; }
                    try {
                        PasskeyService.finishRegistration(req.optString("request", ""), s.id(), credential.toString(), name);
                        server.logAudit("PASSKEY_REGISTERED", ip, "user=" + me.username());
                        send(ex, 200, new JSONObject().put("success", true));
                    } catch (PasskeyService.PasskeyException e) {
                        server.logAudit("PASSKEY_REGISTER_FAILED", ip, "user=" + me.username());
                        send(ex, 400, error(e.getMessage()));
                    }
                }
                case "passkey_rename" -> {
                    String name = req.optString("name", "").trim();
                    if (!PASSKEY_NAME.matcher(name).matches()) { send(ex, 400, error("server.passkey.badName")); return; }
                    if (!AuthStore.renamePasskey(req.optLong("id", -1), me.id(), name)) { send(ex, 404, error("server.account.badId")); return; }
                    send(ex, 200, new JSONObject().put("success", true));
                }
                case "passkey_delete" -> {
                    long id = req.optLong("id", -1);
                    // Without an email for the codes, the last passkey is the only way back in (besides the console).
                    if (AuthStore.passkeysOf(me.id()).size() <= 1 && !me.hasEmail()) { send(ex, 409, error("server.passkey.lastOne")); return; }
                    if (!AuthStore.deletePasskey(id, me.id())) { send(ex, 404, error("server.account.badId")); return; }
                    server.logAudit("PASSKEY_DELETED", ip, "user=" + me.username() + " passkey_id=" + id);
                    send(ex, 200, new JSONObject().put("success", true));
                }
                case "revoke_session" -> {
                    long id = req.optLong("id", -1);
                    if (!Main.sessions.revokeById(id, me.id())) { send(ex, 404, error("server.account.badId")); return; }
                    server.logAudit("SESSION_REVOKED", ip, "user=" + me.username() + " session_id=" + id);
                    send(ex, 200, new JSONObject().put("success", true).put("current", id == s.id()));
                }
                case "revoke_other_sessions" -> {
                    int n = Main.sessions.revokeOthers(me.id(), s.id());
                    server.logAudit("SESSION_REVOKED", ip, "user=" + me.username() + " others=" + n);
                    send(ex, 200, new JSONObject().put("success", true).put("revoked", n));
                }
                case "stepup_options" -> {
                    try {
                        PasskeyService.Started st = PasskeyService.startStepUp(me, s.id(), host(ex));
                        send(ex, 200, new JSONObject().put("success", true).put("request", st.requestId())
                                .put("options", new JSONObject(st.optionsJson())));
                    } catch (PasskeyService.PasskeyException e) {
                        send(ex, 400, error(e.getMessage()));
                    }
                }
                case "stepup_verify" -> {
                    JSONObject credential = req.optJSONObject("credential");
                    if (credential == null) { send(ex, 400, error("server.badRequest")); return; }
                    try {
                        PasskeyService.finishStepUp(req.optString("request", ""), s.id(), me.id(), credential.toString());
                        Main.sessions.markReauthenticated(s.id());
                        send(ex, 200, new JSONObject().put("success", true));
                    } catch (PasskeyService.PasskeyException e) {
                        server.logAudit("LOGIN_FAILURE", ip, "step-up passkey refused user=" + me.username());
                        send(ex, 401, error(e.getMessage()));
                    }
                }
                case "stepup_code_request" -> {
                    if (!me.hasEmail()) { send(ex, 409, error("server.reauth.noEmail")); return; }
                    if (!LoginCodes.requestStepUp(me, ip)) { send(ex, 429, error("server.account.limit")); return; }
                    send(ex, 200, new JSONObject().put("success", true).put("message", I18n.tr("server.reauth.codeSent")));
                }
                case "stepup_code_verify" -> {
                    if (!LoginCodes.verifyStepUp(me, req.optString("code", ""))) {
                        server.logAudit("LOGIN_FAILURE", ip, "step-up code refused user=" + me.username());
                        send(ex, 401, error("server.login.codeWrong"));
                        return;
                    }
                    Main.sessions.markReauthenticated(s.id());
                    send(ex, 200, new JSONObject().put("success", true));
                }
                case "stepup_console_verify" -> {
                    // The way for someone with no passkey who does not receive the email (port 25 closed, no email):
                    // a --access-code code for themselves, as at login, with the same constant wait.
                    long start = System.currentTimeMillis();
                    boolean ok = LoginCodes.verifyConsoleStepUp(me, req.optString("code", ""), ip);
                    padTo(start);
                    if (!ok) {
                        server.logAudit("LOGIN_FAILURE", ip, "step-up console code refused user=" + me.username());
                        send(ex, 401, error("server.login.codeWrong"));
                        return;
                    }
                    Main.sessions.markReauthenticated(s.id());
                    server.logAudit("STEP_UP_CONSOLE_CODE", ip, "user=" + me.username());
                    send(ex, 200, new JSONObject().put("success", true));
                }
                default -> send(ex, 400, error("server.unknownAction"));
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Account request failed", e);
            send(ex, 500, error("server.requestFailed"));
        }
    }

    /** Name, role, login email, passkeys and sessions of the logged-in administrator. */
    private JSONObject info(HttpExchange ex, WebSessions.Current s) {
        AuthStore.Admin me = s.admin();
        JSONArray keys = new JSONArray();
        for (AuthStore.Passkey p : AuthStore.passkeysOf(me.id()))
            keys.put(new JSONObject().put("id", p.id()).put("name", p.name() == null ? "Passkey" : p.name())
                    .put("created_at", iso(p.createdAt())).put("last_used", iso(p.lastUsed())));
        JSONArray sessions = new JSONArray();
        for (WebSessions.Listed l : Main.sessions.list(me.id()))
            sessions.put(new JSONObject().put("id", l.id()).put("ip", l.ip()).put("user_agent", l.userAgent())
                    .put("created_at", iso(l.createdAt())).put("last_seen", iso(l.lastSeenAt()))
                    .put("current", l.id() == s.id()));
        return new JSONObject().put("success", true).put("username", me.username()).put("role", me.role())
                .put("email", me.email()).put("passkeys", keys).put("sessions", sessions)
                .put("passkeysAvailable", PasskeyService.rpId(host(ex)) != null)
                .put("reauthenticated", s.reauthenticatedWithin(REAUTH_SECONDS));
    }

    /** The parameters of a text, for whoever builds messages with values. */
    static Map<String, Object> params(Object... kv) {
        Map<String, Object> m = new java.util.HashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }
}
