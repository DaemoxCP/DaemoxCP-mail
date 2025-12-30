package org.mail_panel.webserver;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.stream.Collectors;

public class WebSessions {
    Collection<Session> sessions;
    private static final long UPDATE_THRESHOLD = 1200; // 20 minutes

    public WebSessions() {
        this.sessions = new ArrayList<>();
    }

    public String create_value_session() {
        final String CHAR_POOL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        SecureRandom random = new SecureRandom();
        return random.ints(1024, 0, CHAR_POOL.length())
                .mapToObj(CHAR_POOL::charAt)
                .map(Object::toString)
                .collect(Collectors.joining());
    }

    public Object[] Add_Session(String UserAgent, String ip) {
        Session sess = new Session();
        sess.code = create_value_session();
        sess.expire = Instant.now().plusSeconds(3600);
        sess.UserAgent = UserAgent;
        sess.ip = ip;
        this.sessions.add(sess);

        Object[] values = new Object[2];
        values[0] = sess.prefix;
        values[1] = sess.code;
        return values;
    }

    public Object[] Get_Session(String session_name) {
        for (Session session : sessions) {
            if (session.code.equals(session_name)) {
                Object[] sessionData = new Object[2];
                sessionData[0] = session.prefix;
                sessionData[1] = session.code;
                return sessionData;
            }
        }
        return null;
    }

    public void deleteCookie(String cookie_name) {
        sessions.removeIf(session -> session.code.equals(cookie_name));
    }

    public boolean checkExistingSession(String sessionCode, String User_agent, String ip) {
        if (sessionCode == null || sessionCode.isEmpty()) return false;

        for (Session session : sessions) {
            if (session.code.equals(sessionCode)) {
                boolean isValid = Instant.now().isBefore(session.expire);
                // Only validate User-Agent (IP validation disabled for CloudFlare/proxy compatibility)
                boolean uaMatches = (session.UserAgent == null && User_agent == null) ||
                                    (session.UserAgent != null && session.UserAgent.equals(User_agent));

                return isValid && uaMatches;
            }
        }
        return false;
    }

    public void removeExpiredSessions() {
        Instant now = Instant.now();
        sessions.removeIf(session -> now.isAfter(session.expire));
    }

    public void updateSessionExpiration(String sessionCode) {
        for (Session session : sessions) {
            if (session.code.equals(sessionCode)) {
                Instant now = Instant.now();
                if (Duration.between(now, session.expire).getSeconds() < UPDATE_THRESHOLD) {
                    session.expire = now.plusSeconds(UPDATE_THRESHOLD);
                }
                break;
            }
        }
    }

    public String getCsrfToken(String sessionCode) {
        if (sessionCode == null || sessionCode.isEmpty()) return null;
        for (Session session : sessions) {
            if (session.code.equals(sessionCode)) {
                return session.csrfToken;
            }
        }
        return null;
    }

    public boolean validateCsrfToken(String sessionCode, String csrfToken) {
        String expectedToken = getCsrfToken(sessionCode);
        return SecurityUtils.validateCsrfToken(expectedToken, csrfToken);
    }

    public void regenerateCsrfToken(String sessionCode) {
        if (sessionCode == null || sessionCode.isEmpty()) return;
        for (Session session : sessions) {
            if (session.code.equals(sessionCode)) {
                session.regenerateCsrfToken();
                break;
            }
        }
    }

    public Session getSession(String sessionCode) {
        if (sessionCode == null || sessionCode.isEmpty()) return null;
        for (Session session : sessions) {
            if (session.code.equals(sessionCode)) {
                return session;
            }
        }
        return null;
    }

    public void setSessionAdmin(String sessionCode, int adminId, String username) {
        Session session = getSession(sessionCode);
        if (session != null) {
            session.adminId = adminId;
            session.username = username;
        }
    }
}
