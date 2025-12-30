package org.mail_panel.webserver;

import java.time.Instant;

public class Session {
    public String prefix = "MailPanel";
    public String code;
    public Instant expire;
    public String UserAgent;
    public String ip;
    public String csrfToken;
    public int adminId;
    public String username;

    public Session() {
        this.csrfToken = SecurityUtils.generateCsrfToken();
    }

    public void regenerateCsrfToken() {
        this.csrfToken = SecurityUtils.generateCsrfToken();
    }
}
