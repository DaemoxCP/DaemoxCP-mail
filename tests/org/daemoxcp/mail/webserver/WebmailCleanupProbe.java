package org.daemoxcp.mail.webserver;

/** For MailboxCleanupTest (another package): the days of the webmail's form, as WebmailPasswordHandler reads them. */
public final class WebmailCleanupProbe {

    private WebmailCleanupProbe() {}

    public static int days(String value) {
        return WebmailPasswordHandler.days(value);
    }
}
