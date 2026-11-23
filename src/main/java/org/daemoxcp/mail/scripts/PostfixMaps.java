package org.daemoxcp.mail.scripts;

/**
 * The queries of the Postfix MySQL maps written by the panel that are also needed outside the installation scripts.
 * They are Postfix configuration text (its %s), not JDBC statements: that is why they live here, with the scripts, and
 * not in the SQL catalog (SqlCatalogTest).
 */
public final class PostfixMaps {

    /** The map that points every mailbox to itself, after the aliases (system.MailboxAddressMap). */
    public static final String MAILBOX_ADDRESSES_FILE = "mysql-virtual-mailbox-addresses.cf";
    /**
     * The mailboxes that receive, with the same condition as virtual_mailbox_maps: Postfix takes as valid every address
     * it finds in virtual_alias_maps, so a mailbox that is disabled or that does not receive here would accept mail it
     * used to reject, even without a catch-all (measured on the VM). With a catch-all its mail goes to the catch-all.
     */
    public static final String MAILBOX_ADDRESSES_QUERY = "SELECT email FROM mailboxes WHERE email='%s' AND active=1 AND receive_enabled=1";

    /** Who owns each sender address, for reject_authenticated_sender_login_mismatch (system.SenderLoginMap). */
    public static final String SENDER_LOGIN_FILE = "mysql-sender-login-maps.cf";
    /**
     * The login names that can send from an address: the mailbox itself (even if it does not receive: a
     * no-reply mailbox sends), and the destination of an alias. Postfix looks up name@domain and then @domain: a
     * catch-all gives its mailbox the addresses of the domain that are neither mailboxes nor aliases, the same ones
     * whose mail it receives.
     */
    public static final String SENDER_LOGIN_QUERY = "SELECT email FROM mailboxes WHERE email='%s' AND active=1"
            + " UNION SELECT destination FROM aliases WHERE source='%s' AND active=1";
    /**
     * smtpd_sender_restrictions in main.cf, so also on 25: without the sender check, which applies only to those who
     * authenticate. On 25 authentication is off (PostfixSubmissionAuth) and Postfix, for every incoming message,
     * wrote "restriction `reject_authenticated_sender_login_mismatch' ignored: no SASL support" (production server,
     * 20 November).
     */
    public static final String SENDER_RESTRICTIONS = "permit_mynetworks, permit_sasl_authenticated, reject_non_fqdn_sender,"
            + " reject_unknown_sender_domain";
    /**
     * smtpd_sender_restrictions on the submission ports (587, 465), with -o in master.cf: the sender check first
     * (before permit_mynetworks: the webmail sends from 127.0.0.1, authenticated), then the same ones as main.cf.
     * Without spaces, like the other -o lines.
     */
    public static final String SUBMISSION_SENDER_RESTRICTIONS = "reject_authenticated_sender_login_mismatch,"
            + SENDER_RESTRICTIONS.replace(", ", ",");

    private PostfixMaps() {}
}
