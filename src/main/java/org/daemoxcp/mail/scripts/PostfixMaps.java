package org.daemoxcp.mail.scripts;

/**
 * Le domande delle mappe MySQL di Postfix scritte dal pannello che servono anche fuori dagli script d'installazione.
 * Sono testo di configurazione di Postfix (il suo %s), non istruzioni JDBC: per questo stanno qui, con gli script, e non
 * nel catalogo SQL (SqlCatalogTest).
 */
public final class PostfixMaps {

    /** La mappa che fa puntare ogni casella a se stessa, dopo gli alias (system.MailboxAddressMap). */
    public static final String MAILBOX_ADDRESSES_FILE = "mysql-virtual-mailbox-addresses.cf";
    /**
     * Le caselle che ricevono, con la stessa condizione di virtual_mailbox_maps: Postfix prende per valido ogni indirizzo
     * che trova nelle virtual_alias_maps, quindi una casella spenta o che non riceve qui accetterebbe posta che prima
     * rifiutava, anche senza catch-all (misurato sulla VM). Con un catch-all la sua posta va al catch-all.
     */
    public static final String MAILBOX_ADDRESSES_QUERY = "SELECT email FROM mailboxes WHERE email='%s' AND active=1 AND receive_enabled=1";

    /** Chi possiede ogni indirizzo mittente, per reject_authenticated_sender_login_mismatch (system.SenderLoginMap). */
    public static final String SENDER_LOGIN_FILE = "mysql-sender-login-maps.cf";
    /**
     * I nomi con cui ci si autentica che possono spedire da un indirizzo: la casella stessa (anche se non riceve: una
     * casella no-reply spedisce), e la destinazione di un alias. Postfix cerca nome@dominio e poi @dominio: un catch-all
     * da' alla sua casella gli indirizzi del dominio che non sono ne' caselle ne' alias, gli stessi di cui riceve la posta.
     */
    public static final String SENDER_LOGIN_QUERY = "SELECT email FROM mailboxes WHERE email='%s' AND active=1"
            + " UNION SELECT destination FROM aliases WHERE source='%s' AND active=1";
    /**
     * smtpd_sender_restrictions in main.cf, quindi anche sulla 25: senza il controllo del mittente, che vale solo per chi
     * si autentica. Sulla 25 l'autenticazione e' spenta (PostfixSubmissionAuth) e Postfix, per ogni messaggio in arrivo,
     * scriveva «restriction `reject_authenticated_sender_login_mismatch' ignored: no SASL support» (server vero, 20/11).
     */
    public static final String SENDER_RESTRICTIONS = "permit_mynetworks, permit_sasl_authenticated, reject_non_fqdn_sender,"
            + " reject_unknown_sender_domain";
    /**
     * smtpd_sender_restrictions sulle porte di invio (587, 465), con -o in master.cf: il controllo del mittente davanti
     * (prima di permit_mynetworks: la webmail spedisce da 127.0.0.1 autenticata), poi le stesse di main.cf. Senza spazi,
     * come le altre righe -o.
     */
    public static final String SUBMISSION_SENDER_RESTRICTIONS = "reject_authenticated_sender_login_mismatch,"
            + SENDER_RESTRICTIONS.replace(", ", ",");

    private PostfixMaps() {}
}
