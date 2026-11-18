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

    private PostfixMaps() {}
}
