package org.daemoxcp.mail.system;

/**
 * Il nome del prodotto, in un posto solo, nelle tre forme che servono sul server.
 *
 * <p>Il pannello si chiama DaemoxCP Mail dal 17/11/2026 (prima FreeBSD Mail Panel, "mailpanel" sul disco). Il nome
 * che vede chi usa il pannello sta nei file di lingua (brand.name); qui stanno quelli tecnici, che non si traducono:
 * <ul>
 *   <li>{@link #NAME}: nelle righe del registro che gli script rileggono, nelle firme dei file scritti dal pannello,
 *       negli User-Agent;</li>
 *   <li>{@link #SLUG}: dove il trattino si puo' usare, cioe' cartelle, file, il jar, i registri;</li>
 *   <li>{@link #ID}: dove il trattino non si puo', cioe' il servizio rc.d e le sue variabili, il database e gli
 *       utenti di MySQL, l'utente di sistema, il plugin di Roundcube.</li>
 * </ul>
 * I nomi di prima stanno in legacy-names.json, mai nel codice.
 */
public final class Product {

    public static final String NAME = "DaemoxCP Mail";
    public static final String SLUG = "daemoxcp-mail";
    public static final String ID = "daemoxcp_mail";

    private Product() {}
}
