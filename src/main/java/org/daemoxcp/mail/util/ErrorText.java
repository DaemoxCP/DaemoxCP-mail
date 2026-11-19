package org.daemoxcp.mail.util;

import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.security.PasskeyService;

import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Il testo di un'eccezione che puo' arrivare a una pagina (reperto 231, r19: all'utente solo messaggi generici, mai
 * nome di tabella, colonna, percorso o versione).
 *
 * <p>Le rotte mettevano nella risposta {@code e.getMessage()} di qualunque eccezione: un duplicato in MySQL diceva alla
 * pagina «Duplicate entry 'x' for key 'mailboxes.email'», un file mancante il suo percorso, un JSON storto il nome della
 * chiave. Qui si decide in un punto solo che cosa passa:
 * <ul>
 *   <li>il testo di ShownException, gia' tradotto: e' quella che il pannello lancia con un testo scritto per chi usa
 *       la pagina (AddressTransform, gli aggiornamenti). Di PasskeyException il testo della chiave che porta. Fino al
 *       19/11/2026 passava il messaggio di ogni IllegalArgumentException e IllegalStateException: molte avevano un
 *       testo inglese scritto nel codice, o il toString() di un'eccezione avvolta (classe, percorso), e arrivavano
 *       cosi' anche nelle pagine italiane (i18n completo);</li>
 *   <li>un duplicato di MySQL (errore 1062, anche dentro un'altra eccezione): «esiste gia'», senza la chiave;</li>
 *   <li>qualunque altra: una riga nel log del pannello con l'eccezione intera, e alla pagina il testo generico.</li>
 * </ul>
 */
public final class ErrorText {

    private static final Logger LOGGER = Logger.getLogger(ErrorText.class.getName());

    /** L'errore di MySQL per un valore gia' presente in una colonna UNIQUE. */
    static final int MYSQL_DUPLICATE = 1062;

    private ErrorText() {}

    /**
     * Il testo che il pannello ha scritto per la pagina, null se l'eccezione non ne porta uno. PasskeyException porta la
     * chiave del testo, non il testo: si traduce.
     */
    static String shown(Throwable e) {
        if (e == null || e.getMessage() == null || e.getMessage().isBlank()) return null;
        if (e instanceof PasskeyService.PasskeyException) return I18n.tr(e.getMessage());
        return e instanceof TranslatedError ? e.getMessage() : null;
    }

    /** Vero se fra le cause c'e' un duplicato di MySQL. */
    static boolean duplicate(Throwable e) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t instanceof SQLException s && s.getErrorCode() == MYSQL_DUPLICATE) return true;
            if (t.getCause() == t) break;
        }
        return false;
    }

    /**
     * Il campo d'errore di una risposta: il messaggio se e' del pannello, «esiste gia'» per un duplicato, altrimenti
     * una riga nel log e «Richiesta non riuscita: i dettagli sono nel log del pannello».
     *
     * @param caller il metodo che risponde, per ritrovare la riga nel log
     */
    public static String forPage(String caller, Throwable e) {
        String text = shown(e);
        if (text != null) return text;
        if (duplicate(e)) return I18n.tr("server.alreadyExists");
        log(caller, e);
        return I18n.tr("server.requestFailed");
    }

    /**
     * Il pezzo da mettere nel posto {error} di un testo che lo incornicia («Conversione non riuscita: {error}»): il
     * messaggio se e' del pannello, altrimenti una riga nel log e «i dettagli sono nel log del pannello».
     */
    public static String detail(String caller, Throwable e) {
        String text = shown(e);
        if (text != null) return text;
        if (duplicate(e)) return I18n.tr("server.alreadyExists");
        log(caller, e);
        return I18n.tr("server.detailsInLog");
    }

    private static void log(String caller, Throwable e) {
        LOGGER.log(Level.WARNING, "[" + caller + "] request failed: " + (e == null ? "no exception" : e.getClass().getName()), e);
    }
}
