package org.daemoxcp.mail.util;

import org.daemoxcp.mail.i18n.I18n;

import java.util.Map;

/**
 * Un errore scritto per chi usa la pagina, gia' nella sua lingua: l'unico, con PasskeyException, il cui testo
 * ErrorText lascia arrivare a una pagina. Un'altra eccezione, anche IllegalArgumentException o IllegalStateException
 * con un testo scritto a mano, finisce nel log del pannello, e alla pagina va il testo generico tradotto: cosi' nessun
 * testo inglese scritto nel codice, ne' il toString() di un'eccezione avvolta (percorsi, classi), arriva a chi usa il
 * pannello (i18n completo, 19/11/2026).
 *
 * <p>Si costruisce con la chiave del testo: of("server.x.y") o of("server.x.y", Map.of("name", ...)). Il testo si
 * traduce subito, nella lingua della richiesta in corso (I18n.current), come faceva chi lo lanciava con I18n.tr.
 */
public class ShownException extends IllegalStateException {

    private final String key;

    private ShownException(String key, String text) {
        super(text);
        this.key = key;
    }

    /** Il testo della chiave, nella lingua della richiesta in corso. */
    public static ShownException of(String key) {
        return new ShownException(key, I18n.tr(key));
    }

    /** Il testo della chiave coi suoi {valori}, nella lingua della richiesta in corso. */
    public static ShownException of(String key, Map<String, ?> params) {
        return new ShownException(key, I18n.tr(key, params));
    }

    /**
     * Un testo gia' tradotto altrove con I18n.tr (un campo di uno stato costruito prima, nella stessa lingua). Solo per
     * quello: un testo scritto nel codice si lancia con of(chiave).
     */
    public static ShownException translated(String text) {
        return new ShownException(null, text);
    }

    /** La chiave del testo, per le prove e per chi deve riconoscere l'errore; null per translated(). */
    public String key() {
        return key;
    }
}
