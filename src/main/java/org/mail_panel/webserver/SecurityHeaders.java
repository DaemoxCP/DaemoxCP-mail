package org.mail_panel.webserver;

/**
 * La Content-Security-Policy del pannello, in un punto solo: la manda il server con ogni risposta
 * (SSLMailServer.addSecurityHeaders) e la usano le prove nel browser, che servono le pagine generate
 * con la stessa intestazione.
 *
 * <p>Senza 'unsafe-inline' e senza 'unsafe-eval' (reperto 178). Prima script-src e style-src avevano
 * 'unsafe-inline', perche' le pagine portavano 458 gestori onclick="...", una trentina di script e
 * stili in linea e 208 attributi style: una stringa iniettata in una pagina poteva eseguire codice.
 * Adesso gli script e gli stili sono file (PageAssets), i gestori sono data-on-* e gli stili
 * data-style (panel-actions.js), e la politica puo' dire solo 'self'.
 *
 * <ul>
 *   <li>img-src tiene data: perche' Bootstrap disegna alcune icone dei moduli (la freccia delle
 *   select, la X di chiusura) con SVG in data: URI dentro il suo CSS; non tiene piu' https:, che
 *   permetteva immagini da qualunque sito (tutto deve venire dal pannello);</li>
 *   <li>object-src 'none', base-uri 'self' e form-action 'self' chiudono i plugin, un &lt;base&gt;
 *   iniettato che sposterebbe gli indirizzi relativi, e un modulo che spedirebbe altrove;</li>
 *   <li>frame-ancestors 'none': nessuno puo' mettere il pannello in un riquadro.</li>
 * </ul>
 */
public final class SecurityHeaders {

    private SecurityHeaders() {}

    /**
     * Costruita con String.join e non scritta come costante: una costante il compilatore la copia
     * dentro ogni classe che la usa, e allora il server e le prove potrebbero mandare e controllare
     * due politiche diverse senza accorgersene (e un guasto piantato qui non si vedrebbe).
     */
    public static final String CONTENT_SECURITY_POLICY = String.join("; ", java.util.List.of(
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self'",
            "img-src 'self' data:",
            "font-src 'self'",
            "connect-src 'self'",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'"));
}
