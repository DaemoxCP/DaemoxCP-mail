package org.daemoxcp.mail.scripts;

import org.daemoxcp.mail.system.PostfixLevels;

/**
 * Il livello di compatibilita' di Postfix all'installazione: quello che chiede il Postfix installato, se il pannello
 * lo ha esaminato. Lo usano i tre script che scrivono main.cf (FullMailServerScript, FullMailStackScript,
 * PostfixScript), dopo main.cf e prima dell'avvio.
 *
 * main.cf nasce con compatibility_level = 3.6, un pavimento: sotto, mynetworks_style = subnet faceva di tutta la rete
 * del server un relay aperto. Ma il pacchetto installato era Postfix 3.11, che chiede 3.11: la Diagnostica avvisava
 * «Postfix: the level is behind» su un server appena installato dal pannello stesso (misurato sulla VM pulita il
 * 16/11/2026, seguendo la guida d'installazione).
 *
 * Il livello lo dice Postfix: `postfix check` scrive «To disable backwards compatibility use "postconf
 * compatibility_level=N"». Si sale a N solo se N e' fra i livelli di PostfixLevels, dove per ognuno sta cosa cambia;
 * PostfixLevelTest controlla che ogni parametro che cambia sia deciso in main.cf da ciascuno dei tre script, o che non
 * conti (TLS-RPT spento). Cosi' salire non cambia il comportamento della posta: toglie solo la rete e l'avviso. Un
 * livello che il pannello non ha ancora esaminato resta com'e', e lo si dice: la Diagnostica lo mostra, e qualcuno
 * deve leggere cosa cambia prima di salire.
 *
 * PF_SBIN e' la cartella di postfix e postconf: /usr/local/sbin, o quella di una prova.
 */
public final class PostfixLevelScript {

    private PostfixLevelScript() {}

    public static String shell() {
        return """
        # --- Il livello di compatibilita' di Postfix (PostfixLevelScript.java) ---
        # Quello che chiede il Postfix installato, se il pannello lo ha esaminato: main.cf decide gia'
        # ogni parametro che a quel livello cambia, quindi salire toglie solo l'avviso.
        PF_SBIN="${PF_SBIN:-/usr/local/sbin}"
        PF_ASKED=$("$PF_SBIN/postfix" check 2>&1 | sed -n 's/.*compatibility_level=\\([0-9][0-9.]*\\).*/\\1/p' | head -n 1)
        PF_LEVEL_NOW=$("$PF_SBIN/postconf" -h compatibility_level 2>/dev/null)
        if [ -z "$PF_ASKED" ]; then
            echo "  Postfix compatibility level: $PF_LEVEL_NOW, the one this Postfix asks for"
        else
            case " __REVIEWED__ " in
                *" $PF_ASKED "*)
                    # Solo in su: Postfix chiede un livello piu' alto di quello scritto, mai uno piu' basso
                    if ! awk -v a="$PF_ASKED" -v n="$PF_LEVEL_NOW" 'BEGIN { split(a, x, "."); split(n, y, ".");
                            exit !((x[1] + 0 > y[1] + 0) || (x[1] + 0 == y[1] + 0 && x[2] + 0 > y[2] + 0)) }'; then
                        echo "  Postfix compatibility level: $PF_LEVEL_NOW (this Postfix asks for $PF_ASKED, not higher)"
                    elif "$PF_SBIN/postconf" -e "compatibility_level=$PF_ASKED"; then
                        echo "  Postfix compatibility level: $PF_ASKED, the one this Postfix asks for (it was $PF_LEVEL_NOW)"
                    else
                        echo "  WARNING: Postfix compatibility level not raised to $PF_ASKED: it stays at $PF_LEVEL_NOW"
                    fi
                    ;;
                *)
                    echo "  WARNING: this Postfix asks for compatibility level $PF_ASKED, which the panel has not reviewed yet: it stays at $PF_LEVEL_NOW"
                    ;;
            esac
        fi
        """.replace("__REVIEWED__", String.join(" ", PostfixLevels.reviewed()));
    }
}
