package org.daemoxcp.mail.scripts;

import org.daemoxcp.mail.system.PostfixLevels;

/**
 * The Postfix compatibility level at installation: the one the installed Postfix asks for, if the panel
 * has examined it. It is used by the three scripts that write main.cf (FullMailServerScript, FullMailStackScript,
 * PostfixScript), after main.cf and before startup.
 *
 * main.cf is created with compatibility_level = 3.6, a floor: below it, mynetworks_style = subnet made the whole
 * network of the server an open relay. But the installed package was Postfix 3.11, which asks for 3.11: Diagnostics
 * warned "Postfix: the level is behind" on a server just installed by the panel itself (measured on the clean VM on
 * 2026-11-16, following the installation guide).
 *
 * The level is stated by Postfix: `postfix check` writes 'To disable backwards compatibility use "postconf
 * compatibility_level=N"'. It goes up to N only if N is among the levels of PostfixLevels, where what changes is
 * written down for each one; PostfixLevelTest checks that every parameter that changes is decided in main.cf by each
 * of the three scripts, or that it does not matter (TLS-RPT off). So going up does not change how mail behaves: it
 * only removes the network and the warning. A level that the panel has not examined yet stays as it is, and this is
 * said: Diagnostics shows it, and someone has to read what changes before going up.
 *
 * PF_SBIN is the folder of postfix and postconf: /usr/local/sbin, or the one of a test.
 */
public final class PostfixLevelScript {

    private PostfixLevelScript() {}

    public static String shell() {
        return """
        # --- Postfix's compatibility level (PostfixLevelScript.java) ---
        # The one the installed Postfix asks for, if the panel has reviewed it: main.cf already decides
        # every parameter that changes at that level, so going up only removes the warning.
        PF_SBIN="${PF_SBIN:-/usr/local/sbin}"
        PF_ASKED=$("$PF_SBIN/postfix" check 2>&1 | sed -n 's/.*compatibility_level=\\([0-9][0-9.]*\\).*/\\1/p' | head -n 1)
        PF_LEVEL_NOW=$("$PF_SBIN/postconf" -h compatibility_level 2>/dev/null)
        if [ -z "$PF_ASKED" ]; then
            echo "  Postfix compatibility level: $PF_LEVEL_NOW, the one this Postfix asks for"
        else
            case " __REVIEWED__ " in
                *" $PF_ASKED "*)
                    # Only upwards: Postfix asks for a level higher than the written one, never a lower one
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
