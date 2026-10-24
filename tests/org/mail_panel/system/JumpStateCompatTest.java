package org.mail_panel.system;

import org.json.JSONObject;

/**
 * Lo stato di un salto di versione scritto dal pannello di prima si rilegge.
 *
 * Il 24/10/2026 le chiavi del file version-jump.json sono passate all'inglese. Un salto
 * attraversa un riavvio, e il pannello puo' essere aggiornato in mezzo: il file l'ha scritto il
 * codice vecchio e lo rilegge quello nuovo. Il testo qui sotto e' un file nel formato di prima,
 * come lo scriveva writeJumpState.
 */
public class JumpStateCompatTest {

    private static int failures = 0;

    public static void main(String[] args) {
        String old = """
                {
                  "bersaglio": "15.1-RELEASE",
                  "fase": "attende-riavvio",
                  "ricostruzione": "nessuna",
                  "passi": [
                    {"giro": 1, "codice": 0, "chiede": "reboot", "kernel": "15.1-RELEASE", "userland": "15.0-RELEASE-p3"}
                  ]
                }
                """;
        JSONObject st = UpdateManager.upgradeOldJumpState(new JSONObject(old));
        check("la fase si legge col nome nuovo", "attende-riavvio".equals(st.optString("phase")));
        check("  e la chiave vecchia non resta", !st.has("fase"));
        check("la versione di arrivo", "15.1-RELEASE".equals(st.optString("target")));
        check("la ricostruzione", "nessuna".equals(st.optString("rebuild")));
        check("i passi", st.optJSONArray("steps") != null && st.getJSONArray("steps").length() == 1);
        JSONObject s = st.optJSONArray("steps") == null || st.getJSONArray("steps").isEmpty()
                ? new JSONObject() : st.getJSONArray("steps").getJSONObject(0);
        check("  un passo: giro, codice e richiesta coi nomi nuovi",
              s.optInt("round") == 1 && s.has("code") && s.optInt("code", -1) == 0 && "reboot".equals(s.optString("asks")));
        check("  e kernel e userland restano", "15.1-RELEASE".equals(s.optString("kernel")) && s.has("userland"));

        // Un file gia' nuovo non cambia
        JSONObject fresh = new JSONObject().put("phase", "finished").put("target", "15.1-RELEASE");
        check("un file gia' nuovo resta com'e'", UpdateManager.upgradeOldJumpState(new JSONObject(fresh.toString())).similar(fresh));

        // Se ci sono tutte e due, vince la nuova
        JSONObject both = UpdateManager.upgradeOldJumpState(new JSONObject().put("fase", "vecchia").put("phase", "nuova"));
        check("con tutte e due le chiavi vince la nuova", "nuova".equals(both.optString("phase")));

        System.out.println(failures == 0 ? "\nTUTTO OK" : "\n" + failures + " PROVE FALLITE");
        if (failures > 0) System.exit(1);
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failures++;
    }
}
