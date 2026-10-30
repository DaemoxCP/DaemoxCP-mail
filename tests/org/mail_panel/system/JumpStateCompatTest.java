package org.mail_panel.system;

import org.json.JSONObject;

/**
 * Lo stato di un salto di versione scritto dal pannello di prima si rilegge.
 *
 * Il 24/10/2026 le chiavi del file version-jump.json sono passate all'inglese, il 29/10 i valori
 * di "asks". Un salto attraversa un riavvio, e il pannello puo' essere aggiornato in mezzo: il
 * file l'ha scritto il codice vecchio e lo rilegge quello nuovo. I nomi di prima non si scrivono
 * qui: si prendono dal file di dati (LegacyNames), e il file nel formato di prima si costruisce
 * da quello di adesso.
 */
public class JumpStateCompatTest {

    private static int failures = 0;

    /** Il nome di prima di {@code current} nella sezione, o current stesso se non ne ha uno. */
    static String old(String section, String current) {
        java.util.List<String> o = LegacyNames.oldNamesOf(section, current);
        return o.isEmpty() ? current : o.get(0);
    }

    public static void main(String[] args) {
        check("il file di dati ha le quattro sezioni dello stato del salto",
              !LegacyNames.pairs("jumpKeys").isEmpty() && !LegacyNames.pairs("jumpStepKeys").isEmpty()
              && !LegacyNames.pairs("jumpAsks").isEmpty() && !LegacyNames.pairs("jumpPhases").isEmpty());

        // Il file come lo scriveva writeJumpState prima del 24/10/2026.
        JSONObject step = new JSONObject()
                .put(old("jumpStepKeys", "round"), 1).put(old("jumpStepKeys", "code"), 0)
                .put(old("jumpStepKeys", "asks"), "reboot")
                .put("kernel", "15.1-RELEASE").put("userland", "15.0-RELEASE-p3");
        JSONObject oldState = new JSONObject()
                .put(old("jumpKeys", "target"), "15.1-RELEASE")
                .put(old("jumpKeys", "phase"), old("jumpPhases", "awaiting-restart"))
                .put(old("jumpKeys", "rebuild"), "-")
                .put(old("jumpKeys", "steps"), new org.json.JSONArray().put(step));
        check("  e il file di prova e' davvero nel formato di prima",
              !oldState.has("phase") && !oldState.has("target") && !step.has("round"));

        JSONObject st = UpdateManager.upgradeOldJumpState(new JSONObject(oldState.toString()));
        check("la fase si legge col nome nuovo", "awaiting-restart".equals(st.optString("phase")));
        check("  e la chiave vecchia non resta", !st.has(old("jumpKeys", "phase")));
        check("la versione di arrivo", "15.1-RELEASE".equals(st.optString("target")));
        check("la ricostruzione", "-".equals(st.optString("rebuild")));
        check("i passi", st.optJSONArray("steps") != null && st.getJSONArray("steps").length() == 1);
        JSONObject s = st.optJSONArray("steps") == null || st.getJSONArray("steps").isEmpty()
                ? new JSONObject() : st.getJSONArray("steps").getJSONObject(0);
        check("  un passo: giro, codice e richiesta coi nomi nuovi",
              s.optInt("round") == 1 && s.has("code") && s.optInt("code", -1) == 0 && "reboot".equals(s.optString("asks")));
        check("  e kernel e userland restano", "15.1-RELEASE".equals(s.optString("kernel")) && s.has("userland"));

        // Ogni fase di prima si legge col suo nome di adesso.
        boolean phases = true;
        for (String[] p : LegacyNames.pairs("jumpPhases"))
            phases &= p[1].equals(UpdateManager.upgradeOldJumpState(new JSONObject().put("phase", p[0])).optString("phase"));
        check("tutte le " + LegacyNames.pairs("jumpPhases").size() + " fasi di prima", phases);

        // I valori di "asks" scritti prima del 29/10/2026, anche sotto la chiave di prima.
        JSONObject asks = UpdateManager.upgradeOldJumpState(new JSONObject()
                .put("phase", "awaiting-restart").put("steps", new org.json.JSONArray()
                        .put(new JSONObject().put("round", 1).put("code", 0).put("asks", old("jumpAsks", "again")))
                        .put(new JSONObject().put("round", 2).put("code", 0).put(old("jumpStepKeys", "asks"), old("jumpAsks", "rebuild")))
                        .put(new JSONObject().put("round", 3).put("code", 0).put("asks", "restart"))));
        org.json.JSONArray ss = asks.getJSONArray("steps");
        check("asks di prima: again e rebuild, e restart resta",
              "again".equals(ss.getJSONObject(0).optString("asks"))
              && "rebuild".equals(ss.getJSONObject(1).optString("asks"))
              && "restart".equals(ss.getJSONObject(2).optString("asks")));

        // Un file gia' nuovo non cambia
        JSONObject fresh = new JSONObject().put("phase", "finished").put("target", "15.1-RELEASE");
        check("un file gia' nuovo resta com'e'", UpdateManager.upgradeOldJumpState(new JSONObject(fresh.toString())).similar(fresh));

        // Se ci sono tutte e due, vince la nuova
        JSONObject both = UpdateManager.upgradeOldJumpState(new JSONObject()
                .put(old("jumpKeys", "phase"), "error").put("phase", "finished"));
        check("con tutte e due le chiavi vince la nuova", "finished".equals(both.optString("phase")));

        System.out.println(failures == 0 ? "\nTUTTO OK" : "\n" + failures + " PROVE FALLITE");
        if (failures > 0) System.exit(1);
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failures++;
    }
}
