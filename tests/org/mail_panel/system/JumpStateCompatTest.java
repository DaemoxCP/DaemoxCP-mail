package org.mail_panel.system;

import org.json.JSONObject;

/**
 * The state of a version jump written by the old panel reads back.
 *
 * On 24/10/2026 the keys of version-jump.json moved to English, on 29/10 the values of "asks". A
 * jump goes across a reboot, and the panel can be updated in between: the old code wrote the file
 * and the new one reads it. The old names are not written here: they come from the data file
 * (LegacyNames), and the file in the old format is built from today's.
 */
public class JumpStateCompatTest {

    private static int failures = 0;

    /** The old name of {@code current} in the section, or current itself if it has none. */
    static String old(String section, String current) {
        java.util.List<String> o = LegacyNames.oldNamesOf(section, current);
        return o.isEmpty() ? current : o.get(0);
    }

    public static void main(String[] args) {
        check("the data file has the four sections of the jump state",
              !LegacyNames.pairs("jumpKeys").isEmpty() && !LegacyNames.pairs("jumpStepKeys").isEmpty()
              && !LegacyNames.pairs("jumpAsks").isEmpty() && !LegacyNames.pairs("jumpPhases").isEmpty());

        // The file as writeJumpState wrote it before 24/10/2026.
        JSONObject step = new JSONObject()
                .put(old("jumpStepKeys", "round"), 1).put(old("jumpStepKeys", "code"), 0)
                .put(old("jumpStepKeys", "asks"), "reboot")
                .put("kernel", "15.1-RELEASE").put("userland", "15.0-RELEASE-p3");
        JSONObject oldState = new JSONObject()
                .put(old("jumpKeys", "target"), "15.1-RELEASE")
                .put(old("jumpKeys", "phase"), old("jumpPhases", "awaiting-restart"))
                .put(old("jumpKeys", "rebuild"), "-")
                .put(old("jumpKeys", "steps"), new org.json.JSONArray().put(step));
        check("  and the test file really is in the old format",
              !oldState.has("phase") && !oldState.has("target") && !step.has("round"));

        JSONObject st = UpdateManager.upgradeOldJumpState(new JSONObject(oldState.toString()));
        check("the phase reads with the new name", "awaiting-restart".equals(st.optString("phase")));
        check("  and the old key does not stay", !st.has(old("jumpKeys", "phase")));
        check("the target version", "15.1-RELEASE".equals(st.optString("target")));
        check("the rebuild", "-".equals(st.optString("rebuild")));
        check("the steps", st.optJSONArray("steps") != null && st.getJSONArray("steps").length() == 1);
        JSONObject s = st.optJSONArray("steps") == null || st.getJSONArray("steps").isEmpty()
                ? new JSONObject() : st.getJSONArray("steps").getJSONObject(0);
        check("  a step: round, code and request with the new names",
              s.optInt("round") == 1 && s.has("code") && s.optInt("code", -1) == 0 && "reboot".equals(s.optString("asks")));
        check("  and kernel and userland stay", "15.1-RELEASE".equals(s.optString("kernel")) && s.has("userland"));

        // Every old phase reads with its name of today.
        boolean phases = true;
        for (String[] p : LegacyNames.pairs("jumpPhases"))
            phases &= p[1].equals(UpdateManager.upgradeOldJumpState(new JSONObject().put("phase", p[0])).optString("phase"));
        check("all " + LegacyNames.pairs("jumpPhases").size() + " old phases", phases);

        // The "asks" values written before 29/10/2026, also under the old key.
        JSONObject asks = UpdateManager.upgradeOldJumpState(new JSONObject()
                .put("phase", "awaiting-restart").put("steps", new org.json.JSONArray()
                        .put(new JSONObject().put("round", 1).put("code", 0).put("asks", old("jumpAsks", "again")))
                        .put(new JSONObject().put("round", 2).put("code", 0).put(old("jumpStepKeys", "asks"), old("jumpAsks", "rebuild")))
                        .put(new JSONObject().put("round", 3).put("code", 0).put("asks", "restart"))));
        org.json.JSONArray ss = asks.getJSONArray("steps");
        check("old asks: again and rebuild, and restart stays",
              "again".equals(ss.getJSONObject(0).optString("asks"))
              && "rebuild".equals(ss.getJSONObject(1).optString("asks"))
              && "restart".equals(ss.getJSONObject(2).optString("asks")));

        // A file that is already new does not change
        JSONObject fresh = new JSONObject().put("phase", "finished").put("target", "15.1-RELEASE");
        check("a file that is already new stays as it is", UpdateManager.upgradeOldJumpState(new JSONObject(fresh.toString())).similar(fresh));

        // If both are there, the new one wins
        JSONObject both = UpdateManager.upgradeOldJumpState(new JSONObject()
                .put(old("jumpKeys", "phase"), "error").put("phase", "finished"));
        check("with both keys the new one wins", "finished".equals(both.optString("phase")));

        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        if (failures > 0) System.exit(1);
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failures++;
    }
}
