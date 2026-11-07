package org.mail_panel.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mail_panel.database.MailDatabase;

import java.util.ArrayList;
import java.util.List;

/**
 * The pieces born from merging the two sequences: the filter by domain and the translation of the
 * outcome into the rows of the DNS page.
 */
public class MtaStsSequenceTest {

    static int failed = 0;
    static void require(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static MailDatabase.Domain dom(String name) {
        MailDatabase.Domain d = new MailDatabase.Domain();
        d.domain = name;
        return d;
    }

    public static void main(String[] a) {
        List<MailDatabase.Domain> allItems = new ArrayList<>();
        for (String s : new String[]{"domain-d.test", "domain-b.test", "domain-a.test"}) allItems.add(dom(s));

        System.out.println("\n== filter(): the filter by domain ==");
        require("null means all", MtaStsSetup.filter(allItems, null).size() == 3);
        require("an exact name leaves one", MtaStsSetup.filter(allItems, "domain-d.test").size() == 1);
        require("upper case does not matter",
                MtaStsSetup.filter(allItems, "DoMaIn-D.TeSt").size() == 1);
        // If the comparison were "contains", "ake.net" would catch domain-d.test and the sequence
        // would work on a domain nobody asked for.
        require("the comparison is exact, not 'contains'",
                MtaStsSetup.filter(allItems, "ake.net").isEmpty());
        require("a domain that does not exist gives an EMPTY list (it is the guard against a false success)",
                MtaStsSetup.filter(allItems, "doesnotexist.invalid").isEmpty());
        require("a null list blows nothing up",
                MtaStsSetup.filter(null, "x.it").isEmpty());

        System.out.println("\n== asEntries(): the outcome translated for the DNS page ==");
        JSONObject outcome = new JSONObject()
            .put("success", true)
            .put("steps", new JSONArray()
                .put(new JSONObject().put("key", "include").put("title", "Include line")
                        .put("ok", true).put("messageText", "it was already in place"))
                .put(new JSONObject().put("key", "cname").put("title", "CNAME mta-sts")
                        .put("detail", new JSONArray()
                            .put(new JSONObject().put("domain", "domain-d.test").put("ok", true)
                                    .put("messageText", "CNAME record created"))))
                .put(new JSONObject().put("key", "txt").put("title", "Policy and TXT record")
                        .put("detail", new JSONArray()
                            .put(new JSONObject().put("domain", "a.it").put("ok", true).put("messageText", "ok"))
                            .put(new JSONObject().put("domain", "b.it").put("ok", false)
                                    .put("messageText", "the policy does not answer yet")))));

        JSONArray v = MtaStsSetup.asEntries(outcome);
        require("three steps become three rows", v.length() == 3);
        require("the simple step keeps title and outcome",
                v.getJSONObject(0).getString("title").equals("Include line")
                && v.getJSONObject(0).getBoolean("ok"));
        require("a per-domain step all successful is green", v.getJSONObject(1).getBoolean("ok"));
        require("the domain appears in the message",
                v.getJSONObject(1).getString("messageText").contains("domain-d.test"));
        // The red row is the only one that explains: if a single one fails, the step is NOT green.
        require("one failed row is enough for the step not to be green",
                !v.getJSONObject(2).getBoolean("ok"));
        require("the message has BOTH rows, not only the first",
                v.getJSONObject(2).getString("messageText").contains("a.it")
                && v.getJSONObject(2).getString("messageText").contains("b.it"));

        System.out.println("\n== asEntries(): an interrupted sequence does not vanish ==");
        JSONObject broken = new JSONObject().put("success", false)
            .put("error", "Without 443 configured the policy cannot answer: stopping.")
            .put("steps", new JSONArray()
                .put(new JSONObject().put("title", "Include line").put("ok", true)
                        .put("messageText", "done")));
        JSONArray vr = MtaStsSetup.asEntries(broken);
        require("the steps already done stay", vr.length() == 2);
        // A list of successful steps that stops without saying why looks like a success.
        require("at the end there is the red row that says why it stopped",
                !vr.getJSONObject(1).getBoolean("ok")
                && vr.getJSONObject(1).getString("messageText").contains("443"));

        System.out.println("\n== asEntries(): an EMPTY per-domain step is not a success ==");
        JSONArray vv = MtaStsSetup.asEntries(new JSONObject().put("success", true)
            .put("steps", new JSONArray().put(new JSONObject().put("title", "CNAME")
                    .put("detail", new JSONArray()))));
        require("no row examined cannot count as green", !vv.getJSONObject(0).getBoolean("ok"));

        System.out.println("\n" + (failed == 0 ? "ALL GREEN" : failed + " CHECKS FAILED"));
        if (failed > 0) System.exit(1);
    }
}
