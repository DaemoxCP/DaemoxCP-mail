package org.mail_panel.system;

import java.util.ArrayList;
import java.util.List;

/**
 * La logica VECCHIA, ricopiata identica dal commit 7204765, messa davanti agli stessi due
 * casi. Serve a dimostrare che i controlli della prova non sono decorativi: se passassero
 * anche qui, non starebbero verificando niente.
 */
public class MtaStsOldLogicTest {
    public static void main(String[] a) {
        List<MtaStsSetup.NameReview> cases = List.of(
            new MtaStsSetup.NameReview("domain-d.test", MtaStsSetup.NameState.ASSENTE,
                "nella zona non c'e' nessun record con questo nome", true),
            new MtaStsSetup.NameReview("x.it", MtaStsSetup.NameState.DA_CORREGGERE,
                "punta a \"altro.host\" invece che a \"mail.domain-b.test\"; passa da Cloudflare", true));

        List<String> absent = new ArrayList<>(), crooked = new ArrayList<>(),
                     proxied = new ArrayList<>(), blind = new ArrayList<>(),
                     propagating = new ArrayList<>();
        for (MtaStsSetup.NameReview e : cases) {
            switch (e.state) {
                case ASSENTE -> absent.add(e.domain + " (" + e.reason + ")");
                case CIECO -> blind.add(e.domain + " (" + e.reason + ")");
                case DA_CORREGGERE -> {
                    if (e.reason.contains("Cloudflare")) proxied.add(e.domain);
                    else crooked.add(e.domain + " (" + e.reason + ")");
                }
                case GIUSTO -> { if (!e.resolves) propagating.add(e.domain); }
            }
        }
        System.out.println("LOGICA VECCHIA, stessi due casi:");
        System.out.println("  proxati  = " + proxied);
        System.out.println("  storti   = " + crooked);
        boolean bugA = !proxied.contains("domain-d.test (non c'e' il record, risponde il jolly *.domain-d.test che sta dietro Cloudflare)")
                    && proxied.stream().noneMatch(s -> s.startsWith("domain-d.test"));
        boolean bugB = crooked.isEmpty();
        System.out.println("\n  domain-d.test NON risulta passare dal proxy  -> " + bugA
                         + "   (passo 5 verde: \"nessuno passa da Cloudflare\")");
        System.out.println("  il record che punta ALTROVE non risulta storto -> " + bugB
                         + "   (passo 4 verde: \"tutti presenti e giusti\")");
        System.out.println("\n" + ((bugA && bugB)
              ? "I due difetti si riproducono: i controlli della prova sono discriminanti."
              : "ATTENZIONE: i difetti NON si riproducono, la prova non dimostra niente."));
        if (!(bugA && bugB)) System.exit(1);
    }
}
