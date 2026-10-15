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
        List<MtaStsSetup.EsameNome> casi = List.of(
            new MtaStsSetup.EsameNome("domain-d.test", MtaStsSetup.StatoNome.ASSENTE,
                "nella zona non c'e' nessun record con questo nome", true),
            new MtaStsSetup.EsameNome("x.it", MtaStsSetup.StatoNome.DA_CORREGGERE,
                "punta a \"altro.host\" invece che a \"mail.domain-b.test\"; passa da Cloudflare", true));

        List<String> assenti = new ArrayList<>(), storti = new ArrayList<>(),
                     proxati = new ArrayList<>(), ciechi = new ArrayList<>(),
                     inPropagazione = new ArrayList<>();
        for (MtaStsSetup.EsameNome e : casi) {
            switch (e.stato) {
                case ASSENTE -> assenti.add(e.dominio + " (" + e.motivo + ")");
                case CIECO -> ciechi.add(e.dominio + " (" + e.motivo + ")");
                case DA_CORREGGERE -> {
                    if (e.motivo.contains("Cloudflare")) proxati.add(e.dominio);
                    else storti.add(e.dominio + " (" + e.motivo + ")");
                }
                case GIUSTO -> { if (!e.risolve) inPropagazione.add(e.dominio); }
            }
        }
        System.out.println("LOGICA VECCHIA, stessi due casi:");
        System.out.println("  proxati  = " + proxati);
        System.out.println("  storti   = " + storti);
        boolean bugA = !proxati.contains("domain-d.test (non c'e' il record, risponde il jolly *.domain-d.test che sta dietro Cloudflare)")
                    && proxati.stream().noneMatch(s -> s.startsWith("domain-d.test"));
        boolean bugB = storti.isEmpty();
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
