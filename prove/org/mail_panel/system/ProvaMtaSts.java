package org.mail_panel.system;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.List;

/**
 * Prova la logica che il piano MTA-STS usa per decidere, con i casi veri del server.
 * Non prova che il codice compili: prova che dica il vero.
 */
public class ProvaMtaSts {

    static int falliti = 0;

    static void esigi(String cosa, boolean condizione) {
        System.out.println((condizione ? "  OK   " : "  FALLITO ") + cosa);
        if (!condizione) falliti++;
    }

    static AttivaMtaSts.EsameNome e(String d, AttivaMtaSts.StatoNome s, String m,
                                    boolean risolve, boolean proxy, boolean storto) {
        return new AttivaMtaSts.EsameNome(d, s, m, risolve, proxy, storto);
    }

    public static void main(String[] a) throws Exception {

        System.out.println("\n== ripartisci(): il caso vero di domain-d.test ==");
        // Nella zona non c'e' mta-sts.domain-d.test; risponde il jolly *.domain-d.test, proxato.
        var rip = AttivaMtaSts.ripartisci(List.of(
                e("domain-d.test", AttivaMtaSts.StatoNome.ASSENTE, "nella zona non c'e'", true, true, false)));
        esigi("il dominio finisce fra gli assenti", rip.assenti.size() == 1);
        esigi("e ANCHE fra quelli che passano dal proxy (era il falso verde)", rip.proxati.size() == 1);
        esigi("il piano sa che il proxy viene da un jolly", rip.proxyDaJolly);
        esigi("la riga del proxy nomina il jolly", rip.proxati.get(0).contains("*.domain-d.test"));

        System.out.println("\n== ripartisci(): record insieme SBAGLIATO e PROXATO ==");
        // Prima finiva nel solo conto del proxy, perche' il motivo conteneva "Cloudflare":
        // il passo dei CNAME dichiarava "tutti presenti e giusti" un record che puntava altrove.
        rip = AttivaMtaSts.ripartisci(List.of(
                e("x.it", AttivaMtaSts.StatoNome.DA_CORREGGERE,
                  "punta a \"altro.host\" invece che a \"mail.domain-b.test\"; passa da Cloudflare",
                  true, true, true)));
        esigi("compare fra gli storti", rip.storti.size() == 1);
        esigi("compare ANCHE fra i proxati", rip.proxati.size() == 1);
        esigi("il proxy non viene da un jolly", !rip.proxyDaJolly);

        System.out.println("\n== ripartisci(): record giusto ma proxato ==");
        rip = AttivaMtaSts.ripartisci(List.of(
                e("y.it", AttivaMtaSts.StatoNome.DA_CORREGGERE, "passa da Cloudflare", true, true, false)));
        esigi("non e' storto", rip.storti.isEmpty());
        esigi("e' proxato", rip.proxati.size() == 1);

        System.out.println("\n== ripartisci(): cieco, propagazione, tutto a posto ==");
        rip = AttivaMtaSts.ripartisci(List.of(
                e("c.it", AttivaMtaSts.StatoNome.CIECO, "zona non visibile", false, false, false),
                e("p.it", AttivaMtaSts.StatoNome.GIUSTO, "punta dritto", false, false, false),
                e("ok.it", AttivaMtaSts.StatoNome.GIUSTO, "punta dritto", true, false, false)));
        esigi("il cieco resta cieco", rip.ciechi.size() == 1);
        esigi("il giusto che non risolve ancora e' in propagazione", rip.inPropagazione.size() == 1);
        esigi("il giusto che risolve non compare da nessuna parte",
                rip.assenti.isEmpty() && rip.storti.isEmpty() && rip.proxati.isEmpty());

        System.out.println("\n== leggiTxt(): uscita VERA di dig, sui domini veri ==");
        Method leggi = AttivaMtaSts.class.getDeclaredMethod("leggiTxt", String.class);
        leggi.setAccessible(true);
        for (String d : new String[]{"domain-d.test", "domain-a.test", "domain-b.test",
                                     "nome-che-non-esiste-99887.invalid"}) {
            Object l = leggi.invoke(null, d);
            Field fe = l.getClass().getDeclaredField("esito"); fe.setAccessible(true);
            Field fc = l.getClass().getDeclaredField("contenuto"); fc.setAccessible(true);
            System.out.println("  " + d + " -> " + fe.get(l) + "  \"" + fc.get(l) + "\"");
            if (d.equals("domain-d.test")) {
                esigi("su domain-d.test il TXT viene VISTO (prima il piano non ci arrivava)",
                        fe.get(l).toString().equals("PRESENTE"));
                esigi("e se ne legge il contenuto",
                        fc.get(l).toString().startsWith("v=STSv1"));
            }
            if (d.endsWith(".invalid"))
                esigi("un nome inesistente e' ASSENTE, non NON_CHIESTO",
                        fe.get(l).toString().equals("ASSENTE"));
        }

        System.out.println("\n" + (falliti == 0 ? "TUTTO VERDE" : falliti + " CONTROLLI FALLITI"));
        if (falliti > 0) System.exit(1);
    }
}
