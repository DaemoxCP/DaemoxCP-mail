package org.mail_panel.security;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Prova la scrittura del record _mta-sts su Cloudflare, AutoDns.allineaTxtMtaSts(), con un
 * Cloudflare finto: la zona sta in memoria, e ogni operazione si puo' far rifiutare.
 *
 * La cosa da dimostrare: alla fine su quel nome resta UN record MTA-STS, con l'id giusto.
 * Con due record v=STSv1 i mittenti fanno come se MTA-STS non ci fosse (RFC 8461 §3.1), e
 * prima la scrittura guardava il primo record: se era gia' giusto rispondeva "invariato" e
 * lasciava l'altro. In fondo la prova rimette quella logica davanti allo stesso caso, per
 * dimostrare che i controlli lo vedono.
 */
public class ProvaRecordMtaSts {

    static int falliti = 0;

    static void esigi(String cosa, boolean condizione) {
        System.out.println((condizione ? "  OK   " : "  FALLITO ") + cosa);
        if (!condizione) falliti++;
    }

    static final String NOME = "_mta-sts.domain-d.test";
    static final String GIUSTO = "v=STSv1; id=0fec393151a7c577266a";
    static final String VECCHIO = "v=STSv1; id=1700000000000";

    /** Una zona Cloudflare in memoria. Restituisce i TXT come fa l'API: con le virgolette. */
    static class Finto extends CloudflareManager {
        final Map<String, TxtRecordInfo> zona = new LinkedHashMap<>();
        final List<String> operazioni = new ArrayList<>();
        String rifiutaCancellazioneDi = null;
        boolean rifiutaAggiornamento = false;
        boolean primaLetturaVuota = false;   // l'elenco che fallisce e torna vuoto senza dirlo
        int letture = 0, prossimo = 1;

        Finto() { super(null); }

        Finto metti(String nome, String contenutoGrezzo) {
            TxtRecordInfo t = new TxtRecordInfo();
            t.id = "r" + (prossimo++); t.name = nome; t.content = contenutoGrezzo; t.ttl = 3600;
            zona.put(t.id, t);
            return this;
        }

        @Override
        public List<TxtRecordInfo> listTxtRecordsContaining(String token, String zoneId, String parte) {
            letture++;
            List<TxtRecordInfo> fuori = new ArrayList<>();
            if (primaLetturaVuota && letture == 1) return fuori;
            for (TxtRecordInfo t : zona.values()) {
                if (parte != null && !t.name.contains(parte)) continue;
                TxtRecordInfo c = new TxtRecordInfo();
                c.id = t.id; c.name = t.name; c.content = t.content; c.ttl = t.ttl;
                fuori.add(c);
            }
            return fuori;
        }

        @Override
        public RecordOp deleteRecord(String token, String zoneId, String id) {
            operazioni.add("togli " + id);
            if (id.equals(rifiutaCancellazioneDi)) return new RecordOp(false, null, "permesso negato (finto)");
            if (zona.remove(id) == null) return new RecordOp(false, null, "record inesistente");
            return new RecordOp(true, id, null);
        }

        @Override
        public RecordOp updateTxtRecord(String token, String zoneId, String id, String nome, String valore, int ttl) {
            operazioni.add("aggiorna " + id);
            if (rifiutaAggiornamento) return new RecordOp(false, null, "permesso negato (finto)");
            TxtRecordInfo t = zona.get(id);
            if (t == null) return new RecordOp(false, null, "record inesistente");
            t.content = formatTxtRecordContent(valore);
            return new RecordOp(true, id, null);
        }

        @Override
        public RecordOp createTxtRecord(String token, String zoneId, String nome, String valore, int ttl) {
            operazioni.add("crea");
            metti(nome, formatTxtRecordContent(valore));
            return new RecordOp(true, "r" + (prossimo - 1), null);
        }

        /** I contenuti MTA-STS rimasti su quel nome, gia' ripuliti dalle virgolette. */
        List<String> mtaSts() {
            List<String> c = new ArrayList<>();
            for (TxtRecordInfo t : zona.values())
                if (t.name.equals(NOME)) c.add(RegoleDns.contenutoCloudflare(t.content));
            return RegoleDns.soloMtaSts(c);
        }

        long altriTxt() {
            return zona.values().stream()
                    .filter(t -> !(t.name.equals(NOME) && RegoleDns.eMtaSts(RegoleDns.contenutoCloudflare(t.content))))
                    .count();
        }
    }

    static JSONObject scrivi(Finto cf) {
        return new AutoDns(null, cf).allineaTxtMtaSts("token", "zona", NOME, GIUSTO, new JSONObject());
    }

    static String tolti(JSONObject r) {
        JSONArray a = r.optJSONArray("tolti");
        return a == null ? "[]" : a.toString();
    }

    public static void main(String[] a) {

        System.out.println("\n== la regola: cosa conta come record MTA-STS ==");
        esigi("\"v=STSv1; id=1\" conta", RegoleDns.eMtaSts("v=STSv1; id=1"));
        esigi("\"V=STSV1; id=1\" conta (mailauth ignora le maiuscole)", RegoleDns.eMtaSts("V=STSV1; id=1"));
        esigi("\" v=STSv1; id=1\" conta (mailauth toglie gli spazi ai bordi)", RegoleDns.eMtaSts(" v=STSv1; id=1"));
        esigi("un SPF non conta", !RegoleDns.eMtaSts("v=spf1 -all"));
        esigi("una verifica di Google non conta", !RegoleDns.eMtaSts("google-site-verification=abc"));
        esigi("null non conta", !RegoleDns.eMtaSts(null));

        System.out.println("\n== nessun record: si crea ==");
        Finto cf = new Finto();
        JSONObject r = scrivi(cf);
        esigi("riuscito: " + r.optString("nota", r.optString("error")), r.optBoolean("success"));
        esigi("sul nome c'e' un record, quello giusto: " + cf.mtaSts(), cf.mtaSts().equals(List.of(GIUSTO)));

        System.out.println("\n== un record giusto: non si tocca niente ==");
        cf = new Finto().metti(NOME, "\"" + GIUSTO + "\"");
        r = scrivi(cf);
        esigi("invariato", r.optBoolean("success") && r.optBoolean("invariato"));
        esigi("nessuna operazione su Cloudflare: " + cf.operazioni, cf.operazioni.isEmpty());

        System.out.println("\n== un record con l'id vecchio: si aggiorna ==");
        cf = new Finto().metti(NOME, VECCHIO);   // senza virgolette, come a volte lo da' Cloudflare
        r = scrivi(cf);
        esigi("riuscito e aggiornato", r.optBoolean("success") && r.optBoolean("aggiornato"));
        esigi("resta un record, quello giusto: " + cf.mtaSts(), cf.mtaSts().equals(List.of(GIUSTO)));

        System.out.println("\n== due record, il primo gia' giusto (il caso che prima diceva \"invariato\") ==");
        cf = new Finto().metti(NOME, "\"" + GIUSTO + "\"").metti(NOME, "\"" + VECCHIO + "\"");
        r = scrivi(cf);
        esigi("riuscito: " + r.optString("nota", r.optString("error")), r.optBoolean("success"));
        esigi("NON dice invariato", !r.optBoolean("invariato"));
        esigi("resta un record solo, quello giusto: " + cf.mtaSts(), cf.mtaSts().equals(List.of(GIUSTO)));
        esigi("toglie solo il vecchio, senza aggiornare niente: " + cf.operazioni,
                cf.operazioni.equals(List.of("togli r2")));
        esigi("e lo dice nella risposta: " + tolti(r), tolti(r).contains(VECCHIO));

        System.out.println("\n== due record, il giusto e' il secondo ==");
        cf = new Finto().metti(NOME, "\"" + VECCHIO + "\"").metti(NOME, "\"" + GIUSTO + "\"");
        r = scrivi(cf);
        esigi("tiene il giusto e toglie l'altro: " + cf.operazioni,
                r.optBoolean("success") && cf.operazioni.equals(List.of("togli r1")));
        esigi("resta un record solo: " + cf.mtaSts(), cf.mtaSts().equals(List.of(GIUSTO)));

        System.out.println("\n== due record, nessuno giusto ==");
        cf = new Finto().metti(NOME, "\"" + VECCHIO + "\"").metti(NOME, "\"v=STSv1; id=2\"");
        r = scrivi(cf);
        esigi("prima toglie l'altro, poi aggiorna quello che resta: " + cf.operazioni,
                cf.operazioni.equals(List.of("togli r2", "aggiorna r1")));
        esigi("riuscito, con un record solo e giusto: " + cf.mtaSts(),
                r.optBoolean("success") && cf.mtaSts().equals(List.of(GIUSTO)));

        System.out.println("\n== tre record, uno scritto in maiuscolo, e TXT che non c'entrano ==");
        cf = new Finto().metti(NOME, "\"" + VECCHIO + "\"").metti(NOME, "\"V=STSV1; id=9\"")
                .metti(NOME, "\"google-site-verification=abc\"").metti(NOME, "\"" + GIUSTO + "\"")
                .metti("domain-d.test", "\"v=spf1 mx -all\"").metti("_mta-sts.altro.it", "\"" + VECCHIO + "\"");
        r = scrivi(cf);
        esigi("riuscito, con un record solo e giusto: " + cf.mtaSts(),
                r.optBoolean("success") && cf.mtaSts().equals(List.of(GIUSTO)));
        esigi("toglie anche quello in maiuscolo, che per mailauth conta: " + tolti(r),
                tolti(r).contains("V=STSV1; id=9"));
        esigi("non tocca la verifica di Google, l'SPF e l'altro dominio (" + cf.altriTxt() + " restano)",
                cf.altriTxt() == 3);

        System.out.println("\n== Cloudflare rifiuta di togliere il record in piu' ==");
        cf = new Finto().metti(NOME, "\"" + GIUSTO + "\"").metti(NOME, "\"" + VECCHIO + "\"");
        cf.rifiutaCancellazioneDi = "r2";
        r = scrivi(cf);
        esigi("NON riuscito", !r.optBoolean("success"));
        esigi("l'errore dice quale record e perche' conta: " + r.optString("error"),
                r.optString("error").contains(VECCHIO) && r.optString("error").contains("RFC 8461"));

        System.out.println("\n== Cloudflare rifiuta l'aggiornamento, dopo aver tolto l'altro ==");
        cf = new Finto().metti(NOME, "\"" + VECCHIO + "\"").metti(NOME, "\"v=STSv1; id=2\"");
        cf.rifiutaAggiornamento = true;
        r = scrivi(cf);
        esigi("NON riuscito", !r.optBoolean("success"));
        esigi("e lo dice, insieme a cio' che ha tolto: " + r.optString("error"),
                r.optString("error").contains("rifiutato l'aggiornamento") && r.optString("error").contains("id=2"));
        esigi("resta un record solo (con l'id vecchio, ma i mittenti lo leggono): " + cf.mtaSts(),
                cf.mtaSts().equals(List.of(VECCHIO)));

        System.out.println("\n== la prima lettura torna vuota per un errore, e c'era gia' un record ==");
        cf = new Finto().metti(NOME, "\"" + VECCHIO + "\"");
        cf.primaLetturaVuota = true;
        r = scrivi(cf);
        esigi("si accorge che ora i record sono due: " + r.optString("error"),
                !r.optBoolean("success") && r.optString("error").contains("2 record"));

        System.out.println("\n== la riga MTA-STS della pagina DNS ==");
        // Letture costruite da uscite di dig nella forma vera, e una politica finta che
        // risponde o no: niente DNS, niente rete.
        String testa = ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 32535\n;; ANSWER SECTION:\n";
        String rigaGiusta = NOME + ".\t3498\tIN\tTXT\t\"" + GIUSTO + "\"\n";
        String rigaVecchia = NOME + ".\t3498\tIN\tTXT\t\"" + VECCHIO + "\"\n";
        java.util.function.Function<String, JSONObject> risponde = d -> new JSONObject().put("ok", true);
        java.util.function.Function<String, JSONObject> tace =
                d -> new JSONObject().put("ok", false).put("errore", "526 (finto).");
        DnsRecordsGenerator.DnsCheck c = DnsRecordsGenerator.controlloMtaSts("domain-d.test",
                org.mail_panel.system.AttivaMtaSts.interpretaTxt(0, testa + rigaGiusta), risponde);
        esigi("un record e la politica che risponde: verde (" + c.message + ")", c.passed);
        c = DnsRecordsGenerator.controlloMtaSts("domain-d.test",
                org.mail_panel.system.AttivaMtaSts.interpretaTxt(0, testa + rigaGiusta + rigaVecchia), risponde);
        esigi("due record, anche con la politica che risponde: NON verde", !c.passed);
        esigi("il messaggio dice perche': " + c.message, c.message.contains("RFC 8461") && c.message.contains("2 record"));
        esigi("e mostra tutti e due i record: " + c.currentValue,
                c.currentValue.contains(GIUSTO) && c.currentValue.contains(VECCHIO));
        esigi("non e' grigio (informativo): e' un guasto", !c.informativo);
        c = DnsRecordsGenerator.controlloMtaSts("domain-d.test",
                org.mail_panel.system.AttivaMtaSts.interpretaTxt(0, testa + rigaGiusta), tace);
        esigi("un record e la politica che non risponde: rosso (" + c.message.substring(0, 40) + "...)", !c.passed);
        c = DnsRecordsGenerator.controlloMtaSts("domain-d.test",
                org.mail_panel.system.AttivaMtaSts.interpretaTxt(0,
                        ";; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 37005\n"), risponde);
        esigi("un SERVFAIL: non \"Non attivo\", ma il motivo vero (" + c.message + ")",
                !c.passed && !c.informativo && c.message.contains("SERVFAIL"));
        c = DnsRecordsGenerator.controlloMtaSts("domain-d.test",
                org.mail_panel.system.AttivaMtaSts.interpretaTxt(0,
                        ";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 2902\n"), risponde);
        esigi("nessun record: grigio, \"Non attivo\"", !c.passed && c.informativo && c.message.startsWith("Non attivo"));

        System.out.println("\n== la scrittura di prima, davanti al caso dei due record ==");
        cf = new Finto().metti(NOME, "\"" + GIUSTO + "\"").metti(NOME, "\"" + VECCHIO + "\"");
        String prima = comeScrivevaPrima(cf);
        System.out.println("  diceva: " + prima + "; sul nome restavano " + cf.mtaSts().size() + " record");
        esigi("prima diceva \"invariato\" e lasciava due record: i controlli qui sopra lo vedono",
                prima.equals("invariato") && cf.mtaSts().size() == 2);

        System.out.println("\n" + (falliti == 0 ? "TUTTO VERDE" : falliti + " CONTROLLI FALLITI"));
        if (falliti > 0) System.exit(1);
    }

    /** Il ciclo di AutoDns.creaTxtMtaSts com'era prima, ridotto all'esito. */
    static String comeScrivevaPrima(Finto cf) {
        for (CloudflareManager.TxtRecordInfo t : cf.listTxtRecordsContaining("token", "zona", null)) {
            if (!t.name.equals(NOME)) continue;
            String c = RegoleDns.contenutoCloudflare(t.content);
            if (!c.toLowerCase(java.util.Locale.ROOT).startsWith("v=stsv1")) continue;
            if (c.trim().equals(GIUSTO.trim())) return "invariato";
            cf.updateTxtRecord("token", "zona", t.id, NOME, GIUSTO, 3600);
            return "aggiornato";
        }
        cf.createTxtRecord("token", "zona", NOME, GIUSTO, 3600);
        return "creato";
    }
}
