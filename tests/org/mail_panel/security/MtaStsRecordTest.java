package org.mail_panel.security;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Prova la scrittura del record _mta-sts su Cloudflare, AutoDns.alignMtaStsTxt(), con un
 * Cloudflare finto: la zona sta in memoria, e ogni operazione si puo' far rifiutare.
 *
 * La cosa da dimostrare: alla fine su quel nome resta UN record MTA-STS, con l'id giusto.
 * Con due record v=STSv1 i mittenti fanno come se MTA-STS non ci fosse (RFC 8461 §3.1), e
 * prima la scrittura guardava il primo record: se era gia' giusto rispondeva "invariato" e
 * lasciava l'altro. In fondo la prova rimette quella logica davanti allo stesso caso, per
 * dimostrare che i controlli lo vedono.
 */
public class MtaStsRecordTest {

    static int failed = 0;

    static void require(String what, boolean condition) {
        System.out.println((condition ? "  OK   " : "  FALLITO ") + what);
        if (!condition) failed++;
    }

    static final String NAME_PATTERN = "_mta-sts.domain-d.test";
    static final String RIGHT = "v=STSv1; id=0fec393151a7c577266a";
    static final String OLD = "v=STSv1; id=1700000000000";

    /** Una zona Cloudflare in memoria. Restituisce i TXT come fa l'API: con le virgolette. */
    static class FakeCloudflare extends CloudflareManager {
        final Map<String, TxtRecordInfo> zone = new LinkedHashMap<>();
        final List<String> operations = new ArrayList<>();
        String refuseDeletionOf = null;
        boolean refuseUpdate = false;
        boolean firstReadingEmpty = false;   // l'elenco che fallisce e torna vuoto senza dirlo
        int readings = 0, next = 1;

        FakeCloudflare() { super(null); }

        FakeCloudflare put(String name, String rawContent) {
            TxtRecordInfo t = new TxtRecordInfo();
            t.id = "r" + (next++); t.name = name; t.content = rawContent; t.ttl = 3600;
            zone.put(t.id, t);
            return this;
        }

        @Override
        public List<TxtRecordInfo> listTxtRecordsContaining(String token, String zoneId, String part) {
            readings++;
            List<TxtRecordInfo> outside = new ArrayList<>();
            if (firstReadingEmpty && readings == 1) return outside;
            for (TxtRecordInfo t : zone.values()) {
                if (part != null && !t.name.contains(part)) continue;
                TxtRecordInfo c = new TxtRecordInfo();
                c.id = t.id; c.name = t.name; c.content = t.content; c.ttl = t.ttl;
                outside.add(c);
            }
            return outside;
        }

        @Override
        public RecordOp deleteRecord(String token, String zoneId, String id) {
            operations.add("togli " + id);
            if (id.equals(refuseDeletionOf)) return new RecordOp(false, null, "permesso negato (finto)");
            if (zone.remove(id) == null) return new RecordOp(false, null, "record inesistente");
            return new RecordOp(true, id, null);
        }

        @Override
        public RecordOp updateTxtRecord(String token, String zoneId, String id, String name, String value, int ttl) {
            operations.add("aggiorna " + id);
            if (refuseUpdate) return new RecordOp(false, null, "permesso negato (finto)");
            TxtRecordInfo t = zone.get(id);
            if (t == null) return new RecordOp(false, null, "record inesistente");
            t.content = formatTxtRecordContent(value);
            return new RecordOp(true, id, null);
        }

        @Override
        public RecordOp createTxtRecord(String token, String zoneId, String name, String value, int ttl) {
            operations.add("crea");
            put(name, formatTxtRecordContent(value));
            return new RecordOp(true, "r" + (next - 1), null);
        }

        /** I contenuti MTA-STS rimasti su quel nome, gia' ripuliti dalle virgolette. */
        List<String> mtaSts() {
            List<String> c = new ArrayList<>();
            for (TxtRecordInfo t : zone.values())
                if (t.name.equals(NAME_PATTERN)) c.add(DnsRules.cloudflareContent(t.content));
            return DnsRules.soloMtaSts(c);
        }

        long otherTxt() {
            return zone.values().stream()
                    .filter(t -> !(t.name.equals(NAME_PATTERN) && DnsRules.eMtaSts(DnsRules.cloudflareContent(t.content))))
                    .count();
        }
    }

    static JSONObject write(FakeCloudflare cf) {
        return new AutoDns(null, cf).alignMtaStsTxt("token", "zona", NAME_PATTERN, RIGHT, new JSONObject());
    }

    static String removed(JSONObject r) {
        JSONArray a = r.optJSONArray("tolti");
        return a == null ? "[]" : a.toString();
    }

    public static void main(String[] a) {

        System.out.println("\n== la regola: cosa conta come record MTA-STS ==");
        require("\"v=STSv1; id=1\" conta", DnsRules.eMtaSts("v=STSv1; id=1"));
        require("\"V=STSV1; id=1\" conta (mailauth ignora le maiuscole)", DnsRules.eMtaSts("V=STSV1; id=1"));
        require("\" v=STSv1; id=1\" conta (mailauth toglie gli spazi ai bordi)", DnsRules.eMtaSts(" v=STSv1; id=1"));
        require("un SPF non conta", !DnsRules.eMtaSts("v=spf1 -all"));
        require("una verifica di Google non conta", !DnsRules.eMtaSts("google-site-verification=abc"));
        require("null non conta", !DnsRules.eMtaSts(null));

        System.out.println("\n== nessun record: si crea ==");
        FakeCloudflare cf = new FakeCloudflare();
        JSONObject r = write(cf);
        require("riuscito: " + r.optString("nota", r.optString("error")), r.optBoolean("success"));
        require("sul nome c'e' un record, quello giusto: " + cf.mtaSts(), cf.mtaSts().equals(List.of(RIGHT)));

        System.out.println("\n== un record giusto: non si tocca niente ==");
        cf = new FakeCloudflare().put(NAME_PATTERN, "\"" + RIGHT + "\"");
        r = write(cf);
        require("invariato", r.optBoolean("success") && r.optBoolean("invariato"));
        require("nessuna operazione su Cloudflare: " + cf.operations, cf.operations.isEmpty());

        System.out.println("\n== un record con l'id vecchio: si aggiorna ==");
        cf = new FakeCloudflare().put(NAME_PATTERN, OLD);   // senza virgolette, come a volte lo da' Cloudflare
        r = write(cf);
        require("riuscito e aggiornato", r.optBoolean("success") && r.optBoolean("aggiornato"));
        require("resta un record, quello giusto: " + cf.mtaSts(), cf.mtaSts().equals(List.of(RIGHT)));

        System.out.println("\n== due record, il primo gia' giusto (il caso che prima diceva \"invariato\") ==");
        cf = new FakeCloudflare().put(NAME_PATTERN, "\"" + RIGHT + "\"").put(NAME_PATTERN, "\"" + OLD + "\"");
        r = write(cf);
        require("riuscito: " + r.optString("nota", r.optString("error")), r.optBoolean("success"));
        require("NON dice invariato", !r.optBoolean("invariato"));
        require("resta un record solo, quello giusto: " + cf.mtaSts(), cf.mtaSts().equals(List.of(RIGHT)));
        require("toglie solo il vecchio, senza aggiornare niente: " + cf.operations,
                cf.operations.equals(List.of("togli r2")));
        require("e lo dice nella risposta: " + removed(r), removed(r).contains(OLD));

        System.out.println("\n== due record, il giusto e' il secondo ==");
        cf = new FakeCloudflare().put(NAME_PATTERN, "\"" + OLD + "\"").put(NAME_PATTERN, "\"" + RIGHT + "\"");
        r = write(cf);
        require("tiene il giusto e toglie l'altro: " + cf.operations,
                r.optBoolean("success") && cf.operations.equals(List.of("togli r1")));
        require("resta un record solo: " + cf.mtaSts(), cf.mtaSts().equals(List.of(RIGHT)));

        System.out.println("\n== due record, nessuno giusto ==");
        cf = new FakeCloudflare().put(NAME_PATTERN, "\"" + OLD + "\"").put(NAME_PATTERN, "\"v=STSv1; id=2\"");
        r = write(cf);
        require("prima toglie l'altro, poi aggiorna quello che resta: " + cf.operations,
                cf.operations.equals(List.of("togli r2", "aggiorna r1")));
        require("riuscito, con un record solo e giusto: " + cf.mtaSts(),
                r.optBoolean("success") && cf.mtaSts().equals(List.of(RIGHT)));

        System.out.println("\n== tre record, uno scritto in maiuscolo, e TXT che non c'entrano ==");
        cf = new FakeCloudflare().put(NAME_PATTERN, "\"" + OLD + "\"").put(NAME_PATTERN, "\"V=STSV1; id=9\"")
                .put(NAME_PATTERN, "\"google-site-verification=abc\"").put(NAME_PATTERN, "\"" + RIGHT + "\"")
                .put("domain-d.test", "\"v=spf1 mx -all\"").put("_mta-sts.altro.it", "\"" + OLD + "\"");
        r = write(cf);
        require("riuscito, con un record solo e giusto: " + cf.mtaSts(),
                r.optBoolean("success") && cf.mtaSts().equals(List.of(RIGHT)));
        require("toglie anche quello in maiuscolo, che per mailauth conta: " + removed(r),
                removed(r).contains("V=STSV1; id=9"));
        require("non tocca la verifica di Google, l'SPF e l'altro dominio (" + cf.otherTxt() + " restano)",
                cf.otherTxt() == 3);

        System.out.println("\n== Cloudflare rifiuta di togliere il record in piu' ==");
        cf = new FakeCloudflare().put(NAME_PATTERN, "\"" + RIGHT + "\"").put(NAME_PATTERN, "\"" + OLD + "\"");
        cf.refuseDeletionOf = "r2";
        r = write(cf);
        require("NON riuscito", !r.optBoolean("success"));
        require("l'errore dice quale record e perche' conta: " + r.optString("error"),
                r.optString("error").contains(OLD) && r.optString("error").contains("RFC 8461"));

        System.out.println("\n== Cloudflare rifiuta l'aggiornamento, dopo aver tolto l'altro ==");
        cf = new FakeCloudflare().put(NAME_PATTERN, "\"" + OLD + "\"").put(NAME_PATTERN, "\"v=STSv1; id=2\"");
        cf.refuseUpdate = true;
        r = write(cf);
        require("NON riuscito", !r.optBoolean("success"));
        require("e lo dice, insieme a cio' che ha tolto: " + r.optString("error"),
                r.optString("error").contains("rifiutato l'aggiornamento") && r.optString("error").contains("id=2"));
        require("resta un record solo (con l'id vecchio, ma i mittenti lo leggono): " + cf.mtaSts(),
                cf.mtaSts().equals(List.of(OLD)));

        System.out.println("\n== la prima lettura torna vuota per un errore, e c'era gia' un record ==");
        cf = new FakeCloudflare().put(NAME_PATTERN, "\"" + OLD + "\"");
        cf.firstReadingEmpty = true;
        r = write(cf);
        require("si accorge che ora i record sono due: " + r.optString("error"),
                !r.optBoolean("success") && r.optString("error").contains("2 record"));

        System.out.println("\n== la riga MTA-STS della pagina DNS ==");
        // Letture costruite da uscite di dig nella forma vera, e una politica finta che
        // risponde o no: niente DNS, niente rete.
        String head = ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 32535\n;; ANSWER SECTION:\n";
        String rightLine = NAME_PATTERN + ".\t3498\tIN\tTXT\t\"" + RIGHT + "\"\n";
        String oldLine = NAME_PATTERN + ".\t3498\tIN\tTXT\t\"" + OLD + "\"\n";
        java.util.function.Function<String, JSONObject> answers = d -> new JSONObject().put("ok", true);
        java.util.function.Function<String, JSONObject> silent =
                d -> new JSONObject().put("ok", false).put("errore", "526 (finto).");
        DnsRecordsGenerator.DnsCheck c = DnsRecordsGenerator.mtaStsCheck("domain-d.test",
                org.mail_panel.system.MtaStsSetup.parseTxt(0, head + rightLine), answers);
        require("un record e la politica che risponde: verde (" + c.message + ")", c.passed);
        c = DnsRecordsGenerator.mtaStsCheck("domain-d.test",
                org.mail_panel.system.MtaStsSetup.parseTxt(0, head + rightLine + oldLine), answers);
        require("due record, anche con la politica che risponde: NON verde", !c.passed);
        require("il messaggio dice perche': " + c.message, c.message.contains("RFC 8461") && c.message.contains("2 record"));
        require("e mostra tutti e due i record: " + c.currentValue,
                c.currentValue.contains(RIGHT) && c.currentValue.contains(OLD));
        require("non e' grigio (informativo): e' un guasto", !c.informational);
        c = DnsRecordsGenerator.mtaStsCheck("domain-d.test",
                org.mail_panel.system.MtaStsSetup.parseTxt(0, head + rightLine), silent);
        require("un record e la politica che non risponde: rosso (" + c.message.substring(0, 40) + "...)", !c.passed);
        c = DnsRecordsGenerator.mtaStsCheck("domain-d.test",
                org.mail_panel.system.MtaStsSetup.parseTxt(0,
                        ";; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 37005\n"), answers);
        require("un SERVFAIL: non \"Non attivo\", ma il motivo vero (" + c.message + ")",
                !c.passed && !c.informational && c.message.contains("SERVFAIL"));
        c = DnsRecordsGenerator.mtaStsCheck("domain-d.test",
                org.mail_panel.system.MtaStsSetup.parseTxt(0,
                        ";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 2902\n"), answers);
        require("nessun record: grigio, \"Non attivo\"", !c.passed && c.informational && c.message.startsWith("Non attivo"));

        System.out.println("\n== la scrittura di prima, davanti al caso dei due record ==");
        cf = new FakeCloudflare().put(NAME_PATTERN, "\"" + RIGHT + "\"").put(NAME_PATTERN, "\"" + OLD + "\"");
        String before = howItWroteBefore(cf);
        System.out.println("  diceva: " + before + "; sul nome restavano " + cf.mtaSts().size() + " record");
        require("prima diceva \"invariato\" e lasciava due record: i controlli qui sopra lo vedono",
                before.equals("invariato") && cf.mtaSts().size() == 2);

        System.out.println("\n" + (failed == 0 ? "TUTTO VERDE" : failed + " CONTROLLI FALLITI"));
        if (failed > 0) System.exit(1);
    }

    /** Il ciclo di AutoDns.creaTxtMtaSts com'era prima, ridotto all'esito. */
    static String howItWroteBefore(FakeCloudflare cf) {
        for (CloudflareManager.TxtRecordInfo t : cf.listTxtRecordsContaining("token", "zona", null)) {
            if (!t.name.equals(NAME_PATTERN)) continue;
            String c = DnsRules.cloudflareContent(t.content);
            if (!c.toLowerCase(java.util.Locale.ROOT).startsWith("v=stsv1")) continue;
            if (c.trim().equals(RIGHT.trim())) return "invariato";
            cf.updateTxtRecord("token", "zona", t.id, NAME_PATTERN, RIGHT, 3600);
            return "aggiornato";
        }
        cf.createTxtRecord("token", "zona", NAME_PATTERN, RIGHT, 3600);
        return "creato";
    }
}
