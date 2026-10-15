package org.mail_panel.system;

import org.json.JSONArray;
import org.mail_panel.i18n.I18n;
import org.json.JSONObject;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Guarda da solo se e' cambiato qualcosa sotto i piedi del pannello.
 *
 * Il problema che risolve: le regole su cui il pannello e' costruito cambiano, e finora ce
 * ne accorgevamo per caso, mentre stavamo facendo altro. Il 01/09/2026 e' successo con DMARC:
 * il pannello era scritto su RFC 7489, che a maggio 2026 era gia' stato sostituito da tre
 * documenti nuovi — e nessuno lo aveva detto.
 *
 * Quella scoperta pero' si poteva automatizzare, perche' il RFC Editor pubblica lo stato di
 * ogni documento in forma leggibile da un programma:
 *   https://www.rfc-editor.org/rfc/rfcNNNN.json  ->  { "obsoleted_by": [...], "updated_by": [...] }
 * Sono 1,3 KB a richiesta. Interrogarli una volta al giorno costa nulla e trasforma una
 * scoperta fortuita in un avviso.
 *
 * Cosa NON fa, per non promettere piu' di quello che mantiene: non legge i documenti nuovi e
 * non dice cosa e' cambiato. Dice che sono usciti e su quale parte del pannello incidono.
 * Leggerli resta un lavoro da fare a mano, ma almeno si sa che va fatto.
 */
public class StandardsWatch {

    /**
     * Le regole su cui il pannello e' costruito, con cio' che gia' sappiamo di loro.
     *
     * Le ultime due colonne sono la fotografia presa il 01/09/2026 leggendo le fonti: servono
     * a distinguere "sostituito" da "sostituito da qualcosa che sapevamo gia'". Senza,
     * il pannello segnalerebbe ogni giorno le stesse cose e si imparerebbe a ignorarlo.
     *
     * numero | cosa governa nel pannello | sostituito-da noti | aggiornato-da noti
     */
    private static final String[][] STANDARD = {
        { "7208", "server.watch.std.7208",                 "",                  "7372,8553,8616" },
        { "6376", "server.watch.std.6376",                "",                  "8301,8463,8553,8616" },
        { "8301", "server.watch.std.8301",      "",                  "" },
        { "9989", "server.watch.std.9989",                "",                  "" },
        { "9990", "server.watch.std.9990",       "",                  "" },
        { "9991", "server.watch.std.9991",                      "",                  "" },
        // Questi tre aggiornamenti li ha trovati la sorveglianza stessa alla prima esecuzione,
        // il 01/09/2026. Sono segnati come noti solo DOPO averli letti e verificati:
        //  - RFC 8553 sposta i nomi con underscore in un registro: non cambia nulla per noi.
        //  - RFC 8314 e' la specifica della 465, che avevamo gia' letto.
        //  - RFC 8997 deprecia TLS 1.0 e 1.1 per posta in invio e in lettura. Verificato:
        //    Dovecot ha ssl_min_protocol = TLSv1.2 e Postfix esclude !TLSv1, !TLSv1.1.
        //    Gia' conforme, niente da fare — ma lo sappiamo perche' l'abbiamo guardato.
        { "6186", "server.watch.std.6186", "",                  "8314,8553" },
        { "6409", "server.watch.std.6409", "",               "8314" },
        { "8314", "server.watch.std.8314",                        "",                  "8997" },
        { "8461", "server.watch.std.8461",     "",                  "" },
    };

    private StandardsWatch() {}

    /* ===================================================================
     * Parte pura: si prova senza rete
     * =================================================================== */

    /** Cio' che c'e' adesso e che non sapevamo. Ordine conservato, nessun doppione. */
    public static List<String> novita(String notiSeparatiDaVirgole, List<String> attuali) {
        Set<String> noti = new LinkedHashSet<>();
        if (notiSeparatiDaVirgole != null)
            for (String n : notiSeparatiDaVirgole.split(","))
                if (!n.trim().isEmpty()) noti.add(normalizza(n));
        List<String> fuori = new ArrayList<>();
        if (attuali == null) return fuori;
        for (String a : attuali) {
            String x = normalizza(a);
            if (x.isEmpty() || noti.contains(x)) continue;
            if (!fuori.contains(x)) fuori.add(x);
        }
        return fuori;
    }

    /** "RFC9989", "rfc 9989", " 9989 " diventano tutti "9989". */
    public static String normalizza(String rfc) {
        if (rfc == null) return "";
        String s = rfc.trim().toUpperCase(java.util.Locale.ROOT).replace(" ", "");
        if (s.startsWith("RFC")) s = s.substring(3);
        return s.trim();
    }

    /* ===================================================================
     * Parte che interroga il RFC Editor
     * =================================================================== */

    public static JSONObject controlla() {
        JSONObject r = new JSONObject().put("success", true);
        JSONArray righe = new JSONArray();
        int sostituiti = 0, aggiornati = 0, nonLetti = 0;

        HttpClient http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(8))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();

        for (String[] s : STANDARD) {
            JSONObject o = new JSONObject().put("rfc", s[0]).put("governa", I18n.tr(s[1]));
            try {
                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create("https://www.rfc-editor.org/rfc/rfc" + s[0] + ".json"))
                        .timeout(Duration.ofSeconds(12))
                        .header("Accept", "application/json")
                        .GET().build();
                HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
                if (resp.statusCode() != 200) {
                    o.put("letto", false).put("problema", I18n.tr("server.watch.editorStatus", java.util.Map.of("c", String.valueOf(resp.statusCode()))));
                    nonLetti++; righe.put(o); continue;
                }
                JSONObject j = new JSONObject(resp.body());
                o.put("letto", true).put("titolo", j.optString("title", ""))
                 .put("stato", j.optString("status", ""));

                List<String> obs = lista(j.optJSONArray("obsoleted_by"));
                List<String> upd = lista(j.optJSONArray("updated_by"));
                List<String> nuoviObs = novita(s[2], obs);
                List<String> nuoviUpd = novita(s[3], upd);

                o.put("sostituitoDa", new JSONArray(nuoviObs));
                o.put("aggiornatoDa", new JSONArray(nuoviUpd));
                if (!nuoviObs.isEmpty()) {
                    sostituiti++;
                    o.put("gravita", 2).put("commento", I18n.tr("server.watch.obsoleted", java.util.Map.of("n", String.valueOf(s[0]), "by", String.valueOf(descrivi(nuoviObs)), "topic", String.valueOf(I18n.tr(s[1])))));
                } else if (!nuoviUpd.isEmpty()) {
                    aggiornati++;
                    o.put("gravita", 1).put("commento", I18n.tr("server.watch.updated", java.util.Map.of("n", String.valueOf(s[0]), "by", String.valueOf(descrivi(nuoviUpd)), "topic", String.valueOf(I18n.tr(s[1])))));
                } else {
                    o.put("gravita", 0).put("commento", I18n.tr("server.watch.nothingNew"));
                }
            } catch (Exception e) {
                // Un controllo che non e' riuscito non e' un "tutto a posto".
                o.put("letto", false).put("gravita", 3)
                 .put("problema", I18n.tr("server.watch.editorFailed", java.util.Map.of("err", String.valueOf(e.getClass().getSimpleName()))));
                nonLetti++;
            }
            righe.put(o);
        }

        r.put("standard", righe).put("sostituiti", sostituiti)
         .put("aggiornati", aggiornati).put("nonLetti", nonLetti);
        r.put("fonte", "https://www.rfc-editor.org/rfc/rfcNNNN.json");
        r.put("nota", sostituiti > 0
                ? (sostituiti == 1 ? I18n.tr("server.watch.sumObsoleted.one")
                                   : I18n.tr("server.watch.sumObsoleted.other", java.util.Map.of("n", String.valueOf(sostituiti))))
                : aggiornati > 0
                ? I18n.tr("server.watch.sumUpdated", java.util.Map.of("n", String.valueOf(aggiornati)))
                : nonLetti > 0
                ? I18n.tr("server.watch.sumUnread", java.util.Map.of("n", String.valueOf(nonLetti)))
                : I18n.tr("server.watch.sumAllCurrent"));
        return r;
    }

    private static List<String> lista(JSONArray a) {
        List<String> l = new ArrayList<>();
        if (a == null) return l;
        for (int i = 0; i < a.length(); i++) l.add(a.optString(i, ""));
        return l;
    }

    private static String descrivi(List<String> rfc) {
        List<String> con = new ArrayList<>();
        for (String x : rfc) con.add("RFC " + x);
        return String.join(", ", con);
    }

    /** Le voci da mettere nel rapporto periodico: solo cio' che merita di essere letto. */
    public static List<String> perIlRapporto(JSONObject controllo) {
        List<String> fuori = new ArrayList<>();
        if (controllo == null || !controllo.optBoolean("success", false)) return fuori;
        JSONArray a = controllo.optJSONArray("standard");
        if (a == null) return fuori;
        for (int i = 0; i < a.length(); i++) {
            JSONObject o = a.getJSONObject(i);
            int g = o.optInt("gravita", 0);
            if (g == 1 || g == 2) fuori.add(o.optString("commento"));
        }
        return fuori;
    }

    /* ===================================================================
     * Cosa e' cambiato: estrazione dal testo del documento
     * =================================================================== */

    /**
     * Ripulisce il testo di un RFC dagli orpelli dell'impaginazione: salti pagina,
     * "[Page 42]" e le intestazioni ripetute in cima a ogni pagina. Senza, l'elenco dei
     * cambiamenti esce spezzato da righe che non c'entrano.
     */
    public static String ripulisci(String testo) {
        if (testo == null) return "";
        StringBuilder sb = new StringBuilder();
        for (String r : testo.split("\n")) {
            String t = r.replace("\f", "");
            if (t.matches("^.*\\[Page \\d+\\]\\s*$")) continue;
            if (t.matches("^RFC \\d+\\s+.*\\s+[A-Z][a-z]+ \\d{4}\\s*$")) continue;
            sb.append(t).append("\n");
        }
        return sb.toString();
    }

    /** Sembra l'inizio di una nuova sezione di primo livello. */
    private static boolean nuovaSezione(String riga) {
        return riga.matches("^(?:Appendix\\s+[A-Z]|[0-9]+)\\.\\s+\\S.*")
            || riga.matches("^(?:Acknowledge?ments|Authors?'? Addresses?|Contributors|"
                          + "Normative References|Informative References|References|Index)\\s*$");
    }

    /**
     * L'appendice in cui gli autori elencano cosa e' cambiato rispetto al documento
     * precedente. Non e' un'invenzione: molti RFC di revisione la contengono, scritta da chi
     * ha fatto le modifiche. RFC 9989 ha "Appendix C. Changes from RFC 7489", RFC 6376 ha
     * "Appendix E. Changes since RFC 4871".
     *
     * Si prende l'ULTIMA occorrenza dell'intestazione: la prima e' quella dell'indice.
     */
    public static String elencoCambiamenti(String testoRfc) {
        String t = ripulisci(testoRfc);
        String[] righe = t.split("\n");
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(
                "^\\s*(?:Appendix\\s+)?[A-Z0-9]{1,4}(?:\\.[0-9]+)*\\.?\\s+"
              // Fra "Changes" e "from/since" ci possono stare altre parole: RFC 7208 intitola
              // "Changes in Implementation Requirements from RFC 4408". Ma "from" o "since"
              // devono esserci: senza il vincolo, "Changes in Policy During a Reporting
              // Period" (RFC 9990 §3.3) verrebbe scambiata per un elenco di cambiamenti.
              + "(?:(?:Summary of\\s+)?Changes?\\b[^.]{0,60}?\\b(?:from|since)\\b.*|Change\\s+Log\\b.*)$",
                java.util.regex.Pattern.CASE_INSENSITIVE);
        int inizio = -1;
        for (int i = 0; i < righe.length; i++) {
            String r = righe[i];
            if (!p.matcher(r).matches()) continue;
            // Le righe dell'indice finiscono con puntini e un numero di pagina.
            if (r.matches("^.*\\.\\s*\\.\\s*\\..*\\d+\\s*$")) continue;
            inizio = i;
        }
        if (inizio < 0) return null;

        StringBuilder sb = new StringBuilder(righe[inizio].trim()).append("\n");
        for (int i = inizio + 1; i < righe.length; i++) {
            if (nuovaSezione(righe[i])) break;
            sb.append(righe[i]).append("\n");
        }
        String out = sb.toString().replaceAll("\n{3,}", "\n\n").trim();
        return out.isEmpty() ? null : out;
    }

    /** L'abstract: c'e' sempre, e serve da ripiego quando l'elenco dei cambiamenti manca. */
    public static String abstractDi(String testoRfc) {
        String t = ripulisci(testoRfc);
        String[] righe = t.split("\n");
        int inizio = -1;
        for (int i = 0; i < righe.length; i++)
            if (righe[i].trim().equalsIgnoreCase("Abstract")) { inizio = i; break; }
        if (inizio < 0) return null;
        StringBuilder sb = new StringBuilder();
        for (int i = inizio + 1; i < righe.length; i++) {
            String r = righe[i];
            String tt = r.trim();
            if (tt.equalsIgnoreCase("Status of This Memo")
                    || tt.equalsIgnoreCase("Copyright Notice")
                    || tt.equalsIgnoreCase("Table of Contents")
                    || nuovaSezione(r)) break;
            sb.append(r).append("\n");
        }
        String out = sb.toString().replaceAll("\n{3,}", "\n\n").trim();
        return out.isEmpty() ? null : out;
    }

    /**
     * Scarica il documento nuovo e ne estrae cio' che dice di se stesso: prima l'elenco dei
     * cambiamenti, e se non c'e' l'abstract.
     *
     * Questo NON dice se il pannello va cambiato: dice cosa e' cambiato nel documento.
     * Decidere se tocca il nostro codice resta un lavoro di lettura — ma partire dall'elenco
     * scritto dagli autori e' un'altra cosa rispetto a partire da centottanta pagine.
     */
    public static JSONObject cosaECambiato(String number) { return cosaECambiato(number, number); }

    /**
     * @param numero     il documento nuovo, da scaricare
     * @param rifermento la specifica del pannello a cui si riferisce, per sapere quali
     *                   identificatori incrociare (per un aggiornamento sono diversi)
     */
    public static JSONObject cosaECambiato(String number, String rifermento) {
        JSONObject r = new JSONObject().put("rfc", normalizza(number));
        String n = normalizza(number);
        if (!n.matches("[0-9]{1,5}"))
            return r.put("success", false).put("error", I18n.tr("server.watch.badNumber"));
        try {
            HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(8)).build();
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create("https://www.rfc-editor.org/rfc/rfc" + n + ".txt"))
                    .timeout(Duration.ofSeconds(30)).GET().build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200)
                return r.put("success", false)
                        .put("error", I18n.tr("server.watch.editorStatus", java.util.Map.of("c", String.valueOf(resp.statusCode()))));
            String testo = resp.body();
            r.put("success", true).put("byte", testo.length());

            String cambi = elencoCambiamenti(testo);
            if (cambi != null) {
                r.put("tipo", "elenco").put("testo", cambi)
                 .put("nota", I18n.tr("server.watch.changeList"));
                // Incrocio con cio' che il pannello usa davvero.
                List<String> tocca = righeCheToccano(cambi, identificatoriDi(rifermento));
                r.put("tiRiguarda", new JSONArray(tocca));
                r.put("notaIncrocio", tocca.isEmpty()
                        ? I18n.tr("server.watch.crossNone")
                        : tocca.size() == 1
                          ? I18n.tr("server.watch.crossSome.one")
                          : I18n.tr("server.watch.crossSome.other", java.util.Map.of("n", String.valueOf(tocca.size()))));
                return r;
            }

            String ab = abstractDi(testo);
            if (ab != null)
                return r.put("tipo", "abstract").put("testo", ab)
                        .put("nota", I18n.tr("server.watch.abstract"));

            return r.put("success", false)
                    .put("error", I18n.tr("server.watch.noChangesNoAbstract"));
        } catch (Exception e) {
            return r.put("success", false)
                    .put("error", I18n.tr("server.watch.downloadFailed", java.util.Map.of("err", String.valueOf(e.getClass().getSimpleName()))));
        }
    }

    /* ===================================================================
     * Quali righe dell'elenco toccano davvero questo pannello
     * =================================================================== */

    /**
     * Gli identificatori che il pannello scrive o riconosce davvero, per ciascuna specifica.
     *
     * Servono a incrociare l'elenco dei cambiamenti con cio' che il pannello fa: se una riga
     * dell'elenco nomina "pct" e il pannello scrive record DMARC, quella riga va letta prima
     * delle altre. E' lo stesso ragionamento che il 01/09/2026 ho fatto a mano con un grep,
     * scritto una volta sola.
     *
     * ATTENZIONE a come si legge il risultato: l'incrocio dice "queste righe ti riguardano di
     * sicuro", NON "solo queste ti riguardano". Un cambiamento descritto a parole senza
     * nominare il tag sfugge. Presentarlo come un filtro completo sarebbe il modo di far
     * saltare proprio la riga che contava.
     *
     * numero | identificatori separati da virgola
     */
    private static final String[][] RILEVANTI = {
        { "7208", "v=spf1,ip4,ip6,include,redirect,exists,all,mx,ptr,permerror,10" },
        { "6376", "rsa-sha256,rsa-sha1,_domainkey,k=rsa,selector,2048,1024" },
        { "8301", "rsa-sha256,rsa-sha1,2048,1024,4096" },
        { "9989", "pct,rua,ruf,adkim,aspf,sp,np,psd,fo,ri,rf,DMARC1,tree walk,none,quarantine,reject" },
        { "9990", "rua,_report._dmarc,gzip,aggregate" },
        { "9991", "ruf,fo,failure" },
        { "6186", "_imaps._tcp,_submission._tcp,993,587,SRV" },
        { "6409", "AUTH,MAIL,submission,587" },
        { "8314", "465,submissions,implicit,STARTTLS,TLS 1.2,TLS 1.1,TLS 1.0" },
        { "8461", "_mta-sts,mta-sts.txt,policy,max_age" },
    };

    private static String identificatoriDi(String rfc) {
        String n = normalizza(rfc);
        for (String[] x : RILEVANTI) if (x[0].equals(n)) return x[1];
        return "";
    }

    /**
     * Le righe dell'elenco che nominano qualcosa che il pannello usa.
     *
     * Il confronto e' a parola intera quando l'identificatore e' fatto di sole lettere e
     * cifre: cercare "all" come sottostringa lo troverebbe dentro "finally", "小" dentro
     * qualunque cosa, e la segnalazione diventerebbe rumore. E' lo stesso errore che sull'SPF
     * faceva passare per buono un record che non autorizzava il server.
     */
    public static List<String> righeCheToccano(String list, String identificatori) {
        List<String> fuori = new ArrayList<>();
        if (list == null || identificatori == null) return fuori;
        List<String> chiavi = new ArrayList<>();
        for (String k : identificatori.split(",")) if (!k.trim().isEmpty()) chiavi.add(k.trim());
        if (chiavi.isEmpty()) return fuori;

        for (String riga : list.split("\n")) {
            String r = riga.trim();
            if (r.length() < 3) continue;
            LinkedHashSet<String> trovati = new LinkedHashSet<>();
            for (String k : chiavi) if (contieneIdentificatore(riga, k)) trovati.add(k);
            if (!trovati.isEmpty()) fuori.add(String.join(", ", trovati) + "  ->  " + r);
        }
        return fuori;
    }

    /** Parola intera per gli identificatori alfanumerici, sottostringa per gli altri. */
    public static boolean contieneIdentificatore(String riga, String chiave) {
        if (riga == null || chiave == null || chiave.isEmpty()) return false;
        boolean semplice = chiave.chars().allMatch(c -> Character.isLetterOrDigit(c));
        if (!semplice) return riga.toLowerCase(java.util.Locale.ROOT)
                                  .contains(chiave.toLowerCase(java.util.Locale.ROOT));
        return java.util.regex.Pattern
                .compile("(?<![A-Za-z0-9])" + java.util.regex.Pattern.quote(chiave) + "(?![A-Za-z0-9])",
                         java.util.regex.Pattern.CASE_INSENSITIVE)
                .matcher(riga).find();
    }

    static String[][] standardPerProva() { return Arrays.stream(STANDARD).toArray(String[][]::new); }
}
