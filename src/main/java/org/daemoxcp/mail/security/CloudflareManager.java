package org.daemoxcp.mail.security;

import org.json.JSONArray;
import org.daemoxcp.mail.i18n.I18n;
import org.json.JSONObject;
import org.daemoxcp.mail.database.MailDatabase;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

/**
 * Integrazione Cloudflare DNS API per la rotazione DKIM automatica.
 *
 * MULTI-ACCOUNT: ogni account = una riga in {@code cloudflare_accounts}
 * con label, email (informativa) e api_token. Ogni dominio si lega a un
 * account specifico (column domains.cloudflare_account_id). Questo
 * permette di gestire domini su account Cloudflare differenti.
 *
 * Token con permessi minimi: Zone:Read + DNS:Edit, scope "Include - Specific zone".
 */
public class CloudflareManager {

    private static final String API_BASE = "https://api.cloudflare.com/client/v4";

    private final MailDatabase database;
    private final HttpClient http;
    /** L'indirizzo dell'API: quello di Cloudflare, o nelle prove un server finto sulla macchina. */
    private final String apiBase;

    public CloudflareManager(MailDatabase database) {
        this(database, API_BASE);
    }

    /** Per le prove: lo stesso gestore, verso un'API finta. */
    CloudflareManager(MailDatabase database, String apiBase) {
        this.database = database;
        this.apiBase = apiBase;
        this.http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();
    }

    // ========= Account management (delega al DB) =========

    public List<MailDatabase.CloudflareAccount> listAccounts() throws Exception {
        return database.listCloudflareAccounts();
    }

    public MailDatabase.CloudflareAccount getAccount(int id) throws Exception {
        return database.getCloudflareAccount(id);
    }

    public MailDatabase.CloudflareAccount getAccountForDomain(int domainId) throws Exception {
        return database.getCloudflareAccountForDomain(domainId);
    }

    /** Verifica il token; se valido, lo salva come nuovo account. */
    public AddAccountResult addAccount(String label, String email, String apiToken) {
        try {
            if (label == null || label.isBlank()) {
                return new AddAccountResult(false, -1, I18n.tr("server.cfm.labelRequired"));
            }
            if (apiToken == null || apiToken.isBlank()) {
                return new AddAccountResult(false, -1, I18n.tr("server.cfm.tokenRequired"));
            }
            TokenCheck tc = verifyToken(apiToken);
            if (!tc.valid) {
                return new AddAccountResult(false, -1, I18n.tr("server.cfm.tokenInvalid", java.util.Map.of("m", String.valueOf(tc.message))));
            }
            int newId = database.addCloudflareAccount(label.trim(),
                email == null ? null : email.trim(), apiToken.trim());
            return new AddAccountResult(true, newId, I18n.tr("server.cfm.added"));
        } catch (Exception e) {
            return new AddAccountResult(false, -1, I18n.tr("server.cfm.error", java.util.Map.of("err", org.daemoxcp.mail.util.ErrorText.detail("CloudflareManager", e))));
        }
    }

    /**
     * Aggiorna label/email di un account esistente; opzionalmente
     * aggiorna anche il token (se non-null/non-vuoto, viene verificato).
     *
     * Se il nuovo token combacia esattamente con quello già salvato,
     * lo salta e restituisce un messaggio specifico ("Il token è invariato").
     */
    public AddAccountResult updateAccount(int id, String label, String email, String newToken) {
        try {
            MailDatabase.CloudflareAccount a = database.getCloudflareAccount(id);
            if (a == null) return new AddAccountResult(false, id, I18n.tr("server.cfm.notFound"));

            boolean labelOrEmailUpdated = false;
            if (label != null && !label.isBlank()) {
                database.updateCloudflareAccount(id, label.trim(), email == null ? null : email.trim());
                labelOrEmailUpdated = true;
            }

            // Token: caso null/vuoto → nessun cambio token, ok
            if (newToken == null || newToken.isBlank()) {
                return new AddAccountResult(true, id,
                    labelOrEmailUpdated ? I18n.tr("server.cfm.labelUpdated") : I18n.tr("server.cfm.noChange"));
            }

            String trimmed = newToken.trim();

            // Caso: stesso identico token di prima → segnala e non rilanciare la verifica Cloudflare
            if (a.apiToken != null && trimmed.equals(a.apiToken)) {
                return new AddAccountResult(true, id,
                    labelOrEmailUpdated
                        ? I18n.tr("server.cfm.sameTokenLabel")
                        : I18n.tr("server.cfm.sameToken"));
            }

            // Token davvero nuovo → verifica e salva
            TokenCheck tc = verifyToken(trimmed);
            if (!tc.valid) return new AddAccountResult(false, id, I18n.tr("server.cfm.tokenInvalid", java.util.Map.of("m", String.valueOf(tc.message))));
            database.updateCloudflareAccountToken(id, trimmed);
            return new AddAccountResult(true, id,
                labelOrEmailUpdated ? I18n.tr("server.cfm.updatedAll")
                                    : I18n.tr("server.cfm.tokenSaved"));

        } catch (Exception e) {
            return new AddAccountResult(false, id, I18n.tr("server.cfm.error", java.util.Map.of("err", org.daemoxcp.mail.util.ErrorText.detail("CloudflareManager", e))));
        }
    }

    public boolean deleteAccount(int id) throws Exception {
        return database.deleteCloudflareAccount(id);
    }

    public boolean assignDomain(int domainId, int accountId) throws Exception {
        return database.assignCloudflareAccountToDomain(domainId, accountId);
    }

    /** Vero se il dominio ha un account CF assegnato. */
    public boolean hasAccountForDomain(int domainId) {
        try {
            return database.getCloudflareAccountForDomain(domainId) != null;
        } catch (Exception e) {
            return false;
        }
    }

    // ========= Cloudflare API calls =========

    /**
     * Verifica un token (GET /user/tokens/verify).
     */
    public TokenCheck verifyToken(String token) {
        try {
            HttpResponse<String> resp = call("GET", "/user/tokens/verify", token, null);
            JSONObject body = new JSONObject(resp.body());
            boolean ok = body.optBoolean("success", false);
            if (!ok) {
                return new TokenCheck(false, extractErrorMessage(body), null);
            }
            JSONObject result = body.optJSONObject("result");
            String status = result == null ? "" : result.optString("status", "");
            if (!"active".equalsIgnoreCase(status)) {
                return new TokenCheck(false, "Token status: " + status, status);
            }
            return new TokenCheck(true, I18n.tr("server.cfm.tokenActive"), status);
        } catch (Exception e) {
            return new TokenCheck(false, I18n.tr("server.cfm.error", java.util.Map.of("err", org.daemoxcp.mail.util.ErrorText.detail("CloudflareManager", e))), null);
        }
    }

    /**
     * Trova la zona Cloudflare per un dominio. Risale a livelli superiori se
     * il dominio è un sotto-dominio gestito da una zona apex.
     */
    public ZoneLookup findZone(String token, String domain) {
        try {
            if (token == null || token.isBlank()) return new ZoneLookup(false, null, null, I18n.tr("server.cfm.noToken"));

            String candidate = domain;
            while (candidate != null && candidate.contains(".")) {
                String path = "/zones?name=" + URLEncoder.encode(candidate, StandardCharsets.UTF_8) + "&status=active";
                HttpResponse<String> resp = call("GET", path, token, null);
                JSONObject body = new JSONObject(resp.body());
                if (body.optBoolean("success", false)) {
                    JSONArray arr = body.optJSONArray("result");
                    if (arr != null && arr.length() > 0) {
                        JSONObject z = arr.getJSONObject(0);
                        return new ZoneLookup(true, z.getString("id"), z.getString("name"), null);
                    }
                } else {
                    return new ZoneLookup(false, null, null, extractErrorMessage(body));
                }
                int dot = candidate.indexOf('.');
                if (dot < 0) break;
                candidate = candidate.substring(dot + 1);
            }
            return new ZoneLookup(false, null, null, I18n.tr("server.cfm.noZone", java.util.Map.of("d", String.valueOf(domain))));
        } catch (Exception e) {
            return new ZoneLookup(false, null, null, I18n.tr("server.cfm.error", java.util.Map.of("err", org.daemoxcp.mail.util.ErrorText.detail("CloudflareManager", e))));
        }
    }

    public RecordOp createTxtRecord(String token, String zoneId, String name, String value, int ttl) {
        try {
            JSONObject payload = new JSONObject();
            payload.put("type", "TXT");
            payload.put("name", name);
            // Pre-formatta il content secondo RFC 1035: stringhe TXT max 255 char ciascuna,
            // ognuna racchiusa tra virgolette, separate da spazio. Così Cloudflare non
            // mostra avvisi di quoting e il record è esplicitamente conforme.
            payload.put("content", formatTxtRecordContent(value));
            payload.put("ttl", ttl <= 0 ? 1 : ttl);
            payload.put("comment", txtComment(name));

            HttpResponse<String> resp = call("POST", "/zones/" + zoneId + "/dns_records", token, payload.toString());
            JSONObject body = new JSONObject(resp.body());
            if (body.optBoolean("success", false)) {
                JSONObject r = body.getJSONObject("result");
                return new RecordOp(true, r.getString("id"), null);
            }
            return new RecordOp(false, null, extractErrorMessage(body));
        } catch (Exception e) {
            return new RecordOp(false, null, I18n.tr("server.cfm.error", java.util.Map.of("err", org.daemoxcp.mail.util.ErrorText.detail("CloudflareManager", e))));
        }
    }

    /** Il commento di un TXT del pannello: quello della rotazione sui record DKIM (DkimManager lo rilegge), altrimenti
     * quello di tutti gli altri record. Prima ogni TXT, anche SPF, DMARC e _mta-sts, diceva "DKIM rotation". */
    static final String DKIM_COMMENT = "DKIM rotation - auto-managed by " + org.daemoxcp.mail.system.Product.NAME;

    static String txtComment(String name) {
        return name != null && name.toLowerCase(java.util.Locale.ROOT).contains("._domainkey.") ? DKIM_COMMENT : RECORD_COMMENT;
    }

    /**
     * Una lettura dei record della zona che non e' riuscita: Cloudflare ha risposto con un errore, non ha risposto, o la
     * zona ha piu' record di quanti se ne leggono. Non e' una zona vuota. Prima le due letture restituivano una lista
     * vuota anche in questi casi, e chi le usa per sapere "c'e' gia'?" avrebbe creato un secondo SPF, DMARC o DKIM
     * accanto al primo, rompendo il dominio. Il messaggio e' gia' nella lingua di chi guarda.
     */
    public static final class ZoneReadException extends RuntimeException {
        public ZoneReadException(String message) { super(message); }
    }

    /** Le pagine da 100 record che si leggono al massimo: oltre, la zona non si puo' dire letta tutta. */
    static final int MAX_PAGES = 10;

    /**
     * Formatta il contenuto di un record TXT secondo lo standard DNS:
     *  - Stringhe DNS character-string sono limitate a 255 ottetti (RFC 1035 §3.3.14).
     *  - Per valori più lunghi, vanno spezzati in più stringhe consecutive, ognuna
     *    racchiusa tra virgolette doppie e separate da uno spazio.
     *  - Il resolver concatena automaticamente le stringhe alla ricezione.
     *
     * Esempi:
     *   "v=spf1 ip4:1.2.3.4 ~all"                                 (corto: una sola stringa)
     *   "v=DKIM1; k=rsa; p=MIIBIj...EwppK2GMQ" "iVl0JWQ...wIDAQAB" (DKIM 2048 = 2 stringhe)
     */
    static String formatTxtRecordContent(String value) {
        if (value == null || value.isEmpty()) return "\"\"";
        final int MAX_LEN = 255;
        if (value.length() <= MAX_LEN) {
            return "\"" + value + "\"";
        }
        StringBuilder sb = new StringBuilder();
        int pos = 0;
        while (pos < value.length()) {
            int end = Math.min(pos + MAX_LEN, value.length());
            if (sb.length() > 0) sb.append(' ');
            sb.append('"').append(value, pos, end).append('"');
            pos = end;
        }
        return sb.toString();
    }

    /**
     * Cerca un record TXT per nome esatto. Utile per ritrovare un record DNS
     * di cui non abbiamo memorizzato l'ID (es. record DKIM originale creato
     * manualmente prima dell'integrazione Cloudflare).
     *
     * @return RecordOp con success=true e recordId valorizzato se trovato,
     *         success=false con error="not found" se non esistente, oppure
     *         success=false con error=... in caso di errore API.
     */
    public RecordOp findTxtRecord(String token, String zoneId, String name) {
        try {
            if (token == null || token.isBlank()) return new RecordOp(false, null, I18n.tr("server.cfm.noToken"));
            String path = "/zones/" + zoneId + "/dns_records?type=TXT&name="
                + URLEncoder.encode(name, StandardCharsets.UTF_8);
            HttpResponse<String> resp = call("GET", path, token, null);
            JSONObject body = new JSONObject(resp.body());
            if (!body.optBoolean("success", false)) {
                return new RecordOp(false, null, extractErrorMessage(body));
            }
            JSONArray arr = body.optJSONArray("result");
            if (arr != null && arr.length() > 0) {
                return new RecordOp(true, arr.getJSONObject(0).getString("id"), null);
            }
            return new RecordOp(false, null, "not found");
        } catch (Exception e) {
            return new RecordOp(false, null, I18n.tr("server.cfm.error", java.util.Map.of("err", org.daemoxcp.mail.util.ErrorText.detail("CloudflareManager", e))));
        }
    }

    /**
     * Lista tutti i record TXT della zona il cui nome contiene una sottostringa specifica.
     * Il confronto è case-insensitive (Cloudflare normalizza i nomi DNS in minuscolo).
     * Esempio uso: {@code listTxtRecordsContaining(token, zoneId, "_domainkey.")} per trovare
     * tutti i record DKIM (sia attivi che orfani) di un dominio.
     * Itera con paginazione fino a 1000 record.
     * Se {@code nameSubstring} è null o vuoto, ritorna TUTTI i record TXT della zona.
     *
     * @throws ZoneReadException se la zona non si e' potuta leggere tutta: mai una lista vuota al posto di un errore
     */
    public java.util.List<TxtRecordInfo> listTxtRecordsContaining(String token, String zoneId, String nameSubstring) {
        java.util.List<TxtRecordInfo> result = new java.util.ArrayList<>();
        String needle = (nameSubstring == null) ? null : nameSubstring.toLowerCase();
        try {
            int page = 1;
            while (true) {
                String path = "/zones/" + zoneId + "/dns_records?type=TXT&per_page=100&page=" + page;
                HttpResponse<String> resp = call("GET", path, token, null);
                JSONObject body = new JSONObject(resp.body());
                if (!body.optBoolean("success", false)) throw unreadable(extractErrorMessage(body));
                JSONArray arr = body.optJSONArray("result");
                if (arr == null || arr.length() == 0) break;
                for (int i = 0; i < arr.length(); i++) {
                    JSONObject r = arr.getJSONObject(i);
                    String name = r.optString("name", "");
                    boolean match = (needle == null || needle.isEmpty())
                        || name.toLowerCase().contains(needle);
                    if (match) {
                        TxtRecordInfo info = new TxtRecordInfo();
                        info.id = r.getString("id");
                        info.name = name;
                        info.content = r.optString("content", "");
                        info.ttl = r.optInt("ttl", 0);
                        info.comment = r.optString("comment", null);
                        result.add(info);
                    }
                }
                JSONObject ri = body.optJSONObject("result_info");
                int totalPages = ri == null ? 1 : ri.optInt("total_pages", 1);
                if (page >= totalPages) break;
                if (page >= MAX_PAGES) throw new ZoneReadException(I18n.tr("server.cfm.zoneTooBig"));
                page++;
            }
        } catch (ZoneReadException e) {
            throw e;
        } catch (Exception e) {
            throw unreadable(String.valueOf(e.getMessage()));
        }
        return result;
    }

    private static ZoneReadException unreadable(String why) {
        return new ZoneReadException(I18n.tr("server.cfm.zoneUnreadable", java.util.Map.of("e", String.valueOf(why))));
    }

    public static class TxtRecordInfo {
        public String id;
        public String name;
        public String content;
        public int ttl;
        public String comment;
    }

    /**
     * Il commento dei record che il pannello crea, per chi li guarda nella dashboard di
     * Cloudflare. Il pannello non lo rilegge (legge solo i commenti dei record DKIM, vedi
     * DkimManager). I record creati prima della fine di ottobre 2026 hanno ancora il testo
     * italiano, e lo tengono: cambiarlo vorrebbe dire scrivere su Cloudflare all'avvio per un
     * commento.
     */
    static final String RECORD_COMMENT = "Created by " + org.daemoxcp.mail.system.Product.NAME;

    /**
     * I record di questa zona che hanno il commento di prima (in italiano fino al 30/10/2026, legacy-names.json,
     * cloudflareRecordComments) prendono quello di adesso. Il committente, il 09/11/2026: «quando aggiunge un record,
     * non usi l'italiano nei commenti tipo "Creato dal pannello di posta" ma sempre e comunque l'inglese» (reperto 211).
     * Cambia SOLO il commento, con PATCH: nome, contenuto, TTL e proxy restano come sono, quindi il DNS non cambia.
     * Restituisce quanti ne ha cambiati, o -1 se Cloudflare non ha risposto come doveva (si riprova al prossimo avvio).
     */
    public int renameLegacyComments(String token, String zoneId) {
        int renamed = 0;
        try {
            for (String[] pair : org.daemoxcp.mail.system.LegacyNames.pairs("cloudflareRecordComments")) {
                // Si cerca col filtro esatto di Cloudflare, e si ricontrolla qui: si tocca solo cio' che ha quel testo. Un
                // record cambiato esce dal filtro, quindi si rilegge sempre la prima pagina finche' ne resta qualcuno; un
                // giro che non cambia niente chiude (niente giri a vuoto).
                for (int round = 0; round < 50; round++) {
                    HttpResponse<String> resp = call("GET", "/zones/" + zoneId + "/dns_records?per_page=100&comment.exact="
                            + URLEncoder.encode(pair[0], StandardCharsets.UTF_8), token, null);
                    JSONObject body = new JSONObject(resp.body());
                    if (!body.optBoolean("success", false)) return -1;
                    JSONArray arr = body.optJSONArray("result");
                    if (arr == null || arr.length() == 0) break;
                    int before = renamed;
                    for (int i = 0; i < arr.length(); i++) {
                        JSONObject r = arr.getJSONObject(i);
                        if (!pair[0].equals(r.optString("comment"))) continue;
                        String id = r.optString("id", "");
                        if (!id.matches("[0-9a-f]{32}")) continue;
                        RecordOp op = outcome(call("PATCH", "/zones/" + zoneId + "/dns_records/" + id, token,
                                new JSONObject().put("comment", pair[1]).toString()));
                        if (!op.success) return -1;
                        renamed++;
                    }
                    if (renamed == before) break;
                }
            }
        } catch (Exception e) {
            return -1;
        }
        return renamed;
    }

    /**
     * Crea un CNAME. Sempre con proxied=false, e non e' una preferenza: un CNAME
     * proxato non risponde piu' con il CNAME ma con gli indirizzi di Cloudflare, quindi
     * il client di posta non troverebbe piu' l'host che cerca e la verifica del pannello
     * direbbe "punta altrove". La nuvola grigia qui non e' un consiglio, e' un requisito.
     */
    public RecordOp createCnameRecord(String token, String zoneId, String name, String target, int ttl) {
        try {
            JSONObject payload = new JSONObject();
            payload.put("type", "CNAME");
            payload.put("name", name);
            payload.put("content", target);
            payload.put("proxied", false);
            payload.put("ttl", ttl <= 0 ? 1 : ttl);
            payload.put("comment", RECORD_COMMENT);
            return outcome(call("POST", "/zones/" + zoneId + "/dns_records", token, payload.toString()));
        } catch (Exception e) {
            return new RecordOp(false, null, I18n.tr("server.cfm.error", java.util.Map.of("err", org.daemoxcp.mail.util.ErrorText.detail("CloudflareManager", e))));
        }
    }

    /**
     * Un record A o AAAA (ServerAddresses e HostRecords). Il nome della posta va sempre senza proxy: Cloudflare non fa
     * passare la porta 25 (developers.cloudflare.com/dns/troubleshooting/email-issues/), e il nome a cui punta un MX deve
     * essere «DNS only». Il pannello e la webmail invece si' (2096 e 8443 sono porte che Cloudflare inoltra).
     */
    public RecordOp createAddressRecord(String token, String zoneId, String name, String type, String ip, boolean proxied) {
        if (!"A".equals(type) && !"AAAA".equals(type))
            return new RecordOp(false, null, I18n.tr("server.cfm.error", java.util.Map.of("err", "type " + type)));
        try {
            JSONObject payload = new JSONObject();
            payload.put("type", type);
            payload.put("name", name);
            payload.put("content", ip);
            payload.put("proxied", proxied);
            payload.put("ttl", 1);
            payload.put("comment", RECORD_COMMENT);
            return outcome(call("POST", "/zones/" + zoneId + "/dns_records", token, payload.toString()));
        } catch (Exception e) {
            return new RecordOp(false, null, I18n.tr("server.cfm.error", java.util.Map.of("err", org.daemoxcp.mail.util.ErrorText.detail("CloudflareManager", e))));
        }
    }

    /**
     * Crea un SRV nella forma documentata da Cloudflare: nome completo in "name" e i soli
     * campi priority/weight/port/target dentro "data".
     *
     * Esempio della documentazione ufficiale:
     *   {"type":"SRV","name":"_xmpp._tcp.example.com",
     *    "data":{"priority":10,"weight":5,"port":5223,"target":"server.example.com"}}
     */
    public RecordOp createSrvRecord(String token, String zoneId, String name, String target,
                                    int priority, int weight, int port, int ttl) {
        try {
            JSONObject data = new JSONObject()
                    .put("priority", priority).put("weight", weight)
                    .put("port", port).put("target", target);
            JSONObject payload = new JSONObject();
            payload.put("type", "SRV");
            payload.put("name", name);
            payload.put("data", data);
            payload.put("ttl", ttl <= 0 ? 1 : ttl);
            payload.put("comment", RECORD_COMMENT);
            return outcome(call("POST", "/zones/" + zoneId + "/dns_records", token, payload.toString()));
        } catch (Exception e) {
            return new RecordOp(false, null, I18n.tr("server.cfm.error", java.util.Map.of("err", org.daemoxcp.mail.util.ErrorText.detail("CloudflareManager", e))));
        }
    }

    /**
     * Cambia il contenuto di un record TXT esistente.
     *
     * Metodo e percorso presi dalla documentazione ufficiale, letta a pagina renderizzata:
     *   PATCH /zones/{zone_id}/dns_records/{dns_record_id}  -  "Update an existing DNS record"
     * Il corpo segue la forma dell'esempio della stessa pagina, che indica tipo, nome e
     * contenuto. PATCH lascia stare cio' che non si nomina, quindi commento e altri campi
     * del record restano dove sono.
     */
    public RecordOp updateTxtRecord(String token, String zoneId, String recordId,
                                    String name, String value, int ttl) {
        try {
            JSONObject payload = new JSONObject()
                    .put("type", "TXT")
                    .put("name", name)
                    .put("content", formatTxtRecordContent(value))
                    .put("ttl", ttl <= 0 ? 1 : ttl);
            return outcome(call("PATCH", "/zones/" + zoneId + "/dns_records/" + recordId,
                    token, payload.toString()));
        } catch (Exception e) {
            return new RecordOp(false, null, I18n.tr("server.cfm.error", java.util.Map.of("err", org.daemoxcp.mail.util.ErrorText.detail("CloudflareManager", e))));
        }
    }

    /**
     * Accende o spegne il proxy di Cloudflare su un record.
     *
     * Serve per i nomi che devono puntare DRITTI al server: mta-sts e autoconfig. Con il
     * proxy acceso, chi li interroga parla con Cloudflare, che a sua volta deve poter
     * validare il certificato dell'origine — un secondo pezzo che deve funzionare, e che
     * quando non funziona risponde 526 senza spiegare cosa manchi. Diretto sono meno cose
     * che possono rompersi.
     *
     * Si usa PATCH, che tocca il solo campo indicato e lascia stare nome, contenuto e TTL.
     */
    public RecordOp setProxy(String token, String zoneId, String recordId, boolean proxied) {
        try {
            JSONObject payload = new JSONObject().put("proxied", proxied);
            return outcome(call("PATCH", "/zones/" + zoneId + "/dns_records/" + recordId,
                    token, payload.toString()));
        } catch (Exception e) {
            return new RecordOp(false, null, I18n.tr("server.cfm.error", java.util.Map.of("err", org.daemoxcp.mail.util.ErrorText.detail("CloudflareManager", e))));
        }
    }

    /** Corregge un CNAME esistente: destinazione giusta e proxy spento. */
    public RecordOp updateCname(String token, String zoneId, String recordId,
                                  String name, String target) {
        try {
            JSONObject payload = new JSONObject()
                    .put("type", "CNAME").put("name", name)
                    .put("content", target).put("proxied", false);
            return outcome(call("PATCH", "/zones/" + zoneId + "/dns_records/" + recordId,
                    token, payload.toString()));
        } catch (Exception e) {
            return new RecordOp(false, null, I18n.tr("server.cfm.error", java.util.Map.of("err", org.daemoxcp.mail.util.ErrorText.detail("CloudflareManager", e))));
        }
    }

    /** Corregge un SRV esistente: destinazione e porta giuste. */
    public RecordOp updateSrv(String token, String zoneId, String recordId, String name,
                                String target, int priority, int weight, int port) {
        try {
            JSONObject data = new JSONObject().put("priority", priority).put("weight", weight)
                    .put("port", port).put("target", target);
            JSONObject payload = new JSONObject()
                    .put("type", "SRV").put("name", name).put("data", data);
            return outcome(call("PATCH", "/zones/" + zoneId + "/dns_records/" + recordId,
                    token, payload.toString()));
        } catch (Exception e) {
            return new RecordOp(false, null, I18n.tr("server.cfm.error", java.util.Map.of("err", org.daemoxcp.mail.util.ErrorText.detail("CloudflareManager", e))));
        }
    }

    private RecordOp outcome(HttpResponse<String> resp) {
        JSONObject body = new JSONObject(resp.body());
        if (body.optBoolean("success", false))
            return new RecordOp(true, body.getJSONObject("result").getString("id"), null);
        return new RecordOp(false, null, extractErrorMessage(body));
    }

    /**
     * Tutti i record della zona, di qualunque tipo, con il tipo riportato.
     *
     * Serve guardare ANCHE i tipi diversi da quello che si vuole creare: il DNS non
     * ammette un CNAME accanto ad altri dati sullo stesso nome, quindi un record A su
     * "autoconfig" fa rifiutare il CNAME da Cloudflare. Meglio dirlo prima, spiegando
     * perche', che mostrare l'errore grezzo dell'API.
     *
     * @throws ZoneReadException se la zona non si e' potuta leggere tutta: mai una lista vuota al posto di un errore
     */
    public java.util.List<DnsRecordInfo> listRecords(String token, String zoneId) {
        java.util.List<DnsRecordInfo> result = new java.util.ArrayList<>();
        try {
            int page = 1;
            while (true) {
                String path = "/zones/" + zoneId + "/dns_records?per_page=100&page=" + page;
                HttpResponse<String> resp = call("GET", path, token, null);
                JSONObject body = new JSONObject(resp.body());
                if (!body.optBoolean("success", false)) throw unreadable(extractErrorMessage(body));
                JSONArray arr = body.optJSONArray("result");
                if (arr == null || arr.length() == 0) break;
                for (int i = 0; i < arr.length(); i++) {
                    JSONObject r = arr.getJSONObject(i);
                    DnsRecordInfo info = new DnsRecordInfo();
                    info.id = r.optString("id", "");
                    info.type = r.optString("type", "");
                    info.name = r.optString("name", "");
                    info.content = r.optString("content", "");
                    info.proxied = r.optBoolean("proxied", false);
                    // I campi strutturati, quando ci sono, valgono piu' della stringa.
                    JSONObject data = r.optJSONObject("data");
                    if (data != null) {
                        if (data.has("priority")) info.srvPriority = data.optInt("priority");
                        if (data.has("weight"))   info.srvWeight     = data.optInt("weight");
                        if (data.has("port"))     info.srvPort    = data.optInt("port");
                        String targetValue = data.optString("target", "");
                        if (!targetValue.isEmpty()) info.srvDestination = targetValue;
                    }
                    // La priorita' Cloudflare la espone anche fuori da "data".
                    if (info.srvPriority == null && r.has("priority"))
                        info.srvPriority = r.optInt("priority");
                    result.add(info);
                }
                JSONObject ri = body.optJSONObject("result_info");
                int totalPages = ri == null ? 1 : ri.optInt("total_pages", 1);
                if (page >= totalPages) break;
                if (page >= MAX_PAGES) throw new ZoneReadException(I18n.tr("server.cfm.zoneTooBig"));
                page++;
            }
        } catch (ZoneReadException e) {
            throw e;
        } catch (Exception e) {
            throw unreadable(String.valueOf(e.getMessage()));
        }
        return result;
    }

    public static class DnsRecordInfo {
        public String id;
        public String type;
        public String name;
        public String content;
        public boolean proxied;
        /**
         * SRV: i campi che Cloudflare restituisce in "data", piu' la priorita'.
         *
         * Per un SRV il campo "content" e' una stringa di comodo, e Cloudflare ci mette solo
         * PESO, PORTA e DESTINAZIONE: la priorita' vive in un campo suo. Chi legge la
         * priorita' da "content" la legge dal posto sbagliato — e chi pretende quattro campi
         * da una stringa che ne ha tre non ottiene un valore sbagliato, ottiene NULL, cioe'
         * "record non riconosciuto". E' cosi' che il pannello ha riscritto a ogni esecuzione
         * due SRV che erano gia' giusti, annunciando ogni volta una differenza inesistente.
         */
        public Integer srvPriority;
        public Integer srvWeight;
        public Integer srvPort;
        public String srvDestination;
    }

    public RecordOp deleteRecord(String token, String zoneId, String recordId) {
        try {
            HttpResponse<String> resp = call("DELETE", "/zones/" + zoneId + "/dns_records/" + recordId, token, null);
            JSONObject body = new JSONObject(resp.body());
            if (body.optBoolean("success", false)) {
                return new RecordOp(true, recordId, null);
            }
            return new RecordOp(false, null, extractErrorMessage(body));
        } catch (Exception e) {
            return new RecordOp(false, null, I18n.tr("server.cfm.error", java.util.Map.of("err", org.daemoxcp.mail.util.ErrorText.detail("CloudflareManager", e))));
        }
    }

    // ========= Helpers =========

    private HttpResponse<String> call(String method, String path, String token, String jsonBody) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder()
            .uri(URI.create(apiBase + path))
            .timeout(Duration.ofSeconds(15))
            .header("Authorization", "Bearer " + token)
            .header("Content-Type", "application/json");

        HttpRequest.BodyPublisher pub = (jsonBody == null)
            ? HttpRequest.BodyPublishers.noBody()
            : HttpRequest.BodyPublishers.ofString(jsonBody, StandardCharsets.UTF_8);

        if ("GET".equalsIgnoreCase(method))         b.GET();
        else if ("DELETE".equalsIgnoreCase(method)) b.DELETE();
        else                                         b.method(method.toUpperCase(), pub);

        return http.send(b.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private String extractErrorMessage(JSONObject body) {
        JSONArray errors = body.optJSONArray("errors");
        if (errors != null && errors.length() > 0) {
            JSONObject e = errors.getJSONObject(0);
            String raw = e.optString("message", I18n.tr("server.cfm.unknown")) + " (code " + e.optInt("code", 0) + ")";
            // Il token che Cloudflare non riconosce: la sua frase da sola («Invalid request headers (code 6003)») non dice
            // a chi installa cosa fare (reperto 250, provato sulla VM con un token finto)
            return TOKEN_REFUSED.contains(e.optInt("code", 0)) ? I18n.tr("server.cfm.tokenRefused", java.util.Map.of("m", raw)) : raw;
        }
        return I18n.tr("server.cfm.unknown");
    }

    /**
     * I codici con cui Cloudflare rifiuta il token stesso, non l'operazione: 6003 e 6111 (intestazione non valida: token
     * incompleto, con spazi o caratteri in piu'), 1000 (token non valido), 9109 (token non valido o senza accesso),
     * 10000 (autenticazione).
     */
    private static final java.util.Set<Integer> TOKEN_REFUSED = java.util.Set.of(6003, 6111, 1000, 9109, 10000);

    /** Maschera un token mostrando solo gli ultimi 4 caratteri. */
    public static String maskToken(String token) {
        if (token == null || token.isEmpty()) return "";
        if (token.length() <= 8) return "•••";
        return "•••" + token.substring(token.length() - 4);
    }

    // ========= Result classes =========

    public static class TokenCheck {
        public final boolean valid;
        public final String message;
        public final String status;
        public TokenCheck(boolean valid, String message, String status) {
            this.valid = valid; this.message = message; this.status = status;
        }
    }

    public static class ZoneLookup {
        public final boolean found;
        public final String zoneId;
        public final String zoneName;
        public final String error;
        public ZoneLookup(boolean found, String zoneId, String zoneName, String error) {
            this.found = found; this.zoneId = zoneId; this.zoneName = zoneName; this.error = error;
        }
    }

    public static class RecordOp {
        public final boolean success;
        public final String recordId;
        public final String error;
        public RecordOp(boolean success, String recordId, String error) {
            this.success = success; this.recordId = recordId; this.error = error;
        }
    }

    public static class AddAccountResult {
        public final boolean success;
        public final int accountId;
        public final String message;
        public AddAccountResult(boolean success, int accountId, String message) {
            this.success = success; this.accountId = accountId; this.message = message;
        }
    }
}
