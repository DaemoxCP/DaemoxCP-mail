package org.mail_panel.security;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mail_panel.database.MailDatabase;

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

    public CloudflareManager(MailDatabase database) {
        this.database = database;
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
                return new AddAccountResult(false, -1, "Label richiesta");
            }
            if (apiToken == null || apiToken.isBlank()) {
                return new AddAccountResult(false, -1, "Token richiesto");
            }
            TokenCheck tc = verifyToken(apiToken);
            if (!tc.valid) {
                return new AddAccountResult(false, -1, "Token non valido: " + tc.message);
            }
            int newId = database.addCloudflareAccount(label.trim(),
                email == null ? null : email.trim(), apiToken.trim());
            return new AddAccountResult(true, newId, "Account aggiunto e token verificato");
        } catch (Exception e) {
            return new AddAccountResult(false, -1, "Errore: " + e.getMessage());
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
            if (a == null) return new AddAccountResult(false, id, "Account non trovato");

            boolean labelOrEmailUpdated = false;
            if (label != null && !label.isBlank()) {
                database.updateCloudflareAccount(id, label.trim(), email == null ? null : email.trim());
                labelOrEmailUpdated = true;
            }

            // Token: caso null/vuoto → nessun cambio token, ok
            if (newToken == null || newToken.isBlank()) {
                return new AddAccountResult(true, id,
                    labelOrEmailUpdated ? "Etichetta/email aggiornate. Token invariato." : "Nessuna modifica.");
            }

            String trimmed = newToken.trim();

            // Caso: stesso identico token di prima → segnala e non rilanciare la verifica Cloudflare
            if (a.apiToken != null && trimmed.equals(a.apiToken)) {
                return new AddAccountResult(true, id,
                    labelOrEmailUpdated
                        ? "Il token inserito è IDENTICO a quello già salvato — token invariato. Etichetta/email aggiornate."
                        : "Il token inserito è IDENTICO a quello già salvato — nessuna modifica effettuata.");
            }

            // Token davvero nuovo → verifica e salva
            TokenCheck tc = verifyToken(trimmed);
            if (!tc.valid) return new AddAccountResult(false, id, "Token non valido: " + tc.message);
            database.updateCloudflareAccountToken(id, trimmed);
            return new AddAccountResult(true, id,
                labelOrEmailUpdated ? "Account aggiornato (etichetta/email + nuovo token verificato e salvato)."
                                    : "Nuovo token verificato e salvato.");

        } catch (Exception e) {
            return new AddAccountResult(false, id, "Errore: " + e.getMessage());
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
            return new TokenCheck(true, "Token attivo e valido", status);
        } catch (Exception e) {
            return new TokenCheck(false, "Errore: " + e.getMessage(), null);
        }
    }

    /**
     * Trova la zona Cloudflare per un dominio. Risale a livelli superiori se
     * il dominio è un sotto-dominio gestito da una zona apex.
     */
    public ZoneLookup findZone(String token, String domain) {
        try {
            if (token == null || token.isBlank()) return new ZoneLookup(false, null, null, "Token non fornito");

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
            return new ZoneLookup(false, null, null, "Nessuna zona attiva trovata per " + domain + " su questo account Cloudflare");
        } catch (Exception e) {
            return new ZoneLookup(false, null, null, "Errore: " + e.getMessage());
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
            payload.put("comment", "DKIM rotation - auto-managed by FreeBSD Mail Panel");

            HttpResponse<String> resp = call("POST", "/zones/" + zoneId + "/dns_records", token, payload.toString());
            JSONObject body = new JSONObject(resp.body());
            if (body.optBoolean("success", false)) {
                JSONObject r = body.getJSONObject("result");
                return new RecordOp(true, r.getString("id"), null);
            }
            return new RecordOp(false, null, extractErrorMessage(body));
        } catch (Exception e) {
            return new RecordOp(false, null, "Errore: " + e.getMessage());
        }
    }

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
            if (token == null || token.isBlank()) return new RecordOp(false, null, "Token non fornito");
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
            return new RecordOp(false, null, "Errore: " + e.getMessage());
        }
    }

    /**
     * Lista tutti i record TXT della zona il cui nome contiene una sottostringa specifica.
     * Il confronto è case-insensitive (Cloudflare normalizza i nomi DNS in minuscolo).
     * Esempio uso: {@code listTxtRecordsContaining(token, zoneId, "_domainkey.")} per trovare
     * tutti i record DKIM (sia attivi che orfani) di un dominio.
     * Itera con paginazione fino a 1000 record.
     * Se {@code nameSubstring} è null o vuoto, ritorna TUTTI i record TXT della zona.
     */
    public java.util.List<TxtRecordInfo> listTxtRecordsContaining(String token, String zoneId, String nameSubstring) {
        java.util.List<TxtRecordInfo> result = new java.util.ArrayList<>();
        String needle = (nameSubstring == null) ? null : nameSubstring.toLowerCase();
        try {
            int page = 1;
            while (page <= 10) { // max 10 pagine × 100 = 1000 record (più che abbastanza)
                String path = "/zones/" + zoneId + "/dns_records?type=TXT&per_page=100&page=" + page;
                HttpResponse<String> resp = call("GET", path, token, null);
                JSONObject body = new JSONObject(resp.body());
                if (!body.optBoolean("success", false)) break;
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
                page++;
            }
        } catch (Exception ignore) {}
        return result;
    }

    public static class TxtRecordInfo {
        public String id;
        public String name;
        public String content;
        public int ttl;
        public String comment;
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
            return new RecordOp(false, null, "Errore: " + e.getMessage());
        }
    }

    // ========= Helpers =========

    private HttpResponse<String> call(String method, String path, String token, String jsonBody) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder()
            .uri(URI.create(API_BASE + path))
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
            return e.optString("message", "Errore Cloudflare sconosciuto") + " (code " + e.optInt("code", 0) + ")";
        }
        return "Errore Cloudflare sconosciuto";
    }

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
