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
 * Cloudflare DNS API integration for automatic DKIM rotation.
 *
 * MULTI-ACCOUNT: each account = one row in {@code cloudflare_accounts}
 * with label, email (informational) and api_token. Each domain is tied to a
 * specific account (column domains.cloudflare_account_id). This
 * allows managing domains on different Cloudflare accounts.
 *
 * Token with minimal permissions: Zone:Read + DNS:Edit, scope "Include - Specific zone".
 */
public class CloudflareManager {

    private static final String API_BASE = "https://api.cloudflare.com/client/v4";

    private final MailDatabase database;
    private final HttpClient http;
    /** The API address: Cloudflare's, or in the tests a fake server on the machine. */
    private final String apiBase;

    public CloudflareManager(MailDatabase database) {
        this(database, API_BASE);
    }

    /** For the tests: the same manager, pointed at a fake API. */
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

    /** Verifies the token; if valid, saves it as a new account. */
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
     * Updates label/email of an existing account; optionally
     * also updates the token (if non-null/non-empty, it is verified).
     *
     * If the new token matches exactly the one already saved,
     * it skips it and returns a specific message ("The token is unchanged").
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

            // Token: null/empty case -> no token change, ok
            if (newToken == null || newToken.isBlank()) {
                return new AddAccountResult(true, id,
                    labelOrEmailUpdated ? I18n.tr("server.cfm.labelUpdated") : I18n.tr("server.cfm.noChange"));
            }

            String trimmed = newToken.trim();

            // Case: the very same token as before -> report it and do not run the Cloudflare verification again
            if (a.apiToken != null && trimmed.equals(a.apiToken)) {
                return new AddAccountResult(true, id,
                    labelOrEmailUpdated
                        ? I18n.tr("server.cfm.sameTokenLabel")
                        : I18n.tr("server.cfm.sameToken"));
            }

            // Truly new token -> verify and save
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

    /** True if the domain has a CF account assigned. */
    public boolean hasAccountForDomain(int domainId) {
        try {
            return database.getCloudflareAccountForDomain(domainId) != null;
        } catch (Exception e) {
            return false;
        }
    }

    // ========= Cloudflare API calls =========

    /**
     * Verifies a token (GET /user/tokens/verify).
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
     * Finds the Cloudflare zone for a domain. Goes up to higher levels if
     * the domain is a subdomain managed by an apex zone.
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
            // Pre-formats the content according to RFC 1035: TXT strings of max 255 chars each,
            // each one enclosed in quotes, separated by a space. This way Cloudflare does not
            // show quoting warnings and the record is explicitly compliant.
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

    /**
     * The comment of a panel TXT: the rotation one on DKIM records (DkimManager reads it back), otherwise
     * the one of all the other records. Before, every TXT, even SPF, DMARC and _mta-sts, said "DKIM rotation".
     */
    static final String DKIM_COMMENT = "DKIM rotation - auto-managed by " + org.daemoxcp.mail.system.Product.NAME;

    static String txtComment(String name) {
        return name != null && name.toLowerCase(java.util.Locale.ROOT).contains("._domainkey.") ? DKIM_COMMENT : RECORD_COMMENT;
    }

    /**
     * A read of the records of the zone that did not succeed: Cloudflare answered with an error, did not answer, or the
     * zone has more records than are read. It is not an empty zone. Before, the two reads returned an empty list in
     * these cases too, and whoever uses them to know "is it already there?" would have created a second SPF, DMARC or
     * DKIM next to the first, breaking the domain. The message is already in the language of whoever is looking.
     */
    public static final class ZoneReadException extends RuntimeException {
        public ZoneReadException(String message) { super(message); }
    }

    /** The maximum number of 100-record pages that are read: beyond that, the zone cannot be said to be read in full. */
    static final int MAX_PAGES = 10;

    /**
     * Formats the content of a TXT record according to the DNS standard:
     *  - DNS character-string strings are limited to 255 octets (RFC 1035 section 3.3.14).
     *  - Longer values must be split into several consecutive strings, each
     *    enclosed in double quotes and separated by a space.
     *  - The resolver automatically concatenates the strings on receipt.
     *
     * Examples:
     *   "v=spf1 ip4:1.2.3.4 ~all"                                 (short: a single string)
     *   "v=DKIM1; k=rsa; p=MIIBIj...EwppK2GMQ" "iVl0JWQ...wIDAQAB" (DKIM 2048 = 2 strings)
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
     * Looks up a TXT record by exact name. Useful to find again a DNS record
     * whose ID we have not stored (e.g. an original DKIM record created
     * manually before the Cloudflare integration).
     *
     * @return RecordOp with success=true and recordId set if found,
     *         success=false with error="not found" if it does not exist, or
     *         success=false with error=... in case of an API error.
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
     * Lists all the TXT records of the zone whose name contains a specific substring.
     * The comparison is case-insensitive (Cloudflare normalizes DNS names to lowercase).
     * Usage example: {@code listTxtRecordsContaining(token, zoneId, "_domainkey.")} to find
     * all the DKIM records (both active and orphaned) of a domain.
     * Iterates with pagination up to 1000 records.
     * If {@code nameSubstring} is null or empty, returns ALL the TXT records of the zone.
     *
     * @throws ZoneReadException if the zone could not be read in full: never an empty list in place of an error
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
     * The comment of the records that the panel creates, for whoever looks at them in the Cloudflare
     * dashboard. The panel does not read it back (it reads only the comments of DKIM records, see
     * DkimManager). Records created before the end of October 2026 still have the Italian
     * text, and keep it: changing it would mean writing to Cloudflare at startup for a
     * comment.
     */
    static final String RECORD_COMMENT = "Created by " + org.daemoxcp.mail.system.Product.NAME;

    /**
     * The records of this zone that have the old comment (in Italian until 2026-10-30, legacy-names.json,
     * cloudflareRecordComments) get the current one. The owner, on 2026-11-09: "when you add a record, do not use
     * Italian in comments like `Creato dal pannello di posta` but always and in any case English" (finding 211).
     * Only the comment changes, with PATCH: name, content, TTL and proxy stay as they are, so DNS does not change.
     * Returns how many it changed, or -1 if Cloudflare did not answer as it should (it retries at the next startup).
     */
    public int renameLegacyComments(String token, String zoneId) {
        int renamed = 0;
        try {
            for (String[] pair : org.daemoxcp.mail.system.LegacyNames.pairs("cloudflareRecordComments")) {
                // The search uses Cloudflare's exact filter, and it is checked again here: only what has that text is
                // touched. A changed record drops out of the filter, so the first page is always reread while some
                // remain; a round that changes nothing ends it (no empty rounds).
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
     * Creates a CNAME. Always with proxied=false, and it is not a preference: a proxied
     * CNAME no longer answers with the CNAME but with Cloudflare's addresses, so
     * the mail client would no longer find the host it is looking for and the panel's check
     * would say "points elsewhere". The gray cloud here is not advice, it is a requirement.
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
     * An A or AAAA record (ServerAddresses and HostRecords). The mail name always goes without proxy: Cloudflare does
     * not let port 25 through (developers.cloudflare.com/dns/troubleshooting/email-issues/), and the name an MX points
     * to must be "DNS only". The panel and the webmail, instead, do (2096 and 8443 are ports that Cloudflare forwards).
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
     * Creates an SRV in the form documented by Cloudflare: full name in "name" and only the
     * priority/weight/port/target fields inside "data".
     *
     * Example from the official documentation:
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
     * Changes the content of an existing TXT record.
     *
     * Method and path taken from the official documentation, read on the rendered page:
     *   PATCH /zones/{zone_id}/dns_records/{dns_record_id}  -  "Update an existing DNS record"
     * The body follows the form of the example on the same page, which gives type, name and
     * content. PATCH leaves alone what is not named, so the comment and the other fields
     * of the record stay where they are.
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
     * Turns the Cloudflare proxy on or off on a record.
     *
     * It is needed for the names that must point STRAIGHT to the server: mta-sts and autoconfig. With the
     * proxy on, whoever queries them talks to Cloudflare, which in turn must be able to
     * validate the certificate of the origin: a second piece that has to work, and that
     * when it does not work answers 526 without explaining what is missing. Direct means fewer things
     * that can break.
     *
     * PATCH is used, which touches only the given field and leaves name, content and TTL alone.
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

    /** Fixes an existing CNAME: right target and proxy off. */
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

    /** Fixes an existing SRV: right target and port. */
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
     * All the records of the zone, of any type, with the type reported.
     *
     * It is necessary to look ALSO at types other than the one to be created: DNS does not
     * allow a CNAME next to other data on the same name, so an A record on
     * "autoconfig" makes Cloudflare reject the CNAME. Better to say so beforehand, explaining
     * why, than to show the raw error of the API.
     *
     * @throws ZoneReadException if the zone could not be read in full: never an empty list in place of an error
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
                    // The structured fields, when present, are worth more than the string.
                    JSONObject data = r.optJSONObject("data");
                    if (data != null) {
                        if (data.has("priority")) info.srvPriority = data.optInt("priority");
                        if (data.has("weight"))   info.srvWeight     = data.optInt("weight");
                        if (data.has("port"))     info.srvPort    = data.optInt("port");
                        String targetValue = data.optString("target", "");
                        if (!targetValue.isEmpty()) info.srvDestination = targetValue;
                    }
                    // Cloudflare also exposes the priority outside "data".
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
         * SRV: the fields that Cloudflare returns in "data", plus the priority.
         *
         * For an SRV the "content" field is a convenience string, and Cloudflare puts in it only
         * WEIGHT, PORT and TARGET: the priority lives in a field of its own. Whoever reads the
         * priority from "content" reads it from the wrong place, and whoever demands four fields
         * from a string that has three does not get a wrong value, they get NULL, that is,
         * "record not recognized". That is how the panel rewrote, on every run, two SRV records
         * that were already right, announcing each time a difference that did not exist.
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
            // The token that Cloudflare does not recognize: its sentence alone ("Invalid request headers (code 6003)")
            // does not tell whoever installs what to do (finding 250, tested on the VM with a fake token)
            return TOKEN_REFUSED.contains(e.optInt("code", 0)) ? I18n.tr("server.cfm.tokenRefused", java.util.Map.of("m", raw)) : raw;
        }
        return I18n.tr("server.cfm.unknown");
    }

    /**
     * The codes with which Cloudflare rejects the token itself, not the operation: 6003 and 6111 (invalid header: token
     * incomplete, with spaces or extra characters), 1000 (invalid token), 9109 (token invalid or without access),
     * 10000 (authentication).
     */
    private static final java.util.Set<Integer> TOKEN_REFUSED = java.util.Set.of(6003, 6111, 1000, 9109, 10000);

    /** Masks a token, showing only the last 4 characters. */
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
