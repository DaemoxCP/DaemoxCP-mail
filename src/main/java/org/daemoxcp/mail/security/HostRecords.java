package org.daemoxcp.mail.security;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.daemoxcp.mail.database.MailDatabase;

/**
 * I record A e AAAA dei nomi del server su Cloudflare: quello della posta (senza proxy), e per un server solo IPv6 anche
 * quelli del pannello e della webmail (col proxy, che Cloudflare fa passare sulla 2096 e sulla 8443). Usati dalla guida
 * degli indirizzi (ServerAddresses).
 *
 * La regola di AutoDns vale anche qui: non si sovrascrive mai un record che c'e'. Se il nome ha gia' un A (o AAAA) con
 * un altro indirizzo, il pannello lo dice e si ferma: puo' essere un altro server, ed e' l'amministratore a decidere.
 * Togliere toglie solo il record che punta all'indirizzo del server, mai gli altri.
 *
 * L'account Cloudflare: quello del dominio del pannello a cui il nome appartiene (mail.example.org -> example.org); se il
 * dominio non e' fra quelli del pannello, l'unico account che vede la zona. Se nessuno la vede, l'amministratore crea il
 * record a mano e la guida controlla nel DNS pubblico.
 */
public final class HostRecords {

    /** Esito: fatto o no, chiave della lingua, valori per il testo. */
    public record Outcome(boolean ok, String key, Map<String, String> args) {
        static Outcome ok(String key, Map<String, String> args) { return new Outcome(true, key, args); }
        static Outcome no(String key, Map<String, String> args) { return new Outcome(false, key, args); }
    }

    /** Dove scrivere: il token dell'account, la zona. */
    record Target(String token, String zoneId, String account) {}

    private HostRecords() {}

    /**
     * Se il DNS pubblico da' gia' quell'indirizzo per quel nome, chiesto ai server della zona (FreshDns): un record
     * appena scritto su Cloudflare si vede subito, non quando scade il «nessun record» ricordato dal risolutore.
     */
    public static boolean published(String host, String type, String ip) {
        if (!validHost(host)) return false;
        return DnsRecordsGenerator.containsAddress(FreshDns.query(type, host), ip);
    }

    /** Se il nome ha un record di quel tipo, qualunque indirizzo (FreshDns): per sapere se c'e' ancora un A da togliere. */
    public static boolean hasAny(String host, String type) {
        if (!validHost(host)) return false;
        for (String l : FreshDns.query(type, host).split("\n"))
            if (l.trim().matches("[0-9A-Fa-f:.]{2,45}")) return true;
        return false;
    }

    /** Se c'e' un account Cloudflare che vede la zona di questo nome. */
    public static boolean canWrite(MailDatabase db, CloudflareManager cf, String host) {
        return target(db, cf, host) != null;
    }

    /**
     * Se su Cloudflare il nome ha un record di quel tipo verso quell'indirizzo (per i nomi col proxy il DNS pubblico da'
     * gli indirizzi di Cloudflare, non quello del server: si guarda nella zona). Null se nessun account vede la zona.
     */
    public static Outcome check(MailDatabase db, CloudflareManager cf, String host, String type, String ip) {
        Map<String, String> args = Map.of("h", String.valueOf(host), "t", type, "ip", String.valueOf(ip));
        Target t = target(db, cf, host);
        if (t == null || ip == null) return null;
        try {
            for (CloudflareManager.DnsRecordInfo r : sameName(cf.listRecords(t.token(), t.zoneId()), host, type))
                if (DnsRecordsGenerator.containsAddress(r.content, ip)) return Outcome.ok("server.hr.already", args);
            return Outcome.no("server.hr.notThere", args);
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** Crea il record (o lo trova gia' giusto). proxied: false per la posta, true per pannello e webmail. */
    public static Outcome ensure(MailDatabase db, CloudflareManager cf, String host, String type, String ip, boolean proxied) {
        Map<String, String> args = Map.of("h", String.valueOf(host), "t", type, "ip", String.valueOf(ip));
        if (!validHost(host) || ip == null) return Outcome.no("server.hr.badInput", args);
        Target t = target(db, cf, host);
        if (t == null) return Outcome.no("server.hr.noAccount", args);
        List<CloudflareManager.DnsRecordInfo> same;
        try {
            same = sameName(cf.listRecords(t.token(), t.zoneId()), host, type);
        } catch (RuntimeException e) {
            return Outcome.no("server.hr.readFailed", args);
        }
        for (CloudflareManager.DnsRecordInfo r : same) {
            if (DnsRecordsGenerator.containsAddress(r.content, ip)) {
                if (r.proxied != proxied) cf.setProxy(t.token(), t.zoneId(), r.id, proxied);
                return Outcome.ok("server.hr.already", args);
            }
        }
        if (!same.isEmpty()) return Outcome.no("server.hr.otherRecord", Map.of("h", host, "t", type, "ip", ip, "other", same.get(0).content));
        CloudflareManager.RecordOp op = cf.createAddressRecord(t.token(), t.zoneId(), host, type, ip, proxied);
        return op.success ? Outcome.ok("server.hr.created", args)
                : Outcome.no("server.hr.failed", Map.of("h", host, "t", type, "ip", ip, "e", String.valueOf(op.error)));
    }

    /** Toglie il record di quel tipo che punta all'indirizzo del server; gli altri restano. */
    public static Outcome remove(MailDatabase db, CloudflareManager cf, String host, String type, String ip) {
        Map<String, String> args = Map.of("h", String.valueOf(host), "t", type, "ip", String.valueOf(ip));
        if (!validHost(host) || ip == null) return Outcome.no("server.hr.badInput", args);
        Target t = target(db, cf, host);
        if (t == null) return Outcome.no("server.hr.noAccount", args);
        List<CloudflareManager.DnsRecordInfo> same;
        try {
            same = sameName(cf.listRecords(t.token(), t.zoneId()), host, type);
        } catch (RuntimeException e) {
            return Outcome.no("server.hr.readFailed", args);
        }
        for (CloudflareManager.DnsRecordInfo r : same) {
            if (!DnsRecordsGenerator.containsAddress(r.content, ip)) continue;
            CloudflareManager.RecordOp op = cf.deleteRecord(t.token(), t.zoneId(), r.id);
            return op.success ? Outcome.ok("server.hr.removed", args)
                    : Outcome.no("server.hr.failed", Map.of("h", host, "t", type, "ip", ip, "e", String.valueOf(op.error)));
        }
        return Outcome.ok("server.hr.notThere", args);
    }

    static List<CloudflareManager.DnsRecordInfo> sameName(List<CloudflareManager.DnsRecordInfo> all, String host, String type) {
        List<CloudflareManager.DnsRecordInfo> out = new ArrayList<>();
        if (all == null) return out;
        for (CloudflareManager.DnsRecordInfo r : all)
            if (type.equals(r.type) && r.name != null && r.name.equalsIgnoreCase(host)) out.add(r);
        return out;
    }

    /** L'account e la zona: quello del dominio del pannello a cui appartiene il nome, oppure l'unico che vede la zona. */
    static Target target(MailDatabase db, CloudflareManager cf, String host) {
        if (db == null || cf == null || !validHost(host)) return null;
        String h = host.toLowerCase(Locale.ROOT);
        try {
            for (MailDatabase.Domain d : db.getDomains()) {
                String dn = d.domain == null ? "" : d.domain.toLowerCase(Locale.ROOT);
                if (dn.isEmpty() || !(h.equals(dn) || h.endsWith("." + dn))) continue;
                MailDatabase.CloudflareAccount acct = cf.getAccountForDomain(d.id);
                if (acct == null) continue;
                CloudflareManager.ZoneLookup zl = cf.findZone(acct.apiToken, h);
                if (zl.found) return new Target(acct.apiToken, zl.zoneId, acct.label);
            }
            Target only = null;
            for (MailDatabase.CloudflareAccount acct : cf.listAccounts()) {
                CloudflareManager.ZoneLookup zl = cf.findZone(acct.apiToken, h);
                if (!zl.found) continue;
                if (only != null) return null;   // piu' di uno: non si sceglie a caso
                only = new Target(acct.apiToken, zl.zoneId, acct.label);
            }
            return only;
        } catch (Exception e) {
            return null;
        }
    }

    static boolean validHost(String host) {
        return host != null && host.matches("[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?") && host.contains(".");
    }
}
