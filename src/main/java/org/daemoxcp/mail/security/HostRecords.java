package org.daemoxcp.mail.security;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.daemoxcp.mail.database.MailDatabase;

/**
 * The A and AAAA records of the server's names on Cloudflare: the mail one (without proxy), and for an IPv6-only
 * server also those of the panel and the webmail (with the proxy, which Cloudflare passes through on 2096 and 8443).
 * Used by the addresses guide (ServerAddresses).
 *
 * The AutoDns rule applies here too: an existing record is never overwritten. If the name already has an A (or AAAA)
 * with another address, the panel says so and stops: it may be another server, and it is up to the administrator to
 * decide. Removing removes only the record that points to the server's address, never the others.
 *
 * The Cloudflare account: the one of the panel's domain the name belongs to (mail.example.org -> example.org); if the
 * domain is not among the panel's ones, the only account that sees the zone. If none sees it, the administrator
 * creates the record by hand and the guide checks in the public DNS.
 */
public final class HostRecords {

    /** Outcome: done or not, language key, values for the text. */
    public record Outcome(boolean ok, String key, Map<String, String> args) {
        static Outcome ok(String key, Map<String, String> args) { return new Outcome(true, key, args); }
        static Outcome no(String key, Map<String, String> args) { return new Outcome(false, key, args); }
    }

    /** Where to write: the account's token, the zone. */
    record Target(String token, String zoneId, String account) {}

    private HostRecords() {}

    /**
     * Whether the public DNS already gives that address for that name, asked of the zone's servers (FreshDns): a
     * record just written on Cloudflare is seen right away, not when the "no record" remembered by the resolver
     * expires.
     */
    public static boolean published(String host, String type, String ip) {
        if (!validHost(host)) return false;
        return DnsRecordsGenerator.containsAddress(FreshDns.query(type, host), ip);
    }

    /**
     * Whether the name has a record of that type, any address (FreshDns): to know whether there is still an A to
     * remove.
     */
    public static boolean hasAny(String host, String type) {
        if (!validHost(host)) return false;
        for (String l : FreshDns.query(type, host).split("\n"))
            if (l.trim().matches("[0-9A-Fa-f:.]{2,45}")) return true;
        return false;
    }

    /** Whether there is a Cloudflare account that sees the zone of this name. */
    public static boolean canWrite(MailDatabase db, CloudflareManager cf, String host) {
        return target(db, cf, host) != null;
    }

    /**
     * Whether on Cloudflare the name has a record of that type pointing to that address (for proxied names the public
     * DNS gives Cloudflare's addresses, not the server's: the zone is looked at). Null if no account sees the zone.
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

    /** Creates the record (or finds it already correct). proxied: false for mail, true for panel and webmail. */
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

    /** Removes the record of that type that points to the server's address; the others stay. */
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

    /** The account and the zone: the one of the panel's domain the name belongs to, or the only one that sees the zone. */
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
                if (only != null) return null;   // more than one: we do not pick at random
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
