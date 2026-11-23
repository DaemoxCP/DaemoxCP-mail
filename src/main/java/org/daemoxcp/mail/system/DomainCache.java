package org.daemoxcp.mail.system;

import org.daemoxcp.mail.Main;

import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

/**
 * The list of managed domains, kept in memory for a few seconds.
 *
 * Why it exists. The panel's two public routes -- the configuration for Thunderbird and
 * the MTA-STS policy -- are not authenticated, and cannot be: they are called by mail clients
 * and sending servers that have no credentials. But every request made a query to the
 * database to know whether the domain was ours.
 *
 * Anyone can call those routes as many times as they like. Without this cache, a thousand
 * requests per second become a thousand queries per second, and what goes down is not the web
 * page: it is MySQL, that is the MAIL. A public endpoint that touches the database on every hit
 * is a lever to shut down the service, not a convenience.
 *
 * The list of domains changes rarely -- when one is added -- so thirty seconds of delay
 * bother nobody: a newly created domain answers half a minute later.
 */
public class DomainCache {

    private static final long VALIDITY_MS = 30_000;

    private static volatile Set<String> list = null;
    private static volatile long expiry = 0;

    private DomainCache() {}

    /** The managed domains, in lower case. Re-reads from the database only when the copy has expired. */
    public static Set<String> domains() {
        long now = System.currentTimeMillis();
        Set<String> copy = list;
        if (copy != null && now < expiry) return copy;

        Set<String> fresh = new LinkedHashSet<>();
        try {
            // Only the names: these routes are public, and in the web part their procedure does not ask for a session.
            for (String d : Main.mailDatabase.getDomainNames())
                if (d != null && !d.isBlank())
                    fresh.add(d.trim().toLowerCase(Locale.ROOT));
        } catch (Exception e) {
            // If the database does not answer, the old copy is kept instead of emptying
            // the list: answering with data from thirty seconds ago is better than answering
            // "this domain does not exist" to a sending server because of a problem of ours.
            if (copy != null) {
                expiry = now + VALIDITY_MS;
                return copy;
            }
            return Set.of();
        }
        list = fresh;
        expiry = now + VALIDITY_MS;
        return fresh;
    }

    /** The name as it is in the database, if the domain is managed. Otherwise null. */
    public static String managed(String required) {
        if (required == null) return null;
        String r = required.trim().toLowerCase(Locale.ROOT);
        int p = r.indexOf(':');
        if (p > 0) r = r.substring(0, p);
        if (r.isEmpty()) return null;
        return domains().contains(r) ? r : null;
    }

    /** To be called when the domains change, so as not to wait for the expiry. */
    public static void invalidate() {
        expiry = 0;
    }
}
