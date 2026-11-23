package org.daemoxcp.mail.webserver;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Is the Host header of the request the one through which this panel is reached?
 *
 * <p>Before, nobody asked this question: any Host was fine. It is not a
 * formality, because the <strong>rpId</strong> and the <strong>origin</strong> of passkeys
 * come from Host ({@link org.daemoxcp.mail.security.PasskeyService}), and because a panel that
 * answers to any name is a panel that can be put under someone else's name.
 * PasskeyService checks that the Host <em>looks like</em> a DNS name, not that it is the name of
 * this panel: {@code evil.example} passes that check without difficulty.
 *
 * <p>Three choices, all three deliberate:
 *
 * <ul>
 *   <li><strong>Exact comparison of the name</strong>, not a containment check. With
 *       {@code panel.esempio.it} configured, a containment comparison would also let through
 *       {@code panel.esempio.it.qualcunaltro.com}, that is, a name that anyone can
 *       register.</li>
 *   <li><strong>The port stays out</strong> of the comparison: in front of the panel there may be
 *       a proxy that answers on 443 while the panel listens on 2096.</li>
 *   <li><strong>Never a DNS resolution.</strong> Calling {@code InetAddress.getByName} on a
 *       name would mean querying DNS at every request and, above all, letting through
 *       any name made to point at this machine: that is, exactly the rebinding that
 *       this check defends against. A name is recognised beforehand, from the text.</li>
 * </ul>
 *
 * <p>Two IP addresses, on the other hand, are compared <em>as addresses</em>: {@code ::1} and
 * {@code 0:0:0:0:0:0:0:1} are the same address and as text they look different.
 *
 * <p>A separate case, and not a theoretical one: the configured address is a <em>wildcard</em>. The
 * mail panel installer writes exactly {@code 0.0.0.0} into {@code panel_host} after
 * installation. {@code 0.0.0.0} is not a name, it is "listen on every address": no
 * browser will ever send {@code Host: 0.0.0.0}, so comparing it with the Host could
 * never succeed and the panel would refuse every request. So we accept what
 * "listen everywhere" can really mean: {@code localhost}, or an IP address <em>of
 * this machine</em>. Not a name, because any name is the rebinding described above.
 */
public final class HostCheck {

    private HostCheck() {}

    /** The values that mean "listen on every address", not "the panel is called this". */
    private static final Set<String> WILDCARD_HOSTS =
            Set.of("", "0.0.0.0", "::", "[::]", "*", "0:0:0:0:0:0:0:0");

    public static boolean isWildcardHost(String configuredHost) {
        return configuredHost == null || WILDCARD_HOSTS.contains(configuredHost.trim().toLowerCase());
    }

    /** The addresses of this machine, reread every minute: interfaces change rarely. */
    private static volatile Set<String> localAddresses = Set.of();
    private static volatile long localAddressesRead = 0;

    public static Set<String> localAddresses() {
        long now = System.currentTimeMillis();
        if (now - localAddressesRead < 60_000 && !localAddresses.isEmpty()) return localAddresses;
        Set<String> found = new HashSet<>();
        // The loopback is there anyway: if reading the interfaces failed, an empty set
        // would mean refusing 127.0.0.1 too, that is, locking out even whoever is on the
        // machine -- and the webmail with them. A read error must not switch off the panel.
        found.add("127.0.0.1");
        found.add("0:0:0:0:0:0:0:1");
        try {
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces()))
                for (InetAddress a : Collections.list(ni.getInetAddresses()))
                    found.add(a.getHostAddress().replaceAll("%.*$", "").toLowerCase());
        } catch (Exception e) {
            System.out.println("WARNING: cannot read this machine's addresses: " + e.getMessage());
        }
        localAddresses = found;
        localAddressesRead = now;
        return found;
    }

    /**
     * The normal form of an IP address written out in full, or null if that is not an
     * address but a name. Nothing is ever resolved via DNS: a colon means IPv6,
     * four groups of digits separated by dots mean IPv4, everything else is a name.
     */
    static String literalIp(String name) {
        if (name == null || name.isEmpty()) return null;
        boolean v6 = name.indexOf(':') >= 0;
        if (!v6 && !name.matches("\\d{1,3}(\\.\\d{1,3}){3}")) return null;
        try {
            return InetAddress.getByName(name).getHostAddress().replaceAll("%.*$", "").toLowerCase();
        } catch (Exception e) {
            return null;
        }
    }

    /** The name inside a Host header, without port, lowercase and without the trailing dot. */
    static String hostName(String header) {
        if (header == null) return "";
        String h = header.trim();
        if (h.startsWith("[")) {                       // IPv6 in brackets: [::1] or [::1]:2096
            int close = h.indexOf(']');
            if (close > 0) return h.substring(1, close).toLowerCase();
        }
        int colon = h.indexOf(':');
        // A bare IPv6 has more than one ':' and is not split: the port, if present, comes after the last
        // ']', which is not there here.
        if (colon >= 0 && h.indexOf(':', colon + 1) < 0) h = h.substring(0, colon);
        if (h.endsWith(".")) h = h.substring(0, h.length() - 1);   // the DNS root dot
        return h.toLowerCase();
    }

    /** Does this Host reach this panel? */
    public static boolean allowed(String hostHeader, String configuredHost) {
        String name = hostName(hostHeader);
        if (name.isEmpty()) return false;
        if (!isWildcardHost(configuredHost)) {
            String configured = hostName(configuredHost);
            // Two IP addresses are compared as addresses, not as text; two names as
            // text. That way the panel configured at ::1 also answers to 0:0:0:0:0:0:0:1.
            String a = literalIp(name), b = literalIp(configured);
            return a != null && b != null ? a.equals(b) : name.equals(configured);
        }
        if (name.equals("localhost")) return true;
        String ip = literalIp(name);
        return ip != null && localAddresses().contains(ip);
    }

    /** Why this request was refused, for the log (not for whoever sent it). */
    public static String why(String hostHeader, String configuredHost) {
        return "Request refused: Host is " + hostHeader + ", "
                + (isWildcardHost(configuredHost)
                   ? "and the panel address is " + configuredHost + " (listen everywhere), so only"
                     + " localhost and this machine's own addresses are accepted "
                     + localAddresses() + ". Set the panel's name in the terminal menu, option 2 (Edit Panel Configuration)."
                   : "while the panel answers to " + configuredHost + ".");
    }
}
