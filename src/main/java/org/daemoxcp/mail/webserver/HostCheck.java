package org.daemoxcp.mail.webserver;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * L'intestazione Host della richiesta e' quella con cui si raggiunge questo pannello?
 *
 * <p>Prima questa domanda non se la faceva nessuno: qualunque Host andava bene. Non e' una
 * formalita', perche' da Host vengono l'<strong>rpId</strong> e l'<strong>origine</strong>
 * delle passkey ({@link org.daemoxcp.mail.security.PasskeyService}), e perche' un pannello che
 * risponde a qualunque nome e' un pannello che si puo' mettere sotto un nome altrui.
 * PasskeyService controlla che l'Host <em>somigli</em> a un nome DNS, non che sia il nome di
 * questo pannello: {@code evil.example} passa quel controllo senza difficolta'.
 *
 * <p>Tre scelte, tutte e tre deliberate:
 *
 * <ul>
 *   <li><strong>Confronto esatto sul nome</strong>, non un contenimento. Con
 *       {@code panel.esempio.it} configurato, un confronto per contenimento farebbe passare
 *       anche {@code panel.esempio.it.qualcunaltro.com}, cioe' un nome che registra chi
 *       vuole.</li>
 *   <li><strong>La porta resta fuori</strong> dal confronto: davanti al pannello puo' esserci
 *       un proxy che risponde sulla 443 mentre il pannello ascolta sulla 2096.</li>
 *   <li><strong>Mai una risoluzione DNS.</strong> Chiamare {@code InetAddress.getByName} su un
 *       nome vorrebbe dire interrogare il DNS a ogni richiesta e, soprattutto, far passare
 *       qualunque nome fatto puntare a questa macchina: cioe' esattamente il rebinding da cui
 *       questo controllo difende. Un nome lo si riconosce prima, dal testo.</li>
 * </ul>
 *
 * <p>Due indirizzi IP invece si confrontano <em>come indirizzi</em>: {@code ::1} e
 * {@code 0:0:0:0:0:0:0:1} sono lo stesso indirizzo e come testo sembrano diversi.
 *
 * <p>Caso a parte, e non teorico: l'indirizzo configurato e' un <em>wildcard</em>. L'installatore
 * del pannello mail scrive proprio {@code 0.0.0.0} in {@code panel_host} dopo
 * l'installazione. {@code 0.0.0.0} non e' un nome, e' "ascolta su ogni indirizzo": nessun
 * browser mandera' mai {@code Host: 0.0.0.0}, quindi confrontarlo con l'Host non potrebbe
 * riuscire mai e il pannello rifiuterebbe ogni richiesta. Allora si accetta quello che
 * "ascolta ovunque" puo' voler dire davvero: {@code localhost}, o un indirizzo IP <em>di
 * questa macchina</em>. Un nome no, perche' un nome qualunque e' il rebinding di cui sopra.
 */
public final class HostCheck {

    private HostCheck() {}

    /** I valori che vogliono dire "ascolta su ogni indirizzo", non "il pannello si chiama cosi'". */
    private static final Set<String> WILDCARD_HOSTS =
            Set.of("", "0.0.0.0", "::", "[::]", "*", "0:0:0:0:0:0:0:0");

    public static boolean isWildcardHost(String configuredHost) {
        return configuredHost == null || WILDCARD_HOSTS.contains(configuredHost.trim().toLowerCase());
    }

    /** Gli indirizzi di questa macchina, riletti ogni minuto: le interfacce cambiano di rado. */
    private static volatile Set<String> localAddresses = Set.of();
    private static volatile long localAddressesRead = 0;

    public static Set<String> localAddresses() {
        long now = System.currentTimeMillis();
        if (now - localAddressesRead < 60_000 && !localAddresses.isEmpty()) return localAddresses;
        Set<String> found = new HashSet<>();
        // Il loopback c'e' comunque: se la lettura delle interfacce fallisse, un insieme vuoto
        // vorrebbe dire rifiutare anche 127.0.0.1, cioe' chiudere fuori anche chi e' sulla
        // macchina -- e con lui la webmail. Un errore di lettura non deve spegnere il pannello.
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
     * La forma normale di un indirizzo IP scritto per esteso, o null se quello non e' un
     * indirizzo ma un nome. Non si risolve mai niente col DNS: due punti vuol dire IPv6,
     * quattro gruppi di cifre separati da punti vuol dire IPv4, tutto il resto e' un nome.
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

    /** Il nome dentro un'intestazione Host, senza porta, minuscolo e senza il punto finale. */
    static String hostName(String header) {
        if (header == null) return "";
        String h = header.trim();
        if (h.startsWith("[")) {                       // IPv6 fra parentesi: [::1] oppure [::1]:2096
            int close = h.indexOf(']');
            if (close > 0) return h.substring(1, close).toLowerCase();
        }
        int colon = h.indexOf(':');
        // Un IPv6 nudo ha piu' di un ':' e non si divide: la porta, se c'e', sta dopo l'ultimo
        // ']', che qui non c'e'.
        if (colon >= 0 && h.indexOf(':', colon + 1) < 0) h = h.substring(0, colon);
        if (h.endsWith(".")) h = h.substring(0, h.length() - 1);   // il punto della radice DNS
        return h.toLowerCase();
    }

    /** Questo Host raggiunge questo pannello? */
    public static boolean allowed(String hostHeader, String configuredHost) {
        String name = hostName(hostHeader);
        if (name.isEmpty()) return false;
        if (!isWildcardHost(configuredHost)) {
            String configured = hostName(configuredHost);
            // Due indirizzi IP si confrontano come indirizzi, non come testo; due nomi come
            // testo. Cosi' il pannello configurato a ::1 risponde anche a 0:0:0:0:0:0:0:1.
            String a = literalIp(name), b = literalIp(configured);
            return a != null && b != null ? a.equals(b) : name.equals(configured);
        }
        if (name.equals("localhost")) return true;
        String ip = literalIp(name);
        return ip != null && localAddresses().contains(ip);
    }

    /** Perche' questa richiesta e' stata rifiutata, per il registro (non per chi l'ha mandata). */
    public static String why(String hostHeader, String configuredHost) {
        return "Request refused: Host is " + hostHeader + ", "
                + (isWildcardHost(configuredHost)
                   ? "and the panel address is " + configuredHost + " (listen everywhere), so only"
                     + " localhost and this machine's own addresses are accepted "
                     + localAddresses() + ". Set the panel's name in the terminal menu, option 2 (Edit Panel Configuration)."
                   : "while the panel answers to " + configuredHost + ".");
    }
}
