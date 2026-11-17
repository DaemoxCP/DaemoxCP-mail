package org.daemoxcp.mail.security;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;

/**
 * Chi il pannello riconosce come Cloudflare: l'unico da cui accetta l'intestazione CF-Connecting-IP con
 * l'indirizzo vero di chi bussa (r18). Da qualunque altro indirizzo, loopback e reti private comprese,
 * le intestazioni di inoltro (CF-Connecting-IP, X-Forwarded-For, X-Real-IP) sono testo che chiunque puo'
 * scrivere, e conta solo l'indirizzo TCP.
 *
 * Prima ci si fidava anche del loopback e delle reti private (10/8, 172.16/12, 192.168/16, fc00::/7):
 * bastava un'altra macchina nella stessa rete privata del fornitore, o una richiesta alla superficie
 * sulla 443 (nginx passa al pannello le intestazioni del client), per scegliersi l'indirizzo nei registri e
 * nei limiti dei tentativi.
 *
 * Le IP range Cloudflare possono cambiare nel tempo: la scheda "Chi il pannello riconosce come
 * Cloudflare" le confronta con quelle ufficiali.
 *   https://www.cloudflare.com/ips-v4
 *   https://www.cloudflare.com/ips-v6
 */
public final class TrustedProxy {
    private TrustedProxy() {}

    // Cloudflare IPv4 ranges — https://www.cloudflare.com/ips-v4
    private static final List<String> CLOUDFLARE_V4 = Arrays.asList(
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22"
    );

    // Cloudflare IPv6 ranges — https://www.cloudflare.com/ips-v6
    private static final List<String> CLOUDFLARE_V6 = Arrays.asList(
        "2400:cb00::/32",
        "2606:4700::/32",
        "2803:f800::/32",
        "2405:b500::/32",
        "2405:8100::/32",
        "2a06:98c0::/29",
        "2c0f:f248::/32"
    );

    /**
     * Quando la lista qui sopra e' stata confrontata con quella ufficiale, da un essere umano.
     *
     * Il 02/09/2026 il confronto e' stato eseguito davvero contro cloudflare.com/ips-v4 e
     * ips-v6: 15 intervalli IPv4 e 7 IPv6, nessuna divergenza in nessuna delle due direzioni.
     * La lista non e' cambiata da dicembre — e' stata verificata, che e' un'altra cosa e vale
     * la pena distinguerla: "scritta allora" non dice se sia ancora giusta.
     */
    public static final String UPDATED_ON = "2026-09-02";

    /** Gli intervalli compilati dentro il pannello: quelli da cui si accettano le
     *  intestazioni di inoltro. Si espongono per poterli MOSTRARE, non solo confrontare:
     *  una lista che decide di chi fidarsi e che nessuno puo' leggere e' una regola segreta. */
    public static List<String> cloudflareV4() { return List.copyOf(CLOUDFLARE_V4); }
    public static List<String> cloudflareV6() { return List.copyOf(CLOUDFLARE_V6); }

    /**
     * L'indirizzo appartiene a Cloudflare? Solo gli intervalli pubblicati, confrontati bit per bit.
     * @param ipString l'IP da verificare in formato testuale (mai un nome: non si interroga il DNS)
     */
    public static boolean isCloudflare(String ipString) {
        if (ipString == null || ipString.isEmpty() || !InputValidator.isValidIp(ipString.trim())) return false;
        try {
            byte[] addrBytes = InetAddress.getByName(ipString.trim()).getAddress();
            List<String> ranges = addrBytes.length == 4 ? CLOUDFLARE_V4 : addrBytes.length == 16 ? CLOUDFLARE_V6 : List.of();
            for (String cidr : ranges) {
                if (isInRange(addrBytes, cidr)) return true;
            }
        } catch (UnknownHostException e) {
            return false;
        }
        return false;
    }

    /**
     * L'indirizzo di chi bussa (r18): quello di CF-Connecting-IP se la connessione arriva da Cloudflare e
     * l'intestazione e' un indirizzo valido, altrimenti quello TCP. Nient'altro: X-Forwarded-For e
     * X-Real-IP non contano da nessuno, perche' Cloudflare manda sempre CF-Connecting-IP.
     */
    public static String clientAddress(String tcpAddress, String cfConnectingIp) {
        if (isCloudflare(tcpAddress) && cfConnectingIp != null) {
            String claimed = cfConnectingIp.trim();
            if (InputValidator.isValidIp(claimed)) return claimed;
        }
        return tcpAddress;
    }

    /**
     * Confronta i bit di addrBytes contro un CIDR (es. "173.245.48.0/20").
     */
    private static boolean isInRange(byte[] addrBytes, String cidr) {
        try {
            int slashIdx = cidr.indexOf('/');
            if (slashIdx < 0) return false;
            String network = cidr.substring(0, slashIdx);
            int prefixLen = Integer.parseInt(cidr.substring(slashIdx + 1));

            byte[] networkBytes = InetAddress.getByName(network).getAddress();
            if (addrBytes.length != networkBytes.length) return false;

            int fullBytes = prefixLen / 8;
            int remainingBits = prefixLen % 8;

            for (int i = 0; i < fullBytes; i++) {
                if (addrBytes[i] != networkBytes[i]) return false;
            }
            if (remainingBits > 0 && fullBytes < addrBytes.length) {
                int mask = 0xFF << (8 - remainingBits);
                if ((addrBytes[fullBytes] & mask) != (networkBytes[fullBytes] & mask)) return false;
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
