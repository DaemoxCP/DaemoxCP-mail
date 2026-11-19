package org.daemoxcp.mail.system;

import java.util.ArrayList;
import java.util.List;

/**
 * La guida degli indirizzi: dallo stato del server e dall'obiettivo (IPv4 e IPv6, solo IPv4, solo IPv6) i passi, in
 * ordine, ognuno «fatto», «adesso», «dopo» o «bloccato» col motivo. Il pannello mostra il passo di adesso con UN
 * pulsante (guided-one-step-with-logs); i passi che deve fare l'amministratore fuori dal pannello (il DNS inverso nella
 * console del provider, l'IPv4 che solo il provider assegna o toglie) hanno «Controlla di nuovo».
 *
 * Solo logica, nessun comando: i fatti li raccoglie chi chiama (ServerAddresses, i controlli DNS), cosi' ogni
 * combinazione si prova senza toccare una rete.
 *
 * L'ordine, scelto per non perdere posta e per non chiudere fuori nessuno:
 *  - verso IPv4 e IPv6: prima ogni famiglia completa (indirizzo che esce su internet, il firewall del provider che lascia
 *    entrare l'IPv6, DNS inverso, record), poi la posta in tutte e due. Il firewall del provider (Hetzner Cloud Firewalls
 *    e simili) dal server non si vede: senza l'IPv6 aperto la posta in IPv6 non arriva (chi spedisce riprova in IPv4, in
 *    ritardo), quindi lo conferma l'amministratore. La posta va in IPv6 solo col DNS inverso IPv6 a posto: Gmail e Microsoft rifiutano senza.
 *  - verso solo IPv4: i nomi del pannello e della webmail di nuovo in IPv4 su Cloudflare, la posta in solo IPv4, poi
 *    via il record AAAA, poi l'indirizzo IPv6 (chi spedisce in IPv6 smette di provarci prima che l'indirizzo sparisca).
 *  - i nomi col proxy di Cloudflare: con A e AAAA insieme Cloudflare arriva al server in IPv4 («Cloudflare will prefer
 *    the IPv4 address», developers.cloudflare.com/network/ipv6-compatibility/). Quindi verso solo IPv6 AAAA e via gli
 *    A, verso solo IPv4 A e via gli AAAA: altrimenti il pannello e la webmail non si raggiungono piu'.
 *  - verso solo IPv6: l'IPv6 completo, i nomi del pannello e della webmail anche in IPv6, la posta in solo IPv6, via il
 *    record A, poi l'IPv4 tolto dal provider e la sua configurazione rimasta. Togliere l'IPv4 e' bloccato finche' chi
 *    usa il pannello non ci arriva in IPv6 e finche' sshd non ascolta in IPv6: dopo, quella sarebbe l'unica strada.
 */
public final class AddressGuide {

    public enum Goal {
        BOTH("both"), V4("ipv4"), V6("ipv6");
        public final String key;
        Goal(String key) { this.key = key; }
        public static Goal of(String k) {
            for (Goal g : values()) if (g.key.equals(k)) return g;
            return null;
        }
    }

    /**
     * Quello che si sa del server. I Boolean null sono «non si sa» (un controllo DNS che non e' stato possibile, per
     * esempio senza nome della posta): contano come «non fatto».
     */
    public record Facts(boolean v4, boolean v4Internet, boolean v4Config,
                        boolean v6, boolean v6Internet, boolean v6Firewall,
                        Boolean a, Boolean aaaa, Boolean ptr4, Boolean ptr6, Boolean webAaaa, Boolean webA,
                        IpFamily.Family mail, IpFamily.Family via, boolean sshOnV6) {}

    /** Un passo: id (che e' anche la chiave dei testi), chi lo fa («panel» o «you»), stato, motivo se bloccato. */
    public record Step(String id, String who, String status, String blocked) {}

    private AddressGuide() {}

    public static List<Step> plan(Facts f, Goal g) {
        List<String> ids = new ArrayList<>();
        switch (g) {
            case BOTH -> {
                ids.addAll(List.of("v4Address", "v4Ptr", "v4Dns"));
                ids.addAll(List.of("v6Address", "v6Firewall", "v6Ptr", "v6Dns"));
                ids.add("mailBoth");
            }
            case V4 -> {
                ids.addAll(List.of("v4Address", "v4Ptr", "v4Dns"));
                ids.addAll(List.of("webA", "mailV4", "v6DnsRemove", "v6AddressRemove"));
            }
            case V6 -> {
                ids.addAll(List.of("v6Address", "v6Firewall", "v6Ptr", "v6Dns", "webAaaa", "mailV6"));
                ids.addAll(List.of("v4DnsRemove", "v4Provider", "v4Clean"));
            }
        }
        List<Step> out = new ArrayList<>();
        boolean nowGiven = false;
        for (String id : ids) {
            if (done(f, id)) {
                out.add(new Step(id, who(id), "done", null));
                continue;
            }
            if (nowGiven) {
                out.add(new Step(id, who(id), "next", null));
                continue;
            }
            nowGiven = true;
            String why = blocked(f, id);
            out.add(new Step(id, who(id), why == null ? "now" : "blocked", why));
        }
        return out;
    }

    /** Se lo stato del server e' gia' quello dell'obiettivo (tutti i passi fatti). */
    public static boolean reached(List<Step> plan) {
        for (Step s : plan) if (!"done".equals(s.status())) return false;
        return true;
    }

    static String who(String id) {
        return switch (id) {
            case "v4Ptr", "v6Ptr", "v6Firewall", "v4Provider" -> "you";
            default -> "panel";
        };
    }

    static boolean done(Facts f, String id) {
        return switch (id) {
            case "v4Address" -> f.v4() && f.v4Internet();
            case "v4Ptr" -> Boolean.TRUE.equals(f.ptr4());
            case "v4Dns" -> Boolean.TRUE.equals(f.a());
            case "v6Address" -> f.v6() && f.v6Internet();
            // Il firewall del provider il server non lo vede da dentro: lo conferma l'amministratore, dopo averlo guardato.
            case "v6Firewall" -> f.v6Firewall();
            case "v6Ptr" -> Boolean.TRUE.equals(f.ptr6());
            case "v6Dns" -> Boolean.TRUE.equals(f.aaaa());
            // Senza un account Cloudflare che veda la zona non lo si puo' sapere: non si blocca la guida (null = fatto).
            case "webAaaa" -> !Boolean.FALSE.equals(f.webAaaa());
            case "webA" -> !Boolean.FALSE.equals(f.webA());
            case "mailBoth" -> f.mail() == IpFamily.Family.BOTH;
            case "mailV4" -> f.mail() == IpFamily.Family.IPV4;
            case "mailV6" -> f.mail() == IpFamily.Family.IPV6;
            case "v6DnsRemove" -> !Boolean.TRUE.equals(f.aaaa());
            case "v6AddressRemove" -> !f.v6();
            case "v4DnsRemove" -> !Boolean.TRUE.equals(f.a());
            case "v4Provider" -> !f.v4Internet();
            case "v4Clean" -> !f.v4() && !f.v4Config();
            default -> false;
        };
    }

    /** Il DNS inverso IPv6 completo: il PTR da' il nome della posta, e quel nome ha l'AAAA dell'indirizzo. */
    static boolean fcrdns6(Facts f) {
        return Boolean.TRUE.equals(f.ptr6()) && Boolean.TRUE.equals(f.aaaa());
    }

    /** Perche' il passo di adesso non si puo' fare ancora (chiave della lingua), o null. */
    static String blocked(Facts f, String id) {
        return switch (id) {
            // La posta in IPv6 solo col DNS inverso IPv6 confermato all'andata: il PTR da' il nome (ptr6) e il nome ha
            // l'AAAA dell'indirizzo (aaaa). Senza, Gmail e Microsoft rifiutano.
            case "mailBoth" -> f.v6() && !fcrdns6(f) ? "guide.blocked.ptr6" : null;
            // Solo IPv6 anche per il pannello (pf lo fa rispettare): chi lo sceglie deve arrivarci gia' in IPv6.
            case "mailV6" -> !fcrdns6(f) ? "guide.blocked.ptr6"
                    : f.via() == IpFamily.Family.IPV4 ? "guide.blocked.viaV4" : null;
            case "mailV4" -> f.via() == IpFamily.Family.IPV6 ? "guide.blocked.viaV6" : null;
            // Non si toglie la famiglia da cui l'amministratore sta usando il pannello.
            case "v6AddressRemove" -> f.via() == IpFamily.Family.IPV6 ? "guide.blocked.viaV6" : null;
            case "v4Provider" -> f.via() != IpFamily.Family.IPV6 ? "guide.blocked.viaV4"
                    : !f.sshOnV6() ? "guide.blocked.sshV4" : null;
            case "v4Clean" -> f.v4Internet() ? "guide.blocked.v4Works" : null;
            default -> null;
        };
    }
}
