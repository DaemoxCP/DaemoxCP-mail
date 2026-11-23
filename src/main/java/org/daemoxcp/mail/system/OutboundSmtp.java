package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Outbound port 25: can the server deliver mail to the other servers? (finding 246)
 *
 * <p>Many providers close it on new accounts: Hetzner Cloud closes 25 and 465 outbound and opens them on
 * request, after the first paid invoice. With 25 closed, incoming mail works and outgoing mail stays in the
 * queue without anything saying so clearly. Here we connect to port 25 of three large mail servers, read only
 * the greeting (220), write QUIT and close: no message, no address. One successful connection is enough to say
 * that the port is open; if nobody answers and the names resolve, it is closed.
 */
public final class OutboundSmtp {

    private OutboundSmtp() {}

    /** Servers that always answer on 25: Gmail, iCloud, Outlook.com (their MX). */
    static final List<String> HOSTS = List.of("gmail-smtp-in.l.google.com", "mx01.mail.icloud.com",
            "outlook-com.olc.protection.outlook.com");
    static final int TIMEOUT_MS = 8000;

    /** A server's greeting on port 25, or an exception. */
    interface Dialer {
        String banner(String host) throws IOException;
    }

    /**
     * We connect with the addresses of the family Postfix uses (IpFamily): with IPv6 only, a connection over IPv4
     * would succeed anyway (the system goes out over IPv4), and would call open a port that Postfix does not use.
     */
    static Dialer dialer = host -> {
        IpFamily.Family f = IpFamily.effective();
        IOException last = null;
        for (java.net.InetAddress a : java.net.InetAddress.getAllByName(host)) {
            boolean six = a instanceof java.net.Inet6Address;
            // Outbound, what matters is whether Postfix sends in that family (even with IPv6 mail outbound only).
            if (six ? !f.sends6() : !f.v4()) continue;
            try {
                return bannerAt(a);
            } catch (IOException e) {
                last = e;
            }
        }
        throw last != null ? last : new IOException(host + " has no " + f.key + " address");
    };

    private static String bannerAt(java.net.InetAddress address) throws IOException {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(address, 25), TIMEOUT_MS);
            s.setSoTimeout(TIMEOUT_MS);
            BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.US_ASCII));
            String line;
            try {
                line = in.readLine();
            } catch (java.net.SocketTimeoutException e) {
                line = "";   // connected, but no greeting in time: the port is open anyway
            }
            OutputStream out = s.getOutputStream();
            out.write("QUIT\r\n".getBytes(StandardCharsets.US_ASCII));
            out.flush();
            return line == null ? "" : line;
        }
    }

    /** open (at least one successful connection), blocked (names resolved, no connection), unknown (no name resolved). */
    public static JSONObject check() {
        JSONArray tried = new JSONArray();
        int resolved = 0;
        String openOn = null;
        for (String host : HOSTS) {
            JSONObject t = new JSONObject().put("host", host);
            try {
                String b = dialer.banner(host);
                resolved++;
                // Connected: the port is open, even if the greeting is not 220 (a refusal is still an answer).
                t.put("result", b.startsWith("220") ? "greeted" : "answered");
                if (openOn == null) openOn = host;
            } catch (UnknownHostException e) {
                t.put("result", "noName");
            } catch (IOException e) {
                resolved++;
                t.put("result", "noConnection");
            }
            tried.put(t);
            if (openOn != null) break;
        }
        String state = openOn != null ? "open" : resolved > 0 ? "blocked" : "unknown";
        return new JSONObject().put("success", true).put("state", state).put("tried", tried)
                .put("openOn", openOn == null ? "" : openOn);
    }
}
