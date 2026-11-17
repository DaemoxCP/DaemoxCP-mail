package org.daemoxcp.mail.webserver;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Map;

/**
 * One request forged on the real root socket of a separated panel: what a broken-into web part could
 * send. It prints the status and the body, or "NO ANSWER" if the root part closed the connection
 * without answering (a user other than mailpanel). Used by tests/separation-service-test.sh.
 *
 * Usage: java -cp "tests:daemoxcp-mail-1.0.jar" org.daemoxcp.mail.webserver.RootSocketProbe
 *        <socket> <route> <method> <path> <admin id> <session id> [json body]
 */
public class RootSocketProbe {
    public static void main(String[] a) {
        byte[] body = a.length > 6 ? a[6].getBytes(StandardCharsets.UTF_8) : null;
        RootChannel.Request r = new RootChannel.Request(a[1], a[2], a[3], null,
                body == null ? Map.of() : Map.of("Content-type", "application/json", "Cookie", "__Host-DaemoxCPMail=forged"),
                "198.51.100.9", "en", Long.parseLong(a[4]), Long.parseLong(a[5]), body);
        try (RootChannel.Exchange ex = RootChannel.send(Path.of(a[0]), r)) {
            System.out.println(ex.head().status() + " " + new String(ex.body().readAllBytes(), StandardCharsets.UTF_8));
        } catch (Exception e) {
            System.out.println("NO ANSWER (" + e.getMessage() + ")");
        }
    }
}
