package org.daemoxcp.mail.system;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Another panel process holding the turn of the package jobs: for the tests of the turn across
 * processes (PackageTurnAcrossProcessesTest, and by hand on the VM).
 *
 * It takes the turn with PackageQueue.take, that is like a real job; given a list of packages it
 * writes it to disk like a job that unlocked them. It prints "HELD" when it holds it, then waits
 * for stdin to close (or to be killed) and releases.
 *
 * Usage: java -cp tests:<jar> org.daemoxcp.mail.system.TurnHolder <list> <description> [package...]
 *        <list> is the list's path ("-" for the real one, /var/db/mail-panel-maintenance-locks):
 *        the turn file sits next to it.
 */
public class TurnHolder {
    public static void main(String[] args) throws Exception {
        if (!"-".equals(args[0])) {
            PackageQueue.list = Path.of(args[0]);
            PackageQueue.turnLock = PackageQueue.list.resolveSibling("package-turn.lock");
        }
        String id = "holder-" + ProcessHandle.current().pid();
        String refusal = PackageQueue.take(id, args[1]);
        if (refusal != null) {
            System.out.println("REFUSED " + refusal);
            System.exit(3);
        }
        if (args.length > 2) {
            String e = PackageQueue.writeState(List.of(args).subList(2, args.length));
            if (e != null) { System.out.println("NOLIST " + e); PackageQueue.release(id); System.exit(4); }
        }
        System.out.println("HELD " + ProcessHandle.current().pid());
        System.out.flush();
        while (System.in.read() != -1) { }
        if (args.length > 2) Files.deleteIfExists(PackageQueue.list);
        PackageQueue.release(id);
        System.out.println("RELEASED");
    }
}
