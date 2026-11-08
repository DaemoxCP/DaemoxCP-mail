package org.mail_panel.system;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.List;

/**
 * Root's SSH keys from the panel (RootSshKeys): only root's authorized_keys file, never sshd_config.
 *
 *  1. a new key: ed25519, ECDSA and RSA of 3072 bits pass; RSA of 2048, DSA, a key with options in front,
 *     a type that is not the key's, a comment with other characters, garbage, nothing are refused;
 *  2. the file: comments and keys with options written by hand are listed or kept as they are; a key is
 *     added at the end, not twice; removing takes only that key's line;
 *  3. in a test folder (mailpanel.root.ssh.dir), never root's real one: the file is written 0600, the
 *     previous one kept; the last key cannot be removed; a symbolic link is not followed;
 *  4. on the VM (-De2e.vm=yes): the fingerprints are the ones of ssh-keygen -l.
 *
 * Usage (on the VM; the property must be set before the class loads):
 *   java -De2e.vm=yes -Dmailpanel.root.ssh.dir=/var/tmp/ssh-keys-test -cp "tests:target/freebsd-mail-panel-1.0.jar" \
 *        org.mail_panel.system.RootSshKeysTest
 */
public class RootSshKeysTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static void string(ByteArrayOutputStream o, byte[] b) {
        int n = b.length;
        o.write(n >>> 24); o.write(n >>> 16); o.write(n >>> 8); o.write(n);
        o.write(b, 0, n);
    }

    static String b64(ByteArrayOutputStream o) { return Base64.getEncoder().encodeToString(o.toByteArray()); }

    public static String ed25519() throws Exception {
        byte[] x509 = KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic().getEncoded();
        byte[] raw = java.util.Arrays.copyOfRange(x509, x509.length - 32, x509.length);
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        string(o, "ssh-ed25519".getBytes(StandardCharsets.US_ASCII));
        string(o, raw);
        return "ssh-ed25519 " + b64(o);
    }

    static String rsa(int bits) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(bits);
        RSAPublicKey k = (RSAPublicKey) g.generateKeyPair().getPublic();
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        string(o, "ssh-rsa".getBytes(StandardCharsets.US_ASCII));
        string(o, k.getPublicExponent().toByteArray());
        string(o, k.getModulus().toByteArray());
        return "ssh-rsa " + b64(o);
    }

    static String ecdsa256() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        ECPublicKey k = (ECPublicKey) g.generateKeyPair().getPublic();
        byte[] point = new byte[65];
        point[0] = 4;
        byte[] x = fixed(k.getW().getAffineX()), y = fixed(k.getW().getAffineY());
        System.arraycopy(x, 0, point, 1, 32);
        System.arraycopy(y, 0, point, 33, 32);
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        string(o, "ecdsa-sha2-nistp256".getBytes(StandardCharsets.US_ASCII));
        string(o, "nistp256".getBytes(StandardCharsets.US_ASCII));
        string(o, point);
        return "ecdsa-sha2-nistp256 " + b64(o);
    }

    static byte[] fixed(BigInteger v) {
        byte[] b = v.toByteArray(), out = new byte[32];
        int n = Math.min(32, b.length);
        System.arraycopy(b, b.length - n, out, 32 - n, n);
        return out;
    }

    static String fingerprintOf(String key) {
        RootSshKeys.Outcome o = RootSshKeys.validate(key);
        return o.success() ? o.key().fingerprint() : "";
    }

    public static void main(String[] args) throws Exception {
        String ed = ed25519(), ec = ecdsa256(), rsa3072 = rsa(3072), rsa2048 = rsa(2048);

        System.out.println("== 1. A new key ==");
        RootSshKeys.Outcome o = RootSshKeys.validate(ed + "   admin@laptop  ");
        check("ed25519 with a comment passes, the line is type, key, comment", o.success()
                && o.line().equals(ed + " admin@laptop") && o.key().fingerprint().matches("SHA256:[A-Za-z0-9+/]{43}"));
        check("ECDSA P-256 passes", RootSshKeys.validate(ec + " phone").success());
        check("RSA of 3072 bits passes", RootSshKeys.validate(rsa3072).success());
        o = RootSshKeys.validate(rsa2048);
        check("RSA of 2048 bits is refused, saying how many bits (" + o.params() + ")",
                "server.ssh.rsaShort".equals(o.errorKey()) && Integer.valueOf(2048).equals(o.params().get("bits")));
        check("DSA is refused", "server.ssh.dsa".equals(RootSshKeys.validate("ssh-dss AAAAB3NzaC1kc3M= old").errorKey()));
        check("a key with options in front is refused", "server.ssh.options".equals(RootSshKeys.validate("from=\"1.2.3.4\" " + ed).errorKey())
                && "server.ssh.options".equals(RootSshKeys.validate("command=\"/bin/sh\" " + ed).errorKey()));
        check("a type that is not the key's is refused", "server.ssh.badKey".equals(
                RootSshKeys.validate("ssh-ed25519 " + rsa3072.substring("ssh-rsa ".length())).errorKey()));
        check("a comment with other characters is refused", "server.ssh.badComment".equals(RootSshKeys.validate(ed + " a;b").errorKey())
                && "server.ssh.badComment".equals(RootSshKeys.validate(ed + " " + "x".repeat(101)).errorKey()));
        check("a line break, garbage and nothing are refused", !RootSshKeys.validate(ed + "\nssh-ed25519 AAAA x").success()
                && "server.ssh.badKey".equals(RootSshKeys.validate("hello world").errorKey())
                && "server.ssh.empty".equals(RootSshKeys.validate("   ").errorKey()));

        System.out.println("\n== 2. The file ==");
        String file = "# written by hand\n" + ed + " admin@laptop\n\nfrom=\"10.0.0.0/8\" " + ec + " backup\nsomething else\n";
        List<RootSshKeys.Key> keys = RootSshKeys.keys(file);
        check("two keys listed, the one with options too (" + keys.size() + ")", keys.size() == 2
                && keys.get(1).options().equals("from=\"10.0.0.0/8\"") && keys.get(1).comment().equals("backup"));
        RootSshKeys.Outcome add = RootSshKeys.validate(rsa3072 + " new");
        String added = RootSshKeys.withKey(file, add.key(), add.line());
        check("a key is added at the end, the rest as it was", added != null && added.equals(file + rsa3072 + " new\n"));
        check("  not twice", RootSshKeys.withKey(added, add.key(), add.line()) == null);
        check("  a file without a final line break gets one first", (ed + "\n" + rsa3072 + " new\n").equals(
                RootSshKeys.withKey(ed, add.key(), add.line())));
        String removed = RootSshKeys.withoutKey(added, keys.get(0).fingerprint());
        check("removing takes only that key's line: comments, the key with options, the line not understood stay",
                removed != null && !removed.contains(ed) && removed.contains("# written by hand") && removed.contains("from=\"10.0.0.0/8\"")
                && removed.contains("something else") && removed.contains(rsa3072));
        check("  a key that is not there: nothing", RootSshKeys.withoutKey(file, fingerprintOf(rsa3072)) == null);

        System.out.println("\n== 3. In a test folder ==");
        Path dir = RootSshKeys.DIR;
        if (dir.toString().equals("/root/.ssh")) {
            System.out.println("  (part 3 skipped: -Dmailpanel.root.ssh.dir is not set, and root's real keys are never touched)");
        } else {
            org.mail_panel.util.Shell.run("rm", "-rf", dir.toString());
            check("no folder: no keys", RootSshKeys.list().isEmpty());
            check("adding the first key creates the folder 0700 and the file 0600", RootSshKeys.add(ed + " first").success()
                    && "rwx------".equals(PosixFilePermissions.toString(Files.getPosixFilePermissions(dir)))
                    && "rw-------".equals(PosixFilePermissions.toString(Files.getPosixFilePermissions(RootSshKeys.FILE))));
            check("the last key cannot be removed", "server.ssh.lastKey".equals(RootSshKeys.remove(fingerprintOf(ed)).errorKey())
                    && RootSshKeys.list().size() == 1);
            check("a second key, then the first can go", RootSshKeys.add(ec + " second").success()
                    && RootSshKeys.remove(fingerprintOf(ed)).success() && RootSshKeys.list().size() == 1);
            check("  the file before is kept, 0600", Files.readString(RootSshKeys.PREVIOUS).contains(ed)
                    && "rw-------".equals(PosixFilePermissions.toString(Files.getPosixFilePermissions(RootSshKeys.PREVIOUS))));
            check("a fingerprint that is not one: not found", "server.ssh.notFound".equals(RootSshKeys.remove("SHA256:x;rm").errorKey()));
            Path real = dir.resolveSibling(dir.getFileName() + "-real");
            Files.createDirectories(real);
            Files.writeString(real.resolve("authorized_keys"), ed + "\n");
            Files.delete(RootSshKeys.FILE);
            Files.createSymbolicLink(RootSshKeys.FILE, real.resolve("authorized_keys"));
            boolean refused;
            try {
                RootSshKeys.add(rsa3072);
                refused = false;
            } catch (java.io.IOException e) {
                refused = true;
            }
            check("authorized_keys as a symbolic link: not followed, the file it points to unchanged",
                    refused && Files.readString(real.resolve("authorized_keys")).equals(ed + "\n"));
            org.mail_panel.util.Shell.run("rm", "-rf", dir.toString(), real.toString());
        }

        boolean e2e = "yes".equals(System.getProperty("e2e.vm"));
        if (e2e) {
            System.out.println("\n== 4. The fingerprints of ssh-keygen ==");
            for (String k : new String[]{ed, ec, rsa3072}) {
                Path f = Files.createTempFile("key-", ".pub");
                Files.writeString(f, k + " probe\n");
                String out = org.mail_panel.util.Shell.run("ssh-keygen", "-l", "-f", f.toString()).outputTrim();
                Files.deleteIfExists(f);
                check(k.substring(0, k.indexOf(' ')) + ": " + fingerprintOf(k) + " is in \"" + out + "\"", out.contains(fingerprintOf(k)));
            }
        } else {
            System.out.println("\n  (part 4 skipped: it needs ssh-keygen, turned on with -De2e.vm=yes on the VM)");
        }

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
