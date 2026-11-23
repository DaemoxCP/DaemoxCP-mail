package org.daemoxcp.mail.system;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Root's SSH keys, from the panel (requested by the owner on 2026-11-08): view them, add one,
 * remove one. Only the file {@code /root/.ssh/authorized_keys}: sshd_config, port 22 and the pf rules
 * are never touched from here.
 *
 * <p>Who decides: a superadmin (permission ssh.manage) with a recent confirmation (passkey or code, as for the
 * vault), checked by the route handler. Here, the rules of the file:
 * <ul>
 *   <li>only a plain key is added: type, key, comment, without options ({@code from=},
 *       {@code command=}...). The types: ed25519, ecdsa (256, 384, 521), their security-key versions (sk-),
 *       and RSA of at least 3072 bits; not DSA. The written type must be the one inside the key;</li>
 *   <li>the comment: letters, digits and a few symbols (r4), at most 100 characters;</li>
 *   <li>the last key is not removed: without it, nobody could log in as root via SSH any more;</li>
 *   <li>the lines the panel does not understand (comments, keys with hand-written options) stay as they were;</li>
 *   <li>the file is rewritten whole and atomically, 0600 root:wheel, in the .ssh folder 0700; the previous
 *       version stays beside it ({@code authorized_keys.panel-previous}); a symbolic link is not followed.</li>
 * </ul>
 * The fingerprint is the one of {@code ssh-keygen -l}: "SHA256:" and the SHA-256 of the key in base64 without "=".
 */
public final class RootSshKeys {

    private RootSshKeys() {}

    /** /root/.ssh; the tests move it to a folder of their own (daemoxcp.mail.root.ssh.dir), never the real one. */
    static final Path DIR = Path.of(System.getProperty("daemoxcp.mail.root.ssh.dir", "/root/.ssh"));
    static final Path FILE = DIR.resolve("authorized_keys");
    static final Path PREVIOUS = DIR.resolve("authorized_keys.panel-previous");

    /** The types accepted for a new key. */
    static final List<String> ACCEPTED = List.of("ssh-ed25519", "sk-ssh-ed25519@openssh.com", "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "sk-ecdsa-sha2-nistp256@openssh.com", "ssh-rsa");
    /** The types recognised in a file already written (DSA too, so that it can be seen and removed). */
    private static final Pattern KEY = Pattern.compile("(?:^|\\s)(ssh-ed25519|sk-ssh-ed25519@openssh\\.com|ecdsa-sha2-nistp(?:256|384|521)"
            + "|sk-ecdsa-sha2-nistp256@openssh\\.com|ssh-rsa|ssh-dss)\\s+([A-Za-z0-9+/]+={0,2})(?:\\s+(.*))?$");
    private static final Pattern COMMENT = Pattern.compile("[A-Za-z0-9 ._@+:()-]{0,100}");
    static final int MIN_RSA_BITS = 3072;
    static final int MAX_LINE = 8192;
    public static final Pattern FINGERPRINT = Pattern.compile("SHA256:[A-Za-z0-9+/]{43}");

    /** A key of the file: type, fingerprint, comment, the options written before it (empty if none). */
    public record Key(String type, String fingerprint, String comment, String options) {}

    /**
     * The result of a check, an addition or a removal: errorKey null if it goes through, otherwise the message key
     * with its parameters. key is the key in question; line the line to write (only from the check).
     */
    public record Outcome(String errorKey, Map<String, Object> params, Key key, String line) {
        static Outcome ok(Key k) { return new Outcome(null, Map.of(), k, null); }
        static Outcome ok(Key k, String line) { return new Outcome(null, Map.of(), k, line); }
        static Outcome fail(String key) { return new Outcome(key, Map.of(), null, null); }
        static Outcome fail(String key, Map<String, Object> params) { return new Outcome(key, params, null, null); }
        public boolean success() { return errorKey == null; }
    }

    // ===================== The parts that are tested without a system underneath =====================

    static String fingerprint(byte[] blob) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(blob);
            return "SHA256:" + Base64.getEncoder().withoutPadding().encodeToString(h);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** A line of the file, if it is a key; null if not (a comment, an empty line, one that cannot be understood). */
    static Key parse(String line) {
        String t = line == null ? "" : line.trim();
        if (t.isEmpty() || t.startsWith("#")) return null;
        Matcher m = KEY.matcher(t);
        if (!m.find()) return null;
        byte[] blob;
        try {
            blob = Base64.getDecoder().decode(m.group(2));
        } catch (IllegalArgumentException e) {
            return null;
        }
        String options = t.substring(0, m.start()).trim();
        String comment = m.group(3) == null ? "" : m.group(3).trim();
        return new Key(m.group(1), fingerprint(blob), comment, options);
    }

    public static List<Key> keys(String content) {
        List<Key> out = new ArrayList<>();
        if (content == null) return out;
        for (String line : content.split("\n")) {
            Key k = parse(line);
            if (k != null) out.add(k);
        }
        return out;
    }

    /** The first field of a key: an SSH string (4-byte length and the bytes), or null. */
    private static byte[] sshString(ByteBuffer b) {
        if (b.remaining() < 4) return null;
        int n = b.getInt();
        if (n < 0 || n > b.remaining()) return null;
        byte[] out = new byte[n];
        b.get(out);
        return out;
    }

    /**
     * A new key, checked: the line to write (type, key and comment separated by one space), or the
     * reason why it is not accepted (the message key, in Outcome).
     */
    static Outcome validate(String input) {
        String t = input == null ? "" : input.trim();
        if (t.isEmpty()) return Outcome.fail("server.ssh.empty");
        if (t.length() > MAX_LINE || !t.matches("[\\x20-\\x7E]+")) return Outcome.fail("server.ssh.badKey");
        String[] parts = t.split(" +", 3);
        if (!ACCEPTED.contains(parts[0])) {
            if (parts[0].equals("ssh-dss")) return Outcome.fail("server.ssh.dsa");
            return Outcome.fail(KEY.matcher(t).find() ? "server.ssh.options" : "server.ssh.badKey");
        }
        if (parts.length < 2 || !parts[1].matches("[A-Za-z0-9+/]+={0,2}")) return Outcome.fail("server.ssh.badKey");
        String comment = parts.length > 2 ? parts[2].trim().replaceAll(" +", " ") : "";
        if (!COMMENT.matcher(comment).matches()) return Outcome.fail("server.ssh.badComment");
        byte[] blob;
        try {
            blob = Base64.getDecoder().decode(parts[1]);
        } catch (IllegalArgumentException e) {
            return Outcome.fail("server.ssh.badKey");
        }
        ByteBuffer b = ByteBuffer.wrap(blob);
        byte[] inner = sshString(b);
        if (inner == null || !new String(inner, StandardCharsets.US_ASCII).equals(parts[0])) return Outcome.fail("server.ssh.badKey");
        if (parts[0].equals("ssh-rsa")) {
            byte[] e = sshString(b), n = sshString(b);
            if (e == null || n == null) return Outcome.fail("server.ssh.badKey");
            int bits = new BigInteger(1, n).bitLength();
            if (bits < MIN_RSA_BITS) return Outcome.fail("server.ssh.rsaShort", Map.of("bits", bits, "min", MIN_RSA_BITS));
        } else if (parts[0].equals("ssh-ed25519")) {
            byte[] k = sshString(b);
            if (k == null || k.length != 32) return Outcome.fail("server.ssh.badKey");
        } else if (parts[0].startsWith("ecdsa-sha2-")) {
            byte[] curve = sshString(b), point = sshString(b);
            if (curve == null || point == null || !parts[0].endsWith(new String(curve, StandardCharsets.US_ASCII)))
                return Outcome.fail("server.ssh.badKey");
        }
        String line = parts[0] + " " + parts[1] + (comment.isEmpty() ? "" : " " + comment);
        return Outcome.ok(new Key(parts[0], fingerprint(blob), comment, ""), line);
    }

    /** The file with the line of the extra key at the end; null if the key is already there. */
    static String withKey(String content, Key key, String line) {
        String c = content == null ? "" : content;
        for (Key k : keys(c)) if (k.fingerprint().equals(key.fingerprint())) return null;
        if (!c.isEmpty() && !c.endsWith("\n")) c += "\n";
        return c + line + "\n";
    }

    /** The file without the lines of that key; null if it is not there. */
    static String withoutKey(String content, String fingerprint) {
        if (content == null) return null;
        StringBuilder out = new StringBuilder();
        boolean found = false;
        for (String line : content.split("\n", -1)) {
            Key k = parse(line);
            if (k != null && k.fingerprint().equals(fingerprint)) {
                found = true;
                continue;
            }
            out.append(line).append('\n');
        }
        if (!found) return null;
        String s = out.toString();
        return s.endsWith("\n\n") ? s.substring(0, s.length() - 1) : s;
    }

    // ===================== The real file =====================

    private static void refuseLinks() throws IOException {
        if (Files.isSymbolicLink(DIR) || Files.isSymbolicLink(FILE)) throw new IOException("a symbolic link in " + DIR + ": not followed");
    }

    public static synchronized List<Key> list() throws IOException {
        refuseLinks();
        if (!Files.isRegularFile(FILE, LinkOption.NOFOLLOW_LINKS)) return List.of();
        return keys(Files.readString(FILE, StandardCharsets.UTF_8));
    }

    public static synchronized Outcome add(String input) throws IOException {
        Outcome v = validate(input);
        if (!v.success()) return v;
        refuseLinks();
        String current = Files.isRegularFile(FILE, LinkOption.NOFOLLOW_LINKS) ? Files.readString(FILE, StandardCharsets.UTF_8) : "";
        String next = withKey(current, v.key(), v.line());
        if (next == null) return Outcome.fail("server.ssh.duplicate");
        write(current, next);
        return Outcome.ok(v.key());
    }

    public static synchronized Outcome remove(String fingerprint) throws IOException {
        if (fingerprint == null || !FINGERPRINT.matcher(fingerprint).matches()) return Outcome.fail("server.ssh.notFound");
        refuseLinks();
        if (!Files.isRegularFile(FILE, LinkOption.NOFOLLOW_LINKS)) return Outcome.fail("server.ssh.notFound");
        String current = Files.readString(FILE, StandardCharsets.UTF_8);
        Key target = keys(current).stream().filter(k -> k.fingerprint().equals(fingerprint)).findFirst().orElse(null);
        String next = withoutKey(current, fingerprint);
        if (target == null || next == null) return Outcome.fail("server.ssh.notFound");
        if (keys(next).isEmpty()) return Outcome.fail("server.ssh.lastKey");
        write(current, next);
        return Outcome.ok(target);
    }

    private static void write(String current, String next) throws IOException {
        if (!Files.isDirectory(DIR, LinkOption.NOFOLLOW_LINKS)) {
            Files.createDirectories(DIR);
            Files.setPosixFilePermissions(DIR, PosixFilePermissions.fromString("rwx------"));
        }
        if (!current.isEmpty()) {
            Path prev = Files.createTempFile(DIR, ".authorized_keys.", ".prev");
            Files.writeString(prev, current, StandardCharsets.UTF_8);
            Files.setPosixFilePermissions(prev, PosixFilePermissions.fromString("rw-------"));
            Files.move(prev, PREVIOUS, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        }
        Path tmp = Files.createTempFile(DIR, ".authorized_keys.", ".new");
        Files.writeString(tmp, next, StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rw-------"));
        Files.move(tmp, FILE, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }
}
