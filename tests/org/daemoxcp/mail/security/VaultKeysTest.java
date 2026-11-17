package org.daemoxcp.mail.security;

import org.daemoxcp.mail.database.MailDatabase;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.Base64;
import java.util.Properties;

/**
 * The asymmetric vault of the mailbox password copies, in a test folder, as
 * root on the VM:
 *
 *  1. the key pair: generated once, the private key only in root's secrets file and the public one in the web part's;
 *     a second call changes nothing; a public key lost or not matching is written again from the private one;
 *  2. a copy: "v2:", a different blob every time for the same password, back to that password; a byte changed in the
 *     version, the wrapped key, the nonce or the text and it does not open; another pair does not open it;
 *  3. the web part (not root): it encrypts with the public key, decrypts nothing, has no private key to export;
 *  4. a copy of before (v1, master.key) still opens, as root;
 *  5. with the test MySQL and its root (-Dmysql.port), in a database of its own: the copies of before encrypted again
 *     at start, only those, and the second time nothing; a rotation: a new pair, every copy encrypted again, the
 *     previous private key kept, and a copy left with the previous key still opens.
 *
 * Usage (on the VM, as root):
 *   java -Dmysql.port=33062 -Dmysql.user=mailpanel -Dmysql.password=... \
 *        -cp "tests:target/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.security.VaultKeysTest
 */
public class VaultKeysTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static Properties file(Path dir, String name) throws Exception {
        Properties p = new Properties();
        Path f = dir.resolve(name);
        if (Files.exists(f)) try (Reader r = Files.newBufferedReader(f)) { p.load(r); }
        return p;
    }

    static boolean opens(String blob) {
        try {
            PasswordVault.getInstance().decrypt(blob);
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** The copy with one byte changed at that offset of the decoded blob. */
    static String flipped(String blob, int offset) {
        byte[] b = Base64.getDecoder().decode(blob.substring(PasswordVault.V2_PREFIX.length()));
        b[offset] ^= 1;
        return PasswordVault.V2_PREFIX + Base64.getEncoder().encodeToString(b);
    }

    /** A copy as the vault of before wrote it: base64(nonce || AES-256-GCM text and tag) with the master.key key. */
    static String oldCopy(String plain, byte[] key) throws Exception {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        byte[] ct = c.doFinal(plain.getBytes(StandardCharsets.UTF_8));
        byte[] out = new byte[iv.length + ct.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(ct, 0, out, iv.length, ct.length);
        return Base64.getEncoder().encodeToString(out);
    }

    public static void main(String[] args) throws Exception {
        if (!"root".equals(System.getProperty("user.name"))) {
            System.out.println("Run it as root (on the VM): the vault's private key is root's.");
            System.exit(1);
        }
        Path dir = Files.createTempDirectory("vault-keys");
        System.setProperty("daemoxcp.mail.secrets.dir", dir.toString());
        byte[] masterKey = new byte[32];
        new SecureRandom().nextBytes(masterKey);
        Files.writeString(dir.resolve("master.key"), Base64.getEncoder().encodeToString(masterKey));
        System.setProperty("daemoxcp.mail.vault.key", dir.resolve("master.key").toString());
        PasswordVault vault = PasswordVault.getInstance();

        System.out.println("== 1. The key pair ==");
        check("generated the first time", PasswordVault.ensureKeyPair());
        Properties web = file(dir, "panel-secrets.properties"), root = file(dir, "root-secrets.properties");
        check("the private key only in root's file, the public one in the web part's",
                !root.getProperty("vault_private_key", "").isEmpty() && !web.containsKey("vault_private_key")
                && !web.getProperty("vault_public_key", "").isEmpty() && !root.containsKey("vault_public_key"));
        check("  RSA 3072, the public one the private one's", PasswordVault.publicKey(web.getProperty("vault_public_key"))
                .equals(PasswordVault.publicOf(PasswordVault.privateKey(root.getProperty("vault_private_key"))))
                && ((java.security.interfaces.RSAKey) PasswordVault.publicKey(web.getProperty("vault_public_key"))).getModulus().bitLength() == 3072);
        check("  root's file is 0600", "rw-------".equals(java.nio.file.attribute.PosixFilePermissions.toString(
                Files.getPosixFilePermissions(dir.resolve("root-secrets.properties")))));
        check("a second call changes nothing", !PasswordVault.ensureKeyPair()
                && file(dir, "root-secrets.properties").getProperty("vault_private_key").equals(root.getProperty("vault_private_key")));
        PanelSecrets.setText(PanelSecrets.VAULT_PUBLIC_KEY, "");
        PasswordVault.ensureKeyPair();
        check("a public key lost: written again from the private one",
                web.getProperty("vault_public_key").equals(PanelSecrets.text(PanelSecrets.VAULT_PUBLIC_KEY)));
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(3072);
        java.security.KeyPair other = g.generateKeyPair();
        PanelSecrets.setText(PanelSecrets.VAULT_PUBLIC_KEY, Base64.getEncoder().encodeToString(other.getPublic().getEncoded()));
        PasswordVault.ensureKeyPair();
        check("  a public key not matching (someone else's): written again from the private one",
                web.getProperty("vault_public_key").equals(PanelSecrets.text(PanelSecrets.VAULT_PUBLIC_KEY)));

        System.out.println("\n== 2. A copy ==");
        String password = "Vault-Test-Password-2026";
        String a = vault.encrypt(password), b = vault.encrypt(password);
        check("\"v2:\" in front, a different copy every time (" + a.length() + " characters)",
                a.startsWith("v2:") && b.startsWith("v2:") && !a.equals(b) && PasswordVault.isCurrentFormat(a));
        check("back to the same password", password.equals(vault.decrypt(a)) && password.equals(vault.decrypt(b)));
        check("a non-ASCII password too", "Pässwörd-€-2026".equals(vault.decrypt(vault.encrypt("Pässwörd-€-2026"))));
        int len = Base64.getDecoder().decode(a.substring(3)).length;
        check("a byte changed in the version, the wrapped key, the nonce, the text: it does not open",
                !opens(flipped(a, 0)) && !opens(flipped(a, 100)) && !opens(flipped(a, 1 + 384 + 3)) && !opens(flipped(a, len - 20))
                && !opens(flipped(a, len - 1)));
        check("another pair does not open it", !opensWith(a, other.getPrivate()));
        check("nothing at all: null", vault.decrypt(null) == null && vault.decrypt("") == null);

        System.out.println("\n== 3. The web part ==");
        System.setProperty("user.name", "mailpanel");
        try {
            String fromWeb = vault.encrypt(password);
            boolean decrypts;
            try {
                vault.decrypt(fromWeb);
                decrypts = true;
            } catch (RuntimeException e) {
                decrypts = false;
            }
            boolean exports;
            try {
                vault.exportPrivateKeyBase64();
                exports = true;
            } catch (RuntimeException e) {
                exports = false;
            }
            check("it encrypts with the public key", fromWeb.startsWith("v2:"));
            check("  it decrypts nothing, not even what it wrote", !decrypts);
            check("  it has no private key to export", !exports);
            check("  it does not generate keys", !PasswordVault.ensureKeyPair());
            System.setProperty("user.name", "root");
            check("what the web part wrote, root reads", password.equals(vault.decrypt(fromWeb)));
        } finally {
            System.setProperty("user.name", "root");
        }

        System.out.println("\n== 4. A copy of before ==");
        String old = oldCopy(password, masterKey);
        check("v1 (no prefix) still opens, with master.key", !PasswordVault.isCurrentFormat(old) && password.equals(vault.decrypt(old)));

        String port = System.getProperty("mysql.port");
        if (port == null) {
            System.out.println("\n  (part 5 skipped: it needs the test MySQL, -Dmysql.port and its root)");
        } else {
            System.out.println("\n== 5. With MySQL: the copies of before, and a rotation ==");
            String base = "jdbc:mysql://127.0.0.1:" + port + "/";
            String opts = "?useSSL=true&requireSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC";
            String user = System.getProperty("mysql.user", "mailpanel");
            try (Connection r = DriverManager.getConnection(base + opts, "root", System.getProperty("mysql.root.password", ""));
                 Statement s = r.createStatement()) {
                s.execute("DROP DATABASE IF EXISTS vault_keys_test");
                s.execute("CREATE DATABASE vault_keys_test CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
                s.execute("GRANT ALL ON vault_keys_test.* TO '" + user + "'@'127.0.0.1'");
            }
            MailDatabase db = new MailDatabase();
            db.setCredentials(user, System.getProperty("mysql.password", ""));
            db.setConnection("127.0.0.1", Integer.parseInt(port), "vault_keys_test");
            check("connected", db.connect());
            org.daemoxcp.mail.Main.mailDatabase = db;
            db.createSchema();
            db.ensureColumnUpgrades();
            int did = db.addDomain("vault-keys.example", "vault test");
            int m1 = db.addMailbox(did, "one@vault-keys.example", "First-Password-2026", "One", 10);
            int m2 = db.addMailbox(did, "two@vault-keys.example", "Second-Password-2026", "Two", 10);
            try (Connection c = DriverManager.getConnection(base + "vault_keys_test" + opts, user, System.getProperty("mysql.password", ""));
                 PreparedStatement p = c.prepareStatement("UPDATE mailboxes SET password_encrypted = ? WHERE id = ?")) {
                p.setString(1, oldCopy("Second-Password-2026", masterKey));
                p.setInt(2, m2);
                p.executeUpdate();
            }
            check("one copy of before planted", !PasswordVault.isCurrentFormat(db.getMailboxPasswordEncrypted(m2)));
            PasswordVault.Reencrypted re = PasswordVault.reencryptOldCopies(db);
            check("at start, only the copy of before is encrypted again (" + re + ")", re.total() == 1 && re.reencrypted() == 1 && re.failed() == 0
                    && PasswordVault.isCurrentFormat(db.getMailboxPasswordEncrypted(m2))
                    && "Second-Password-2026".equals(vault.decrypt(db.getMailboxPasswordEncrypted(m2))));
            re = PasswordVault.reencryptOldCopies(db);
            check("  the second time nothing (" + re + ")", re.total() == 0);
            String privateBefore = PanelSecrets.text(PanelSecrets.VAULT_PRIVATE_KEY);
            String leftBehind = vault.encrypt("Left-Behind-2026");
            PasswordVault.Reencrypted rot = vault.rotate(db);
            check("a rotation: a new pair, both copies encrypted again (" + rot + ")", rot.total() == 2 && rot.reencrypted() == 2
                    && !privateBefore.equals(PanelSecrets.text(PanelSecrets.VAULT_PRIVATE_KEY))
                    && "First-Password-2026".equals(vault.decrypt(db.getMailboxPasswordEncrypted(m1)))
                    && "Second-Password-2026".equals(vault.decrypt(db.getMailboxPasswordEncrypted(m2))));
            check("  the previous private key kept in root's file, and a copy left with it still opens",
                    privateBefore.equals(file(dir, "root-secrets.properties").getProperty("vault_previous_private_key"))
                    && "Left-Behind-2026".equals(vault.decrypt(leftBehind)));
            check("  the public key in the web part's file is the new private key's", PasswordVault.publicOf(PasswordVault.privateKey(
                    PanelSecrets.text(PanelSecrets.VAULT_PRIVATE_KEY))).equals(PasswordVault.publicKey(PanelSecrets.text(PanelSecrets.VAULT_PUBLIC_KEY))));
            try (Connection r = DriverManager.getConnection(base + opts, "root", System.getProperty("mysql.root.password", ""));
                 Statement s = r.createStatement()) {
                s.execute("DROP DATABASE vault_keys_test");
            }
        }

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }

    static boolean opensWith(String blob, java.security.PrivateKey key) {
        try {
            PasswordVault.getInstance().decryptWith(blob, key);
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }
}
