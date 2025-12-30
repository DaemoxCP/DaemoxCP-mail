package org.mail_panel.security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * TOTP (Time-based One-Time Password) Manager for 2FA
 * Implements RFC 6238 TOTP algorithm compatible with Google Authenticator, Authy, etc.
 */
public class TotpManager {

    private static final int SECRET_SIZE = 20; // 160 bits
    private static final int CODE_DIGITS = 6;
    private static final int TIME_STEP = 30; // seconds
    private static final int WINDOW = 1; // Allow 1 step before/after for clock drift
    private static final String HMAC_ALGORITHM = "HmacSHA1";

    // Base32 alphabet for encoding secrets (RFC 4648)
    private static final String BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    /**
     * Generate a new random secret for TOTP
     * @return Base32 encoded secret
     */
    public static String generateSecret() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[SECRET_SIZE];
        random.nextBytes(bytes);
        return base32Encode(bytes);
    }

    /**
     * Generate QR code URL for authenticator apps
     * @param secret Base32 encoded secret
     * @param email User email/username
     * @param issuer Application name
     * @return otpauth:// URL for QR code
     */
    public static String getQrCodeUrl(String secret, String email, String issuer) {
        return String.format(
            "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
            urlEncode(issuer),
            urlEncode(email),
            secret,
            urlEncode(issuer),
            CODE_DIGITS,
            TIME_STEP
        );
    }

    /**
     * Get URL for QR code image (using QRServer.com API)
     * @param secret Base32 encoded secret
     * @param email User email
     * @param issuer Application name
     * @return URL to QR code image
     */
    public static String getQrCodeImageUrl(String secret, String email, String issuer) {
        String otpUrl = getQrCodeUrl(secret, email, issuer);
        return String.format(
            "https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=%s",
            urlEncode(otpUrl)
        );
    }

    /**
     * Verify a TOTP code
     * @param secret Base32 encoded secret
     * @param code 6-digit code from authenticator
     * @return true if code is valid
     */
    public static boolean verifyCode(String secret, String code) {
        if (secret == null || code == null) {
            return false;
        }

        // Clean code (remove spaces)
        code = code.replaceAll("\\s", "");

        if (code.length() != CODE_DIGITS) {
            return false;
        }

        try {
            int codeInt = Integer.parseInt(code);
            long currentTime = System.currentTimeMillis() / 1000;
            byte[] secretBytes = base32Decode(secret);

            // Check current time step and adjacent steps (for clock drift)
            for (int i = -WINDOW; i <= WINDOW; i++) {
                long timeStep = (currentTime / TIME_STEP) + i;
                int expectedCode = generateCode(secretBytes, timeStep);
                if (expectedCode == codeInt) {
                    return true;
                }
            }
        } catch (Exception e) {
            // Invalid code format
        }

        return false;
    }

    /**
     * Generate TOTP code for a given time step
     */
    private static int generateCode(byte[] secret, long timeStep) throws Exception {
        byte[] timeBytes = ByteBuffer.allocate(8).putLong(timeStep).array();

        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(new SecretKeySpec(secret, HMAC_ALGORITHM));
        byte[] hash = mac.doFinal(timeBytes);

        // Dynamic truncation (RFC 4226)
        int offset = hash[hash.length - 1] & 0x0F;
        int binary = ((hash[offset] & 0x7F) << 24) |
                     ((hash[offset + 1] & 0xFF) << 16) |
                     ((hash[offset + 2] & 0xFF) << 8) |
                     (hash[offset + 3] & 0xFF);

        return binary % (int) Math.pow(10, CODE_DIGITS);
    }

    /**
     * Encode bytes to Base32
     */
    private static String base32Encode(byte[] data) {
        StringBuilder result = new StringBuilder();
        int buffer = 0;
        int bitsLeft = 0;

        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;

            while (bitsLeft >= 5) {
                int index = (buffer >> (bitsLeft - 5)) & 0x1F;
                result.append(BASE32_CHARS.charAt(index));
                bitsLeft -= 5;
            }
        }

        if (bitsLeft > 0) {
            int index = (buffer << (5 - bitsLeft)) & 0x1F;
            result.append(BASE32_CHARS.charAt(index));
        }

        return result.toString();
    }

    /**
     * Decode Base32 to bytes
     */
    private static byte[] base32Decode(String encoded) {
        encoded = encoded.toUpperCase().replaceAll("[^A-Z2-7]", "");

        int outputLength = encoded.length() * 5 / 8;
        byte[] result = new byte[outputLength];

        int buffer = 0;
        int bitsLeft = 0;
        int index = 0;

        for (char c : encoded.toCharArray()) {
            int value = BASE32_CHARS.indexOf(c);
            if (value < 0) continue;

            buffer = (buffer << 5) | value;
            bitsLeft += 5;

            if (bitsLeft >= 8) {
                result[index++] = (byte) (buffer >> (bitsLeft - 8));
                bitsLeft -= 8;
            }
        }

        return result;
    }

    /**
     * URL encode a string
     */
    private static String urlEncode(String s) {
        try {
            return java.net.URLEncoder.encode(s, "UTF-8").replace("+", "%20");
        } catch (Exception e) {
            return s;
        }
    }

    /**
     * Generate backup codes for recovery
     * @param count Number of backup codes to generate
     * @return Array of backup codes (8 characters each)
     */
    public static String[] generateBackupCodes(int count) {
        SecureRandom random = new SecureRandom();
        String[] codes = new String[count];

        for (int i = 0; i < count; i++) {
            StringBuilder code = new StringBuilder();
            for (int j = 0; j < 8; j++) {
                code.append(BASE32_CHARS.charAt(random.nextInt(32)));
            }
            codes[i] = code.toString();
        }

        return codes;
    }

    /**
     * Hash a backup code for storage
     */
    public static String hashBackupCode(String code) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(code.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Verify a backup code against its hash
     */
    public static boolean verifyBackupCode(String code, String hash) {
        String codeHash = hashBackupCode(code);
        return codeHash != null && codeHash.equals(hash);
    }
}
