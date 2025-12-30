package org.mail_panel.security;

import com.yubico.webauthn.*;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.exception.*;
import org.mail_panel.database.MailDatabase;

import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * WebAuthn/Passkey Manager for passwordless authentication
 */
public class PasskeyManager {

    private final RelyingParty rp;
    private final MailDatabase database;
    private final CredentialRepository credentialRepository;

    // Temporary storage for registration/authentication challenges
    private final Map<String, RegistrationRequest> pendingRegistrations = new ConcurrentHashMap<>();
    private final Map<String, AuthenticationRequest> pendingAuthentications = new ConcurrentHashMap<>();

    // Challenge expiry time (5 minutes)
    private static final long CHALLENGE_EXPIRY_MS = 5 * 60 * 1000;

    public PasskeyManager(MailDatabase database, String rpId, String rpName, Set<String> origins) {
        this.database = database;
        this.credentialRepository = new DatabaseCredentialRepository(database);

        RelyingPartyIdentity rpIdentity = RelyingPartyIdentity.builder()
                .id(rpId)
                .name(rpName)
                .build();

        this.rp = RelyingParty.builder()
                .identity(rpIdentity)
                .credentialRepository(credentialRepository)
                .origins(origins)
                .allowOriginPort(true)  // Allow non-standard ports
                .allowOriginSubdomain(false)
                .build();
    }

    /**
     * Start passkey registration for an admin
     */
    public RegistrationStartResponse startRegistration(int adminId, String username, String displayName) {
        try {
            UserIdentity userIdentity = UserIdentity.builder()
                    .name(username)
                    .displayName(displayName != null ? displayName : username)
                    .id(new ByteArray(intToBytes(adminId)))
                    .build();

            StartRegistrationOptions options = StartRegistrationOptions.builder()
                    .user(userIdentity)
                    .authenticatorSelection(AuthenticatorSelectionCriteria.builder()
                            .residentKey(ResidentKeyRequirement.PREFERRED)
                            .userVerification(UserVerificationRequirement.PREFERRED)
                            .build())
                    .build();

            PublicKeyCredentialCreationOptions pkcco = rp.startRegistration(options);

            // Store for verification later
            String challengeId = generateChallengeId();
            pendingRegistrations.put(challengeId, new RegistrationRequest(adminId, pkcco, System.currentTimeMillis()));

            // Clean up old challenges
            cleanupExpiredChallenges();

            return new RegistrationStartResponse(challengeId, pkcco);
        } catch (Exception e) {
            throw new RuntimeException("Failed to start registration: " + e.getMessage(), e);
        }
    }

    /**
     * Finish passkey registration
     */
    public RegistrationResult finishRegistration(String challengeId, String credentialJson, String passkeyName) {
        RegistrationRequest pending = pendingRegistrations.remove(challengeId);
        if (pending == null) {
            return new RegistrationResult(false, "Challenge not found or expired", null);
        }

        if (System.currentTimeMillis() - pending.timestamp > CHALLENGE_EXPIRY_MS) {
            return new RegistrationResult(false, "Challenge expired", null);
        }

        try {
            PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> pkc =
                    PublicKeyCredential.parseRegistrationResponseJson(credentialJson);

            FinishRegistrationOptions options = FinishRegistrationOptions.builder()
                    .request(pending.options)
                    .response(pkc)
                    .build();

            com.yubico.webauthn.RegistrationResult result = rp.finishRegistration(options);

            // Save to database
            byte[] credentialId = result.getKeyId().getId().getBytes();
            byte[] publicKeyCose = result.getPublicKeyCose().getBytes();
            long signCount = result.getSignatureCount();
            byte[] aaguid = result.getAaguid().getBytes();

            boolean saved = database.savePasskey(
                    pending.adminId,
                    credentialId,
                    publicKeyCose,
                    signCount,
                    passkeyName,
                    aaguid
            );

            if (saved) {
                return new RegistrationResult(true, "Passkey registered successfully", credentialId);
            } else {
                return new RegistrationResult(false, "Failed to save passkey to database", null);
            }
        } catch (RegistrationFailedException e) {
            return new RegistrationResult(false, "Registration failed: " + e.getMessage(), null);
        } catch (Exception e) {
            return new RegistrationResult(false, "Error: " + e.getMessage(), null);
        }
    }

    /**
     * Start passkey authentication for a username
     */
    public AuthenticationStartResponse startAuthentication(String username) {
        try {
            // Get admin's registered credentials
            int adminId = database.getAdminIdByUsername(username);
            if (adminId == 0) {
                return new AuthenticationStartResponse(null, null, "User not found");
            }

            List<MailDatabase.Passkey> passkeys = database.getPasskeysByUsername(username);
            if (passkeys.isEmpty()) {
                return new AuthenticationStartResponse(null, null, "No passkeys registered");
            }

            StartAssertionOptions options = StartAssertionOptions.builder()
                    .username(username)
                    .userVerification(UserVerificationRequirement.PREFERRED)
                    .build();

            AssertionRequest assertionRequest = rp.startAssertion(options);

            String challengeId = generateChallengeId();
            pendingAuthentications.put(challengeId, new AuthenticationRequest(username, adminId, assertionRequest, System.currentTimeMillis()));

            cleanupExpiredChallenges();

            return new AuthenticationStartResponse(challengeId, assertionRequest, null);
        } catch (Exception e) {
            return new AuthenticationStartResponse(null, null, "Error: " + e.getMessage());
        }
    }

    /**
     * Finish passkey authentication
     */
    public AuthenticationResult finishAuthentication(String challengeId, String credentialJson) {
        AuthenticationRequest pending = pendingAuthentications.remove(challengeId);
        if (pending == null) {
            return new AuthenticationResult(false, 0, "Challenge not found or expired");
        }

        if (System.currentTimeMillis() - pending.timestamp > CHALLENGE_EXPIRY_MS) {
            return new AuthenticationResult(false, 0, "Challenge expired");
        }

        try {
            PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> pkc =
                    PublicKeyCredential.parseAssertionResponseJson(credentialJson);

            FinishAssertionOptions options = FinishAssertionOptions.builder()
                    .request(pending.assertionRequest)
                    .response(pkc)
                    .build();

            AssertionResult result = rp.finishAssertion(options);

            if (result.isSuccess()) {
                // Update sign count
                byte[] credentialId = result.getCredential().getCredentialId().getBytes();
                long newSignCount = result.getSignatureCount();
                database.updatePasskeySignCount(credentialId, newSignCount);

                return new AuthenticationResult(true, pending.adminId, null);
            } else {
                return new AuthenticationResult(false, 0, "Authentication failed");
            }
        } catch (AssertionFailedException e) {
            return new AuthenticationResult(false, 0, "Authentication failed: " + e.getMessage());
        } catch (Exception e) {
            return new AuthenticationResult(false, 0, "Error: " + e.getMessage());
        }
    }

    private String generateChallengeId() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private byte[] intToBytes(int value) {
        return new byte[] {
                (byte) (value >> 24),
                (byte) (value >> 16),
                (byte) (value >> 8),
                (byte) value
        };
    }

    private void cleanupExpiredChallenges() {
        long now = System.currentTimeMillis();
        pendingRegistrations.entrySet().removeIf(e -> now - e.getValue().timestamp > CHALLENGE_EXPIRY_MS);
        pendingAuthentications.entrySet().removeIf(e -> now - e.getValue().timestamp > CHALLENGE_EXPIRY_MS);
    }

    // ===== Response classes =====

    public record RegistrationStartResponse(String challengeId, PublicKeyCredentialCreationOptions options) {}
    public record RegistrationResult(boolean success, String message, byte[] credentialId) {}
    public record AuthenticationStartResponse(String challengeId, AssertionRequest options, String error) {}
    public record AuthenticationResult(boolean success, int adminId, String error) {}

    // ===== Request storage classes =====

    private record RegistrationRequest(int adminId, PublicKeyCredentialCreationOptions options, long timestamp) {}
    private record AuthenticationRequest(String username, int adminId, AssertionRequest assertionRequest, long timestamp) {}

    // ===== Credential Repository Implementation =====

    private static class DatabaseCredentialRepository implements CredentialRepository {
        private final MailDatabase database;

        public DatabaseCredentialRepository(MailDatabase database) {
            this.database = database;
        }

        @Override
        public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
            Set<PublicKeyCredentialDescriptor> credentials = new HashSet<>();
            for (MailDatabase.Passkey passkey : database.getPasskeysByUsername(username)) {
                credentials.add(PublicKeyCredentialDescriptor.builder()
                        .id(new ByteArray(passkey.credentialId))
                        .type(PublicKeyCredentialType.PUBLIC_KEY)
                        .build());
            }
            return credentials;
        }

        @Override
        public Optional<ByteArray> getUserHandleForUsername(String username) {
            int adminId = database.getAdminIdByUsername(username);
            if (adminId > 0) {
                return Optional.of(new ByteArray(intToBytes(adminId)));
            }
            return Optional.empty();
        }

        @Override
        public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
            // We store admin ID in user handle
            int adminId = bytesToInt(userHandle.getBytes());
            // This would need a method to get username by ID
            // For now, we can leave this empty as it's optional
            return Optional.empty();
        }

        @Override
        public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
            MailDatabase.Passkey passkey = database.getPasskeyByCredentialId(credentialId.getBytes());
            if (passkey != null) {
                return Optional.of(RegisteredCredential.builder()
                        .credentialId(new ByteArray(passkey.credentialId))
                        .userHandle(new ByteArray(intToBytes(passkey.adminId)))
                        .publicKeyCose(new ByteArray(passkey.publicKeyCose))
                        .signatureCount(passkey.signCount)
                        .build());
            }
            return Optional.empty();
        }

        @Override
        public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
            MailDatabase.Passkey passkey = database.getPasskeyByCredentialId(credentialId.getBytes());
            if (passkey != null) {
                return Set.of(RegisteredCredential.builder()
                        .credentialId(new ByteArray(passkey.credentialId))
                        .userHandle(new ByteArray(intToBytes(passkey.adminId)))
                        .publicKeyCose(new ByteArray(passkey.publicKeyCose))
                        .signatureCount(passkey.signCount)
                        .build());
            }
            return Set.of();
        }

        private static byte[] intToBytes(int value) {
            return new byte[] {
                    (byte) (value >> 24),
                    (byte) (value >> 16),
                    (byte) (value >> 8),
                    (byte) value
            };
        }

        private static int bytesToInt(byte[] bytes) {
            if (bytes.length < 4) return 0;
            return ((bytes[0] & 0xFF) << 24) |
                   ((bytes[1] & 0xFF) << 16) |
                   ((bytes[2] & 0xFF) << 8) |
                   (bytes[3] & 0xFF);
        }
    }
}
