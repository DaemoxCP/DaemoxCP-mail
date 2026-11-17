package org.mail_panel.security;

import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.ResidentKeyRequirement;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.UserVerificationRequirement;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Le passkey del pannello (WebAuthn), verificate dalla libreria Yubico webauthn-server-core.
 *
 *  - la registrazione salva la chiave pubblica COSE, controllando sfida, origine e rpId, e chiede
 *    una passkey "discoverable" con verifica dell'utente (impronta, volto o PIN);
 *  - il login verifica la firma, la sfida (usabile una volta, scade in tre minuti), l'origine,
 *    l'rpId, la verifica dell'utente e il contatore;
 *  - il login non chiede il nome utente: niente da indovinare, niente che dica se un account
 *    esiste. Prima la pagina chiedeva il nome e /api/auth/check rispondeva se esisteva e se
 *    aveva una passkey;
 *  - la conferma di un'operazione delicata (STEP_UP) vale solo per la sessione e l'amministratore
 *    che l'hanno chiesta.
 *
 * rpId e origine vengono dalla richiesta (Host e schema), che
 * {@link org.mail_panel.webserver.HostCheck} ha gia' controllato: una passkey registrata per un
 * nome vale solo per quel nome, perche' l'autenticatore firma l'hash dell'rpId e il browser
 * scrive l'origine vera della pagina.
 *
 * Il controllo qui sotto guarda che l'Host SOMIGLI a un nome DNS, non che sia il nome di questo
 * pannello: {@code evil.example} lo passa senza difficolta'. Finche' nessuno controllava l'Host,
 * bastava quello per far cominciare una cerimonia con un rpId scelto da chi chiedeva.
 */
public final class PasskeyService {

    private PasskeyService() {}

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final long CEREMONY_MS = 180_000;
    private static final int MAX_PENDING = 500;
    /** Un nome DNS: le passkey non funzionano con un indirizzo IP come rpId. */
    private static final Pattern DNS_NAME = Pattern.compile("(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*");
    private static final Pattern HOST_HEADER = Pattern.compile("[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?");

    static LongSupplier clock = System::currentTimeMillis;

    public enum Kind { LOGIN, REGISTER, STEP_UP }

    /** Una cerimonia avviata e non ancora conclusa. */
    record Pending(Kind kind, String rpId, String origin, long adminId, long sessionId,
                   AssertionRequest assertion, PublicKeyCredentialCreationOptions creation, long started) {}

    private static final Map<String, Pending> PENDING = new ConcurrentHashMap<>();

    /** Il messaggio e' una chiave dei testi (server.passkey.*), tradotta da chi risponde. */
    public static class PasskeyException extends Exception {
        public PasskeyException(String messageKey) { super(messageKey); }
    }

    public record Started(String requestId, String optionsJson) {}

    // ===================== rpId e origine =====================

    /** L'rpId dalla richiesta: il nome dell'Host senza porta, o null se non e' un nome DNS. */
    public static String rpId(String hostHeader) {
        if (hostHeader == null || !HOST_HEADER.matcher(hostHeader.trim()).matches()) return null;
        String h = hostHeader.trim().toLowerCase(java.util.Locale.ROOT);
        int colon = h.lastIndexOf(':');
        if (colon > 0) h = h.substring(0, colon);
        if (h.matches("[0-9.]+") || !DNS_NAME.matcher(h).matches()) return null;
        return h;
    }

    /** L'origine che il browser scrive in clientDataJSON: https + Host, porta compresa. */
    public static String origin(String hostHeader) {
        return "https://" + hostHeader.trim().toLowerCase(java.util.Locale.ROOT);
    }

    private static RelyingParty relyingParty(String rpId, String origin) {
        return RelyingParty.builder()
                .identity(RelyingPartyIdentity.builder().id(rpId).name(org.mail_panel.i18n.I18n.tr("brand.name")).build())
                .credentialRepository(REPOSITORY)
                .origins(Set.of(origin))
                .allowOriginPort(false)
                .allowOriginSubdomain(false)
                .validateSignatureCounter(true)
                .build();
    }

    // ===================== Cerimonie in sospeso =====================

    private static String newRequestId() {
        byte[] b = new byte[24];
        RANDOM.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private static void remember(String id, Pending p) throws PasskeyException {
        long now = clock.getAsLong();
        PENDING.entrySet().removeIf(e -> now - e.getValue().started() > CEREMONY_MS);
        if (PENDING.size() >= MAX_PENDING) throw new PasskeyException("server.passkey.busy");
        PENDING.put(id, p);
    }

    /** La cerimonia, tolta dall'elenco (vale una volta sola), se c'era e non e' scaduta. */
    private static Pending take(String id, Kind kind) throws PasskeyException {
        Pending p = id == null || id.length() > 64 ? null : PENDING.remove(id);
        if (p == null || p.kind() != kind || clock.getAsLong() - p.started() > CEREMONY_MS)
            throw new PasskeyException("server.passkey.expired");
        return p;
    }

    // ===================== Login =====================

    public static Started startLogin(String hostHeader) throws PasskeyException {
        String rpId = rpId(hostHeader);
        if (rpId == null) throw new PasskeyException("server.passkey.needsDomain");
        try {
            String origin = origin(hostHeader);
            AssertionRequest req = relyingParty(rpId, origin).startAssertion(StartAssertionOptions.builder()
                    .userVerification(UserVerificationRequirement.REQUIRED)
                    .timeout(CEREMONY_MS)
                    .build());
            String id = newRequestId();
            remember(id, new Pending(Kind.LOGIN, rpId, origin, -1, -1, req, null, clock.getAsLong()));
            return new Started(id, req.toCredentialsGetJson());
        } catch (PasskeyException e) {
            throw e;
        } catch (Exception e) {
            throw new PasskeyException("server.passkey.failed");
        }
    }

    /** L'amministratore che la passkey dimostra, dopo aver verificato tutta l'asserzione. */
    public static AuthStore.Admin finishLogin(String requestId, String credentialJson) throws PasskeyException {
        Pending p = take(requestId, Kind.LOGIN);
        AssertionResult r = verifyAssertion(p, credentialJson);
        return AuthStore.adminByUserHandle(r.getCredential().getUserHandle())
                .orElseThrow(() -> new PasskeyException("server.passkey.failed"));
    }

    private static AssertionResult verifyAssertion(Pending p, String credentialJson) throws PasskeyException {
        AssertionResult r;
        try {
            r = relyingParty(p.rpId(), p.origin()).finishAssertion(FinishAssertionOptions.builder()
                    .request(p.assertion())
                    .response(com.yubico.webauthn.data.PublicKeyCredential.parseAssertionResponseJson(credentialJson))
                    .build());
        } catch (Exception e) {
            throw new PasskeyException("server.passkey.failed");
        }
        if (!r.isSuccess() || !r.isUserVerified()) throw new PasskeyException("server.passkey.failed");
        AuthStore.passkeyUsed(r.getCredential().getCredentialId(), r.getSignatureCount());
        return r;
    }

    // ===================== Registrazione =====================

    public static Started startRegistration(AuthStore.Admin admin, long sessionId, String hostHeader) throws PasskeyException {
        String rpId = rpId(hostHeader);
        if (rpId == null) throw new PasskeyException("server.passkey.needsDomain");
        try {
            String origin = origin(hostHeader);
            PublicKeyCredentialCreationOptions req = relyingParty(rpId, origin).startRegistration(StartRegistrationOptions.builder()
                    .user(UserIdentity.builder().name(admin.username()).displayName(admin.username()).id(admin.userHandleBytes()).build())
                    .authenticatorSelection(AuthenticatorSelectionCriteria.builder()
                            .residentKey(ResidentKeyRequirement.REQUIRED)
                            .userVerification(UserVerificationRequirement.REQUIRED)
                            .build())
                    .timeout(CEREMONY_MS)
                    .build());
            String id = newRequestId();
            remember(id, new Pending(Kind.REGISTER, rpId, origin, admin.id(), sessionId, null, req, clock.getAsLong()));
            return new Started(id, req.toCredentialsCreateJson());
        } catch (PasskeyException e) {
            throw e;
        } catch (Exception e) {
            throw new PasskeyException("server.passkey.failed");
        }
    }

    public static void finishRegistration(String requestId, long sessionId, String credentialJson, String name) throws PasskeyException {
        Pending p = take(requestId, Kind.REGISTER);
        if (p.sessionId() != sessionId) throw new PasskeyException("server.passkey.expired");
        RegistrationResult r;
        try {
            r = relyingParty(p.rpId(), p.origin()).finishRegistration(FinishRegistrationOptions.builder()
                    .request(p.creation())
                    .response(com.yubico.webauthn.data.PublicKeyCredential.parseRegistrationResponseJson(credentialJson))
                    .build());
        } catch (Exception e) {
            throw new PasskeyException("server.passkey.failed");
        }
        if (!AuthStore.passkeysByCredentialId(r.getKeyId().getId()).isEmpty()) throw new PasskeyException("server.passkey.duplicate");
        if (!AuthStore.addPasskey(p.adminId(), r.getKeyId().getId(), r.getPublicKeyCose(), r.getSignatureCount(),
                name, p.rpId(), p.creation().getUser().getId().getBase64Url()))
            throw new PasskeyException("server.passkey.saveFailed");
    }

    // ===================== Conferma di un'operazione con la passkey =====================

    /** Chiede all'amministratore di confermare con una delle sue passkey. */
    public static Started startStepUp(AuthStore.Admin admin, long sessionId, String hostHeader) throws PasskeyException {
        String rpId = rpId(hostHeader);
        if (rpId == null) throw new PasskeyException("server.passkey.needsDomain");
        try {
            String origin = origin(hostHeader);
            AssertionRequest req = relyingParty(rpId, origin).startAssertion(StartAssertionOptions.builder()
                    .username(admin.username())
                    .userVerification(UserVerificationRequirement.REQUIRED)
                    .timeout(CEREMONY_MS)
                    .build());
            String id = newRequestId();
            remember(id, new Pending(Kind.STEP_UP, rpId, origin, admin.id(), sessionId, req, null, clock.getAsLong()));
            return new Started(id, req.toCredentialsGetJson());
        } catch (PasskeyException e) {
            throw e;
        } catch (Exception e) {
            throw new PasskeyException("server.passkey.failed");
        }
    }

    /** Riesce solo se la passkey e' di quell'amministratore e la cerimonia e' di quella sessione. */
    public static void finishStepUp(String requestId, long sessionId, long adminId, String credentialJson) throws PasskeyException {
        Pending p = take(requestId, Kind.STEP_UP);
        if (p.sessionId() != sessionId || p.adminId() != adminId) throw new PasskeyException("server.passkey.expired");
        AssertionResult r = verifyAssertion(p, credentialJson);
        Optional<AuthStore.Admin> who = AuthStore.adminByUserHandle(r.getCredential().getUserHandle());
        if (who.isEmpty() || who.get().id() != adminId) throw new PasskeyException("server.passkey.failed");
    }

    // ===================== Le credenziali, dal database =====================

    static final CredentialRepository REPOSITORY = new CredentialRepository() {
        @Override
        public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
            return AuthStore.adminByUsername(username)
                    .map(a -> AuthStore.passkeysOf(a.id()).stream()
                            .map(pk -> PublicKeyCredentialDescriptor.builder().id(pk.credentialId()).build())
                            .collect(Collectors.toSet()))
                    .orElse(Set.of());
        }

        @Override
        public Optional<ByteArray> getUserHandleForUsername(String username) {
            return AuthStore.adminByUsername(username).map(AuthStore.Admin::userHandleBytes);
        }

        @Override
        public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
            return AuthStore.adminByUserHandle(userHandle).map(AuthStore.Admin::username);
        }

        @Override
        public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
            return lookupAll(credentialId).stream().filter(c -> c.getUserHandle().equals(userHandle)).findFirst();
        }

        @Override
        public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
            return AuthStore.passkeysByCredentialId(credentialId).stream()
                    .map(pk -> RegisteredCredential.builder()
                            .credentialId(pk.credentialId())
                            .userHandle(bytes(pk.userHandle()))
                            .publicKeyCose(pk.publicKeyCose())
                            .signatureCount(pk.signCount())
                            .build())
                    .collect(Collectors.toSet());
        }
    };

    private static ByteArray bytes(String b64url) {
        try { return ByteArray.fromBase64Url(b64url); } catch (Exception e) { throw new IllegalStateException(e); }
    }
}
