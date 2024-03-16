package com.harshalsharma.webauthncommons.entities;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Getter;

import java.util.Map;

@Getter
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthenticatorData {

    private static final int SIGN_COUNT_SIZE = 4;
    private static final int RP_ID_HASH_SIZE = 32;
    private static final int FLAGS_SIZE = 1;

    /**
     * 8 bits which indicates various properties.
     * <a href="https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Authenticator_data#flags">details</a>
     */
    private byte flags;

    /**
     * 32 bytes long
     * The SHA 256 hash of the Relying Party ID that this credential is scoped to.
     * The server will ensure that this hash matches the SHA256 hash of its own relying party ID
     * in order to prevent phishing or other man in the middle attacks.
     */
    private byte[] rpIdHash;

    /**
     * 4 bytes or 4*8=32 bits long signature counter.
     * if supported by the authenticator or zero otherwise.
     * servers may optionally use this counter to detect authenticator cloning.
     */
    private int signCount;

    /**
     * variable length, attestedCredentialData.
     */
    private AttestedCredentialData attestedCredentialData;

    /**
     * extensions.
     */
    private Map<?, ?> extensions;
}
