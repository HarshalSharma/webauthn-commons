package com.harshalsharma.webauthncommons.registeration;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.jetbrains.annotations.NotNull;

import java.util.List;
import java.util.Map;

@Getter
@RequiredArgsConstructor
@Builder
@AllArgsConstructor
public class PublicKeyCreationOptions {

    @NotNull
    private final PublicKeyCredentialRpEntity rp;

    @NotNull
    private final PublicKeyCredentialUserEntity user;

    /**
     * challenge intended to be used for generating the newly created credential’s attestation object.
     */
    @NotNull
    private final String challenge;

    @NotNull
    private final List<PublicKeyCredentialParameters> pubKeyCredParams;

    private long timeout;

    private List<PublicKeyCredentialDescriptor> excludeCredentials;

    private AuthenticatorSelectionCriteria authenticatorSelection;

    @NotNull
    private String attestation = "none";

    private Map<?, ?> extensions;
}
