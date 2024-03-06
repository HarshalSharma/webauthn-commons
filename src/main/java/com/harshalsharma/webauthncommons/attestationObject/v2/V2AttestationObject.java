package com.harshalsharma.webauthncommons.attestationObject.v2;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.harshalsharma.webauthncommons.attestationObject.AttestationObject;
import lombok.Builder;
import lombok.Getter;

import java.util.Base64;

@Getter
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class V2AttestationObject implements AttestationObject {

    private String fmt;

    private V2AuthenticatorData authData;

    @Override
    public String getBase64UrlSafeCredentialId() {
        byte[] credentialId = authData.getAttestedCredentialData().getCredentialId();
        return Base64.getEncoder().encodeToString(credentialId);
    }
}
