package com.harshalsharma.webauthncommons.attestationObject.entities;

import lombok.Builder;
import lombok.Getter;

import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Getter
@Builder
public class PublicKeyCredential {

    private byte[] cborPublicKeyCredential;

    private String alg;

    private X509EncodedKeySpec keySpec;

    private String keyType;

    public String getEncodedKeySpec() {
        return Base64.getEncoder().encodeToString(keySpec.getEncoded());
    }

}
