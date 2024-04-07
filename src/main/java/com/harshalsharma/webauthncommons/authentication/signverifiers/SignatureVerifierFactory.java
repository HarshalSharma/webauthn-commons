package com.harshalsharma.webauthncommons.authentication.signverifiers;

import com.harshalsharma.webauthncommons.authentication.SignatureVerifier;

import java.util.Optional;

public interface SignatureVerifierFactory {

    SignatureVerifier ecSignatureVerifier = new ECSignatureVerifier();
    SignatureVerifier rsaSignatureVerifier = new RSASignatureVerifier();

    static Optional<SignatureVerifier> getSignatureVerifier(String keyType) {
        SignatureVerifier verifier = null;
        if ("EC".equals(keyType)) {
            verifier = ecSignatureVerifier;
        } else if ("RSA".equals(keyType)) {
            verifier = rsaSignatureVerifier;
        }
        return Optional.ofNullable(verifier);
    }


}
