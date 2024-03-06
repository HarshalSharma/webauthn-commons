package com.harshalsharma.webauthncommons.attestationObject;

/**
 * Object version of the attestation object which simplifies reading its properties.
 */
public interface AttestationObject {

    /**
     * Reads client id from attestation object -> authenticator data -> attData -> credential id.
     * credential id is present as binary data inside attData, this method returns it as base64-url-safe version of it.
     *
     * @return base64 url safe encoded client id.
     */
    String getBase64UrlSafeCredentialId();
}
