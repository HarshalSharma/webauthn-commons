package com.harshalsharma.webauthncommons.attestationObject;

import com.harshalsharma.webauthncommons.entities.AttestationObject;
import com.harshalsharma.webauthncommons.publickey.PublicKeyCredential;

/**
 * Utility version of the attestation object which simplifies reading its properties.
 */
public interface AttestationObjectExplorer {

    /**
     * Returns Decoded AttestationObject in its native properties.
     *
     * @return decoded AttestationObject
     */
    AttestationObject getAttestationObject();

    /**
     * Reads client id from attestation object -> authenticator data -> attData -> credential id.
     * credential id is present as binary data inside attData, this method returns it as base64-url-safe version of it.
     *
     * @return base64 url safe encoded client id.
     */
    String getWebauthnId();

    /**
     * Returns base64 encoded public key spec.
     *
     * @return base64 encoded public key spec.
     */
    String getEncodedPublicKeySpec();

    /**
     * Returns public key type.
     *
     * @return public key type.
     */
    String getKeyType();

    PublicKeyCredential getPublicKeyCredential();
}
