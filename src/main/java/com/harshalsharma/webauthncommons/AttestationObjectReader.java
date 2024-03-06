package com.harshalsharma.webauthncommons;

import com.harshalsharma.webauthncommons.attestationObject.AttestationObject;

/**
 * AttestationObjectReader provides utility to read different versions of AttestationObject base64 string representation.
 */
public interface AttestationObjectReader {

    /**
     * Reads the AttestationObject from base64(Cbor-encoded) attestation object string.
     *
     * @param base64AttestationObject base64(Cbor-encoded) attestation object string
     * @return AttestationObject which one can use to easily read its details.
     */
    AttestationObject read(String base64AttestationObject);
}
