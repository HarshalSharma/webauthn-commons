package com.harshalsharma.webauthncommons.attestationObject;

import com.harshalsharma.webauthncommons.attestationObject.entities.AttestationObject;
import com.harshalsharma.webauthncommons.attestationObject.parsers.AttestationObjectExplorerImpl;
import com.harshalsharma.webauthncommons.attestationObject.parsers.AuthenticatorDataReader;
import com.harshalsharma.webauthncommons.io.DataEncoderDecoder;

/**
 * AttestationObjectReader provides utility to read different versions of AttestationObject base64 string representation.
 */
public interface AttestationObjectReader {

    /**
     * Reads the AttestationObject from base64(Cbor-encoded) attestation object string.
     *
     * @param base64AttestationObject base64(Cbor-encoded) attestation object string
     * @return AttestationObjectExplorer which one can use to easily read details from AttestationObject.
     */
    static AttestationObjectExplorer read(String base64AttestationObject) {
        AttestationObject attestationObjectRaw = DataEncoderDecoder.fromBase64Cbor(base64AttestationObject, AttestationObject.class);
        AttestationObject attestationObject = AttestationObject.builder().fmt(attestationObjectRaw.getFmt())
                .authData(attestationObjectRaw.getAuthData())
                .authDataObj(AuthenticatorDataReader.read(attestationObjectRaw.getAuthData())).build();
        return new AttestationObjectExplorerImpl(attestationObject);
    }
}
