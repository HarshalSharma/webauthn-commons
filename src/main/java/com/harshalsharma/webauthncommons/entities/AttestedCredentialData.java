package com.harshalsharma.webauthncommons.entities;

import com.harshalsharma.webauthncommons.publickey.PublicKeyCredential;
import lombok.Builder;
import lombok.Getter;

import java.nio.ByteBuffer;

/**
 * <b>attestedCredentialData variable length</b>
 * <a href="https://developer.mozilla.org/en-US/docs/Web/API/Web_Authnetication_API/Authenticator_data#attestedcredentialdata">read more</a>
 * <p></p><p>
 * <b>First 16 bytes are AAGUID</b>
 * Authenticator Attestation Globally Unique Identifier.
 * a unique number that identifies the model of the authenticator (not the specific instance of the authenticator).
 * </p><p></p>
 * <p>
 * <b>credentialIdLength 2 bytes</b> The length of the credential ID that immediately follows these bytes.
 * </p>
 */
@Getter
@Builder
public class AttestedCredentialData {

    private static final int AAGUID_LENGTH = 16;
    private static final int CREDENTIAL_ID_LENGTH = 2;

    /**
     * 16 byte long aaguid.
     */
    private byte[] aaguid;

    /**
     * size of webauthn id - 2 bytes
     */
    private short credentialIdLength;

    /**
     * webauthn id
     */
    private byte[] credentialId;

    /**
     * CBOR encoded public key
     */
    private PublicKeyCredential publicKey;

    public byte[] encode() {
        byte[] credIdLengthBytes = ByteBuffer.allocate(2).putShort(credentialIdLength).array();
        byte[] cborCredentialPublicKey = publicKey.getCborPublicKeyCredential();
        ByteBuffer buffer = ByteBuffer.allocate(aaguid.length + credIdLengthBytes.length +
                credentialId.length + cborCredentialPublicKey.length);
        buffer.put(aaguid);
        buffer.put(credIdLengthBytes);
        buffer.put(credentialId);
        buffer.put(cborCredentialPublicKey);
        return buffer.array();
    }

    public int getBinaryLength() {
        byte[] credIdLengthBytes = ByteBuffer.allocate(2).putShort(credentialIdLength).array();
        return aaguid.length + credIdLengthBytes.length + credentialId.length
                + publicKey.getCborPublicKeyCredential().length;
    }
}
