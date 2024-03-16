package com.harshalsharma.webauthncommons.attestationObject.parsers;

import com.harshalsharma.webauthncommons.entities.AttestedCredentialData;
import com.harshalsharma.webauthncommons.attestationObject.exceptions.InvalidAttestationObjException;
import com.harshalsharma.webauthncommons.io.CborObject;
import com.harshalsharma.webauthncommons.io.DataEncoderDecoder;
import org.apache.commons.lang3.ArrayUtils;

import java.nio.ByteBuffer;
import java.util.Map;

public class AttestedCredentialDataReader {

    private static final int MIN_ATT_DATA_LENGTH = 18;
    public static final int AAGUID_BYTES_LENGTH = 16;

    public static AttestedCredentialData read(byte[] attestedData) {
        if (ArrayUtils.isEmpty(attestedData) || attestedData.length < MIN_ATT_DATA_LENGTH) {
            throw new InvalidAttestationObjException("Auth Data is in invalid format.");
        }
        AttestedCredentialData.AttestedCredentialDataBuilder builder = AttestedCredentialData.builder();
        builder.aaguid(readAAGUIDBytes(attestedData));
        short credIdLength = readCredIdLength(attestedData);
        builder.credentialIdLength(credIdLength);
        builder.credentialId(readCredential(attestedData, credIdLength));
        byte[] remainingBytes = ArrayUtils.subarray(attestedData, 18 + credIdLength, attestedData.length);
        CborObject cborObject = DataEncoderDecoder.readFirstCborObject(remainingBytes).orElseThrow(
                () -> new InvalidAttestationObjException("Public key not found")
        );
        builder.publicKey(PublicKeyCredentialReader.read(cborObject));
        return builder.build();
    }

    private static byte[] readAAGUIDBytes(byte[] attestedData) {
        return ArrayUtils.subarray(attestedData, 0, AAGUID_BYTES_LENGTH);
    }

    private static short readCredIdLength(byte[] attestedData) {
        byte[] length = ArrayUtils.subarray(attestedData, 16, 18);
        return ByteBuffer.wrap(length).getShort();
    }

    private static byte[] readCredential(byte[] attestedData, short credIdLength) {
        return ArrayUtils.subarray(attestedData, 18, 18 + credIdLength);
    }

    private static Map<Integer, Object> readPublicKeyMap(byte[] attestedData, short credIdLength) {
        byte[] remainingBytes = ArrayUtils.subarray(attestedData, 18 + credIdLength, attestedData.length);
        byte[] keyBytes = ArrayUtils.subarray(remainingBytes, 0, 78);

        throw new InvalidAttestationObjException("Public key not found");
    }

}
