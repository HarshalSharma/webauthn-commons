package com.harshalsharma.webauthncommons.attestationObject.parsers;

import com.harshalsharma.webauthncommons.entities.AttestedCredentialData;
import com.harshalsharma.webauthncommons.entities.AuthenticatorData;
import com.harshalsharma.webauthncommons.attestationObject.exceptions.InvalidAttestationObjException;
import com.harshalsharma.webauthncommons.io.DataEncoderDecoder;
import org.apache.commons.lang3.ArrayUtils;

import java.math.BigInteger;
import java.util.Map;

/**
 * @author harshalsharma
 */
public class AuthenticatorDataReader {

    public static final int RP_ID_HASH_BYTES_LENGTH = 32;
    public static final int FLAGS_BYTE_LENGTH = 1;
    public static final int SIGNATURE_COUNT_BYTES_LENGTH = 4;
    private static final int MIN_AUTH_DATA_LENGTH = RP_ID_HASH_BYTES_LENGTH + FLAGS_BYTE_LENGTH + SIGNATURE_COUNT_BYTES_LENGTH;

    public static AuthenticatorData read(byte[] authData) {
        if (ArrayUtils.isEmpty(authData) || authData.length < MIN_AUTH_DATA_LENGTH) {
            throw new InvalidAttestationObjException("Auth Data is in invalid format.");
        }

        byte[] rpIdHashBytes = readRpIdHashBytes(authData);
        byte flags = readFlags(authData);
        int signCount = readSignatureCount(authData);

        AuthenticatorData.AuthenticatorDataBuilder authDataBuilder = AuthenticatorData.builder()
                .rpIdHash(rpIdHashBytes)
                .flags(flags)
                .signCount(signCount);

        int attestedCredentialDataLength = 0;
        if (hasAttestedCredentialData(flags)) {
            byte[] attestedDataExtended = ArrayUtils.subarray(authData, MIN_AUTH_DATA_LENGTH, authData.length);
            AttestedCredentialData attestedCredentialData = AttestedCredentialDataReader.read(attestedDataExtended);
            attestedCredentialDataLength = attestedCredentialData.getBinaryLength();
            authDataBuilder.attestedCredentialData(attestedCredentialData);
        }
        if (hasExtensions(flags)) {
            byte[] extensions = ArrayUtils.subarray(authData,
                    MIN_AUTH_DATA_LENGTH + attestedCredentialDataLength, authData.length);
            Map<?, ?> extensionsMap = DataEncoderDecoder.fromCbor(extensions, Map.class);
            authDataBuilder.extensions(extensionsMap);
        }
        return authDataBuilder.build();
    }

    /**
     * checks if the 2nd most significant bit is set.
     * bitwise AND with 01000000
     *
     * @param flags flags set in current auth data.
     * @return true when 2nd most MSB is set, false otherwise.
     */
    private static boolean hasAttestedCredentialData(byte flags) {
        return (flags & 64) == 64;
    }

    /**
     * checks if the most significant bit is set.
     * bitwise AND with 10000000
     *
     * @param flags flags set in current auth data.
     * @return true when MSB is set, false otherwise.
     */
    private static boolean hasExtensions(byte flags) {
        return (flags & 128) == 128;
    }

    private static byte[] readRpIdHashBytes(byte[] authData) {
        return ArrayUtils.subarray(authData, 0, RP_ID_HASH_BYTES_LENGTH);
    }

    private static byte readFlags(byte[] authData) {
        return authData[32];
    }

    private static int readSignatureCount(byte[] authData) {
        return new BigInteger(ArrayUtils.subarray(authData, 33, 33 + SIGNATURE_COUNT_BYTES_LENGTH)).intValue();
    }
}
