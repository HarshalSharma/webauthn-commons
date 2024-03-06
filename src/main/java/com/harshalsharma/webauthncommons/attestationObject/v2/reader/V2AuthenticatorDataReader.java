package com.harshalsharma.webauthncommons.attestationObject.v2.reader;

import com.harshalsharma.webauthncommons.attestationObject.InvalidAttestationObjException;
import com.harshalsharma.webauthncommons.attestationObject.v2.V2AuthenticatorData;
import org.apache.commons.lang3.ArrayUtils;

import java.math.BigInteger;

/**
 * @author harshalsharma
 */
public class V2AuthenticatorDataReader {

    public static final int RP_ID_HASH_BYTES_LENGTH = 32;
    public static final int FLAGS_BYTE_LENGTH = 1;
    public static final int SIGNATURE_COUNT_BYTES_LENGTH = 4;
    private static final int MIN_AUTH_DATA_LENGTH = RP_ID_HASH_BYTES_LENGTH + FLAGS_BYTE_LENGTH + SIGNATURE_COUNT_BYTES_LENGTH;

    public static V2AuthenticatorData read(byte[] authData) {
        if (ArrayUtils.isEmpty(authData) || authData.length < MIN_AUTH_DATA_LENGTH) {
            throw new InvalidAttestationObjException("Auth Data is in invalid format.");
        }
        V2AuthenticatorData.V2AuthenticatorDataBuilder builder = V2AuthenticatorData.builder();
        byte[] rpIdHashBytes = readRpIdHashBytes(authData);
        byte flags = readFlags(authData);
        int signCount = readSignatureCount(authData);
        V2AuthenticatorData.V2AuthenticatorDataBuilder authDataBuilder = V2AuthenticatorData.builder()
                .rpIdHash(rpIdHashBytes)
                .flags(flags)
                .signCount(signCount);
        if (hasAttestedCredentialData(flags)) {

        }
        if (hasExtensions(flags)) {

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
