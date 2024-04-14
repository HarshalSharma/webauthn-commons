package com.harshalsharma.webauthncommons.authentication;

import com.harshalsharma.webauthncommons.attestationObject.parsers.AuthenticatorDataReader;
import com.harshalsharma.webauthncommons.entities.AuthenticatorData;
import com.harshalsharma.webauthncommons.io.DataEncoderDecoder;
import com.harshalsharma.webauthncommons.io.MessageUtils;
import lombok.Builder;

import java.util.Arrays;

@Builder
public class AuthNDataValidator {

    private static final int BIT_USER_PRESENCE = 1;
    private static final int BIT_USER_VERIFICATION = 1 << 2;
    private String rpId;

    /**
     * Validate the Authenticator Data received during Authentication.
     * It compares the RP ID hash, and also verifies that either UP or UV bit is set.
     * <p>
     * Bit 0, User Presence (UP): If set (i.e., to 1), the authenticator validated that the user was present through some Test of User Presence (TUP), such as touching a button on the authenticator.
     * Bit 2, User Verification (UV): If set, the authenticator verified the actual user through a biometric, PIN, or other method.
     *
     * @param authData base64 authenticator data as received in assertion response.
     */
    public void validate(String authData) {
        AuthenticatorData authenticatorData = AuthenticatorDataReader
                .read(DataEncoderDecoder.decodeBase64Bytes(authData));

        if (!Arrays.equals(MessageUtils.hashSHA256(rpId.getBytes()), authenticatorData.getRpIdHash())) {
            throw new InvalidAuthDataException(InvalidAuthDataException.INVALID_RP_ID_HASH);
        }

        byte flags = authenticatorData.getFlags();
        if (!(isUserPresent(flags) || isVerified(flags))) {
            throw new InvalidAuthDataException(InvalidAuthDataException.NO_UP_OR_UV_BIT_SET);
        }
    }

    private static boolean isVerified(byte flags) {
        return (flags & BIT_USER_VERIFICATION) != 0;
    }

    private static boolean isUserPresent(byte flags) {
        return (flags & BIT_USER_PRESENCE) != 0;
    }
}
