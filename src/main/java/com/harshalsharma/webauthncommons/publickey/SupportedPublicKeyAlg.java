package com.harshalsharma.webauthncommons.publickey;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Arrays;
import java.util.Optional;

/**
 * https://fidoalliance.org/specs/fido-v2.0-rd-20180702/FIDO-COMPLETE-v2.0-rd-20180702.pdf
 */
@Getter
@AllArgsConstructor
public enum SupportedPublicKeyAlg {

    ES256(-7),
    RS256(-257);

    private static final String EC = "EC";
    private static final String RSA = "RSA";

    private final int code;

    public static Optional<SupportedPublicKeyAlg> getByCode(int code) {
        return Arrays.stream(SupportedPublicKeyAlg.values()).filter(type -> type.getCode() == code).findFirst();
    }
}
