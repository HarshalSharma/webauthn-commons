package com.harshalsharma.webauthncommons.attestationObject.entities;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Arrays;
import java.util.Optional;

@Getter
@AllArgsConstructor
public enum SupportedPublicKeyAlg {

    ES256(-7),
    RS256(-40),
    RS384(-41),
    RS512(-42),
    PS256(-37),
    PS384(-38),
    PS512(-39);

    private static final String EC = "EC";
    private static final String RSA = "RSA";

    private final int code;

    public static Optional<SupportedPublicKeyAlg> getByCode(int code) {
        return Arrays.stream(SupportedPublicKeyAlg.values()).filter(type -> type.getCode() == code).findFirst();
    }
}
