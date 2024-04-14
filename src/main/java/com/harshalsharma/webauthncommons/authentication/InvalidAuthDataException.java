package com.harshalsharma.webauthncommons.authentication;

public class InvalidAuthDataException extends RuntimeException {

    public static String INVALID_RP_ID_HASH = "Invalid RP ID Hash.";
    public static String NO_UP_OR_UV_BIT_SET = "Neither User Presence or User Verification bit is set.";

    public InvalidAuthDataException(String message) {
        super(message);
    }
}
