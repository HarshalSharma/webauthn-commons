package com.harshalsharma.webauthncommons.clientdatajson;

public class InvalidClientDataJsonException extends RuntimeException {

    public static final String INVALID_FORMAT = "Format of the client data json is invalid.";
    public static final String INVALID_ORIGIN = "Invalid Origin.";
    public static final String INVALID_TYPE = "Invalid Client Data Json Type.";
    public static final String INVALID_CHALLENGE = "Challenge Verification Failed.";

    public InvalidClientDataJsonException(String message) {
        super(message);
    }

    public InvalidClientDataJsonException(String message, Throwable cause) {
        super(message, cause);
    }
}
