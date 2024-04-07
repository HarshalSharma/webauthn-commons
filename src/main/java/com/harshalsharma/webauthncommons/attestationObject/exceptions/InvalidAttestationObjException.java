package com.harshalsharma.webauthncommons.attestationObject.exceptions;

public class InvalidAttestationObjException extends RuntimeException {
    public InvalidAttestationObjException(String message) {
        super(message);
    }

    public InvalidAttestationObjException(Throwable e) {
        super(e);
    }
}
