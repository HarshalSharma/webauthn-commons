package com.harshalsharma.webauthncommons.attestationObject;

public class InvalidAttestationObjException extends RuntimeException {
    public InvalidAttestationObjException(String message) {
        super(message);
    }
}
