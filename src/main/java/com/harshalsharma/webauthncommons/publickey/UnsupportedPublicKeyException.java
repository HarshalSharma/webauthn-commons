package com.harshalsharma.webauthncommons.publickey;

public class UnsupportedPublicKeyException extends RuntimeException {
    public UnsupportedPublicKeyException(String message) {
        super(message);
    }

    public UnsupportedPublicKeyException(String message, Throwable e) {
        super(message, e);
    }
}
