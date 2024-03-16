package com.harshalsharma.webauthncommons.publickey;

public class UnsupportedPublicKeyCredential extends RuntimeException {
    public UnsupportedPublicKeyCredential(String message) {
        super(message);
    }

    public UnsupportedPublicKeyCredential(String message, Throwable e) {
        super(message, e);
    }
}
