package com.harshalsharma.webauthncommons.publickey;

public interface PublicKeyAccessor {

    String getEncodedKeySpec();

    String getKeyType();

    String getAlg();

}
