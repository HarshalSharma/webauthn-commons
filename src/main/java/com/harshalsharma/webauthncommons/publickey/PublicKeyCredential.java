package com.harshalsharma.webauthncommons.publickey;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class PublicKeyCredential implements PublicKeyAccessor {

    private byte[] cborPublicKeyCredential;

    private String alg;

    private String encodedKeySpec;

    private String keyType;

}
