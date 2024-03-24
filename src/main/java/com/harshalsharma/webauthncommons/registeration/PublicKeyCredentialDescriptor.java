package com.harshalsharma.webauthncommons.registeration;

import java.util.List;

public class PublicKeyCredentialDescriptor {
    private String type;

    /**
     * credential id as binary.
     */
    private byte[] id;

    private List<String> transports;
}
