package com.harshalsharma.webauthncommons.entities;


import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class AuthenticatorAssertionResponse {

    private final String base64AuthenticatorData;
    private final String base64Signature;
    private final String base64ClientDataJson;

}
