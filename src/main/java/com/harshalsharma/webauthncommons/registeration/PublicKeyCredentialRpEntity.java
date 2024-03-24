package com.harshalsharma.webauthncommons.registeration;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.jetbrains.annotations.NotNull;

@Getter
@AllArgsConstructor
public class PublicKeyCredentialRpEntity {

    @NotNull
    private String id;

}
