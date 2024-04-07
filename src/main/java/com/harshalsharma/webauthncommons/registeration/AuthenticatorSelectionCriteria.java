package com.harshalsharma.webauthncommons.registeration;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
public class AuthenticatorSelectionCriteria {
    private String authenticatorAttachment;
    private String residentKey;
    private boolean requireResidentKey = false;
    private String userVerification = "preferred";
}
