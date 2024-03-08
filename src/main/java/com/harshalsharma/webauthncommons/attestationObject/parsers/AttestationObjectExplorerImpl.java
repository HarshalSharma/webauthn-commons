package com.harshalsharma.webauthncommons.attestationObject.parsers;

import com.harshalsharma.webauthncommons.attestationObject.AttestationObjectExplorer;
import com.harshalsharma.webauthncommons.attestationObject.entities.AttestationObject;
import com.harshalsharma.webauthncommons.io.DataEncoderDecoder;

import java.security.spec.X509EncodedKeySpec;

public class AttestationObjectExplorerImpl implements AttestationObjectExplorer {
    private final AttestationObject attestationObject;

    public AttestationObjectExplorerImpl(AttestationObject attestationObject) {
        this.attestationObject = attestationObject;
    }

    @Override
    public AttestationObject getAttestationObject() {
        return attestationObject;
    }

    @Override
    public String getWebauthnId() {
        byte[] credentialId = attestationObject.getAuthDataObj().getAttestedCredentialData().getCredentialId();
        return DataEncoderDecoder.encodeBase64URLSafeString(credentialId);
    }

    @Override
    public X509EncodedKeySpec getPublicKeySpec() {
        return attestationObject.getAuthDataObj().getAttestedCredentialData()
                .getPublicKey().getKeySpec();
    }

    @Override
    public String getEncodedPublicKeySpec() {
        return attestationObject.getAuthDataObj().getAttestedCredentialData()
                .getPublicKey().getEncodedKeySpec();
    }

    @Override
    public String getKeyType() {
        return attestationObject.getAuthDataObj().getAttestedCredentialData()
                .getPublicKey().getKeyType();
    }

}
