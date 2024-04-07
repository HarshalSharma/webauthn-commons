package com.harshalsharma.webauthncommons;

import com.harshalsharma.webauthncommons.attestationObject.AttestationObjectExplorer;
import com.harshalsharma.webauthncommons.attestationObject.AttestationObjectReader;
import com.harshalsharma.webauthncommons.authentication.SignatureVerifier;
import com.harshalsharma.webauthncommons.entities.AuthenticatorAssertionResponse;
import com.harshalsharma.webauthncommons.publickey.PublicKeyCredential;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class PublicKeyTests {

    @Test
    void test4() {
        //given saved public key
        String publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHpNucNkC043MTDaX9+Bp9xs70tsy97UN9WtEy7dMqXv7BPWdyizseH6Qd+IXG668Q1C3dFRzt68PgV7C8Qis2A==";
        String keyType = "EC";
        String keyAlg = "ES256";
        //given authentication authData, signature and clientDataJson
        String challenge = "EGYtAMgi8B2Ey1FNVfVF93m5LEz_CfwTy00W2zoPEN4";
        String authData = "t8DGRTBfls-BhOH2QC404lvdhe_t2_NkvM0nQWEEADcFAAAAAA";
        String signature = "MEQCIG6svxsNl8nCYkCbBvPmjHRKfc5_oFdeln2t0xqyOSdbAiAgBh26HMQDGW0q3uwToegYpmQuk3bmJ2qFC0GvOakq3Q";
        String clientDataJson = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiRUdZdEFNZ2k4QjJFeTFGTlZmVkY5M201TEV6X0Nmd1R5MDBXMnpvUEVONCIsIm9yaWdpbiI6Imh0dHBzOi8vb3BvdG9ubmllZS5naXRodWIuaW8iLCJjcm9zc09yaWdpbiI6ZmFsc2V9";


        AuthenticatorAssertionResponse assertion = AuthenticatorAssertionResponse.builder()
                .base64AuthenticatorData(authData)
                .base64ClientDataJson(clientDataJson)
                .base64Signature(signature)
                .build();
        boolean verifySignature = SignatureVerifier.verifySignature(assertion, challenge,
                PublicKeyCredential.builder().encodedKeySpec(publicKey).keyType(keyType).alg(keyAlg).build());
        assertTrue(verifySignature, "Signature verification should succeed.");
    }

    @Test
    void test3() {
        //given registration attestation object
        String attestationObject = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikt8DGRTBfls-BhOH2QC404lvdhe_t2_NkvM0nQWEEADdFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIG3U68BVLKmmjpNF5gfsJf9w4gbLeAAuoOUO92iCL8yMpQECAyYgASFYIB6TbnDZAtONzEw2l_fgafcbO9LbMve1DfVrRMu3TKl7Ilgg-wT1ncos7Hh-kHfiFxuuvENQt3RUc7evD4FewvEIrNg";
        //given authentication authData, signature and clientDataJson
        String challenge = "EGYtAMgi8B2Ey1FNVfVF93m5LEz_CfwTy00W2zoPEN4";
        String authData = "t8DGRTBfls-BhOH2QC404lvdhe_t2_NkvM0nQWEEADcFAAAAAA";
        String signature = "MEQCIG6svxsNl8nCYkCbBvPmjHRKfc5_oFdeln2t0xqyOSdbAiAgBh26HMQDGW0q3uwToegYpmQuk3bmJ2qFC0GvOakq3Q";
        String clientDataJson = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiRUdZdEFNZ2k4QjJFeTFGTlZmVkY5M201TEV6X0Nmd1R5MDBXMnpvUEVONCIsIm9yaWdpbiI6Imh0dHBzOi8vb3BvdG9ubmllZS5naXRodWIuaW8iLCJjcm9zc09yaWdpbiI6ZmFsc2V9";


        AttestationObjectExplorer attestationObjectExplorer = AttestationObjectReader.read(attestationObject);
        AuthenticatorAssertionResponse assertion = AuthenticatorAssertionResponse.builder()
                .base64AuthenticatorData(authData)
                .base64ClientDataJson(clientDataJson)
                .base64Signature(signature)
                .build();
        boolean verifySignature = SignatureVerifier.verifySignature(assertion, challenge,
                attestationObjectExplorer.getPublicKeyCredential());
        assertTrue(verifySignature, "Signature verification should succeed.");
    }
}
