package com.harshalsharma.webauthncommons.authentication;

import com.harshalsharma.webauthncommons.entities.AuthenticatorAssertionResponse;
import com.harshalsharma.webauthncommons.entities.ClientDataJson;
import com.harshalsharma.webauthncommons.publickey.PublicKeyAccessor;
import org.apache.commons.codec.binary.Base64;

import java.util.Arrays;
import java.util.Optional;

import static com.harshalsharma.webauthncommons.authentication.signverifiers.SignatureVerifierFactory.getSignatureVerifier;
import static com.harshalsharma.webauthncommons.io.MessageUtils.decodeJSON;
import static com.harshalsharma.webauthncommons.io.MessageUtils.hashSHA256;

public interface SignatureVerifier {

    static boolean verifySignature(AuthenticatorAssertionResponse assertion, String challenge,
                                   PublicKeyAccessor credential) {
        byte[] clientDataJsonAsBytes = Base64.decodeBase64(assertion.getBase64ClientDataJson());
        ClientDataJson clientDataJson = decodeJSON(clientDataJsonAsBytes, ClientDataJson.class);
        byte[] challengeBytes = Base64.decodeBase64(challenge);
        byte[] cdjChallengeBytes = Base64.decodeBase64(clientDataJson.getChallenge());
        if (!Arrays.equals(challengeBytes, cdjChallengeBytes)) {
            return false;
        }
        byte[] clientDataJsonHash = hashSHA256(clientDataJsonAsBytes);
        byte[] authDataBytes = Base64.decodeBase64(assertion.getBase64AuthenticatorData());
        byte[] dataToSign = new byte[authDataBytes.length + clientDataJsonHash.length];
        System.arraycopy(authDataBytes, 0, dataToSign, 0, authDataBytes.length);
        System.arraycopy(clientDataJsonHash, 0, dataToSign, authDataBytes.length, clientDataJsonHash.length);
        return verifySignature(dataToSign, assertion.getBase64Signature(), credential);
    }

    static boolean verifySignature(byte[] data, String base64Signature, PublicKeyAccessor credential) {
        String keyType = credential.getKeyType();
        Optional<SignatureVerifier> signatureVerifier = getSignatureVerifier(keyType);
        return signatureVerifier.map(verifier ->
                        verifier.verifySignature(data, Base64.decodeBase64(base64Signature),
                                credential.getEncodedKeySpec()))
                .orElse(false);
    }

    boolean verifySignature(byte[] data, byte[] base64Signature, String keySpec);
}
