package com.harshalsharma.webauthncommons.authentication;

import com.harshalsharma.webauthncommons.entities.AuthenticatorAssertionResponse;
import com.harshalsharma.webauthncommons.entities.ClientDataJson;
import com.harshalsharma.webauthncommons.publickey.PublicKeyAccessor;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.util.Arrays;

import java.util.Optional;

import static com.harshalsharma.webauthncommons.authentication.signverifiers.SignatureVerifierFactory.getSignatureVerifier;
import static com.harshalsharma.webauthncommons.io.MessageUtils.decodeJSON;
import static com.harshalsharma.webauthncommons.io.MessageUtils.hashSHA256;

public interface SignatureVerifier {

    static boolean verifySignature(AuthenticatorAssertionResponse assertion, String challenge,
                                   PublicKeyAccessor credential) {
        byte[] clientDataJsonAsBytes = Base64.decodeBase64(assertion.getBase64ClientDataJson());
        ClientDataJson clientDataJson = decodeJSON(clientDataJsonAsBytes, ClientDataJson.class);
        if (StringUtils.isBlank(challenge) || !challenge.equals(clientDataJson.getChallenge())) {
            return false;
        }
        byte[] clientDataJsonHash = hashSHA256(clientDataJsonAsBytes);
        byte[] authDataBytes = Base64.decodeBase64(assertion.getBase64AuthenticatorData());
        byte[] dataToSign = Arrays.concatenate(authDataBytes, clientDataJsonHash);
        return verifySignature(dataToSign, assertion.getBase64Signature(), credential);
    }

    static boolean verifySignature(byte[] data, String base64Signature, PublicKeyAccessor credential) {
        String keyType = credential.getKeyType();
        Optional<SignatureVerifier> signatureVerifier = getSignatureVerifier(keyType);
        return signatureVerifier.map(verifier ->
                        verifier.verifySignature(data, Base64.decodeBase64(base64Signature),
                                credential.getAlg(), credential.getEncodedKeySpec()))
                .orElse(false);
    }

    boolean verifySignature(byte[] data, byte[] base64Signature, String alg, String keySpec);
}
