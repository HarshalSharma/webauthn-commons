package com.harshalsharma.webauthncommons.authentication.signverifiers;

import com.harshalsharma.webauthncommons.authentication.SignatureVerifier;
import com.harshalsharma.webauthncommons.publickey.SupportedPublicKeyAlg;
import com.harshalsharma.webauthncommons.publickey.UnsupportedPublicKeyException;
import org.apache.commons.codec.binary.Base64;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class RSASignatureVerifier implements SignatureVerifier {
    @Override
    public boolean verifySignature(byte[] data, byte[] signature, String alg, String base64KeySpec) {
        Arrays.stream(SupportedPublicKeyAlg.values()).filter(supportedAlg -> supportedAlg.name().equals(alg))
                .findAny().orElseThrow(() -> new UnsupportedPublicKeyException("RSA Public key algorithm not supported: " + alg));

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(Base64.decodeBase64(base64KeySpec)));
            Signature signatureVerifier = Signature.getInstance("SHA256withRSA");
            signatureVerifier.initVerify(publicKey);
            signatureVerifier.update(data);
            return signatureVerifier.verify(signature);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException(e);
        }
    }
}
