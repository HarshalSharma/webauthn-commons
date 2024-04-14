package com.harshalsharma.webauthncommons.authentication.signverifiers;

import com.harshalsharma.webauthncommons.authentication.SignatureVerifier;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class ECSignatureVerifier implements SignatureVerifier {

    private static final BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();

    @Override
    public boolean verifySignature(byte[] data, byte[] signature, String base64KeySpec) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("EC", bouncyCastleProvider);
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(Base64.decodeBase64(base64KeySpec)));
            Signature signatureVerifier = Signature.getInstance("SHA256withECDSA", bouncyCastleProvider);
            signatureVerifier.initVerify(publicKey);
            signatureVerifier.update(data);
            return signatureVerifier.verify(signature);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException(e);
        }
    }
}
