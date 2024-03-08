package com.harshalsharma.webauthncommons.attestationObject.parsers;

import com.fasterxml.jackson.core.type.TypeReference;
import com.harshalsharma.webauthncommons.attestationObject.entities.PublicKeyCredential;
import com.harshalsharma.webauthncommons.attestationObject.entities.SupportedPublicKeyAlg;
import com.harshalsharma.webauthncommons.attestationObject.exceptions.UnsupportedPublicKeyCredential;
import com.harshalsharma.webauthncommons.io.CborObject;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.*;
import java.util.Map;
import java.util.Optional;

/**
 * The credential public key encoded in <a href="https://datatracker.ietf.org/doc/html/rfc8152">COSE_Key format</a>.
 * <p></p>
 * The example is a COSE_Key Elliptic Curve public key in EC2 format.
 * <p>1: is the key type. A value of 2 is the EC2 type</p>
 * <p>3: is the signature algorithm. A value of -7 is the ES256 signature algorithm</p>
 * <p>-1: is the curve type. A value of 1 is the P-256 curve</p>
 * <p>-2: is the x-coordinate as byte string</p>
 * <p>-3: is the y-coordinate as byte string</p>
 *
 * @author harshalsharma
 */
public class PublicKeyCredentialReader {

    public static final int RSA_COSE_KEY_SIZE = 4;
    public static final int EC_COSE_KEY_SIZE = 5;
    public static final String RSA_KEY_TYPE = "RSA";
    public static final String EC_KEY_TYPE = "EC";
    public static final int SIGNATURE_ALG = 3;

    // EC KEY CONSTANTS
    public static final int X_COORDINATE = -2;
    public static final int Y_COORDINATE = -3;
    public static final int CURVE_TYPE = -1;

    // RSA KEY CONSTANTS
    public static final int RSA_EXPONENT = -2;
    public static final int RSA_MODULUS = -1;

    public static PublicKeyCredential read(CborObject publicKeyCredentialCbor) {
        Map<Integer, Object> coseMap = publicKeyCredentialCbor.getAs(new TypeReference<Map<Integer, Object>>() {
        });
        String keyType = null;
        X509EncodedKeySpec keySpec = null;
        Optional<SupportedPublicKeyAlg> alg = SupportedPublicKeyAlg.getByCode((Integer) coseMap.getOrDefault(SIGNATURE_ALG, 0));
        if (!alg.isPresent()) {
            throw new UnsupportedPublicKeyCredential("Unsupported Algorithm of Public key.");
        }
        try {
            if (coseMap.size() == RSA_COSE_KEY_SIZE && !coseMap.containsKey(Y_COORDINATE)) {
                // Extract RSA Key
                keyType = RSA_KEY_TYPE;
                keySpec = readRSAKeySpec(coseMap, alg.get());
            } else if (coseMap.size() == EC_COSE_KEY_SIZE && coseMap.containsKey(Y_COORDINATE)) {
                // Extract Elliptic Curve Key
                keyType = EC_KEY_TYPE;
                keySpec = readECKeySpec(coseMap, alg.get());
            }
        } catch (Exception e) {
            throw new UnsupportedPublicKeyCredential("Could not read the available key.", e);
        }
        if (StringUtils.isBlank(keyType) || ObjectUtils.isEmpty(keySpec)) {
            throw new UnsupportedPublicKeyCredential("Could not read the available key.");
        }
        return PublicKeyCredential.builder()
                .cborPublicKeyCredential(publicKeyCredentialCbor.getCborBytes())
                .keyType(keyType)
                .keySpec(keySpec)
                .alg(alg.get().name()).build();
    }

    private static X509EncodedKeySpec readECKeySpec(Map<Integer, Object> coseMap, SupportedPublicKeyAlg alg) {
        byte[] x = (byte[]) coseMap.getOrDefault(X_COORDINATE, new byte[0]);
        byte[] y = (byte[]) coseMap.getOrDefault(Y_COORDINATE, new byte[0]);
        if (SupportedPublicKeyAlg.ES256.equals(alg) && ArrayUtils.isNotEmpty(x) && ArrayUtils.isNotEmpty(y)) {
            ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec("P-256");
            ECParameterSpec params = new ECNamedCurveSpec(parameterSpec.getName(), parameterSpec.getCurve(),
                    parameterSpec.getG(), parameterSpec.getN(), parameterSpec.getH(), parameterSpec.getSeed());
            ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(new ECPoint(new BigInteger(x), new BigInteger(y)), params);
            return getX509EncodedKeySpec(publicKeySpec, EC_KEY_TYPE);
        }
        throw new UnsupportedPublicKeyCredential("Unable to decode EC key");
    }

    private static X509EncodedKeySpec readRSAKeySpec(Map<Integer, Object> coseMap, SupportedPublicKeyAlg alg) {
        byte[] modulus = (byte[]) coseMap.getOrDefault(RSA_MODULUS, new byte[0]);
        byte[] publicExponent = (byte[]) coseMap.getOrDefault(RSA_EXPONENT, new byte[0]);
        if (ArrayUtils.isNotEmpty(publicExponent) && ArrayUtils.isNotEmpty(modulus)) {
            RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(new BigInteger(1, modulus), new BigInteger(1, publicExponent));
            return getX509EncodedKeySpec(rsaPublicKeySpec, RSA_KEY_TYPE);
        }
        throw new UnsupportedPublicKeyCredential("Unable to decode RSA key");
    }

    private static X509EncodedKeySpec getX509EncodedKeySpec(KeySpec keySpec, String keyType) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(keyType);
            PublicKey key = keyFactory.generatePublic(keySpec);
            return new X509EncodedKeySpec(key.getEncoded());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }
}
