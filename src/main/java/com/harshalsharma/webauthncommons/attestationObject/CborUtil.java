package com.harshalsharma.webauthncommons.attestationObject;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.util.Base64;

public final class CborUtil {

    private static final ObjectMapper mapper = new ObjectMapper(new CBORFactory());

    public static <T> T fromBase64Cbor(final String cborEncodedBase64String, final Class<T> type) {
        if (StringUtils.isBlank(cborEncodedBase64String)) {
            throw new IllegalArgumentException("Cbor encoded string cannot be null or empty.");
        }
        return fromCbor(Base64.getDecoder().decode(cborEncodedBase64String), type);
    }

    private static <T> T fromCbor(final byte[] cborBytes, Class<T> type) {
        if (ArrayUtils.isEmpty(cborBytes)) {
            throw new IllegalArgumentException("Cbor bytes cannot be empty.");
        }
        try {
            return mapper.readValue(cborBytes, type);
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

}
