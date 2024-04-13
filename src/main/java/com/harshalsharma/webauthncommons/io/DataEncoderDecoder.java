package com.harshalsharma.webauthncommons.io;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORParser;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.util.Optional;

public final class DataEncoderDecoder {

    private static final ObjectMapper mapper = new ObjectMapper(new CBORFactory());
    private static final CBORFactory cborFactory = new CBORFactory();

    static {
        mapper.disable(SerializationFeature.INDENT_OUTPUT);
        cborFactory.setCodec(new CBORMapper());
    }

    public static <T> T fromBase64Cbor(final String cborEncodedBase64String, final Class<T> type) {
        if (StringUtils.isBlank(cborEncodedBase64String)) {
            throw new IllegalArgumentException("Cbor encoded string cannot be null or empty.");
        }
        return fromCbor(decodeBase64Bytes(cborEncodedBase64String), type);
    }

    public static <T> T fromCbor(final byte[] cborBytes, Class<T> type) {
        if (ArrayUtils.isEmpty(cborBytes)) {
            throw new IllegalArgumentException("Cbor bytes cannot be empty.");
        }
        try {
            return mapper.readValue(cborBytes, type);
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static Optional<CborObject> readFirstCborObject(byte[] cborData) {
        try {
            CBORParser parser = cborFactory.createParser(cborData);
            int start = (int) parser.currentLocation().getByteOffset();
            JsonNode object = parser.readValueAsTree();
            int end = (int) parser.currentLocation().getByteOffset();
            byte[] specificBytes = ArrayUtils.subarray(cborData, start, end);
            parser.close();
            return Optional.of(new CborObject(specificBytes, object));
        } catch (IOException ignored) {
            return Optional.empty();
        }
    }

    public static <T> byte[] toBase64CborBytes(final T object) {
        return encodeBase64(toCbor(object));
    }

    public static <T> byte[] toCbor(T object) {
        if (ObjectUtils.isEmpty(object)) {
            throw new IllegalArgumentException("Object cannot be empty.");
        }
        try {
            return mapper.writeValueAsBytes(object);
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static byte[] decodeBase64Bytes(String encodedBase64String) {
        return Base64.decodeBase64(encodedBase64String);
    }

    public static byte[] encodeBase64(byte[] bytes) {
        return Base64.encodeBase64(bytes);
    }

    public static String encodeBase64String(byte[] bytes) {
        return Base64.encodeBase64String(bytes);
    }

    public static String encodeBase64URLSafeString(byte[] bytes) {
        return Base64.encodeBase64URLSafeString(bytes);
    }

    public static <T> T convert(JsonNode node, TypeReference<T> typeReference) {
        return mapper.convertValue(node, typeReference);
    }
}
