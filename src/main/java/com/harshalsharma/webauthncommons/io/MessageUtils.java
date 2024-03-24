package com.harshalsharma.webauthncommons.io;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MessageUtils {

    private static final String SHA_256 = "SHA-256";
    private static final ObjectMapper mapper = new ObjectMapper();
    private static final MessageDigest messageDigest;

    static {
        try {
            messageDigest = MessageDigest.getInstance(SHA_256);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static <T> T decodeJSON(byte[] json, Class<T> type) {
        try {
            return mapper.readValue(json, type);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] hashSHA256(byte[] data) {
        return messageDigest.digest(data);
    }

}
