package com.harshalsharma.webauthncommons.io;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class CborObject {

    private byte[] cborBytes;

    JsonNode jsonNode;

    public <T> T getAs(TypeReference<T> typeReference) {
        return DataEncoderDecoder.convert(jsonNode, typeReference);
    }
}
