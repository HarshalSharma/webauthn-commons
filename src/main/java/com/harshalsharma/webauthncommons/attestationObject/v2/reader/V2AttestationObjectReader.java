package com.harshalsharma.webauthncommons.attestationObject.v2.reader;

import com.fasterxml.jackson.databind.JsonNode;
import com.harshalsharma.webauthncommons.AttestationObjectReader;
import com.harshalsharma.webauthncommons.attestationObject.AttestationObject;
import com.harshalsharma.webauthncommons.attestationObject.CborUtil;
import com.harshalsharma.webauthncommons.attestationObject.v2.V2AttestationObject;

import java.nio.charset.StandardCharsets;

public class V2AttestationObjectReader implements AttestationObjectReader {

    @Override
    public AttestationObject read(String base64AttestationObject) {
        JsonNode jsonNode = CborUtil.fromBase64Cbor(base64AttestationObject, JsonNode.class);
        String fmt = jsonNode.get("fmt").asText();
        byte[] authData = jsonNode.get("authData").asText().getBytes(StandardCharsets.UTF_8);
        return V2AttestationObject.builder().fmt(fmt).authData(V2AuthenticatorDataReader.read(authData)).build();
    }
}
