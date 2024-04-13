package com.harshalsharma.webauthncommons.clientdatajson;

import com.harshalsharma.webauthncommons.entities.ClientDataJson;
import com.harshalsharma.webauthncommons.io.DataEncoderDecoder;
import com.harshalsharma.webauthncommons.io.MessageUtils;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;

/**
 * Provides utility to read client data json.
 */
public class ClientDataJsonReader {

    /**
     * Reads and validates the client data json.
     *
     * @param base64EncodedClientDataJson base64 encoded client data json.
     * @return ClientDataJson object.
     */
    public static ClientDataJson read(String base64EncodedClientDataJson) {
        ClientDataJson clientDataJsonObject;
        if (StringUtils.isBlank(base64EncodedClientDataJson)) {
            throw new InvalidClientDataJsonException(InvalidClientDataJsonException.INVALID_FORMAT);
        }
        String decodedClientDataJson = getBase64DecodedString(base64EncodedClientDataJson);
        clientDataJsonObject = parseJsonObject(decodedClientDataJson);
        return clientDataJsonObject;
    }

    @NotNull
    private static String getBase64DecodedString(String base64EncodedClientDataJson) {
        try {
            return new String(DataEncoderDecoder.decodeBase64Bytes(base64EncodedClientDataJson));
        } catch (Exception e) {
            throw new InvalidClientDataJsonException(InvalidClientDataJsonException.INVALID_FORMAT);
        }
    }

    private static ClientDataJson parseJsonObject(String decodedClientDataJson) {
        try {
            return MessageUtils.decodeJSON(decodedClientDataJson.getBytes(), ClientDataJson.class);
        } catch (Exception e) {
            throw new InvalidClientDataJsonException(InvalidClientDataJsonException.INVALID_FORMAT, e);
        }
    }

}
