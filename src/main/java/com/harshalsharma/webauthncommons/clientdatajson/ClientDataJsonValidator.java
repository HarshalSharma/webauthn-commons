package com.harshalsharma.webauthncommons.clientdatajson;

import com.harshalsharma.webauthncommons.entities.ClientDataJson;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import org.apache.commons.lang3.StringUtils;

@Builder
public class ClientDataJsonValidator {

    private final String origin;

    private final CDJType operation;

    public void validate(ClientDataJson clientDataJson, String challenge) {
        if (!StringUtils.equals(clientDataJson.getOrigin(), origin)) {
            throw new InvalidClientDataJsonException(InvalidClientDataJsonException.INVALID_ORIGIN);
        }
        if (!StringUtils.equals(clientDataJson.getType(), operation.getType())) {
            throw new InvalidClientDataJsonException(InvalidClientDataJsonException.INVALID_TYPE);
        }
        if (!StringUtils.equals(clientDataJson.getChallenge(), challenge)) {
            throw new InvalidClientDataJsonException(InvalidClientDataJsonException.INVALID_CHALLENGE);
        }
    }

    @Getter
    @AllArgsConstructor
    public enum CDJType {
        WEBAUTHN_CREATE("webauthn.create"),
        WEBAUTHN_GET("webauthn.get");
        private final String type;
    }

}
