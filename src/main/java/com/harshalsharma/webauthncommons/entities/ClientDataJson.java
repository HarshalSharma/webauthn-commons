package com.harshalsharma.webauthncommons.entities;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@AllArgsConstructor
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class ClientDataJson {

    private String type;
    private String challenge;
    private String origin;
    private boolean crossOrigin;

}
