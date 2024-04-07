package com.harshalsharma.webauthncommons;

import com.harshalsharma.webauthncommons.attestationObject.AttestationObjectExplorer;
import com.harshalsharma.webauthncommons.attestationObject.AttestationObjectReader;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class AttestationObjectReaderTest {

    @Test
    @DisplayName("Test Attestation Object is readable as expected.")
    void testAttestationObjectIsReadable() {
        //given
        String base64AttestationObject = "v2NmbXRxYW5kcm9pZC1zYWZ0ZXluZXRoYXV0aERhdGFZAWPTYawhamZZ/PbSqCEHbskIXPzBI8IWn1oUyCUzoNKBuN0iAAAATepeCkiJpY6O8A2uIrntGgAyXKQW8gzymKv5OM4v8gyR1BPx6HJuTnicm0BvcTDY0q2719a3vkHMrGXK1IyXbdsbsWulAQADJiAAIVghAInZCQ8uEzdjmtYYfT2SwYhnRJ0GPM7uCalWTU3dxnm+IlggbIsqqOebA9n9ALaxTkvztCMFlNTeATOYY0DR3OQwPvu/YjExG1SwvOKzlpGcYjEyGzmt+37haczzYjEzGys5KJB4HK1nYjE0G3nbbtstmFHUYTAbWbRtBof/CGZhMRt04wajdNwsM2EyG1LJ3STDTFnrYTMbf6oNM61TBRphNBsSsf3E4DdOWWE1Gx88Z0etM3QSYTYbaafEDRxQBw5hNxsnvdlPmAeammE4Gwea46DCqeuAYTkbakFGVMgaQOpiMTAbe3yTAObsH4///w==";
        String expectedCredentialId = "XKQW8gzymKv5OM4v8gyR1BPx6HJuTnicm0BvcTDY0q2719a3vkHMrGXK1IyXbdsbsWs";
        String publicKeyType = "EC";
        String publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEidkJDy4TN2Oa1hh9PZLBiGdEnQY8zu4JqVZNTd3Geb5siyqo55sD2f0AtrFOS/O0IwWU1N4BM5hjQNHc5DA++w==";

        //when
        AttestationObjectExplorer attestationObjectExplorer = AttestationObjectReader.read(base64AttestationObject);

        //then
        assertNotNull(attestationObjectExplorer, "AttestationObject must be present.");
        assertEquals(attestationObjectExplorer.getWebauthnId(), expectedCredentialId,
                "Credential ID must be same.");
        assertEquals(attestationObjectExplorer.getKeyType(), publicKeyType,
                "Public key type must be same.");
        assertEquals(attestationObjectExplorer.getEncodedPublicKeySpec(), publicKey,
                "Public key must be same.");
    }

}
