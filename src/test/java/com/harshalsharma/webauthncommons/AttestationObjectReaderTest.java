package com.harshalsharma.webauthncommons;

import com.harshalsharma.webauthncommons.attestationObject.AttestationObject;
import com.harshalsharma.webauthncommons.attestationObject.v2.reader.V2AttestationObjectReader;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class AttestationObjectReaderTest {

    @Test
    @DisplayName("Test Attestation Object is readable.")
    void testAttestationObjectIsReadable() {
        //given
        String base64AttestationObject = "v2NmbXRxYW5kcm9pZC1zYWZ0ZXluZXRoYXV0aERhdGFZAWPTYawhamZZ/PbSqCEHbskIXPzBI8IWn1oUyCUzoNKBuN0iAAAATepeCkiJpY6O8A2uIrntGgAyXKQW8gzymKv5OM4v8gyR1BPx6HJuTnicm0BvcTDY0q2719a3vkHMrGXK1IyXbdsbsWulAQADJiAAIVghAInZCQ8uEzdjmtYYfT2SwYhnRJ0GPM7uCalWTU3dxnm+IlggbIsqqOebA9n9ALaxTkvztCMFlNTeATOYY0DR3OQwPvu/YjExG1SwvOKzlpGcYjEyGzmt+37haczzYjEzGys5KJB4HK1nYjE0G3nbbtstmFHUYTAbWbRtBof/CGZhMRt04wajdNwsM2EyG1LJ3STDTFnrYTMbf6oNM61TBRphNBsSsf3E4DdOWWE1Gx88Z0etM3QSYTYbaafEDRxQBw5hNxsnvdlPmAeammE4Gwea46DCqeuAYTkbakFGVMgaQOpiMTAbe3yTAObsH4///w==";
        String expectedCredentialId = "XKQW8gzymKv5OM4v8gyR1BPx6HJuTnicm0BvcTDY0q2719a3vkHMrGXK1IyXbdsbsWs";

        //when
        AttestationObjectReader reader = new V2AttestationObjectReader();
        AttestationObject attestationObject = reader.read(base64AttestationObject);

        //then
        assertNotNull(attestationObject, "AttestationObject must be present.");
        assertEquals(attestationObject.getBase64UrlSafeCredentialId(), expectedCredentialId,
                "Credential ID must be same.");
    }

}
