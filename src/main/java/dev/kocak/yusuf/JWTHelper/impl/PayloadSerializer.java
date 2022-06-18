package dev.kocak.yusuf.JWTHelper.impl;

import dev.kocak.yusuf.JWTHelper.RegisteredClaims;
import com.fasterxml.jackson.core.JsonGenerator;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class PayloadSerializer extends ClaimsSerializer<PayloadClaimsHolder> {
    public PayloadSerializer() {
        super(PayloadClaimsHolder.class);
    }

    @Override
    protected void writeClaim(Map.Entry<String, Object> entry, JsonGenerator gen) throws IOException {
        if (RegisteredClaims.AUDIENCE.equals(entry.getKey())) {
            writeAudience(gen, entry);
        } else {
            super.writeClaim(entry, gen);
        }
    }

    private void writeAudience(JsonGenerator gen, Map.Entry<String, Object> e) throws IOException {
        if (e.getValue() instanceof String) {
            gen.writeFieldName(e.getKey());
            gen.writeString((String) e.getValue());
        } else {
            List<String> audArray = new ArrayList<>();
            if (e.getValue() instanceof String[]) {
                audArray = Arrays.asList((String[]) e.getValue());
            } else if (e.getValue() instanceof List) {
                List<?> audList = (List<?>) e.getValue();
                for (Object aud : audList) {
                    if (aud instanceof String) {
                        audArray.add((String) aud);
                    }
                }
            }
            if (audArray.size() == 1) {
                gen.writeFieldName(e.getKey());
                gen.writeString(audArray.get(0));
            } else if (audArray.size() > 1) {
                gen.writeFieldName(e.getKey());
                gen.writeStartArray();
                for (String aud : audArray) {
                    gen.writeString(aud);
                }
                gen.writeEndArray();
            }
        }
    }
}
