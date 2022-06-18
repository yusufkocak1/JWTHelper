package dev.kocak.yusuf.JWTHelper.impl;


import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import dev.kocak.yusuf.JWTHelper.RegisteredClaims;
import dev.kocak.yusuf.JWTHelper.exceptions.JWTDecodeException;
import dev.kocak.yusuf.JWTHelper.model.IPayload;

import java.io.IOException;
import java.time.Instant;
import java.util.*;

class PayloadDeserializer extends StdDeserializer<IPayload> {

    private final ObjectReader objectReader;

    PayloadDeserializer(ObjectReader reader) {
        this(null, reader);
    }

    private PayloadDeserializer(Class<?> vc, ObjectReader reader) {
        super(vc);

        this.objectReader = reader;
    }

    @Override
    public IPayload deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        Map<String, JsonNode> tree = p.getCodec().readValue(p, new TypeReference<Map<String, JsonNode>>() {
        });
        if (tree == null) {
            throw new JWTDecodeException("Parsing the Payload's JSON resulted on a Null map");
        }

        String issuer = getString(tree, RegisteredClaims.ISSUER);
        String subject = getString(tree, RegisteredClaims.SUBJECT);
        List<String> audience = getStringOrArray(tree, RegisteredClaims.AUDIENCE);
        Instant expiresAt = getInstantFromSeconds(tree, RegisteredClaims.EXPIRES_AT);
        Instant notBefore = getInstantFromSeconds(tree, RegisteredClaims.NOT_BEFORE);
        Instant issuedAt = getInstantFromSeconds(tree, RegisteredClaims.ISSUED_AT);
        String jwtId = getString(tree, RegisteredClaims.JWT_ID);

        return new PayloadImpl(issuer, subject, audience, expiresAt, notBefore, issuedAt, jwtId, tree, objectReader);
    }

    List<String> getStringOrArray(Map<String, JsonNode> tree, String claimName) throws JWTDecodeException {
        JsonNode node = tree.get(claimName);
        if (node == null || node.isNull() || !(node.isArray() || node.isTextual())) {
            return null;
        }
        if (node.isTextual() && !node.asText().isEmpty()) {
            return Collections.singletonList(node.asText());
        }

        List<String> list = new ArrayList<>(node.size());
        for (int i = 0; i < node.size(); i++) {
            try {
                list.add(objectReader.treeToValue(node.get(i), String.class));
            } catch (JsonProcessingException e) {
                throw new JWTDecodeException("Couldn't map the Claim's array contents to String", e);
            }
        }
        return list;
    }

    Instant getInstantFromSeconds(Map<String, JsonNode> tree, String claimName) {
        JsonNode node = tree.get(claimName);
        if (node == null || node.isNull()) {
            return null;
        }
        if (!node.canConvertToLong()) {
            throw new JWTDecodeException(
                    String.format("The claim '%s' contained a non-numeric date value.", claimName));
        }
        return Instant.ofEpochSecond(node.asLong());
    }

    String getString(Map<String, JsonNode> tree, String claimName) {
        JsonNode node = tree.get(claimName);
        if (node == null || node.isNull()) {
            return null;
        }
        return node.asText(null);
    }
}
