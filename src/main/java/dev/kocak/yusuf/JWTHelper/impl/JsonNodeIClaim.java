package dev.kocak.yusuf.JWTHelper.impl;

import dev.kocak.yusuf.JWTHelper.exceptions.JWTDecodeException;
import dev.kocak.yusuf.JWTHelper.model.IClaim;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectReader;

import java.io.IOException;
import java.lang.reflect.Array;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;


class JsonNodeIClaim implements IClaim {

    private final ObjectReader objectReader;
    private final JsonNode data;

    private JsonNodeIClaim(JsonNode node, ObjectReader objectReader) {
        this.data = node;
        this.objectReader = objectReader;
    }

    @Override
    public Boolean asBoolean() {
        return isMissing() || isNull() || !data.isBoolean() ? null : data.asBoolean();
    }

    @Override
    public Integer asInt() {
        return isMissing() || isNull() || !data.isNumber() ? null : data.asInt();
    }

    @Override
    public Long asLong() {
        return isMissing() || isNull() || !data.isNumber() ? null : data.asLong();
    }

    @Override
    public Double asDouble() {
        return isMissing() || isNull() || !data.isNumber() ? null : data.asDouble();
    }

    @Override
    public String asString() {
        return isMissing() || isNull() || !data.isTextual() ? null : data.asText();
    }

    @Override
    public Date asDate() {
        if (isMissing() || isNull() || !data.canConvertToLong()) {
            return null;
        }
        long seconds = data.asLong();
        return new Date(seconds * 1000);
    }

    @Override
    public Instant asInstant() {
        if (isMissing() || isNull() || !data.canConvertToLong()) {
            return null;
        }
        long seconds = data.asLong();
        return Instant.ofEpochSecond(seconds);
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> T[] asArray(Class<T> clazz) throws JWTDecodeException {
        if (isMissing() || isNull() || !data.isArray()) {
            return null;
        }

        T[] arr = (T[]) Array.newInstance(clazz, data.size());
        for (int i = 0; i < data.size(); i++) {
            try {
                arr[i] = objectReader.treeToValue(data.get(i), clazz);
            } catch (JsonProcessingException e) {
                throw new JWTDecodeException("Couldn't map the Claim's array contents to " + clazz.getSimpleName(), e);
            }
        }
        return arr;
    }

    @Override
    public <T> List<T> asList(Class<T> clazz) throws JWTDecodeException {
        if (isMissing() || isNull() || !data.isArray()) {
            return null;
        }

        List<T> list = new ArrayList<>();
        for (int i = 0; i < data.size(); i++) {
            try {
                list.add(objectReader.treeToValue(data.get(i), clazz));
            } catch (JsonProcessingException e) {
                throw new JWTDecodeException("Couldn't map the Claim's array contents to " + clazz.getSimpleName(), e);
            }
        }
        return list;
    }

    @Override
    public Map<String, Object> asMap() throws JWTDecodeException {
        if (isMissing() || isNull() || !data.isObject()) {
            return null;
        }

        try {
            TypeReference<Map<String, Object>> mapType = new TypeReference<Map<String, Object>>() {
            };
            JsonParser thisParser = objectReader.treeAsTokens(data);
            return thisParser.readValueAs(mapType);
        } catch (IOException e) {
            throw new JWTDecodeException("Couldn't map the Claim value to Map", e);
        }
    }

    @Override
    public <T> T as(Class<T> clazz) throws JWTDecodeException {
        try {
            if (isMissing() || isNull()) {
                return null;
            }
            return objectReader.treeAsTokens(data).readValueAs(clazz);
        } catch (IOException e) {
            throw new JWTDecodeException("Couldn't map the Claim value to " + clazz.getSimpleName(), e);
        }
    }

    @Override
    public boolean isNull() {
        return !isMissing() && data.isNull();
    }

    @Override
    public boolean isMissing() {
        return data == null || data.isMissingNode();
    }

    @Override
    public String toString() {
        if (isMissing()) {
            return "Missing claim";
        } else if (isNull()) {
            return "Null claim";
        }
        return data.toString();
    }
    
    static IClaim extractClaim(String claimName, Map<String, JsonNode> tree, ObjectReader objectReader) {
        JsonNode node = tree.get(claimName);
        return claimFromNode(node, objectReader);
    }

    
    static IClaim claimFromNode(JsonNode node, ObjectReader objectReader) {
        return new JsonNodeIClaim(node, objectReader);
    }

}