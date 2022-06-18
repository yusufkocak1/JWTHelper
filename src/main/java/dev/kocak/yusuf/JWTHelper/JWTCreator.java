package dev.kocak.yusuf.JWTHelper;

import dev.kocak.yusuf.JWTHelper.algorithms.Algorithm;
import dev.kocak.yusuf.JWTHelper.exceptions.JWTCreationException;
import dev.kocak.yusuf.JWTHelper.exceptions.SignatureGenerationException;
import dev.kocak.yusuf.JWTHelper.impl.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.Map.Entry;


@SuppressWarnings("WeakerAccess")
public final class JWTCreator {

    private final Algorithm algorithm;
    private final String headerJson;
    private final String payloadJson;

    private static final ObjectMapper mapper;
    private static final SimpleModule module;

    static {
        mapper = new ObjectMapper();
        module = new SimpleModule();
        module.addSerializer(PayloadClaimsHolder.class, new PayloadSerializer());
        module.addSerializer(HeaderClaimsHolder.class, new HeaderSerializer());
        mapper.registerModule(module);
        mapper.configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true);
    }

    private JWTCreator(Algorithm algorithm, Map<String, Object> headerClaims, Map<String, Object> payloadClaims)
            throws JWTCreationException {
        this.algorithm = algorithm;
        try {
            headerJson = mapper.writeValueAsString(new HeaderClaimsHolder(headerClaims));
            payloadJson = mapper.writeValueAsString(new PayloadClaimsHolder(payloadClaims));
        } catch (JsonProcessingException e) {
            throw new JWTCreationException("Some of the Claims couldn't be converted to a valid JSON format.", e);
        }
    }


    
    static Builder init() {
        return new Builder();
    }

    
    public static class Builder {
        private final Map<String, Object> payloadClaims;
        private final Map<String, Object> headerClaims;

        Builder() {
            this.payloadClaims = new HashMap<>();
            this.headerClaims = new HashMap<>();
        }

        
        public Builder withHeader(Map<String, Object> headerClaims) {
            if (headerClaims == null) {
                return this;
            }

            for (Entry<String, Object> entry : headerClaims.entrySet()) {
                if (entry.getValue() == null) {
                    this.headerClaims.remove(entry.getKey());
                } else {
                    this.headerClaims.put(entry.getKey(), entry.getValue());
                }
            }

            return this;
        }

        
        public Builder withKeyId(String keyId) {
            this.headerClaims.put(HeaderParams.KEY_ID, keyId);
            return this;
        }

        
        public Builder withIssuer(String issuer) {
            addClaim(RegisteredClaims.ISSUER, issuer);
            return this;
        }

        
        public Builder withSubject(String subject) {
            addClaim(RegisteredClaims.SUBJECT, subject);
            return this;
        }

        
        public Builder withAudience(String... audience) {
            addClaim(RegisteredClaims.AUDIENCE, audience);
            return this;
        }

        
        public Builder withExpiresAt(Date expiresAt) {
            addClaim(RegisteredClaims.EXPIRES_AT, expiresAt);
            return this;
        }

        
        public Builder withExpiresAt(Instant expiresAt) {
            addClaim(RegisteredClaims.EXPIRES_AT, expiresAt);
            return this;
        }

        
        public Builder withNotBefore(Date notBefore) {
            addClaim(RegisteredClaims.NOT_BEFORE, notBefore);
            return this;
        }

        
        public Builder withNotBefore(Instant notBefore) {
            addClaim(RegisteredClaims.NOT_BEFORE, notBefore);
            return this;
        }

        
        public Builder withIssuedAt(Date issuedAt) {
            addClaim(RegisteredClaims.ISSUED_AT, issuedAt);
            return this;
        }

        
        public Builder withIssuedAt(Instant issuedAt) {
            addClaim(RegisteredClaims.ISSUED_AT, issuedAt);
            return this;
        }

        
        public Builder withJWTId(String jwtId) {
            addClaim(RegisteredClaims.JWT_ID, jwtId);
            return this;
        }

        
        public Builder withClaim(String name, Boolean value) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, value);
            return this;
        }

        
        public Builder withClaim(String name, Integer value) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, value);
            return this;
        }

        
        public Builder withClaim(String name, Long value) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, value);
            return this;
        }

        
        public Builder withClaim(String name, Double value) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, value);
            return this;
        }

        
        public Builder withClaim(String name, String value) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, value);
            return this;
        }

        
        public Builder withClaim(String name, Date value) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, value);
            return this;
        }

        
        public Builder withClaim(String name, Instant value) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, value);
            return this;
        }

        
        public Builder withClaim(String name, Map<String, ?> map) throws IllegalArgumentException {
            assertNonNull(name);
            // validate map contents
            if (map != null && !validateClaim(map)) {
                throw new IllegalArgumentException("Expected map containing Map, List, Boolean, Integer, "
                        + "Long, Double, String and Date");
            }
            addClaim(name, map);
            return this;
        }

        
        public Builder withClaim(String name, List<?> list) throws IllegalArgumentException {
            assertNonNull(name);
            // validate list contents
            if (list != null && !validateClaim(list)) {
                throw new IllegalArgumentException("Expected list containing Map, List, Boolean, Integer, "
                        + "Long, Double, String and Date");
            }
            addClaim(name, list);
            return this;
        }

        
        public Builder withNullClaim(String name) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, null);
            return this;
        }

        
        public Builder withArrayClaim(String name, String[] items) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, items);
            return this;
        }

        
        public Builder withArrayClaim(String name, Integer[] items) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, items);
            return this;
        }

        
        public Builder withArrayClaim(String name, Long[] items) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, items);
            return this;
        }

        
        public Builder withPayload(Map<String, ?> payloadClaims) throws IllegalArgumentException {
            if (payloadClaims == null) {
                return this;
            }

            if (!validatePayload(payloadClaims)) {
                throw new IllegalArgumentException("Claim values must only be of types Map, List, Boolean, Integer, "
                        + "Long, Double, String, Date, Instant, and Null");
            }

            // add claims only after validating all claims so as not to corrupt the claims map of this builder
            for (Entry<String, ?> entry : payloadClaims.entrySet()) {
                addClaim(entry.getKey(), entry.getValue());
            }

            return this;
        }

        private boolean validatePayload(Map<String, ?> payload) {
            for (Entry<String, ?> entry : payload.entrySet()) {
                String key = entry.getKey();
                assertNonNull(key);

                Object value = entry.getValue();
                if (value instanceof List && !validateClaim((List<?>) value)) {
                    return false;
                } else if (value instanceof Map && !validateClaim((Map<?, ?>) value)) {
                    return false;
                } else if (!isSupportedType(value)) {
                    return false;
                }
            }
            return true;
        }

        private static boolean validateClaim(Map<?, ?> map) {
            // do not accept null values in maps
            for (Entry<?, ?> entry : map.entrySet()) {
                Object value = entry.getValue();
                if (!isSupportedType(value)) {
                    return false;
                }

                if (entry.getKey() == null || !(entry.getKey() instanceof String)) {
                    return false;
                }
            }
            return true;
        }

        private static boolean validateClaim(List<?> list) {
            // accept null values in list
            for (Object object : list) {
                if (!isSupportedType(object)) {
                    return false;
                }
            }
            return true;
        }

        private static boolean isSupportedType(Object value) {
            if (value instanceof List) {
                return validateClaim((List<?>) value);
            } else if (value instanceof Map) {
                return validateClaim((Map<?, ?>) value);
            } else {
                return isBasicType(value);
            }
        }

        private static boolean isBasicType(Object value) {
            if (value == null) {
                return true;
            } else {
                Class<?> c = value.getClass();

                if (c.isArray()) {
                    return c == Integer[].class || c == Long[].class || c == String[].class;
                }
                return c == String.class || c == Integer.class || c == Long.class || c == Double.class
                        || c == Date.class || c == Instant.class || c == Boolean.class;
            }
        }

        
        public String sign(Algorithm algorithm) throws IllegalArgumentException, JWTCreationException {
            if (algorithm == null) {
                throw new IllegalArgumentException("The Algorithm cannot be null.");
            }
            headerClaims.put(HeaderParams.ALGORITHM, algorithm.getName());
            if (!headerClaims.containsKey(HeaderParams.TYPE)) {
                headerClaims.put(HeaderParams.TYPE, "JWT");
            }
            String signingKeyId = algorithm.getSigningKeyId();
            if (signingKeyId != null) {
                withKeyId(signingKeyId);
            }
            return new JWTCreator(algorithm, headerClaims, payloadClaims).sign();
        }

        private void assertNonNull(String name) {
            if (name == null) {
                throw new IllegalArgumentException("The Custom Claim's name can't be null.");
            }
        }

        private void addClaim(String name, Object value) {
            payloadClaims.put(name, value);
        }
    }

    private String sign() throws SignatureGenerationException {
        String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));

        byte[] signatureBytes = algorithm.sign(header.getBytes(StandardCharsets.UTF_8),
                payload.getBytes(StandardCharsets.UTF_8));
        String signature = Base64.getUrlEncoder().withoutPadding().encodeToString((signatureBytes));

        return String.format("%s.%s.%s", header, payload, signature);
    }
}
