package dev.kocak.yusuf.JWTHelper;

import dev.kocak.yusuf.JWTHelper.algorithms.Algorithm;
import dev.kocak.yusuf.JWTHelper.exceptions.*;
import dev.kocak.yusuf.JWTHelper.impl.JWTParser;
import dev.kocak.yusuf.JWTHelper.model.IClaim;
import dev.kocak.yusuf.JWTHelper.model.IDecodedJWT;
import dev.kocak.yusuf.JWTHelper.model.ExpectedCheckHolder;
import dev.kocak.yusuf.JWTHelper.model.IJWTVerifier;
import dev.kocak.yusuf.JWTHelper.model.IVerification;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.function.BiPredicate;


public final class JWTVerifier implements IJWTVerifier {
    private final Algorithm algorithm;
    final List<ExpectedCheckHolder> expectedChecks;
    private final JWTParser parser;

    JWTVerifier(Algorithm algorithm, List<ExpectedCheckHolder> expectedChecks) {
        this.algorithm = algorithm;
        this.expectedChecks = Collections.unmodifiableList(expectedChecks);
        this.parser = new JWTParser();
    }

    
    static IVerification init(Algorithm algorithm) throws IllegalArgumentException {
        return new BaseVerification(algorithm);
    }

    
    public static class BaseVerification implements IVerification {
        private final Algorithm algorithm;
        private final List<ExpectedCheckHolder> expectedChecks;
        private long defaultLeeway;
        private final Map<String, Long> customLeeways;
        private boolean ignoreIssuedAt;
        private Clock clock;

        BaseVerification(Algorithm algorithm) throws IllegalArgumentException {
            if (algorithm == null) {
                throw new IllegalArgumentException("The Algorithm cannot be null.");
            }

            this.algorithm = algorithm;
            this.expectedChecks = new ArrayList<>();
            this.customLeeways = new HashMap<>();
            this.defaultLeeway = 0;
        }

        @Override
        public IVerification withIssuer(String... issuer) {
            List<String> value = isNullOrEmpty(issuer) ? null : Arrays.asList(issuer);
            addCheck(RegisteredClaims.ISSUER, ((claim, decodedJWT) -> {
                if (verifyNull(claim, value)) {
                    return true;
                }
                if (value == null || !value.contains(claim.asString())) {
                    throw new IncorrectClaimException(
                            "The Claim 'iss' value doesn't match the required issuer.", RegisteredClaims.ISSUER, claim);
                }
                return true;
            }));
            return this;
        }

        @Override
        public IVerification withSubject(String subject) {
            addCheck(RegisteredClaims.SUBJECT, (claim, decodedJWT) ->
                    verifyNull(claim, subject) || subject.equals(claim.asString()));
            return this;
        }

        @Override
        public IVerification withAudience(String... audience) {
            List<String> value = isNullOrEmpty(audience) ? null : Arrays.asList(audience);
            addCheck(RegisteredClaims.AUDIENCE, ((claim, decodedJWT) -> {
                if (verifyNull(claim, value)) {
                    return true;
                }
                if (!assertValidAudienceClaim(decodedJWT.getAudience(), value, true)) {
                    throw new IncorrectClaimException("The Claim 'aud' value doesn't contain the required audience.",
                            RegisteredClaims.AUDIENCE, claim);
                }
                return true;
            }));
            return this;
        }

        @Override
        public IVerification withAnyOfAudience(String... audience) {
            List<String> value = isNullOrEmpty(audience) ? null : Arrays.asList(audience);
            addCheck(RegisteredClaims.AUDIENCE, ((claim, decodedJWT) -> {
                if (verifyNull(claim, value)) {
                    return true;
                }
                if (!assertValidAudienceClaim(decodedJWT.getAudience(), value, false)) {
                    throw new IncorrectClaimException("The Claim 'aud' value doesn't contain the required audience.",
                            RegisteredClaims.AUDIENCE, claim);
                }
                return true;
            }));
            return this;
        }

        @Override
        public IVerification acceptLeeway(long leeway) throws IllegalArgumentException {
            assertPositive(leeway);
            this.defaultLeeway = leeway;
            return this;
        }

        @Override
        public IVerification acceptExpiresAt(long leeway) throws IllegalArgumentException {
            assertPositive(leeway);
            customLeeways.put(RegisteredClaims.EXPIRES_AT, leeway);
            return this;
        }

        @Override
        public IVerification acceptNotBefore(long leeway) throws IllegalArgumentException {
            assertPositive(leeway);
            customLeeways.put(RegisteredClaims.NOT_BEFORE, leeway);
            return this;
        }

        @Override
        public IVerification acceptIssuedAt(long leeway) throws IllegalArgumentException {
            assertPositive(leeway);
            customLeeways.put(RegisteredClaims.ISSUED_AT, leeway);
            return this;
        }

        @Override
        public IVerification ignoreIssuedAt() {
            this.ignoreIssuedAt = true;
            return this;
        }

        @Override
        public IVerification withJWTId(String jwtId) {
            addCheck(RegisteredClaims.JWT_ID, ((claim, decodedJWT) ->
                    verifyNull(claim, jwtId) || jwtId.equals(claim.asString())));
            return this;
        }

        @Override
        public IVerification withClaimPresence(String name) throws IllegalArgumentException {
            assertNonNull(name);
            //since addCheck already checks presence, we just return true
            withClaim(name, ((claim, decodedJWT) -> true));
            return this;
        }

        @Override
        public IVerification withNullClaim(String name) throws IllegalArgumentException {
            assertNonNull(name);
            withClaim(name, ((claim, decodedJWT) -> claim.isNull()));
            return this;
        }

        @Override
        public IVerification withClaim(String name, Boolean value) throws IllegalArgumentException {
            assertNonNull(name);
            addCheck(name, ((claim, decodedJWT) -> verifyNull(claim, value)
                    || value.equals(claim.asBoolean())));
            return this;
        }

        @Override
        public IVerification withClaim(String name, Integer value) throws IllegalArgumentException {
            assertNonNull(name);
            addCheck(name, ((claim, decodedJWT) -> verifyNull(claim, value)
                    || value.equals(claim.asInt())));
            return this;
        }

        @Override
        public IVerification withClaim(String name, Long value) throws IllegalArgumentException {
            assertNonNull(name);
            addCheck(name, ((claim, decodedJWT) -> verifyNull(claim, value)
                    || value.equals(claim.asLong())));
            return this;
        }

        @Override
        public IVerification withClaim(String name, Double value) throws IllegalArgumentException {
            assertNonNull(name);
            addCheck(name, ((claim, decodedJWT) -> verifyNull(claim, value)
                    || value.equals(claim.asDouble())));
            return this;
        }

        @Override
        public IVerification withClaim(String name, String value) throws IllegalArgumentException {
            assertNonNull(name);
            addCheck(name, ((claim, decodedJWT) -> verifyNull(claim, value)
                    || value.equals(claim.asString())));
            return this;
        }

        @Override
        public IVerification withClaim(String name, Date value) throws IllegalArgumentException {
            return withClaim(name, value != null ? value.toInstant() : null);
        }

        @Override
        public IVerification withClaim(String name, Instant value) throws IllegalArgumentException {
            assertNonNull(name);
            // Since date-time claims are serialized as epoch seconds,
            // we need to compare them with only seconds-granularity
            addCheck(name,
                    ((claim, decodedJWT) -> verifyNull(claim, value)
                            || value.truncatedTo(ChronoUnit.SECONDS).equals(claim.asInstant())));
            return this;
        }

        @Override
        public IVerification withClaim(String name, BiPredicate<IClaim, IDecodedJWT> predicate)
                throws IllegalArgumentException {
            assertNonNull(name);
            addCheck(name, ((claim, decodedJWT) -> verifyNull(claim, predicate)
                    || predicate.test(claim, decodedJWT)));
            return this;
        }

        @Override
        public IVerification withArrayClaim(String name, String... items) throws IllegalArgumentException {
            assertNonNull(name);
            addCheck(name, ((claim, decodedJWT) -> verifyNull(claim, items)
                    || assertValidCollectionClaim(claim, items)));
            return this;
        }

        @Override
        public IVerification withArrayClaim(String name, Integer... items) throws IllegalArgumentException {
            assertNonNull(name);
            addCheck(name, ((claim, decodedJWT) -> verifyNull(claim, items)
                    || assertValidCollectionClaim(claim, items)));
            return this;
        }

        @Override
        public IVerification withArrayClaim(String name, Long... items) throws IllegalArgumentException {
            assertNonNull(name);
            addCheck(name, ((claim, decodedJWT) -> verifyNull(claim, items)
                    || assertValidCollectionClaim(claim, items)));
            return this;
        }

        @Override
        public JWTVerifier build() {
            return this.build(Clock.systemUTC());
        }

        
        public JWTVerifier build(Clock clock) {
            this.clock = clock;
            addMandatoryClaimChecks();
            return new JWTVerifier(algorithm, expectedChecks);
        }

        
        public long getLeewayFor(String name) {
            return customLeeways.getOrDefault(name, defaultLeeway);
        }

        private void addMandatoryClaimChecks() {
            long expiresAtLeeway = getLeewayFor(RegisteredClaims.EXPIRES_AT);
            long notBeforeLeeway = getLeewayFor(RegisteredClaims.NOT_BEFORE);
            long issuedAtLeeway = getLeewayFor(RegisteredClaims.ISSUED_AT);

            expectedChecks.add(constructExpectedCheck(RegisteredClaims.EXPIRES_AT, (claim, decodedJWT) ->
                    assertValidInstantClaim(RegisteredClaims.EXPIRES_AT, claim, expiresAtLeeway, true)));
            expectedChecks.add(constructExpectedCheck(RegisteredClaims.NOT_BEFORE, (claim, decodedJWT) ->
                    assertValidInstantClaim(RegisteredClaims.NOT_BEFORE, claim, notBeforeLeeway, false)));
            if (!ignoreIssuedAt) {
                expectedChecks.add(constructExpectedCheck(RegisteredClaims.ISSUED_AT, (claim, decodedJWT) ->
                        assertValidInstantClaim(RegisteredClaims.ISSUED_AT, claim, issuedAtLeeway, false)));
            }
        }

        private boolean assertValidCollectionClaim(IClaim IClaim, Object[] expectedClaimValue) {
            List<Object> claimArr;
            Object[] claimAsObject = IClaim.as(Object[].class);

            // Jackson uses 'natural' mapping which uses Integer if value fits in 32 bits.
            if (expectedClaimValue instanceof Long[]) {
                // convert Integers to Longs for comparison with equals
                claimArr = new ArrayList<>(claimAsObject.length);
                for (Object cao : claimAsObject) {
                    if (cao instanceof Integer) {
                        claimArr.add(((Integer) cao).longValue());
                    } else {
                        claimArr.add(cao);
                    }
                }
            } else {
                claimArr = Arrays.asList(IClaim.as(Object[].class));
            }
            List<Object> valueArr = Arrays.asList(expectedClaimValue);
            return claimArr.containsAll(valueArr);
        }

        private boolean assertValidInstantClaim(String claimName, IClaim IClaim, long leeway, boolean shouldBeFuture) {
            Instant claimVal = IClaim.asInstant();
            Instant now = clock.instant().truncatedTo(ChronoUnit.SECONDS);
            boolean isValid;
            if (shouldBeFuture) {
                isValid = assertInstantIsFuture(claimVal, leeway, now);
                if (!isValid) {
                    throw new TokenExpiredException(String.format("The Token has expired on %s.", claimVal), claimVal);
                }
            } else {
                isValid = assertInstantIsPast(claimVal, leeway, now);
                if (!isValid) {
                    throw new IncorrectClaimException(
                            String.format("The Token can't be used before %s.", claimVal), claimName, IClaim);
                }
            }
            return true;
        }

        private boolean assertInstantIsFuture(Instant claimVal, long leeway, Instant now) {
            return !(claimVal != null && now.minus(Duration.ofSeconds(leeway)).isAfter(claimVal));
        }

        private boolean assertInstantIsPast(Instant claimVal, long leeway, Instant now) {
            return !(claimVal != null && now.plus(Duration.ofSeconds(leeway)).isBefore(claimVal));
        }

        private boolean assertValidAudienceClaim(
                List<String> audience,
                List<String> values,
                boolean shouldContainAll
        ) {
            return !(audience == null || (shouldContainAll && !audience.containsAll(values))
                    || (!shouldContainAll && Collections.disjoint(audience, values)));
        }

        private void assertPositive(long leeway) {
            if (leeway < 0) {
                throw new IllegalArgumentException("Leeway value can't be negative.");
            }
        }

        private void assertNonNull(String name) {
            if (name == null) {
                throw new IllegalArgumentException("The Custom Claim's name can't be null.");
            }
        }

        private void addCheck(String name, BiPredicate<IClaim, IDecodedJWT> predicate) {
            expectedChecks.add(constructExpectedCheck(name, (claim, decodedJWT) -> {
                if (claim.isMissing()) {
                    throw new MissingClaimException(name);
                }
                return predicate.test(claim, decodedJWT);
            }));
        }

        private ExpectedCheckHolder constructExpectedCheck(String claimName, BiPredicate<IClaim, IDecodedJWT> check) {
            return new ExpectedCheckHolder() {
                @Override
                public String getClaimName() {
                    return claimName;
                }

                @Override
                public boolean verify(IClaim IClaim, IDecodedJWT decodedJWT) {
                    return check.test(IClaim, decodedJWT);
                }
            };
        }

        private boolean verifyNull(IClaim IClaim, Object value) {
            return value == null && IClaim.isNull();
        }

        private boolean isNullOrEmpty(String[] args) {
            if (args == null || args.length == 0) {
                return true;
            }
            boolean isAllNull = true;
            for (String arg : args) {
                if (arg != null) {
                    isAllNull = false;
                    break;
                }
            }
            return isAllNull;
        }
    }


    
    @Override
    public IDecodedJWT verify(String token) throws JWTVerificationException {
        IDecodedJWT jwt = new JWTDecoder(parser, token);
        return verify(jwt);
    }

    
    @Override
    public IDecodedJWT verify(IDecodedJWT jwt) throws JWTVerificationException {
        verifyAlgorithm(jwt, algorithm);
        algorithm.verify(jwt);
        verifyClaims(jwt, expectedChecks);
        return jwt;
    }

    private void verifyAlgorithm(IDecodedJWT jwt, Algorithm expectedAlgorithm) throws AlgorithmMismatchException {
        if (!expectedAlgorithm.getName().equals(jwt.getAlgorithm())) {
            throw new AlgorithmMismatchException(
                    "The provided Algorithm doesn't match the one defined in the JWT's Header.");
        }
    }

    private void verifyClaims(IDecodedJWT jwt, List<ExpectedCheckHolder> expectedChecks)
            throws TokenExpiredException, InvalidClaimException {
        for (ExpectedCheckHolder expectedCheck : expectedChecks) {
            boolean isValid;
            String claimName = expectedCheck.getClaimName();
            IClaim IClaim = jwt.getClaim(claimName);

            isValid = expectedCheck.verify(IClaim, jwt);

            if (!isValid) {
                throw new IncorrectClaimException(
                        String.format("The Claim '%s' value doesn't match the required one.", claimName),
                        claimName,
                        IClaim
                );
            }
        }
    }
}
