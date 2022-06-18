package dev.kocak.yusuf.JWTHelper.model;


import dev.kocak.yusuf.JWTHelper.JWTVerifier;

import java.time.Instant;
import java.util.Date;
import java.util.function.BiPredicate;


public interface IVerification {

    default IVerification withIssuer(String issuer) {
        return withIssuer(new String[]{issuer});
    }
    IVerification withIssuer(String... issuer);
    IVerification withSubject(String subject);
    IVerification withAudience(String... audience);
    IVerification withAnyOfAudience(String... audience);
    IVerification acceptLeeway(long leeway) throws IllegalArgumentException;
    IVerification acceptExpiresAt(long leeway) throws IllegalArgumentException;
    IVerification acceptNotBefore(long leeway) throws IllegalArgumentException;
    IVerification acceptIssuedAt(long leeway) throws IllegalArgumentException;
    IVerification withJWTId(String jwtId);
    IVerification withClaimPresence(String name) throws IllegalArgumentException;
    IVerification withNullClaim(String name) throws IllegalArgumentException;
    IVerification withClaim(String name, Boolean value) throws IllegalArgumentException;
    IVerification withClaim(String name, Integer value) throws IllegalArgumentException;
    IVerification withClaim(String name, Long value) throws IllegalArgumentException;
    IVerification withClaim(String name, Double value) throws IllegalArgumentException;
    IVerification withClaim(String name, String value) throws IllegalArgumentException;
    IVerification withClaim(String name, Date value) throws IllegalArgumentException;
    default IVerification withClaim(String name, Instant value) throws IllegalArgumentException {
        return withClaim(name, value != null ? Date.from(value) : null);
    }
    IVerification withClaim(String name, BiPredicate<IClaim, IDecodedJWT> predicate) throws IllegalArgumentException;
    IVerification withArrayClaim(String name, String... items) throws IllegalArgumentException;
    IVerification withArrayClaim(String name, Integer... items) throws IllegalArgumentException;
    IVerification withArrayClaim(String name, Long ... items) throws IllegalArgumentException;
    IVerification ignoreIssuedAt();
    IJWTVerifier build();
}
