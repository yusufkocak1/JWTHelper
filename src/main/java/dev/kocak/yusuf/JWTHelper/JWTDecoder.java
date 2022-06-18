package dev.kocak.yusuf.JWTHelper;


import dev.kocak.yusuf.JWTHelper.exceptions.JWTDecodeException;
import dev.kocak.yusuf.JWTHelper.impl.JWTParser;
import dev.kocak.yusuf.JWTHelper.model.IClaim;
import dev.kocak.yusuf.JWTHelper.model.IDecodedJWT;
import dev.kocak.yusuf.JWTHelper.model.IHeader;
import dev.kocak.yusuf.JWTHelper.model.IPayload;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;


@SuppressWarnings("WeakerAccess")
final class JWTDecoder implements IDecodedJWT, Serializable {

    private static final long serialVersionUID = 1873362438023312895L;

    private final String[] parts;
    private final IHeader header;
    private final IPayload payload;

    JWTDecoder(String jwt) throws JWTDecodeException {
        this(new JWTParser(), jwt);
    }

    JWTDecoder(JWTParser converter, String jwt) throws JWTDecodeException {
        parts = TokenUtils.splitToken(jwt);
        String headerJson;
        String payloadJson;
        try {
            headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        } catch (NullPointerException e) {
            throw new JWTDecodeException("The UTF-8 Charset isn't initialized.", e);
        } catch (IllegalArgumentException e) {
            throw new JWTDecodeException("The input is not a valid base 64 encoded string.", e);
        }
        header = converter.parseHeader(headerJson);
        payload = converter.parsePayload(payloadJson);
    }

    @Override
    public String getAlgorithm() {
        return header.getAlgorithm();
    }

    @Override
    public String getType() {
        return header.getType();
    }

    @Override
    public String getContentType() {
        return header.getContentType();
    }

    @Override
    public String getKeyId() {
        return header.getKeyId();
    }

    @Override
    public IClaim getHeaderClaim(String name) {
        return header.getHeaderClaim(name);
    }

    @Override
    public String getIssuer() {
        return payload.getIssuer();
    }

    @Override
    public String getSubject() {
        return payload.getSubject();
    }

    @Override
    public List<String> getAudience() {
        return payload.getAudience();
    }

    @Override
    public Date getExpiresAt() {
        return payload.getExpiresAt();
    }

    @Override
    public Instant getExpiresAtAsInstant() {
        return payload.getExpiresAtAsInstant();
    }

    @Override
    public Date getNotBefore() {
        return payload.getNotBefore();
    }

    @Override
    public Instant getNotBeforeAsInstant() {
        return  payload.getNotBeforeAsInstant();
    }

    @Override
    public Date getIssuedAt() {
        return payload.getIssuedAt();
    }

    @Override
    public Instant getIssuedAtAsInstant() {
        return payload.getIssuedAtAsInstant();
    }

    @Override
    public String getId() {
        return payload.getId();
    }

    @Override
    public IClaim getClaim(String name) {
        return payload.getClaim(name);
    }

    @Override
    public Map<String, IClaim> getClaims() {
        return payload.getClaims();
    }

    @Override
    public String getHeader() {
        return parts[0];
    }

    @Override
    public String getPayload() {
        return parts[1];
    }

    @Override
    public String getSignature() {
        return parts[2];
    }

    @Override
    public String getToken() {
        return String.format("%s.%s.%s", parts[0], parts[1], parts[2]);
    }
}
