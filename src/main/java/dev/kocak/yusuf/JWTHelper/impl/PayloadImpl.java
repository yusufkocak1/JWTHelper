package dev.kocak.yusuf.JWTHelper.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectReader;
import dev.kocak.yusuf.JWTHelper.model.IClaim;
import dev.kocak.yusuf.JWTHelper.model.IPayload;

import java.io.Serializable;
import java.time.Instant;
import java.util.*;

import static dev.kocak.yusuf.JWTHelper.impl.JsonNodeIClaim.extractClaim;

class PayloadImpl implements IPayload, Serializable {

    private static final long serialVersionUID = 1659021498824562311L;

    private final String issuer;
    private final String subject;
    private final List<String> audience;
    private final Instant expiresAt;
    private final Instant notBefore;
    private final Instant issuedAt;
    private final String jwtId;
    private final Map<String, JsonNode> tree;
    private final ObjectReader objectReader;

    PayloadImpl(
            String issuer,
            String subject,
            List<String> audience,
            Instant expiresAt,
            Instant notBefore,
            Instant issuedAt,
            String jwtId,
            Map<String, JsonNode> tree,
            ObjectReader objectReader
    ) {
        this.issuer = issuer;
        this.subject = subject;
        this.audience = audience != null ? Collections.unmodifiableList(audience) : null;
        this.expiresAt = expiresAt;
        this.notBefore = notBefore;
        this.issuedAt = issuedAt;
        this.jwtId = jwtId;
        this.tree = tree != null ? Collections.unmodifiableMap(tree) : Collections.<String, JsonNode>emptyMap();
        this.objectReader = objectReader;
    }

    Map<String, JsonNode> getTree() {
        return tree;
    }

    @Override
    public String getIssuer() {
        return issuer;
    }

    @Override
    public String getSubject() {
        return subject;
    }

    @Override
    public List<String> getAudience() {
        return audience;
    }

    @Override
    public Date getExpiresAt() {
        return (expiresAt != null) ? Date.from(expiresAt) : null;
    }


    @Override
    public Instant getExpiresAtAsInstant() {
        return expiresAt;
    }

    @Override
    public Date getIssuedAt() {
        return (issuedAt != null) ? Date.from(issuedAt) : null;
    }

    @Override
    public Instant getIssuedAtAsInstant() {
        return issuedAt;
    }

    @Override
    public Date getNotBefore() {
        return (notBefore != null) ? Date.from(notBefore) : null;
    }

    @Override
    public Instant getNotBeforeAsInstant() {
        return notBefore;
    }

    @Override
    public String getId() {
        return jwtId;
    }

    @Override
    public IClaim getClaim(String name) {
        return extractClaim(name, tree, objectReader);
    }

    @Override
    public Map<String, IClaim> getClaims() {
        Map<String, IClaim> claims = new HashMap<>(tree.size() * 2);
        for (String name : tree.keySet()) {
            claims.put(name, extractClaim(name, tree, objectReader));
        }
        return Collections.unmodifiableMap(claims);
    }
}
