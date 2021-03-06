package dev.kocak.yusuf.JWTHelper.model;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

public interface IPayload {

    String getIssuer();

    String getSubject();

    List<String> getAudience();

    Date getExpiresAt();

    default Instant getExpiresAtAsInstant() {
        return getExpiresAt() != null ? getExpiresAt().toInstant() : null;
    }

    Date getNotBefore();

    default Instant getNotBeforeAsInstant() {
        return getNotBefore() != null ? getNotBefore().toInstant() : null;
    }


    Date getIssuedAt();


    default Instant getIssuedAtAsInstant() {
        return getIssuedAt() != null ? getIssuedAt().toInstant() : null;
    }

    String getId();

    IClaim getClaim(String name);

    Map<String, IClaim> getClaims();
}
