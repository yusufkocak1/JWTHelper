package dev.kocak.yusuf.JWTHelper.impl;

import java.util.HashMap;
import java.util.Map;


public abstract class ClaimsHolder {
    private Map<String, Object> claims;

    protected ClaimsHolder(Map<String, Object> claims) {
        this.claims = claims == null ? new HashMap<>() : claims;
    }

    Map<String, Object> getClaims() {
        return claims;
    }
}
