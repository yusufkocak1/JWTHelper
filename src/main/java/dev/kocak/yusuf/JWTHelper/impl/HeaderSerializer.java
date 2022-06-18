package dev.kocak.yusuf.JWTHelper.impl;


public class HeaderSerializer extends ClaimsSerializer<HeaderClaimsHolder> {
    public HeaderSerializer() {
        super(HeaderClaimsHolder.class);
    }
}
