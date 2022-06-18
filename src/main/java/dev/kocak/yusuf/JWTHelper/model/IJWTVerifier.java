package dev.kocak.yusuf.JWTHelper.model;


import dev.kocak.yusuf.JWTHelper.exceptions.JWTVerificationException;

public interface IJWTVerifier {

    IDecodedJWT verify(String token) throws JWTVerificationException;

    IDecodedJWT verify(IDecodedJWT jwt) throws JWTVerificationException;
}
