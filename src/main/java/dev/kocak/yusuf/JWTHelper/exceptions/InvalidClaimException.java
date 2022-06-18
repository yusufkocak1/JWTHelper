package dev.kocak.yusuf.JWTHelper.exceptions;


public class InvalidClaimException extends JWTVerificationException {
    public InvalidClaimException(String message) {
        super(message);
    }
}