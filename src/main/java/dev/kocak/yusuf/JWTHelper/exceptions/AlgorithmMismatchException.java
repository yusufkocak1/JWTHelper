package dev.kocak.yusuf.JWTHelper.exceptions;


public class AlgorithmMismatchException extends JWTVerificationException {
    public AlgorithmMismatchException(String message) {
        super(message);
    }
}
