package dev.kocak.yusuf.JWTHelper.algorithms;


import dev.kocak.yusuf.JWTHelper.exceptions.SignatureGenerationException;
import dev.kocak.yusuf.JWTHelper.exceptions.SignatureVerificationException;
import dev.kocak.yusuf.JWTHelper.model.IDecodedJWT;

import java.util.Base64;

class NoneAlgorithm extends Algorithm {

    NoneAlgorithm() {
        super("none", "none");
    }

    @Override
    public void verify(IDecodedJWT jwt) throws SignatureVerificationException {
        try {
            byte[] signatureBytes = Base64.getUrlDecoder().decode(jwt.getSignature());

            if (signatureBytes.length > 0) {
                throw new SignatureVerificationException(this);
            }
        } catch (IllegalArgumentException e) {
            throw new SignatureVerificationException(this, e);
        }
    }

    @Override
    public byte[] sign(byte[] headerBytes, byte[] payloadBytes) throws SignatureGenerationException {
        return new byte[0];
    }

    @Override
    public byte[] sign(byte[] contentBytes) throws SignatureGenerationException {
        return new byte[0];
    }
}
