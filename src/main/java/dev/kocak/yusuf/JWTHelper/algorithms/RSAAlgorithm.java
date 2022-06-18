package dev.kocak.yusuf.JWTHelper.algorithms;


import dev.kocak.yusuf.JWTHelper.exceptions.SignatureGenerationException;
import dev.kocak.yusuf.JWTHelper.exceptions.SignatureVerificationException;
import dev.kocak.yusuf.JWTHelper.model.IDecodedJWT;
import dev.kocak.yusuf.JWTHelper.model.IRSAKeyProvider;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;


class RSAAlgorithm extends Algorithm {

    private final IRSAKeyProvider keyProvider;
    private final CryptoHelper crypto;

    //Visible for testing
    RSAAlgorithm(CryptoHelper crypto, String id, String algorithm, IRSAKeyProvider keyProvider)
            throws IllegalArgumentException {
        super(id, algorithm);
        if (keyProvider == null) {
            throw new IllegalArgumentException("The Key Provider cannot be null.");
        }
        this.keyProvider = keyProvider;
        this.crypto = crypto;
    }

    RSAAlgorithm(String id, String algorithm, IRSAKeyProvider keyProvider) throws IllegalArgumentException {
        this(new CryptoHelper(), id, algorithm, keyProvider);
    }

    @Override
    public void verify(IDecodedJWT jwt) throws SignatureVerificationException {
        try {
            byte[] signatureBytes = Base64.getUrlDecoder().decode(jwt.getSignature());
            RSAPublicKey publicKey = keyProvider.getPublicKeyById(jwt.getKeyId());
            if (publicKey == null) {
                throw new IllegalStateException("The given Public Key is null.");
            }
            boolean valid = crypto.verifySignatureFor(
                    getDescription(), publicKey, jwt.getHeader(), jwt.getPayload(), signatureBytes);
            if (!valid) {
                throw new SignatureVerificationException(this);
            }
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException
                | IllegalArgumentException | IllegalStateException e) {
            throw new SignatureVerificationException(this, e);
        }
    }

    @Override
    public byte[] sign(byte[] headerBytes, byte[] payloadBytes) throws SignatureGenerationException {
        try {
            RSAPrivateKey privateKey = keyProvider.getPrivateKey();
            if (privateKey == null) {
                throw new IllegalStateException("The given Private Key is null.");
            }
            return crypto.createSignatureFor(getDescription(), privateKey, headerBytes, payloadBytes);
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException | IllegalStateException e) {
            throw new SignatureGenerationException(this, e);
        }
    }

    @Override
    public byte[] sign(byte[] contentBytes) throws SignatureGenerationException {
        try {
            RSAPrivateKey privateKey = keyProvider.getPrivateKey();
            if (privateKey == null) {
                throw new IllegalStateException("The given Private Key is null.");
            }
            return crypto.createSignatureFor(getDescription(), privateKey, contentBytes);
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException | IllegalStateException e) {
            throw new SignatureGenerationException(this, e);
        }
    }

    @Override
    public String getSigningKeyId() {
        return keyProvider.getPrivateKeyId();
    }

    //Visible for testing
    static IRSAKeyProvider providerForKeys(final RSAPublicKey publicKey, final RSAPrivateKey privateKey) {
        if (publicKey == null && privateKey == null) {
            throw new IllegalArgumentException("Both provided Keys cannot be null.");
        }
        return new IRSAKeyProvider() {
            @Override
            public RSAPublicKey getPublicKeyById(String keyId) {
                return publicKey;
            }

            @Override
            public RSAPrivateKey getPrivateKey() {
                return privateKey;
            }

            @Override
            public String getPrivateKeyId() {
                return null;
            }
        };
    }
}
