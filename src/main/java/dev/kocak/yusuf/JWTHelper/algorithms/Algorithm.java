package dev.kocak.yusuf.JWTHelper.algorithms;

import dev.kocak.yusuf.JWTHelper.exceptions.SignatureGenerationException;
import dev.kocak.yusuf.JWTHelper.exceptions.SignatureVerificationException;
import dev.kocak.yusuf.JWTHelper.model.IDecodedJWT;
import dev.kocak.yusuf.JWTHelper.model.IECDSAKeyProvider;
import dev.kocak.yusuf.JWTHelper.model.IRSAKeyProvider;

import java.security.interfaces.*;


@SuppressWarnings("WeakerAccess")
public abstract class Algorithm {

    private final String name;
    private final String description;

    
    public static Algorithm RSA256(IRSAKeyProvider keyProvider) throws IllegalArgumentException {
        return new RSAAlgorithm("RS256", "SHA256withRSA", keyProvider);
    }

    
    public static Algorithm RSA256(RSAPublicKey publicKey, RSAPrivateKey privateKey) throws IllegalArgumentException {
        return RSA256(RSAAlgorithm.providerForKeys(publicKey, privateKey));
    }

    
    public static Algorithm RSA256(RSAKey key) throws IllegalArgumentException {
        RSAPublicKey publicKey = key instanceof RSAPublicKey ? (RSAPublicKey) key : null;
        RSAPrivateKey privateKey = key instanceof RSAPrivateKey ? (RSAPrivateKey) key : null;
        return RSA256(publicKey, privateKey);
    }

    
    public static Algorithm RSA384(IRSAKeyProvider keyProvider) throws IllegalArgumentException {
        return new RSAAlgorithm("RS384", "SHA384withRSA", keyProvider);
    }

    
    public static Algorithm RSA384(RSAPublicKey publicKey, RSAPrivateKey privateKey) throws IllegalArgumentException {
        return RSA384(RSAAlgorithm.providerForKeys(publicKey, privateKey));
    }

    
    public static Algorithm RSA384(RSAKey key) throws IllegalArgumentException {
        RSAPublicKey publicKey = key instanceof RSAPublicKey ? (RSAPublicKey) key : null;
        RSAPrivateKey privateKey = key instanceof RSAPrivateKey ? (RSAPrivateKey) key : null;
        return RSA384(publicKey, privateKey);
    }

    
    public static Algorithm RSA512(IRSAKeyProvider keyProvider) throws IllegalArgumentException {
        return new RSAAlgorithm("RS512", "SHA512withRSA", keyProvider);
    }

    
    public static Algorithm RSA512(RSAPublicKey publicKey, RSAPrivateKey privateKey) throws IllegalArgumentException {
        return RSA512(RSAAlgorithm.providerForKeys(publicKey, privateKey));
    }

    
    public static Algorithm RSA512(RSAKey key) throws IllegalArgumentException {
        RSAPublicKey publicKey = key instanceof RSAPublicKey ? (RSAPublicKey) key : null;
        RSAPrivateKey privateKey = key instanceof RSAPrivateKey ? (RSAPrivateKey) key : null;
        return RSA512(publicKey, privateKey);
    }

    
    public static Algorithm HMAC256(String secret) throws IllegalArgumentException {
        return new HMACAlgorithm("HS256", "HmacSHA256", secret);
    }

    
    public static Algorithm HMAC256(byte[] secret) throws IllegalArgumentException {
        return new HMACAlgorithm("HS256", "HmacSHA256", secret);
    }

    
    public static Algorithm HMAC384(String secret) throws IllegalArgumentException {
        return new HMACAlgorithm("HS384", "HmacSHA384", secret);
    }

    
    public static Algorithm HMAC384(byte[] secret) throws IllegalArgumentException {
        return new HMACAlgorithm("HS384", "HmacSHA384", secret);
    }

    
    public static Algorithm HMAC512(String secret) throws IllegalArgumentException {
        return new HMACAlgorithm("HS512", "HmacSHA512", secret);
    }

    
    public static Algorithm HMAC512(byte[] secret) throws IllegalArgumentException {
        return new HMACAlgorithm("HS512", "HmacSHA512", secret);
    }


    
    public static Algorithm ECDSA256(IECDSAKeyProvider keyProvider) throws IllegalArgumentException {
        return new ECDSAAlgorithm("ES256", "SHA256withECDSA", 32, keyProvider);
    }

    
    public static Algorithm ECDSA256(ECPublicKey publicKey, ECPrivateKey privateKey) throws IllegalArgumentException {
        return ECDSA256(ECDSAAlgorithm.providerForKeys(publicKey, privateKey));
    }

    
    public static Algorithm ECDSA256(ECKey key) throws IllegalArgumentException {
        ECPublicKey publicKey = key instanceof ECPublicKey ? (ECPublicKey) key : null;
        ECPrivateKey privateKey = key instanceof ECPrivateKey ? (ECPrivateKey) key : null;
        return ECDSA256(publicKey, privateKey);
    }

    
    public static Algorithm ECDSA384(IECDSAKeyProvider keyProvider) throws IllegalArgumentException {
        return new ECDSAAlgorithm("ES384", "SHA384withECDSA", 48, keyProvider);
    }

    
    public static Algorithm ECDSA384(ECPublicKey publicKey, ECPrivateKey privateKey) throws IllegalArgumentException {
        return ECDSA384(ECDSAAlgorithm.providerForKeys(publicKey, privateKey));
    }

    
    public static Algorithm ECDSA384(ECKey key) throws IllegalArgumentException {
        ECPublicKey publicKey = key instanceof ECPublicKey ? (ECPublicKey) key : null;
        ECPrivateKey privateKey = key instanceof ECPrivateKey ? (ECPrivateKey) key : null;
        return ECDSA384(publicKey, privateKey);
    }

    
    public static Algorithm ECDSA512(IECDSAKeyProvider keyProvider) throws IllegalArgumentException {
        return new ECDSAAlgorithm("ES512", "SHA512withECDSA", 66, keyProvider);
    }

    
    public static Algorithm ECDSA512(ECPublicKey publicKey, ECPrivateKey privateKey) throws IllegalArgumentException {
        return ECDSA512(ECDSAAlgorithm.providerForKeys(publicKey, privateKey));
    }

    
    public static Algorithm ECDSA512(ECKey key) throws IllegalArgumentException {
        ECPublicKey publicKey = key instanceof ECPublicKey ? (ECPublicKey) key : null;
        ECPrivateKey privateKey = key instanceof ECPrivateKey ? (ECPrivateKey) key : null;
        return ECDSA512(publicKey, privateKey);
    }


    public static Algorithm none() {
        return new NoneAlgorithm();
    }

    protected Algorithm(String name, String description) {
        this.name = name;
        this.description = description;
    }

    
    public String getSigningKeyId() {
        return null;
    }

    
    public String getName() {
        return name;
    }

    
    String getDescription() {
        return description;
    }

    @Override
    public String toString() {
        return description;
    }

    
    public abstract void verify(IDecodedJWT jwt) throws SignatureVerificationException;

    
    public byte[] sign(byte[] headerBytes, byte[] payloadBytes) throws SignatureGenerationException {
        // default implementation; keep around until sign(byte[]) method is removed
        byte[] contentBytes = new byte[headerBytes.length + 1 + payloadBytes.length];

        System.arraycopy(headerBytes, 0, contentBytes, 0, headerBytes.length);
        contentBytes[headerBytes.length] = (byte) '.';
        System.arraycopy(payloadBytes, 0, contentBytes, headerBytes.length + 1, payloadBytes.length);

        return sign(contentBytes);
    }

    

    public abstract byte[] sign(byte[] contentBytes) throws SignatureGenerationException;

}
