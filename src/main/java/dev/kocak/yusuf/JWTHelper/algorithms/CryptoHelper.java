package dev.kocak.yusuf.JWTHelper.algorithms;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;


class CryptoHelper {

    private static final byte JWT_PART_SEPARATOR = (byte) 46;

    

    boolean verifySignatureFor(
            String algorithm,
            byte[] secretBytes,
            String header,
            String payload,
            byte[] signatureBytes
    ) throws NoSuchAlgorithmException, InvalidKeyException {
        return verifySignatureFor(algorithm, secretBytes,
                header.getBytes(StandardCharsets.UTF_8), payload.getBytes(StandardCharsets.UTF_8), signatureBytes);
    }

    

    boolean verifySignatureFor(
            String algorithm,
            byte[] secretBytes,
            byte[] headerBytes,
            byte[] payloadBytes,
            byte[] signatureBytes
    ) throws NoSuchAlgorithmException, InvalidKeyException {
        return MessageDigest.isEqual(createSignatureFor(algorithm, secretBytes, headerBytes, payloadBytes),
                signatureBytes);
    }

    
    boolean verifySignatureFor(
            String algorithm,
            PublicKey publicKey,
            String header,
            String payload,
            byte[] signatureBytes
    ) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        return verifySignatureFor(algorithm, publicKey, header.getBytes(StandardCharsets.UTF_8),
                payload.getBytes(StandardCharsets.UTF_8), signatureBytes);
    }

    
    boolean verifySignatureFor(
            String algorithm,
            PublicKey publicKey,
            byte[] headerBytes,
            byte[] payloadBytes,
            byte[] signatureBytes
    ) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        final Signature s = Signature.getInstance(algorithm);
        s.initVerify(publicKey);
        s.update(headerBytes);
        s.update(JWT_PART_SEPARATOR);
        s.update(payloadBytes);
        return s.verify(signatureBytes);
    }

    
    byte[] createSignatureFor(
            String algorithm,
            PrivateKey privateKey,
            byte[] headerBytes,
            byte[] payloadBytes
    ) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        final Signature s = Signature.getInstance(algorithm);
        s.initSign(privateKey);
        s.update(headerBytes);
        s.update(JWT_PART_SEPARATOR);
        s.update(payloadBytes);
        return s.sign();
    }

    
    byte[] createSignatureFor(
            String algorithm,
            byte[] secretBytes,
            byte[] headerBytes,
            byte[] payloadBytes
    ) throws NoSuchAlgorithmException, InvalidKeyException {
        final Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(secretBytes, algorithm));
        mac.update(headerBytes);
        mac.update(JWT_PART_SEPARATOR);
        return mac.doFinal(payloadBytes);
    }

    
    byte[] createSignatureFor(String algorithm, byte[] secretBytes, byte[] contentBytes)
            throws NoSuchAlgorithmException, InvalidKeyException {
        final Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(secretBytes, algorithm));
        return mac.doFinal(contentBytes);
    }

    

    byte[] createSignatureFor(
            String algorithm,
            PrivateKey privateKey,
            byte[] contentBytes
    ) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        final Signature s = Signature.getInstance(algorithm);
        s.initSign(privateKey);
        s.update(contentBytes);
        return s.sign();
    }
}
