package dev.kocak.yusuf.JWTHelper.model;

import java.security.PrivateKey;
import java.security.PublicKey;


interface IKeyProvider<U extends PublicKey, R extends PrivateKey> {
    U getPublicKeyById(String keyId);

    R getPrivateKey();

    String getPrivateKeyId();
}
