package dev.kocak.yusuf.JWTHelper;

import dev.kocak.yusuf.JWTHelper.algorithms.Algorithm;
import dev.kocak.yusuf.JWTHelper.exceptions.JWTDecodeException;
import dev.kocak.yusuf.JWTHelper.impl.JWTParser;
import dev.kocak.yusuf.JWTHelper.model.IDecodedJWT;
import dev.kocak.yusuf.JWTHelper.model.IVerification;


@SuppressWarnings("WeakerAccess")
public class JWT {

    private final JWTParser parser;

    
    public JWT() {
        parser = new JWTParser();
    }

    
    public IDecodedJWT decodeJwt(String token) throws JWTDecodeException {
        return new JWTDecoder(parser, token);
    }

    
    public static IDecodedJWT decode(String token) throws JWTDecodeException {
        return new JWTDecoder(token);
    }

    
    public static IVerification require(Algorithm algorithm) {
        return JWTVerifier.init(algorithm);
    }

    
    public static JWTCreator.Builder create() {
        return JWTCreator.init();
    }
}
