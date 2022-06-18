package dev.kocak.yusuf.JWTHelper;


import dev.kocak.yusuf.JWTHelper.exceptions.JWTDecodeException;

abstract class TokenUtils {

    
    static String[] splitToken(String token) throws JWTDecodeException {
        String[] parts = token.split("\\.");
        if (parts.length == 2 && token.endsWith(".")) {
            //Tokens with alg='none' have empty String as Signature.
            parts = new String[]{parts[0], parts[1], ""};
        }
        if (parts.length != 3) {
            throw new JWTDecodeException(
                    String.format("The token was expected to have 3 parts, but got %s.", parts.length));
        }
        return parts;
    }
}
