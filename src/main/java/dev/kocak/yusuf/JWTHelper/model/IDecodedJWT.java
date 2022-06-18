package dev.kocak.yusuf.JWTHelper.model;


public interface IDecodedJWT extends IPayload, IHeader {
    String getToken();

    String getHeader();

    String getPayload();

    String getSignature();
}
