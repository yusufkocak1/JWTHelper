package dev.kocak.yusuf.JWTHelper.model;

public interface ExpectedCheckHolder {

    String getClaimName();


    boolean verify(IClaim IClaim, IDecodedJWT decodedJWT);
}
