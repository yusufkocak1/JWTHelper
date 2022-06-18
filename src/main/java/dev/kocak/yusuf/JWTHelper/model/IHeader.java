package dev.kocak.yusuf.JWTHelper.model;

/**
 * The Header class represents the 1st part of the JWT, where the Header value is held.
 */
public interface IHeader {

    String getAlgorithm();

    String getType();

    String getContentType();


    String getKeyId();

    IClaim getHeaderClaim(String name);
}
