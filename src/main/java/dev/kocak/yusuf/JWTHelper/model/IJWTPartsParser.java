package dev.kocak.yusuf.JWTHelper.model;


import dev.kocak.yusuf.JWTHelper.exceptions.JWTDecodeException;


public interface IJWTPartsParser {

    IPayload parsePayload(String json) throws JWTDecodeException;

    IHeader parseHeader(String json) throws JWTDecodeException;
}
