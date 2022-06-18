package dev.kocak.yusuf.JWTHelper.impl;


import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.module.SimpleModule;
import dev.kocak.yusuf.JWTHelper.exceptions.JWTDecodeException;
import dev.kocak.yusuf.JWTHelper.model.IHeader;
import dev.kocak.yusuf.JWTHelper.model.IJWTPartsParser;
import dev.kocak.yusuf.JWTHelper.model.IPayload;

import java.io.IOException;

public class JWTParser implements IJWTPartsParser {
    private final ObjectReader payloadReader;
    private final ObjectReader headerReader;

    public JWTParser() {
        this(getDefaultObjectMapper());
    }

    JWTParser(ObjectMapper mapper) {
        addDeserializers(mapper);
        this.payloadReader = mapper.readerFor(IPayload.class);
        this.headerReader = mapper.readerFor(IHeader.class);
    }

    @Override
    public IPayload parsePayload(String json) throws JWTDecodeException {
        if (json == null) {
            throw decodeException();
        }

        try {
            return payloadReader.readValue(json);
        } catch (IOException e) {
            throw decodeException(json);
        }
    }

    @Override
    public IHeader parseHeader(String json) throws JWTDecodeException {
        if (json == null) {
            throw decodeException();
        }

        try {
            return headerReader.readValue(json);
        } catch (IOException e) {
            throw decodeException(json);
        }
    }

    private void addDeserializers(ObjectMapper mapper) {
        SimpleModule module = new SimpleModule();
        ObjectReader reader = mapper.reader();
        module.addDeserializer(IPayload.class, new PayloadDeserializer(reader));
        module.addDeserializer(IHeader.class, new HeaderDeserializer(reader));
        mapper.registerModule(module);
    }

    static ObjectMapper getDefaultObjectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);
        mapper.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);
        return mapper;
    }

    private static JWTDecodeException decodeException() {
        return decodeException(null);
    }

    private static JWTDecodeException decodeException(String json) {
        return new JWTDecodeException(String.format("The string '%s' doesn't have a valid JSON format.", json));
    }
}
