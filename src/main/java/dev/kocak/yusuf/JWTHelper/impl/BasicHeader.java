package dev.kocak.yusuf.JWTHelper.impl;


import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectReader;
import dev.kocak.yusuf.JWTHelper.model.IClaim;
import dev.kocak.yusuf.JWTHelper.model.IHeader;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static dev.kocak.yusuf.JWTHelper.impl.JsonNodeIClaim.extractClaim;


class BasicHeader implements IHeader, Serializable {
    private static final long serialVersionUID = -4659137688548605095L;

    private final String algorithm;
    private final String type;
    private final String contentType;
    private final String keyId;
    private final Map<String, JsonNode> tree;
    private final ObjectReader objectReader;

    BasicHeader(
            String algorithm,
            String type,
            String contentType,
            String keyId,
            Map<String, JsonNode> tree,
            ObjectReader objectReader
    ) {
        this.algorithm = algorithm;
        this.type = type;
        this.contentType = contentType;
        this.keyId = keyId;
        this.tree = Collections.unmodifiableMap(tree == null ? new HashMap<String, JsonNode>() : tree);
        this.objectReader = objectReader;
    }

    Map<String, JsonNode> getTree() {
        return tree;
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getType() {
        return type;
    }

    @Override
    public String getContentType() {
        return contentType;
    }

    @Override
    public String getKeyId() {
        return keyId;
    }

    @Override
    public IClaim getHeaderClaim(String name) {
        return extractClaim(name, tree, objectReader);
    }
}
