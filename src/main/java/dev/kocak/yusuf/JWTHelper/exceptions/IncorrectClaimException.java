package dev.kocak.yusuf.JWTHelper.exceptions;

import dev.kocak.yusuf.JWTHelper.model.IClaim;


public class IncorrectClaimException extends InvalidClaimException {
    private final String claimName;

    private final IClaim IClaimValue;

    
    public IncorrectClaimException(String message, String claimName, IClaim IClaim) {
        super(message);
        this.claimName = claimName;
        this.IClaimValue = IClaim;
    }

    
    public String getClaimName() {
        return claimName;
    }

    
    public IClaim getClaimValue() {
        return IClaimValue;
    }
}