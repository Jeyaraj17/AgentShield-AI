package com.agentshield.identity.config;

import java.text.ParseException;
import java.util.Set;

import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

final class KeyIdValidatingJwtDecoder implements JwtDecoder {

    private final JwtDecoder delegate;
    private final Set<String> allowedKeyIds;

    KeyIdValidatingJwtDecoder(JwtDecoder delegate, Set<String> allowedKeyIds) {
        this.delegate = delegate;
        this.allowedKeyIds = Set.copyOf(allowedKeyIds);
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        try {
            String keyId = SignedJWT.parse(token).getHeader().getKeyID();
            if (keyId == null || !allowedKeyIds.contains(keyId)) {
                throw new JwtException("JWT signing key identifier is missing or unknown");
            }
        } catch (ParseException exception) {
            throw new JwtException("JWT is malformed", exception);
        }
        return delegate.decode(token);
    }
}
