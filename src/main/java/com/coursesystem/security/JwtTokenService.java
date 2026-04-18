package com.coursesystem.security;

import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Collections;

import javax.crypto.SecretKey;

import com.coursesystem.config.SecurityProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
public class JwtTokenService {

    private final SecretKey signingKey;

    public JwtTokenService(SecurityProperties securityProperties) {
        String jwtSecret = securityProperties.getJwtSecret();
        if (!StringUtils.hasText(jwtSecret) || jwtSecret.length() < 32) {
            throw new IllegalStateException("app.security.jwt-secret must be set to at least 32 characters.");
        }

        this.signingKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    public Authentication toAuthentication(String token) {
        Claims claims = Jwts.parser()
            .verifyWith(signingKey)
            .build()
            .parseSignedClaims(token)
            .getPayload();

        String subject = claims.getSubject();
        if (!StringUtils.hasText(subject)) {
            throw new JwtException("JWT subject is missing.");
        }

        Collection<? extends GrantedAuthority> authorities = extractAuthorities(claims);
        return new UsernamePasswordAuthenticationToken(subject, token, authorities);
    }

    private Collection<? extends GrantedAuthority> extractAuthorities(Claims claims) {
        Object rolesClaim = claims.get("roles");
        if (!(rolesClaim instanceof Collection<?> roles)) {
            return Collections.emptyList();
        }

        return roles.stream()
            .filter(String.class::isInstance)
            .map(String.class::cast)
            .filter(StringUtils::hasText)
            .map(SimpleGrantedAuthority::new)
            .toList();
    }
}
