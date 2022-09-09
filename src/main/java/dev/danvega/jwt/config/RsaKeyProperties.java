package dev.danvega.jwt.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@ConfigurationProperties(prefix = "jwt")
public record JwtConfigProperties(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
}
