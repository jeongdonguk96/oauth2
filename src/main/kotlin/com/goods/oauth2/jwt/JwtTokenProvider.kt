package com.goods.oauth2.jwt

import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.Jwts.SIG
import io.jsonwebtoken.Jwts.claims
import io.jsonwebtoken.security.Keys
import io.jsonwebtoken.security.SignatureException
import java.security.KeyRep
import java.time.LocalDateTime
import java.time.ZoneId
import java.util.*
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component


@Component
class JwtTokenProvider(
    @Value("\${jwt.secret}") private val secretKey: String,
    @Value("\${jwt.expiry}") private val expiry: Long
) {
    private val secretKeyBytes = Base64.getEncoder().encode(secretKey.toByteArray())
    private val key = Keys.hmacShaKeyFor(secretKeyBytes)

    fun createToken(
        subject: String,
        roles: List<String>
    ): String {
        val now = Date()
        val expireAt = Date(now.time + expiry)

        return Jwts.builder()
            .subject(subject)
            .claim("roles", roles)
            .issuedAt(now)
            .expiration(expireAt)
            .signWith(key, SIG.HS256)
            .compact()
    }

    fun getSubject(token: String): String {
        return Jwts.parser()
            .verifyWith(key)
            .build()
            .parseSignedClaims(token)
            .payload
            .subject
    }

    fun getRoles(token: String): List<String> {
        val claims = Jwts.parser()
            .verifyWith(key)
            .build()
            .parseSignedClaims(token)

        return claims.payload["roles"] as? List<String> ?: emptyList()
    }

    fun validateToken(token: String) : Boolean {
        try {
            Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)

            return true
        } catch (e: Exception) {
            if (e is SignatureException) {
                throw RuntimeException("JWT Token Invalid Exception")
            } else if (e is ExpiredJwtException) {
                throw RuntimeException("JWT Token Expired Exception")
            } else {
                throw RuntimeException("JWT Exception")
            }
        }
    }

}