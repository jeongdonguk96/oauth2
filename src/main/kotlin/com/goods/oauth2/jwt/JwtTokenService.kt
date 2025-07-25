package com.goods.oauth2.jwt

import com.goods.oauth2.entity.Member
import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.Jwts.SIG
import io.jsonwebtoken.security.Keys
import io.jsonwebtoken.security.SignatureException
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import java.security.PrivateKey
import java.time.Instant
import java.util.*


@Component
class JwtTokenService(
    @Value("\${oauth2.jwt.access-token-expiry}") private val accessTokenExpiry: Long,
    @Value("\${oauth2.jwt.refresh-token-expiry}") private val refreshTokenExpiry: Long,
    @Value("\${oauth2.jwt.secret}") private val secretKey: String
) {
    private val secretKeyBytes = Base64.getEncoder().encode(secretKey.toByteArray())
    private val key = Keys.hmacShaKeyFor(secretKeyBytes)


    fun generateAccessToken(
        member: Member
    ): String {
        return Jwts.builder()
            .subject(member.email)
            .issuedAt(Date())
            .expiration(Date.from(Instant.now().plusSeconds(accessTokenExpiry)))
            .signWith(key, SIG.HS256)
            .compact()
    }


    fun generateRefreshToken(
        member: Member
    ): String {
        return Jwts.builder()
            .subject(member.email)
            .issuedAt(Date())
            .expiration(Date.from(Instant.now().plusSeconds(refreshTokenExpiry)))
            .signWith(key, SIG.HS256)
            .compact()
    }


    fun generateAppleClientSecret(
        keyId: String,
        teamId: String,
        clientId: String,
        audienceUri: String,
        privateKey: PrivateKey
    ): String {
        return Jwts.builder()
            .header()
                .add("kid", keyId)
                .and()
            .claims()
                .add("aud",audienceUri)
                .issuer(teamId)
                .subject(clientId)
                .issuedAt(Date())
                .expiration(Date.from(Instant.now().plusSeconds(15777000)))
                .and()
            .signWith(privateKey, SIG.ES256)
            .compact()
    }


    fun getSubject(
        token: String
    ): String {
        return Jwts.parser()
            .verifyWith(key)
            .build()
            .parseSignedClaims(token)
            .payload
            .subject
    }


    fun getRoles(
        token: String
    ): List<String> {
        val claims = Jwts.parser()
            .verifyWith(key)
            .build()
            .parseSignedClaims(token)

        return claims.payload["roles"] as? List<String> ?: emptyList()
    }


    fun validateToken(
    token: String
    ) : Boolean {
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