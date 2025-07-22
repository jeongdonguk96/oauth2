package com.goods.oauth2.jwt

import com.goods.oauth2.entity.Member
import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.Jwts.SIG
import io.jsonwebtoken.security.Keys
import io.jsonwebtoken.security.SignatureException
import java.security.PrivateKey
import java.util.*
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component


@Component
class JwtTokenProvider(
    @Value("\${jwt.secret}") private val secretKey: String,
    @Value("\${jwt.access-expiry}") private val accessExpiry: Long,
    @Value("\${jwt.refresh-expiry}") private val refreshExpiry: Long
) {
    private val secretKeyBytes = Base64.getEncoder().encode(secretKey.toByteArray())
    private val key = Keys.hmacShaKeyFor(secretKeyBytes)

    fun generateAccessToken(
        member: Member
    ): String {
        val now = Date()
        val expireAt = Date(now.time + accessExpiry)

        return Jwts.builder()
            .subject(member.id.toString())
            .issuedAt(now)
            .expiration(expireAt)
            .signWith(key, SIG.HS256)
            .compact()
    }

    fun generateRefreshToken(
        member: Member
    ): String {
        val now = Date()
        val expiryDate = Date(now.time + refreshExpiry)

        return Jwts.builder()
            .subject(member.id.toString())
            .issuedAt(now)
            .expiration(expiryDate)
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
        val now = Date()
        val expireAt = Date(now.time + 15777000 * 1000)

        return Jwts.builder()
            .setHeaderParam("kid", keyId)
            .setAudience(audienceUri)
            .issuer(teamId)
            .subject(clientId)
            .issuedAt(now)
            .expiration(expireAt)
            .signWith(privateKey, SIG.ES256)
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