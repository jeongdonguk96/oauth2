package com.goods.oauth2.jwt

import com.goods.oauth2.entity.Member
import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.Jwts.SIG
import io.jsonwebtoken.security.Keys
import io.jsonwebtoken.security.SignatureException
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import java.time.Duration
import java.time.Instant
import java.util.*


@Component
class JwtTokenService(
    @Value("\${oauth2.jwt.access-token-expiry}") private val accessTokenExpiry: Duration,
    @Value("\${oauth2.jwt.refresh-token-expiry}") private val refreshTokenExpiry: Duration,
    @Value("\${oauth2.jwt.secret}") private val secretKey: String
) {

    private val key = Keys.hmacShaKeyFor(Base64.getDecoder().decode(secretKey))


    fun generateAccessToken(
        member: Member
    ): String {
        return generateToken(member.email, accessTokenExpiry)
    }


    fun generateRefreshToken(
        member: Member
    ): String {
        return generateToken(member.email, refreshTokenExpiry)
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
                // TODO: 토큰 검증 실패 예외를 던진다.
                throw RuntimeException("JWT Token Invalid Exception")
            } else if (e is ExpiredJwtException) {
                // TODO: DB의 리프레시 토큰을 조회해 재검증해 true를 리턴하거나 다시 예외를 던진다.
                throw RuntimeException("JWT Token Expired Exception")
            } else {
                // TODO: 토큰 기타 예외를 던진다.
                throw RuntimeException("JWT Exception")
            }
        }
    }


    private fun generateToken(
        subject: String,
        tokenExpiry: Duration
    ): String {
        val now = Instant.now()
        return Jwts.builder()
            .subject(subject)
            .issuedAt(Date.from(now))
            .expiration(Date.from(now.plusSeconds(tokenExpiry.seconds)))
            .signWith(key, SIG.HS256)
            .compact()
    }

}