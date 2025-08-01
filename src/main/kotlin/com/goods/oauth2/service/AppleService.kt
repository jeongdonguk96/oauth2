package com.goods.oauth2.service

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import com.goods.oauth2.dto.AppleJwkKeys
import com.goods.oauth2.dto.AppleTokenResponse
import com.goods.oauth2.dto.CommonOAuthUserInfo
import com.goods.oauth2.dto.OAuthUserInfo
import com.goods.oauth2.enums.Provider
import com.goods.oauth2.extention.logger
import com.goods.oauth2.jwt.JwtTokenService
import com.goods.oauth2.util.FileUtil
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.Jwts.SIG
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.MediaType
import org.springframework.stereotype.Service
import org.springframework.web.reactive.function.BodyInserters
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.awaitBody
import java.math.BigInteger
import java.net.URI
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPublicKeySpec
import java.time.Duration
import java.time.Instant
import java.util.*


@Service
class AppleService(
    private val webClient: WebClient,
    private val jwtTokenService: JwtTokenService,
    @Value("\${oauth2.apple.key-id}") private val keyId: String,
    @Value("\${oauth2.apple.team-id}") private val teamId: String,
    @Value("\${oauth2.apple.client-id}") private val clientId: String,
    @Value("\${oauth2.apple.secret-expiry}") private val secretExpiry: Duration,
    @Value("\${oauth2.apple.private-key-path}") private val privateKeyPath: String,
    @Value("\${oauth2.apple.redirect-uri}") private val redirectUri: String,
    @Value("\${oauth2.apple.jwks-uri}") private val jwksUri: String,
    @Value("\${oauth2.apple.audience-uri}") private val audienceUri: String,
    @Value("\${oauth2.apple.user-info-uri}") private val userInfoUri: String
) : OAuth2Service {
    private val log = logger
    private val mapper = jacksonObjectMapper()


    override suspend fun getUserInfoByAuthorizationCode(
        code: String
    ): OAuthUserInfo {
        val p8File = FileUtil.readFile(privateKeyPath)
        log.info("p8File: $p8File")

        val privateKey = loadPrivateKeyFromP8File(p8File)
        log.info("privateKey: $privateKey")

        val clientSecret = generateAppleClientSecret(privateKey)
        log.info("clientSecret: $clientSecret")

        val userResponse = getUserInfo(code, clientSecret)
        return mapUserInfo(userResponse)
    }


    private fun loadPrivateKeyFromP8File(
        p8FileContent: String
    ): PrivateKey {
        val privateKeyPEM = p8FileContent
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replace("\\s".toRegex(), "")
        val encoded = Base64.getDecoder().decode(privateKeyPEM)
        val keySpec = PKCS8EncodedKeySpec(encoded)
        val kf = KeyFactory.getInstance("EC")

        return kf.generatePrivate(keySpec)
    }


    private fun generateAppleClientSecret(
        privateKey: PrivateKey
    ): String {
        val now = Instant.now()
        return Jwts.builder()
            .header()
                .add("kid", keyId)
                .and()
            .claims()
                .add("aud",audienceUri)
                .issuer(teamId)
                .subject(clientId)
                .issuedAt(Date())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(secretExpiry.seconds)))
                .and()
            .signWith(privateKey, SIG.ES256)
            .compact()
    }


    private suspend fun getUserInfo(
        code: String,
        clientSecret: String
    ): AppleTokenResponse {
        return webClient.post()
            .uri(userInfoUri)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .body(
                BodyInserters.fromFormData("grant_type", "authorization_code")
                    .with("client_id", clientId)
                    .with("client_secret", clientSecret)
                    .with("code", code)
                    .with("redirect_uri", redirectUri)
            )
            .retrieve()
            .onStatus({ it.is4xxClientError }) { response ->
                response.bodyToMono(String::class.java).map { body ->
                    log.error("❌ Apple API 4xx Error Body: {}", body)
                    throw IllegalArgumentException("Apple API 호출 실패: $body")
                }
            }
            .awaitBody<AppleTokenResponse>()
    }


    private fun mapUserInfo(
        userResponse: AppleTokenResponse
    ) : OAuthUserInfo {
        val claims = parseAndValidateAppleIdToken(userResponse.id_token)
        val sub = claims.subject
        val email = claims["email"] as? String ?: "no-email@apple.com"

        return CommonOAuthUserInfo(
            id = sub,
            email = email,
            provider = Provider.APPLE
        )
    }


    private fun parseAndValidateAppleIdToken(idToken: String): Claims {
        // 1. JWT 헤더에서 kid를 추출한다.
        val jwtParts = idToken.split(".")
        if (jwtParts.size != 3) throw IllegalArgumentException("Invalid JWT structure")

        val headerJson = String(Base64.getUrlDecoder().decode(jwtParts[0]), Charsets.UTF_8)
        val kid = mapper.readTree(headerJson).get("kid")?.asText()
            ?: throw IllegalArgumentException("No 'kid' in token header")

        // 2. Apple에서 공개키를 가져온다.
        val publicKey = fetchApplePublicKey(kid)

        // 3. JWT 파서 빌드해 token을 검증한다.
        val parser = Jwts.parser()
            .verifyWith(publicKey)
            .build()

        val jws = parser.parseSignedClaims(idToken)
        val claims = jws.payload

        // 4. 필수 필드를 검증하고 claim을 반환한다.
        return validateAndReturnClaim(claims)
    }


    private fun fetchApplePublicKey(kid: String): PublicKey {
        val jwkUrl = URI(jwksUri).toURL()
        log.info("jwkUrl: $jwkUrl")
        val keySet = jwkUrl.openStream().use {
            mapper.readValue<AppleJwkKeys>(it)
        }
        log.info("keySet: $keySet")

        val matchingKey = keySet.keys.find { it.kid == kid }
            ?: throw IllegalArgumentException("No matching Apple public key found for kid: $kid")

        val modulus = Base64.getUrlDecoder().decode(matchingKey.n)
        val exponent = Base64.getUrlDecoder().decode(matchingKey.e)

        val spec = RSAPublicKeySpec(BigInteger(1, modulus), BigInteger(1, exponent))
        return KeyFactory.getInstance("RSA").generatePublic(spec)
    }


    private fun validateAndReturnClaim(
        claims: Claims
    ) : Claims {
        if (claims.issuer != audienceUri)
            throw IllegalArgumentException("Invalid token issuer")
        if (claims.expiration.before(Date()))
            throw IllegalArgumentException("Token expired")

        return claims
    }

}

