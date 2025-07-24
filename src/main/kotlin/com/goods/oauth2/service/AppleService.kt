package com.goods.oauth2.service

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import com.goods.oauth2.dto.AppleJwkKeys
import com.goods.oauth2.dto.AppleTokenResponse
import com.goods.oauth2.dto.CommonOAuthUserInfo
import com.goods.oauth2.dto.OAuthUserInfo
import com.goods.oauth2.extention.logger
import com.goods.oauth2.jwt.JwtTokenProvider
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import kotlinx.coroutines.reactor.awaitSingle
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.MediaType
import org.springframework.stereotype.Service
import org.springframework.web.reactive.function.BodyInserters
import org.springframework.web.reactive.function.client.WebClient
import java.math.BigInteger
import java.net.URL
import java.nio.file.Files
import java.nio.file.Paths
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPublicKeySpec
import java.util.*


@Service
class AppleService(
    private val webClient: WebClient,
    private val jwtTokenProvider: JwtTokenProvider,
    @Value("\${oauth2.apple.key-id}") private val keyId: String,
    @Value("\${oauth2.apple.team-id}") private val teamId: String,
    @Value("\${oauth2.apple.client-id}") private val clientId: String,
    @Value("\${oauth2.apple.private-key-path}") private val privateKeyPath: String,
    @Value("\${oauth2.apple.redirect-uri}") private val redirectUri: String,
    @Value("\${oauth2.apple.audience-uri}") private val audienceUri: String,
    @Value("\${oauth2.apple.user-info-uri}") private val userInfoUri: String
) : OAuth2Service {

    private val log = logger

    override suspend fun getUserInfoByAuthorizationCode(
        code: String
    ): OAuthUserInfo {
        val p8File = readP8File(privateKeyPath)
        log.info("p8File: $p8File")

        val privateKey = loadPrivateKeyFromP8(p8File)
        log.info("privateKey: $privateKey")

        val clientSecret = jwtTokenProvider.generateAppleClientSecret(keyId, teamId, clientId, audienceUri, privateKey)
        log.info("clientSecret: $clientSecret")

        val userResponse = getUserInfo(code, clientSecret)
        return mapUserInfo(userResponse)
    }

    private fun readP8File(
        filePath: String
    ): String {
        val path = Paths.get(filePath)
        return Files.readString(path)
    }

    private fun loadPrivateKeyFromP8(
        p8Content: String
    ): PrivateKey {
        val privateKeyPEM = p8Content
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replace("\\s".toRegex(), "")
        val encoded = Base64.getDecoder().decode(privateKeyPEM)
        val keySpec = PKCS8EncodedKeySpec(encoded)
        val kf = KeyFactory.getInstance("EC")
        return kf.generatePrivate(keySpec)
    }

    private suspend fun getUserInfo(
        code: String,
        clientSecret: String
    ): AppleTokenResponse {
        val rawResponse = webClient.post()
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
            .bodyToMono(String::class.java)
            .awaitSingle()

        log.info("✅ Apple API 성공 응답: {}", rawResponse)

        val mapper = jacksonObjectMapper()
        return mapper.readValue(rawResponse, AppleTokenResponse::class.java)
    }

    fun mapUserInfo(
        userResponse: AppleTokenResponse
    ) : OAuthUserInfo {
        val claims = parseAndValidateAppleIdToken(userResponse.id_token)

        val id = claims.subject // Apple에서 발급한 고유 사용자 ID
        val email = claims["email"] as? String ?: "no-email@apple.com"
        val nickname = null // Apple은 nickname 제공 안 함
        val profileImage = null // Apple은 프로필 이미지 제공 안 함

        return CommonOAuthUserInfo(
            id = id,
            email = email,
            nickname = nickname,
            profile_image = profileImage
        )
    }

    fun fetchApplePublicKey(kid: String): PublicKey {
        val jwkUrl = URL("https://appleid.apple.com/auth/keys")
        val mapper = jacksonObjectMapper()
        val keySet = jwkUrl.openStream().use {
            mapper.readValue<AppleJwkKeys>(it)
        }

        val matchingKey = keySet.keys.find { it.kid == kid }
            ?: throw IllegalArgumentException("No matching Apple public key found for kid: $kid")

        val modulus = Base64.getUrlDecoder().decode(matchingKey.n)
        val exponent = Base64.getUrlDecoder().decode(matchingKey.e)

        val spec = RSAPublicKeySpec(BigInteger(1, modulus), BigInteger(1, exponent))
        return KeyFactory.getInstance("RSA").generatePublic(spec)
    }

    fun parseAndValidateAppleIdToken(idToken: String): Claims {
        // 1. JWT 헤더에서 kid 추출
        val jwtParts = idToken.split(".")
        if (jwtParts.size != 3) throw IllegalArgumentException("Invalid JWT structure")

        val headerJson = String(Base64.getUrlDecoder().decode(jwtParts[0]), Charsets.UTF_8)
        val kid = jacksonObjectMapper().readTree(headerJson).get("kid")?.asText()
            ?: throw IllegalArgumentException("No 'kid' in token header")

        // 2. Apple 공개키 가져오기
        val publicKey = fetchApplePublicKey(kid)

        // 3. JWT 파서 빌드 및 검증
        val parser = Jwts.parser()
            .setSigningKey(publicKey)
            .build()

        val jws = parser.parseSignedClaims(idToken)  // ✅ 여기 주의: "parseSignedClaims" 사용
        val claims = jws.payload

        // 4. 필수 필드 검증
        if (claims.issuer != "https://appleid.apple.com")
            throw IllegalArgumentException("Invalid token issuer")
        if (claims.expiration.before(Date()))
            throw IllegalArgumentException("Token expired")

        return claims
    }

}

