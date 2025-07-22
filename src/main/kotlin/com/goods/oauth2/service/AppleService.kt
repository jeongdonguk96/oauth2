package com.goods.oauth2.service

import com.goods.oauth2.dto.CommonOAuthUserInfo
import com.goods.oauth2.dto.OAuthUserInfo
import com.goods.oauth2.jwt.JwtTokenProvider
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.Jwts.SIG
import java.nio.file.Files
import java.nio.file.Paths
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.time.LocalDateTime
import java.time.ZoneId
import java.util.Base64
import java.util.Date
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.MediaType
import org.springframework.stereotype.Service
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.awaitBody


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

    override suspend fun getUserInfoByAuthorizationCode(
        code: String
    ): OAuthUserInfo {
        val p8File = readP8File(privateKeyPath)
        val privateKey = loadPrivateKeyFromP8(p8File)
        val clientSecret = jwtTokenProvider.generateAppleClientSecret(keyId, teamId, clientId, audienceUri, privateKey)
        return getUserInfo(code, clientSecret)
    }

    private fun readP8File(filePath: String): String {
        val path = Paths.get(filePath)
        return Files.readString(path)
    }

    private fun loadPrivateKeyFromP8(p8Content: String): PrivateKey {
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
    ): OAuthUserInfo {
        return webClient.post()
            .uri(userInfoUri)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .bodyValue(
                mapOf(
                    "grant_type" to "authorization_code",
                    "client_id" to clientId,
                    "client_secret" to clientSecret,
                    "code" to code,
                    "redirect_uri" to redirectUri
                )
            )
            .retrieve()
            .awaitBody<CommonOAuthUserInfo>()
    }

}

