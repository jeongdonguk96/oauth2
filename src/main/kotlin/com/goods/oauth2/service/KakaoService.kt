package com.goods.oauth2.service

import com.goods.oauth2.dto.CommonOAuthUserInfo
import com.goods.oauth2.dto.KakaoTokenResponse
import com.goods.oauth2.dto.OAuthTokenResponse
import com.goods.oauth2.dto.OAuthUserInfo
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.MediaType
import org.springframework.stereotype.Service
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.awaitBody

@Service
class KakaoService(
    private val webClient: WebClient,
    @Value("\${oauth2.kakao.client-id}") private val clientId: String,
    @Value("\${oauth2.kakao.client-secret}") private val clientSecret: String,
    @Value("\${oauth2.kakao.redirect-uri}") private val redirectUri: String,
    @Value("\${oauth2.kakao.token-uri}") private val tokenUri: String,
    @Value("\${oauth2.kakao.user-info-uri}") private val userInfoUri: String
) : OAuth2Service {

    override suspend fun getUserInfoByAuthorizationCode(
        code: String
    ): OAuthUserInfo {
        val token = getAccessToken(code)
        return getUserInfo(token.access_token)
    }

    private suspend fun getAccessToken(
        code: String
    ): OAuthTokenResponse {
        return webClient.post()
            .uri(tokenUri)
            .contentType(MediaType.APPLICATION_JSON)
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
            .awaitBody<KakaoTokenResponse>()
    }

    private suspend fun getUserInfo(
        accessToken: String
    ): OAuthUserInfo {
        return webClient.get()
            .uri(userInfoUri)
            .header("Authorization", "Bearer $accessToken")
            .retrieve()
            .awaitBody<CommonOAuthUserInfo>()
    }

}

