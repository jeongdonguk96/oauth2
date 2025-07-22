package com.goods.oauth2.service

import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.client.WebClient

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class KakaoServiceTest {

    private lateinit var kakaoService: KakaoService
    private lateinit var mockWebServer: MockWebServer

    @BeforeAll
    fun setUp() {
        mockWebServer = MockWebServer()
        mockWebServer.start()

        val webClient = WebClient.builder()
            .baseUrl(mockWebServer.url("/").toString())
            .build()

        kakaoService = KakaoService(
            webClient = webClient,
            clientId = "test-client-id",
            clientSecret = "test-client-secret",
            redirectUri = "http://localhost/api/auth/kakao/callback",
            tokenUri = "/oauth/token",
            userInfoUri = "/v2/user/me"
        )
    }

    @AfterAll
    fun tearDown() {
        mockWebServer.shutdown()
    }

    @Test
    fun `요청한 액세스 토큰을 이용하여 사용자 정보를 성공적으로 받아온다`() = runTest {
        // given - access token 응답
        val tokenJson = """
            {
              "access_token": "access123",
              "token_type": "bearer",
              "refresh_token": "refresh456",
              "expires_in": 3600,
              "scope": "account_email",
              "refresh_token_expires_in": 86400
            }
        """.trimIndent()

        mockWebServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                .setBody(tokenJson)
        )

        // given - user info 응답
        val userInfoJson = """
            {
              "id": 123456789,
              "email": "test@kakao.com",
              "nickname": "홍길동",
              "profile_image": "http://test.image"
            }
        """.trimIndent()

        mockWebServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                .setBody(userInfoJson)
        )

        // when
        val userInfo = kakaoService.getUserInfoByAuthorizationCode("test-authorization-code")

        // then
        assertThat(userInfo.id).isEqualTo("123456789")
        assertThat(userInfo.email).isEqualTo("test@kakao.com")
        assertThat(userInfo.nickname).isEqualTo("홍길동")
        assertThat(userInfo.profile_image).isEqualTo("http://test.image")
    }
}