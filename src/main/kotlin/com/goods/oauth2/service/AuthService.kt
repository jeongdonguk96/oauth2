package com.goods.oauth2.service

import com.goods.oauth2.jwt.JwtTokenProvider
import com.goods.oauth2.resolver.OAuth2ServiceResolver
import org.springframework.stereotype.Service

@Service
class AuthService(
    private val oAuth2ServiceResolver: OAuth2ServiceResolver,
    private val memberService: MemberService,
    private val jwtTokenProvider: JwtTokenProvider
) {

    suspend fun handleOAuth2Login(
        provider: String,
        code: String
    ): String {
        val oAuth2Service = oAuth2ServiceResolver.resolve(provider)
        val oAuth2UserInfo = oAuth2Service.getUserInfoByAuthorizationCode(code)
        val member = memberService.findOrRegister(oAuth2UserInfo)

        val accessToken = jwtTokenProvider.generateAccessToken(member)
        val refreshToken = jwtTokenProvider.generateRefreshToken(member)

        // TODO: 알맞은 응답 객체를 반환한다.
        return accessToken
    }
}