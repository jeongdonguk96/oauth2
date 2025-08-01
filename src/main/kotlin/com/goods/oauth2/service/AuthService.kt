package com.goods.oauth2.service

import com.goods.oauth2.enums.Provider
import com.goods.oauth2.extention.logger
import com.goods.oauth2.jwt.JwtTokenService
import com.goods.oauth2.resolver.OAuth2ServiceResolver
import org.springframework.stereotype.Service

@Service
class AuthService(
    private val oAuth2ServiceResolver: OAuth2ServiceResolver,
    private val memberService: MemberService,
    private val jwtTokenService: JwtTokenService
) {
    private val log = logger

    suspend fun handleOAuth2Login(
        provider: Provider,
        code: String
    ): String {
        val oAuth2Service = oAuth2ServiceResolver.resolve(provider)
        log.info("oAuth2Service: $oAuth2Service")

        val oAuth2UserInfo = oAuth2Service.getUserInfoByAuthorizationCode(code)
        log.info("oAuth2UserInfo: $oAuth2UserInfo")

        val member = memberService.findOrRegister(oAuth2UserInfo)
        log.info("member: $member")

        val accessToken = jwtTokenService.generateAccessToken(member)
        log.info("accessToken: $accessToken")

        val refreshToken = jwtTokenService.generateRefreshToken(member)
        log.info("refreshToken: $refreshToken")

        // TODO: 알맞은 응답 객체를 반환한다.
        return accessToken
    }

}