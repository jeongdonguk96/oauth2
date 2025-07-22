package com.goods.oauth2.controller

import com.goods.oauth2.dto.OAuthUserInfo
import com.goods.oauth2.resolver.OAuth2ServiceResolver
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/auth")
class OAuth2Controller(
    private val oAuth2ServiceResolver: OAuth2ServiceResolver
) {

    @PostMapping("/{provider}/callback")
    suspend fun handleOAuth2Callback(
        @PathVariable provider: String,
        @RequestParam code: String
    ): ResponseEntity<OAuthUserInfo> {
        // TODO: 별도의 인증 서비스 클래스 하나 더 추가하여 거기에서 여러 service를 주입받아 모든 로직 처리
        // TODO: 받아온 정보로 (최초일 경우 회원가입 처리 후) 액세스/리프레시 토큰 생성 후 응답 처리
        val service = oAuth2ServiceResolver.resolve(provider)

        val userInfo = service.getUserInfoByCode(code)
        return ResponseEntity.ok(userInfo)
    }

}

