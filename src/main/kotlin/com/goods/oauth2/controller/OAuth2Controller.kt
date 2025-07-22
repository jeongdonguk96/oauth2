package com.goods.oauth2.controller

import com.goods.oauth2.dto.OAuthUserInfo
import com.goods.oauth2.service.AuthService
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/auth")
class OAuth2Controller(
    private val authService: AuthService
) {

    @PostMapping("/{provider}/callback")
    suspend fun handleOAuth2Callback(
        @PathVariable provider: String,
        @RequestParam code: String
    ): ResponseEntity<String> {
        val userInfo = authService.handleOAuth2Login(provider, code)
        return ResponseEntity.ok(userInfo)
    }

}

