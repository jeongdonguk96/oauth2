package com.goods.oauth2.controller

import com.goods.oauth2.dto.OAuth2Request
import com.goods.oauth2.extention.logger
import com.goods.oauth2.service.AuthService
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/auth")
class OAuth2Controller(
    private val authService: AuthService,
) {

    private val log = logger

    @PostMapping("/{provider}/callback")
    suspend fun handleOAuth2Callback(
        @PathVariable(value = "provider") provider: String,
        @RequestBody oAuth2Request: OAuth2Request
    ): ResponseEntity<String> {
        log.info("==================== API START ====================")
        log.info("provider: $provider, code: ${oAuth2Request.code}")

        val userInfo = authService.handleOAuth2Login(provider, oAuth2Request.code)
        log.info("==================== API END ====================")
        return ResponseEntity.ok(userInfo)
    }

}

