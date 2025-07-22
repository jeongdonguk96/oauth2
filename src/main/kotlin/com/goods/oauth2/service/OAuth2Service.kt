package com.goods.oauth2.service

import com.goods.oauth2.dto.OAuthUserInfo

interface OAuth2Service {
    suspend fun getUserInfoByAuthorizationCode(code: String): OAuthUserInfo
}
