package com.goods.oauth2.dto

import com.goods.oauth2.enums.Provider

interface OAuthUserInfo {
    val id: String
    val email: String
    val provider: Provider
}
