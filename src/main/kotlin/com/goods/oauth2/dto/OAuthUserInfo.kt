package com.goods.oauth2.dto

interface OAuthUserInfo {
    val id: String
    val email: String?
    val nickname: String?
    val profile_image: String?
}
