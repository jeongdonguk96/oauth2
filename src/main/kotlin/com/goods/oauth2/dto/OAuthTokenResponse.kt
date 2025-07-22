package com.goods.oauth2.dto

interface OAuthTokenResponse {
    val access_token: String
    val token_type: String
    val refresh_token: String?
    val expires_in: Int?
}