package com.goods.oauth2.dto

data class KakaoTokenResponse(
    override val access_token: String,
    override val token_type: String,
    override val refresh_token: String?,
    override val expires_in: Int?,
    val scope: String?,
    val refresh_token_expires_in: Int?
) : OAuthTokenResponse

