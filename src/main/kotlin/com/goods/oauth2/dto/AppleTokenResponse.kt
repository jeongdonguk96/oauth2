package com.goods.oauth2.dto

data class AppleTokenResponse(
    override val access_token: String,
    override val token_type: String,
    override val expires_in: Int,
    override val refresh_token: String,
    val id_token: String,
) : OAuthTokenResponse

