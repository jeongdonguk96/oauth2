package com.goods.oauth2.dto

data class OAuth2Response(
    val memberEmail: String,
    val accessToken: String,
    val refreshToken: String,
)