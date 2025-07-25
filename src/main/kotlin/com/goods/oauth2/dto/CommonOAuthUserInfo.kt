package com.goods.oauth2.dto

data class CommonOAuthUserInfo(
    override val id: String,
    override val email: String,
) : OAuthUserInfo
