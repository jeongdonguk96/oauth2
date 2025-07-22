package com.goods.oauth2.dto

data class CommonOAuthUserInfo(
    override val id: String,
    override val email: String?,
    override val nickname: String?,
    override val profile_image: String?
) : OAuthUserInfo
