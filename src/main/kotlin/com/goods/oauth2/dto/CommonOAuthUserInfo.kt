package com.goods.oauth2.dto

import com.goods.oauth2.enums.Provider

data class CommonOAuthUserInfo(
    override val id: String,
    override val email: String,
    override val provider: Provider,
) : OAuthUserInfo
