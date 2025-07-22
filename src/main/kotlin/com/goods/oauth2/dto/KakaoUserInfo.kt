package com.goods.oauth2.dto

data class KakaoUserInfo(
    val id: Long,
    val properties: Properties,
    val kakao_account: KakaoAccount
) {
    data class Properties(
        val nickname: String,
        val profile_image: String?,
        val thumbnail_image: String?
    )

    data class KakaoAccount(
        val email: String?,
        val email_needs_agreement: Boolean?,
        val is_email_valid: Boolean?,
        val is_email_verified: Boolean?,
        val profile: Profile?,
        val profile_nickname_needs_agreement: Boolean?,
        val profile_image_needs_agreement: Boolean?
    ) {
        data class Profile(
            val nickname: String,
            val thumbnail_image_url: String?,
            val profile_image_url: String?,
            val is_default_image: Boolean
        )
    }
}
