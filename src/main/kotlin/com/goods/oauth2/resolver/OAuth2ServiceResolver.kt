package com.goods.oauth2.resolver

import com.goods.oauth2.service.OAuth2Service
import org.springframework.stereotype.Component

@Component
class OAuth2ServiceResolver(
    private val services: Map<String, OAuth2Service>
) {
    private val providerToBeanName: Map<String, String> = mapOf(
        "apple" to "appleService",
        "kakao" to "kakaoService",
        "google" to "googleService"
    )

    fun resolve(provider: String): OAuth2Service {
        val beanName = providerToBeanName[provider]
            ?: throw IllegalArgumentException("Unsupported provider: $provider")

        return services[beanName]
            ?: throw IllegalStateException("No service found for bean: $beanName")
    }
}