package com.goods.oauth2.resolver

import com.goods.oauth2.enums.Provider
import com.goods.oauth2.service.AppleService
import com.goods.oauth2.service.KakaoService
import com.goods.oauth2.service.OAuth2Service
import org.springframework.stereotype.Component

@Component
class OAuth2ServiceResolver(
    appleService: AppleService,
    kakaoService: KakaoService,
) {

    private val serviceMap: Map<Provider, OAuth2Service> = mapOf(
        Provider.APPLE to appleService,
        Provider.KAKAO to kakaoService,
    )


    fun resolve(
        provider: Provider
    ): OAuth2Service {
        return serviceMap[provider]
            ?: throw IllegalArgumentException("Unsupported provider: $provider")
    }

}