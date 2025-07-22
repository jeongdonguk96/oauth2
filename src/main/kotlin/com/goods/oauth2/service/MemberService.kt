package com.goods.oauth2.service

import com.goods.oauth2.dto.OAuthUserInfo
import com.goods.oauth2.entity.Member
import org.springframework.stereotype.Service

@Service
class MemberService {

    fun findOrRegister(
        userInfo: OAuthUserInfo
    ): Member {
        // TODO: 회원가입이 안되어 있으면 회원가입 후 사용자 정보를, 이미 가입되어 있으면 가입된 정보를 반환한다.
        return Member()
    }
}