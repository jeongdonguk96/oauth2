package com.goods.oauth2.service

import com.goods.oauth2.dto.OAuthUserInfo
import com.goods.oauth2.entity.Member
import com.goods.oauth2.repository.MemberRepository
import org.springframework.stereotype.Service

@Service
class MemberService(
    private val memberRepository: MemberRepository
) {

    fun findOrRegister(
        userInfo: OAuthUserInfo
    ): Member {
        return memberRepository.findByEmail(userInfo.email)
            ?: memberRepository.save(
                Member(
                    userInfo.email,
                    userInfo.provider,
                )
            )
    }

}