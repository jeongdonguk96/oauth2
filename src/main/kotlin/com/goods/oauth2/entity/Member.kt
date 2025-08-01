package com.goods.oauth2.entity

import com.goods.oauth2.enums.Provider
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id

@Entity
class Member(
    val email: String,
    @Enumerated(EnumType.STRING)
    val provider: Provider,

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    val id: Long? = 0L
) {
    override fun toString(): String {
        return "Member(id=$id, email=$email)"
    }
}