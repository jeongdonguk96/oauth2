package com.goods.oauth2.entity

import jakarta.persistence.Entity
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id

@Entity
class Member(
    val email: String,

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    val id: Long? = 0L
) {
    override fun toString(): String {
        return "Member(id=$id, email=$email)"
    }
}