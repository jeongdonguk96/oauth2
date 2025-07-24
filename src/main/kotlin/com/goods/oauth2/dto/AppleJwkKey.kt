package com.goods.oauth2.dto

data class AppleJwkKey(
    val kid: String,
    val alg: String,
    val kty: String,
    val use: String,
    val n: String,
    val e: String
)

data class AppleJwkKeys(val keys: List<AppleJwkKey>)