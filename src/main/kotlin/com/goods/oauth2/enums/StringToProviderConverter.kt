package com.goods.oauth2.enums

import org.springframework.core.convert.converter.Converter
import org.springframework.stereotype.Component

@Component
class StringToProviderConverter : Converter<String, Provider> {
    override fun convert(
        source: String
    ): Provider {
        return Provider.entries.find { it.name.equals(source, ignoreCase = true) }
            ?: throw IllegalArgumentException("Unknown provider: $source")
    }
}