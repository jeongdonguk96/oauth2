package com.goods.oauth2.extention

import org.slf4j.Logger
import org.slf4j.LoggerFactory

val <T : Any> T.logger: Logger
    get() = LoggerFactory.getLogger(this::class.java)