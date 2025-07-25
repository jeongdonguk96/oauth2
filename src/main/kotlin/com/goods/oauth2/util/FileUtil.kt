package com.goods.oauth2.util

import java.nio.file.Files
import java.nio.file.Paths

class FileUtil {
    companion object {

        fun readFile(
            filePath: String
        ): String {
            val path = Paths.get(filePath)
            return Files.readString(path)
        }

    }
}