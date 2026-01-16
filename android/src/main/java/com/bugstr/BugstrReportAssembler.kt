/**
 * Copyright (c) 2025 Vitor Pamplona
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
 * Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 * AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package com.bugstr

import android.os.Build

/**
 * Builds a markdown friendly crash report that includes device metadata and stack traces.
 */
class BugstrReportAssembler(
    private val appName: String? = null,
    private val appVersionName: String = "0.0.0",
    private val buildVariant: String = "RELEASE",
    private val maxStackCharacters: Int = 200_000,
    private val maxAttachmentCharacters: Int = 50_000,
) {
    /**
     * Builds a markdown friendly crash report that includes device metadata and stack traces.
     */
    fun buildReport(
        e: Throwable,
        attachments: Map<String, String> = emptyMap(),
    ): String {
        val builder =
            buildString {
                appendLine(appName ?: "Bugstr Report")
                append(e.javaClass.simpleName)
                append(": ")
                appendLine("$appVersionName-${buildVariant.uppercase()}")
                appendLine()

                appendLine("| Prop | Value |")
                appendLine("|------|-------|")
                append("| Manuf |")
                append(Build.MANUFACTURER)
                appendLine(" |")
                append("| Model |")
                append(Build.MODEL)
                appendLine(" |")
                append("| Prod |")
                append(Build.PRODUCT)
                appendLine(" |")

                append("| Android |")
                append(Build.VERSION.RELEASE)
                appendLine(" |")
                append("| SDK Int |")
                append(Build.VERSION.SDK_INT.toString())
                appendLine(" |")

                append("| Brand |")
                append(Build.BRAND)
                appendLine(" |")
                append("| Hardware |")
                append(Build.HARDWARE)
                appendLine(" |")

                append("| Device | ")
                append(Build.DEVICE)
                appendLine(" |")
                appendLine()

                if (attachments.isNotEmpty()) {
                    appendLine("Attachments")
                    attachments.forEach { (key, value) ->
                        val safeKey = key.ifBlank { "attachment" }
                        appendLine("### $safeKey")
                        appendLine("```")
                        appendLine(value.take(maxAttachmentCharacters))
                        appendLine("```")
                    }
                    appendLine()
                }

                appendLine("```")
                appendThrowable(e, indent = 0, visited = mutableSetOf())
                appendLine("```")
            }

        return if (builder.length <= maxStackCharacters) {
            builder
        } else {
            builder.substring(0, maxStackCharacters) + "\n\n... Bugstr truncated the stack trace ..."
        }
    }

    private fun StringBuilder.appendThrowable(
        throwable: Throwable,
        indent: Int,
        visited: MutableSet<Throwable>,
    ) {
        if (!visited.add(throwable)) {
            append("    ".repeat(indent))
            appendLine("[cycle detected: ${throwable::class.java.simpleName}]")
            return
        }

        append("    ".repeat(indent))
        appendLine(throwable.toString())
        throwable.stackTrace.forEach {
            append("    ".repeat(indent + 1))
            appendLine(it.toString())
        }
        throwable.cause?.let { cause ->
            append("    ".repeat(indent))
            appendLine("Caused by:")
            appendThrowable(cause, indent + 1, visited)
        }
    }
}
