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
) {
    fun buildReport(e: Throwable): String =
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
            append("| Host | ")
            append(Build.HOST)
            appendLine(" |")
            append("| User | ")
            append(Build.USER)
            appendLine(" |")
            appendLine()

            appendLine("```")
            appendLine(e.toString())
            e.stackTrace.forEach {
                append("    ")
                appendLine(it.toString())
            }
            val cause = e.cause
            if (cause != null) {
                appendLine("\n\nCause:")
                append("    ")
                appendLine(cause.toString())
                cause.stackTrace.forEach {
                    append("        ")
                    appendLine(it.toString())
                }
            }
            appendLine("```")
        }
}
