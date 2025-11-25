/**
 * Lightweight ANR watcher that writes a synthetic Bugstr report when the main thread stalls.
 */
package com.bugstr

import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.util.Log
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull

class BugstrAnrWatcher(
    private val cache: BugstrCrashReportCache,
    private val assembler: BugstrReportAssembler,
    private val timeoutMs: Long = 5_000,
    private val pollIntervalMs: Long = 1_000,
    private val writeTimeoutMs: Long = 1_000,
    private val shouldStore: () -> Boolean = { true },
) {
    private val running = AtomicBoolean(false)
    private val beat = AtomicLong(SystemClock.uptimeMillis())
    private val handler = Handler(Looper.getMainLooper())
    private val executor = Executors.newSingleThreadExecutor()

    private val ticker =
        object : Runnable {
            override fun run() {
                beat.set(SystemClock.uptimeMillis())
                if (running.get()) handler.postDelayed(this, pollIntervalMs)
            }
        }

    fun start() {
        if (!running.compareAndSet(false, true)) return
        beat.set(SystemClock.uptimeMillis())
        handler.post(ticker)
        executor.execute { monitor() }
    }

    fun stop() {
        if (!running.compareAndSet(true, false)) return
        handler.removeCallbacks(ticker)
        executor.shutdownNow()
    }

    private fun monitor() {
        while (running.get()) {
            try {
                Thread.sleep(pollIntervalMs)
            } catch (_: InterruptedException) {
                return
            }
            val idleFor = SystemClock.uptimeMillis() - beat.get()
            if (idleFor < timeoutMs) continue
            if (!shouldStore()) {
                beat.set(SystemClock.uptimeMillis())
                continue
            }
            writeAnr(idleFor)
            beat.set(SystemClock.uptimeMillis())
        }
    }

    private fun writeAnr(idleFor: Long) {
        val throwable = ApplicationNotRespondingException("Main thread stalled for ${idleFor}ms")
        val report = assembler.buildReport(throwable)
        val result =
            runBlocking {
                withTimeoutOrNull(writeTimeoutMs) {
                    cache.writeReport(report, slotKey = "anr")
                } ?: runCatching { error("Bugstr ANR write timed out after ${writeTimeoutMs}ms") }
            }

        result?.onFailure { Log.w("BugstrAnrWatcher", "Failed to persist ANR report", it) }
    }
}

private class ApplicationNotRespondingException(message: String) : RuntimeException(message)
