# Bugstr

Bugstr packages the crash reporting flow that [Amethyst](https://github.com/vitorpamplona/amethyst) uses to prompt users to share stack traces with developers over expiring ([NIP-17](https://github.com/nostr-protocol/nips/blob/master/17.md)) direct messages. Bugstr includes [Quartz](https://github.com/vitorpamplona/quartz), or Android SDK via Amethyst. It is designed to be re-used by other Nostr apps—or any Android app that wants an opt-in crash reporter that keeps the user in control of what is sent.

<img width="256" height="256" alt="image" src="https://github.com/user-attachments/assets/1c3c17dc-6a6d-4881-9ac7-32217bd4e1ad" />



## Components

Bugstr ships three small building blocks:

1. `BugstrCrashReportCache` stores crash stack traces on disk. It defaults to one slot; set `maxReports` or a custom `slotKey` for multi-slot rotation. All disk I/O is suspend and runs on `Dispatchers.IO`.
2. `BugstrCrashHandler` installs an `UncaughtExceptionHandler`, accepts an attachments provider, and blocks the crashing thread with a bounded timeout while flushing to disk.
3. `BugstrCrashPrompt` is a Jetpack Compose dialog that surfaces all cached reports (newest first) and lets the user send, keep, or dismiss them.
4. `BugstrAnrWatcher` (optional) can write a synthetic report when the main thread stalls.

## Installing the crash handler

```kotlin
class MyApp : Application() {
    private val bugstrCache by lazy { BugstrCrashReportCache(this, maxReports = 3) }
    private val bugstrHandler by lazy {
        BugstrCrashHandler(
            cache = bugstrCache,
            assembler = BugstrReportAssembler(
                appName = "My App",
                appVersionName = BuildConfig.VERSION_NAME,
                buildVariant = BuildConfig.FLAVOR.ifBlank { "release" },
            ),
            attachmentsProvider = { mapOf("recent logs" to fetchRecentLogs()) },
            writeTimeoutMs = 1_000,
        )
    }

    override fun onCreate() {
        super.onCreate()
        bugstrHandler.installAsDefault()
    }
}
```

This mirrors the way Amethyst keeps the default handler and only writes non-OOM crashes to disk.

### Optional ANR watcher

If you also want ANR coverage, wire up `BugstrAnrWatcher`:

```kotlin
private val anrWatcher by lazy {
    BugstrAnrWatcher(
        cache = bugstrCache,
        assembler = BugstrReportAssembler(
            appName = "My App",
            appVersionName = BuildConfig.VERSION_NAME,
            buildVariant = BuildConfig.FLAVOR.ifBlank { "release" },
        )
    )
}

override fun onCreate() {
    super.onCreate()
    bugstrHandler.installAsDefault()
    anrWatcher.start()
}
```

## Showing the prompt

In any Compose screen you can drop `BugstrCrashPrompt` and wire up the `onSendReport` callback to your own navigation or DM composer. Bugstr will load and delete the cached crash reports on the first composition.

```kotlin
@Composable
fun CrashReportEntryPoint(
    accountViewModel: AccountViewModel,
    nav: INav,
) {
    BugstrCrashPrompt(
        cache = Amethyst.instance.crashReportCache,
        developerName = "Amethyst",
        onSendReport = { stack ->
            nav.nav {
                routeToMessage(
                    user = LocalCache.getOrCreateUser(AMETHYST_DEV_PUBKEY),
                    draftMessage = stack,
                    accountViewModel = accountViewModel,
                    expiresDays = 30, // <- enables expiring NIP-17 DMs
                )
            }
        },
    )
}
```

In this example the `expiresDays` flag is what turns the DM composer into a NIP-17 ephemeral message, so the crash report vanishes for everyone after 30 days.

### Customizing strings

`BugstrCrashPrompt` exposes optional parameters (`titleText`, `descriptionText`, `sendButtonText`, `dismissButtonText`, `retryButtonText`, `loadingText`) so you can plug in your own localized strings or keep Bugstr’s defaults. The default copy now reminds users that stack traces might contain personal data.

## Notes

 - Bugstr avoids reading or sending anything automatically. Users stay in control and can inspect/edit the crash report before sharing.
- You can store multiple crashes by setting `maxReports` or providing a slot key when writing. The prompt iterates through everything it finds.
- `BugstrCrashPrompt` offers a “Keep for later” button that rewrites the remaining reports to disk instead of discarding them.
- `BugstrReportAssembler` recurses through the entire `Throwable` cause chain, trims overly large traces (default 200k characters), and intentionally omits `Build.HOST`/`Build.USER` to keep ROM build metadata out of the report. Tune `maxStackCharacters` if needed.
- Attachments are supported via the crash handler’s `attachmentsProvider`. They render under their own headings and are truncated for safety.
