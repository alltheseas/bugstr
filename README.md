# Bugstr

Bugstr packages the crash reporting flow that [Amethyst](https://github.com/vitorpamplona/amethyst) uses to prompt users to share stack traces with developers over expiring ([NIP-17](https://github.com/nostr-protocol/nips/blob/master/17.md)) direct messages. It is designed to be re-used by other Nostr apps—or any Android app that wants an opt-in crash reporter that keeps the user in control of what is sent.

<img width=256" height="256" alt="bugstr" src="https://github.com/user-attachments/assets/142f5f0e-5c12-40a7-b8fa-88c26b859809" />



## Components

Bugstr ships three small building blocks:

1. `BugstrCrashReportCache` stores the most recent crash stack trace on disk (one report at a time), exposes suspend APIs that run on `Dispatchers.IO`, and lets you customize the backing filename if you want multiple slots.
2. `BugstrCrashHandler` installs an `UncaughtExceptionHandler` that serializes crashes via `BugstrReportAssembler` and blocks the crashing thread until the report is flushed.
3. `BugstrCrashPrompt` is a Jetpack Compose dialog that gives the user the option to send the cached report anywhere you like.

## Installing the crash handler

```kotlin
class MyApp : Application() {
    private val bugstrCache by lazy { BugstrCrashReportCache(this) }
    private val bugstrHandler by lazy {
        BugstrCrashHandler(
            cache = bugstrCache,
            assembler = BugstrReportAssembler(
                appName = "My App",
                appVersionName = BuildConfig.VERSION_NAME,
                buildVariant = BuildConfig.FLAVOR.ifBlank { "release" },
            ),
        )
    }

    override fun onCreate() {
        super.onCreate()
        bugstrHandler.installAsDefault()
    }
}
```

This mirrors the way Amethyst keeps the default handler and only writes non-OOM crashes to disk.

## Showing the prompt

In any Compose screen you can drop `BugstrCrashPrompt` and wire up the `onSendReport` callback to your own navigation or DM composer. Bugstr will load and delete the cached crash report on the first composition.

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
- Only a single crash report is cached at a time. If you need durability for multiple crashes, provide your own queue by swapping the `fileName` argument in `BugstrCrashReportCache` per slot.
- `BugstrCrashPrompt` offers a “Keep for later” button that rewrites the report to disk instead of discarding it.
- `BugstrReportAssembler` recurses through the entire `Throwable` cause chain, trims overly large traces (default 200k characters), and intentionally omits `Build.HOST`/`Build.USER` to keep ROM build metadata out of the report. Tune `maxStackCharacters` if needed.
