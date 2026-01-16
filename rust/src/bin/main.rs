//! Bugstr CLI - Privacy-focused crash report receiver
//!
//! Subscribes to Nostr relays and decrypts NIP-17 gift-wrapped crash reports.
//! Optionally serves a web dashboard for viewing and analyzing crashes.

use bugstr::{
    decompress_payload, parse_crash_content, AppState, CrashReport, CrashStorage, create_router,
    MappingStore, Platform, Symbolicator, SymbolicationContext,
    is_crash_report_kind, is_chunked_kind, DirectPayload, ManifestPayload, ChunkPayload,
    reassemble_payload, KIND_CHUNK,
};
use tokio::sync::Mutex;
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use colored::Colorize;
use futures_util::{SinkExt, StreamExt};
use nostr::nips::nip44;
use nostr::prelude::*;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_tungstenite::{connect_async, tungstenite::Message};

const DEFAULT_RELAYS: &[&str] = &["wss://relay.damus.io", "wss://nos.lol"];
const DEFAULT_DB_PATH: &str = "bugstr.db";

#[derive(Parser)]
#[command(name = "bugstr")]
#[command(about = "Zero-infrastructure crash reporting — no server to run, no SaaS to pay for")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Listen for incoming crash reports (terminal output only)
    Listen {
        /// Your private key (hex or nsec)
        #[arg(short, long, env = "BUGSTR_PRIVKEY")]
        privkey: String,

        /// Relay URLs to connect to
        #[arg(short, long, default_values_t = DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect::<Vec<_>>())]
        relays: Vec<String>,

        /// Output format: pretty, json, or raw
        #[arg(short, long, default_value = "pretty")]
        format: OutputFormat,
    },

    /// Run the web dashboard with crash collection
    Serve {
        /// Your private key (hex or nsec)
        #[arg(short, long, env = "BUGSTR_PRIVKEY")]
        privkey: String,

        /// Relay URLs to connect to
        #[arg(short, long, default_values_t = DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect::<Vec<_>>())]
        relays: Vec<String>,

        /// Web server port
        #[arg(long, default_value = "3000")]
        port: u16,

        /// Database file path
        #[arg(long, default_value = DEFAULT_DB_PATH)]
        db: PathBuf,

        /// Directory containing mapping files for symbolication
        #[arg(long)]
        mappings: Option<PathBuf>,
    },

    /// Show your receiver pubkey (npub)
    Pubkey {
        /// Your private key (hex or nsec)
        #[arg(short, long, env = "BUGSTR_PRIVKEY")]
        privkey: String,
    },

    /// Symbolicate a stack trace using mapping files
    Symbolicate {
        /// Platform: android, electron, flutter, rust, go, python, react-native
        #[arg(short = 'P', long)]
        platform: String,

        /// Input file containing stack trace (or - for stdin)
        #[arg(short, long, default_value = "-")]
        input: String,

        /// Directory containing mapping files
        #[arg(short, long, default_value = "mappings")]
        mappings: PathBuf,

        /// Application ID (package name, bundle id, etc.)
        #[arg(short, long)]
        app_id: Option<String>,

        /// Application version
        #[arg(short, long)]
        version: Option<String>,

        /// Output format: pretty or json
        #[arg(short, long, default_value = "pretty")]
        format: SymbolicateFormat,
    },
}

#[derive(Clone, Debug, clap::ValueEnum)]
enum OutputFormat {
    Pretty,
    Json,
    Raw,
}

#[derive(Clone, Debug, clap::ValueEnum)]
enum SymbolicateFormat {
    Pretty,
    Json,
}

/// A received crash report ready for storage.
struct ReceivedCrash {
    event_id: String,
    sender_pubkey: String,
    created_at: i64,
    content: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Listen {
            privkey,
            relays,
            format,
        } => {
            listen(&privkey, &relays, format).await?;
        }
        Commands::Serve {
            privkey,
            relays,
            port,
            db,
            mappings,
        } => {
            serve(&privkey, &relays, port, db, mappings).await?;
        }
        Commands::Pubkey { privkey } => {
            show_pubkey(&privkey)?;
        }
        Commands::Symbolicate {
            platform,
            input,
            mappings,
            app_id,
            version,
            format,
        } => {
            symbolicate_stack(&platform, &input, &mappings, app_id, version, format)?;
        }
    }

    Ok(())
}

fn parse_privkey(input: &str) -> Result<SecretKey, Box<dyn std::error::Error>> {
    if input.starts_with("nsec") {
        let secret = SecretKey::from_bech32(input)?;
        Ok(secret)
    } else {
        let secret = SecretKey::from_hex(input)?;
        Ok(secret)
    }
}

fn show_pubkey(privkey: &str) -> Result<(), Box<dyn std::error::Error>> {
    let secret = parse_privkey(privkey)?;
    let keys = Keys::new(secret);
    let pubkey = keys.public_key();

    println!("Receiver pubkey:");
    println!("  npub: {}", pubkey.to_bech32()?);
    println!("  hex:  {}", pubkey.to_hex());
    println!();
    println!("Add this pubkey to your app's bugstr configuration.");

    Ok(())
}

/// Symbolicate a stack trace using mapping files.
///
/// Reads a stack trace from a file or stdin, symbolicates it using the appropriate
/// platform-specific symbolicator, and outputs the result in the specified format.
///
/// # Parameters
///
/// * `platform_str` - Platform identifier string. Supported values:
///   - `"android"` - Android (ProGuard/R8 mapping files)
///   - `"electron"` or `"javascript"` or `"js"` - JavaScript/Electron (source maps)
///   - `"flutter"` or `"dart"` - Flutter/Dart (symbol files)
///   - `"rust"` - Rust (backtrace parsing)
///   - `"go"` or `"golang"` - Go (goroutine stacks)
///   - `"python"` - Python (traceback parsing)
///   - `"react-native"` or `"reactnative"` or `"rn"` - React Native (Hermes + source maps)
///   Unknown platforms trigger a warning but still attempt symbolication.
///
/// * `input` - Path to file containing the stack trace, or `"-"` to read from stdin.
///   The file is read entirely into memory as UTF-8 text.
///
/// * `mappings_dir` - Borrowed reference to the directory containing mapping files.
///   Expected structure: `<root>/<platform>/<app_id>/<version>/<mapping_file>`.
///   See [`MappingStore`] for detailed directory layout.
///
/// * `app_id` - Optional application identifier (e.g., package name, bundle ID).
///   Used to locate the correct mapping file. If `None`, defaults to `"unknown"`.
///
/// * `version` - Optional application version string (e.g., `"1.0.0"`).
///   Used to locate the correct mapping file. If `None`, defaults to `"unknown"`.
///   Falls back to newest available version if exact match not found.
///
/// * `format` - Output format selection. See [`SymbolicateFormat`]:
///   - `Pretty` - Human-readable colored output with frame numbers and source locations
///   - `Json` - Machine-readable JSON with full frame details
///
/// # Returns
///
/// * `Ok(())` - Symbolication completed (results printed to stdout)
/// * `Err(_)` - One of the following errors occurred:
///   - IO error reading input file or stdin
///   - [`SymbolicationError::MappingNotFound`] - No mapping file for platform/app/version
///   - [`SymbolicationError::ParseError`] - Failed to parse mapping file
///   - [`SymbolicationError::IoError`] - Failed to read mapping file
///   - [`SymbolicationError::UnsupportedPlatform`] - Platform::Unknown was provided
///   - JSON serialization error (for JSON format output)
///
/// # Output Format
///
/// **Pretty format** (default):
/// ```text
/// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
/// Symbolication Results 5 frames symbolicated (83.3%)
/// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
///
///   #0 com.example.MyClass.myMethod (MyClass.java:42)
///   #1 com.example.OtherClass.call (OtherClass.java:15)
/// ```
///
/// **JSON format**:
/// ```json
/// {
///   "symbolicated_count": 5,
///   "total_count": 6,
///   "percentage": 83.33,
///   "frames": [
///     {
///       "raw": "at a.b.c(Unknown:1)",
///       "function": "com.example.MyClass.myMethod",
///       "file": "MyClass.java",
///       "line": 42,
///       "column": null,
///       "symbolicated": true
///     }
///   ]
/// }
/// ```
///
/// # Side Effects
///
/// - Reads from filesystem (input file and mapping files)
/// - Reads from stdin if `input` is `"-"`
/// - Writes to stdout (symbolication results)
/// - Writes to stderr (warnings for unknown platform, missing mappings)
/// - Creates mapping directory if it doesn't exist (via [`MappingStore::scan`])
///
/// # Panics
///
/// This function does not panic under normal operation. All errors are returned
/// as `Result::Err`.
///
/// # Example
///
/// ```ignore
/// // Symbolicate an Android stack trace from a file
/// symbolicate_stack(
///     "android",
///     "crash.txt",
///     &PathBuf::from("./mappings"),
///     Some("com.myapp".to_string()),
///     Some("1.0.0".to_string()),
///     SymbolicateFormat::Pretty,
/// )?;
///
/// // Symbolicate from stdin with JSON output
/// symbolicate_stack(
///     "python",
///     "-",
///     &PathBuf::from("./mappings"),
///     None,
///     None,
///     SymbolicateFormat::Json,
/// )?;
/// ```
fn symbolicate_stack(
    platform_str: &str,
    input: &str,
    mappings_dir: &PathBuf,
    app_id: Option<String>,
    version: Option<String>,
    format: SymbolicateFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    // Read stack trace
    let stack_trace = if input == "-" {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        buf
    } else {
        std::fs::read_to_string(input)?
    };

    // Parse platform
    let platform = Platform::from_str(platform_str);
    if matches!(platform, Platform::Unknown(_)) {
        eprintln!(
            "{} Unknown platform '{}'. Supported: android, electron, flutter, rust, go, python, react-native",
            "warning".yellow(),
            platform_str
        );
    }

    // Create symbolicator with scanned mapping store
    let mut store = MappingStore::new(mappings_dir);
    let count = store.scan()?;
    if count == 0 {
        eprintln!(
            "{} No mapping files found in {}",
            "warning".yellow(),
            mappings_dir.display()
        );
    }
    let symbolicator = Symbolicator::new(store);

    // Create context
    let context = SymbolicationContext {
        platform,
        app_id,
        version,
        build_id: None,
    };

    // Symbolicate
    let result = symbolicator.symbolicate(&stack_trace, &context)?;

    // Output
    match format {
        SymbolicateFormat::Pretty => {
            println!("{}", "━".repeat(60).dimmed());
            println!(
                "{} {} frames symbolicated ({:.1}%)",
                "Symbolication Results".green().bold(),
                result.symbolicated_count,
                result.percentage()
            );
            println!("{}", "━".repeat(60).dimmed());
            println!();

            for (i, frame) in result.frames.iter().enumerate() {
                if frame.symbolicated {
                    let location = match (&frame.file, frame.line) {
                        (Some(f), Some(l)) => format!(" ({}:{})", f.dimmed(), l),
                        (Some(f), None) => format!(" ({})", f.dimmed()),
                        _ => String::new(),
                    };
                    println!(
                        "  {} {}{}",
                        format!("#{}", i).cyan(),
                        frame.function.as_deref().unwrap_or("<unknown>").green(),
                        location
                    );
                } else {
                    println!("  {} {}", format!("#{}", i).cyan(), frame.raw.dimmed());
                }
            }
            println!();
        }
        SymbolicateFormat::Json => {
            let output = serde_json::json!({
                "symbolicated_count": result.symbolicated_count,
                "total_count": result.total_count,
                "percentage": result.percentage(),
                "frames": result.frames.iter().map(|f| {
                    serde_json::json!({
                        "raw": f.raw,
                        "function": f.function,
                        "file": f.file,
                        "line": f.line,
                        "column": f.column,
                        "symbolicated": f.symbolicated,
                    })
                }).collect::<Vec<_>>()
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
    }

    Ok(())
}

/// Run web dashboard with crash collection.
async fn serve(
    privkey: &str,
    relays: &[String],
    port: u16,
    db_path: PathBuf,
    mappings_dir: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let secret = parse_privkey(privkey)?;
    let keys = Keys::new(secret);
    let pubkey = keys.public_key();

    // Open/create database
    let storage = CrashStorage::open(&db_path)?;

    // Create symbolicator if mappings directory is provided
    let symbolicator = if let Some(ref dir) = mappings_dir {
        let mut store = MappingStore::new(dir);
        match store.scan() {
            Ok(count) => {
                if count == 0 {
                    eprintln!(
                        "{} No mapping files found in {}",
                        "warning".yellow(),
                        dir.display()
                    );
                } else {
                    println!("  {} {} mapping files loaded", "Loaded:".cyan(), count);
                }
                Some(Arc::new(Symbolicator::new(store)))
            }
            Err(e) => {
                eprintln!("{} Failed to scan mappings: {}", "error".red(), e);
                None
            }
        }
    } else {
        None
    };

    let state = Arc::new(AppState {
        storage: Mutex::new(storage),
        symbolicator,
    });

    println!("{}", "━".repeat(60).dimmed());
    println!(
        "{} Bugstr Receiver",
        "▸".green().bold()
    );
    println!("{}", "━".repeat(60).dimmed());
    println!("  {} {}", "Pubkey:".cyan(), pubkey.to_bech32()?);
    println!("  {} {}", "Database:".cyan(), db_path.display());
    println!("  {} http://localhost:{}", "Dashboard:".cyan(), port);
    println!("  {} {}", "Relays:".cyan(), relays.join(", "));
    if let Some(ref dir) = mappings_dir {
        println!("  {} {}", "Mappings:".cyan(), dir.display());
    }
    println!("{}", "━".repeat(60).dimmed());
    println!();

    // Channel for received crashes
    let (tx, mut rx) = mpsc::channel::<ReceivedCrash>(100);

    // Clone relay list for chunk fetching (need all relays available to each listener)
    let all_relays: Vec<String> = relays.iter().cloned().collect();

    // Spawn relay listeners
    for relay_url in relays {
        let relay = relay_url.clone();
        let keys = keys.clone();
        let tx = tx.clone();
        let relay_urls = all_relays.clone();

        tokio::spawn(async move {
            loop {
                match subscribe_relay_with_storage(&relay, &keys, &tx, &relay_urls).await {
                    Ok(()) => {}
                    Err(e) => {
                        let err_msg = e.to_string();
                        eprintln!("{} Relay {} error: {} - reconnecting...", "error".red(), relay, err_msg);
                    }
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        });
    }

    // Spawn crash storage worker
    let storage_state = state.clone();
    tokio::spawn(async move {
        while let Some(crash) = rx.recv().await {
            let parsed = parse_crash_content(&crash.content);
            let now = Utc::now().timestamp();

            let report = CrashReport {
                id: 0, // Will be set by insert
                event_id: crash.event_id.clone(),
                sender_pubkey: crash.sender_pubkey,
                received_at: now,
                created_at: crash.created_at,
                app_name: parsed.app_name,
                app_version: parsed.app_version,
                exception_type: parsed.exception_type,
                message: parsed.message,
                stack_trace: parsed.stack_trace,
                raw_content: crash.content,
                environment: parsed.environment,
                release: parsed.release,
            };

            let storage = storage_state.storage.lock().await;
            match storage.insert(&report) {
                Ok(Some(_id)) => {
                    println!(
                        "{} Stored crash: {} - {}",
                        "✓".green(),
                        report.exception_type.as_deref().unwrap_or("Unknown"),
                        report.message.as_deref().unwrap_or("No message").chars().take(50).collect::<String>()
                    );
                }
                Ok(None) => {
                    // Duplicate, ignore
                }
                Err(e) => {
                    eprintln!("{} Failed to store crash: {}", "error".red(), e);
                }
            }
        }
    });

    // Start web server
    let router = create_router(state);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("{} Web server listening on http://localhost:{}", "✓".green(), port);

    axum::serve(listener, router).await?;

    Ok(())
}

/// Subscribe to relay and send crashes to storage channel.
async fn subscribe_relay_with_storage(
    relay_url: &str,
    keys: &Keys,
    tx: &mpsc::Sender<ReceivedCrash>,
    all_relay_urls: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut seen: HashSet<EventId> = HashSet::new();
    let (ws_stream, _) = connect_async(relay_url).await?;
    let (mut write, mut read) = ws_stream.split();

    // Subscribe to gift wraps (kind 1059) addressed to us
    let filter = Filter::new()
        .kind(Kind::GiftWrap)
        .pubkey(keys.public_key())
        .limit(100);

    let subscription_id = "bugstr-listen";
    let req = format!(
        r#"["REQ","{}",{}]"#,
        subscription_id,
        serde_json::to_string(&filter)?
    );

    write.send(Message::Text(req.into())).await?;
    println!("{} Connected to {}", "✓".green(), relay_url.cyan());

    while let Some(msg) = read.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                if let Some(crash) = handle_message_for_storage(&text, keys, &mut seen, all_relay_urls).await {
                    if tx.send(crash).await.is_err() {
                        break;
                    }
                }
            }
            Ok(Message::Close(_)) => {
                println!("{} {} closed connection", "info".blue(), relay_url);
                break;
            }
            Err(e) => {
                eprintln!("{} WebSocket error: {}", "error".red(), e);
                break;
            }
            _ => {}
        }
    }

    Ok(())
}

/// Fetch chunk events from relays by their event IDs.
///
/// Uses relay hints from the manifest when available to optimize fetching.
/// For each chunk, tries the hinted relay first before falling back to all relays.
///
/// # Arguments
///
/// * `relay_urls` - List of relay WebSocket URLs to query (fallback)
/// * `chunk_ids` - Event IDs of chunks to fetch (hex-encoded)
/// * `chunk_relays` - Optional map of chunk ID to relay hints from manifest
///
/// # Returns
///
/// Vector of `ChunkPayload` in order by index, ready for reassembly.
///
/// # Errors
///
/// Returns an error if:
/// - Any chunk ID is not valid hex
/// - Not all chunks could be fetched from all relays combined
/// - A chunk is missing at a specific index
async fn fetch_chunks(
    relay_urls: &[String],
    chunk_ids: &[String],
    chunk_relays: Option<&std::collections::HashMap<String, Vec<String>>>,
) -> Result<Vec<ChunkPayload>, Box<dyn std::error::Error + Send + Sync>> {
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::Mutex as TokioMutex;

    if chunk_ids.is_empty() {
        return Ok(vec![]);
    }

    // Parse event IDs
    let event_ids: Vec<EventId> = chunk_ids
        .iter()
        .filter_map(|id| EventId::from_hex(id).ok())
        .collect();

    if event_ids.len() != chunk_ids.len() {
        return Err("Invalid chunk event IDs in manifest".into());
    }

    let expected_count = chunk_ids.len();
    let chunks: Arc<TokioMutex<HashMap<u32, ChunkPayload>>> = Arc::new(TokioMutex::new(HashMap::new()));

    // Determine if we have relay hints
    let has_hints = chunk_relays.map(|h| !h.is_empty()).unwrap_or(false);

    if has_hints {
        println!("  {} Fetching {} chunks using relay hints", "↓".blue(), expected_count);

        // Phase 1: Try hinted relays first (grouped by relay for efficiency)
        let mut relay_to_chunks: HashMap<String, Vec<(usize, EventId)>> = HashMap::new();

        for (i, chunk_id) in chunk_ids.iter().enumerate() {
            if let Some(hints) = chunk_relays.and_then(|h| h.get(chunk_id)) {
                if let Some(relay) = hints.first() {
                    relay_to_chunks
                        .entry(relay.clone())
                        .or_default()
                        .push((i, event_ids[i]));
                }
            }
        }

        // Spawn parallel fetch tasks for hinted relays
        let mut handles = Vec::new();
        for (relay_url, chunk_indices) in relay_to_chunks {
            let relay = relay_url.clone();
            let ids: Vec<EventId> = chunk_indices.iter().map(|(_, id)| *id).collect();
            let chunks_clone = Arc::clone(&chunks);
            let expected = expected_count;

            let handle = tokio::spawn(async move {
                fetch_chunks_from_relay(&relay, &ids, chunks_clone, expected).await
            });
            handles.push(handle);
        }

        // Wait for hinted relay fetches
        for handle in handles {
            let _ = handle.await;
        }

        // Check if we got all chunks from hinted relays
        let current_count = chunks.lock().await.len();
        if current_count == expected_count {
            println!("  {} All {} chunks retrieved from hinted relays", "✓".green(), expected_count);
            let final_chunks = chunks.lock().await;
            let mut ordered: Vec<ChunkPayload> = Vec::with_capacity(expected_count);
            for i in 0..expected_count {
                match final_chunks.get(&(i as u32)) {
                    Some(chunk) => ordered.push(chunk.clone()),
                    None => return Err(format!("Missing chunk at index {}", i).into()),
                }
            }
            return Ok(ordered);
        }

        // Phase 2: Fall back to all relays for missing chunks
        let missing = expected_count - current_count;
        println!("  {} {} chunks missing, falling back to all relays", "↓".blue(), missing);
    } else {
        println!("  {} Fetching {} chunks from {} relays in parallel", "↓".blue(), expected_count, relay_urls.len());
    }

    // Spawn parallel fetch tasks for all relays (for missing chunks or no hints)
    let mut handles = Vec::new();
    for relay_url in relay_urls {
        let relay = relay_url.clone();
        let ids = event_ids.clone();
        let chunks_clone = Arc::clone(&chunks);
        let expected = expected_count;

        let handle = tokio::spawn(async move {
            fetch_chunks_from_relay(&relay, &ids, chunks_clone, expected).await
        });
        handles.push(handle);
    }

    // Wait for all relay fetches to complete
    for handle in handles {
        let _ = handle.await;
    }

    // Extract results
    let final_chunks = chunks.lock().await;

    // Check we got all chunks
    if final_chunks.len() != expected_count {
        return Err(format!(
            "Missing chunks: got {}, expected {} (aggregated across {} relays)",
            final_chunks.len(),
            expected_count,
            relay_urls.len()
        ).into());
    }

    // Return chunks in order
    let mut ordered: Vec<ChunkPayload> = Vec::with_capacity(expected_count);
    for i in 0..expected_count {
        match final_chunks.get(&(i as u32)) {
            Some(chunk) => ordered.push(chunk.clone()),
            None => return Err(format!("Missing chunk at index {}", i).into()),
        }
    }

    println!("  {} All {} chunks retrieved", "✓".green(), expected_count);
    Ok(ordered)
}

/// Fetch chunks from a single relay into the shared chunks map.
async fn fetch_chunks_from_relay(
    relay_url: &str,
    event_ids: &[EventId],
    chunks: Arc<tokio::sync::Mutex<std::collections::HashMap<u32, ChunkPayload>>>,
    expected_count: usize,
) {
    use tokio::time::{timeout, Duration};

    let connect_result = timeout(Duration::from_secs(10), connect_async(relay_url)).await;
    let (ws_stream, _) = match connect_result {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            eprintln!("    {} {}: connect failed: {}", "⚠".yellow(), relay_url, e);
            return;
        }
        Err(_) => {
            eprintln!("    {} {}: connect timeout", "⚠".yellow(), relay_url);
            return;
        }
    };

    let (mut write, mut read) = ws_stream.split();

    // Check which chunks we still need
    let needed: Vec<EventId> = {
        let current = chunks.lock().await;
        event_ids
            .iter()
            .enumerate()
            .filter(|(i, _)| !current.contains_key(&(*i as u32)))
            .map(|(_, id)| *id)
            .collect()
    };

    if needed.is_empty() {
        return;
    }

    let filter = Filter::new()
        .ids(needed)
        .kind(Kind::Custom(KIND_CHUNK));

    // Safely extract relay identifier, handling both wss:// and ws:// schemes
    let relay_suffix = relay_url
        .strip_prefix("wss://")
        .or_else(|| relay_url.strip_prefix("ws://"))
        .unwrap_or(relay_url);
    let subscription_id = format!("bugstr-{}", relay_suffix.chars().take(8).collect::<String>());
    let req = format!(
        r#"["REQ","{}",{}]"#,
        subscription_id,
        serde_json::to_string(&filter).unwrap_or_default()
    );

    if write.send(Message::Text(req.into())).await.is_err() {
        return;
    }

    // Read events with timeout
    let fetch_timeout = Duration::from_secs(30);
    let start = std::time::Instant::now();

    while start.elapsed() < fetch_timeout {
        // Check if we have all chunks (another relay might have found them)
        if chunks.lock().await.len() >= expected_count {
            break;
        }

        let msg_result = timeout(Duration::from_secs(5), read.next()).await;

        match msg_result {
            Ok(Some(Ok(Message::Text(text)))) => {
                let msg: Vec<serde_json::Value> = match serde_json::from_str(&text) {
                    Ok(m) => m,
                    Err(_) => continue,
                };

                if msg.len() >= 3 && msg[0].as_str() == Some("EVENT") {
                    if let Ok(event) = serde_json::from_value::<Event>(msg[2].clone()) {
                        if let Ok(chunk) = ChunkPayload::from_json(&event.content) {
                            let index = chunk.index;
                            let mut current = chunks.lock().await;
                            if !current.contains_key(&index) {
                                current.insert(index, chunk);
                                println!("    {} {} chunk {}/{}", "✓".green(), relay_url, current.len(), expected_count);
                            }
                        }
                    }
                } else if msg.len() >= 2 && msg[0].as_str() == Some("EOSE") {
                    break;
                }
            }
            Ok(Some(Ok(Message::Close(_)))) => break,
            Ok(Some(Ok(_))) => continue,
            Ok(Some(Err(_))) => break,
            Ok(None) => break,
            Err(_) => break,
        }
    }

    // Close subscription
    let close_msg = format!(r#"["CLOSE","{}"]"#, subscription_id);
    let _ = write.send(Message::Text(close_msg.into())).await;
}

/// Handle incoming message and return crash for storage.
async fn handle_message_for_storage(
    text: &str,
    keys: &Keys,
    seen: &mut HashSet<EventId>,
    relay_urls: &[String],
) -> Option<ReceivedCrash> {
    let msg: Vec<serde_json::Value> = serde_json::from_str(text).ok()?;

    if msg.len() < 3 {
        return None;
    }

    let msg_type = msg[0].as_str()?;
    if msg_type != "EVENT" {
        return None;
    }

    let event: Event = serde_json::from_value(msg[2].clone()).ok()?;

    // Deduplicate
    if seen.contains(&event.id) {
        return None;
    }
    seen.insert(event.id);

    println!(
        "{} Received gift wrap: {} (from {})",
        "→".blue(),
        &event.id.to_hex()[..16],
        &event.pubkey.to_hex()[..16]
    );

    // Unwrap gift wrap
    let rumor = match unwrap_gift_wrap(keys, &event) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{} Failed to unwrap gift wrap {}: {}", "✗".red(), &event.id.to_hex()[..16], e);
            return None;
        }
    };

    let rumor_kind = rumor.kind as u16;

    // Decompress payload once before any parsing (handles both compressed manifests and direct payloads)
    let decompressed = decompress_payload(&rumor.content).unwrap_or_else(|_| rumor.content.clone());

    // Handle different transport kinds
    if is_chunked_kind(rumor_kind) {
        // Kind 10421: Manifest for chunked crash report
        match ManifestPayload::from_json(&decompressed) {
            Ok(manifest) => {
                println!(
                    "{} Received manifest: {} chunks, {} bytes total",
                    "📦".cyan(),
                    manifest.chunk_count,
                    manifest.total_size
                );

                // Fetch chunks from relays (using relay hints if available)
                let chunks = match fetch_chunks(
                    relay_urls,
                    &manifest.chunk_ids,
                    manifest.chunk_relays.as_ref(),
                ).await {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("{} Failed to fetch chunks: {}", "✗".red(), e);
                        return None;
                    }
                };

                // Reassemble the payload
                let reassembled = match reassemble_payload(&manifest, &chunks) {
                    Ok(data) => data,
                    Err(e) => {
                        eprintln!("{} Failed to reassemble payload: {}", "✗".red(), e);
                        return None;
                    }
                };

                // Decompress reassembled data
                let payload_str = String::from_utf8_lossy(&reassembled);
                let decompressed = decompress_payload(&payload_str)
                    .unwrap_or_else(|_| payload_str.to_string());

                println!("{} Reassembled {} bytes from {} chunks", "✓".green(), decompressed.len(), chunks.len());

                return Some(ReceivedCrash {
                    event_id: event.id.to_hex(),
                    sender_pubkey: rumor.pubkey.clone(),
                    created_at: rumor.created_at as i64,
                    content: decompressed,
                });
            }
            Err(e) => {
                eprintln!("{} Failed to parse manifest: {}", "✗".red(), e);
                return None;
            }
        }
    }

    // Extract crash content based on transport kind (decompressed already computed above)
    let content = if is_crash_report_kind(rumor_kind) {
        // Kind 10420: Direct crash report with DirectPayload wrapper
        match DirectPayload::from_json(&decompressed) {
            Ok(direct) => {
                // Convert JSON value to string for storage
                serde_json::to_string(&direct.crash).unwrap_or(decompressed)
            }
            Err(_) => {
                // Fall back to treating content as raw crash data
                decompressed
            }
        }
    } else {
        // Legacy kind 14 or other: treat content as raw crash data
        decompressed
    };

    Some(ReceivedCrash {
        event_id: event.id.to_hex(),
        sender_pubkey: rumor.pubkey.clone(),
        created_at: rumor.created_at as i64,
        content,
    })
}

// ============================================================================
// Original listen command (terminal-only, no storage)
// ============================================================================

async fn listen(
    privkey: &str,
    relays: &[String],
    format: OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let secret = parse_privkey(privkey)?;
    let keys = Keys::new(secret);
    let pubkey = keys.public_key();

    println!(
        "{} Listening for crash reports...",
        "bugstr".green().bold()
    );
    println!("  Pubkey: {}", pubkey.to_bech32()?);
    println!("  Relays: {}", relays.join(", "));
    println!();

    // Connect to all relays concurrently
    let mut handles = vec![];
    for relay_url in relays {
        let relay = relay_url.clone();
        let keys = keys.clone();
        let format = format.clone();

        let handle = tokio::spawn(async move {
            if let Err(e) = subscribe_relay(&relay, &keys, &format).await {
                eprintln!("{} Relay {} error: {}", "error".red(), relay, e);
            }
        });
        handles.push(handle);
    }

    // Wait for all relay connections
    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}

async fn subscribe_relay(
    relay_url: &str,
    keys: &Keys,
    format: &OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut seen: HashSet<EventId> = HashSet::new();
    let (ws_stream, _) = connect_async(relay_url).await?;
    let (mut write, mut read) = ws_stream.split();

    // Subscribe to gift wraps (kind 1059) addressed to us
    let filter = Filter::new()
        .kind(Kind::GiftWrap)
        .pubkey(keys.public_key())
        .limit(100);

    let subscription_id = "bugstr-listen";
    let req = format!(
        r#"["REQ","{}",{}]"#,
        subscription_id,
        serde_json::to_string(&filter)?
    );

    write.send(Message::Text(req.into())).await?;

    println!(
        "{} Connected to {}",
        "✓".green(),
        relay_url.cyan()
    );

    while let Some(msg) = read.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                if let Err(e) = handle_message(&text, keys, format, &mut seen) {
                    eprintln!("{} Parse error: {}", "warn".yellow(), e);
                }
            }
            Ok(Message::Close(_)) => {
                println!("{} {} closed connection", "info".blue(), relay_url);
                break;
            }
            Err(e) => {
                eprintln!("{} WebSocket error: {}", "error".red(), e);
                break;
            }
            _ => {}
        }
    }

    Ok(())
}

fn handle_message(
    text: &str,
    keys: &Keys,
    format: &OutputFormat,
    seen: &mut HashSet<EventId>,
) -> Result<(), Box<dyn std::error::Error>> {
    let msg: Vec<serde_json::Value> = serde_json::from_str(text)?;

    if msg.len() < 3 {
        return Ok(());
    }

    let msg_type = msg[0].as_str().unwrap_or("");
    if msg_type != "EVENT" {
        return Ok(());
    }

    let event: Event = serde_json::from_value(msg[2].clone())?;

    // Deduplicate
    if seen.contains(&event.id) {
        return Ok(());
    }
    seen.insert(event.id);

    // Unwrap gift wrap
    let unwrapped = unwrap_gift_wrap(keys, &event)?;

    // Output based on format
    match format {
        OutputFormat::Pretty => print_pretty(&unwrapped, &event),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&unwrapped)?),
        OutputFormat::Raw => println!("{}", unwrapped.content),
    }

    Ok(())
}

/// Unwrapped rumor from a gift wrap.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct Rumor {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u64,
    pub content: String,
    #[serde(default)]
    pub tags: Vec<Vec<String>>,
    #[serde(default)]
    pub sig: String, // Empty for rumors
}

fn unwrap_gift_wrap(keys: &Keys, gift_wrap: &Event) -> Result<Rumor, Box<dyn std::error::Error>> {
    // Decrypt gift wrap to get seal
    let seal_json = nip44::decrypt(keys.secret_key(), &gift_wrap.pubkey, &gift_wrap.content)?;
    let seal: Event = serde_json::from_str(&seal_json)?;

    // Decrypt seal to get rumor (unsigned, so parse as Rumor not Event)
    let rumor_json = nip44::decrypt(keys.secret_key(), &seal.pubkey, &seal.content)?;
    let rumor: Rumor = serde_json::from_str(&rumor_json)?;

    Ok(rumor)
}

fn print_pretty(rumor: &Rumor, gift_wrap: &Event) {
    let timestamp = DateTime::<Utc>::from_timestamp(rumor.created_at as i64, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Try to decompress content
    let content = match decompress_payload(&rumor.content) {
        Ok(decompressed) => decompressed,
        Err(_) => rumor.content.clone(),
    };

    println!("{}", "━".repeat(60).dimmed());
    println!(
        "{} {}",
        "CRASH REPORT".red().bold(),
        timestamp.dimmed()
    );
    println!("{}", "━".repeat(60).dimmed());
    println!("{}: {}", "From".cyan(), &rumor.pubkey);
    println!("{}: {}", "Gift Wrap ID".cyan(), gift_wrap.id);
    println!();

    // Try to parse as JSON for structured output
    if let Ok(payload) = serde_json::from_str::<serde_json::Value>(&content) {
        if let Some(msg) = payload.get("message").and_then(|v| v.as_str()) {
            println!("{}: {}", "Message".yellow().bold(), msg);
        }
        if let Some(stack) = payload.get("stack").and_then(|v| v.as_str()) {
            println!();
            println!("{}:", "Stack Trace".yellow().bold());
            for line in stack.lines().take(20) {
                println!("  {}", line.dimmed());
            }
            let line_count = stack.lines().count();
            if line_count > 20 {
                println!("  {} (+{} more lines)", "...".dimmed(), line_count - 20);
            }
        }
        if let Some(env) = payload.get("environment").and_then(|v| v.as_str()) {
            println!("{}: {}", "Environment".cyan(), env);
        }
        if let Some(release) = payload.get("release").and_then(|v| v.as_str()) {
            println!("{}: {}", "Release".cyan(), release);
        }
    } else {
        // Raw content (likely markdown from Android)
        println!("{}", content);
    }

    println!();
}
