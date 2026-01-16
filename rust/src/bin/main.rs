//! Bugstr CLI - Privacy-focused crash report receiver
//!
//! Subscribes to Nostr relays and decrypts NIP-17 gift-wrapped crash reports.
//! Optionally serves a web dashboard for viewing and analyzing crashes.

use bugstr::{
    decompress_payload, parse_crash_content, AppState, CrashReport, CrashStorage, create_router,
    MappingStore, Platform, Symbolicator, SymbolicationContext,
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

    // Create symbolicator
    let store = MappingStore::new(mappings_dir);
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
    let symbolicator = mappings_dir.as_ref().map(|dir| {
        let store = MappingStore::new(dir);
        Symbolicator::new(store)
    });

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

    // Spawn relay listeners
    for relay_url in relays {
        let relay = relay_url.clone();
        let keys = keys.clone();
        let tx = tx.clone();

        tokio::spawn(async move {
            loop {
                match subscribe_relay_with_storage(&relay, &keys, &tx).await {
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
                if let Some(crash) = handle_message_for_storage(&text, keys, &mut seen) {
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

/// Handle incoming message and return crash for storage.
fn handle_message_for_storage(
    text: &str,
    keys: &Keys,
    seen: &mut HashSet<EventId>,
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

    // Decompress if needed
    let content = decompress_payload(&rumor.content).unwrap_or_else(|_| rumor.content.clone());

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
