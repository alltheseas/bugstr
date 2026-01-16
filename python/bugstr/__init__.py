"""
Bugstr - Zero-infrastructure crash reporting via NIP-17 encrypted DMs.

For large crash reports (>50KB), uses CHK chunking:
- Chunks are published as public events (kind 10422)
- Manifest with root hash is gift-wrapped (kind 10421)
- Only the recipient can decrypt chunks using the root hash

Basic usage:

    import bugstr

    bugstr.init(developer_pubkey="npub1...")

    # Automatic exception capture
    try:
        risky_operation()
    except Exception as e:
        bugstr.capture_exception(e)

    # Or install global exception hook
    bugstr.install_exception_hook()
"""

import atexit
import base64
import gzip
import hashlib
import json
import os
import random
import re
import secrets
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field
from typing import Callable, Optional, Pattern

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Transport layer constants
KIND_DIRECT = 10420
KIND_MANIFEST = 10421
KIND_CHUNK = 10422
DIRECT_SIZE_THRESHOLD = 50 * 1024  # 50KB
MAX_CHUNK_SIZE = 48 * 1024  # 48KB

# Relay rate limits (strfry + noteguard: 8 posts/min = 7.5s between posts)
DEFAULT_RELAY_RATE_LIMIT = 7.5  # seconds
RELAY_RATE_LIMITS = {
    "wss://relay.damus.io": 7.5,
    "wss://nos.lol": 7.5,
    "wss://relay.primal.net": 7.5,
}


def get_relay_rate_limit(relay_url: str) -> float:
    """Get rate limit for a relay URL in seconds."""
    return RELAY_RATE_LIMITS.get(relay_url, DEFAULT_RELAY_RATE_LIMIT)


def estimate_upload_seconds(total_chunks: int, num_relays: int) -> int:
    """Estimate upload time for given chunks and relays."""
    sec_per_chunk = DEFAULT_RELAY_RATE_LIMIT / num_relays
    return max(1, int(total_chunks * sec_per_chunk))


@dataclass
class Progress:
    """Progress state for crash report upload (HIG-compliant)."""
    phase: str  # 'preparing', 'uploading', 'finalizing'
    current_chunk: int
    total_chunks: int
    fraction_completed: float
    estimated_seconds_remaining: int
    localized_description: str

# Nostr imports - using nostr-sdk
try:
    from nostr_sdk import Keys, Client, Event, EventBuilder, Kind, Tag, PublicKey, SecretKey
    from nostr_sdk import nip44
    HAS_NOSTR = True
except ImportError:
    HAS_NOSTR = False

__version__ = "0.1.0"
__all__ = [
    "init",
    "capture_exception",
    "capture_message",
    "install_exception_hook",
    "Config",
    "Payload",
]

# Default configuration
DEFAULT_RELAYS = ["wss://relay.damus.io", "wss://relay.primal.net", "wss://nos.lol"]

DEFAULT_REDACTIONS = [
    re.compile(r"cashuA[a-zA-Z0-9]+"),
    re.compile(r"lnbc[a-z0-9]+", re.IGNORECASE),
    re.compile(r"npub1[a-z0-9]+", re.IGNORECASE),
    re.compile(r"nsec1[a-z0-9]+", re.IGNORECASE),
    re.compile(r"https?://[^\s\"]*mint[^\s\"]*", re.IGNORECASE),
]


@dataclass
class Config:
    """Bugstr configuration."""

    developer_pubkey: str
    """Recipient's public key (npub or hex)."""

    relays: list[str] = field(default_factory=lambda: DEFAULT_RELAYS.copy())
    """Relay URLs to publish to."""

    environment: Optional[str] = None
    """Environment tag (e.g., 'production')."""

    release: Optional[str] = None
    """Release version tag."""

    redact_patterns: list[Pattern] = field(default_factory=lambda: DEFAULT_REDACTIONS.copy())
    """Regex patterns for redacting sensitive data."""

    before_send: Optional[Callable[["Payload"], Optional["Payload"]]] = None
    """Hook to modify/filter payloads. Return None to drop."""

    confirm_send: Optional[Callable[[str, str], bool]] = None
    """Hook to confirm before sending. Args: (message, stack_preview). Return True to send."""

    on_progress: Optional[Callable[["Progress"], None]] = None
    """Progress callback for large crash reports. Fires in background thread."""


@dataclass
class Payload:
    """Crash report payload."""

    message: str
    stack: Optional[str] = None
    timestamp: int = field(default_factory=lambda: int(time.time() * 1000))
    environment: Optional[str] = None
    release: Optional[str] = None

    def to_dict(self) -> dict:
        d = {"message": self.message, "timestamp": self.timestamp}
        if self.stack:
            d["stack"] = self.stack
        if self.environment:
            d["environment"] = self.environment
        if self.release:
            d["release"] = self.release
        return d


# Global state
_config: Optional[Config] = None
_sender_keys: Optional[Keys] = None
_developer_pubkey_hex: str = ""
_initialized = False
_lock = threading.Lock()
_original_excepthook = None
_last_post_time: dict[str, float] = {}
_last_post_time_lock = threading.Lock()


def init(
    developer_pubkey: str,
    relays: Optional[list[str]] = None,
    environment: Optional[str] = None,
    release: Optional[str] = None,
    redact_patterns: Optional[list[Pattern]] = None,
    before_send: Optional[Callable[[Payload], Optional[Payload]]] = None,
    confirm_send: Optional[Callable[[str, str], bool]] = None,
) -> None:
    """
    Initialize Bugstr.

    Args:
        developer_pubkey: Recipient's npub or hex pubkey (required).
        relays: Relay URLs (default: damus.io, nos.lol).
        environment: Environment tag.
        release: Version tag.
        redact_patterns: Custom redaction patterns.
        before_send: Hook to modify/filter payloads.
        confirm_send: Hook to confirm before sending.

    Example:
        bugstr.init(
            developer_pubkey="npub1...",
            environment="production",
            release="1.0.0",
        )
    """
    global _config, _sender_keys, _developer_pubkey_hex, _initialized

    if not HAS_NOSTR:
        raise ImportError("nostr-sdk is required. Install with: pip install nostr-sdk")

    with _lock:
        if _initialized:
            return

        _config = Config(
            developer_pubkey=developer_pubkey,
            relays=relays or DEFAULT_RELAYS.copy(),
            environment=environment,
            release=release,
            redact_patterns=redact_patterns or DEFAULT_REDACTIONS.copy(),
            before_send=before_send,
            confirm_send=confirm_send,
        )

        # Decode npub to hex
        _developer_pubkey_hex = _decode_pubkey(developer_pubkey)
        if not _developer_pubkey_hex:
            raise ValueError("Invalid developer_pubkey")

        # Generate ephemeral sender keys
        _sender_keys = Keys.generate()

        _initialized = True


def capture_exception(exc: BaseException) -> None:
    """
    Capture an exception and send as crash report.

    Args:
        exc: The exception to report.

    Example:
        try:
            risky_operation()
        except Exception as e:
            bugstr.capture_exception(e)
    """
    if not _initialized or not _config:
        return

    payload = _build_payload(exc)
    _maybe_send(payload)


def capture_message(message: str) -> None:
    """
    Send a message as crash report.

    Args:
        message: The message to report.
    """
    capture_exception(Exception(message))


def install_exception_hook() -> None:
    """
    Install a global exception hook to capture uncaught exceptions.

    Call this after init() to automatically capture all uncaught exceptions.

    Example:
        bugstr.init(developer_pubkey="npub1...")
        bugstr.install_exception_hook()
    """
    global _original_excepthook

    if not _initialized:
        return

    _original_excepthook = sys.excepthook
    sys.excepthook = _exception_hook


def _exception_hook(exc_type, exc_value, exc_tb):
    """Global exception hook."""
    # Capture the exception
    capture_exception(exc_value)

    # Call the original hook
    if _original_excepthook:
        _original_excepthook(exc_type, exc_value, exc_tb)


def _decode_pubkey(pubkey: str) -> str:
    """Decode npub to hex if needed."""
    if not pubkey:
        return ""
    if pubkey.startswith("npub"):
        try:
            pk = PublicKey.from_bech32(pubkey)
            return pk.to_hex()
        except Exception:
            return ""
    return pubkey


def _redact(text: str, patterns: list[Pattern]) -> str:
    """Apply redaction patterns to text."""
    for pattern in patterns:
        text = pattern.sub("[redacted]", text)
    return text


def _build_payload(exc: BaseException) -> Payload:
    """Build payload from exception."""
    message = str(exc) or "Unknown error"
    stack = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))

    patterns = _config.redact_patterns if _config else DEFAULT_REDACTIONS

    return Payload(
        message=_redact(message, patterns),
        stack=_redact(stack, patterns),
        environment=_config.environment if _config else None,
        release=_config.release if _config else None,
    )


def _random_past_timestamp() -> int:
    """Generate a random timestamp within the past 2 days."""
    now = int(time.time())
    max_offset = 60 * 60 * 24 * 2  # 2 days
    offset = random.randint(0, max_offset)
    return now - offset


def _maybe_compress(plaintext: str) -> str:
    """Compress if over 1KB."""
    if len(plaintext.encode()) < 1024:
        return plaintext

    compressed = gzip.compress(plaintext.encode())
    envelope = {
        "v": 1,
        "compression": "gzip",
        "payload": base64.b64encode(compressed).decode(),
    }
    return json.dumps(envelope)


def _chk_encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypt data using AES-256-CBC with the given key. IV is prepended."""
    iv = secrets.token_bytes(16)

    # PKCS7 padding
    pad_len = 16 - len(data) % 16
    padded = data + bytes([pad_len] * pad_len)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()

    return iv + encrypted


def _chunk_payload(data: bytes) -> tuple[str, list[dict]]:
    """Split data into chunks and encrypt each using CHK.

    Returns:
        Tuple of (root_hash, list of chunk dicts with index, hash, encrypted)
    """
    chunks = []
    chunk_hashes = []

    offset = 0
    index = 0
    while offset < len(data):
        end = min(offset + MAX_CHUNK_SIZE, len(data))
        chunk_data = data[offset:end]

        # Compute hash of plaintext (becomes encryption key)
        chunk_hash = hashlib.sha256(chunk_data).digest()
        chunk_hashes.append(chunk_hash)

        # Encrypt chunk using its hash as key
        encrypted = _chk_encrypt(chunk_data, chunk_hash)

        chunks.append({
            "index": index,
            "hash": chunk_hash.hex(),
            "encrypted": encrypted,
        })

        offset = end
        index += 1

    # Compute root hash from all chunk hashes
    root_hash_input = b"".join(chunk_hashes)
    root_hash = hashlib.sha256(root_hash_input).hexdigest()

    return root_hash, chunks


def _maybe_send(payload: Payload) -> None:
    """Apply hooks and send payload."""
    if not _config:
        return

    # Apply before_send hook
    if _config.before_send:
        result = _config.before_send(payload)
        if result is None:
            return
        payload = result

    # Apply confirm_send hook
    if _config.confirm_send:
        stack_preview = "\n".join((payload.stack or "").split("\n")[:3])
        if not _config.confirm_send(payload.message, stack_preview):
            return

    # Send in background thread
    thread = threading.Thread(target=_send_to_nostr, args=(payload,), daemon=True)
    thread.start()


def _build_gift_wrap(rumor_kind: int, content: str) -> Event:
    """Build a NIP-17 gift-wrapped event for a rumor."""
    rumor = {
        "pubkey": _sender_keys.public_key().to_hex(),
        "created_at": _random_past_timestamp(),
        "kind": rumor_kind,
        "tags": [["p", _developer_pubkey_hex]],
        "content": content,
        "sig": "",
    }

    serialized = json.dumps([
        0,
        rumor["pubkey"],
        rumor["created_at"],
        rumor["kind"],
        rumor["tags"],
        rumor["content"],
    ], separators=(",", ":"))
    rumor["id"] = hashlib.sha256(serialized.encode()).hexdigest()

    rumor_json = json.dumps(rumor)

    developer_pk = PublicKey.from_hex(_developer_pubkey_hex)
    seal_content = nip44.encrypt(_sender_keys.secret_key(), developer_pk, rumor_json)

    seal = EventBuilder(
        Kind(13),
        seal_content,
    ).custom_created_at(_random_past_timestamp()).to_event(_sender_keys)

    wrapper_keys = Keys.generate()
    seal_json = seal.as_json()
    gift_content = nip44.encrypt(wrapper_keys.secret_key(), developer_pk, seal_json)

    return EventBuilder(
        Kind(1059),
        gift_content,
    ).custom_created_at(_random_past_timestamp()).tags([
        Tag.public_key(developer_pk)
    ]).to_event(wrapper_keys)


def _build_chunk_event(chunk: dict) -> Event:
    """Build a public chunk event (kind 10422)."""
    chunk_keys = Keys.generate()
    chunk_payload = {
        "v": 1,
        "index": chunk["index"],
        "hash": chunk["hash"],
        "data": base64.b64encode(chunk["encrypted"]).decode(),
    }
    return EventBuilder(
        Kind(KIND_CHUNK),
        json.dumps(chunk_payload),
    ).custom_created_at(_random_past_timestamp()).to_event(chunk_keys)


def _publish_to_relays(event: Event) -> None:
    """Publish an event to the first successful relay."""
    client = Client(Keys.generate())
    for relay_url in _config.relays:
        try:
            client.add_relay(relay_url)
        except Exception:
            pass

    client.connect()
    client.send_event(event)
    client.disconnect()


def _publish_to_all_relays(event: Event) -> None:
    """Publish an event to all relays for redundancy."""
    # Use threads to publish in parallel
    threads = []
    for relay_url in _config.relays:
        def publish_to_relay(url):
            try:
                client = Client(Keys.generate())
                client.add_relay(url)
                client.connect()
                client.send_event(event)
                client.disconnect()
            except Exception:
                pass

        t = threading.Thread(target=publish_to_relay, args=(relay_url,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=10)


def _wait_for_rate_limit(relay_url: str) -> None:
    """Wait for relay rate limit if needed."""
    with _last_post_time_lock:
        last_time = _last_post_time.get(relay_url, 0)

    rate_limit = get_relay_rate_limit(relay_url)
    elapsed = time.time() - last_time

    if elapsed < rate_limit:
        time.sleep(rate_limit - elapsed)


def _record_post_time(relay_url: str) -> None:
    """Record post time for rate limiting."""
    with _last_post_time_lock:
        _last_post_time[relay_url] = time.time()


def _publish_chunk_to_relay(event: Event, relay_url: str) -> bool:
    """Publish a chunk to a single relay with rate limiting."""
    _wait_for_rate_limit(relay_url)
    try:
        client = Client(Keys.generate())
        client.add_relay(relay_url)
        client.connect()
        client.send_event(event)
        client.disconnect()
        _record_post_time(relay_url)
        return True
    except Exception:
        return False


def _verify_chunk_exists(event_id: str, relay_url: str) -> bool:
    """Verify a chunk event exists on a relay."""
    try:
        from nostr_sdk import Filter
        client = Client(Keys.generate())
        client.add_relay(relay_url)
        client.connect()

        # Query for the specific event by ID
        filter = Filter().id(event_id).kind(Kind(KIND_CHUNK)).limit(1)
        events = client.get_events_of([filter], timeout=5)
        client.disconnect()

        return len(events) > 0
    except Exception:
        return False


def _publish_chunk_with_verify(event: Event, relays: list[str], start_index: int) -> tuple[bool, str]:
    """Publish a chunk with verification and retry on failure.

    Args:
        event: The chunk event to publish
        relays: List of relay URLs
        start_index: Starting relay index (for round-robin)

    Returns:
        Tuple of (success, relay_url) where relay_url is where the chunk was published
    """
    num_relays = len(relays)
    event_id = event.id().to_hex()

    # Try each relay starting from start_index
    for attempt in range(num_relays):
        relay_url = relays[(start_index + attempt) % num_relays]

        # Publish with rate limiting
        if not _publish_chunk_to_relay(event, relay_url):
            continue  # Try next relay

        # Brief delay before verification to allow relay to process
        time.sleep(0.5)

        # Verify the chunk exists
        if _verify_chunk_exists(event_id, relay_url):
            return True, relay_url

        # Verification failed, try next relay

    return False, ""


def _send_to_nostr(payload: Payload) -> None:
    """Send payload via NIP-17 gift wrap, using chunking for large payloads.

    Uses round-robin relay distribution to maximize throughput while
    respecting per-relay rate limits (8 posts/min for strfry+noteguard).
    """
    if not _sender_keys or not _config:
        return

    try:
        plaintext = json.dumps(payload.to_dict())
        content = _maybe_compress(plaintext)
        payload_bytes = content.encode()
        payload_size = len(payload_bytes)

        if payload_size <= DIRECT_SIZE_THRESHOLD:
            # Small payload: direct gift-wrapped delivery (no progress needed)
            direct_payload = {"v": 1, "crash": payload.to_dict()}
            gift_wrap = _build_gift_wrap(KIND_DIRECT, json.dumps(direct_payload))
            _publish_to_relays(gift_wrap)
        else:
            # Large payload: chunked delivery with round-robin distribution
            root_hash, chunks = _chunk_payload(payload_bytes)
            total_chunks = len(chunks)
            relays = _config.relays or DEFAULT_RELAYS
            num_relays = len(relays)

            # Report initial progress
            if _config.on_progress:
                estimated_seconds = estimate_upload_seconds(total_chunks, num_relays)
                _config.on_progress(Progress(
                    phase="preparing",
                    current_chunk=0,
                    total_chunks=total_chunks,
                    fraction_completed=0.0,
                    estimated_seconds_remaining=estimated_seconds,
                    localized_description="Preparing crash report...",
                ))

            # Build and publish chunk events with round-robin distribution and verification
            chunk_ids = []
            chunk_relays = {}

            for i, chunk in enumerate(chunks):
                chunk_event = _build_chunk_event(chunk)
                chunk_id = chunk_event.id().to_hex()
                chunk_ids.append(chunk_id)

                # Publish with verification and retry (starts at round-robin relay)
                success, success_relay = _publish_chunk_with_verify(chunk_event, relays, i % num_relays)
                if success:
                    chunk_relays[chunk_id] = [success_relay]
                # If all relays failed, chunk is lost - receiver will report missing chunk

                # Report progress
                if _config.on_progress:
                    remaining_chunks = total_chunks - i - 1
                    remaining_seconds = estimate_upload_seconds(remaining_chunks, num_relays)
                    _config.on_progress(Progress(
                        phase="uploading",
                        current_chunk=i + 1,
                        total_chunks=total_chunks,
                        fraction_completed=(i + 1) / total_chunks * 0.95,
                        estimated_seconds_remaining=remaining_seconds,
                        localized_description=f"Uploading chunk {i + 1} of {total_chunks}",
                    ))

            # Report finalizing
            if _config.on_progress:
                _config.on_progress(Progress(
                    phase="finalizing",
                    current_chunk=total_chunks,
                    total_chunks=total_chunks,
                    fraction_completed=0.95,
                    estimated_seconds_remaining=2,
                    localized_description="Finalizing...",
                ))

            # Build and publish manifest with relay hints
            manifest = {
                "v": 1,
                "root_hash": root_hash,
                "total_size": payload_size,
                "chunk_count": total_chunks,
                "chunk_ids": chunk_ids,
                "chunk_relays": chunk_relays,
            }
            manifest_gift_wrap = _build_gift_wrap(KIND_MANIFEST, json.dumps(manifest))
            _publish_to_relays(manifest_gift_wrap)

            # Report complete
            if _config.on_progress:
                _config.on_progress(Progress(
                    phase="finalizing",
                    current_chunk=total_chunks,
                    total_chunks=total_chunks,
                    fraction_completed=1.0,
                    estimated_seconds_remaining=0,
                    localized_description="Complete",
                ))

    except Exception:
        # Silent failure - don't crash the app
        pass
