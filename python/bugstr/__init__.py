"""
Bugstr - Zero-infrastructure crash reporting via NIP-17 encrypted DMs.

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
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field
from typing import Callable, Optional, Pattern

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


def _send_to_nostr(payload: Payload) -> None:
    """Send payload via NIP-17 gift wrap."""
    if not _sender_keys or not _config:
        return

    try:
        plaintext = json.dumps(payload.to_dict())
        content = _maybe_compress(plaintext)

        # Build rumor (kind 14, unsigned)
        rumor = {
            "pubkey": _sender_keys.public_key().to_hex(),
            "created_at": _random_past_timestamp(),
            "kind": 14,
            "tags": [["p", _developer_pubkey_hex]],
            "content": content,
            "sig": "",
        }

        # Compute rumor ID
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

        # Encrypt into seal (kind 13)
        developer_pk = PublicKey.from_hex(_developer_pubkey_hex)
        seal_content = nip44.encrypt(_sender_keys.secret_key(), developer_pk, rumor_json)

        seal = EventBuilder(
            Kind(13),
            seal_content,
        ).custom_created_at(_random_past_timestamp()).to_event(_sender_keys)

        # Wrap in gift wrap (kind 1059) with random key
        wrapper_keys = Keys.generate()
        seal_json = seal.as_json()
        gift_content = nip44.encrypt(wrapper_keys.secret_key(), developer_pk, seal_json)

        gift_wrap = EventBuilder(
            Kind(1059),
            gift_content,
        ).custom_created_at(_random_past_timestamp()).tags([
            Tag.public_key(developer_pk)
        ]).to_event(wrapper_keys)

        # Publish to relays
        client = Client(wrapper_keys)
        for relay_url in _config.relays:
            try:
                client.add_relay(relay_url)
            except Exception:
                pass

        client.connect()
        client.send_event(gift_wrap)
        client.disconnect()

    except Exception:
        # Silent failure - don't crash the app
        pass
