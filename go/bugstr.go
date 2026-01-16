// Package bugstr provides zero-infrastructure crash reporting via NIP-17 encrypted DMs.
//
// Bugstr delivers crash reports via Nostr gift-wrapped encrypted direct messages
// with user consent. Reports auto-expire after 30 days.
//
// Basic usage:
//
//	bugstr.Init(bugstr.Config{
//	    DeveloperPubkey: "npub1...",
//	})
//	defer bugstr.Recover()
//
//	// Your application code...
package bugstr

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/nbd-wtf/go-nostr/nip44"
)

// Config holds the Bugstr configuration.
type Config struct {
	// DeveloperPubkey is the recipient's public key (npub or hex).
	DeveloperPubkey string

	// Relays to publish crash reports to.
	// Defaults to ["wss://relay.damus.io", "wss://relay.primal.net", "wss://nos.lol"].
	Relays []string

	// Environment tag (e.g., "production", "staging").
	Environment string

	// Release version tag.
	Release string

	// RedactPatterns are regex patterns for redacting sensitive data.
	// Defaults include cashu tokens, lightning invoices, and nostr keys.
	RedactPatterns []*regexp.Regexp

	// BeforeSend allows modifying or filtering payloads before sending.
	// Return nil to drop the report.
	BeforeSend func(payload *Payload) *Payload

	// ConfirmSend prompts the user before sending. Return true to send.
	// If nil, reports are sent automatically (suitable for servers).
	ConfirmSend func(summary Summary) bool
}

// Payload is the crash report data sent to the developer.
type Payload struct {
	Message     string `json:"message"`
	Stack       string `json:"stack,omitempty"`
	Timestamp   int64  `json:"timestamp"`
	Environment string `json:"environment,omitempty"`
	Release     string `json:"release,omitempty"`
}

// Summary provides a preview of the crash for confirmation prompts.
type Summary struct {
	Message      string
	StackPreview string
}

// CompressedEnvelope wraps compressed payloads.
type CompressedEnvelope struct {
	V           int    `json:"v"`
	Compression string `json:"compression"`
	Payload     string `json:"payload"`
}

var (
	config           Config
	senderPrivkey    string
	developerPubkeyHex string
	initialized      bool
	initMu           sync.Mutex

	defaultRelays = []string{"wss://relay.damus.io", "wss://relay.primal.net", "wss://nos.lol"}

	defaultRedactions = []*regexp.Regexp{
		regexp.MustCompile(`cashuA[a-zA-Z0-9]+`),
		regexp.MustCompile(`(?i)lnbc[a-z0-9]+`),
		regexp.MustCompile(`(?i)npub1[a-z0-9]+`),
		regexp.MustCompile(`(?i)nsec1[a-z0-9]+`),
		regexp.MustCompile(`(?i)https?://[^\s"]*mint[^\s"]*`),
	}
)

// Init initializes Bugstr with the given configuration.
// Call this early in your application's startup.
func Init(cfg Config) error {
	initMu.Lock()
	defer initMu.Unlock()

	if initialized {
		return nil
	}

	if cfg.DeveloperPubkey == "" {
		return fmt.Errorf("bugstr: DeveloperPubkey is required")
	}

	config = cfg

	// Decode npub to hex if needed
	developerPubkeyHex = decodePubkey(cfg.DeveloperPubkey)
	if developerPubkeyHex == "" {
		return fmt.Errorf("bugstr: invalid DeveloperPubkey")
	}

	// Generate ephemeral sender key
	senderPrivkey = nostr.GeneratePrivateKey()

	initialized = true
	return nil
}

// Recover captures panics and sends a crash report.
// Use with defer at the top of main() or goroutines:
//
//	defer bugstr.Recover()
func Recover() {
	if r := recover(); r != nil {
		err := fmt.Errorf("panic: %v", r)
		CaptureException(err)
		// Re-panic after reporting
		panic(r)
	}
}

// RecoverAndContinue captures panics without re-panicking.
// Useful for goroutines that should not crash the program:
//
//	go func() {
//	    defer bugstr.RecoverAndContinue()
//	    // ...
//	}()
func RecoverAndContinue() {
	if r := recover(); r != nil {
		err := fmt.Errorf("panic: %v", r)
		CaptureException(err)
	}
}

// CaptureException sends an error as a crash report.
func CaptureException(err error) {
	if !initialized {
		return
	}

	payload := buildPayload(err)

	if config.BeforeSend != nil {
		payload = config.BeforeSend(payload)
		if payload == nil {
			return
		}
	}

	summary := Summary{
		Message:      payload.Message,
		StackPreview: truncateStack(payload.Stack, 3),
	}

	if config.ConfirmSend != nil {
		if !config.ConfirmSend(summary) {
			return
		}
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if sendErr := sendToNostr(ctx, payload); sendErr != nil {
			// Silent failure - don't crash the app due to reporting
		}
	}()
}

// CaptureMessage sends a message as a crash report.
func CaptureMessage(msg string) {
	CaptureException(fmt.Errorf("%s", msg))
}

func decodePubkey(pubkey string) string {
	if pubkey == "" {
		return ""
	}
	if strings.HasPrefix(pubkey, "npub") {
		prefix, data, err := nip19.Decode(pubkey)
		if err != nil || prefix != "npub" {
			return ""
		}
		s, ok := data.(string)
		if !ok {
			return ""
		}
		return s
	}
	return pubkey
}

func buildPayload(err error) *Payload {
	msg := "Unknown error"
	if err != nil {
		msg = err.Error()
	}

	stack := captureStack()
	patterns := config.RedactPatterns
	if len(patterns) == 0 {
		patterns = defaultRedactions
	}

	return &Payload{
		Message:     redact(msg, patterns),
		Stack:       redact(stack, patterns),
		Timestamp:   time.Now().UnixMilli(),
		Environment: config.Environment,
		Release:     config.Release,
	}
}

func captureStack() string {
	buf := make([]byte, 64*1024)
	n := runtime.Stack(buf, false)
	return string(buf[:n])
}

func redact(input string, patterns []*regexp.Regexp) string {
	for _, p := range patterns {
		input = p.ReplaceAllString(input, "[redacted]")
	}
	return input
}

func truncateStack(stack string, lines int) string {
	parts := strings.SplitN(stack, "\n", lines+1)
	if len(parts) > lines {
		return strings.Join(parts[:lines], "\n")
	}
	return stack
}

func randomPastTimestamp() int64 {
	now := time.Now().Unix()
	maxOffset := int64(60 * 60 * 24 * 2) // up to 2 days
	offset := rand.Int63n(maxOffset)
	return now - offset
}

func maybeCompress(plaintext string) string {
	if len(plaintext) < 1024 {
		return plaintext
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write([]byte(plaintext))
	gz.Close()

	envelope := CompressedEnvelope{
		V:           1,
		Compression: "gzip",
		Payload:     base64.StdEncoding.EncodeToString(buf.Bytes()),
	}

	result, _ := json.Marshal(envelope)
	return string(result)
}

func sendToNostr(ctx context.Context, payload *Payload) error {
	relays := config.Relays
	if len(relays) == 0 {
		relays = defaultRelays
	}

	plaintext, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	content := maybeCompress(string(plaintext))
	senderPubkey, _ := nostr.GetPublicKey(senderPrivkey)

	// Build unsigned kind 14 rumor
	rumor := map[string]interface{}{
		"id":         "", // Computed later
		"pubkey":     senderPubkey,
		"created_at": randomPastTimestamp(),
		"kind":       14,
		"tags":       [][]string{{"p", developerPubkeyHex}},
		"content":    content,
		"sig":        "",
	}

	// Compute rumor ID per NIP-01: sha256 of [0, pubkey, created_at, kind, tags, content]
	serialized, _ := json.Marshal([]interface{}{
		0,
		rumor["pubkey"],
		rumor["created_at"],
		rumor["kind"],
		rumor["tags"],
		rumor["content"],
	})
	hash := sha256.Sum256(serialized)
	rumorID := hex.EncodeToString(hash[:])
	rumor["id"] = rumorID

	// Encrypt rumor into seal
	rumorBytes, _ := json.Marshal(rumor)
	conversationKey, err := nip44.GenerateConversationKey(senderPrivkey, developerPubkeyHex)
	if err != nil {
		return err
	}
	sealContent, err := nip44.Encrypt(string(rumorBytes), conversationKey)
	if err != nil {
		return err
	}

	seal := nostr.Event{
		Kind:      13,
		CreatedAt: nostr.Timestamp(randomPastTimestamp()),
		Tags:      nostr.Tags{},
		Content:   sealContent,
	}
	seal.Sign(senderPrivkey)

	// Wrap seal in gift wrap with random key
	wrapperPrivkey := nostr.GeneratePrivateKey()
	wrapKey, err := nip44.GenerateConversationKey(wrapperPrivkey, developerPubkeyHex)
	if err != nil {
		return err
	}

	sealJSON, _ := json.Marshal(seal)
	giftContent, err := nip44.Encrypt(string(sealJSON), wrapKey)
	if err != nil {
		return err
	}

	giftWrap := nostr.Event{
		Kind:      1059,
		CreatedAt: nostr.Timestamp(randomPastTimestamp()),
		Tags:      nostr.Tags{{"p", developerPubkeyHex}},
		Content:   giftContent,
	}
	giftWrap.Sign(wrapperPrivkey)

	// Publish to relays
	var lastErr error
	for _, relayURL := range relays {
		relay, err := nostr.RelayConnect(ctx, relayURL)
		if err != nil {
			lastErr = err
			continue
		}
		err = relay.Publish(ctx, giftWrap)
		relay.Close()
		if err == nil {
			return nil
		}
		lastErr = err
	}

	return lastErr
}
