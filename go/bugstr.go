// Package bugstr provides zero-infrastructure crash reporting via NIP-17 encrypted DMs.
//
// Bugstr delivers crash reports via Nostr gift-wrapped encrypted direct messages
// with user consent. Reports auto-expire after 30 days.
//
// For large crash reports (>50KB), uses CHK chunking:
//   - Chunks are published as public events (kind 10422)
//   - Manifest with root hash is gift-wrapped (kind 10421)
//   - Only the recipient can decrypt chunks using the root hash
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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	mathrand "math/rand"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/nbd-wtf/go-nostr/nip44"
)

// Transport layer constants
const (
	// KindDirect is the event kind for direct crash report delivery (<=50KB).
	KindDirect = 10420
	// KindManifest is the event kind for hashtree manifest (>50KB crash reports).
	KindManifest = 10421
	// KindChunk is the event kind for CHK-encrypted chunk data.
	KindChunk = 10422
	// DirectSizeThreshold is the size threshold for switching to chunked transport (50KB).
	DirectSizeThreshold = 50 * 1024
	// MaxChunkSize is the maximum chunk size (48KB).
	MaxChunkSize = 48 * 1024
	// DefaultRelayRateLimit is the rate limit for strfry+noteguard relays (8 posts/min = 7500ms).
	DefaultRelayRateLimit = 7500 * time.Millisecond
)

// RelayRateLimits contains known relay rate limits.
var RelayRateLimits = map[string]time.Duration{
	"wss://relay.damus.io":   7500 * time.Millisecond,
	"wss://nos.lol":          7500 * time.Millisecond,
	"wss://relay.primal.net": 7500 * time.Millisecond,
}

// GetRelayRateLimit returns the rate limit for a relay URL.
func GetRelayRateLimit(relayURL string) time.Duration {
	if limit, ok := RelayRateLimits[relayURL]; ok {
		return limit
	}
	return DefaultRelayRateLimit
}

// EstimateUploadSeconds estimates upload time for given chunks and relays.
func EstimateUploadSeconds(totalChunks, numRelays int) int {
	msPerChunk := int(DefaultRelayRateLimit.Milliseconds()) / numRelays
	return (totalChunks * msPerChunk) / 1000
}

// ProgressPhase represents the current phase of upload.
type ProgressPhase string

const (
	ProgressPhasePreparing  ProgressPhase = "preparing"
	ProgressPhaseUploading  ProgressPhase = "uploading"
	ProgressPhaseFinalizing ProgressPhase = "finalizing"
)

// Progress represents upload progress for HIG-compliant UI.
type Progress struct {
	Phase                    ProgressPhase
	CurrentChunk             int
	TotalChunks              int
	FractionCompleted        float64
	EstimatedSecondsRemaining int
	LocalizedDescription     string
}

// ProgressCallback is called with upload progress.
type ProgressCallback func(Progress)

// DirectPayload wraps crash data for direct delivery (kind 10420).
type DirectPayload struct {
	V     int         `json:"v"`
	Crash interface{} `json:"crash"`
}

// ManifestPayload contains metadata for chunked crash reports (kind 10421).
type ManifestPayload struct {
	V           int                 `json:"v"`
	RootHash    string              `json:"root_hash"`
	TotalSize   int                 `json:"total_size"`
	ChunkCount  int                 `json:"chunk_count"`
	ChunkIDs    []string            `json:"chunk_ids"`
	ChunkRelays map[string][]string `json:"chunk_relays,omitempty"`
}

// ChunkPayload contains encrypted chunk data (kind 10422).
type ChunkPayload struct {
	V     int    `json:"v"`
	Index int    `json:"index"`
	Hash  string `json:"hash"`
	Data  string `json:"data"`
}

// ChunkData holds chunked data before publishing.
type ChunkData struct {
	Index     int
	Hash      []byte
	Encrypted []byte
}

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

	// OnProgress is called with upload progress for large crash reports.
	// Fires asynchronously - does not block the main goroutine.
	OnProgress ProgressCallback
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
	config             Config
	senderPrivkey      string
	developerPubkeyHex string
	initialized        bool
	initMu             sync.Mutex
	lastPostTime       = make(map[string]time.Time)
	lastPostTimeMu     sync.Mutex

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
	offset := mathrand.Int63n(maxOffset)
	return now - offset
}

// chkEncrypt encrypts data using AES-256-CBC with the given key.
// IV is prepended to the ciphertext.
func chkEncrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// PKCS7 padding
	padLen := aes.BlockSize - len(data)%aes.BlockSize
	padded := make([]byte, len(data)+padLen)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	encrypted := make([]byte, len(iv)+len(padded))
	copy(encrypted, iv)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(encrypted[aes.BlockSize:], padded)

	return encrypted, nil
}

// chunkPayloadData splits data into chunks and encrypts each using CHK.
func chunkPayloadData(data []byte) (rootHash string, chunks []ChunkData, err error) {
	var chunkHashes [][]byte

	offset := 0
	index := 0
	for offset < len(data) {
		end := offset + MaxChunkSize
		if end > len(data) {
			end = len(data)
		}
		chunkData := data[offset:end]

		// Compute hash of plaintext chunk (becomes encryption key)
		hash := sha256.Sum256(chunkData)
		chunkHashes = append(chunkHashes, hash[:])

		// Encrypt chunk using its hash as key
		encrypted, err := chkEncrypt(chunkData, hash[:])
		if err != nil {
			return "", nil, err
		}

		chunks = append(chunks, ChunkData{
			Index:     index,
			Hash:      hash[:],
			Encrypted: encrypted,
		})

		offset = end
		index++
	}

	// Compute root hash from all chunk hashes
	var rootHashInput []byte
	for _, h := range chunkHashes {
		rootHashInput = append(rootHashInput, h...)
	}
	rootHashBytes := sha256.Sum256(rootHashInput)
	return hex.EncodeToString(rootHashBytes[:]), chunks, nil
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

// buildGiftWrap creates a NIP-17 gift-wrapped event for a rumor.
func buildGiftWrap(rumorKind int, content string) (nostr.Event, error) {
	senderPubkey, _ := nostr.GetPublicKey(senderPrivkey)

	rumor := map[string]interface{}{
		"id":         "",
		"pubkey":     senderPubkey,
		"created_at": randomPastTimestamp(),
		"kind":       rumorKind,
		"tags":       [][]string{{"p", developerPubkeyHex}},
		"content":    content,
		"sig":        "",
	}

	serialized, _ := json.Marshal([]interface{}{
		0,
		rumor["pubkey"],
		rumor["created_at"],
		rumor["kind"],
		rumor["tags"],
		rumor["content"],
	})
	hash := sha256.Sum256(serialized)
	rumor["id"] = hex.EncodeToString(hash[:])

	rumorBytes, _ := json.Marshal(rumor)
	conversationKey, err := nip44.GenerateConversationKey(senderPrivkey, developerPubkeyHex)
	if err != nil {
		return nostr.Event{}, err
	}
	sealContent, err := nip44.Encrypt(string(rumorBytes), conversationKey)
	if err != nil {
		return nostr.Event{}, err
	}

	seal := nostr.Event{
		Kind:      13,
		CreatedAt: nostr.Timestamp(randomPastTimestamp()),
		Tags:      nostr.Tags{},
		Content:   sealContent,
	}
	seal.Sign(senderPrivkey)

	wrapperPrivkey := nostr.GeneratePrivateKey()
	wrapKey, err := nip44.GenerateConversationKey(wrapperPrivkey, developerPubkeyHex)
	if err != nil {
		return nostr.Event{}, err
	}

	sealJSON, _ := json.Marshal(seal)
	giftContent, err := nip44.Encrypt(string(sealJSON), wrapKey)
	if err != nil {
		return nostr.Event{}, err
	}

	giftWrap := nostr.Event{
		Kind:      1059,
		CreatedAt: nostr.Timestamp(randomPastTimestamp()),
		Tags:      nostr.Tags{{"p", developerPubkeyHex}},
		Content:   giftContent,
	}
	giftWrap.Sign(wrapperPrivkey)

	return giftWrap, nil
}

// buildChunkEvent creates a public chunk event (kind 10422).
func buildChunkEvent(chunk ChunkData) nostr.Event {
	chunkPrivkey := nostr.GeneratePrivateKey()
	chunkPayload := ChunkPayload{
		V:     1,
		Index: chunk.Index,
		Hash:  hex.EncodeToString(chunk.Hash),
		Data:  base64.StdEncoding.EncodeToString(chunk.Encrypted),
	}
	content, _ := json.Marshal(chunkPayload)

	event := nostr.Event{
		Kind:      KindChunk,
		CreatedAt: nostr.Timestamp(randomPastTimestamp()),
		Tags:      nostr.Tags{},
		Content:   string(content),
	}
	event.Sign(chunkPrivkey)
	return event
}

// publishToRelays publishes an event to the first successful relay.
func publishToRelays(ctx context.Context, relays []string, event nostr.Event) error {
	var lastErr error
	for _, relayURL := range relays {
		relay, err := nostr.RelayConnect(ctx, relayURL)
		if err != nil {
			lastErr = err
			continue
		}
		err = relay.Publish(ctx, event)
		relay.Close()
		if err == nil {
			return nil
		}
		lastErr = err
	}
	return lastErr
}

// publishToAllRelays publishes an event to all relays for redundancy.
func publishToAllRelays(ctx context.Context, relays []string, event nostr.Event) error {
	var wg sync.WaitGroup
	successCount := 0
	var mu sync.Mutex

	for _, relayURL := range relays {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			relay, err := nostr.RelayConnect(ctx, url)
			if err != nil {
				return
			}
			err = relay.Publish(ctx, event)
			relay.Close()
			if err == nil {
				mu.Lock()
				successCount++
				mu.Unlock()
			}
		}(relayURL)
	}

	wg.Wait()
	if successCount == 0 {
		return fmt.Errorf("failed to publish chunk to any relay")
	}
	return nil
}

// waitForRateLimit waits until enough time has passed since the last post to this relay.
func waitForRateLimit(relayURL string) {
	lastPostTimeMu.Lock()
	lastTime, exists := lastPostTime[relayURL]
	lastPostTimeMu.Unlock()

	if exists {
		rateLimit := GetRelayRateLimit(relayURL)
		elapsed := time.Since(lastTime)
		if elapsed < rateLimit {
			time.Sleep(rateLimit - elapsed)
		}
	}
}

// recordPostTime records the time of a post to a relay.
func recordPostTime(relayURL string) {
	lastPostTimeMu.Lock()
	lastPostTime[relayURL] = time.Now()
	lastPostTimeMu.Unlock()
}

// publishChunkToRelay publishes a chunk to a single relay with rate limiting.
func publishChunkToRelay(ctx context.Context, relayURL string, event nostr.Event) error {
	waitForRateLimit(relayURL)

	relay, err := nostr.RelayConnect(ctx, relayURL)
	if err != nil {
		return err
	}
	defer relay.Close()

	err = relay.Publish(ctx, event)
	if err == nil {
		recordPostTime(relayURL)
	}
	return err
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
	payloadSize := len(content)

	if payloadSize <= DirectSizeThreshold {
		// Small payload: direct gift-wrapped delivery
		directPayload := DirectPayload{V: 1, Crash: payload}
		directContent, _ := json.Marshal(directPayload)

		giftWrap, err := buildGiftWrap(KindDirect, string(directContent))
		if err != nil {
			return err
		}

		return publishToRelays(ctx, relays, giftWrap)
	}

	// Large payload: chunked delivery with round-robin distribution
	rootHash, chunks, err := chunkPayloadData([]byte(content))
	if err != nil {
		return err
	}

	totalChunks := len(chunks)
	numRelays := len(relays)

	// Report initial progress
	if config.OnProgress != nil {
		estimatedSeconds := EstimateUploadSeconds(totalChunks, numRelays)
		config.OnProgress(Progress{
			Phase:                    ProgressPhasePreparing,
			CurrentChunk:             0,
			TotalChunks:              totalChunks,
			FractionCompleted:        0,
			EstimatedSecondsRemaining: estimatedSeconds,
			LocalizedDescription:     "Preparing crash report...",
		})
	}

	// Build and publish chunk events with round-robin distribution
	chunkIDs := make([]string, totalChunks)
	chunkRelays := make(map[string][]string)

	for i, chunk := range chunks {
		chunkEvent := buildChunkEvent(chunk)
		chunkIDs[i] = chunkEvent.ID

		// Round-robin relay selection
		relayURL := relays[i%numRelays]
		chunkRelays[chunkEvent.ID] = []string{relayURL}

		// Publish with rate limiting
		if err := publishChunkToRelay(ctx, relayURL, chunkEvent); err != nil {
			// Try fallback relay
			fallbackRelay := relays[(i+1)%numRelays]
			if err := publishChunkToRelay(ctx, fallbackRelay, chunkEvent); err != nil {
				// Continue anyway, cross-relay aggregation may still find it
			} else {
				chunkRelays[chunkEvent.ID] = []string{fallbackRelay}
			}
		}

		// Report progress
		if config.OnProgress != nil {
			remainingChunks := totalChunks - i - 1
			remainingSeconds := EstimateUploadSeconds(remainingChunks, numRelays)
			config.OnProgress(Progress{
				Phase:                    ProgressPhaseUploading,
				CurrentChunk:             i + 1,
				TotalChunks:              totalChunks,
				FractionCompleted:        float64(i+1) / float64(totalChunks) * 0.95,
				EstimatedSecondsRemaining: remainingSeconds,
				LocalizedDescription:     fmt.Sprintf("Uploading chunk %d of %d", i+1, totalChunks),
			})
		}
	}

	// Report finalizing
	if config.OnProgress != nil {
		config.OnProgress(Progress{
			Phase:                    ProgressPhaseFinalizing,
			CurrentChunk:             totalChunks,
			TotalChunks:              totalChunks,
			FractionCompleted:        0.95,
			EstimatedSecondsRemaining: 2,
			LocalizedDescription:     "Finalizing...",
		})
	}

	// Build and publish manifest with relay hints
	manifest := ManifestPayload{
		V:           1,
		RootHash:    rootHash,
		TotalSize:   len(content),
		ChunkCount:  totalChunks,
		ChunkIDs:    chunkIDs,
		ChunkRelays: chunkRelays,
	}
	manifestContent, _ := json.Marshal(manifest)

	manifestGiftWrap, err := buildGiftWrap(KindManifest, string(manifestContent))
	if err != nil {
		return err
	}

	err = publishToRelays(ctx, relays, manifestGiftWrap)

	// Report complete
	if err == nil && config.OnProgress != nil {
		config.OnProgress(Progress{
			Phase:                    ProgressPhaseFinalizing,
			CurrentChunk:             totalChunks,
			TotalChunks:              totalChunks,
			FractionCompleted:        1.0,
			EstimatedSecondsRemaining: 0,
			LocalizedDescription:     "Complete",
		})
	}

	return err
}
