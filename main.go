package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sync"
	"sync/atomic"
	"time"
)

// RuleEngine interface for local static and hot-patched dynamic rules
type RuleEngine interface {
	Evaluate(query string) (verdict Verdict, rewritten string)
}

// Verdict represents the decision from the rule engine
type Verdict int

const (
	Allow Verdict = iota
	Block
	Rewrite
)

// SubscriptionTier represents the client's service level
type SubscriptionTier int

const (
	FreeTier       SubscriptionTier = iota // Static rules only
	PremiumTier                            // Full ActiveBrain protection
	EnterpriseTier                         // Enterprise with custom rules + priority support
)

// SubscriptionConfig holds the subscription settings for a Sentinel instance
type SubscriptionConfig struct {
	Tier              SubscriptionTier `json:"tier"`
	ClientName        string           `json:"client_name"`
	LicenseKey        string           `json:"license_key"`
	ExpiresAt         string           `json:"expires_at"`
	MaxQueriesPerDay  int              `json:"max_queries_per_day"`
	NeuralAnalysis    bool             `json:"neural_analysis"`    // Premium+
	StealthMonitoring bool             `json:"stealth_monitoring"` // Premium+
	CustomRules       bool             `json:"custom_rules"`       // Enterprise
	PrioritySupport   bool             `json:"priority_support"`   // Enterprise
}

// DefaultSubscriptionConfigs returns the default settings for each tier
func DefaultSubscriptionConfigs() map[SubscriptionTier]SubscriptionConfig {
	return map[SubscriptionTier]SubscriptionConfig{
		FreeTier: {
			Tier:              FreeTier,
			MaxQueriesPerDay:  1000,
			NeuralAnalysis:    false,
			StealthMonitoring: false,
			CustomRules:       false,
			PrioritySupport:   false,
		},
		PremiumTier: {
			Tier:              PremiumTier,
			MaxQueriesPerDay:  100000,
			NeuralAnalysis:    true,
			StealthMonitoring: true,
			CustomRules:       false,
			PrioritySupport:   false,
		},
		EnterpriseTier: {
			Tier:              EnterpriseTier,
			MaxQueriesPerDay:  -1, // Unlimited
			NeuralAnalysis:    true,
			StealthMonitoring: true,
			CustomRules:       true,
			PrioritySupport:   true,
		},
	}
}

// StaticRuleEngine implements RuleEngine with regex-based static rules
type StaticRuleEngine struct {
	rules []regexp.Regexp
}

// Evaluate checks the query against static regex rules
func (s *StaticRuleEngine) Evaluate(query string) (Verdict, string) {
	for _, rule := range s.rules {
		if rule.MatchString(query) {
			return Block, ""
		}
	}
	return Allow, ""
}

// DynamicRuleEngine holds a pointer to a dynamic rule function, swappable atomically
type DynamicRuleEngine struct {
	ruleFunc atomic.Pointer[func(string) (Verdict, string)]
}

// Evaluate executes the current dynamic rule function
func (d *DynamicRuleEngine) Evaluate(query string) (Verdict, string) {
	fn := d.ruleFunc.Load()
	if fn != nil {
		return (*fn)(query)
	}
	return Allow, ""
}

// HotPatch updates the dynamic rule function atomically
func (d *DynamicRuleEngine) HotPatch(newFunc func(string) (Verdict, string)) {
	d.ruleFunc.Store(&newFunc)
}

// InferenceSnapshot represents metadata fingerprint of the request
type InferenceSnapshot struct {
	QueryLength int    `json:"query_length"`
	TokenCount  int    `json:"token_count"`
	Hash        string `json:"hash"`
}

// NeuralTunnelClient handles secure communication with NEUS Logic Engine
type NeuralTunnelClient struct {
	endpoint string
	keyPool  *sync.Pool // For rotating keys derived from micro-neural-net state
}

// NewNeuralTunnelClient initializes the client with a key pool
func NewNeuralTunnelClient(endpoint string) *NeuralTunnelClient {
	return &NeuralTunnelClient{
		endpoint: endpoint,
		keyPool: &sync.Pool{
			New: func() interface{} {
				// Simulate key derivation from micro-neural-net state (placeholder)
				key := make([]byte, 32)
				rand.Read(key)
				return key
			},
		},
	}
}

// SendFingerprint sends the encrypted fingerprint camouflaged as HTTP 200 OK JSON
func (n *NeuralTunnelClient) SendFingerprint(ctx context.Context, snapshot InferenceSnapshot) (Verdict, error) {
	data, _ := json.Marshal(snapshot)
	key := n.keyPool.Get().([]byte)
	defer n.keyPool.Put(key)

	encrypted, _ := encryptAES(data, key)

	// Camouflage: Wrap in standard health check JSON
	payload := map[string]interface{}{
		"status": "ok",
		"data":   encrypted, // Encrypted payload
	}
	body, _ := json.Marshal(payload)

	req, _ := http.NewRequestWithContext(ctx, "POST", n.endpoint, bytes.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Block, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return Block, fmt.Errorf("invalid response")
	}

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)
	// Decrypt and parse verdict (simplified)
	return Allow, nil // Placeholder
}

// SendFingerprintToNEUS sends the fingerprint to NEUS Overmind for neural analysis
func (n *NeuralTunnelClient) SendFingerprintToNEUS(ctx context.Context, snapshot InferenceSnapshot, clientID string, neusEndpoint string) (Verdict, error) {
	// Prepare fingerprint payload for NEUS
	payload := map[string]interface{}{
		"client_id": clientID,
		"fingerprint": map[string]interface{}{
			"query_length": snapshot.QueryLength,
			"token_count":  snapshot.TokenCount,
			"hash":         snapshot.Hash,
		},
	}
	body, _ := json.Marshal(payload)

	req, _ := http.NewRequestWithContext(ctx, "POST", neusEndpoint+"/api/sentinel/fingerprint", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "neus-dev-key-2025")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("⚠️ Failed to send fingerprint to NEUS: %v", err)
		return Allow, err // Don't block on NEUS communication failure
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("⚠️ NEUS returned status %d", resp.StatusCode)
		return Allow, nil
	}

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)

	// Check if NEUS detected a threat
	if verdict, ok := response["verdict"].(string); ok && verdict == "Block" {
		log.Printf("🛡️ NEUS neural analysis detected threat - blocking")
		return Block, nil
	}

	return Allow, nil
}

// encryptAES is a helper for AES encryption
func encryptAES(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	io.ReadFull(rand.Reader, iv)
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)
	return ciphertext, nil
}

// decryptAES is a helper for AES decryption
func decryptAES(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(data) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	return ciphertext, nil
}

// InferenceHandler processes requests using the Neural Tunnel
type InferenceHandler struct {
	ruleEngine *DynamicRuleEngine
	tunnel     *NeuralTunnelClient
	bufferPool *sync.Pool // For tokenization buffers
}

// NewInferenceHandler initializes the handler
func NewInferenceHandler(ruleEngine *DynamicRuleEngine, tunnel *NeuralTunnelClient) *InferenceHandler {
	return &InferenceHandler{
		ruleEngine: ruleEngine,
		tunnel:     tunnel,
		bufferPool: &sync.Pool{
			New: func() interface{} {
				return make([]byte, 0, 1024)
			},
		},
	}
}

// ProcessRequest inspects, evaluates, and forwards the request
func (h *InferenceHandler) ProcessRequest(ctx context.Context, query string) (Verdict, string, error) {
	// Request Inspection: Tokenize using buffer pool
	buffer := h.bufferPool.Get().([]byte)
	defer h.bufferPool.Put(buffer[:0])

	tokens := tokenizeQuery(query, buffer)
	snapshot := InferenceSnapshot{
		QueryLength: len(query),
		TokenCount:  len(tokens),
		Hash:        fmt.Sprintf("%x", len(query)), // Placeholder hash
	}

	// Local Heuristics: Fast-path evaluation
	if verdict, rewritten := h.ruleEngine.Evaluate(query); verdict == Block {
		return verdict, rewritten, nil
	}

	// Send to Neural Tunnel
	verdict, err := h.tunnel.SendFingerprint(ctx, snapshot)
	return verdict, "", err
}

// tokenizeQuery is a simple tokenizer using the buffer
func tokenizeQuery(query string, buffer []byte) []string {
	// Simplified tokenization (split by spaces)
	return regexp.MustCompile(`\s+`).Split(query, -1)
}

// NEUS OVERMUND endpoint for neural inference routing
const NEUSOvermundEndpoint = "https://overmund.neus.ai/v1/inference"

// SentinelServer handles HTTP API for NEUS communication
type SentinelServer struct {
	handler      *InferenceHandler
	ruleEngine   *DynamicRuleEngine
	privateKey   *rsa.PrivateKey
	publicKey    *rsa.PublicKey
	clientID     string
	sessions     sync.Map // map[clientID][]byte for session keys
	subscription SubscriptionConfig
	queryCount   int64 // Daily query counter
	bypassLog    []BypassAttempt
	bypassMu     sync.Mutex
}

// BypassAttempt records stealth monitoring data
type BypassAttempt struct {
	Timestamp   string `json:"timestamp"`
	SourceIP    string `json:"source_ip"`
	Query       string `json:"query"`
	Method      string `json:"method"`
	Detected    bool   `json:"detected"`
	Description string `json:"description"`
}

// NewSentinelServer creates a new HTTP server with RSA key pair
func NewSentinelServer(handler *InferenceHandler, ruleEngine *DynamicRuleEngine) (*SentinelServer, error) {
	return NewSentinelServerWithTier(handler, ruleEngine, FreeTier)
}

// NewSentinelServerWithTier creates a server with specific subscription tier
func NewSentinelServerWithTier(handler *InferenceHandler, ruleEngine *DynamicRuleEngine, tier SubscriptionTier) (*SentinelServer, error) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Generate unique client ID
	clientIDBytes := make([]byte, 16)
	rand.Read(clientIDBytes)
	clientID := fmt.Sprintf("sentinel-%x", clientIDBytes)

	// Get subscription config for tier
	configs := DefaultSubscriptionConfigs()
	subscription := configs[tier]
	subscription.ClientName = clientID

	return &SentinelServer{
		handler:      handler,
		ruleEngine:   ruleEngine,
		privateKey:   privateKey,
		publicKey:    &privateKey.PublicKey,
		clientID:     clientID,
		subscription: subscription,
		bypassLog:    make([]BypassAttempt, 0),
	}, nil
}

// PublicKeyResponse represents the response for /api/public_key
type PublicKeyResponse struct {
	ClientID  string `json:"client_id"`
	PublicKey string `json:"public_key"`
}

// KeyExchangeRequest represents the request for /api/key_exchange
type KeyExchangeRequest struct {
	ClientID  string `json:"client_id"`
	PublicKey string `json:"public_key"`
}

// KeyExchangeResponse represents the response for /api/key_exchange
type KeyExchangeResponse struct {
	SessionKey string `json:"session_key"`
	Signature  string `json:"signature"`
}

// HandlePublicKey returns the Sentinel's public key
func (s *SentinelServer) HandlePublicKey(w http.ResponseWriter, r *http.Request) {
	// Export public key to PEM format
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(s.publicKey)
	if err != nil {
		http.Error(w, "failed to marshal public key", http.StatusInternalServerError)
		return
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	response := PublicKeyResponse{
		ClientID:  s.clientID,
		PublicKey: string(pubKeyPEM),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleKeyExchange performs secure key exchange with NEUS
func (s *SentinelServer) HandleKeyExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req KeyExchangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Generate session key
	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)

	// Store session key for this client
	s.sessions.Store(req.ClientID, sessionKey)

	// Create signature of session key
	hash := sha256.Sum256(sessionKey)
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, 0, hash[:])
	if err != nil {
		http.Error(w, "failed to sign session key", http.StatusInternalServerError)
		return
	}

	response := KeyExchangeResponse{
		SessionKey: base64.StdEncoding.EncodeToString(sessionKey),
		Signature:  base64.StdEncoding.EncodeToString(signature),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HotPatchRequest represents a hot-patch deployment request from NEUS
type HotPatchRequest struct {
	ThreatType    string   `json:"threat_type"`
	Indicators    []string `json:"indicators"`
	Severity      string   `json:"severity"`
	Description   string   `json:"description"`
	EncryptedData string   `json:"encrypted_data,omitempty"`
	Signature     string   `json:"signature,omitempty"`
	ClientID      string   `json:"client_id,omitempty"`
}

// HandleHotPatch receives and applies hot-patches from NEUS
func (s *SentinelServer) HandleHotPatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req HotPatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Check if this is an encrypted payload from NEUS
	if req.EncryptedData != "" {
		log.Printf("🔐 Received encrypted hot-patch from NEUS (client: %s)", req.ClientID)
		// For now, acknowledge receipt - full decryption would require session key
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "success",
			"message": "Encrypted hot-patch received and queued for processing",
		})
		return
	}

	// Build regex patterns from indicators
	patterns := make([]*regexp.Regexp, 0, len(req.Indicators))
	for _, indicator := range req.Indicators {
		if pattern, err := regexp.Compile(regexp.QuoteMeta(indicator)); err == nil {
			patterns = append(patterns, pattern)
		}
	}

	// Hot-patch the rule engine with new patterns
	s.ruleEngine.HotPatch(func(q string) (Verdict, string) {
		for _, pattern := range patterns {
			if pattern.MatchString(q) {
				return Block, ""
			}
		}
		return Allow, ""
	})

	log.Printf("🔄 Hot-patch applied: %s - %d indicators loaded", req.ThreatType, len(patterns))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("Hot-patch applied: %d patterns", len(patterns)),
	})
}

// HandleHealth returns server health status
func (s *SentinelServer) HandleHealth(w http.ResponseWriter, r *http.Request) {
	tierNames := map[SubscriptionTier]string{
		FreeTier:       "free",
		PremiumTier:    "premium",
		EnterpriseTier: "enterprise",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":             "healthy",
		"service":            "NEUS_Sentinel_Field_Agent",
		"client_id":          s.clientID,
		"version":            "2.0.0",
		"active_patches":     0,
		"encryption":         "enabled",
		"subscription_tier":  tierNames[s.subscription.Tier],
		"neural_analysis":    s.subscription.NeuralAnalysis,
		"stealth_monitoring": s.subscription.StealthMonitoring,
		"queries_today":      atomic.LoadInt64(&s.queryCount),
		"max_queries":        s.subscription.MaxQueriesPerDay,
	})
}

// HandleSubscription returns subscription details
func (s *SentinelServer) HandleSubscription(w http.ResponseWriter, r *http.Request) {
	tierNames := map[SubscriptionTier]string{
		FreeTier:       "free",
		PremiumTier:    "premium",
		EnterpriseTier: "enterprise",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"client_id":           s.clientID,
		"tier":                tierNames[s.subscription.Tier],
		"client_name":         s.subscription.ClientName,
		"license_key":         s.subscription.LicenseKey,
		"expires_at":          s.subscription.ExpiresAt,
		"max_queries_per_day": s.subscription.MaxQueriesPerDay,
		"features": map[string]bool{
			"neural_analysis":    s.subscription.NeuralAnalysis,
			"stealth_monitoring": s.subscription.StealthMonitoring,
			"custom_rules":       s.subscription.CustomRules,
			"priority_support":   s.subscription.PrioritySupport,
		},
		"usage": map[string]interface{}{
			"queries_today":   atomic.LoadInt64(&s.queryCount),
			"bypass_attempts": len(s.bypassLog),
		},
	})
}

// HandleBypassLog returns stealth monitoring bypass attempts (Premium+ only)
func (s *SentinelServer) HandleBypassLog(w http.ResponseWriter, r *http.Request) {
	if !s.subscription.StealthMonitoring {
		http.Error(w, "Stealth monitoring requires Premium or Enterprise tier", http.StatusForbidden)
		return
	}

	s.bypassMu.Lock()
	defer s.bypassMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":          "success",
		"total_attempts":  len(s.bypassLog),
		"bypass_attempts": s.bypassLog,
	})
}

// RecordBypassAttempt logs a bypass attempt (for stealth monitoring)
func (s *SentinelServer) RecordBypassAttempt(sourceIP, query, method, description string, detected bool) {
	if !s.subscription.StealthMonitoring {
		return
	}

	s.bypassMu.Lock()
	defer s.bypassMu.Unlock()

	attempt := BypassAttempt{
		Timestamp:   fmt.Sprintf("%d", time.Now().Unix()),
		SourceIP:    sourceIP,
		Query:       query,
		Method:      method,
		Detected:    detected,
		Description: description,
	}

	s.bypassLog = append(s.bypassLog, attempt)

	// Keep only last 1000 attempts
	if len(s.bypassLog) > 1000 {
		s.bypassLog = s.bypassLog[1:]
	}

	log.Printf("🕵️ Stealth Monitor: Bypass attempt from %s - %s", sourceIP, method)
}

// HandleUpgrade handles subscription upgrade requests
func (s *SentinelServer) HandleUpgrade(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		LicenseKey string `json:"license_key"`
		Tier       string `json:"tier"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// Validate license key (in production, verify with NEUS server)
	tierMap := map[string]SubscriptionTier{
		"free":       FreeTier,
		"premium":    PremiumTier,
		"enterprise": EnterpriseTier,
	}

	newTier, ok := tierMap[req.Tier]
	if !ok {
		http.Error(w, "invalid tier", http.StatusBadRequest)
		return
	}

	// Update subscription
	configs := DefaultSubscriptionConfigs()
	s.subscription = configs[newTier]
	s.subscription.LicenseKey = req.LicenseKey
	s.subscription.ClientName = s.clientID

	log.Printf("⬆️ Subscription upgraded to %s", req.Tier)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("Upgraded to %s tier", req.Tier),
		"features": map[string]bool{
			"neural_analysis":    s.subscription.NeuralAnalysis,
			"stealth_monitoring": s.subscription.StealthMonitoring,
			"custom_rules":       s.subscription.CustomRules,
			"priority_support":   s.subscription.PrioritySupport,
		},
	})
}

// Start begins the HTTP server on the specified port
func (s *SentinelServer) Start(port string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/public_key", s.HandlePublicKey)
	mux.HandleFunc("/api/key_exchange", s.HandleKeyExchange)
	mux.HandleFunc("/api/hot_patch", s.HandleHotPatch)
	mux.HandleFunc("/api/hotpatch", s.HandleHotPatch) // Alias for NEUS compatibility
	mux.HandleFunc("/api/subscription", s.HandleSubscription)
	mux.HandleFunc("/api/upgrade", s.HandleUpgrade)
	mux.HandleFunc("/api/bypass_log", s.HandleBypassLog)
	mux.HandleFunc("/health", s.HandleHealth)

	tierNames := map[SubscriptionTier]string{
		FreeTier:       "FREE",
		PremiumTier:    "PREMIUM",
		EnterpriseTier: "ENTERPRISE",
	}

	log.Printf("🚀 Sentinel server starting on port %s", port)
	log.Printf("📋 Subscription: %s tier", tierNames[s.subscription.Tier])
	log.Printf("🧠 Neural Analysis: %v", s.subscription.NeuralAnalysis)
	log.Printf("🕵️ Stealth Monitoring: %v", s.subscription.StealthMonitoring)
	log.Printf("📡 Endpoints: /api/public_key, /api/key_exchange, /api/hot_patch, /api/subscription, /api/upgrade, /health")

	return http.ListenAndServe(":"+port, mux)
}

// Example usage in main (for demonstration)
func main() {
	// Parse command line flags for subscription tier
	tier := FreeTier // Default to free tier

	// Check for environment variable or flag to set tier
	tierEnv := os.Getenv("SENTINEL_TIER")
	switch tierEnv {
	case "premium":
		tier = PremiumTier
	case "enterprise":
		tier = EnterpriseTier
	}

	ruleEngine := &DynamicRuleEngine{}
	tunnel := NewNeuralTunnelClient(NEUSOvermundEndpoint)
	handler := NewInferenceHandler(ruleEngine, tunnel)

	// Create and start the Sentinel HTTP server with specified tier
	server, err := NewSentinelServerWithTier(handler, ruleEngine, tier)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Start server on port 8081 (matching NEUS control_test.py)
	log.Fatal(server.Start("8081"))
}
