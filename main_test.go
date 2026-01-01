package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"
)

// TestStaticRuleEngine checks if basic SQL injection patterns are blocked
func TestStaticRuleEngine(t *testing.T) {
	rules := []regexp.Regexp{
		*regexp.MustCompile(`(?i)DROP TABLE`),
		*regexp.MustCompile(`(?i)OR 1=1`),
	}
	engine := &StaticRuleEngine{rules: rules}

	tests := []struct {
		query    string
		expected Verdict
	}{
		{"SELECT * FROM users", Allow},
		{"DROP TABLE users", Block},
		{"SELECT * FROM users WHERE id = 1 OR 1=1", Block},
	}

	for _, tt := range tests {
		verdict, _ := engine.Evaluate(tt.query)
		if verdict != tt.expected {
			t.Errorf("For query %q, expected %v, got %v", tt.query, tt.expected, verdict)
		}
	}
}

// TestHotPatching ensures that rules can be swapped atomically at runtime
func TestHotPatching(t *testing.T) {
	engine := &DynamicRuleEngine{}

	// Initial state should allow everything
	if verdict, _ := engine.Evaluate("SELECT * FROM sensitive_data"); verdict != Allow {
		t.Fatal("Initial state should allow queries")
	}

	// Patch the engine with a specific block rule
	newRule := func(q string) (Verdict, string) {
		if regexp.MustCompile(`sensitive_data`).MatchString(q) {
			return Block, ""
		}
		return Allow, ""
	}
	engine.HotPatch(newRule)

	// Post-patch state should block
	if verdict, _ := engine.Evaluate("SELECT * FROM sensitive_data"); verdict != Block {
		t.Error("Hot-patching failed to block target query")
	}
}

// TestEncryption ensures the Neural Tunnel can encrypt and decrypt metadata
func TestEncryption(t *testing.T) {
	key := []byte("a_very_secret_32_byte_key_123456") // 32 bytes for AES-256
	originalData := []byte("{\"query_length\": 100}")

	encrypted, err := encryptAES(originalData, key)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	if string(encrypted) == string(originalData) {
		t.Error("Data was not encrypted")
	}

	decrypted, err := decryptAES(encrypted, key)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if string(decrypted) != string(originalData) {
		t.Error("Decryption did not match original")
	}
}

// TestTokenization checks if the buffer-pool logic works as expected
func TestTokenization(t *testing.T) {
	query := "SELECT id FROM orders"
	buffer := make([]byte, 0, 1024)
	tokens := tokenizeQuery(query, buffer)

	expectedCount := 4
	if len(tokens) != expectedCount {
		t.Errorf("Expected %d tokens, got %d", expectedCount, len(tokens))
	}
}

// TestInferenceHandlerBlock tests that the handler blocks queries based on rules without calling the tunnel
func TestInferenceHandlerBlock(t *testing.T) {
	engine := &DynamicRuleEngine{}
	engine.HotPatch(func(q string) (Verdict, string) {
		if regexp.MustCompile(`DROP`).MatchString(q) {
			return Block, ""
		}
		return Allow, ""
	})
	tunnel := NewNeuralTunnelClient("dummy")
	handler := NewInferenceHandler(engine, tunnel)

	verdict, _, err := handler.ProcessRequest(context.Background(), "DROP TABLE users")
	if verdict != Block {
		t.Errorf("Expected Block, got %v", verdict)
	}
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

// TestSentinelServerPublicKey tests the /api/public_key endpoint
func TestSentinelServerPublicKey(t *testing.T) {
	engine := &DynamicRuleEngine{}
	tunnel := NewNeuralTunnelClient("dummy")
	handler := NewInferenceHandler(engine, tunnel)

	server, err := NewSentinelServer(handler, engine)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/public_key", nil)
	w := httptest.NewRecorder()

	server.HandlePublicKey(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response PublicKeyResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response.ClientID == "" {
		t.Error("Expected non-empty client_id")
	}
	if response.PublicKey == "" {
		t.Error("Expected non-empty public_key")
	}
}

// TestSentinelServerKeyExchange tests the /api/key_exchange endpoint
func TestSentinelServerKeyExchange(t *testing.T) {
	engine := &DynamicRuleEngine{}
	tunnel := NewNeuralTunnelClient("dummy")
	handler := NewInferenceHandler(engine, tunnel)

	server, err := NewSentinelServer(handler, engine)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	reqBody := KeyExchangeRequest{
		ClientID:  "test_client",
		PublicKey: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/key_exchange", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.HandleKeyExchange(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response KeyExchangeResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response.SessionKey == "" {
		t.Error("Expected non-empty session_key")
	}
	if response.Signature == "" {
		t.Error("Expected non-empty signature")
	}
}

// TestSentinelServerHotPatch tests the /api/hot_patch endpoint
func TestSentinelServerHotPatch(t *testing.T) {
	engine := &DynamicRuleEngine{}
	tunnel := NewNeuralTunnelClient("dummy")
	handler := NewInferenceHandler(engine, tunnel)

	server, err := NewSentinelServer(handler, engine)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Verify initial state allows query
	if verdict, _ := engine.Evaluate("DROP TABLE users"); verdict != Allow {
		t.Error("Initial state should allow queries")
	}

	// Send hot-patch request
	reqBody := HotPatchRequest{
		ThreatType:  "sql_injection",
		Indicators:  []string{"DROP TABLE", "UNION SELECT"},
		Severity:    "high",
		Description: "SQL injection patterns",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/hot_patch", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.HandleHotPatch(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Verify hot-patch was applied
	if verdict, _ := engine.Evaluate("DROP TABLE users"); verdict != Block {
		t.Error("Hot-patch should block DROP TABLE queries")
	}
}

// TestSentinelServerHealth tests the /health endpoint
func TestSentinelServerHealth(t *testing.T) {
	engine := &DynamicRuleEngine{}
	tunnel := NewNeuralTunnelClient("dummy")
	handler := NewInferenceHandler(engine, tunnel)

	server, err := NewSentinelServer(handler, engine)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	server.HandleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["status"] != "healthy" {
		t.Error("Expected status to be 'healthy'")
	}
}

// TestSubscriptionTiers tests the subscription tier system
func TestSubscriptionTiers(t *testing.T) {
	configs := DefaultSubscriptionConfigs()

	tests := []struct {
		tier             SubscriptionTier
		expectedNeural   bool
		expectedStealth  bool
		expectedCustom   bool
		expectedPriority bool
	}{
		{FreeTier, false, false, false, false},
		{PremiumTier, true, true, false, false},
		{EnterpriseTier, true, true, true, true},
	}

	for _, tt := range tests {
		config := configs[tt.tier]
		if config.NeuralAnalysis != tt.expectedNeural {
			t.Errorf("Tier %d: NeuralAnalysis expected %v, got %v", tt.tier, tt.expectedNeural, config.NeuralAnalysis)
		}
		if config.StealthMonitoring != tt.expectedStealth {
			t.Errorf("Tier %d: StealthMonitoring expected %v, got %v", tt.tier, tt.expectedStealth, config.StealthMonitoring)
		}
		if config.CustomRules != tt.expectedCustom {
			t.Errorf("Tier %d: CustomRules expected %v, got %v", tt.tier, tt.expectedCustom, config.CustomRules)
		}
		if config.PrioritySupport != tt.expectedPriority {
			t.Errorf("Tier %d: PrioritySupport expected %v, got %v", tt.tier, tt.expectedPriority, config.PrioritySupport)
		}
	}
}

// TestSubscriptionEndpoint tests the /api/subscription endpoint
func TestSubscriptionEndpoint(t *testing.T) {
	engine := &DynamicRuleEngine{}
	tunnel := NewNeuralTunnelClient("dummy")
	handler := NewInferenceHandler(engine, tunnel)

	server, err := NewSentinelServerWithTier(handler, engine, PremiumTier)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/subscription", nil)
	w := httptest.NewRecorder()

	server.HandleSubscription(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["tier"] != "premium" {
		t.Errorf("Expected tier 'premium', got %v", response["tier"])
	}
}

// TestBypassLogging tests the stealth monitoring system
func TestBypassLogging(t *testing.T) {
	engine := &DynamicRuleEngine{}
	tunnel := NewNeuralTunnelClient("dummy")
	handler := NewInferenceHandler(engine, tunnel)

	server, err := NewSentinelServerWithTier(handler, engine, PremiumTier)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Record a bypass attempt
	server.RecordBypassAttempt("192.168.1.100", "DROP TABLE users", "sql_injection", "Attempt to bypass using DROP TABLE", true)

	// Check bypass log
	req := httptest.NewRequest(http.MethodGet, "/api/bypass_log", nil)
	w := httptest.NewRecorder()

	server.HandleBypassLog(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	attempts, ok := response["bypass_attempts"].([]interface{})
	if !ok || len(attempts) != 1 {
		t.Errorf("Expected 1 bypass attempt in log, got %v", response)
	}
}

// TestUpgradeEndpoint tests the /api/upgrade endpoint
func TestUpgradeEndpoint(t *testing.T) {
	engine := &DynamicRuleEngine{}
	tunnel := NewNeuralTunnelClient("dummy")
	handler := NewInferenceHandler(engine, tunnel)

	server, err := NewSentinelServerWithTier(handler, engine, FreeTier)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Verify starting tier
	if server.subscription.Tier != FreeTier {
		t.Errorf("Expected FreeTier, got %d", server.subscription.Tier)
	}

	// Upgrade to premium
	reqBody := map[string]string{"tier": "premium"}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/api/upgrade", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.HandleUpgrade(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Verify tier was upgraded
	if server.subscription.Tier != PremiumTier {
		t.Errorf("Expected PremiumTier after upgrade, got %d", server.subscription.Tier)
	}
}

// TestUpgradeToEnterprise tests upgrade to enterprise tier
func TestUpgradeToEnterprise(t *testing.T) {
	engine := &DynamicRuleEngine{}
	tunnel := NewNeuralTunnelClient("dummy")
	handler := NewInferenceHandler(engine, tunnel)

	server, err := NewSentinelServerWithTier(handler, engine, PremiumTier)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	reqBody := map[string]string{"tier": "enterprise"}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/api/upgrade", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.HandleUpgrade(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	if server.subscription.Tier != EnterpriseTier {
		t.Errorf("Expected EnterpriseTier after upgrade, got %d", server.subscription.Tier)
	}
}

// TestUpgradeInvalidTier tests upgrade with invalid tier
func TestUpgradeInvalidTier(t *testing.T) {
	engine := &DynamicRuleEngine{}
	tunnel := NewNeuralTunnelClient("dummy")
	handler := NewInferenceHandler(engine, tunnel)

	server, err := NewSentinelServerWithTier(handler, engine, FreeTier)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	reqBody := map[string]string{"tier": "invalid_tier"}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/api/upgrade", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.HandleUpgrade(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for invalid tier, got %d", w.Code)
	}
}

// TestBypassLogFreeTier tests that bypass log is forbidden for free tier
func TestBypassLogFreeTier(t *testing.T) {
	engine := &DynamicRuleEngine{}
	tunnel := NewNeuralTunnelClient("dummy")
	handler := NewInferenceHandler(engine, tunnel)

	server, err := NewSentinelServerWithTier(handler, engine, FreeTier)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/bypass_log", nil)
	w := httptest.NewRecorder()

	server.HandleBypassLog(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 for free tier, got %d", w.Code)
	}
}

// TestRecordBypassAttemptFreeTier tests that bypass attempts are not recorded for free tier
func TestRecordBypassAttemptFreeTier(t *testing.T) {
	engine := &DynamicRuleEngine{}
	tunnel := NewNeuralTunnelClient("dummy")
	handler := NewInferenceHandler(engine, tunnel)

	server, err := NewSentinelServerWithTier(handler, engine, FreeTier)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Try to record - should be ignored
	server.RecordBypassAttempt("192.168.1.1", "test", "test", "test", true)

	// Bypass log should be empty
	if len(server.bypassLog) != 0 {
		t.Error("Free tier should not record bypass attempts")
	}
}

// TestProcessRequestBlock tests that blocked queries are caught by rules
func TestProcessRequestBlock(t *testing.T) {
	engine := &DynamicRuleEngine{}
	// Set up a rule that blocks specific patterns
	engine.HotPatch(func(q string) (Verdict, string) {
		if regexp.MustCompile(`DANGEROUS`).MatchString(q) {
			return Block, "blocked_dangerous"
		}
		return Allow, ""
	})
	tunnel := NewNeuralTunnelClient("http://localhost:9999")
	handler := NewInferenceHandler(engine, tunnel)

	// Test that dangerous queries are blocked before reaching tunnel
	verdict, rewritten, err := handler.ProcessRequest(context.Background(), "DANGEROUS operation")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if verdict != Block {
		t.Errorf("Expected Block for dangerous query, got %v", verdict)
	}
	if rewritten != "blocked_dangerous" {
		t.Errorf("Expected rewritten 'blocked_dangerous', got %q", rewritten)
	}
}

// TestEncryptionDecryptionRoundtrip tests AES encryption/decryption
func TestEncryptionDecryptionRoundtrip(t *testing.T) {
	key := []byte("12345678901234567890123456789012") // 32 bytes
	testCases := []string{
		"",
		"short",
		"a longer test string with special chars: !@#$%^&*()",
		`{"json": "data", "number": 123}`,
	}

	for _, original := range testCases {
		encrypted, err := encryptAES([]byte(original), key)
		if err != nil {
			t.Errorf("Encryption failed for %q: %v", original, err)
			continue
		}

		decrypted, err := decryptAES(encrypted, key)
		if err != nil {
			t.Errorf("Decryption failed for %q: %v", original, err)
			continue
		}

		if string(decrypted) != original {
			t.Errorf("Roundtrip failed: expected %q, got %q", original, string(decrypted))
		}
	}
}

// TestDecryptAESInvalidData tests decryption with invalid data
func TestDecryptAESInvalidData(t *testing.T) {
	key := []byte("12345678901234567890123456789012")

	// Too short data (less than IV size)
	_, err := decryptAES([]byte("short"), key)
	if err == nil {
		t.Error("Expected error for short ciphertext")
	}
}

// TestHandleKeyExchangeInvalidMethod tests key exchange with wrong HTTP method
func TestHandleKeyExchangeInvalidMethod(t *testing.T) {
	engine := &DynamicRuleEngine{}
	tunnel := NewNeuralTunnelClient("dummy")
	handler := NewInferenceHandler(engine, tunnel)

	server, err := NewSentinelServer(handler, engine)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/key_exchange", nil)
	w := httptest.NewRecorder()

	server.HandleKeyExchange(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}

// TestHandleKeyExchangeInvalidJSON tests key exchange with invalid JSON
func TestHandleKeyExchangeInvalidJSON(t *testing.T) {
	engine := &DynamicRuleEngine{}
	tunnel := NewNeuralTunnelClient("dummy")
	handler := NewInferenceHandler(engine, tunnel)

	server, err := NewSentinelServer(handler, engine)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/key_exchange", bytes.NewReader([]byte("invalid json")))
	w := httptest.NewRecorder()

	server.HandleKeyExchange(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

// TestHandleHotPatchInvalidMethod tests hot patch with wrong HTTP method
func TestHandleHotPatchInvalidMethod(t *testing.T) {
	engine := &DynamicRuleEngine{}
	tunnel := NewNeuralTunnelClient("dummy")
	handler := NewInferenceHandler(engine, tunnel)

	server, err := NewSentinelServer(handler, engine)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/hot_patch", nil)
	w := httptest.NewRecorder()

	server.HandleHotPatch(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}

// TestHandleHotPatchInvalidJSON tests hot patch with invalid JSON
func TestHandleHotPatchInvalidJSON(t *testing.T) {
	engine := &DynamicRuleEngine{}
	tunnel := NewNeuralTunnelClient("dummy")
	handler := NewInferenceHandler(engine, tunnel)

	server, err := NewSentinelServer(handler, engine)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/hot_patch", bytes.NewReader([]byte("not json")))
	w := httptest.NewRecorder()

	server.HandleHotPatch(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

// TestHandlePublicKeyMultipleCalls tests that public key is consistent
func TestHandlePublicKeyMultipleCalls(t *testing.T) {
	engine := &DynamicRuleEngine{}
	tunnel := NewNeuralTunnelClient("dummy")
	handler := NewInferenceHandler(engine, tunnel)

	server, err := NewSentinelServer(handler, engine)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// First call
	req1 := httptest.NewRequest(http.MethodGet, "/api/public_key", nil)
	w1 := httptest.NewRecorder()
	server.HandlePublicKey(w1, req1)

	var resp1 PublicKeyResponse
	json.NewDecoder(w1.Body).Decode(&resp1)

	// Second call - should return same key
	req2 := httptest.NewRequest(http.MethodGet, "/api/public_key", nil)
	w2 := httptest.NewRecorder()
	server.HandlePublicKey(w2, req2)

	var resp2 PublicKeyResponse
	json.NewDecoder(w2.Body).Decode(&resp2)

	if resp1.PublicKey != resp2.PublicKey {
		t.Error("Public key should be consistent across calls")
	}
}

// TestHandleUpgradeInvalidMethod tests upgrade with wrong HTTP method
func TestHandleUpgradeInvalidMethod(t *testing.T) {
	engine := &DynamicRuleEngine{}
	tunnel := NewNeuralTunnelClient("dummy")
	handler := NewInferenceHandler(engine, tunnel)

	server, err := NewSentinelServer(handler, engine)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/upgrade", nil)
	w := httptest.NewRecorder()

	server.HandleUpgrade(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}

// TestHandleUpgradeInvalidJSON tests upgrade with invalid JSON
func TestHandleUpgradeInvalidJSON(t *testing.T) {
	engine := &DynamicRuleEngine{}
	tunnel := NewNeuralTunnelClient("dummy")
	handler := NewInferenceHandler(engine, tunnel)

	server, err := NewSentinelServer(handler, engine)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/upgrade", bytes.NewReader([]byte("bad json")))
	w := httptest.NewRecorder()

	server.HandleUpgrade(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

// TestMultipleBypassAttempts tests recording multiple bypass attempts
func TestMultipleBypassAttempts(t *testing.T) {
	engine := &DynamicRuleEngine{}
	tunnel := NewNeuralTunnelClient("dummy")
	handler := NewInferenceHandler(engine, tunnel)

	server, err := NewSentinelServerWithTier(handler, engine, EnterpriseTier)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Record multiple attempts
	for i := 0; i < 5; i++ {
		server.RecordBypassAttempt("192.168.1.1", "query", "method", "desc", true)
	}

	if len(server.bypassLog) != 5 {
		t.Errorf("Expected 5 bypass attempts, got %d", len(server.bypassLog))
	}
}

// TestTokenizeQueryEmpty tests tokenizing empty query
func TestTokenizeQueryEmpty(t *testing.T) {
	buffer := make([]byte, 0, 1024)
	tokens := tokenizeQuery("", buffer)
	// Empty string produces one empty token with strings.Fields behavior
	if len(tokens) > 1 {
		t.Errorf("Expected at most 1 token for empty query, got %d", len(tokens))
	}
}

// TestTokenizeQuerySpecialChars tests tokenizing with special characters
func TestTokenizeQuerySpecialChars(t *testing.T) {
	buffer := make([]byte, 0, 1024)
	tokens := tokenizeQuery("SELECT * FROM users WHERE id=1", buffer)
	if len(tokens) < 5 {
		t.Errorf("Expected at least 5 tokens, got %d", len(tokens))
	}
}

// TestEnterpriseTierFeatures tests enterprise tier has all features
func TestEnterpriseTierFeatures(t *testing.T) {
	engine := &DynamicRuleEngine{}
	tunnel := NewNeuralTunnelClient("dummy")
	handler := NewInferenceHandler(engine, tunnel)

	server, err := NewSentinelServerWithTier(handler, engine, EnterpriseTier)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	if !server.subscription.NeuralAnalysis {
		t.Error("Enterprise tier should have NeuralAnalysis")
	}
	if !server.subscription.StealthMonitoring {
		t.Error("Enterprise tier should have StealthMonitoring")
	}
	if !server.subscription.CustomRules {
		t.Error("Enterprise tier should have CustomRules")
	}
	if !server.subscription.PrioritySupport {
		t.Error("Enterprise tier should have PrioritySupport")
	}
}

// TestSendFingerprintSuccess tests sending fingerprint to a mock server
func TestSendFingerprintSuccess(t *testing.T) {
	// Create mock server that returns OK
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "ok",
			"verdict": "Allow",
		})
	}))
	defer mockServer.Close()

	tunnel := NewNeuralTunnelClient(mockServer.URL)
	snapshot := InferenceSnapshot{
		QueryLength: 100,
		TokenCount:  5,
		Hash:        "abc123",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	verdict, err := tunnel.SendFingerprint(ctx, snapshot)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if verdict != Allow {
		t.Errorf("Expected Allow verdict, got %v", verdict)
	}
}

// TestSendFingerprintServerError tests sending fingerprint when server returns error
func TestSendFingerprintServerError(t *testing.T) {
	// Create mock server that returns error
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer mockServer.Close()

	tunnel := NewNeuralTunnelClient(mockServer.URL)
	snapshot := InferenceSnapshot{
		QueryLength: 100,
		TokenCount:  5,
		Hash:        "abc123",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	verdict, err := tunnel.SendFingerprint(ctx, snapshot)
	if err == nil {
		t.Error("Expected error for server error response")
	}
	if verdict != Block {
		t.Errorf("Expected Block verdict on error, got %v", verdict)
	}
}

// TestSendFingerprintToNEUSSuccess tests sending fingerprint to NEUS
func TestSendFingerprintToNEUSSuccess(t *testing.T) {
	// Create mock NEUS server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/sentinel/fingerprint" {
			t.Errorf("Unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "analyzed",
			"verdict": "Allow",
		})
	}))
	defer mockServer.Close()

	tunnel := NewNeuralTunnelClient("dummy")
	snapshot := InferenceSnapshot{
		QueryLength: 50,
		TokenCount:  3,
		Hash:        "xyz789",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	verdict, err := tunnel.SendFingerprintToNEUS(ctx, snapshot, "test-client", mockServer.URL)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if verdict != Allow {
		t.Errorf("Expected Allow verdict, got %v", verdict)
	}
}

// TestSendFingerprintToNEUSBlock tests NEUS detecting a threat
func TestSendFingerprintToNEUSBlock(t *testing.T) {
	// Create mock NEUS server that detects threat
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "threat_detected",
			"verdict": "Block",
		})
	}))
	defer mockServer.Close()

	tunnel := NewNeuralTunnelClient("dummy")
	snapshot := InferenceSnapshot{
		QueryLength: 50,
		TokenCount:  3,
		Hash:        "malicious",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	verdict, err := tunnel.SendFingerprintToNEUS(ctx, snapshot, "test-client", mockServer.URL)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if verdict != Block {
		t.Errorf("Expected Block verdict for threat, got %v", verdict)
	}
}

// TestSendFingerprintToNEUSConnectionError tests NEUS connection failure
func TestSendFingerprintToNEUSConnectionError(t *testing.T) {
	tunnel := NewNeuralTunnelClient("dummy")
	snapshot := InferenceSnapshot{
		QueryLength: 50,
		TokenCount:  3,
		Hash:        "test",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Use invalid URL to trigger connection error
	verdict, err := tunnel.SendFingerprintToNEUS(ctx, snapshot, "test-client", "http://invalid.local:9999")
	if err == nil {
		t.Error("Expected error for connection failure")
	}
	// Should still allow (fail-open)
	if verdict != Allow {
		t.Errorf("Expected Allow verdict on connection error (fail-open), got %v", verdict)
	}
}

// TestSendFingerprintToNEUSNon200 tests NEUS returning non-200 status
func TestSendFingerprintToNEUSNon200(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer mockServer.Close()

	tunnel := NewNeuralTunnelClient("dummy")
	snapshot := InferenceSnapshot{
		QueryLength: 50,
		TokenCount:  3,
		Hash:        "test",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	verdict, _ := tunnel.SendFingerprintToNEUS(ctx, snapshot, "test-client", mockServer.URL)
	// Should allow (fail-open on non-200)
	if verdict != Allow {
		t.Errorf("Expected Allow verdict on non-200 status, got %v", verdict)
	}
}

// TestNewNeuralTunnelClient tests creating a new tunnel client
func TestNewNeuralTunnelClient(t *testing.T) {
	tunnel := NewNeuralTunnelClient("http://test.endpoint")
	if tunnel == nil {
		t.Error("Expected non-nil tunnel client")
	}
	if tunnel.endpoint != "http://test.endpoint" {
		t.Errorf("Expected endpoint 'http://test.endpoint', got %q", tunnel.endpoint)
	}
	if tunnel.keyPool == nil {
		t.Error("Expected non-nil key pool")
	}
	// Test key pool returns 32-byte key
	key := tunnel.keyPool.Get().([]byte)
	if len(key) != 32 {
		t.Errorf("Expected 32-byte key, got %d bytes", len(key))
	}
}

// TestHandleHotPatchEncrypted tests encrypted hot-patch handling
func TestHandleHotPatchEncrypted(t *testing.T) {
	engine := &DynamicRuleEngine{}
	tunnel := NewNeuralTunnelClient("dummy")
	handler := NewInferenceHandler(engine, tunnel)

	server, err := NewSentinelServer(handler, engine)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Send encrypted hot-patch
	reqBody := map[string]interface{}{
		"client_id":      "test-client",
		"encrypted_data": "base64encrypteddata==",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/hot_patch", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.HandleHotPatch(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(w.Body).Decode(&response)
	if response["status"] != "success" {
		t.Errorf("Expected success status, got %v", response)
	}
}

// TestHandleHotPatchEmptyIndicators tests hot-patch with empty indicators
func TestHandleHotPatchEmptyIndicators(t *testing.T) {
	engine := &DynamicRuleEngine{}
	tunnel := NewNeuralTunnelClient("dummy")
	handler := NewInferenceHandler(engine, tunnel)

	server, err := NewSentinelServer(handler, engine)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	reqBody := HotPatchRequest{
		ThreatType:  "test",
		Indicators:  []string{},
		Severity:    "low",
		Description: "Empty test",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/hot_patch", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.HandleHotPatch(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

// TestProcessRequestWithMockTunnel tests full request processing with mock
func TestProcessRequestWithMockTunnel(t *testing.T) {
	// Create mock server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"verdict": "Allow"})
	}))
	defer mockServer.Close()

	engine := &DynamicRuleEngine{}
	tunnel := NewNeuralTunnelClient(mockServer.URL)
	handler := NewInferenceHandler(engine, tunnel)

	verdict, _, err := handler.ProcessRequest(context.Background(), "SELECT * FROM users")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if verdict != Allow {
		t.Errorf("Expected Allow, got %v", verdict)
	}
}

// TestRecordBypassAttemptOverflow tests bypass log overflow handling
func TestRecordBypassAttemptOverflow(t *testing.T) {
	engine := &DynamicRuleEngine{}
	tunnel := NewNeuralTunnelClient("dummy")
	handler := NewInferenceHandler(engine, tunnel)

	server, err := NewSentinelServerWithTier(handler, engine, EnterpriseTier)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Record more than 1000 attempts to trigger overflow handling
	for i := 0; i < 1005; i++ {
		server.RecordBypassAttempt("192.168.1.1", "query", "method", "desc", true)
	}

	// Should be capped at 1000
	if len(server.bypassLog) > 1000 {
		t.Errorf("Bypass log should be capped at 1000, got %d", len(server.bypassLog))
	}
}

// TestEncryptAESShortKey tests encryption with invalid key
func TestEncryptAESShortKey(t *testing.T) {
	shortKey := []byte("short") // Less than 16 bytes
	_, err := encryptAES([]byte("test data"), shortKey)
	if err == nil {
		t.Error("Expected error for short key")
	}
}

// TestDecryptAESShortKey tests decryption with invalid key
func TestDecryptAESShortKey(t *testing.T) {
	shortKey := []byte("short")
	_, err := decryptAES([]byte("1234567890123456testdata"), shortKey)
	if err == nil {
		t.Error("Expected error for short key")
	}
}

// TestKeyExchangeValidPEM tests key exchange with properly formatted PEM
func TestKeyExchangeValidPEM(t *testing.T) {
	engine := &DynamicRuleEngine{}
	tunnel := NewNeuralTunnelClient("dummy")
	handler := NewInferenceHandler(engine, tunnel)

	server, err := NewSentinelServer(handler, engine)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	reqBody := KeyExchangeRequest{
		ClientID:  "neus_test",
		PublicKey: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\ntest\n-----END PUBLIC KEY-----",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/key_exchange", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.HandleKeyExchange(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

// TestAllTiersHealth tests health endpoint for all tiers
func TestAllTiersHealth(t *testing.T) {
	tiers := []SubscriptionTier{FreeTier, PremiumTier, EnterpriseTier}
	expectedNames := []string{"free", "premium", "enterprise"}

	for i, tier := range tiers {
		engine := &DynamicRuleEngine{}
		tunnel := NewNeuralTunnelClient("dummy")
		handler := NewInferenceHandler(engine, tunnel)

		server, err := NewSentinelServerWithTier(handler, engine, tier)
		if err != nil {
			t.Fatalf("Failed to create server for tier %d: %v", tier, err)
		}

		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()

		server.HandleHealth(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Tier %s: Expected status 200, got %d", expectedNames[i], w.Code)
		}

		var response map[string]interface{}
		json.NewDecoder(w.Body).Decode(&response)

		if response["subscription_tier"] != expectedNames[i] {
			t.Errorf("Expected tier %s, got %v", expectedNames[i], response["subscription_tier"])
		}
	}
}

// TestSubscriptionEndpointAllTiers tests subscription for all tiers
func TestSubscriptionEndpointAllTiers(t *testing.T) {
	tiers := []SubscriptionTier{FreeTier, PremiumTier, EnterpriseTier}
	expectedNames := []string{"free", "premium", "enterprise"}

	for i, tier := range tiers {
		engine := &DynamicRuleEngine{}
		tunnel := NewNeuralTunnelClient("dummy")
		handler := NewInferenceHandler(engine, tunnel)

		server, err := NewSentinelServerWithTier(handler, engine, tier)
		if err != nil {
			t.Fatalf("Failed to create server for tier %d: %v", tier, err)
		}

		req := httptest.NewRequest(http.MethodGet, "/api/subscription", nil)
		w := httptest.NewRecorder()

		server.HandleSubscription(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Tier %s: Expected status 200, got %d", expectedNames[i], w.Code)
		}

		var response map[string]interface{}
		json.NewDecoder(w.Body).Decode(&response)

		if response["tier"] != expectedNames[i] {
			t.Errorf("Expected tier %s, got %v", expectedNames[i], response["tier"])
		}
	}
}
