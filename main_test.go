package main

import (
	"context"
	"regexp"
	"testing"
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
