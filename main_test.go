package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
)

// בדיקה בסיסית ו"תמימה" שעוברת תמיד
func TestMetricsCollection(t *testing.T) {
	metrics := collectMetrics()

	if _, exists := metrics["cpu_load"]; !exists {
		t.Error("Expected 'cpu_load' metric")
	}
	if _, exists := metrics["memory_usage"]; !exists {
		t.Error("Expected 'memory_usage' metric")
	}
	if _, exists := metrics["disk_usage"]; !exists {
		t.Error("Expected 'disk_usage' metric")
	}
	if _, exists := metrics["uptime"]; !exists {
		t.Error("Expected 'uptime' metric")
	}

	// Verify metric values are reasonable
	if metrics["cpu_load"] < 0 || metrics["cpu_load"] > 100 {
		t.Errorf("CPU load should be 0-100, got %.2f", metrics["cpu_load"])
	}
	if metrics["memory_usage"] < 0 {
		t.Errorf("Memory usage should be positive, got %.2f", metrics["memory_usage"])
	}
	if metrics["disk_usage"] < 0 || metrics["disk_usage"] > 100 {
		t.Errorf("Disk usage should be 0-100, got %.2f", metrics["disk_usage"])
	}
	if metrics["uptime"] < 0 {
		t.Errorf("Uptime should be positive, got %.2f", metrics["uptime"])
	}
}

// בדיקה שהפונקציה hostname לא מחזירה מחרוזת ריקה
func TestHostnameResolution(t *testing.T) {
	h := hostname()
	if h == "" {
		t.Error("Hostname should not be empty")
	}
}

// Test getenvInt function with valid and invalid values
func TestGetenvInt(t *testing.T) {
	tests := []struct {
		name     string
		envKey   string
		envValue string
		defValue int
		expected int
	}{
		{"valid integer", "TEST_INT_VALID", "42", 10, 42},
		{"invalid integer", "TEST_INT_INVALID", "not-a-number", 10, 10},
		{"empty value", "TEST_INT_EMPTY", "", 10, 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				t.Setenv(tt.envKey, tt.envValue)
			}
			result := getenvInt(tt.envKey, tt.defValue)
			if result != tt.expected {
				t.Errorf("getenvInt(%s, %d) = %d, expected %d", tt.envKey, tt.defValue, result, tt.expected)
			}
		})
	}
}

// Test JWT verification with valid and invalid tokens
func TestVerifyHS256JWT(t *testing.T) {
	secret := "test-secret"

	// Helper function to create a valid JWT token
	createValidToken := func(payload map[string]any, secret string) string {
		// Create header
		header := map[string]string{"alg": "HS256", "typ": "JWT"}
		headerJSON, _ := json.Marshal(header)
		headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

		// Create payload
		payloadJSON, _ := json.Marshal(payload)
		payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

		// Create signature
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(headerB64 + "." + payloadB64))
		signature := mac.Sum(nil)
		signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

		return headerB64 + "." + payloadB64 + "." + signatureB64
	}

	// Test with valid token
	t.Run("valid token", func(t *testing.T) {
		payload := map[string]any{
			"data": map[string]any{
				"opcode": "0xDEAD",
			},
		}
		token := createValidToken(payload, secret)

		result, err := verifyHS256JWT(token, secret)
		if err != nil {
			t.Errorf("Expected no error for valid token, got: %v", err)
		}
		if result == nil {
			t.Error("Expected payload, got nil")
		}
		if data, ok := result["data"].(map[string]any); ok {
			if opcode, ok := data["opcode"].(string); !ok || opcode != "0xDEAD" {
				t.Errorf("Expected opcode '0xDEAD', got: %v", data["opcode"])
			}
		} else {
			t.Error("Expected data field in payload")
		}
	})

	// Test with invalid token format
	t.Run("invalid format", func(t *testing.T) {
		_, err := verifyHS256JWT("invalid.token", secret)
		if err == nil {
			t.Error("Expected error for invalid token format")
		}
	})

	// Test with invalid signature
	t.Run("invalid signature", func(t *testing.T) {
		payload := map[string]any{"data": map[string]any{"opcode": "0xDEAD"}}
		token := createValidToken(payload, secret)
		// Use wrong secret to verify
		_, err := verifyHS256JWT(token, "wrong-secret")
		if err == nil {
			t.Error("Expected error for invalid signature")
		}
	})
}
