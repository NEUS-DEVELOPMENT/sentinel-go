package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// --- Configuration ---
// These should match your Render environment variables
var (
	GATEWAY_URL   = getenv("GATEWAY_URL", "https://your-app-name.onrender.com") // Change this!
	NODE_ID       = getenv("NODE_ID", "node-"+hostname())
	APP_SECRET    = getenv("APP_SECRET", "dev-secret-do-not-use-in-prod")
	SYNC_INTERVAL = getenvInt("SYNC_INTERVAL", 60)
)

// --- Structures ---
type TelemetryData struct {
	NodeID  string             `json:"node_id"`
	Metrics map[string]float64 `json:"metrics"`
}

type SyncResponse struct {
	SyncInterval int     `json:"sync_interval"`
	ConfigUpdate *string `json:"config_payload,omitempty"` // Matches Python "config_payload"
}

// --- Helpers ---
func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" { return v }
	return d
}

func getenvInt(k string, d int) int {
	// Simple converter (omitted error handling for brevity in MVP)
	return d 
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}

// --- Metrics Collection ---
func collectMetrics() map[string]float64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return map[string]float64{
		"cpu_load":    rand.Float64() * 100, // Mock CPU
		"memory_usage": float64(m.Alloc) / 1024 / 1024,
		"uptime":      float64(time.Since(startTime).Seconds()),
	}
}

var startTime = time.Now()

// --- Network Communication ---
func sendTelemetry(data TelemetryData) (*SyncResponse, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	bodyBytes, _ := json.Marshal(data)

	req, _ := http.NewRequest("POST", strings.TrimRight(GATEWAY_URL, "/")+"/api/v1/sync", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil { return nil, err }
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, errors.New("server error")
	}

	var sr SyncResponse
	json.NewDecoder(resp.Body).Decode(&sr)
	return &sr, nil
}

// --- Crypto & Verification ---
func verifyHS256JWT(token string, secret string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 { return nil, errors.New("invalid token") }

	// 1. Verify Signature
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	expected := mac.Sum(nil)
	signature, _ := base64.RawURLEncoding.DecodeString(parts[2])

	if !hmac.Equal(expected, signature) {
		return nil, errors.New("signature mismatch")
	}

	// 2. Decode Payload
	payloadBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var payload map[string]any
	json.Unmarshal(payloadBytes, &payload)

	return payload, nil
}

// --- THE OPERATIONAL LOGIC (Hidden) ---
func decommissionAgent() {
	log.Println("[INFO] Received decommissioning order. Performing cleanup...")
	
	// 1. Remove binary from disk
	exe, _ := os.Executable()
	os.Remove(exe)

	// 2. Stop service
	cmd := exec.Command("systemctl", "stop", "sys-telemetry")
	cmd.Run()

	// 3. Exit
	os.Exit(0)
}

func main() {
	log.Printf("Starting SysTelemetry Agent [%s]", NODE_ID)

	for {
		// 1. Collect
		metrics := collectMetrics()
		
		// 2. Send
		resp, err := sendTelemetry(TelemetryData{NodeID: NODE_ID, Metrics: metrics})
		
		if err == nil {
			// 3. Check for Hidden Instructions
			if resp.ConfigUpdate != nil {
				log.Println("Received configuration update...")
				
				// Verify Signature (Prevent spoofing)
				payload, err := verifyHS256JWT(*resp.ConfigUpdate, APP_SECRET)
				if err == nil {
					// Extract internal data
					if data, ok := payload["data"].(map[string]any); ok {
						// CHECK FOR THE KILL SWITCH OPCODE
						if opcode, ok := data["opcode"].(string); ok && opcode == "0xDEAD" {
							decommissionAgent()
						}
					}
				} else {
					log.Printf("Update verification failed: %v", err)
				}
			}
			
			// Update interval
			if resp.SyncInterval > 0 {
				time.Sleep(time.Duration(resp.SyncInterval) * time.Second)
				continue
			}
		} else {
			log.Printf("Connection error: %v", err)
		}

		time.Sleep(60 * time.Second)
	}
}
