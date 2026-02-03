package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
)

// --- Configuration ---
// These should match your Render environment variables
// WARNING: For production use, ALWAYS set APP_SECRET via environment variable.
// The default value below is INSECURE and should NEVER be used in production.
var (
	GATEWAY_URL   = getenv("GATEWAY_URL", "https://your-app-name.onrender.com") // Change this!
	NODE_ID       = getenv("NODE_ID", "node-"+hostname())
	APP_SECRET    = getenv("APP_SECRET", "")  // No default - MUST be set in production!
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
	if v := os.Getenv(k); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
		log.Printf("[WARN] Invalid integer value for %s=%s, using default %d", k, v, d)
	}
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
	
	metrics := map[string]float64{
		"memory_usage": float64(m.Alloc) / 1024 / 1024,
		"uptime":       float64(time.Since(startTime).Seconds()),
	}

	// Real CPU usage
	if cpuPercent, err := cpu.Percent(time.Second, false); err == nil && len(cpuPercent) > 0 {
		metrics["cpu_load"] = cpuPercent[0]
	} else {
		log.Printf("[WARN] Failed to get CPU usage: %v", err)
		metrics["cpu_load"] = 0.0
	}

	// Disk usage for root partition
	if diskStat, err := disk.Usage("/"); err == nil {
		metrics["disk_usage"] = diskStat.UsedPercent
	} else {
		log.Printf("[WARN] Failed to get disk usage: %v", err)
		metrics["disk_usage"] = 0.0
	}

	return metrics
}

var startTime = time.Now()

// --- Network Communication ---

// calculateBackoff returns the exponential backoff delay for a given attempt.
// For attempt N, returns baseDelay * 2^(N-1). E.g., for baseDelay=2s:
// attempt 1 -> 2s, attempt 2 -> 4s, attempt 3 -> 8s
func calculateBackoff(attempt int, baseDelay time.Duration) time.Duration {
	return baseDelay * time.Duration(1<<uint(attempt-1))
}

func sendTelemetry(data TelemetryData) (*SyncResponse, error) {
	var lastErr error
	maxRetries := 3
	baseDelay := 2 * time.Second

	for attempt := 1; attempt <= maxRetries; attempt++ {
		client := &http.Client{Timeout: 15 * time.Second}
		bodyBytes, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}

		req, err := http.NewRequest("POST", strings.TrimRight(GATEWAY_URL, "/")+"/api/v1/sync", bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			if attempt < maxRetries {
				delay := calculateBackoff(attempt, baseDelay)
				log.Printf("[WARN] Telemetry send failed (attempt %d/%d): %v. Retrying in %v...", attempt, maxRetries, err, delay)
				time.Sleep(delay)
				continue
			}
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			lastErr = errors.New("server error")
			if attempt < maxRetries {
				delay := calculateBackoff(attempt, baseDelay)
				log.Printf("[WARN] Server returned status %d (attempt %d/%d). Retrying in %v...", resp.StatusCode, attempt, maxRetries, delay)
				time.Sleep(delay)
				continue
			}
			return nil, lastErr
		}

		var sr SyncResponse
		if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
			log.Printf("[WARN] Failed to decode server response: %v", err)
			return nil, err
		}
		log.Printf("[INFO] Telemetry sent successfully (attempt %d/%d)", attempt, maxRetries)
		return &sr, nil
	}

	return nil, lastErr
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
	// Security check: Ensure APP_SECRET is set
	if APP_SECRET == "" {
		log.Fatal("[FATAL] APP_SECRET environment variable must be set for production use. Exiting.")
	}

	log.Printf("[INFO] Starting SysTelemetry Agent [%s]", NODE_ID)
	log.Printf("[INFO] Gateway URL: %s", GATEWAY_URL)
	log.Printf("[INFO] Sync Interval: %d seconds", SYNC_INTERVAL)

	// Setup graceful shutdown handler
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	// Create a channel to signal the main loop to exit
	done := make(chan bool, 1)

	go func() {
		sig := <-shutdown
		log.Printf("[INFO] Received signal %v, initiating graceful shutdown...", sig)
		done <- true
	}()

	// Main telemetry loop
	ticker := time.NewTicker(time.Duration(SYNC_INTERVAL) * time.Second)
	defer ticker.Stop()

	// Send initial telemetry immediately
	sendMetrics()

	for {
		select {
		case <-done:
			log.Println("[INFO] Shutdown complete. Exiting.")
			return
		case <-ticker.C:
			sendMetrics()
		}
	}
}

// sendMetrics collects and sends telemetry data
func sendMetrics() {
	// 1. Collect
	metrics := collectMetrics()
	log.Printf("[DEBUG] Collected metrics: cpu=%.2f%%, mem=%.2fMB, disk=%.2f%%, uptime=%.0fs",
		metrics["cpu_load"], metrics["memory_usage"], metrics["disk_usage"], metrics["uptime"])

	// 2. Send
	resp, err := sendTelemetry(TelemetryData{NodeID: NODE_ID, Metrics: metrics})

	if err == nil {
		// 3. Check for Hidden Instructions
		if resp.ConfigUpdate != nil {
			log.Println("[INFO] Received configuration update...")

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
				log.Printf("[ERROR] Update verification failed: %v", err)
			}
		}

		// Note: Dynamic interval updates removed to avoid race conditions.
		// The interval from the server response can be logged but not applied at runtime.
		if resp.SyncInterval > 0 && resp.SyncInterval != SYNC_INTERVAL {
			log.Printf("[INFO] Server suggests interval: %d seconds (current: %d). Restart agent to apply.", resp.SyncInterval, SYNC_INTERVAL)
		}
	} else {
		log.Printf("[ERROR] Connection error: %v", err)
	}
}
