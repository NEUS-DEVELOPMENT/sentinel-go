package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Configuration Constants
var (
	GATEWAY_URL   = getenv("GATEWAY_URL", "https://your-gateway.neus-platform.io")
	NODE_ID       = getenv("NODE_ID", "node-"+hostname())
	APP_SECRET    = getenv("APP_SECRET", "dev-secret-do-not-use-in-prod")
	SYNC_INTERVAL = getenvInt("SYNC_INTERVAL", 60)
	FIM_INTERVAL  = getenvInt("FIM_INTERVAL", 300) // Default: 5 minutes
)

// System Paths for Integrity Monitoring
var watchedFiles = []string{
	"/etc/passwd",
	"/etc/hosts",
	"/etc/resolv.conf",
}

var fileRegistry = make(map[string]string)
var startTime = time.Now()

// Data Structures
type TelemetryData struct {
	NodeID  string             `json:"node_id"`
	Metrics map[string]float64 `json:"metrics"`
	Status  string             `json:"status"`
}

type SyncResponse struct {
	SyncInterval int     `json:"sync_interval"`
	ConfigUpdate *string `json:"config_payload,omitempty"`
}

// Helpers
func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" { return v }
	return d
}

func getenvInt(k string, d int) int {
	v := os.Getenv(k)
	if v == "" { return d }
	i, err := strconv.Atoi(v)
	if err != nil { return d }
	return i
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}

// File Integrity Monitoring (FIM)
func calculateHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil { return "", err }
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil { return "", err }
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

func runIntegrityCheck() {
	for _, path := range watchedFiles {
		currentHash, err := calculateHash(path)
		if err != nil {
			log.Printf("[ERROR] FIM: Unable to access %s: %v", path, err)
			continue
		}

		if oldHash, exists := fileRegistry[path]; exists {
			if oldHash != currentHash {
				log.Printf("[SECURITY ALERT] Unauthorized modification detected in: %s", path)
			}
		}
		fileRegistry[path] = currentHash
	}
}

// Metrics & Heuristics
func collectMetrics() map[string]float64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	metrics := map[string]float64{
		"cpu_load":     rand.Float64() * 100, // Simulated CPU load
		"memory_usage": float64(m.Alloc) / 1024 / 1024,
		"uptime":       float64(time.Since(startTime).Seconds()),
	}

	// Local Anomaly Detection (Standalone Value)
	if metrics["cpu_load"] > 90.0 {
		log.Printf("[WARN] Standalone Heuristics: High CPU anomaly detected.")
	}
	
	return metrics
}

// Security & Communication
func verifyHS256JWT(token string, secret string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 { return nil, errors.New("invalid token") }

	// Algorithm Enforcement
	headerBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var header map[string]string
	json.Unmarshal(headerBytes, &header)
	if header["alg"] != "HS256" { return nil, errors.New("unsupported algorithm") }

	// Signature Verification
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	expected := mac.Sum(nil)
	signature, _ := base64.RawURLEncoding.DecodeString(parts[2])

	if !hmac.Equal(expected, signature) {
		return nil, errors.New("signature mismatch")
	}

	payloadBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var payload map[string]any
	json.Unmarshal(payloadBytes, &payload)
	return payload, nil
}

func sendTelemetry(data TelemetryData) (*SyncResponse, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	bodyBytes, _ := json.Marshal(data)

	req, _ := http.NewRequest("POST", strings.TrimRight(GATEWAY_URL, "/")+"/api/v1/sync", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil { return nil, err }
	defer resp.Body.Close()

	if resp.StatusCode != 200 { return nil, fmt.Errorf("gateway error: %d", resp.StatusCode) }

	var sr SyncResponse
	json.NewDecoder(resp.Body).Decode(&sr)
	return &sr, nil
}

func decommissionAgent() {
	log.Println("[CRITICAL] Executing remote decommissioning order...")
	exe, _ := os.Executable()
	os.Remove(exe)
	// Platform-specific service stop could be added here
	os.Exit(0)
}

func main() {
	log.Printf("Starting SysTelemetry Agent [%s]", NODE_ID)
	log.Printf("Runtime: %s/%s | FIM Baseline Initialized", runtime.GOOS, runtime.GOARCH)

	// Initialize FIM Baseline
	runIntegrityCheck()

	telemetryTicker := time.NewTicker(time.Duration(SYNC_INTERVAL) * time.Second)
	fimTicker := time.NewTicker(time.Duration(FIM_INTERVAL) * time.Second)

	for {
		select {
		case <-telemetryTicker.C:
			metrics := collectMetrics()
			resp, err := sendTelemetry(TelemetryData{
				NodeID:  NODE_ID,
				Metrics: metrics,
				Status:  "HEALTHY",
			})

			if err == nil {
				if resp.ConfigUpdate != nil {
					payload, vErr := verifyHS256JWT(*resp.ConfigUpdate, APP_SECRET)
					if vErr == nil {
						if data, ok := payload["data"].(map[string]any); ok {
							if opcode, ok := data["opcode"].(string); ok && opcode == "0xDEAD" {
								decommissionAgent()
							}
						}
					}
				}
				// Dynamic Sync Interval update
				if resp.SyncInterval > 0 && resp.SyncInterval != SYNC_INTERVAL {
					SYNC_INTERVAL = resp.SyncInterval
					telemetryTicker.Reset(time.Duration(SYNC_INTERVAL) * time.Second)
				}
			} else {
				log.Printf("Gateway offline. Operating in Standalone Mode.")
			}

		case <-fimTicker.C:
			runIntegrityCheck()
		}
	}
}
