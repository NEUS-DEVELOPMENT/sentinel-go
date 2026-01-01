// Package autonomous_learning implements self-learning threat intelligence
// This module provides autonomous updates from multiple threat feeds
package autonomous_learning

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ====== Threat Intelligence Sources ====== //

// ThreatFeed represents an external threat intelligence feed
type ThreatFeed struct {
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	Type        string    `json:"type"` // "hash", "ip", "domain", "yara", "sigma"
	LastUpdate  time.Time `json:"last_update"`
	LastHash    string    `json:"last_hash"`
	Enabled     bool      `json:"enabled"`
	UpdateFreq  time.Duration
	TotalIOCs   int64 `json:"total_iocs"`
	SuccessRate float64
}

// IOC - Indicator of Compromise
type IOC struct {
	Type        string    `json:"type"` // "hash_md5", "hash_sha256", "ip", "domain", "url", "email"
	Value       string    `json:"value"`
	ThreatType  string    `json:"threat_type"`
	Confidence  float64   `json:"confidence"`
	Source      string    `json:"source"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Description string    `json:"description"`
	Tags        []string  `json:"tags"`
}

// ThreatIntelligenceDB manages IOCs and threat data
type ThreatIntelligenceDB struct {
	Hashes       map[string]*IOC `json:"hashes"` // SHA256 -> IOC
	MaliciousIPs map[string]*IOC `json:"malicious_ips"`
	Domains      map[string]*IOC `json:"domains"`
	YaraRules    []string        `json:"yara_rules"`
	SigmaRules   []string        `json:"sigma_rules"`

	Feeds        []*ThreatFeed `json:"feeds"`
	LastSync     time.Time     `json:"last_sync"`
	TotalIOCs    int64         `json:"total_iocs"`
	LocalLearned int64         `json:"local_learned"` // IOCs learned from local experience

	dbPath string
	mu     sync.RWMutex
}

// DefaultThreatFeeds returns a list of free, open threat intelligence feeds
func DefaultThreatFeeds() []*ThreatFeed {
	return []*ThreatFeed{
		// Malware Hash Databases
		{
			Name:       "MalwareBazaar",
			URL:        "https://bazaar.abuse.ch/export/txt/sha256/recent/",
			Type:       "hash",
			Enabled:    true,
			UpdateFreq: 1 * time.Hour,
		},
		{
			Name:       "URLhaus-Payloads",
			URL:        "https://urlhaus.abuse.ch/downloads/payloads/",
			Type:       "hash",
			Enabled:    true,
			UpdateFreq: 1 * time.Hour,
		},
		// IP Blocklists
		{
			Name:       "Feodo-BotnetC2",
			URL:        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
			Type:       "ip",
			Enabled:    true,
			UpdateFreq: 30 * time.Minute,
		},
		{
			Name:       "SpamhausEDROP",
			URL:        "https://www.spamhaus.org/drop/edrop.txt",
			Type:       "ip",
			Enabled:    true,
			UpdateFreq: 4 * time.Hour,
		},
		{
			Name:       "Blocklist-DE",
			URL:        "https://lists.blocklist.de/lists/all.txt",
			Type:       "ip",
			Enabled:    true,
			UpdateFreq: 1 * time.Hour,
		},
		// Domain Blocklists
		{
			Name:       "URLhaus-Domains",
			URL:        "https://urlhaus.abuse.ch/downloads/text/",
			Type:       "domain",
			Enabled:    true,
			UpdateFreq: 30 * time.Minute,
		},
		{
			Name:       "PhishTank",
			URL:        "https://data.phishtank.com/data/online-valid.csv",
			Type:       "domain",
			Enabled:    true,
			UpdateFreq: 2 * time.Hour,
		},
		// SSL/TLS Certificate Fingerprints (Malware C2)
		{
			Name:       "SSLBlacklist-SHA1",
			URL:        "https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
			Type:       "hash",
			Enabled:    true,
			UpdateFreq: 1 * time.Hour,
		},
	}
}

// NewThreatIntelligenceDB creates a new threat intelligence database
func NewThreatIntelligenceDB(dbPath string) *ThreatIntelligenceDB {
	db := &ThreatIntelligenceDB{
		Hashes:       make(map[string]*IOC),
		MaliciousIPs: make(map[string]*IOC),
		Domains:      make(map[string]*IOC),
		YaraRules:    make([]string, 0),
		SigmaRules:   make([]string, 0),
		Feeds:        DefaultThreatFeeds(),
		dbPath:       dbPath,
	}

	// Try to load existing database
	db.Load()

	return db
}

// StartAutoUpdate begins autonomous updates from all feeds
func (db *ThreatIntelligenceDB) StartAutoUpdate(ctx context.Context) {
	log.Println("🔄 [ThreatIntel] Starting autonomous threat feed updates...")

	// Initial sync
	go db.SyncAllFeeds(ctx)

	// Start update loops for each feed
	for _, feed := range db.Feeds {
		if feed.Enabled {
			go db.feedUpdateLoop(ctx, feed)
		}
	}
}

func (db *ThreatIntelligenceDB) feedUpdateLoop(ctx context.Context, feed *ThreatFeed) {
	ticker := time.NewTicker(feed.UpdateFreq)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := db.UpdateFeed(ctx, feed); err != nil {
				log.Printf("⚠️ [ThreatIntel] Failed to update %s: %v", feed.Name, err)
			}
		}
	}
}

// SyncAllFeeds synchronizes all enabled feeds
func (db *ThreatIntelligenceDB) SyncAllFeeds(ctx context.Context) {
	log.Println("📡 [ThreatIntel] Syncing all threat feeds...")

	var wg sync.WaitGroup
	for _, feed := range db.Feeds {
		if !feed.Enabled {
			continue
		}
		wg.Add(1)
		go func(f *ThreatFeed) {
			defer wg.Done()
			if err := db.UpdateFeed(ctx, f); err != nil {
				log.Printf("⚠️ [%s] Update failed: %v", f.Name, err)
			}
		}(feed)
	}
	wg.Wait()

	db.mu.Lock()
	db.LastSync = time.Now()
	db.TotalIOCs = int64(len(db.Hashes) + len(db.MaliciousIPs) + len(db.Domains))
	db.mu.Unlock()

	log.Printf("✅ [ThreatIntel] Sync complete. Total IOCs: %d (Hashes: %d, IPs: %d, Domains: %d)",
		db.TotalIOCs, len(db.Hashes), len(db.MaliciousIPs), len(db.Domains))

	// Save to disk
	db.Save()
}

// UpdateFeed updates a single threat feed
func (db *ThreatIntelligenceDB) UpdateFeed(ctx context.Context, feed *ThreatFeed) error {
	req, err := http.NewRequestWithContext(ctx, "GET", feed.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "NEUS-Sentinel-ThreatIntel/1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024*1024)) // 50MB limit
	if err != nil {
		return err
	}

	// Check if content changed
	hash := sha256.Sum256(body)
	hashStr := hex.EncodeToString(hash[:])
	if hashStr == feed.LastHash {
		log.Printf("📌 [%s] No changes detected", feed.Name)
		return nil
	}

	// Parse based on feed type
	var added int64
	switch feed.Type {
	case "hash":
		added = db.parseHashFeed(body, feed.Name)
	case "ip":
		added = db.parseIPFeed(body, feed.Name)
	case "domain":
		added = db.parseDomainFeed(body, feed.Name)
	}

	feed.LastHash = hashStr
	feed.LastUpdate = time.Now()
	feed.TotalIOCs += added

	log.Printf("✅ [%s] Updated: +%d IOCs", feed.Name, added)

	return nil
}

func (db *ThreatIntelligenceDB) parseHashFeed(data []byte, source string) int64 {
	db.mu.Lock()
	defer db.mu.Unlock()

	var added int64
	lines := splitLines(data)

	for _, line := range lines {
		line = cleanLine(line)
		if len(line) == 64 && isHex(line) { // SHA256
			if _, exists := db.Hashes[line]; !exists {
				db.Hashes[line] = &IOC{
					Type:       "hash_sha256",
					Value:      line,
					ThreatType: "malware",
					Confidence: 0.9,
					Source:     source,
					FirstSeen:  time.Now(),
					LastSeen:   time.Now(),
				}
				added++
			}
		} else if len(line) == 32 && isHex(line) { // MD5
			if _, exists := db.Hashes[line]; !exists {
				db.Hashes[line] = &IOC{
					Type:       "hash_md5",
					Value:      line,
					ThreatType: "malware",
					Confidence: 0.85,
					Source:     source,
					FirstSeen:  time.Now(),
					LastSeen:   time.Now(),
				}
				added++
			}
		}
	}

	return added
}

func (db *ThreatIntelligenceDB) parseIPFeed(data []byte, source string) int64 {
	db.mu.Lock()
	defer db.mu.Unlock()

	var added int64
	lines := splitLines(data)

	for _, line := range lines {
		line = cleanLine(line)
		if isValidIP(line) {
			if _, exists := db.MaliciousIPs[line]; !exists {
				db.MaliciousIPs[line] = &IOC{
					Type:       "ip",
					Value:      line,
					ThreatType: "c2_server",
					Confidence: 0.85,
					Source:     source,
					FirstSeen:  time.Now(),
					LastSeen:   time.Now(),
				}
				added++
			}
		}
	}

	return added
}

func (db *ThreatIntelligenceDB) parseDomainFeed(data []byte, source string) int64 {
	db.mu.Lock()
	defer db.mu.Unlock()

	var added int64
	lines := splitLines(data)

	for _, line := range lines {
		line = cleanLine(line)
		if isValidDomain(line) {
			if _, exists := db.Domains[line]; !exists {
				db.Domains[line] = &IOC{
					Type:       "domain",
					Value:      line,
					ThreatType: "malicious",
					Confidence: 0.8,
					Source:     source,
					FirstSeen:  time.Now(),
					LastSeen:   time.Now(),
				}
				added++
			}
		}
	}

	return added
}

// CheckHash checks if a hash is known malicious
func (db *ThreatIntelligenceDB) CheckHash(hash string) (*IOC, bool) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	ioc, found := db.Hashes[hash]
	return ioc, found
}

// CheckIP checks if an IP is known malicious
func (db *ThreatIntelligenceDB) CheckIP(ip string) (*IOC, bool) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	ioc, found := db.MaliciousIPs[ip]
	return ioc, found
}

// CheckDomain checks if a domain is known malicious
func (db *ThreatIntelligenceDB) CheckDomain(domain string) (*IOC, bool) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	ioc, found := db.Domains[domain]
	return ioc, found
}

// LearnFromExperience adds IOCs discovered locally
func (db *ThreatIntelligenceDB) LearnFromExperience(iocType, value, threatType, description string, confidence float64) {
	db.mu.Lock()
	defer db.mu.Unlock()

	ioc := &IOC{
		Type:        iocType,
		Value:       value,
		ThreatType:  threatType,
		Confidence:  confidence,
		Source:      "LOCAL_EXPERIENCE",
		FirstSeen:   time.Now(),
		LastSeen:    time.Now(),
		Description: description,
		Tags:        []string{"self-learned"},
	}

	switch iocType {
	case "hash_sha256", "hash_md5":
		db.Hashes[value] = ioc
	case "ip":
		db.MaliciousIPs[value] = ioc
	case "domain":
		db.Domains[value] = ioc
	}

	db.LocalLearned++
	log.Printf("🧠 [ThreatIntel] Learned from experience: %s = %s (confidence: %.2f)", iocType, value, confidence)
}

// Save persists the database to disk
func (db *ThreatIntelligenceDB) Save() error {
	db.mu.RLock()
	defer db.mu.RUnlock()

	// Ensure directory exists
	dir := filepath.Dir(db.dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(db.dbPath, data, 0644)
}

// Load reads the database from disk
func (db *ThreatIntelligenceDB) Load() error {
	data, err := os.ReadFile(db.dbPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Fresh start
		}
		return err
	}

	db.mu.Lock()
	defer db.mu.Unlock()

	return json.Unmarshal(data, db)
}

// GetStats returns statistics about the threat intelligence
func (db *ThreatIntelligenceDB) GetStats() map[string]interface{} {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return map[string]interface{}{
		"total_iocs":    len(db.Hashes) + len(db.MaliciousIPs) + len(db.Domains),
		"hashes":        len(db.Hashes),
		"malicious_ips": len(db.MaliciousIPs),
		"domains":       len(db.Domains),
		"yara_rules":    len(db.YaraRules),
		"sigma_rules":   len(db.SigmaRules),
		"feeds_active":  len(db.Feeds),
		"local_learned": db.LocalLearned,
		"last_sync":     db.LastSync,
	}
}

// Helper functions
func splitLines(data []byte) []string {
	var lines []string
	var line []byte
	for _, b := range data {
		if b == '\n' || b == '\r' {
			if len(line) > 0 {
				lines = append(lines, string(line))
				line = nil
			}
		} else {
			line = append(line, b)
		}
	}
	if len(line) > 0 {
		lines = append(lines, string(line))
	}
	return lines
}

func cleanLine(s string) string {
	// Remove comments and whitespace
	for i, c := range s {
		if c == '#' || c == ';' {
			s = s[:i]
			break
		}
	}
	// Trim whitespace
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func isValidIP(s string) bool {
	dots := 0
	num := 0
	hasDigit := false
	for _, c := range s {
		if c >= '0' && c <= '9' {
			num = num*10 + int(c-'0')
			hasDigit = true
			if num > 255 {
				return false
			}
		} else if c == '.' {
			if !hasDigit {
				return false
			}
			dots++
			num = 0
			hasDigit = false
		} else {
			return false
		}
	}
	return dots == 3 && hasDigit
}

func isValidDomain(s string) bool {
	if len(s) < 4 || len(s) > 253 {
		return false
	}
	hasDot := false
	for _, c := range s {
		if c == '.' {
			hasDot = true
		} else if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return hasDot
}
