// Package autonomous_learning implements behavioral learning engine
// This module learns from observed behaviors to detect anomalies
package autonomous_learning

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// ====== Behavioral Learning Engine ====== //

// ProcessBehavior represents learned process behavior patterns
type ProcessBehavior struct {
	ProcessName    string `json:"process_name"`
	ExecutablePath string `json:"executable_path"`
	ExecutableHash string `json:"executable_hash"`

	// Learned patterns
	NormalPorts     []int           `json:"normal_ports"`     // Ports it normally uses
	NormalDomains   []string        `json:"normal_domains"`   // Domains it normally connects to
	NormalFiles     []string        `json:"normal_files"`     // Files it normally accesses
	NormalChildren  []string        `json:"normal_children"`  // Child processes it normally spawns
	NormalResources ResourceProfile `json:"normal_resources"` // Normal resource usage
	NormalSchedule  []TimeWindow    `json:"normal_schedule"`  // When it normally runs

	// Statistics
	ObservationCount int64     `json:"observation_count"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
	TrustScore       float64   `json:"trust_score"`
	AnomalyCount     int64     `json:"anomaly_count"`

	// Heuristic weights learned over time
	Weights BehaviorWeights `json:"weights"`
}

// ResourceProfile defines normal resource usage
type ResourceProfile struct {
	AvgCPU       float64 `json:"avg_cpu"`
	MaxCPU       float64 `json:"max_cpu"`
	AvgMemoryMB  float64 `json:"avg_memory_mb"`
	MaxMemoryMB  float64 `json:"max_memory_mb"`
	AvgDiskIO    float64 `json:"avg_disk_io"`
	AvgNetworkIO float64 `json:"avg_network_io"`
}

// TimeWindow represents when a process normally runs
type TimeWindow struct {
	DayOfWeek int  `json:"day_of_week"` // 0=Sunday, 6=Saturday
	HourStart int  `json:"hour_start"`
	HourEnd   int  `json:"hour_end"`
	IsNormal  bool `json:"is_normal"`
}

// BehaviorWeights are learned weights for anomaly detection
type BehaviorWeights struct {
	NetworkWeight    float64 `json:"network_weight"`
	FileAccessWeight float64 `json:"file_access_weight"`
	ResourceWeight   float64 `json:"resource_weight"`
	ScheduleWeight   float64 `json:"schedule_weight"`
	ChildProcWeight  float64 `json:"child_proc_weight"`
}

// BehaviorEvent represents an observed behavior
type BehaviorEvent struct {
	Timestamp    time.Time `json:"timestamp"`
	ProcessName  string    `json:"process_name"`
	ProcessPath  string    `json:"process_path"`
	EventType    string    `json:"event_type"` // "network", "file", "registry", "process", "resource"
	Details      string    `json:"details"`
	TargetPort   int       `json:"target_port,omitempty"`
	TargetDomain string    `json:"target_domain,omitempty"`
	TargetFile   string    `json:"target_file,omitempty"`
	ChildProcess string    `json:"child_process,omitempty"`
	CPUPercent   float64   `json:"cpu_percent,omitempty"`
	MemoryMB     float64   `json:"memory_mb,omitempty"`
}

// AnomalyResult represents detected anomaly
type AnomalyResult struct {
	Timestamp         time.Time `json:"timestamp"`
	ProcessName       string    `json:"process_name"`
	AnomalyType       string    `json:"anomaly_type"`
	Description       string    `json:"description"`
	Severity          float64   `json:"severity"`   // 0-1
	Confidence        float64   `json:"confidence"` // 0-1
	RecommendedAction string    `json:"recommended_action"`
}

// BehaviorLearningEngine learns and detects behavioral anomalies
type BehaviorLearningEngine struct {
	Behaviors      map[string]*ProcessBehavior `json:"behaviors"`
	GlobalBaseline *SystemBaseline             `json:"global_baseline"`

	// Real-time analysis
	recentEvents []BehaviorEvent
	anomalies    []AnomalyResult

	// Configuration
	LearningRate     float64 `json:"learning_rate"`
	AnomalyThreshold float64 `json:"anomaly_threshold"`
	TrustDecayRate   float64 `json:"trust_decay_rate"`

	dbPath string
	mu     sync.RWMutex
}

// SystemBaseline represents the overall system normal state
type SystemBaseline struct {
	AvgProcessCount    float64   `json:"avg_process_count"`
	AvgNetworkConns    float64   `json:"avg_network_connections"`
	NormalServices     []string  `json:"normal_services"`
	NormalStartupProcs []string  `json:"normal_startup_procs"`
	BaselineTime       time.Time `json:"baseline_time"`
	Observations       int64     `json:"observations"`
}

// NewBehaviorLearningEngine creates a new behavioral learning engine
func NewBehaviorLearningEngine(dbPath string) *BehaviorLearningEngine {
	engine := &BehaviorLearningEngine{
		Behaviors:        make(map[string]*ProcessBehavior),
		GlobalBaseline:   &SystemBaseline{},
		recentEvents:     make([]BehaviorEvent, 0),
		anomalies:        make([]AnomalyResult, 0),
		LearningRate:     0.1,
		AnomalyThreshold: 0.7,
		TrustDecayRate:   0.01,
		dbPath:           dbPath,
	}

	// Load existing learned data
	engine.Load()

	return engine
}

// ObserveEvent processes a new behavioral event and learns from it
func (e *BehaviorLearningEngine) ObserveEvent(event BehaviorEvent) *AnomalyResult {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Get or create process behavior profile
	key := e.processKey(event.ProcessName, event.ProcessPath)
	behavior, exists := e.Behaviors[key]

	if !exists {
		// New process - create profile
		behavior = &ProcessBehavior{
			ProcessName:    event.ProcessName,
			ExecutablePath: event.ProcessPath,
			NormalPorts:    make([]int, 0),
			NormalDomains:  make([]string, 0),
			NormalFiles:    make([]string, 0),
			NormalChildren: make([]string, 0),
			FirstSeen:      event.Timestamp,
			TrustScore:     0.5, // Start neutral
			Weights:        DefaultBehaviorWeights(),
		}
		e.Behaviors[key] = behavior
	}

	behavior.LastSeen = event.Timestamp
	behavior.ObservationCount++

	// Check for anomaly
	var anomaly *AnomalyResult
	if behavior.ObservationCount > 10 { // Need enough data to detect anomalies
		anomaly = e.checkAnomaly(behavior, event)
	}

	// Learn from event (update profile)
	e.learnFromEvent(behavior, event)

	// Store recent event
	e.recentEvents = append(e.recentEvents, event)
	if len(e.recentEvents) > 10000 {
		e.recentEvents = e.recentEvents[1000:] // Keep last 9000
	}

	// Store anomaly if detected
	if anomaly != nil {
		e.anomalies = append(e.anomalies, *anomaly)
		behavior.AnomalyCount++
		behavior.TrustScore -= 0.1 // Decrease trust on anomaly
		if behavior.TrustScore < 0 {
			behavior.TrustScore = 0
		}
	} else {
		// Normal behavior increases trust
		behavior.TrustScore += e.LearningRate * 0.01
		if behavior.TrustScore > 1 {
			behavior.TrustScore = 1
		}
	}

	return anomaly
}

// checkAnomaly checks if the event is anomalous
func (e *BehaviorLearningEngine) checkAnomaly(behavior *ProcessBehavior, event BehaviorEvent) *AnomalyResult {
	anomalyScore := 0.0
	var reasons []string

	switch event.EventType {
	case "network":
		if event.TargetPort > 0 && !containsInt(behavior.NormalPorts, event.TargetPort) {
			// New port - check if suspicious
			if isSuspiciousPort(event.TargetPort) {
				anomalyScore += behavior.Weights.NetworkWeight * 0.8
				reasons = append(reasons, "unusual network port")
			} else {
				anomalyScore += behavior.Weights.NetworkWeight * 0.3
			}
		}
		if event.TargetDomain != "" && !containsString(behavior.NormalDomains, event.TargetDomain) {
			anomalyScore += behavior.Weights.NetworkWeight * 0.4
			reasons = append(reasons, "new domain connection")
		}

	case "file":
		if event.TargetFile != "" {
			if isSensitivePath(event.TargetFile) && !containsString(behavior.NormalFiles, event.TargetFile) {
				anomalyScore += behavior.Weights.FileAccessWeight * 0.9
				reasons = append(reasons, "sensitive file access")
			}
		}

	case "process":
		if event.ChildProcess != "" && !containsString(behavior.NormalChildren, event.ChildProcess) {
			if isSuspiciousChild(event.ChildProcess) {
				anomalyScore += behavior.Weights.ChildProcWeight * 0.85
				reasons = append(reasons, "suspicious child process")
			} else {
				anomalyScore += behavior.Weights.ChildProcWeight * 0.2
			}
		}

	case "resource":
		if event.CPUPercent > behavior.NormalResources.MaxCPU*1.5 {
			anomalyScore += behavior.Weights.ResourceWeight * 0.5
			reasons = append(reasons, "unusual CPU usage")
		}
		if event.MemoryMB > behavior.NormalResources.MaxMemoryMB*2 {
			anomalyScore += behavior.Weights.ResourceWeight * 0.4
			reasons = append(reasons, "unusual memory usage")
		}
	}

	// Check schedule
	if !e.isNormalSchedule(behavior, event.Timestamp) {
		anomalyScore += behavior.Weights.ScheduleWeight * 0.3
		reasons = append(reasons, "unusual time of execution")
	}

	// Factor in trust score - trusted processes get benefit of doubt
	anomalyScore *= (1 - behavior.TrustScore*0.5)

	if anomalyScore >= e.AnomalyThreshold {
		severity := math.Min(anomalyScore, 1.0)
		confidence := math.Min(float64(behavior.ObservationCount)/100.0, 0.95)

		action := "monitor"
		if severity > 0.8 {
			action = "quarantine"
		} else if severity > 0.6 {
			action = "alert"
		}

		return &AnomalyResult{
			Timestamp:         event.Timestamp,
			ProcessName:       event.ProcessName,
			AnomalyType:       event.EventType,
			Description:       joinStrings(reasons, ", "),
			Severity:          severity,
			Confidence:        confidence,
			RecommendedAction: action,
		}
	}

	return nil
}

// learnFromEvent updates the behavior profile based on observed event
func (e *BehaviorLearningEngine) learnFromEvent(behavior *ProcessBehavior, event BehaviorEvent) {
	alpha := e.LearningRate

	switch event.EventType {
	case "network":
		if event.TargetPort > 0 && !containsInt(behavior.NormalPorts, event.TargetPort) {
			behavior.NormalPorts = append(behavior.NormalPorts, event.TargetPort)
			// Keep only most common ports
			if len(behavior.NormalPorts) > 50 {
				behavior.NormalPorts = behavior.NormalPorts[10:]
			}
		}
		if event.TargetDomain != "" && !containsString(behavior.NormalDomains, event.TargetDomain) {
			behavior.NormalDomains = append(behavior.NormalDomains, event.TargetDomain)
			if len(behavior.NormalDomains) > 100 {
				behavior.NormalDomains = behavior.NormalDomains[20:]
			}
		}

	case "file":
		if event.TargetFile != "" && !containsString(behavior.NormalFiles, event.TargetFile) {
			behavior.NormalFiles = append(behavior.NormalFiles, event.TargetFile)
			if len(behavior.NormalFiles) > 200 {
				behavior.NormalFiles = behavior.NormalFiles[50:]
			}
		}

	case "process":
		if event.ChildProcess != "" && !containsString(behavior.NormalChildren, event.ChildProcess) {
			behavior.NormalChildren = append(behavior.NormalChildren, event.ChildProcess)
			if len(behavior.NormalChildren) > 30 {
				behavior.NormalChildren = behavior.NormalChildren[5:]
			}
		}

	case "resource":
		// Exponential moving average
		r := &behavior.NormalResources
		r.AvgCPU = r.AvgCPU*(1-alpha) + event.CPUPercent*alpha
		r.AvgMemoryMB = r.AvgMemoryMB*(1-alpha) + event.MemoryMB*alpha
		if event.CPUPercent > r.MaxCPU {
			r.MaxCPU = event.CPUPercent
		}
		if event.MemoryMB > r.MaxMemoryMB {
			r.MaxMemoryMB = event.MemoryMB
		}
	}

	// Update schedule patterns
	e.updateSchedule(behavior, event.Timestamp)
}

func (e *BehaviorLearningEngine) updateSchedule(behavior *ProcessBehavior, t time.Time) {
	dow := int(t.Weekday())
	hour := t.Hour()

	// Check if this time window exists
	found := false
	for i := range behavior.NormalSchedule {
		w := &behavior.NormalSchedule[i]
		if w.DayOfWeek == dow && hour >= w.HourStart && hour <= w.HourEnd {
			w.IsNormal = true
			found = true
			break
		}
	}

	if !found {
		// Add new time window (2-hour window)
		behavior.NormalSchedule = append(behavior.NormalSchedule, TimeWindow{
			DayOfWeek: dow,
			HourStart: max(0, hour-1),
			HourEnd:   min(23, hour+1),
			IsNormal:  true,
		})
	}
}

func (e *BehaviorLearningEngine) isNormalSchedule(behavior *ProcessBehavior, t time.Time) bool {
	if len(behavior.NormalSchedule) == 0 {
		return true // Not enough data
	}

	dow := int(t.Weekday())
	hour := t.Hour()

	for _, w := range behavior.NormalSchedule {
		if w.DayOfWeek == dow && hour >= w.HourStart && hour <= w.HourEnd && w.IsNormal {
			return true
		}
	}

	return false
}

func (e *BehaviorLearningEngine) processKey(name, path string) string {
	h := sha256.Sum256([]byte(name + "|" + path))
	return hex.EncodeToString(h[:16])
}

// GetProcessTrust returns the trust score for a process
func (e *BehaviorLearningEngine) GetProcessTrust(processName, processPath string) float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()

	key := e.processKey(processName, processPath)
	if behavior, exists := e.Behaviors[key]; exists {
		return behavior.TrustScore
	}
	return 0.5 // Unknown process
}

// GetRecentAnomalies returns recently detected anomalies
func (e *BehaviorLearningEngine) GetRecentAnomalies(limit int) []AnomalyResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if len(e.anomalies) <= limit {
		return e.anomalies
	}
	return e.anomalies[len(e.anomalies)-limit:]
}

// GetStats returns learning statistics
func (e *BehaviorLearningEngine) GetStats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	totalObs := int64(0)
	totalAnomalies := int64(0)
	avgTrust := 0.0

	for _, b := range e.Behaviors {
		totalObs += b.ObservationCount
		totalAnomalies += b.AnomalyCount
		avgTrust += b.TrustScore
	}

	if len(e.Behaviors) > 0 {
		avgTrust /= float64(len(e.Behaviors))
	}

	return map[string]interface{}{
		"known_processes":    len(e.Behaviors),
		"total_observations": totalObs,
		"total_anomalies":    totalAnomalies,
		"avg_trust_score":    avgTrust,
		"learning_rate":      e.LearningRate,
		"anomaly_threshold":  e.AnomalyThreshold,
	}
}

// Save persists learned behaviors to disk
func (e *BehaviorLearningEngine) Save() error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	dir := filepath.Dir(e.dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(e.dbPath, data, 0644)
}

// Load reads learned behaviors from disk
func (e *BehaviorLearningEngine) Load() error {
	data, err := os.ReadFile(e.dbPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	return json.Unmarshal(data, e)
}

// StartPeriodicSave saves learned data periodically
func (e *BehaviorLearningEngine) StartPeriodicSave(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			e.Save()
			return
		case <-ticker.C:
			if err := e.Save(); err != nil {
				log.Printf("⚠️ [BehaviorEngine] Failed to save: %v", err)
			} else {
				log.Printf("💾 [BehaviorEngine] Saved %d behavior profiles", len(e.Behaviors))
			}
		}
	}
}

// DefaultBehaviorWeights returns default weights
func DefaultBehaviorWeights() BehaviorWeights {
	return BehaviorWeights{
		NetworkWeight:    1.0,
		FileAccessWeight: 1.2,
		ResourceWeight:   0.6,
		ScheduleWeight:   0.4,
		ChildProcWeight:  1.0,
	}
}

// Helper functions
func containsInt(slice []int, val int) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

func containsString(slice []string, val string) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}

func isSuspiciousPort(port int) bool {
	suspiciousPorts := []int{4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 12345, 54321}
	return containsInt(suspiciousPorts, port)
}

func isSensitivePath(path string) bool {
	sensitivePaths := []string{
		"\\Windows\\System32\\config",
		"\\Windows\\System32\\drivers",
		"\\Users\\",
		"\\AppData\\Roaming\\",
		"\\ProgramData\\",
		".ssh",
		".aws",
		"credentials",
		"password",
		"wallet",
	}
	for _, s := range sensitivePaths {
		if len(path) >= len(s) {
			// Simple substring check
			for i := 0; i <= len(path)-len(s); i++ {
				if path[i:i+len(s)] == s {
					return true
				}
			}
		}
	}
	return false
}

func isSuspiciousChild(child string) bool {
	suspicious := []string{
		"powershell", "cmd.exe", "wscript", "cscript", "mshta",
		"regsvr32", "rundll32", "certutil", "bitsadmin",
	}
	for _, s := range suspicious {
		if len(child) >= len(s) {
			for i := 0; i <= len(child)-len(s); i++ {
				if child[i:i+len(s)] == s {
					return true
				}
			}
		}
	}
	return false
}

// SortBehaviorsByTrust returns behaviors sorted by trust score
func (e *BehaviorLearningEngine) SortBehaviorsByTrust() []*ProcessBehavior {
	e.mu.RLock()
	defer e.mu.RUnlock()

	behaviors := make([]*ProcessBehavior, 0, len(e.Behaviors))
	for _, b := range e.Behaviors {
		behaviors = append(behaviors, b)
	}

	sort.Slice(behaviors, func(i, j int) bool {
		return behaviors[i].TrustScore > behaviors[j].TrustScore
	})

	return behaviors
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
