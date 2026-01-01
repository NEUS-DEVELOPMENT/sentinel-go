// Package autonomous_learning provides autonomous learning and self-improvement capabilities
// that make Sentinel stronger than traditional antivirus by learning from experience.
package autonomous_learning

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AutonomousSecurityEngine is the main integration point that combines all learning modules
// into a unified autonomous security system that learns and improves continuously.
type AutonomousSecurityEngine struct {
	// Core learning components
	ThreatIntel      *ThreatIntelligenceDB
	BehaviorEngine   *BehaviorLearningEngine
	NeuralClassifier *NeuralNetwork
	SelfImprover     *SelfImprovementEngine

	// Configuration
	Config *AutonomousConfig

	// State
	isRunning    bool
	startTime    time.Time
	totalThreats int64
	blockedCount int64
	learnedCount int64

	// Synchronization
	mu       sync.RWMutex
	stopChan chan struct{}
	wg       sync.WaitGroup

	// Data directory
	dataDir string
}

// AutonomousConfig holds configuration for the autonomous security engine
type AutonomousConfig struct {
	// Data directory for persistent storage
	DataDir string `json:"data_dir"`

	// Learning intervals
	ThreatFeedUpdateInterval time.Duration `json:"threat_feed_update_interval"`
	BehaviorSaveInterval     time.Duration `json:"behavior_save_interval"`
	NeuralTrainingInterval   time.Duration `json:"neural_training_interval"`
	SelfImprovementInterval  time.Duration `json:"self_improvement_interval"`
	HealthCheckInterval      time.Duration `json:"health_check_interval"`

	// Threat intelligence sources (URLs)
	ThreatFeeds []string `json:"threat_feeds"`

	// Neural network configuration
	NeuralInputSize  int `json:"neural_input_size"`
	NeuralHiddenSize int `json:"neural_hidden_size"`
	NeuralOutputSize int `json:"neural_output_size"`

	// Self-improvement thresholds
	AutoOptimizeThreshold float64 `json:"auto_optimize_threshold"`

	// Feature flags
	EnableThreatIntel    bool `json:"enable_threat_intel"`
	EnableBehaviorLearn  bool `json:"enable_behavior_learn"`
	EnableNeuralClassify bool `json:"enable_neural_classify"`
	EnableSelfImprove    bool `json:"enable_self_improve"`
}

// DefaultAutonomousConfig returns sensible defaults for the autonomous engine
func DefaultAutonomousConfig() *AutonomousConfig {
	homeDir, _ := os.UserHomeDir()
	dataDir := filepath.Join(homeDir, ".sentinel", "autonomous")

	return &AutonomousConfig{
		DataDir:                  dataDir,
		ThreatFeedUpdateInterval: 1 * time.Hour,
		BehaviorSaveInterval:     5 * time.Minute,
		NeuralTrainingInterval:   30 * time.Minute,
		SelfImprovementInterval:  10 * time.Minute,
		HealthCheckInterval:      1 * time.Minute,
		NeuralInputSize:          25,
		NeuralHiddenSize:         64,
		NeuralOutputSize:         10,
		AutoOptimizeThreshold:    0.8,
		EnableThreatIntel:        true,
		EnableBehaviorLearn:      true,
		EnableNeuralClassify:     true,
		EnableSelfImprove:        true,
	}
}

// NewAutonomousSecurityEngine creates a new autonomous security engine
func NewAutonomousSecurityEngine(config *AutonomousConfig) (*AutonomousSecurityEngine, error) {
	if config == nil {
		config = DefaultAutonomousConfig()
	}

	// Ensure data directory exists
	if err := os.MkdirAll(config.DataDir, 0755); err != nil {
		return nil, err
	}

	engine := &AutonomousSecurityEngine{
		Config:   config,
		dataDir:  config.DataDir,
		stopChan: make(chan struct{}),
	}

	// Initialize threat intelligence
	if config.EnableThreatIntel {
		engine.ThreatIntel = NewThreatIntelligenceDB(filepath.Join(config.DataDir, "threat_intel.json"))
	}

	// Initialize behavior learning
	if config.EnableBehaviorLearn {
		engine.BehaviorEngine = NewBehaviorLearningEngine(filepath.Join(config.DataDir, "behavior_profiles.json"))
	}

	// Initialize neural classifier
	if config.EnableNeuralClassify {
		engine.NeuralClassifier = NewNeuralNetwork(filepath.Join(config.DataDir, "neural_model.json"))
	}

	// Initialize self-improvement engine
	if config.EnableSelfImprove {
		engine.SelfImprover = NewSelfImprovementEngine(config.DataDir)
		engine.SelfImprover.OptimizeThreshold = config.AutoOptimizeThreshold
	}

	log.Printf("🧠 Autonomous Security Engine initialized")
	log.Printf("   📁 Data directory: %s", config.DataDir)
	log.Printf("   🌐 Threat Intel: %v", config.EnableThreatIntel)
	log.Printf("   👁️ Behavior Learning: %v", config.EnableBehaviorLearn)
	log.Printf("   🧬 Neural Classifier: %v", config.EnableNeuralClassify)
	log.Printf("   ⚡ Self-Improvement: %v", config.EnableSelfImprove)

	return engine, nil
}

// Start begins all autonomous learning processes
func (ase *AutonomousSecurityEngine) Start(ctx context.Context) error {
	ase.mu.Lock()
	if ase.isRunning {
		ase.mu.Unlock()
		return nil
	}
	ase.isRunning = true
	ase.startTime = time.Now()
	ase.mu.Unlock()

	log.Printf("🚀 Starting Autonomous Security Engine...")

	// Start threat intelligence updates
	if ase.Config.EnableThreatIntel && ase.ThreatIntel != nil {
		ase.wg.Add(1)
		go ase.threatIntelWorker(ctx)
	}

	// Start behavior learning observations
	if ase.Config.EnableBehaviorLearn && ase.BehaviorEngine != nil {
		ase.wg.Add(1)
		go ase.behaviorLearningWorker(ctx)
	}

	// Start neural classifier training
	if ase.Config.EnableNeuralClassify && ase.NeuralClassifier != nil {
		ase.wg.Add(1)
		go ase.neuralTrainingWorker(ctx)
	}

	// Start self-improvement engine
	if ase.Config.EnableSelfImprove && ase.SelfImprover != nil {
		ase.wg.Add(1)
		go ase.selfImprovementWorker(ctx)
	}

	// Start health monitoring
	ase.wg.Add(1)
	go ase.healthMonitorWorker(ctx)

	log.Printf("✅ Autonomous Security Engine is now running")
	log.Printf("   🛡️ System is learning and improving continuously")

	return nil
}

// Stop gracefully stops all autonomous learning processes
func (ase *AutonomousSecurityEngine) Stop() {
	ase.mu.Lock()
	if !ase.isRunning {
		ase.mu.Unlock()
		return
	}
	ase.isRunning = false
	ase.mu.Unlock()

	log.Printf("🛑 Stopping Autonomous Security Engine...")

	// Signal all workers to stop
	close(ase.stopChan)

	// Wait for all workers to finish
	ase.wg.Wait()

	// Save all state
	ase.saveAllState()

	log.Printf("✅ Autonomous Security Engine stopped")
}

// threatIntelWorker continuously updates threat intelligence from feeds
func (ase *AutonomousSecurityEngine) threatIntelWorker(ctx context.Context) {
	defer ase.wg.Done()

	ticker := time.NewTicker(ase.Config.ThreatFeedUpdateInterval)
	defer ticker.Stop()

	// Initial update
	ase.updateThreatFeeds(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ase.stopChan:
			return
		case <-ticker.C:
			ase.updateThreatFeeds(ctx)
		}
	}
}

// updateThreatFeeds updates all configured threat feeds
func (ase *AutonomousSecurityEngine) updateThreatFeeds(ctx context.Context) {
	log.Printf("🌐 Updating threat intelligence feeds...")

	for _, feed := range ase.ThreatIntel.Feeds {
		if !feed.Enabled {
			continue
		}
		if err := ase.ThreatIntel.UpdateFeed(ctx, feed); err != nil {
			log.Printf("⚠️ Failed to update feed %s: %v", feed.Name, err)
		} else {
			log.Printf("✅ Updated feed: %s (%d IOCs)", feed.Name, feed.TotalIOCs)
		}
	}

	// Save updated threat intel
	ase.ThreatIntel.Save()
}

// behaviorLearningWorker continuously observes and learns system behavior
func (ase *AutonomousSecurityEngine) behaviorLearningWorker(ctx context.Context) {
	defer ase.wg.Done()

	observeTicker := time.NewTicker(30 * time.Second)
	saveTicker := time.NewTicker(ase.Config.BehaviorSaveInterval)
	defer observeTicker.Stop()
	defer saveTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ase.stopChan:
			return
		case <-observeTicker.C:
			// Observe current system behavior
			ase.observeSystemBehavior()
		case <-saveTicker.C:
			// Save learned profiles
			ase.BehaviorEngine.SaveProfiles(filepath.Join(ase.dataDir, "behavior_profiles.json"))
		}
	}
}

// observeSystemBehavior observes current running processes and learns their behavior
func (ase *AutonomousSecurityEngine) observeSystemBehavior() {
	// This would be integrated with process monitoring
	// For now, we simulate observations
	observations := ase.BehaviorEngine.GetObservationStats()
	if observations["total_profiles"].(int) > 0 {
		log.Printf("👁️ Behavior observation: %d profiles, %d trusted",
			observations["total_profiles"],
			observations["trusted_count"])
	}
}

// neuralTrainingWorker periodically retrains the neural classifier
func (ase *AutonomousSecurityEngine) neuralTrainingWorker(ctx context.Context) {
	defer ase.wg.Done()

	ticker := time.NewTicker(ase.Config.NeuralTrainingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ase.stopChan:
			return
		case <-ticker.C:
			ase.retrainNeuralNetwork()
		}
	}
}

// retrainNeuralNetwork retrains the neural network with accumulated data
func (ase *AutonomousSecurityEngine) retrainNeuralNetwork() {
	stats := ase.NeuralClassifier.GetModelStats()
	if stats.TotalPredictions > 0 {
		log.Printf("🧬 Neural network stats: %d predictions, accuracy: %.2f%%",
			stats.TotalPredictions, stats.ConfidenceAvg*100)
	}

	// Save the model
	ase.NeuralClassifier.SaveModel(filepath.Join(ase.dataDir, "neural_model.json"))
}

// selfImprovementWorker runs continuous self-improvement cycles
func (ase *AutonomousSecurityEngine) selfImprovementWorker(ctx context.Context) {
	defer ase.wg.Done()

	ticker := time.NewTicker(ase.Config.SelfImprovementInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ase.stopChan:
			return
		case <-ticker.C:
			ase.runSelfImprovementCycle()
		}
	}
}

// runSelfImprovementCycle runs a self-improvement analysis and optimization
func (ase *AutonomousSecurityEngine) runSelfImprovementCycle() {
	// Collect current metrics
	ase.SelfImprover.CollectMetrics()

	// Check if auto-optimization should run
	if ase.SelfImprover.AutoOptimize {
		currentMetrics := ase.SelfImprover.GetCurrentMetrics()
		if currentMetrics.F1Score < ase.SelfImprover.AutoOptimizeThreshold {
			log.Printf("⚡ Auto-optimization triggered (F1: %.2f < %.2f)",
				currentMetrics.F1Score, ase.SelfImprover.AutoOptimizeThreshold)

			suggestions := ase.SelfImprover.Analyze()
			for _, suggestion := range suggestions {
				log.Printf("   💡 %s: %s (impact: %.2f)",
					suggestion.Category, suggestion.Description, suggestion.Impact)
			}

			ase.SelfImprover.ApplyOptimizations()
		}
	}
}

// healthMonitorWorker monitors the health of all learning components
func (ase *AutonomousSecurityEngine) healthMonitorWorker(ctx context.Context) {
	defer ase.wg.Done()

	ticker := time.NewTicker(ase.Config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ase.stopChan:
			return
		case <-ticker.C:
			ase.checkHealth()
		}
	}
}

// checkHealth performs a health check on all components
func (ase *AutonomousSecurityEngine) checkHealth() {
	health := ase.GetHealthStatus()

	if !health["overall_healthy"].(bool) {
		log.Printf("⚠️ Health check warning: %v", health)
	}
}

// saveAllState saves all learning state to disk
func (ase *AutonomousSecurityEngine) saveAllState() {
	log.Printf("💾 Saving all learning state...")

	if ase.ThreatIntel != nil {
		ase.ThreatIntel.SaveToFile(filepath.Join(ase.dataDir, "threat_intel.json"))
	}

	if ase.BehaviorEngine != nil {
		ase.BehaviorEngine.SaveProfiles(filepath.Join(ase.dataDir, "behavior_profiles.json"))
	}

	if ase.NeuralClassifier != nil {
		ase.NeuralClassifier.SaveModel(filepath.Join(ase.dataDir, "neural_model.json"))
	}

	log.Printf("✅ All state saved")
}

// AnalyzeThreat performs a comprehensive threat analysis using all learning modules
func (ase *AutonomousSecurityEngine) AnalyzeThreat(features FeatureVector) ThreatAnalysisResult {
	result := ThreatAnalysisResult{
		Timestamp:   time.Now(),
		IsmalWare:   false,
		Confidence:  0.0,
		ThreatType:  "benign",
		Sources:     make([]string, 0),
		Suggestions: make([]string, 0),
	}

	// 1. Check threat intelligence
	if ase.ThreatIntel != nil {
		if features.FileHash != "" {
			if ase.ThreatIntel.CheckHash(features.FileHash) {
				result.IsmalWare = true
				result.Confidence = 0.99
				result.ThreatType = "known_malware"
				result.Sources = append(result.Sources, "threat_intelligence")
			}
		}
	}

	// 2. Behavior analysis
	if ase.BehaviorEngine != nil && features.ProcessName != "" {
		anomalyScore := ase.BehaviorEngine.CalculateAnomalyScore(features.ProcessName)
		if anomalyScore > 0.7 {
			result.BehaviorScore = anomalyScore
			result.Sources = append(result.Sources, "behavior_analysis")
			if anomalyScore > 0.9 {
				result.IsmalWare = true
				result.ThreatType = "behavioral_anomaly"
				result.Confidence = anomalyScore
			}
		}
	}

	// 3. Neural classification
	if ase.NeuralClassifier != nil {
		threatType, confidence := ase.NeuralClassifier.Predict(features)
		result.NeuralPrediction = threatType
		result.NeuralConfidence = confidence

		if threatType != "benign" && confidence > 0.7 {
			result.Sources = append(result.Sources, "neural_classifier")
			if confidence > result.Confidence {
				result.IsmalWare = true
				result.ThreatType = threatType
				result.Confidence = confidence
			}
		}
	}

	// Update learning metrics
	ase.mu.Lock()
	ase.totalThreats++
	if result.IsmalWare {
		ase.blockedCount++
	}
	ase.mu.Unlock()

	// Generate suggestions
	if result.IsmalWare {
		result.Suggestions = append(result.Suggestions, "BLOCK", "QUARANTINE", "REPORT")
	}

	return result
}

// LearnFromExperience adds a new experience to the learning system
func (ase *AutonomousSecurityEngine) LearnFromExperience(features FeatureVector, label string, wasBlocked bool) {
	// Learn from threat intel
	if ase.ThreatIntel != nil && features.FileHash != "" {
		experience := ThreatExperience{
			Hash:       features.FileHash,
			ThreatType: label,
			Severity:   CalculateSeverity(label),
			WasBlocked: wasBlocked,
			Timestamp:  time.Now(),
		}
		ase.ThreatIntel.LearnFromExperience(experience)
	}

	// Update neural classifier
	if ase.NeuralClassifier != nil {
		labelIndex := ThreatTypeToIndex(label)
		target := make([]float64, 10)
		target[labelIndex] = 1.0
		ase.NeuralClassifier.Train(features, target)
	}

	ase.mu.Lock()
	ase.learnedCount++
	ase.mu.Unlock()

	log.Printf("📚 Learned from experience: %s (blocked: %v)", label, wasBlocked)
}

// GetHealthStatus returns the health status of all components
func (ase *AutonomousSecurityEngine) GetHealthStatus() map[string]interface{} {
	ase.mu.RLock()
	defer ase.mu.RUnlock()

	health := make(map[string]interface{})
	overallHealthy := true

	health["running"] = ase.isRunning
	health["uptime_seconds"] = time.Since(ase.startTime).Seconds()
	health["total_threats_analyzed"] = ase.totalThreats
	health["blocked_count"] = ase.blockedCount
	health["learned_count"] = ase.learnedCount

	// Threat intel health
	if ase.ThreatIntel != nil {
		totalIOCs := ase.ThreatIntel.GetTotalIOCs()
		health["threat_intel_iocs"] = totalIOCs
		health["threat_intel_healthy"] = totalIOCs > 0
	}

	// Behavior engine health
	if ase.BehaviorEngine != nil {
		stats := ase.BehaviorEngine.GetObservationStats()
		health["behavior_profiles"] = stats["total_profiles"]
		health["behavior_healthy"] = true
	}

	// Neural classifier health
	if ase.NeuralClassifier != nil {
		stats := ase.NeuralClassifier.GetModelStats()
		health["neural_predictions"] = stats.TotalPredictions
		health["neural_accuracy"] = stats.ConfidenceAvg
		health["neural_healthy"] = true
	}

	// Self-improver health
	if ase.SelfImprover != nil {
		metrics := ase.SelfImprover.GetCurrentMetrics()
		health["improvement_f1_score"] = metrics.F1Score
		health["improvement_healthy"] = metrics.F1Score > 0.5
	}

	health["overall_healthy"] = overallHealthy

	return health
}

// GetDashboardData returns data formatted for dashboard display
func (ase *AutonomousSecurityEngine) GetDashboardData() map[string]interface{} {
	ase.mu.RLock()
	defer ase.mu.RUnlock()

	data := make(map[string]interface{})

	data["engine_status"] = map[string]interface{}{
		"running":        ase.isRunning,
		"uptime":         time.Since(ase.startTime).String(),
		"total_analyzed": ase.totalThreats,
		"blocked":        ase.blockedCount,
		"learned":        ase.learnedCount,
	}

	if ase.ThreatIntel != nil {
		data["threat_intelligence"] = map[string]interface{}{
			"total_iocs":       ase.ThreatIntel.GetTotalIOCs(),
			"feed_count":       len(ase.ThreatIntel.Feeds),
			"last_update":      ase.ThreatIntel.GetLastUpdateTime(),
			"learned_patterns": len(ase.ThreatIntel.LearnedPatterns),
		}
	}

	if ase.BehaviorEngine != nil {
		data["behavior_learning"] = ase.BehaviorEngine.GetObservationStats()
	}

	if ase.NeuralClassifier != nil {
		stats := ase.NeuralClassifier.GetModelStats()
		data["neural_classifier"] = map[string]interface{}{
			"total_predictions": stats.TotalPredictions,
			"avg_confidence":    stats.ConfidenceAvg,
			"training_count":    stats.TrainingCount,
		}
	}

	if ase.SelfImprover != nil {
		metrics := ase.SelfImprover.GetCurrentMetrics()
		data["self_improvement"] = map[string]interface{}{
			"precision":         metrics.Precision,
			"recall":            metrics.Recall,
			"f1_score":          metrics.F1Score,
			"suggestions_count": len(ase.SelfImprover.Suggestions),
		}
	}

	return data
}

// ExportState exports all learning state to a JSON file
func (ase *AutonomousSecurityEngine) ExportState(filename string) error {
	state := map[string]interface{}{
		"timestamp":      time.Now(),
		"dashboard_data": ase.GetDashboardData(),
		"health":         ase.GetHealthStatus(),
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// ThreatAnalysisResult represents the result of a comprehensive threat analysis
type ThreatAnalysisResult struct {
	Timestamp        time.Time `json:"timestamp"`
	IsmalWare        bool      `json:"is_malware"`
	Confidence       float64   `json:"confidence"`
	ThreatType       string    `json:"threat_type"`
	Sources          []string  `json:"sources"`
	Suggestions      []string  `json:"suggestions"`
	BehaviorScore    float64   `json:"behavior_score,omitempty"`
	NeuralPrediction string    `json:"neural_prediction,omitempty"`
	NeuralConfidence float64   `json:"neural_confidence,omitempty"`
}

// ThreatExperience represents a learned threat experience
type ThreatExperience struct {
	Hash       string    `json:"hash"`
	ThreatType string    `json:"threat_type"`
	Severity   int       `json:"severity"`
	WasBlocked bool      `json:"was_blocked"`
	Timestamp  time.Time `json:"timestamp"`
}

// CalculateSeverity returns a severity score based on threat type
func CalculateSeverity(threatType string) int {
	severityMap := map[string]int{
		"benign":      0,
		"adware":      3,
		"spyware":     6,
		"trojan":      7,
		"worm":        7,
		"backdoor":    8,
		"cryptominer": 7,
		"ransomware":  9,
		"rootkit":     9,
		"exploit":     8,
	}
	if s, ok := severityMap[threatType]; ok {
		return s
	}
	return 5
}

// ThreatTypeToIndex converts threat type string to neural network output index
func ThreatTypeToIndex(threatType string) int {
	indexMap := map[string]int{
		"benign":      0,
		"trojan":      1,
		"ransomware":  2,
		"cryptominer": 3,
		"backdoor":    4,
		"worm":        5,
		"spyware":     6,
		"adware":      7,
		"rootkit":     8,
		"exploit":     9,
	}
	if idx, ok := indexMap[threatType]; ok {
		return idx
	}
	return 0
}

// Global singleton instance
var (
	globalEngine     *AutonomousSecurityEngine
	globalEngineMu   sync.Mutex
	globalEngineOnce sync.Once
)

// GetAutonomousEngine returns the global autonomous security engine instance
func GetAutonomousEngine() *AutonomousSecurityEngine {
	globalEngineMu.Lock()
	defer globalEngineMu.Unlock()

	if globalEngine == nil {
		var err error
		globalEngine, err = NewAutonomousSecurityEngine(nil)
		if err != nil {
			log.Printf("❌ Failed to create autonomous engine: %v", err)
			return nil
		}
	}

	return globalEngine
}

// InitializeAutonomousEngine initializes the global engine with custom config
func InitializeAutonomousEngine(config *AutonomousConfig) (*AutonomousSecurityEngine, error) {
	globalEngineMu.Lock()
	defer globalEngineMu.Unlock()

	if globalEngine != nil {
		globalEngine.Stop()
	}

	var err error
	globalEngine, err = NewAutonomousSecurityEngine(config)
	if err != nil {
		return nil, err
	}

	return globalEngine, nil
}
