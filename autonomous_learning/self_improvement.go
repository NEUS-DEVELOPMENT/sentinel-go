// Package autonomous_learning implements the self-improvement engine
// This module enables the system to improve itself over time
package autonomous_learning

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ====== Self-Improvement Engine ====== //

// ImprovementRecord tracks a single improvement made by the system
type ImprovementRecord struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	Category    string    `json:"category"` // "detection", "performance", "accuracy", "efficiency"
	Description string    `json:"description"`
	OldValue    float64   `json:"old_value"`
	NewValue    float64   `json:"new_value"`
	Improvement float64   `json:"improvement_percent"`
	Source      string    `json:"source"` // "experience", "feedback", "optimization"
	Applied     bool      `json:"applied"`
}

// PerformanceMetrics tracks system performance over time
type PerformanceMetrics struct {
	// Detection metrics
	TruePositives  int64   `json:"true_positives"`
	FalsePositives int64   `json:"false_positives"`
	TrueNegatives  int64   `json:"true_negatives"`
	FalseNegatives int64   `json:"false_negatives"`
	Precision      float64 `json:"precision"`
	Recall         float64 `json:"recall"`
	F1Score        float64 `json:"f1_score"`

	// Response metrics
	AvgResponseTimeMs  float64 `json:"avg_response_time_ms"`
	MaxResponseTimeMs  float64 `json:"max_response_time_ms"`
	ThreatBlockedCount int64   `json:"threats_blocked"`

	// Learning metrics
	TotalLearningEvents  int64   `json:"total_learning_events"`
	ModelAccuracy        float64 `json:"model_accuracy"`
	BehaviorProfileCount int     `json:"behavior_profile_count"`
	IOCCount             int64   `json:"ioc_count"`

	// Timestamps
	LastUpdate    time.Time `json:"last_update"`
	StartTime     time.Time `json:"start_time"`
	UptimeSeconds int64     `json:"uptime_seconds"`
}

// OptimizationSuggestion represents an optimization the system discovered
type OptimizationSuggestion struct {
	ID          string    `json:"id"`
	Category    string    `json:"category"`
	Description string    `json:"description"`
	Impact      float64   `json:"expected_impact"` // Expected improvement %
	Confidence  float64   `json:"confidence"`
	AutoApply   bool      `json:"auto_apply"`
	Applied     bool      `json:"applied"`
	AppliedAt   time.Time `json:"applied_at,omitempty"`
}

// SelfImprovementEngine manages autonomous system improvement
type SelfImprovementEngine struct {
	// Components
	ThreatIntel    *ThreatIntelligenceDB   `json:"-"`
	BehaviorEngine *BehaviorLearningEngine `json:"-"`
	NeuralNet      *NeuralNetwork          `json:"-"`

	// Metrics
	CurrentMetrics    *PerformanceMetrics   `json:"current_metrics"`
	HistoricalMetrics []*PerformanceMetrics `json:"historical_metrics"`

	// Improvements
	Improvements []ImprovementRecord      `json:"improvements"`
	Suggestions  []OptimizationSuggestion `json:"suggestions"`

	// Configuration
	AutoOptimize      bool    `json:"auto_optimize"`
	OptimizeThreshold float64 `json:"optimize_threshold"` // Min improvement to auto-apply
	MetricsInterval   time.Duration

	dbPath string
	mu     sync.RWMutex
}

// NewSelfImprovementEngine creates a new self-improvement engine
func NewSelfImprovementEngine(dataDir string) *SelfImprovementEngine {
	engine := &SelfImprovementEngine{
		ThreatIntel:    NewThreatIntelligenceDB(filepath.Join(dataDir, "threat_intel.json")),
		BehaviorEngine: NewBehaviorLearningEngine(filepath.Join(dataDir, "behavior.json")),
		NeuralNet:      NewNeuralNetwork(filepath.Join(dataDir, "neural_model.json")),
		CurrentMetrics: &PerformanceMetrics{
			StartTime: time.Now(),
		},
		HistoricalMetrics: make([]*PerformanceMetrics, 0),
		Improvements:      make([]ImprovementRecord, 0),
		Suggestions:       make([]OptimizationSuggestion, 0),
		AutoOptimize:      true,
		OptimizeThreshold: 5.0, // 5% improvement required to auto-apply
		MetricsInterval:   1 * time.Hour,
		dbPath:            filepath.Join(dataDir, "self_improvement.json"),
	}

	// Load existing state
	engine.Load()

	return engine
}

// Start begins all autonomous learning processes
func (e *SelfImprovementEngine) Start(ctx context.Context) {
	log.Println("🚀 [SelfImprovement] Starting autonomous learning engine...")

	// Start threat intelligence updates
	e.ThreatIntel.StartAutoUpdate(ctx)

	// Start behavior learning periodic save
	go e.BehaviorEngine.StartPeriodicSave(ctx, 5*time.Minute)

	// Start metrics collection
	go e.metricsCollectionLoop(ctx)

	// Start optimization loop
	go e.optimizationLoop(ctx)

	log.Println("✅ [SelfImprovement] All learning systems active")
}

// metricsCollectionLoop periodically collects and saves metrics
func (e *SelfImprovementEngine) metricsCollectionLoop(ctx context.Context) {
	ticker := time.NewTicker(e.MetricsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			e.Save()
			return
		case <-ticker.C:
			e.collectMetrics()
			e.analyzePerformance()
			e.Save()
		}
	}
}

// collectMetrics gathers current performance metrics
func (e *SelfImprovementEngine) collectMetrics() {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Calculate derived metrics
	m := e.CurrentMetrics

	total := float64(m.TruePositives + m.FalsePositives)
	if total > 0 {
		m.Precision = float64(m.TruePositives) / total
	}

	totalActual := float64(m.TruePositives + m.FalseNegatives)
	if totalActual > 0 {
		m.Recall = float64(m.TruePositives) / totalActual
	}

	if m.Precision+m.Recall > 0 {
		m.F1Score = 2 * (m.Precision * m.Recall) / (m.Precision + m.Recall)
	}

	m.BehaviorProfileCount = len(e.BehaviorEngine.Behaviors)
	m.IOCCount = e.ThreatIntel.TotalIOCs
	m.LastUpdate = time.Now()
	m.UptimeSeconds = int64(time.Since(m.StartTime).Seconds())

	// Store historical snapshot
	snapshot := *m
	e.HistoricalMetrics = append(e.HistoricalMetrics, &snapshot)

	// Keep only last 168 hours (1 week)
	if len(e.HistoricalMetrics) > 168 {
		e.HistoricalMetrics = e.HistoricalMetrics[1:]
	}

	log.Printf("📊 [SelfImprovement] Metrics: Precision=%.2f, Recall=%.2f, F1=%.2f, IOCs=%d, Profiles=%d",
		m.Precision, m.Recall, m.F1Score, m.IOCCount, m.BehaviorProfileCount)
}

// analyzePerformance analyzes metrics and generates optimization suggestions
func (e *SelfImprovementEngine) analyzePerformance() {
	e.mu.Lock()
	defer e.mu.Unlock()

	m := e.CurrentMetrics

	// Check for high false positive rate
	if m.FalsePositives > 0 && m.TruePositives > 0 {
		fpRate := float64(m.FalsePositives) / float64(m.FalsePositives+m.TrueNegatives)
		if fpRate > 0.1 { // More than 10% false positives
			e.addSuggestion(OptimizationSuggestion{
				ID:          fmt.Sprintf("reduce_fp_%d", time.Now().Unix()),
				Category:    "accuracy",
				Description: "High false positive rate detected. Consider increasing anomaly threshold.",
				Impact:      fpRate * 100,
				Confidence:  0.8,
				AutoApply:   false,
			})
		}
	}

	// Check for low detection rate
	if m.FalseNegatives > 0 && m.TruePositives > 0 {
		fnRate := float64(m.FalseNegatives) / float64(m.FalseNegatives+m.TruePositives)
		if fnRate > 0.2 { // Missing more than 20% of threats
			e.addSuggestion(OptimizationSuggestion{
				ID:          fmt.Sprintf("improve_detection_%d", time.Now().Unix()),
				Category:    "detection",
				Description: "Low detection rate. Consider lowering anomaly threshold and updating threat intel.",
				Impact:      fnRate * 100,
				Confidence:  0.85,
				AutoApply:   false,
			})
		}
	}

	// Check neural network performance
	nnStats := e.NeuralNet.GetStats()
	if lastLoss, ok := nnStats["last_loss"].(float64); ok && lastLoss > 0.5 {
		e.addSuggestion(OptimizationSuggestion{
			ID:          fmt.Sprintf("train_nn_%d", time.Now().Unix()),
			Category:    "accuracy",
			Description: "Neural network loss is high. Consider additional training.",
			Impact:      (lastLoss - 0.1) * 100,
			Confidence:  0.7,
			AutoApply:   true,
		})
	}

	// Check behavior learning coverage
	behaviorStats := e.BehaviorEngine.GetStats()
	if knownProcs, ok := behaviorStats["known_processes"].(int); ok && knownProcs < 50 {
		e.addSuggestion(OptimizationSuggestion{
			ID:          fmt.Sprintf("expand_behavior_%d", time.Now().Unix()),
			Category:    "coverage",
			Description: "Limited behavior profiles. System needs more observation time.",
			Impact:      float64(50-knownProcs) * 2,
			Confidence:  0.9,
			AutoApply:   false,
		})
	}
}

func (e *SelfImprovementEngine) addSuggestion(suggestion OptimizationSuggestion) {
	// Check if similar suggestion already exists
	for _, s := range e.Suggestions {
		if s.Category == suggestion.Category && !s.Applied {
			return // Don't duplicate
		}
	}
	e.Suggestions = append(e.Suggestions, suggestion)
	log.Printf("💡 [SelfImprovement] New suggestion: %s (impact: %.1f%%)",
		suggestion.Description, suggestion.Impact)
}

// optimizationLoop periodically applies auto-optimizations
func (e *SelfImprovementEngine) optimizationLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if e.AutoOptimize {
				e.applyAutoOptimizations()
			}
		}
	}
}

// applyAutoOptimizations applies optimizations that meet the threshold
func (e *SelfImprovementEngine) applyAutoOptimizations() {
	e.mu.Lock()
	defer e.mu.Unlock()

	for i := range e.Suggestions {
		s := &e.Suggestions[i]
		if s.AutoApply && !s.Applied && s.Impact >= e.OptimizeThreshold && s.Confidence >= 0.7 {
			log.Printf("🔧 [SelfImprovement] Auto-applying optimization: %s", s.Description)

			// Apply based on category
			switch s.Category {
			case "accuracy":
				// Adjust learning rate or thresholds
				e.BehaviorEngine.LearningRate *= 1.1
				if e.BehaviorEngine.LearningRate > 0.5 {
					e.BehaviorEngine.LearningRate = 0.5
				}
			case "detection":
				// Lower anomaly threshold
				e.BehaviorEngine.AnomalyThreshold *= 0.95
				if e.BehaviorEngine.AnomalyThreshold < 0.3 {
					e.BehaviorEngine.AnomalyThreshold = 0.3
				}
			}

			s.Applied = true
			s.AppliedAt = time.Now()

			// Record improvement
			e.Improvements = append(e.Improvements, ImprovementRecord{
				ID:          s.ID,
				Timestamp:   time.Now(),
				Category:    s.Category,
				Description: s.Description,
				Improvement: s.Impact,
				Source:      "optimization",
				Applied:     true,
			})
		}
	}
}

// RecordDetection records a detection result for metrics
func (e *SelfImprovementEngine) RecordDetection(isThreat bool, wasCorrect bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if isThreat {
		if wasCorrect {
			e.CurrentMetrics.TruePositives++
			e.CurrentMetrics.ThreatBlockedCount++
		} else {
			e.CurrentMetrics.FalsePositives++
		}
	} else {
		if wasCorrect {
			e.CurrentMetrics.TrueNegatives++
		} else {
			e.CurrentMetrics.FalseNegatives++
		}
	}

	e.CurrentMetrics.TotalLearningEvents++
}

// RecordResponseTime records a response time measurement
func (e *SelfImprovementEngine) RecordResponseTime(ms float64) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Update average (exponential moving average)
	alpha := 0.1
	e.CurrentMetrics.AvgResponseTimeMs = e.CurrentMetrics.AvgResponseTimeMs*(1-alpha) + ms*alpha

	if ms > e.CurrentMetrics.MaxResponseTimeMs {
		e.CurrentMetrics.MaxResponseTimeMs = ms
	}
}

// GetDashboardData returns data for the dashboard
func (e *SelfImprovementEngine) GetDashboardData() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return map[string]interface{}{
		"metrics":       e.CurrentMetrics,
		"threat_intel":  e.ThreatIntel.GetStats(),
		"behavior":      e.BehaviorEngine.GetStats(),
		"neural_net":    e.NeuralNet.GetStats(),
		"improvements":  len(e.Improvements),
		"suggestions":   len(e.Suggestions),
		"auto_optimize": e.AutoOptimize,
	}
}

// GetStatus returns the current status of all learning systems
func (e *SelfImprovementEngine) GetStatus() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return map[string]interface{}{
		"status":       "active",
		"uptime_hours": e.CurrentMetrics.UptimeSeconds / 3600,
		"threat_intel": map[string]interface{}{
			"total_iocs":    e.ThreatIntel.TotalIOCs,
			"local_learned": e.ThreatIntel.LocalLearned,
			"last_sync":     e.ThreatIntel.LastSync,
			"feeds_active":  len(e.ThreatIntel.Feeds),
		},
		"behavior_learning": map[string]interface{}{
			"known_processes":    len(e.BehaviorEngine.Behaviors),
			"anomalies_detected": len(e.BehaviorEngine.anomalies),
			"learning_rate":      e.BehaviorEngine.LearningRate,
		},
		"neural_network": map[string]interface{}{
			"training_epochs": e.NeuralNet.TrainingEpochs,
			"total_samples":   e.NeuralNet.TotalSamples,
			"best_loss":       e.NeuralNet.BestLoss,
		},
		"self_improvement": map[string]interface{}{
			"improvements_made":   len(e.Improvements),
			"pending_suggestions": countPending(e.Suggestions),
			"auto_optimize":       e.AutoOptimize,
		},
	}
}

func countPending(suggestions []OptimizationSuggestion) int {
	count := 0
	for _, s := range suggestions {
		if !s.Applied {
			count++
		}
	}
	return count
}

// Save persists the engine state
func (e *SelfImprovementEngine) Save() error {
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

	// Also save components
	e.ThreatIntel.Save()
	e.BehaviorEngine.Save()
	e.NeuralNet.Save()

	return os.WriteFile(e.dbPath, data, 0644)
}

// Load reads the engine state
func (e *SelfImprovementEngine) Load() error {
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
