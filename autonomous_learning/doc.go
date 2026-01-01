// Package autonomous_learning provides comprehensive autonomous security capabilities
// for the Sentinel security agent, making it stronger than traditional antivirus
// through continuous learning and self-improvement.
//
// # Overview
//
// This package implements several key components that work together:
//
// 1. Threat Intelligence (threat_intelligence.go):
//   - Updates from 8+ external threat feeds (MalwareBazaar, URLhaus, etc.)
//   - Tracks malicious hashes, IPs, and domains
//   - Learns from personal experience and blocked threats
//
// 2. Behavior Learning (behavior_learning.go):
//   - Profiles normal behavior of all running processes
//   - Detects anomalies based on learned patterns
//   - Maintains trust scores for known good processes
//
// 3. Neural Classification (neural_classifier.go):
//   - Pure Go neural network for threat classification
//   - 10 threat categories: benign, trojan, ransomware, cryptominer, backdoor,
//     worm, spyware, adware, rootkit, exploit
//   - Online learning from detected threats
//
// 4. Self-Improvement (self_improvement.go):
//   - Collects performance metrics (precision, recall, F1)
//   - Generates optimization suggestions
//   - Automatically applies improvements when threshold is met
//
// 5. Integration (integration.go):
//   - Unified AutonomousSecurityEngine that coordinates all components
//   - Background workers for continuous updates
//   - Dashboard data export for monitoring
//
// # Usage
//
// Basic usage:
//
//	import "sentinel/autonomous_learning"
//
//	// Get or create the global engine
//	engine := autonomous_learning.GetAutonomousEngine()
//
//	// Start autonomous operation
//	ctx := context.Background()
//	engine.Start(ctx)
//
//	// Analyze a potential threat
//	features := autonomous_learning.FeatureVector{
//	    FileSize: 1024000,
//	    Entropy: 7.8,
//	    HasNetwork: true,
//	    // ... more features
//	}
//	result := engine.AnalyzeThreat(features)
//
//	if result.IsmalWare {
//	    log.Printf("Threat detected: %s (confidence: %.2f)", result.ThreatType, result.Confidence)
//	}
//
//	// Learn from experience
//	engine.LearnFromExperience(features, "trojan", true)
//
//	// Get dashboard data
//	data := engine.GetDashboardData()
//
//	// Stop when done
//	engine.Stop()
//
// # Configuration
//
// Custom configuration example:
//
//	config := &autonomous_learning.AutonomousConfig{
//	    DataDir: "/path/to/data",
//	    ThreatFeedUpdateInterval: 30 * time.Minute,
//	    EnableThreatIntel: true,
//	    EnableBehaviorLearn: true,
//	    EnableNeuralClassify: true,
//	    EnableSelfImprove: true,
//	    AutoOptimizeThreshold: 0.85,
//	}
//
//	engine, err := autonomous_learning.InitializeAutonomousEngine(config)
//
// # Thread Safety
//
// All exported functions and methods are thread-safe and can be called
// concurrently from multiple goroutines.
//
// # Persistence
//
// Learning state is automatically persisted to disk:
//   - threat_intel.json: Threat intelligence data
//   - behavior_profiles.json: Process behavior profiles
//   - neural_model.json: Neural network weights
//
// Data is saved periodically and on graceful shutdown.
package autonomous_learning
