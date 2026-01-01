// Package autonomous_learning implements neural network for threat classification
// This is a pure Go implementation of a neural network for malware classification
package autonomous_learning

import (
	"encoding/json"
	"log"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ====== Neural Network for Threat Classification ====== //

// NeuralNetwork represents a multi-layer perceptron
type NeuralNetwork struct {
	InputSize  int `json:"input_size"`
	HiddenSize int `json:"hidden_size"`
	OutputSize int `json:"output_size"`

	// Weights
	WeightsIH [][]float64 `json:"weights_ih"` // Input -> Hidden
	WeightsHO [][]float64 `json:"weights_ho"` // Hidden -> Output
	BiasH     []float64   `json:"bias_h"`
	BiasO     []float64   `json:"bias_o"`

	// Training parameters
	LearningRate float64 `json:"learning_rate"`
	Momentum     float64 `json:"momentum"`

	// Velocity for momentum
	velocityIH [][]float64
	velocityHO [][]float64

	// Statistics
	TrainingEpochs int     `json:"training_epochs"`
	LastLoss       float64 `json:"last_loss"`
	BestLoss       float64 `json:"best_loss"`
	TotalSamples   int64   `json:"total_samples"`

	dbPath string
	mu     sync.RWMutex
}

// ThreatClassification represents the output of threat classification
type ThreatClassification struct {
	IsMalware  float64            `json:"is_malware"`
	ThreatType string             `json:"threat_type"`
	Confidence float64            `json:"confidence"`
	RiskScore  float64            `json:"risk_score"`
	Categories map[string]float64 `json:"categories"`
}

// ThreatCategories for classification
var ThreatCategories = []string{
	"benign",      // 0
	"trojan",      // 1
	"ransomware",  // 2
	"cryptominer", // 3
	"backdoor",    // 4
	"worm",        // 5
	"spyware",     // 6
	"adware",      // 7
	"rootkit",     // 8
	"exploit",     // 9
}

// FeatureVector represents features extracted from a process/file
type FeatureVector struct {
	// Binary features (0 or 1)
	HasNetworkActivity   float64
	HasFileModification  float64
	HasRegistryAccess    float64
	HasProcessInjection  float64
	HasPersistence       float64
	HasEncryption        float64
	HasPackedCode        float64
	HasAntiDebug         float64
	HasAntiVM            float64
	HasSuspiciousImports float64

	// Continuous features (normalized 0-1)
	CPUUsage             float64
	MemoryUsage          float64
	DiskIO               float64
	NetworkConnections   float64
	ChildProcesses       float64
	FileOperationsPerSec float64
	APICallsPerSec       float64
	EntropyScore         float64
	SuspiciousStrings    float64
	SignatureMatch       float64

	// Behavior features
	UnusualPortUsage    float64
	SensitiveFileAccess float64
	ScheduleAnomaly     float64
	TrustScore          float64
	ObservationTime     float64
}

// ToSlice converts FeatureVector to a slice for neural network input
func (f *FeatureVector) ToSlice() []float64 {
	return []float64{
		f.HasNetworkActivity,
		f.HasFileModification,
		f.HasRegistryAccess,
		f.HasProcessInjection,
		f.HasPersistence,
		f.HasEncryption,
		f.HasPackedCode,
		f.HasAntiDebug,
		f.HasAntiVM,
		f.HasSuspiciousImports,
		f.CPUUsage,
		f.MemoryUsage,
		f.DiskIO,
		f.NetworkConnections,
		f.ChildProcesses,
		f.FileOperationsPerSec,
		f.APICallsPerSec,
		f.EntropyScore,
		f.SuspiciousStrings,
		f.SignatureMatch,
		f.UnusualPortUsage,
		f.SensitiveFileAccess,
		f.ScheduleAnomaly,
		f.TrustScore,
		f.ObservationTime,
	}
}

const FeatureVectorSize = 25

// NewNeuralNetwork creates a new neural network for threat classification
func NewNeuralNetwork(dbPath string) *NeuralNetwork {
	nn := &NeuralNetwork{
		InputSize:    FeatureVectorSize,
		HiddenSize:   64,
		OutputSize:   len(ThreatCategories),
		LearningRate: 0.01,
		Momentum:     0.9,
		BestLoss:     math.MaxFloat64,
		dbPath:       dbPath,
	}

	// Try to load existing model
	if err := nn.Load(); err != nil {
		log.Println("🧠 [NeuralNet] Initializing new neural network...")
		nn.initWeights()
	} else {
		log.Printf("🧠 [NeuralNet] Loaded model with %d training epochs, loss: %.4f",
			nn.TrainingEpochs, nn.LastLoss)
	}

	return nn
}

// initWeights initializes weights with Xavier initialization
func (nn *NeuralNetwork) initWeights() {
	rand.Seed(time.Now().UnixNano())

	// Xavier initialization scale
	scaleIH := math.Sqrt(2.0 / float64(nn.InputSize+nn.HiddenSize))
	scaleHO := math.Sqrt(2.0 / float64(nn.HiddenSize+nn.OutputSize))

	// Input -> Hidden weights
	nn.WeightsIH = make([][]float64, nn.InputSize)
	nn.velocityIH = make([][]float64, nn.InputSize)
	for i := 0; i < nn.InputSize; i++ {
		nn.WeightsIH[i] = make([]float64, nn.HiddenSize)
		nn.velocityIH[i] = make([]float64, nn.HiddenSize)
		for j := 0; j < nn.HiddenSize; j++ {
			nn.WeightsIH[i][j] = (rand.Float64()*2 - 1) * scaleIH
		}
	}

	// Hidden biases
	nn.BiasH = make([]float64, nn.HiddenSize)
	for i := range nn.BiasH {
		nn.BiasH[i] = 0.0
	}

	// Hidden -> Output weights
	nn.WeightsHO = make([][]float64, nn.HiddenSize)
	nn.velocityHO = make([][]float64, nn.HiddenSize)
	for i := 0; i < nn.HiddenSize; i++ {
		nn.WeightsHO[i] = make([]float64, nn.OutputSize)
		nn.velocityHO[i] = make([]float64, nn.OutputSize)
		for j := 0; j < nn.OutputSize; j++ {
			nn.WeightsHO[i][j] = (rand.Float64()*2 - 1) * scaleHO
		}
	}

	// Output biases
	nn.BiasO = make([]float64, nn.OutputSize)
	for i := range nn.BiasO {
		nn.BiasO[i] = 0.0
	}
}

// Forward performs forward propagation
func (nn *NeuralNetwork) Forward(input []float64) []float64 {
	nn.mu.RLock()
	defer nn.mu.RUnlock()

	if len(input) != nn.InputSize {
		log.Printf("⚠️ [NeuralNet] Invalid input size: %d (expected %d)", len(input), nn.InputSize)
		return make([]float64, nn.OutputSize)
	}

	// Hidden layer
	hidden := make([]float64, nn.HiddenSize)
	for j := 0; j < nn.HiddenSize; j++ {
		sum := nn.BiasH[j]
		for i := 0; i < nn.InputSize; i++ {
			sum += input[i] * nn.WeightsIH[i][j]
		}
		hidden[j] = relu(sum)
	}

	// Output layer (softmax)
	output := make([]float64, nn.OutputSize)
	maxVal := math.Inf(-1)
	for k := 0; k < nn.OutputSize; k++ {
		sum := nn.BiasO[k]
		for j := 0; j < nn.HiddenSize; j++ {
			sum += hidden[j] * nn.WeightsHO[j][k]
		}
		output[k] = sum
		if sum > maxVal {
			maxVal = sum
		}
	}

	// Softmax normalization
	expSum := 0.0
	for k := 0; k < nn.OutputSize; k++ {
		output[k] = math.Exp(output[k] - maxVal) // Subtract max for numerical stability
		expSum += output[k]
	}
	for k := 0; k < nn.OutputSize; k++ {
		output[k] /= expSum
	}

	return output
}

// Classify classifies a feature vector
func (nn *NeuralNetwork) Classify(features *FeatureVector) *ThreatClassification {
	input := features.ToSlice()
	output := nn.Forward(input)

	// Find max probability
	maxIdx := 0
	maxProb := output[0]
	for i := 1; i < len(output); i++ {
		if output[i] > maxProb {
			maxProb = output[i]
			maxIdx = i
		}
	}

	// Build categories map
	categories := make(map[string]float64)
	for i, cat := range ThreatCategories {
		categories[cat] = output[i]
	}

	// Calculate risk score
	isMalware := 1.0 - output[0] // Everything except benign
	riskScore := isMalware * maxProb

	return &ThreatClassification{
		IsMalware:  isMalware,
		ThreatType: ThreatCategories[maxIdx],
		Confidence: maxProb,
		RiskScore:  riskScore,
		Categories: categories,
	}
}

// Train trains the network on a single sample (online learning)
func (nn *NeuralNetwork) Train(input []float64, target []float64) float64 {
	nn.mu.Lock()
	defer nn.mu.Unlock()

	if len(input) != nn.InputSize || len(target) != nn.OutputSize {
		return 0
	}

	// Forward pass
	hidden := make([]float64, nn.HiddenSize)
	for j := 0; j < nn.HiddenSize; j++ {
		sum := nn.BiasH[j]
		for i := 0; i < nn.InputSize; i++ {
			sum += input[i] * nn.WeightsIH[i][j]
		}
		hidden[j] = relu(sum)
	}

	// Output layer
	output := make([]float64, nn.OutputSize)
	maxVal := math.Inf(-1)
	for k := 0; k < nn.OutputSize; k++ {
		sum := nn.BiasO[k]
		for j := 0; j < nn.HiddenSize; j++ {
			sum += hidden[j] * nn.WeightsHO[j][k]
		}
		output[k] = sum
		if sum > maxVal {
			maxVal = sum
		}
	}

	// Softmax
	expSum := 0.0
	for k := 0; k < nn.OutputSize; k++ {
		output[k] = math.Exp(output[k] - maxVal)
		expSum += output[k]
	}
	for k := 0; k < nn.OutputSize; k++ {
		output[k] /= expSum
	}

	// Compute loss (cross-entropy)
	loss := 0.0
	for k := 0; k < nn.OutputSize; k++ {
		if target[k] > 0 {
			loss -= target[k] * math.Log(output[k]+1e-10)
		}
	}

	// Backpropagation
	// Output layer gradients
	outputGrad := make([]float64, nn.OutputSize)
	for k := 0; k < nn.OutputSize; k++ {
		outputGrad[k] = output[k] - target[k]
	}

	// Hidden layer gradients
	hiddenGrad := make([]float64, nn.HiddenSize)
	for j := 0; j < nn.HiddenSize; j++ {
		sum := 0.0
		for k := 0; k < nn.OutputSize; k++ {
			sum += outputGrad[k] * nn.WeightsHO[j][k]
		}
		hiddenGrad[j] = sum * reluDerivative(hidden[j])
	}

	// Update weights with momentum
	for j := 0; j < nn.HiddenSize; j++ {
		for k := 0; k < nn.OutputSize; k++ {
			grad := outputGrad[k] * hidden[j]
			nn.velocityHO[j][k] = nn.Momentum*nn.velocityHO[j][k] - nn.LearningRate*grad
			nn.WeightsHO[j][k] += nn.velocityHO[j][k]
		}
	}

	for i := 0; i < nn.InputSize; i++ {
		for j := 0; j < nn.HiddenSize; j++ {
			grad := hiddenGrad[j] * input[i]
			nn.velocityIH[i][j] = nn.Momentum*nn.velocityIH[i][j] - nn.LearningRate*grad
			nn.WeightsIH[i][j] += nn.velocityIH[i][j]
		}
	}

	// Update biases
	for k := 0; k < nn.OutputSize; k++ {
		nn.BiasO[k] -= nn.LearningRate * outputGrad[k]
	}
	for j := 0; j < nn.HiddenSize; j++ {
		nn.BiasH[j] -= nn.LearningRate * hiddenGrad[j]
	}

	nn.TotalSamples++
	nn.LastLoss = loss
	if loss < nn.BestLoss {
		nn.BestLoss = loss
	}

	return loss
}

// TrainBatch trains on a batch of samples
func (nn *NeuralNetwork) TrainBatch(inputs [][]float64, targets [][]float64, epochs int) {
	log.Printf("🎓 [NeuralNet] Starting training: %d samples, %d epochs", len(inputs), epochs)

	for epoch := 0; epoch < epochs; epoch++ {
		totalLoss := 0.0

		// Shuffle data
		indices := rand.Perm(len(inputs))

		for _, idx := range indices {
			loss := nn.Train(inputs[idx], targets[idx])
			totalLoss += loss
		}

		avgLoss := totalLoss / float64(len(inputs))
		nn.TrainingEpochs++

		if epoch%10 == 0 || epoch == epochs-1 {
			log.Printf("📊 [NeuralNet] Epoch %d: avg_loss=%.4f, best_loss=%.4f",
				nn.TrainingEpochs, avgLoss, nn.BestLoss)
		}
	}

	// Save after training
	nn.Save()
}

// LearnFromExperience learns from a classified threat
func (nn *NeuralNetwork) LearnFromExperience(features *FeatureVector, actualCategory string) {
	input := features.ToSlice()

	// Create one-hot target
	target := make([]float64, nn.OutputSize)
	for i, cat := range ThreatCategories {
		if cat == actualCategory {
			target[i] = 1.0
			break
		}
	}

	loss := nn.Train(input, target)
	log.Printf("🧠 [NeuralNet] Learned: %s (loss: %.4f)", actualCategory, loss)
}

// Save persists the neural network to disk
func (nn *NeuralNetwork) Save() error {
	nn.mu.RLock()
	defer nn.mu.RUnlock()

	dir := filepath.Dir(nn.dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(nn, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(nn.dbPath, data, 0644)
}

// Load reads the neural network from disk
func (nn *NeuralNetwork) Load() error {
	data, err := os.ReadFile(nn.dbPath)
	if err != nil {
		return err
	}

	nn.mu.Lock()
	defer nn.mu.Unlock()

	if err := json.Unmarshal(data, nn); err != nil {
		return err
	}

	// Reinitialize velocity matrices
	nn.velocityIH = make([][]float64, nn.InputSize)
	for i := 0; i < nn.InputSize; i++ {
		nn.velocityIH[i] = make([]float64, nn.HiddenSize)
	}
	nn.velocityHO = make([][]float64, nn.HiddenSize)
	for i := 0; i < nn.HiddenSize; i++ {
		nn.velocityHO[i] = make([]float64, nn.OutputSize)
	}

	return nil
}

// GetStats returns neural network statistics
func (nn *NeuralNetwork) GetStats() map[string]interface{} {
	nn.mu.RLock()
	defer nn.mu.RUnlock()

	return map[string]interface{}{
		"input_size":      nn.InputSize,
		"hidden_size":     nn.HiddenSize,
		"output_size":     nn.OutputSize,
		"training_epochs": nn.TrainingEpochs,
		"total_samples":   nn.TotalSamples,
		"last_loss":       nn.LastLoss,
		"best_loss":       nn.BestLoss,
		"learning_rate":   nn.LearningRate,
		"categories":      ThreatCategories,
	}
}

// Activation functions
func relu(x float64) float64 {
	if x > 0 {
		return x
	}
	return 0
}

func reluDerivative(x float64) float64 {
	if x > 0 {
		return 1
	}
	return 0
}

func sigmoid(x float64) float64 {
	return 1.0 / (1.0 + math.Exp(-x))
}

func sigmoidDerivative(x float64) float64 {
	s := sigmoid(x)
	return s * (1 - s)
}
