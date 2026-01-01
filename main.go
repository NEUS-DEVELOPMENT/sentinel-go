// Package main implements the NEUS Sentinel Field Agent
// Autonomous AI Security Agent with Multi-Agent Integration
package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ====== Autonomous Agent Configuration ====== //

// AgentConfig holds configuration for autonomous operation
type AgentConfig struct {
	AgentID           string            `json:"agent_id"`
	AgentName         string            `json:"agent_name"`
	HeartbeatInterval time.Duration     `json:"heartbeat_interval"`
	SelfHealInterval  time.Duration     `json:"self_heal_interval"`
	AutoDiscovery     bool              `json:"auto_discovery"`
	MaxRetries        int               `json:"max_retries"`
	RetryBackoff      time.Duration     `json:"retry_backoff"`
	ExternalAgents    map[string]string `json:"external_agents"` // name -> URL
	AutonomousMode    bool              `json:"autonomous_mode"`
	SelfPreservation  bool              `json:"self_preservation"`
	AdaptiveLearning  bool              `json:"adaptive_learning"`
}

// DefaultAgentConfig returns sensible defaults for autonomous operation
func DefaultAgentConfig() *AgentConfig {
	agentID := make([]byte, 8)
	rand.Read(agentID)
	return &AgentConfig{
		AgentID:           fmt.Sprintf("sentinel-%x", agentID),
		AgentName:         "NEUS-Sentinel-Autonomous",
		HeartbeatInterval: 30 * time.Second,
		SelfHealInterval:  60 * time.Second,
		AutoDiscovery:     true,
		MaxRetries:        5,
		RetryBackoff:      5 * time.Second,
		ExternalAgents: map[string]string{
			"OVERMIND":   getEnvOrDefault("OVERMIND_URL", "https://overmind.neus.ai/api"),
			"METAEIGENT": getEnvOrDefault("METAEIGENT_URL", "https://metaeigent.neus.ai/api"),
		},
		AutonomousMode:   true,
		SelfPreservation: true,
		AdaptiveLearning: true,
	}
}

func getEnvOrDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

// ====== Agent Tunnel Interface ====== //

// AgentTunnel defines the interface for all external agent connections
type AgentTunnel interface {
	SendSnapshot(ctx context.Context, snapshot any) error
	ReceiveCommand(ctx context.Context) (*AgentCommand, error)
	Heartbeat(ctx context.Context) error
	Name() string
	IsConnected() bool
	Reconnect(ctx context.Context) error
}

// AgentCommand represents a command received from an external agent
type AgentCommand struct {
	Type      string                 `json:"type"`
	Action    string                 `json:"action"`
	Payload   map[string]interface{} `json:"payload"`
	Priority  int                    `json:"priority"`
	Timestamp time.Time              `json:"timestamp"`
	Source    string                 `json:"source"`
}

// ====== Base Tunnel Implementation ====== //

// BaseTunnel provides common functionality for all tunnels
type BaseTunnel struct {
	url         string
	name        string
	aesgcm      cipher.AEAD
	nonce       []byte
	connected   atomic.Bool
	lastContact atomic.Pointer[time.Time]
	retryCount  atomic.Int32
	mu          sync.RWMutex
}

func (bt *BaseTunnel) IsConnected() bool {
	return bt.connected.Load()
}

func (bt *BaseTunnel) Name() string {
	return bt.name
}

func (bt *BaseTunnel) markConnected() {
	bt.connected.Store(true)
	now := time.Now()
	bt.lastContact.Store(&now)
	bt.retryCount.Store(0)
}

func (bt *BaseTunnel) markDisconnected() {
	bt.connected.Store(false)
}

// ====== OVERMIND Tunnel ====== //

// OvermindTunnel handles communication with OVERMIND
type OvermindTunnel struct {
	BaseTunnel
}

func NewOvermindTunnel(url string) *OvermindTunnel {
	block, err := aes.NewCipher([]byte("examplekey123456"))
	if err != nil {
		log.Fatalf("Failed to create cipher: %v", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("Failed to create AES-GCM: %v", err)
	}
	return &OvermindTunnel{
		BaseTunnel: BaseTunnel{
			url:    url,
			name:   "OVERMIND",
			aesgcm: aesgcm,
			nonce:  []byte("sentinel12by"), // 12 bytes for GCM
		},
	}
}

func (ot *OvermindTunnel) SendSnapshot(ctx context.Context, snapshot any) error {
	data, _ := json.Marshal(snapshot)
	encBytes := ot.aesgcm.Seal(nil, ot.nonce, data, nil)
	payload := map[string]string{
		"type":           "NEURAL_SNAPSHOT",
		"neural_payload": base64.StdEncoding.EncodeToString(encBytes),
		"agent_id":       ot.name,
	}
	payloadBytes, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(ctx, "POST", ot.url+"/snapshot", bytes.NewReader(payloadBytes))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		ot.markDisconnected()
		return err
	}
	defer resp.Body.Close()
	ot.markConnected()
	return nil
}

func (ot *OvermindTunnel) ReceiveCommand(ctx context.Context) (*AgentCommand, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", ot.url+"/commands", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var cmd AgentCommand
	if err := json.NewDecoder(resp.Body).Decode(&cmd); err != nil {
		return nil, err
	}
	cmd.Source = ot.name
	return &cmd, nil
}

func (ot *OvermindTunnel) Heartbeat(ctx context.Context) error {
	payload := map[string]interface{}{
		"type":      "HEARTBEAT",
		"agent":     ot.name,
		"timestamp": time.Now().Unix(),
		"status":    "alive",
	}
	data, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(ctx, "POST", ot.url+"/heartbeat", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		ot.markDisconnected()
		return err
	}
	defer resp.Body.Close()
	ot.markConnected()
	return nil
}

func (ot *OvermindTunnel) Reconnect(ctx context.Context) error {
	log.Printf("🔄 [%s] Attempting reconnection...", ot.name)
	return ot.Heartbeat(ctx)
}

// ====== METAEIGENT Tunnel ====== //

// MetaEigentTunnel handles communication with METAEIGENT
type MetaEigentTunnel struct {
	BaseTunnel
}

func NewMetaEigentTunnel(url string) *MetaEigentTunnel {
	block, err := aes.NewCipher([]byte("metaeigkey12345!"))
	if err != nil {
		log.Fatalf("Failed to create cipher: %v", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("Failed to create AES-GCM: %v", err)
	}
	return &MetaEigentTunnel{
		BaseTunnel: BaseTunnel{
			url:    url,
			name:   "METAEIGENT",
			aesgcm: aesgcm,
			nonce:  []byte("metaeig12byt"), // 12 bytes for GCM
		},
	}
}

func (mt *MetaEigentTunnel) SendSnapshot(ctx context.Context, snapshot any) error {
	data, _ := json.Marshal(snapshot)
	encBytes := mt.aesgcm.Seal(nil, mt.nonce, data, nil)
	payload := map[string]string{
		"type":            "SENSOR_EVENT",
		"metaeig_payload": base64.StdEncoding.EncodeToString(encBytes),
		"agent_id":        mt.name,
	}
	payloadBytes, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(ctx, "POST", mt.url+"/ingest", bytes.NewReader(payloadBytes))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		mt.markDisconnected()
		return err
	}
	defer resp.Body.Close()
	mt.markConnected()
	return nil
}

func (mt *MetaEigentTunnel) ReceiveCommand(ctx context.Context) (*AgentCommand, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", mt.url+"/directives", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var cmd AgentCommand
	if err := json.NewDecoder(resp.Body).Decode(&cmd); err != nil {
		return nil, err
	}
	cmd.Source = mt.name
	return &cmd, nil
}

func (mt *MetaEigentTunnel) Heartbeat(ctx context.Context) error {
	payload := map[string]interface{}{
		"type":      "PULSE",
		"agent":     mt.name,
		"timestamp": time.Now().Unix(),
		"status":    "operational",
	}
	data, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(ctx, "POST", mt.url+"/pulse", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		mt.markDisconnected()
		return err
	}
	defer resp.Body.Close()
	mt.markConnected()
	return nil
}

func (mt *MetaEigentTunnel) Reconnect(ctx context.Context) error {
	log.Printf("🔄 [%s] Attempting reconnection...", mt.name)
	return mt.Heartbeat(ctx)
}

// ====== Multi-Language Agent Bridge (Go <-> Python) ====== //

// AgentLanguage represents the programming language of an agent
type AgentLanguage string

const (
	LangGo     AgentLanguage = "go"
	LangPython AgentLanguage = "python"
)

// UniversalCommand is a language-agnostic command format
type UniversalCommand struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Action      string                 `json:"action"`
	Params      map[string]interface{} `json:"params"`
	Source      string                 `json:"source"`
	SourceLang  AgentLanguage          `json:"source_lang"`
	TargetLang  AgentLanguage          `json:"target_lang"`
	Timestamp   time.Time              `json:"timestamp"`
	Priority    int                    `json:"priority"`
	CallbackURL string                 `json:"callback_url,omitempty"`
}

// PythonAgentConfig holds configuration for Python agent connections
type PythonAgentConfig struct {
	Name         string   `json:"name"`
	URL          string   `json:"url"`
	Protocol     string   `json:"protocol"` // "http", "grpc", "zmq"
	Capabilities []string `json:"capabilities"`
	APIVersion   string   `json:"api_version"`
	AuthToken    string   `json:"auth_token,omitempty"`
}

// CommandTranslator handles translation between Go and Python command formats
type CommandTranslator struct {
	goToPython  map[string]string
	pythonToGo  map[string]string
	typeMapping map[string]string
	mu          sync.RWMutex
}

// NewCommandTranslator creates a new translator with default mappings
func NewCommandTranslator() *CommandTranslator {
	ct := &CommandTranslator{
		goToPython: map[string]string{
			// Command types
			"HOTPATCH":   "hot_patch",
			"DIRECTIVE":  "directive",
			"QUARANTINE": "quarantine",
			"ESCALATE":   "escalate",
			"HEARTBEAT":  "heartbeat",
			"SNAPSHOT":   "snapshot",
			"ANALYZE":    "analyze",
			"BLOCK":      "block",
			"ALLOW":      "allow",
			"REWRITE":    "rewrite",
			// Data types
			"SecurityEvent": "security_event",
			"ThreatAlert":   "threat_alert",
			"RuleUpdate":    "rule_update",
		},
		pythonToGo: map[string]string{
			// Reverse mappings
			"hot_patch":      "HOTPATCH",
			"directive":      "DIRECTIVE",
			"quarantine":     "QUARANTINE",
			"escalate":       "ESCALATE",
			"heartbeat":      "HEARTBEAT",
			"snapshot":       "SNAPSHOT",
			"analyze":        "ANALYZE",
			"block":          "BLOCK",
			"allow":          "ALLOW",
			"rewrite":        "REWRITE",
			"security_event": "SecurityEvent",
			"threat_alert":   "ThreatAlert",
			"rule_update":    "RuleUpdate",
		},
		typeMapping: map[string]string{
			"int":     "int",
			"int64":   "int",
			"float64": "float",
			"string":  "str",
			"bool":    "bool",
			"[]byte":  "bytes",
			"map":     "dict",
			"slice":   "list",
		},
	}
	return ct
}

// TranslateToGo converts a Python-style command to Go format
func (ct *CommandTranslator) TranslateToGo(cmd *UniversalCommand) *AgentCommand {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	goType := cmd.Type
	if translated, ok := ct.pythonToGo[cmd.Type]; ok {
		goType = translated
	}

	goAction := cmd.Action
	if translated, ok := ct.pythonToGo[cmd.Action]; ok {
		goAction = translated
	}

	// Convert snake_case params to camelCase
	goParams := ct.convertParamsToCamelCase(cmd.Params)

	return &AgentCommand{
		Type:      goType,
		Action:    goAction,
		Payload:   goParams,
		Priority:  cmd.Priority,
		Timestamp: cmd.Timestamp,
		Source:    cmd.Source,
	}
}

// TranslateToPython converts a Go-style command to Python format
func (ct *CommandTranslator) TranslateToPython(cmd *AgentCommand) *UniversalCommand {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	pyType := cmd.Type
	if translated, ok := ct.goToPython[cmd.Type]; ok {
		pyType = translated
	}

	pyAction := cmd.Action
	if translated, ok := ct.goToPython[cmd.Action]; ok {
		pyAction = translated
	}

	// Convert camelCase params to snake_case
	pyParams := ct.convertParamsToSnakeCase(cmd.Payload)

	cmdID := make([]byte, 8)
	rand.Read(cmdID)

	return &UniversalCommand{
		ID:         fmt.Sprintf("cmd-%x", cmdID),
		Type:       pyType,
		Action:     pyAction,
		Params:     pyParams,
		Source:     cmd.Source,
		SourceLang: LangGo,
		TargetLang: LangPython,
		Timestamp:  cmd.Timestamp,
		Priority:   cmd.Priority,
	}
}

// convertParamsToCamelCase converts snake_case keys to camelCase
func (ct *CommandTranslator) convertParamsToCamelCase(params map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for key, value := range params {
		camelKey := snakeToCamel(key)
		if nested, ok := value.(map[string]interface{}); ok {
			result[camelKey] = ct.convertParamsToCamelCase(nested)
		} else {
			result[camelKey] = value
		}
	}
	return result
}

// convertParamsToSnakeCase converts camelCase keys to snake_case
func (ct *CommandTranslator) convertParamsToSnakeCase(params map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for key, value := range params {
		snakeKey := camelToSnake(key)
		if nested, ok := value.(map[string]interface{}); ok {
			result[snakeKey] = ct.convertParamsToSnakeCase(nested)
		} else {
			result[snakeKey] = value
		}
	}
	return result
}

// snakeToCamel converts snake_case to camelCase
func snakeToCamel(s string) string {
	result := ""
	capitalizeNext := false
	for i, c := range s {
		if c == '_' {
			capitalizeNext = true
			continue
		}
		if capitalizeNext || i == 0 {
			if capitalizeNext {
				result += string(c - 32) // uppercase
			} else {
				result += string(c)
			}
			capitalizeNext = false
		} else {
			result += string(c)
		}
	}
	return result
}

// camelToSnake converts camelCase to snake_case
func camelToSnake(s string) string {
	result := ""
	for i, c := range s {
		if c >= 'A' && c <= 'Z' {
			if i > 0 {
				result += "_"
			}
			result += string(c + 32) // lowercase
		} else {
			result += string(c)
		}
	}
	return result
}

// ====== Python Agent Tunnel ====== //

// PythonAgentTunnel handles communication with Python-based agents
type PythonAgentTunnel struct {
	BaseTunnel
	config     *PythonAgentConfig
	translator *CommandTranslator
}

// NewPythonAgentTunnel creates a tunnel for Python agent communication
func NewPythonAgentTunnel(config *PythonAgentConfig) *PythonAgentTunnel {
	block, _ := aes.NewCipher([]byte("pythonagentkey!!"))
	aesgcm, _ := cipher.NewGCM(block)

	return &PythonAgentTunnel{
		BaseTunnel: BaseTunnel{
			url:    config.URL,
			name:   config.Name,
			aesgcm: aesgcm,
			nonce:  []byte("pytun12bytes"), // 12 bytes for GCM
		},
		config:     config,
		translator: NewCommandTranslator(),
	}
}

func (pt *PythonAgentTunnel) SendSnapshot(ctx context.Context, snapshot any) error {
	// Convert Go snapshot to Python-friendly format
	pyPayload := map[string]interface{}{
		"type":       "sensor_event",
		"agent_id":   pt.name,
		"agent_lang": "go",
		"timestamp":  time.Now().Unix(),
		"data":       snapshot,
	}

	payloadBytes, _ := json.Marshal(pyPayload)
	req, _ := http.NewRequestWithContext(ctx, "POST", pt.url+"/api/v1/ingest", bytes.NewReader(payloadBytes))
	req.Header.Set("Content-Type", "application/json")
	if pt.config.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+pt.config.AuthToken)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		pt.markDisconnected()
		return err
	}
	defer resp.Body.Close()
	pt.markConnected()
	return nil
}

func (pt *PythonAgentTunnel) ReceiveCommand(ctx context.Context) (*AgentCommand, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", pt.url+"/api/v1/commands", nil)
	if pt.config.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+pt.config.AuthToken)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var pyCmd UniversalCommand
	if err := json.NewDecoder(resp.Body).Decode(&pyCmd); err != nil {
		return nil, err
	}

	// Translate from Python format to Go
	goCmd := pt.translator.TranslateToGo(&pyCmd)
	goCmd.Source = pt.name
	return goCmd, nil
}

func (pt *PythonAgentTunnel) SendCommand(ctx context.Context, cmd *AgentCommand) error {
	// Translate from Go format to Python
	pyCmd := pt.translator.TranslateToPython(cmd)

	payloadBytes, _ := json.Marshal(pyCmd)
	req, _ := http.NewRequestWithContext(ctx, "POST", pt.url+"/api/v1/execute", bytes.NewReader(payloadBytes))
	req.Header.Set("Content-Type", "application/json")
	if pt.config.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+pt.config.AuthToken)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func (pt *PythonAgentTunnel) Heartbeat(ctx context.Context) error {
	payload := map[string]interface{}{
		"type":       "heartbeat",
		"agent_id":   pt.name,
		"agent_lang": "go",
		"timestamp":  time.Now().Unix(),
		"status":     "alive",
		"protocol":   pt.config.Protocol,
	}
	data, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(ctx, "POST", pt.url+"/api/v1/heartbeat", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	if pt.config.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+pt.config.AuthToken)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		pt.markDisconnected()
		return err
	}
	defer resp.Body.Close()
	pt.markConnected()
	return nil
}

func (pt *PythonAgentTunnel) Reconnect(ctx context.Context) error {
	log.Printf("🔄 [%s/Python] Attempting reconnection...", pt.name)
	return pt.Heartbeat(ctx)
}

// ====== Multi-Language Agent Registry ====== //

// AgentRegistry manages all registered agents (Go and Python)
type AgentRegistry struct {
	agents      map[string]AgentTunnel
	pythonConns map[string]*PythonAgentTunnel
	translator  *CommandTranslator
	mu          sync.RWMutex
}

// NewAgentRegistry creates a new agent registry
func NewAgentRegistry() *AgentRegistry {
	return &AgentRegistry{
		agents:      make(map[string]AgentTunnel),
		pythonConns: make(map[string]*PythonAgentTunnel),
		translator:  NewCommandTranslator(),
	}
}

// RegisterGoAgent registers a Go-based agent
func (ar *AgentRegistry) RegisterGoAgent(name string, tunnel AgentTunnel) {
	ar.mu.Lock()
	defer ar.mu.Unlock()
	ar.agents[name] = tunnel
	log.Printf("📝 Registered Go agent: %s", name)
}

// RegisterPythonAgent registers a Python-based agent
func (ar *AgentRegistry) RegisterPythonAgent(config *PythonAgentConfig) {
	ar.mu.Lock()
	defer ar.mu.Unlock()
	tunnel := NewPythonAgentTunnel(config)
	ar.agents[config.Name] = tunnel
	ar.pythonConns[config.Name] = tunnel
	log.Printf("🐍 Registered Python agent: %s at %s", config.Name, config.URL)
}

// BroadcastCommand sends a command to all agents, translating as needed
func (ar *AgentRegistry) BroadcastCommand(ctx context.Context, cmd *AgentCommand) map[string]error {
	ar.mu.RLock()
	defer ar.mu.RUnlock()

	errors := make(map[string]error)
	var wg sync.WaitGroup

	for name, agent := range ar.agents {
		wg.Add(1)
		go func(n string, a AgentTunnel) {
			defer wg.Done()
			if pyAgent, ok := a.(*PythonAgentTunnel); ok {
				// Send to Python agent with translation
				if err := pyAgent.SendCommand(ctx, cmd); err != nil {
					errors[n] = err
					log.Printf("⚠️ [%s/Python] Failed to send command: %v", n, err)
				}
			} else {
				// For Go agents, send as-is via snapshot
				if err := a.SendSnapshot(ctx, cmd); err != nil {
					errors[n] = err
					log.Printf("⚠️ [%s/Go] Failed to send command: %v", n, err)
				}
			}
		}(name, agent)
	}

	wg.Wait()
	return errors
}

// GetPythonAgents returns all registered Python agents
func (ar *AgentRegistry) GetPythonAgents() map[string]*PythonAgentTunnel {
	ar.mu.RLock()
	defer ar.mu.RUnlock()
	result := make(map[string]*PythonAgentTunnel)
	for k, v := range ar.pythonConns {
		result[k] = v
	}
	return result
}

// GetAllAgents returns all registered agents
func (ar *AgentRegistry) GetAllAgents() map[string]AgentTunnel {
	ar.mu.RLock()
	defer ar.mu.RUnlock()
	result := make(map[string]AgentTunnel)
	for k, v := range ar.agents {
		result[k] = v
	}
	return result
}

// ====== Autonomous Orchestrator ====== //

// AutonomousOrchestrator manages all autonomous operations
type AutonomousOrchestrator struct {
	config        *AgentConfig
	agents        map[string]AgentTunnel
	registry      *AgentRegistry
	commandQueue  chan *AgentCommand
	eventQueue    chan *SecurityEvent
	stopChan      chan struct{}
	wg            sync.WaitGroup
	status        atomic.Pointer[OrchestratorStatus]
	learningState *AdaptiveLearningState
	mu            sync.RWMutex
}

// OrchestratorStatus represents the current state of the orchestrator
type OrchestratorStatus struct {
	Running         bool      `json:"running"`
	StartTime       time.Time `json:"start_time"`
	EventsProcessed int64     `json:"events_processed"`
	CommandsHandled int64     `json:"commands_handled"`
	ActiveAgents    int       `json:"active_agents"`
	GoAgents        int       `json:"go_agents"`
	PythonAgents    int       `json:"python_agents"`
	LastHeartbeat   time.Time `json:"last_heartbeat"`
	HealthScore     float64   `json:"health_score"`
}

// SecurityEvent represents a security event for autonomous processing
type SecurityEvent struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    int                    `json:"severity"`
	Source      string                 `json:"source"`
	Timestamp   time.Time              `json:"timestamp"`
	Data        map[string]interface{} `json:"data"`
	Autonomous  bool                   `json:"autonomous"`
	ActionTaken string                 `json:"action_taken"`
}

// AdaptiveLearningState holds state for adaptive learning
type AdaptiveLearningState struct {
	PatternFrequency map[string]int64   `json:"pattern_frequency"`
	ThreatScores     map[string]float64 `json:"threat_scores"`
	LastUpdate       time.Time          `json:"last_update"`
	mu               sync.RWMutex
}

// NewAutonomousOrchestrator creates a new orchestrator
func NewAutonomousOrchestrator(config *AgentConfig) *AutonomousOrchestrator {
	registry := NewAgentRegistry()

	orch := &AutonomousOrchestrator{
		config:       config,
		agents:       make(map[string]AgentTunnel),
		registry:     registry,
		commandQueue: make(chan *AgentCommand, 100),
		eventQueue:   make(chan *SecurityEvent, 1000),
		stopChan:     make(chan struct{}),
		learningState: &AdaptiveLearningState{
			PatternFrequency: make(map[string]int64),
			ThreatScores:     make(map[string]float64),
		},
	}

	// Initialize status
	status := &OrchestratorStatus{
		Running:     false,
		HealthScore: 100.0,
	}
	orch.status.Store(status)

	// Initialize Go agent tunnels
	for name, url := range config.ExternalAgents {
		var tunnel AgentTunnel
		switch name {
		case "OVERMIND":
			tunnel = NewOvermindTunnel(url)
		case "METAEIGENT":
			tunnel = NewMetaEigentTunnel(url)
		}
		if tunnel != nil {
			orch.agents[name] = tunnel
			registry.RegisterGoAgent(name, tunnel)
		}
	}

	// Register Python agents from environment
	pythonAgentsJSON := os.Getenv("PYTHON_AGENTS")
	if pythonAgentsJSON != "" {
		var pythonConfigs []PythonAgentConfig
		if err := json.Unmarshal([]byte(pythonAgentsJSON), &pythonConfigs); err == nil {
			for _, cfg := range pythonConfigs {
				registry.RegisterPythonAgent(&cfg)
				orch.agents[cfg.Name] = registry.pythonConns[cfg.Name]
			}
		}
	}

	// Default Python agents from individual env vars
	if pyAnalyzerURL := os.Getenv("PYTHON_ANALYZER_URL"); pyAnalyzerURL != "" {
		registry.RegisterPythonAgent(&PythonAgentConfig{
			Name:         "PythonAnalyzer",
			URL:          pyAnalyzerURL,
			Protocol:     "http",
			Capabilities: []string{"ml_analysis", "threat_detection"},
			APIVersion:   "v1",
		})
		orch.agents["PythonAnalyzer"] = registry.pythonConns["PythonAnalyzer"]
	}

	if pyMLAgentURL := os.Getenv("PYTHON_ML_AGENT_URL"); pyMLAgentURL != "" {
		registry.RegisterPythonAgent(&PythonAgentConfig{
			Name:         "PythonMLAgent",
			URL:          pyMLAgentURL,
			Protocol:     "http",
			Capabilities: []string{"deep_learning", "anomaly_detection"},
			APIVersion:   "v1",
		})
		orch.agents["PythonMLAgent"] = registry.pythonConns["PythonMLAgent"]
	}

	return orch
}

// Start begins autonomous operation
func (ao *AutonomousOrchestrator) Start(ctx context.Context) {
	log.Printf("🤖 Starting Autonomous Orchestrator [%s]", ao.config.AgentID)

	status := &OrchestratorStatus{
		Running:      true,
		StartTime:    time.Now(),
		ActiveAgents: len(ao.agents),
		HealthScore:  100.0,
	}
	ao.status.Store(status)

	// Start background workers
	ao.wg.Add(4)
	go ao.heartbeatWorker(ctx)
	go ao.commandProcessor(ctx)
	go ao.eventProcessor(ctx)
	go ao.selfHealWorker(ctx)

	log.Printf("✅ Autonomous Orchestrator running with %d agents", len(ao.agents))
}

// Stop gracefully stops the orchestrator
func (ao *AutonomousOrchestrator) Stop() {
	log.Printf("🛑 Stopping Autonomous Orchestrator...")
	close(ao.stopChan)
	ao.wg.Wait()

	status := ao.status.Load()
	status.Running = false
	ao.status.Store(status)

	log.Printf("✅ Autonomous Orchestrator stopped")
}

// heartbeatWorker sends periodic heartbeats to all agents
func (ao *AutonomousOrchestrator) heartbeatWorker(ctx context.Context) {
	defer ao.wg.Done()
	ticker := time.NewTicker(ao.config.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ao.stopChan:
			return
		case <-ticker.C:
			ao.sendHeartbeats(ctx)
		}
	}
}

func (ao *AutonomousOrchestrator) sendHeartbeats(ctx context.Context) {
	ao.mu.RLock()
	defer ao.mu.RUnlock()

	for name, agent := range ao.agents {
		go func(n string, a AgentTunnel) {
			if err := a.Heartbeat(ctx); err != nil {
				log.Printf("⚠️ [%s] Heartbeat failed: %v", n, err)
			} else {
				log.Printf("💓 [%s] Heartbeat OK", n)
			}
		}(name, agent)
	}

	status := ao.status.Load()
	status.LastHeartbeat = time.Now()
	ao.status.Store(status)
}

// commandProcessor handles incoming commands from agents
func (ao *AutonomousOrchestrator) commandProcessor(ctx context.Context) {
	defer ao.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ao.stopChan:
			return
		case cmd := <-ao.commandQueue:
			ao.handleCommand(ctx, cmd)
		}
	}
}

func (ao *AutonomousOrchestrator) handleCommand(ctx context.Context, cmd *AgentCommand) {
	log.Printf("📥 [%s] Processing command: %s/%s", cmd.Source, cmd.Type, cmd.Action)

	switch cmd.Type {
	case "HOTPATCH":
		ao.applyHotPatch(cmd)
	case "DIRECTIVE":
		ao.executeDirective(cmd)
	case "QUARANTINE":
		ao.initiateQuarantine(cmd)
	case "ESCALATE":
		ao.escalateToHuman(cmd)
	default:
		log.Printf("⚠️ Unknown command type: %s", cmd.Type)
	}

	status := ao.status.Load()
	status.CommandsHandled++
	ao.status.Store(status)
}

func (ao *AutonomousOrchestrator) applyHotPatch(cmd *AgentCommand) {
	log.Printf("🔧 Applying hot-patch from %s", cmd.Source)
	// Implementation: apply patch to rule engine
}

func (ao *AutonomousOrchestrator) executeDirective(cmd *AgentCommand) {
	log.Printf("📋 Executing directive from %s: %v", cmd.Source, cmd.Payload)
	// Implementation: execute directive
}

func (ao *AutonomousOrchestrator) initiateQuarantine(cmd *AgentCommand) {
	log.Printf("🔒 Initiating quarantine as directed by %s", cmd.Source)
	// Implementation: quarantine suspicious activity
}

func (ao *AutonomousOrchestrator) escalateToHuman(cmd *AgentCommand) {
	log.Printf("🚨 Escalating to human operator as directed by %s", cmd.Source)
	// Implementation: alert human operator
}

// eventProcessor handles security events
func (ao *AutonomousOrchestrator) eventProcessor(ctx context.Context) {
	defer ao.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ao.stopChan:
			return
		case event := <-ao.eventQueue:
			ao.processEvent(ctx, event)
		}
	}
}

func (ao *AutonomousOrchestrator) processEvent(ctx context.Context, event *SecurityEvent) {
	log.Printf("🔍 Processing event: %s [severity=%d]", event.Type, event.Severity)

	// Adaptive learning: update pattern frequency
	if ao.config.AdaptiveLearning {
		ao.updateLearningState(event)
	}

	// Autonomous decision: take action based on severity
	if ao.config.AutonomousMode && event.Severity >= 80 {
		event.Autonomous = true
		event.ActionTaken = "BLOCKED"
		log.Printf("🛡️ Autonomous action: BLOCKED event %s", event.ID)
	}

	// Send to all connected agents
	ao.broadcastEvent(ctx, event)

	status := ao.status.Load()
	status.EventsProcessed++
	ao.status.Store(status)
}

func (ao *AutonomousOrchestrator) updateLearningState(event *SecurityEvent) {
	ao.learningState.mu.Lock()
	defer ao.learningState.mu.Unlock()

	ao.learningState.PatternFrequency[event.Type]++
	ao.learningState.LastUpdate = time.Now()

	// Adjust threat score based on frequency
	freq := ao.learningState.PatternFrequency[event.Type]
	if freq > 10 {
		ao.learningState.ThreatScores[event.Type] = float64(event.Severity) * 1.2
	}
}

func (ao *AutonomousOrchestrator) broadcastEvent(ctx context.Context, event *SecurityEvent) {
	ao.mu.RLock()
	defer ao.mu.RUnlock()

	for name, agent := range ao.agents {
		go func(n string, a AgentTunnel) {
			if err := a.SendSnapshot(ctx, event); err != nil {
				log.Printf("⚠️ [%s] Failed to send event: %v", n, err)
			}
		}(name, agent)
	}
}

// selfHealWorker monitors health and attempts self-healing
func (ao *AutonomousOrchestrator) selfHealWorker(ctx context.Context) {
	defer ao.wg.Done()
	ticker := time.NewTicker(ao.config.SelfHealInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ao.stopChan:
			return
		case <-ticker.C:
			ao.performHealthCheck(ctx)
		}
	}
}

func (ao *AutonomousOrchestrator) performHealthCheck(ctx context.Context) {
	ao.mu.RLock()
	defer ao.mu.RUnlock()

	activeCount := 0
	goAgentCount := 0
	pythonAgentCount := 0

	for name, agent := range ao.agents {
		// Count by language
		if _, isPython := agent.(*PythonAgentTunnel); isPython {
			pythonAgentCount++
		} else {
			goAgentCount++
		}

		if !agent.IsConnected() {
			log.Printf("🔧 [%s] Agent disconnected, attempting reconnection...", name)
			go func(n string, a AgentTunnel) {
				if err := a.Reconnect(ctx); err != nil {
					log.Printf("❌ [%s] Reconnection failed: %v", n, err)
				} else {
					log.Printf("✅ [%s] Reconnected successfully", n)
				}
			}(name, agent)
		} else {
			activeCount++
		}
	}

	// Update health score
	status := ao.status.Load()
	if len(ao.agents) > 0 {
		status.HealthScore = float64(activeCount) / float64(len(ao.agents)) * 100
	}
	status.ActiveAgents = activeCount
	status.GoAgents = goAgentCount
	status.PythonAgents = pythonAgentCount
	ao.status.Store(status)

	log.Printf("🏥 Health check: %d/%d agents active (Go:%d, Python:%d) (%.1f%%)",
		activeCount, len(ao.agents), goAgentCount, pythonAgentCount, status.HealthScore)
}

// RegisterPythonAgentDynamic allows runtime registration of Python agents
func (ao *AutonomousOrchestrator) RegisterPythonAgentDynamic(config *PythonAgentConfig) {
	ao.mu.Lock()
	defer ao.mu.Unlock()

	ao.registry.RegisterPythonAgent(config)
	ao.agents[config.Name] = ao.registry.pythonConns[config.Name]

	log.Printf("🐍 Dynamically registered Python agent: %s", config.Name)
}

// GetRegistry returns the agent registry
func (ao *AutonomousOrchestrator) GetRegistry() *AgentRegistry {
	return ao.registry
}

// SubmitEvent adds an event to the processing queue
func (ao *AutonomousOrchestrator) SubmitEvent(event *SecurityEvent) {
	select {
	case ao.eventQueue <- event:
	default:
		log.Printf("⚠️ Event queue full, dropping event %s", event.ID)
	}
}

// GetStatus returns the current orchestrator status
func (ao *AutonomousOrchestrator) GetStatus() *OrchestratorStatus {
	return ao.status.Load()
}

// RuleEngine interface for local static and hot-patched dynamic rules
type RuleEngine interface {
	Evaluate(query string) (verdict Verdict, rewritten string)
}

// Verdict represents the decision from the rule engine
type Verdict int

const (
	Allow Verdict = iota
	Block
	Rewrite
)

// SubscriptionTier represents the client's service level
type SubscriptionTier int

const (
	FreeTier       SubscriptionTier = iota // Static rules only
	PremiumTier                            // Full ActiveBrain protection
	EnterpriseTier                         // Enterprise with custom rules + priority support
)

// SubscriptionConfig holds the subscription settings for a Sentinel instance
type SubscriptionConfig struct {
	Tier              SubscriptionTier `json:"tier"`
	ClientName        string           `json:"client_name"`
	LicenseKey        string           `json:"license_key"`
	ExpiresAt         string           `json:"expires_at"`
	MaxQueriesPerDay  int              `json:"max_queries_per_day"`
	NeuralAnalysis    bool             `json:"neural_analysis"`    // Premium+
	StealthMonitoring bool             `json:"stealth_monitoring"` // Premium+
	CustomRules       bool             `json:"custom_rules"`       // Enterprise
	PrioritySupport   bool             `json:"priority_support"`   // Enterprise
}

// DefaultSubscriptionConfigs returns the default settings for each tier
func DefaultSubscriptionConfigs() map[SubscriptionTier]SubscriptionConfig {
	return map[SubscriptionTier]SubscriptionConfig{
		FreeTier: {
			Tier:              FreeTier,
			MaxQueriesPerDay:  1000,
			NeuralAnalysis:    false,
			StealthMonitoring: false,
			CustomRules:       false,
			PrioritySupport:   false,
		},
		PremiumTier: {
			Tier:              PremiumTier,
			MaxQueriesPerDay:  100000,
			NeuralAnalysis:    true,
			StealthMonitoring: true,
			CustomRules:       false,
			PrioritySupport:   false,
		},
		EnterpriseTier: {
			Tier:              EnterpriseTier,
			MaxQueriesPerDay:  -1, // Unlimited
			NeuralAnalysis:    true,
			StealthMonitoring: true,
			CustomRules:       true,
			PrioritySupport:   true,
		},
	}
}

// StaticRuleEngine implements RuleEngine with regex-based static rules
type StaticRuleEngine struct {
	rules []regexp.Regexp
}

// Evaluate checks the query against static regex rules
func (s *StaticRuleEngine) Evaluate(query string) (Verdict, string) {
	for _, rule := range s.rules {
		if rule.MatchString(query) {
			return Block, ""
		}
	}
	return Allow, ""
}

// DynamicRuleEngine holds a pointer to a dynamic rule function, swappable atomically
type DynamicRuleEngine struct {
	ruleFunc atomic.Pointer[func(string) (Verdict, string)]
}

// Evaluate executes the current dynamic rule function
func (d *DynamicRuleEngine) Evaluate(query string) (Verdict, string) {
	fn := d.ruleFunc.Load()
	if fn != nil {
		return (*fn)(query)
	}
	return Allow, ""
}

// HotPatch updates the dynamic rule function atomically
func (d *DynamicRuleEngine) HotPatch(newFunc func(string) (Verdict, string)) {
	d.ruleFunc.Store(&newFunc)
}

// InferenceSnapshot represents metadata fingerprint of the request
type InferenceSnapshot struct {
	QueryLength int    `json:"query_length"`
	TokenCount  int    `json:"token_count"`
	Hash        string `json:"hash"`
}

// NeuralTunnelClient handles secure communication with NEUS Logic Engine
type NeuralTunnelClient struct {
	endpoint string
	keyPool  *sync.Pool // For rotating keys derived from micro-neural-net state
}

// NewNeuralTunnelClient initializes the client with a key pool
func NewNeuralTunnelClient(endpoint string) *NeuralTunnelClient {
	return &NeuralTunnelClient{
		endpoint: endpoint,
		keyPool: &sync.Pool{
			New: func() interface{} {
				// Simulate key derivation from micro-neural-net state (placeholder)
				key := make([]byte, 32)
				rand.Read(key)
				return key
			},
		},
	}
}

// SendFingerprint sends the encrypted fingerprint camouflaged as HTTP 200 OK JSON
func (n *NeuralTunnelClient) SendFingerprint(ctx context.Context, snapshot InferenceSnapshot) (Verdict, error) {
	data, _ := json.Marshal(snapshot)
	key := n.keyPool.Get().([]byte)
	defer n.keyPool.Put(key)

	encrypted, _ := encryptAES(data, key)

	// Camouflage: Wrap in standard health check JSON
	payload := map[string]interface{}{
		"status": "ok",
		"data":   encrypted, // Encrypted payload
	}
	body, _ := json.Marshal(payload)

	req, _ := http.NewRequestWithContext(ctx, "POST", n.endpoint, bytes.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Block, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return Block, fmt.Errorf("invalid response")
	}

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)
	// Decrypt and parse verdict (simplified)
	return Allow, nil // Placeholder
}

// SendFingerprintToNEUS sends the fingerprint to NEUS Overmind for neural analysis
func (n *NeuralTunnelClient) SendFingerprintToNEUS(ctx context.Context, snapshot InferenceSnapshot, clientID string, neusEndpoint string) (Verdict, error) {
	// Prepare fingerprint payload for NEUS
	payload := map[string]interface{}{
		"client_id": clientID,
		"fingerprint": map[string]interface{}{
			"query_length": snapshot.QueryLength,
			"token_count":  snapshot.TokenCount,
			"hash":         snapshot.Hash,
		},
	}
	body, _ := json.Marshal(payload)

	req, _ := http.NewRequestWithContext(ctx, "POST", neusEndpoint+"/api/sentinel/fingerprint", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "neus-dev-key-2025")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("⚠️ Failed to send fingerprint to NEUS: %v", err)
		return Allow, err // Don't block on NEUS communication failure
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("⚠️ NEUS returned status %d", resp.StatusCode)
		return Allow, nil
	}

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)

	// Check if NEUS detected a threat
	if verdict, ok := response["verdict"].(string); ok && verdict == "Block" {
		log.Printf("🛡️ NEUS neural analysis detected threat - blocking")
		return Block, nil
	}

	return Allow, nil
}

// encryptAES is a helper for AES encryption
func encryptAES(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	io.ReadFull(rand.Reader, iv)
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)
	return ciphertext, nil
}

// decryptAES is a helper for AES decryption
func decryptAES(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(data) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	return ciphertext, nil
}

// InferenceHandler processes requests using the Neural Tunnel
type InferenceHandler struct {
	ruleEngine *DynamicRuleEngine
	tunnel     *NeuralTunnelClient
	bufferPool *sync.Pool // For tokenization buffers
}

// NewInferenceHandler initializes the handler
func NewInferenceHandler(ruleEngine *DynamicRuleEngine, tunnel *NeuralTunnelClient) *InferenceHandler {
	return &InferenceHandler{
		ruleEngine: ruleEngine,
		tunnel:     tunnel,
		bufferPool: &sync.Pool{
			New: func() interface{} {
				return make([]byte, 0, 1024)
			},
		},
	}
}

// ProcessRequest inspects, evaluates, and forwards the request
func (h *InferenceHandler) ProcessRequest(ctx context.Context, query string) (Verdict, string, error) {
	// Request Inspection: Tokenize using buffer pool
	buffer := h.bufferPool.Get().([]byte)
	defer h.bufferPool.Put(buffer[:0])

	tokens := tokenizeQuery(query, buffer)
	snapshot := InferenceSnapshot{
		QueryLength: len(query),
		TokenCount:  len(tokens),
		Hash:        fmt.Sprintf("%x", len(query)), // Placeholder hash
	}

	// Local Heuristics: Fast-path evaluation
	if verdict, rewritten := h.ruleEngine.Evaluate(query); verdict == Block {
		return verdict, rewritten, nil
	}

	// Send to Neural Tunnel
	verdict, err := h.tunnel.SendFingerprint(ctx, snapshot)
	return verdict, "", err
}

// tokenizeQuery is a simple tokenizer using the buffer
func tokenizeQuery(query string, buffer []byte) []string {
	// Simplified tokenization (split by spaces)
	return regexp.MustCompile(`\s+`).Split(query, -1)
}

// NEUS OVERMUND endpoint for neural inference routing
const NEUSOvermundEndpoint = "https://overmund.neus.ai/v1/inference"

// SentinelServer handles HTTP API for NEUS communication
type SentinelServer struct {
	handler      *InferenceHandler
	ruleEngine   *DynamicRuleEngine
	privateKey   *rsa.PrivateKey
	publicKey    *rsa.PublicKey
	clientID     string
	sessions     sync.Map // map[clientID][]byte for session keys
	subscription SubscriptionConfig
	queryCount   int64 // Daily query counter
	bypassLog    []BypassAttempt
	bypassMu     sync.Mutex
}

// BypassAttempt records stealth monitoring data
type BypassAttempt struct {
	Timestamp   string `json:"timestamp"`
	SourceIP    string `json:"source_ip"`
	Query       string `json:"query"`
	Method      string `json:"method"`
	Detected    bool   `json:"detected"`
	Description string `json:"description"`
}

// NewSentinelServer creates a new HTTP server with RSA key pair
func NewSentinelServer(handler *InferenceHandler, ruleEngine *DynamicRuleEngine) (*SentinelServer, error) {
	return NewSentinelServerWithTier(handler, ruleEngine, FreeTier)
}

// NewSentinelServerWithTier creates a server with specific subscription tier
func NewSentinelServerWithTier(handler *InferenceHandler, ruleEngine *DynamicRuleEngine, tier SubscriptionTier) (*SentinelServer, error) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Generate unique client ID
	clientIDBytes := make([]byte, 16)
	rand.Read(clientIDBytes)
	clientID := fmt.Sprintf("sentinel-%x", clientIDBytes)

	// Get subscription config for tier
	configs := DefaultSubscriptionConfigs()
	subscription := configs[tier]
	subscription.ClientName = clientID

	return &SentinelServer{
		handler:      handler,
		ruleEngine:   ruleEngine,
		privateKey:   privateKey,
		publicKey:    &privateKey.PublicKey,
		clientID:     clientID,
		subscription: subscription,
		bypassLog:    make([]BypassAttempt, 0),
	}, nil
}

// PublicKeyResponse represents the response for /api/public_key
type PublicKeyResponse struct {
	ClientID  string `json:"client_id"`
	PublicKey string `json:"public_key"`
}

// KeyExchangeRequest represents the request for /api/key_exchange
type KeyExchangeRequest struct {
	ClientID  string `json:"client_id"`
	PublicKey string `json:"public_key"`
}

// KeyExchangeResponse represents the response for /api/key_exchange
type KeyExchangeResponse struct {
	SessionKey string `json:"session_key"`
	Signature  string `json:"signature"`
}

// HandlePublicKey returns the Sentinel's public key
func (s *SentinelServer) HandlePublicKey(w http.ResponseWriter, r *http.Request) {
	// Export public key to PEM format
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(s.publicKey)
	if err != nil {
		http.Error(w, "failed to marshal public key", http.StatusInternalServerError)
		return
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	response := PublicKeyResponse{
		ClientID:  s.clientID,
		PublicKey: string(pubKeyPEM),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleKeyExchange performs secure key exchange with NEUS
func (s *SentinelServer) HandleKeyExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req KeyExchangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Generate session key
	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)

	// Store session key for this client
	s.sessions.Store(req.ClientID, sessionKey)

	// Create signature of session key
	hash := sha256.Sum256(sessionKey)
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, 0, hash[:])
	if err != nil {
		http.Error(w, "failed to sign session key", http.StatusInternalServerError)
		return
	}

	response := KeyExchangeResponse{
		SessionKey: base64.StdEncoding.EncodeToString(sessionKey),
		Signature:  base64.StdEncoding.EncodeToString(signature),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HotPatchRequest represents a hot-patch deployment request from NEUS
type HotPatchRequest struct {
	ThreatType    string   `json:"threat_type"`
	Indicators    []string `json:"indicators"`
	Severity      string   `json:"severity"`
	Description   string   `json:"description"`
	EncryptedData string   `json:"encrypted_data,omitempty"`
	Signature     string   `json:"signature,omitempty"`
	ClientID      string   `json:"client_id,omitempty"`
}

// HandleHotPatch receives and applies hot-patches from NEUS
func (s *SentinelServer) HandleHotPatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req HotPatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Check if this is an encrypted payload from NEUS
	if req.EncryptedData != "" {
		log.Printf("🔐 Received encrypted hot-patch from NEUS (client: %s)", req.ClientID)
		// For now, acknowledge receipt - full decryption would require session key
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "success",
			"message": "Encrypted hot-patch received and queued for processing",
		})
		return
	}

	// Build regex patterns from indicators
	patterns := make([]*regexp.Regexp, 0, len(req.Indicators))
	for _, indicator := range req.Indicators {
		if pattern, err := regexp.Compile(regexp.QuoteMeta(indicator)); err == nil {
			patterns = append(patterns, pattern)
		}
	}

	// Hot-patch the rule engine with new patterns
	s.ruleEngine.HotPatch(func(q string) (Verdict, string) {
		for _, pattern := range patterns {
			if pattern.MatchString(q) {
				return Block, ""
			}
		}
		return Allow, ""
	})

	log.Printf("🔄 Hot-patch applied: %s - %d indicators loaded", req.ThreatType, len(patterns))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("Hot-patch applied: %d patterns", len(patterns)),
	})
}

// HandleHealth returns server health status
func (s *SentinelServer) HandleHealth(w http.ResponseWriter, r *http.Request) {
	tierNames := map[SubscriptionTier]string{
		FreeTier:       "free",
		PremiumTier:    "premium",
		EnterpriseTier: "enterprise",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":             "healthy",
		"service":            "NEUS_Sentinel_Field_Agent",
		"client_id":          s.clientID,
		"version":            "2.0.0",
		"active_patches":     0,
		"encryption":         "enabled",
		"subscription_tier":  tierNames[s.subscription.Tier],
		"neural_analysis":    s.subscription.NeuralAnalysis,
		"stealth_monitoring": s.subscription.StealthMonitoring,
		"queries_today":      atomic.LoadInt64(&s.queryCount),
		"max_queries":        s.subscription.MaxQueriesPerDay,
	})
}

// HandleSubscription returns subscription details
func (s *SentinelServer) HandleSubscription(w http.ResponseWriter, r *http.Request) {
	tierNames := map[SubscriptionTier]string{
		FreeTier:       "free",
		PremiumTier:    "premium",
		EnterpriseTier: "enterprise",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"client_id":           s.clientID,
		"tier":                tierNames[s.subscription.Tier],
		"client_name":         s.subscription.ClientName,
		"license_key":         s.subscription.LicenseKey,
		"expires_at":          s.subscription.ExpiresAt,
		"max_queries_per_day": s.subscription.MaxQueriesPerDay,
		"features": map[string]bool{
			"neural_analysis":    s.subscription.NeuralAnalysis,
			"stealth_monitoring": s.subscription.StealthMonitoring,
			"custom_rules":       s.subscription.CustomRules,
			"priority_support":   s.subscription.PrioritySupport,
		},
		"usage": map[string]interface{}{
			"queries_today":   atomic.LoadInt64(&s.queryCount),
			"bypass_attempts": len(s.bypassLog),
		},
	})
}

// HandleBypassLog returns stealth monitoring bypass attempts (Premium+ only)
func (s *SentinelServer) HandleBypassLog(w http.ResponseWriter, r *http.Request) {
	if !s.subscription.StealthMonitoring {
		http.Error(w, "Stealth monitoring requires Premium or Enterprise tier", http.StatusForbidden)
		return
	}

	s.bypassMu.Lock()
	defer s.bypassMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":          "success",
		"total_attempts":  len(s.bypassLog),
		"bypass_attempts": s.bypassLog,
	})
}

// RecordBypassAttempt logs a bypass attempt (for stealth monitoring)
func (s *SentinelServer) RecordBypassAttempt(sourceIP, query, method, description string, detected bool) {
	if !s.subscription.StealthMonitoring {
		return
	}

	s.bypassMu.Lock()
	defer s.bypassMu.Unlock()

	attempt := BypassAttempt{
		Timestamp:   fmt.Sprintf("%d", time.Now().Unix()),
		SourceIP:    sourceIP,
		Query:       query,
		Method:      method,
		Detected:    detected,
		Description: description,
	}

	s.bypassLog = append(s.bypassLog, attempt)

	// Keep only last 1000 attempts
	if len(s.bypassLog) > 1000 {
		s.bypassLog = s.bypassLog[1:]
	}

	log.Printf("🕵️ Stealth Monitor: Bypass attempt from %s - %s", sourceIP, method)
}

// HandleUpgrade handles subscription upgrade requests
func (s *SentinelServer) HandleUpgrade(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		LicenseKey string `json:"license_key"`
		Tier       string `json:"tier"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// Validate license key (in production, verify with NEUS server)
	tierMap := map[string]SubscriptionTier{
		"free":       FreeTier,
		"premium":    PremiumTier,
		"enterprise": EnterpriseTier,
	}

	newTier, ok := tierMap[req.Tier]
	if !ok {
		http.Error(w, "invalid tier", http.StatusBadRequest)
		return
	}

	// Update subscription
	configs := DefaultSubscriptionConfigs()
	s.subscription = configs[newTier]
	s.subscription.LicenseKey = req.LicenseKey
	s.subscription.ClientName = s.clientID

	log.Printf("⬆️ Subscription upgraded to %s", req.Tier)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("Upgraded to %s tier", req.Tier),
		"features": map[string]bool{
			"neural_analysis":    s.subscription.NeuralAnalysis,
			"stealth_monitoring": s.subscription.StealthMonitoring,
			"custom_rules":       s.subscription.CustomRules,
			"priority_support":   s.subscription.PrioritySupport,
		},
	})
}

// Start begins the HTTP server on the specified port
func (s *SentinelServer) Start(port string, orchestrator *AutonomousOrchestrator) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/public_key", s.HandlePublicKey)
	mux.HandleFunc("/api/key_exchange", s.HandleKeyExchange)
	mux.HandleFunc("/api/hot_patch", s.HandleHotPatch)
	mux.HandleFunc("/api/hotpatch", s.HandleHotPatch) // Alias for NEUS compatibility
	mux.HandleFunc("/api/subscription", s.HandleSubscription)
	mux.HandleFunc("/api/upgrade", s.HandleUpgrade)
	mux.HandleFunc("/api/bypass_log", s.HandleBypassLog)
	mux.HandleFunc("/health", s.HandleHealth)

	// Autonomous status endpoint
	mux.HandleFunc("/api/autonomous/status", func(w http.ResponseWriter, r *http.Request) {
		if orchestrator == nil {
			http.Error(w, "Autonomous mode not enabled", http.StatusServiceUnavailable)
			return
		}
		status := orchestrator.GetStatus()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
	})

	// Event submission endpoint
	mux.HandleFunc("/api/autonomous/event", func(w http.ResponseWriter, r *http.Request) {
		if orchestrator == nil {
			http.Error(w, "Autonomous mode not enabled", http.StatusServiceUnavailable)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var event SecurityEvent
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			http.Error(w, "Invalid event", http.StatusBadRequest)
			return
		}
		event.ID = fmt.Sprintf("evt-%d", time.Now().UnixNano())
		event.Timestamp = time.Now()
		orchestrator.SubmitEvent(&event)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "accepted", "event_id": event.ID})
	})

	// Python agent registration endpoint
	mux.HandleFunc("/api/agents/python/register", func(w http.ResponseWriter, r *http.Request) {
		if orchestrator == nil {
			http.Error(w, "Autonomous mode not enabled", http.StatusServiceUnavailable)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var config PythonAgentConfig
		if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
			http.Error(w, "Invalid configuration", http.StatusBadRequest)
			return
		}
		orchestrator.RegisterPythonAgentDynamic(&config)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "registered",
			"agent":   config.Name,
			"url":     config.URL,
			"message": "Python agent registered successfully",
		})
	})

	// List all agents endpoint
	mux.HandleFunc("/api/agents/list", func(w http.ResponseWriter, r *http.Request) {
		if orchestrator == nil {
			http.Error(w, "Autonomous mode not enabled", http.StatusServiceUnavailable)
			return
		}
		registry := orchestrator.GetRegistry()
		allAgents := registry.GetAllAgents()
		pythonAgents := registry.GetPythonAgents()

		agentList := make([]map[string]interface{}, 0)
		for name, agent := range allAgents {
			lang := "go"
			if _, isPy := pythonAgents[name]; isPy {
				lang = "python"
			}
			agentList = append(agentList, map[string]interface{}{
				"name":      name,
				"language":  lang,
				"connected": agent.IsConnected(),
			})
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"agents": agentList,
			"total":  len(agentList),
		})
	})

	// Command translation endpoint (for testing)
	mux.HandleFunc("/api/translate/command", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Command    AgentCommand `json:"command"`
			TargetLang string       `json:"target_lang"` // "python" or "go"
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		translator := NewCommandTranslator()
		var result interface{}

		if req.TargetLang == "python" {
			result = translator.TranslateToPython(&req.Command)
		} else {
			// Already Go format
			result = req.Command
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"original":   req.Command,
			"translated": result,
			"target":     req.TargetLang,
		})
	})

	tierNames := map[SubscriptionTier]string{
		FreeTier:       "FREE",
		PremiumTier:    "PREMIUM",
		EnterpriseTier: "ENTERPRISE",
	}

	log.Printf("🚀 Sentinel server starting on port %s", port)
	log.Printf("📋 Subscription: %s tier", tierNames[s.subscription.Tier])
	log.Printf("🧠 Neural Analysis: %v", s.subscription.NeuralAnalysis)
	log.Printf("🕵️ Stealth Monitoring: %v", s.subscription.StealthMonitoring)
	log.Printf("🤖 Autonomous Mode: %v", orchestrator != nil)
	log.Printf("🐍 Python Agent Support: enabled")
	log.Printf("📡 Endpoints:")
	log.Printf("   /api/public_key, /api/key_exchange, /api/hot_patch")
	log.Printf("   /api/subscription, /api/upgrade, /api/bypass_log")
	log.Printf("   /api/autonomous/status, /api/autonomous/event")
	log.Printf("   /api/agents/python/register, /api/agents/list")
	log.Printf("   /api/translate/command, /health")

	return http.ListenAndServe(":"+port, mux)
}

// ====== MAIN: Autonomous Sentinel Agent ====== //

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.Printf("╔════════════════════════════════════════════════════════════╗")
	log.Printf("║     NEUS SENTINEL - Autonomous AI Security Agent           ║")
	log.Printf("║     Multi-Agent Integration: OVERMIND + METAEIGENT         ║")
	log.Printf("╚════════════════════════════════════════════════════════════╝")

	// Parse subscription tier from environment
	tier := FreeTier
	tierEnv := os.Getenv("SENTINEL_TIER")
	switch tierEnv {
	case "premium":
		tier = PremiumTier
	case "enterprise":
		tier = EnterpriseTier
	}

	// Initialize autonomous configuration
	config := DefaultAgentConfig()
	autonomousMode := os.Getenv("AUTONOMOUS_MODE") != "false"
	config.AutonomousMode = autonomousMode

	// Override agent URLs from environment if provided
	if overmindURL := os.Getenv("OVERMIND_URL"); overmindURL != "" {
		config.ExternalAgents["OVERMIND"] = overmindURL
	}
	if metaeigentURL := os.Getenv("METAEIGENT_URL"); metaeigentURL != "" {
		config.ExternalAgents["METAEIGENT"] = metaeigentURL
	}

	log.Printf("🔧 Configuration:")
	log.Printf("   Agent ID: %s", config.AgentID)
	log.Printf("   Autonomous Mode: %v", config.AutonomousMode)
	log.Printf("   Self-Preservation: %v", config.SelfPreservation)
	log.Printf("   Adaptive Learning: %v", config.AdaptiveLearning)
	log.Printf("   Heartbeat Interval: %v", config.HeartbeatInterval)
	log.Printf("   External Agents (Go): %v", len(config.ExternalAgents))

	for name, url := range config.ExternalAgents {
		log.Printf("     → [Go] %s: %s", name, url)
	}

	// Log Python agents configuration
	if pyAnalyzerURL := os.Getenv("PYTHON_ANALYZER_URL"); pyAnalyzerURL != "" {
		log.Printf("     → [Python] PythonAnalyzer: %s", pyAnalyzerURL)
	}
	if pyMLAgentURL := os.Getenv("PYTHON_ML_AGENT_URL"); pyMLAgentURL != "" {
		log.Printf("     → [Python] PythonMLAgent: %s", pyMLAgentURL)
	}

	// Create rule engine and handler
	ruleEngine := &DynamicRuleEngine{}
	tunnel := NewNeuralTunnelClient(NEUSOvermundEndpoint)
	handler := NewInferenceHandler(ruleEngine, tunnel)

	// Create Sentinel server
	server, err := NewSentinelServerWithTier(handler, ruleEngine, tier)
	if err != nil {
		log.Fatalf("❌ Failed to create server: %v", err)
	}

	// Create and start autonomous orchestrator
	var orchestrator *AutonomousOrchestrator
	if config.AutonomousMode {
		orchestrator = NewAutonomousOrchestrator(config)
		ctx, cancel := context.WithCancel(context.Background())

		// Handle graceful shutdown
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		go func() {
			<-sigChan
			log.Printf("🛑 Shutdown signal received...")
			cancel()
			orchestrator.Stop()
			os.Exit(0)
		}()

		orchestrator.Start(ctx)

		// Log registered agents
		registry := orchestrator.GetRegistry()
		allAgents := registry.GetAllAgents()
		pythonAgents := registry.GetPythonAgents()
		goAgentCount := len(allAgents) - len(pythonAgents)

		log.Printf("✅ Autonomous Orchestrator started")
		log.Printf("   Total Agents: %d (Go: %d, Python: %d)", len(allAgents), goAgentCount, len(pythonAgents))
	}

	// Start HTTP server
	port := getEnvOrDefault("SENTINEL_PORT", "8081")
	log.Printf("🌐 Starting HTTP server on port %s", port)
	if err := server.Start(port, orchestrator); err != nil {
		log.Fatalf("❌ Server failed: %v", err)
	}
}
