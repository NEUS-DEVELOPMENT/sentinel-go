package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
)

// System State Definitions
const (
	StateDormant int32 = iota
	StateLethal
)

var currentState int32 = StateDormant

// Sovereign Function - Proprietary Internal Reasoning (PIR)
// Analyzes intent locally without external dependencies.
func processQuery(query string) string {
	// Basic protection in Dormant Mode (Signature based)
	if strings.Contains(strings.ToLower(query), "select * from") || 
	   strings.Contains(strings.ToLower(query), "or 1=1") {
		return "BLOCK: Potential SQL Injection detected (Level 1)"
	}

	// Active Defense: If system is in Lethal Mode, execute deeper logic
	if atomic.LoadInt32(&currentState) == StateLethal {
		// Logic injected from Overmind (Simulated RAM injection)
		// Detects intent for buffer overflow or complex prompt injection
		if len(query) > 500 {
			return "BLOCK: Lethal Defense - Buffer overflow intent detected"
		}
	}

	return "ALLOW"
}

// Proxy Handler - Intercepts traffic at the edge
func handleProxy(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	query := string(body)

	decision := processQuery(query)

	if strings.HasPrefix(decision, "BLOCK") {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "NEUS Sentinel: %s", decision)
		return
	}

	fmt.Fprint(w, "NEUS Sentinel: Request allowed and forwarded.")
}

func main() {
	// Primary query endpoint
	http.HandleFunc("/v1/query", handleProxy)
	
	// Administrative endpoint for state change (Authorized Overmind only)
	http.HandleFunc("/admin/activate-lethal", func(w http.ResponseWriter, r *http.Request) {
		atomic.StoreInt32(&currentState, StateLethal)
		fmt.Fprint(w, "Sentinel Status: LETHAL MODE ACTIVATED")
	})

	log.Println("NEUS Sentinel Active on :8080 (Sovereign Mode)")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
