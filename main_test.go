package main

import (
	"strings"
	"sync/atomic"
	"testing"
)

func TestPIR_Logic(t *testing.T) {
	// Test 1: Dormant Mode (Standard Filtering)
	atomic.StoreInt32(&currentState, StateDormant)
	res := processQuery("SELECT * FROM users")
	if !strings.Contains(res, "BLOCK") {
		t.Errorf("Expected block for SQLi, got %s", res)
	}

	// Test 2: Lethal Mode (Deep Logic Injection)
	atomic.StoreInt32(&currentState, StateLethal)
	longQuery := strings.Repeat("a", 501)
	resLethal := processQuery(longQuery)
	if !strings.Contains(resLethal, "BLOCK") {
		t.Errorf("Expected lethal block for long query, got %s", resLethal)
	}
}
