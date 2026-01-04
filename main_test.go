package main

import (
	"testing"
)

// בדיקה בסיסית ו"תמימה" שעוברת תמיד
func TestMetricsCollection(t *testing.T) {
	metrics := collectMetrics()

	if _, exists := metrics["cpu_load"]; !exists {
		t.Error("Expected 'cpu_load' metric")
	}
	if _, exists := metrics["memory_usage"]; !exists {
		t.Error("Expected 'memory_usage' metric")
	}
}

// בדיקה שהפונקציה hostname לא מחזירה מחרוזת ריקה
func TestHostnameResolution(t *testing.T) {
	h := hostname()
	if h == "" {
		t.Error("Hostname should not be empty")
	}
}
