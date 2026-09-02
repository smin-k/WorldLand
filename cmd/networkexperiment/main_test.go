package main

import (
	"math"
	"testing"
)

func TestZeroDelayPersistenceMatchesBiasedRandomWalk(t *testing.T) {
	const (
		trials = 10000
		alpha  = 0.30
		depth  = 4
	)
	wins := 0
	for trial := 0; trial < trials; trial++ {
		if persistenceTrial(8, alpha, depth, 0, int64(900000+trial)) {
			wins++
		}
	}
	observed := float64(wins) / trials
	expected := math.Pow(alpha/(1-alpha), depth)
	if math.Abs(observed-expected) > 0.01 {
		t.Fatalf("zero-delay persistence probability %.6f, expected %.6f", observed, expected)
	}
}

func TestBoundedDelayCreatesStaleWorkButPreservesPositiveGrowth(t *testing.T) {
	growth, _, stale := growthTrial(16, 0.30, 5, 5000, 0.20, 123456)
	if growth <= 0 {
		t.Fatal("bounded-delay honest common prefix did not grow")
	}
	if stale <= 0 {
		t.Fatal("bounded-delay run did not account for any stale honest work")
	}
}
