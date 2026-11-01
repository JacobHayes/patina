package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The package's tests, built by `cargo patina build --go --go-test` and run
// as a guest: a test of the package's own code, one of the guest filesystem,
// and one that fails only when the run plants a failure, so the test binary's
// exit status is shown to carry a failing test out.

func TestComputeIsCancelled(t *testing.T) {
	if got := compute(); got != "cancelled" {
		t.Fatalf("compute() = %q, want cancelled", got)
	}
}

func TestTempDirRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(path, []byte("go-test"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "go-test" {
		t.Fatalf("read back %q, %v", got, err)
	}
}

func TestPlantedFailure(t *testing.T) {
	if os.Getenv("GO_GUEST_PLANT_FAILURE") == "" {
		t.Skip("no failure planted")
	}
	t.Fatal("planted failure")
}
