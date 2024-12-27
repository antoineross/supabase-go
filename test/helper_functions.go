package test

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/supabase-community/supabase-go"
)

var (
	// client is the Supabase client used across all tests
	client *supabase.Client
)

func init() {
	// Initialize random seed
	rand.Seed(time.Now().UnixNano())

	// Initialize Supabase client
	var err error
	client, err = supabase.NewClient(
		"YOUR_SUPABASE_URL",
		"YOUR_SUPABASE_KEY",
		nil,
	)
	if err != nil {
		panic(fmt.Sprintf("failed to initialize Supabase client: %v", err))
	}
}

// Helper functions

// GenerateRandomEmail generates a random email for testing
func GenerateRandomEmail() string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	length := 10
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return fmt.Sprintf("test+%s@example.com", string(b))
}

// AssertNoError checks for error and fails test if present
func AssertNoError(t *testing.T, err error, msg string) {
	t.Helper() // Marks this as a helper function for better test output
	if err != nil {
		t.Fatalf("%s: %v", msg, err)
	}
}
