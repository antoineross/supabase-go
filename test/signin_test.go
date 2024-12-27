package test

import (
	"testing"
	"time"
)

// CreateTestUser creates a test user and returns email and password
func CreateTestUser(t *testing.T) (email, password string) {
	t.Helper()
	email = GenerateRandomEmail()
	password = "password123" // You could also make this random if needed

	_, err := client.SignUp(email, password, nil)
	AssertNoError(t, err, "Failed to create test user")

	// Wait for user creation to complete
	time.Sleep(1 * time.Second)
	return email, password
}

func TestSignInWithEmailPassword(t *testing.T) {
	// Create test user using helper
	email, password := CreateTestUser(t)

	// Test successful sign in
	session, err := client.SignInWithEmailPassword(email, password)
	AssertNoError(t, err, "SignIn failed")
	if session.AccessToken == "" {
		t.Fatal("SignIn response missing access token")
	}

	// Test invalid credentials
	_, err = client.SignInWithEmailPassword(email, "wrongpassword")
	if err == nil {
		t.Fatal("Expected error with invalid credentials")
	}
}

func TestSignInWithOTP(t *testing.T) {
	email := GenerateRandomEmail()

	// Test OTP request
	err := client.SignUpWithEmailOTP(email, nil)
	AssertNoError(t, err, "Failed to send OTP")

	t.Log("OTP sent successfully - manual verification required")
}
