package test

import (
	"testing"
)

func TestSignUpWithEmailPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		data     map[string]interface{}
		wantErr  bool
	}{
		{
			name:     "Valid signup",
			password: "password123",
			data:     nil,
			wantErr:  false,
		},
		{
			name:     "With metadata",
			password: "password123",
			data: map[string]interface{}{
				"full_name": "Test User",
			},
			wantErr: false,
		},
		{
			name:     "Empty password",
			password: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := GenerateRandomEmail()
			resp, err := client.SignUp(email, tt.password, tt.data)

			if tt.wantErr {
				if err == nil {
					t.Fatal("Expected error but got none")
				}
				return
			}

			AssertNoError(t, err, "SignUp failed")
			if resp.User.Email != email {
				t.Errorf("Expected email %s, got %s", email, resp.User.Email)
				if resp.Session.AccessToken == "" {
					t.Error("Expected access token but got none")
				}
			}
		})
	}
}

func TestDuplicateSignUp(t *testing.T) {
	email := GenerateRandomEmail()
	password := "password123"

	// First signup
	_, err := client.SignUp(email, password, nil)
	AssertNoError(t, err, "First signup failed")

	// Attempt duplicate signup
	_, err = client.SignUp(email, password, nil)
	if err == nil {
		t.Fatal("Expected error with duplicate signup")
	}
}
