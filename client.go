package supabase

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/supabase-community/auth-go"
	"github.com/supabase-community/auth-go/types"
	"github.com/supabase-community/functions-go"
	postgrest "github.com/supabase-community/postgrest-go"
	storage_go "github.com/supabase-community/storage-go"
)

const (
	REST_URL      = "/rest/v1"
	STORAGE_URL   = "/storage/v1"
	AUTH_URL      = "/auth/v1"
	FUNCTIONS_URL = "/functions/v1"
)

type Client struct {
	// Why is this a private field??
	rest    *postgrest.Client
	Storage *storage_go.Client
	// Auth is an interface. We don't need a pointer to an interface.
	Auth      auth.Client
	Functions *functions.Client
	options   clientOptions
}

type clientOptions struct {
	url     string
	headers map[string]string
}

type ClientOptions struct {
	Headers map[string]string
	Schema  string
}

type SignUpOptions struct {
	Data       map[string]interface{}
	RedirectTo string
}

func NewClient(url, key string, options *ClientOptions) (*Client, error) {

	if url == "" || key == "" {
		return nil, errors.New("url and key are required")
	}

	headers := map[string]string{
		"Authorization": "Bearer " + key,
		"apikey":        key,
	}

	if options != nil && options.Headers != nil {
		for k, v := range options.Headers {
			headers[k] = v
		}
	}

	client := &Client{}
	client.options.url = url
	client.options.headers = headers

	var schema string
	if options != nil && options.Schema != "" {
		schema = options.Schema
	} else {
		schema = "public"
	}

	client.rest = postgrest.NewClient(url+REST_URL, schema, headers)
	client.Storage = storage_go.NewClient(url+STORAGE_URL, key, headers)
	tmp := auth.New(url, key)
	client.Auth = tmp.WithCustomAuthURL(url + AUTH_URL)
	client.Functions = functions.NewClient(url+FUNCTIONS_URL, key, headers)

	return client, nil
}

func (c *Client) HealthCheck() (*types.HealthCheckResponse, error) {
	return c.Auth.HealthCheck()
}

func (c *Client) From(table string) *postgrest.QueryBuilder {
	return c.rest.From(table)
}

func (c *Client) Rpc(name, count string, rpcBody interface{}) string {
	return c.rest.Rpc(name, count, rpcBody)
}

// ---------------------------- Auth Functions ---------------------------- //
func (c *Client) SignUp(email, password string, data map[string]interface{}) (*types.SignupResponse, error) {
	req := types.SignupRequest{
		Email:    email,
		Password: password,
		Data:     data, // Optional user metadata
	}

	resp, err := c.Auth.Signup(req)
	if err != nil {
		return nil, err
	}

	// If autoconfirm is enabled, update the client's auth session
	if resp.Session.AccessToken != "" {
		c.UpdateAuthSession(resp.Session)
	}

	return resp, nil
}

func (c *Client) SignUpWithEmailOTP(email string, options *SignUpOptions) error {
	if options == nil {
		options = &SignUpOptions{}
	}

	req := types.OTPRequest{
		Email:      email,
		CreateUser: true,         // This creates a new user after verification
		Data:       options.Data, // Optional metadata for the new user
	}

	return c.Auth.OTP(req)
}

func (c *Client) VerifyEmailOTP(email, code string) (*types.Session, error) {
	req := types.VerifyForUserRequest{
		Type:  types.VerificationTypeSignup,
		Email: email,
		Token: code,
	}

	resp, err := c.Auth.VerifyForUser(req)
	if err != nil {
		return nil, err
	}

	c.UpdateAuthSession(resp.Session)
	return &resp.Session, nil
}

func (c *Client) SignInWithEmailPassword(email, password string) (types.Session, error) {
	token, err := c.Auth.SignInWithEmailPassword(email, password)
	if err != nil {
		return types.Session{}, err
	}
	c.UpdateAuthSession(token.Session)

	return token.Session, err
}

func (c *Client) SignInWithPhonePassword(phone, password string) (types.Session, error) {
	token, err := c.Auth.SignInWithPhonePassword(phone, password)
	if err != nil {
		return types.Session{}, err
	}
	c.UpdateAuthSession(token.Session)
	return token.Session, err
}

func (c *Client) SignInWithProvider(provider types.Provider, redirectTo string) (*types.AuthorizeResponse, error) {
	req := types.AuthorizeRequest{
		Provider:   provider,
		RedirectTo: redirectTo,
		FlowType:   types.FlowPKCE, // Use PKCE flow for better security
		Scopes:     "",             // Use default scopes
	}

	return c.Auth.Authorize(req)
}

func (c *Client) ExchangeCode(code, codeVerifier string) (types.Session, error) {
	token, err := c.Auth.Token(types.TokenRequest{
		GrantType:    "pkce",
		Code:         code,
		CodeVerifier: codeVerifier,
	})
	if err != nil {
		return types.Session{}, err
	}

	c.UpdateAuthSession(token.Session)
	return token.Session, nil
}

func (c *Client) Logout() error {
	err := c.Auth.Logout()
	if err != nil {
		return err
	}

	c.UpdateAuthSession(types.Session{})
	return nil
}

// ---------------------------- Session Management ---------------------------- //
func (c *Client) EnableTokenAutoRefresh(session types.Session) {
	go func() {
		attempt := 0
		expiresAt := time.Now().Add(time.Duration(session.ExpiresIn) * time.Second)

		for {
			sleepDuration := (time.Until(expiresAt) / 4) * 3
			if sleepDuration > 0 {
				time.Sleep(sleepDuration)
			}

			newSession, err := c.RefreshToken(session.RefreshToken)
			if err != nil {
				attempt++
				if attempt <= 3 {
					log.Printf("Error refreshing token, retrying with exponential backoff: %v", err)
					time.Sleep(time.Duration(1<<attempt) * time.Second)
				} else {
					log.Printf("Error refreshing token, retrying every 30 seconds: %v", err)
					time.Sleep(30 * time.Second)
				}
				continue
			}

			// Update Session, Reset Attempt Counter, and Update the expiresAt time
			c.UpdateAuthSession(newSession)
			session = newSession
			attempt = 0
			expiresAt = time.Now().Add(time.Duration(session.ExpiresIn) * time.Second)
		}
	}()
}

func (c *Client) RefreshToken(refreshToken string) (types.Session, error) {
	token, err := c.Auth.RefreshToken(refreshToken)
	if err != nil {
		return types.Session{}, err
	}
	c.UpdateAuthSession(token.Session)
	return token.Session, err
}

func (c *Client) UpdateAuthSession(session types.Session) {
	c.Auth = c.Auth.WithToken(session.AccessToken)
	c.rest.SetAuthToken(session.AccessToken)
	c.options.headers["Authorization"] = "Bearer " + session.AccessToken
	c.Storage = storage_go.NewClient(c.options.url+STORAGE_URL, session.AccessToken, c.options.headers)
	c.Functions = functions.NewClient(c.options.url+FUNCTIONS_URL, session.AccessToken, c.options.headers)

}

// ---------------------------- User Functions ---------------------------- //
func (c *Client) GetUser() (*types.UserResponse, error) {
	return c.Auth.GetUser()
}

func (c *Client) UpdateUser(updates types.UpdateUserRequest) (*types.UpdateUserResponse, error) {
	resp, err := c.Auth.UpdateUser(updates)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (c *Client) UpdatePassword(newPassword string) error {
	_, err := c.Auth.UpdateUser(types.UpdateUserRequest{
		Password: &newPassword,
	})
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}
