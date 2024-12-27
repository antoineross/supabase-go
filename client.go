package supabase

import (
	"errors"
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

// NewClient creates a new Supabase client.
// url is the Supabase URL.
// key is the Supabase API key.
// options is the Supabase client options.
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
	// map is pass by reference, so this gets updated by rest of function
	client.options.headers = headers

	var schema string
	if options != nil && options.Schema != "" {
		schema = options.Schema
	} else {
		schema = "public"
	}

	client.rest = postgrest.NewClient(url+REST_URL, schema, headers)
	client.Storage = storage_go.NewClient(url+STORAGE_URL, key, headers)
	// ugly to make auth client use custom URL
	tmp := auth.New(url, key)
	client.Auth = tmp.WithCustomAuthURL(url + AUTH_URL)
	client.Functions = functions.NewClient(url+FUNCTIONS_URL, key, headers)

	return client, nil
}

// Wrap postgrest From method
// From returns a QueryBuilder for the specified table.
func (c *Client) From(table string) *postgrest.QueryBuilder {
	return c.rest.From(table)
}

// Wrap postgrest Rpc method
// Rpc returns a string for the specified function.
func (c *Client) Rpc(name, count string, rpcBody interface{}) string {
	return c.rest.Rpc(name, count, rpcBody)
}

// SignUp registers a new user with email and password.
// Optionally accepts user metadata.
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

type SignUpOptions struct {
	Data       map[string]interface{}
	RedirectTo string
}

// SignUpWithEmailOTP initiates a signup flow using email OTP verification.
// It sends a one-time password to the user's email.
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

// VerifyEmailOTP completes the signup process by verifying the OTP code.
// Returns the new user session if verification is successful.
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

	// Update client session with the new tokens
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

// SignInWithProvider initiates OAuth sign-in with the specified provider.
// It returns the authorization URL that the user should be redirected to,
// along with the PKCE verifier that should be stored for the token exchange.
func (c *Client) SignInWithProvider(provider types.Provider, redirectTo string) (*types.AuthorizeResponse, error) {
	req := types.AuthorizeRequest{
		Provider:   provider,
		RedirectTo: redirectTo,
		FlowType:   types.FlowPKCE, // Use PKCE flow for better security
		Scopes:     "",             // Use default scopes
	}

	return c.Auth.Authorize(req)
}

// ExchangeCode exchanges the authorization code for a session token after OAuth sign-in.
// The codeVerifier is the PKCE verifier returned from SignInWithProvider.
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

func (c *Client) EnableTokenAutoRefresh(session types.Session) {
	go func() {
		attempt := 0
		expiresAt := time.Now().Add(time.Duration(session.ExpiresIn) * time.Second)

		for {
			sleepDuration := (time.Until(expiresAt) / 4) * 3
			if sleepDuration > 0 {
				time.Sleep(sleepDuration)
			}

			// Refresh the token
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

			// Update the session, reset the attempt counter, and update the expiresAt time
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
