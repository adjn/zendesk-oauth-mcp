package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	oauthClientID     = os.Getenv("ZENDESK_OAUTH_CLIENT_ID")
	oauthClientSecret = os.Getenv("ZENDESK_OAUTH_CLIENT_SECRET")
	oauthScopes       = os.Getenv("ZENDESK_OAUTH_SCOPES") // optional, defaults to "read"

	oauthMu         sync.Mutex
	oauthToken      *oauthTokenData
	oauthHTTPClient = http.DefaultClient // overridable for testing
)

// oauthTokenData holds the cached OAuth token and metadata.
type oauthTokenData struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type"`
	ExpiresAt    time.Time `json:"expires_at"`
	Scope        string    `json:"scope,omitempty"`
}

// initOAuth validates config and loads a cached token or runs the auth flow.
func initOAuth() error {
	if oauthClientID == "" {
		return fmt.Errorf("ZENDESK_OAUTH_CLIENT_ID is required when ZENDESK_AUTH_MODE=oauth")
	}
	if oauthClientSecret == "" {
		return fmt.Errorf("ZENDESK_OAUTH_CLIENT_SECRET is required when ZENDESK_AUTH_MODE=oauth")
	}
	if zendeskSubdomain == "" {
		return fmt.Errorf("ZENDESK_SUBDOMAIN is required")
	}

	// Try loading a cached token from disk.
	if tok, err := loadCachedToken(); err == nil && tok.AccessToken != "" {
		if time.Now().Before(tok.ExpiresAt) {
			oauthMu.Lock()
			oauthToken = tok
			oauthMu.Unlock()
			fmt.Fprintf(os.Stderr, "zendesk-oauth-mcp: loaded cached OAuth token (expires %s)\n", tok.ExpiresAt.Format(time.RFC3339))
			return nil
		}
		// Token expired — try refresh before falling through to full flow.
		if tok.RefreshToken != "" {
			if err := doTokenRefresh(tok.RefreshToken); err == nil {
				return nil
			}
		}
	}

	// No valid cached token — run the interactive OAuth flow.
	return runOAuthFlow()
}

// getOAuthToken returns the current access token, refreshing if expired.
func getOAuthToken() (string, error) {
	oauthMu.Lock()
	tok := oauthToken
	oauthMu.Unlock()

	if tok == nil || tok.AccessToken == "" {
		return "", fmt.Errorf("no OAuth token available — restart the server to re-authenticate")
	}

	if time.Now().After(tok.ExpiresAt) && tok.RefreshToken != "" {
		if err := doTokenRefresh(tok.RefreshToken); err != nil {
			return "", fmt.Errorf("token expired and refresh failed: %w", err)
		}
		oauthMu.Lock()
		tok = oauthToken
		oauthMu.Unlock()
	}

	return tok.AccessToken, nil
}

// refreshOAuthToken is called on 401 to force a token refresh.
func refreshOAuthToken() error {
	oauthMu.Lock()
	tok := oauthToken
	oauthMu.Unlock()

	if tok == nil || tok.RefreshToken == "" {
		return fmt.Errorf("no refresh token available — restart the server to re-authenticate")
	}
	return doTokenRefresh(tok.RefreshToken)
}

// --- OAuth 2.1 PKCE Flow ---

func runOAuthFlow() error {
	// Start a local HTTP server to receive the redirect.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("starting local redirect server: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	// Generate PKCE verifier and challenge.
	verifier, challenge, err := generatePKCE()
	if err != nil {
		listener.Close()
		return fmt.Errorf("generating PKCE: %w", err)
	}

	state, err := randomString(32)
	if err != nil {
		listener.Close()
		return fmt.Errorf("generating state: %w", err)
	}

	scopes := oauthScopeList()

	// Build the authorization URL.
	authURL := fmt.Sprintf("https://%s.zendesk.com/oauth/authorizations/new?%s",
		zendeskSubdomain,
		url.Values{
			"response_type":         {"code"},
			"client_id":             {oauthClientID},
			"redirect_uri":          {redirectURI},
			"scope":                 {scopes},
			"state":                 {state},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		}.Encode(),
	)

	// Channel to receive the auth code from the callback handler.
	type callbackResult struct {
		code string
		err  error
	}
	resultCh := make(chan callbackResult, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			resultCh <- callbackResult{err: fmt.Errorf("state mismatch")}
			http.Error(w, "State mismatch", http.StatusBadRequest)
			return
		}
		if errParam := r.URL.Query().Get("error"); errParam != "" {
			resultCh <- callbackResult{err: fmt.Errorf("OAuth error: %s — %s", errParam, r.URL.Query().Get("error_description"))}
			fmt.Fprintf(w, "Authentication failed: %s", errParam)
			return
		}
		code := r.URL.Query().Get("code")
		if code == "" {
			resultCh <- callbackResult{err: fmt.Errorf("no authorization code in callback")}
			http.Error(w, "Missing code", http.StatusBadRequest)
			return
		}
		resultCh <- callbackResult{code: code}
		fmt.Fprint(w, "✅ Authentication successful! You can close this tab and return to your terminal.")
	})

	srv := &http.Server{Handler: mux}
	go srv.Serve(listener)
	defer srv.Shutdown(context.Background())

	// Open the browser.
	fmt.Fprintf(os.Stderr, "zendesk-oauth-mcp: opening browser for Zendesk OAuth authorization...\n")
	// TODO: Review whether logging the full auth URL is a security concern —
	// it contains the state (CSRF token) and code_challenge parameters.
	fmt.Fprintf(os.Stderr, "  If the browser doesn't open, visit:\n  %s\n", authURL)
	openBrowser(authURL)

	// Wait for the callback (with timeout).
	select {
	case result := <-resultCh:
		if result.err != nil {
			return result.err
		}
		return exchangeCodeForToken(result.code, redirectURI, verifier)
	case <-time.After(5 * time.Minute):
		return fmt.Errorf("timed out waiting for OAuth callback — did you complete the browser authorization?")
	}
}

// exchangeCodeForToken trades the authorization code for an access token.
func exchangeCodeForToken(code, redirectURI, verifier string) error {
	tokenURL := fmt.Sprintf("https://%s.zendesk.com/oauth/tokens", zendeskSubdomain)

	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {oauthClientID},
		"client_secret": {oauthClientSecret},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}

	return doTokenRequest(tokenURL, data)
}

// doTokenRefresh uses a refresh token to obtain a new access token.
func doTokenRefresh(refreshToken string) error {
	tokenURL := fmt.Sprintf("https://%s.zendesk.com/oauth/tokens", zendeskSubdomain)

	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {oauthClientID},
		"client_secret": {oauthClientSecret},
	}

	return doTokenRequest(tokenURL, data)
}

// doTokenRequest performs the POST to the token endpoint and caches the result.
func doTokenRequest(tokenURL string, data url.Values) error {
	parsed, err := url.Parse(tokenURL)
	if err != nil || parsed.Scheme != "https" {
		return fmt.Errorf("token endpoint must be HTTPS: %s", tokenURL)
	}

	resp, err := oauthHTTPClient.PostForm(tokenURL, data)
	if err != nil {
		return fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	var raw struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
		Error        string `json:"error"`
		ErrorDesc    string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return fmt.Errorf("parsing token response: %w", err)
	}
	if raw.Error != "" {
		return fmt.Errorf("token error: %s — %s", raw.Error, raw.ErrorDesc)
	}
	if raw.AccessToken == "" {
		return fmt.Errorf("token response missing access_token (HTTP %d)", resp.StatusCode)
	}

	tok := &oauthTokenData{
		AccessToken:  raw.AccessToken,
		RefreshToken: raw.RefreshToken,
		TokenType:    raw.TokenType,
		Scope:        raw.Scope,
	}
	if raw.ExpiresIn > 0 {
		tok.ExpiresAt = time.Now().Add(time.Duration(raw.ExpiresIn) * time.Second)
	} else {
		// Zendesk tokens don't always include expires_in; default to 2 hours.
		tok.ExpiresAt = time.Now().Add(2 * time.Hour)
	}

	oauthMu.Lock()
	oauthToken = tok
	oauthMu.Unlock()

	if err := saveCachedToken(tok); err != nil {
		fmt.Fprintf(os.Stderr, "zendesk-oauth-mcp: warning: could not cache token: %v\n", err)
	}

	fmt.Fprintf(os.Stderr, "zendesk-oauth-mcp: OAuth token acquired (expires %s)\n", tok.ExpiresAt.Format(time.RFC3339))
	return nil
}

// --- Token Cache ---

func tokenCachePath() string {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "zendesk-oauth-mcp", zendeskSubdomain+"-token.json")
}

func loadCachedToken() (*oauthTokenData, error) {
	data, err := os.ReadFile(tokenCachePath())
	if err != nil {
		return nil, err
	}
	var tok oauthTokenData
	if err := json.Unmarshal(data, &tok); err != nil {
		return nil, err
	}
	return &tok, nil
}

func saveCachedToken(tok *oauthTokenData) error {
	path := tokenCachePath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(tok, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// --- PKCE Helpers ---

// generatePKCE creates a code_verifier and its S256 code_challenge per RFC 7636.
func generatePKCE() (verifier, challenge string, err error) {
	verifier, err = randomString(64)
	if err != nil {
		return "", "", err
	}
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return verifier, challenge, nil
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b)[:n], nil
}

// openBrowser opens a URL in the user's default browser.
func openBrowser(rawURL string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", rawURL)
	case "linux":
		cmd = exec.Command("xdg-open", rawURL)
	default:
		return
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "zendesk-oauth-mcp: could not open browser: %v\n", err)
	}
}

// --- Scopes Helper ---

// oauthScopeList returns the configured scopes as a space-separated string.
func oauthScopeList() string {
	s := strings.TrimSpace(oauthScopes)
	if s == "" {
		return "read"
	}
	return s
}
