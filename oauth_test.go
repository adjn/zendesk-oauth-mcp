package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGeneratePKCE(t *testing.T) {
	verifier, challenge, err := generatePKCE()
	if err != nil {
		t.Fatalf("generatePKCE() error: %v", err)
	}

	if len(verifier) != 64 {
		t.Errorf("verifier length = %d, want 64", len(verifier))
	}

	// Verify the challenge is the base64url-encoded SHA256 of the verifier.
	h := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(h[:])
	if challenge != expected {
		t.Errorf("challenge does not match SHA256(verifier)\n  got:  %s\n  want: %s", challenge, expected)
	}
}

func TestGeneratePKCEUniqueness(t *testing.T) {
	v1, _, _ := generatePKCE()
	v2, _, _ := generatePKCE()
	if v1 == v2 {
		t.Error("two calls to generatePKCE() produced identical verifiers")
	}
}

func TestRandomString(t *testing.T) {
	tests := []struct {
		name string
		n    int
	}{
		{"short", 8},
		{"medium", 32},
		{"long", 64},
		{"very long", 128},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := randomString(tt.n)
			if err != nil {
				t.Fatalf("randomString(%d) error: %v", tt.n, err)
			}
			if len(s) != tt.n {
				t.Errorf("randomString(%d) length = %d", tt.n, len(s))
			}
		})
	}
}

func TestOAuthScopeList(t *testing.T) {
	tests := []struct {
		name  string
		env   string
		want  string
	}{
		{"empty defaults to read", "", "read"},
		{"whitespace defaults to read", "   ", "read"},
		{"single scope", "read", "read"},
		{"multiple scopes", "read write", "read write"},
		{"trimmed", "  tickets:read  ", "tickets:read"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := oauthScopes
			defer func() { oauthScopes = orig }()

			oauthScopes = tt.env
			got := oauthScopeList()
			if got != tt.want {
				t.Errorf("oauthScopeList() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTokenCacheSaveLoad(t *testing.T) {
	// Use a temp dir as XDG_CONFIG_HOME so we don't touch real config.
	tmpDir := t.TempDir()
	origXDG := os.Getenv("XDG_CONFIG_HOME")
	origSubdomain := zendeskSubdomain
	defer func() {
		os.Setenv("XDG_CONFIG_HOME", origXDG)
		zendeskSubdomain = origSubdomain
	}()
	os.Setenv("XDG_CONFIG_HOME", tmpDir)
	zendeskSubdomain = "testcompany"

	tok := &oauthTokenData{
		AccessToken:  "at_test123",
		RefreshToken: "rt_test456",
		TokenType:    "bearer",
		ExpiresAt:    time.Now().Add(1 * time.Hour).Truncate(time.Millisecond),
		Scope:        "read",
	}

	// Save.
	if err := saveCachedToken(tok); err != nil {
		t.Fatalf("saveCachedToken() error: %v", err)
	}

	// Verify file exists with restricted permissions.
	path := tokenCachePath()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("token cache file missing: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("token cache permissions = %o, want 0600", perm)
	}

	// Verify parent dir permissions.
	dirInfo, _ := os.Stat(filepath.Dir(path))
	if perm := dirInfo.Mode().Perm(); perm != 0700 {
		t.Errorf("token cache dir permissions = %o, want 0700", perm)
	}

	// Load.
	loaded, err := loadCachedToken()
	if err != nil {
		t.Fatalf("loadCachedToken() error: %v", err)
	}
	if loaded.AccessToken != tok.AccessToken {
		t.Errorf("AccessToken = %q, want %q", loaded.AccessToken, tok.AccessToken)
	}
	if loaded.RefreshToken != tok.RefreshToken {
		t.Errorf("RefreshToken = %q, want %q", loaded.RefreshToken, tok.RefreshToken)
	}
	if loaded.Scope != tok.Scope {
		t.Errorf("Scope = %q, want %q", loaded.Scope, tok.Scope)
	}
}

func TestLoadCachedTokenMissing(t *testing.T) {
	origXDG := os.Getenv("XDG_CONFIG_HOME")
	origSubdomain := zendeskSubdomain
	defer func() {
		os.Setenv("XDG_CONFIG_HOME", origXDG)
		zendeskSubdomain = origSubdomain
	}()
	os.Setenv("XDG_CONFIG_HOME", t.TempDir())
	zendeskSubdomain = "nonexistent"

	_, err := loadCachedToken()
	if err == nil {
		t.Error("loadCachedToken() should error for missing file")
	}
}

func TestGetOAuthTokenValid(t *testing.T) {
	origToken := oauthToken
	defer func() {
		oauthMu.Lock()
		oauthToken = origToken
		oauthMu.Unlock()
	}()

	oauthMu.Lock()
	oauthToken = &oauthTokenData{
		AccessToken: "valid-token",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}
	oauthMu.Unlock()

	got, err := getOAuthToken()
	if err != nil {
		t.Fatalf("getOAuthToken() error: %v", err)
	}
	if got != "valid-token" {
		t.Errorf("getOAuthToken() = %q, want valid-token", got)
	}
}

func TestGetOAuthTokenNil(t *testing.T) {
	origToken := oauthToken
	defer func() {
		oauthMu.Lock()
		oauthToken = origToken
		oauthMu.Unlock()
	}()

	oauthMu.Lock()
	oauthToken = nil
	oauthMu.Unlock()

	_, err := getOAuthToken()
	if err == nil {
		t.Error("getOAuthToken() should error when token is nil")
	}
}

func TestDoTokenRequestSuccess(t *testing.T) {
	origToken := oauthToken
	origXDG := os.Getenv("XDG_CONFIG_HOME")
	origSubdomain := zendeskSubdomain
	origClient := oauthHTTPClient
	defer func() {
		oauthMu.Lock()
		oauthToken = origToken
		oauthMu.Unlock()
		os.Setenv("XDG_CONFIG_HOME", origXDG)
		zendeskSubdomain = origSubdomain
		oauthHTTPClient = origClient
	}()
	os.Setenv("XDG_CONFIG_HOME", t.TempDir())
	zendeskSubdomain = "test"

	// Mock token endpoint over TLS.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "new-access-token",
			"refresh_token": "new-refresh-token",
			"token_type":    "bearer",
			"expires_in":    7200,
			"scope":         "read",
		})
	}))
	defer srv.Close()
	oauthHTTPClient = srv.Client()

	err := doTokenRequest(srv.URL, map[string][]string{
		"grant_type": {"authorization_code"},
		"code":       {"test-code"},
	})
	if err != nil {
		t.Fatalf("doTokenRequest() error: %v", err)
	}

	oauthMu.Lock()
	tok := oauthToken
	oauthMu.Unlock()

	if tok.AccessToken != "new-access-token" {
		t.Errorf("AccessToken = %q, want new-access-token", tok.AccessToken)
	}
	if tok.RefreshToken != "new-refresh-token" {
		t.Errorf("RefreshToken = %q, want new-refresh-token", tok.RefreshToken)
	}
}

func TestDoTokenRequestTable(t *testing.T) {
	tests := []struct {
		name      string
		response  map[string]any
		status    int
		wantErr   string
		wantToken string
	}{
		{
			name: "successful token exchange",
			response: map[string]any{
				"access_token":  "tok_success",
				"refresh_token": "rt_success",
				"token_type":    "bearer",
				"expires_in":    3600,
			},
			status:    200,
			wantToken: "tok_success",
		},
		{
			name: "token with no expires_in defaults to 2h",
			response: map[string]any{
				"access_token": "tok_no_expiry",
				"token_type":   "bearer",
			},
			status:    200,
			wantToken: "tok_no_expiry",
		},
		{
			name: "oauth error response",
			response: map[string]any{
				"error":             "invalid_grant",
				"error_description": "authorization code expired",
			},
			status:  400,
			wantErr: "invalid_grant",
		},
		{
			name:     "empty access token",
			response: map[string]any{"token_type": "bearer"},
			status:   200,
			wantErr:  "missing access_token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origToken := oauthToken
			origXDG := os.Getenv("XDG_CONFIG_HOME")
			origSubdomain := zendeskSubdomain
			origClient := oauthHTTPClient
			defer func() {
				oauthMu.Lock()
				oauthToken = origToken
				oauthMu.Unlock()
				os.Setenv("XDG_CONFIG_HOME", origXDG)
				zendeskSubdomain = origSubdomain
				oauthHTTPClient = origClient
			}()
			os.Setenv("XDG_CONFIG_HOME", t.TempDir())
			zendeskSubdomain = "test"

			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				json.NewEncoder(w).Encode(tt.response)
			}))
			defer srv.Close()
			oauthHTTPClient = srv.Client()

			err := doTokenRequest(srv.URL, map[string][]string{"grant_type": {"test"}})

			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error = %q, want substring %q", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			oauthMu.Lock()
			tok := oauthToken
			oauthMu.Unlock()

			if tok.AccessToken != tt.wantToken {
				t.Errorf("AccessToken = %q, want %q", tok.AccessToken, tt.wantToken)
			}
		})
	}
}

func TestInitOAuthMissingConfig(t *testing.T) {
	tests := []struct {
		name      string
		clientID  string
		clientSec string
		subdomain string
		wantErr   string
	}{
		{"missing client ID", "", "secret", "test", "ZENDESK_OAUTH_CLIENT_ID"},
		{"missing client secret", "id", "", "test", "ZENDESK_OAUTH_CLIENT_SECRET"},
		{"missing subdomain", "id", "secret", "", "ZENDESK_SUBDOMAIN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origID := oauthClientID
			origSecret := oauthClientSecret
			origSubdomain := zendeskSubdomain
			defer func() {
				oauthClientID = origID
				oauthClientSecret = origSecret
				zendeskSubdomain = origSubdomain
			}()

			oauthClientID = tt.clientID
			oauthClientSecret = tt.clientSec
			zendeskSubdomain = tt.subdomain

			err := initOAuth()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestTokenCachePathUsesSubdomain(t *testing.T) {
	origXDG := os.Getenv("XDG_CONFIG_HOME")
	origSubdomain := zendeskSubdomain
	defer func() {
		os.Setenv("XDG_CONFIG_HOME", origXDG)
		zendeskSubdomain = origSubdomain
	}()

	os.Setenv("XDG_CONFIG_HOME", "/tmp/test-config")
	zendeskSubdomain = "mycompany"

	got := tokenCachePath()
	want := "/tmp/test-config/zendesk-oauth-mcp/mycompany-token.json"
	if got != want {
		t.Errorf("tokenCachePath() = %q, want %q", got, want)
	}
}

func TestRefreshOAuthTokenNoRefreshToken(t *testing.T) {
	origToken := oauthToken
	defer func() {
		oauthMu.Lock()
		oauthToken = origToken
		oauthMu.Unlock()
	}()

	// Token exists but has no refresh_token.
	oauthMu.Lock()
	oauthToken = &oauthTokenData{
		AccessToken: "at",
		ExpiresAt:   time.Now().Add(-1 * time.Hour),
	}
	oauthMu.Unlock()

	err := refreshOAuthToken()
	if err == nil {
		t.Fatal("refreshOAuthToken() should error without refresh token")
	}
	if !strings.Contains(err.Error(), "no refresh token") {
		t.Errorf("error = %q, want 'no refresh token' substring", err)
	}
}

func TestTokenCachePathDefaultsToHomeConfig(t *testing.T) {
	origXDG := os.Getenv("XDG_CONFIG_HOME")
	origSubdomain := zendeskSubdomain
	defer func() {
		os.Setenv("XDG_CONFIG_HOME", origXDG)
		zendeskSubdomain = origSubdomain
	}()

	os.Unsetenv("XDG_CONFIG_HOME")
	zendeskSubdomain = "acme"

	got := tokenCachePath()
	home, _ := os.UserHomeDir()
	want := fmt.Sprintf("%s/.config/zendesk-oauth-mcp/acme-token.json", home)
	if got != want {
		t.Errorf("tokenCachePath() = %q, want %q", got, want)
	}
}
