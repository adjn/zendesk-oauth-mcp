package main

import (
	"net/http"
	"testing"
	"time"
)

func TestApplyAuthCookieMode(t *testing.T) {
	// Save and restore global state.
	origMode := currentAuthMode
	origCookie := zendeskCookie
	defer func() {
		currentAuthMode = origMode
		zendeskCookie = origCookie
	}()

	currentAuthMode = authModeCookie
	zendeskCookie = "_zendesk_session=abc123"

	req, _ := http.NewRequest("GET", "https://example.zendesk.com/api/v2/tickets.json", nil)
	if err := applyAuth(req); err != nil {
		t.Fatalf("applyAuth(cookie mode) error: %v", err)
	}

	if got := req.Header.Get("Cookie"); got != "_zendesk_session=abc123" {
		t.Errorf("Cookie header = %q, want _zendesk_session=abc123", got)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization header should be empty in cookie mode, got %q", got)
	}
}

func TestApplyAuthOAuthMode(t *testing.T) {
	origMode := currentAuthMode
	origToken := oauthToken
	defer func() {
		currentAuthMode = origMode
		oauthMu.Lock()
		oauthToken = origToken
		oauthMu.Unlock()
	}()

	currentAuthMode = authModeOAuth
	oauthMu.Lock()
	oauthToken = &oauthTokenData{
		AccessToken: "test-access-token-xyz",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}
	oauthMu.Unlock()

	req, _ := http.NewRequest("GET", "https://example.zendesk.com/api/v2/tickets.json", nil)
	if err := applyAuth(req); err != nil {
		t.Fatalf("applyAuth(oauth mode) error: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "Bearer test-access-token-xyz" {
		t.Errorf("Authorization header = %q, want Bearer test-access-token-xyz", got)
	}
	if got := req.Header.Get("Cookie"); got != "" {
		t.Errorf("Cookie header should be empty in oauth mode, got %q", got)
	}
}

func TestApplyAuthOAuthModeNoToken(t *testing.T) {
	origMode := currentAuthMode
	origToken := oauthToken
	defer func() {
		currentAuthMode = origMode
		oauthMu.Lock()
		oauthToken = origToken
		oauthMu.Unlock()
	}()

	currentAuthMode = authModeOAuth
	oauthMu.Lock()
	oauthToken = nil
	oauthMu.Unlock()

	req, _ := http.NewRequest("GET", "https://example.zendesk.com/api/v2/tickets.json", nil)
	err := applyAuth(req)
	if err == nil {
		t.Fatal("applyAuth(oauth, no token) should return error")
	}
}

func TestApplyAuthCookieModeNoCookie(t *testing.T) {
	origMode := currentAuthMode
	origCookie := zendeskCookie
	defer func() {
		currentAuthMode = origMode
		zendeskCookie = origCookie
	}()

	currentAuthMode = authModeCookie
	zendeskCookie = ""

	req, _ := http.NewRequest("GET", "https://example.zendesk.com/api/v2/tickets.json", nil)
	err := applyAuth(req)
	if err == nil {
		t.Fatal("applyAuth(cookie, no cookie) should return error")
	}
}
