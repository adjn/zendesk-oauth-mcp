package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
)

// authMode controls how the server authenticates to Zendesk.
type authMode int

const (
	authModeCookie authMode = iota // Browser session cookie
	authModeOAuth                  // OAuth 2.1 access token
)

var currentAuthMode authMode

// initAuth is called at startup before any Zendesk requests. It reads
// ZENDESK_AUTH_MODE to decide the authentication strategy, then initializes
// the appropriate credential source. When mode is "oauth", cookie extraction
// is never attempted.
func initAuth() error {
	mode := strings.ToLower(os.Getenv("ZENDESK_AUTH_MODE"))

	switch mode {
	case "oauth":
		currentAuthMode = authModeOAuth
		return initOAuth()
	case "cookie":
		currentAuthMode = authModeCookie
		return initCookie()
	default:
		return fmt.Errorf("ZENDESK_AUTH_MODE must be set to \"cookie\" or \"oauth\"")
	}
}

// applyAuth sets the appropriate authentication header on an outgoing request.
func applyAuth(req *http.Request) error {
	switch currentAuthMode {
	case authModeOAuth:
		token, err := getOAuthToken()
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
	case authModeCookie:
		cookie, err := getCookie()
		if err != nil {
			return err
		}
		req.Header.Set("Cookie", cookie)
	}
	return nil
}

// refreshAuth re-acquires credentials after a 401 response. For OAuth mode
// this uses the refresh token; for cookie mode it re-extracts from the browser.
func refreshAuth() error {
	switch currentAuthMode {
	case authModeOAuth:
		return refreshOAuthToken()
	case authModeCookie:
		_, err := refreshCookie()
		return err
	}
	return nil
}
