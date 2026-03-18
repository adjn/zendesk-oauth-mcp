package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/browserutils/kooky"
	"github.com/browserutils/kooky/browser/chrome"
	firefoxkooky "github.com/browserutils/kooky/browser/firefox"
	"github.com/browserutils/kooky/browser/safari"
)

type cookieCandidate struct {
	value   string
	expires time.Time
}

var (
	cookieMu     sync.Mutex
	cachedCookie string
)

// extractCookieFromBrowser searches installed browsers for Zendesk session cookies.
// Supports Chrome, Firefox, Safari, and Zen (Firefox-based).
// When multiple browsers have the same cookie, the one with the latest expiry wins.
func extractCookieFromBrowser(subdomain string) (string, error) {
	domain := subdomain + ".zendesk.com"

	best := map[string]cookieCandidate{}

	filters := []kooky.Filter{
		kooky.Valid,
		kooky.DomainHasSuffix(domain),
	}

	// Try Zen and Firefox first (no Keychain prompt)
	for _, c := range extractZenCookiesFull(domain) {
		if prev, ok := best[c.Name]; !ok || c.Expires.After(prev.expires) {
			best[c.Name] = cookieCandidate{value: c.Name + "=" + c.Value, expires: c.Expires}
		}
	}

	for c := range firefoxkooky.TraverseCookies("", filters...).OnlyCookies() {
		if prev, ok := best[c.Name]; !ok || c.Expires.After(prev.expires) {
			best[c.Name] = cookieCandidate{value: c.Name + "=" + c.Value, expires: c.Expires}
		}
	}

	// If we found cookies, use them without touching Chrome/Safari
	if len(best) > 0 {
		return buildCookieString(best), nil
	}

	// Fall back to Safari, then Chrome (may trigger Keychain prompt)
	for _, finder := range []func(string, ...kooky.Filter) kooky.CookieSeq{
		safari.TraverseCookies,
		chrome.TraverseCookies,
	} {
		for c := range finder("", filters...).OnlyCookies() {
			if prev, ok := best[c.Name]; !ok || c.Expires.After(prev.expires) {
				best[c.Name] = cookieCandidate{value: c.Name + "=" + c.Value, expires: c.Expires}
			}
		}
		if len(best) > 0 {
			return buildCookieString(best), nil
		}
	}

	return "", fmt.Errorf("no Zendesk cookies found in any browser for %s", domain)
}

func buildCookieString(best map[string]cookieCandidate) string {
	var parts []string
	for _, c := range best {
		parts = append(parts, c.value)
	}
	fmt.Fprintf(os.Stderr, "zendesk-oauth-mcp: extracted %d cookies from browser\n", len(parts))
	return strings.Join(parts, "; ")
}

func extractZenCookiesFull(domain string) []*kooky.Cookie {
	var roots []string
	switch runtime.GOOS {
	case "darwin":
		home, _ := os.UserHomeDir()
		roots = append(roots, filepath.Join(home, "Library", "Application Support", "zen"))
	case "linux":
		home, _ := os.UserHomeDir()
		roots = append(roots, filepath.Join(home, ".zen"))
	}

	var found []*kooky.Cookie
	for _, root := range roots {
		profiles, err := filepath.Glob(filepath.Join(root, "Profiles", "*", "cookies.sqlite"))
		if err != nil {
			continue
		}
		for _, dbPath := range profiles {
			for c := range firefoxkooky.TraverseCookies(dbPath, kooky.Valid, kooky.DomainHasSuffix(domain)).OnlyCookies() {
				found = append(found, c)
			}
			if len(found) > 0 {
				return found
			}
		}
	}

	return nil
}

// refreshCookie re-extracts the cookie from the browser and updates the cache.
func refreshCookie() (string, error) {
	if zendeskSubdomain == "" {
		return "", fmt.Errorf("ZENDESK_SUBDOMAIN is required to extract cookies")
	}

	cookie, err := extractCookieFromBrowser(zendeskSubdomain)
	if err != nil {
		return "", err
	}

	cookieMu.Lock()
	cachedCookie = cookie
	zendeskCookie = cookie
	cookieMu.Unlock()

	return cookie, nil
}

// initCookie sets up the cookie, either from env or browser extraction.
func initCookie() error {
	if zendeskCookie != "" {
		return nil
	}

	_, err := refreshCookie()
	return err
}
