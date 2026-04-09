package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// browserKind identifies which browser family provided the session cookie.
type browserKind int

const (
	browserUnknown browserKind = iota
	browserFirefox
	browserChrome
	browserSafari
)

func (b browserKind) String() string {
	switch b {
	case browserFirefox:
		return "Firefox"
	case browserChrome:
		return "Chrome"
	case browserSafari:
		return "Safari"
	default:
		return "Unknown"
	}
}

// detectUserAgent builds a User-Agent string matching the browser that
// provided the session cookie. This ensures Zendesk sees the same UA
// it would from a real browser session, avoiding bot-detection issues.
func detectUserAgent(browser browserKind) string {
	switch browser {
	case browserFirefox:
		if ua := firefoxUserAgent(); ua != "" {
			return ua
		}
	case browserChrome:
		if ua := chromeUserAgent(); ua != "" {
			return ua
		}
	case browserSafari:
		return safariUserAgent()
	}
	return defaultUserAgent()
}

// firefoxUserAgent reads the Firefox/Zen engine version from compatibility.ini
// in known profile directories.
func firefoxUserAgent() string {
	for _, roots := range [][]string{zenProfileRoots(), firefoxProfileRoots()} {
		for _, root := range roots {
			matches, _ := filepath.Glob(filepath.Join(root, "*", "compatibility.ini"))
			for _, path := range matches {
				if ver := readFirefoxVersion(path); ver != "" {
					return buildFirefoxUA(ver)
				}
			}
		}
	}
	return ""
}

// readFirefoxVersion parses compatibility.ini for the LastVersion line
// (e.g. "LastVersion=128.0_20240801/…" → "128.0").
func readFirefoxVersion(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "LastVersion=") {
			ver := strings.TrimPrefix(line, "LastVersion=")
			// Strip build suffix after _ or /
			if idx := strings.IndexAny(ver, "_/"); idx > 0 {
				ver = ver[:idx]
			}
			return ver
		}
	}
	return ""
}

// buildFirefoxUA constructs a Firefox User-Agent. The "Mozilla/5.0" prefix
// and "Gecko/20100101" token are historical compatibility constants that
// Firefox itself still sends unchanged.
func buildFirefoxUA(version string) string {
	return fmt.Sprintf("Mozilla/5.0 (%s; rv:%s) Gecko/20100101 Firefox/%s",
		platformToken("firefox"), version, version)
}

// chromeUserAgent reads the Chrome or Edge version from the "Last Version"
// file in the browser's data directory.
func chromeUserAgent() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	var paths []string
	switch runtime.GOOS {
	case "darwin":
		paths = []string{
			filepath.Join(home, "Library", "Application Support", "Google", "Chrome", "Last Version"),
			filepath.Join(home, "Library", "Application Support", "Microsoft Edge", "Last Version"),
		}
	case "linux":
		paths = []string{
			filepath.Join(home, ".config", "google-chrome", "Last Version"),
			filepath.Join(home, ".config", "microsoft-edge", "Last Version"),
		}
	}

	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if ver := strings.TrimSpace(string(data)); ver != "" {
			return buildChromeUA(ver)
		}
	}
	return ""
}

// buildChromeUA constructs a Chrome User-Agent. Chrome froze the AppleWebKit
// and Safari tokens at 537.36 — they never increment. Only the Chrome/<version>
// portion is dynamic.
func buildChromeUA(version string) string {
	return fmt.Sprintf("Mozilla/5.0 (%s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36",
		platformToken("chrome"), version)
}

// safariUserAgent reads the macOS and Safari versions from plist files.
// The AppleWebKit/605.1.15 and Safari/605.1.15 tokens are effectively frozen
// by Apple. Only the OS version and Version/<safari> are dynamic.
func safariUserAgent() string {
	if runtime.GOOS != "darwin" {
		return defaultUserAgent()
	}

	macVer := readPlistValue(
		"/System/Library/CoreServices/SystemVersion.plist",
		"ProductVersion",
	)
	safariVer := readPlistValue(
		"/Applications/Safari.app/Contents/Info.plist",
		"CFBundleShortVersionString",
	)

	if macVer == "" {
		macVer = "10_15_7"
	} else {
		// Safari UA convention uses underscores for the OS version
		macVer = strings.ReplaceAll(macVer, ".", "_")
	}
	if safariVer == "" {
		safariVer = "18.0"
	}

	return fmt.Sprintf(
		"Mozilla/5.0 (Macintosh; Intel Mac OS X %s) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/%s Safari/605.1.15",
		macVer, safariVer,
	)
}

// readPlistValue extracts a string value for the given key from an XML plist.
func readPlistValue(path, key string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	content := string(data)
	marker := "<key>" + key + "</key>"
	idx := strings.Index(content, marker)
	if idx < 0 {
		return ""
	}
	rest := content[idx+len(marker):]
	start := strings.Index(rest, "<string>")
	end := strings.Index(rest, "</string>")
	if start < 0 || end < 0 || end <= start {
		return ""
	}
	return rest[start+len("<string>") : end]
}

// defaultUserAgent returns a recent Firefox UA as a fallback when browser
// detection fails. Firefox is chosen because its UA format is widely accepted
// and unlikely to trigger bot-detection heuristics.
func defaultUserAgent() string {
	return buildFirefoxUA("133.0")
}

// platformToken returns the OS/arch parenthetical for User-Agent strings.
// Firefox uses dots in macOS versions ("10.15"), Chrome uses underscores ("10_15_7").
func platformToken(browser string) string {
	switch runtime.GOOS {
	case "darwin":
		if browser == "chrome" {
			return "Macintosh; Intel Mac OS X 10_15_7"
		}
		return "Macintosh; Intel Mac OS X 10.15"
	default:
		arch := runtime.GOARCH
		switch arch {
		case "amd64":
			arch = "x86_64"
		case "arm64":
			arch = "aarch64"
		}
		return "X11; Linux " + arch
	}
}
