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
	browserFirefox             // covers both Firefox and Zen (same engine)
	browserChrome              // covers Chrome and Edge (Chromium-based)
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

// detectUserAgent determines the User-Agent string for the browser that
// provided the session cookie by reading version info from profile directories.
func detectUserAgent(browser browserKind) string {
	switch browser {
	case browserFirefox:
		if ua := firefoxLikeUserAgent(); ua != "" {
			return ua
		}
	case browserChrome:
		if ua := chromeLikeUserAgent(); ua != "" {
			return ua
		}
	case browserSafari:
		return safariUserAgent()
	}
	return defaultUserAgent()
}

// firefoxLikeUserAgent reads the Firefox/Zen version from compatibility.ini
// found in known profile directories.
func firefoxLikeUserAgent() string {
	for _, roots := range [][]string{zenProfileRoots(), firefoxProfileRoots()} {
		for _, root := range roots {
			matches, _ := filepath.Glob(filepath.Join(root, "*", "compatibility.ini"))
			for _, path := range matches {
				if version := readFirefoxVersion(path); version != "" {
					return buildFirefoxUA(version)
				}
			}
		}
	}
	return ""
}

// readFirefoxVersion parses a compatibility.ini file and returns the version
// from the LastVersion line (e.g. "128.0" from "LastVersion=128.0_2024…/…").
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
			version := strings.TrimPrefix(line, "LastVersion=")
			if idx := strings.IndexAny(version, "_/"); idx > 0 {
				version = version[:idx]
			}
			return version
		}
	}
	return ""
}

func buildFirefoxUA(version string) string {
	return fmt.Sprintf("Mozilla/5.0 (%s; rv:%s) Gecko/20100101 Firefox/%s",
		uaPlatformFirefox(), version, version)
}

// chromeLikeUserAgent reads the Chrome or Edge version from the "Last Version"
// file in the browser's data directory.
func chromeLikeUserAgent() string {
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
		version := strings.TrimSpace(string(data))
		if version != "" {
			return buildChromeUA(version)
		}
	}
	return ""
}

func buildChromeUA(version string) string {
	return fmt.Sprintf("Mozilla/5.0 (%s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36",
		uaPlatformChrome(), version)
}

func safariUserAgent() string {
	if runtime.GOOS != "darwin" {
		return defaultUserAgent()
	}
	return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"
}

// defaultUserAgent returns a recent Firefox UA as a sensible fallback.
func defaultUserAgent() string {
	return buildFirefoxUA("133.0")
}

// Platform strings used in User-Agent construction.

func uaPlatformFirefox() string {
	switch runtime.GOOS {
	case "darwin":
		return "Macintosh; Intel Mac OS X 10.15"
	default:
		return "X11; Linux " + normalizeArch()
	}
}

func uaPlatformChrome() string {
	switch runtime.GOOS {
	case "darwin":
		return "Macintosh; Intel Mac OS X 10_15_7"
	default:
		return "X11; Linux " + normalizeArch()
	}
}

func normalizeArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	default:
		return runtime.GOARCH
	}
}
