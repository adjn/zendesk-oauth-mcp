package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBrowserKindString(t *testing.T) {
	tests := []struct {
		kind browserKind
		want string
	}{
		{browserUnknown, "Unknown"},
		{browserFirefox, "Firefox"},
		{browserChrome, "Chrome"},
		{browserSafari, "Safari"},
	}
	for _, tt := range tests {
		if got := tt.kind.String(); got != tt.want {
			t.Errorf("browserKind(%d).String() = %q, want %q", tt.kind, got, tt.want)
		}
	}
}

func TestReadFirefoxVersion(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "version with build suffix",
			content: "[Compatibility]\nLastVersion=128.0_20240801/20240801\n",
			want:    "128.0",
		},
		{
			name:    "version with underscore only",
			content: "[Compatibility]\nLastVersion=131.0.2_20241010\n",
			want:    "131.0.2",
		},
		{
			name:    "version with slash only",
			content: "LastVersion=115.0/build123\n",
			want:    "115.0",
		},
		{
			name:    "bare version no suffix",
			content: "LastVersion=99.0\n",
			want:    "99.0",
		},
		{
			name:    "empty file",
			content: "",
			want:    "",
		},
		{
			name:    "no LastVersion key",
			content: "[Compatibility]\nLastPlatformDir=/usr/lib/firefox\n",
			want:    "",
		},
		{
			name:    "LastVersion with empty value",
			content: "LastVersion=\n",
			want:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "compatibility.ini")
			if err := os.WriteFile(path, []byte(tt.content), 0644); err != nil {
				t.Fatal(err)
			}
			got := readFirefoxVersion(path)
			if got != tt.want {
				t.Errorf("readFirefoxVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReadFirefoxVersionMissingFile(t *testing.T) {
	got := readFirefoxVersion("/nonexistent/compatibility.ini")
	if got != "" {
		t.Errorf("readFirefoxVersion(missing) = %q, want empty", got)
	}
}

func TestBuildFirefoxUA(t *testing.T) {
	ua := buildFirefoxUA("128.0")

	for _, substr := range []string{
		"Mozilla/5.0 (",
		"rv:128.0",
		"Gecko/20100101",
		"Firefox/128.0",
	} {
		if !strings.Contains(ua, substr) {
			t.Errorf("buildFirefoxUA missing %q: got %s", substr, ua)
		}
	}
}

func TestBuildChromeUA(t *testing.T) {
	ua := buildChromeUA("120.0.6099.109")

	for _, substr := range []string{
		"Mozilla/5.0 (",
		"AppleWebKit/537.36",
		"Chrome/120.0.6099.109",
		"Safari/537.36",
	} {
		if !strings.Contains(ua, substr) {
			t.Errorf("buildChromeUA missing %q: got %s", substr, ua)
		}
	}
}

func TestDefaultUserAgent(t *testing.T) {
	ua := defaultUserAgent()
	if !strings.Contains(ua, "Firefox/133.0") {
		t.Errorf("defaultUserAgent() = %q, want Firefox/133.0 fallback", ua)
	}
}

func TestDetectUserAgentTable(t *testing.T) {
	tests := []struct {
		name    string
		browser browserKind
		want    string // substring expected in the result
	}{
		{"unknown returns Firefox fallback", browserUnknown, "Firefox/133.0"},
		{"safari on non-darwin returns Firefox fallback", browserSafari, "Firefox/"},
	}

	// Safari detection reads macOS plist files, so on Linux it falls back
	if runtime.GOOS == "darwin" {
		tests[1].want = "Safari/"
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ua := detectUserAgent(tt.browser)
			if ua == "" {
				t.Fatal("detectUserAgent returned empty string")
			}
			if !strings.Contains(ua, tt.want) {
				t.Errorf("detectUserAgent(%v) = %q, want substring %q", tt.browser, ua, tt.want)
			}
		})
	}
}

func TestDetectUserAgentAlwaysValid(t *testing.T) {
	for _, b := range []browserKind{browserUnknown, browserFirefox, browserChrome, browserSafari} {
		ua := detectUserAgent(b)
		if ua == "" {
			t.Errorf("detectUserAgent(%v) returned empty", b)
		}
		if !strings.HasPrefix(ua, "Mozilla/5.0") {
			t.Errorf("detectUserAgent(%v) = %q, missing Mozilla/5.0 prefix", b, ua)
		}
	}
}

func TestReadPlistValue(t *testing.T) {
	tests := []struct {
		name    string
		content string
		key     string
		want    string
	}{
		{
			name: "macOS SystemVersion",
			content: `<?xml version="1.0"?>
<plist version="1.0">
<dict>
	<key>ProductName</key>
	<string>macOS</string>
	<key>ProductVersion</key>
	<string>15.3.2</string>
</dict>
</plist>`,
			key:  "ProductVersion",
			want: "15.3.2",
		},
		{
			name: "Safari bundle version",
			content: `<?xml version="1.0"?>
<plist version="1.0">
<dict>
	<key>CFBundleShortVersionString</key>
	<string>18.3</string>
</dict>
</plist>`,
			key:  "CFBundleShortVersionString",
			want: "18.3",
		},
		{
			name:    "key not present",
			content: `<dict><key>Other</key><string>val</string></dict>`,
			key:     "Missing",
			want:    "",
		},
		{
			name:    "empty file",
			content: "",
			key:     "ProductVersion",
			want:    "",
		},
		{
			name:    "no string element after key",
			content: `<dict><key>ProductVersion</key><integer>15</integer></dict>`,
			key:     "ProductVersion",
			want:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "test.plist")
			if err := os.WriteFile(path, []byte(tt.content), 0644); err != nil {
				t.Fatal(err)
			}
			got := readPlistValue(path, tt.key)
			if got != tt.want {
				t.Errorf("readPlistValue(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

func TestReadPlistValueMissingFile(t *testing.T) {
	got := readPlistValue("/nonexistent/test.plist", "any")
	if got != "" {
		t.Errorf("readPlistValue(missing) = %q, want empty", got)
	}
}

func TestPlatformToken(t *testing.T) {
	ff := platformToken("firefox")
	ch := platformToken("chrome")

	switch runtime.GOOS {
	case "darwin":
		if !strings.Contains(ff, "Macintosh") {
			t.Errorf("firefox token on darwin = %q, want Macintosh", ff)
		}
		if !strings.Contains(ch, "Macintosh") {
			t.Errorf("chrome token on darwin = %q, want Macintosh", ch)
		}
	case "linux":
		if !strings.HasPrefix(ff, "X11; Linux") {
			t.Errorf("firefox token on linux = %q, want X11; Linux prefix", ff)
		}
	}
}

func TestSafariUserAgentNonDarwin(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("only valid on non-darwin")
	}
	ua := safariUserAgent()
	if !strings.Contains(ua, "Firefox/") {
		t.Errorf("safariUserAgent() on non-darwin = %q, want Firefox fallback", ua)
	}
}
