package main

import (
	"strings"
	"testing"
)

func TestSanitizeStringReplacesAndReports(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		finds   int
		firstCP string
	}{
		{
			name: "plain text untouched",
			in:   "Billing question about invoice",
			want: "Billing question about invoice",
		},
		{
			// Combining marks (category Mn) and ordinary printable Unicode are
			// NOT control/format characters and must pass through untouched.
			// This pins the category boundary: we neutralize invisible Cc/Cf
			// codepoints, not every non-ASCII rune.
			name: "combining marks and normal unicode preserved",
			in:   "cafe\u0301 日本語 build ✅ Ω",
			want: "cafe\u0301 日本語 build ✅ Ω",
		},
		{
			name: "whitespace preserved",
			in:   "line1\tcol\nline2\r\nline3",
			want: "line1\tcol\nline2\r\nline3",
		},
		{
			name:    "rtl override",
			in:      "good\u202eliar",
			want:    "good[U+202E]liar",
			finds:   1,
			firstCP: "U+202E",
		},
		{
			name:    "zero width space and bom",
			in:      "a\u200bb\ufeffc",
			want:    "a[U+200B]b[U+FEFF]c",
			finds:   2,
			firstCP: "U+200B",
		},
		{
			name:    "repeated codepoint counted once",
			in:      "x\u200by\u200bz",
			want:    "x[U+200B]y[U+200B]z",
			finds:   1,
			firstCP: "U+200B",
		},
		{
			name:    "del control char",
			in:      "a\u007fb",
			want:    "a[U+007F]b",
			finds:   1,
			firstCP: "U+007F",
		},
		{
			name:    "c1 control",
			in:      "a\u0085b",
			want:    "a[U+0085]b",
			finds:   1,
			firstCP: "U+0085",
		},
		{
			name:    "bidi isolate",
			in:      "a\u2066b\u2069c",
			want:    "a[U+2066]b[U+2069]c",
			finds:   2,
			firstCP: "U+2066",
		},
		{
			name:    "escape sequence neutralized",
			in:      "a\u001b[31mred",
			want:    "a[U+001B][31mred",
			finds:   1,
			firstCP: "U+001B",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, finds := sanitizeString(tc.in)
			if got != tc.want {
				t.Errorf("sanitizeString(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if len(finds) != tc.finds {
				t.Fatalf("finds = %d, want %d: %+v", len(finds), tc.finds, finds)
			}
			if tc.finds > 0 && finds[0].codepoint != tc.firstCP {
				t.Errorf("first codepoint = %q, want %q", finds[0].codepoint, tc.firstCP)
			}
		})
	}
}

// TestSanitizeStringNamesKnownCodepoints checks the curated Unicode names are
// attached, and unknown format/control chars fall back to a category label.
func TestSanitizeStringNamesKnownCodepoints(t *testing.T) {
	_, finds := sanitizeString("a\u202eb")
	if len(finds) != 1 || finds[0].name != "RIGHT-TO-LEFT OVERRIDE" {
		t.Errorf("expected RIGHT-TO-LEFT OVERRIDE name, got %+v", finds)
	}
}

// TestSanitizeDataWalksContainers proves the reflective walk reaches strings
// behind pointers, slices, structs, and maps, recording their JSON paths.
func TestSanitizeDataWalksContainers(t *testing.T) {
	type inner struct {
		Name string `json:"name"`
	}
	type outer struct {
		Title string   `json:"title"`
		Items []inner  `json:"items"`
		Ptr   *string  `json:"ptr"`
		Skip  string   `json:"-"`
	}
	ptr := "ptr\u200bval"
	in := outer{
		Title: "clean",
		Items: []inner{{Name: "bad\u202ename"}},
		Ptr:   &ptr,
		Skip:  "ignored\u200bfield",
	}

	cleaned, notes := sanitizeData(in)
	if len(notes) != 2 {
		t.Fatalf("notes = %d, want 2 (items[0].name, ptr): %+v", len(notes), notes)
	}

	paths := map[string]bool{}
	for _, n := range notes {
		paths[n.Field] = true
	}
	if !paths["items[0].name"] {
		t.Errorf("missing note for items[0].name: %+v", notes)
	}
	if !paths["ptr"] {
		t.Errorf("missing note for ptr: %+v", notes)
	}

	out := cleaned.(outer)
	if strings.ContainsRune(out.Items[0].Name, '\u202e') {
		t.Errorf("items[0].name not sanitized: %q", out.Items[0].Name)
	}
	if strings.ContainsRune(*out.Ptr, '\u200b') {
		t.Errorf("ptr not sanitized: %q", *out.Ptr)
	}
	// json:"-" fields are excluded from the walk path but still travel with the
	// value; they simply carry no note (they are never serialized to the model).
	if len(notes) != 2 {
		t.Errorf("json:\"-\" field should not add a note")
	}
}
