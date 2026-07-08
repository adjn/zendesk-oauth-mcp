package main

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"unicode"
)

// sanitizedNote records one class of hidden/control character found in one
// customer-controlled field. It is surfaced out-of-band in the response
// envelope's _meta.sanitized list (never inline in the value), so the operator
// and the model get an explicit, structured "this was detected and replaced"
// signal without the human-readable description polluting the data itself.
type sanitizedNote struct {
	Field     string `json:"field"`     // dotted JSON path, e.g. "comments[0].body"
	Codepoint string `json:"codepoint"` // e.g. "U+202E"
	Name      string `json:"name"`      // Unicode name, e.g. "RIGHT-TO-LEFT OVERRIDE"
	Count     int    `json:"count"`     // occurrences of this codepoint in the field
}

// sanitizedLead is the loud, human-readable banner attached to _meta when any
// sanitization happened. The structured `sanitized` list says exactly what and
// where; this line says, in one sentence, that it happened and why — so a
// skimming operator or model cannot miss it.
const sanitizedLead = "Hidden or bidirectional control characters were detected in customer-controlled values and replaced with visible [U+XXXX] markers. They were not passed through verbatim, to prevent bidi/zero-width text-spoofing. See \"sanitized\" for the exact field, codepoint, and count of each."

// runeNames gives friendly Unicode names for the control/format characters most
// likely to be used adversarially (bidi overrides/isolates, zero-width chars,
// the BOM, soft hyphen, word joiner). Anything outside this map falls back to a
// generic category label in runeName, so the list never depends on shipping the
// full Unicode Character Database.
var runeNames = map[rune]string{
	0x00AD: "SOFT HYPHEN",
	0x200B: "ZERO WIDTH SPACE",
	0x200C: "ZERO WIDTH NON-JOINER",
	0x200D: "ZERO WIDTH JOINER",
	0x200E: "LEFT-TO-RIGHT MARK",
	0x200F: "RIGHT-TO-LEFT MARK",
	0x202A: "LEFT-TO-RIGHT EMBEDDING",
	0x202B: "RIGHT-TO-LEFT EMBEDDING",
	0x202C: "POP DIRECTIONAL FORMATTING",
	0x202D: "LEFT-TO-RIGHT OVERRIDE",
	0x202E: "RIGHT-TO-LEFT OVERRIDE",
	0x2060: "WORD JOINER",
	0x2066: "LEFT-TO-RIGHT ISOLATE",
	0x2067: "RIGHT-TO-LEFT ISOLATE",
	0x2068: "FIRST STRONG ISOLATE",
	0x2069: "POP DIRECTIONAL ISOLATE",
	0xFEFF: "ZERO WIDTH NO-BREAK SPACE (BOM)",
}

// isDangerous reports whether r is a character that must not reach the model
// verbatim. It targets the Unicode Control (Cc) and Format (Cf) categories,
// which together cover C0/C1 controls, DEL, all bidi controls, and every
// zero-width / invisible formatting character — i.e. "invisible characters" as
// a class, per the Secure AI Standard, rather than a fixed enumerated list
// (which would leave equally-invisible codepoints like U+200B live). Ordinary
// whitespace (tab, newline, carriage return) is deliberately preserved — it is
// not an invisible spoofing vector, and encoding/json already renders it
// visibly as \t / \n / \r.
//
// Note ESC (U+001B) falls inside the C0 range, so ANSI color/cursor escape
// sequences are neutralized here too.
func isDangerous(r rune) bool {
	switch r {
	case '\t', '\n', '\r':
		return false
	}
	return unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r)
}

// runeName returns a human-readable name for a dangerous codepoint: the curated
// Unicode name when known, otherwise a category label.
func runeName(r rune) string {
	if n, ok := runeNames[r]; ok {
		return n
	}
	if unicode.Is(unicode.Cf, r) {
		return "format character"
	}
	return "control character"
}

// runeFinding is the per-codepoint tally returned by sanitizeString.
type runeFinding struct {
	codepoint string
	name      string
	count     int
}

// sanitizeString replaces every dangerous character in s with a visible
// "[U+XXXX]" marker and returns the cleaned string plus a per-codepoint tally
// (sorted by codepoint for deterministic output). A string with nothing
// dangerous is returned unchanged with a nil tally, so the common case is
// allocation-free past the initial scan.
func sanitizeString(s string) (string, []runeFinding) {
	dangerous := false
	for _, r := range s {
		if isDangerous(r) {
			dangerous = true
			break
		}
	}
	if !dangerous {
		return s, nil
	}

	var b strings.Builder
	b.Grow(len(s))
	counts := map[rune]int{}
	for _, r := range s {
		if isDangerous(r) {
			counts[r]++
			fmt.Fprintf(&b, "[U+%04X]", r)
			continue
		}
		b.WriteRune(r)
	}

	runes := make([]rune, 0, len(counts))
	for r := range counts {
		runes = append(runes, r)
	}
	sort.Slice(runes, func(i, j int) bool { return runes[i] < runes[j] })

	finds := make([]runeFinding, 0, len(runes))
	for _, r := range runes {
		finds = append(finds, runeFinding{
			codepoint: fmt.Sprintf("U+%04X", r),
			name:      runeName(r),
			count:     counts[r],
		})
	}
	return b.String(), finds
}

// sanitizeData walks data, replaces dangerous characters in every reachable
// string (struct fields, slice/array elements, map keys and values, and values
// behind pointers or interfaces), and returns the cleaned value alongside the
// list of findings for the envelope. This is the single choke point all data
// tools share, so no handler can forget to sanitize and the output schema
// cannot grow an unsanitized field.
//
// The walk runs against an addressable box of the top-level value, so a
// value-typed input is not replaced wholesale. It does NOT deep-copy, though:
// when data is a pointer, map, or slice — as the callers pass — the shared
// underlying data is sanitized in place. Callers discard the original
// immediately, so this is intended; do not rely on the argument being pristine
// after the call.
func sanitizeData(data any) (any, []sanitizedNote) {
	if data == nil {
		return data, nil
	}
	orig := reflect.ValueOf(data)
	box := reflect.New(orig.Type())
	box.Elem().Set(orig)

	var notes []sanitizedNote
	sanitizeValue(box.Elem(), "", &notes)
	return box.Elem().Interface(), notes
}

// sanitizeValue recurses through pointers, interfaces, structs, slices, arrays,
// and maps, sanitizing each string leaf and recording its JSON path. Every
// JSON-serializable container kind is handled so a dangerous string cannot hide
// in a shape the walker silently skips; non-string scalar kinds (numbers,
// bools) carry no text and are no-ops.
func sanitizeValue(v reflect.Value, path string, notes *[]sanitizedNote) {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return
		}
		sanitizeValue(v.Elem(), path, notes)

	case reflect.Interface:
		// An interface's concrete value is not addressable, so sanitize an
		// addressable copy and write it back. Without this, a dangerous string
		// inside an any-typed field (e.g. a custom-field value) would be
		// detected but silently dropped, because CanSet would be false on the
		// inner string.
		if v.IsNil() {
			return
		}
		inner := v.Elem()
		box := reflect.New(inner.Type()).Elem()
		box.Set(inner)
		sanitizeValue(box, path, notes)
		if v.CanSet() {
			v.Set(box)
		}

	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" {
				continue // unexported
			}
			name := jsonFieldName(f)
			if name == "" {
				continue // json:"-"
			}
			sanitizeValue(v.Field(i), joinPath(path, name), notes)
		}

	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			sanitizeValue(v.Index(i), fmt.Sprintf("%s[%d]", path, i), notes)
		}

	case reflect.Map:
		// Map elements are not addressable, so each value is sanitized via an
		// addressable copy written back with SetMapIndex. String keys are also
		// customer-visible (they become JSON object keys), so a dangerous key
		// is escaped and the entry is re-keyed. MapKeys returns a snapshot, so
		// mutating the map during the loop is safe.
		for _, k := range v.MapKeys() {
			cleanedKey, keyFinds := "", []runeFinding(nil)
			if k.Kind() == reflect.String {
				cleanedKey, keyFinds = sanitizeString(k.String())
			}

			var elemPath string
			if k.Kind() == reflect.String {
				elemPath = fmt.Sprintf("%s[%s]", path, cleanedKey)
			} else {
				elemPath = fmt.Sprintf("%s[%v]", path, k.Interface())
			}

			mv := v.MapIndex(k)
			box := reflect.New(mv.Type()).Elem()
			box.Set(mv)
			sanitizeValue(box, elemPath, notes)

			if len(keyFinds) == 0 {
				v.SetMapIndex(k, box)
				continue
			}
			v.SetMapIndex(k, reflect.Value{}) // delete the original key
			nk := reflect.New(k.Type()).Elem()
			nk.SetString(cleanedKey)
			v.SetMapIndex(nk, box)
			for _, f := range keyFinds {
				*notes = append(*notes, sanitizedNote{
					Field:     elemPath + " (key)",
					Codepoint: f.codepoint,
					Name:      f.name,
					Count:     f.count,
				})
			}
		}

	case reflect.String:
		if !v.CanSet() {
			return
		}
		cleaned, finds := sanitizeString(v.String())
		if len(finds) == 0 {
			return
		}
		v.SetString(cleaned)
		for _, f := range finds {
			*notes = append(*notes, sanitizedNote{
				Field:     path,
				Codepoint: f.codepoint,
				Name:      f.name,
				Count:     f.count,
			})
		}
	}
}

// jsonFieldName returns the JSON object key a struct field serializes under,
// falling back to the Go field name. It returns "" for json:"-" fields, which
// never appear in output and so contribute no path.
func jsonFieldName(f reflect.StructField) string {
	tag := f.Tag.Get("json")
	if tag == "" {
		return f.Name
	}
	name, _, _ := strings.Cut(tag, ",")
	if name == "-" {
		return ""
	}
	if name == "" {
		return f.Name
	}
	return name
}

func joinPath(base, name string) string {
	if base == "" {
		return name
	}
	return base + "." + name
}
