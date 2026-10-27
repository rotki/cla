package site

import (
	"strings"
	"testing"
)

func TestResolveDefaults(t *testing.T) {
	s := Resolve(Settings{}, "acme-org")
	if s.Name != "acme-org" || s.Mark != "a" || s.Source != DefaultSource || s.Accent != DefaultAccent || s.LegalName != DefaultLegalName || s.Homepage != "" {
		t.Fatalf("defaults %+v", s)
	}
}

func TestResolveKeepsValidValues(t *testing.T) {
	s := Resolve(Settings{
		Name:        "  Acme  ",
		LegalName:   "Acme GmbH",
		Homepage:    "https://acme.example",
		Source:      "https://git.acme.example/cla",
		AccentColor: "#FF8800",
	}, "acme-org")
	if s.Name != "Acme" || s.Mark != "a" || s.LegalName != "Acme GmbH" || s.Homepage != "https://acme.example" ||
		s.Source != "https://git.acme.example/cla" || s.Accent != "#ff8800" {
		t.Fatalf("resolved %+v", s)
	}
}

func TestResolveRejectsUnsafeValues(t *testing.T) {
	s := Resolve(Settings{
		Name:        "Ac\x00me\n",
		Homepage:    "javascript:alert(1)",
		Source:      "/relative",
		AccentColor: "red; } body { display:none",
	}, "acme-org")
	if s.Name != "Acme" || s.Homepage != "" || s.Source != DefaultSource || s.Accent != DefaultAccent {
		t.Fatalf("resolved %+v", s)
	}
	if long := Resolve(Settings{Name: strings.Repeat("x", 500)}, "o"); len(long.Name) != 60 {
		t.Fatalf("name not capped: %d", len(long.Name))
	}
}

func TestThemeCSS(t *testing.T) {
	css := Resolve(Settings{AccentColor: "#ff8800"}, "o").ThemeCSS()
	if !strings.Contains(css, "--primary: rgb(255, 136, 0);") || !strings.Contains(css, "prefers-color-scheme: dark") {
		t.Fatalf("theme:\n%s", css)
	}
	// A hover shade darker than the accent in light mode.
	if !strings.Contains(css, "--primary-hover: rgb(178, 95, 0);") {
		t.Fatalf("hover shade:\n%s", css)
	}
}
