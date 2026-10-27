// Package site holds the branding an organization sets in config.json: the
// name shown on the pages, the legal owner, links, and an accent colour.
// Values that are missing or not safe to use fall back to the defaults,
// so a bad edit to config.json degrades the look, never the pages.
package site

import (
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// DefaultSource is where this service's code lives. Under the AGPL, an
// organization running a modified copy must point "source" at its own.
const DefaultSource = "https://github.com/rotki/cla"

// DefaultLegalName is the copyright holder in the footer when none is set.
const DefaultLegalName = "Rotki Solutions GmbH"

// DefaultAccent is the accent colour when none or an invalid one is set.
const DefaultAccent = "#4e5ba6"

// Settings is the "site" block of config.json.
type Settings struct {
	// Name is the organization's display name; the GitHub org name if empty.
	Name string `json:"name"`
	// LegalName is the footer copyright holder; DefaultLegalName if empty.
	LegalName string `json:"legal_name"`
	// Homepage is linked from the footer; omitted if empty.
	Homepage string `json:"homepage"`
	// Source links to this service's source code.
	Source string `json:"source"`
	// AccentColor is a #rrggbb colour for buttons, links and highlights.
	AccentColor string `json:"accent_color"`
}

// Site is the resolved branding the pages use.
type Site struct {
	Name      string
	Mark      string
	LegalName string
	Homepage  string
	Source    string
	Accent    string
}

var hexColor = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// Resolve applies the defaults: org stands in for a missing name.
func Resolve(s Settings, org string) Site {
	out := Site{
		Name:      clean(s.Name, 60),
		LegalName: clean(s.LegalName, 120),
		Homepage:  safeURL(s.Homepage),
		Source:    safeURL(s.Source),
		Accent:    strings.ToLower(s.AccentColor),
	}
	if out.Name == "" {
		out.Name = org
	}
	if out.Source == "" {
		out.Source = DefaultSource
	}
	if out.LegalName == "" {
		out.LegalName = DefaultLegalName
	}
	if !hexColor.MatchString(out.Accent) {
		out.Accent = DefaultAccent
	}
	for _, r := range out.Name {
		out.Mark = strings.ToLower(string(r))
		break
	}
	return out
}

// clean trims a display string, drops control characters and caps its
// length; html/template does the escaping.
func clean(s string, limit int) string {
	var b strings.Builder
	n := 0
	for _, r := range strings.TrimSpace(s) {
		if r < 0x20 || r == 0x7f {
			continue
		}
		if n == limit {
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// safeURL accepts only absolute http(s) URLs.
func safeURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return ""
	}
	return u.String()
}

// ThemeCSS renders the custom properties that carry the accent colour, for
// light and dark mode. The colour is validated, so nothing else can reach
// the stylesheet.
func (s Site) ThemeCSS() string {
	r, g, b := rgb(s.Accent)
	dark := mix(r, g, b, 255, 255, 255, 0.12)
	link := mix(r, g, b, 255, 255, 255, 0.55)
	hover := mix(r, g, b, 0, 0, 0, 0.3)
	darkHover := mix(r, g, b, 255, 255, 255, 0.25)
	return fmt.Sprintf(`/* Generated from config.json "site.accent_color". */
:root {
  --primary: rgb(%[1]s);
  --primary-hover: rgb(%[2]s);
  --primary-soft: rgba(%[1]s, 0.08);
  --primary-ring: rgba(%[1]s, 0.35);
  --link: rgb(%[1]s);
}
@media (prefers-color-scheme: dark) {
  :root {
    --primary: rgb(%[3]s);
    --primary-hover: rgb(%[4]s);
    --primary-soft: rgba(%[3]s, 0.14);
    --primary-ring: rgba(%[5]s, 0.45);
    --link: rgb(%[5]s);
  }
}
`, triple(r, g, b), triple(hover[0], hover[1], hover[2]), triple(dark[0], dark[1], dark[2]),
		triple(darkHover[0], darkHover[1], darkHover[2]), triple(link[0], link[1], link[2]))
}

func rgb(hex string) (r, g, b int) {
	v, _ := strconv.ParseUint(strings.TrimPrefix(hex, "#"), 16, 32)
	return int(v >> 16 & 0xff), int(v >> 8 & 0xff), int(v & 0xff)
}

// mix moves a colour the given share towards another.
func mix(r, g, b, tr, tg, tb int, share float64) [3]int {
	f := func(c, t int) int { return c + int(math.Round(float64(t-c)*share)) }
	return [3]int{f(r, tr), f(g, tg), f(b, tb)}
}

func triple(r, g, b int) string {
	return fmt.Sprintf("%d, %d, %d", r, g, b)
}
