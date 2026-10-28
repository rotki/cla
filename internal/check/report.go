package check

import (
	"fmt"
	"net/url"
	"strings"
)

// Marker identifies the bot's comment so it is edited, never duplicated.
const Marker = "<!-- cla-status -->"

const linkEmailDocs = "https://docs.github.com/en/account-and-profile/setting-up-and-managing-your-personal-account-on-github/managing-email-preferences/adding-an-email-address-to-your-github-account"

// Status is a commit status to set.
type Status struct {
	State       string
	Description string
}

// StatusFor maps a result to a commit status. Unsigned work is "pending",
// like cla-assistant, so newcomers do not see a red failure first.
func StatusFor(r Result) Status {
	total := r.Total()
	switch {
	case total == 0:
		return Status{"success", "No commit authors need to sign the CLA."}
	case r.OK():
		return Status{"success", "All commit authors have signed the CLA."}
	case len(r.Unsigned) == 0 && len(r.Unlinked) == 0:
		return Status{"pending", "Waiting for an employer signature to be confirmed."}
	}
	return Status{"pending", fmt.Sprintf("%d of %d commit authors have signed the CLA.", len(r.Signed), total)}
}

// SignURL is the signing page for one pull request.
func SignURL(baseURL, owner, repo string, number int) string {
	q := url.Values{"owner": {owner}, "repo": {repo}, "pr": {fmt.Sprint(number)}}
	return baseURL + "/sign?" + q.Encode()
}

// Comment renders the sticky comment. needed is false when everything is
// signed, in which case a comment is only written if one already exists.
func Comment(r Result, signURL, claURL string) (body string, needed bool) {
	var b strings.Builder
	b.WriteString(Marker + "\n")

	if r.OK() {
		fmt.Fprintf(&b, "All commit authors have signed the [Contributor License Agreement](%s). Thank you!\n", claURL)
		return b.String(), false
	}

	fmt.Fprintf(&b, "Thank you for your contribution! Before we can merge it, every commit author in this pull request needs to sign our [Contributor License Agreement](%s).\n\n", claURL)
	if len(r.Unsigned) > 0 {
		fmt.Fprintf(&b, "**[Sign the CLA](%s)**\n\n", signURL)
	}
	fmt.Fprintf(&b, "**%d** of **%d** commit authors have signed the CLA.\n\n", len(r.Signed), r.Total())

	// Lists are capped: a pull request with very many authors must not push
	// the comment past GitHub's 65,536 character limit.
	lines := make([]string, 0, r.Total())
	for _, a := range r.Unsigned {
		lines = append(lines, "- [ ] "+profile(a.Login))
	}
	for _, a := range r.Pending {
		lines = append(lines, "- [ ] "+profile(a.Login)+" (employer signature waiting for an admin to confirm it)")
	}
	for _, a := range r.Signed {
		lines = append(lines, "- [x] "+profile(a.Login))
	}
	lines, more := capped(lines, maxListed)
	for _, line := range lines {
		b.WriteString(line + "\n")
	}
	if more > 0 {
		fmt.Fprintf(&b, "- and %d more\n", more)
	}

	if len(r.Unlinked) > 0 {
		names := make([]string, 0, len(r.Unlinked))
		for _, a := range r.Unlinked {
			names = append(names, codeSpan(a.Name))
		}
		names, more := capped(names, maxNames)
		list := strings.Join(names, ", ")
		if more > 0 {
			list += fmt.Sprintf(" and %d more", more)
		}
		fmt.Fprintf(&b, "\nSome commits are authored with an email address that is not linked to a GitHub account: %s. [Add that email to your GitHub account](%s), or amend the commits with an email that is, then push again.\n", list, linkEmailDocs)
	}
	return b.String(), true
}

const (
	maxListed = 50
	maxNames  = 20
	// maxNameLength trims a git author name, which can be any length.
	maxNameLength = 100
)

// capped keeps the first limit items and says how many were left out.
func capped(items []string, limit int) (shown []string, more int) {
	if len(items) <= limit {
		return items, 0
	}
	return items[:limit], len(items) - limit
}

// profile names an account by a link to its profile rather than an
// @mention, so the comment notifies nobody, as with cla-assistant: authors
// already hear about their pull request, and the comment is rewritten on
// every push. Logins are letters, digits and hyphens (plus "[bot]" for an
// App), so they need no escaping.
func profile(login string) string {
	return "[" + login + "](https://github.com/" + login + ")"
}

// codeSpan shows a git author name, which anyone can set to anything, as
// inline code: no formatting, links, autolinks or mentions can form inside
// it. Backticks and control characters are dropped and the length is
// capped, so it cannot break out of the span or flood the comment.
func codeSpan(name string) string {
	var b strings.Builder
	n := 0
	for _, r := range name {
		if r == '`' || r < 0x20 || r == 0x7f {
			continue
		}
		if n == maxNameLength {
			b.WriteString("…")
			break
		}
		b.WriteRune(r)
		n++
	}
	if b.Len() == 0 {
		return "`(no name)`"
	}
	return "`" + b.String() + "`"
}
