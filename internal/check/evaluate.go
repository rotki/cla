// Package check decides whether a pull request's commit authors are covered
// by the CLA, and reports it as a commit status and one sticky comment.
//
// The rules follow cla-assistant: every commit author counts, falling back to
// the committer when the author's email is not linked to a GitHub account;
// the allowlist and the exempt team need not sign; Co-authored-by trailers
// are ignored; a commit with no linked account at all fails. Bot commits are
// exempt in pull requests a bot account opened; elsewhere only a bot account
// on the allowlist is.
package check

import (
	"strings"

	"github.com/rotki/cla/internal/store"
)

// Author is one distinct commit author on a pull request.
type Author struct {
	ID    int64
	Login string
	// Name is the git author name, used only when no account is linked.
	Name string
	Bot  bool
}

// Linked reports whether the commit is tied to a GitHub account.
func (a Author) Linked() bool {
	return a.ID > 0
}

// Result sorts the authors that must be covered. Exempt authors are left out.
type Result struct {
	Signed   []Author
	Pending  []Author
	Unsigned []Author
	Unlinked []Author
	// Bots are bot accounts with commits in a pull request a person opened.
	// They cannot sign, so a maintainer decides: allowlist the bot, or have
	// the commits rewritten.
	Bots []Author
}

func (r Result) Total() int {
	return len(r.Signed) + len(r.Pending) + len(r.Unsigned) + len(r.Unlinked) + len(r.Bots)
}

// OK reports whether the pull request may be merged.
func (r Result) OK() bool {
	return len(r.Pending) == 0 && len(r.Unsigned) == 0 && len(r.Unlinked) == 0 && len(r.Bots) == 0
}

// Blocking returns the account IDs whose signature would change the result.
func (r Result) Blocking() []int64 {
	ids := make([]int64, 0, len(r.Unsigned)+len(r.Pending))
	for _, a := range r.Unsigned {
		ids = append(ids, a.ID)
	}
	for _, a := range r.Pending {
		ids = append(ids, a.ID)
	}
	return ids
}

// Rules holds the exemptions. Logins are compared case-insensitively.
type Rules struct {
	Allowlist  map[string]bool
	ExemptTeam map[string]bool
	// BotPR exempts commits that claim to be a bot's. It is only set for a
	// pull request opened by a bot account: in one opened by a person, such
	// a commit could be anyone's, so it has to be linked like any other, and
	// a linked bot account is exempt only when it is on the allowlist.
	BotPR bool
}

// NewRules lower-cases the allowlist from config.json.
func NewRules(allowlist []string, team map[string]bool, botPR bool) Rules {
	allow := make(map[string]bool, len(allowlist))
	for _, login := range allowlist {
		allow[strings.ToLower(login)] = true
	}
	return Rules{Allowlist: allow, ExemptTeam: team, BotPR: botPR}
}

func (r Rules) exempt(a Author) bool {
	login := strings.ToLower(a.Login)
	if a.Bot {
		// Allowlisting a bot trusts its noreply address the way a signature
		// trusts a person's email: a commit links to whoever's it names.
		return r.BotPR || (login != "" && r.Allowlist[login])
	}
	return login != "" && (r.Allowlist[login] || r.ExemptTeam[login])
}

// Evaluate sorts authors by where they stand.
func Evaluate(authors []Author, rules Rules, standing func(int64) store.Standing) Result {
	var res Result
	for _, a := range authors {
		if rules.exempt(a) {
			continue
		}
		if !a.Linked() {
			res.Unlinked = append(res.Unlinked, a)
			continue
		}
		if a.Bot {
			res.Bots = append(res.Bots, a)
			continue
		}
		switch standing(a.ID) {
		case store.Signed, store.GrandfatheredIn:
			res.Signed = append(res.Signed, a)
		case store.Pending:
			res.Pending = append(res.Pending, a)
		default:
			res.Unsigned = append(res.Unsigned, a)
		}
	}
	return res
}
