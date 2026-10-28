package check

import (
	"context"
	"strconv"
	"strings"

	"github.com/rotki/cla/internal/githubapp"
)

const prQuery = `query($owner: String!, $name: String!, $number: Int!, $cursor: String) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      state
      headRefOid
      author { __typename }
      commits(first: 100, after: $cursor) {
        pageInfo { hasNextPage endCursor }
        nodes {
          commit {
            author { name email user { databaseId login } }
            committer { name email user { databaseId login } }
          }
        }
      }
    }
  }
}`

type gitActor struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	User  *struct {
		DatabaseID int64  `json:"databaseId"`
		Login      string `json:"login"`
	} `json:"user"`
}

// PR is what a check needs to know about a pull request.
type PR struct {
	Open    bool
	HeadSHA string
	// OpenedByBot is true when a GitHub App account opened the pull request.
	// Unlike a commit's author, the opener is authenticated by GitHub.
	OpenedByBot bool
	Authors     []Author
}

// fetchPR loads the state, head and distinct commit authors, 100 commits per
// page.
func fetchPR(ctx context.Context, c *githubapp.Client, owner, repo string, number int) (PR, error) {
	var pr PR
	seen := map[string]bool{}
	var cursor *string
	for {
		var data struct {
			Repository struct {
				PullRequest *struct {
					State      string `json:"state"`
					HeadRefOid string `json:"headRefOid"`
					Author     *struct {
						Typename string `json:"__typename"`
					} `json:"author"`
					Commits struct {
						PageInfo struct {
							HasNextPage bool   `json:"hasNextPage"`
							EndCursor   string `json:"endCursor"`
						} `json:"pageInfo"`
						Nodes []struct {
							Commit struct {
								Author    gitActor `json:"author"`
								Committer gitActor `json:"committer"`
							} `json:"commit"`
						} `json:"nodes"`
					} `json:"commits"`
				} `json:"pullRequest"`
			} `json:"repository"`
		}
		vars := map[string]any{"owner": owner, "name": repo, "number": number, "cursor": cursor}
		if err := c.GraphQL(ctx, prQuery, vars, &data); err != nil {
			return pr, err
		}
		p := data.Repository.PullRequest
		if p == nil {
			return pr, nil
		}
		pr.Open = p.State == "OPEN"
		pr.HeadSHA = p.HeadRefOid
		pr.OpenedByBot = p.Author != nil && p.Author.Typename == "Bot"

		for _, n := range p.Commits.Nodes {
			a := authorOf(n.Commit.Author, n.Commit.Committer)
			key := "id:" + strconv.FormatInt(a.ID, 10)
			if !a.Linked() {
				key = "name:" + strings.ToLower(a.Name)
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			pr.Authors = append(pr.Authors, a)
		}

		if !p.Commits.PageInfo.HasNextPage {
			return pr, nil
		}
		end := p.Commits.PageInfo.EndCursor
		cursor = &end
	}
}

// authorOf picks the account a commit is attributed to: the author's, else
// the committer's, else none. GitHub's own web-flow committer is skipped, so a
// web edit by an unlinked author does not count as GitHub's.
//
// A git name and email are free text, so a linked account always counts as
// that person whatever the name says. A commit by a bot, linked to its App
// account (as renovate's are) or only claiming to be a bot's, is marked Bot
// for Evaluate to judge, never exempted here.
func authorOf(author, committer gitActor) Author {
	if author.User != nil {
		return linkedAuthor(author.User.DatabaseID, author.User.Login)
	}
	if claimsBot(author) {
		return Author{Name: author.Name, Bot: true}
	}
	if committer.User != nil && committer.User.Login != "web-flow" {
		return linkedAuthor(committer.User.DatabaseID, committer.User.Login)
	}
	return Author{Name: author.Name}
}

// linkedAuthor is the account a commit is linked to. Only GitHub App accounts
// have "[bot]" in their login. The link itself comes from the commit's email,
// which anyone can set to a bot's noreply address, so a linked bot is no more
// trusted than one that only claims to be a bot.
func linkedAuthor(id int64, login string) Author {
	return Author{ID: id, Login: login, Bot: strings.HasSuffix(login, "[bot]")}
}

// claimsBot recognises an unlinked commit written as a GitHub App account:
// its name and noreply email are all there is, which anyone can also type.
func claimsBot(a gitActor) bool {
	return strings.HasSuffix(a.Name, "[bot]") ||
		strings.HasSuffix(strings.ToLower(a.Email), "[bot]@users.noreply.github.com")
}
