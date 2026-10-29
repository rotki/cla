// Package fakegh is an in-memory stand-in for the parts of the GitHub API the
// service uses. It exists for tests only.
package fakegh

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
)

// Commit is a commit on a fake pull request.
type Commit struct {
	AuthorName  string
	AuthorEmail string
	AuthorID    int64
	AuthorLogin string
}

// PR is a fake pull request.
type PR struct {
	Open        bool
	HeadSHA     string
	OpenedByBot bool
	Commits     []Commit
}

// Status is a commit status on a fake pull request.
type Status struct {
	Repo, SHA, State, Context, Description, TargetURL string
	// Creator is who set a status the service did not, such as the tool it
	// replaced; empty means the service's App.
	Creator string
}

// Comment is an issue comment.
type Comment struct {
	ID     int64
	Repo   string
	Number int
	Body   string
	Login  string
}

type Server struct {
	*httptest.Server

	Mu     sync.Mutex
	Admins map[string]bool
	Team   []string
	User   struct {
		ID          int64
		Login, Name string
	}
	Emails   []string
	PRs      map[string]PR
	Statuses []Status
	Comments []Comment
	BotLogin string
	CLA      string
	// Requests counts every call; Paths counts them by method and path.
	Requests int
	Paths    map[string]int
	// Revoked counts user tokens revoked through the OAuth app API.
	Revoked int
	// Installed lists the repositories the installation covers; nil means
	// all of them. Like GitHub, statuses on any other repository get a 403.
	Installed []string
	// Private lists the private repositories. Like GitHub, a search with
	// is:public leaves out their pull requests.
	Private []string
}

// repoNames is every repository the fake knows of: those with pull
// requests, plus the private ones.
func (s *Server) repoNames() []string {
	names := slices.Clone(s.Private)
	for key := range s.PRs {
		name, _, _ := strings.Cut(key, "#")
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

func New() *Server {
	s := &Server{
		Admins:   map[string]bool{},
		PRs:      map[string]PR{},
		Paths:    map[string]int{},
		BotLogin: "rotki-cla[bot]",
		CLA:      "# CLA\n\nYou grant us rights.",
	}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	p := r.URL.Path
	parts := strings.Split(strings.Trim(p, "/"), "/")
	s.Requests++
	s.Paths[r.Method+" "+p]++
	switch {
	case r.Method == http.MethodGet && p == "/app":
		writeJSON(w, 200, map[string]string{"slug": strings.TrimSuffix(s.BotLogin, "[bot]")})

	case r.Method == http.MethodGet && strings.HasSuffix(p, "/installation"):
		writeJSON(w, 200, map[string]int64{"id": 42})

	case r.Method == http.MethodPost && strings.HasSuffix(p, "/access_tokens"):
		writeJSON(w, 201, map[string]string{"token": "ghs_installation", "expires_at": "2099-01-01T00:00:00Z"})

	case r.Method == http.MethodDelete && strings.HasPrefix(p, "/applications/") && strings.HasSuffix(p, "/token"):
		s.Revoked++
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodGet && strings.HasPrefix(p, "/orgs/") && strings.Contains(p, "/memberships/"):
		if s.Admins[parts[len(parts)-1]] {
			writeJSON(w, 200, map[string]string{"state": "active", "role": "admin"})
			return
		}
		w.WriteHeader(404)

	case r.Method == http.MethodGet && strings.Contains(p, "/teams/"):
		var members []map[string]string
		for _, m := range s.Team {
			members = append(members, map[string]string{"login": m})
		}
		writeJSON(w, 200, members)

	case r.Method == http.MethodGet && p == "/user":
		writeJSON(w, 200, map[string]any{"id": s.User.ID, "login": s.User.Login, "name": s.User.Name})

	case r.Method == http.MethodGet && p == "/user/emails":
		var emails []map[string]any
		for i, e := range s.Emails {
			emails = append(emails, map[string]any{"email": e, "primary": i == 0, "verified": true})
		}
		emails = append(emails, map[string]any{"email": "unverified@example.com", "verified": false})
		writeJSON(w, 200, emails)

	case r.Method == http.MethodGet && p == "/login/oauth/authorize":
		// Approve straight away, as if the user clicked Authorize.
		q := r.URL.Query()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code=fake&state="+q.Get("state"), http.StatusFound)

	case r.Method == http.MethodPost && p == "/login/oauth/access_token":
		if r.FormValue("code") == "" || r.FormValue("code_verifier") == "" {
			writeJSON(w, 200, map[string]string{"error": "bad_verification_code"})
			return
		}
		writeJSON(w, 200, map[string]string{"access_token": "ghu_user"})

	case r.Method == http.MethodGet && strings.HasPrefix(p, "/gists/"):
		writeJSON(w, 200, map[string]any{"files": map[string]any{"cla.md": map[string]string{"content": s.CLA}}})

	case r.Method == http.MethodPost && p == "/markdown":
		var body struct{ Text string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, "<p>%d chars of markdown</p>", len(body.Text))

	case r.Method == http.MethodGet && p == "/installation/repositories":
		selection, names := "all", s.repoNames()
		if s.Installed != nil {
			selection, names = "selected", s.Installed
		}
		repos := []map[string]any{}
		for _, name := range names {
			repos = append(repos, map[string]any{"name": name, "private": slices.Contains(s.Private, name)})
		}
		writeJSON(w, 200, map[string]any{"total_count": len(repos), "repository_selection": selection, "repositories": repos})

	case r.Method == http.MethodPost && strings.Contains(p, "/statuses/") && s.Installed != nil && !slices.Contains(s.Installed, parts[2]):
		writeJSON(w, 403, map[string]string{"message": "Resource not accessible by integration"})

	case r.Method == http.MethodPost && strings.Contains(p, "/statuses/"):
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		s.Statuses = append(s.Statuses, Status{
			Repo: parts[2], SHA: parts[len(parts)-1], State: body["state"],
			Context: body["context"], Description: body["description"], TargetURL: body["target_url"],
		})
		writeJSON(w, 201, map[string]string{})

	case r.Method == http.MethodPost && p == "/graphql":
		s.graphql(w, r)

	case strings.Contains(p, "/issues/"):
		s.comments(w, r, parts)

	default:
		w.WriteHeader(404)
	}
}

func (s *Server) graphql(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	repo, _ := req.Variables["name"].(string)

	if strings.Contains(req.Query, "search(type: ISSUE") {
		query, _ := req.Variables["query"].(string)
		context, _ := req.Variables["context"].(string)
		var nodes []map[string]any
		for key, pr := range s.PRs {
			repoName, num, _ := strings.Cut(key, "#")
			if !pr.Open || (strings.Contains(query, "repo:") && !strings.Contains(query, "/"+repoName+" ")) ||
				(strings.Contains(query, "is:public") && slices.Contains(s.Private, repoName)) {
				continue
			}
			var n int
			_, _ = fmt.Sscanf(num, "%d", &n)
			var status any
			for i := len(s.Statuses) - 1; i >= 0; i-- {
				st := s.Statuses[i]
				if st.Repo == repoName && st.SHA == pr.HeadSHA && st.Context == context {
					// GraphQL names an App's bot by its slug, without "[bot]".
					creator := cmp.Or(st.Creator, strings.TrimSuffix(s.BotLogin, "[bot]"))
					status = map[string]any{"context": map[string]any{
						"state": strings.ToUpper(st.State), "description": st.Description,
						"creator": map[string]string{"login": creator},
					}}
					break
				}
			}
			nodes = append(nodes, map[string]any{
				"number": n, "headRefOid": pr.HeadSHA,
				"repository": map[string]string{"name": repoName},
				"commits":    map[string]any{"nodes": []any{map[string]any{"commit": map[string]any{"status": status}}}},
			})
		}
		writeJSON(w, 200, map[string]any{"data": map[string]any{"search": map[string]any{
			"issueCount": len(nodes), "pageInfo": map[string]any{"hasNextPage": false}, "nodes": nodes,
		}}})
		return
	}

	number := int(req.Variables["number"].(float64))
	pr, ok := s.PRs[fmt.Sprintf("%s#%d", repo, number)]
	if !ok {
		writeJSON(w, 200, map[string]any{"data": map[string]any{"repository": map[string]any{"pullRequest": nil}}})
		return
	}
	state := "CLOSED"
	if pr.Open {
		state = "OPEN"
	}
	var nodes []any
	for _, c := range pr.Commits {
		author := map[string]any{"name": c.AuthorName, "email": c.AuthorEmail, "user": nil}
		if c.AuthorID > 0 {
			author["user"] = map[string]any{"databaseId": c.AuthorID, "login": c.AuthorLogin}
		}
		nodes = append(nodes, map[string]any{"commit": map[string]any{
			"author":    author,
			"committer": map[string]any{"name": "GitHub", "user": map[string]any{"databaseId": 19864447, "login": "web-flow"}},
		}})
	}
	writeJSON(w, 200, map[string]any{"data": map[string]any{"repository": map[string]any{"pullRequest": map[string]any{
		"state": state, "headRefOid": pr.HeadSHA, "author": map[string]string{"__typename": opener(pr)},
		"commits": map[string]any{"pageInfo": map[string]any{"hasNextPage": false}, "nodes": nodes},
	}}}})
}

func opener(pr PR) string {
	if pr.OpenedByBot {
		return "Bot"
	}
	return "User"
}

func (s *Server) comments(w http.ResponseWriter, r *http.Request, parts []string) {
	repo := parts[2]
	switch r.Method {
	case http.MethodGet:
		var number int
		_, _ = fmt.Sscanf(parts[4], "%d", &number)
		var out []map[string]any
		for _, c := range s.Comments {
			if c.Repo == repo && c.Number == number {
				out = append(out, map[string]any{"id": c.ID, "body": c.Body, "user": map[string]string{"login": c.Login}})
			}
		}
		writeJSON(w, 200, out)
	case http.MethodPost:
		var number int
		_, _ = fmt.Sscanf(parts[4], "%d", &number)
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		id := int64(len(s.Comments) + 1)
		s.Comments = append(s.Comments, Comment{ID: id, Repo: repo, Number: number, Body: body["body"], Login: s.BotLogin})
		writeJSON(w, 201, map[string]any{"id": id})
	case http.MethodPatch:
		var id int64
		_, _ = fmt.Sscanf(parts[len(parts)-1], "%d", &id)
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		for i := range s.Comments {
			if s.Comments[i].ID == id {
				s.Comments[i].Body = body["body"]
				writeJSON(w, 200, map[string]any{})
				return
			}
		}
		w.WriteHeader(404)
	default:
		w.WriteHeader(405)
	}
}
