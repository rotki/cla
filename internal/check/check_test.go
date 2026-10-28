package check

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rotki/cla/internal/store"
)

func user(id int64, login string) *struct {
	DatabaseID int64  `json:"databaseId"`
	Login      string `json:"login"`
} {
	return &struct {
		DatabaseID int64  `json:"databaseId"`
		Login      string `json:"login"`
	}{id, login}
}

func TestAuthorOf(t *testing.T) {
	cases := []struct {
		name              string
		author, committer gitActor
		want              Author
	}{
		{
			name:   "linked author",
			author: gitActor{Name: "A", User: user(1, "alice")},
			want:   Author{ID: 1, Login: "alice"},
		},
		{
			name:      "unlinked author falls back to the committer",
			author:    gitActor{Name: "A", Email: "a@laptop.local"},
			committer: gitActor{Name: "Bob", User: user(2, "bob")},
			want:      Author{ID: 2, Login: "bob"},
		},
		{
			name:      "web-flow is not a fallback",
			author:    gitActor{Name: "A", Email: "a@laptop.local"},
			committer: gitActor{Name: "GitHub", User: user(19864447, "web-flow")},
			want:      Author{Name: "A"},
		},
		{
			name:   "claims to be a bot by noreply email",
			author: gitActor{Name: "dependabot", Email: "49699333+dependabot[bot]@users.noreply.github.com"},
			want:   Author{Name: "dependabot", Bot: true},
		},
		{
			name:   "claims to be a bot by name",
			author: gitActor{Name: "renovate[bot]"},
			want:   Author{Name: "renovate[bot]", Bot: true},
		},
		{
			name:   "a linked account is that person, whatever the name says",
			author: gitActor{Name: "alice[bot]", Email: "alice@example.com", User: user(7, "alice")},
			want:   Author{ID: 7, Login: "alice"},
		},
		{
			// How renovate's commits arrive: linked to its App account.
			name:   "linked to a bot account",
			author: gitActor{Name: "renovate[bot]", Email: "29139614+renovate[bot]@users.noreply.github.com", User: user(29139614, "renovate[bot]")},
			want:   Author{ID: 29139614, Login: "renovate[bot]", Bot: true},
		},
		{
			// The commit is the person's; a bot only committed it.
			name:      "a bot committer is not a fallback",
			author:    gitActor{Name: "A", Email: "a@laptop.local"},
			committer: gitActor{Name: "x", User: user(9, "pre-commit-ci[bot]")},
			want:      Author{Name: "A"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := authorOf(tc.author, tc.committer); got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestEvaluate(t *testing.T) {
	standing := map[int64]store.Standing{
		1: store.Signed,
		2: store.GrandfatheredIn,
		3: store.Pending,
	}
	authors := []Author{
		{ID: 1, Login: "signed"},
		{ID: 2, Login: "old"},
		{ID: 3, Login: "employee"},
		{ID: 4, Login: "new"},
		{ID: 5, Login: "Maintainer"},
		{ID: 6, Login: "listed"},
		{Login: "dependabot", Bot: true},
		{Name: "Laptop User"},
	}
	rules := NewRules([]string{"LISTED"}, map[string]bool{"maintainer": true}, true)
	res := Evaluate(authors, rules, func(id int64) store.Standing { return standing[id] })

	if len(res.Signed) != 2 || len(res.Pending) != 1 || len(res.Unsigned) != 1 || len(res.Unlinked) != 1 {
		t.Fatalf("unexpected result %+v", res)
	}
	if res.Total() != 5 {
		t.Fatalf("exempt authors must not count, total %d", res.Total())
	}
	if res.OK() {
		t.Fatal("result with unsigned authors is OK")
	}
	if got := res.Blocking(); len(got) != 2 || got[0] != 4 || got[1] != 3 {
		t.Fatalf("blocking %v", got)
	}
}

func TestBotCommitsNeedABotOpener(t *testing.T) {
	bot := []Author{{Name: "renovate[bot]", Bot: true}}
	none := func(int64) store.Standing { return store.NotSigned }

	// A bot-opened pull request: its bot commits need no signature.
	if res := Evaluate(bot, NewRules(nil, nil, true), none); !res.OK() || res.Total() != 0 {
		t.Fatalf("bot PR: %+v", res)
	}
	// A person's pull request: anyone can name a commit "x[bot]", so it is
	// an unlinked commit like any other and blocks the merge.
	if res := Evaluate(bot, NewRules(nil, nil, false), none); res.OK() || len(res.Unlinked) != 1 {
		t.Fatalf("human PR: %+v", res)
	}

	// Commits linked to an App account, as renovate's are. Linking goes by
	// email, which anyone can set, so the same rule holds.
	linked := []Author{{ID: 29139614, Login: "renovate[bot]", Bot: true}}
	if res := Evaluate(linked, NewRules(nil, nil, true), none); !res.OK() || res.Total() != 0 {
		t.Fatalf("bot PR, linked bot: %+v", res)
	}
	// In a person's pull request it waits for a maintainer, not a signature.
	res := Evaluate(linked, NewRules(nil, nil, false), none)
	if res.OK() || len(res.Bots) != 1 || len(res.Unsigned) != 0 || len(res.Blocking()) != 0 {
		t.Fatalf("human PR, linked bot: %+v", res)
	}
	if s := StatusFor(res); s.State != "pending" || !strings.Contains(s.Description, "maintainer") {
		t.Fatalf("status %+v", s)
	}
	// An allowlisted bot account passes there too; a name alone does not.
	if res := Evaluate(linked, NewRules([]string{"Renovate[bot]"}, nil, false), none); !res.OK() {
		t.Fatalf("human PR, allowlisted bot: %+v", res)
	}
	if res := Evaluate(bot, NewRules([]string{"renovate[bot]"}, nil, false), none); res.OK() {
		t.Fatalf("human PR, unlinked bot name on the allowlist: %+v", res)
	}
}

func TestStatusFor(t *testing.T) {
	signed := Author{ID: 1, Login: "a"}
	cases := []struct {
		res   Result
		state string
		desc  string
	}{
		{Result{}, "success", "No commit authors"},
		{Result{Signed: []Author{signed}}, "success", "All commit authors"},
		{Result{Pending: []Author{signed}}, "pending", "employer signature"},
		{Result{Signed: []Author{signed}, Unsigned: []Author{{ID: 2}}}, "pending", "1 of 2"},
		{Result{Unlinked: []Author{{Name: "x"}}}, "pending", "0 of 1"},
	}
	for _, tc := range cases {
		s := StatusFor(tc.res)
		if s.State != tc.state || !strings.Contains(s.Description, tc.desc) {
			t.Errorf("StatusFor(%+v) = %+v", tc.res, s)
		}
		if len(s.Description) > 140 {
			t.Errorf("description over GitHub's 140 characters: %q", s.Description)
		}
	}
}

func TestComment(t *testing.T) {
	res := Result{
		Signed:   []Author{{ID: 1, Login: "alice"}},
		Pending:  []Author{{ID: 3, Login: "carol"}},
		Unsigned: []Author{{ID: 2, Login: "bob"}},
		Unlinked: []Author{{Name: "Eve *bold* @everyone"}},
	}
	body, needed := Comment(res, "https://cla.rotki.com/sign?x", "https://cla.rotki.com/cla")
	if !needed || !strings.HasPrefix(body, Marker) {
		t.Fatalf("needed=%v body=%q", needed, body)
	}
	for _, want := range []string{"- [x] [alice](https://github.com/alice)", "- [ ] [bob](https://github.com/bob)", "[carol](https://github.com/carol) (employer", "**1** of **4**", "(https://cla.rotki.com/sign?x)"} {
		if !strings.Contains(body, want) {
			t.Errorf("comment lacks %q:\n%s", want, body)
		}
	}
	bots, _ := Comment(Result{Bots: []Author{{ID: 9, Login: "pre-commit-ci[bot]", Bot: true}}}, "SIGN", "c")
	if !strings.Contains(bots, "[pre-commit-ci[bot]](https://github.com/apps/pre-commit-ci) (a bot account") || strings.Contains(bots, "SIGN") {
		t.Errorf("bot line:\n%s", bots)
	}
	// Outside the inline-code git name, nothing may mention anyone.
	if strings.Contains(strings.ReplaceAll(body, "`Eve *bold* @everyone`", ""), "@") {
		t.Errorf("comment mentions someone:\n%s", body)
	}
	if !strings.Contains(body, "`Eve *bold* @everyone`") {
		t.Errorf("git author name not shown as inline code:\n%s", body)
	}

	done, needed := Comment(Result{Signed: []Author{{ID: 1, Login: "alice"}}}, "s", "c")
	if needed || !strings.Contains(done, "All commit authors have signed") {
		t.Fatalf("needed=%v body=%q", needed, done)
	}

	onlyPending, _ := Comment(Result{Pending: []Author{{ID: 3, Login: "carol"}}}, "SIGN", "c")
	if strings.Contains(onlyPending, "SIGN") {
		t.Error("sign link shown when nobody needs to sign")
	}
}

func TestBlockingIndex(t *testing.T) {
	c := &Checker{blocked: map[int64]map[Ref]bool{}, blocks: map[Ref][]int64{}, comments: map[Ref]comment{}}
	a := Ref{Repo: "rotki", Number: 1}
	b := Ref{Repo: "docs", Number: 2}

	c.setBlocking(a, []int64{10, 11})
	c.setBlocking(b, []int64{10})
	if got := c.BlockedBy(10); len(got) != 2 {
		t.Fatalf("BlockedBy(10) = %v", got)
	}

	c.setBlocking(a, []int64{11})
	if got := c.BlockedBy(10); len(got) != 1 || got[0] != b {
		t.Fatalf("after re-check BlockedBy(10) = %v", got)
	}

	c.setBlocking(b, nil)
	if got := c.BlockedBy(10); len(got) != 0 {
		t.Fatalf("settled PR still blocked: %v", got)
	}
	if len(c.blocked) != 1 {
		t.Fatalf("index keeps empty entries: %v", c.blocked)
	}
}

func TestBackoffDoubles(t *testing.T) {
	want := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute, 32 * time.Minute, time.Hour, time.Hour}
	for i, w := range want {
		if got := backoff(i + 1); got != w {
			t.Errorf("backoff(%d) = %v, want %v", i+1, got, w)
		}
	}
}

func TestCommentNeutralisesNamesAndStaysSmall(t *testing.T) {
	var res Result
	res.Unlinked = append(res.Unlinked, Author{Name: "Sign at https://evil.example `x` [click](https://evil.example)"})
	for i := range 500 {
		res.Unsigned = append(res.Unsigned, Author{ID: int64(i + 1), Login: fmt.Sprintf("user%d", i)})
		res.Unlinked = append(res.Unlinked, Author{Name: strings.Repeat("n", 500) + fmt.Sprint(i)})
	}
	body, _ := Comment(res, "s", "c")
	if strings.Contains(body, "`x`") || !strings.Contains(body, "`Sign at https://evil.example x [click](https://evil.example)`") {
		t.Errorf("name not confined to one code span:\n%.400s", body)
	}
	if !strings.Contains(body, "- and 450 more") || !strings.Contains(body, " and 481 more") {
		t.Errorf("lists not capped:\n%.200s", body[len(body)-400:])
	}
	if len(body) > 20000 {
		t.Fatalf("comment is %d characters", len(body))
	}
}

func TestJobsForPeopleGoFirst(t *testing.T) {
	q := NewQueue(nil, nil, nil, 10)
	a, b, c := Ref{Repo: "r", Number: 1}, Ref{Repo: "r", Number: 2}, Ref{Repo: "r", Number: 3}
	q.Enqueue(Job{Ref: a, Background: true})
	q.Enqueue(Job{Ref: b, Bulk: true})
	q.Enqueue(Job{Ref: c})
	if len(q.people) != 1 || len(q.jobs) != 2 {
		t.Fatalf("people %d, background %d", len(q.people), len(q.jobs))
	}

	// A signing for a pull request already waiting as background work
	// jumps the queue; the background copy is then skipped.
	q.Enqueue(Job{Ref: a})
	if len(q.people) != 2 || !q.superseded[a] {
		t.Fatalf("not promoted: people %d, superseded %v", len(q.people), q.superseded)
	}
	q.Enqueue(Job{Ref: a, Background: true})
	if len(q.jobs) != 2 {
		t.Fatal("a background job was queued behind a waiting job for people")
	}
	q.handle(context.Background(), <-q.jobs) // a's background copy: skipped, no checker needed
	if q.superseded[a] {
		t.Fatal("the skipped copy left its mark")
	}
}

func TestMergeKeepsTheHighestPriority(t *testing.T) {
	cases := []struct {
		a, b               Job
		people, background bool
	}{
		{Job{Background: true}, Job{}, true, false},
		{Job{Bulk: true}, Job{}, true, false},
		{Job{Background: true}, Job{Bulk: true}, false, false},
		{Job{Background: true}, Job{Background: true}, false, true},
	}
	for _, tc := range cases {
		m := tc.a.merge(tc.b)
		if m.forPeople() != tc.people || m.Background != tc.background {
			t.Errorf("%+v merged with %+v gave %+v", tc.a, tc.b, m)
		}
	}
}

func TestOnlySigningsUseTheReserve(t *testing.T) {
	if (Job{}).Signed || !(Job{Signed: true}).merge(Job{}).Signed {
		t.Fatal("Signed is not kept through a merge")
	}
}

func TestStoppingDropsWaitingJobs(t *testing.T) {
	q := NewQueue(nil, nil, nil, 10)
	q.Enqueue(Job{Ref: Ref{Repo: "r", Number: 1}, Background: true})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() { q.Run(ctx, 2); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("a stopped queue kept running")
	}
	if len(q.jobs) != 1 {
		t.Fatal("a stopped queue started a waiting job")
	}
}
