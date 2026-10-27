// cla-tool holds the one-off maintenance commands:
//
//	cla-tool seed     build grandfathered.json from the org's history
//	cla-tool import   turn a cla-assistant export into signature records
//	cla-tool verify   check every record and the audit log, optionally decrypting them
//	cla-tool rekey    re-encrypt every record to a new key
//	cla-tool backup   verify the data directory and archive it
//	cla-tool decrypt  open the sealed personal data of one record
//
// The commands that change records take the service's lock and log each
// change, so they can run while the service does, e.g. through
// docker compose exec.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"

	"github.com/rotki/cla/internal/config"
	"github.com/rotki/cla/internal/githubapp"
	"github.com/rotki/cla/internal/records"
	"github.com/rotki/cla/internal/seal"
	"github.com/rotki/cla/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "seed":
		err = seed(os.Args[2:])
	case "import":
		err = importExport(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	case "rekey":
		err = rekey(os.Args[2:])
	case "backup":
		err = backup(os.Args[2:])
	case "decrypt":
		err = decrypt(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: cla-tool seed|import|verify|rekey|backup|decrypt [flags]")
	os.Exit(2)
}

// seed lists everyone who authored a commit on a default branch or opened a
// pull request in any repo of the org. They are treated as having signed.
func seed(args []string) error {
	fs := flag.NewFlagSet("seed", flag.ExitOnError)
	org := fs.String("org", "", "GitHub organization (required)")
	out := fs.String("o", "grandfathered.json", "output file")
	merge := fs.String("merge", "", "existing grandfathered.json to merge with")
	includeForks := fs.Bool("include-forks", false, "include forked repos (their history is mostly upstream authors)")
	apiURL := fs.String("api", "https://api.github.com", "GitHub API URL")
	_ = fs.Parse(args)

	if *org == "" {
		return errors.New("-org is required")
	}
	token, err := config.Secret("GITHUB_TOKEN")
	if err != nil {
		return err
	}
	if token == "" {
		return errors.New("GITHUB_TOKEN or GITHUB_TOKEN_FILE is required (an org owner's token, e.g. from `gh auth token`)")
	}
	ctx := context.Background()
	c := githubapp.NewClient(*apiURL, token)

	ids := map[int64]bool{}
	if *merge != "" {
		data, err := os.ReadFile(*merge)
		if err != nil {
			return err
		}
		var existing []int64
		if err := json.Unmarshal(data, &existing); err != nil {
			return err
		}
		for _, id := range existing {
			ids[id] = true
		}
	}

	type account struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Type  string `json:"type"`
	}
	add := func(a account) {
		if a.ID > 0 && a.Type != "Bot" && !strings.HasSuffix(a.Login, "[bot]") {
			ids[a.ID] = true
		}
	}

	var repos []string
	err = githubapp.Paginate(ctx, c, "/orgs/"+*org+"/repos?type=all&per_page=100", func(page []struct {
		Name string `json:"name"`
		Fork bool   `json:"fork"`
	}) error {
		for _, r := range page {
			if !r.Fork || *includeForks {
				repos = append(repos, r.Name)
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("listing repos: %w", err)
	}

	for _, repo := range repos {
		contributors := 0
		err := githubapp.Paginate(ctx, c, fmt.Sprintf("/repos/%s/%s/contributors?per_page=100", *org, repo), func(page []account) error {
			contributors += len(page)
			for _, a := range page {
				add(a)
			}
			return nil
		})
		if err != nil && !githubapp.IsStatus(err, 404) {
			return fmt.Errorf("%s contributors: %w", repo, err)
		}
		if contributors >= 500 {
			fmt.Fprintf(os.Stderr, "warning: %s has %d contributors; GitHub only links the first 500 author emails, check its PR authors cover the rest\n", repo, contributors)
		}

		prs := 0
		err = githubapp.Paginate(ctx, c, fmt.Sprintf("/repos/%s/%s/pulls?state=all&per_page=100", *org, repo), func(page []struct {
			User account `json:"user"`
		}) error {
			prs += len(page)
			for _, p := range page {
				add(p.User)
			}
			return nil
		})
		if err != nil && !githubapp.IsStatus(err, 404) {
			return fmt.Errorf("%s pull requests: %w", repo, err)
		}
		fmt.Fprintf(os.Stderr, "%-40s %5d contributors %6d pull requests\n", repo, contributors, prs)
	}

	list := make([]int64, 0, len(ids))
	for id := range ids {
		list = append(list, id)
	}
	sort.Slice(list, func(i, j int) bool { return list[i] < list[j] })
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%d accounts across %d repos\n", len(list), len(repos))
	return writeNew(*out, append(data, '\n'))
}

// writeNew writes path through a temporary file created fresh next to it
// and a rename. The rename replaces whatever is at path, a symlink included,
// instead of writing through it: run as root against a data directory, a
// link planted there cannot send the output to another file on the host.
func writeNew(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// importExport writes signatures/<id>.json for every signer in a
// cla-assistant export, sealing their name and email like the service does.
func importExport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	export := fs.String("export", "", "cla-assistant export (JSON array)")
	recipient := fs.String("recipient", "", "age public key (age1...)")
	keyID := fs.String("key-id", "", "key ID stored with each record")
	dir := fs.String("dir", ".", "the data directory")
	_ = fs.Parse(args)
	if *export == "" || *recipient == "" || *keyID == "" {
		return errors.New("-export, -recipient and -key-id are required")
	}
	sealer, err := seal.New(*recipient, *keyID)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*export)
	if err != nil {
		return err
	}
	if err := runAsOwner(*dir); err != nil {
		return err
	}
	res, err := records.Import(data, *dir, sealer)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%d records written, %d already present, %d entries skipped (revoked or without an account ID)\n", res.Written, res.Existing, res.Skipped)
	fmt.Fprintln(os.Stderr, "Run `cla-tool verify` on the data directory, then delete the export: it holds names and emails in plain text.")
	return nil
}

// runAsOwner switches a cla-tool run as root to the owner of the data
// directory before it touches it: the commands then read and write only
// what the service user may, so a symlink that user planted there cannot
// make root overwrite or archive a file elsewhere on the host, and every
// file created belongs to the service. Anything that needs root, such as
// reading a private key or an export, is done before this. Run as anyone
// else, it does nothing.
func runAsOwner(dir string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("the data directory must exist, owned by the service user: %w", err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid == 0 || st.Gid == 0 {
		return errors.New("the data directory is owned by root or the root group; it must belong to the service user and its group (65532:65532 in the image)")
	}
	if err := syscall.Setgroups(nil); err != nil {
		return err
	}
	if err := syscall.Setgid(int(st.Gid)); err != nil {
		return err
	}
	return syscall.Setuid(int(st.Uid))
}

// identityFiles collects repeated -identity flags.
type identityFiles []string

func (f *identityFiles) String() string     { return strings.Join(*f, ",") }
func (f *identityFiles) Set(v string) error { *f = append(*f, v); return nil }

func loadIdentities(paths []string) ([]age.Identity, error) {
	var all []age.Identity
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		ids, err := age.ParseIdentities(f)
		_ = f.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		all = append(all, ids...)
	}
	return all, nil
}

// verify checks the data directory and its audit log. With -identity it
// also decrypts every record; it never prints what it decrypts. With -anchor
// it checks the log against a head published earlier.
func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	dir := fs.String("dir", ".", "the data directory")
	anchor := fs.String("anchor", "", "a published audit anchor, <seq>:<hash>, to check the log against")
	var keys identityFiles
	fs.Var(&keys, "identity", "age identity file; repeat for several keys (optional: without it only the structure is checked)")
	_ = fs.Parse(args)

	identities, err := loadIdentities(keys)
	if err != nil {
		return err
	}
	if err := runAsOwner(*dir); err != nil {
		return err
	}
	report, err := records.Verify(*dir, identities)
	if err != nil {
		return err
	}
	fmt.Printf("%d records, %d grandfathered accounts\n", report.Records, report.Grandfathered)
	fmt.Printf("audit log: %d events, head %s\n", report.Events, report.Head)
	if *anchor != "" {
		seq, hash, ok := strings.Cut(*anchor, ":")
		n, err := strconv.ParseInt(seq, 10, 64)
		if !ok || err != nil {
			return errors.New("-anchor must be <seq>:<hash>")
		}
		if err := records.CheckAnchor(*dir, n, hash); err != nil {
			report.Problems = append(report.Problems, records.Problem{Path: store.AuditLog, Reason: err.Error()})
		} else {
			fmt.Printf("the log matches the anchor at event %d\n", n)
		}
	}
	keyIDs := make([]string, 0, len(report.ByKey))
	for k := range report.ByKey {
		keyIDs = append(keyIDs, k)
	}
	sort.Strings(keyIDs)
	for _, k := range keyIDs {
		fmt.Printf("  key %q: %d records\n", k, report.ByKey[k])
	}
	if len(identities) > 0 {
		fmt.Printf("%d decrypted\n", report.Decrypted)
	} else {
		fmt.Println("decryption not checked (no -identity given)")
	}
	for _, p := range report.Problems {
		fmt.Println("problem:", p)
	}
	if !report.OK() {
		return fmt.Errorf("%d problems", len(report.Problems))
	}
	fmt.Println("all records are valid")
	return nil
}

// rekey re-encrypts every record to a new key. See records.Rekey.
func rekey(args []string) error {
	fs := flag.NewFlagSet("rekey", flag.ExitOnError)
	dir := fs.String("dir", ".", "the data directory")
	recipient := fs.String("recipient", "", "the new age public key (age1...)")
	keyID := fs.String("key-id", "", "the new key ID")
	dryRun := fs.Bool("dry-run", false, "count what would change, write nothing")
	var keys identityFiles
	fs.Var(&keys, "identity", "the old age identity file; repeat for several keys")
	_ = fs.Parse(args)
	if *recipient == "" || *keyID == "" || len(keys) == 0 {
		return errors.New("-recipient, -key-id and at least one -identity (the old key) are required")
	}

	identities, err := loadIdentities(keys)
	if err != nil {
		return err
	}
	sealer, err := seal.New(*recipient, *keyID)
	if err != nil {
		return err
	}
	if err := runAsOwner(*dir); err != nil {
		return err
	}
	changed, err := records.Rekey(*dir, identities, sealer, *dryRun)
	if err != nil {
		return err
	}
	if *dryRun {
		fmt.Printf("%d records would be re-encrypted to key %q\n", changed, *keyID)
		return nil
	}
	fmt.Printf("%d records re-encrypted to key %q\n", changed, *keyID)
	fmt.Println("Next: cla-tool verify -identity <new key> to check them, then destroy the old key once every backup made before the rotation is gone (see docs/operations.md).")
	return nil
}

// backup verifies the data directory and archives it, like the service's
// scheduled backup. It prints the manifest and fails when verification
// found problems; the archive is written either way. See records.Backup.
func backup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	dir := fs.String("dir", ".", "the data directory")
	out := fs.String("o", "", "the directory to write the archive to (required, outside -dir)")
	keep := fs.Int("keep", 0, "keep only the newest N archives in -o (0 keeps all)")
	_ = fs.Parse(args)
	if *out == "" {
		return errors.New("-o is required")
	}
	if err := runAsOwner(*dir); err != nil {
		return err
	}
	m, err := records.Backup(*dir, *out, time.Now(), *keep)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		return err
	}
	if !m.OK {
		return fmt.Errorf("%d problems; archived as %s anyway, run cla-tool verify for details", m.Problems, m.Archive)
	}
	return nil
}

// decrypt prints the sealed name and email of one record. It needs the
// offline age identity.
func decrypt(args []string) error {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	var keys identityFiles
	fs.Var(&keys, "identity", "age identity file; repeat for several keys")
	_ = fs.Parse(args)
	if len(keys) == 0 || fs.NArg() != 1 {
		return errors.New("usage: cla-tool decrypt -identity key.txt signatures/<id>.json")
	}
	identities, err := loadIdentities(keys)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	var rec store.Record
	if err := json.Unmarshal(data, &rec); err != nil {
		return err
	}
	p, err := seal.Open(rec.PII, identities...)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(p)
}
