package seal

import (
	"strings"
	"testing"

	"filippo.io/age"
)

func TestSealRoundTrip(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(id.Recipient().String(), "test-key")
	if err != nil {
		t.Fatal(err)
	}

	in := Personal{Name: "Jane Doe", Email: "jane@example.com"}
	sealed, err := s.Seal(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sealed, "-----BEGIN AGE ENCRYPTED FILE-----") {
		t.Fatalf("not armored: %q", sealed[:40])
	}
	if strings.Contains(sealed, "jane") || strings.Contains(sealed, "Jane") {
		t.Fatal("sealed block contains plain text")
	}

	out, err := Open(sealed, id)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("got %+v, want %+v", out, in)
	}

	other, _ := age.GenerateX25519Identity()
	if _, err := Open(sealed, other); err == nil {
		t.Fatal("a different identity opened the record")
	}
}

func TestNewRejectsBadRecipient(t *testing.T) {
	if _, err := New("not-a-key", "k"); err == nil {
		t.Fatal("want error")
	}
}
