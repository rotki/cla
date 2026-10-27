// Package seal encrypts the personal part of a signature record.
//
// The service only holds the age public key, so it can seal but never open a
// record. The private key lives offline and is used for disputes and data
// access requests only.
package seal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// Personal is the data that must never be stored in plain text.
type Personal struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type Sealer struct {
	recipient age.Recipient
	keyID     string
}

func New(recipient, keyID string) (*Sealer, error) {
	r, err := age.ParseX25519Recipient(recipient)
	if err != nil {
		return nil, fmt.Errorf("parsing age recipient: %w", err)
	}
	return &Sealer{recipient: r, keyID: keyID}, nil
}

// KeyID names the key pair, so records sealed before a key rotation can be
// told apart.
func (s *Sealer) KeyID() string {
	return s.keyID
}

// Seal returns the armored age ciphertext of p.
func (s *Sealer) Seal(p Personal) (string, error) {
	plain, err := json.Marshal(p)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	armored := armor.NewWriter(&buf)
	w, err := age.Encrypt(armored, s.recipient)
	if err != nil {
		return "", err
	}
	if _, err := w.Write(plain); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	if err := armored.Close(); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// Open decrypts a sealed block with whichever of the identities it was
// sealed to. Only the offline tooling has identities.
func Open(sealed string, identities ...age.Identity) (Personal, error) {
	var p Personal
	r, err := age.Decrypt(armor.NewReader(bytes.NewReader([]byte(sealed))), identities...)
	if err != nil {
		return p, err
	}
	plain, err := io.ReadAll(r)
	if err != nil {
		return p, err
	}
	err = json.Unmarshal(plain, &p)
	return p, err
}
