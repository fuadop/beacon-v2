package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func testKey(t *testing.T) *Key {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	k, err := NewKey(hex.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	k := testKey(t)
	plaintext := "public-v2c-community-string"

	ciphertext, err := k.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if ciphertext == plaintext {
		t.Fatal("ciphertext must not equal plaintext")
	}

	got, err := k.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got != plaintext {
		t.Fatalf("got %q, want %q", got, plaintext)
	}
}

func TestEncryptEmptyStringRoundTripsToEmpty(t *testing.T) {
	k := testKey(t)
	ciphertext, err := k.Encrypt("")
	if err != nil {
		t.Fatal(err)
	}
	if ciphertext != "" {
		t.Fatalf("expected empty ciphertext for empty plaintext, got %q", ciphertext)
	}
	got, err := k.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Fatalf("expected empty plaintext, got %q", got)
	}
}

func TestDecryptWithWrongKeyFails(t *testing.T) {
	k1 := testKey(t)
	k2 := testKey(t)

	ciphertext, err := k1.Encrypt("secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k2.Decrypt(ciphertext); err == nil {
		t.Fatal("expected decryption with wrong key to fail")
	}
}

func TestNewKeyRejectsBadInput(t *testing.T) {
	cases := []string{"", "not-hex!!", "abcd", hex.EncodeToString(make([]byte, 16))}
	for _, c := range cases {
		if _, err := NewKey(c); err == nil {
			t.Errorf("NewKey(%q) expected error, got nil", c)
		}
	}
}
