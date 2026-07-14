// Package crypto provides AES-256-GCM encryption for credential fields at rest.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

var ErrEmptyKey = errors.New("crypto: encryption key is empty")

// Key holds a ready-to-use AES-256-GCM cipher derived from a 32-byte key.
type Key struct {
	gcm cipher.AEAD
}

// NewKey builds a Key from a hex-encoded 32-byte (64 hex char) secret,
// typically sourced from the ENCRYPTION_KEY environment variable.
func NewKey(hexKey string) (*Key, error) {
	if hexKey == "" {
		return nil, ErrEmptyKey
	}
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: decoding hex key: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("crypto: key must be 32 bytes (64 hex chars), got %d bytes", len(raw))
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, fmt.Errorf("crypto: creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: creating GCM: %w", err)
	}
	return &Key{gcm: gcm}, nil
}

// Encrypt returns base64(nonce || ciphertext || tag). Empty plaintext encrypts to an empty string
// so optional credential fields (e.g. unused v3 keys) round-trip as empty rather than as ciphertext noise.
func (k *Key) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	nonce := make([]byte, k.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("crypto: generating nonce: %w", err)
	}
	sealed := k.gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt reverses Encrypt. An empty input decrypts to an empty string.
func (k *Key) Decrypt(encoded string) (string, error) {
	if encoded == "" {
		return "", nil
	}
	sealed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("crypto: decoding base64: %w", err)
	}
	nonceSize := k.gcm.NonceSize()
	if len(sealed) < nonceSize {
		return "", errors.New("crypto: ciphertext too short")
	}
	nonce, ciphertext := sealed[:nonceSize], sealed[nonceSize:]
	plaintext, err := k.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("crypto: decrypting: %w", err)
	}
	return string(plaintext), nil
}
