package togoalone

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
)

// Signer Struct for signing data with a secret.
type Signer struct {
	hash  hash.Hash
	dirty bool
}

// New Return a new Signer.
func New(secret []byte) Signer {
	return Signer{
		hash: hmac.New(sha256.New, secret),
	}
}

// Sign Signs data with secret and returns []byte.
func (s *Signer) Sign(data []byte) []byte {
	// Reset if reused
	if s.dirty {
		s.hash.Reset()
	}

	// Write data to hasher and set dirty.
	s.hash.Write(data)
	s.dirty = true

	// Make result into bytestring.
	// The result will be `data.hash`.
	t := make([]byte, 0, len(data)+33)
	t = append(t, data...)
	t = append(t, '.')
	t = s.hash.Sum(t)

	// Return the result.
	return t
}

// Verify validates a token and returns a bool
func (s Signer) Verify(token []byte) bool {

	tl := len(token)

	// A token must be at least 34 bytes long to be valid.
	if tl < 34 {
		return false
	}

	nt := s.Sign(token[0 : tl-33])

	for i := tl - 32; i < tl; i++ {
		if token[i] != nt[i] {
			return false
		}
	}

	return true
}
