package goalone

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"errors"
	"hash"
	"sync"
)

// Sword is a Wooden Sword to be used for protection, because it's dangerous out
// there... Also, it is the main struct used to sign and unsign data using this
// package.
//
// TODO: You may create it manually or use the New() function.
type Sword struct {
	sync.Mutex
	hash  hash.Hash // Will need to expose a way to set this..
	dirty bool      // Tracks if the hash is dirty
}

// ErrInvalidSignature is returned by Unsign when the provided token's
// signatuire is not valid.
var ErrInvalidSignature = errors.New("invalid signature")

// ErrShortToken is returned by Unsign when the provided token's length
// is too short to be a vlaid token.
var ErrShortToken = errors.New("token is too small to be valid")

// New takes a key and returns a new Sword struct using default values.
//
// TODO: You can customize many options by manually creating the Sword struct or
// altering the struct returned by this function. If you pass nil as the key
// then this function will return an empty Sword struct.
func New(key []byte) *Sword {

	if key == nil {
		return &Sword{}
	}

	return &Sword{
		hash: hmac.New(sha1.New, key),
	}
}

// Sign signs data and returns []byte in the format `data.signature`.
func (s *Sword) Sign(data []byte) []byte {

	s.Lock()

	// Reset if reused
	if s.dirty {
		s.hash.Reset()
	}

	// Write data to hasher and set dirty.
	s.hash.Write(data)
	s.dirty = true

	// The result will be `data.hash`.
	t := make([]byte, 0, len(data)+s.hash.Size()+1)
	t = append(t, data...)
	t = append(t, '.')
	t = s.hash.Sum(t)
	s.Unlock()

	// Return the result.
	return t
}

// Unsign validates a signature and if successful returns the data portion of
// the []byte. If unsuccessful it will return an error and nil for the data.
func (s *Sword) Unsign(token []byte) ([]byte, error) {

	tl := len(token)

	// A token must be at least hash.Size+2 bytes long to be valid.
	if tl < s.hash.Size()+2 {
		return nil, ErrShortToken
	}

	s.Lock()

	// Reset if reused
	if s.dirty {
		s.hash.Reset()
	}

	// Write data to hasher and set dirty.
	s.hash.Write(token[0 : tl-(s.hash.Size()+1)])
	s.dirty = true

	h := make([]byte, 0, s.hash.Size())
	h = s.hash.Sum(h)
	s.Unlock()

	if subtle.ConstantTimeCompare(token[tl-s.hash.Size():], h) != 1 {
		return nil, ErrInvalidSignature
	}

	return token[0 : tl-(s.hash.Size()+1)], nil
}
