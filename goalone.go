package goalone

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"hash"
	"sync"
)

// Sword is a Wooden Sword to be used for protection, because it's dangerous out
// there... Also, it is the main struct used to sign, verify, and unsign
// data using this package. You may create it manually and customize thei
// settings or use the New() function to use defaults.
type Sword struct {
	sync.Mutex
	hash  hash.Hash // Will need to expose a way to set this..
	dirty bool      // Tracks if the hash is dirty
}

// New takes a key and returns a new Sword struct using default values.
// You can customize many options by manually creating the Sword struct or
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

// Sign signs data with key and returns []byte.
func (s *Sword) Sign(data []byte) []byte {

	s.Lock()

	// Reset if reused
	if s.dirty {
		s.hash.Reset()
	}

	// Write data to hasher and set dirty.
	s.hash.Write(data)
	s.dirty = true

	// Make result into bytestring.
	// The result will be `data.hash`.
	t := make([]byte, 0, len(data)+s.hash.Size()+1)
	t = append(t, data...)
	t = append(t, '.')
	t = s.hash.Sum(t)
	s.Unlock()

	// Return the result.
	return t
}

// Unsign validates a hmac signature and if successful returns the data
// portion of the []byte
func (s *Sword) Unsign(token []byte) (bool, []byte) {

	tl := len(token)

	// A token must be at least hash.Size+2 bytes long to be valid.
	if tl < s.hash.Size()+2 {
		return false, nil
	}

	s.Lock()
	// Reset if reused
	if s.dirty {
		s.hash.Reset()
	}

	// Write data to hasher and set dirty.
	s.hash.Write(token[0 : tl-(s.hash.Size()+1)])
	s.dirty = true

	// Make result into bytestring.
	// The result will be `data.hash`.
	h := make([]byte, 0, s.hash.Size())
	h = s.hash.Sum(h)
	s.Unlock()

	if subtle.ConstantTimeCompare(token[tl-s.hash.Size():], h) != 1 {
		return false, nil
	}

	return true, token[0 : tl-(s.hash.Size()+1)]
}
