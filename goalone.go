package goalone

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"hash"
)

const (
	DefaultEpoch = 1293840000 // itsdangerous Epoch
)

// Signer Struct for signing data with a secret.
type Signer struct {
	hash  hash.Hash
	dirty bool
	epoch int
}

// New Return a new Signer.
func New(secret []byte) Signer {
	return Signer{
		hash:  hmac.New(sha1.New, secret),
		epoch: DefaultEpoch,
	}
}

// Sign Signs data with secret and returns []byte.
func (s *Signer) Sign(data []byte) []byte {
	s.hash.Size()

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

	// Return the result.
	return t
}

// Verify validates a token and returns a bool
func (s *Signer) Validate(token []byte) bool {

	tl := len(token)

	// A token must be at least .. bytes long to be valid.
	if tl < s.hash.Size()+2 {
		return false
	}

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

	return (subtle.ConstantTimeCompare(token[tl-s.hash.Size():], h) == 1)
}

func EncodeUint64(i uint64) []byte {

	// covert int into bytes
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, i)

	// encode bytes to base64, striping off leading 0's
	buf2 := make([]byte, 11)
	base64.RawURLEncoding.Encode(buf2, bytes.TrimLeft(buf, "\x00"))

	// return result, removing training `\x00`
	return bytes.TrimRight(buf2, "\x00")
}

func DecodeUint64(b []byte) uint64 {

	l := len(b) * 6 / 8 // cause DecodedLen has a bug // https://github.com/golang/go/commit/87151c82b68023e4224b016a6a66ead2c4b8ece7
	buf := make([]byte, 8)

	base64.RawURLEncoding.Decode(buf[8-l:], b)
	return binary.BigEndian.Uint64(buf)
}
