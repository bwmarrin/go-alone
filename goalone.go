package goalone

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash"
	"sync"
	"time"
)

// Options that can be configured and passed to New()
type Options struct {
	// hash algorithm to use when signing tokens, ex. sha1.New
	Algorithm func() hash.Hash

	// Epoch to use for Timestamps, when signing/parsing Tokens
	Epoch int64

	// Should the Sign method add a timestamp to tokens?
	Timestamp bool
}

// Sword is a magical Wooden Sword to be used for protection, because it's dangerous out
// there... Also, it is the main struct used to sign and unsign data using this
// package.
type Sword struct {
	sync.Mutex
	hash  hash.Hash
	dirty bool

	Options
}

// ErrInvalidSignature is returned by Unsign when the provided token's
// signatuire is not valid.
var ErrInvalidSignature = errors.New("invalid signature")

// ErrShortToken is returned by Unsign when the provided token's length
// is too short to be a vlaid token.
var ErrShortToken = errors.New("token is too small to be valid")

// New takes a secret key and returns a new Sword.  If no Options are provided
// then minimal defaults will be used.
func New(key []byte, o *Options) *Sword {

	if key == nil {
		return &Sword{}
	}

	if o == nil {
		return &Sword{hash: hmac.New(sha1.New, key)}
	}

	s := &Sword{Options: *o}
	if s.Algorithm == nil {
		s.hash = hmac.New(sha1.New, key)
	} else {
		s.hash = hmac.New(s.Algorithm, key)
	}

	return s
}

// Sign signs data and returns []byte in the format `data.signature`. Optionally
// add a timestamp and return in the format `data.timestamp.signature`
func (s *Sword) Sign(data []byte) []byte {

	// Build the payload
	el := base64.RawURLEncoding.EncodedLen(s.hash.Size())
	var t []byte

	if s.Timestamp {
		now := time.Now().UTC().Unix() - s.Epoch
		ts := encodeUint64(uint64(now))
		t = make([]byte, 0, len(data)+len(ts)+el+2)
		t = append(t, data...)
		t = append(t, '.')
		t = append(t, ts...)
	} else {
		t = make([]byte, 0, len(data)+el+1)
		t = append(t, data...)
	}

	// Now lets lock the hash and create the signature
	s.Lock()
	if s.dirty {
		s.hash.Reset()
	}
	s.dirty = true
	s.hash.Write(t)
	h := s.hash.Sum(nil)
	s.Unlock()

	// Append signature to token
	t = append(t, '.')
	tl := len(t)
	t = t[0 : tl+el]
	base64.RawURLEncoding.Encode(t[tl:], h)

	// Return the token to the caller
	return t
}

// Unsign validates a signature and if successful returns the data portion of
// the []byte. If unsuccessful it will return an error and nil for the data.
func (s *Sword) Unsign(token []byte) ([]byte, error) {

	tl := len(token)
	el := base64.RawURLEncoding.EncodedLen(s.hash.Size())

	// A token must be at least el+2 bytes long to be valid.
	if tl < el+2 {
		return nil, ErrShortToken
	}

	// Now lets lock the hash and create the signature
	s.Lock()
	if s.dirty {
		s.hash.Reset()
	}
	s.dirty = true
	s.hash.Write(token[0 : tl-(el+1)])
	h := s.hash.Sum(nil)
	s.Unlock()

	// Encode hash into dst
	dst := make([]byte, el)
	base64.RawURLEncoding.Encode(dst, h)

	if subtle.ConstantTimeCompare(token[tl-el:], dst) != 1 {
		return nil, ErrInvalidSignature
	}

	return token[0 : tl-(el+1)], nil
}

func encodeUint64(i uint64) []byte {

	// covert int into bytes
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, i)

	// encode bytes to base64, striping off leading 0's
	buf2 := make([]byte, 11)
	base64.RawURLEncoding.Encode(buf2, bytes.TrimLeft(buf, "\x00"))

	// return result, removing training `\x00`
	return bytes.TrimRight(buf2, "\x00")
}

func decodeUint64(b []byte) uint64 {

	l := len(b) * 6 / 8 // cause DecodedLen has a bug // https://github.com/golang/go/commit/87151c82b68023e4224b016a6a66ead2c4b8ece7
	buf := make([]byte, 8)

	base64.RawURLEncoding.Decode(buf[8-l:], b)
	return binary.BigEndian.Uint64(buf)
}
