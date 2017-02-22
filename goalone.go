package goalone

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
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
	// Number of seconds since January 1, 1970 UTC
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

	// Create a map for decoding Base58.  This speeds up the process tremendously.
	for i := 0; i < len(encodeBase58Map); i++ {
		decodeBase58Map[encodeBase58Map[i]] = byte(i)
	}

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
		ts := time.Now().Unix() - s.Epoch
		etl := encodeBase58Len(ts)
		t = make([]byte, 0, len(data)+etl+el+2) // +2 for "." chars
		t = append(t, data...)
		t = append(t, '.')
		t = t[0 : len(t)+etl] // expand for timestamp
		encodeBase58(ts, t)
	} else {
		t = make([]byte, 0, len(data)+el+1)
		t = append(t, data...)
	}

	// Append and encode signature to token
	t = append(t, '.')
	tl := len(t)
	t = t[0 : tl+el]

	// Add the signature to the token
	s.sign(t[tl:], t[0:tl-1])

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

	// Get the signature of the payload
	dst := make([]byte, el)
	s.sign(dst, token[0:tl-(el+1)])

	if subtle.ConstantTimeCompare(token[tl-el:], dst) != 1 {
		return nil, ErrInvalidSignature
	}

	return token[0 : tl-(el+1)], nil
}

///////////////////////////////////////////////////////////////////////////////
// Unexported Code ////////////////////////////////////////////////////////////

// This is the map of characters used during base58 encoding.  These replicate
// the flickr shortid mapping.
const encodeBase58Map = "123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"

// Used to create a decode map so we can decode base58 fairly fast.
var decodeBase58Map [256]byte

// sign creates the encoded signature of payload and writes to dst
func (s *Sword) sign(dst, payload []byte) {

	s.Lock()
	if s.dirty {
		s.hash.Reset()
	}
	s.dirty = true
	s.hash.Write(payload)
	h := s.hash.Sum(nil)
	s.Unlock()

	base64.RawURLEncoding.Encode(dst, h)
}

// returns the len of base58 encoded i
func encodeBase58Len(i int64) int {

	var l = 1
	for i >= 58 {
		l++
		i /= 58
	}
	return l
}

// encode time int64 into b []byte
func encodeBase58(i int64, b []byte) {
	p := len(b) - 1
	for i >= 58 {
		b[p] = encodeBase58Map[i%58]
		p--
		i /= 58
	}
	b[p] = encodeBase58Map[i]
}

// parses a base58 []byte into a int64
func decodeBase58(b []byte) int64 {
	var id int64
	for p := range b {
		id = id*58 + int64(decodeBase58Map[b[p]])
	}
	return id
}
