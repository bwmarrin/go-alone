package togoalone

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash"
)

type signer struct {
	h hash.Hash
}

// New returns a new Signer
func Signer(secret []byte) signer {
	return signer{hmac.New(sha256.New, secret)}
}

// Sign signs data with secret and returns []byte
func (s signer) Sign(data []byte) ([]byte, error) {

	fmt.Printf("data : %d / %d\n", len(data), cap(data))

	_, err := s.h.Write(data)
	if err != nil {
		return nil, err
	}

	t := make([]byte, 0, len(data)+33)
	t = append(t, data...)
	t = append(t, []byte(`.`)...)
	t = append(t, s.h.Sum(nil)...)
	return t, nil
}
