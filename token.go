package authtoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"time"
)

// A Token struct stores the individual fields within the Token
type Token struct {
	Expire time.Time `json:"expire"`
	Data   []byte    `json:"data"`
	HMAC   []byte    `json:"hmac"`
}

// Generate creates and returns a signed authentication token with the
// following format: expire.data.hmac
//
//   expire : the time that this token should expire
//   data   : the data stored in this token
//   secret : the secret key used to sign the token
func Generate(expire time.Time, data, secret []byte) (*Token, error) {

	t := Token{}
	t.Expire = expire
	t.Data = data

	h := hmac.New(sha256.New, secret)
	_, err := h.Write([]byte(fmt.Sprintf("%d.%s", expire.UTC().Unix(), data)))
	if err != nil {
		return nil, err
	}
	t.HMAC = h.Sum(nil)

	return &t, nil
}
