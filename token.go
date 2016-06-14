package authtoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
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

// Verify accepts a string Token and returns true if it is valid.
// maybe make this VerifyString? ughmn.
func Verify(token string, secret []byte) (bool, error) {

	parts := strings.Split(token, ".")

	// make sure it's the right size
	if len(parts) < 3 {
		return false, fmt.Errorf("token is missing parts")
	}

	// convert the string expire to an int
	expire, err := strconv.Atoi(parts[0])
	if err != nil {
		return false, err
	}

	// check if the token is expired.
	if time.Now().UTC().Unix() > int64(expire) {
		return false, fmt.Errorf("expired token")
	}

	// verify HMAC
	h := hmac.New(sha256.New, secret)
	_, err = h.Write([]byte(fmt.Sprintf("%d.%s", expire, parts[1])))
	if err != nil {
		return false, err
	}

	nh := base64.StdEncoding.EncodeToString(h.Sum(nil))
	if parts[2] != string(nh) {
		return false, fmt.Errorf("invalid signature")
	}

	return true, nil
}

func (t Token) String() string {
	return fmt.Sprintf("%d.%s.%s", t.Expire.UTC().Unix(), t.Data, base64.StdEncoding.EncodeToString(t.HMAC))
}
