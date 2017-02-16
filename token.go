package goalone

import (
	"encoding/base64"
	"time"
)

// Token is used to parse out a []byte token provided by Sign()
type Token struct {
	Payload   []byte
	Timestamp time.Time
}

// Parse ... a []byte token into a Token
// This parses the []byte based on the Sword Options.  For this to work
// corectly the Sword Options need to match that of what was used when the
// token was initially created.
func (s *Sword) Parse(t []byte) Token {

	tl := len(t)
	el := base64.RawURLEncoding.EncodedLen(s.hash.Size())

	token := Token{}

	if s.Timestamp {
		token.Timestamp = time.Unix(int64(decodeUint64(t[tl-(el+7):tl-(el+1)])), 0)
		token.Payload = t[0 : tl-(el+8)]
	} else {
		token.Payload = t[0 : tl-(el+1)]
	}

	return token
}
