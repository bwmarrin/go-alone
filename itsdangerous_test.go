// This is a work in progress to show how to Sign/Unsign It's Dangerous
// style tokens.

package goalone

import (
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"testing"
)

const (
	// ItsDangerousEpoch is the default epoch used by It's Dangerous
	ItsDangerousEpoch = 1293840000
	// ItsDangerousDerivation is the default Derivation used by It's Dangerous
	ItsDangerousDerivation = `django-concat`
)

var (
	// ItsDangerousSignerSalt is the default salt used by the It's Dangerous
	// "Signer" signer
	ItsDangerousSignerSalt = []byte(`itsdangerous.Signer`)
	// ItsDangerousSerializerSalt is the default salt used by the It's Dangerous
	// "Serializer" and "URLSafeSerializer" signers
	ItsDangerousSerializerSalt = []byte(`itsdangerous`)
)

// This test provides an example and a compatability test to the itsdangerous
// "Signer" signer.  This signer uses "Salt" by default, which is combined
// with the secret key and sha1.Sum'd.  Following this example you should be
// able to sign or unsign this type of itsdangerous token.
func TestItsDangerousSigner(t *testing.T) {

	// payload is the information that we're going to sign
	payload := []byte("my string")

	// key is the secret "password" used to sign the payload
	key := []byte(`secret-key`)

	// want is what we expect returned from Sign, this is the example
	// shown in the itsdangerous documentation for this signer
	want := []byte(`my string.wh6tMHxLgJqB6oY1uT73iMlyrOA`)

	// Take the key and add the default Signer Salt, combined with "signer" then
	// create a sha1.Sum of the result and uses that as the key
	key = append(append(ItsDangerousSignerSalt, []byte(`signer`)...), key...)
	ks := sha1.Sum(key)

	// Now, Sign the payload with the key.
	got := New(ks[:], nil).Sign(payload)

	// Test to make sure it worked and returned the right response.
	if subtle.ConstantTimeCompare(got, want) != 1 {
		t.Logf("payload : \n%s\n", payload)
		t.Logf("want    : \n%s\n", want)
		t.Logf("got     : \n%s\n", got)
		t.Fatal("got and want do not match")
	}
}

// This test provides an example and a compatability test to the itsdangerous
// Serializer signer.  This signer uses "Salt" by default, which is combined
// with the secret key and sha1.Sum'd.  Following this example you should be
// able to sign or unsign this type of itsdangerous token.
func TestItsDangerousSerializer(t *testing.T) {

	// payload is the information that we're going to sign
	payload := []byte("[1, 2, 3, 4]")

	// key is the secret "password" used to sign the payload
	key := []byte(`secret-key`)

	// want is what we expect returned from Sign, this is the example
	// shown in the itsdangerous documentation for this signer
	want := []byte("[1, 2, 3, 4].r7R9RhGgDPvvWl3iNzLuIIfELmo")

	// Take the key and add the default Serializer Salt, combined with
	// "signer" then create a sha1.Sum of the result and uses that as the key
	key = append(append(ItsDangerousSerializerSalt, []byte(`signer`)...), key...)
	ks := sha1.Sum(key)

	// Now, Sign the payload with the key.
	got := New(ks[:], nil).Sign(payload)

	// Test to make sure it worked and returned the right response.
	if subtle.ConstantTimeCompare(got, want) != 1 {
		t.Logf("payload : \n%s\n", payload)
		t.Logf("want    : \n%s\n", want)
		t.Logf("got     : \n%s\n", got)
		t.Fatal("got and want do not match")
	}
}

// This test provides an example and a compatability test to the itsdangerous
// URLSafeSerializer signer.  This signer uses "Salt" by default, which is
// combined with the secret key and sha1.Sum'd.  Following this example you
// should be able to sign or unsign this type of itsdangerous token.
func TestItsDangerousURLSafeSerializer(t *testing.T) {

	// payload is the information that we're going to sign
	payload := []byte("[1,2,3,4]")
	//	payload := []byte("WzEsMiwzLDRd")

	// key is the secret "password" used to sign the payload
	key := []byte(`secret-key`)

	// want is what we expect returned from Sign, this is the example
	// shown in the itsdangerous documentation for this signer.
	want := []byte("WzEsMiwzLDRd.wSPHqC0gR7VUqivlSukJ0IeTDgo")

	// Take the key and add the default Serializer Salt, combined with
	// "signer" then create a sha1.Sum of the result and uses that as the key
	key = append(append(ItsDangerousSerializerSalt, []byte(`signer`)...), key...)
	ks := sha1.Sum(key)

	// First, Base64 URL encode the payload

	ep := base64.RawURLEncoding.EncodeToString(payload)

	// Now, Sign the payload with the key.
	got := New(ks[:], nil).Sign([]byte(ep))

	// Test to make sure it worked and returned the right response.
	if subtle.ConstantTimeCompare(got, want) != 1 {
		t.Logf("payload : \n%s\n", payload)
		t.Logf("want    : \n%s\n", want)
		t.Logf("got     : \n%s\n", got)
		t.Fatal("got and want do not match")
	}
}
