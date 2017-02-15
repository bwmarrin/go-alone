// This is a work in progress to show how to Sign/Unsign It's Dangerous
// style tokens.

package goalone

import (
	"crypto/sha1"
	"crypto/subtle"
	"testing"
)

func TestItsDangerousSigner(t *testing.T) {

	// itsdangerous example using the normal "Signer" signer
	// this signer uses Salt by default, which is then sha1.Sum'd

	want := []byte(`my string.wh6tMHxLgJqB6oY1uT73iMlyrOA`)
	data := []byte("my string")
	saltkey := []byte(`itsdangerous.Signersignersecret-key`)
	salt := sha1.Sum(saltkey)
	key := salt[:]

	got := New(key, nil).Sign(data)

	if subtle.ConstantTimeCompare(got, want) != 1 {
		t.Logf("data: \n%s\n", data)
		t.Logf("want: \n%s\n", want)
		t.Logf("got : \n%s\n", got)
		t.Fatal("got and want do not match")
	}
}

func TestItsDangerousSerializer(t *testing.T) {

	// itsdangerous example using the "Serializer" signer
	// this signer uses a different salt...

	want := []byte("[1, 2, 3, 4].r7R9RhGgDPvvWl3iNzLuIIfELmo")
	data := []byte("[1, 2, 3, 4]")
	saltkey := []byte(`itsdangeroussignersecret-key`)
	salt := sha1.Sum(saltkey)
	key := salt[:]

	got := New(key, nil).Sign(data)

	if subtle.ConstantTimeCompare(got, want) != 1 {
		t.Logf("data: \n%s\n", data)
		t.Logf("want: \n%s\n", want)
		t.Logf("got : \n%s\n", got)
		t.Fatal("got and want do not match")
	}
}

func TestItsDangerousURLSafeSerializer(t *testing.T) {

	// itsdangerous example using the "URLSafeSerializer" signer
	// this signer uses the same salt as the Serializer signer does
	want := []byte("WzEsMiwzLDRd.wSPHqC0gR7VUqivlSukJ0IeTDgo")
	data := []byte("WzEsMiwzLDRd")
	saltkey := []byte(`itsdangeroussignersecret-key`)
	salt := sha1.Sum(saltkey)
	key := salt[:]

	got := New(key, nil).Sign(data)

	if subtle.ConstantTimeCompare(got, want) != 1 {
		t.Logf("data: \n%s\n", data)
		t.Logf("want: \n%s\n", want)
		t.Logf("got : \n%s\n", got)
		t.Fatal("got and want do not match")
	}
}
