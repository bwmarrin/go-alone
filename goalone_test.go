package goalone

import (
	"crypto/subtle"
	"testing"
)

func TestNewSecret(t *testing.T) {

	secret := []byte(`B1nzyRateLimits`)
	s := New(secret, nil)
	if s == nil {
		t.Fatal("New returned a nil")
	}

	if s.hash == nil {
		t.Fatal("New returned a Sword with a nil hash")
	}

	if s.dirty {
		t.Fatal("New returned a dirty hash")
	}
}

func TestNewNil(t *testing.T) {

	s := New(nil, nil)
	if s == nil {
		t.Fatal("New returned a nil")
	}

	if s.hash != nil {
		t.Fatal("New returned a Sword without nil hash")
	}

	if s.dirty {
		t.Fatal("New returned a dirty hash")
	}
}

func TestSign(t *testing.T) {

	secret := []byte(`B1nzyRateLimits`)
	data := []byte(`1203981209381290.LutinRocks`)
	want := []byte("1203981209381290.LutinRocks.9yhDXQheVrk0W-dcDAnW0_DglKk")

	s := New(secret, nil)
	token := s.Sign(data)

	if subtle.ConstantTimeCompare(token, want) != 1 {
		t.Logf("data: \n%s\n", data)
		t.Logf("want: \n%s\n", want)
		t.Logf("got : \n%s\n", token)
		t.Fatal("token and want do not match")
	}

	// sign after a dirty hash

	if !s.dirty {
		t.Fatal("Hash is not dirty, but it should be")
	}

	token = s.Sign(data)

	if subtle.ConstantTimeCompare(token, want) != 1 {
		t.Logf("data: \n%s\n", data)
		t.Logf("want: \n%s\n", want)
		t.Logf("got : \n%s\n", token)
		t.Fatal("token and want do not match")
	}

}

func TestUnsignTooLittle(t *testing.T) {

	secret := []byte(`B1nzyRateLimits`)
	token := []byte("9yhDXQheVrk0W-dcDAnW0_DglKk")

	s := New(secret, nil)
	got, err := s.Unsign(token)

	if got != nil {
		t.Error("Unsign returned data, but should have returned nil")
	}

	if err != ErrShortToken {
		t.Fatal("Unsign did not return the correct error")
	}

}

func TestUnsign(t *testing.T) {

	secret := []byte(`B1nzyRateLimits`)
	token := []byte("1203981209381290.LutinRocks.9yhDXQheVrk0W-dcDAnW0_DglKk")
	want := []byte(`1203981209381290.LutinRocks`)

	s := New(secret, nil)
	got, err := s.Unsign(token)
	if err != nil {
		t.Fatal("Unsign returned an err,", err)
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		t.Logf("token: \n%s\n", token)
		t.Logf("want: \n%s\n", want)
		t.Logf("got : \n%s\n", got)
		t.Fatal("data of token does not match original data")
	}

	if !s.dirty {
		t.Fatal("Hash is not dirty, but it should be")
	}

	token = []byte("1203981209381290.LutinRocks.9yhDXQheVrkkW-dcDAnW0_DglKk")
	got, err = s.Unsign(token)
	if err != ErrInvalidSignature {
		t.Fatal("Unsign returned incorrect error")
	}
	if got != nil {
		t.Logf("token: \n%s\n", token)
		t.Logf("want: \n%s\n", want)
		t.Logf("got : \n%s\n", got)
		t.Fatal("got should be nil")
	}
}

func BenchmarkNew(b *testing.B) {
	secret := []byte(`B1nzyRateLimits`)

	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		New(secret, nil)
	}
}

func BenchmarkSignLittle(b *testing.B) {
	secret := []byte(`B1nzyRateLimits`)
	data := []byte(`1203981209381290.LutinRocks`)

	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		New(secret, nil).Sign(data)
	}
}

func BenchmarkReuseSignLittle(b *testing.B) {
	s := New([]byte(`B1nzyRateLimits`), nil)
	data := []byte(`1203981209381290.LutinRocks`)

	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		s.Sign(data)
	}
}

func BenchmarkSignBig(b *testing.B) {
	secret := []byte(`B1nzyRateLimits`)
	data := []byte(`1203981209381290.7h90g7h089234g75908347gh09384h7v0897fg08947f5097423058974h908fg702f9j75028fg5704239hg7053498dj7249038jd57j097g5v029dh79hc47f507v9082h7f509234j7dc02d750j24935h7f924`)

	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		New(secret, nil).Sign(data)
	}
}

func BenchmarkSignBigReuse(b *testing.B) {
	s := New([]byte(`B1nzyRateLimits`), nil)
	data := []byte(`1203981209381290.7h90g7h089234g75908347gh09384h7v0897fg08947f5097423058974h908fg702f9j75028fg5704239hg7053498dj7249038jd57j097g5v029dh79hc47f507v9082h7f509234j7dc02d750j24935h7f924`)

	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		s.Sign(data)
	}
}
func BenchmarkUnsignLittle(b *testing.B) {
	secret := []byte(`B1nzyRateLimits`)
	data := []byte(`1203981209381290.LutinRocks`)

	s := New([]byte(`B1nzyRateLimits`), nil)
	t := s.Sign(data)

	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		New(secret, nil).Unsign(t)
	}
}

func BenchmarkUnsignLittleReuse(b *testing.B) {
	s := New([]byte(`B1nzyRateLimits`), nil)
	data := []byte(`1203981209381290.LutinRocks`)
	t := s.Sign(data)

	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		s.Unsign(t)
	}
}

func BenchmarkUnsignBig(b *testing.B) {
	secret := []byte(`B1nzyRateLimits`)
	data := []byte(`1203981209381290.7h90g7h089234g75908347gh09384h7v0897fg08947f5097423058974h908fg702f9j75028fg5704239hg7053498dj7249038jd57j097g5v029dh79hc47f507v9082h7f509234j7dc02d750j24935h7f924`)
	s := New([]byte(`B1nzyRateLimits`), nil)
	t := s.Sign(data)

	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		New(secret, nil).Unsign(t)
	}
}

func BenchmarkUnsignReuseBig(b *testing.B) {
	s := New([]byte(`B1nzyRateLimits`), nil)
	data := []byte(`1203981209381290.7h90g7h089234g75908347gh09384h7v0897fg08947f5097423058974h908fg702f9j75028fg5704239hg7053498dj7249038jd57j097g5v029dh79hc47f507v9082h7f509234j7dc02d750j24935h7f924`)
	t := s.Sign(data)

	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		s.Unsign(t)
	}
}
